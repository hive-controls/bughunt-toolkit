"""Hermetic tests for bughunt.core.route (injected probe + resolver)."""
import json

import pytest

from bughunt.core import route
from bughunt.core.route_probe import Interface, ProbeError

WG = Interface(5, "wg0", "WireGuard Tunnel", True)
LO = Interface(1, "lo0", "", True)
ETH = Interface(2, "en0", "", True)


class FakeProbe:
    def __init__(self, interfaces, routes, interface_error=None):
        self._interfaces, self._routes, self._interface_error = interfaces, routes, interface_error
        self.lookups: list[str] = []

    def interfaces(self):
        if self._interface_error:
            raise self._interface_error
        return list(self._interfaces)

    def egress_indexes(self, address):
        self.lookups.append(address)
        outcome = self._routes.get(address, ProbeError(f"no route to {address}"))
        if isinstance(outcome, Exception):
            raise outcome
        return set(outcome)


class FakeResolver:
    def __init__(self, mapping=None, error=None):
        self.mapping, self.error, self.calls = mapping or {}, error, []

    def __call__(self, host, port, *args, **kwargs):
        self.calls.append(host)
        if self.error:
            raise self.error
        return [(0, 0, 0, "", (address, 0)) for address in self.mapping.get(host, [])]


def policy(**overrides):
    base = {"interfaces": ("wg0",), "probe_address": "1.1.1.1"}
    base.update(overrides)
    return route.RoutePolicy(**base)


def good_probe(**extra):
    routes = {"1.1.1.1": {5}, "127.0.0.1": {1}}
    routes.update(extra)
    return FakeProbe([LO, ETH, WG], routes)


CONFIG = {"schema_version": 1, "interfaces": ["wg0"]}


# ------------------------------------------------------------------ config

def test_valid_config_defaults():
    parsed = route.parse_config(json.dumps(CONFIG))
    assert parsed.probe_address == "1.1.1.1" and parsed.protect == route.PROTECT_POINTS
    assert parsed.allow_loopback_proxy is False


def test_valid_config_full():
    parsed = route.parse_config(json.dumps({**CONFIG, "probe_address": "9.9.9.9", "protect": ["console"],
                                            "allow_loopback_proxy": True}))
    assert (parsed.probe_address, parsed.protect, parsed.allow_loopback_proxy) == ("9.9.9.9", ("console",), True)


@pytest.mark.parametrize("mutation", [
    {"surprise": 1}, {"interfaces": "wg0"}, {"interfaces": []}, {"interfaces": [""]}, {"interfaces": [3]},
    {"probe_address": "example.com"}, {"probe_address": 7}, {"protect": ["scan"]}, {"protect": "console"},
    {"allow_loopback_proxy": "yes"}, {"schema_version": 2}, {"schema_version": True},
])
def test_invalid_config_values_rejected(mutation):
    with pytest.raises(route.ConfigError):
        route.parse_config(json.dumps({**CONFIG, **mutation}))


@pytest.mark.parametrize("text", ["{", "[]", '{"schema_version": 1}', "null"])
def test_invalid_config_shapes_rejected(text):
    with pytest.raises(route.ConfigError):
        route.parse_config(text)


def test_oversize_config_rejected(tmp_path):
    big = tmp_path / "route.json"
    big.write_text(json.dumps({**CONFIG, "interfaces": ["x" * 70000]}))
    with pytest.raises(route.ConfigError, match="64 KiB"):
        route.load_config(big)


# ------------------------------------------------------------------ precedence + gate()

@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "ws"))
    monkeypatch.delenv(route.ENV_CONFIG, raising=False)
    (tmp_path / "ws").mkdir()
    return tmp_path / "ws"


def test_nothing_configured_gate_is_none(workspace):
    assert route.gate("proxy_scan", "proxy.example", probe=good_probe()) is None


def test_workspace_config_used(workspace):
    (workspace / "route.json").write_text(json.dumps(CONFIG))
    verdict = route.gate("console", probe=good_probe())
    assert verdict is not None and verdict.ok


def test_env_config_wins_over_workspace(workspace, tmp_path):
    (workspace / "route.json").write_text(json.dumps(CONFIG))
    other = tmp_path / "other.json"
    other.write_text(json.dumps({**CONFIG, "interfaces": ["nomatch"]}))
    verdict = route.gate("console", env={route.ENV_CONFIG: str(other)}, probe=good_probe())
    assert verdict is not None and not verdict.ok


def test_env_pointing_at_missing_file_blocks(workspace, tmp_path):
    verdict = route.gate("console", env={route.ENV_CONFIG: str(tmp_path / "typo.json")}, probe=good_probe())
    assert verdict is not None and not verdict.ok and "invalid" in verdict.summary


def test_present_but_invalid_workspace_config_blocks(workspace):
    (workspace / "route.json").write_text('{"schema_version": 1, "interfaces": []}')
    probe = good_probe()
    verdict = route.gate("proxy_scan", "proxy.example", probe=probe)
    assert verdict is not None and not verdict.ok and probe.lookups == []


def test_protect_empty_or_unlisted_point_is_none(workspace):
    (workspace / "route.json").write_text(json.dumps({**CONFIG, "protect": []}))
    assert route.gate("console", probe=good_probe()) is None
    (workspace / "route.json").write_text(json.dumps({**CONFIG, "protect": ["console"]}))
    assert route.gate("proxy_scan", "proxy.example", probe=good_probe()) is None


# ------------------------------------------------------------------ verify

def test_pass_probe_only():
    verdict = route.verify(policy(), probe=good_probe())
    assert verdict.ok and verdict.details


def test_no_matching_interface_blocks():
    verdict = route.verify(policy(interfaces=("nomatch",)), probe=good_probe())
    assert not verdict.ok and "No matching tunnel" in verdict.summary


def test_matching_but_down_blocks():
    probe = FakeProbe([Interface(5, "wg0", "", False)], {"1.1.1.1": {5}})
    assert not route.verify(policy(), probe=probe).ok


def test_up_but_probe_routes_elsewhere_has_distinct_message():
    verdict = route.verify(policy(), probe=good_probe(**{"1.1.1.1": {2}}))
    assert not verdict.ok and "does not use it" in verdict.summary


def test_probe_lookup_error_blocks():
    probe = FakeProbe([WG], {"1.1.1.1": ProbeError("boom")})
    verdict = route.verify(policy(), probe=probe)
    assert not verdict.ok and "boom" in verdict.summary


def test_backend_exception_blocks_not_raises():
    probe = FakeProbe([], {}, interface_error=ProbeError("ip missing"))
    assert not route.verify(policy(), probe=probe).ok


def test_match_is_case_insensitive_and_covers_description():
    assert route.verify(policy(interfaces=("WIREGUARD",)), probe=good_probe()).ok
    assert route.verify(policy(interfaces=("WG0",)), probe=good_probe()).ok


def test_destination_all_addresses_via_tunnel_passes():
    resolver = FakeResolver({"proxy.example": ["203.0.113.5", "2001:db8::5"]})
    probe = good_probe(**{"203.0.113.5": {5}, "2001:db8::5": {5}})
    assert route.verify(policy(), destination="proxy.example", kind="proxy", probe=probe, resolver=resolver).ok


def test_one_ipv6_address_outside_blocks():
    resolver = FakeResolver({"proxy.example": ["203.0.113.5", "2001:db8::5"]})
    probe = good_probe(**{"203.0.113.5": {5}, "2001:db8::5": {2}})
    assert not route.verify(policy(), destination="proxy.example", probe=probe, resolver=resolver).ok


def test_address_with_no_route_blocks():
    resolver = FakeResolver({"proxy.example": ["203.0.113.5"]})
    assert not route.verify(policy(), destination="proxy.example", probe=good_probe(), resolver=resolver).ok


def test_resolver_error_and_zero_addresses_block():
    assert not route.verify(policy(), destination="gone.example", probe=good_probe(),
                            resolver=FakeResolver(error=OSError("nxdomain"))).ok
    assert not route.verify(policy(), destination="empty.example", probe=good_probe(),
                            resolver=FakeResolver({})).ok


def test_ip_literal_never_calls_resolver():
    resolver = FakeResolver()
    probe = good_probe(**{"203.0.113.9": {5}})
    assert route.verify(policy(), destination="203.0.113.9", probe=probe, resolver=resolver).ok
    assert resolver.calls == []


def test_multipath_with_any_egress_outside_blocks_subset_rule():
    probe = good_probe(**{"203.0.113.9": {5, 2}})
    assert not route.verify(policy(), destination="203.0.113.9", probe=probe, resolver=FakeResolver()).ok


# ------------------------------------------------------------------ D1: loopback

def test_loopback_proxy_blocked_by_default():
    resolver = FakeResolver({"localhost": ["127.0.0.1"]})
    verdict = route.verify(policy(), destination="localhost", kind="proxy", probe=good_probe(), resolver=resolver)
    assert not verdict.ok and "127.0.0.1" in verdict.summary


def test_loopback_proxy_allowed_only_with_flag_and_proxy_kind():
    resolver = FakeResolver({"localhost": ["127.0.0.1"]})
    allowed = policy(allow_loopback_proxy=True)
    assert route.verify(allowed, destination="localhost", kind="proxy", probe=good_probe(), resolver=resolver).ok
    assert not route.verify(allowed, destination="localhost", kind="probe", probe=good_probe(), resolver=resolver).ok


def test_loopback_flag_does_not_waive_probe_check():
    probe = good_probe(**{"1.1.1.1": {2}})
    verdict = route.verify(policy(allow_loopback_proxy=True), destination="127.0.0.1", kind="proxy", probe=probe)
    assert not verdict.ok


def test_mixed_loopback_and_public_not_waived():
    resolver = FakeResolver({"proxy.example": ["127.0.0.1", "203.0.113.5"]})
    probe = good_probe(**{"203.0.113.5": {2}})
    assert not route.verify(policy(allow_loopback_proxy=True), destination="proxy.example", kind="proxy",
                            probe=probe, resolver=resolver).ok


def test_unsupported_platform_blocks_via_default_probe(monkeypatch):
    monkeypatch.setattr(route.route_probe.sys, "platform", "plan9")
    verdict = route.verify(policy())
    assert not verdict.ok and "not supported" in verdict.summary


# ------------------------------------------------------------------ mutation-proof gate

def test_gate_blocks_proxy_outside_tunnel_and_asks_probe_once(workspace):
    """Mutation target: disabling the route.verify call in gate() turns this red."""
    (workspace / "route.json").write_text(json.dumps(CONFIG))
    resolver = FakeResolver({"proxy.example": ["203.0.113.5"]})
    probe = good_probe(**{"203.0.113.5": {2}})
    verdict = route.gate("proxy_scan", "proxy.example", kind="proxy", probe=probe, resolver=resolver)
    assert verdict is not None and not verdict.ok
    assert probe.lookups.count("203.0.113.5") == 1
