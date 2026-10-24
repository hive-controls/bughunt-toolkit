"""Hermetic tests for `bughunt route` (injected probe and resolver, no real network or OS reads)."""
import json
import sys

import pytest

from bughunt.console import doctor, ui
from bughunt.core import route, route_probe
from bughunt.core.route_probe import Interface, ProbeError
from bughunt.modules import route as route_module

WG = Interface(5, "wg0", "WireGuard Tunnel", True)
ETH = Interface(2, "en0", "", True)
IN_SCOPE = "target.example"


class FakeProbe:
    def __init__(self, interfaces, routes):
        self._interfaces, self._routes = interfaces, routes

    def interfaces(self):
        return list(self._interfaces)

    def egress_indexes(self, address):
        outcome = self._routes.get(address, ProbeError(f"no route to {address}"))
        if isinstance(outcome, Exception):
            raise outcome
        return set(outcome)


@pytest.fixture
def workspace_root(tmp_path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    monkeypatch.delenv(route.ENV_CONFIG, raising=False)
    return root


@pytest.fixture
def tunnel_up(monkeypatch):
    probe = FakeProbe([WG, ETH], {"1.1.1.1": {5}, "10.0.0.9": {5}, "8.8.8.8": {2}})
    monkeypatch.setattr(route_probe, "default_probe", lambda platform=None: probe)
    monkeypatch.setattr(route_module, "_resolver",
                        lambda host, port: [(0, 0, 0, "", ({IN_SCOPE: "10.0.0.9"}[host], 0))])
    return probe


def write_config(root, **overrides):
    document = {"schema_version": 1, "interfaces": ["wg0"], **overrides}
    (root / "route.json").write_text(json.dumps(document), encoding="utf-8")


def add_scope(root, entry=IN_SCOPE):
    (root / "scope.txt").write_text(f"{entry}\n", encoding="utf-8")


def run(capfd, *argv):
    capfd.readouterr()
    original = ui.console.file
    ui.console.file = sys.stdout  # the console binds stdout at import; follow this test's capture
    try:
        code = route_module.main(list(argv))
    finally:
        ui.console.file = original
    return code, capfd.readouterr().out


# ----------------------------------------------------------------------------- init

def test_init_writes_a_valid_config_atomically(workspace_root, capfd):
    code, _ = run(capfd, "init", "--interface", "wg0", "--interface", "corp-vpn")
    assert code == 0
    written = workspace_root / "route.json"
    policy = route.load_config(written)
    assert policy.interfaces == ("wg0", "corp-vpn")
    assert not list(workspace_root.glob(".route-*"))


def test_init_refuses_to_overwrite_without_force(workspace_root, capfd):
    write_config(workspace_root, interfaces=["keep-me"])
    code, out = run(capfd, "init", "--interface", "other")
    assert code == 2
    assert "--force" in out
    assert route.load_config(workspace_root / "route.json").interfaces == ("keep-me",)
    assert not list(workspace_root.glob(".route-*"))


def test_init_force_replaces_and_path_overrides_location(workspace_root, tmp_path, capfd):
    write_config(workspace_root, interfaces=["old"])
    assert run(capfd, "init", "--interface", "new", "--force")[0] == 0
    assert route.load_config(workspace_root / "route.json").interfaces == ("new",)
    elsewhere = tmp_path / "pinned" / "route.json"
    assert run(capfd, "init", "--interface", "x", "--path", str(elsewhere))[0] == 0
    assert elsewhere.is_file()


def test_init_rejects_blank_interface_without_writing(workspace_root, capfd):
    code, _ = run(capfd, "init", "--interface", "  ")
    assert code == 2
    assert not (workspace_root / "route.json").exists()


# --------------------------------------------------------------------------- status

def test_status_without_config_is_inactive_and_exit_zero(workspace_root, capfd):
    code, out = run(capfd, "status")
    assert code == 0
    assert "inactive" in out


def test_status_reports_workspace_source_and_interfaces(workspace_root, tunnel_up, capfd):
    write_config(workspace_root, protect=["console"])
    code, out = run(capfd, "status", "--json")
    report = json.loads(out)
    assert code == 0
    assert report["source"] == str(workspace_root / "route.json")
    assert report["protect"] == ["console"]
    rows = {row["name"]: row for row in report["interfaces"]}
    assert rows["wg0"]["matches"] and rows["wg0"]["carries_probe"]
    assert not rows["en0"]["matches"] and not rows["en0"]["carries_probe"]


def test_status_env_source_wins_over_workspace(workspace_root, tmp_path, monkeypatch, tunnel_up, capfd):
    write_config(workspace_root, interfaces=["workspace"])
    pinned = tmp_path / "pinned.json"
    pinned.write_text(json.dumps({"schema_version": 1, "interfaces": ["pinned"]}), encoding="utf-8")
    monkeypatch.setenv(route.ENV_CONFIG, str(pinned))
    code, out = run(capfd, "status", "--json")
    assert code == 0
    assert json.loads(out)["source"] == str(pinned)


def test_status_invalid_config_exits_two(workspace_root, capfd):
    (workspace_root / "route.json").write_text("{not json", encoding="utf-8")
    code, out = run(capfd, "status")
    assert code == 2
    assert "invalid" in out


def test_status_survives_a_missing_backend(workspace_root, monkeypatch, capfd):
    write_config(workspace_root)

    def broken(platform=None):
        raise ProbeError("no routing tool")

    monkeypatch.setattr(route_probe, "default_probe", broken)
    code, out = run(capfd, "status", "--json")
    assert code == 0
    assert json.loads(out)["backend_error"] == "no routing tool"


# ---------------------------------------------------------------------------- check

def test_check_probe_passes_when_the_tunnel_carries_it(workspace_root, tunnel_up, capfd):
    write_config(workspace_root)
    code, out = run(capfd, "check", "--json")
    assert code == 0
    assert json.loads(out)["ok"] is True


def test_check_blocks_when_probe_route_leaves_the_tunnel(workspace_root, monkeypatch, capfd):
    write_config(workspace_root)
    leaking = FakeProbe([WG, ETH], {"1.1.1.1": {2}})
    monkeypatch.setattr(route_probe, "default_probe", lambda platform=None: leaking)
    code, out = run(capfd, "check", "--json")
    assert code == 2
    assert json.loads(out)["ok"] is False


def test_check_in_scope_host_resolves_and_passes(workspace_root, tunnel_up, capfd):
    write_config(workspace_root)
    add_scope(workspace_root)
    code, out = run(capfd, "check", IN_SCOPE, "--json")
    assert code == 0
    assert any("10.0.0.9" in line for line in json.loads(out)["details"])


def test_check_out_of_scope_host_is_never_resolved(workspace_root, tunnel_up, monkeypatch, capfd):
    write_config(workspace_root)
    add_scope(workspace_root, "other.example")
    resolved = []
    monkeypatch.setattr(route_module, "_resolver", lambda host, port: resolved.append(host) or [])
    code, out = run(capfd, "check", IN_SCOPE)
    assert code == 2
    assert resolved == []
    assert "scope" in out


def test_check_blocks_a_destination_that_bypasses_the_tunnel(workspace_root, monkeypatch, capfd):
    write_config(workspace_root)
    add_scope(workspace_root)
    probe = FakeProbe([WG, ETH], {"1.1.1.1": {5}, "8.8.8.8": {2}})
    monkeypatch.setattr(route_probe, "default_probe", lambda platform=None: probe)
    monkeypatch.setattr(route_module, "_resolver", lambda host, port: [(0, 0, 0, "", ("8.8.8.8", 0))])
    code, _ = run(capfd, "check", IN_SCOPE)
    assert code == 2


def test_check_invalid_or_absent_config_blocks(workspace_root, capfd):
    assert run(capfd, "check")[0] == 2
    (workspace_root / "route.json").write_text("[]", encoding="utf-8")
    assert run(capfd, "check")[0] == 2


# --------------------------------------------------------------------------- doctor

def test_doctor_has_no_route_row_without_config(workspace_root):
    assert [c.name for c in doctor._route_checks()] == []


def test_doctor_route_row_is_offline_and_never_required(workspace_root, monkeypatch):
    write_config(workspace_root, protect=["proxy_scan"])
    monkeypatch.setattr(route_probe, "default_probe", lambda platform=None: FakeProbe([], {}))
    (row,) = doctor._route_checks()
    assert (row.name, row.ok, row.required) == ("route gate", True, False)
    assert "proxy_scan" in row.detail and str(workspace_root / "route.json") in row.detail


def test_doctor_route_row_flags_invalid_config_without_failing_doctor(workspace_root):
    (workspace_root / "route.json").write_text("{", encoding="utf-8")
    (row,) = doctor._route_checks()
    assert row.ok is False and row.required is False
