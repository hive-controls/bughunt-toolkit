"""The console-open route gate: `protect: console` blocks `bughunt console` unless the tunnel is proven up."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bughunt.console import cli
from bughunt.core import route, route_probe
from bughunt.core.route_probe import Interface, ProbeError

from console_support import env  # noqa: F401  (pytest fixture)

WG = Interface(5, "wg0", "WireGuard Tunnel", True)
ETHERNET = Interface(2, "eth0", "", True)
TOOL_FILE = Path(cli.__file__)


class FakeProbe:
    def __init__(self, routes=None, interfaces=(ETHERNET, WG), interface_error=None):
        self.routes = {"1.1.1.1": {5}} if routes is None else routes
        self.interface_list, self.interface_error = list(interfaces), interface_error

    def interfaces(self):
        if self.interface_error:
            raise self.interface_error
        return list(self.interface_list)

    def egress_indexes(self, address):
        outcome = self.routes.get(address, ProbeError(f"no route to {address}"))
        if isinstance(outcome, Exception):
            raise outcome
        return set(outcome)


@pytest.fixture
def opened(env, monkeypatch):
    """Records every console that actually opens (the typed console is stubbed)."""
    calls = []
    import bughunt.console.console as console_module

    monkeypatch.setattr(cli, "_terminal_attached", lambda: False)
    monkeypatch.setattr(
        console_module, "run_console", lambda **kwargs: calls.append(kwargs) or 0
    )
    return calls


def _config(**overrides):
    document = {
        "schema_version": 1,
        "interfaces": ["wg0"],
        "protect": ["console"],
        **overrides,
    }
    (route.workspace_dir() / route.CONFIG_FILENAME).write_text(
        json.dumps(document), encoding="utf-8"
    )


def _open(probe=None):
    return cli.open_console(
        tool_file=TOOL_FILE, scan_main=None, build_parser=None, probe=probe
    )


def test_no_config_opens(opened):
    assert _open(FakeProbe(interface_error=ProbeError("never consulted"))) == 0
    assert len(opened) == 1


def test_protect_without_console_opens(opened):
    _config(protect=["proxy_scan"])
    assert _open(FakeProbe(interface_error=ProbeError("never consulted"))) == 0
    assert len(opened) == 1


def test_protected_and_tunnel_up_opens(opened):
    _config()
    assert _open(FakeProbe()) == 0
    assert len(opened) == 1


@pytest.mark.parametrize(
    "probe",
    [
        FakeProbe(interfaces=(ETHERNET,)),
        FakeProbe(
            interface_error=ProbeError(
                "route verification is not supported on this platform"
            )
        ),
        FakeProbe(routes={"1.1.1.1": ProbeError("lookup failed")}),
        FakeProbe(routes={"1.1.1.1": {2}}),
    ],
    ids=[
        "tunnel-down",
        "unsupported-backend",
        "probe-error",
        "probe-address-off-tunnel",
    ],
)
def test_protected_and_not_verified_is_denied(opened, probe):
    _config()
    assert _open(probe) == 2
    assert opened == []


def test_invalid_config_is_denied(opened):
    (route.workspace_dir() / route.CONFIG_FILENAME).write_text(
        "{not json", encoding="utf-8"
    )
    assert _open(FakeProbe()) == 2
    assert opened == []


def test_missing_explicit_config_is_denied(opened, monkeypatch, tmp_path):
    monkeypatch.setenv("BUGHUNT_ROUTE_CONFIG", str(tmp_path / "absent.json"))
    assert _open(FakeProbe()) == 2
    assert opened == []


def test_unexpected_backend_exception_is_denied(opened):
    _config()

    class Exploding(FakeProbe):
        def interfaces(self):
            raise RuntimeError("boom")

    assert _open(Exploding()) == 2
    assert opened == []


def test_unexpected_exception_from_verify_is_denied(opened, monkeypatch):
    _config()
    monkeypatch.setattr(
        route, "verify", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert _open(FakeProbe()) == 2
    assert opened == []


def test_none_verdict_is_denied(opened, monkeypatch):
    _config()
    monkeypatch.setattr(route, "verify", lambda *a, **k: None)
    assert _open(FakeProbe()) == 2
    assert opened == []


def test_config_locate_failure_is_denied(opened, monkeypatch):
    monkeypatch.setattr(
        route, "locate_config", lambda *a, **k: (_ for _ in ()).throw(OSError("fs"))
    )
    assert _open(FakeProbe()) == 2
    assert opened == []


def test_denial_survives_a_failing_output_stream(opened, monkeypatch):
    _config()
    monkeypatch.setattr(
        cli, "_line", lambda *a, **k: (_ for _ in ()).throw(OSError("closed"))
    )
    assert _open(FakeProbe(interfaces=(ETHERNET,))) == 2
    assert opened == []


def test_console_command_and_bare_entry_are_both_gated(opened, monkeypatch):
    _config()
    monkeypatch.setattr(
        route_probe, "default_probe", lambda *a, **k: FakeProbe(interfaces=(ETHERNET,))
    )
    assert (
        cli.dispatch(
            ["console"], scan_main=None, build_parser=None, tool_file=TOOL_FILE
        )
        == 2
    )
    assert (
        cli.dispatch(
            [], scan_main=None, build_parser=None, tool_file=TOOL_FILE, interactive=True
        )
        == 2
    )
    assert opened == []


def test_optout_env_opens_a_denied_tunnel_and_warns_on_stderr(
    opened, monkeypatch, capsys
):
    _config()
    monkeypatch.setenv("BUGHUNT_ALLOW_NO_ROUTE", "1")
    # A tunnel-down probe would normally deny with exit 2; the opt-out must still open.
    assert _open(FakeProbe(interfaces=(ETHERNET,))) == 0
    assert len(opened) == 1
    captured = capsys.readouterr()
    assert "route/VPN protection is DISABLED" in captured.err
    assert "BUGHUNT_ALLOW_NO_ROUTE" in captured.err
    assert "DISABLED" not in captured.out


def test_optout_env_bypasses_invalid_config_and_warns(opened, monkeypatch, capsys):
    (route.workspace_dir() / route.CONFIG_FILENAME).write_text(
        "{not json", encoding="utf-8"
    )
    monkeypatch.setenv("BUGHUNT_ALLOW_NO_ROUTE", "1")
    assert _open(FakeProbe()) == 0
    assert len(opened) == 1
    assert "route/VPN protection is DISABLED" in capsys.readouterr().err


def test_optout_env_not_set_to_one_leaves_the_gate_blocking(opened, monkeypatch):
    _config()
    monkeypatch.setenv("BUGHUNT_ALLOW_NO_ROUTE", "0")
    assert _open(FakeProbe(interfaces=(ETHERNET,))) == 2
    assert opened == []


def test_optout_audit_failure_blocks_console(opened, monkeypatch):
    from bughunt.core import ledger

    monkeypatch.setenv("BUGHUNT_ALLOW_NO_ROUTE", "1")
    monkeypatch.setattr(
        ledger, "_write_manifest", lambda *args: (_ for _ in ()).throw(OSError("full"))
    )
    assert _open(FakeProbe()) == 2
    assert opened == []
