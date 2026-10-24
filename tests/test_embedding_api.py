import pytest


@pytest.mark.parametrize(
    "name,operation,options",
    [
        ("oast", "show", {"run_id": "owned"}),
        ("zap", "status", {"job_id": "owned"}),
        ("race", "cancel", {"job_id": "owned"}),
        ("desync", "status", {"job_id": "owned"}),
        ("ws", "show", {"run_id": "owned"}),
    ],
)
def test_local_lab_controls_do_not_probe_external_routes(
    name, operation, options, monkeypatch
):
    from argparse import Namespace
    from bughunt.core import api, route
    from bughunt.core.results import ExecutionContext

    monkeypatch.setattr(
        route, "gate", lambda *_: pytest.fail("local action probed route")
    )
    monkeypatch.setattr(route, "optout_requested", lambda: False)
    assert (
        api._route_check(name, operation, Namespace(**options), ExecutionContext())
        == []
    )


def test_library_local_result_and_invalid_input_do_not_print(
    capsys, monkeypatch, tmp_path
):
    import bughunt

    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    result = bughunt.run_module("scope", operation="list")
    assert result.status == "success"
    assert result.artifacts[0].kind == "inventory"
    invalid = bughunt.run_module("dns", options={"made_up": "value"})
    assert invalid.status == "invalid"
    assert capsys.readouterr().out == ""


def test_option_conversion_preserves_argparse_types_and_required_fields():
    from bughunt.core.adapters import parse_options

    args = parse_options(
        "discover",
        "default",
        {"exchange_id": "a" * 64, "requests": 7, "header": ["X-Test"]},
    )
    assert args.requests == 7
    assert args.header == ["X-Test"]
    with pytest.raises(ValueError):
        parse_options(
            "discover", "default", {"exchange_id": "a" * 64, "requests": True}
        )
    with pytest.raises(ValueError):
        parse_options("exchange", "import-raw", {"request": "test.http"})


def test_unknown_module_never_falls_back_to_scanner():
    import bughunt

    result = bughunt.run_module("does-not-exist", options={})
    assert result.status == "invalid"
    assert result.exit_code == 2


def test_typed_positional_values_are_never_reinterpreted_as_options():
    from bughunt.core.adapters import parse_options

    assert parse_options("dns", "default", {"name": "--help"}).name == "--help"
    assert parse_options("dns", "default", {"name": "--resolver"}).name == "--resolver"


def test_result_finalization_failure_stays_inside_public_contract(monkeypatch):
    import bughunt
    from bughunt.core import adapters
    from bughunt.core.results import ModuleOutput

    monkeypatch.setattr(
        adapters, "execute", lambda *args: ModuleOutput(run_ids=["not-a-run-id"])
    )
    result = bughunt.run_module("scope", operation="list")
    assert result.status == "failed"
    assert result.errors[0]["code"] == "invalid_producer_result"


def test_embedding_does_not_replace_process_output_streams(monkeypatch):
    import sys
    import bughunt
    from bughunt.console import ui
    from bughunt.core import adapters
    from bughunt.core.results import ModuleOutput

    streams = sys.stdout, sys.stderr, ui.console._file

    def producer(*args):
        assert (sys.stdout, sys.stderr, ui.console._file) == streams
        return ModuleOutput()

    monkeypatch.setattr(adapters, "execute", producer)
    assert bughunt.run_module("scope", operation="list").status == "success"


def test_explicit_dry_run_cannot_be_overridden_by_context(monkeypatch):
    import bughunt
    from bughunt.core import adapters
    from bughunt.core.results import ExecutionContext, ModuleOutput

    observed = []

    def producer(name, operation, args, context):
        observed.append(context.dry_run)
        return ModuleOutput(status="planned" if context.dry_run else "success")

    monkeypatch.setattr(adapters, "execute", producer)
    result = bughunt.run_module(
        "scope", operation="list", dry_run=True, context=ExecutionContext(dry_run=False)
    )
    assert observed == [True]
    assert result.status == "planned"


def test_embedding_rechecks_configured_route_without_bypassing_optout_audit(
    monkeypatch,
):
    import bughunt
    from bughunt.core import adapters, route
    from bughunt.core.results import ModuleOutput

    monkeypatch.setattr(
        route, "gate", lambda *args, **kwargs: route.Verdict(False, "blocked", ())
    )
    monkeypatch.setattr(
        adapters, "execute", lambda *args: pytest.fail("blocked route reached producer")
    )
    result = bughunt.run_module("dns", options={"name": "app.example.test"})
    assert result.status == "blocked"


@pytest.fixture
def owned_receiver():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"owned")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _configured_route(monkeypatch, tmp_path, *, tunnel_up):
    import json
    from bughunt.core import route, route_probe

    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    monkeypatch.delenv(route.ENV_CONFIG, raising=False)
    monkeypatch.delenv(route.ENV_ALLOW_NO_ROUTE, raising=False)
    (tmp_path / "route.json").write_text(
        json.dumps({"schema_version": 1, "interfaces": ["owned-tunnel"]})
    )
    probes = []

    class Probe:
        def interfaces(self):
            probes.append("interfaces")
            return (
                [route_probe.Interface(5, "owned-tunnel", "owned fixture", True)]
                if tunnel_up
                else []
            )

        def egress_indexes(self, address):
            probes.append(address)
            return {5}

    monkeypatch.setattr(route_probe, "default_probe", Probe)
    return probes


def _receiver_producer(url):
    from urllib.request import urlopen
    from bughunt.core.results import ModuleOutput

    def execute(name, operation, args, context):
        if context.dry_run:
            return ModuleOutput(status="planned")
        with urlopen(url, timeout=2) as response:
            assert response.read() == b"owned"
        return ModuleOutput()

    return execute


def test_configured_route_probe_controls_owned_receiver_admission(
    monkeypatch, tmp_path, owned_receiver
):
    import bughunt
    from bughunt.core import adapters

    url, hits = owned_receiver
    probes = _configured_route(monkeypatch, tmp_path, tunnel_up=False)
    monkeypatch.setattr(adapters, "execute", _receiver_producer(url))
    assert bughunt.run_module("dns", options={"name": "localhost"}).status == "blocked"
    assert probes == ["interfaces"] and hits == []
    probes = _configured_route(monkeypatch, tmp_path, tunnel_up=True)
    assert bughunt.run_module("dns", options={"name": "localhost"}).status == "success"
    assert probes and hits == ["/"]


@pytest.mark.parametrize(
    "name,operation,options,explicit",
    [
        ("dns", None, {"name": "localhost"}, True),
        ("discover", None, {"exchange_id": "a" * 64, "dry_run": True}, False),
        ("repeater", None, {"request": "owned.http", "preview": True}, False),
        (
            "engine",
            "dry-run",
            {
                "profile_id": "zap-passive",
                "exchange_id": ["a" * 64],
                "mission": "owned",
            },
            False,
        ),
    ],
)
def test_dry_run_and_preview_never_invoke_route_probe_or_receiver(
    name, operation, options, explicit, monkeypatch, tmp_path, owned_receiver
):
    import bughunt
    from bughunt.core import adapters

    url, hits = owned_receiver
    probes = _configured_route(monkeypatch, tmp_path, tunnel_up=False)
    monkeypatch.setattr(adapters, "execute", _receiver_producer(url))
    result = bughunt.run_module(
        name, operation=operation, options=options, dry_run=explicit
    )
    assert result.status == "planned"
    assert result.dry_run is True
    assert probes == [] and hits == []


def test_optout_audit_failure_prevents_owned_receiver_send(
    monkeypatch, tmp_path, owned_receiver
):
    import bughunt
    from bughunt.core import adapters, ledger, route

    url, hits = owned_receiver
    probes = _configured_route(monkeypatch, tmp_path, tunnel_up=False)
    monkeypatch.setenv(route.ENV_ALLOW_NO_ROUTE, "1")
    monkeypatch.setattr(adapters, "execute", _receiver_producer(url))

    def audit_failed(point):
        raise OSError("owned persistence failure")

    monkeypatch.setattr(ledger, "record_route_optout", audit_failed)
    assert bughunt.run_module("dns", options={"name": "localhost"}).status == "blocked"
    assert probes == [] and hits == []
