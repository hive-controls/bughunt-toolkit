"""Addon structured producers retain real data without parsing CLI rendering."""

import json
import socket
from types import SimpleNamespace

import bughunt
import httpx
import pytest

from bughunt.core import adapters, addon_adapters, egress
from bughunt.core import pipeline_context
from test_gate import seed_policy

SCAN_ID = "12345678-1234-4123-8123-123456789012"


def assert_success_contract(result):
    assert result.status == "success", result.to_dict()
    assert {item.kind for item in result.artifacts} <= set(
        adapters.output_kinds(result.module_id, result.operation)
    )


SITE = {
    "uuid": SCAN_ID,
    "domain": "allowed.example",
    "url": "https://allowed.example/item",
    "score": 75,
    "company": "Fixture",
    "country": "US",
    "first_seen": "2026-10-22T00:00:00Z",
}
INDICATOR = {
    "date": "2026-10-22 00:00:00",
    "type": "domain",
    "value": "allowed.example",
    "tags": ["fixture"],
}


def intelligence_response(request):
    host, path = request.url.host, request.url.path
    if host == "crt.name":
        return httpx.Response(200, text="allowed.example 2026-10-01\n")
    if host == "phishunt.io":
        if path == "/feed.json":
            return httpx.Response(200, json=[SITE])
        if "blocklist" in path or path.endswith((".csv", ".txt")):
            return httpx.Response(200, text="allowed.example\n")
        return httpx.Response(
            200, json={"results": [SITE], "count": 1, "total": 1, "marker": "fixture"}
        )
    if host == "api.tweetfeed.live":
        if path.endswith(".txt"):
            return httpx.Response(200, text="allowed.example\n")
        if path.startswith(("/v1/today", "/v1/since")):
            return httpx.Response(200, json=[INDICATOR])
        return httpx.Response(
            200, json={"found": True, "records": [INDICATOR], "marker": "fixture"}
        )
    if host == "urlscan.io":
        if path.startswith("/screenshots"):
            return httpx.Response(200, content=b"fixture-png")
        if path.startswith("/dom"):
            return httpx.Response(200, text="<title>fixture</title>")
        return httpx.Response(
            200,
            json={"uuid": SCAN_ID, "results": [{"page": SITE}], "marker": "fixture"},
        )
    if "download" in path:
        return httpx.Response(200, content=b"PK" + b"fixture" * 100)
    if host in {"feodotracker.abuse.ch", "sslbl.abuse.ch"} or path.endswith(
        (".txt", ".csv")
    ):
        return httpx.Response(200, text="203.0.113.10,fixture\n")
    if host.endswith("abuse.ch"):
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "urls": [SITE],
                "payloads": [SITE],
                "data": [SITE],
            },
        )
    return httpx.Response(200, text="fixture response")


@pytest.fixture
def addon_wire(monkeypatch, tmp_path):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    (tmp_path / "scope.txt").write_text("allowed.example\n")
    policy = seed_policy(tmp_path)
    policy["assets"].append(
        {**policy["assets"][0], "id": "sslbl", "origin": "https://sslbl.abuse.ch"}
    )
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    seen = []

    def respond(request):
        seen.append(request)
        return intelligence_response(request)

    transport = httpx.MockTransport(respond)
    original_client, original_async = egress.client, egress.async_client
    monkeypatch.setattr(
        egress,
        "client",
        lambda **kwargs: original_client(**{**kwargs, "transport": transport}),
    )
    monkeypatch.setattr(
        egress,
        "async_client",
        lambda **kwargs: original_async(**{**kwargs, "transport": transport}),
    )
    monkeypatch.setattr(addon_adapters.load_addon("chroma"), "HTTP", None)

    def forbidden(*args, **kwargs):
        raise AssertionError("Real network boundary reached")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    return seen


PHISH_CASES = [
    ("about", {}),
    ("pulse", {}),
    ("hunt", {}),
    ("search", {"query": "fixture"}),
    ("analyze", {"url": "https://allowed.example/", "yes": True}),
    (
        "deep",
        {"url": "https://allowed.example/", "yes": True, "token": "fixture-secret"},
    ),
    ("campaigns", {}),
    ("campaign", {"key": "fixture"}),
    ("related", {"uuid": SCAN_ID}),
    ("enrich", {"uuid": SCAN_ID}),
    ("brand", {"slug": "fixture"}),
    ("cert", {"name": "fixture"}),
    ("feed", {"kind": "json"}),
    ("blocklist", {"kind": "domains"}),
    ("pivot", {"field": "country", "min_count": 1}),
    ("triage", {}),
    ("inspect", {"uuid": SCAN_ID}),
    ("match", {}),
    ("watch", {"polls": 1}),
    ("snapshot", {}),
    ("diff", {}),
    ("report", {}),
    ("self-test", {}),
]


@pytest.mark.parametrize("operation,options", PHISH_CASES)
def test_every_phish_operation_returns_domain_data(
    addon_wire, tmp_path, capsys, operation, options
):
    selected = {**options, "fresh": True}
    if operation == "match":
        source = tmp_path / "indicators.txt"
        source.write_text("allowed.example\n")
        selected["file"] = str(source)
    if operation == "diff":
        source = tmp_path / "before.json"
        source.write_text("[]")
        selected["snapshot"] = str(source)
    if operation == "snapshot":
        selected["out"] = str(tmp_path / "snapshot.json")
    result = bughunt.run_module("phish", operation=operation, options=selected)
    assert_success_contract(result)
    records = result.artifacts[0].payload["records"]
    assert records
    if operation == "match":
        assert records[0]["hit_indicators"] == 1
    if operation == "pivot":
        assert records[0]["value"] == "US" and records[0]["count"] == 1
    if operation == "diff":
        assert records[0]["added"] == 1
    assert str(tmp_path) not in json.dumps(result.to_dict())
    assert "fixture-secret" not in json.dumps(result.to_dict())
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "operation,options",
    [
        ("feed", {}),
        ("lookup", {"value": "allowed.example"}),
        ("campaigns", {}),
        ("trends", {}),
        ("counts", {}),
        ("status", {}),
        ("watch", {"polls": 1}),
        ("blocklist", {"kind": "domains"}),
    ],
)
def test_every_ioc_operation_returns_data(addon_wire, capsys, operation, options):
    result = bughunt.run_module("ioc", operation=operation, options=options)
    assert_success_contract(result)
    records = result.artifacts[0].payload["records"]
    assert records
    if operation == "feed":
        assert records[0]["value"] == "allowed.example"
    if operation == "watch":
        assert records[0]["records"][0]["value"] == "allowed.example"
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "operation,options",
    [
        ("search", {"query": ["allowed.example"]}),
        ("scan", {"url": "https://allowed.example/", "yes": True}),
        ("result", {"uuid": SCAN_ID}),
        ("screenshot", {"uuid": SCAN_ID}),
        ("dom", {"uuid": SCAN_ID}),
        ("quotas", {}),
        ("whoami", {}),
        ("fields", {}),
    ],
)
def test_every_urlscan_operation_returns_data(
    addon_wire, tmp_path, capsys, operation, options
):
    selected = {"api_key": "fixture-key", **options}
    if operation == "screenshot":
        selected["output"] = str(tmp_path / "screen.png")
    result = bughunt.run_module("urlscan", operation=operation, options=selected)
    assert_success_contract(result)
    records = result.artifacts[0].payload["records"]
    assert records
    if operation == "dom":
        assert records[0]["dom"] == "<title>fixture</title>"
    if operation == "screenshot":
        assert (tmp_path / "screen.png").read_bytes() == b"fixture-png"
        assert records[0]["bytes"] == 11
    assert str(tmp_path) not in json.dumps(result.to_dict())
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "operation,options",
    [
        ("hunt", {"indicator": "allowed.example"}),
        ("url", {"value": "https://allowed.example/"}),
        ("host", {"value": "allowed.example"}),
        ("hash", {"value": "a" * 64}),
        ("recent", {}),
        ("payloads", {}),
        ("tag", {"value": "fixture"}),
        ("family", {"value": "fixture"}),
        ("iocs", {}),
        ("fox", {"value": "allowed.example"}),
        ("bazaar", {}),
        ("feodo", {}),
        ("sslbl", {}),
        ("watch", {"polls": 1}),
        ("download", {"sha256": "a" * 64, "i_understand": True}),
    ],
)
def test_every_chroma_one_shot_returns_data(
    addon_wire, tmp_path, capsys, operation, options
):
    result = bughunt.run_module(
        "chroma", operation=operation, options={"key": "fixture-key", **options}
    )
    assert_success_contract(result)
    records = result.artifacts[0].payload["records"]
    assert records
    if operation in {"hash", "family"}:
        assert len(records) == 3
    if operation == "recent":
        assert records[0]["payload"]["urls"][0]["domain"] == "allowed.example"
    assert str(tmp_path) not in json.dumps(result.to_dict())
    assert capsys.readouterr().out == ""


def test_carve_api_returns_extracted_links_without_printing(tmp_path, capsys):
    source = tmp_path / "owned.html"
    source.write_text('<a href="https://owned.example/item">owned</a>')
    result = bughunt.run_module("carve", options={"inputs": [str(source)]})
    assert_success_contract(result)
    assert "https://owned.example/item" in json.dumps(result.to_dict())
    assert str(tmp_path) not in json.dumps(result.to_dict())
    assert capsys.readouterr().out == ""


def test_pulse_preview_reads_and_validates_inputs_without_writing(tmp_path, capsys):
    source = tmp_path / "urls.txt"
    source.write_text("https://owned.example/\n")
    destination = tmp_path / "result.json"
    result = bughunt.run_module(
        "pulse",
        options={"file": str(source), "json_out": str(destination)},
        dry_run=True,
    )
    assert result.status == "planned", result.to_dict()
    assert result.artifacts[0].payload["items"][0]["input_count"] == 1
    assert not destination.exists()
    assert capsys.readouterr().out == ""


def test_pulse_explicit_urls_produce_handoff_and_wire_metrics(addon_wire, capsys):
    result = bughunt.run_module(
        "pulse", options={"urls": ["https://allowed.example/item"]}
    )
    assert_success_contract(result)
    assert next(item for item in result.artifacts if item.kind == "urls").payload == {
        "urls": ["https://allowed.example/item"]
    }
    assert len(addon_wire) == 1
    assert result.artifacts[0].payload["records"][0]["status"] == 200
    assert capsys.readouterr().out == ""


def test_ct_produces_real_hosts_and_probed_urls(addon_wire, capsys):
    result = bughunt.run_module(
        "ct", options={"domain": "allowed.example", "check": True, "dates": True}
    )
    assert_success_contract(result)
    assert next(item for item in result.artifacts if item.kind == "hosts").payload == {
        "hosts": ["allowed.example"]
    }
    assert next(item for item in result.artifacts if item.kind == "urls").payload == {
        "urls": ["https://allowed.example"]
    }
    assert result.artifacts[0].payload["records"][0]["dates"] == {
        "allowed.example": ["2026-10-01"]
    }
    assert len(addon_wire) == 2
    assert capsys.readouterr().out == ""


def test_skiff_produces_classified_outcomes(addon_wire, tmp_path, capsys):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("item\n")
    result = bughunt.run_module(
        "skiff",
        options={"url": "https://allowed.example/FUZZ", "wordlist": str(wordlist)},
    )
    assert_success_contract(result)
    envelope = result.artifacts[0].payload["records"][0]
    assert envelope["run"]["requests_sent"] == 1
    assert envelope["outcomes"][0]["status"] == 200
    assert str(tmp_path) not in json.dumps(result.to_dict())
    assert capsys.readouterr().out == ""


def test_tcurl_returns_body_document_and_recorded_runs(
    addon_wire, monkeypatch, tmp_path, capsys
):
    module = addon_adapters.load_addon("tcurl")
    policy = json.loads((tmp_path / "policy.json").read_text())
    policy["assets"].append(
        {**policy["assets"][0], "id": "socks", "origin": "http://127.0.0.1:9050"}
    )
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    monkeypatch.setattr(
        module,
        "open_client",
        lambda plan, operation, options, **kwargs: egress.client(operation=operation),
    )
    result = bughunt.run_module(
        "tcurl", options={"url": "https://allowed.example/item", "no_exit_check": True}
    )
    assert_success_contract(result)
    assert (
        next(item for item in result.artifacts if item.kind == "document").payload[
            "text"
        ]
        == "fixture response"
    )
    runs = next(item for item in result.artifacts if item.kind == "runs").payload[
        "run_ids"
    ]
    assert runs and set(runs) == {item["run_id"] for item in result.evidence}
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "name,operation,options",
    [
        ("pulse", None, {"urls": ["https://allowed.example/"]}),
        ("ct", None, {"domain": "allowed.example", "check": True}),
        ("phish", "snapshot", {}),
        ("ioc", "watch", {"polls": 2}),
        ("chroma", "download", {"sha256": "a" * 64, "i_understand": True}),
        ("urlscan", "screenshot", {"uuid": SCAN_ID}),
    ],
)
def test_preview_sends_and_writes_nothing(
    addon_wire, tmp_path, capsys, name, operation, options
):
    before = {str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")}
    result = bughunt.run_module(
        name, operation=operation, options=options, dry_run=True
    )
    assert result.status == "planned", result.to_dict()
    assert not addon_wire
    assert {str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")} == before
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "name,operation,options",
    [
        ("phish", "search", {"query": "fixture"}),
        ("ioc", "lookup", {"value": "allowed.example"}),
        ("chroma", "host", {"value": "allowed.example", "key": "fixture-key"}),
        ("urlscan", "search", {"query": ["allowed.example"]}),
    ],
)
def test_provider_policy_denial_is_blocked_without_dispatch(
    addon_wire, tmp_path, name, operation, options
):
    policy = json.loads((tmp_path / "policy.json").read_text())
    policy["permissions"]["passive"] = False
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    result = bughunt.run_module(name, operation=operation, options=options)
    assert result.status == "blocked", result.to_dict()
    assert not addon_wire


@pytest.mark.parametrize("name", ["ioc", "phish", "chroma"])
def test_watch_wait_observes_pipeline_stop_in_short_slices(monkeypatch, name):
    module = addon_adapters.load_addon(name)
    state = {"stopped": False, "sleeps": [], "polls": 0}

    def check():
        if state["stopped"]:
            raise egress.PolicyBlocked("pipeline-cancelled")

    def sleep(duration):
        state["sleeps"].append(duration)
        state["stopped"] = True

    def poll(*args, **kwargs):
        state["polls"] += 1
        if name == "ioc":
            return "2026-10-22T00:00:00Z", []
        return ([], "2026-10-22T00:00:00Z") if name == "phish" else {"records": []}

    monkeypatch.setattr(
        pipeline_context, "current", lambda: SimpleNamespace(check=check)
    )
    monkeypatch.setattr(module.time, "sleep", sleep)
    args = adapters.parse_options(name, "watch", {"polls": 2})
    if name == "ioc":
        monkeypatch.setattr(module, "_poll_once", poll)
        call = lambda: module.cmd_watch(args, structured=True)
    elif name == "phish":
        args.structured = True
        monkeypatch.setattr(module, "new_client", lambda args: None)
        monkeypatch.setattr(module, "poll_new", poll)
        call = lambda: module.cmd_watch(args)
    else:
        monkeypatch.setattr(module, "_watch_poll", poll)
        settings = module.Settings("fixture", structured=True)
        call = lambda: module.run_watch(settings, 30, 10, 2)
    with pytest.raises(egress.PolicyBlocked, match="pipeline-cancelled"):
        call()
    assert state["polls"] == 1
    assert state["sleeps"] and max(state["sleeps"]) <= 0.05


def test_structured_pipeline_phish_feed_bypasses_cache(monkeypatch):
    module = addon_adapters.load_addon("phish")
    accesses = []
    monkeypatch.setattr(pipeline_context, "current", lambda: object())
    monkeypatch.setattr(
        module, "read_cache", lambda: accesses.append("read") or ([{"old": True}], 1)
    )
    monkeypatch.setattr(module, "write_cache", lambda rows: accesses.append("write"))
    monkeypatch.setattr(module, "fetch_feed", lambda client: [SITE])
    args = SimpleNamespace(timeout=30, verbose=False, structured=True)
    rows = module.load_feed(module.new_client(args))
    assert rows == [SITE]
    assert accesses == []


@pytest.mark.parametrize("name", ["ioc", "phish", "chroma"])
def test_unbounded_watches_refused_before_dispatch(addon_wire, capsys, name):
    result = bughunt.run_module(name, operation="watch")
    assert result.status == "invalid", result.to_dict()
    assert not addon_wire
    assert capsys.readouterr().out == ""


def test_chroma_repl_lists_one_shot_equivalents(addon_wire):
    result = bughunt.run_module("chroma", operation="repl")
    assert result.status == "unsupported"
    assert (
        "hunt" in result.errors[0]["message"]
        and "download" in result.errors[0]["message"]
    )
    assert not addon_wire


@pytest.mark.parametrize(
    "name,operation,options",
    [
        ("urlscan", "scan", {"url": "https://allowed.example/"}),
        ("phish", "analyze", {"url": "https://allowed.example/"}),
        ("chroma", "download", {"sha256": "a" * 64}),
    ],
)
def test_disclosure_and_sample_consent_never_prompt(
    addon_wire, monkeypatch, name, operation, options
):
    monkeypatch.setattr(
        "builtins.input", lambda *args: pytest.fail("embedding prompted")
    )
    result = bughunt.run_module(name, operation=operation, options=options)
    assert result.status == "invalid"
    assert not addon_wire
