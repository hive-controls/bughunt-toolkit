import json

import httpx
import pytest

import bughunt
from bughunt.core import route
from test_gate import boundaries, policy
from test_native_lab_adapters import assert_artifact_contract


def _tree_bytes(root):
    return {
        str(path.relative_to(root)): path.read_bytes() if path.is_file() else None
        for path in root.rglob("*")
    }


def test_scope_write_previews_describe_changes_without_writes(tmp_path, monkeypatch):
    from bughunt.core import workspace

    root = tmp_path / "workspace"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    result = bughunt.run_module("scope", operation="init", dry_run=True)
    assert result.status == "planned"
    plan = result.artifacts[0].payload["items"][0]
    assert plan["workspace"] == str(root.resolve())
    assert set(plan["create"]) == {"requests", "scope.txt", "urls.txt"}
    assert not root.exists()
    assert bughunt.run_module("scope", operation="init").status == "success"
    workspace.add_entries(["existing.example"])
    before = _tree_bytes(tmp_path)
    for operation, hosts, expected in [
        (
            "add",
            ["EXISTING.example", "https://new.example/a", "new.example"],
            ["new.example"],
        ),
        ("remove", ["EXISTING.example", "missing.example"], ["existing.example"]),
    ]:
        result = bughunt.run_module(
            "scope", operation=operation, options={"hosts": hosts}, dry_run=True
        )
        assert result.status == "planned", result.to_dict()
        assert result.artifacts[0].payload["items"][0]["entries"] == expected
        assert _tree_bytes(tmp_path) == before
        actual = bughunt.run_module(
            "scope", operation=operation, options={"hosts": hosts}
        )
        assert actual.artifacts[0].payload["identifiers"] == expected
        before = _tree_bytes(tmp_path)


def test_scope_url_preview_matches_write(tmp_path, monkeypatch):
    from bughunt.core import workspace

    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "workspace"))
    workspace.add_entries(["allowed.example"])
    source = tmp_path / "urls.txt"
    source.write_text("https://allowed.example/a\nhttps://foreign.example/a\n")
    before = _tree_bytes(tmp_path)
    result = bughunt.run_module(
        "scope", operation="import-urls", options={"file": str(source)}, dry_run=True
    )
    assert result.status == "planned", result.to_dict()
    assert result.artifacts[0].payload["items"][0]["urls"] == [
        "https://allowed.example/a"
    ]
    assert _tree_bytes(tmp_path) == before
    actual = bughunt.run_module(
        "scope", operation="import-urls", options={"file": str(source)}
    )
    assert actual.artifacts[0].payload["urls"] == workspace.read_urls()


def test_policy_preview_validates_and_preserves_destination(tmp_path, monkeypatch):
    from bughunt.modules import policy as command

    root = tmp_path / "workspace"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    source = tmp_path / "profile.json"
    source.write_text(json.dumps(command.example_document()))
    for installed in (False, True):
        if installed:
            root.mkdir()
            (root / "policy.json").write_text("existing bytes")
        before = _tree_bytes(tmp_path)
        result = bughunt.run_module(
            "policy", operation="import", options={"file": str(source)}, dry_run=True
        )
        assert result.status == "planned", result.to_dict()
        plan = result.artifacts[0].payload["items"][0]
        assert plan["destination"] == str((root / "policy.json").resolve())
        assert plan["profile"]["mission"] == "owned-lab"
        assert _tree_bytes(tmp_path) == before
    source.write_text("{}")
    result = bughunt.run_module(
        "policy", operation="import", options={"file": str(source)}, dry_run=True
    )
    assert result.status == "invalid", result.to_dict()


@pytest.mark.parametrize(
    "words",
    [
        ["scope", "init", "--dry-run"],
        ["scope", "add", "allowed.example", "--dry-run"],
    ],
)
@pytest.mark.parametrize("structured", [False, True])
def test_scope_cli_preview_is_available(
    tmp_path, monkeypatch, capsys, words, structured
):
    from bughunt.core.scanner import main

    root = tmp_path / "workspace"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    assert main((["--json"] if structured else []) + words) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["status"] == "planned"
    assert not root.exists()


@pytest.mark.parametrize("structured", [False, True])
def test_policy_cli_preview(tmp_path, monkeypatch, capsys, structured):
    from bughunt.core.scanner import main
    from bughunt.modules import policy as command

    root = tmp_path / "workspace"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    source = tmp_path / "profile.json"
    source.write_text(json.dumps(command.example_document()))
    words = ["policy", "import", "--file", str(source), "--dry-run"]
    before = _tree_bytes(tmp_path)
    assert main((["--json"] if structured else []) + words) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "planned"
    assert _tree_bytes(tmp_path) == before


@pytest.mark.parametrize(
    "operation,options",
    [
        ("add", {"hosts": ["invalid host"]}),
        ("import-urls", {"file": "missing-urls.txt"}),
    ],
)
def test_invalid_scope_preview_creates_nothing(
    tmp_path, monkeypatch, operation, options
):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "workspace"))
    before = _tree_bytes(tmp_path)
    result = bughunt.run_module(
        "scope", operation=operation, options=options, dry_run=True
    )
    assert result.status == "invalid", result.to_dict()
    assert _tree_bytes(tmp_path) == before


def test_preview_flags_are_in_catalog_and_cli_help(capsys):
    from bughunt.core import adapters

    for name, operation in [
        ("scope", verb) for verb in ("init", "add", "remove", "import-urls")
    ] + [("policy", "import")]:
        parser = adapters.parser_for(name)
        with pytest.raises(SystemExit) as stopped:
            parser.parse_args([operation, "--help"])
        assert stopped.value.code == 0
        assert "--dry-run" in capsys.readouterr().out
        advertised = next(
            row
            for row in adapters.describe(name)["operations"]
            if row["id"] == operation
        )
        assert advertised["supports_dry_run"] is True


def _write_preview_values(source, destination, job_id):
    return {
        "hosts": ["allowed.example"],
        "file": str(source),
        "name": "owned",
        "kind": "owner",
        "origin": ["https://allowed.example"],
        "owned": True,
        "header": "cookie",
        "value": ["synthetic"],
        "url": "https://allowed.example/app",
        "run_id": "synthetic-run",
        "state": "complete",
        "interface": ["owned"],
        "request": str(source),
        "source_id": "synthetic-source",
        "timezone": "UTC",
        "exchange_ids": ["synthetic-exchange"],
        "exchange_id": "synthetic-exchange",
        "output": str(destination / "output.json"),
        "label": "owned",
        "text": ["note"],
        "job_id": job_id,
        "sha256": "a" * 64,
    }


def test_all_catalog_write_previews_leave_files_unchanged(policy, boundaries, tmp_path):
    import argparse
    from bughunt.console import catalog
    from bughunt.core import adapters, job, workspace

    budget = job.Budget(frozenset({("GET", "https://allowed.example/app")}), 1, 30)
    budget.activate()
    source = tmp_path / "urls.txt"
    source.write_text("https://allowed.example/app\n")
    values = _write_preview_values(source, tmp_path, budget.job_id)
    before = _tree_bytes(tmp_path)
    workspace_before = _tree_bytes(workspace.workspace_dir())
    audited = []
    for _, names in catalog.MODULE_GROUPS:
        for name in names:
            for operation in adapters.describe(name)["operations"]:
                if (
                    operation["side_effect"] != "write"
                    or not operation["supports_dry_run"]
                ):
                    continue
                verb = operation["id"]
                options = {
                    a.dest: values[a.dest]
                    for p in adapters._selected_parsers(adapters.parser_for(name), verb)
                    for a in p._actions
                    if not isinstance(a, argparse._SubParsersAction) and a.required
                }
                if name == "policy":
                    options["file"] = str(workspace.workspace_dir() / "policy.json")
                if name == "session" and verb == "set":
                    options["kind"] = "cookie"
                if name == "chroma":
                    options.update(i_understand=True, dest="preview-samples")
                result = bughunt.run_module(
                    name, operation=verb, options=options, dry_run=True
                )
                assert result.status == "planned", (name, verb, result.to_dict())
                assert _tree_bytes(tmp_path) == before, (name, verb)
                assert _tree_bytes(workspace.workspace_dir()) == workspace_before, (
                    name,
                    verb,
                )
                audited.append((name, verb))
    assert len(audited) >= 36


def test_repeater_structured_send_and_preview_preserve_source(
    policy, boundaries, monkeypatch, capsys
):
    from bughunt.core import egress, ledger

    path = policy[1] / "request.http"
    original = b"GET https://allowed.example/app HTTP/1.1\r\nHost: allowed.example\r\nCookie: private-cookie\r\n\r\n"
    path.write_bytes(original)
    options = {"request": str(path), "path": "/changed", "save_request": "edited"}
    planned = bughunt.run_module("repeater", options=options, dry_run=True)
    assert planned.status == "planned", planned.to_dict()
    assert planned.artifacts[0].kind == "observations"
    assert not (policy[1] / "requests").exists()
    real_client = egress.client
    seen = []

    def respond(request):
        seen.append(str(request.url))
        return httpx.Response(200, content=b"owned")

    monkeypatch.setattr(
        egress,
        "client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(respond), **kwargs),
    )
    result = bughunt.run_module("repeater", options=options)
    assert result.status == "success", result.to_dict()
    assert seen == ["https://allowed.example/changed"]
    assert result.artifacts[0].payload["items"][0]["attributes"]["status"] == 200
    assert result.evidence
    assert path.read_bytes() == original
    assert "private-cookie" not in json.dumps(result.to_dict())
    assert capsys.readouterr().out == ""
    assert ledger.runs_dir().exists()


def test_repeater_redirect_refusal_never_renders(
    policy, boundaries, monkeypatch, capsys
):
    from bughunt.core import egress

    path = policy[1] / "request.http"
    path.write_bytes(
        b"GET https://allowed.example/app HTTP/1.1\r\nHost: allowed.example\r\n\r\n"
    )
    real_client = egress.client
    monkeypatch.setattr(
        egress,
        "client",
        lambda **kwargs: real_client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    302,
                    headers={"Location": "https://outside.example/"},
                    content=b"stop",
                )
            ),
            **kwargs,
        ),
    )
    result = bughunt.run_module(
        "repeater", options={"request": str(path), "follow": True}
    )
    assert result.status == "blocked", result.to_dict()
    assert result.evidence
    assert capsys.readouterr().out == ""


def test_decode_local_returns_decoded_document_without_terminal_output(
    policy, boundaries, monkeypatch, capsys
):
    monkeypatch.setattr(route, "gate", lambda *_: None)
    path = policy[1] / "page.html"
    path.write_text("<p>data:text/plain;base64,b3duZWQgdGV4dA==</p>")
    result = bughunt.run_module("decode", options={"target": str(path)})
    assert result.status == "success", result.to_dict()
    document = next(item for item in result.artifacts if item.kind == "document")
    assert "owned text" in document.payload["text"]
    assert capsys.readouterr().out == ""


def test_diff_local_returns_comparison_values(policy, boundaries, monkeypatch):
    monkeypatch.setattr(route, "gate", lambda *_: None)
    left, right = policy[1] / "left.http", policy[1] / "right.http"
    left.write_bytes(b"HTTP/1.1 200 OK\r\nX-Test: before\r\n\r\nold")
    right.write_bytes(b"HTTP/1.1 404 Missing\r\nX-Test: after\r\n\r\nnew")
    result = bughunt.run_module(
        "diff", options={"left": str(left), "right": str(right)}
    )
    assert result.status == "success", result.to_dict()
    value = result.artifacts[0].payload["items"][0]["attributes"]
    assert value["left"]["status"] == "200"
    assert value["right"]["status"] == "404"
    assert value["body_equal"] is False


def test_route_init_and_status_report_actual_configuration(policy, boundaries):
    result = bughunt.run_module(
        "route", operation="init", options={"interface": ["utun"]}
    )
    assert result.status == "success", result.to_dict()
    assert result.artifacts[0].payload["changed"] is True
    assert json.loads((policy[1] / "route.json").read_text())["interfaces"] == ["utun"]
    rejected = bughunt.run_module(
        "route", operation="init", options={"interface": ["utun"]}
    )
    assert rejected.status in {"failed", "invalid"}


def test_route_preview_does_not_write_or_probe(policy, boundaries):
    result = bughunt.run_module(
        "route", operation="init", options={"interface": ["utun"]}, dry_run=True
    )
    assert result.status == "planned", result.to_dict()
    assert result.artifacts[0].payload["resource"] == "route-plan"
    assert not (policy[1] / "route.json").exists()


def test_policy_import_and_ledger_cleanup_return_mutation_effects(policy, boundaries):
    from bughunt.core import ledger
    import test_oast

    result = bughunt.run_module(
        "policy", operation="import", options={"file": str(policy[1] / "policy.json")}
    )
    assert any(item.kind == "effect" for item in result.artifacts)
    run_id = test_oast.origin_run()
    result = bughunt.run_module(
        "ledger", operation="cleanup", options={"run_id": run_id, "state": "complete"}
    )
    assert any(item.kind == "effect" for item in result.artifacts), result.to_dict()
    assert ledger.manifest_for(run_id)["cleanup"] == "complete"


def test_robots_preview_rejects_missing_input(policy, boundaries):
    result = bughunt.run_module(
        "robots", options={"inputs": [str(policy[1] / "missing.txt")]}, dry_run=True
    )
    assert result.status == "invalid", result.to_dict()


def test_forms_local_returns_fields_and_saves_drafts_without_claiming_capture(
    policy, boundaries, monkeypatch, capsys
):
    monkeypatch.setattr(route, "gate", lambda *_: None)
    path = policy[1] / "forms.html"
    path.write_text(
        '<form action="/owned" method="post"><input name="item" value="one"></form>'
    )
    result = bughunt.run_module(
        "forms",
        options={
            "inputs": [str(path)],
            "base": "https://allowed.example/page",
            "save_requests": True,
        },
    )
    assert result.status == "success", result.to_dict()
    value = result.artifacts[0].payload["items"][0]["attributes"]
    assert value["findings"][0]["name"] == "item"
    assert list((policy[1] / "requests").glob("form-*.http"))
    assert all(artifact.kind != "exchanges" for artifact in result.artifacts)
    assert capsys.readouterr().out == ""


def test_silk_preview_validates_target_and_crawl_bounds(policy, boundaries):
    result = bughunt.run_module(
        "silk", options={"url": "https://allowed.example/", "limit": 0}, dry_run=True
    )
    assert result.status == "invalid", result.to_dict()


def test_vhost_preview_uses_actual_scope_roster(policy, boundaries):
    result = bughunt.run_module(
        "vhost",
        options={
            "url": "https://allowed.example/",
            "names": ["foreign.example", "allowed.example"],
        },
        dry_run=True,
    )
    assert result.status == "planned", result.to_dict()
    value = result.artifacts[0].payload["items"][0]
    assert value["names"] == ["allowed.example"]


def test_owned_whois_query_uses_physical_dispatch(policy, monkeypatch):
    import socketserver
    import threading
    from bughunt.core import egress

    requests = []

    class Receiver(socketserver.BaseRequestHandler):
        def handle(self):
            requests.append(self.request.recv(4096))
            self.request.sendall(
                b"Registrar: Owned Registry\r\nName Server: ns.allowed.example\r\n"
            )

    admitted = []
    dispatch = egress.dispatch

    def tracked(*args, **kwargs):
        admitted.append(args[:3])
        return dispatch(*args, **kwargs)

    monkeypatch.setattr(egress, "dispatch", tracked)
    with socketserver.TCPServer(("127.0.0.1", 0), Receiver) as receiver:
        port = receiver.server_address[1]
        document, root = policy
        document["assets"].append(
            {
                "id": "owned-whois",
                "origin": f"http://127.0.0.1:{port}",
                "paths": ["/"],
                "operations": ["passive"],
                "methods": ["GET"],
            }
        )
        (root / "policy.json").write_text(json.dumps(document))
        worker = threading.Thread(target=receiver.serve_forever, daemon=True)
        worker.start()
        try:
            result = bughunt.run_module(
                "whois",
                options={
                    "name": "allowed.example",
                    "server": "127.0.0.1",
                    "port": port,
                },
            )
        finally:
            receiver.shutdown()
            worker.join(timeout=3)
    assert result.status == "success", result.to_dict()
    assert requests == [b"allowed.example\r\n"]
    assert len(admitted) == 1
    value = result.artifacts[0].payload["items"][0]["attributes"]
    assert value["record"]["registrar"] == "Owned Registry"
