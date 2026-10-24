import json

import httpx

import bughunt
from bughunt.core import route
from test_gate import boundaries, policy
from test_native_lab_adapters import assert_artifact_contract


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
