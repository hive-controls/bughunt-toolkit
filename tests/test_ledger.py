"""Secret-presence, provenance and evidence-integrity fixtures."""

import asyncio
import hashlib
import io
import json

import httpx
import pytest

from bughunt.core import egress, exchange, ledger
from bughunt.modules import ledger as command, session, snare
from bughunt.core.session import write_session
from test_gate import policy


@pytest.mark.parametrize("point", ["console", "proxy_scan", "tooling_launcher"])
def test_route_optout_is_metadata_only_and_uses_current_workspace(
    monkeypatch, tmp_path, capsys, point
):
    for name in ("one", "two"):
        monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / name))
        run_id = ledger.record_route_optout(point)
        manifest = ledger.manifest_for(run_id)
        assert manifest["route_gate"] == {
            "point": point,
            "disabled_by": "BUGHUNT_ALLOW_NO_ROUTE=1",
        }
        assert manifest["decision"] == "operator-optout"
        assert manifest["request"] is None and manifest["response"] is None
        assert not (ledger.runs_dir() / run_id / "request.http").exists()
        assert ledger.export_run(run_id)["captures"] == {}
        for arguments in (["list"], ["show", run_id], ["export", run_id]):
            assert command.main(arguments) == 0
            assert run_id in capsys.readouterr().out


def test_route_optout_uses_default_workspace(monkeypatch, tmp_path):
    monkeypatch.delenv("BUGHUNT_SCOPE", raising=False)
    monkeypatch.chdir(tmp_path)
    run_id = ledger.record_route_optout("console")
    assert (tmp_path / ".bughunt" / "runs" / run_id / "manifest.json").is_file()


def test_http_capture_private_originals_and_sanitized_round_trip(policy):
    _, path = policy
    (path / "redaction.json").write_text(
        json.dumps({"patterns": ["custom-value"]}), encoding="utf-8"
    )

    def respond(request):
        return httpx.Response(
            200,
            headers={"Set-Cookie": "session=server-secret"},
            content=b"custom-value\n-----BEGIN "
            + b"PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----",
        )

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        client.post(
            "https://allowed.example/?token=query-secret",
            headers={
                "Cookie": "session=cookie-secret",
                "Authorization": "Bearer auth-secret",
                "Proxy-Authorization": "Basic proxy-secret",
            },
            content=b"custom-value",
        )
    manifest = json.loads(next(ledger.runs_dir().glob("*/manifest.json")).read_text())
    assert manifest["policy_version"] == "1" and manifest["actor"] == "default"
    assert (
        manifest["operation"] == "manual"
        and manifest["classification"] == "observation"
    )
    assert manifest["cleanup"] == "pending" and manifest["environment"]["python"]
    assert (
        manifest["policy_source"] and manifest["started_at"] and manifest["finished_at"]
    )
    raw_request = (ledger.runs_dir() / manifest["run_id"] / "request.http").read_bytes()
    assert b"cookie-secret" in raw_request
    assert hashlib.sha256(raw_request).hexdigest() == manifest["request"]["sha256"]
    exported = ledger.export_run(manifest["run_id"])
    text = json.dumps(exported)
    for secret in (
        "cookie-secret",
        "auth-secret",
        "proxy-secret",
        "query-secret",
        "server-secret",
        "custom-value",
        "key-material",
    ):
        assert secret not in text
    assert (
        exported["captures"]["request"]["original_sha256"]
        == manifest["request"]["sha256"]
    )
    assert exported["manifest"]["run_id"] == manifest["run_id"]


def test_new_runs_have_distinct_stable_ids(policy):
    with egress.client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"ok"))
    ) as client:
        client.get("https://allowed.example/")
        client.get("https://allowed.example/")
    ids = [path.parent.name for path in ledger.runs_dir().glob("*/manifest.json")]
    assert len(ids) == len(set(ids)) == 2
    assert ledger.manifest_for(ids[0])["run_id"] == ids[0]


@pytest.mark.parametrize("register_provider", [False, True])
def test_private_writer_preserves_foreign_manifest_bytes(
    policy, tmp_path, register_provider
):
    secret = "provider-manifest-key"
    if register_provider:
        ledger.remember_secret(secret, redact_at_rest=True)
    payload = b'{"url":"https://allowed.example/?key=provider-manifest-key"}\n'
    path = tmp_path / "foreign" / "manifest.json"
    ledger._write_private(path, payload)
    assert path.read_bytes() == payload


@pytest.mark.parametrize("target", [b"/?", b"/raw/\xff?"])
def test_private_capture_without_provider_secrets_preserves_request_bytes(
    policy, target
):
    request = b"GET " + target + b" HTTP/1.1\r\nHost: allowed.example\r\n\r\n"
    capture = ledger.begin(
        egress.current_profile(),
        tool="fixture",
        operation="manual",
        target="https://allowed.example/",
        request=request,
    )
    assert (capture.root / "request.http").read_bytes() == request


@pytest.mark.parametrize(
    "secret", ["provider-transport-secret-42", 'provider-sensitive/?+"']
)
def test_provider_secret_is_sent_but_omitted_from_persisted_evidence(policy, secret):
    ledger.remember_secret(secret, redact_at_rest=True)

    def respond(request):
        assert request.headers["Auth-Key"] == secret
        return httpx.Response(200, content=("echo " + secret).encode())

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        client.get(
            "https://allowed.example/",
            params={"key": secret},
            headers={"Auth-Key": secret},
        )
    manifest = json.loads(next(ledger.runs_dir().glob("*/manifest.json")).read_text())
    assert secret not in json.dumps(manifest)
    assert "[REDACTED]" in manifest["target"]
    for kind in ("request", "response"):
        evidence = manifest[kind]
        stored = (
            ledger.runs_dir() / manifest["run_id"] / evidence["path"]
        ).read_bytes()
        assert secret.encode() not in stored and b"[REDACTED]" in stored
        assert evidence["sanitized_at_rest"] is True
        assert evidence["size"] == len(stored)
        assert evidence["sha256"] == hashlib.sha256(stored).hexdigest()
    imported = exchange.from_run(manifest["run_id"])
    assert secret not in exchange.decode(imported["request"]["raw_b64"]).decode()


@pytest.mark.parametrize(
    "secret", ['provider-quoted"credential', "provider\\credential", "provider-\u00e9"]
)
@pytest.mark.parametrize("ensure_ascii", [True, False])
def test_provider_json_echo_is_sanitized_before_persistence(
    policy, secret, ensure_ascii
):
    ledger.remember_secret(secret, redact_at_rest=True)
    payload = json.dumps({"echo": secret}, ensure_ascii=ensure_ascii).encode()
    with egress.client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=payload))
    ) as client:
        client.get("https://allowed.example/")
    response = next(ledger.runs_dir().glob("*/response.http")).read_bytes()
    body = response.partition(b"\r\n\r\n")[2]
    assert json.loads(body)["echo"] == "[REDACTED]"


def test_provider_secret_persistence_registration_is_workspace_scoped(
    policy, monkeypatch, tmp_path
):
    secret = "workspace-provider-secret-42"
    ledger.remember_secret(secret, redact_at_rest=True)
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "other-mission"))
    evidence = ledger._evidence(
        tmp_path / "other-mission" / "response.http", secret.encode(), False
    )
    assert (
        tmp_path / "other-mission" / "response.http"
    ).read_bytes() == secret.encode()
    assert "sanitized_at_rest" not in evidence


@pytest.mark.parametrize(
    "secret",
    ["request", "manual", "logical-http", "GET", "k", "HTTP", "200", "allowed.example"],
)
def test_provider_secret_redaction_preserves_manifest_structure(policy, secret):
    ledger.remember_secret(secret, redact_at_rest=True)
    with egress.client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"ok"))
    ) as client:
        client.get(
            "https://allowed.example/",
            params={"key": secret},
            headers={"Auth-Key": secret},
        )
    manifest_path = next(ledger.runs_dir().glob("*/manifest.json"))
    manifest = json.loads(manifest_path.read_text())
    assert manifest["run_id"] == manifest_path.parent.name
    assert manifest["request"]["path"] == "request.http"
    assert manifest["operation"] == "manual"
    assert manifest["representation"] == "logical-http; not a wire-byte claim"
    assert "[REDACTED]" in manifest["target"]
    record = exchange.from_run(manifest["run_id"])
    request = exchange.decode(record["request"]["raw_b64"])
    assert b"auth-key: [REDACTED]" in request


def test_tampered_evidence_cannot_export(policy):
    capture = ledger.begin(
        egress.current_profile(),
        tool="fixture",
        operation="manual",
        target="https://allowed.example/",
        request=b"GET / HTTP/1.1\r\n\r\n",
    )
    capture.finish()
    (capture.root / "request.http").write_bytes(b"altered")
    with pytest.raises(ValueError, match="hash"):
        ledger.export_run(capture.manifest["run_id"])


def test_cap_and_partial_stream_are_explicit(policy):
    with egress.client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200, stream=httpx.ByteStream(b"x" * (ledger.CAPTURE_LIMIT + 1))
            )
        )
    ) as client:
        client.get("https://allowed.example/")
    manifest = json.loads(next(ledger.runs_dir().glob("*/manifest.json")).read_text())
    assert manifest["response"]["truncated"]
    assert manifest["response"]["size"] < ledger.CAPTURE_LIMIT + 100


def test_unread_response_is_marked_incomplete(policy):
    with egress.client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, stream=httpx.ByteStream(b"unread"))
        )
    ) as client:
        response = client.send(
            client.build_request("GET", "https://allowed.example/"), stream=True
        )
        response.close()
    manifest = json.loads(next(ledger.runs_dir().glob("*/manifest.json")).read_text())
    assert manifest["response"]["truncated"]


def test_failure_is_invalid_and_does_not_leak_error_secret(policy):
    def fail(_):
        raise httpx.ConnectError("Authorization: exception-secret")

    with egress.client(transport=httpx.MockTransport(fail)) as client:
        with pytest.raises(httpx.ConnectError):
            client.get("https://allowed.example/")
    manifest = json.loads(next(ledger.runs_dir().glob("*/manifest.json")).read_text())
    assert (
        manifest["classification"] == "invalid" and manifest["error"] == "ConnectError"
    )


def test_session_show_does_not_display_credentials(policy, capsys):
    write_session(
        {"cookie": "session=cookie-secret", "authorization": "Bearer auth-secret"}
    )
    assert session.main(["show"]) == 0
    output = capsys.readouterr().out
    assert "cookie-secret" not in output and "auth-secret" not in output
    assert output.count("[REDACTED]") == 2


def test_console_writer_redacts_split_lines_and_private_key_blocks(policy):
    output = io.StringIO()
    writer = ledger._Output(output)
    writer.write("Author")
    writer.write("ization: Bearer secret-value\n")
    writer.write(
        "-----BEGIN " + "PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----\n"
    )
    writer.flush()
    assert (
        "secret-value" not in output.getvalue()
        and "key-material" not in output.getvalue()
    )


@pytest.mark.parametrize(
    "text",
    [
        "http://user:proxy-secret@proxy.example/",
        "Authorization: Bearer auth-secret",
        '{"Authorization": "auth-secret"}',
        "?api_key=query-secret&safe=1",
    ],
)
def test_redaction_secrets_and_json_are_safe(policy, text):
    sanitized = ledger.redact_text(text)
    assert "secret" not in sanitized
    if text.startswith("{"):
        assert json.loads(sanitized)["Authorization"] == "[REDACTED]"


@pytest.mark.parametrize(
    "label",
    ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"],
)
@pytest.mark.parametrize("complete", [False, True])
def test_private_key_redaction_handles_incomplete_blocks(policy, label, complete):
    text = f"prefix\n-----BEGIN {label}-----\nMIIE-OWNED-SYNTHETIC-KEY-MATERIAL\n"
    if complete:
        text += f"-----END {label}-----\nsafe suffix"
    sanitized = ledger.redact_text(text)
    assert "SYNTHETIC-KEY-MATERIAL" not in sanitized
    assert sanitized == "prefix\n[REDACTED PRIVATE KEY]" + (
        "\nsafe suffix" if complete else ""
    )


def test_cleanup_cli_and_export_are_sanitized(policy, capsys):
    capture = ledger.begin(
        egress.current_profile(),
        tool="fixture",
        operation="manual",
        target="https://allowed.example/",
        request=b"Authorization: Bearer secret\r\n",
    )
    capture.finish()
    run_id = capture.manifest["run_id"]
    assert command.main(["cleanup", run_id, "complete"]) == 0
    assert command.main(["export", run_id]) == 0
    assert "Bearer secret" not in capsys.readouterr().out
    assert ledger.manifest_for(run_id)["cleanup"] == "complete"
    assert command.main(["show", "../elsewhere"]) == 2


@pytest.mark.parametrize("header", ["Authorization", "Cookie", "Proxy-Authorization"])
def test_cli_export_preserves_json_and_redacts_embedded_http(policy, capsys, header):
    request = (
        f"GET / HTTP/1.1\r\n{header}: private-fixture-value\r\n"
        "X-Control: preserved\r\n\r\n"
    ).encode()
    capture = ledger.begin(
        egress.current_profile(),
        tool="fixture",
        operation="manual",
        target="https://allowed.example/",
        request=request,
    )
    capture.response_prefix = (
        b"HTTP/1.1 200 OK\r\nSet-Cookie: private-response-value\r\n\r\n"
    )
    capture.body.extend(b"safe body")
    capture.finish()
    assert command.main(["export", capture.manifest["run_id"]]) == 0
    output = capsys.readouterr().out
    exported = json.loads(output)
    assert (
        "private-fixture-value" not in output and "private-response-value" not in output
    )
    assert "X-Control: preserved" in exported["captures"]["request"]["text"]
    assert (
        exported["captures"]["request"]["original_sha256"]
        == hashlib.sha256(request).hexdigest()
    )
    assert exported["captures"]["response"]["text"].endswith("safe body")


def test_invalid_redaction_configuration_fails_closed(policy):
    _, path = policy
    (path / "redaction.json").write_text('{"patterns": [123]}', encoding="utf-8")
    with pytest.raises(ValueError):
        ledger.redact_text("do not display")


def test_async_capture_has_response_and_releases_slot(policy):
    async def run():
        async with egress.async_client(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(200, content=b"response")
            )
        ) as client:
            await client.get("https://allowed.example/")

    asyncio.run(run())
    manifest = json.loads(next(ledger.runs_dir().glob("*/manifest.json")).read_text())
    assert manifest["response"] and manifest["classification"] == "observation"
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0


def test_snare_capture_links_original_files_and_truncation(policy):
    request = b"GET / HTTP/1.1\r\nCookie: private-cookie\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nSet-Cookie: private-server-cookie\r\n\r\nhello"
    name = snare._store(
        request, response, "https://allowed.example/", "allowed.example", truncated=True
    )
    manifest = json.loads(next(ledger.runs_dir().glob("*/manifest.json")).read_text())
    assert (
        manifest["tool"] == "snare"
        and manifest["source_files"]["request"] == f"requests/{name}"
    )
    assert manifest["request"]["truncated"] and manifest["response"]["truncated"]
    assert (
        ledger.runs_dir() / manifest["run_id"] / "response.http"
    ).read_bytes() == response
    assert "private-cookie" not in json.dumps(ledger.export_run(manifest["run_id"]))


def test_saved_option_and_binary_output_are_redacted(policy):
    output = io.StringIO()
    writer = ledger._Output(output)
    writer.write("AUTHORIZATION => Bearer option-secret\n")
    writer.buffer.write(b"Cookie: binary-secret\r\n")
    writer.flush()
    assert (
        "option-secret" not in output.getvalue()
        and "binary-secret" not in output.getvalue()
    )


def test_console_context_restores_stream_and_tool(policy):
    import sys
    from bughunt.console import ui

    previous_out, previous_file = sys.stdout, ui.console._file
    with ledger.sanitized_output():
        print("Authorization: must-not-escape")
    assert sys.stdout is previous_out and ui.console._file is previous_file


def test_scanner_reports_and_artifacts_redact_configured_values(policy, tmp_path):
    from bughunt.core import scanner as bughunt_scanner

    _, path = policy
    (path / "redaction.json").write_text(
        '{"patterns": ["artifact-secret"]}', encoding="utf-8"
    )
    hit = bughunt_scanner.error_hit(
        "https", "https://allowed.example/?token=query-secret", 0, ""
    )
    hit.status, hit.title, hit.body = 200, "artifact-secret", b"artifact-secret"
    hit.final_url = hit.url
    sink = bughunt_scanner.ArtifactSink(
        tmp_path / "urls.txt", tmp_path / "source", tmp_path / "headers"
    )
    sink.capture("allowed.example", 443, hit)
    sink.close()
    report = bughunt_scanner.HostReport(
        "allowed.example", [], [bughunt_scanner.PortResult(443, True, [hit])], 0
    )
    bughunt_scanner.write_csv(tmp_path / "report.csv", [report])
    bughunt_scanner.write_markdown(tmp_path / "report.md", [report], 0)
    # Reach checks (M2). The secret-absence sweep below is only meaningful if the sink and both writers actually
    # processed the LIVE hit. The hit list was once passed positionally into PortResult.tcp_error, so nothing live
    # reached any writer and the sweep passed on empty files. These assertions fail in that situation.
    csv_text = (tmp_path / "report.csv").read_text(encoding="utf-8")
    assert (
        len(csv_text.splitlines()) == 2
        and ",200," in csv_text
        and "[REDACTED]" in csv_text
    )
    markdown_text = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert (
        "### Live HTTP(S)" in markdown_text
        and "| 443 |" in markdown_text
        and "[REDACTED]" in markdown_text
    )
    assert (tmp_path / "urls.txt").read_text(encoding="utf-8").count("\n") == 1
    assert (
        len(list((tmp_path / "source").iterdir())) == 1
        and len(list((tmp_path / "headers").iterdir())) == 1
    )
    for file in tmp_path.rglob("*"):
        if (
            file.is_file()
            and file.parent.name not in {"runs"}
            and file.name != "redaction.json"
            and "runs" not in file.parts
            and file.name != "policy.json"
        ):
            assert b"artifact-secret" not in file.read_bytes()
            assert b"query-secret" not in file.read_bytes()


def test_write_markdown_renders_live_http_table_for_speaking_hits(policy, tmp_path):
    from bughunt.core import scanner as bughunt_scanner

    explicit_port_hit = bughunt_scanner.error_hit(
        "https", "https://allowed.example:8443/", 0, ""
    )
    explicit_port_hit.status, explicit_port_hit.server, explicit_port_hit.title = (
        200,
        "nginx",
        "Admin",
    )
    default_port_hit = bughunt_scanner.error_hit(
        "http", "http://allowed.example/", 0, ""
    )
    default_port_hit.status, default_port_hit.server, default_port_hit.title = (
        200,
        "apache",
        "Home",
    )
    ports = [
        bughunt_scanner.PortResult(8443, True, hits=[explicit_port_hit]),
        bughunt_scanner.PortResult(80, True, hits=[default_port_hit]),
    ]
    report = bughunt_scanner.HostReport("allowed.example", [], ports, 0)
    markdown_path = tmp_path / "report.md"
    bughunt_scanner.write_markdown(markdown_path, [report], 0)
    text = markdown_path.read_text(encoding="utf-8")
    assert "### Live HTTP(S)" in text
    assert "| 8443 | `https://allowed.example:8443/` | 200 | nginx | Admin |" in text
    assert "| 80 | `http://allowed.example/` | 200 | apache | Home |" in text
