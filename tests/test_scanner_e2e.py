"""Characterization oracle (M2): complete scans, end to end, against loopback services.

No test elsewhere in the suite completes a scan. These do. Each drives the real pipeline
(``scan_main`` -> policy preflight -> DNS -> TCP -> HTTP(S) -> analysis -> JSON / CSV / Markdown
and artifact files) against a scripted local server and pins the OBSERVABLE output only, so a
clean-room rebuild that keeps the public surface must reproduce it.

Tiers follow the behavior spec (m2-scanner-spec.md): [K] = current behavior pinned, [C] = contract.
Expected values are derived from spec sections 4 and 5 and were checked against a run of the
current tree. Where the current behavior is a documented defect it is marked CURRENT/DEFECT and
is pinned on purpose; see test_scanner_known_defects.py for the matching correct-behavior xfails.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import socket
import types
from datetime import datetime
from pathlib import Path

import httpx
import pytest

from bughunt import VERSION
from bughunt.core import egress, scanner
from scanner_oracle_support import (  # noqa: F401  (fixtures are consumed by name)
    FAVICON_HASH,
    NOT_FOUND,
    ROUTES,
    LabServer,
    RawServer,
    closed_port,
    grant,
    lab,
    make_self_signed_certificate,
    run_cli,
    squash,
    workspace,
)

SCAN_PATHS = [
    "/",
    "/admin",
    "/login",
    "/old",
    "/boom",
    "/listing",
    "/welcome",
    "/.env",
    "/app.js",
    "/.well-known/security.txt",
    "/missing",
    "/favicon.ico",
    "/info.php",
    "/data.json",
    "/reflect",
    "/star",
]

JSON_TOP_KEYS = ["tool", "version", "scanned_at", "elapsed_seconds", "hosts"]
JSON_HOST_KEYS = [
    "target",
    "resolved",
    "elapsed_seconds",
    "dns",
    "ct_names",
    "favicon_hash",
    "favicon_hint",
    "js_urls",
    "banners",
    "findings",
    "ports",
]
JSON_PORT_KEYS = ["port", "tcp_open", "tcp_error", "hits"]
JSON_HIT_KEYS = [
    "scheme",
    "url",
    "final_url",
    "status",
    "reason",
    "server",
    "powered_by",
    "content_type",
    "location",
    "title",
    "snippet",
    "bytes_read",
    "sha256",
    "elapsed_ms",
    "tags",
    "headers",
    "tls",
    "error",
]
JSON_TLS_KEYS = [
    "version",
    "cipher",
    "subject",
    "issuer",
    "not_before",
    "not_after",
    "san",
    "expired",
    "error",
]
JSON_FINDING_KEYS = ["severity", "title", "detail", "url", "evidence"]
CSV_HEADER = [
    "target",
    "port",
    "scheme",
    "url",
    "final_url",
    "status",
    "server",
    "title",
    "tags",
    "sha256",
    "bytes",
    "ms",
]
MISSING_HEADER_FINDINGS = [  # spec 5.1, HTTP (HSTS is HTTPS only), in rule order
    ("medium", "Missing CSP"),
    ("low", "Missing X-Frame-Options"),
    ("low", "Missing X-Content-Type-Options"),
    ("info", "Missing Referrer-Policy"),
    ("info", "Missing Permissions-Policy"),
]
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Everything about each response that is not derived from the body bytes (spec 4.4).
EXPECTED = {
    "/": dict(
        status=200,
        reason="OK",
        server="nginx/1.25",
        powered_by="",
        content_type="text/html",
        location="",
        title="Lab Home | Page",
        snippet="Lab Home | Page nginx demo",
        tags=["nginx"],
        headers={"server": "nginx/1.25", "x-custom": "yes", "set-cookie": "[REDACTED]"},
    ),
    "/admin": dict(
        status=403,
        reason="Forbidden",
        server="",
        powered_by="",
        content_type="text/html",
        location="",
        title="Forbidden",
        snippet="Forbidden",
        tags=["forbidden"],
        headers={},
    ),
    "/login": dict(
        status=401,
        reason="Unauthorized",
        server="nginx/1.25",
        powered_by="",
        content_type="text/plain",
        location="",
        title="",
        snippet="auth needed",
        tags=["auth-required", "nginx"],
        headers={"server": "nginx/1.25", "www-authenticate": 'Basic realm="lab"'},
    ),
    "/old": dict(
        status=302,
        reason="Found",
        server="Apache",
        powered_by="",
        content_type="text/plain",
        location="/new",
        title="",
        snippet="",
        tags=["redirect", "apache"],
        headers={"location": "/new", "server": "Apache"},
    ),
    "/boom": dict(
        status=500,
        reason="Internal Server Error",
        server="",
        powered_by="",
        content_type="text/html",
        location="",
        title="",
        snippet="Jenkins",
        tags=["server-error", "jenkins"],
        headers={},
    ),
    "/listing": dict(
        status=200,
        reason="OK",
        server="",
        powered_by="",
        content_type="text/html",
        location="",
        title="Index of /",
        snippet="Index of /",
        tags=["dir-listing"],
        headers={},
    ),
    "/welcome": dict(
        status=200,
        reason="OK",
        server="",
        powered_by="",
        content_type="text/html",
        location="",
        title="Welcome to nginx!",
        snippet="Welcome to nginx!",
        tags=["default-page", "nginx"],
        headers={},
    ),
    "/.env": dict(
        status=200,
        reason="OK",
        server="nginx/1.25",
        powered_by="",
        content_type="text/plain",
        location="",
        title="",
        snippet="SECRET=[REDACTED]",
        tags=["nginx"],
        headers={"server": "nginx/1.25"},
    ),
    "/app.js": dict(
        status=200,
        reason="OK",
        server="nginx/1.25",
        powered_by="",
        content_type="application/javascript",
        location="",
        title="",
        snippet="fetch('/api/items'); var api_key='[REDACTED]';",
        tags=["nginx"],
        headers={"server": "nginx/1.25"},
    ),
    "/.well-known/security.txt": dict(
        status=200,
        reason="OK",
        server="",
        powered_by="",
        content_type="text/plain",
        location="",
        title="",
        tags=["security-txt"],
        headers={},
    ),
    "/missing": dict(
        status=404,
        reason="Not Found",
        server="nginx/1.25",
        powered_by="",
        content_type="text/plain",
        location="",
        title="",
        snippet="nope",
        tags=["nginx"],
        headers={"server": "nginx/1.25"},
    ),
    "/favicon.ico": dict(
        status=200,
        reason="OK",
        server="",
        powered_by="",
        content_type="image/x-icon",
        location="",
        title="",
        tags=[f"favicon:{FAVICON_HASH}"],
        headers={},
    ),
    "/info.php": dict(
        status=200,
        reason="OK",
        server="",
        powered_by="PHP/8.2.1",
        content_type="text/html",
        location="",
        title="",
        snippet="phpinfo()",
        tags=[],
        headers={"x-powered-by": "PHP/8.2.1"},
    ),
    "/data.json": dict(
        status=200,
        reason="OK",
        server="",
        powered_by="",
        content_type="application/json",
        location="",
        title="",
        snippet='{"a": 1}',
        tags=[],
        headers={},
    ),
    "/reflect": dict(
        status=200,
        reason="OK",
        server="",
        powered_by="",
        content_type="text/html",
        location="",
        title="",
        snippet="reflect",
        tags=[],
        headers={"access-control-allow-origin": "https://evil.bughunt.example"},
    ),
    "/star": dict(
        status=200,
        reason="OK",
        server="",
        powered_by="",
        content_type="text/html",
        location="",
        title="",
        snippet="star",
        tags=[],
        headers={"access-control-allow-origin": "*"},
    ),
}
# Sink file extension per path (spec 4.7); the sink writes a body file only for non-empty bodies.
PAGE_EXTENSION = {
    "/": ".html",
    "/admin": ".html",
    "/login": ".txt",
    "/boom": ".html",
    "/listing": ".html",
    "/welcome": ".html",
    "/.env": ".txt",
    "/app.js": ".js",
    "/.well-known/security.txt": ".txt",
    "/missing": ".txt",
    "/favicon.ico": ".bin",
    "/info.php": ".html",
    "/data.json": ".json",
    "/reflect": ".html",
    "/star": ".html",
}
SECRET_PAGES = {"/.env": b"SECRET=1", "/app.js": b"ABCDEFGH12345"}


def _body(path: str) -> bytes:
    return ROUTES.get(path, NOT_FOUND)[2]


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()[:16] if body else ""


def _stem(port: int, path: str, scheme: str = "http") -> str:
    part = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/") or "root")[:60]
    return f"127.0.0.1_{port}_{scheme}_{part}"


class Keystone:
    """One complete scan, run once, shared by the read-only assertions below."""

    def __init__(
        self, port: int, closed: int, out: Path, returncode: int, stdout: str
    ) -> None:
        self.port, self.closed, self.out = port, closed, out
        self.returncode, self.stdout = returncode, stdout
        self.report = json.loads((out / "bughunt.json").read_text(encoding="utf-8"))

    @property
    def host(self) -> dict:
        return self.report["hosts"][0]

    @property
    def hits(self) -> list[dict]:
        return self.host["ports"][0]["hits"]

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"


@pytest.fixture(scope="module")
def keystone(tmp_path_factory):
    base = tmp_path_factory.mktemp("keystone")
    with pytest.MonkeyPatch.context() as patch:
        workspace_dir = base / "workspace"
        workspace_dir.mkdir()
        patch.setenv("BUGHUNT_SCOPE", str(workspace_dir))
        patch.delenv("BUGHUNT_ROUTE_CONFIG", raising=False)
        server, closed = LabServer(), closed_port()
        grant(workspace_dir, http=[server.port, closed])
        out = base / "out"
        # Generous connect budget keeps CI independent of the residual egress-guard loop stall (perf; the connect
        # false negative it used to hide is fixed by PR-3). See test_scanner_known_defects.py.
        code, stdout = run_cli(
            [
                "127.0.0.1",
                "--ports",
                f"{server.port},{closed}",
                "--http-only",
                "--quiet",
                "--connect-timeout",
                "5",
                "--concurrency",
                "8",
                "--output-dir",
                str(out),
                "--paths",
                ",".join(SCAN_PATHS),
            ]
        )
        yield Keystone(server.port, closed, out, code, stdout)
        server.close()


# ======================================================================================
# The keystone scan: one real scan, every output surface
# ======================================================================================


def test_keystone_scan_completes_with_exit_zero_and_all_outputs(keystone):
    assert keystone.returncode == 0
    names = {path.name for path in keystone.out.iterdir()}
    assert names == {
        "bughunt.json",
        "bughunt.csv",
        "bughunt.md",
        "live.txt",
        "pages",
        "headers",
    }


def test_json_top_level_and_host_shape(keystone):
    report = keystone.report
    assert list(report) == JSON_TOP_KEYS
    assert report["tool"] == "Bughunt" and report["version"] == VERSION
    stamp = datetime.fromisoformat(report["scanned_at"])
    assert stamp.utcoffset().total_seconds() == 0 and report["scanned_at"].endswith(
        "+00:00"
    )
    assert (
        isinstance(report["elapsed_seconds"], float) and report["elapsed_seconds"] >= 0
    )
    assert round(report["elapsed_seconds"], 3) == report["elapsed_seconds"]
    assert len(report["hosts"]) == 1
    host = keystone.host
    assert list(host) == JSON_HOST_KEYS
    assert host["target"] == "127.0.0.1" and host["resolved"] == ["127.0.0.1"]
    assert (
        isinstance(host["elapsed_seconds"], float)
        and round(host["elapsed_seconds"], 3) == host["elapsed_seconds"]
    )
    assert host["dns"] == {} and host["ct_names"] == [] and host["banners"] == []


def test_json_lists_only_tcp_open_ports_and_never_the_closed_one(keystone):
    ports = keystone.host["ports"]
    assert [entry["port"] for entry in ports] == [keystone.port]
    assert list(ports[0]) == JSON_PORT_KEYS
    assert ports[0]["tcp_open"] is True and ports[0]["tcp_error"] == ""
    assert keystone.closed not in {entry["port"] for entry in ports}


def test_json_hits_follow_path_order_with_exact_key_order(keystone):
    assert [hit["url"] for hit in keystone.hits] == [
        keystone.url(path) for path in SCAN_PATHS
    ]
    assert all(list(hit) == JSON_HIT_KEYS for hit in keystone.hits)
    assert all(
        hit["scheme"] == "http" and hit["tls"] is None and hit["error"] == ""
        for hit in keystone.hits
    )
    assert all(
        hit["final_url"] == hit["url"] for hit in keystone.hits
    )  # redirects are never followed
    assert all(
        isinstance(hit["elapsed_ms"], float) and hit["elapsed_ms"] > 0
        for hit in keystone.hits
    )


@pytest.mark.parametrize("path", SCAN_PATHS)
def test_json_hit_fields_for_each_response(keystone, path):
    hit = keystone.hits[SCAN_PATHS.index(path)]
    expected = dict(EXPECTED[path])
    body = _body(path)
    expected.update(bytes_read=len(body), sha256=_digest(body))
    for field, value in expected.items():
        assert hit[field] == value, f"{path}: {field}"


def test_json_redirect_is_reported_not_followed(keystone):
    hit = keystone.hits[SCAN_PATHS.index("/old")]
    assert (hit["status"], hit["location"], hit["bytes_read"], hit["sha256"]) == (
        302,
        "/new",
        0,
        "",
    )


def test_json_findings_are_the_exact_ordered_analysis_output(keystone):
    expected: list[tuple[str, str, str]] = []

    def add(path, *items):
        expected.extend(
            (severity, title, keystone.url(path)) for severity, title in items
        )

    add(
        "/",
        *MISSING_HEADER_FINDINGS,
        ("low", "Cookie 'sid' missing HttpOnly"),
        ("low", "Cookie 'sid' missing SameSite"),
    )
    add("/listing", *MISSING_HEADER_FINDINGS)
    add("/welcome", *MISSING_HEADER_FINDINGS)
    add("/.env", ("high", "Sensitive path responded"))
    add("/app.js", ("high", "Possible secret in JavaScript/HTML"))
    add(
        "/.well-known/security.txt",
        ("info", "security.txt present"),
        ("info", "security.txt Expires"),
        ("info", "security.txt policy"),
    )
    add("/info.php", *MISSING_HEADER_FINDINGS)
    add("/reflect", *MISSING_HEADER_FINDINGS, ("high", "Reflected CORS origin"))
    add("/star", *MISSING_HEADER_FINDINGS, ("medium", "CORS allows any origin"))
    findings = keystone.host["findings"]
    assert all(list(item) == JSON_FINDING_KEYS for item in findings)
    assert [
        (item["severity"], item["title"], item["url"]) for item in findings
    ] == expected


def test_json_finding_details_and_evidence(keystone):
    by_title = {
        (item["title"], item["url"]): item for item in keystone.host["findings"]
    }
    sensitive = by_title[("Sensitive path responded", keystone.url("/.env"))]
    assert (
        sensitive["detail"] == "Artifact-style path returned a body"
        and sensitive["evidence"] == ""
    )
    secret = by_title[("Possible secret in JavaScript/HTML", keystone.url("/app.js"))]
    assert secret[
        "detail"
    ] == "Key-like assignment for 'api_key'" and "ABCDEFGH12345" not in json.dumps(
        secret
    )
    reflected = by_title[("Reflected CORS origin", keystone.url("/reflect"))]
    assert reflected["detail"] == "Server echoed a foreign Origin"
    assert reflected["evidence"] == "https://evil.bughunt.example"
    star = by_title[("CORS allows any origin", keystone.url("/star"))]
    assert (star["detail"], star["evidence"]) == ("Access-Control-Allow-Origin: *", "*")
    contact = by_title[
        ("security.txt present", keystone.url("/.well-known/security.txt"))
    ]
    assert (
        contact["detail"] == "Contact: mailto:sec@x.example"
        and contact["evidence"] == "mailto:sec@x.example"
    )
    expires = by_title[
        ("security.txt Expires", keystone.url("/.well-known/security.txt"))
    ]
    assert expires["detail"] == "2999-01-01T00:00:00Z"
    cookie = by_title[("Cookie 'sid' missing HttpOnly", keystone.url("/"))]
    assert (
        cookie["evidence"] == "sid" and "abc123" not in cookie["detail"]
    )  # the cookie value is redacted


def test_json_intel_fields_from_the_analysis_pass(keystone):
    host = keystone.host
    assert host["js_urls"] == [keystone.url("/app.js"), keystone.url("/api/items")]
    assert host["favicon_hash"] == FAVICON_HASH and host["favicon_hint"] == ""


def test_json_is_redacted_recursively(keystone):
    text = (keystone.out / "bughunt.json").read_text(encoding="utf-8")
    assert (
        "abc123" not in text and "ABCDEFGH12345" not in text and "SECRET=1" not in text
    )
    assert keystone.hits[0]["headers"]["set-cookie"] == "[REDACTED]"


def test_csv_header_crlf_and_one_row_per_speaking_hit(keystone):
    raw = (keystone.out / "bughunt.csv").read_bytes()
    assert raw.endswith(b"\r\n") and b"\n" not in raw.replace(b"\r\n", b"")
    rows = list(
        csv.reader(raw.decode("utf-8").splitlines(keepends=True), dialect="excel")
    )
    assert rows[0] == CSV_HEADER
    data = rows[1:]
    assert len(data) == len(
        SCAN_PATHS
    )  # every hit here has a status, closed ports contribute nothing
    for row, path in zip(data, SCAN_PATHS):
        expected = EXPECTED[path]
        body = _body(path)
        assert row[:2] == ["127.0.0.1", str(keystone.port)]
        assert row[2:5] == ["http", keystone.url(path), keystone.url(path)]
        assert row[5:9] == [
            str(expected["status"]),
            expected["server"],
            expected["title"],
            ",".join(expected["tags"]),
        ]
        assert row[9:11] == [_digest(body), str(len(body))]
        assert re.fullmatch(r"\d+\.\d", row[11]), row[11]  # exactly one decimal


def test_csv_quotes_multi_tag_fields_only(keystone):
    text = (keystone.out / "bughunt.csv").read_text(encoding="utf-8")
    assert ',"auth-required,nginx",' in text and ',"default-page,nginx",' in text
    assert ",nginx," in text  # a single tag is not quoted


def test_markdown_header_and_live_table(keystone):
    text = (keystone.out / "bughunt.md").read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines[0] == "# Bughunt report" and lines[1] == ""
    assert re.fullmatch(
        rf"Generated `[^`]+\+00:00` by Bughunt {re.escape(VERSION)}\.", lines[2]
    )
    assert re.fullmatch(
        r"Elapsed \*\*\d+\.\d\ds\*\* across \*\*1\*\* host\(s\)\.", lines[3]
    )
    assert (
        lines[4] == ""
        and lines[5]
        == "Authorized assessment notes only. Confirm scope before acting on findings."
    )
    assert "## 127.0.0.1" in lines and "Resolved: `127.0.0.1`" in lines
    assert (
        f"Favicon mmh3: `{FAVICON_HASH}`" in lines
    )  # no hint for an unknown hash: no parentheses
    start = lines.index("### Live HTTP(S)")
    assert lines[start + 1] == "| Port | URL | Status | Server | Title | Tags |"
    assert lines[start + 2] == "| ---: | --- | --- | --- | --- | --- |"
    rows = lines[start + 3 : start + 3 + len(SCAN_PATHS)]
    for row, path in zip(rows, SCAN_PATHS):
        expected = EXPECTED[path]
        title = expected["title"].replace("|", "/")
        tags = ", ".join(expected["tags"])
        assert row == (
            f"| {keystone.port} | `{keystone.url(path)}` | {expected['status']} | "
            f"{expected['server']} | {title} | {tags} |"
        ), path
    assert lines[start + 3 + len(SCAN_PATHS)] == ""


def test_markdown_js_urls_and_findings_sorted_by_severity(keystone):
    lines = (keystone.out / "bughunt.md").read_text(encoding="utf-8").splitlines()
    start = lines.index("### JavaScript / API URLs")
    assert lines[start + 1 : start + 3] == [
        f"- `{keystone.url('/app.js')}`",
        f"- `{keystone.url('/api/items')}`",
    ]
    first = lines.index("### Findings") + 1
    findings = [line for line in lines[first:] if line.startswith("- **")]
    ranks = [
        SEVERITY_RANK[re.match(r"- \*\*(\w+)\*\*", line).group(1).lower()]
        for line in findings
    ]
    assert ranks == sorted(ranks) and len(findings) == len(keystone.host["findings"])
    assert findings[0].startswith(
        f"- **HIGH** Sensitive path responded — `{keystone.url('/.env')}`. "
        "Artifact-style path returned a body"
    )
    assert (
        f"- **MEDIUM** CORS allows any origin — `{keystone.url('/star')}`. Access-Control-Allow-Origin: *"
        in "\n".join(findings)
    )
    # No DNS / CT / banner sections when those are empty.
    assert "### DNS" not in lines and "### Certificate transparency" not in lines
    assert "### Non-HTTP banners" not in lines


def test_markdown_is_redacted(keystone):
    text = (keystone.out / "bughunt.md").read_text(encoding="utf-8")
    assert "abc123" not in text and "ABCDEFGH12345" not in text


def test_live_url_file_lists_each_speaking_url_once_in_scan_order(keystone):
    lines = (keystone.out / "live.txt").read_text(encoding="utf-8").splitlines()
    assert lines == [keystone.url(path) for path in SCAN_PATHS]


def test_page_files_hold_response_bodies_named_by_stem_and_content_type(keystone):
    pages = {path.name: path for path in (keystone.out / "pages").iterdir()}
    expected_names = {
        f"{_stem(keystone.port, path)}{ext}" for path, ext in PAGE_EXTENSION.items()
    }
    assert set(pages) == expected_names  # /old has no body, so it has no page file
    for path, extension in PAGE_EXTENSION.items():
        content = pages[f"{_stem(keystone.port, path)}{extension}"].read_bytes()
        if path in SECRET_PAGES:
            assert SECRET_PAGES[path] not in content and b"[REDACTED]" in content
        else:
            assert content == _body(path), path


def test_header_files_summarize_each_speaking_hit(keystone):
    headers_dir = keystone.out / "headers"
    assert {item.name for item in headers_dir.iterdir()} == {
        f"{_stem(keystone.port, path)}.headers.txt" for path in SCAN_PATHS
    }
    login = (headers_dir / f"{_stem(keystone.port, '/login')}.headers.txt").read_text(
        encoding="utf-8"
    )
    assert login == (
        f"URL: {keystone.url('/login')}\nFinal-URL: {keystone.url('/login')}\n"
        "Status: 401 Unauthorized\nSHA256-16: b02d64c97f1a477a\n\n"
        'server: nginx/1.25\nwww-authenticate: Basic realm="lab"\n'
    )
    root = (headers_dir / f"{_stem(keystone.port, '/')}.headers.txt").read_text(
        encoding="utf-8"
    )
    assert root.splitlines()[:5] == [
        f"URL: {keystone.url('/')}",
        f"Final-URL: {keystone.url('/')}",
        "Status: 200 OK",
        f"SHA256-16: {_digest(_body('/'))}",
        "",
    ]
    assert "abc123" not in root and "x-custom: yes" in root.splitlines()
    redirect = (headers_dir / f"{_stem(keystone.port, '/old')}.headers.txt").read_text(
        encoding="utf-8"
    )
    assert redirect.splitlines()[2:4] == ["Status: 302 Found", "SHA256-16: "]


# ======================================================================================
# Behavior of individual flags, each through a complete scan
# ======================================================================================


def _scan(lab, *extra, ports=None, name="result.json"):
    out = lab.out
    out.mkdir(exist_ok=True)
    code, stdout = run_cli(
        [
            "127.0.0.1",
            "--ports",
            str(ports or lab.port),
            "--http-only",
            "--quiet",
            "--concurrency",
            "4",
            "--connect-timeout",
            "0.5",
            "--json",
            str(out / name),
            *extra,
        ]
    )
    report = (
        json.loads((out / name).read_text(encoding="utf-8"))
        if (out / name).exists()
        else None
    )
    return code, stdout, report


def _hits(report):
    return report["hosts"][0]["ports"][0]["hits"]


def _unrequested_path_errors(lab, report, expected_paths):
    """Assertion-message helper: the status and error the report recorded for each path the server never saw."""
    by_path = (
        {hit["url"].removeprefix(lab.base("")): hit for hit in _hits(report)}
        if report
        else {}
    )
    never_requested = sorted(expected_paths - set(lab.server.paths()))
    return {
        path: (by_path[path]["status"], by_path[path]["error"])
        if path in by_path
        else "no hit recorded"
        for path in never_requested
    }


def test_intel_requests_the_artifact_paths_and_runs_the_whole_analysis(lab):
    code, _, report = _scan(lab, "--intel")
    assert code == 0
    requested = set(lab.server.paths())
    artifact_paths = {
        "/robots.txt",
        "/sitemap.xml",
        "/favicon.ico",
        "/.well-known/security.txt",
        "/.git/HEAD",
        "/.git/config",
        "/.svn/entries",
        "/.hg/requires",
        "/.env",
        "/.env.local",
        "/.htpasswd",
        "/.htaccess",
        "/.DS_Store",
        "/web.config",
        "/crossdomain.xml",
        "/server-status",
        "/server-info",
        "/phpinfo.php",
        "/info.php",
        "/backup.zip",
        "/backup.tar.gz",
        "/dump.sql",
    }
    assert requested == {"/"} | artifact_paths and len(lab.server.paths()) == 23, (
        f"{len(lab.server.paths())} requests seen; (status, error) of each path never requested: "
        f"{_unrequested_path_errors(lab, report, {'/'} | artifact_paths)}"
    )
    assert {item.method for item in lab.requests} == {
        "GET"
    }  # --intel does not switch on --cors
    assert not (lab.out / "bughunt.md").exists()  # ... nor --md
    hits = _hits(report)
    assert [hit["url"].removeprefix(lab.base("")) for hit in hits][:2] == [
        "/",
        "/robots.txt",
    ]
    host = report["hosts"][0]
    assert host["favicon_hash"] == FAVICON_HASH
    by_path = {hit["url"].removeprefix(lab.base("")): hit for hit in hits}
    assert by_path["/favicon.ico"]["tags"] == [f"favicon:{FAVICON_HASH}"]
    assert by_path["/.well-known/security.txt"]["tags"] == ["security-txt"]
    assert any(
        item["title"] == "Sensitive path responded" and item["url"].endswith("/.env")
        for item in host["findings"]
    )
    assert (
        host["dns"] == {}
    )  # --intel turns on --dns, but an IP literal has no DNS records


def test_discover_alone_runs_analysis_but_keeps_no_bodies(lab):
    code, _, report = _scan(lab, "--discover")
    host = report["hosts"][0]
    assert code == 0 and len(_hits(report)) == 23
    assert any(
        item["title"] == "Missing CSP" for item in host["findings"]
    )  # analysis ran (headers)
    assert (
        host["favicon_hash"] == "" and host["js_urls"] == []
    )  # but no body was kept for body-based rules
    assert any(
        item["title"] == "Sensitive path responded" for item in host["findings"]
    )  # a path rule needs no body


def test_md_flag_alone_triggers_analysis_and_writes_the_report(lab, tmp_path):
    markdown = tmp_path / "only.md"
    code, _, report = _scan(lab, "--md", str(markdown), "--paths", "/,/.env")
    text = markdown.read_text(encoding="utf-8")
    assert code == 0 and "### Findings" in text
    assert any(
        item["title"] == "Sensitive path responded"
        for item in report["hosts"][0]["findings"]
    )


def test_without_any_analysis_flag_there_are_no_findings_and_no_analysis_tags(lab):
    _, _, report = _scan(lab, "--paths", "/,/.env,/.well-known/security.txt")
    host = report["hosts"][0]
    assert (
        host["findings"] == [] and host["js_urls"] == [] and host["favicon_hash"] == ""
    )
    assert (
        _hits(report)[2]["tags"] == []
    )  # the security-txt tag is added by the analysis pass only


def test_status_filter_tags_failures_filtered_and_hides_them_from_live_outputs(
    lab, tmp_path
):
    urls, csv_path, markdown = (
        tmp_path / "urls.txt",
        tmp_path / "f.csv",
        tmp_path / "f.md",
    )
    code, _, report = _scan(
        lab,
        "--paths",
        "/,/admin,/missing,/old",
        "--status",
        "200,302",
        "--save-urls",
        str(urls),
        "--csv",
        str(csv_path),
        "--md",
        str(markdown),
    )
    assert code == 0
    tags = {hit["url"].removeprefix(lab.base("")): hit["tags"] for hit in _hits(report)}
    assert tags == {
        "/": ["nginx"],
        "/admin": ["forbidden", "filtered"],
        "/missing": ["nginx", "filtered"],
        "/old": ["redirect", "apache"],
    }  # still in JSON, tagged filtered
    assert urls.read_text(encoding="utf-8").split() == [lab.base("/"), lab.base("/old")]
    csv_rows = list(csv.reader(csv_path.read_text(encoding="utf-8").splitlines()))
    assert [row[3] for row in csv_rows[1:]] == [
        lab.base(path) for path in ("/", "/admin", "/missing", "/old")
    ]
    assert "forbidden,filtered" in csv_path.read_text(
        encoding="utf-8"
    )  # CSV keeps filtered rows
    table = [
        line
        for line in markdown.read_text(encoding="utf-8").splitlines()
        if line.startswith("| ") and "http" in line
    ]
    assert [line.split("`")[1] for line in table] == [
        lab.base("/"),
        lab.base("/old"),
    ]  # Markdown drops them


def test_filtered_hits_are_excluded_from_the_analysis_pass(lab):
    _, _, report = _scan(
        lab, "--paths", "/,/.env", "--status", "404", "--score-headers"
    )
    host = report["hosts"][0]
    assert (
        host["findings"] == []
    )  # both responses are 200, so both are filtered, so nothing is analysed
    assert all("filtered" in hit["tags"] for hit in _hits(report))


def test_grep_filter_searches_title_snippet_server_and_is_case_insensitive(lab):
    _, _, report = _scan(
        lab, "--paths", "/,/admin,/old,/login", "--grep", "FORBID|NGINX"
    )
    tags = {
        hit["url"].removeprefix(lab.base("")): "filtered" in hit["tags"]
        for hit in _hits(report)
    }
    assert tags == {"/": False, "/admin": False, "/old": True, "/login": False}


def test_a_reversed_status_range_is_an_empty_set_which_means_no_filter(lab):
    _, _, report = _scan(lab, "--paths", "/,/admin", "--status", "300-299")
    assert [hit["tags"] for hit in _hits(report)] == [["nginx"], ["forbidden"]]


def test_status_and_grep_must_both_pass(lab):
    _, _, report = _scan(
        lab, "--paths", "/,/login", "--status", "200,401", "--grep", "auth needed"
    )
    flags = {
        hit["url"].removeprefix(lab.base("")): "filtered" in hit["tags"]
        for hit in _hits(report)
    }
    assert flags == {"/": True, "/login": False}


def test_head_method_returns_status_and_headers_but_no_body(lab):
    _, _, report = _scan(lab, "--paths", "/,/old", "--method", "HEAD")
    hits = _hits(report)
    assert [
        (hit["status"], hit["bytes_read"], hit["sha256"], hit["title"], hit["snippet"])
        for hit in hits
    ] == [(200, 0, "", "", ""), (302, 0, "", "", "")]
    assert {item.method for item in lab.requests} == {"HEAD"}


def test_options_method_adds_an_allow_tag_with_spaces_removed(lab):
    _, _, report = _scan(lab, "--paths", "/", "--method", "OPTIONS")
    hit = _hits(report)[0]
    assert hit["status"] == 200 and hit["tags"] == ["allow:GET,HEAD,OPTIONS"]
    assert hit["headers"]["allow"] == "GET, HEAD, OPTIONS"
    assert {item.method for item in lab.requests} == {"OPTIONS"}


def test_method_is_case_sensitive_at_parse_time():
    with pytest.raises(SystemExit) as raised:
        scanner.scan_main(["127.0.0.1", "--method", "get", "--quiet"])
    assert raised.value.code == 2


def test_request_headers_on_the_wire(lab):
    code, _, _ = _scan(
        lab,
        "--paths",
        "/",
        "-H",
        "X-Test: 1",
        "-H",
        "X-Test2: a:b",
        "--auth",
        "u:p:q",
        "--user-agent",
        "MyAgent/1",
        "--host-header",
        f"localhost:{lab.port}",
    )
    assert code == 0
    sent = lab.requests[0].headers
    assert (
        sent["x-test"] == "1" and sent["x-test2"] == "a:b"
    )  # header split on the first colon only
    assert (
        sent["authorization"] == "Basic dTpwOnE="
    )  # u:p:q -> user "u", password "p:q"
    assert sent["accept"] == "*/*" and sent["host"] == f"localhost:{lab.port}"
    # The guarded client overwrites the agent with the policy's user agent and adds the required header.
    assert (
        sent["user-agent"] == "Bughunt-owned-lab"
        and sent["x-researcher"] == "owned-lab"
    )


def test_header_file_and_headers_file_are_merged_last_value_wins(lab, tmp_path):
    first, second = tmp_path / "h1.txt", tmp_path / "h2.txt"
    first.write_text("# comment\nX-From-File: one\n\nX-Dup: first\n", encoding="utf-8")
    second.write_text("X-Dup: second\n", encoding="utf-8")
    code, _, _ = _scan(
        lab, "--paths", "/", "-H", str(first), "--headers-file", str(second)
    )
    sent = lab.requests[0].headers
    assert code == 0 and sent["x-from-file"] == "one" and sent["x-dup"] == "second"


def test_a_host_header_outside_the_policy_is_denied_at_request_time_not_in_the_preflight(
    lab,
):
    code, _, report = _scan(lab, "--paths", "/", "--host-header", "other.example")
    # The preflight only authorizes the planned URLs, so the scan starts; the per-request re-check of the
    # forced Host then denies the request, which is recorded as an error hit (spec section 10 item 6).
    assert code == 0
    hit = _hits(report)[0]
    assert hit["status"] is None and hit["error"].endswith("; no outbound action ran")
    assert lab.requests == []  # nothing ever reached the server


def test_cors_flag_probes_root_hits_with_two_origins_and_records_findings(lab):
    lab.server.cors = "echo"
    code, _, report = _scan(lab, "--paths", "/,/admin", "--cors")
    assert code == 0
    findings = report["hosts"][0]["findings"]
    assert [
        (item["severity"], item["title"], item["url"], item["evidence"])
        for item in findings
    ] == [
        ("high", "Permissive CORS", lab.base("/"), "https://bughunt.invalid"),
        ("high", "Permissive CORS", lab.base("/"), "http://127.0.0.1"),
    ]
    assert (
        findings[0]["detail"]
        == "OPTIONS Origin https://bughunt.invalid → https://bughunt.invalid"
    )
    probes = [item for item in lab.requests if item.method == "OPTIONS"]
    assert [
        (
            item.path,
            item.headers["origin"],
            item.headers["access-control-request-method"],
        )
        for item in probes
    ] == [
        ("/", "https://bughunt.invalid", "GET"),
        ("/", "http://127.0.0.1", "GET"),
    ]  # /admin is not a root hit


def test_cors_wildcard_is_medium_and_a_silent_server_adds_nothing(lab):
    lab.server.cors = "star"
    _, _, report = _scan(lab, "--paths", "/", "--cors")
    assert [
        (item["severity"], item["evidence"]) for item in report["hosts"][0]["findings"]
    ] == [("medium", "*"), ("medium", "*")]
    lab.server.cors = "none"
    _, _, quiet = _scan(lab, "--paths", "/", "--cors", name="quiet.json")
    assert quiet["hosts"][0]["findings"] == []


def test_non_ascii_titles_are_escaped_in_json_and_written_as_utf8_elsewhere(
    lab, tmp_path
):
    out = tmp_path / "unicode"
    code, _ = run_cli(
        [
            "127.0.0.1",
            "--ports",
            str(lab.port),
            "--http-only",
            "--quiet",
            "--paths",
            "/unicode",
            "--output-dir",
            str(out),
        ]
    )
    assert code == 0
    title = "Caf\u00e9 \u2014 menu"
    raw_json = (out / "bughunt.json").read_text(encoding="utf-8")
    assert (
        "Caf\\u00e9 \\u2014 menu" in raw_json
    )  # default json.dumps escaping: the file itself is pure ASCII
    assert raw_json.isascii()
    assert json.loads(raw_json)["hosts"][0]["ports"][0]["hits"][0]["title"] == title
    assert title in (out / "bughunt.csv").read_bytes().decode("utf-8")
    assert title in (out / "bughunt.md").read_bytes().decode("utf-8")


def test_max_body_below_1024_is_clamped_to_1024(lab, tmp_path):
    pages = tmp_path / "pages"
    code, _, report = _scan(
        lab, "--paths", "/big", "--max-body", "10", "--save-source", str(pages)
    )
    saved = next(pages.iterdir())
    assert code == 0 and saved.stat().st_size == 1024 and saved.suffix == ".txt"
    hit = _hits(report)[0]
    assert hit["bytes_read"] == 5000 and hit["sha256"] == _digest(
        _body("/big")
    )  # hash/size cover the FULL body


def test_save_flags_work_without_output_dir_and_urls_append_across_runs(lab, tmp_path):
    urls, headers = tmp_path / "live.txt", tmp_path / "hdr"
    for name in ("one.json", "two.json"):
        _scan(
            lab,
            "--paths",
            "/",
            "--save-urls",
            str(urls),
            "--save-headers",
            str(headers),
            name=name,
        )
    assert urls.read_text(encoding="utf-8").split() == [
        lab.base("/"),
        lab.base("/"),
    ]  # append mode
    assert [item.name for item in headers.iterdir()] == [
        f"{_stem(lab.port, '/')}.headers.txt"
    ]


def test_output_dir_fills_only_the_outputs_left_unset(lab, tmp_path):
    out = tmp_path / "fills"
    custom = tmp_path / "custom.json"
    code, _ = run_cli(
        [
            "127.0.0.1",
            "--ports",
            str(lab.port),
            "--http-only",
            "--quiet",
            "--connect-timeout",
            "0.5",
            "--output-dir",
            str(out),
            "--json",
            str(custom),
        ]
    )
    assert code == 0 and custom.exists()
    assert {item.name for item in out.iterdir()} == {
        "bughunt.csv",
        "bughunt.md",
        "live.txt",
        "pages",
        "headers",
    }


def test_skip_tcp_sends_http_to_every_selected_port_including_closed_ones(lab):
    _, _, report = _scan(
        lab,
        "--paths",
        "/",
        "--skip-tcp",
        "--http-timeout",
        "0.5",
        ports=f"{lab.port},{lab.closed}",
    )
    by_port = {entry["port"]: entry for entry in report["hosts"][0]["ports"]}
    expected_order = sorted(
        [lab.port, lab.closed]
    )  # the scanner emits ascending port order
    assert list(by_port) == expected_order
    assert [
        (port, by_port[port]["tcp_open"], by_port[port]["tcp_error"])
        for port in expected_order
    ] == [(port, True, "") for port in expected_order]
    dead = by_port[lab.closed]["hits"][0]
    assert dead["status"] is None and (
        dead["error"] == "timeout" or dead["error"].startswith("connect:")
    )


def test_closed_port_alone_gives_an_empty_report_and_exit_zero(lab):
    out = lab.out
    out.mkdir()
    code, _ = run_cli(
        [
            "127.0.0.1",
            "--ports",
            str(lab.closed),
            "--http-only",
            "--quiet",
            "--connect-timeout",
            "0.4",
            "--json",
            str(out / "closed.json"),
            "--csv",
            str(out / "closed.csv"),
        ]
    )
    report = json.loads((out / "closed.json").read_text(encoding="utf-8"))
    assert code == 0 and report["hosts"][0]["ports"] == []
    assert (out / "closed.csv").read_bytes() == (",".join(CSV_HEADER) + "\r\n").encode()


def test_no_http_traffic_when_nothing_is_tcp_open(lab):
    run_cli(
        [
            "127.0.0.1",
            "--ports",
            str(lab.closed),
            "--http-only",
            "--quiet",
            "--connect-timeout",
            "0.4",
        ]
    )
    assert lab.requests == []


def test_keyboard_interrupt_returns_130_and_closes_the_sink(lab, monkeypatch, tmp_path):
    def interrupted(_target):
        raise KeyboardInterrupt

    monkeypatch.setattr(scanner, "resolve_host", interrupted)
    urls = tmp_path / "urls.txt"
    code, _ = run_cli(
        [
            "127.0.0.1",
            "--ports",
            str(lab.port),
            "--http-only",
            "--quiet",
            "--save-urls",
            str(urls),
        ]
    )
    assert code == 130 and urls.exists()


def test_dns_failure_records_an_empty_host_and_the_scan_continues(
    workspace, tmp_path, monkeypatch
):
    server = LabServer()
    try:
        (workspace / "scope.txt").write_text("dnsfail.example\n", encoding="utf-8")
        grant(workspace, http=[server.port], hosts=("127.0.0.1", "dnsfail.example"))
        real = socket.getaddrinfo

        def resolver(host, *args, **kwargs):
            if host == "dnsfail.example":
                raise socket.gaierror(-2, "Name or service not known")
            return real(host, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", resolver)
        out = tmp_path / "dns"
        code, _ = run_cli(
            [
                "dnsfail.example",
                "127.0.0.1",
                "--ports",
                str(server.port),
                "--http-only",
                "--quiet",
                "--output-dir",
                str(out),
            ]
        )
        report = json.loads((out / "bughunt.json").read_text(encoding="utf-8"))
        failed, good = report["hosts"]
        assert code == 0  # a DNS failure is not a scan failure
        assert (
            failed["target"] == "dnsfail.example"
            and failed["resolved"] == []
            and failed["ports"] == []
        )
        assert failed["elapsed_seconds"] == 0.0 and failed["findings"] == []
        assert (
            good["target"] == "127.0.0.1" and len(good["ports"]) == 1
        )  # input order is preserved
        assert "dnsfail.example" in (out / "bughunt.md").read_text(encoding="utf-8")
    finally:
        server.close()


def test_a_policy_denied_url_blocks_the_whole_scan_before_any_traffic(lab):
    grant(
        lab.workspace,
        http=[lab.port],
        hosts=("127.0.0.1",),
        exclusions=[(f"http://127.0.0.1:{lab.port}", ["/private"])],
    )
    code, stdout = run_cli(
        [
            "127.0.0.1",
            "--ports",
            str(lab.port),
            "--http-only",
            "--quiet",
            "--paths",
            "/,/private",
        ]
    )
    assert code == 2 and "asset-excluded" in squash(stdout)
    assert (
        lab.requests == []
    )  # the allowed "/" was not sent either: all-or-nothing preflight


# ======================================================================================
# Non-HTTP ports: banners
# ======================================================================================


@pytest.fixture
def banner_pair(workspace):
    banner_server, silent_server = (
        RawServer(banner=b"SSH-2.0-lab\r\n"),
        RawServer(banner=b""),
    )
    grant(workspace, http=[banner_server.port, silent_server.port])
    yield banner_server, silent_server
    banner_server.close()
    silent_server.close()


def _banner_scan(banner_pair, tmp_path, *extra):
    banner_server, silent_server = banner_pair
    out = tmp_path / "banners.json"
    code, _ = run_cli(
        [
            "127.0.0.1",
            "--ports",
            f"{banner_server.port},{silent_server.port}",
            "--http-only",
            "--quiet",
            "--connect-timeout",
            "1",
            "--json",
            str(out),
            *extra,
        ]
    )
    return code, json.loads(out.read_text(encoding="utf-8"))["hosts"][0]


def test_non_http_open_ports_become_error_hits_that_are_not_live(banner_pair, tmp_path):
    code, host = _banner_scan(banner_pair, tmp_path)
    assert code == 0 and len(host["ports"]) == 2
    for entry in host["ports"]:
        assert entry["tcp_open"] is True
        (hit,) = entry["hits"]
        # httpcore reports a peer that never answers HTTP as "Server disconnected ...". That text contains
        # the noise word "connect", so the hit is NOT "speaking" and does not appear in any live output.
        assert (
            hit["status"] is None
            and hit["error"] == "Server disconnected without sending a response."
        )


def test_banners_flag_alone_populates_the_report_without_analysis(
    banner_pair, tmp_path
):
    _, host = _banner_scan(banner_pair, tmp_path, "--banners")
    assert host["banners"] and host["findings"] == []


def test_banners_with_an_analysis_flag_reach_the_report_and_findings(
    banner_pair, tmp_path
):
    banner_server, silent_server = banner_pair
    _, host = _banner_scan(banner_pair, tmp_path, "--banners", "--score-headers")
    assert host["banners"] == [
        f"{banner_server.port}/tcp SSH-2.0-lab"
    ]  # the silent port yields no banner
    assert [
        (item["severity"], item["title"], item["detail"], item["url"], item["evidence"])
        for item in host["findings"]
    ] == [("info", f"Banner on port {banner_server.port}", "SSH-2.0-lab", "", "")]
    assert all(
        "banner" not in entry for entry in host["ports"]
    )  # per-port banner is not in the JSON


# ======================================================================================
# DNS-over-HTTPS and certificate-transparency lookups (the HTTP edge is replaced, nothing leaves the machine)
# ======================================================================================

DOH_TYPES_IN_ORDER = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


@pytest.fixture
def resolver_edge(lab, monkeypatch):
    """Send the DoH / CT lookups to an in-memory handler; ``state.handler`` is set by each test."""
    grant(
        lab.workspace,
        http=[lab.port, lab.closed],
        hosts=("127.0.0.1", "localhost"),
        extra_origins=["https://cloudflare-dns.com", "https://crt.sh"],
    )
    state = types.SimpleNamespace(
        seen=[], handler=lambda request: httpx.Response(200, json={})
    )
    real_client = egress.client

    def dispatch(request):
        state.seen.append(request)
        return state.handler(request)

    monkeypatch.setattr(
        egress,
        "client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(dispatch), **kwargs),
    )
    return state


def _lookup_scan(lab, tmp_path, *flags, target="localhost"):
    out = tmp_path / "lookup.json"
    code, _ = run_cli(
        [
            target,
            "--ports",
            str(lab.closed),
            "--http-only",
            "--connect-timeout",
            "0.3",
            "--quiet",
            "--json",
            str(out),
            *flags,
        ]
    )
    return code, json.loads(out.read_text(encoding="utf-8"))["hosts"][0]


def test_dns_flag_queries_each_record_type_through_doh_and_keeps_only_the_non_empty_ones(
    lab, resolver_edge, tmp_path
):
    answers = {
        "A": [{"data": " 10.0.0.9 "}],
        "MX": [{"data": "10 mail.localhost."}],
        "TXT": [{"data": '"v=spf1 -all"'}, {"data": ""}, {"data": '"second"'}],
    }

    def handler(request):
        return httpx.Response(
            200,
            json={"Answer": answers[request.url.params["type"]]}
            if request.url.params["type"] in answers
            else {"Status": 0},
        )

    resolver_edge.handler = handler
    code, host = _lookup_scan(lab, tmp_path, "--dns")
    assert code == 0
    assert host["dns"] == {
        "A": ["10.0.0.9"],
        "MX": ["10 mail.localhost."],
        "TXT": ["v=spf1 -all", "second"],
    }
    assert list(host["dns"]) == [
        "A",
        "MX",
        "TXT",
    ]  # record types keep their query order; empty ones are absent
    queries = [
        (item.url.params["name"], item.url.params["type"])
        for item in resolver_edge.seen
    ]
    assert queries == [("localhost", kind) for kind in DOH_TYPES_IN_ORDER]
    first = resolver_edge.seen[0]
    assert first.method == "GET" and str(first.url).startswith(
        "https://cloudflare-dns.com/dns-query?"
    )
    assert first.headers["accept"] == "application/dns-json"


def test_the_dmarc_lookup_is_never_reached_because_its_name_cannot_be_granted(
    lab, resolver_edge, tmp_path
):
    # CURRENT / DEFECT (found while writing this oracle; not in spec section 10): the DMARC query first needs a
    # policy grant for the host "_dmarc.<host>", and the policy schema rejects an underscore host, so no DMARC
    # request is ever sent and the "DMARC" key can never appear in the report.
    resolver_edge.handler = lambda request: httpx.Response(
        200, json={"Answer": [{"data": '"v=DMARC1; p=none"'}]}
    )
    _, host = _lookup_scan(lab, tmp_path, "--dns")
    assert "DMARC" not in host["dns"]
    assert not any(
        item.url.params["name"].startswith("_dmarc") for item in resolver_edge.seen
    )


def test_dns_failures_are_silent(lab, resolver_edge, tmp_path):
    def broken(request):
        raise httpx.ConnectError("resolver down")

    resolver_edge.handler = broken
    code, host = _lookup_scan(lab, tmp_path, "--dns")
    assert code == 0 and host["dns"] == {} and len(resolver_edge.seen) == 7


def test_dns_and_ct_do_nothing_for_an_ip_literal_target(lab, resolver_edge, tmp_path):
    code, host = _lookup_scan(lab, tmp_path, "--dns", "--ct", target="127.0.0.1")
    assert (
        code == 0
        and host["dns"] == {}
        and host["ct_names"] == []
        and resolver_edge.seen == []
    )


def test_ct_flag_keeps_unique_lowercase_names_that_contain_the_host(
    lab, resolver_edge, tmp_path
):
    rows = [
        {
            "name_value": "*.localhost\nmail.localhost\nother.example\nLOCALHOST\n  Mail.Localhost  "
        },
        {"name_value": ".dev.localhost\nlocalhost.example"},
    ]
    resolver_edge.handler = lambda request: httpx.Response(200, json=rows)
    code, host = _lookup_scan(lab, tmp_path, "--ct")
    assert code == 0
    assert host["ct_names"] == [
        "localhost",
        "mail.localhost",
        "dev.localhost",
        "localhost.example",
    ]
    (request,) = resolver_edge.seen
    assert request.method == "GET" and request.url.host == "crt.sh"
    assert dict(request.url.params) == {"q": "localhost", "output": "json"}


def test_ct_flag_caps_the_name_list_at_eighty(lab, resolver_edge, tmp_path):
    rows = [{"name_value": "\n".join(f"n{index}.localhost" for index in range(100))}]
    resolver_edge.handler = lambda request: httpx.Response(200, json=rows)
    _, host = _lookup_scan(lab, tmp_path, "--ct")
    assert host["ct_names"] == [f"n{index}.localhost" for index in range(80)]


@pytest.mark.parametrize(
    "reply",
    [
        lambda request: httpx.Response(200, json={"not": "a list"}),
        lambda request: httpx.Response(200, content=b"<html>not json</html>"),
        lambda request: (_ for _ in ()).throw(httpx.ConnectError("crt.sh down")),
    ],
)
def test_ct_failures_and_odd_replies_give_an_empty_list(
    lab, resolver_edge, tmp_path, reply
):
    resolver_edge.handler = reply
    code, host = _lookup_scan(lab, tmp_path, "--ct")
    assert code == 0 and host["ct_names"] == []


def test_a_lookup_the_policy_does_not_grant_is_an_empty_result_not_an_error(
    lab, resolver_edge, tmp_path
):
    grant(
        lab.workspace, http=[lab.port, lab.closed], hosts=("127.0.0.1", "localhost")
    )  # no resolver / CT origins
    code, host = _lookup_scan(lab, tmp_path, "--dns", "--ct")
    assert (
        code == 0
        and host["dns"] == {}
        and host["ct_names"] == []
        and resolver_edge.seen == []
    )


def test_dns_and_ct_results_reach_the_markdown_report(lab, resolver_edge, tmp_path):
    resolver_edge.handler = lambda request: (
        httpx.Response(200, json=[{"name_value": "mail.localhost"}])
        if request.url.host == "crt.sh"
        else httpx.Response(200, json={"Answer": [{"data": "10.0.0.9"}]})
    )
    markdown = tmp_path / "lookup.md"
    _lookup_scan(lab, tmp_path, "--dns", "--ct", "--md", str(markdown))
    lines = markdown.read_text(encoding="utf-8").splitlines()
    assert "### DNS" in lines and "- **A**: `10.0.0.9`" in lines
    assert "### Certificate transparency" in lines and "- `mail.localhost`" in lines


# ======================================================================================
# HTTPS and TLS metadata
# ======================================================================================


@pytest.fixture
def tls_lab(workspace, tmp_path):
    material = make_self_signed_certificate(tmp_path)
    if material is None:
        pytest.skip("openssl CLI not available to mint a throwaway certificate")
    server = LabServer(tls=material)
    grant(workspace, https=[server.port])
    yield server
    server.close()


def _tls_scan(tls_lab, tmp_path, *extra):
    out = tmp_path / "tls.json"
    code, _ = run_cli(
        [
            "127.0.0.1",
            "--ports",
            str(tls_lab.port),
            "--https-only",
            "--quiet",
            "--connect-timeout",
            "2",
            "--http-timeout",
            "5",
            "--concurrency",
            "4",
            "--json",
            str(out),
            *extra,
        ]
    )
    return code, json.loads(out.read_text(encoding="utf-8"))["hosts"][0]


def test_https_scan_with_insecure_collects_tls_version_and_cipher(tls_lab, tmp_path):
    code, host = _tls_scan(tls_lab, tmp_path, "--insecure", "--paths", "/,/admin")
    assert code == 0
    hits = host["ports"][0]["hits"]
    assert [hit["scheme"] for hit in hits] == ["https", "https"] and [
        hit["status"] for hit in hits
    ] == [200, 403]
    for hit in hits:
        assert list(hit["tls"]) == JSON_TLS_KEYS
        assert hit["tls"]["version"].startswith("TLS") and hit["tls"]["cipher"]
        assert hit["tls"]["error"] == ""
    for hit in hits:
        assert "127.0.0.1" in hit["tls"]["subject"]
        assert (
            hit["tls"]["issuer"]
            and hit["tls"]["not_before"]
            and hit["tls"]["not_after"]
        )
        assert hit["tls"]["expired"] is False
        assert "expired-cert" not in hit["tags"]
    assert all(
        hit["url"].startswith(f"https://127.0.0.1:{tls_lab.port}/") for hit in hits
    )


def test_https_header_scoring_adds_hsts_and_secure_cookie_rules(tls_lab, tmp_path):
    _, host = _tls_scan(
        tls_lab, tmp_path, "--insecure", "--score-headers", "--paths", "/"
    )
    titles = [(item["severity"], item["title"]) for item in host["findings"]]
    assert titles == [
        ("medium", "Missing HSTS"),
        *MISSING_HEADER_FINDINGS,
        ("medium", "Cookie 'sid' missing Secure"),
        ("low", "Cookie 'sid' missing HttpOnly"),
        ("low", "Cookie 'sid' missing SameSite"),
    ]


def test_no_cert_flag_skips_tls_metadata(tls_lab, tmp_path):
    _, host = _tls_scan(tls_lab, tmp_path, "--insecure", "--no-cert", "--paths", "/")
    assert host["ports"][0]["hits"][0]["tls"] is None


def test_certificate_verification_is_on_by_default_and_failures_still_get_tls_metadata(
    tls_lab, tmp_path
):
    _, host = _tls_scan(tls_lab, tmp_path, "--paths", "/")
    (hit,) = host["ports"][0]["hits"]
    assert (
        hit["status"] is None
        and hit["error"].startswith("connect:")
        and "ssl" in hit["error"].lower()
    )
    # The metadata probe runs for a failed handshake too (error text contains "ssl") and itself ignores verification.
    assert hit["tls"] is not None and hit["tls"]["version"].startswith("TLS")
