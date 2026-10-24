"""Offline pre-DNS, socket and process checks for mission-policy enforcement."""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import subprocess
import time

import httpx
import pytest

from bughunt.core import egress
from bughunt.console import loader
from bughunt.modules import cert, dns, repeater, snare, whois
from bughunt.modules.policy import example_document
from bughunt.core import scanner as bughunt_scanner


def seed_policy(path: Path) -> dict:
    document = example_document()
    document.update(
        state="verified", verified_at=datetime.now(timezone.utc).isoformat()
    )
    document["permissions"] = {operation: True for operation in document["permissions"]}
    document["limits"] = {"requests_per_second": 1000000, "concurrency": 100}
    origins = [
        "https://allowed.example",
        "http://allowed.example",
        "https://allowed.example:80",
        "https://www.allowed.example",
        "https://cdn.allowed.example",
        "http://proxy.example:8080",
        "https://api.example",
        "https://urlscan.io",
        "https://phishunt.io",
        "https://api.tweetfeed.live",
        "https://raw.githubusercontent.com",
        "https://urlhaus-api.abuse.ch",
        "https://mb-api.abuse.ch",
        "https://crt.sh",
        "https://sslbl-api.abuse.ch",
        "https://threatfox-api.abuse.ch",
        "https://feodotracker-api.abuse.ch",
        "https://feodotracker.abuse.ch",
        "https://crt.name",
    ]
    document["assets"] = [
        {
            "id": f"asset-{index}",
            "origin": origin,
            "paths": ["/"],
            "operations": list(document["permissions"]),
            "methods": ["GET", "HEAD", "POST", "OPTIONS", "CONNECT"],
        }
        for index, origin in enumerate(origins)
    ]
    document["exclusions"] = []
    path.mkdir(parents=True, exist_ok=True)
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    return document


@pytest.fixture
def policy(monkeypatch, tmp_path):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    (tmp_path / "scope.txt").write_text("allowed.example\n", encoding="utf-8")
    document = seed_policy(tmp_path)
    return document, tmp_path


@pytest.fixture
def boundaries(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Downstream boundary reached")

    for name in ("getaddrinfo", "gethostbyname", "create_connection"):
        monkeypatch.setattr(socket, name, forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    return forbidden


@pytest.mark.parametrize(
    "state", ["missing", "unknown", "stale", "excluded", "disallowed"]
)
def test_http_denials_never_reach_transport(policy, state):
    document, path = policy
    if state in {"unknown", "stale"}:
        document["state"] = state
    if state == "excluded":
        document["exclusions"] = [
            {"id": "exclude", "origin": "https://allowed.example", "paths": ["/"]}
        ]
    if state == "disallowed":
        document["permissions"]["manual"] = False
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    if state == "missing":
        (path / "policy.json").unlink()
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(200, content=b"allowed fixture")

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(egress.PolicyBlocked):
            client.get("https://allowed.example/")
    assert seen == []


def test_http_headers_redirects_and_host_override(policy):
    seen = []

    def respond(request):
        seen.append(request)
        assert request.headers["X-Researcher"] == "owned-lab"
        assert request.headers["User-Agent"] == "Bughunt-owned-lab"
        return httpx.Response(
            302, headers={"Location": "https://outside.example/"}, content=b""
        )

    with egress.client(
        transport=httpx.MockTransport(respond), follow_redirects=True
    ) as client:
        with pytest.raises(egress.PolicyBlocked):
            client.get("https://allowed.example/")
        with pytest.raises(egress.PolicyBlocked):
            client.get("https://allowed.example/", headers={"Host": "outside.example"})
    assert len(seen) == 1


def test_user_agent_trailing_space_stripped_before_transport(policy):
    document, path = policy
    document["user_agent"] = "Bughunt-owned-lab "
    document["required_headers"] = {"X-Researcher": "owned-lab "}
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(200, content=b"allowed fixture")

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        client.get("https://allowed.example/")
    assert len(seen) == 1
    user_agent = seen[0].headers["User-Agent"]
    assert user_agent == "Bughunt-owned-lab" and user_agent == user_agent.strip()
    assert seen[0].headers["X-Researcher"] == "owned-lab"


def test_async_http_denial_before_transport(policy):
    seen = []

    async def run():
        async with egress.async_client(
            transport=httpx.MockTransport(lambda request: seen.append(request))
        ) as client:
            with pytest.raises(egress.PolicyBlocked):
                await client.get("https://outside.example/")

    asyncio.run(run())
    assert seen == []


@pytest.mark.parametrize(
    "entry", ["resolve", "tls", "tcp", "banner", "dns", "whois", "fetch", "process"]
)
@pytest.mark.parametrize(
    "state", ["verified", "unknown", "stale", "missing", "disallowed"]
)
def test_raw_unknown_targets_block_before_boundaries(
    policy, boundaries, entry, monkeypatch, state
):
    document, path = policy
    if state in {"unknown", "stale"}:
        document["state"] = state
    if state == "disallowed":
        document["permissions"] = {key: False for key in document["permissions"]}
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    if state == "missing":
        (path / "policy.json").unlink()
    if entry == "dns":
        monkeypatch.setattr(dns.socket, "socket", boundaries)
    host = "outside.example" if state == "verified" else "allowed.example"
    calls = {
        "resolve": lambda: bughunt_scanner.resolve_host(host),
        "tls": lambda: cert.fetch_certificate(host, 443, 1),
        "tcp": lambda: asyncio.run(bughunt_scanner.tcp_probe(host, 80, 1)),
        "banner": lambda: asyncio.run(bughunt_scanner.banner_grab(host, 80, 1)),
        "dns": lambda: dns.lookup(host, "127.0.0.1", 53, 1),
        "whois": lambda: whois._fetch(host, 43, "allowed.example", 1),
        "fetch": lambda: snare._fetch(
            host, 80, "http", b"GET / HTTP/1.1\r\n\r\n", snare.Settings()
        ),
        "process": lambda: snare._openssl([], Path.cwd()),
    }
    with pytest.raises(egress.PolicyBlocked):
        calls[entry]()


def test_scan_missing_policy_stops_before_dns(monkeypatch, tmp_path, boundaries):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    (tmp_path / "scope.txt").write_text("allowed.example", encoding="utf-8")
    assert (
        bughunt_scanner.scan_main(["allowed.example", "--ports", "80", "--quiet"]) == 2
    )


def test_snare_policy_denial_stops_before_fetch(policy, monkeypatch, boundaries):
    document, path = policy
    document["permissions"]["manual"] = False
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    statuses = []
    monkeypatch.setattr(
        snare, "_send_status", lambda _, code, reason: statuses.append(code)
    )
    snare._handle_exchange(
        object(),
        None,
        snare._Message("GET / HTTP/1.1", []),
        "GET",
        "http://allowed.example/",
        "HTTP/1.1",
        snare.Settings(),
        scheme=None,
        default_port=None,
    )
    assert statuses == [403]


def test_dry_run_and_stream_capacity(policy):
    document, path = policy
    document["limits"]["concurrency"] = 1
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    dry = egress.dry_run("https://allowed.example/", "manual")
    assert dry["permitted"] and dry["concurrency"] == 1 and dry["actor"] == "default"
    with egress.client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=httpx.ByteStream(b"ok"))
        )
    ) as client:
        response = client.send(
            client.build_request("GET", "https://allowed.example/"), stream=True
        )
        assert not egress._try_reserve(egress.current_profile())
        response.close()
    assert egress._try_reserve(egress.current_profile())
    egress._release()


def test_scan_dry_run_has_exact_targets_without_network(policy, boundaries, capsys):
    assert (
        bughunt_scanner.scan_main(
            ["allowed.example", "--ports", "80", "--http-only", "--dry-run", "--quiet"]
        )
        == 0
    )
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["target"] == "http://allowed.example:80/"
    assert rows[0]["operation"] == "active_scan" and rows[0]["rate"] == 1000000


def test_rate_cap_is_shared_across_clients(policy):
    document, path = policy
    document["limits"]["requests_per_second"] = 25
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    starts = []

    def respond(request):
        # Measure with perf_counter, the same fine clock the egress gate enforces spacing on
        # (PR-1). time.monotonic is GetTickCount64 on CPython<=3.12 Windows (15.625 ms), which
        # quantizes a real ~0.04s enforced gap down to 2 ticks (0.03125) and false-fails the
        # >=0.039 assert even though the rate is correctly enforced.
        starts.append(time.perf_counter())
        return httpx.Response(200, content=b"ok")

    with (
        egress.client(transport=httpx.MockTransport(respond)) as first,
        egress.client(transport=httpx.MockTransport(respond)) as second,
    ):
        first.get("https://allowed.example/")
        second.get("https://allowed.example/")
    assert starts[1] - starts[0] >= 0.039


def test_transport_failure_releases_capacity(policy):
    def fail(request):
        raise httpx.ConnectError("controlled failure")

    with egress.client(transport=httpx.MockTransport(fail)) as client:
        with pytest.raises(httpx.ConnectError):
            client.get("https://allowed.example/")
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0


def test_stale_policy_while_waiting_blocks_before_transport(policy):
    document, path = policy
    profile = egress.current_profile()
    assert egress._try_reserve(profile)
    document["limits"]["concurrency"] = 1
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")

    def expire():
        document["state"] = "stale"
        (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")

    import threading

    timer = threading.Timer(0.03, expire)
    timer.start()
    seen = []
    try:
        with egress.client(
            transport=httpx.MockTransport(lambda request: seen.append(request))
        ) as client:
            with pytest.raises(egress.PolicyBlocked):
                client.get("https://allowed.example/")
    finally:
        timer.join()
        egress._release()
    assert seen == []


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("window", ["waiting", "reserved"])
def test_raw_action_rechecks_secondary_grant_after_queue(
    policy, monkeypatch, asynchronous, window
):
    document, workspace = policy
    secondary = "http://whois.example:43/"
    document["assets"].append(
        {
            "id": "registry",
            "origin": secondary.rstrip("/"),
            "paths": ["/"],
            "operations": ["passive"],
            "methods": ["GET"],
        }
    )
    (workspace / "policy.json").write_text(json.dumps(document))
    reserve, changed, reached = egress._try_reserve, [], []

    def revoke(profile):
        if changed:
            return reserve(profile)
        result = reserve(profile) if window == "reserved" else False
        document["assets"] = [
            asset for asset in document["assets"] if asset["id"] != "registry"
        ]
        (workspace / "policy.json").write_text(json.dumps(document))
        changed.append(True)
        return result

    monkeypatch.setattr(egress, "_try_reserve", revoke)
    targets = lambda arguments: ["https://allowed.example/", secondary]

    @egress.guarded("passive", targets)
    def synchronous():
        reached.append(True)

    @egress.guarded("passive", targets)
    async def asynchronous_action():
        reached.append(True)

    with pytest.raises(egress.PolicyBlocked):
        if asynchronous:
            asyncio.run(asynchronous_action())
        else:
            synchronous()
    assert reached == []
    assert egress._budgets[str(workspace.resolve())][0] == 0


def test_whois_registry_revocation_blocks_socket_after_queue(policy, monkeypatch):
    document, workspace = policy
    document["assets"].append(
        {
            "id": "registry",
            "origin": "http://whois.example:43",
            "paths": ["/"],
            "operations": ["passive"],
            "methods": ["GET"],
        }
    )
    (workspace / "policy.json").write_text(json.dumps(document))
    reserve, changed, reached = egress._try_reserve, [], []

    def revoke(profile):
        if changed:
            return reserve(profile)
        document["assets"] = [
            asset for asset in document["assets"] if asset["id"] != "registry"
        ]
        (workspace / "policy.json").write_text(json.dumps(document))
        changed.append(True)
        return False

    def forbidden(*args, **kwargs):
        reached.append(args)
        raise AssertionError("Revoked registry reached the socket boundary")

    monkeypatch.setattr(egress, "_try_reserve", revoke)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    with pytest.raises(egress.PolicyBlocked):
        whois._fetch("whois.example", 43, "allowed.example", 1)
    assert reached == []
    assert egress._budgets[str(workspace.resolve())][0] == 0


def test_unapproved_proxy_is_blocked_before_target_transport(policy):
    request = httpx.Request("GET", "https://allowed.example/")
    with pytest.raises(egress.PolicyBlocked):
        egress._prepare(request, "manual", "http://outside.example:8080")


def test_loader_program_requires_policy_before_subprocess(policy, boundaries):
    with pytest.raises(egress.PolicyBlocked):
        loader._run_program(Path("anything.sh"), [], "test")


def test_third_party_grant_does_not_authorize_disallowed_target_scan(
    policy, monkeypatch
):
    document, path = policy
    document["permissions"]["active_scan"] = False
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    urlscan = loader.import_script(
        Path(bughunt_scanner.__file__).parents[2] / "addons/urlscan/urlscan.py"
    )
    with pytest.raises(SystemExit):
        urlscan.scan_gate("https://allowed.example/", "private", True)


@pytest.mark.parametrize("entry", ["resolve", "tls", "fetch"])
def test_permitted_raw_action_reaches_controlled_boundary(policy, boundaries, entry):
    calls = {
        "resolve": lambda: bughunt_scanner.resolve_host("allowed.example"),
        "tls": lambda: cert.fetch_certificate("allowed.example", 443, 1),
        "fetch": lambda: snare._fetch(
            "allowed.example", 80, "http", b"GET / HTTP/1.1\r\n\r\n", snare.Settings()
        ),
    }
    with pytest.raises(AssertionError, match="Downstream boundary reached"):
        calls[entry]()


def test_stream_release_uses_the_original_workspace(policy, monkeypatch, tmp_path):
    original_key = str(egress.workspace_dir().resolve())
    with egress.client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, stream=httpx.ByteStream(b"response"))
        )
    ) as client:
        response = client.send(
            client.build_request("GET", "https://allowed.example/"), stream=True
        )
        monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "other-workspace"))
        response.close()
    assert egress._budgets[original_key][0] == 0
