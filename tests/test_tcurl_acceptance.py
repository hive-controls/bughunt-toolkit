"""Acceptance oracle for addons/tcurl: Tor-aware transport behind the scope and policy gate.

This pins the TARGET behavior of the rebuilt tcurl (it does not characterize the old bash script, which
needed torsocks and a live Tor daemon and cannot run here). Network posture: NO real Tor and NO internet.
A loopback fake SOCKS5 server stands in for Tor; a booby trap records any local DNS lookup or direct TCP
connect, so a leak is a visible failure. UNVERIFIED (needs a live Tor daemon): that the daemon isolates
streams per SOCKS credential, the exact live JSON of check.torproject.org, circuit-build latency,
and Tor Browser's port 9150.

The gate-not-weakened proofs are the `*_mutation_goes_red` tests: each states an invariant as a function,
shows it holds, then applies the named weakening and shows the same invariant fails.

Point the suite at another copy of the script with `BUGHUNT_TCURL_UNDER_TEST=<path to tcurl.py>`.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import os
import re
import socket
import sys
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest

from bughunt.console import catalog, cli, loader
from bughunt.console.catalog_export import export_catalog
from bughunt.core import egress, ledger, scanner
from socks_support import (CHECK_HOST, ONION_V3, FakeSocks, NetworkTrap, Seen, asset, build_policy, closed_port,
                           default_responder)

REPO = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT = REPO / "addons" / "tcurl" / "tcurl.py"
SCRIPT = Path(os.environ.get("BUGHUNT_TCURL_UNDER_TEST") or DEFAULT_SCRIPT).resolve()
SOCKSIO_PRESENT = importlib.util.find_spec("socksio") is not None
ANSI = re.compile(r"\x1b\[[0-9;]*m")

TARGET = "http://target.example/"
OTHER = "http://other.example/"
OUTSIDE = "http://outside.example/"
HTTP_CHECK_URL = f"http://{CHECK_HOST}/api/ip"


@dataclass
class Run:
    code: int
    out: str
    err: str

    @property
    def document(self) -> dict:
        return json.loads(self.out)


# ---------------------------------------------------------------------------------------------
# Workspace: scope.txt + a verified policy with target, hop and check rows (each switchable)
# ---------------------------------------------------------------------------------------------


SCOPE_LINES = ("target.example", "other.example", "nopolicy.example", ONION_V3)


class World:
    """One scratch workspace, one fake SOCKS server and a booby trap, plus a `main()` runner."""

    def __init__(self, tcurl, monkeypatch, tmp_path, capsys):
        self.tcurl, self.mp, self.tmp, self.capsys = tcurl, monkeypatch, tmp_path, capsys
        self.tool_token = ledger.CURRENT_TOOL.set("tcurl")
        self.dir = tmp_path / "scope"
        self.dir.mkdir()
        self.socks = FakeSocks()
        self.trap = NetworkTrap().install(monkeypatch)
        self.trap.allow(self.socks.port)
        monkeypatch.setenv("BUGHUNT_SCOPE", str(self.dir))
        monkeypatch.setenv(tcurl.SOCKS_ENV_VAR, self.socks.endpoint)
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
        monkeypatch.setenv("COLUMNS", "250")
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setattr(tcurl, "EXIT_CHECK_URL", HTTP_CHECK_URL)
        self.scope(*SCOPE_LINES)
        self.policy()

    def close(self) -> None:
        self.socks.close()
        ledger.CURRENT_TOOL.reset(self.tool_token)

    def scope(self, *hosts: str) -> None:
        (self.dir / "scope.txt").write_text("\n".join(hosts) + "\n", encoding="utf-8")

    def policy(self, **options) -> None:
        build_policy(self.dir, socks_port=options.pop("socks_port", self.socks.port), **options)

    def serve(self, routes: dict | None = None, *, check_answer: bytes | None = None, check_status=200) -> None:
        """routes: (host, path) -> (status, headers, body). Unlisted paths get the default answer."""
        def responder(seen: Seen):
            if (seen.host, seen.target) in (routes or {}):
                return routes[(seen.host, seen.target)]
            if seen.host == CHECK_HOST and (check_answer is not None or check_status != 200):
                return check_status, {"Content-Type": "application/json"}, check_answer or b"{}"
            return default_responder(seen)
        self.socks.responder = responder

    def run(self, *argv: str) -> Run:
        code = self.tcurl.main(list(argv))
        out, err = self.capsys.readouterr()
        return Run(code, out, err)

    def target_connections(self) -> list[Seen]:
        return [seen for seen in self.socks.connections if seen.host != CHECK_HOST]

    def check_connections(self) -> list[Seen]:
        return [seen for seen in self.socks.connections if seen.host == CHECK_HOST]

    def manifests(self) -> list[dict]:
        paths = sorted((self.dir / "runs").glob("*/manifest.json"))
        manifests = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        return sorted(manifests, key=lambda manifest: manifest["started_at"])

    def workspace_text(self) -> str:
        parts = []
        for path in sorted(self.dir.rglob("*")):
            if path.is_file() and path.name not in {"policy.json", "scope.txt"}:
                parts.append(path.read_bytes().decode("latin-1"))
        return "\n".join(parts)


@pytest.fixture(scope="session")
def tcurl():
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("COLUMNS", "250")
        return loader.import_script(SCRIPT)


def make_world(tcurl, monkeypatch, tmp_path, capsys):
    created = World(tcurl, monkeypatch, tmp_path, capsys)
    return created


@pytest.fixture
def world(tcurl, monkeypatch, tmp_path, capsys):
    if not SOCKSIO_PRESENT:
        pytest.skip("socksio is not installed; run pip install 'bughunt[tor]' to exercise the Tor route")
    created = make_world(tcurl, monkeypatch, tmp_path, capsys)
    yield created
    created.close()


@pytest.fixture
def bare_world(tcurl, monkeypatch, tmp_path, capsys):
    """Same workspace, for tests that must pass whether or not socksio is installed."""
    created = make_world(tcurl, monkeypatch, tmp_path, capsys)
    yield created
    created.close()


# ---------------------------------------------------------------------------------------------
# A. The --json document (spec section 6)
# ---------------------------------------------------------------------------------------------

OUTCOMES = {"ok", "tor-unreachable", "exit-not-tor", "blocked", "transport-error", "invalid-input", "interrupted"}
EXIT_STATES = {"confirmed", "not-tor", "unverified", "skipped"}
TOP_KEYS = {"schema_version", "tool", "generated_at", "outcome", "error", "route", "exit", "request",
            "policy", "redirects", "response", "exit_code"}
ROUTE_KEYS = {"class", "scheme", "endpoint", "dns", "isolation", "vpn_attribution", "disclosure"}
EXIT_KEYS = {"state", "ip", "is_tor", "check_url", "check_run_id"}
REQUEST_KEYS = {"method", "url", "onion", "header_names", "body_bytes", "actor"}
POLICY_KEYS = {"mission", "policy_version", "operation", "target_decision", "hop_decision", "check_decision",
               "run_id"}
RESPONSE_KEYS = {"status", "reason", "http_version", "final_url", "content_type", "headers", "elapsed_ms", "body"}
BODY_KEYS = {"bytes", "truncated", "sha256", "saved_to", "text", "encoding"}


def validate_document(document: dict) -> None:
    assert set(document) == TOP_KEYS
    assert document["schema_version"] == 1 and document["tool"] == "tcurl"
    datetime.fromisoformat(document["generated_at"])
    assert document["outcome"] in OUTCOMES
    assert document["error"] is None or set(document["error"]) == {"kind", "message"}
    assert (document["outcome"] == "ok") == (document["error"] is None)
    assert set(document["route"]) == ROUTE_KEYS
    assert (document["route"]["class"], document["route"]["scheme"]) == ("tor", "socks5h")
    assert set(document["exit"]) == EXIT_KEYS and document["exit"]["state"] in EXIT_STATES
    assert set(document["request"]) == REQUEST_KEYS
    assert isinstance(document["request"]["onion"], bool) and isinstance(document["request"]["header_names"], list)
    assert set(document["policy"]) == POLICY_KEYS and document["policy"]["operation"] == "manual"
    for key in ("target_decision", "hop_decision", "check_decision"):
        decision = document["policy"][key]
        assert decision is None or (set(decision) == {"permitted", "reason"} and isinstance(decision["permitted"], bool))
    for hop in document["redirects"]:
        assert set(hop) == {"from", "to", "status", "followed", "note"}
    response = document["response"]
    if response is not None:
        assert set(response) == RESPONSE_KEYS and set(response["body"]) == BODY_KEYS
        assert all(isinstance(pair, list) and len(pair) == 2 for pair in response["headers"])
    assert isinstance(document["exit_code"], int)


def test_success_document_matches_the_schema_and_carries_the_run_ids(world):
    run = world.run(TARGET, "--json")
    document = run.document
    validate_document(document)
    assert run.code == 0 and document["exit_code"] == 0 and document["outcome"] == "ok"
    assert run.err == ""
    assert document["exit"] == {"state": "confirmed", "ip": "203.0.113.7", "is_tor": True,
                                "check_url": HTTP_CHECK_URL, "check_run_id": document["exit"]["check_run_id"]}
    assert document["policy"]["mission"] == "owned-lab" and document["policy"]["run_id"]
    assert document["exit"]["check_run_id"] != document["policy"]["run_id"]
    assert document["route"]["endpoint"] == world.socks.endpoint
    assert document["route"]["dns"].startswith("remote") and "not your VPN address" in document["route"]["disclosure"]
    assert document["route"]["isolation"] == "socks-auth per run" and document["route"]["vpn_attribution"].startswith("not applicable")
    response = document["response"]
    assert (response["status"], response["reason"], response["content_type"]) == (200, "OK", "text/plain")
    assert response["body"]["text"] == "hello via fake tor" and response["body"]["bytes"] == 18
    assert response["final_url"] == TARGET and document["request"]["method"] == "GET"


def test_json_mode_prints_only_the_document(world):
    run = world.run(TARGET, "--json")
    assert run.out.endswith("}\n") and run.out.count("\n{") == 0
    assert run.err == ""


def test_failure_documents_also_match_the_schema(world):
    world.policy(hop=False)
    run = world.run(TARGET, "--json")
    validate_document(run.document)
    assert run.document["outcome"] == "blocked" and run.document["response"] is None


def test_the_credential_never_appears_in_output_errors_or_the_ledger(world):
    run = world.run(TARGET)
    credential = world.socks.connections[0].user
    assert credential and len(credential) >= 16
    assert credential not in run.out and credential not in run.err and credential not in world.workspace_text()
    as_json = world.run(TARGET, "--json")
    assert credential not in as_json.out and credential not in as_json.err


def test_error_text_is_scrubbed_of_the_isolation_credential(tcurl):
    failure = httpx.ConnectError("could not use socks5h://deadbeefdeadbeef:deadbeefdeadbeef@127.0.0.1:9050")
    problem = tcurl.classify_failure(failure, [], "deadbeefdeadbeef")
    assert "deadbeefdeadbeef" not in problem.message and "[isolation]" in problem.message


# ---------------------------------------------------------------------------------------------
# B. Routing (spec B1, B8, B13): every byte goes through the SOCKS proxy, remote DNS only
# ---------------------------------------------------------------------------------------------


def test_b1_check_and_fetch_share_one_credential_and_use_remote_dns(world):
    run = world.run(TARGET)
    assert run.code == 0
    connections = world.socks.connections
    assert [seen.host for seen in connections] == [CHECK_HOST, "target.example"]
    assert {seen.atyp for seen in connections} == {3}
    assert [seen.port for seen in connections] == [80, 80]
    assert [seen.first_line for seen in connections] == ["GET /api/ip", "GET /"]
    users = {(seen.user, seen.password) for seen in connections}
    assert len(users) == 1 and None not in next(iter(users))
    assert world.trap.attempts == []


def test_b1_the_next_run_uses_a_different_credential(world):
    world.run(TARGET)
    world.run(TARGET)
    first, second = ({seen.user for seen in world.socks.connections[start:start + 2]} for start in (0, 2))
    assert len(first) == 1 and len(second) == 1 and first != second


def test_b13_policy_headers_and_user_agent_replace_the_callers(world):
    run = world.run(TARGET, "-A", "Mozilla/5.0 curl-like", "-H", "X-Custom: kept", "--json")
    seen = world.target_connections()[0]
    assert seen.headers["user-agent"] == "BughuntTcurlProbe/1"
    assert seen.headers["x-probe-handle"] == "tcurl-probe" and seen.headers["x-custom"] == "kept"
    document = run.document
    assert "User-Agent" in document["request"]["header_names"] and "X-Custom" in document["request"]["header_names"]
    text_run = world.run(TARGET, "-A", "Mozilla/5.0 curl-like")
    assert "-A is replaced" in text_run.err


def test_check_is_a_passive_request_and_the_fetch_is_manual(world):
    world.run(TARGET)
    operations = [manifest["operation"] for manifest in world.manifests()]
    assert operations == ["passive", "manual"]


def test_b8_onion_target_travels_as_a_domain_name_and_never_touches_local_dns(world):
    run = world.run(ONION_V3, "--json")
    assert run.code == 0
    seen = world.target_connections()[0]
    assert (seen.host, seen.atyp, seen.port) == (ONION_V3, 3, 80)
    assert run.document["request"]["onion"] is True and run.document["request"]["url"] == f"http://{ONION_V3}"
    assert world.trap.attempts == []


def test_onion_policy_grant_must_be_an_exact_origin_even_with_a_tld_scope_line(world):
    world.scope("onion", "target.example")
    world.policy(onion=False)
    run = world.run(f"http://{ONION_V3}/", "--json")
    assert run.code == 2 and run.document["policy"]["target_decision"]["reason"] == "asset-unknown"
    assert world.socks.connections == []


@pytest.mark.parametrize("address, fragment", [
    ("abcdefghijklmnop.onion", "v2 onion"),
    ("short.onion", "not a valid v3"),
    ("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW1.onion", "not a valid v3"),
])
def test_onion_addresses_other_than_v3_are_refused_before_anything_is_sent(world, address, fragment):
    run = world.run(f"http://{address}/")
    assert run.code == 2 and fragment in run.err
    assert world.socks.connections == []


def test_a_bare_host_means_https_and_a_bare_onion_means_http(world):
    https_run = world.run("target.example", "--dry-run")
    onion_run = world.run(ONION_V3, "--dry-run")
    assert https_run.document["request"]["url"] == "https://target.example"
    assert onion_run.document["request"]["url"] == f"http://{ONION_V3}"


@pytest.mark.parametrize("url", ["ftp://target.example/", "file:///etc/passwd", "gopher://target.example/",
                                 "http://user:pw@target.example/", "http://target.example:99999/", "",
                                 "http://target .example/", "http:\\\\target.example"])
def test_unsupported_or_malformed_urls_exit_2_without_traffic(world, url):
    run = world.run(url)
    assert run.code == 2
    assert world.socks.connections == [] and world.trap.attempts == []


def test_a_fragment_is_dropped_from_the_request(world):
    world.run(f"{TARGET}page#section")
    assert world.target_connections()[0].target == "/page"


# ---------------------------------------------------------------------------------------------
# C. The gate (spec B2-B5): scope and policy per request, the SOCKS hop as a policy asset
# ---------------------------------------------------------------------------------------------


def inv_hop_missing_sends_nothing(world) -> None:
    world.policy(hop=False)
    run = world.run(TARGET)
    assert run.code == 2, run.err
    assert "SOCKS hop" in run.err and f"http://127.0.0.1:{world.socks.port}/" in run.err
    assert world.socks.connections == []
    assert world.trap.attempts == []


def test_b2_a_missing_hop_row_blocks_everything_and_names_the_hop(world):
    inv_hop_missing_sends_nothing(world)


def test_b2_the_hop_row_must_allow_every_operation_tcurl_uses(world):
    world.policy(hop_operations=("manual",))
    run = world.run(TARGET)
    assert run.code == 2 and "SOCKS hop" in run.err and "passive" in run.err
    assert world.socks.connections == []
    ok = world.run(TARGET, "--no-exit-check")
    assert ok.code == 0 and [seen.host for seen in world.socks.connections] == ["target.example"]


def test_b3_a_target_outside_scope_txt_sends_nothing(world):
    world.scope("other.example")
    run = world.run(TARGET)
    assert run.code == 2 and "outside" in run.err and "scope" in run.err
    assert world.socks.connections == []


def test_b4_a_target_missing_from_the_policy_sends_nothing(world):
    run = world.run("http://nopolicy.example/")
    assert run.code == 2 and "asset-unknown" in run.err and "target" in run.err
    assert world.socks.connections == []


def test_b5_a_missing_check_row_blocks_unless_the_check_is_skipped(world):
    world.policy(check=False)
    blocked = world.run(TARGET)
    assert blocked.code == 2 and "exit-check host" in blocked.err and world.socks.connections == []
    skipped = world.run(TARGET, "--no-exit-check", "--json")
    assert skipped.code == 0
    assert skipped.document["exit"]["state"] == "skipped" and skipped.document["policy"]["check_decision"] is None
    assert [seen.host for seen in world.socks.connections] == ["target.example"]


def test_every_missing_grant_is_reported_at_once(world):
    world.policy(hop=False, check=False)
    run = world.run("http://nopolicy.example/")
    for fragment in ("target", "SOCKS hop", "exit-check host"):
        assert fragment in run.err
    assert world.socks.connections == []


def test_a_missing_policy_file_blocks(world):
    (world.dir / "policy.json").unlink()
    run = world.run(TARGET)
    assert run.code == 2 and "policy-missing-or-invalid" in run.err
    assert world.socks.connections == []


def test_the_method_must_be_granted_for_the_target_and_connect_is_refused(world):
    put = world.run(TARGET, "-X", "PUT")
    connect = world.run(TARGET, "-X", "CONNECT")
    assert put.code == 2 and "asset-method-disallowed" in put.err
    assert connect.code == 2 and "CONNECT" in connect.err
    assert world.socks.connections == []


def test_a_post_needs_only_a_get_row_for_the_hop(world):
    run = world.run(TARGET, "-d", "a=1", "-d", "b=2", "--json")
    seen = world.target_connections()[0]
    assert run.code == 0 and seen.method == "POST" and seen.body == b"a=1&b=2"
    assert seen.headers["content-type"] == "application/x-www-form-urlencoded"


def test_defense_in_depth_egress_alone_still_blocks_a_missing_hop(world, monkeypatch):
    monkeypatch.setattr(world.tcurl, "hop_decision", lambda plan, operations: world.tcurl.DecisionInfo(True, "permitted"))
    world.policy(hop=False)
    run = world.run(TARGET)
    assert run.code == 2 and "asset-unknown" in run.err
    assert world.socks.connections == []


def test_dry_run_decides_everything_and_sends_nothing(bare_world):
    world = bare_world
    run = world.run(TARGET, "--dry-run")
    document = run.document
    validate_document(document)
    assert run.code == 0 and document["response"] is None
    assert [document["policy"][key]["permitted"] for key in ("target_decision", "hop_decision", "check_decision")] == [True] * 3
    assert world.socks.connections == [] and world.trap.attempts == []
    world.policy(hop=False)
    blocked = world.run(TARGET, "--dry-run")
    assert blocked.code == 2 and blocked.document["policy"]["hop_decision"]["permitted"] is False
    assert world.socks.connections == []


def test_socks_endpoint_precedence_flag_then_env_then_default(bare_world):
    world = bare_world
    assert world.run(TARGET, "--dry-run").document["route"]["endpoint"] == world.socks.endpoint
    assert world.run(TARGET, "--dry-run", "--socks", "127.0.0.1:9150").document["route"]["endpoint"] == "127.0.0.1:9150"
    world.mp.delenv(world.tcurl.SOCKS_ENV_VAR)
    assert world.run(TARGET, "--dry-run").document["route"]["endpoint"] == "127.0.0.1:9050"


def test_an_env_endpoint_cannot_reroute_without_a_policy_grant(world):
    world.mp.setenv(world.tcurl.SOCKS_ENV_VAR, "127.0.0.1:9999")
    run = world.run(TARGET)
    assert run.code == 2 and "http://127.0.0.1:9999/" in run.err
    assert world.socks.connections == []


@pytest.mark.parametrize("endpoint", ["127.0.0.1:0", "127.0.0.1:99999", "127.0.0.1:abc", "a/b:1", " ", "user@host:9050"])
def test_a_malformed_socks_endpoint_is_a_usage_error(world, endpoint):
    run = world.run(TARGET, "--socks", endpoint, "--dry-run")
    assert run.code == 2 and run.document["outcome"] == "invalid-input"
    assert world.socks.connections == []


# ---------------------------------------------------------------------------------------------
# D. Fail closed (spec B6): no direct route, ever
# ---------------------------------------------------------------------------------------------


def use_closed_socks_port(world) -> int:
    port = closed_port()
    world.trap.allow(port)
    world.mp.setenv(world.tcurl.SOCKS_ENV_VAR, f"127.0.0.1:{port}")
    world.policy(socks_port=port)
    return port


def inv_closed_socks_port_fails_closed(world) -> None:
    use_closed_socks_port(world)
    run = world.run(TARGET, "--json")
    document = run.document
    assert run.code == 1 and document["outcome"] == "tor-unreachable", run.out
    assert world.trap.attempts == [], world.trap.attempts
    assert document["response"] is None


def test_b6_a_closed_socks_port_is_tor_unreachable_with_no_direct_attempt(world):
    inv_closed_socks_port_fails_closed(world)


def test_b6_the_same_holds_when_the_check_is_skipped(world):
    use_closed_socks_port(world)
    run = world.run(TARGET, "--no-exit-check", "--json")
    assert run.code == 1 and run.document["outcome"] == "tor-unreachable"
    assert world.trap.attempts == []


def test_a_non_socks_listener_is_reported_as_a_failed_handshake_not_a_fallback(world):
    junk = socket.socket()
    junk.bind(("127.0.0.1", 0))
    junk.listen(1)
    port = junk.getsockname()[1]
    def speak_http():
        connection, _address = junk.accept()
        connection.recv(64)
        connection.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        connection.close()
    threading.Thread(target=speak_http, daemon=True).start()
    world.trap.allow(port)
    world.policy(socks_port=port)
    try:
        run = world.run(TARGET, "--socks", f"127.0.0.1:{port}", "--json")
    finally:
        junk.close()
    assert run.code == 1 and run.document["outcome"] == "tor-unreachable"
    assert world.trap.attempts == []


# ---------------------------------------------------------------------------------------------
# E. The exit check (spec B7): fixed host, passive, and the Tor decision
# ---------------------------------------------------------------------------------------------


def inv_not_tor_exit_is_refused(world) -> None:
    world.serve(check_answer=b'{"IsTor": false, "IP": "198.51.100.9"}')
    run = world.run(TARGET, "--json")
    assert run.code == 1 and run.document["outcome"] == "exit-not-tor", run.out
    assert world.target_connections() == []
    assert run.document["exit"]["state"] == "not-tor" and run.document["exit"]["ip"] == "198.51.100.9"


def test_b7_a_non_tor_exit_stops_before_the_target_is_contacted(world):
    inv_not_tor_exit_is_refused(world)


@pytest.mark.parametrize("answer", [b"not json", b"[]", b'{"IP": "203.0.113.7"}', b'{"IsTor": "yes", "IP": "203.0.113.7"}',
                                    b'{"IsTor": true, "IP": "not-an-address"}', b'{"IsTor": true}'])
def test_b7_an_unreadable_check_answer_is_unverified_and_the_request_still_goes(world, answer):
    world.serve(check_answer=answer)
    run = world.run(TARGET, "--json")
    assert run.code == 0 and run.document["exit"]["state"] == "unverified"
    assert len(world.target_connections()) == 1


def test_b7_a_failing_check_host_is_unverified_not_fatal(world):
    world.serve(check_status=500)
    run = world.run(TARGET, "--json")
    assert run.code == 0 and run.document["exit"]["state"] == "unverified"


def test_a_check_redirect_is_never_followed(world):
    world.serve({(CHECK_HOST, "/api/ip"): (302, {"Location": "http://evil.example/"}, b"")})
    run = world.run(TARGET, "--json")
    assert run.document["exit"]["state"] == "unverified"
    assert "evil.example" not in world.socks.hosts()


def test_the_check_client_refuses_any_host_but_the_fixed_one(world, monkeypatch):
    monkeypatch.setattr(world.tcurl, "EXIT_CHECK_URL", "http://target.example/api/ip")
    world.policy(extra=[asset("check2", "http://target.example", ["/api/ip"], ["passive"], ["GET"])])
    run = world.run(TARGET, "--json")
    assert run.code == 2 and run.document["outcome"] == "blocked"
    assert world.socks.connections == []


def test_text_mode_shows_the_exit_address_and_state(world):
    run = world.run(TARGET)
    assert re.search(r"(?m)^exit\s+203\.0\.113\.7\s+Tor exit confirmed", run.err)


# ---------------------------------------------------------------------------------------------
# F. Redirects (spec B9): one request per hop, scope + policy before each
# ---------------------------------------------------------------------------------------------


def hop_routes(location: str, status: int = 302) -> dict:
    return {("target.example", "/"): (status, {"Location": location}, b""),
            ("other.example", "/landing"): (200, {"Content-Type": "text/plain"}, b"landed"),
            ("target.example", "/there"): (200, {"Content-Type": "text/plain"}, b"there")}


def test_a_redirect_is_not_followed_without_dash_l(world):
    world.serve(hop_routes("http://other.example/landing"))
    run = world.run(TARGET, "--json")
    assert run.code == 0 and run.document["response"]["status"] == 302 and run.document["redirects"] == []
    assert len(world.target_connections()) == 1


def test_b9_an_in_scope_permitted_hop_is_followed_on_the_same_circuit(world):
    world.serve(hop_routes("http://other.example/landing"))
    run = world.run(TARGET, "-L", "--json")
    document = run.document
    assert run.code == 0 and document["response"]["body"]["text"] == "landed"
    assert document["response"]["final_url"] == "http://other.example/landing"
    assert document["redirects"] == [{"from": TARGET, "to": "http://other.example/landing", "status": 302,
                                      "followed": True, "note": ""}]
    assert [seen.host for seen in world.socks.connections] == [CHECK_HOST, "target.example", "other.example"]
    assert len({seen.user for seen in world.socks.connections}) == 1


def inv_out_of_scope_hop_is_not_followed(world) -> None:
    world.policy(extra=[])
    world.serve(hop_routes(OUTSIDE))
    run = world.run(TARGET, "-L", "--json")
    document = run.document
    assert run.code == 0, run.out
    assert "outside.example" not in world.socks.hosts(), world.socks.hosts()
    assert document["redirects"][0]["followed"] is False and "outside scope" in document["redirects"][0]["note"]
    assert document["response"]["status"] == 302


def test_b9_an_out_of_scope_hop_is_reported_and_never_contacted(world):
    inv_out_of_scope_hop_is_not_followed(world)


def test_b9_an_in_scope_hop_the_policy_does_not_grant_is_not_followed(world):
    world.serve(hop_routes("http://nopolicy.example/"))
    run = world.run(TARGET, "-L", "--json")
    hop = run.document["redirects"][0]
    assert run.code == 0 and hop["followed"] is False and "policy" in hop["note"]
    assert "nopolicy.example" not in world.socks.hosts()


def test_a_hop_is_checked_with_the_method_it_will_use(world):
    world.serve({("target.example", "/"): (307, {"Location": "http://other.example/landing"}, b"")})
    run = world.run(TARGET, "-L", "-X", "POST", "-d", "x=1", "--json")
    hop = run.document["redirects"][0]
    assert hop["followed"] is False and "asset-method-disallowed" in hop["note"]


@pytest.mark.parametrize("status, method, expected", [(301, "POST", "GET"), (302, "POST", "GET"), (303, "POST", "GET"),
                                                      (307, "POST", "POST"), (308, "POST", "POST"), (303, "HEAD", "HEAD")])
def test_redirect_method_rewriting_follows_curl(tcurl, status, method, expected):
    assert tcurl.next_method(status, method)[0] == expected


def test_a_post_redirected_with_303_becomes_a_get_without_a_body(world):
    world.policy(extra=[asset("t-post", "http://target.example", ["/"], ["manual"], ["GET", "POST"])])
    world.serve({("target.example", "/"): (303, {"Location": "http://target.example/there"}, b"")})
    run = world.run(TARGET, "-L", "-d", "a=1", "--json")
    last = world.target_connections()[-1]
    assert run.code == 0 and (last.method, last.target, last.body) == ("GET", "/there", b"")


def test_credentials_are_dropped_when_a_redirect_crosses_origins(world):
    world.serve(hop_routes("http://other.example/landing"))
    world.run(TARGET, "-L", "-H", "Authorization: Bearer secret-token", "-H", "X-Keep: 1")
    first, second = world.target_connections()
    assert first.headers["authorization"] == "Bearer secret-token"
    assert "authorization" not in second.headers and second.headers["x-keep"] == "1"


def test_the_redirect_limit_is_enforced(world):
    world.serve({("target.example", "/"): (302, {"Location": "http://target.example/"}, b"")})
    run = world.run(TARGET, "-L", "--max-redirs", "2", "--json")
    redirects = run.document["redirects"]
    assert [hop["followed"] for hop in redirects] == [True, True, False]
    assert "stopped after 2 redirects" in redirects[-1]["note"]
    assert len(world.target_connections()) == 3


def test_a_redirect_to_a_non_http_scheme_is_not_followed(world):
    world.serve(hop_routes("ftp://other.example/x"))
    run = world.run(TARGET, "-L", "--json")
    assert run.document["redirects"][0]["followed"] is False


# ---------------------------------------------------------------------------------------------
# G. Bodies (spec B10, B11) and output modes (B16)
# ---------------------------------------------------------------------------------------------


def test_b10_max_body_truncates_and_hashes_the_kept_bytes(world):
    import hashlib
    world.serve({("target.example", "/"): (200, {"Content-Type": "text/plain"}, b"0123456789" * 10)})
    run = world.run(TARGET, "--max-body", "25", "--json")
    body = run.document["response"]["body"]
    assert (body["bytes"], body["truncated"], body["text"]) == (25, True, "0123456789" * 2 + "01234")
    assert body["sha256"] == hashlib.sha256(b"0123456789" * 2 + b"01234").hexdigest()
    exact = world.run(TARGET, "--max-body", "100", "--json").document["response"]["body"]
    assert exact["bytes"] == 100 and exact["truncated"] is False


BINARY = bytes(range(256))


def test_b11_a_binary_body_is_withheld_in_text_mode_and_null_in_json(world):
    world.serve({("target.example", "/"): (200, {"Content-Type": "application/octet-stream"}, BINARY)})
    text = world.run(TARGET)
    assert text.code == 0 and "kept off the terminal" in text.err and "-o" in text.err
    assert text.out == ""
    document = world.run(TARGET, "--json").document
    assert document["response"]["body"]["text"] is None and document["response"]["body"]["bytes"] == 256


def test_o_saves_the_body_and_the_json_names_the_path(world, tmp_path):
    world.serve({("target.example", "/"): (200, {"Content-Type": "application/octet-stream"}, BINARY)})
    target = tmp_path / "saved.bin"
    run = world.run(TARGET, "-o", str(target), "--json")
    assert target.read_bytes() == BINARY
    assert run.document["response"]["body"]["saved_to"] == str(target) and run.document["response"]["body"]["text"] is None
    text = world.run(TARGET, "-o", str(target))
    assert re.search(r"(?m)^saved\s+", text.err) and text.out == ""


def test_o_to_an_unwritable_place_exits_2_before_any_traffic(world, tmp_path):
    run = world.run(TARGET, "-o", str(tmp_path / "missing" / "x.bin"))
    assert run.code == 2 and world.socks.connections == []


def test_json_and_dash_o_dash_cannot_share_stdout(world):
    assert world.run(TARGET, "--json", "-o", "-").code == 2
    assert world.socks.connections == []


def test_head_sends_head_and_prints_the_headers(world):
    run = world.run(TARGET, "-I")
    assert world.target_connections()[0].method == "HEAD"
    assert run.code == 0 and "content-type: text/plain" in run.out.lower()


def test_i_shows_headers_above_the_body(world):
    run = world.run(TARGET, "-i")
    assert run.out.startswith("HTTP/1.1 200 OK") and run.out.rstrip().endswith("hello via fake tor")


def test_b16_piped_stdout_gets_the_plain_body_and_stderr_gets_the_banner(world):
    run = world.run(TARGET)
    assert run.out == "hello via fake tor"
    for label in ("exit", "route", "request", "status"):
        assert re.search(rf"(?m)^{label}\s", run.err), label
    assert "Route: Tor (SOCKS5, remote DNS) via " + world.socks.endpoint in run.err
    assert "not your VPN address" in run.err
    assert "\x1b[" not in run.err and "\x1b[" not in run.out


def test_a_clearnet_http_target_gets_the_plaintext_warning_but_an_onion_does_not(world):
    clearnet = world.run(TARGET)
    onion = world.run(ONION_V3)
    assert "Plain http over Tor" in clearnet.err and "Plain http over Tor" not in onion.err


def test_a_status_other_than_200_is_still_exit_0(world):
    world.serve({("target.example", "/"): (404, {"Content-Type": "text/plain"}, b"nope")})
    run = world.run(TARGET)
    assert run.code == 0 and "404 Not Found" in run.err


def test_hostile_response_text_cannot_inject_terminal_escapes(tcurl):
    assert tcurl.neutralize("a\x1b[2Jb\x07c\rd") == "a\ufffd[2Jb\ufffdc\ufffdd"


def test_color_and_pager_flags_are_accepted(world):
    for flag in ("--no-color", "--color", "--no-pager", "--raw", "-v"):
        assert world.run(TARGET, flag).code == 0, flag


def test_verbose_prints_a_header_summary_on_stderr_and_hides_credential_values(world):
    world.serve({("target.example", "/"): (200, {"Set-Cookie": "sid=abc", "X-Plain": "visible"}, b"x")})
    run = world.run(TARGET, "-v")
    assert "< X-Plain: visible" in run.err and "sid=abc" not in run.err
    assert "> GET http://target.example/" in run.err


class TerminalOut(io.StringIO):
    """A stdout that claims to be a terminal, so tcurl takes its interactive presentation path."""

    encoding = "utf-8"

    def isatty(self) -> bool:
        return True


def enter_terminal(world, monkeypatch) -> TerminalOut:
    """Swap stdout for a fake terminal. Call it inside the test body: pytest re-points sys.stdout per phase."""
    shown = TerminalOut()
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(sys, "stdout", shown)
    monkeypatch.setattr(world.tcurl.shutil, "which", lambda name: None)
    return shown


HTML = b"<html><body><h1>hello</h1></body></html>"


def test_on_a_terminal_the_banner_and_the_body_share_stdout_and_hostile_escapes_are_neutralized(world, monkeypatch):
    world.serve({("target.example", "/"): (200, {"Content-Type": "text/html"}, HTML + b"[2Jevil")})
    terminal = enter_terminal(world, monkeypatch)
    code = world.tcurl.main([TARGET, "--no-color"])
    out = terminal.getvalue()
    assert code == 0 and re.search(r"(?m)^exit\s+203\.0\.113\.7", out) and "<h1>hello</h1>" in out
    assert "[2J" not in out and "" not in out


def test_a_terminal_run_with_color_highlights_html_without_losing_the_text(world, monkeypatch):
    world.serve({("target.example", "/"): (200, {"Content-Type": "text/html"}, HTML)})
    terminal = enter_terminal(world, monkeypatch)
    assert world.tcurl.main([TARGET, "--color", "--no-pager"]) == 0
    out = terminal.getvalue()
    assert "hello" in out and "[" in out


def test_the_pager_is_used_only_on_a_terminal_when_less_exists_and_never_with_the_opt_outs(world, monkeypatch):
    enter_terminal(world, monkeypatch)
    paged = []
    monkeypatch.setattr(world.tcurl.pydoc, "pipepager", lambda text, command: paged.append((text, command)))
    monkeypatch.setattr(world.tcurl.shutil, "which", lambda name: "/usr/bin/less")
    assert world.tcurl.main([TARGET, "--no-color"]) == 0
    assert len(paged) == 1 and paged[0][1] == world.tcurl.PAGER_COMMAND and "hello via fake tor" in paged[0][0]
    for flag in ("--no-pager", "--raw", "--json"):
        assert world.tcurl.main([TARGET, flag]) == 0
    assert len(paged) == 1


def test_the_pager_is_not_used_when_stdout_is_piped(world, monkeypatch):
    paged = []
    monkeypatch.setattr(world.tcurl.pydoc, "pipepager", lambda text, command: paged.append(text))
    monkeypatch.setattr(world.tcurl.shutil, "which", lambda name: "/usr/bin/less")
    assert world.run(TARGET).code == 0 and paged == []


def test_dash_o_dash_writes_the_body_to_stdout(world):
    assert world.run(TARGET, "-o", "-").out == "hello via fake tor"


# ---------------------------------------------------------------------------------------------
# H. Exit codes (spec 5.3) and interrupts
# ---------------------------------------------------------------------------------------------


def test_exit_code_3_when_tor_reaches_but_the_target_cannot_be_connected(world):
    world.socks.reply_code = lambda host, port: 5 if host == "target.example" else 0
    run = world.run(TARGET, "--json")
    assert run.code == 3 and run.document["outcome"] == "transport-error"
    assert run.document["error"]["kind"] == "socks-reply" and world.trap.attempts == []


def test_exit_code_3_on_a_read_timeout(world):
    world.socks.stall_seconds = 2.5
    run = world.run(TARGET, "--no-exit-check", "-m", "1", "--json")
    assert run.code == 3 and run.document["error"]["kind"] == "timeout"


def test_exit_code_130_on_interrupt(world, monkeypatch):
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(world.tcurl, "check_exit", interrupted)
    run = world.run(TARGET, "--json")
    assert run.code == 130 and run.document["outcome"] == "interrupted"


@pytest.mark.parametrize("flag", ["-x", "--proxy", "--resolve", "-K", "--config", "-T", "-F", "-b", "-c", "--netrc",
                                  "-w", "-O", "--retry", "-Z", "--unix-socket", "--interface", "--connect-to",
                                  "--preproxy", "--noproxy", "--doh-url", "--cert", "--key", "-s", "-S"])
def test_b14_unsupported_curl_flags_exit_2_with_no_traffic(world, flag):
    run = world.run(TARGET, flag, "value")
    assert run.code == 2
    assert "tcurl no longer wraps curl" in run.err and flag in run.err
    assert world.socks.connections == [] and world.trap.attempts == []


def test_b14_an_unsupported_flag_before_the_url_cannot_swallow_it_as_a_value(world):
    run = world.run("-x", "socks5://evil.example:1080", TARGET)
    assert run.code == 2 and "-x" in run.err
    assert world.socks.connections == []


def test_b14_an_at_file_in_dash_d_is_literal_text(world, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET", encoding="utf-8")
    run = world.run(TARGET, "-d", f"@{secret}", "--json")
    seen = world.target_connections()[0]
    assert run.code == 0 and seen.body == f"@{secret}".encode()
    assert b"TOP-SECRET" not in seen.body


@pytest.mark.parametrize("argv", [[], [TARGET, "http://other.example/"], [TARGET, "--max-time", "0"],
                                  [TARGET, "--max-body", "0"], [TARGET, "--max-redirs", "-1"],
                                  [TARGET, "-I", "-d", "x"], [TARGET, "-H", "no-colon"], [TARGET, "-H", "Bad Name: v"]])
def test_usage_errors_exit_2(world, argv):
    run = world.run(*argv)
    assert run.code == 2 and world.socks.connections == []


def test_help_exits_0_and_documents_the_flags(world):
    run = world.run("--help")
    assert run.code == 0 and "--no-exit-check" in run.out and "--dry-run" in run.out


# ---------------------------------------------------------------------------------------------
# I. CLI surface and module hygiene
# ---------------------------------------------------------------------------------------------

EXPECTED_FLAGS = {
    "-X": "request", "-I": "head", "-H": "header", "-d": "data", "-A": "user_agent", "-L": "location",
    "--max-redirs": "max_redirs", "-k": "insecure", "-m": "max_time", "--connect-timeout": "connect_timeout",
    "--max-body": "max_body", "--socks": "socks", "--no-exit-check": "no_exit_check", "--dry-run": "dry_run",
    "-i": "include", "-o": "output", "-v": "verbose", "--json": "json", "--no-pager": "no_pager",
    "--raw": "no_pager", "--no-color": "no_color", "--color": "color",
}


def test_parser_flags_and_destinations(tcurl):
    parser = tcurl.build_parser()
    seen = {flag: action.dest for action in parser._actions for flag in action.option_strings}
    seen.pop("-h"), seen.pop("--help")
    for flag, dest in EXPECTED_FLAGS.items():
        assert seen.get(flag) == dest, flag
    assert set(seen) == set(EXPECTED_FLAGS) | {"--request", "--head", "--header", "--data", "--user-agent",
                                               "--location", "--insecure", "--max-time", "--include", "--output",
                                               "--verbose"}


def test_parser_defaults_and_kinds(tcurl):
    options = tcurl.build_parser().parse_args(["x.example"])
    assert (options.max_time, options.connect_timeout, options.max_redirs, options.max_body) == (60.0, 30.0, 10, 8 * 1024 * 1024)
    assert (options.json, options.no_exit_check, options.dry_run, options.location) == (False, False, False, False)
    assert options.header is None and options.data is None and options.socks is None
    parsed = tcurl.build_parser().parse_args(["x.example", "-H", "A: 1", "-H", "B: 2", "-d", "p", "-d", "q"])
    assert parsed.header == ["A: 1", "B: 2"] and parsed.data == ["p", "q"]


def test_no_curl_passthrough_flag_survives(tcurl):
    flags = {flag for action in tcurl.build_parser()._actions for flag in action.option_strings}
    assert not flags & {"-x", "--proxy", "--resolve", "-K", "--config", "-F", "-T", "--netrc", "-w", "-O"}


def imported_modules(path: Path) -> set[str]:
    modules = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add(node.module or "")
    return modules


def test_r1_tcurl_has_one_door_it_never_imports_a_network_or_process_primitive():
    imported = imported_modules(SCRIPT)
    banned = {"socket", "ssl", "subprocess", "urllib.request", "http.client", "requests", "aiohttp", "asyncio",
              "socksio", "httpcore", "urllib3", "ftplib", "telnetlib"}
    assert not imported & banned, imported & banned


def test_r1_tcurl_never_builds_a_transport_or_a_client_of_its_own():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    built = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
             and node.func.value.id == "httpx"}
    assert not built & {"Client", "AsyncClient", "HTTPTransport", "AsyncHTTPTransport", "MockTransport",
                        "get", "post", "request", "stream", "send"}, built
    source = SCRIPT.read_text(encoding="utf-8")
    assert not re.search(r"trust_env\s*=\s*True", source)
    assert "socks5://" not in source and "socks4" not in source


def test_importing_tcurl_has_no_side_effects(tcurl):
    assert tcurl.__name__.startswith("bughunt_tools.tcurl_") and callable(tcurl.main) and callable(tcurl.build_parser)


# ---------------------------------------------------------------------------------------------
# J. Console, catalog and packaging (spec B17-B19, section 8)
# ---------------------------------------------------------------------------------------------


def test_tcurl_is_re_enabled_in_the_catalog():
    assert "tcurl" not in catalog.DISABLED_REFERENCES and catalog.DISABLED_REFERENCES == frozenset()
    tool = catalog.tool_by_command("tcurl")
    assert (tool.folder, tool.script) == ("tcurl", "tcurl.py")
    assert "disabled" not in catalog.MODULE_WHEN["tcurl"].lower()
    assert catalog.group_for("tcurl") == "Intel"


def test_the_old_bash_script_is_gone_and_the_python_module_is_present():
    assert not (REPO / "addons" / "tcurl" / "tcurl").exists()
    assert (REPO / "addons" / "tcurl" / "tcurl.py").is_file() and (REPO / "addons" / "tcurl" / "README.md").is_file()


def test_b17_the_console_form_has_url_and_repeatable_header(tcurl):
    entry = next(module for phase in export_catalog(tool_file=Path(scanner.__file__), build_parser=scanner.build_parser)["phases"]
                 for module in phase["modules"] if module["name"] == "tcurl")
    assert entry["disabled"] is False and entry["form"] is not None
    options = {option["name"]: option for option in entry["form"]["options"]}
    assert options["URL"]["kind"] == "positional" and options["URL"]["required"] is True
    assert options["HEADER"]["repeatable"] is True and options["DATA"]["repeatable"] is True
    assert options["JSON"]["kind"] == "bool" and options["SOCKS"]["kind"] == "value"
    assert "EXTRA" not in options


def test_b18_without_socksio_import_and_form_work_and_run_prints_the_install_hint(bare_world, monkeypatch):
    world = bare_world
    monkeypatch.setitem(sys.modules, "socksio", None)
    assert world.tcurl.build_parser().parse_args([TARGET]).url == TARGET
    run = world.run(TARGET)
    assert run.code == 2 and "bughunt[tor]" in run.err and "socksio" in run.err
    assert world.socks.connections == []


def test_the_loader_runs_tcurl_in_process_and_maps_a_block_to_exit_2(world, monkeypatch):
    world.policy(hop=False)
    code = loader.run_named("tcurl", [TARGET], tool_file=Path(scanner.__file__).resolve(), scan_main=scanner.scan_main)
    world.capsys.readouterr()
    assert code == 2 and world.socks.connections == []


def dispatch_tcurl(world, *argv: str) -> int:
    code = cli.dispatch(["tcurl", *argv], scan_main=scanner.scan_main, build_parser=scanner.build_parser,
                        tool_file=Path(scanner.__file__).resolve(), interactive=False)
    world.capsys.readouterr()
    return code


def test_b19_the_ledger_records_tool_tcurl_and_the_route_without_credentials(world):
    assert dispatch_tcurl(world, TARGET) == 0
    manifests = world.manifests()
    assert [manifest["tool"] for manifest in manifests] == ["tcurl", "tcurl"]
    assert {manifest["route"]["kind"] for manifest in manifests} == {"socks5h"}
    assert {manifest["route"]["endpoint"] for manifest in manifests} == {world.socks.endpoint}
    credential = world.socks.connections[0].user
    assert credential not in world.workspace_text()
    for manifest in manifests:
        exported = ledger.export_run(manifest["run_id"])
        assert credential not in json.dumps(exported) and exported["manifest"]["route"] == manifest["route"]


def test_b19_a_cli_run_prints_the_same_document_as_main(world):
    code = cli.dispatch(["tcurl", TARGET, "--json"], scan_main=scanner.scan_main, build_parser=scanner.build_parser,
                        tool_file=Path(scanner.__file__).resolve(), interactive=False)
    out = world.capsys.readouterr().out
    validate_document(json.loads(out))
    assert code == 0


def test_requirements_and_packaging_declare_socksio_exactly_pinned():
    assert (REPO / "addons" / "tcurl" / "requirements.txt").read_text(encoding="utf-8").count("socksio==1.0.0") == 1
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'(?m)^tor = \["socksio==1\.0\.0"\]', pyproject)
    for name in ("requirements.txt", "requirements-hardened.txt"):
        assert re.search(r"(?m)^socksio==1\.0\.0$", (REPO / name).read_text(encoding="utf-8")), name


# ---------------------------------------------------------------------------------------------
# K. Gate-not-weakened proofs: each weakening must turn its invariant red
# ---------------------------------------------------------------------------------------------


def inv_credential_rotates_per_run(world) -> None:
    world.run(TARGET)
    world.run(TARGET)
    first = {seen.user for seen in world.socks.connections[:2]}
    second = {seen.user for seen in world.socks.connections[2:4]}
    assert len(first) == 1 and len(second) == 1 and first != second


def inv_remote_dns_only(world) -> None:
    world.run(TARGET)
    assert {seen.atyp for seen in world.socks.connections} == {3}
    assert world.trap.attempts == [], world.trap.attempts


def inv_exit_check_runs_by_default(world) -> None:
    world.run(TARGET)
    assert world.socks.connections[0].host == CHECK_HOST


def inv_no_credentials_in_the_ledger(world) -> None:
    world.run(TARGET)
    credential = world.socks.connections[0].user
    assert credential not in world.workspace_text()
    assert all("route" in manifest for manifest in world.manifests())


def test_proof_hop_authorization_holds(world):
    inv_hop_missing_sends_nothing(world)


def test_proof_dropping_hop_authorization_in_both_layers_goes_red(world, monkeypatch):
    monkeypatch.setattr(world.tcurl, "hop_decision", lambda plan, operations: world.tcurl.DecisionInfo(True, "permitted"))
    monkeypatch.setattr(egress, "authorize_proxy", lambda proxy, operation: None)
    with pytest.raises(AssertionError):
        inv_hop_missing_sends_nothing(world)
    assert world.socks.connections, "the weakened variant really did reach the SOCKS server"


def test_proof_a_direct_fallback_goes_red(world, monkeypatch):
    inv_closed_socks_port_fails_closed(world)
    original = world.tcurl.open_client

    class LeakyClient:
        def __init__(self, via_tor, direct):
            self.via_tor, self.direct = via_tor, direct
            self.cookies = via_tor.cookies

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            self.via_tor.close()
            self.direct.close()

        def build_request(self, *args, **kwargs):
            return self.via_tor.build_request(*args, **kwargs)

        def send(self, request, **kwargs):
            try:
                return self.via_tor.send(request, **kwargs)
            except httpx.ConnectError:
                plain = self.direct.build_request(request.method, str(request.url))
                return self.direct.send(plain, **kwargs)

    def leaky_open_client(plan, operation, options, *, insecure=False, hooks=None):
        via_tor = original(plan, operation, options, insecure=insecure, hooks=hooks)
        return LeakyClient(via_tor, egress.client(operation=operation, timeout=2, follow_redirects=False))

    monkeypatch.setattr(world.tcurl, "open_client", leaky_open_client)
    with pytest.raises(AssertionError):
        inv_closed_socks_port_fails_closed(world)
    assert world.trap.attempts, "the weakened variant really tried a direct connection"


def test_proof_remote_dns_holds(world):
    inv_remote_dns_only(world)


def test_proof_a_local_dns_lookup_goes_red(world, monkeypatch):
    original = world.tcurl.build_plan

    def resolving_build_plan(options):
        plan = original(options)
        try:
            socket.getaddrinfo(urlsplit(plan.url).hostname, 80)
        except socket.gaierror:
            pass
        return plan

    monkeypatch.setattr(world.tcurl, "build_plan", resolving_build_plan)
    with pytest.raises(AssertionError):
        inv_remote_dns_only(world)


def test_proof_one_credential_per_run_holds(world):
    inv_credential_rotates_per_run(world)


def test_proof_reusing_one_credential_across_runs_goes_red(world, monkeypatch):
    monkeypatch.setattr(world.tcurl, "new_isolation_token", lambda: "0123456789abcdef")
    with pytest.raises(AssertionError):
        inv_credential_rotates_per_run(world)


def test_proof_redirect_hop_scope_holds(world):
    inv_out_of_scope_hop_is_not_followed(world)


def test_proof_skipping_scope_on_redirect_hops_goes_red(world, monkeypatch):
    world.policy(extra=[])
    monkeypatch.setattr(world.tcurl, "hop_in_scope", lambda url: True)
    with pytest.raises(AssertionError):
        inv_out_of_scope_hop_is_not_followed(world)
    assert "outside.example" in world.socks.hosts()


def test_proof_the_not_tor_refusal_holds(world):
    inv_not_tor_exit_is_refused(world)


def test_proof_dropping_the_not_tor_refusal_goes_red(world, monkeypatch):
    monkeypatch.setattr(world.tcurl, "enforce_exit_state", lambda info: None)
    with pytest.raises(AssertionError):
        inv_not_tor_exit_is_refused(world)
    assert world.target_connections(), "the weakened variant contacted the target through a non-Tor exit"


def test_proof_the_exit_check_is_on_by_default(world):
    inv_exit_check_runs_by_default(world)


def test_proof_defaulting_no_exit_check_on_goes_red(world, monkeypatch):
    original = world.tcurl.build_parser

    def lax_parser():
        parser = original()
        parser.set_defaults(no_exit_check=True)
        return parser

    monkeypatch.setattr(world.tcurl, "build_parser", lax_parser)
    with pytest.raises(AssertionError):
        inv_exit_check_runs_by_default(world)


def test_proof_the_manifest_carries_the_route_but_no_credentials(world):
    inv_no_credentials_in_the_ledger(world)


def test_proof_putting_credentials_in_the_manifest_goes_red(world, monkeypatch):
    original = ledger.Capture.finish

    def leaky_finish(self, *args, **kwargs):
        seen = world.socks.connections[-1]
        if "route" in self.manifest:
            self.manifest["route"]["endpoint"] = f"socks5h://{seen.user}:{seen.password}@{self.manifest['route']['endpoint']}"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(ledger.Capture, "finish", leaky_finish)
    with pytest.raises(AssertionError):
        inv_no_credentials_in_the_ledger(world)
