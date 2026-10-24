"""Characterization oracle for bughunt.core.http (M2 REST-OF-CORE).

Written BEFORE the clean-room rebuild. Vectors are the M2 spec (section 5, A.6 to
A.8) plus runs of the tree this branch was cut from.

Mocking happens only at the egress/httpx edge: `egress.client` is substituted
through the module attribute (the contract is "looked up at call time"), and
requests are answered by httpx.MockTransport. Nothing here patches an attribute
of workspace, session or http, and no test touches the network.
"""

import gzip
import os
import ssl
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from bughunt import VERSION
from bughunt.core import egress, http, identity, session
from test_gate import policy  # noqa: F401  (fixture)

REPO_ROOT = Path(__file__).resolve().parents[1]
SENTINEL = object()


@pytest.fixture
def ws(monkeypatch, tmp_path):
    root = tmp_path / "ws"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    monkeypatch.chdir(tmp_path)
    return root


@pytest.fixture
def captured(monkeypatch):
    """Substitute egress.client; record the keyword arguments of each call."""
    calls = []

    def fake(**kwargs):
        calls.append(kwargs)
        return SENTINEL

    monkeypatch.setattr(egress, "client", fake)
    return calls


# --------------------------------------------------------------------------
# client(): what is handed to egress.client (spec 5.2, A.6)
# --------------------------------------------------------------------------

def test_client_hands_egress_exactly_the_documented_keywords(ws, captured):
    result = http.client(7.5)
    assert result is SENTINEL
    assert captured == [{
        "operation": "manual", "timeout": 7.5, "follow_redirects": False, "trust_env": False,
        "verify": True,
        "headers": {"User-Agent": f"Bughunt/{VERSION}", "Accept-Encoding": "identity"},
    }]


def test_client_insecure_flag_turns_verification_off(ws, captured):
    http.client(1, insecure=True)
    http.client(1, insecure=False)
    assert [call["verify"] for call in captured] == [False, True]


def test_client_merges_caller_headers_over_the_defaults_and_applies_flags(ws, captured):
    http.client(3, insecure=True, cookie=" c=1 ", authorization="Bearer z",
                headers={"X-A": "1", "User-Agent": "mine"})
    call = captured[0]
    assert call["verify"] is False and call["timeout"] == 3
    assert call["headers"] == {"User-Agent": "mine", "Accept-Encoding": "identity", "X-A": "1",
                               "Cookie": "c=1", "Authorization": "Bearer z"}


def test_client_none_flags_use_the_saved_session(ws, captured):
    session.write_session({"cookie": "saved=1", "authorization": "Bearer saved"})
    http.client(3)
    assert captured[0]["headers"]["Cookie"] == "saved=1"
    assert captured[0]["headers"]["Authorization"] == "Bearer saved"


def test_client_text_flags_override_the_saved_session(ws, captured):
    session.write_session({"cookie": "saved=1", "authorization": "Bearer saved"})
    http.client(3, cookie="flag=1")
    assert captured[0]["headers"]["Cookie"] == "flag=1"
    assert captured[0]["headers"]["Authorization"] == "Bearer saved"


def test_client_empty_flags_send_neither_even_with_a_saved_session(ws, captured):
    session.write_session({"cookie": "saved=1", "authorization": "Bearer saved"})
    http.client(3, cookie="", authorization="")
    assert "Cookie" not in captured[0]["headers"]
    assert "Authorization" not in captured[0]["headers"]


def test_client_drops_a_cookie_passed_in_headers_when_nothing_supplies_one(ws, captured):
    http.client(3, headers={"Cookie": "fromheaders=1"})
    assert "Cookie" not in captured[0]["headers"]


def test_client_timeout_is_the_only_positional_parameter(ws, captured):
    with pytest.raises(TypeError):
        http.client(1, True)
    with pytest.raises(TypeError):
        http.client()
    assert captured == []


def test_client_looks_egress_up_through_the_module_at_call_time(ws, monkeypatch):
    first, second = object(), object()
    monkeypatch.setattr(egress, "client", lambda **kwargs: first)
    assert http.client(1) is first
    monkeypatch.setattr(egress, "client", lambda **kwargs: second)
    assert http.client(1) is second


def test_client_real_object_never_follows_redirects_and_ignores_the_environment(ws, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:9")
    with http.client(2.0) as built:
        assert isinstance(built, httpx.Client)
        assert built.follow_redirects is False
        assert built.timeout == httpx.Timeout(2.0)
        assert built._trust_env is False
        assert built.headers["User-Agent"] == f"Bughunt/{VERSION}"
        assert built.headers["Accept-Encoding"] == "identity"


def test_client_real_object_verifies_certificates_unless_insecure(ws):
    # Reads httpx 0.28.1 / httpcore 1.0.9 internals (both pinned in pyproject.toml); the
    # `verify=` keyword handed to egress.client is also pinned above without internals.
    with http.client(2.0) as strict, http.client(2.0, insecure=True) as lax:
        assert strict._transport._pool._ssl_context.verify_mode == ssl.CERT_REQUIRED
        assert lax._transport._pool._ssl_context.verify_mode == ssl.CERT_NONE


# --------------------------------------------------------------------------
# client(): wire facts through the real egress (spec 6.2, A.6)
# --------------------------------------------------------------------------

@pytest.fixture
def wire(monkeypatch):
    """Route egress.client onto a recording MockTransport; policy and actor logic stay real."""
    real = egress.client
    seen = []

    def build(**kwargs):
        kwargs["transport"] = httpx.MockTransport(
            lambda request: (seen.append(request), httpx.Response(200))[1])
        return real(**kwargs)

    monkeypatch.setattr(egress, "client", build)
    return seen


def test_wire_user_agent_is_the_policys_and_encoding_is_identity(policy, wire):
    document, _root = policy
    with http.client(3) as built:
        built.get("https://allowed.example/")
    assert wire[0].headers["User-Agent"] == document["user_agent"]
    assert wire[0].headers["Accept-Encoding"] == "identity"


def test_wire_default_actor_flags_and_saved_session_pass_through(policy, wire):
    session.write_session({"cookie": "saved=1", "authorization": "Bearer saved"})
    with http.client(3) as saved_client:
        saved_client.get("https://allowed.example/")
    with http.client(3, cookie="flag=1") as flag_client:
        flag_client.get("https://allowed.example/")
    with http.client(3, cookie="", authorization="") as empty_client:
        empty_client.get("https://allowed.example/")
    rows = [(request.headers.get("Cookie"), request.headers.get("Authorization")) for request in wire]
    assert rows == [("saved=1", "Bearer saved"), ("flag=1", "Bearer saved"), (None, None)]


def test_wire_named_actor_credentials_replace_flags_and_saved_session(policy, wire):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.set_credential("owner", "cookie", "session=actor")
    identity.use_profile("owner")
    with http.client(3, cookie="flag=1", authorization="Bearer flag") as built:
        built.get("https://allowed.example/")
    assert wire[0].headers["Cookie"] == "session=actor"
    assert "Authorization" not in wire[0].headers


# --------------------------------------------------------------------------
# redirect_target (spec 5.2, A.7)
# --------------------------------------------------------------------------

def redirect(status, location=None):
    headers = {} if location is None else {"Location": location}
    return httpx.Response(status, headers=headers)


BASE = "http://a.example/x/y"


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_target_follows_the_five_redirect_statuses(status):
    assert http.redirect_target(BASE, redirect(status, "../z?q=1")) == "http://a.example/z?q=1"


@pytest.mark.parametrize("status", [200, 204, 300, 304, 305, 306, 404, 500])
def test_redirect_target_ignores_every_other_status(status):
    assert http.redirect_target(BASE, redirect(status, "../z?q=1")) == ""


@pytest.mark.parametrize("current, location, expected", [
    (BASE, "https://evil.example/p", "https://evil.example/p"),
    (BASE, "  /p  ", "http://a.example/p"),
    (BASE, "../z?q=1", "http://a.example/z?q=1"),
    (BASE, "sibling", "http://a.example/x/sibling"),
    ("https://a.example/x/y", "//b.example/q", "https://b.example/q"),
    ("http://a.example/x/y?old=1", "?n=2", "http://a.example/x/y?n=2"),
    (BASE, "ftp://f.example/", "ftp://f.example/"),
])
def test_redirect_target_resolves_the_location_against_the_current_url(current, location, expected):
    assert http.redirect_target(current, redirect(302, location)) == expected


@pytest.mark.parametrize("location", [None, "", "   "])
def test_redirect_target_missing_or_blank_location_is_empty(location):
    assert http.redirect_target(BASE, redirect(302, location)) == ""


def test_redirect_target_reads_location_case_insensitively():
    response = httpx.Response(302, headers={"LOCATION": "/p"})
    assert http.redirect_target(BASE, response) == "http://a.example/p"


def test_redirect_target_does_no_scope_check():
    assert http.redirect_target(BASE, redirect(301, "http://169.254.169.254/")) == \
        "http://169.254.169.254/"


def test_redirect_statuses_constant():
    assert http.REDIRECT_STATUSES == frozenset({301, 302, 303, 307, 308})


# --------------------------------------------------------------------------
# HostNotAllowed / host_listed (spec 5.2, A.7)
# --------------------------------------------------------------------------

def test_host_not_allowed_is_an_httpx_error_but_not_a_value_error():
    assert issubclass(http.HostNotAllowed, httpx.HTTPError)
    assert not issubclass(http.HostNotAllowed, ValueError)
    error = http.HostNotAllowed("evil.example is not listed")
    assert str(error) == "evil.example is not listed"
    with pytest.raises(httpx.HTTPError):
        raise error


@pytest.mark.parametrize("host, hosts, expected", [
    ("api.example", {"api.example"}, True),
    ("API.Example.", {"api.example"}, True),
    ("sub.api.example", {"api.example"}, True),
    ("a.b.api.example", {"api.example"}, True),
    ("notapi.example", {"api.example"}, False),
    ("evilapi.example", {"api.example"}, False),
    ("api.example.evil.net", {"api.example"}, False),
    ("example", {"api.example"}, False),
    ("api.example", {"API.example"}, False),
    ("a.b", {"b"}, True),
    ("", {""}, True),
    ("x.example", {"y.example", "x.example"}, True),
    ("x.example", set(), False),
])
def test_host_listed_vectors(host, hosts, expected):
    assert http.host_listed(host, frozenset(hosts)) is expected


# --------------------------------------------------------------------------
# api_client (spec 5.2, A.6)
# --------------------------------------------------------------------------

def test_api_client_hands_egress_exactly_the_documented_keywords(captured):
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    result = http.api_client(frozenset({"api.example"}), timeout=3, headers={"X-K": "v"},
                             transport=transport)
    assert result is SENTINEL
    call = captured[0]
    assert set(call) == {"operation", "timeout", "follow_redirects", "trust_env", "headers",
                         "transport", "event_hooks"}
    assert call["operation"] == "passive"
    assert (call["timeout"], call["follow_redirects"], call["trust_env"]) == (3, False, False)
    assert call["headers"] == {"X-K": "v"} and call["transport"] is transport
    assert list(call["event_hooks"]) == ["request"] and len(call["event_hooks"]["request"]) == 1


def test_api_client_defaults_pass_none_for_headers_and_transport(captured):
    http.api_client(frozenset({"api.example"}), timeout=1)
    assert captured[0]["headers"] is None and captured[0]["transport"] is None


def test_api_client_parameters_after_hosts_are_keyword_only(captured):
    with pytest.raises(TypeError):
        http.api_client(frozenset({"api.example"}), 3)
    with pytest.raises(TypeError):
        http.api_client(frozenset({"api.example"}))


def test_api_client_guard_blocks_unlisted_hosts_and_names_the_host(captured):
    http.api_client(frozenset({"api.example"}), timeout=1)
    guard = captured[0]["event_hooks"]["request"][0]
    assert guard(httpx.Request("GET", "https://api.example/x")) is None
    assert guard(httpx.Request("GET", "https://SUB.API.example./x")) is None
    with pytest.raises(http.HostNotAllowed) as caught:
        guard(httpx.Request("GET", "https://evil.example/x"))
    assert "evil.example" in str(caught.value)
    with pytest.raises(http.HostNotAllowed):
        guard(httpx.Request("GET", "https://notapi.example/x"))


def recording_transport(responder=None):
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return responder(request) if responder else httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(handler), seen


def test_api_client_real_object_defaults(policy):
    transport, _seen = recording_transport()
    with http.api_client(frozenset({"api.example"}), timeout=3, headers={"X-K": "v"},
                         transport=transport) as built:
        assert built.follow_redirects is False
        assert built._trust_env is False
        assert len(built.event_hooks["request"]) == 1
        assert built.headers["X-K"] == "v"
        assert built.headers["User-Agent"].startswith("python-httpx/")
        assert built.headers["Accept-Encoding"] != "identity"


def test_api_client_unlisted_host_never_reaches_the_transport(policy):
    transport, seen = recording_transport()
    with http.api_client(frozenset({"api.example"}), timeout=1, transport=transport) as built:
        with pytest.raises(http.HostNotAllowed):
            built.get("https://evil.example/", headers={"Auth-Key": "secret"})
        assert built.get("https://api.example/ok").status_code == 200
    assert seen == ["https://api.example/ok"]


def test_api_client_listed_host_is_still_subject_to_egress_policy(policy):
    transport, seen = recording_transport()
    with http.api_client(frozenset({"allowed.example"}), timeout=1, transport=transport) as built:
        assert built.get("https://www.allowed.example/").status_code == 200
        with pytest.raises(egress.PolicyBlocked):
            built.get("https://sub.allowed.example/")
    assert seen == ["https://www.allowed.example/"]


# --------------------------------------------------------------------------
# get_following (spec 5.2, A.8)
# --------------------------------------------------------------------------

def chain_transport(final_after=None):
    """/start -> /r1 -> /r2 ... (all 302); optionally answer 200 at /r<final_after>."""
    seen = []

    def handler(request):
        seen.append(request)
        path = request.url.path
        step = 0 if path == "/start" else int(path[2:])
        if final_after is not None and step >= final_after:
            return httpx.Response(200, text="done")
        return httpx.Response(302, headers={"Location": f"/r{step + 1}"})

    return httpx.MockTransport(handler), seen


@pytest.mark.parametrize("limit, requested", [(None, 6), (5, 6), (2, 3), (1, 2), (0, 1)])
def test_get_following_request_count_is_limit_plus_one(limit, requested):
    transport, seen = chain_transport()
    kwargs = {} if limit is None else {"limit": limit}
    with httpx.Client(transport=transport) as plain:
        last = http.get_following(plain, "http://api.example/start", **kwargs)
    assert len(seen) == requested
    assert [request.url.path for request in seen] == ["/start"] + [f"/r{n}" for n in range(1, requested)]
    assert last.status_code == 302
    assert last.url.path == seen[-1].url.path


def test_get_following_stops_at_the_first_non_redirect():
    transport, seen = chain_transport(final_after=2)
    with httpx.Client(transport=transport) as plain:
        last = http.get_following(plain, "http://api.example/start")
    assert [request.url.path for request in seen] == ["/start", "/r1", "/r2"]
    assert (last.status_code, last.text) == (200, "done")


def test_get_following_non_redirect_makes_one_request():
    transport, seen = chain_transport(final_after=0)
    with httpx.Client(transport=transport) as plain:
        assert http.get_following(plain, "http://api.example/start").status_code == 200
    assert len(seen) == 1


def test_get_following_sends_params_once_and_resends_other_keywords_on_every_hop():
    transport, seen = chain_transport(final_after=2)
    with httpx.Client(transport=transport) as plain:
        http.get_following(plain, "http://api.example/start", params={"q": "1"},
                           headers={"X-T": "tok"})
    assert [request.url.query for request in seen] == [b"q=1", b"", b""]
    assert [request.headers["X-T"] for request in seen] == ["tok", "tok", "tok"]


def test_get_following_resolves_each_hop_against_the_latest_response_url():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.path == "/a/b":
            return httpx.Response(302, headers={"Location": "../c"})
        if request.url.path == "/c":
            return httpx.Response(301, headers={"Location": "https://other.example/d"})
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(handler)) as plain:
        http.get_following(plain, "http://api.example/a/b")
    assert seen == ["http://api.example/a/b", "http://api.example/c", "https://other.example/d"]


def test_get_following_with_api_client_refuses_an_off_host_hop_after_one_request(policy):
    transport, seen = recording_transport(lambda request: httpx.Response(
        302, headers={"Location": "https://evil.example/steal"}))
    with http.api_client(frozenset({"api.example"}), timeout=1, transport=transport) as built:
        with pytest.raises(http.HostNotAllowed):
            http.get_following(built, "https://api.example/start", headers={"Auth-Key": "k"})
    assert seen == ["https://api.example/start"]


def test_get_following_with_api_client_follows_listed_hops(policy):
    def responder(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "https://crt.sh/next"})
        return httpx.Response(200, text="arrived")

    transport, seen = recording_transport(responder)
    with http.api_client(frozenset({"api.example", "crt.sh"}), timeout=1,
                         transport=transport) as built:
        last = http.get_following(built, "https://api.example/start")
    assert seen == ["https://api.example/start", "https://crt.sh/next"]
    assert last.text == "arrived"


# --------------------------------------------------------------------------
# read_body (spec 5.2, A.8)
# --------------------------------------------------------------------------

def streamed(chunks, headers=None):
    def handler(request):
        return httpx.Response(200, headers=headers or {}, content=iter(chunks))

    return httpx.Client(transport=httpx.MockTransport(handler))


CHUNKS = [b"abc", b"def", b"ghi", b"jkl"]


@pytest.mark.parametrize("limit, expected", [
    (0, b""), (1, b"a"), (3, b"abc"), (4, b"abcd"), (6, b"abcdef"), (7, b"abcdefg"),
    (12, b"abcdefghijkl"), (13, b"abcdefghijkl"), (100, b"abcdefghijkl"), (-1, b""),
])
def test_read_body_truncates_a_streamed_response_to_the_limit(limit, expected):
    with streamed(CHUNKS) as http_client:
        with http_client.stream("GET", "http://x.example/") as response:
            assert http.read_body(response, limit) == expected


def test_read_body_empty_and_empty_chunk_streams():
    assert http.read_body(httpx.Response(200, content=iter([])), 5) == b""
    assert http.read_body(httpx.Response(200, content=iter([b"", b"ab", b""])), 5) == b"ab"


def test_read_body_works_on_an_already_read_response():
    assert http.read_body(httpx.Response(200, content=b"0123456789"), 4) == b"0123"
    assert http.read_body(httpx.Response(200, content=b"0123456789"), 99) == b"0123456789"


def test_read_body_counts_decoded_bytes():
    body = gzip.compress(b"hello world")
    with streamed([body], headers={"Content-Encoding": "gzip"}) as http_client:
        with http_client.stream("GET", "http://x.example/") as response:
            assert http.read_body(response, 5) == b"hello"
    with streamed([body], headers={"Content-Encoding": "gzip"}) as http_client:
        with http_client.stream("GET", "http://x.example/") as response:
            assert http.read_body(response, 500) == b"hello world"


def test_read_body_never_exceeds_the_limit_for_one_oversized_chunk():
    with streamed([b"x" * 100_000]) as http_client:
        with http_client.stream("GET", "http://x.example/") as response:
            assert http.read_body(response, 10) == b"x" * 10


def test_read_body_does_not_close_the_response():
    with streamed(CHUNKS) as http_client:
        with http_client.stream("GET", "http://x.example/") as response:
            http.read_body(response, 4)
            assert response.is_closed is False


# --------------------------------------------------------------------------
# import contract (spec 2.1)
# --------------------------------------------------------------------------

def test_importing_http_has_no_effects(tmp_path):
    probe = (
        "import os, sys\n"
        f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "before = set(os.listdir('.'))\n"
        "import bughunt.core.http\n"
        "assert set(os.listdir('.')) == before, 'import created files'\n"
    )
    env = {key: value for key, value in os.environ.items() if key != "BUGHUNT_SCOPE"}
    done = subprocess.run([sys.executable, "-c", probe], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
