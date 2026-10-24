"""Egress contract for a `socks5h` proxy: the gate still decides first, the hop is a policy asset, DNS stays remote.

Three additive contracts in `bughunt.core.egress` are pinned here, for the sync AND the async client:

C1  `authorize_proxy` accepts the scheme `socks5h` only, and authorizes the endpoint identifier
    `http://host:port` (default port 1080). Credentials in the proxy URL never take part and never appear in
    an error.
C2  `_Dispatch._native_setup` accepts a `socks5h` pool, keeps the version / no-retry / no-unix-socket checks, and
    authorizes the endpoint it reads from the pool itself (not from what the caller claimed).
C3  The run manifest records `route` = {"kind", "endpoint"} for any proxied request, never credentials.

A loopback fake SOCKS5 server stands in for Tor; a booby trap records any local DNS lookup or direct connect.
"""

from __future__ import annotations

import asyncio
import json
import re

import httpx
import pytest

from bughunt.core import egress, job, ledger
from socks_support import FakeSocks, NetworkTrap, asset, build_policy
from test_gate import boundaries, policy
from test_native_dispatch import _headers, _native

pytest.importorskip("socksio", reason="the SOCKS route needs socksio (pip install 'bughunt[tor]')")

SECRET = "hunter2-isolation"
TARGET = "http://target.example/"


class Lab:
    def __init__(self, monkeypatch, tmp_path):
        self.dir = tmp_path / "scope"
        self.dir.mkdir()
        self.socks = FakeSocks()
        self.trap = NetworkTrap().install(monkeypatch)
        self.trap.allow(self.socks.port)
        monkeypatch.setenv("BUGHUNT_SCOPE", str(self.dir))
        self.policy()

    def policy(self, **options) -> None:
        options.setdefault("hop_operations", ("manual",))
        options.setdefault("check", False)
        options.setdefault("onion", False)
        build_policy(self.dir, socks_port=self.socks.port, **options)

    @property
    def proxy(self) -> str:
        return f"socks5h://{SECRET}:{SECRET}@127.0.0.1:{self.socks.port}"

    def manifest(self, response) -> dict:
        return ledger.manifest_for(response.extensions["bughunt_run_id"])

    def all_text(self) -> str:
        return "\n".join(path.read_bytes().decode("latin-1") for path in self.dir.rglob("*")
                         if path.is_file() and path.name not in {"policy.json"})


@pytest.fixture
def lab(monkeypatch, tmp_path):
    created = Lab(monkeypatch, tmp_path)
    yield created
    created.socks.close()


# ---------------------------------------------------------------------------------------------
# C1: authorize_proxy
# ---------------------------------------------------------------------------------------------


def blocked(call, pattern: str) -> None:
    """Plain-assert twin of pytest.raises, so a failed invariant is an AssertionError a mutation test can expect."""
    try:
        call()
    except egress.PolicyBlocked as refusal:
        assert re.search(pattern, str(refusal)), str(refusal)
        return
    raise AssertionError(f"expected a policy block matching {pattern!r}")


def inv_missing_hop_blocks_before_any_connection(lab: Lab) -> None:
    lab.policy(hop=False)
    with egress.client(operation="manual", proxy=lab.proxy, timeout=3) as client:
        blocked(lambda: client.get(TARGET), "asset-unknown")
    assert lab.socks.connections == [] and lab.trap.attempts == []


def inv_transport_form_missing_hop_blocks(lab: Lab) -> None:
    lab.policy(hop=False)
    transport = httpx.HTTPTransport(proxy=lab.proxy, trust_env=False)
    with egress.client(operation="manual", transport=transport, timeout=3) as client:
        blocked(lambda: client.get(TARGET), "asset-unknown")
    assert lab.socks.connections == []


def inv_socks5_without_h_is_rejected(lab: Lab) -> None:
    for scheme in ("socks5", "socks4", "socks4a"):
        blocked(lambda: egress.authorize_proxy(f"{scheme}://127.0.0.1:{lab.socks.port}", "manual"),
                "proxy-invalid-or-unsupported")


def test_a_granted_socks5h_hop_is_authorized_and_credentials_do_not_matter(lab):
    egress.authorize_proxy(lab.proxy, "manual")
    egress.authorize_proxy(f"socks5h://127.0.0.1:{lab.socks.port}", "manual")


def test_a_missing_hop_row_is_refused_and_the_error_does_not_echo_credentials(lab):
    lab.policy(hop=False)
    with pytest.raises(egress.PolicyBlocked, match="asset-unknown") as raised:
        egress.authorize_proxy(lab.proxy, "manual")
    assert SECRET not in str(raised.value)


def test_the_hop_row_must_allow_the_operation_and_the_get_method(lab):
    lab.policy(hop_operations=("passive",))
    with pytest.raises(egress.PolicyBlocked, match="asset-method-disallowed"):
        egress.authorize_proxy(lab.proxy, "manual")
    lab.policy(hop_methods=("POST",))
    with pytest.raises(egress.PolicyBlocked, match="asset-method-disallowed"):
        egress.authorize_proxy(lab.proxy, "manual")


def test_only_socks5h_is_accepted_of_the_socks_schemes(lab):
    inv_socks5_without_h_is_rejected(lab)


def test_the_default_socks_port_is_1080(lab):
    with pytest.raises(egress.PolicyBlocked, match="asset-unknown"):
        egress.authorize_proxy("socks5h://127.0.0.1", "manual")
    lab.policy(extra=[asset("socks-default", "http://127.0.0.1:1080", ["/"], ["manual"], ["GET"])])
    egress.authorize_proxy("socks5h://127.0.0.1", "manual")


def test_ipv6_and_hostname_endpoints_use_the_same_identifier_form(lab):
    lab.policy(extra=[asset("v6", "http://[::1]:9050", ["/"], ["manual"], ["GET"]),
                      asset("named", "http://tor.internal:9050", ["/"], ["manual"], ["GET"])])
    egress.authorize_proxy("socks5h://[::1]:9050", "manual")
    egress.authorize_proxy("socks5h://tor.internal:9050", "manual")
    with pytest.raises(egress.PolicyBlocked, match="asset-unknown"):
        egress.authorize_proxy("socks5h://other.internal:9050", "manual")


@pytest.mark.parametrize("proxy", ["socks5h://", "socks5h:///x", "ftp://127.0.0.1:9050", "127.0.0.1:9050"])
def test_a_proxy_without_a_host_or_with_another_scheme_is_invalid(lab, proxy):
    with pytest.raises(egress.PolicyBlocked, match="proxy-invalid-or-unsupported"):
        egress.authorize_proxy(proxy, "manual")


def test_http_proxy_identifiers_are_unchanged(lab):
    lab.policy(extra=[asset("p", "http://proxy.example:8080", ["/"], ["manual"], ["GET"])])
    egress.authorize_proxy("http://proxy.example:8080", "manual")
    with pytest.raises(egress.PolicyBlocked, match="asset-unknown"):
        egress.authorize_proxy("http://other-proxy.example:8080", "manual")


# ---------------------------------------------------------------------------------------------
# C2: the client and the native dispatch seam (sync)
# ---------------------------------------------------------------------------------------------


def test_a_socks5h_client_routes_through_the_proxy_with_remote_dns(lab):
    with egress.client(operation="manual", proxy=lab.proxy, timeout=3) as client:
        response = client.get(TARGET)
    seen = lab.socks.connections[0]
    assert response.status_code == 200 and response.text == "hello via fake tor"
    assert (seen.host, seen.atyp, seen.port) == ("target.example", 3, 80)
    assert (seen.user, seen.password) == (SECRET, SECRET)
    assert lab.trap.attempts == []


def test_the_policy_gate_still_decides_before_the_proxy_is_used(lab):
    with egress.client(operation="manual", proxy=lab.proxy, timeout=3) as client:
        with pytest.raises(egress.PolicyBlocked, match="asset-unknown"):
            client.get("http://nopolicy.example/")
        with pytest.raises(egress.PolicyBlocked, match="asset-method-disallowed"):
            client.request("DELETE", TARGET)
    assert lab.socks.connections == []


def test_a_missing_hop_row_blocks_the_client_before_any_connection(lab):
    inv_missing_hop_blocks_before_any_connection(lab)


def test_the_transport_form_is_authorized_from_the_pool_not_from_the_caller(lab):
    transport = httpx.HTTPTransport(proxy=lab.proxy, trust_env=False)
    with egress.client(operation="manual", transport=transport, timeout=3) as client:
        assert client.get(TARGET).status_code == 200
    lab.socks.connections.clear()
    inv_transport_form_missing_hop_blocks(lab)


def test_socks5_without_h_is_blocked_by_two_independent_walls(lab):
    transport = httpx.HTTPTransport(proxy=f"socks5://127.0.0.1:{lab.socks.port}", trust_env=False)
    with egress.client(operation="manual", transport=transport, timeout=3) as client:
        with pytest.raises(egress.PolicyBlocked, match="native-dispatch-proxy-unsupported"):
            client.get(TARGET)
    with pytest.raises(egress.PolicyBlocked, match="proxy-invalid-or-unsupported"):
        with egress.client(operation="manual", proxy=f"socks5://127.0.0.1:{lab.socks.port}", timeout=3) as client:
            client.get(TARGET)
    assert lab.socks.connections == [] and lab.trap.attempts == []


def test_even_with_authorize_proxy_neutralised_socks5_cannot_dispatch(lab, monkeypatch):
    monkeypatch.setattr(egress, "authorize_proxy", lambda proxy, operation: None)
    with egress.client(operation="manual", proxy=f"socks5://127.0.0.1:{lab.socks.port}", timeout=3) as client:
        with pytest.raises(egress.PolicyBlocked, match="native-dispatch-proxy-unsupported"):
            client.get(TARGET)
    assert lab.socks.connections == []


@pytest.mark.parametrize("fault", ["retries", "uds"])
def test_native_layout_drift_still_blocks_a_socks_route(lab, fault):
    transport = httpx.HTTPTransport(proxy=lab.proxy, trust_env=False)
    if fault == "retries":
        transport._pool._retries = 1
    else:
        transport._pool._uds = "owned.socket"
    with egress.client(operation="manual", transport=transport, timeout=3) as client:
        with pytest.raises(egress.PolicyBlocked, match="retry-or-socket-route"):
            client.get(TARGET)
    assert lab.socks.connections == []


def test_a_connect_request_is_refused_on_a_socks_route(lab):
    lab.policy(extra=[asset("c", "http://connect.example", ["/"], ["manual"], ["CONNECT"])])
    with egress.client(operation="manual", proxy=lab.proxy, timeout=3) as client:
        with pytest.raises(egress.PolicyBlocked, match="nested-proxy-connect-unsupported"):
            client.request("CONNECT", "http://connect.example/")
    assert lab.socks.connections == []


def test_a_non_native_transport_cannot_be_combined_with_a_proxy(lab):
    budget = job.Budget(frozenset({("GET", TARGET)}), 1, 10)
    with pytest.raises(egress.PolicyBlocked, match="managed-transport-proxy"):
        egress.client(transport=job.Transport(budget), proxy=lab.proxy)


# ---------------------------------------------------------------------------------------------
# C2: the async client shares the same setup
# (The event loop is created before the network trap is installed: the Windows proactor loop opens a loopback
# self-pipe at creation. The trap's DNS lookup recording still covers the async path; its connect recording
# does not see overlapped connects, so the async proofs rest on the fake server's connection log.)
# ---------------------------------------------------------------------------------------------


@pytest.fixture
def loop():
    created = asyncio.new_event_loop()
    yield created
    created.close()


@pytest.fixture
def async_lab(loop, monkeypatch, tmp_path):
    created = Lab(monkeypatch, tmp_path)
    yield created
    created.socks.close()


def test_the_async_client_routes_through_the_proxy_with_remote_dns(loop, async_lab):
    lab = async_lab

    async def go():
        async with egress.async_client(operation="manual", proxy=lab.proxy, timeout=3) as client:
            return await client.get(TARGET)

    response = loop.run_until_complete(go())
    seen = lab.socks.connections[0]
    assert response.status_code == 200 and (seen.host, seen.atyp) == ("target.example", 3)
    assert lab.trap.attempts == []
    assert lab.manifest(response)["route"] == {"kind": "socks5h", "endpoint": lab.socks.endpoint}


def test_the_async_client_blocks_a_missing_hop_and_socks5(loop, async_lab):
    lab = async_lab

    async def blocked_get(proxy, pattern):
        async with egress.async_client(operation="manual", proxy=proxy, timeout=3) as client:
            with pytest.raises(egress.PolicyBlocked, match=pattern):
                await client.get(TARGET)

    lab.policy(hop=False)
    loop.run_until_complete(blocked_get(lab.proxy, "asset-unknown"))
    lab.policy()
    loop.run_until_complete(blocked_get(f"socks5://127.0.0.1:{lab.socks.port}", "proxy-invalid-or-unsupported"))
    assert lab.socks.connections == [] and lab.trap.attempts == []


def test_the_async_transport_form_is_authorized_from_the_pool(loop, async_lab):
    lab = async_lab
    lab.policy(hop=False)

    async def go():
        transport = httpx.AsyncHTTPTransport(proxy=lab.proxy, trust_env=False)
        async with egress.async_client(operation="manual", transport=transport, timeout=3) as client:
            with pytest.raises(egress.PolicyBlocked, match="asset-unknown"):
                await client.get(TARGET)

    loop.run_until_complete(go())
    assert lab.socks.connections == []


# ---------------------------------------------------------------------------------------------
# C3: the ledger records the route and never credentials
# ---------------------------------------------------------------------------------------------


def test_the_manifest_records_the_socks_route_without_credentials(lab):
    with egress.client(operation="manual", proxy=lab.proxy, timeout=3) as client:
        response = client.get(TARGET)
    manifest = lab.manifest(response)
    assert manifest["route"] == {"kind": "socks5h", "endpoint": lab.socks.endpoint}
    assert manifest["schema_version"] == 1 and manifest["classification"] == "observation"
    assert SECRET not in lab.all_text()


def test_exporting_a_run_with_a_route_works_and_stays_credential_free(lab):
    with egress.client(operation="manual", proxy=lab.proxy, timeout=3) as client:
        response = client.get(TARGET)
    exported = ledger.export_run(response.extensions["bughunt_run_id"])
    assert exported["manifest"]["route"] == {"kind": "socks5h", "endpoint": lab.socks.endpoint}
    assert SECRET not in json.dumps(exported)


def test_a_direct_request_has_no_route_key(lab):
    with egress.client(operation="manual", transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
        response = client.get(TARGET)
    assert "route" not in lab.manifest(response)


def test_an_http_proxy_route_is_recorded_as_http_proxy(policy, boundaries, monkeypatch):
    def respond(request):
        _headers(request, method=b"CONNECT")
        _headers(request)
        return httpx.Response(200)
    transport = _native(monkeypatch, respond, proxy="http://proxy.example:8080")
    with egress.client(transport=transport) as client:
        response = client.get("https://allowed.example/")
    manifest = ledger.manifest_for(response.extensions["bughunt_run_id"])
    assert manifest["route"] == {"kind": "http-proxy", "endpoint": "proxy.example:8080"}


# ---------------------------------------------------------------------------------------------
# Mutation proofs: weakening the egress contract must turn its invariant red
# ---------------------------------------------------------------------------------------------


def test_proof_hop_authorization_holds(lab):
    inv_missing_hop_blocks_before_any_connection(lab)
    inv_transport_form_missing_hop_blocks(lab)


def test_proof_dropping_authorize_proxy_goes_red(lab, monkeypatch):
    monkeypatch.setattr(egress, "authorize_proxy", lambda proxy, operation: None)
    with pytest.raises(AssertionError):
        inv_missing_hop_blocks_before_any_connection(lab)
    assert lab.socks.connections, "the weakened variant really reached the SOCKS server"


def test_proof_accepting_plain_socks5_goes_red(lab, monkeypatch):
    inv_socks5_without_h_is_rejected(lab)
    original = egress.authorize_proxy
    monkeypatch.setattr(egress, "authorize_proxy",
                        lambda proxy, operation: original(proxy.replace("socks5://", "socks5h://"), operation))
    with pytest.raises(AssertionError):
        inv_socks5_without_h_is_rejected(lab)


def test_proof_trusting_the_caller_instead_of_the_pool_goes_red(lab, monkeypatch):
    """If _native_setup stopped authorizing the endpoint it reads from the pool, a transport-form proxy would slip through."""
    original = egress._Dispatch._native_setup

    def trusting_setup(self, transport):
        proxy = getattr(getattr(transport, "_pool", None), "_proxy_url", None)
        if proxy is not None and proxy.scheme == b"socks5h":
            return None
        return original(self, transport)

    monkeypatch.setattr(egress._Dispatch, "_native_setup", trusting_setup)
    with pytest.raises(AssertionError):
        inv_transport_form_missing_hop_blocks(lab)
    assert lab.socks.connections, "the weakened variant really reached the SOCKS server"
