"""Network-free regressions for re-enabled addons. Each addon must stay inside scope."""

import asyncio
from pathlib import Path

import httpx
import pytest

from bughunt.console import loader
from bughunt.console.catalog import DISABLED_REFERENCES
from bughunt.core.http import HostNotAllowed, api_client
from bughunt.core import scanner as bughunt_scanner
from test_gate import seed_policy


@pytest.fixture(autouse=True)
def permitted_fixture_policy(monkeypatch, tmp_path):
    workspace = tmp_path / "default-policy"
    seed_policy(workspace)
    monkeypatch.setenv("BUGHUNT_SCOPE", str(workspace))


ADDONS = Path(bughunt_scanner.__file__).parents[2] / "addons"


def _scope(monkeypatch, tmp_path):
    workspace = tmp_path / "scope"
    workspace.mkdir()
    (workspace / "scope.txt").write_text("allowed.example\n", encoding="utf-8")
    seed_policy(workspace)
    monkeypatch.setenv("BUGHUNT_SCOPE", str(workspace))


def _recording_transport(routes):
    """MockTransport that records every URL it is asked for. Unknown URLs fail the test."""
    seen = []

    def handler(request):
        url = str(request.url)
        seen.append(url)
        if url not in routes:
            raise AssertionError(f"unexpected request {url}")
        status, headers = routes[url]
        return httpx.Response(status, headers=headers, request=request)

    return httpx.MockTransport(handler), seen


def _pulse():
    return loader.import_script(ADDONS / "pulse" / "pulse.py")


def _addon(folder, script):
    return loader.import_script(ADDONS / folder / script)


def _sync_transport(routes):
    """Sync twin of _recording_transport. Values are (status, headers, body)."""
    seen = []

    def handler(request):
        url = str(request.url)
        seen.append(url)
        if url not in routes:
            raise AssertionError(f"unexpected request {url}")
        status, headers, body = routes[url]
        return httpx.Response(status, headers=headers, content=body, request=request)

    return httpx.MockTransport(handler), seen


def test_api_client_blocks_unlisted_host_before_send():
    transport, seen = _sync_transport({})
    with api_client(frozenset({"api.example"}), timeout=1, transport=transport) as http:
        with pytest.raises(HostNotAllowed):
            http.get("https://evil.example/", headers={"Auth-Key": "secret"})
    assert seen == []


@pytest.mark.parametrize(
    "name", ["carve", "pulse", "ioc", "chroma", "phish", "urlscan", "ct", "tcurl"]
)
def test_reviewed_addon_is_enabled(name):
    assert name not in DISABLED_REFERENCES


def test_pulse_skips_out_of_scope_url_without_a_request(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    pulse = _pulse()
    transport, seen = _recording_transport({})

    async def go():
        async with httpx.AsyncClient(transport=transport) as client:
            return await pulse.check_one(
                client, "https://outside.example/", follow=False, retries=0
            )

    result = asyncio.run(go())

    assert seen == []
    assert result.ok is False
    assert "scope" in result.error


def test_pulse_does_not_follow_redirect_out_of_scope(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    pulse = _pulse()
    transport, seen = _recording_transport(
        {
            "https://allowed.example/": (
                302,
                {"location": "https://outside.example/landing"},
            )
        }
    )

    async def go():
        async with httpx.AsyncClient(transport=transport) as client:
            return await pulse.check_one(
                client, "https://allowed.example/", follow=True, retries=0
            )

    result = asyncio.run(go())

    assert seen == ["https://allowed.example/"]
    assert result.status == 302
    assert "outside.example" in result.error


def test_pulse_follows_in_scope_redirect_hop_by_hop(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    pulse = _pulse()
    transport, seen = _recording_transport(
        {
            "https://allowed.example/": (301, {"location": "/home"}),
            "https://allowed.example/home": (200, {}),
        }
    )

    async def go():
        async with httpx.AsyncClient(transport=transport) as client:
            return await pulse.check_one(
                client, "https://allowed.example/", follow=True, retries=0
            )

    result = asyncio.run(go())

    assert seen == ["https://allowed.example/", "https://allowed.example/home"]
    assert result.status == 200
    assert result.final_url == "https://allowed.example/home"
    assert result.redirects == [
        "https://allowed.example/",
        "https://allowed.example/home",
    ]


def test_pulse_client_ignores_proxy_env_and_auto_redirects(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://outside-proxy.invalid:8080")
    pulse = _pulse()

    class ClientReached(Exception):
        pass

    def inspect_client(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        raise ClientReached

    monkeypatch.setattr(pulse.httpx, "AsyncClient", inspect_client)
    with pytest.raises(ClientReached):
        asyncio.run(
            pulse.run_checks(
                ["https://allowed.example/"],
                follow=False,
                timeout=1,
                concurrency=1,
                retries=0,
                user_agent="t",
                insecure=False,
                method_note="",
            )
        )


def _ioc(monkeypatch, routes):
    ioc = _addon("IOCaw", "iocaw.py")
    transport, seen = _sync_transport(routes)
    monkeypatch.setattr(
        ioc, "SESSION", api_client(ioc.API_HOSTS, timeout=1, transport=transport)
    )
    return ioc, seen


def test_ioc_session_ignores_proxy_env_and_auto_redirects():
    ioc = _addon("IOCaw", "iocaw.py")
    session = ioc._session()
    assert session.trust_env is False
    assert session.follow_redirects is False


def test_ioc_follows_year_redirect_to_listed_host(monkeypatch):
    csv_url = (
        "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv"
    )
    ioc, seen = _ioc(
        monkeypatch,
        {
            "https://api.tweetfeed.live/v1/year": (302, {"location": csv_url}, b""),
            csv_url: (
                200,
                {"content-type": "text/csv"},
                b"date,user,type,value,tags,tweet\n",
            ),
        },
    )

    text, _resp = ioc.api_get("/v1/year", expect_json=False)

    assert seen == ["https://api.tweetfeed.live/v1/year", csv_url]
    assert text.startswith("date,")


def test_ioc_does_not_follow_redirect_off_its_api_hosts(monkeypatch):
    ioc, seen = _ioc(
        monkeypatch,
        {
            "https://api.tweetfeed.live/v1/year": (
                302,
                {"location": "https://evil.example/x.csv"},
                b"",
            ),
        },
    )

    with pytest.raises(ioc.TweetFeedError):
        ioc.api_get("/v1/year", expect_json=False)
    assert seen == ["https://api.tweetfeed.live/v1/year"]


def test_ioc_rejects_absolute_url_path(monkeypatch):
    ioc, seen = _ioc(monkeypatch, {})

    with pytest.raises(ioc.TweetFeedError):
        ioc.api_get("https://evil.example/")
    assert seen == []


def test_ioc_campaign_id_cannot_change_the_api_path(monkeypatch):
    ioc, seen = _ioc(
        monkeypatch,
        {
            "https://api.tweetfeed.live/v1/campaigns/..%2F..%2Fadmin": (
                200,
                {"content-type": "application/json"},
                b"{}",
            ),
        },
    )
    args = ioc.build_parser().parse_args(["campaigns", "--id", "../../admin", "--json"])

    with pytest.raises(ioc.TweetFeedError, match="invalid-target"):
        ioc.cmd_campaigns(args)
    assert seen == []


SAMPLE = "a" * 64


def _chroma(monkeypatch, routes):
    chroma = _addon("chromahaus", "chromahaus.py")
    transport, seen = _sync_transport(routes)
    monkeypatch.setattr(
        chroma, "HTTP", api_client(chroma.API_HOSTS, timeout=1, transport=transport)
    )
    return chroma, seen


def test_chroma_client_ignores_proxy_env_and_auto_redirects():
    chroma = _addon("chromahaus", "chromahaus.py")
    http = chroma._http()
    assert http.trust_env is False
    assert http.follow_redirects is False


def test_chroma_redirect_off_abuse_ch_never_receives_the_key(monkeypatch):
    chroma_url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
    chroma, seen = _chroma(
        monkeypatch,
        {
            chroma_url: (302, {"location": "https://evil.example/list.txt"}, b""),
        },
    )

    with pytest.raises(RuntimeError):
        chroma.fetch_text_list(chroma_url, "secret-key")
    assert seen == [chroma_url]


def test_chroma_download_refused_without_i_understand(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    chroma, seen = _chroma(monkeypatch, {})

    with pytest.raises(SystemExit):
        chroma.cmd_download("key", SAMPLE, ".", False)
    assert seen == []


def test_chroma_download_lands_in_workspace_samples(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    url = f"https://urlhaus-api.abuse.ch/v1/download/{SAMPLE}/"
    chroma, seen = _chroma(
        monkeypatch,
        {url: (200, {"content-type": "application/zip"}, b"PK" + b"\0" * 64)},
    )
    monkeypatch.chdir(tmp_path)

    chroma.cmd_download("key", SAMPLE, ".", True)

    assert (tmp_path / "scope" / "samples" / f"{SAMPLE}.zip").is_file()
    assert not (tmp_path / f"{SAMPLE}.zip").exists()


def test_chroma_download_dest_cannot_escape_samples(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    chroma, seen = _chroma(monkeypatch, {})

    with pytest.raises(SystemExit):
        chroma.cmd_download("key", SAMPLE, str(tmp_path / "elsewhere"), True)
    with pytest.raises(SystemExit):
        chroma.cmd_download("key", SAMPLE, "../..", True)
    assert seen == []


ANALYZE = "https://phishunt.io/api/v1/analyze?url=https%3A%2F%2Fallowed.example%2Flogin"


def _phish(monkeypatch, routes):
    phish = _addon("Lanternjaw", "lanternjaw.py")
    transport, seen = _sync_transport(routes)
    real_client = phish.Client

    def client_with_mock(*args, **kwargs):
        client = real_client(*args, **kwargs)
        client.session = api_client(phish.API_HOSTS, timeout=1, transport=transport)
        client.min_interval = 0
        return client

    monkeypatch.setattr(phish, "Client", client_with_mock)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    return phish, seen


def test_phish_client_ignores_proxy_env_and_auto_redirects():
    phish = _addon("Lanternjaw", "lanternjaw.py")
    session = phish.Client().session
    assert session.trust_env is False
    assert session.follow_redirects is False


def test_phish_redirect_off_phishunt_is_not_requested(monkeypatch):
    phish, seen = _phish(
        monkeypatch,
        {
            "https://phishunt.io/feed.json": (
                302,
                {"location": "https://evil.example/feed.json"},
                b"",
            ),
        },
    )

    with pytest.raises(phish.PhishuntError):
        phish.Client().request("/feed.json")
    assert seen == ["https://phishunt.io/feed.json"]


def test_phish_rejects_absolute_url_path(monkeypatch):
    phish, seen = _phish(monkeypatch, {})

    with pytest.raises(phish.PhishuntError):
        phish.Client().request("https://evil.example/")
    assert seen == []


def test_phish_analyze_out_of_scope_url_is_not_sent(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    phish, seen = _phish(monkeypatch, {})

    assert (
        phish.main(["--quiet", "analyze", "https://outside.example/login", "--yes"])
        != 0
    )
    assert seen == []


def test_phish_analyze_needs_confirmation_when_not_interactive(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    phish, seen = _phish(monkeypatch, {})

    assert phish.main(["--quiet", "analyze", "https://allowed.example/login"]) != 0
    assert seen == []


def test_phish_analyze_in_scope_with_yes_is_sent(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    phish, seen = _phish(
        monkeypatch, {ANALYZE: (200, {"content-type": "application/json"}, b"{}")}
    )

    assert (
        phish.main(
            ["--quiet", "analyze", "https://allowed.example/login", "--yes", "--json"]
        )
        == 0
    )
    assert seen == [ANALYZE]


def test_phish_deep_out_of_scope_url_is_not_sent(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    phish, seen = _phish(monkeypatch, {})

    assert (
        phish.main(
            ["--quiet", "deep", "https://outside.example/", "--token", "t", "--yes"]
        )
        != 0
    )
    assert seen == []


SCAN_URL = "https://urlscan.io/api/v1/scan/"


def _urlscan(monkeypatch, routes, bodies=None):
    urlscan = _addon("urlscan", "urlscan.py")
    seen = []

    def handler(request):
        url = str(request.url)
        seen.append(url)
        if bodies is not None:
            bodies.append(request.content)
        if url not in routes:
            raise AssertionError(f"unexpected request {url}")
        status, headers, body = routes[url]
        return httpx.Response(status, headers=headers, content=body, request=request)

    real_client = urlscan.Client

    def client_with_mock(*args, **kwargs):
        client = real_client(*args, **kwargs)
        client.http = api_client(
            urlscan.API_HOSTS, timeout=1, transport=httpx.MockTransport(handler)
        )
        return client

    monkeypatch.setattr(urlscan, "Client", client_with_mock)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    return urlscan, seen


def test_urlscan_client_ignores_proxy_env_and_auto_redirects():
    urlscan = _addon("urlscan", "urlscan.py")
    http = urlscan.Client(api_key=None).http
    assert http.trust_env is False
    assert http.follow_redirects is False


def test_urlscan_rejects_absolute_url_path(monkeypatch):
    urlscan, seen = _urlscan(monkeypatch, {})

    with pytest.raises(urlscan.APIError):
        urlscan.Client(api_key="k").request("GET", "https://evil.example/x")
    assert seen == []


def test_urlscan_scan_out_of_scope_is_not_submitted(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    urlscan, seen = _urlscan(monkeypatch, {})

    with pytest.raises(SystemExit):
        urlscan.main(["--api-key", "k", "scan", "https://outside.example/", "--yes"])
    assert seen == []


def test_urlscan_scan_needs_confirmation_when_not_interactive(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    urlscan, seen = _urlscan(monkeypatch, {})

    with pytest.raises(SystemExit):
        urlscan.main(["--api-key", "k", "scan", "https://allowed.example/"])
    assert seen == []


def test_urlscan_scan_defaults_to_private(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    bodies = []
    urlscan, seen = _urlscan(
        monkeypatch,
        {SCAN_URL: (200, {"content-type": "application/json"}, b'{"uuid": "x"}')},
        bodies,
    )

    urlscan.main(
        ["--api-key", "k", "--json", "scan", "https://allowed.example/", "--yes"]
    )

    assert seen == [SCAN_URL]
    assert b'"visibility": "private"' in bodies[0]


def _ct(monkeypatch, tmp_path, *, api_body=b"", probe_routes=None, extra=()):
    _scope(monkeypatch, tmp_path)
    ct = _addon("crt-scout", "crt-scout.py")
    args = ct.create_parser().parse_args(["allowed.example", "-q", *extra])
    scout = ct.CrtScout(args.domain, args)
    api_url = "https://crt.name/v1/search?apex=allowed.example"
    api_transport, api_seen = _sync_transport({api_url: (200, {}, api_body)})
    probe_transport, probe_seen = _recording_transport(probe_routes or {})
    monkeypatch.setattr(
        scout,
        "_api",
        lambda: api_client(ct.API_HOSTS, timeout=1, transport=api_transport),
    )
    monkeypatch.setattr(
        scout, "_probe_client", lambda: httpx.AsyncClient(transport=probe_transport)
    )
    return ct, scout, api_seen, probe_seen


def test_ct_clients_verify_tls_and_ignore_proxy_env(monkeypatch, tmp_path):
    ct = _addon("crt-scout", "crt-scout.py")
    args = ct.create_parser().parse_args(["allowed.example"])
    scout = ct.CrtScout(args.domain, args)
    api = scout._api()
    probe = scout._probe_client()
    assert api.trust_env is False and api.follow_redirects is False
    assert probe.trust_env is False and probe.follow_redirects is False
    assert (
        not hasattr(scout, "ssl_context")
        or scout.ssl_context.verify_mode != ct.ssl.CERT_NONE
    )


def test_ct_refuses_out_of_scope_domain_before_any_request(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    ct = _addon("crt-scout", "crt-scout.py")
    monkeypatch.setattr("sys.argv", ["bughunt ct", "outside.example", "-c"])
    monkeypatch.setattr(
        ct.CrtScout, "_api", lambda self: (_ for _ in ()).throw(AssertionError("api"))
    )

    with pytest.raises(SystemExit):
        asyncio.run(ct.main())


def test_ct_keeps_only_names_under_the_domain(monkeypatch, tmp_path):
    body = b"www.allowed.example\nallowed.example\nevil.example\n*.allowed.example\nx.allowed.example@evil.example\n169.254.169.254\n"
    ct, scout, _api_seen, _probe_seen = _ct(monkeypatch, tmp_path, api_body=body)

    asyncio.run(scout.fetch_subdomains())

    assert scout.subdomains == {"www.allowed.example", "allowed.example"}


def test_ct_probe_does_not_follow_redirect_out_of_scope(monkeypatch, tmp_path):
    ct, scout, _api_seen, probe_seen = _ct(
        monkeypatch,
        tmp_path,
        api_body=b"www.allowed.example\n",
        probe_routes={
            "https://www.allowed.example": (302, {"location": "https://evil.example/"})
        },
        extra=("-c", "--https-only"),
    )

    asyncio.run(scout.run())

    assert probe_seen == ["https://www.allowed.example"]
    assert scout.results == [("www.allowed.example", "https", 302)]


class _FakeRoute:
    """Stands in for a Playwright Route. `chain` maps URL -> (status, location)."""

    def __init__(self, url, chain=None):
        self.request = type("Request", (), {"url": url})()
        self.chain = chain or {}
        self.outcome = None
        self.fetched = []
        self.fulfilled_with = None

    def fetch(self, url=None, max_redirects=None, headers=None):
        assert max_redirects == 0
        assert headers["X-Researcher"] == "owned-lab"
        target = url or self.request.url
        self.fetched.append(target)
        status, location = self.chain.get(target, (200, ""))
        headers = {"location": location} if location else {}
        return type(
            "Reply", (), {"status": status, "headers": headers, "url": target}
        )()

    def fulfill(self, response=None):
        self.outcome = "fulfilled"
        self.fulfilled_with = response.url

    def abort(self, reason="failed"):
        self.outcome = f"aborted:{reason}"


class _FakeSocket:
    def __init__(self, url):
        self.url = url
        self.outcome = None

    def connect_to_server(self):
        self.outcome = "connected"

    def close(self, **kwargs):
        self.outcome = "closed"


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://allowed.example/", "fulfilled"),
        ("https://cdn.allowed.example/app.js", "fulfilled"),
        ("https://outside.example/pixel.gif", "aborted:blockedbyclient"),
        ("ftp://allowed.example/file", "aborted:blockedbyclient"),
    ],
)
def test_screenshot_route_only_lets_in_scope_http_out(
    monkeypatch, tmp_path, url, expected
):
    _scope(monkeypatch, tmp_path)
    route = _FakeRoute(url)

    bughunt_scanner.scope_route(route)

    assert route.outcome == expected
    assert bool(route.fetched) is (expected == "fulfilled")


def test_screenshot_route_walks_in_scope_redirects_itself(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    route = _FakeRoute(
        "https://allowed.example/",
        {
            "https://allowed.example/": (302, "/home"),
            "https://allowed.example/home": (301, "https://www.allowed.example/"),
        },
    )

    bughunt_scanner.scope_route(route)

    assert route.fetched == [
        "https://allowed.example/",
        "https://allowed.example/home",
        "https://www.allowed.example/",
    ]
    assert route.fulfilled_with == "https://www.allowed.example/"


def test_screenshot_route_never_fetches_out_of_scope_hop(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    route = _FakeRoute(
        "https://allowed.example/",
        {
            "https://allowed.example/": (302, "/next"),
            "https://allowed.example/next": (302, "https://outside.example/"),
        },
    )

    bughunt_scanner.scope_route(route)

    assert route.outcome == "aborted:blockedbyclient"
    assert "https://outside.example/" not in route.fetched


def test_screenshot_route_fails_closed_when_fetch_breaks(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    route = _FakeRoute("https://allowed.example/")
    route.fetch = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("context closed"))

    bughunt_scanner.scope_route(route)

    assert route.outcome == "aborted:blockedbyclient"


@pytest.mark.parametrize(
    "url, expected",
    [("wss://allowed.example/live", "connected"), ("wss://outside.example/live", None)],
)
def test_screenshot_websocket_only_in_scope(monkeypatch, tmp_path, url, expected):
    _scope(monkeypatch, tmp_path)
    socket = _FakeSocket(url)

    bughunt_scanner.scope_socket(socket)

    assert socket.outcome == expected


def test_screenshot_browser_ignores_system_proxy_and_blocks_service_workers():
    launch, context = bughunt_scanner.browser_settings(None)
    assert "--no-proxy-server" in launch["args"]
    assert context["service_workers"] == "block"

    launch, _context = bughunt_scanner.browser_settings("http://10.8.0.1:3128")
    assert launch["proxy"] == {"server": "http://10.8.0.1:3128"}


@pytest.mark.parametrize("command", ["screenshot", "dom", "result"])
def test_urlscan_rejects_uuid_that_is_not_a_uuid(monkeypatch, command):
    urlscan, seen = _urlscan(monkeypatch, {})

    with pytest.raises(SystemExit):
        urlscan.main(["--api-key", "k", command, "../../user/username"])
    assert seen == []
