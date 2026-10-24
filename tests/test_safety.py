"""Network-free regressions for scope checks at active entry points."""

import asyncio
from contextlib import nullcontext
import json
import os
from pathlib import Path
import runpy
import sys
from types import ModuleType, SimpleNamespace

import pytest

from bughunt.core import egress, identity, route, route_probe
from bughunt.core.route_probe import Interface, ProbeError
from bughunt.console import loader
from bughunt.console import options
from bughunt.modules import snare
from bughunt.core import scanner as bughunt_scanner
from test_gate import seed_policy


def _scope(monkeypatch, tmp_path):
    workspace = tmp_path / "scope"
    workspace.mkdir()
    (workspace / "scope.txt").write_text("allowed.example\n", encoding="utf-8")
    document = seed_policy(workspace)
    document["assets"].append(
        {
            "id": "process",
            "origin": "http://localhost",
            "paths": ["/"],
            "operations": ["process"],
            "methods": ["GET"],
        }
    )
    import json

    (workspace / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv("BUGHUNT_SCOPE", str(workspace))


@pytest.mark.parametrize("extra", [[], ["--authorized"]])
def test_scan_rejects_out_of_scope_before_dns(monkeypatch, tmp_path, extra):
    _scope(monkeypatch, tmp_path)
    monkeypatch.setattr(
        bughunt_scanner,
        "resolve_host",
        lambda target: (_ for _ in ()).throw(AssertionError(target)),
    )

    assert (
        bughunt_scanner.scan_main(
            ["outside.example", "--ports", "80", "--quiet", *extra]
        )
        == 2
    )


def test_scan_rejects_unchecked_redirects_before_dns(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    monkeypatch.setattr(
        bughunt_scanner,
        "resolve_host",
        lambda target: (_ for _ in ()).throw(AssertionError(target)),
    )

    assert (
        bughunt_scanner.scan_main(
            ["allowed.example", "--ports", "80", "--follow-redirects", "--quiet"]
        )
        == 2
    )


def test_scan_screenshots_still_reject_out_of_scope_before_dns(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    monkeypatch.setattr(
        bughunt_scanner,
        "resolve_host",
        lambda target: (_ for _ in ()).throw(AssertionError(target)),
    )

    assert (
        bughunt_scanner.scan_main(
            ["outside.example", "--ports", "80", "--screenshots", "shots", "--quiet"]
        )
        == 2
    )


def test_scan_screenshots_proceed_for_in_scope_target(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    monkeypatch.setattr(
        bughunt_scanner,
        "resolve_host",
        lambda target: (_ for _ in ()).throw(AssertionError("DNS reached")),
    )

    with pytest.raises(AssertionError, match="DNS reached"):
        bughunt_scanner.scan_main(
            [
                "allowed.example",
                "--ports",
                "80",
                "--screenshots",
                str(tmp_path / "shots"),
                "--quiet",
            ]
        )


class _ScreenshotRoute:
    def __init__(self, url, headers=None, redirects=None, method="GET"):
        self.request = SimpleNamespace(url=url, method=method, headers=headers or {})
        self.redirects = redirects or {}
        self.sent = []
        self.outcome = None

    def fetch(self, *, url, max_redirects, headers):
        assert max_redirects == 0
        self.sent.append((url, headers))
        redirect = self.redirects.get(url)
        status, location = (
            redirect
            if isinstance(redirect, tuple)
            else (302 if redirect else 200, redirect)
        )
        return SimpleNamespace(
            url=url, status=status, headers={"location": location} if location else {}
        )

    def fulfill(self, *, response):
        self.outcome = "fulfilled"

    def abort(self, reason):
        self.outcome = "aborted"


def test_screenshot_named_actor_scrubs_browser_headers_and_binds_host(
    monkeypatch, tmp_path
):
    _scope(monkeypatch, tmp_path)
    identity.create_profile("owner", "browser", ["https://allowed.example"], owned=True)
    identity.set_credential("owner", "authorization", "Bearer owned-token")
    identity.use_profile("owner")
    route = _ScreenshotRoute(
        "https://allowed.example/",
        {
            "Host": "allowed.example",
            "Cookie": "session=stale",
            "Authorization": "Bearer stale",
            "X-API-Key": "stale",
        },
    )

    bughunt_scanner.scope_route(route)

    assert route.outcome == "fulfilled"
    sent = {name.lower(): value for name, value in route.sent[0][1].items()}
    assert sent["authorization"] == "Bearer owned-token"
    assert "cookie" not in sent and "x-api-key" not in sent
    runs = list((tmp_path / "scope" / "runs").glob("*/manifest.json"))
    assert any(json.loads(path.read_text())["actor"] == "owner" for path in runs)

    wrong_host = _ScreenshotRoute("https://allowed.example/", {"Host": "api.example"})
    bughunt_scanner.scope_route(wrong_host)
    assert wrong_host.outcome == "aborted" and wrong_host.sent == []


def test_screenshot_named_actor_blocks_other_origin_and_websocket(
    monkeypatch, tmp_path
):
    _scope(monkeypatch, tmp_path)
    identity.create_profile("owner", "browser", ["https://allowed.example"], owned=True)
    identity.use_profile("owner")
    route = _ScreenshotRoute(
        "https://allowed.example/",
        redirects={"https://allowed.example/": "https://www.allowed.example/"},
    )
    bughunt_scanner.scope_route(route)
    assert route.outcome == "aborted"
    assert [url for url, _headers in route.sent] == ["https://allowed.example/"]
    socket = SimpleNamespace(
        url="wss://allowed.example/live",
        connect_to_server=lambda: pytest.fail("named actor socket connected"),
    )
    bughunt_scanner.scope_socket(socket)


def test_screenshot_stale_context_cannot_send_after_actor_switch(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    for name, kind in (("owner", "browser"), ("guest", "anonymous")):
        identity.create_profile(name, kind, ["https://allowed.example"], owned=True)
    identity.use_profile("owner")
    signature = identity.selection_signature()
    identity.use_profile("guest")
    route = _ScreenshotRoute("https://allowed.example/next")

    bughunt_scanner.scope_route(route, signature)

    assert route.outcome == "aborted" and route.sent == []


def test_screenshot_post_does_not_override_browser_body_framing(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    identity.create_profile("owner", "browser", ["https://allowed.example"], owned=True)
    identity.use_profile("owner")
    route = _ScreenshotRoute(
        "https://allowed.example/submit",
        {"Content-Type": "application/json"},
        method="POST",
    )

    bughunt_scanner.scope_route(route)

    assert route.outcome == "fulfilled"
    sent = {name.lower(): value for name, value in route.sent[0][1].items()}
    assert "content-length" not in sent and "transfer-encoding" not in sent
    chunked = _ScreenshotRoute(
        "https://allowed.example/submit",
        {"Transfer-Encoding": "chunked"},
        method="POST",
    )
    bughunt_scanner.scope_route(chunked)
    assert "transfer-encoding" not in {name.lower() for name in chunked.sent[0][1]}


def test_screenshot_post_redirect_stops_before_second_send(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    identity.create_profile("owner", "browser", ["https://allowed.example"], owned=True)
    identity.use_profile("owner")
    route = _ScreenshotRoute(
        "https://allowed.example/submit",
        redirects={
            "https://allowed.example/submit": (303, "https://allowed.example/moved")
        },
        method="POST",
    )

    bughunt_scanner.scope_route(route)

    assert route.outcome == "aborted"
    assert [url for url, _headers in route.sent] == ["https://allowed.example/submit"]


class _ScreenshotContext:
    def __init__(self, contexts):
        self.contexts = contexts
        self.cookies, self.routes, self.closed = [], [], False

    def add_cookies(self, cookies):
        self.cookies.extend(cookies)

    def route(self, _pattern, handler):
        self.handler = handler

    def route_web_socket(self, _pattern, handler):
        self.socket_handler = handler

    def new_page(self):
        return _ScreenshotPage(self)

    def close(self):
        self.closed = True


class _ScreenshotPage:
    def __init__(self, context):
        self.context = context

    def goto(self, url, **_kwargs):
        redirects = (
            {url: "https://www.allowed.example/next"}
            if len(self.context.contexts) == 1
            else {}
        )
        route = _ScreenshotRoute(
            url,
            {
                "Cookie": "session=browser-stale",
                "Authorization": "Bearer browser-stale",
            },
            redirects,
        )
        self.context.handler(route)
        self.context.routes.append(route)
        if len(self.context.contexts) == 1:
            identity.use_profile("guest")

    def screenshot(self, **_kwargs):
        pass

    def close(self):
        pass


def _fake_screenshot_browser(monkeypatch):
    contexts = []

    def new_context(**_kwargs):
        contexts.append(_ScreenshotContext(contexts))
        return contexts[-1]

    browser = SimpleNamespace(new_context=new_context, close=lambda: None)
    playwright = SimpleNamespace(
        chromium=SimpleNamespace(launch=lambda **_kwargs: browser)
    )
    module = ModuleType("playwright.sync_api")
    module.sync_playwright = lambda: nullcontext(playwright)
    monkeypatch.setitem(sys.modules, "playwright", ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", module)
    return contexts


def test_screenshot_contexts_keep_owner_and_anonymous_separate(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    identity.create_profile(
        "owner",
        "browser",
        ["https://allowed.example", "https://www.allowed.example"],
        owned=True,
    )
    identity.create_profile(
        "guest", "anonymous", ["https://allowed.example"], owned=True
    )
    identity.set_credential("owner", "cookie", "session=owner-secret; theme=dark")
    identity.use_profile("owner")
    contexts = _fake_screenshot_browser(monkeypatch)
    hits = [
        SimpleNamespace(
            url=f"https://allowed.example/{path}", final_url="", status=200, tags=[]
        )
        for path in ("one", "two")
    ]
    report = SimpleNamespace(results=[SimpleNamespace(hits=hits)])

    bughunt_scanner.capture_screenshots(report, tmp_path / "shots")

    assert len(contexts) == 2 and all(context.closed for context in contexts)
    assert {
        (cookie["url"], cookie["name"], cookie["value"])
        for cookie in contexts[0].cookies
    } == {
        (origin + "/", name, value)
        for origin in ("https://allowed.example", "https://www.allowed.example")
        for name, value in (("session", "owner-secret"), ("theme", "dark"))
    }
    assert contexts[1].cookies == []
    assert all(
        route.outcome == "fulfilled" for context in contexts for route in context.routes
    )
    assert [url for url, _headers in contexts[0].routes[0].sent] == [
        "https://allowed.example/one",
        "https://www.allowed.example/next",
    ]
    assert all(
        not {"cookie", "authorization"} & {name.lower() for name in headers}
        for context in contexts
        for route in context.routes
        for _url, headers in route.sent
    )


def test_snare_rejects_out_of_scope_connect(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    statuses = []
    monkeypatch.setattr(
        snare, "_tunnel", lambda *args: (_ for _ in ()).throw(AssertionError("tunnel"))
    )
    monkeypatch.setattr(
        snare,
        "_send_status",
        lambda _conn, code, reason: statuses.append((code, reason)),
    )

    snare._handle_connect(object(), "outside.example:443", snare.Settings())

    assert statuses == [(403, "Outside scope")]


def test_snare_rejects_out_of_scope_http_before_fetch(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    statuses = []
    monkeypatch.setattr(
        snare, "_fetch", lambda *args: (_ for _ in ()).throw(AssertionError("fetch"))
    )
    monkeypatch.setattr(
        snare,
        "_send_status",
        lambda _conn, code, reason: statuses.append((code, reason)),
    )

    snare._handle_exchange(
        object(),
        None,
        snare._Message("GET / HTTP/1.1", []),
        "GET",
        "http://outside.example/",
        "HTTP/1.1",
        snare.Settings(),
        scheme=None,
        default_port=None,
    )

    assert statuses == [(403, "Outside scope")]


@pytest.mark.parametrize("name", ["tcurl"])
def test_unreviewed_addon_is_not_dispatched(monkeypatch, name):
    monkeypatch.setattr(loader, "DISABLED_REFERENCES", frozenset({name}))
    monkeypatch.setattr(
        loader,
        "locate_script",
        lambda *args: (_ for _ in ()).throw(AssertionError("loaded")),
    )

    assert (
        loader.run_named(
            name,
            [],
            tool_file=Path(bughunt_scanner.__file__),
            scan_main=bughunt_scanner.scan_main,
        )
        == 2
    )


def test_unreviewed_addon_options_do_not_import_code(monkeypatch):
    monkeypatch.setattr(options, "DISABLED_REFERENCES", frozenset({"tcurl"}))
    monkeypatch.setattr(
        options,
        "locate_script",
        lambda *args: (_ for _ in ()).throw(AssertionError("loaded")),
    )

    with pytest.raises(options.SpecError, match="disabled"):
        options.load_spec(
            "tcurl",
            tool_file=Path(bughunt_scanner.__file__),
            build_parser=bughunt_scanner.build_parser,
        )


WG = Interface(5, "wg0", "WireGuard Tunnel", True)
LOOPBACK = Interface(1, "lo", "", True)
ETHERNET = Interface(2, "eth0", "", True)
PROXY_ARGS = [
    "allowed.example",
    "--ports",
    "80",
    "--http-only",
    "--proxy",
    "http://proxy.example:8080",
    "--quiet",
]
LOOPBACK_ARGS = [
    "allowed.example",
    "--ports",
    "80",
    "--http-only",
    "--proxy",
    "http://127.0.0.1:8080",
    "--quiet",
]


class FakeProbe:
    def __init__(
        self, routes, interfaces=(LOOPBACK, ETHERNET, WG), interface_error=None
    ):
        self.routes, self.interface_list, self.interface_error = (
            routes,
            list(interfaces),
            interface_error,
        )
        self.lookups = []

    def interfaces(self):
        if self.interface_error:
            raise self.interface_error
        return list(self.interface_list)

    def egress_indexes(self, address):
        self.lookups.append(address)
        outcome = self.routes.get(address, ProbeError(f"no route to {address}"))
        if isinstance(outcome, Exception):
            raise outcome
        return set(outcome)


class FakeResolver:
    def __init__(self, mapping=None, error=None):
        self.mapping, self.error, self.calls = mapping or {}, error, []

    def __call__(self, host, port, *args, **kwargs):
        self.calls.append(host)
        if self.error:
            raise self.error
        return [(0, 0, 0, "", (address, 0)) for address in self.mapping.get(host, [])]


def _route_config(**overrides):
    document = {"schema_version": 1, "interfaces": ["wg0"], **overrides}
    (Path(os.environ["BUGHUNT_SCOPE"]) / "route.json").write_text(
        json.dumps(document), encoding="utf-8"
    )


def _route_env(monkeypatch, probe, resolver=None):
    """Install an injected probe and resolver; any DNS that is not the gate's own fails the test."""
    resolver = resolver or FakeResolver({"proxy.example": ["203.0.113.9"]})
    monkeypatch.setattr(route_probe, "default_probe", lambda *args, **kwargs: probe)
    monkeypatch.setattr(bughunt_scanner.socket, "getaddrinfo", resolver)
    monkeypatch.setattr(
        bughunt_scanner,
        "resolve_host",
        lambda target: (_ for _ in ()).throw(AssertionError("DNS reached")),
    )
    monkeypatch.delenv("BUGHUNT_ROUTE_CONFIG", raising=False)
    return resolver


def _good_routes(**extra):
    return {"1.1.1.1": {5}, "203.0.113.9": {5}, **extra}


def _output(capsys):
    return " ".join(capsys.readouterr().out.split())


def test_proxy_blocked_outside_tunnel_before_target_dns(monkeypatch, tmp_path, capsys):
    # The planned URL is granted, so the failing route check is the ONLY thing that can produce exit 2.
    _scope(monkeypatch, tmp_path)
    _route_config()
    probe = FakeProbe(_good_routes(**{"203.0.113.9": {2}}))
    resolver = _route_env(monkeypatch, probe)

    assert bughunt_scanner.scan_main(PROXY_ARGS) == 2
    assert probe.lookups.count("203.0.113.9") == 1 and resolver.calls == [
        "proxy.example"
    ]
    assert "Proxy route check failed for proxy.example; scan blocked." in _output(
        capsys
    )


def test_default_ports_are_stopped_by_the_policy_preflight_not_the_route_gate(
    monkeypatch, tmp_path
):
    # Without --ports the policy preflight exits 2 first; the spy proves the route gate never ran.
    _scope(monkeypatch, tmp_path)
    _route_config()
    probe = FakeProbe(_good_routes())
    _route_env(monkeypatch, probe)
    monkeypatch.setattr(
        route,
        "verify",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("verify ran")),
    )

    assert (
        bughunt_scanner.scan_main(
            ["allowed.example", "--proxy", "http://proxy.example:8080", "--quiet"]
        )
        == 2
    )
    assert probe.lookups == []


def test_gate_is_inactive_without_a_route_config(monkeypatch, tmp_path, capsys):
    _scope(monkeypatch, tmp_path)
    _route_env(monkeypatch, None)
    monkeypatch.setattr(
        route_probe,
        "default_probe",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("probed")),
    )

    with pytest.raises(AssertionError, match="DNS reached"):
        bughunt_scanner.scan_main(PROXY_ARGS)
    assert 'route gate: not configured; see "bughunt route init"' in _output(capsys)


def test_gate_is_inactive_when_proxy_scan_is_not_protected(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    _route_config(protect=["console"])
    probe = FakeProbe(_good_routes(**{"203.0.113.9": {2}}))
    _route_env(monkeypatch, probe)

    with pytest.raises(AssertionError, match="DNS reached"):
        bughunt_scanner.scan_main(PROXY_ARGS)
    assert probe.lookups == []


def test_gate_rejects_a_proxy_without_a_host_before_probing(
    monkeypatch, tmp_path, capsys
):
    _scope(monkeypatch, tmp_path)
    _route_config()
    probe = FakeProbe(_good_routes())
    _route_env(monkeypatch, probe)

    assert (
        bughunt_scanner.scan_main(
            [
                "allowed.example",
                "--ports",
                "80",
                "--http-only",
                "--proxy",
                "notaproxy",
                "--quiet",
            ]
        )
        == 2
    )
    assert probe.lookups == [] and "--proxy must contain a valid host." in _output(
        capsys
    )


@pytest.mark.parametrize(
    "probe",
    [
        FakeProbe(
            {},
            interface_error=ProbeError(
                "route verification is not supported on this platform"
            ),
        ),
        FakeProbe({}, interface_error=ProbeError("ip: command not found")),
        FakeProbe({"1.1.1.1": ProbeError("lookup failed")}),
        FakeProbe(_good_routes(**{"203.0.113.9": ProbeError("no route")})),
        FakeProbe(_good_routes(), interfaces=(LOOPBACK, ETHERNET)),
        FakeProbe(
            _good_routes(),
            interfaces=(LOOPBACK, Interface(5, "wg0", "WireGuard Tunnel", False)),
        ),
        FakeProbe({}, interface_error=RuntimeError("unexpected backend crash")),
        FakeProbe({}, interface_error=AttributeError("windows ctypes backend broke")),
    ],
)
def test_any_probe_uncertainty_blocks_the_proxy(monkeypatch, tmp_path, capsys, probe):
    _scope(monkeypatch, tmp_path)
    _route_config()
    _route_env(monkeypatch, probe)

    assert bughunt_scanner.scan_main(PROXY_ARGS) == 2
    assert "scan blocked" in _output(capsys)


@pytest.mark.parametrize(
    "resolver",
    [FakeResolver(error=OSError("nxdomain")), FakeResolver({"proxy.example": []})],
)
def test_unresolvable_or_empty_destination_blocks_the_proxy(
    monkeypatch, tmp_path, resolver
):
    _scope(monkeypatch, tmp_path)
    _route_config()
    _route_env(monkeypatch, FakeProbe(_good_routes()), resolver)

    assert bughunt_scanner.scan_main(PROXY_ARGS) == 2


@pytest.mark.parametrize(
    "text",
    [
        "{not json",
        '{"schema_version": 1, "interfaces": []}',
        '{"schema_version": 1, "interfaces": ["wg0"], "surprise": 1}',
    ],
)
def test_invalid_route_config_blocks_the_proxy(monkeypatch, tmp_path, capsys, text):
    _scope(monkeypatch, tmp_path)
    (Path(os.environ["BUGHUNT_SCOPE"]) / "route.json").write_text(
        text, encoding="utf-8"
    )
    probe = FakeProbe(_good_routes())
    _route_env(monkeypatch, probe)

    assert bughunt_scanner.scan_main(PROXY_ARGS) == 2
    assert "Route config invalid; blocked" in _output(capsys) and probe.lookups == []


def test_route_config_env_pointing_at_a_missing_file_blocks_the_proxy(
    monkeypatch, tmp_path
):
    _scope(monkeypatch, tmp_path)
    _route_env(monkeypatch, FakeProbe(_good_routes()))
    monkeypatch.setenv("BUGHUNT_ROUTE_CONFIG", str(tmp_path / "typo.json"))

    assert bughunt_scanner.scan_main(PROXY_ARGS) == 2


def test_gate_needs_the_process_grant_before_it_probes(monkeypatch, tmp_path):
    workspace = tmp_path / "scope"
    workspace.mkdir()
    (workspace / "scope.txt").write_text("allowed.example\n", encoding="utf-8")
    seed_policy(
        workspace
    )  # deliberately WITHOUT the localhost "process" asset that _scope adds
    monkeypatch.setenv("BUGHUNT_SCOPE", str(workspace))
    _route_config()
    probe = FakeProbe(_good_routes())
    _route_env(monkeypatch, probe)

    assert bughunt_scanner.scan_main(PROXY_ARGS) == 2
    assert (
        probe.lookups == []
    )  # a policy block while preparing the gate is exit 2 and the probe never runs


def test_proxy_through_the_tunnel_is_allowed_and_continues(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    _route_config()
    probe = FakeProbe(_good_routes())
    _route_env(monkeypatch, probe)

    with pytest.raises(AssertionError, match="DNS reached"):
        bughunt_scanner.scan_main(PROXY_ARGS)
    assert probe.lookups == ["1.1.1.1", "203.0.113.9"]


def _grant_loopback_proxy():
    policy_file = Path(os.environ["BUGHUNT_SCOPE"]) / "policy.json"
    document = json.loads(policy_file.read_text(encoding="utf-8"))
    document["assets"].append(
        {
            "id": "loopback-proxy",
            "origin": "http://127.0.0.1:8080",
            "paths": ["/"],
            "operations": ["manual"],
            "methods": ["GET"],
        }
    )
    policy_file.write_text(json.dumps(document), encoding="utf-8")


def test_loopback_proxy_is_blocked_by_default(monkeypatch, tmp_path, capsys):
    _scope(monkeypatch, tmp_path)
    _grant_loopback_proxy()
    _route_config()
    _route_env(monkeypatch, FakeProbe(_good_routes(**{"127.0.0.1": {1}})))

    assert bughunt_scanner.scan_main(LOOPBACK_ARGS) == 2
    assert "Proxy route check failed for 127.0.0.1; scan blocked." in _output(capsys)


def test_loopback_proxy_is_allowed_only_with_allow_loopback_proxy(
    monkeypatch, tmp_path
):
    _scope(monkeypatch, tmp_path)
    _grant_loopback_proxy()
    _route_config(allow_loopback_proxy=True)
    _route_env(monkeypatch, FakeProbe(_good_routes(**{"127.0.0.1": {1}})))

    with pytest.raises(AssertionError, match="DNS reached"):
        bughunt_scanner.scan_main(LOOPBACK_ARGS)


def test_check_proxy_route_returns_blocked_code_instead_of_raising(
    monkeypatch, tmp_path
):
    _scope(monkeypatch, tmp_path)
    _route_config()
    _route_env(monkeypatch, None)

    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(route, "verify", explode)
    assert bughunt_scanner.check_proxy_route("http://proxy.example:8080") == 2


def test_hostname_proxy_warns_about_connect_time_reresolution_but_ip_literal_does_not(
    monkeypatch, tmp_path, capsys
):
    _scope(monkeypatch, tmp_path)
    _route_config()
    _route_env(monkeypatch, FakeProbe(_good_routes()))

    assert bughunt_scanner.check_proxy_route("http://proxy.example:8080") is None
    assert "re-resolves a hostname" in _output(capsys)
    bughunt_scanner._warn_if_hostname_proxy("203.0.113.9")
    bughunt_scanner._warn_if_hostname_proxy("::1")
    assert "re-resolves" not in _output(capsys)


def test_mixed_loopback_and_tunnel_resolution_is_denied(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    _route_config()
    resolver = FakeResolver({"proxy.example": ["203.0.113.9", "127.0.0.1"]})
    _route_env(monkeypatch, FakeProbe(_good_routes(**{"127.0.0.1": {1}})), resolver)

    assert bughunt_scanner.check_proxy_route("http://proxy.example:8080") == 2


@pytest.mark.parametrize("truthy", ["yes", 1, ["x"], object()])
def test_non_bool_truthy_verdict_ok_is_not_treated_as_allowed(
    monkeypatch, tmp_path, truthy
):
    _scope(monkeypatch, tmp_path)
    _route_config()
    _route_env(monkeypatch, FakeProbe(_good_routes()))
    monkeypatch.setattr(
        route, "verify", lambda *args, **kwargs: SimpleNamespace(ok=truthy, details=())
    )

    assert bughunt_scanner.check_proxy_route("http://proxy.example:8080") == 2


def test_output_failure_while_denying_still_denies(monkeypatch, tmp_path):
    _scope(monkeypatch, tmp_path)
    _route_config()
    _route_env(monkeypatch, FakeProbe(_good_routes()))

    def explode_verify(*args, **kwargs):
        raise RuntimeError("boom")

    def explode_emit(*args, **kwargs):
        raise OSError("stdout closed")

    monkeypatch.setattr(route, "verify", explode_verify)
    monkeypatch.setattr(bughunt_scanner, "emit", explode_emit)
    assert bughunt_scanner.check_proxy_route("http://proxy.example:8080") == 2


def test_optout_env_bypasses_a_failing_proxy_route_and_warns_on_stderr(
    monkeypatch, tmp_path, capsys
):
    _scope(monkeypatch, tmp_path)
    _route_config()
    # The proxy routes off the tunnel: without the opt-out this blocks with exit 2.
    _route_env(monkeypatch, FakeProbe(_good_routes(**{"203.0.113.9": {2}})))
    monkeypatch.setenv("BUGHUNT_ALLOW_NO_ROUTE", "1")

    assert bughunt_scanner.check_proxy_route("http://proxy.example:8080") is None
    captured = capsys.readouterr()
    assert "route/VPN protection is DISABLED" in captured.err
    assert "BUGHUNT_ALLOW_NO_ROUTE" in captured.err
    assert "DISABLED" not in captured.out


def test_optout_env_bypasses_invalid_proxy_config_and_warns(
    monkeypatch, tmp_path, capsys
):
    _scope(monkeypatch, tmp_path)
    (Path(os.environ["BUGHUNT_SCOPE"]) / "route.json").write_text(
        "{not json", encoding="utf-8"
    )
    monkeypatch.setenv("BUGHUNT_ALLOW_NO_ROUTE", "1")

    assert bughunt_scanner.check_proxy_route("http://proxy.example:8080") is None
    assert "route/VPN protection is DISABLED" in capsys.readouterr().err


@pytest.mark.parametrize(
    "error", [OSError("private-path"), ValueError("private-value")]
)
def test_proxy_optout_audit_failure_blocks_without_leaking(
    monkeypatch, tmp_path, capsys, error
):
    from bughunt.core import ledger

    _scope(monkeypatch, tmp_path)
    monkeypatch.setenv("BUGHUNT_ALLOW_NO_ROUTE", "1")

    def fail_save(*args):
        raise error

    monkeypatch.setattr(ledger, "_write_manifest", fail_save)
    assert bughunt_scanner.check_proxy_route("http://proxy.example:8080") == 2
    captured = capsys.readouterr()
    assert "audit could not be saved" in captured.out
    assert "private-" not in captured.out + captured.err


def test_optout_env_not_set_to_one_leaves_the_proxy_gate_blocking(
    monkeypatch, tmp_path
):
    _scope(monkeypatch, tmp_path)
    _route_config()
    _route_env(monkeypatch, FakeProbe(_good_routes(**{"203.0.113.9": {2}})))
    monkeypatch.setenv("BUGHUNT_ALLOW_NO_ROUTE", "0")

    assert bughunt_scanner.check_proxy_route("http://proxy.example:8080") == 2


def test_optout_env_lets_scan_main_proceed_past_the_proxy_gate(
    monkeypatch, tmp_path, capsys
):
    _scope(monkeypatch, tmp_path)
    _route_config()
    # Off-tunnel proxy: without the opt-out scan_main returns 2 at the proxy gate before any DNS.
    _route_env(monkeypatch, FakeProbe(_good_routes(**{"203.0.113.9": {2}})))
    monkeypatch.setenv("BUGHUNT_ALLOW_NO_ROUTE", "1")

    with pytest.raises(AssertionError, match="DNS reached"):
        bughunt_scanner.scan_main(PROXY_ARGS)
    assert "route/VPN protection is DISABLED" in capsys.readouterr().err


def test_optout_still_enforces_mission_policy_authorization(monkeypatch, tmp_path):
    # The route opt-out disables ONLY the route gate, never mission-policy authorization.
    # seed_policy omits the localhost "process" asset that _scope adds, so the process grant is absent
    # and egress.authorize must still block even with BUGHUNT_ALLOW_NO_ROUTE=1.
    workspace = tmp_path / "scope"
    workspace.mkdir()
    (workspace / "scope.txt").write_text("allowed.example\n", encoding="utf-8")
    seed_policy(workspace)
    monkeypatch.setenv("BUGHUNT_SCOPE", str(workspace))
    _route_config()
    _route_env(monkeypatch, FakeProbe(_good_routes()))
    monkeypatch.setenv("BUGHUNT_ALLOW_NO_ROUTE", "1")

    with pytest.raises(egress.PolicyBlocked):
        bughunt_scanner.check_proxy_route("http://proxy.example:8080")


def test_direct_skiff_invocation_verifies_tls_by_default():
    script = Path(bughunt_scanner.__file__).parents[2] / "addons" / "skiff" / "skiff.py"
    parser = runpy.run_path(str(script))["build_parser"]()

    assert parser.get_default("verify_ssl") is True


def test_scanner_ignores_inherited_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://outside-proxy.invalid:8080")

    class ClientReached(Exception):
        pass

    def inspect_client(**kwargs):
        assert kwargs["trust_env"] is False
        raise ClientReached

    monkeypatch.setattr(bughunt_scanner.httpx, "AsyncClient", inspect_client)
    with pytest.raises(ClientReached):
        asyncio.run(
            bughunt_scanner.scan_host(
                target="allowed.example",
                ports=[80],
                connect_timeout=1,
                http_timeout=1,
                concurrency=1,
                paths=["/"],
                follow_redirects=False,
                try_http=True,
                try_https=False,
                verify_tls=True,
                user_agents=[],
                rotate_agent=False,
                host_header=None,
                custom_headers={},
                collect_certs=False,
                keep_body=False,
                max_body=1024,
                delay_lo=0,
                delay_hi=0,
                proxy=None,
                sink=None,
                status_allow=None,
                grep=None,
                skip_tcp=True,
                method="GET",
                retries=0,
                auth=None,
            )
        )


def test_cors_probe_ignores_inherited_proxy(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://outside-proxy.invalid:8080")

    class ClientReached(Exception):
        pass

    def inspect_client(**kwargs):
        assert kwargs["trust_env"] is False
        raise ClientReached

    monkeypatch.setattr(bughunt_scanner.httpx, "AsyncClient", inspect_client)
    report = bughunt_scanner.HostReport("allowed.example", [], [], 0.0)
    with pytest.raises(ClientReached):
        asyncio.run(
            bughunt_scanner.cors_probe(report, timeout=1, verify_tls=True, proxy=None)
        )
