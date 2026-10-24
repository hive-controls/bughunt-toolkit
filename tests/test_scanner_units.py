"""Characterization oracle (M2): the scanner's public building blocks, one at a time.

Covers the names the behavior spec marks as the public surface and that no test exercised before:
``resolve_host``, ``tcp_probe``, ``banner_grab``, ``cors_probe``, ``error_hit``, ``scan_host`` and
``ArtifactSink``. Real loopback sockets are used wherever a behavior can be observed on the wire; the
only mocks sit at the network edge (``socket.getaddrinfo``, ``asyncio.open_connection``,
``httpx.AsyncClient``), exactly where the spec allows them.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import re
import socket
import time

import httpx
import pytest

from bughunt.core import egress, scanner
from scanner_oracle_support import (  # noqa: F401  (fixtures are consumed by name)
    LabServer,
    RawServer,
    closed_port,
    csv_rows_for,
    grant,
    lab,
    make_hit,
    workspace,
)


def run(coroutine):
    return asyncio.run(coroutine)


# ======================================================================================
# error_hit
# ======================================================================================


def test_error_hit_is_a_statusless_record_carrying_only_the_error():
    url = "https://x.example:8443/a?b=1"
    hit = scanner.error_hit("https", url, time.perf_counter() - 0.5, "boom")
    assert (hit.scheme, hit.url, hit.final_url, hit.status, hit.error) == (
        "https",
        url,
        url,
        None,
        "boom",
    )
    for field in (
        "reason",
        "server",
        "powered_by",
        "content_type",
        "location",
        "title",
        "snippet",
        "sha256",
    ):
        assert getattr(hit, field) == "", field
    assert (
        hit.bytes_read == 0
        and hit.tags == []
        and hit.headers == {}
        and hit.tls is None
        and hit.body == b""
    )
    assert 450 <= hit.elapsed_ms < 10_000  # (now - started) * 1000, in milliseconds


def test_error_hit_elapsed_scales_with_the_start_reference():
    recent = scanner.error_hit("http", "http://x/", time.perf_counter(), "e")
    older = scanner.error_hit("http", "http://x/", time.perf_counter() - 2.0, "e")
    assert recent.elapsed_ms < 500 and 1500 < older.elapsed_ms < 10_000


# ======================================================================================
# resolve_host
# ======================================================================================


def test_resolve_host_returns_unique_addresses_in_first_seen_order(lab, monkeypatch):
    asked = []

    def fake(host, *args, **kwargs):
        asked.append(host)
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("10.0.0.5", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.6", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    assert scanner.resolve_host("127.0.0.1") == ["10.0.0.5", "::1", "10.0.0.6"]
    assert asked == ["127.0.0.1"]


def test_resolve_host_lets_a_dns_failure_through_unchanged(lab, monkeypatch):
    def failing(host, *args, **kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", failing)
    with pytest.raises(
        socket.gaierror
    ):  # scan_main relies on this exact type to record a DNS failure
        scanner.resolve_host("127.0.0.1")


def test_resolve_host_refuses_a_host_without_a_grant_before_asking_dns(
    lab, monkeypatch
):
    asked = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: asked.append(a) or [])
    with pytest.raises(egress.PolicyBlocked):
        scanner.resolve_host("not-granted.example")
    assert asked == []


# ======================================================================================
# tcp_probe
# ======================================================================================


def test_tcp_probe_reports_open_and_closes_the_connection_immediately(workspace):
    server = RawServer(read_wait=2.0)
    try:
        grant(workspace, http=[server.port])
        assert run(scanner.tcp_probe("127.0.0.1", server.port, 2)) == (True, "")
        assert (
            server.eof_seen.wait(2.0) and server.received == []
        )  # connect-and-close: nothing was sent
    finally:
        server.close()


def test_tcp_probe_reports_a_closed_port_as_refused_or_timeout(lab):
    # A refused loopback connect is immediate on POSIX ("refused"); Windows lets it time out instead.
    opened, error = run(scanner.tcp_probe("127.0.0.1", lab.closed, 0.3))
    assert opened is False and error in {"refused", "timeout"}


def test_tcp_probe_maps_a_hung_connect_to_timeout(lab, monkeypatch):
    async def hang(host, port):
        await asyncio.sleep(30)

    monkeypatch.setattr(asyncio, "open_connection", hang)
    started = time.perf_counter()
    assert run(scanner.tcp_probe("127.0.0.1", lab.port, 0.1)) == (False, "timeout")
    assert time.perf_counter() - started < 5


@pytest.mark.parametrize(
    "raised, expected",
    [
        (ConnectionRefusedError(), "refused"),
        (
            OSError(errno.EHOSTUNREACH, "No route to host"),
            "No route to host",
        ),  # OS text when there is some
        (OSError("plain failure"), "plain failure"),  # str() when there is none
        (
            RuntimeError("something else"),
            "something else",
        ),  # any other exception: its text
    ],
)
def test_tcp_probe_error_text_by_failure_kind(lab, monkeypatch, raised, expected):
    async def fail(host, port):
        raise raised

    monkeypatch.setattr(asyncio, "open_connection", fail)
    assert run(scanner.tcp_probe("127.0.0.1", lab.port, 1)) == (False, expected)


class _FakeWriter:
    def close(self):
        pass

    async def wait_closed(self):
        pass


# The Windows default is the proactor loop and the Linux default is the selector loop; both must survive the
# stall. ProactorEventLoop is Windows-only, so it is included only where it exists (on ubuntu CI the selector
# leg runs on its own, against the real epoll loop).
_LOOP_FACTORIES = [("selector", asyncio.SelectorEventLoop)]
if hasattr(asyncio, "ProactorEventLoop"):
    _LOOP_FACTORIES.append(("proactor", asyncio.ProactorEventLoop))


@pytest.mark.parametrize("loop_name, loop_factory", _LOOP_FACTORIES)
def test_tcp_probe_does_not_report_a_connected_port_as_timeout_after_a_loop_stall(
    workspace, monkeypatch, loop_name, loop_factory
):
    # Deterministic reproduction of the high-concurrency false negative, with no host-speed dependence: a
    # connect that completes before the timeout but still needs two more loop steps to return, while a sibling
    # task stalls the loop past the timeout so the completion and the due timer land in the same ready batch.
    # The old wait_for cancels the already-connected probe -> (False, "timeout"); the bounded-yield grace lets
    # the connection object finish building first. RED without the grace, GREEN with it, on both loop types.
    port = 4321
    grant(workspace, http=[port])
    connect_lands, timeout, stall = 0.05, 0.1, 0.3

    async def fake_open_connection(host, probe_port):
        await asyncio.sleep(
            connect_lands
        )  # the kernel connect completes here, before the timeout
        await asyncio.sleep(0)  # create_connection's transport-waiter step
        await asyncio.sleep(
            0
        )  # selector loops deliver readiness via one more callback hop
        return None, _FakeWriter()

    async def blocker():
        await asyncio.sleep(0.01)  # let the probe arm its timer and issue the connect
        time.sleep(
            stall
        )  # synchronous stall > timeout: completion and timer land together

    async def scenario():
        result, _ = await asyncio.gather(
            scanner.tcp_probe("127.0.0.1", port, timeout), blocker()
        )
        return result

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    with asyncio.Runner(loop_factory=loop_factory) as runner:
        assert runner.run(scenario()) == (True, "")


def test_tcp_probe_cancels_and_reaps_a_hung_connect_on_timeout(workspace, monkeypatch):
    # The timeout path must cancel the connect task (not orphan it) and reap it before returning.
    port = 4322
    grant(workspace, http=[port])
    observed: dict[str, bool] = {}

    async def hung(host, probe_port):
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            observed["cancelled"] = True
            raise

    monkeypatch.setattr(asyncio, "open_connection", hung)
    started = time.perf_counter()
    assert run(scanner.tcp_probe("127.0.0.1", port, 0.1)) == (False, "timeout")
    assert (
        observed.get("cancelled") is True
    )  # the connect task was cancelled, not left running
    assert (
        time.perf_counter() - started < 3
    )  # and reaped promptly, not left to run its 5 s sleep


def test_tcp_probe_outer_cancellation_is_honored_and_cancels_the_connect(
    workspace, monkeypatch
):
    # An outer cancel (shutdown, gather cancel) must propagate AND cancel the in-flight connect, never orphan it.
    port = 4323
    grant(workspace, http=[port])
    observed: dict[str, bool] = {}

    async def hung(host, probe_port):
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            observed["inner_cancelled"] = True
            raise

    async def drive():
        probe = asyncio.ensure_future(scanner.tcp_probe("127.0.0.1", port, 5))
        await asyncio.sleep(0.05)  # let the probe enter its bounded wait
        probe.cancel()
        with pytest.raises(
            asyncio.CancelledError
        ):  # the outer cancel is propagated, not swallowed
            await probe
        for _ in range(5):  # let the inner connect task process its cancellation
            await asyncio.sleep(0)
        return observed.get(
            "inner_cancelled"
        )  # checked before loop teardown would cancel any orphan

    monkeypatch.setattr(asyncio, "open_connection", hung)
    assert run(drive()) is True


# ======================================================================================
# banner_grab
# ======================================================================================


def _raw(banner: bytes, workspace, port: int = 0):
    try:
        server = RawServer(banner=banner, port=port)
    except OSError:
        pytest.skip(f"cannot bind loopback port {port} on this machine")
    grant(workspace, http=[server.port])
    return server


@pytest.mark.parametrize(
    "sent, expected",
    [
        (b"SSH-2.0-lab\r\n", "SSH-2.0-lab"),  # surrounding CR/LF trimmed
        (
            b"220 hello\r\nwelcome",
            "220 hello  welcome",
        ),  # each CR and LF becomes a space
        (b"\xff\xfeAB", "��AB"),  # undecodable bytes are replaced, not fatal
        (
            b"a" * 300,
            "a" * 200,
        ),  # at most 256 bytes are read, then the text is cut to 200 characters
    ],
)
def test_banner_grab_decodes_and_trims_what_the_server_says_first(
    workspace, sent, expected
):
    server = _raw(sent, workspace)
    try:
        assert run(scanner.banner_grab("127.0.0.1", server.port, 1)) == expected
    finally:
        server.close()


def test_banner_grab_returns_empty_text_for_a_silent_server_and_a_closed_port(
    workspace,
):
    server = _raw(b"", workspace)
    dead = closed_port()
    grant(workspace, http=[server.port, dead])
    try:
        assert run(scanner.banner_grab("127.0.0.1", server.port, 0.3)) == ""
        assert run(scanner.banner_grab("127.0.0.1", dead, 0.3)) == ""
    finally:
        server.close()


def test_banner_grab_sends_nothing_to_an_ordinary_port(workspace):
    server = _raw(b"hi\r\n", workspace)
    try:
        assert run(scanner.banner_grab("127.0.0.1", server.port, 1)) == "hi"
        assert server.eof_seen.wait(2.0) and server.received == []
    finally:
        server.close()


@pytest.mark.parametrize(
    "port, payload",
    [
        (2525, b"EHLO bughunt.local\r\n"),
        (587, b"EHLO bughunt.local\r\n"),
        (25, b"EHLO bughunt.local\r\n"),
        (6379, b"PING\r\n"),
    ],
)
def test_banner_grab_greets_smtp_and_redis_ports_before_reading(
    workspace, port, payload
):
    server = _raw(b"220 mail.example\r\n", workspace, port=port)
    try:
        assert run(scanner.banner_grab("127.0.0.1", port, 1)) == "220 mail.example"
        deadline = time.time() + 2
        while not server.received and time.time() < deadline:
            time.sleep(0.02)
        assert server.received == [payload]
    finally:
        server.close()


class _FakeReader:
    async def read(self, limit):
        return b"220 hello\r\n"

    async def drain(self):
        pass


class _FakeBannerWriter(_FakeWriter):
    def write(self, data):
        pass

    async def drain(self):
        pass


@pytest.mark.parametrize("loop_name, loop_factory", _LOOP_FACTORIES)
def test_banner_grab_keeps_a_connected_banner_after_a_loop_stall(
    workspace, monkeypatch, loop_name, loop_factory
):
    # Same deterministic race as the tcp_probe grace test: the connect completes before the timeout but needs two
    # more loop steps, while a sibling stalls the loop past the timeout. Without the shared grace the connected
    # socket is cancelled and the banner comes back empty; with it the banner is captured.
    port = 4323
    grant(workspace, http=[port])
    connect_lands, timeout, stall = 0.05, 0.1, 0.3

    async def fake_open_connection(host, probe_port):
        await asyncio.sleep(connect_lands)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return _FakeReader(), _FakeBannerWriter()

    async def blocker():
        await asyncio.sleep(0.01)
        time.sleep(stall)

    async def scenario():
        result, _ = await asyncio.gather(
            scanner.banner_grab("127.0.0.1", port, timeout), blocker()
        )
        return result

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    with asyncio.Runner(loop_factory=loop_factory) as runner:
        assert runner.run(scenario()) == "220 hello"


def test_banner_grab_cancels_and_reaps_a_hung_connect_on_timeout(
    workspace, monkeypatch
):
    port = 4324
    grant(workspace, http=[port])
    observed: dict[str, bool] = {}

    async def hung(host, probe_port):
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            observed["cancelled"] = True
            raise

    monkeypatch.setattr(asyncio, "open_connection", hung)
    started = time.perf_counter()
    assert run(scanner.banner_grab("127.0.0.1", port, 0.1)) == ""
    assert observed.get("cancelled") is True and time.perf_counter() - started < 3


def test_clamped_concurrency_never_exceeds_the_profile_cap(workspace):
    grant(workspace, http=[4325])  # the fixture policy caps concurrency at 100
    assert scanner._clamped_concurrency(256) == 100
    assert scanner._clamped_concurrency(8) == 8
    assert scanner._clamped_concurrency(100) == 100


def test_scan_host_fans_out_at_the_clamped_concurrency(lab, monkeypatch):
    seen: dict[str, int] = {}

    async def spy(target, ports, timeout, concurrency, jitter, skip_tcp):
        seen["concurrency"] = concurrency
        return []

    monkeypatch.setattr(scanner, "probe_ports", spy)
    call_scan_host(lab, ports=[lab.port], concurrency=256)
    assert seen["concurrency"] == 100


# ======================================================================================
# cors_probe
# ======================================================================================


def _report(lab, *hits):
    return scanner.HostReport(
        "127.0.0.1",
        ["127.0.0.1"],
        [scanner.PortResult(lab.port, True, hits=list(hits))],
        0.0,
    )


def _live(lab, path: str, **extra):
    return make_hit("http", lab.base(path), status=extra.pop("status", 200), **extra)


def _probe(lab, report, **kwargs):
    run(
        scanner.cors_probe(
            report, timeout=kwargs.pop("timeout", 2), verify_tls=True, proxy=None
        )
    )
    return report.findings


def _options(lab):
    return [item for item in lab.requests if item.method == "OPTIONS"]


def test_cors_probe_flags_a_reflected_origin_as_high_for_each_probe_origin(lab):
    lab.server.cors = "echo"
    findings = _probe(lab, _report(lab, _live(lab, "/")))
    assert [
        (item.severity, item.title, item.url, item.evidence) for item in findings
    ] == [
        ("high", "Permissive CORS", lab.base("/"), "https://bughunt.invalid"),
        ("high", "Permissive CORS", lab.base("/"), "http://127.0.0.1"),
    ]
    assert (
        findings[0].detail
        == "OPTIONS Origin https://bughunt.invalid → https://bughunt.invalid"
    )
    assert findings[1].detail == "OPTIONS Origin http://127.0.0.1 → http://127.0.0.1"
    assert [
        (item.headers["origin"], item.headers["access-control-request-method"])
        for item in _options(lab)
    ] == [("https://bughunt.invalid", "GET"), ("http://127.0.0.1", "GET")]


def test_cors_probe_flags_a_wildcard_as_medium(lab):
    lab.server.cors = "star"
    findings = _probe(lab, _report(lab, _live(lab, "/")))
    assert [(item.severity, item.evidence) for item in findings] == [
        ("medium", "*"),
        ("medium", "*"),
    ]
    assert findings[0].detail == "OPTIONS Origin https://bughunt.invalid → *"


def test_cors_probe_adds_nothing_when_the_server_sends_no_allow_origin(lab):
    lab.server.cors = "none"
    assert _probe(lab, _report(lab, _live(lab, "/"))) == [] and len(_options(lab)) == 2


def test_cors_probe_prefers_root_hits_and_probes_at_most_six_of_them(lab):
    lab.server.cors = "echo"
    root_hits = [_live(lab, "/") for _ in range(8)] + [_live(lab, "/admin")]
    _probe(lab, _report(lab, *root_hits))
    assert [item.path for item in _options(lab)] == [
        "/"
    ] * 12  # 6 hits x 2 origins, /admin never probed


def test_cors_probe_falls_back_to_the_first_four_live_hits_when_there_is_no_root_hit(
    lab,
):
    lab.server.cors = "echo"
    paths = ["/a", "/b", "/c", "/d", "/e", "/f"]
    _probe(lab, _report(lab, *[_live(lab, path) for path in paths]))
    assert [item.path for item in _options(lab)] == [
        "/a",
        "/a",
        "/b",
        "/b",
        "/c",
        "/c",
        "/d",
        "/d",
    ]


def test_cors_probe_ignores_hits_that_are_not_live(lab):
    lab.server.cors = "echo"
    dead = make_hit("http", lab.base("/"), error="connect: refused")
    findings = _probe(lab, _report(lab, dead, _live(lab, "/admin")))
    assert findings and {item.path for item in _options(lab)} == {
        "/admin"
    }  # no root hit is live: fallback list


def test_cors_probe_skips_failed_requests_without_raising(lab):
    unreachable = make_hit("http", f"http://127.0.0.1:{lab.closed}/", status=200)
    report = _report(lab, unreachable)
    assert _probe(lab, report, timeout=0.3) == []


def test_cors_probe_appends_without_deduplicating(lab):
    lab.server.cors = "echo"
    report = _report(lab, _live(lab, "/"))
    _probe(lab, report)
    _probe(lab, report)
    assert len(report.findings) == 4


# ======================================================================================
# scan_host (direct)
# ======================================================================================


def call_scan_host(lab, **overrides):
    arguments = dict(
        target="127.0.0.1",
        ports=[lab.port],
        connect_timeout=0.4,
        http_timeout=3.0,
        concurrency=8,
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
        keep_body=True,
        max_body=1024,
        delay_lo=0,
        delay_hi=0,
        proxy=None,
        sink=None,
        status_allow=None,
        grep=None,
        skip_tcp=False,
        method="GET",
        retries=0,
        auth=None,
    )
    arguments.update(overrides)
    return run(scanner.scan_host(**arguments))


def test_scan_host_returns_one_record_per_port_in_input_order_closed_ports_included(
    lab,
):
    results = call_scan_host(lab, ports=[lab.closed, lab.port], paths=["/", "/admin"])
    assert [item.port for item in results] == [lab.closed, lab.port]
    closed, opened = results
    assert (
        closed.tcp_open is False
        and closed.hits == []
        and closed.tcp_error in {"refused", "timeout"}
    )
    assert opened.tcp_open is True and opened.tcp_error == ""
    assert [hit.url for hit in opened.hits] == [lab.base("/"), lab.base("/admin")]


def test_scan_host_sends_no_http_when_nothing_is_tcp_open(lab):
    results = call_scan_host(lab, ports=[lab.closed], connect_timeout=0.3)
    assert [item.tcp_open for item in results] == [False] and lab.requests == []


def test_scan_host_skip_tcp_marks_every_port_open_and_tries_http_on_dead_ports(lab):
    results = call_scan_host(
        lab,
        ports=[lab.closed, lab.port],
        skip_tcp=True,
        connect_timeout=0.3,
        http_timeout=0.5,
    )
    dead, alive = results
    assert (
        dead.tcp_open
        and alive.tcp_open
        and dead.tcp_error == ""
        and alive.tcp_error == ""
    )
    (dead_hit,) = dead.hits
    assert dead_hit.status is None and (
        dead_hit.error == "timeout" or dead_hit.error.startswith("connect:")
    )
    assert alive.hits[0].status == 200


def test_scan_host_hits_follow_job_order_not_completion_order(lab):
    lab.server.slow_seconds = 0.6
    (result,) = call_scan_host(lab, paths=["/slow", "/", "/admin"])
    assert [hit.url.removeprefix(lab.base("")) for hit in result.hits] == [
        "/slow",
        "/",
        "/admin",
    ]


def test_scan_host_both_schemes_are_tried_http_first_for_each_path(lab):
    (result,) = call_scan_host(
        lab, paths=["/", "/admin"], try_https=True, http_timeout=0.5
    )
    schemes = [
        (hit.scheme, hit.url.removeprefix(f"{hit.scheme}://127.0.0.1:{lab.port}"))
        for hit in result.hits
    ]
    # Job order within a port is scheme-major: every http path first, then every https path.
    assert schemes == [
        ("http", "/"),
        ("http", "/admin"),
        ("https", "/"),
        ("https", "/admin"),
    ]


def test_scan_host_timeout_is_a_statusless_error_hit_that_is_not_live(lab, tmp_path):
    (result,) = call_scan_host(lab, paths=["/slow"], http_timeout=0.3)
    (hit,) = result.hits
    assert hit.status is None and hit.error == "timeout" and hit.elapsed_ms >= 250
    assert hit.final_url == hit.url and hit.bytes_read == 0 and hit.sha256 == ""
    assert (
        csv_rows_for(tmp_path, hit) == []
    )  # "timeout" is a noise word: not a live hit


def test_scan_host_retries_back_off_150_then_300_milliseconds_between_attempts(lab):
    (result,) = call_scan_host(
        lab,
        ports=[lab.closed],
        skip_tcp=True,
        connect_timeout=0.2,
        http_timeout=0.2,
        retries=2,
    )
    (hit,) = result.hits
    assert hit.status is None
    assert (
        hit.elapsed_ms >= 445
    )  # two waits, 0.15 s then 0.30 s; the attempts themselves are on top of that


def test_scan_host_does_not_retry_when_retries_is_zero(lab):
    started = time.perf_counter()
    call_scan_host(
        lab,
        ports=[lab.closed],
        skip_tcp=True,
        connect_timeout=0.2,
        http_timeout=0.2,
        retries=0,
    )
    assert time.perf_counter() - started < 2.0


def test_scan_host_empty_response_has_empty_digest_and_zero_bytes(lab):
    (result,) = call_scan_host(lab, paths=["/empty"])
    (hit,) = result.hits
    assert (hit.status, hit.reason, hit.bytes_read, hit.sha256, hit.tags) == (
        204,
        "No Content",
        0,
        "",
        [],
    )


def test_scan_host_stores_a_truncated_body_but_hashes_and_counts_the_full_one(lab):
    (result,) = call_scan_host(lab, paths=["/big"], max_body=1024)
    (hit,) = result.hits
    assert len(hit.body) == 1024 and hit.bytes_read == 5000
    assert (
        hit.sha256 == hashlib.sha256(b"x" * 5000).hexdigest()[:16]
    )  # of the FULL body, not the stored part


def test_scan_host_still_derives_title_and_snippet_when_bodies_are_not_kept(lab):
    (result,) = call_scan_host(lab, paths=["/", "/big"], keep_body=False)
    root, big = result.hits
    assert root.body == b"" and big.body == b""
    assert (
        root.title == "Lab Home | Page" and root.snippet == "Lab Home | Page nginx demo"
    )
    assert big.snippet == "x" * 180  # cut to 180 characters


def test_scan_host_filters_tag_failing_status_hits_but_never_error_hits(lab):
    pattern = re.compile("nope", re.I)
    (result,) = call_scan_host(
        lab, paths=["/", "/missing"], status_allow={404}, grep=pattern
    )
    root, missing = result.hits
    assert (
        "filtered" in root.tags and "filtered" not in missing.tags
    )  # / is 200 and has no "nope"
    (dead_result,) = call_scan_host(
        lab,
        ports=[lab.closed],
        skip_tcp=True,
        connect_timeout=0.2,
        http_timeout=0.2,
        status_allow={200},
        grep=pattern,
    )
    assert (
        dead_result.hits[0].status is None
        and "filtered" not in dead_result.hits[0].tags
    )  # never tagged


def test_scan_host_treats_an_empty_status_set_as_no_filter(lab):
    (result,) = call_scan_host(lab, paths=["/", "/admin"], status_allow=set())
    assert all("filtered" not in hit.tags for hit in result.hits)


def test_scan_host_offers_only_live_unfiltered_hits_to_the_sink(lab, tmp_path):
    sink = scanner.ArtifactSink(
        tmp_path / "urls.txt", tmp_path / "pages", tmp_path / "headers"
    )
    call_scan_host(
        lab, paths=["/", "/admin", "/missing"], status_allow={200}, sink=sink
    )
    sink.close()
    assert sink.seen_urls == {lab.base("/")}
    assert [item.name for item in (tmp_path / "pages").iterdir()] == [
        f"127.0.0.1_{lab.port}_http_root.html"
    ]


def test_scan_host_custom_headers_replace_defaults_and_host_and_auth_are_forced(lab):
    call_scan_host(
        lab,
        custom_headers={"Accept": "text/x-lab", "X-Mine": "1"},
        host_header=f"localhost:{lab.port}",
        auth=httpx.BasicAuth("u", "p"),
        user_agents=["Agent-A", "Agent-B"],
        rotate_agent=True,
    )
    sent = lab.requests[0].headers
    assert (
        sent["accept"] == "text/x-lab"
        and sent["x-mine"] == "1"
        and sent["host"] == f"localhost:{lab.port}"
    )
    assert sent["authorization"] == "Basic dTpw"
    assert (
        sent["user-agent"] == "Bughunt-owned-lab"
    )  # the guarded client always writes the policy's agent


def test_scan_host_request_time_policy_denial_is_recorded_but_not_live(lab, tmp_path):
    grant(
        lab.workspace,
        http=[lab.port],
        exclusions=[(f"http://127.0.0.1:{lab.port}", ["/private"])],
    )
    (result,) = call_scan_host(lab, paths=["/private", "/"])
    denied, allowed = result.hits
    assert (
        denied.status is None
        and denied.error == "asset-excluded; no outbound action ran"
    )
    assert allowed.status == 200
    rows = csv_rows_for(tmp_path, denied, port=lab.port)
    assert rows == [] and denied.tags == ["policy-blocked"]
    assert lab.server.paths() == ["/"]  # the denied request never reached the server


def test_scan_host_jitter_delays_every_tcp_connect_and_every_request(lab):
    started = time.perf_counter()
    call_scan_host(lab, delay_lo=0.2, delay_hi=0.2, skip_tcp=True)
    skip_tcp_seconds = time.perf_counter() - started
    started = time.perf_counter()
    call_scan_host(lab, delay_lo=0.2, delay_hi=0.2)
    both_seconds = time.perf_counter() - started
    assert (
        skip_tcp_seconds >= 0.19 and both_seconds >= 0.39
    )  # one wait, then two waits (lower bounds only)


@pytest.mark.parametrize("concurrency, ceiling", [(8, 4), (24, 12)])
def test_scan_host_http_concurrency_is_half_the_tcp_concurrency_with_a_floor_of_four(
    lab, concurrency, ceiling
):
    lab.server.slow_seconds = 0.25
    paths = [f"/slow?n={index}" for index in range(ceiling * 2)]
    call_scan_host(lab, paths=paths, concurrency=concurrency, http_timeout=5)
    assert (
        2 <= lab.server.max_inflight <= ceiling
    )  # never above max(4, concurrency // 2)


def test_scan_host_builds_one_guarded_client_with_the_documented_settings(
    workspace, monkeypatch
):
    class ClientReached(Exception):
        pass

    captured = {}

    def inspect_client(**kwargs):
        captured.update(kwargs)
        raise ClientReached

    monkeypatch.setattr(scanner.httpx, "AsyncClient", inspect_client)
    auth = httpx.BasicAuth("u", "p")
    with pytest.raises(ClientReached):
        run(
            scanner.scan_host(
                target="127.0.0.1",
                ports=[80],
                connect_timeout=1.5,
                http_timeout=7.0,
                concurrency=300,
                paths=["/"],
                follow_redirects=False,
                try_http=True,
                try_https=False,
                verify_tls=False,
                user_agents=["Agent-A", "Agent-B"],
                rotate_agent=False,
                host_header="vhost.example",
                custom_headers={"Accept": "x/y", "X-Mine": "1"},
                collect_certs=False,
                keep_body=False,
                max_body=1024,
                delay_lo=0,
                delay_hi=0,
                proxy="http://proxy.example:8080",
                sink=None,
                status_allow=None,
                grep=None,
                skip_tcp=True,
                method="GET",
                retries=0,
                auth=auth,
            )
        )
    assert (
        captured["trust_env"] is False
        and captured["follow_redirects"] is False
        and captured["verify"] is False
    )
    assert (
        captured["timeout"] == httpx.Timeout(7.0, connect=1.5)
        and captured["http2"] is False
    )
    assert captured["limits"] == httpx.Limits(
        max_connections=150, max_keepalive_connections=75
    )
    assert captured["auth"] is auth and captured["proxy"] == "http://proxy.example:8080"
    assert captured["headers"] == {
        "User-Agent": "Agent-A",
        "Accept": "x/y",
        "X-Mine": "1",
        "Host": "vhost.example",
    }


def test_scan_host_client_settings_floor_and_defaults(workspace, monkeypatch):
    class ClientReached(Exception):
        pass

    captured = {}

    def inspect_client(**kwargs):
        captured.update(kwargs)
        raise ClientReached

    monkeypatch.setattr(scanner.httpx, "AsyncClient", inspect_client)
    with pytest.raises(ClientReached):
        run(
            scanner.scan_host(
                target="127.0.0.1",
                ports=[80],
                connect_timeout=1.0,
                http_timeout=4.0,
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
    assert captured["limits"] == httpx.Limits(
        max_connections=8, max_keepalive_connections=4
    )
    assert (
        "proxy" not in captured
        and captured["verify"] is True
        and captured["auth"] is None
    )
    assert (
        captured["headers"]["Accept"] == "*/*" and captured["headers"]["User-Agent"]
    )  # an agent is always sent
    assert "Host" not in captured["headers"]


# ======================================================================================
# fetch_once: a connect-phase timeout never sent the request, so it earns one free extra attempt
# ======================================================================================


class _ScriptedTransport(httpx.AsyncBaseTransport):
    """The network edge under the real guarded client: each attempt raises the next scripted error or answers 200."""

    def __init__(self, *outcomes):
        self.outcomes, self.attempts = list(outcomes), 0

    async def handle_async_request(self, request):
        self.attempts += 1
        outcome = self.outcomes.pop(0)
        if outcome is not None:
            raise outcome
        return httpx.Response(200, content=b"ok", request=request)


def _guarded_fetch(lab, monkeypatch, outcomes, retries=0):
    """Drive fetch_once through the real egress guard; return (hit, scripted transport, guard-reserved URLs)."""
    transport = _ScriptedTransport(*outcomes)
    reserved_urls = []
    real_reserve = egress._reserve_async

    async def spy_on_reserve(url, *args, **kwargs):
        reserved_urls.append(url)
        return await real_reserve(url, *args, **kwargs)

    monkeypatch.setattr(egress, "_reserve_async", spy_on_reserve)

    async def drive():
        async with egress.async_client(
            operation="active_scan",
            transport=transport,
            timeout=httpx.Timeout(2.0, connect=0.5),
        ) as client:
            return await scanner.fetch_once(
                client,
                "GET",
                "http",
                "127.0.0.1",
                lab.port,
                "/x",
                True,
                4096,
                retries,
                None,
            )

    return run(drive()), transport, reserved_urls


def test_fetch_once_retries_a_connect_timeout_once_with_zero_retries_and_guards_both_attempts(
    lab, monkeypatch
):
    hit, transport, reserved_urls = _guarded_fetch(
        lab, monkeypatch, [httpx.ConnectTimeout("stalled"), None]
    )
    assert (hit.status, hit.error, transport.attempts) == (200, "", 2)
    assert (
        reserved_urls == [lab.base("/x")] * 2
    )  # the extra attempt re-entered the policy/scope guard, not around it


@pytest.mark.parametrize("retries", [0, 3])
def test_fetch_once_never_retries_a_policy_denial(retries):
    class DeniedClient:
        attempts = 0

        async def request(self, *args, **kwargs):
            self.attempts += 1
            raise egress.PolicyBlocked("asset-excluded; no outbound action ran")

    client = DeniedClient()
    hit = run(
        scanner.fetch_once(
            client, "GET", "http", "127.0.0.1", 80, "/", False, 1024, retries, None
        )
    )
    assert client.attempts == 1
    assert hit.status is None and hit.tags == ["policy-blocked"]
    assert hit.error == "asset-excluded; no outbound action ran"
    assert not scanner.speaking(hit)


def test_fetch_once_gives_the_free_connect_retry_only_once(lab, monkeypatch):
    hit, transport, reserved_urls = _guarded_fetch(
        lab,
        monkeypatch,
        [httpx.ConnectTimeout("first"), httpx.ConnectTimeout("second"), None],
    )
    assert (hit.status, hit.error, transport.attempts) == (
        None,
        "timeout",
        2,
    )  # no third attempt, same result text
    assert len(reserved_urls) == 2


def test_fetch_once_free_connect_retry_does_not_consume_the_retries_budget(
    lab, monkeypatch
):
    outcomes = [httpx.ConnectTimeout("stalled"), httpx.ReadTimeout("slow"), None]
    hit, transport, _ = _guarded_fetch(lab, monkeypatch, outcomes, retries=1)
    # attempt 1 is the free one; --retries 1 still buys the two ordinary attempts after it
    assert (hit.status, hit.error, transport.attempts) == (200, "", 3)


@pytest.mark.parametrize(
    "failure, expected_error",
    [
        (httpx.ReadTimeout("slow"), "timeout"),
        (httpx.ConnectError("refused"), "connect: refused"),
    ],
)
def test_fetch_once_gives_no_free_retry_to_other_failures(
    lab, monkeypatch, failure, expected_error
):
    hit, transport, _ = _guarded_fetch(lab, monkeypatch, [failure, None])
    assert (hit.status, hit.error, transport.attempts) == (None, expected_error, 1)


# ======================================================================================
# ArtifactSink
# ======================================================================================


def _sink(tmp_path, **kwargs):
    return scanner.ArtifactSink(
        tmp_path / "urls.txt", tmp_path / "pages", tmp_path / "headers", **kwargs
    )


def _live_hit(url="http://127.0.0.1:80/", **extra):
    defaults = dict(
        status=200,
        reason="OK",
        content_type="text/html",
        sha256="ab12cd34ef56ab12",
        body=b"<html>x</html>",
        bytes_read=14,
        headers={"server": "nginx", "x-a": "1"},
    )
    defaults.update(extra)
    return make_hit(url.split(":")[0], url, **defaults)


def test_sink_creates_directories_opens_the_url_file_for_append_and_close_is_idempotent(
    workspace, tmp_path
):
    urls = tmp_path / "deep" / "er" / "urls.txt"
    urls.parent.mkdir(parents=True)
    urls.write_text("previous\n", encoding="utf-8")
    sink = scanner.ArtifactSink(
        urls, tmp_path / "a" / "pages", tmp_path / "b" / "headers"
    )
    assert (tmp_path / "a" / "pages").is_dir() and (tmp_path / "b" / "headers").is_dir()
    sink.capture("h", 80, _live_hit())
    sink.close()
    sink.close()
    assert urls.read_text(encoding="utf-8").splitlines() == [
        "previous",
        "http://127.0.0.1:80/",
    ]


def test_sink_with_every_destination_unset_does_nothing_and_does_not_fail(workspace):
    sink = scanner.ArtifactSink(None, None, None)
    sink.capture("h", 80, _live_hit())
    sink.close()
    assert (
        sink.seen_urls == set()
    )  # the URL list is off, so nothing is remembered either


def test_sink_ignores_hits_that_are_not_live(workspace, tmp_path):
    sink = _sink(tmp_path)
    sink.capture("h", 80, make_hit("http", "http://h/", error="timeout"))
    sink.capture("h", 80, make_hit("http", "http://h/", error=""))
    sink.capture(
        "h",
        80,
        make_hit("http", "http://h/", error="asset-excluded", tags=["policy-blocked"]),
    )
    sink.close()
    assert sink.seen_urls == set() and list((tmp_path / "pages").iterdir()) == []
    assert list((tmp_path / "headers").iterdir()) == []


@pytest.mark.parametrize(
    "host, port, scheme, url, stem",
    [
        (
            "127.0.0.1",
            80,
            "http",
            "http://127.0.0.1:80/.git/HEAD",
            "127.0.0.1_80_http_.git_HEAD",
        ),
        (
            "Ex Ample:1",
            8080,
            "https",
            "https://x.example:8080/a b/c?d=e",
            "Ex_Ample_1_8080_https_a_b_c",
        ),
        ("h.example", 443, "https", "https://h.example/", "h.example_443_https_root"),
        ("h", 80, "http", "http://h/dir/", "h_80_http_dir"),
        (
            "h",
            80,
            "http",
            "http://h/a?x=1",
            "h_80_http_a",
        ),  # the query is not part of the file stem
        (
            "h" * 100,
            80,
            "http",
            "http://h/" + "p" * 100,
            "h" * 80 + "_80_http_" + "p" * 60,
        ),
    ],
)
def test_sink_file_stem_vectors(workspace, tmp_path, host, port, scheme, url, stem):
    sink = _sink(tmp_path)
    sink.capture(
        host,
        port,
        make_hit(
            scheme, url, status=200, reason="OK", body=b"x", content_type="text/plain"
        ),
    )
    sink.close()
    assert [item.name for item in (tmp_path / "headers").iterdir()] == [
        f"{stem}.headers.txt"
    ]
    assert [item.name for item in (tmp_path / "pages").iterdir()] == [f"{stem}.txt"]


def test_sink_different_queries_on_one_path_share_a_stem_and_the_later_one_wins(
    workspace, tmp_path
):
    sink = _sink(tmp_path)
    sink.capture(
        "h",
        80,
        make_hit(
            "http",
            "http://h/a?x=1",
            status=200,
            body=b"first",
            content_type="text/plain",
        ),
    )
    sink.capture(
        "h",
        80,
        make_hit(
            "http",
            "http://h/a?x=2",
            status=200,
            body=b"second",
            content_type="text/plain",
        ),
    )
    sink.close()
    assert [item.read_bytes() for item in (tmp_path / "pages").iterdir()] == [b"second"]
    assert sink.seen_urls == {"http://h/a?x=1", "http://h/a?x=2"}


@pytest.mark.parametrize(
    "content_type, body, extension",
    [
        ("application/json", b"[]", ".json"),
        ("text/plain", b' {"a":1}', ".json"),
        ("text/html", b'{"x":1}', ".json"),
        ("text/html", b"<p>", ".html"),
        ("", b"<!DOCTYPE html>", ".html"),
        ("", b"  <!doctype html>", ".html"),
        ("", b"x<html>", ".html"),
        ("application/xml", b"<a/>", ".xml"),
        ("text/xml", b"<a/>", ".xml"),
        ("application/javascript", b"var a", ".js"),
        ("text/css", b"a{}", ".css"),
        ("text/plain", b"hi", ".txt"),
        ("image/png", b"\x89PNG", ".bin"),
        ("", b"plain", ".bin"),
    ],
)
def test_sink_extension_rules_in_priority_order(
    workspace, tmp_path, content_type, body, extension
):
    sink = _sink(tmp_path)
    sink.capture(
        "h",
        80,
        make_hit(
            "http", "http://h/f", status=200, body=body, content_type=content_type
        ),
    )
    sink.close()
    assert [item.name for item in (tmp_path / "pages").iterdir()] == [
        f"h_80_http_f{extension}"
    ]


def test_sink_writes_no_source_file_for_a_hit_without_a_body(workspace, tmp_path):
    sink = _sink(tmp_path)
    sink.capture(
        "h", 80, make_hit("http", "http://h/", status=302, reason="Found", body=b"")
    )
    sink.close()
    assert (
        list((tmp_path / "pages").iterdir()) == []
        and len(list((tmp_path / "headers").iterdir())) == 1
    )


def test_sink_header_file_layout_and_redaction(workspace, tmp_path):
    hit = _live_hit(
        "http://h.example:81/p?token=secret-query",
        headers={"server": "nginx", "set-cookie": "sid=cookie-secret", "x-a": "1"},
    )
    hit.final_url = "http://h.example:81/p?token=secret-query"
    sink = _sink(tmp_path)
    sink.capture("h.example", 81, hit)
    sink.close()
    text = (tmp_path / "headers" / "h.example_81_http_p.headers.txt").read_text(
        encoding="utf-8"
    )
    assert "secret-query" not in text and "cookie-secret" not in text
    lines = text.splitlines()
    assert lines[0].startswith("URL: http://h.example:81/p?token=") and lines[
        1
    ].startswith("Final-URL: ")
    assert (
        lines[2] == "Status: 200 OK"
        and lines[3] == "SHA256-16: ab12cd34ef56ab12"
        and lines[4] == ""
    )
    assert "server: nginx" in lines and "x-a: 1" in lines and text.endswith("\n")


def test_sink_status_line_is_trimmed_for_statusless_live_hits(workspace, tmp_path):
    sink = _sink(tmp_path)
    sink.capture(
        "h", 80, make_hit("http", "http://h/", error="Invalid port: ':1:80'")
    )  # live-looking error hit
    sink.close()
    text = (tmp_path / "headers" / "h_80_http_root.headers.txt").read_text(
        encoding="utf-8"
    )
    assert text.splitlines()[2] == "Status: None" and sink.seen_urls == {"http://h/"}


def test_sink_url_file_is_redacted_but_deduplicates_on_the_raw_url(workspace, tmp_path):
    sink = _sink(tmp_path)
    for _ in range(2):
        sink.capture("h", 80, _live_hit("http://h/?api_key=hunter2hunter2"))
    sink.close()
    assert sink.seen_urls == {"http://h/?api_key=hunter2hunter2"}
    written = (tmp_path / "urls.txt").read_text(encoding="utf-8")
    assert (
        written.count("\n") == 1
        and "hunter2" not in written
        and "[REDACTED]" in written
    )


def test_sink_records_the_final_url_but_names_files_after_the_requested_path(
    workspace, tmp_path
):
    hit = _live_hit("http://h/old")
    hit.final_url = "http://h/new"
    sink = _sink(tmp_path)
    sink.capture("h", 80, hit)
    sink.close()
    assert sink.seen_urls == {"http://h/new"}
    assert [item.name for item in (tmp_path / "headers").iterdir()] == [
        "h_80_http_old.headers.txt"
    ]


def test_sink_redacts_credentials_inside_saved_bodies(workspace, tmp_path):
    sink = _sink(tmp_path)
    sink.capture(
        "h",
        80,
        make_hit(
            "http",
            "http://h/f",
            status=200,
            content_type="text/plain",
            body=b"hello\nAuthorization: Bearer top-secret-token\nbye",
        ),
    )
    sink.close()
    saved = (tmp_path / "pages" / "h_80_http_f.txt").read_bytes()
    assert b"top-secret-token" not in saved and saved.startswith(b"hello")


# ======================================================================================
# analyze_hit: backup/sensitive-path severity gate (BH-4)
# ======================================================================================

_SPA_INDEX = (
    b"<!doctype html><html><head><title>App</title></head><body>app shell</body></html>"
)


def _sensitive_findings(hit):
    report = scanner.HostReport("h.example", ["h.example"], [], 0.0)
    return [
        (item.severity, item.title)
        for item in scanner.analyze_hit(report, hit)
        if item.title.startswith("Sensitive path")
    ]


def test_backup_archive_soft_404_html_is_not_scored_high():
    hit = make_hit(
        "http",
        "http://h.example/backup.zip",
        status=200,
        content_type="text/html; charset=utf-8",
        body=_SPA_INDEX,
    )
    findings = _sensitive_findings(hit)
    assert ("high", "Sensitive path responded") not in findings
    assert findings and all(
        severity != "high" for severity, _ in findings
    )  # downgraded, not dropped


def test_git_config_with_non_html_content_stays_high():
    hit = make_hit(
        "http",
        "http://h.example/.git/config",
        status=200,
        content_type="text/plain",
        body=b"[core]\n\trepositoryformatversion = 0\n",
    )
    assert ("high", "Sensitive path responded") in _sensitive_findings(hit)


def test_backup_archive_with_zip_magic_stays_high_under_an_html_content_type():
    hit = make_hit(
        "http",
        "http://h.example/backup.zip",
        status=200,
        content_type="text/html",
        body=b"PK\x03\x04\x14\x00backup bytes",
    )
    assert ("high", "Sensitive path responded") in _sensitive_findings(hit)


def test_dotenv_exposed_as_text_stays_high():
    hit = make_hit(
        "http",
        "http://h.example/.env",
        status=200,
        content_type="text/plain",
        body=b"SECRET=1\n",
    )
    assert ("high", "Sensitive path responded") in _sensitive_findings(hit)


def test_tightened_markers_do_not_match_a_nested_backup_html_or_envrc():
    backup_html = make_hit(
        "http",
        "http://h.example/old/backup.html",
        status=200,
        content_type="text/plain",
        body=b"not an archive",
    )
    envrc = make_hit(
        "http",
        "http://h.example/.envrc",
        status=200,
        content_type="text/plain",
        body=b"export FOO=bar",
    )
    assert _sensitive_findings(backup_html) == []
    assert _sensitive_findings(envrc) == []


# ---- FIX-NEEDED review follow-up: content-type is server-controlled; markers must be depth-agnostic ----


def test_plaintext_secret_under_an_html_content_type_header_stays_high():
    # A server can label a plaintext secret as text/html; the BODY, not the header, decides exposure (FIX 1).
    env = make_hit(
        "http",
        "http://h.example/.env",
        status=200,
        content_type="text/html",
        body=b"SECRET=topsecret\nDB_PASSWORD=hunter2\n",
    )
    gitconfig = make_hit(
        "http",
        "http://h.example/.git/config",
        status=200,
        content_type="text/html; charset=utf-8",
        body=b"[core]\n\trepositoryformatversion = 0\n",
    )
    assert ("high", "Sensitive path responded") in _sensitive_findings(env)
    assert ("high", "Sensitive path responded") in _sensitive_findings(gitconfig)


def test_nested_and_credential_exposures_score_high():
    # Depth-agnostic markers: real exposures below the web root are not missed (FIX 2).
    archive = make_hit(
        "http",
        "http://h.example/data/backup.zip",
        status=200,
        content_type="application/zip",
        body=b"PK\x03\x04\x14\x00deadbeef",
    )
    sqldump = make_hit(
        "http",
        "http://h.example/db/dump.sql",
        status=200,
        content_type="application/sql",
        body=b"-- dump\nINSERT INTO users VALUES (1);\n",
    )
    gitcreds = make_hit(
        "http",
        "http://h.example/.git-credentials",
        status=200,
        content_type="text/plain",
        body=b"https://user:token@host\n",
    )
    assert ("high", "Sensitive path responded") in _sensitive_findings(archive)
    assert ("high", "Sensitive path responded") in _sensitive_findings(sqldump)
    assert ("high", "Sensitive path responded") in _sensitive_findings(gitcreds)


def test_html_body_soft_404_and_envrc_still_do_not_score_high():
    # No FP regression: an HTML-body soft-404 and the distinct .envrc filename stay out of HIGH.
    backup_html = make_hit(
        "http",
        "http://h.example/old/backup.html",
        status=200,
        content_type="text/html",
        body=_SPA_INDEX,
    )
    envrc = make_hit(
        "http",
        "http://h.example/.envrc",
        status=200,
        content_type="text/plain",
        body=b"export EDITOR=vim\n",
    )
    assert all(severity != "high" for severity, _ in _sensitive_findings(backup_html))
    assert all(severity != "high" for severity, _ in _sensitive_findings(envrc))


# ======================================================================================
# build_hit: body-prefix retention under analysis so BH-4's soft-404 downgrade fires in
# --discover-only, where full bodies are not kept (BH-21)
# ======================================================================================


def _built_hit(url, content, *, content_type, keep_body, analyze, max_body=65536):
    request = httpx.Request("GET", url)
    response = httpx.Response(
        200, headers={"content-type": content_type}, content=content, request=request
    )
    return scanner.build_hit(
        response,
        "http",
        url,
        0.0,
        "GET",
        keep_body=keep_body,
        max_body=max_body,
        analyze=analyze,
    )


def test_discover_only_retains_a_bounded_body_prefix_so_soft_404_downgrades():
    # With keep_body off but analysis on (--discover-only), build_hit keeps a bounded body prefix
    # so BH-4's check can read it; otherwise the HTML fallback has no body and wrongly scores HIGH.
    long_soft_404 = (
        _SPA_INDEX + b"<!-- pad -->" * 200
    )  # longer than the classification prefix cap
    hit = _built_hit(
        "http://h.example/backup.zip",
        long_soft_404,
        content_type="text/html; charset=utf-8",
        keep_body=False,
        analyze=True,
    )
    assert hit.body == b""  # discover-only still does not retain full bodies
    assert (
        len(hit.body_prefix) == scanner.CLASSIFY_PREFIX_BYTES
    )  # a bounded prefix, not the whole body
    assert hit.body_prefix.startswith(b"<!doctype html")
    findings = _sensitive_findings(hit)
    assert findings and all(
        severity != "high" for severity, _ in findings
    )  # downgraded, not dropped


def test_discover_only_prefix_still_scores_a_real_artifact_high():
    # The retained prefix must not over-downgrade: a non-HTML artifact body still scores HIGH.
    hit = _built_hit(
        "http://h.example/.env",
        b"SECRET=topsecret\nDB_PASSWORD=hunter2\n",
        content_type="text/html",
        keep_body=False,
        analyze=True,
    )
    assert ("high", "Sensitive path responded") in _sensitive_findings(hit)


def test_no_body_prefix_is_retained_when_analysis_is_off():
    # keep_body off and no analysis (a plain scan): no body bytes are retained at all.
    hit = _built_hit(
        "http://h.example/backup.zip",
        _SPA_INDEX,
        content_type="text/html",
        keep_body=False,
        analyze=False,
    )
    assert hit.body == b"" and hit.body_prefix == b""


def test_script_intel_static_backticks_and_unresolved_base_templates():
    text = (
        "fetch(`/api/items`); const url = `https://api.example/v1/items`; "
        "const route = `${e.env.core_api}/researcher/submissions`; "
        "const duplicate = `${e.env.core_api}/researcher/submissions`;"
    )
    urls, findings = scanner.extract_script_intel("https://ui.example/main.js", text)
    assert urls == ["https://ui.example/api/items", "https://api.example/v1/items"]
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].title == "Unresolved JavaScript route template"
    assert findings[0].evidence == "${e.env.core_api}/researcher/submissions"
    assert findings[0].url == "https://ui.example/main.js"


@pytest.mark.parametrize(
    "text",
    [
        "// `${e.env.core_api}/researcher/submissions`",
        "/* `${e.env.core_api}/researcher/submissions` */",
        "'`${e.env.core_api}/researcher/submissions`'",
        "`${getBase()}/researcher/submissions`",
        "`${base}/researcher/${identifier}`",
        "`${base}//foreign.example/submissions`",
        "`${base}/images/logo.svg`",
        "`/images/logo.svg`",
        "`https://[invalid/api`",
        "`javascript:alert(1)`",
        "`https://user:password@example.test/api`",
        "`/api/" + "a" * 600 + "`",
    ],
)
def test_script_intel_ignores_unsupported_or_non_route_templates(text):
    assert scanner.extract_script_intel("https://ui.example/main.js", text) == ([], [])


def test_script_intel_bounds_unresolved_findings():
    text = ";".join(f"`${{base}}/api/items/{number}`" for number in range(100))
    urls, findings = scanner.extract_script_intel("https://ui.example/main.js", text)
    assert urls == []
    assert len(findings) == scanner.JS_URL_LIMIT


def test_script_intel_template_scan_input_bound(monkeypatch):
    monkeypatch.setattr(scanner, "JS_TEMPLATE_TEXT_LIMIT", 32)
    assert scanner.extract_script_intel(
        "https://ui.example/main.js", " " * 32 + "`${base}/api/items`"
    ) == ([], [])


def test_script_intel_template_findings_reach_analyze_hit():
    hit = _built_hit(
        "https://ui.example/main.js",
        b"const route = `${e.env.core_api}/researcher/submissions`;",
        content_type="application/javascript",
        keep_body=True,
        analyze=True,
    )
    report = scanner.HostReport("ui.example", [], [], 0.0)
    findings = scanner.analyze_hit(report, hit)
    assert report.js_urls == []
    assert [finding.title for finding in findings] == [
        "Unresolved JavaScript route template"
    ]


def test_script_intel_preserves_quoted_references_and_redacts_assignments():
    text = (
        '<script src="/main.js"></script>; fetch("/items"); '
        'const url = "https://api.example/v1/items"; const route = "/api/items"; '
        'const token = "abcdefgh12345678";'
    )
    urls, findings = scanner.extract_script_intel("https://ui.example/", text)
    assert urls == [
        "https://ui.example/main.js",
        "https://ui.example/items",
        "https://api.example/v1/items",
        "https://ui.example/api/items",
    ]
    assert len(findings) == 1
    assert findings[0].evidence == "token=***"
    assert "abcdefgh12345678" not in repr(findings)


def test_script_intel_unterminated_comment_consumes_remaining_input():
    text = "/*a" * 3000 + "`/api/items`"
    assert scanner.extract_script_intel("https://ui.example/main.js", text) == ([], [])


@pytest.mark.parametrize(
    "source", ["/*a" * 6000] + [quote + ("\\" + quote) * 6000 for quote in "\"'`"]
)
def test_script_template_lexer_bounds_work_on_unterminated_tokens(source):
    class CountedText(str):
        searched_characters = 0
        indexed_characters = 0

        def __getitem__(self, index):
            if isinstance(index, int):
                self.indexed_characters += 1
            return super().__getitem__(index)

        def find(self, substring, start=0, end=None):
            stop = len(self) if end is None else end
            self.searched_characters += stop - start
            return super().find(substring, start, stop)

    text = CountedText(source)
    assert list(scanner._script_template_literals(text)) == []
    assert text.searched_characters <= len(text)
    assert text.indexed_characters <= 3 * len(text)
