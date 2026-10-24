"""Page fetching shared by the content commands: URL vetting, redirect following, client settings, halts."""

import io

import httpx
import pytest

from bughunt import VERSION
from bughunt.core import cli, egress, pagefetch

LOOPBACK = "http://127.0.0.1"
OUTSIDE = "http://evil.example"


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    monkeypatch.chdir(tmp_path)
    return root


class Routes:
    """A client whose answers come from a table: url -> (status, headers, body) or an exception to raise."""

    def __init__(self, **routes):
        self.routes = {f"{LOOPBACK}/{name}": route for name, route in routes.items()}
        self.requested = []

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self._answer))

    def _answer(self, request):
        self.requested.append(str(request.url))
        route = self.routes[str(request.url)]
        if isinstance(route, Exception):
            raise route
        status, headers, body = route
        return httpx.Response(status, headers=headers, content=body)


def moved(location):
    return 302, {"location": location}, b""


# --- URL vetting ------------------------------------------------------------------------------------------


def test_web_parts_need_an_http_scheme_and_a_host_and_ignore_surrounding_space():
    assert pagefetch.web_parts("  https://app.test:8443/x?y=1 ").hostname == "app.test"
    assert pagefetch.web_parts("ftp://app.test/") is None
    assert pagefetch.web_parts("http:///path") is None
    assert pagefetch.web_parts("") is None


def test_is_web_url_is_the_boolean_of_web_parts():
    assert pagefetch.is_web_url(" http://a.test ") is True
    assert pagefetch.is_web_url("file:///etc/hosts") is False


def test_vet_target_lets_an_in_scope_web_url_through(workspace):
    pagefetch.vet_target(LOOPBACK + "/page")


def test_vet_target_names_the_host_of_an_out_of_scope_url(workspace):
    with pytest.raises(pagefetch.ScopeError) as stop:
        pagefetch.vet_target(OUTSIDE + "/page")
    assert stop.value.host == "evil.example"


def test_vet_target_names_the_raw_text_when_there_is_no_host(workspace):
    with pytest.raises(pagefetch.ScopeError) as stop:
        pagefetch.vet_target("file:///etc/hosts")
    assert stop.value.host == "file:///etc/hosts"


def test_vet_target_refuses_an_in_scope_url_that_is_not_http(workspace):
    with pytest.raises(pagefetch.FetchError) as stop:
        pagefetch.vet_target("ftp://127.0.0.1/x")
    assert str(stop.value) == pagefetch.WEB_ONLY


def test_scope_and_fetch_errors_stay_distinct():
    assert not issubclass(pagefetch.ScopeError, pagefetch.FetchError)
    assert not issubclass(pagefetch.FetchError, pagefetch.ScopeError)
    assert str(pagefetch.ScopeError("evil.example")) == "evil.example"


# --- fetch_document ---------------------------------------------------------------------------------------


def test_fetch_document_returns_the_decoded_body_and_where_it_came_from(workspace):
    net = Routes(page=(200, {}, b"hi \xff there"))
    assert pagefetch.fetch_document(net.client(), LOOPBACK + "/page") == (
        "hi � there",
        LOOPBACK + "/page",
    )


def test_fetch_document_follows_three_redirects_and_vets_every_hop(workspace):
    net = Routes(
        r0=moved(LOOPBACK + "/r1"),
        r1=moved("/r2"),
        r2=moved(LOOPBACK + "/end"),
        end=(200, {}, b"landed"),
    )
    assert pagefetch.fetch_document(net.client(), LOOPBACK + "/r0") == (
        "landed",
        LOOPBACK + "/end",
    )
    assert len(net.requested) == 4


def test_fetch_document_classifies_redirect_exhaustion_without_an_extra_request(
    workspace,
):
    net = Routes(**{f"r{number}": moved(f"/r{number + 1}") for number in range(4)})
    with pytest.raises(pagefetch.FetchError) as caught:
        pagefetch.fetch_document(net.client(), LOOPBACK + "/r0")
    assert isinstance(caught.value, pagefetch.RedirectLimitError)
    assert "too many redirects" in str(caught.value)
    assert net.requested == [LOOPBACK + f"/r{number}" for number in range(4)]


def test_fetch_document_does_not_request_an_out_of_scope_hop(workspace):
    net = Routes(go=moved(OUTSIDE + "/x"))
    with pytest.raises(pagefetch.ScopeError) as stop:
        pagefetch.fetch_document(net.client(), LOOPBACK + "/go")
    assert stop.value.host == "evil.example"
    assert net.requested == [LOOPBACK + "/go"]


def test_fetch_document_caps_the_body_it_reads(workspace):
    net = Routes(huge=(200, {}, b"a" * (pagefetch.PAGE_BYTES + 5)))
    text, _ = pagefetch.fetch_document(net.client(), LOOPBACK + "/huge")
    assert len(text) == pagefetch.PAGE_BYTES


def test_fetch_document_names_the_exception_class_by_default(workspace):
    net = Routes(down=httpx.ConnectError("refused by peer"))
    with pytest.raises(pagefetch.FetchError) as caught:
        pagefetch.fetch_document(net.client(), LOOPBACK + "/down")
    assert str(caught.value) == f"Could not fetch {LOOPBACK}/down: ConnectError"


def test_fetch_document_shows_whatever_describe_returns(workspace):
    net = Routes(down=httpx.ConnectError("refused by peer"))
    with pytest.raises(pagefetch.FetchError) as caught:
        pagefetch.fetch_document(net.client(), LOOPBACK + "/down", describe=str)
    assert str(caught.value) == f"Could not fetch {LOOPBACK}/down: refused by peer"


# --- crawl_client -----------------------------------------------------------------------------------------


@pytest.fixture
def built(monkeypatch):
    calls = []

    def record(**kwargs):
        calls.append(kwargs)
        return "client"

    monkeypatch.setattr(egress, "client", record)
    return calls


def test_crawl_client_passes_exactly_these_settings_to_egress(workspace, built):
    assert (
        pagefetch.crawl_client("manual", 7, cookie="a=1", authorization="Bearer x")
        == "client"
    )
    assert built == [
        {
            "operation": "manual",
            "timeout": 7,
            "follow_redirects": False,
            "trust_env": False,
            "headers": {
                "User-Agent": f"Bughunt/{VERSION}",
                "Accept-Encoding": "identity",
                "Cookie": "a=1",
                "Authorization": "Bearer x",
            },
        }
    ]


def test_crawl_client_adds_the_headers_it_is_given_after_the_standard_pair(
    workspace, built
):
    pagefetch.crawl_client("crawl", 3.5, headers={"Accept": "text/html"})
    sent = built[0]["headers"]
    assert built[0]["operation"] == "crawl"
    assert list(sent) == ["User-Agent", "Accept-Encoding", "Accept"]


def test_crawl_client_applies_the_saved_session_unless_told_not_to(workspace, built):
    (workspace / "session.txt").write_text("cookie: saved=1\n", encoding="utf-8")
    pagefetch.crawl_client("manual", 5)
    pagefetch.crawl_client("manual", 5, with_session=False)
    pagefetch.crawl_client("manual", 5, cookie="mine=2", with_session=False)
    assert built[0]["headers"]["Cookie"] == "saved=1"
    assert "Cookie" not in built[1]["headers"]
    assert "Cookie" not in built[2]["headers"]


# --- halting ----------------------------------------------------------------------------------------------


def test_halt_is_a_command_exit_that_also_names_where_to_report():
    spoken = []
    halt = pagefetch.Halt(2, spoken.append, "no")
    assert isinstance(halt, cli.CommandExit)
    assert (halt.code, halt.message, halt.report) == (2, "no", spoken.append)


def test_run_halting_returns_the_exit_code_and_counts_silence_as_success():
    assert pagefetch.run_halting(lambda: 4) == 4
    assert pagefetch.run_halting(lambda: None) == 0
    assert pagefetch.run_halting(lambda left, right: left + right, 1, 2) == 3


def test_run_halting_reports_a_halt_through_its_own_channel(capsys):
    spoken = []

    def refuse():
        raise pagefetch.Halt(2, spoken.append, "Give a page.")

    assert pagefetch.run_halting(refuse) == 2
    assert spoken == ["Give a page."]
    assert capsys.readouterr().err == ""


def test_run_halting_lets_other_errors_through():
    def broken():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        pagefetch.run_halting(broken)


def test_halt_for_a_scope_error_explains_the_host_and_exits_2(workspace):
    halt = pagefetch.halt_for(pagefetch.ScopeError("evil.example"))
    assert (halt.code, halt.report) == (2, pagefetch.report_note)
    assert halt.message.startswith("evil.example was not contacted")


def test_halt_for_a_fetch_error_reports_it_as_an_error_and_exits_1():
    halt = pagefetch.halt_for(pagefetch.FetchError("Could not fetch x: Boom"))
    assert (halt.code, halt.report, halt.message) == (
        1,
        pagefetch.report_error,
        "Could not fetch x: Boom",
    )


def test_halt_for_uses_the_reporters_it_is_given():
    plain, loud = [].append, [].append
    scope = pagefetch.halt_for(
        pagefetch.ScopeError("h"), scope_report=plain, fetch_report=loud
    )
    fetch = pagefetch.halt_for(
        pagefetch.FetchError("f"), scope_report=plain, fetch_report=loud
    )
    assert (scope.report, fetch.report) == (plain, loud)


# --- stderr reporting -------------------------------------------------------------------------------------


class TtyStream(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def terminal(monkeypatch):
    """Call inside the test body: pytest's capture swaps sys.stderr again between setup and call."""

    def install():
        monkeypatch.setenv("TERM", "xterm")
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        stream = TtyStream()
        monkeypatch.setattr("sys.stderr", stream)
        return stream

    return install


def test_report_error_and_note_never_colour_a_terminal_by_default(terminal):
    stream = terminal()
    pagefetch.report_error("bad news")
    pagefetch.report_note("plain news")
    assert stream.getvalue() == "bad news\nplain news\n"


def test_report_error_colours_a_terminal_only_when_asked_to_detect_one(terminal):
    stream = terminal()
    pagefetch.report_error("bad news", detect_terminal=True)
    assert "\x1b[" in stream.getvalue()
    assert "bad news" in stream.getvalue()


def test_report_error_echoes_markup_looking_text_literally(capsys):
    pagefetch.report_error("[bold]not markup[/bold]")
    assert capsys.readouterr().err == "[bold]not markup[/bold]\n"


def test_report_note_does_not_read_markup(capsys):
    pagefetch.report_note("[red]kept as written[/red]")
    assert capsys.readouterr().err == "[red]kept as written[/red]\n"
