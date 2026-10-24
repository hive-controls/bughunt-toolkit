"""Characterization oracle for the group G2 built-in modules: forms, robots, decode, redirect, silk.

PINNED-CURRENT tests. Every test here passes against the modules as they stand at a25e412 and is meant to
stay green through the clean-room rebuild, so each one asserts observable behavior (arguments in, stdout /
stderr / exit code / requests sent / returned values out) and never mirrors the implementation.

Network is the only mock boundary: bughunt.core.egress.client is replaced with a factory that returns an
httpx.Client over httpx.MockTransport, so the modules' own parsing, scoping, redirect and cap logic all run
for real. The factory also records the keyword arguments each module passes to the guarded client.

Known defects follow the repo's two-form convention (see tests/test_chromahaus_defects.py):
  test_*_pinned_current_*  asserts what the code does TODAY, defect included (green now; the rebuild must keep it).
  test_*_correct_*         asserts the CORRECT behavior as xfail(strict=True, raises=AssertionError): it stays
                           xfail while the defect exists and goes red (XPASS) the moment someone fixes it.
"""

from __future__ import annotations

import argparse
import base64
import io
import re
import sys
from collections import namedtuple
from dataclasses import FrozenInstanceError, fields, is_dataclass
from pathlib import Path

import httpx
import pytest

from bughunt import VERSION
from bughunt.core import egress
from bughunt.modules import MODULES, decode, forms, load_builtin, redirect, robots, silk

xfail_correct = pytest.mark.xfail(strict=True, raises=AssertionError)

LOOP = "http://127.0.0.1:8080"
APP = "http://app.internal"
OFF = "http://other.example"
ESC = "\x1b"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

Hit = namedtuple("Hit", "url headers method")
Outcome = namedtuple("Outcome", "rc out err")


# ---------------------------------------------------------------------------------------------------------
# harness: scratch workspace, mock network, invoker
# ---------------------------------------------------------------------------------------------------------


class Workspace:
    def __init__(self, root):
        self.base = root
        self.root = root / "ws"
        self.root.mkdir()

    def scope(self, *hosts):
        (self.root / "scope.txt").write_bytes(
            "".join(f"{host}\n" for host in hosts).encode("utf-8")
        )

    def session(self, **values):
        (self.root / "session.txt").write_bytes(
            "".join(f"{k}: {v}\n" for k, v in values.items()).encode("utf-8")
        )

    def urls(self):
        path = self.root / "urls.txt"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def saved(self):
        folder = self.root / "requests"
        return (
            {p.name: p.read_bytes() for p in sorted(folder.iterdir())}
            if folder.is_dir()
            else {}
        )

    def file(self, name, text, *, binary=False):
        target = self.base / name
        target.write_bytes(text if binary else text.encode("utf-8"))
        return str(target)


@pytest.fixture
def ws(tmp_path, monkeypatch):
    space = Workspace(tmp_path)
    monkeypatch.setenv("BUGHUNT_SCOPE", str(space.root))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("COLUMNS", "500")
    monkeypatch.delenv("NO_COLOR", raising=False)
    return space


class Net:
    def __init__(self):
        self.routes = {}
        self.hits = []
        self.client_calls = []

    def add(self, url, status=200, body="", headers=None):
        self.routes[url] = (status, dict(headers or {}), body)

    def html(self, url, body, status=200):
        self.add(url, status, body, {"content-type": "text/html"})

    def redirect(self, url, location, status=302):
        self.add(url, status, "", {"location": location})

    def fail(self, url, exc):
        self.add(url, 200, exc)

    def urls(self):
        return [hit.url for hit in self.hits]

    def handle(self, request):
        self.hits.append(Hit(str(request.url), dict(request.headers), request.method))
        route = self.routes.get(str(request.url))
        if route is None:
            return httpx.Response(404, content=b"not found")
        status, headers, body = route
        if isinstance(body, Exception):
            raise body
        if isinstance(body, list):
            return httpx.Response(
                status, headers=headers, content=(piece for piece in body)
            )
        return httpx.Response(
            status,
            headers=headers,
            content=body.encode() if isinstance(body, str) else body,
        )

    def client(self, *, operation="manual", **kwargs):
        self.client_calls.append(dict(kwargs, operation=operation))
        return httpx.Client(
            transport=httpx.MockTransport(self.handle),
            headers=kwargs.get("headers"),
            timeout=kwargs.get("timeout"),
            follow_redirects=False,
        )

    def http(self, **headers):
        """A bare client for calling fetch-level functions directly."""
        return self.client(headers=headers or None)


@pytest.fixture
def net(ws, monkeypatch):
    mock = Net()
    monkeypatch.setattr(egress, "client", mock.client)
    return mock


@pytest.fixture
def cli(capsys):
    def invoke(entry, *argv):
        rc = entry(list(argv))
        out, err = capsys.readouterr()
        return Outcome(rc, out, err)

    return invoke


class TtyStream(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def tty(monkeypatch):
    """Call inside the test body: makes both standard streams look like a colour-capable terminal."""

    def install(*, out=True, err=True):
        monkeypatch.setenv("TERM", "xterm")
        streams = (
            (TtyStream() if out else io.StringIO()),
            (TtyStream() if err else io.StringIO()),
        )
        monkeypatch.setattr(sys, "stdout", streams[0])
        monkeypatch.setattr(sys, "stderr", streams[1])
        return streams

    return install


def parser_shape(parser):
    rows = []
    for action in parser._actions:
        if action.dest == "help":
            continue
        rows.append(
            (
                tuple(action.option_strings),
                action.dest,
                type(action).__name__.removeprefix("_").removesuffix("Action"),
                action.default,
                getattr(action.type, "__name__", None),
                action.nargs,
                action.required,
            )
        )
    return rows


def parser_help(parser):
    return {
        action.dest: action.help for action in parser._actions if action.dest != "help"
    }


def strip_ansi(text):
    return ANSI.sub("", text)


# ---------------------------------------------------------------------------------------------------------
# registry + public surface + parser contracts (catalog / console option forms read these)
# ---------------------------------------------------------------------------------------------------------

DESCRIPTIONS = {
    "forms": "Inspect HTML inputs and parameters encoded in page URLs.",
    "robots": "Extract crawl hints from robots and sitemap documents into the URL inventory.",
    "decode": "Render textual base64 content embedded in a fetched page, excluding images.",
    "redirect": "Trace HTTP navigation until it reaches a host or permission boundary.",
    "silk": "Discover site endpoints using bounded crawling and published crawl hints.",
}
MODULE_OBJECTS = {
    "forms": forms,
    "robots": robots,
    "decode": decode,
    "redirect": redirect,
    "silk": silk,
}


@pytest.mark.parametrize("name", sorted(DESCRIPTIONS))
def test_registry_entry_is_byte_identical_and_loads_the_module(name):
    assert MODULES[name] == DESCRIPTIONS[name]
    assert load_builtin(name) is MODULE_OBJECTS[name]


@pytest.mark.parametrize("name", sorted(DESCRIPTIONS))
def test_main_and_build_parser_are_the_console_entry_points(name):
    import inspect

    module = MODULE_OBJECTS[name]
    assert inspect.signature(module.main).parameters["argv"].default is None
    assert not inspect.signature(module.build_parser).parameters
    assert isinstance(module.build_parser(), argparse.ArgumentParser)
    assert module.build_parser().prog == f"bughunt {name}"


FORMS_SHAPE = [
    ((), "inputs", "Store", None, None, "*", False),
    (("--url",), "url", "Append", [], None, None, False),
    (("--base",), "base", "Store", None, None, None, False),
    (("--save",), "save_requests", "StoreTrue", False, None, 0, False),
    (("--no-workspace",), "no_workspace", "StoreTrue", False, None, 0, False),
    (("--limit",), "limit", "Store", 20, "int", None, False),
    (("--timeout",), "timeout", "Store", 10, "float", None, False),
    (("--cookie",), "cookie", "Store", None, None, None, False),
    (("--authorization",), "authorization", "Store", None, None, None, False),
]
ROBOTS_SHAPE = [
    ((), "inputs", "Store", None, None, "*", False),
    (("--base",), "base", "Store", None, None, None, False),
    (("--fetch",), "fetch", "Store", None, None, None, False),
    (("--save",), "save", "Store", None, None, None, False),
    (("--no-workspace",), "no_workspace", "StoreTrue", False, None, 0, False),
]
REDIRECT_SHAPE = [
    ((), "url", "Store", None, None, None, True),
    (("--limit",), "limit", "Store", 10, "int", None, False),
    (("--timeout",), "timeout", "Store", 10.0, "float", None, False),
    (("--insecure",), "insecure", "StoreTrue", False, None, 0, False),
    (("--cookie",), "cookie", "Store", None, None, None, False),
    (("--authorization",), "authorization", "Store", None, None, None, False),
]
DECODE_SHAPE = [
    ((), "target", "Store", None, None, None, True),
    (("--timeout",), "timeout", "Store", 10.0, "float", None, False),
    (("--min",), "min", "Store", 64, "int", None, False),
    (("--insecure",), "insecure", "StoreTrue", False, None, 0, False),
    (("--cookie",), "cookie", "Store", None, None, None, False),
    (("--authorization",), "authorization", "Store", None, None, None, False),
    (("--plain",), "plain", "StoreTrue", False, None, 0, False),
]
SILK_SHAPE = [
    ((), "url", "Store", None, None, None, True),
    (("--depth",), "depth", "Store", 2, "int", None, False),
    (("--limit",), "limit", "Store", 40, "int", None, False),
    (("--timeout",), "timeout", "Store", 10.0, "float", None, False),
    (("--save",), "save", "Store", None, None, None, False),
    (("--no-workspace",), "no_workspace", "StoreTrue", False, None, 0, False),
    (("--plain",), "plain", "StoreTrue", False, None, 0, False),
    (("--cookie",), "cookie", "Store", None, None, None, False),
    (("--authorization",), "authorization", "Store", None, None, None, False),
    (("--actor",), "actor", "Store", None, None, None, False),
]


@pytest.mark.parametrize(
    "name,shape",
    [
        ("forms", FORMS_SHAPE),
        ("robots", ROBOTS_SHAPE),
        ("redirect", REDIRECT_SHAPE),
        ("decode", DECODE_SHAPE),
        ("silk", SILK_SHAPE),
    ],
)
def test_parser_option_surface_is_exact(name, shape):
    assert parser_shape(MODULE_OBJECTS[name].build_parser()) == shape


def test_forms_timeout_default_is_the_int_ten_not_a_float():
    # the console option form renders str(default): "10" here, "10.0" for every sibling module
    default = forms.build_parser().get_default("timeout")
    assert default == 10 and type(default) is int


PARSER_TEXT = {
    "forms": (
        "List form fields and query parameters. Does not send a modified request.",
        {
            "inputs": "Local HTML file, or a file of http(s) URLs.",
            "url": "Fetch this in-scope page with a normal GET.",
            "base": "Page URL used to resolve relative links in a local file.",
            "save_requests": "Write an in-scope raw request for each form and link under .bughunt/requests/.",
            "no_workspace": "List every parsed URL and do not apply the scope filter.",
            "limit": "Maximum pages to fetch. Default 20.",
            "timeout": "Seconds to wait for each page.",
            "cookie": "Cookie for this run. Replaces the saved session cookie.",
            "authorization": "Authorization for this run. Replaces the saved session value.",
        },
    ),
    "robots": (
        "Read robots.txt and sitemaps and print URLs pulse can check.",
        {
            "inputs": "Local robots.txt or sitemap files.",
            "base": "Origin for relative paths, such as https://app.internal.",
            "fetch": "Fetch this in-scope robots.txt or sitemap.",
            "save": "Also write the URL list to this file.",
            "no_workspace": "Print every URL and leave the scope URL list unchanged.",
        },
    ),
    "redirect": (
        "Follow redirects and stop when a hop leaves the host or scope.",
        {
            "url": "In-scope URL to start from.",
            "limit": "Maximum hops. Default 10.",
            "timeout": "Seconds for each hop. Default 10.",
            "insecure": "Do not verify TLS certificates.",
            "cookie": "Cookie for this run. Replaces the saved session cookie.",
            "authorization": "Authorization for this run. Replaces the saved session value.",
        },
    ),
    "decode": (
        "Print one page with non-image base64 blocks shown as text.",
        {
            "target": "In-scope http(s) URL, or a local file.",
            "timeout": "Seconds for the request. Default 10.",
            "min": "Shortest unmarked base64 block to decode. Default 64. Data URIs are always considered.",
            "insecure": "Do not verify TLS certificates.",
            "cookie": "Cookie for this run. Replaces the saved session cookie.",
            "authorization": "Authorization for this run. Replaces the saved session value.",
            "plain": "Skip the banner and leave decoded text uncolored.",
        },
    ),
    "silk": (
        "Discover endpoints with a bounded crawl of one permitted origin, using page links "
        "and published robots and sitemap hints.",
        {
            "url": "Page to start from. Loopback is always in scope.",
            "depth": "Link depth to follow. Default: 2.",
            "limit": "Maximum pages to fetch, including robots.txt and sitemaps. Default: 40.",
            "timeout": "Seconds for each request. Default: 10.",
            "save": "Also write the URL list to this file.",
            "no_workspace": "Leave the scope URL list unchanged.",
            "plain": "Print one URL per line and skip the spider.",
            "cookie": "Cookie for this run. Replaces the saved session cookie.",
            "authorization": "Authorization for this run. Replaces the saved session value.",
            "actor": "Crawl as this owned, origin-bound actor. Sends its credentials and "
            "companion headers; not combinable with --cookie or --authorization.",
        },
    ),
}


@pytest.mark.parametrize("name", sorted(PARSER_TEXT))
def test_parser_description_and_help_text(name):
    description, helps = PARSER_TEXT[name]
    parser = MODULE_OBJECTS[name].build_parser()
    assert parser.description == description
    assert parser_help(parser) == helps


@pytest.mark.parametrize("name", sorted(PARSER_TEXT))
def test_main_with_no_argv_reads_sys_argv(name, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["bughunt", "--no-such-flag"])
    with pytest.raises(SystemExit) as stop:
        MODULE_OBJECTS[name].main(None)
    assert stop.value.code == 2
    assert f"bughunt {name}" in capsys.readouterr().err


# =========================================================================================================
# forms.py
# =========================================================================================================

APPBASE = "http://app.internal/app/"


def parse(text, base=None, page_url="page"):
    return forms.parse_document(text, base, page_url=page_url)


def rows(page):
    return [
        (item.method, item.url, item.name, item.source, item.note)
        for item in page.findings
    ]


def drafts(page):
    return [(item.method, item.url, item.body) for item in page.drafts]


def form_of(inner, action="/x", method=None):
    attribute = f' method="{method}"' if method else ""
    return f'<form action="{action}"{attribute}>{inner}</form>'


def test_forms_data_contracts():
    assert [f.name for f in fields(forms.Finding)] == [
        "method",
        "url",
        "name",
        "source",
        "note",
    ]
    assert [f.name for f in fields(forms.Draft)] == ["method", "url", "body"]
    assert [f.name for f in fields(forms.Page)] == [
        "findings",
        "drafts",
        "unresolved",
        "db_note",
    ]
    assert all(is_dataclass(kind) for kind in (forms.Finding, forms.Draft, forms.Page))
    blank = forms.Page()
    assert (blank.findings, blank.drafts, blank.unresolved, blank.db_note) == (
        [],
        [],
        0,
        "",
    )
    assert (
        blank.findings is not forms.Page().findings
        and blank.drafts is not forms.Page().drafts
    )
    assert forms.Finding("GET", "u", "n", "form", "") == forms.Finding(
        "GET", "u", "n", "form", ""
    )
    assert forms.Finding("GET", "u", "n", "form", "") != forms.Finding(
        "GET", "u", "n", "link", ""
    )
    assert forms.Draft("POST", "u", "a=1") == forms.Draft("POST", "u", "a=1")
    assert forms.Draft("POST", "u", "a=1") != forms.Draft("POST", "u", "a=2")


def test_forms_error_types():
    scope, fetch = forms.ScopeError("evil.example"), forms.FetchError("nope")
    assert (
        isinstance(scope, Exception)
        and scope.host == "evil.example"
        and str(scope) == "evil.example"
    )
    assert isinstance(fetch, Exception) and str(fetch) == "nope"
    assert not isinstance(scope, forms.FetchError) and not isinstance(
        fetch, forms.ScopeError
    )


def test_forms_get_form_findings_and_draft():
    page = parse(
        form_of(
            '<input name="q" value="a b"><input name="note" value="x&y">', "/search"
        ),
        APPBASE,
    )
    assert rows(page) == [
        ("GET", "http://app.internal/search", "q", "form", "review"),
        ("GET", "http://app.internal/search", "note", "form", ""),
    ]
    assert drafts(page) == [("GET", "http://app.internal/search?q=a+b&note=x%26y", "")]
    assert page.unresolved == 0 and page.db_note == ""


def test_forms_get_draft_keeps_existing_query_first_and_drops_fragment():
    page = parse(form_of('<input name="b" value="2">', "/s?a=1&a=0#frag"), APPBASE)
    assert drafts(page) == [("GET", "http://app.internal/s?a=1&a=0&b=2", "")]


def test_forms_get_draft_with_no_pairs_has_no_query_and_gets_a_root_path():
    page = parse(
        form_of('<input name="x" disabled value="1">', "http://app.internal"), None
    )
    assert drafts(page) == [("GET", "http://app.internal/", "")]
    assert rows(page) == [("GET", "http://app.internal", "x", "form", "disabled")]


def test_forms_post_form_body_blanks_password_and_skips_disabled():
    inner = (
        '<input name="user" value="bob"><input name="pw" type="password" value="hunter2">'
        '<input name="tok" type="hidden" value="t&1"><input name="off" disabled value="x"><input type="submit" value="Go">'
    )
    page = parse(form_of(inner, "http://app.internal/login#top", "POST"), None)
    assert rows(page) == [
        ("POST", "http://app.internal/login#top", "user", "form", "review"),
        ("POST", "http://app.internal/login#top", "pw", "form", "password"),
        ("POST", "http://app.internal/login#top", "tok", "form", "hidden"),
        ("POST", "http://app.internal/login#top", "off", "form", "disabled"),
    ]
    assert drafts(page) == [
        ("POST", "http://app.internal/login#top", "user=bob&pw=&tok=t%261")
    ]


@pytest.mark.parametrize(
    "declared,expected",
    [
        (None, "GET"),
        ("get", "GET"),
        ("GET", "GET"),
        ("post", "POST"),
        (" Post ", "POST"),
        ("PUT", "PUT"),
        ("patch", "PATCH"),
        ("delete", "GET"),
        ("dialog", "GET"),
        ("TRACE", "GET"),
        ("", "GET"),
    ],
)
def test_forms_method_is_upcased_and_limited_to_four_verbs(declared, expected):
    page = parse(
        form_of('<input name="a" value="1">', "http://app.internal/m", declared)
    )
    assert [item.method for item in page.findings] == [expected]
    assert page.drafts[0].method == expected
    assert page.drafts[0].body == ("" if expected == "GET" else "a=1")


@pytest.mark.parametrize(
    "snippet,note",
    [
        ('<input name="a">', ""),
        ('<input name="a" type="hidden">', "hidden"),
        ('<input name="a" type=" HIDDEN ">', "hidden"),
        ('<input name="a" type="password">', "password"),
        ('<input name="a" type="password" disabled>', "password, disabled"),
        ('<input name="user_id" type="hidden">', "hidden, review"),
        ('<input name="q" disabled>', "disabled, review"),
        ('<input name="id" type="hidden" disabled>', "hidden, disabled, review"),
        ('<input name="a" type="">', ""),
        ('<input name="a" type="checkbox">', ""),
        ('<textarea name="a"></textarea>', ""),
        ('<textarea name="a" disabled></textarea>', "disabled"),
        ('<select name="a"><option value="1"></select>', ""),
        ('<select name="a" disabled><option value="1"></select>', ""),
        ('<button name="a" value="1">go</button>', ""),
        ('<button name="id" value="1" disabled>go</button>', "disabled, review"),
    ],
)
def test_forms_field_note_composition(snippet, note):
    page = parse(form_of(snippet), APPBASE)
    assert [item.note for item in page.findings] == [note]


@pytest.mark.parametrize(
    "name",
    [
        "id",
        "ID",
        "uid",
        "user",
        "userid",
        "username",
        "email",
        "account",
        "search",
        "q",
        "query",
        "sort",
        "order",
        "orderby",
        "filter",
        "category",
        "cat",
        "item",
        "product",
        "report",
        "page",
        "offset",
        "limit",
        "column",
        "table",
        "field",
        "where",
        "user_id",
        "Order-ID",
        "X_ID",
        "a-id",
        " spaced ",
    ],
)
def test_forms_review_names(name):
    expected = "" if name == " spaced " else "review"
    page = parse(form_of(f'<input name="{name}">'), APPBASE)
    assert [item.note for item in page.findings] == [expected]


@pytest.mark.parametrize(
    "name",
    [
        "foo",
        "identity",
        "valid",
        "userids",
        "idx",
        "uuid",
        "name",
        "password",
        "token",
        "csrf",
        "_id_",
        "id2",
    ],
)
def test_forms_non_review_names(name):
    page = parse(form_of(f'<input name="{name}">'), APPBASE)
    assert [item.note for item in page.findings] == [""]


def draft_query(snippet):
    page = parse(form_of(snippet, "http://app.internal/s"))
    return page.drafts[0].url.partition("?")[2]


@pytest.mark.parametrize(
    "options,expected",
    [
        ('<option value="1"><option value="2" selected>', "s=2"),
        ('<option value="1" selected><option value="2">', "s=1"),
        ('<option value="1"><option value="2" selected><option value="3">', "s=2"),
        (
            '<option value="1" selected><option value="2" selected><option value="3">',
            "s=2",
        ),
        (
            '<option value="1"><option value="2" selected><option value="3" selected>',
            "s=3",
        ),
        ('<option>One</option><option value="9" selected>Two</option>', "s=9"),
        ("<option>One</option><option>Two</option>", "s="),
        ("", "s="),
    ],
)
def test_forms_select_value_selection(options, expected):
    assert draft_query(f'<select name="s">{options}</select>') == expected


def test_forms_unnamed_select_is_ignored_and_does_not_leak_options():
    page = parse(
        form_of(
            '<select><option value="9" selected></select><input name="a" value="1">'
        ),
        APPBASE,
    )
    assert [item.name for item in page.findings] == ["a"]
    assert page.drafts[0].url.endswith("?a=1")


def test_forms_select_options_do_not_bleed_into_the_next_select():
    query = draft_query(
        '<select name="a"><option value="1" selected></select><select name="b"><option value="7"></select>'
    )
    assert query == "a=1&b=7"


def test_forms_textarea_value_is_its_text():
    assert draft_query('<textarea name="t">hello world</textarea>') == "t=hello+world"
    assert draft_query('<textarea name="t"></textarea>') == "t="
    assert draft_query('<textarea name="t">a\nb</textarea>') == "t=a%0Ab"
    assert draft_query('<textarea name="t">a &amp; b</textarea>') == "t=a+%26+b"


def test_forms_textarea_text_with_a_bare_angle_bracket_is_kept_whole():
    assert draft_query('<textarea name="t">a < b</textarea>') == "t=a+%3C+b"


def test_forms_get_draft_preserves_blank_values_in_the_existing_query():
    page = parse(form_of('<input name="b" value="2">', "/s?empty=&a=1"), APPBASE)
    assert drafts(page) == [("GET", "http://app.internal/s?empty=&a=1&b=2", "")]


def test_forms_self_closed_textarea_is_an_empty_field_and_swallows_nothing():
    page = parse(form_of('<textarea name="t"/><input name="u" value="v">'), APPBASE)
    assert [item.name for item in page.findings] == ["t", "u"]
    assert page.drafts[0].url.endswith("?t=&u=v")


def test_forms_unnamed_textarea_and_button_and_input_are_ignored():
    page = parse(
        form_of(
            '<textarea>junk</textarea><button>x</button><input value="v"><input name="  ">'
        ),
        APPBASE,
    )
    assert page.findings == [] and page.drafts == []


def test_forms_button_with_a_name_is_a_field_with_its_value():
    page = parse(
        form_of(
            '<button name="act" value="save">Save</button><button name="n" disabled value="1">'
        ),
        APPBASE,
    )
    assert [(i.name, i.note) for i in page.findings] == [("act", ""), ("n", "disabled")]
    assert page.drafts[0].url.endswith("?act=save")


def test_forms_field_order_is_document_order_across_tags():
    inner = '<input name="a"><select name="b"></select><textarea name="c"></textarea><button name="d"></button><input name="e">'
    assert [i.name for i in parse(form_of(inner), APPBASE).findings] == [
        "a",
        "b",
        "c",
        "d",
        "e",
    ]


def test_forms_only_the_first_forty_named_fields_are_kept():
    inner = "".join(f'<input name="f{n:02d}" value="{n}">' for n in range(50))
    page = parse(form_of(inner, "http://app.internal/big"))
    assert [i.name for i in page.findings] == [f"f{n:02d}" for n in range(40)]
    assert page.drafts[0].url.count("=") == 40


def test_forms_form_without_named_fields_yields_nothing_but_unresolved_still_counts():
    assert parse(form_of('<input type="submit">'), APPBASE).findings == []
    page = parse(form_of('<input type="submit">', "rel"), None)
    assert (page.findings, page.drafts, page.unresolved) == ([], [], 1)


@pytest.mark.parametrize(
    "action,base,target,unresolved",
    [
        ("sub/x", APPBASE, "http://app.internal/app/sub/x", 0),
        ("/x", APPBASE, "http://app.internal/x", 0),
        ("../x", APPBASE, "http://app.internal/x", 0),
        ("?k=1", APPBASE, "http://app.internal/app/?k=1", 0),
        ("//cdn.example/x", APPBASE, "http://cdn.example/x", 0),
        ("https://elsewhere.example/y", APPBASE, "https://elsewhere.example/y", 0),
        ("  /trim  ", APPBASE, "http://app.internal/trim", 0),
        ("", APPBASE, APPBASE, 0),
        ("   ", APPBASE, APPBASE, 0),
        ("rel", None, None, 1),
        ("/abs", None, None, 1),
        ("//cdn.example/x", None, None, 1),
        ("", None, None, 1),
        ("https://elsewhere.example/y", None, "https://elsewhere.example/y", 0),
        ("#frag", APPBASE, None, 0),
        ("#frag", None, None, 0),
        (
            "http://app.internal/a/./b/../c?x=1#f",
            APPBASE,
            "http://app.internal/a/./b/../c?x=1#f",
            0,
        ),
        ("javascript:void(0)", APPBASE, None, 0),
        ("mailto:a@b.example", APPBASE, None, 0),
        ("ftp://files.example/x", APPBASE, None, 0),
        ("tel:123", None, None, 0),
    ],
)
def test_forms_action_resolution(action, base, target, unresolved):
    page = parse(f'<form action="{action}"><input name="a"></form>', base)
    assert [i.url for i in page.findings] == ([target] if target else [])
    assert page.unresolved == unresolved


def test_forms_action_missing_uses_the_base():
    page = parse("<form><input name='a'></form>", APPBASE)
    assert [i.url for i in page.findings] == [APPBASE]


def test_forms_base_href_variants():
    absolute = parse(
        '<base href="http://app.internal/b/">' + form_of('<input name="a">', "x"),
        "http://other.example/z/",
    )
    assert [i.url for i in absolute.findings] == ["http://app.internal/b/x"]
    relative = parse('<base href="sub/">' + form_of('<input name="a">', "x"), APPBASE)
    assert [i.url for i in relative.findings] == ["http://app.internal/app/sub/x"]
    nowhere = parse('<base href="sub/">' + form_of('<input name="a">', "x"), None)
    assert (nowhere.findings, nowhere.unresolved) == ([], 2)
    ignored = parse('<base href="#top">' + form_of('<input name="a">', "x"), APPBASE)
    assert ([i.url for i in ignored.findings], ignored.unresolved) == (
        ["http://app.internal/app/x"],
        0,
    )
    script = parse(
        '<base href="javascript:x">' + form_of('<input name="a">', "x"), APPBASE
    )
    assert [i.url for i in script.findings] == ["http://app.internal/app/x"]


def test_forms_first_non_empty_base_wins():
    two = parse(
        '<base href="http://a.example/"><base href="http://b.example/">'
        + form_of('<input name="a">', "x")
    )
    assert [i.url for i in two.findings] == ["http://a.example/x"]
    empty_first = parse(
        '<base href=""><base href="http://b.example/">'
        + form_of('<input name="a">', "x")
    )
    assert [i.url for i in empty_first.findings] == ["http://b.example/x"]


def test_forms_base_applies_to_empty_action_too():
    page = parse(
        '<base href="http://app.internal/b/">' + "<form><input name='a'></form>",
        "http://other.example/z/",
    )
    assert [i.url for i in page.findings] == ["http://app.internal/b/"]


def test_forms_implicit_close_and_unterminated_forms():
    nested = parse(
        '<form action="/a"><input name="x"><form action="/b"><input name="y"></form>',
        APPBASE,
    )
    assert [(i.url, i.name) for i in nested.findings] == [
        ("http://app.internal/a", "x"),
        ("http://app.internal/b", "y"),
    ]
    open_ended = parse('<form action="/a"><input name="x">', APPBASE)
    assert [i.name for i in open_ended.findings] == ["x"]
    assert (
        parse('<input name="x"><textarea name="t"></textarea>', APPBASE).findings == []
    )
    assert (
        parse(form_of('<input name="x">') + '<input name="late">', APPBASE)
        .findings[-1]
        .name
        == "x"
    )
    assert parse("</form><p>x</p>", APPBASE).findings == []


def test_forms_unterminated_select_or_textarea_at_end_of_input_is_dropped():
    page = parse(
        '<form action="/a"><input name="x"><select name="s"><option value="1">', APPBASE
    )
    assert [i.name for i in page.findings] == ["x"]
    page = parse('<form action="/a"><input name="x"><textarea name="t">abc', APPBASE)
    assert [i.name for i in page.findings] == ["x"]


def test_forms_select_cut_off_by_a_new_form_is_dropped():
    page = parse(
        '<form action="/a"><select name="s"><option value="1"><form action="/b"><input name="y"></form>',
        APPBASE,
    )
    assert [(i.url, i.name) for i in page.findings] == [("http://app.internal/b", "y")]
    late = parse(
        '<form action="/a"><select name="s"><option value="1"><form action="/b"><input name="y"></select></form>',
        APPBASE,
    )
    assert [(i.url, i.name) for i in late.findings] == [("http://app.internal/b", "y")]


def test_forms_tag_and_attribute_case_and_quoting_are_tolerated():
    page = parse(
        "<FORM ACTION=/Up METHOD=Post><INPUT NAME=A TYPE=Hidden VALUE=1></FORM>",
        APPBASE,
    )
    assert rows(page) == [("POST", "http://app.internal/Up", "A", "form", "hidden")]


def test_forms_link_findings_and_drafts():
    page = parse('<a href="/items?id=1&sort=asc&id=2&=x&empty=&bare">i</a>', APPBASE)
    assert rows(page) == [
        (
            "GET",
            "http://app.internal/items?id=1&sort=asc&id=2&=x&empty=&bare",
            "id",
            "link",
            "review",
        ),
        (
            "GET",
            "http://app.internal/items?id=1&sort=asc&id=2&=x&empty=&bare",
            "sort",
            "link",
            "review",
        ),
        (
            "GET",
            "http://app.internal/items?id=1&sort=asc&id=2&=x&empty=&bare",
            "empty",
            "link",
            "",
        ),
        (
            "GET",
            "http://app.internal/items?id=1&sort=asc&id=2&=x&empty=&bare",
            "bare",
            "link",
            "",
        ),
    ]
    assert drafts(page) == [
        ("GET", "http://app.internal/items?id=1&sort=asc&id=2&=x&empty=&bare", "")
    ]


def test_forms_link_param_names_are_percent_decoded_and_trimmed_for_the_review_note():
    page = parse('<a href="/p?user%5Fid=1">x</a>', APPBASE)
    assert [(i.name, i.note) for i in page.findings] == [("user_id", "review")]
    spaced = parse('<a href="/p?%20ID%20=1">x</a>', APPBASE)
    assert [(i.name, i.note) for i in spaced.findings] == [(" ID ", "review")]


@pytest.mark.parametrize(
    "anchors,found,unresolved",
    [
        ('<a href="/plain">x</a>', 0, 0),
        ('<a href="/p?">x</a>', 0, 0),
        ('<a href="/p?&&">x</a>', 0, 0),
        ('<a href="#frag?x=1">x</a>', 0, 0),
        ("<a href=\"javascript:go('?a=1')\">x</a>", 0, 0),
        ('<a href="mailto:a@b.example?subject=hi">x</a>', 0, 0),
        ("<a>x</a><a href='  '>y</a>", 0, 0),
        (
            '<a href="/p?a=1">x</a><a href="/p?a=1">y</a><a href="/app/../p?a=1">z</a>',
            1,
            0,
        ),
        ('<a href="p?a=1">x</a><a href="./p?a=1">y</a><a href="/p?a=1">z</a>', 2, 0),
        ('<a href="/p?a=1">x</a><a href="/p?b=1">y</a>', 2, 0),
        ('<a href="/p?a=1&b=2">x</a><a href="/p?b=2&a=1">y</a>', 4, 0),
    ],
)
def test_forms_link_filters_and_dedupe_with_base(anchors, found, unresolved):
    page = parse(anchors, APPBASE)
    assert len(page.findings) == found and page.unresolved == unresolved
    assert len(page.drafts) == len({item.url for item in page.drafts})
    assert bool(page.drafts) == bool(found)


def test_forms_links_without_base_count_unresolved_per_occurrence():
    page = parse(
        '<a href="rel?a=1">x</a><a href="rel?a=1">y</a><a href="plain.html">p</a><a href="http://app.internal/abs?q=1">z</a>',
        None,
    )
    assert page.unresolved == 2
    assert rows(page) == [("GET", "http://app.internal/abs?q=1", "q", "link", "review")]


def test_forms_area_and_iframe_links_need_a_query_and_anchors_inside_forms_count():
    page = parse(
        '<area href="/a?x=1"><iframe src="/f?y=1"></iframe><iframe src="/noquery"></iframe><area href="/noq">'
        + form_of('<a href="/inside?z=1">in</a>', "/post"),
        APPBASE,
    )
    assert [(i.name, i.source) for i in page.findings] == [
        ("x", "link"),
        ("y", "link"),
        ("z", "link"),
    ]


def test_forms_only_the_first_two_hundred_links_are_considered():
    many = "".join(f'<a href="/p?n{n}=1">x</a>' for n in range(250))
    assert len(parse(many, APPBASE).findings) == 200
    padded = "".join(f'<a href="/plain{n}">x</a>' for n in range(150)) + many
    assert len(parse(padded, APPBASE).findings) == 50


def test_forms_links_without_a_query_on_iframes_do_not_use_up_the_link_cap():
    page = parse(
        "".join(f'<iframe src="/f{n}"></iframe>' for n in range(220))
        + '<a href="/p?late=1">x</a>',
        APPBASE,
    )
    assert [item.name for item in page.findings] == ["late"]


def test_forms_form_findings_come_before_link_findings_and_note_is_first():
    html = (
        '<a href="/l?a=1">x</a>'
        + form_of('<input name="f">', "/post")
        + "<p>ORA-00933 oops</p>"
    )
    page = parse(html, APPBASE, page_url="http://app.internal/here")
    assert [(i.source, i.name) for i in page.findings] == [
        ("database", "-"),
        ("form", "f"),
        ("link", "a"),
    ]
    assert page.findings[0] == forms.Finding(
        "NOTE", "http://app.internal/here", "-", "database", "Oracle error"
    )


DB_MARKERS = [
    ("You have an error in your SQL syntax; check", "MySQL syntax error"),
    ("Warning: mysql_connect(): Access denied", "MySQL warning"),
    ("mysql_fetch_array() expects", "MySQL error"),
    ("mysqli_query failed", "MySQL error"),
    ("pg_query() [function.pg-query]", "PostgreSQL error"),
    ("org.postgresql.util.PSQLException: ERROR", "PostgreSQL error"),
    ("sqlite3.OperationalError: no such table", "SQLite error"),
    ("Unclosed quotation mark after the character string 'x'", "SQL Server error"),
    ("Microsoft OLE DB Provider for ODBC Drivers error", "ODBC error"),
    ("ORA-00933: SQL command not properly ended", "Oracle error"),
    ("ORA-01756: quoted string not properly terminated", "Oracle error"),
    ("SQLSTATE[42000]: Syntax error", "SQLSTATE error"),
]


@pytest.mark.parametrize("text,label", DB_MARKERS)
def test_forms_database_note_markers(text, label):
    assert forms.database_note(text) == label
    assert forms.database_note(text.upper()) == label
    assert forms.database_note(f"<p>before</p> {text} <p>after</p>") == label


def test_forms_database_note_absent_and_precedence_follows_table_order_not_position():
    assert (
        forms.database_note("") == ""
        and forms.database_note("all is well, sql syntax is fine") == ""
    )
    assert (
        forms.database_note(
            "ORA-00933 first, later: you have an error in your sql syntax"
        )
        == "MySQL syntax error"
    )
    assert forms.database_note("mysql_fetch_row and Warning: MySQL") == "MySQL warning"
    assert forms.database_note("SQLSTATE[1] then ORA-01756") == "Oracle error"
    assert (
        forms.database_note("Warning: MySQL says: You have an error in your SQL syntax")
        == "MySQL syntax error"
    )


def test_forms_page_with_only_a_database_error_has_one_note_finding_and_no_drafts():
    page = parse("<html>sqlite3.OperationalError</html>", None, page_url="here.html")
    assert page.db_note == "SQLite error"
    assert page.findings == [
        forms.Finding("NOTE", "here.html", "-", "database", "SQLite error")
    ]
    assert page.drafts == []


def test_forms_render_request_get():
    raw = forms.render_request(
        forms.Draft("GET", "http://app.internal/a?x=1&y=2#frag", "")
    )
    assert (
        raw
        == f"GET /a?x=1&y=2 HTTP/1.1\r\nHost: app.internal\r\nUser-Agent: Bughunt/{VERSION}\r\n\r\n".encode()
    )


def test_forms_render_request_post_has_form_headers_and_body():
    raw = forms.render_request(
        forms.Draft("POST", "http://app.internal/login", "user_id=9&pw=")
    )
    assert (
        raw
        == (
            f"POST /login HTTP/1.1\r\nHost: app.internal\r\nUser-Agent: Bughunt/{VERSION}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nuser_id=9&pw="
        ).encode()
    )


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_forms_render_request_any_non_get_method_carries_body_headers_even_when_empty(
    method,
):
    raw = forms.render_request(forms.Draft(method, "http://app.internal/x", ""))
    assert raw.startswith(f"{method} /x HTTP/1.1\r\n".encode())
    assert (
        b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n"
        in raw
    )


def test_forms_render_request_content_length_counts_utf8_bytes():
    raw = forms.render_request(forms.Draft("POST", "http://app.internal/x", "é=ü"))
    assert b"Content-Length: 5\r\n\r\n" in raw and raw.endswith("é=ü".encode("utf-8"))


@pytest.mark.parametrize(
    "url,line,host",
    [
        ("http://app.internal", "GET / HTTP/1.1", "app.internal"),
        ("http://app.internal?a=1", "GET /?a=1 HTTP/1.1", "app.internal"),
        ("http://APP.Internal/Mixed", "GET /Mixed HTTP/1.1", "app.internal"),
        ("http://app.internal:8080/x", "GET /x HTTP/1.1", "app.internal:8080"),
        ("http://app.internal:80/x", "GET /x HTTP/1.1", "app.internal:80"),
        ("https://app.internal:443/x", "GET /x HTTP/1.1", "app.internal:443"),
        ("http://user:pw@app.internal/x", "GET /x HTTP/1.1", "app.internal"),
        ("http://[::1]/x", "GET /x HTTP/1.1", "[::1]"),
        ("http://[::1]:9000/x", "GET /x HTTP/1.1", "[::1]:9000"),
    ],
)
def test_forms_render_request_start_line_and_host_header(url, line, host):
    head = (
        forms.render_request(forms.Draft("GET", url, ""))
        .decode("latin-1")
        .split("\r\n")
    )
    assert head[0] == line and head[1] == f"Host: {host}"


def test_forms_rendered_requests_are_readable_by_repeater():
    from bughunt.modules.repeater import parse_raw

    parsed = parse_raw(
        forms.render_request(
            forms.Draft("POST", "http://app.internal:8080/login?x=1", "a=1&b=2")
        )
    )
    assert (parsed.method, parsed.target, parsed.body) == (
        "POST",
        "/login?x=1",
        b"a=1&b=2",
    )
    assert ("Host", "app.internal:8080") in parsed.headers and (
        "Content-Length",
        "7",
    ) in parsed.headers
    plain = parse_raw(
        forms.render_request(forms.Draft("GET", "http://app.internal/items?id=1", ""))
    )
    assert (plain.method, plain.target, plain.body) == ("GET", "/items?id=1", b"")


def test_forms_render_request_replaces_characters_outside_latin_one_in_the_head():
    raw = forms.render_request(forms.Draft("GET", "http://app.internal/ā-é", ""))
    assert raw.split(b"\r\n")[0] == b"GET /?-\xe9 HTTP/1.1"


def redirect_chain(net, count, final="landing", *, base=LOOP):
    for number in range(count):
        target = f"{base}/r{number + 1}" if number + 1 < count else f"{base}/{final}"
        net.redirect(f"{base}/r{number}", target)
    net.html(f"{base}/{final}", "<p>done</p>")


@pytest.mark.parametrize("command", ["forms", "robots", "silk"])
@pytest.mark.parametrize("existing_saved", [False, True])
def test_content_commands_report_redirect_exhaustion_without_saving_empty_success(
    ws, net, cli, command, existing_saved
):
    ws.scope("127.0.0.1")
    redirect_chain(net, 5)
    destination = ws.base / "discovered.txt"
    previous = b"previous discovery\n"
    previous_requests = {}
    if existing_saved:
        destination.write_bytes(previous)
        request_folder = ws.root / "requests"
        request_folder.mkdir()
        (request_folder / "kept.http").write_bytes(previous)
        previous_requests = {"kept.http": previous}
    if command == "forms":
        entry, arguments = forms.main, ["--url", LOOP + "/r0", "--save"]
    elif command == "robots":
        entry, arguments = (
            robots.main,
            ["--fetch", LOOP + "/r0", "--save", str(destination)],
        )
    else:
        entry, arguments = (
            silk.main,
            [LOOP + "/r0", "--plain", "--save", str(destination)],
        )
    result = cli(entry, *arguments)
    assert result.rc == 1
    assert "too many redirects" in result.err
    assert result.out == ""
    if existing_saved:
        assert destination.read_bytes() == previous
    else:
        assert not destination.exists()
    assert ws.saved() == previous_requests
    assert ws.urls() == []
    assert net.urls() == [LOOP + f"/r{number}" for number in range(4)]


@pytest.mark.parametrize("command", ["robots", "silk"])
@pytest.mark.parametrize("existing_saved", [False, True])
def test_secondary_redirect_exhaustion_aborts_partial_discovery_without_export(
    ws, net, cli, command, existing_saved
):
    ws.scope("127.0.0.1")
    redirect_chain(net, 5)
    destination = ws.base / "discovered.txt"
    previous = b"previous discovery\n"
    if existing_saved:
        destination.write_bytes(previous)
    if command == "robots":
        net.add(LOOP + "/robots.txt", 200, "Disallow: /known\nSitemap: " + LOOP + "/r0")
        result = cli(
            robots.main, "--fetch", LOOP + "/robots.txt", "--save", str(destination)
        )
    else:
        net.html(LOOP + "/", '<a href="/r0">nested</a>')
        result = cli(silk.main, LOOP + "/", "--plain", "--save", str(destination))
    assert result.rc == 1
    assert "too many redirects" in result.err
    assert result.out == ""
    if existing_saved:
        assert destination.read_bytes() == previous
    else:
        assert not destination.exists()
    assert ws.urls() == []
    assert net.urls()[-4:] == [LOOP + f"/r{number}" for number in range(4)]
    assert LOOP + "/r4" not in net.urls()


def test_forms_fetch_document_returns_decoded_body_and_final_url(ws, net):
    net.html(LOOP + "/p", "<b>hi</b>")
    assert forms.fetch_document(net.http(), LOOP + "/p") == ("<b>hi</b>", LOOP + "/p")
    assert [(hit.method, hit.url) for hit in net.hits] == [("GET", LOOP + "/p")]


def test_forms_fetch_document_decodes_utf8_with_replacement_and_keeps_a_bom(ws, net):
    net.add(LOOP + "/bad", 200, b"ok \xff\xfe end")
    net.add(LOOP + "/bom", 200, b"\xef\xbb\xbfhi")
    assert forms.fetch_document(net.http(), LOOP + "/bad")[0] == "ok �� end"
    assert forms.fetch_document(net.http(), LOOP + "/bom")[0] == "﻿hi"


def test_forms_fetch_document_does_not_look_at_the_status(ws, net):
    net.add(LOOP + "/gone", 404, "missing page")
    assert forms.fetch_document(net.http(), LOOP + "/gone") == (
        "missing page",
        LOOP + "/gone",
    )


def test_forms_fetch_document_follows_three_redirects_relative_or_absolute(ws, net):
    net.redirect(LOOP + "/r0", "/r1", 301)
    net.redirect(LOOP + "/r1", LOOP + "/dir/r2", 307)
    net.redirect(LOOP + "/dir/r2", "../end", 308)
    net.html(LOOP + "/end", "landed")
    assert forms.fetch_document(net.http(), LOOP + "/r0") == ("landed", LOOP + "/end")
    assert net.urls() == [LOOP + "/r0", LOOP + "/r1", LOOP + "/dir/r2", LOOP + "/end"]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_forms_fetch_document_follows_each_redirect_status(ws, net, status):
    net.redirect(LOOP + "/a", "/b", status)
    net.html(LOOP + "/b", "B")
    assert forms.fetch_document(net.http(), LOOP + "/a") == ("B", LOOP + "/b")


@pytest.mark.parametrize("status", [300, 304, 305, 306])
def test_forms_fetch_document_does_not_follow_other_3xx(ws, net, status):
    net.add(LOOP + "/a", status, "body", {"location": "/b"})
    assert forms.fetch_document(net.http(), LOOP + "/a") == ("body", LOOP + "/a")
    assert net.urls() == [LOOP + "/a"]


def test_forms_fetch_document_redirect_without_a_usable_location_returns_that_response(
    ws, net
):
    net.add(LOOP + "/none", 302, "redirect body")
    net.add(LOOP + "/blank", 302, "blank body", {"location": "   "})
    assert forms.fetch_document(net.http(), LOOP + "/none") == (
        "redirect body",
        LOOP + "/none",
    )
    assert forms.fetch_document(net.http(), LOOP + "/blank") == (
        "blank body",
        LOOP + "/blank",
    )
    assert net.urls() == [LOOP + "/none", LOOP + "/blank"]


def test_forms_fetch_document_correct_a_fourth_redirect_is_a_too_many_redirects_error(
    ws, net
):
    redirect_chain(net, 5)
    raised = None
    try:
        forms.fetch_document(net.http(), LOOP + "/r0")
    except forms.FetchError as exc:
        raised = exc
    assert raised is not None and "too many redirects" in str(raised)


def test_forms_fetch_document_off_scope_hop_raises_scope_error_without_requesting_it(
    ws, net
):
    net.redirect(LOOP + "/go", OFF + "/x")
    with pytest.raises(forms.ScopeError) as stop:
        forms.fetch_document(net.http(), LOOP + "/go")
    assert stop.value.host == "other.example"
    assert net.urls() == [LOOP + "/go"]


def test_forms_fetch_document_scope_is_checked_before_the_first_request(ws, net):
    with pytest.raises(forms.ScopeError) as stop:
        forms.fetch_document(net.http(), OFF + "/")
    assert stop.value.host == "other.example" and net.hits == []
    ws.scope("app.internal")
    net.html(APP + "/ok", "yes")
    assert forms.fetch_document(net.http(), APP + "/ok")[0] == "yes"


def test_forms_fetch_document_scope_error_names_the_raw_text_when_there_is_no_host(
    ws, net
):
    with pytest.raises(forms.ScopeError) as stop:
        forms.fetch_document(net.http(), "file:///etc/hosts")
    assert stop.value.host == "file:///etc/hosts" and net.hits == []


def test_forms_fetch_document_only_http_and_https_can_be_fetched(ws, net):
    with pytest.raises(
        forms.FetchError, match=r"^Only http and https URLs can be fetched\.$"
    ):
        forms.fetch_document(net.http(), "ftp://127.0.0.1/x")
    net.redirect(LOOP + "/go", "ftp://127.0.0.1/file")
    with pytest.raises(forms.FetchError, match="Only http and https"):
        forms.fetch_document(net.http(), LOOP + "/go")


@pytest.mark.parametrize(
    "error,name",
    [
        (httpx.ConnectError("boom"), "ConnectError"),
        (httpx.ReadTimeout("slow"), "ReadTimeout"),
        (
            egress.PolicyBlocked("policy-missing-or-invalid; no outbound action ran"),
            "PolicyBlocked",
        ),
    ],
)
def test_forms_fetch_document_http_errors_become_fetch_errors_naming_only_the_class(
    ws, net, error, name
):
    net.fail(LOOP + "/e", error)
    with pytest.raises(forms.FetchError) as caught:
        forms.fetch_document(net.http(), LOOP + "/e")
    assert str(caught.value) == f"Could not fetch {LOOP}/e: {name}"
    assert caught.value.__cause__ is error


def test_forms_fetch_document_error_on_a_later_hop_names_that_hop(ws, net):
    net.redirect(LOOP + "/a", "/b")
    net.fail(LOOP + "/b", httpx.ConnectError("boom"))
    with pytest.raises(forms.FetchError) as caught:
        forms.fetch_document(net.http(), LOOP + "/a")
    assert str(caught.value) == f"Could not fetch {LOOP}/b: ConnectError"


def test_forms_fetch_document_caps_the_body_at_one_million_bytes(ws, net):
    net.add(LOOP + "/huge", 200, b"a" * 1_500_000)
    net.add(LOOP + "/chunks", 200, [b"b" * 400_000] * 4)
    net.add(LOOP + "/exact", 200, b"c" * 1_000_000)
    net.add(LOOP + "/under", 200, b"d" * 999_999)
    assert forms.fetch_document(net.http(), LOOP + "/huge")[0] == "a" * 1_000_000
    assert forms.fetch_document(net.http(), LOOP + "/chunks")[0] == "b" * 1_000_000
    assert len(forms.fetch_document(net.http(), LOOP + "/exact")[0]) == 1_000_000
    assert len(forms.fetch_document(net.http(), LOOP + "/under")[0]) == 999_999


# ---- forms.main ------------------------------------------------------------------------------------------

PAGE = (
    "<html><body>"
    '<form action="/login" method="post"><input name="user_id" type="hidden" value="9"><input name="pw" type="password"></form>'
    '<form action="http://other.example/x"><input name="q"></form>'
    '<a href="/items?id=1&sort=asc">i</a><a href="rel?x=1">r</a>'
    "<p>You have an error in your SQL syntax</p></body></html>"
)
HEADER = "method\turl\tname\tsource\tnote\n"


def test_forms_local_file_with_base_scope_active_lists_in_scope_rows_only(ws, net, cli):
    ws.scope("app.internal")
    result = cli(forms.main, ws.file("page.html", PAGE), "--base", APPBASE)
    assert result.rc == 0
    assert result.out == HEADER + (
        "NOTE\thttp://app.internal/app/\t-\tdatabase\tMySQL syntax error\n"
        "POST\thttp://app.internal/login\tuser_id\tform\thidden, review\n"
        "POST\thttp://app.internal/login\tpw\tform\tpassword\n"
        "GET\thttp://app.internal/items?id=1&sort=asc\tid\tlink\treview\n"
        "GET\thttp://app.internal/items?id=1&sort=asc\tsort\tlink\treview\n"
        "GET\thttp://app.internal/app/rel?x=1\tx\tlink\t\n"
    )
    assert result.err == "6 field(s)  2 outside scope\n"
    assert net.client_calls == [] and net.hits == []


def test_forms_local_file_without_base_reports_unresolved_and_names_the_note_after_the_file(
    ws, net, cli
):
    ws.scope("app.internal")
    result = cli(forms.main, ws.file("page.html", PAGE))
    assert result.rc == 0
    assert result.out == HEADER + "NOTE\tpage.html\t-\tdatabase\tMySQL syntax error\n"
    assert result.err == "1 field(s)  3 relative link(s) need --base  2 outside scope\n"


def test_forms_without_a_scope_file_nothing_is_filtered(ws, net, cli):
    result = cli(forms.main, ws.file("page.html", PAGE), "--base", APPBASE)
    assert result.rc == 0
    assert "GET\thttp://other.example/x\tq\tform\treview\n" in result.out
    assert result.err == "7 field(s)\n"


def test_forms_no_workspace_skips_the_scope_filter_even_when_scope_is_active(
    ws, net, cli
):
    ws.scope("app.internal")
    result = cli(
        forms.main, ws.file("page.html", PAGE), "--base", APPBASE, "--no-workspace"
    )
    assert result.rc == 0 and "http://other.example/x\tq" in result.out
    assert result.err == "7 field(s)\n"


def test_forms_dropped_count_adds_findings_and_drafts(ws, net, cli):
    ws.scope("app.internal")
    page = (
        '<form action="http://other.example/x"><input name="a"><input name="b"></form>'
    )
    result = cli(forms.main, ws.file("p.html", page))
    assert result.out == "" and result.err == "0 field(s)  3 outside scope\n"


@pytest.mark.parametrize(
    "argv,message",
    [
        (["--limit", "0", "--url", LOOP + "/"], "Limit has to be at least 1."),
        (["--limit", "-3", "--url", LOOP + "/"], "Limit has to be at least 1."),
        (["--timeout", "0", "--url", LOOP + "/"], "Timeout has to be greater than 0."),
        (["--timeout", "-1", "--url", LOOP + "/"], "Timeout has to be greater than 0."),
        (
            ["--base", "ftp://x.example/", "--url", LOOP + "/"],
            "Base needs an http or https URL, such as https://app.internal/app.",
        ),
        (
            ["--base", "relative/path", "--url", LOOP + "/"],
            "Base needs an http or https URL, such as https://app.internal/app.",
        ),
        (
            ["--base", "http:///x", "--url", LOOP + "/"],
            "Base needs an http or https URL, such as https://app.internal/app.",
        ),
        ([], "Give a local HTML file, a file of URLs, or --url."),
        (
            ["--save", "--url", LOOP + "/"],
            "No scope workspace yet. Run: bughunt scope init",
        ),
        (
            ["--save", "--no-workspace", "--url", LOOP + "/"],
            "No scope workspace yet. Run: bughunt scope init",
        ),
    ],
)
def test_forms_argument_errors_exit_two_with_a_one_line_message(
    ws, net, cli, argv, message
):
    result = cli(forms.main, *argv)
    assert (result.rc, result.out, result.err) == (2, "", message + "\n")
    assert net.client_calls == []


def test_forms_base_outside_scope_is_refused_only_when_the_filter_applies(ws, net, cli):
    from bughunt.core.workspace import explain_block

    page = ws.file("p.html", PAGE)
    ws.scope("app.internal")
    refused = cli(forms.main, page, "--base", OFF + "/")
    assert (refused.rc, refused.out, refused.err) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )
    assert cli(forms.main, page, "--base", OFF + "/", "--no-workspace").rc == 0


def test_forms_input_that_is_missing_or_neither_html_nor_urls_is_an_error(ws, net, cli):
    missing = cli(forms.main, str(ws.base / "nope.html"))
    assert (
        missing.rc == 2 and missing.err == f"No file named {ws.base / 'nope.html'}.\n"
    )
    notes = ws.file("notes.txt", "just words\nmore words\n")
    assert (
        cli(forms.main, notes).err
        == f"{notes} is not HTML and is not a list of http(s) URLs.\n"
    )
    comments = ws.file("only-comments.txt", "# nothing\n\n")
    assert (
        cli(forms.main, comments).err
        == f"{comments} is not HTML and is not a list of http(s) URLs.\n"
    )
    mixed = ws.file("mixed.txt", f"{LOOP}/a\nnot a url\n")
    assert cli(forms.main, mixed).rc == 2 and net.hits == []


@pytest.mark.parametrize(
    "token",
    ["<form", "<input", "<html", "<a href=x", "<a>", "<base href=x", "<FORM", "<Html>"],
)
def test_forms_html_sniffing_tokens(ws, net, cli, token):
    result = cli(forms.main, ws.file("t.html", f"junk {token} more"))
    assert result.rc == 0


@pytest.mark.parametrize("text", ["<div>x</div>", "<p>x</p>", "<ahref>", "a  href"])
def test_forms_non_sniffed_text_is_not_html(ws, net, cli, text):
    assert cli(forms.main, ws.file("t.txt", text)).rc == 2


def test_forms_html_marker_only_counts_in_the_first_eight_thousand_characters(
    ws, net, cli
):
    late = ws.file(
        "late.txt",
        "x" * 8100 + "<form action='http://app.internal/'><input name=a></form>",
    )
    assert cli(forms.main, late).rc == 2


def test_forms_a_url_given_as_a_positional_argument_is_fetched(ws, net, cli):
    net.html(LOOP + "/p", form_of('<input name="a">', "/go"))
    result = cli(forms.main, LOOP + "/p")
    assert (
        result.rc == 0
        and result.out == HEADER + "GET\thttp://127.0.0.1:8080/go\ta\tform\t\n"
    )


def test_forms_url_list_file_comments_blanks_and_blocked_hosts(ws, net, cli):
    ws.scope("app.internal")
    net.html(APP + "/a", form_of('<input name="id">', "b"))
    listing = ws.file("urls.txt", f"# pages\n\n{APP}/a\n  {OFF}/b  \n")
    result = cli(forms.main, listing)
    assert result.rc == 0
    assert result.out == HEADER + "GET\thttp://app.internal/b\tid\tform\treview\n"
    assert result.err == "1 field(s)  1 page(s) outside scope\n"
    assert net.urls() == [APP + "/a"]


def test_forms_all_urls_blocked_exits_two_with_the_first_blocked_host_and_no_client(
    ws, net, cli
):
    from bughunt.core.workspace import explain_block

    result = cli(forms.main, "--url", OFF + "/a", "--url", "http://third.example/b")
    assert (result.rc, result.out, result.err) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )
    assert net.client_calls == [] and net.hits == []


def test_forms_some_blocked_and_nothing_found_still_exits_two_but_prints_the_summary(
    ws, net, cli
):
    ws.scope("app.internal")
    net.html(APP + "/empty", "<p>nothing</p>")
    result = cli(forms.main, "--url", APP + "/empty", "--url", OFF + "/b")
    assert (result.rc, result.out, result.err) == (
        2,
        "",
        "0 field(s)  1 page(s) outside scope\n",
    )


def test_forms_a_local_file_with_nothing_found_keeps_exit_zero_even_when_a_url_was_blocked(
    ws, net, cli
):
    result = cli(
        forms.main,
        ws.file("p.html", "<html><a>nothing</a></html>"),
        "--url",
        OFF + "/x",
    )
    assert (result.rc, result.out, result.err) == (
        0,
        "",
        "0 field(s)  1 page(s) outside scope\n",
    )


def test_forms_a_fetched_page_with_nothing_to_list_still_exits_zero(ws, net, cli):
    net.html(LOOP + "/p", "<p>nothing</p>")
    result = cli(forms.main, "--url", LOOP + "/p")
    assert (result.rc, result.out, result.err) == (0, "", "0 field(s)\n")


def test_forms_fetched_pages_are_scope_filtered_and_counted(ws, net, cli):
    ws.scope("app.internal")
    net.html(
        APP + "/p",
        form_of('<input name="a">', "http://other.example/x")
        + form_of('<input name="b">', "/ok"),
    )
    result = cli(forms.main, "--url", APP + "/p")
    assert result.out == HEADER + "GET\thttp://app.internal/ok\tb\tform\t\n"
    assert result.err == "1 field(s)  2 outside scope\n"


def test_forms_url_arguments_and_url_list_lines_are_trimmed_and_blank_arguments_ignored(
    ws, net, cli
):
    net.html(LOOP + "/p", "<p>pg_query() failed</p>")
    note = HEADER + f"NOTE\t{LOOP}/p\t-\tdatabase\tPostgreSQL error\n"
    args = cli(forms.main, "--url", f"  {LOOP}/p  ", "--url", "", "--url", "   ")
    assert (args.out, args.err) == (note, "1 field(s)\n")
    listed_file = cli(forms.main, ws.file("urls.txt", f"\n   {LOOP}/p   \n"))
    assert (listed_file.out, listed_file.err) == (note, "1 field(s)\n")
    assert all(hit.url == LOOP + "/p" for hit in net.hits)


def test_forms_base_is_trimmed(ws, net, cli):
    page = ws.file("p.html", '<p>pg_query()</p><a href="x?a=1">l</a>')
    result = cli(forms.main, page, "--base", f"  {APPBASE}  ")
    assert result.out == HEADER + (
        "NOTE\thttp://app.internal/app/\t-\tdatabase\tPostgreSQL error\n"
        "GET\thttp://app.internal/app/x?a=1\ta\tlink\t\n"
    )


def test_forms_html_marker_window_is_the_first_eight_thousand_characters(ws, net, cli):
    inside = ws.file(
        "in.txt",
        "x" * 7500 + "<form action='http://app.internal/'><input name=a></form>",
    )
    assert cli(forms.main, inside).rc == 0


def test_forms_blocked_host_text_is_not_read_as_rich_markup(ws, net, cli):
    from bughunt.core.workspace import explain_block

    result = cli(forms.main, "--url", "x[red]y")
    assert result.err == explain_block("x[red]y") + "\n" and "[red]" in result.err


def test_forms_findings_with_the_same_url_and_name_but_another_source_are_both_kept(
    ws, net, cli
):
    page = ws.file(
        "p.html",
        form_of('<input name="q">', "http://app.internal/s?q=1")
        + '<a href="http://app.internal/s?q=1">l</a>',
    )
    assert cli(forms.main, page).out.splitlines()[1:] == [
        "GET\thttp://app.internal/s?q=1\tq\tform\treview",
        "GET\thttp://app.internal/s?q=1\tq\tlink\treview",
    ]


def test_forms_a_repeated_field_name_in_one_form_reports_only_its_first_note(
    ws, net, cli
):
    page = ws.file(
        "p.html",
        form_of(
            '<input name="a" type="hidden"><input name="a">', "http://app.internal/f"
        ),
    )
    assert (
        cli(forms.main, page).out
        == HEADER + "GET\thttp://app.internal/f\ta\tform\thidden\n"
    )


def test_forms_scope_check_on_urls_ignores_no_workspace(ws, net, cli):
    result = cli(forms.main, "--url", OFF + "/a", "--no-workspace")
    assert result.rc == 2 and net.hits == []


def test_forms_duplicate_urls_are_fetched_once_and_limit_stops_the_loop(ws, net, cli):
    net.html(LOOP + "/a", form_of('<input name="a">', "/fa"))
    net.html(LOOP + "/b", form_of('<input name="b">', "/fb"))
    twice = cli(forms.main, "--url", LOOP + "/a", "--url", LOOP + "/a")
    assert twice.err == "1 field(s)\n" and net.urls() == [LOOP + "/a"]
    net.hits.clear()
    limited = cli(
        forms.main, "--url", LOOP + "/a", "--url", LOOP + "/b", "--limit", "1"
    )
    assert net.urls() == [LOOP + "/a"]
    assert limited.err == "Stopped after 1 page(s).\n1 field(s)\n"
    net.hits.clear()
    roomy = cli(forms.main, "--url", LOOP + "/a", "--url", LOOP + "/b", "--limit", "2")
    assert net.urls() == [LOOP + "/a", LOOP + "/b"] and "Stopped" not in roomy.err


def test_forms_fetched_page_resolves_against_its_final_url_and_notes_use_it(
    ws, net, cli
):
    net.redirect(LOOP + "/old", "/new/page")
    net.html(
        LOOP + "/new/page",
        form_of('<input name="a">', "go") + "<p>pg_query() failed</p>",
    )
    result = cli(forms.main, "--url", LOOP + "/old")
    assert result.out == HEADER + (
        "NOTE\thttp://127.0.0.1:8080/new/page\t-\tdatabase\tPostgreSQL error\n"
        "GET\thttp://127.0.0.1:8080/new/go\ta\tform\t\n"
    )


def test_forms_request_headers_and_client_construction(ws, net, cli):
    net.html(LOOP + "/p", "<p>x</p>")
    cli(forms.main, "--url", LOOP + "/p", "--timeout", "3")
    assert net.client_calls == [
        {
            "operation": "manual",
            "timeout": 3.0,
            "follow_redirects": False,
            "trust_env": False,
            "headers": {
                "User-Agent": f"Bughunt/{VERSION}",
                "Accept-Encoding": "identity",
            },
        }
    ]
    assert net.hits[0].headers["user-agent"] == f"Bughunt/{VERSION}"
    assert (
        "cookie" not in net.hits[0].headers
        and "authorization" not in net.hits[0].headers
    )


def test_forms_cookie_and_authorization_flags_replace_the_saved_session(ws, net, cli):
    net.html(LOOP + "/p", "<p>x</p>")
    ws.session(cookie="saved=1", authorization="Bearer saved")
    cli(forms.main, "--url", LOOP + "/p")
    assert (
        net.hits[-1].headers["cookie"] == "saved=1"
        and net.hits[-1].headers["authorization"] == "Bearer saved"
    )
    cli(
        forms.main,
        "--url",
        LOOP + "/p",
        "--cookie",
        " mine=2 ",
        "--authorization",
        "Bearer mine",
    )
    assert (
        net.hits[-1].headers["cookie"] == "mine=2"
        and net.hits[-1].headers["authorization"] == "Bearer mine"
    )
    cli(forms.main, "--url", LOOP + "/p", "--cookie", "", "--authorization", "")
    assert (
        "cookie" not in net.hits[-1].headers
        and "authorization" not in net.hits[-1].headers
    )


def test_forms_fetch_scope_error_mid_run_discards_everything_gathered(ws, net, cli):
    from bughunt.core.workspace import explain_block

    net.html(LOOP + "/good", form_of('<input name="a">', "/fa"))
    net.redirect(LOOP + "/bad", OFF + "/x")
    result = cli(forms.main, "--url", LOOP + "/good", "--url", LOOP + "/bad")
    assert (result.rc, result.out, result.err) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )


def test_forms_fetch_failure_exits_one_and_discards_everything_gathered(ws, net, cli):
    net.html(LOOP + "/good", form_of('<input name="a">', "/fa"))
    net.fail(LOOP + "/bad", httpx.ConnectError("boom"))
    result = cli(forms.main, "--url", LOOP + "/good", "--url", LOOP + "/bad")
    assert (result.rc, result.out, result.err) == (
        1,
        "",
        f"Could not fetch {LOOP}/bad: ConnectError\n",
    )


def test_forms_policy_block_during_a_fetch_is_reported_as_a_fetch_failure(ws, net, cli):
    net.fail(LOOP + "/p", egress.PolicyBlocked("nope"))
    result = cli(forms.main, "--url", LOOP + "/p")
    assert (result.rc, result.err) == (1, f"Could not fetch {LOOP}/p: PolicyBlocked\n")


def test_forms_file_findings_come_before_fetched_findings_and_duplicates_collapse(
    ws, net, cli
):
    net.html(LOOP + "/p", form_of('<input name="a">', "/same"))
    local = ws.file(
        "l.html",
        form_of('<input name="a"><input name="a">', "http://127.0.0.1:8080/same") * 2,
    )
    result = cli(forms.main, local, "--url", LOOP + "/p")
    assert result.out == HEADER + "GET\thttp://127.0.0.1:8080/same\ta\tform\t\n"
    assert result.err == "1 field(s)\n"


def test_forms_cells_are_flattened_to_single_line_tab_free_text(ws, net, cli):
    page = '<form action="http://127.0.0.1:8080/x"><input name="a\tb"><input name="c\nd"></form>'
    result = cli(forms.main, ws.file("t.html", page))
    lines = result.out.splitlines()
    assert lines[1:] == [
        "GET\thttp://127.0.0.1:8080/x\ta b\tform\t",
        "GET\thttp://127.0.0.1:8080/x\tc d\tform\t",
    ]
    assert all(len(line.split("\t")) == 5 for line in lines)


def test_forms_findings_are_capped_at_two_hundred_with_a_notice(ws, net, cli):
    def many(count):
        return "".join(
            form_of(
                "".join(f'<input name="f{f}_{n}">' for n in range(40)),
                f"http://127.0.0.1:8080/f{f}",
            )
            for f in range(count)
        )

    exact = cli(forms.main, ws.file("e.html", many(5)))
    assert len(exact.out.splitlines()) == 201 and exact.err == "200 field(s)\n"
    over = cli(forms.main, ws.file("o.html", many(6)))
    assert len(over.out.splitlines()) == 201
    assert over.err == "Stopped after 200 fields.\n200 field(s)\n"


def test_forms_local_file_is_cut_at_one_million_characters_and_odd_bytes_are_tolerated(
    ws, net, cli
):
    form = form_of('<input name="late">', "http://127.0.0.1:8080/x")
    early = cli(forms.main, ws.file("early.html", "<html>" + form + "x" * 1_000_100))
    assert "late" in early.out
    late = cli(forms.main, ws.file("late.html", "<html>" + "x" * 1_000_000 + form))
    assert (late.out, late.err) == ("", "0 field(s)\n")
    binary = ws.file("b.html", b"\xff\xfe" + form.encode() + b"\xff", binary=True)
    assert "late" in cli(forms.main, binary).out


def test_forms_save_writes_raw_requests_for_in_scope_drafts(ws, net, cli):
    ws.scope("app.internal")
    result = cli(forms.main, ws.file("page.html", PAGE), "--base", APPBASE, "--save")
    assert result.rc == 0
    assert result.err == (
        "saved form-0001.http\nsaved form-0002.http\nsaved form-0003.http\n"
        "6 field(s)  2 outside scope  3 request(s) saved\n"
    )
    saved = ws.saved()
    assert sorted(saved) == ["form-0001.http", "form-0002.http", "form-0003.http"]
    assert saved["form-0001.http"] == forms.render_request(
        forms.Draft("POST", "http://app.internal/login", "user_id=9&pw=")
    )
    assert saved["form-0002.http"] == forms.render_request(
        forms.Draft("GET", "http://app.internal/items?id=1&sort=asc", "")
    )
    assert saved["form-0003.http"].startswith(
        b"GET /app/rel?x=1 HTTP/1.1\r\nHost: app.internal\r\n"
    )


def test_forms_save_numbering_continues_after_existing_files_and_dedupes_drafts(
    ws, net, cli
):
    ws.scope("app.internal")
    page = ws.file(
        "p.html", form_of('<input name="a">', "/same") * 2 + '<a href="/x?k=1">l</a>'
    )
    cli(forms.main, page, "--base", APPBASE, "--save")
    assert sorted(ws.saved()) == ["form-0001.http", "form-0002.http"]
    (ws.root / "requests" / "form-0003.http").write_bytes(b"keep")
    (ws.root / "requests" / "other.http").write_bytes(b"keep")
    again = cli(forms.main, page, "--base", APPBASE, "--save")
    assert "saved form-0004.http" in again.err and "saved form-0005.http" in again.err
    assert ws.saved()["form-0003.http"] == b"keep"
    assert "Stopped after 40" not in again.err


def test_forms_save_keeps_drafts_that_differ_only_in_method_or_body(ws, net, cli):
    ws.scope("app.internal")
    page = ws.file(
        "p.html",
        form_of('<input name="a" value="1">', "/same", "post")
        + form_of('<input name="a" value="2">', "/same", "post")
        + form_of('<input name="a" value="1">', "/same", "put"),
    )
    result = cli(forms.main, page, "--base", APPBASE, "--save")
    assert result.err.splitlines()[-1].endswith("3 request(s) saved")
    assert sorted(raw.split(b" ")[0] for raw in ws.saved().values()) == [
        b"POST",
        b"POST",
        b"PUT",
    ]


def test_forms_save_skips_drafts_outside_scope_even_with_no_workspace(ws, net, cli):
    ws.scope("app.internal")
    page = ws.file(
        "p.html",
        form_of('<input name="a">', "http://other.example/x")
        + form_of('<input name="b">', APP + "/y"),
    )
    result = cli(forms.main, page, "--save", "--no-workspace")
    assert (
        "http://other.example/x\ta" in result.out and "request(s) saved" in result.err
    )
    assert result.err.splitlines()[-1] == "2 field(s)  1 request(s) saved"
    assert (
        list(ws.saved()) == ["form-0001.http"]
        and b"app.internal" in ws.saved()["form-0001.http"]
    )


def test_forms_save_stops_at_forty_requests_with_a_notice(ws, net, cli):
    links = "".join(f'<a href="/p?n{n}=1">x</a>' for n in range(45))
    ws.scope("127.0.0.1")
    result = cli(
        forms.main, ws.file("many.html", links), "--base", LOOP + "/", "--save"
    )
    assert len(ws.saved()) == 40
    assert "Stopped after 40 saved requests.\n" in result.err
    assert result.err.splitlines()[-1] == "45 field(s)  40 request(s) saved"


def test_forms_exactly_forty_distinct_drafts_save_without_a_stop_notice(ws, net, cli):
    ws.scope("127.0.0.1")
    links = "".join(f'<a href="/p?n{n}=1">x</a>' for n in range(40))
    result = cli(
        forms.main, ws.file("many.html", links), "--base", LOOP + "/", "--save"
    )
    assert len(ws.saved()) == 40 and "Stopped after 40" not in result.err


def test_forms_save_is_quiet_about_nothing_to_save(ws, net, cli):
    ws.scope("app.internal")
    result = cli(forms.main, ws.file("p.html", "<html>nothing</html>"), "--save")
    assert (result.rc, result.out, result.err) == (0, "", "0 field(s)\n")


# =========================================================================================================
# robots.py
# =========================================================================================================


def urlset(*locs):
    body = "".join(f"<url><loc>{loc}</loc></url>" for loc in locs)
    return f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{body}</urlset>'


def sitemapindex(*locs):
    body = "".join(f"<sitemap><loc>{loc}</loc></sitemap>" for loc in locs)
    return f'<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{body}</sitemapindex>'


def robots_of(text, base=None, *, client=None, budget=10, seen=None):
    return robots.robots_urls(
        text, base, client=client, budget=[budget], seen=set() if seen is None else seen
    )


def from_text(text, base=None, *, client=None, budget=10, seen=None):
    return robots.urls_from_text(
        text, base, client=client, budget=[budget], seen=set() if seen is None else seen
    )


def test_robots_error_types():
    scope = robots.ScopeError("evil.example")
    assert (
        isinstance(scope, Exception)
        and scope.host == "evil.example"
        and str(scope) == "evil.example"
    )
    assert isinstance(robots.FetchError("x"), Exception) and not isinstance(
        scope, robots.FetchError
    )


@pytest.mark.parametrize(
    "text,expected",
    [
        ('<?xml version="1.0"?><urlset/>', True),
        ("  \n\t<?xml version='1.0'?>", True),
        ("<urlset>", True),
        ("<URLSET>", True),
        ("<sitemapindex>", True),
        ("<loc>http://x/</loc>", True),
        ("<html><body>hello</body></html>", False),
        ("User-agent: *\nDisallow: /a", False),
        ("", False),
        ("abc <?xml version='1.0'?>", False),
        ("x" * 793 + "<urlset", True),
        ("x" * 794 + "<urlset", False),
        ("x" * 2000 + "<urlset>", False),
    ],
)
def test_robots_looks_like_sitemap(text, expected):
    assert robots.looks_like_sitemap(text) is expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("<sitemapindex>", True),
        ("<SitemapIndex>", True),
        ("<urlset>", False),
        ("", False),
        ("x" * 7987 + "<sitemapindex", True),
        ("x" * 7988 + "<sitemapindex", False),
    ],
)
def test_robots_is_sitemap_index_looks_only_at_the_first_eight_thousand_characters(
    text, expected
):
    assert robots.is_sitemap_index(text) is expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("<loc>http://a/</loc><loc>http://b/</loc>", ["http://a/", "http://b/"]),
        ("<loc>\n  http://a/x \n</loc>", ["http://a/x"]),
        ("<LOC>http://a/</LOC>", ["http://a/"]),
        ("<loc>http://a/?x=1&amp;y=2</loc>", ["http://a/?x=1&y=2"]),
        ("<loc>http://a/?q=&lt;b&gt;</loc>", ["http://a/?q=<b>"]),
        ("<loc></loc><loc>   </loc><loc>http://a/</loc>", ["http://a/"]),
        ("<loc><![CDATA[http://a/]]></loc>", []),
        ("<image:loc>http://img/</image:loc>", []),
        ("<loc>/relative/path</loc>", ["/relative/path"]),
        ("no tags here", []),
        ("", []),
        ("<loc>http://a/ b</loc>", ["http://a/ b"]),
    ],
)
def test_robots_sitemap_locs(text, expected):
    assert robots.sitemap_locs(text) == expected


@pytest.mark.parametrize(
    "value,base,expected",
    [
        ("foo", "https://x/app", "https://x/app/foo"),
        ("foo", "https://x/app/", "https://x/app/foo"),
        ("/foo", "https://x/app", "https://x/foo"),
        ("../foo", "https://x/app/sub", "https://x/app/foo"),
        ("//o.example/a", "https://x/", "https://o.example/a"),
        ("?q=1", "https://x/app", "https://x/app/?q=1"),
        ("  /pad  ", "https://x", "https://x/pad"),
        ("https://abs.example/p", None, "https://abs.example/p"),
        ("https://abs.example/p", "https://x", "https://abs.example/p"),
        ("HTTP://Abs.Example/P", None, "HTTP://Abs.Example/P"),
        ("foo", None, None),
        ("", "https://x", None),
        ("   ", "https://x", None),
        ("mailto:a@b.example", "https://x", None),
        ("ftp://files.example/x", "https://x", None),
        ("ftp://files.example/x", None, None),
        (
            "/go?u=http://elsewhere.example",
            "https://x",
            "https://x/go?u=http://elsewhere.example",
        ),
        ("http://", "https://x", None),
        ("foo", "ftp://x", None),
    ],
)
def test_robots_resolve(value, base, expected):
    assert robots.resolve(value, base) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://Example.COM/a/b?c=d#e", "https://example.com"),
        ("http://example.com:8080/x", "http://example.com:8080"),
        ("https://example.com:443/x", "https://example.com:443"),
        ("http://[::1]:8080/x", "http://[::1]:8080"),
        ("http://[::1]/x", "http://[::1]"),
        ("http://user:pw@example.com/x", "http://example.com"),
        ("ftp://example.com/", None),
        ("/relative", None),
        ("http://", None),
        ("example.com", None),
        ("", None),
    ],
)
def test_robots_origin_of(url, expected):
    assert robots.origin_of(url) == expected


X = "https://x"


@pytest.mark.parametrize(
    "text,base,urls,skipped",
    [
        ("Disallow: /admin/", X, [X + "/admin/"], 0),
        ("Disallow: /admin/", None, [], 1),
        ("Disallow: /admin/\nAllow: /pub/", None, [], 2),
        ("Allow: /pub$", X, [X + "/pub"], 0),
        ("Disallow: /x*", X, [X + "/x"], 0),
        ("Disallow: /x*$", X, [X + "/x"], 0),
        ("Disallow: /x$ ", X, [X + "/x"], 0),
        ("Disallow: /x *", X, [X + "/x"], 0),
        ("Disallow: /*", X, [X + "/"], 0),
        ("Disallow: *", X, [], 0),
        ("Disallow: $", X, [], 0),
        ("Disallow: *$", X, [], 0),
        ("Disallow:", X, [], 0),
        ("Disallow:    ", X, [], 0),
        ("Allow:", X, [], 0),
        ("Disallow: /", X, [X + "/"], 0),
        (
            "disallow: /a\nDISALLOW: /b\n Disallow : /c",
            X,
            [X + "/a", X + "/b", X + "/c"],
            0,
        ),
        (
            "Disallow: /a # hide\n# Disallow: /b\nDisallow: /c#frag",
            X,
            [X + "/a", X + "/c"],
            0,
        ),
        ("User-agent: *\nCrawl-delay: 5\nHost: x.example\nNoindex: /z", X, [], 0),
        ("Disallow: /*.php$", X, [X + "/*.php"], 0),
        ("Disallow: /a/*/b", X, [X + "/a/*/b"], 0),
        ("Disallow: /a?b=c", X, [X + "/a?b=c"], 0),
        ("Disallow: /a\r\nAllow: /b\r\n", X, [X + "/a", X + "/b"], 0),
        ("Disallow /a\nnothing here\n\n", X, [], 0),
        ("Disallow: /a:b", X, [X + "/a:b"], 0),
        ("Disallow: /a:b", None, [], 1),
        ("Disallow: http://other.example/p", None, ["http://other.example/p"], 0),
        ("Disallow: ftp://other.example/p", X, [], 1),
        ("Disallow: private/", X + "/app", [X + "/app/private/"], 0),
        ("Disallow: //cdn.example/x", X, ["https://cdn.example/x"], 0),
        ("Disallow: /a\nDisallow: /a", X, [X + "/a", X + "/a"], 0),
        (
            "User-agent: bot\nDisallow: /a\nUser-agent: *\nDisallow: /b",
            X,
            [X + "/a", X + "/b"],
            0,
        ),
        ("Sitemap: https://x/s.xml\nDisallow: /a", X, [X + "/a", X + "/s.xml"], 0),
        ("Sitemap: /s.xml", X, [X + "/s.xml"], 0),
        ("Sitemap: /s.xml", None, [], 1),
        ("Sitemap:", X, [], 1),
        (
            "SITEMAP: https://x/one.xml\nsitemap: https://x/two.xml",
            None,
            [X + "/one.xml", X + "/two.xml"],
            0,
        ),
        ("Sitemap: ftp://x/s.xml", X, [], 1),
        ("", X, [], 0),
    ],
)
def test_robots_urls_directives(text, base, urls, skipped):
    assert robots_of(text, base) == (urls, skipped)


def test_robots_urls_with_a_client_expands_sitemaps_in_place_of_listing_them(ws, net):
    net.add(LOOP + "/s.xml", 200, urlset(LOOP + "/p1", LOOP + "/p2"))
    urls, skipped = robots_of("Disallow: /a\nSitemap: /s.xml", LOOP, client=net.http())
    assert (urls, skipped) == ([LOOP + "/a", LOOP + "/p1", LOOP + "/p2"], 0)
    assert net.urls() == [LOOP + "/s.xml"]


def test_robots_urls_with_a_client_resolves_nested_sitemap_locs_against_the_given_base(
    ws, net
):
    net.add(LOOP + "/s.xml", 200, urlset("/rel"))
    urls, skipped = robots_of(
        f"Sitemap: {LOOP}/s.xml", "https://pinned.example", client=net.http()
    )
    assert (urls, skipped) == (["https://pinned.example/rel"], 0)


def test_robots_urls_with_a_client_lists_a_sitemap_that_cannot_be_fetched(ws, net):
    net.fail(LOOP + "/s.xml", httpx.ConnectError("boom"))
    assert robots_of("Sitemap: /s.xml", LOOP, client=net.http()) == (
        [LOOP + "/s.xml"],
        0,
    )


def test_urls_from_text_picks_robots_or_sitemap_and_returns_a_pair():
    assert from_text("Disallow: /a", X) == ([X + "/a"], 0)
    assert from_text("Disallow: /a") == ([], 1)
    result = from_text(urlset("https://x/one", "https://x/two"))
    assert result == (["https://x/one", "https://x/two"], 0)


def test_urls_from_text_sitemap_locs_are_resolved_and_unresolvable_ones_vanish_silently():
    text = urlset(
        "/rel", "https://x/abs", "ftp://x/no", "mailto:a@b.example", "x?a=1&amp;b=2"
    )
    assert from_text(text, X) == ([X + "/rel", "https://x/abs", X + "/x?a=1&b=2"], 0)
    assert from_text(text) == (["https://x/abs"], 0)


def test_urls_from_text_xml_without_locs_is_an_empty_sitemap_not_robots():
    assert from_text('<?xml version="1.0"?><rss>Disallow: /a</rss>', X) == ([], 0)


def test_urls_from_text_without_a_client_never_fetches_a_sitemap_index(ws, net):
    assert from_text(sitemapindex(LOOP + "/c1.xml", LOOP + "/c2.xml"), LOOP) == (
        [LOOP + "/c1.xml", LOOP + "/c2.xml"],
        0,
    )
    assert net.hits == []


def test_urls_from_text_with_a_client_expands_an_index_but_not_a_urlset(ws, net):
    net.add(LOOP + "/c1.xml", 200, urlset(LOOP + "/a", LOOP + "/b"))
    net.add(LOOP + "/c2.xml", 200, urlset(LOOP + "/c"))
    expanded = from_text(
        sitemapindex(LOOP + "/c1.xml", LOOP + "/c2.xml"), client=net.http()
    )
    assert expanded == ([LOOP + "/a", LOOP + "/b", LOOP + "/c"], 0)
    assert net.urls() == [LOOP + "/c1.xml", LOOP + "/c2.xml"]
    net.hits.clear()
    flat = from_text(urlset(LOOP + "/a.xml"), client=net.http())
    assert flat == ([LOOP + "/a.xml"], 0) and net.hits == []


def test_urls_from_text_sitemap_budget_caps_fetches_and_lists_the_rest(ws, net):
    children = [f"{LOOP}/c{n}.xml" for n in range(1, 13)]
    for number, child in enumerate(children, start=1):
        net.add(child, 200, urlset(f"{LOOP}/page{number}"))
    budget, seen = [10], set()
    urls, skipped = robots.urls_from_text(
        sitemapindex(*children), None, client=net.http(), budget=budget, seen=seen
    )
    assert urls == [f"{LOOP}/page{n}" for n in range(1, 11)] + children[10:]
    assert skipped == 0 and net.urls() == children[:10]
    assert budget == [0] and seen == set(children[:10])


def test_urls_from_text_small_budget_and_shared_seen_set(ws, net):
    net.add(LOOP + "/c1.xml", 200, urlset(LOOP + "/p1"))
    net.add(LOOP + "/c2.xml", 200, urlset(LOOP + "/p2"))
    budget = [1]
    urls, _ = robots.urls_from_text(
        sitemapindex(LOOP + "/c1.xml", LOOP + "/c2.xml"),
        None,
        client=net.http(),
        budget=budget,
        seen=set(),
    )
    assert urls == [LOOP + "/p1", LOOP + "/c2.xml"] and budget == [0]
    already = {LOOP + "/c1.xml"}
    urls, _ = robots.urls_from_text(
        sitemapindex(LOOP + "/c1.xml", LOOP + "/c2.xml"),
        None,
        client=net.http(),
        budget=[5],
        seen=already,
    )
    assert urls == [LOOP + "/p2"]


def test_urls_from_text_nested_indexes_share_one_budget(ws, net):
    net.add(
        LOOP + "/mid.xml", 200, sitemapindex(LOOP + "/leaf1.xml", LOOP + "/leaf2.xml")
    )
    net.add(LOOP + "/leaf1.xml", 200, urlset(LOOP + "/p1"))
    net.add(LOOP + "/other.xml", 200, urlset(LOOP + "/p2"))
    budget = [2]
    urls, _ = robots.urls_from_text(
        sitemapindex(LOOP + "/mid.xml", LOOP + "/other.xml"),
        None,
        client=net.http(),
        budget=budget,
        seen=set(),
    )
    assert urls == [LOOP + "/p1", LOOP + "/leaf2.xml", LOOP + "/other.xml"]
    assert net.urls() == [LOOP + "/mid.xml", LOOP + "/leaf1.xml"] and budget == [0]


def test_urls_from_text_a_sitemap_cycle_is_fetched_once_per_sitemap(ws, net):
    net.add(LOOP + "/a.xml", 200, sitemapindex(LOOP + "/b.xml"))
    net.add(LOOP + "/b.xml", 200, sitemapindex(LOOP + "/a.xml"))
    urls, _ = from_text(sitemapindex(LOOP + "/a.xml"), client=net.http())
    assert urls == [] and net.urls() == [LOOP + "/a.xml", LOOP + "/b.xml"]


def test_urls_from_text_child_listed_twice_is_fetched_once_and_not_listed_again(
    ws, net
):
    net.add(LOOP + "/c1.xml", 200, urlset(LOOP + "/p1"))
    urls, _ = from_text(
        sitemapindex(LOOP + "/c1.xml", LOOP + "/c1.xml"), client=net.http()
    )
    assert urls == [LOOP + "/p1"] and net.urls() == [LOOP + "/c1.xml"]


def test_urls_from_text_child_outcomes_failure_is_listed_404_is_silent_off_scope_redirect_is_dropped(
    ws, net
):
    net.fail(LOOP + "/boom.xml", httpx.ConnectError("boom"))
    net.add(LOOP + "/missing.xml", 404, "nothing here")
    net.redirect(LOOP + "/away.xml", OFF + "/x.xml")
    index = sitemapindex(LOOP + "/boom.xml", LOOP + "/missing.xml", LOOP + "/away.xml")
    assert from_text(index, client=net.http()) == ([LOOP + "/boom.xml"], 0)


def test_urls_from_text_off_scope_children_depend_on_whether_a_scope_file_exists(
    ws, net
):
    index = sitemapindex(OFF + "/c.xml", LOOP + "/ok.xml")
    net.add(LOOP + "/ok.xml", 200, urlset(LOOP + "/p"))
    assert from_text(index, client=net.http()) == ([OFF + "/c.xml", LOOP + "/p"], 0)
    ws.scope("app.internal")
    assert from_text(index, client=net.http()) == ([LOOP + "/p"], 0)
    assert OFF + "/c.xml" not in net.urls()


def test_urls_from_text_exhausted_budget_lists_in_scope_children_and_drops_off_scope_ones_when_scoped(
    ws, net
):
    ws.scope("app.internal")
    index = sitemapindex(APP + "/c1.xml", OFF + "/c2.xml", APP + "/c3.xml")
    net.add(APP + "/c1.xml", 200, urlset(APP + "/p"))
    urls, _ = robots.urls_from_text(
        index, None, client=net.http(), budget=[1], seen=set()
    )
    assert urls == [APP + "/p", APP + "/c3.xml"]


def test_urls_from_text_nested_indexes_and_relative_locs_resolve_against_the_child_origin(
    ws, net
):
    net.add(LOOP + "/top.xml", 200, sitemapindex(LOOP + "/mid.xml"))
    net.add(LOOP + "/mid.xml", 200, sitemapindex(LOOP + "/leaf.xml"))
    net.add(LOOP + "/leaf.xml", 200, urlset("/rel/page", "other.html"))
    urls, _ = from_text(net.routes[LOOP + "/top.xml"][2], client=net.http())
    assert urls == [LOOP + "/rel/page", LOOP + "/other.html"]
    assert net.urls() == [LOOP + "/mid.xml", LOOP + "/leaf.xml"]


def test_urls_from_text_given_base_wins_over_the_child_origin(ws, net):
    net.add(LOOP + "/leaf.xml", 200, urlset("/rel"))
    urls, _ = from_text(
        sitemapindex(LOOP + "/leaf.xml"), "https://pinned.example", client=net.http()
    )
    assert urls == ["https://pinned.example/rel"]


def test_urls_from_text_a_fetched_child_that_is_robots_text_is_parsed_as_robots(
    ws, net
):
    net.add(LOOP + "/odd.xml", 200, "Disallow: /from-robots\n")
    assert from_text(sitemapindex(LOOP + "/odd.xml"), client=net.http()) == (
        [LOOP + "/from-robots"],
        0,
    )


def test_robots_fetch_document_returns_body_and_final_url_following_three_redirects(
    ws, net
):
    net.redirect(LOOP + "/r0", "/r1", 301)
    net.redirect(LOOP + "/r1", "/r2")
    net.redirect(LOOP + "/r2", "/end")
    net.add(LOOP + "/end", 200, "landed")
    assert robots.fetch_document(net.http(), LOOP + "/r0") == ("landed", LOOP + "/end")
    assert {hit.method for hit in net.hits} == {"GET"}


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_robots_fetch_document_follows_each_redirect_status(ws, net, status):
    net.redirect(LOOP + "/a", "/b", status)
    net.add(LOOP + "/b", 200, "B")
    assert robots.fetch_document(net.http(), LOOP + "/a") == ("B", LOOP + "/b")


@pytest.mark.parametrize("status", [300, 304, 305])
def test_robots_fetch_document_does_not_follow_other_3xx(ws, net, status):
    net.add(LOOP + "/a", status, "body", {"location": "/b"})
    assert robots.fetch_document(net.http(), LOOP + "/a") == ("body", LOOP + "/a")
    assert net.urls() == [LOOP + "/a"]


def test_robots_fetch_document_body_edge_cases(ws, net):
    net.add(LOOP + "/bad", 200, b"ok \xff end")
    net.add(LOOP + "/bom", 200, b"\xef\xbb\xbfhi")
    net.add(LOOP + "/gone", 404, "missing")
    net.add(LOOP + "/huge", 200, [b"a" * 600_000] * 3)
    assert robots.fetch_document(net.http(), LOOP + "/bad")[0] == "ok � end"
    assert robots.fetch_document(net.http(), LOOP + "/bom")[0] == "﻿hi"
    assert robots.fetch_document(net.http(), LOOP + "/gone")[0] == "missing"
    assert robots.fetch_document(net.http(), LOOP + "/huge")[0] == "a" * 1_000_000


def test_robots_fetch_document_redirect_without_location_returns_the_redirect_response(
    ws, net
):
    net.add(LOOP + "/n", 301, "moved")
    net.add(LOOP + "/m", 304, "same", {"location": "/z"})
    net.add(LOOP + "/blank", 302, "blank", {"location": "   "})
    assert robots.fetch_document(net.http(), LOOP + "/n") == ("moved", LOOP + "/n")
    assert robots.fetch_document(net.http(), LOOP + "/m") == ("same", LOOP + "/m")
    assert robots.fetch_document(net.http(), LOOP + "/blank") == (
        "blank",
        LOOP + "/blank",
    )
    assert net.urls() == [LOOP + "/n", LOOP + "/m", LOOP + "/blank"]


def test_robots_fetch_document_scope_and_scheme_errors(ws, net):
    net.redirect(LOOP + "/go", OFF + "/x")
    with pytest.raises(robots.ScopeError) as stop:
        robots.fetch_document(net.http(), LOOP + "/go")
    assert stop.value.host == "other.example" and net.urls() == [LOOP + "/go"]
    with pytest.raises(robots.ScopeError) as raw_stop:
        robots.fetch_document(net.http(), "file:///etc/passwd")
    assert raw_stop.value.host == "file:///etc/passwd"
    with pytest.raises(
        robots.FetchError, match=r"^Only http and https URLs can be fetched\.$"
    ):
        robots.fetch_document(net.http(), "ftp://127.0.0.1/x")


def test_robots_fetch_document_failure_message_carries_the_error_text_not_just_the_class(
    ws, net
):
    net.fail(LOOP + "/e", httpx.ConnectError("boom"))
    with pytest.raises(robots.FetchError) as caught:
        robots.fetch_document(net.http(), LOOP + "/e")
    assert str(caught.value) == f"Could not fetch {LOOP}/e: boom"
    assert isinstance(caught.value.__cause__, httpx.ConnectError)
    net.redirect(LOOP + "/first", "/second")
    net.fail(LOOP + "/second", httpx.ReadTimeout("slow"))
    with pytest.raises(robots.FetchError) as later:
        robots.fetch_document(net.http(), LOOP + "/first")
    assert str(later.value) == f"Could not fetch {LOOP}/second: slow"
    net.fail(
        LOOP + "/p",
        egress.PolicyBlocked("policy-missing-or-invalid; no outbound action ran"),
    )
    with pytest.raises(robots.FetchError) as caught:
        robots.fetch_document(net.http(), LOOP + "/p")
    assert (
        str(caught.value)
        == f"Could not fetch {LOOP}/p: policy-missing-or-invalid; no outbound action ran"
    )


def test_robots_fetch_document_correct_a_fourth_redirect_is_a_too_many_redirects_error(
    ws, net
):
    redirect_chain(net, 5)
    raised = None
    try:
        robots.fetch_document(net.http(), LOOP + "/r0")
    except robots.FetchError as exc:
        raised = exc
    assert raised is not None and "too many redirects" in str(raised)


# ---- robots.main -----------------------------------------------------------------------------------------

ROBOTS_FILE = (
    "User-agent: *\nDisallow: /admin/\nAllow: /pub$\nDisallow: /x*\nSitemap: /map.xml\n"
    "Disallow: http://other.example/z\n"
)


@pytest.mark.parametrize(
    "argv,message",
    [
        ([], "Give a local robots.txt or sitemap, or pass --fetch URL."),
        (
            ["--base", "x.example", "--fetch", LOOP + "/robots.txt"],
            "Base needs an http or https URL, such as https://app.internal.",
        ),
        (
            ["--base", "ftp://x.example", "--fetch", LOOP + "/robots.txt"],
            "Base needs an http or https URL, such as https://app.internal.",
        ),
    ],
)
def test_robots_argument_errors_exit_two(ws, net, cli, argv, message):
    result = cli(robots.main, *argv)
    assert (result.rc, result.out, result.err) == (2, "", message + "\n")
    assert net.client_calls == []


def test_robots_base_and_fetch_outside_scope_are_refused(ws, net, cli):
    from bughunt.core.workspace import explain_block

    local = ws.file("robots.txt", ROBOTS_FILE)
    ws.scope("app.internal")
    base = cli(robots.main, local, "--base", OFF)
    assert (base.rc, base.out, base.err) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )
    assert cli(robots.main, local, "--base", OFF, "--no-workspace").rc == 0
    fetch = cli(robots.main, "--fetch", OFF + "/robots.txt", "--no-workspace")
    assert (fetch.rc, fetch.out, fetch.err) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )
    assert net.hits == [] and net.client_calls == []


def test_robots_fetch_of_a_non_loopback_host_is_refused_when_there_is_no_scope_file(
    ws, net, cli
):
    from bughunt.core.workspace import explain_block

    result = cli(robots.main, "--fetch", APP + "/robots.txt")
    assert (result.rc, result.err) == (2, explain_block("app.internal") + "\n")
    assert "no scope file" in result.err and net.client_calls == []
    marked = cli(robots.main, "--fetch", "x[red]y")
    assert marked.err == explain_block("x[red]y") + "\n" and "[red]" in marked.err


def test_robots_local_file_with_base_prints_in_scope_urls_and_remembers_them(
    ws, net, cli
):
    ws.scope("app.internal")
    result = cli(robots.main, ws.file("robots.txt", ROBOTS_FILE), "--base", APP)
    assert result.rc == 0
    assert result.out == "".join(
        f"{APP}{path}\n" for path in ("/admin/", "/pub", "/x", "/map.xml")
    )
    assert result.err == "4 URL(s)  1 outside scope  4 new in urls.txt\n"
    assert ws.urls() == [
        f"{APP}{path}" for path in ("/admin/", "/pub", "/x", "/map.xml")
    ]
    assert net.client_calls == []
    again = cli(robots.main, ws.file("robots.txt", ROBOTS_FILE), "--base", APP)
    assert (
        again.out == result.out
        and again.err == "4 URL(s)  1 outside scope  0 new in urls.txt\n"
    )
    assert len(ws.urls()) == 4


def test_robots_local_file_without_base_counts_relative_paths_as_skipped(ws, net, cli):
    ws.scope("app.internal")
    result = cli(robots.main, ws.file("robots.txt", ROBOTS_FILE))
    assert (result.rc, result.out) == (0, "")
    assert (
        result.err
        == "0 URL(s)  4 relative path(s) need --base  1 outside scope  0 new in urls.txt\n"
    )


def test_robots_without_a_scope_file_lists_everything_and_remembers_nothing(
    ws, net, cli
):
    result = cli(robots.main, ws.file("robots.txt", ROBOTS_FILE), "--base", APP)
    assert result.out.splitlines()[-2] == "http://other.example/z"
    assert result.err == "5 URL(s)\n"
    assert ws.urls() == []


def test_robots_no_workspace_neither_filters_nor_remembers(ws, net, cli):
    ws.scope("app.internal")
    result = cli(
        robots.main, ws.file("robots.txt", ROBOTS_FILE), "--base", APP, "--no-workspace"
    )
    assert "http://other.example/z\n" in result.out and result.err == "5 URL(s)\n"
    assert ws.urls() == []


def test_robots_base_is_trimmed(ws, net, cli):
    result = cli(
        robots.main,
        ws.file("r.txt", "Disallow: /a\n"),
        "--base",
        f"  {APP}  ",
        "--no-workspace",
    )
    assert result.out == f"{APP}/a\n"


def test_robots_save_writes_only_the_kept_urls(ws, net, cli):
    ws.scope("app.internal")
    target = ws.base / "out.txt"
    cli(
        robots.main,
        ws.file("robots.txt", ROBOTS_FILE),
        "--base",
        APP,
        "--save",
        str(target),
    )
    saved = target.read_text(encoding="utf-8")
    assert "other.example" not in saved and saved.count("\n") == 4


def test_robots_inputs_combine_in_order_and_duplicates_collapse(ws, net, cli):
    one = ws.file("one.txt", "Disallow: /a\nDisallow: /b\n")
    two = ws.file("two.txt", "Disallow: /b\nDisallow: /c\n")
    result = cli(robots.main, one, two, "--base", APP, "--no-workspace")
    assert result.out == f"{APP}/a\n{APP}/b\n{APP}/c\n"


def test_robots_a_missing_input_aborts_with_exit_two_and_prints_no_urls(ws, net, cli):
    one = ws.file("one.txt", "Disallow: /a\n")
    result = cli(robots.main, one, str(ws.base / "missing.txt"), "--base", APP)
    assert (result.rc, result.out) == (2, "")
    assert result.err == f"No file named {ws.base / 'missing.txt'}.\n"


def test_robots_local_sitemap_files_are_read_without_fetching(ws, net, cli):
    sitemap = ws.file("sitemap.xml", sitemapindex(LOOP + "/c1.xml") + "")
    result = cli(robots.main, sitemap)
    assert result.out == LOOP + "/c1.xml\n" and net.client_calls == []
    flat = ws.file("flat.xml", urlset("/rel", LOOP + "/abs"))
    both = cli(robots.main, flat, "--base", LOOP)
    assert both.out == f"{LOOP}/rel\n{LOOP}/abs\n"


def test_robots_non_utf8_and_crlf_input_is_tolerated(ws, net, cli):
    raw = b"\xff\xfeDisallow: /a\r\nAllow: /b\r\n"
    result = cli(robots.main, ws.file("r.txt", raw, binary=True), "--base", LOOP)
    assert result.out == f"{LOOP}/b\n"


def test_robots_save_writes_the_printed_urls_even_when_empty(ws, net, cli):
    target = ws.base / "out.txt"
    result = cli(
        robots.main,
        ws.file("robots.txt", ROBOTS_FILE),
        "--base",
        APP,
        "--no-workspace",
        "--save",
        str(target),
    )
    assert result.rc == 0 and target.read_text(encoding="utf-8") == result.out
    empty = ws.base / "empty.txt"
    cli(robots.main, ws.file("blank.txt", "# nothing\n"), "--save", str(empty))
    assert empty.read_text(encoding="utf-8") == ""


def test_robots_save_failure_exits_one_after_the_urls_were_printed(ws, net, cli):
    folder = ws.base / "a-folder"
    folder.mkdir()
    result = cli(
        robots.main,
        ws.file("robots.txt", "Disallow: /a\n"),
        "--base",
        APP,
        "--no-workspace",
        "--save",
        str(folder),
    )
    assert result.rc == 1 and result.out == f"{APP}/a\n"
    assert result.err.startswith(f"Could not write {folder}: ")


def test_robots_fetch_reads_robots_follows_redirects_and_expands_sitemaps(ws, net, cli):
    ws.scope("app.internal")
    net.redirect(APP + "/robots.txt", "/r2", 301)
    net.add(
        APP + "/r2",
        200,
        "Disallow: /z\nSitemap: " + APP + "/sm.xml\nSitemap: " + APP + "/idx.xml\n",
    )
    net.add(APP + "/sm.xml", 200, urlset(APP + "/s1"))
    net.add(
        APP + "/idx.xml",
        200,
        sitemapindex(
            APP + "/c1.xml", APP + "/c1.xml", APP + "/c2.xml", OFF + "/c3.xml"
        ),
    )
    net.add(APP + "/c1.xml", 200, urlset(APP + "/n1"))
    net.fail(APP + "/c2.xml", httpx.ConnectError("x"))
    result = cli(robots.main, "--fetch", APP + "/robots.txt")
    assert result.rc == 0
    assert result.out == "".join(
        f"{APP}{path}\n" for path in ("/z", "/s1", "/n1", "/c2.xml")
    )
    assert result.err == "4 URL(s)  4 new in urls.txt\n"
    assert net.urls() == [
        f"{APP}{path}"
        for path in ("/robots.txt", "/r2", "/sm.xml", "/idx.xml", "/c1.xml", "/c2.xml")
    ]


def test_robots_fetch_uses_the_final_origin_unless_base_is_given(ws, net, cli):
    net.add(LOOP + "/robots.txt", 200, "Disallow: /rel\n")
    assert cli(robots.main, "--fetch", LOOP + "/robots.txt").out == f"{LOOP}/rel\n"
    pinned = cli(
        robots.main, "--fetch", LOOP + "/robots.txt", "--base", "http://127.0.0.1:9999"
    )
    assert pinned.out == "http://127.0.0.1:9999/rel\n"


def test_robots_fetch_resolves_relative_paths_against_the_final_origin(ws, net, cli):
    net.redirect(LOOP + "/robots.txt", "http://127.0.0.1:9090/robots.txt")
    net.add("http://127.0.0.1:9090/robots.txt", 200, "Disallow: /rel\n")
    assert (
        cli(robots.main, "--fetch", LOOP + "/robots.txt").out
        == "http://127.0.0.1:9090/rel\n"
    )


def test_robots_fetched_text_also_counts_unresolvable_entries(ws, net, cli):
    net.add(
        LOOP + "/robots.txt",
        200,
        "Disallow: /ok\nDisallow: ftp://x.example/y\nSitemap:\n",
    )
    result = cli(robots.main, "--fetch", LOOP + "/robots.txt")
    assert (
        result.out == f"{LOOP}/ok\n"
        and result.err == "1 URL(s)  2 relative path(s) need --base\n"
    )


def test_robots_fetch_goes_after_local_files(ws, net, cli):
    net.add(LOOP + "/robots.txt", 200, "Disallow: /remote\n")
    local = ws.file("l.txt", "Disallow: /local\n")
    result = cli(robots.main, local, "--fetch", LOOP + "/robots.txt", "--base", LOOP)
    assert result.out == f"{LOOP}/local\n{LOOP}/remote\n"


def test_robots_fetch_of_an_index_stops_expanding_after_ten_sitemaps(ws, net, cli):
    children = [f"{LOOP}/c{n}.xml" for n in range(1, 13)]
    net.add(LOOP + "/index.xml", 200, sitemapindex(*children))
    for number, child in enumerate(children, start=1):
        net.add(child, 200, urlset(f"{LOOP}/page{number}"))
    result = cli(robots.main, "--fetch", LOOP + "/index.xml")
    assert (
        result.out.splitlines()
        == [f"{LOOP}/page{n}" for n in range(1, 11)] + children[10:]
    )
    assert len(net.hits) == 11


def test_robots_fetch_errors(ws, net, cli):
    from bughunt.core.workspace import explain_block

    net.fail(LOOP + "/robots.txt", httpx.ConnectError("boom"))
    failed = cli(robots.main, "--fetch", LOOP + "/robots.txt")
    assert (failed.rc, failed.out, failed.err) == (
        1,
        "",
        f"Could not fetch {LOOP}/robots.txt: boom\n",
    )
    net.redirect(LOOP + "/away", OFF + "/robots.txt")
    away = cli(robots.main, "--fetch", LOOP + "/away")
    assert (away.rc, away.out, away.err) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )


def test_robots_fetch_client_construction_sends_no_credentials(ws, net, cli):
    ws.session(cookie="saved=1", authorization="Bearer saved")
    net.add(LOOP + "/robots.txt", 200, "Disallow: /a\n")
    cli(robots.main, "--fetch", LOOP + "/robots.txt")
    assert net.client_calls == [
        {
            "operation": "manual",
            "timeout": 10.0,
            "follow_redirects": False,
            "trust_env": False,
            "headers": {
                "User-Agent": f"Bughunt/{VERSION}",
                "Accept-Encoding": "identity",
            },
        }
    ]
    assert (
        "cookie" not in net.hits[0].headers
        and "authorization" not in net.hits[0].headers
    )


# =========================================================================================================
# redirect.py
# =========================================================================================================


def test_redirect_prints_each_hop_then_the_final_status(ws, net, cli):
    net.redirect(LOOP + "/a", "/b", 301)
    net.redirect(LOOP + "/b", LOOP + "/c", 302)
    net.add(LOOP + "/c", 200, "ok")
    result = cli(redirect.main, LOOP + "/a")
    assert (result.rc, result.err) == (0, "")
    assert (
        result.out
        == f"301 {LOOP}/a -> {LOOP}/b\n302 {LOOP}/b -> {LOOP}/c\n200 {LOOP}/c\n"
    )
    assert [hit.method for hit in net.hits] == ["GET", "GET", "GET"]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_follows_each_redirect_status(ws, net, cli, status):
    net.redirect(LOOP + "/a", "/b", status)
    net.add(LOOP + "/b", 204)
    assert (
        cli(redirect.main, LOOP + "/a").out
        == f"{status} {LOOP}/a -> {LOOP}/b\n204 {LOOP}/b\n"
    )


@pytest.mark.parametrize("status", [200, 204, 300, 304, 305, 400, 404, 500])
def test_redirect_other_statuses_end_the_chain_even_with_a_location_header(
    ws, net, cli, status
):
    net.add(LOOP + "/a", status, "", {"location": "/b"})
    result = cli(redirect.main, LOOP + "/a")
    assert (result.rc, result.out, result.err) == (0, f"{status} {LOOP}/a\n", "")
    assert net.urls() == [LOOP + "/a"]


@pytest.mark.parametrize("location", [None, "", "   "])
def test_redirect_without_a_usable_location_prints_the_status_line_only(
    ws, net, cli, location
):
    net.add(
        LOOP + "/a", 302, "", {"location": location} if location is not None else None
    )
    assert cli(redirect.main, LOOP + "/a").out == f"302 {LOOP}/a\n"


@pytest.mark.parametrize(
    "location,target",
    [
        ("/b", LOOP + "/b"),
        ("b", LOOP + "/dir/b"),
        ("../b", LOOP + "/b"),
        ("?x=1", LOOP + "/dir/a?x=1"),
        ("//127.0.0.1:8080/b", LOOP + "/b"),
        ("  /padded  ", LOOP + "/padded"),
        ("/b#frag", LOOP + "/b#frag"),
    ],
)
def test_redirect_resolves_locations_against_the_current_url(
    ws, net, cli, location, target
):
    net.redirect(LOOP + "/dir/a", location)
    net.add(target if "#" not in target else target.split("#")[0], 200)
    result = cli(redirect.main, LOOP + "/dir/a")
    assert result.out.splitlines()[0] == f"302 {LOOP}/dir/a -> {target}"


def test_redirect_limit_is_a_request_budget_and_the_stop_notice_follows_the_last_arrow(
    ws, net, cli
):
    net.redirect(LOOP + "/loop", "/loop")
    one = cli(redirect.main, LOOP + "/loop", "--limit", "1")
    assert (one.rc, one.out, one.err) == (
        0,
        f"302 {LOOP}/loop -> {LOOP}/loop\n",
        "Stopped after 1 hops.\n",
    )
    assert len(net.hits) == 1
    net.hits.clear()
    three = cli(redirect.main, LOOP + "/loop", "--limit", "3")
    assert (
        three.out == f"302 {LOOP}/loop -> {LOOP}/loop\n" * 3
        and three.err == "Stopped after 3 hops.\n"
    )
    assert len(net.hits) == 3


def test_redirect_chain_that_ends_exactly_inside_the_limit_has_no_stop_notice(
    ws, net, cli
):
    net.redirect(LOOP + "/a", "/b")
    net.redirect(LOOP + "/b", "/c")
    net.add(LOOP + "/c", 200)
    inside = cli(redirect.main, LOOP + "/a", "--limit", "3")
    assert inside.out.splitlines()[-1] == f"200 {LOOP}/c" and inside.err == ""
    short = cli(redirect.main, LOOP + "/a", "--limit", "2")
    assert (
        short.out.splitlines()[-1] == f"302 {LOOP}/b -> {LOOP}/c"
        and short.err == "Stopped after 2 hops.\n"
    )


def test_redirect_stops_when_a_hop_changes_hostname_after_printing_the_arrow(
    ws, net, cli
):
    net.redirect(LOOP + "/x", "http://localhost:8080/y")
    result = cli(redirect.main, LOOP + "/x")
    assert (result.rc, result.out) == (0, f"302 {LOOP}/x -> http://localhost:8080/y\n")
    assert result.err == "Stopped. http://localhost:8080/y is not on 127.0.0.1.\n"
    assert net.urls() == [LOOP + "/x"]


def test_redirect_hostname_comparison_ignores_case_and_a_trailing_dot(ws, net, cli):
    net.redirect("http://localhost:8080/a", "http://LOCALHOST.:8080/b")
    net.add("http://localhost.:8080/b", 200)
    result = cli(redirect.main, "http://LocalHost:8080/a")
    assert result.out.splitlines() == [
        "302 http://LocalHost:8080/a -> http://LOCALHOST.:8080/b",
        "200 http://LOCALHOST.:8080/b",
    ]


def test_redirect_hostname_check_comes_before_the_limit_notice(ws, net, cli):
    net.redirect(LOOP + "/x", "http://localhost:8080/y")
    result = cli(redirect.main, LOOP + "/x", "--limit", "1")
    assert result.err == "Stopped. http://localhost:8080/y is not on 127.0.0.1.\n"


def test_redirect_a_trailing_dot_on_the_start_host_does_not_make_the_next_hop_foreign(
    ws, net, cli
):
    net.redirect("http://localhost.:8080/a", "http://localhost:8080/b")
    net.add("http://localhost:8080/b", 200)
    result = cli(redirect.main, "http://localhost.:8080/a")
    assert (
        result.out.splitlines()[-1] == "200 http://localhost:8080/b"
        and result.err == ""
    )


def test_redirect_start_url_is_trimmed(ws, net, cli):
    net.add(LOOP + "/a", 200)
    assert cli(redirect.main, f"  {LOOP}/a \n").out == f"200 {LOOP}/a\n"


@pytest.mark.parametrize(
    "argv",
    [
        ["--limit", "0"],
        ["--limit", "-1"],
        ["--limit", "21"],
        ["--timeout", "0"],
        ["--timeout", "-2"],
        ["--limit", "0", "--timeout", "0"],
    ],
)
def test_redirect_numeric_argument_errors(ws, net, cli, argv):
    result = cli(redirect.main, LOOP + "/a", *argv)
    assert (result.rc, result.out) == (2, "")
    assert result.err == "Limit must be 1 through 20. Timeout must be greater than 0.\n"
    assert net.client_calls == []


@pytest.mark.parametrize("limit", ["1", "20"])
def test_redirect_limit_bounds_are_inclusive(ws, net, cli, limit):
    net.add(LOOP + "/a", 200)
    assert cli(redirect.main, LOOP + "/a", "--limit", limit).rc == 0


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1/",
        "127.0.0.1:8080/a",
        "http://",
        "https://",
        "file:///etc/passwd",
        "/just/a/path",
        "  ",
    ],
)
def test_redirect_rejects_non_http_urls(ws, net, cli, url):
    result = cli(redirect.main, url)
    assert (result.rc, result.out, result.err) == (
        2,
        "",
        "Give an http or https URL, such as http://127.0.0.1/.\n",
    )
    assert net.client_calls == []


def test_redirect_start_outside_scope_is_refused_without_contacting_anything(
    ws, net, cli
):
    from bughunt.core.workspace import explain_block

    result = cli(redirect.main, OFF + "/")
    assert (result.rc, result.out, result.err) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )
    assert net.client_calls == [] and net.hits == []
    ws.scope("app.internal")
    net.add(APP + "/", 200)
    assert cli(redirect.main, APP + "/").out == f"200 {APP}/\n"


def test_redirect_network_failure_exits_one_and_keeps_earlier_lines(ws, net, cli):
    net.redirect(LOOP + "/a", "/b")
    net.fail(LOOP + "/b", httpx.ConnectError("boom"))
    result = cli(redirect.main, LOOP + "/a")
    assert result.rc == 1 and result.out == f"302 {LOOP}/a -> {LOOP}/b\n"
    assert result.err == f"Could not fetch {LOOP}/b: ConnectError\n"


@pytest.mark.parametrize(
    "error,name",
    [
        (httpx.ReadTimeout("slow"), "ReadTimeout"),
        (egress.PolicyBlocked("blocked; no outbound action ran"), "PolicyBlocked"),
    ],
)
def test_redirect_error_message_names_the_error_class_only(ws, net, cli, error, name):
    net.fail(LOOP + "/a", error)
    result = cli(redirect.main, LOOP + "/a")
    assert (result.rc, result.out, result.err) == (
        1,
        "",
        f"Could not fetch {LOOP}/a: {name}\n",
    )


def test_redirect_builds_the_guarded_client_with_manual_operation_and_no_auto_redirects(
    ws, net, cli
):
    net.add(LOOP + "/a", 200)
    cli(redirect.main, LOOP + "/a", "--timeout", "2.5")
    assert net.client_calls == [
        {
            "operation": "manual",
            "timeout": 2.5,
            "verify": True,
            "trust_env": False,
            "follow_redirects": False,
            "headers": {
                "User-Agent": f"Bughunt/{VERSION}",
                "Accept-Encoding": "identity",
            },
        }
    ]
    cli(redirect.main, LOOP + "/a", "--insecure")
    assert net.client_calls[-1]["verify"] is False


def test_redirect_credentials_come_from_flags_or_the_saved_session(ws, net, cli):
    net.add(LOOP + "/a", 200)
    ws.session(cookie="saved=1", authorization="Bearer saved")
    cli(redirect.main, LOOP + "/a")
    assert (
        net.hits[-1].headers["cookie"] == "saved=1"
        and net.hits[-1].headers["authorization"] == "Bearer saved"
    )
    cli(
        redirect.main,
        LOOP + "/a",
        "--cookie",
        "mine=2",
        "--authorization",
        "Bearer mine",
    )
    assert (
        net.hits[-1].headers["cookie"] == "mine=2"
        and net.hits[-1].headers["authorization"] == "Bearer mine"
    )
    cli(redirect.main, LOOP + "/a", "--cookie", "", "--authorization", " ")
    assert (
        "cookie" not in net.hits[-1].headers
        and "authorization" not in net.hits[-1].headers
    )


def test_redirect_every_same_host_hop_carries_the_credentials(ws, net, cli):
    net.redirect(LOOP + "/a", "/b")
    net.add(LOOP + "/b", 200)
    cli(redirect.main, LOOP + "/a", "--cookie", "s=1")
    assert [hit.headers.get("cookie") for hit in net.hits] == ["s=1", "s=1"]


# =========================================================================================================
# decode.py
# =========================================================================================================

SENTENCE = "hello world, this is a long enough sentence to cross sixty four chars!!"
GREEN, RESET = "\x1b[1;92m", "\x1b[0m"


def b64(value):
    return base64.b64encode(
        value.encode() if isinstance(value, str) else value
    ).decode()


ENC = b64(SENTENCE)
assert len(ENC) == 96


def data_uri(payload, mime="text/plain"):
    return f"data:{mime};base64,{payload}"


def test_decode_unfolded_is_a_frozen_value_with_three_fields():
    assert [f.name for f in fields(decode.Unfolded)] == ["text", "decoded", "images"]
    value = decode.Unfolded("t", 1, 2)
    assert (value.text, value.decoded, value.images) == ("t", 1, 2)
    assert value == decode.Unfolded("t", 1, 2) and hash(value) == hash(
        decode.Unfolded("t", 1, 2)
    )
    with pytest.raises(FrozenInstanceError):
        value.text = "other"


def test_decode_stop_exceptions_carry_their_context():
    scope, host = decode.ScopeStop("evil.example"), decode.HostStop("http://b/x", "a")
    assert (
        isinstance(scope, Exception)
        and scope.host == "evil.example"
        and str(scope) == "evil.example"
    )
    assert (
        isinstance(host, Exception)
        and (host.url, host.origin) == ("http://b/x", "a")
        and str(host) == "http://b/x"
    )


@pytest.mark.parametrize(
    "text", ["", "plain text, nothing to see", "<p>short YWJj token</p>", "a=b&c=d"]
)
def test_decode_unfold_leaves_text_without_blocks_untouched(text):
    assert decode.unfold(text) == decode.Unfolded(text, 0, 0)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("data:text/plain;base64,SGVsbG8gd29ybGQ=", "Hello world"),
        ("DATA:TEXT/PLAIN;BASE64,SGVsbG8gd29ybGQ=", "Hello world"),
        ("data:text/plain;charset=utf-8;base64,SGVsbG8=", "Hello"),
        ("data:text/plain;charset=utf-8;format=flowed;base64,SGVsbG8=", "Hello"),
        ("data:;base64,SGVsbG8=", "Hello"),
        ("data:text/plain;base64,SGVsbG8", "Hello"),
        ("data:text/plain;base64,SGVs\nbG8=", "Hello"),
        ("data:text/plain;base64,SGVs\r\nbG8=", "Hello"),
        ('<a href="data:text/plain;base64,SGVsbG8=">x</a>', '<a href="Hello">x</a>'),
        ("data:application/json;base64," + b64('{"a": 1}'), '{"a": 1}'),
        (
            "data:text/plain;base64,"
            + base64.urlsafe_b64encode("hé?>>>".encode()).decode(),
            "hé?>>>",
        ),
        ("data:text/plain;base64," + b64("café ✓"), "café ✓"),
        ("data:text/plain;base64," + b64("tab\there\nnew line"), "tab\there\nnew line"),
        (
            "data:text/plain;base64," + b64(r"back\slash \1 \g<0> $1"),
            r"back\slash \1 \g<0> $1",
        ),
    ],
)
def test_decode_unfold_replaces_the_whole_data_uri_with_its_text(raw, expected):
    assert decode.unfold(raw) == decode.Unfolded(expected, 1, 0)


@pytest.mark.parametrize(
    "raw",
    [
        "data:text/plain;base64," + b64(bytes(range(256))),
        "data:text/plain;base64," + b64("ab\x00cd"),
        "data:text/plain;base64," + b64("   \n\t "),
        "data:text/plain;base64," + b64("abcdefgh\x01\x02"),
        "data:text/plain;base64," + b64(b"\xff\xfe\xfd"),
        "data:text/plain;base64,A",
        "data:text/plain;base64,SGVsbG8gd",
        "data:text/plain;base64,ab+/cd-_",
    ],
)
def test_decode_unfold_leaves_data_uris_that_are_not_clean_text(raw):
    assert decode.unfold(raw) == decode.Unfolded(raw, 0, 0)


def test_decode_unfold_printable_ratio_boundary_is_ninety_percent():
    assert decode.unfold(data_uri(b64("abcdefghi\x01"))).decoded == 1
    assert decode.unfold(data_uri(b64("abcdefgh\x01\x02"))).decoded == 0
    assert decode.unfold(data_uri(b64("tab\tnl\nand\rcr"))).decoded == 1


def test_decode_unfold_image_data_uris_stay_encoded_and_are_counted():
    raw = (
        "see data:image/png;base64,SGVsbG8= and data:IMAGE/SVG+xml;base64,PHN2Zz4= end"
    )
    assert decode.unfold(raw) == decode.Unfolded(raw, 0, 2)
    for mime in ("image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon"):
        assert decode.unfold(data_uri("!!", mime)) == decode.Unfolded(
            data_uri("!!", mime), 0, 0
        )
        assert decode.unfold(data_uri("SGVsbG8=", mime)) == decode.Unfolded(
            data_uri("SGVsbG8=", mime), 0, 1
        )
        # the image mime alone settles it: the payload is never validated or decoded
        assert decode.unfold(data_uri("not-valid-b64", mime)) == decode.Unfolded(
            data_uri("not-valid-b64", mime), 0, 1
        )


IMAGE_BLOBS = {
    "png": b"\x89PNG\r\n\x1a\n" + b"A" * 60,
    "jpeg": b"\xff\xd8\xff" + b"A" * 60,
    "gif87": b"GIF87a" + b"A" * 60,
    "gif89": b"GIF89a" + b"A" * 60,
    "webp": b"RIFF\x00\x00\x00\x00WEBP" + b"A" * 60,
    "ico": b"\x00\x00\x01\x00" + b"A" * 60,
    "cur": b"\x00\x00\x02\x00" + b"A" * 60,
    "bmp": b"BM" + b"\x00" * 8 + b"A" * 60,
}
NOT_IMAGES = {
    "bmp-nonzero-reserved": b"BM" + b"AAAA" + b"\x01\x00\x00\x00" + b"A" * 60,
    "riff-wave": b"RIFF\x00\x00\x00\x00WAVE" + b"A" * 60,
    "png-prefix-only": b"\x89PNG" + b"A" * 60,
}


@pytest.mark.parametrize("kind", sorted(IMAGE_BLOBS))
def test_decode_unfold_recognises_image_bytes_by_signature_in_both_block_kinds(kind):
    payload = b64(IMAGE_BLOBS[kind])
    bare = f"x {payload} y"
    assert decode.unfold(bare) == decode.Unfolded(bare, 0, 1)
    uri = data_uri(payload, "application/octet-stream")
    assert decode.unfold(uri) == decode.Unfolded(uri, 0, 1)


@pytest.mark.parametrize("kind", sorted(NOT_IMAGES))
def test_decode_unfold_look_alike_signatures_are_just_undecodable_binary(kind):
    bare = f"x {b64(NOT_IMAGES[kind])} y"
    assert decode.unfold(bare) == decode.Unfolded(bare, 0, 0)


def test_decode_unfold_counts_images_and_text_independently():
    raw = f"{data_uri('SGVsbG8=')} | {data_uri(b64(IMAGE_BLOBS['png']), 'application/x')} | {ENC[:48]}"
    result = decode.unfold(raw)
    assert (result.decoded, result.images) == (1, 1)
    assert result.text.startswith("Hello | data:application/x;base64,")


def test_decode_unfold_bare_block_cases():
    assert decode.unfold(f'x "{ENC}" y') == decode.Unfolded(f'x "{SENTENCE}" y', 1, 0)
    assert decode.unfold(f"before {ENC}\n- next") == decode.Unfolded(
        f"before {SENTENCE}\n- next", 1, 0
    )
    assert decode.unfold(ENC) == decode.Unfolded(SENTENCE, 1, 0)
    assert decode.unfold(f"token={ENC};") == decode.Unfolded(f"token={SENTENCE};", 1, 0)
    assert decode.unfold(f"{ENC} y") == decode.Unfolded(f"{SENTENCE} y", 1, 0)
    assert decode.unfold(f"{ENC} abc z") == decode.Unfolded(f"{SENTENCE} abc z", 1, 0)


def test_decode_unfold_wrapped_blocks_are_joined_before_decoding():
    assert decode.unfold("\n".join([ENC[:40], ENC[40:]])) == decode.Unfolded(
        SENTENCE, 1, 0
    )
    mime = base64.encodebytes((SENTENCE * 3).encode()).decode()
    assert decode.unfold(mime) == decode.Unfolded(SENTENCE * 3 + "\n", 1, 0)
    spaced = " ".join([ENC[:48], ENC[48:]])
    assert decode.unfold(spaced) == decode.Unfolded(SENTENCE, 1, 0)


def test_decode_unfold_minimum_applies_to_the_compact_length_of_bare_blocks_only():
    forty_eight, forty_five = b64("x" * 48), b64("x" * 45)
    assert (len(forty_eight), len(forty_five)) == (64, 60)
    assert decode.unfold(f"[{forty_eight}]") == decode.Unfolded(f"[{'x' * 48}]", 1, 0)
    assert decode.unfold(f"[{forty_five}]").decoded == 0
    assert decode.unfold(f"[{forty_five}]", minimum=60).decoded == 1
    assert decode.unfold(f"[{forty_five}]", minimum=61).decoded == 0
    assert decode.unfold(data_uri("SGVsbG8="), minimum=10_000).decoded == 1


def test_decode_unfold_a_bare_block_needs_forty_characters_whatever_the_minimum():
    thirty = b64("0123456789abcdefghijklmnopqrst")
    twenty_seven = b64("0123456789abcdefghijklmnopq")
    assert (len(thirty), len(twenty_seven)) == (40, 36)
    assert decode.unfold(f"hash {thirty} end", minimum=16).decoded == 1
    assert decode.unfold(f"hash {twenty_seven} end", minimum=16).decoded == 0
    assert decode.unfold(f"hash {thirty} end").decoded == 0


def test_decode_unfold_bare_block_minimum_of_forty_counts_alphabet_characters_not_padding():
    padded = b64("0123456789abcdefghijklmnopqrs")
    assert len(padded) == 40 and padded.endswith("=")
    assert decode.unfold(f"hash {padded} end", minimum=16).decoded == 0


def test_decode_unfold_bare_minimum_is_measured_without_the_whitespace_between_groups():
    forty_four = b64("0123456789abcdefghijklmnopqrstuvw")
    assert len(forty_four) == 44
    split = f"{forty_four[:40]} {forty_four[40:]}"
    assert decode.unfold(f"x {split} y", minimum=44) == decode.Unfolded(
        "x 0123456789abcdefghijklmnopqrstuvw y", 1, 0
    )
    assert decode.unfold(f"x {split} y", minimum=45) == decode.Unfolded(
        f"x {split} y", 0, 0
    )


def test_decode_unfold_a_standard_and_a_url_safe_character_in_one_payload_are_never_decoded():
    assert b64("~~~???") == "fn5+Pz8/"
    for payload, decoded in (
        ("fn5+Pz8/", 1),
        ("fn5-Pz8_", 1),
        ("fn5+Pz8_", 0),
        ("fn5-Pz8/", 0),
    ):
        assert decode.unfold(data_uri(payload)).decoded == decoded, payload
    assert decode.unfold(data_uri("fn5-Pz8_")).text == "~~~???"


def test_decode_unfold_image_signatures_are_recognised_at_their_minimum_length():
    exact = {
        "webp": b"RIFF\x00\x00\x00\x00WEBP",
        "ico": b"\x00\x00\x01\x00\x01\x02\x03\x04",
        "bmp": b"BM\x01\x02\x03\x04\x00\x00\x00\x00\x0a\x0b\x0c\x0d",
    }
    for kind, blob in exact.items():
        uri = data_uri(b64(blob), "application/octet-stream")
        assert decode.unfold(uri) == decode.Unfolded(uri, 0, 1), kind


def test_decode_unfold_adjacent_blocks_that_only_touch_are_both_decoded():
    result = decode.unfold(data_uri("SGVsbG8=") + ENC)
    assert result == decode.Unfolded("Hello" + SENTENCE, 2, 0)


def test_decode_unfold_printable_ratio_is_not_rounded_to_the_nearest_five_percent():
    assert (
        decode.unfold(data_uri(b64("abcdefghijklmnopq\x01\x02\x03"))).decoded == 0
    )  # 17 of 20 printable


def test_decode_unfold_bare_blocks_with_mixed_alphabets_or_binary_payloads_are_left_alone():
    assert decode.unfold("x " + "ab+/" * 12 + "cd-_" * 2).decoded == 0
    assert decode.unfold("hash " + "a" * 64 + " end").decoded == 0
    blob = b64(bytes(range(200, 256)) * 2)
    assert decode.unfold(f"x {blob} y") == decode.Unfolded(f"x {blob} y", 0, 0)


def test_decode_unfold_url_safe_bare_block():
    payload = base64.urlsafe_b64encode(("é>?" * 25).encode()).decode()
    assert "-" in payload or "_" in payload
    assert decode.unfold(f"x [{payload}] y") == decode.Unfolded(
        f"x [{'é>?' * 25}] y", 1, 0
    )


def test_decode_unfold_a_data_uri_payload_is_not_decoded_twice():
    result = decode.unfold(data_uri(ENC))
    assert result == decode.Unfolded(SENTENCE, 1, 0)


def test_decode_unfold_several_blocks_keep_the_text_between_them_in_order():
    raw = f"a {data_uri('SGVsbG8=')} b [{ENC}] c {data_uri('V29ybGQ=')} d"
    assert decode.unfold(raw) == decode.Unfolded(
        f"a Hello b [{SENTENCE}] c World d", 3, 0
    )


def test_decode_unfold_color_wraps_only_the_replacements():
    raw = f"a {data_uri('SGVsbG8=')} b [{ENC}] c"
    painted = decode.unfold(raw, color=True)
    assert painted.text == f"a {GREEN}Hello{RESET} b [{GREEN}{SENTENCE}{RESET}] c"
    assert painted.decoded == 2
    assert strip_ansi(painted.text) == decode.unfold(raw).text
    assert decode.unfold("nothing here", color=True).text == "nothing here"


def test_decode_banner_plain_art():
    lines = decode.format_banner(False).split("\n")
    assert lines == [
        "        .------.",
        "      .'        '.",
        "     /   decode   \\",
        "    |    (    )    |",
        "     \\   '----'   /",
        "      '.        .'",
        "        '------'",
        "page source, with non-image base64 written out as text",
    ]


def test_decode_banner_color_is_the_plain_banner_with_ansi_styling():
    colored = decode.format_banner(True)
    assert strip_ansi(colored) == decode.format_banner(False)
    assert colored.startswith("\x1b[1;96m") and colored.endswith("\x1b[0m")
    assert "\x1b[1;95mdecode\x1b[1;96m" in colored
    assert "\x1b[1;93m(" in colored and "\x1b[1;93m)" in colored
    assert all(line.endswith("\x1b[0m") for line in colored.split("\n"))


# ---- decode.fetch_page -----------------------------------------------------------------------------------


def test_decode_fetch_page_returns_body_type_final_url_truncation_and_status(ws, net):
    net.add(
        LOOP + "/p", 203, b"<p>hi</p>", {"content-type": "text/html; charset=utf-8"}
    )
    assert decode.fetch_page(net.http(), LOOP + "/p") == (
        b"<p>hi</p>",
        "text/html; charset=utf-8",
        LOOP + "/p",
        False,
        203,
    )
    assert [(hit.method, hit.url) for hit in net.hits] == [("GET", LOOP + "/p")]


def test_decode_fetch_page_follows_three_redirects_and_reports_the_last_url_and_status(
    ws, net
):
    net.redirect(LOOP + "/a", "/b", 301)
    net.redirect(LOOP + "/b", "/c", 307)
    net.redirect(LOOP + "/c", "/d", 308)
    net.add(LOOP + "/d", 200, b"end", {"content-type": "text/plain"})
    assert decode.fetch_page(net.http(), LOOP + "/a") == (
        b"end",
        "text/plain",
        LOOP + "/d",
        False,
        200,
    )


def test_decode_fetch_page_a_fourth_redirect_is_a_runtime_error(ws, net):
    redirect_chain(net, 5)
    with pytest.raises(RuntimeError, match=r"^Stopped after 3 redirects\.$"):
        decode.fetch_page(net.http(), LOOP + "/r0")
    assert net.urls() == [LOOP + f"/r{n}" for n in range(4)]


def test_decode_fetch_page_a_redirect_without_location_is_the_page(ws, net):
    net.add(LOOP + "/n", 302, b"moved body", {"content-type": "text/plain"})
    assert decode.fetch_page(net.http(), LOOP + "/n") == (
        b"moved body",
        "text/plain",
        LOOP + "/n",
        False,
        302,
    )
    net.add(LOOP + "/blank", 302, b"b", {"location": "   "})
    assert decode.fetch_page(net.http(), LOOP + "/blank") == (
        b"b",
        "",
        LOOP + "/blank",
        False,
        302,
    )
    assert net.urls() == [LOOP + "/n", LOOP + "/blank"]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_decode_fetch_page_follows_each_redirect_status(ws, net, status):
    net.redirect(LOOP + "/a", "/b", status)
    net.add(LOOP + "/b", 200, b"B", {"content-type": "text/plain"})
    assert decode.fetch_page(net.http(), LOOP + "/a") == (
        b"B",
        "text/plain",
        LOOP + "/b",
        False,
        200,
    )


@pytest.mark.parametrize("status", [200, 300, 304, 305, 404])
def test_decode_fetch_page_only_redirect_statuses_are_followed(ws, net, status):
    net.add(LOOP + "/a", status, b"body", {"location": "/b"})
    assert decode.fetch_page(net.http(), LOOP + "/a") == (
        b"body",
        "",
        LOOP + "/a",
        False,
        status,
    )
    assert net.urls() == [LOOP + "/a"]


def test_decode_fetch_page_truncation_flag_and_cap(ws, net):
    net.add(LOOP + "/exact", 200, b"a" * 1_000_000)
    net.add(LOOP + "/over", 200, b"b" * 1_000_001)
    net.add(LOOP + "/chunks", 200, [b"c" * 600_000, b"c" * 600_000])
    body, _, _, truncated, _ = decode.fetch_page(net.http(), LOOP + "/exact")
    assert len(body) == 1_000_000 and truncated is False
    body, _, _, truncated, _ = decode.fetch_page(net.http(), LOOP + "/over")
    assert len(body) == 1_000_000 and truncated is True
    body, _, _, truncated, _ = decode.fetch_page(net.http(), LOOP + "/chunks")
    assert len(body) == 1_000_000 and truncated is True


def test_decode_fetch_page_stops_at_scope_and_hostname_changes(ws, net):
    net.redirect(LOOP + "/off", OFF + "/x")
    with pytest.raises(decode.ScopeStop) as stop:
        decode.fetch_page(net.http(), LOOP + "/off")
    assert stop.value.host == "other.example"
    net.redirect(LOOP + "/other", "http://localhost:8080/x")
    with pytest.raises(decode.HostStop) as moved:
        decode.fetch_page(net.http(), LOOP + "/other")
    assert (moved.value.url, moved.value.origin) == (
        "http://localhost:8080/x",
        "127.0.0.1",
    )
    assert net.urls() == [LOOP + "/off", LOOP + "/other"]


def test_decode_fetch_page_scope_is_checked_before_any_request(ws, net):
    with pytest.raises(decode.ScopeStop) as stop:
        decode.fetch_page(net.http(), OFF + "/")
    assert stop.value.host == "other.example" and net.hits == []


def test_decode_fetch_page_lets_http_errors_through_unchanged(ws, net):
    error = httpx.ConnectError("boom")
    net.fail(LOOP + "/e", error)
    with pytest.raises(httpx.ConnectError) as caught:
        decode.fetch_page(net.http(), LOOP + "/e")
    assert caught.value is error


# ---- decode.main -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv", [["--timeout", "0"], ["--timeout", "-1"], ["--min", "15"], ["--min", "0"]]
)
def test_decode_numeric_argument_errors(ws, net, cli, argv):
    result = cli(decode.main, ws.file("p.txt", "x"), *argv)
    assert (result.rc, result.out) == (2, "")
    assert (
        result.err == "Timeout must be greater than 0, and --min must be 16 or more.\n"
    )


def test_decode_local_file_is_decoded_without_any_network(ws, net, cli):
    path = ws.file(
        "page.html", f'<img src="{data_uri("SGVsbG8=")}"> and {data_uri("V29ybGQ=")}\n'
    )
    result = cli(decode.main, path, "--min", "16")
    assert (result.rc, result.out) == (0, '<img src="Hello"> and World\n')
    assert result.err == "decoded 2 block(s)\n"
    assert net.client_calls == [] and net.hits == []


def test_decode_output_always_ends_with_exactly_one_newline_added_when_missing(
    ws, net, cli
):
    assert cli(decode.main, ws.file("a.txt", "no newline")).out == "no newline\n"
    assert cli(decode.main, ws.file("b.txt", "has newline\n")).out == "has newline\n"
    assert (
        cli(decode.main, ws.file("c.txt", "two newlines\n\n")).out == "two newlines\n\n"
    )
    assert cli(decode.main, ws.file("d.txt", "")).out == "\n"


def test_decode_summary_mentions_images_only_when_there_are_some(ws, net, cli):
    png = data_uri(b64(IMAGE_BLOBS["png"]), "application/octet-stream")
    only_text = cli(decode.main, ws.file("t.txt", data_uri("SGVsbG8=")))
    assert only_text.err == "decoded 1 block(s)\n"
    mixed = cli(
        decode.main,
        ws.file("m.txt", f"{data_uri('SGVsbG8=')} {png} data:image/gif;base64,R0lG"),
    )
    assert mixed.err == "decoded 1 block(s), left 2 image block(s) encoded\n"
    none = cli(decode.main, ws.file("n.txt", "nothing"))
    assert none.err == "decoded 0 block(s)\n"


def test_decode_local_file_ignores_charset_and_replaces_invalid_utf8(ws, net, cli):
    result = cli(decode.main, ws.file("b.txt", b"caf\xe9 ok", binary=True))
    assert result.out == "caf� ok\n"


def test_decode_local_file_is_truncated_at_one_million_bytes(ws, net, cli):
    over = cli(decode.main, ws.file("big.txt", b"a" * 1_000_001, binary=True))
    assert over.out == "a" * 1_000_000 + "\n"
    assert over.err == "The page was truncated.\ndecoded 0 block(s)\n"
    exact = cli(decode.main, ws.file("exact.txt", b"a" * 1_000_000, binary=True))
    assert exact.err == "decoded 0 block(s)\n"


@pytest.mark.parametrize(
    "target",
    [
        "ftp://127.0.0.1/x",
        "not-a-file-or-url",
        "127.0.0.1:8080/a",
        "http://",
        "file:///nope",
    ],
)
def test_decode_target_must_be_an_http_url_or_an_existing_file(ws, net, cli, target):
    result = cli(decode.main, target)
    assert (result.rc, result.out, result.err) == (
        2,
        "",
        "Give an http or https URL, or a file that exists.\n",
    )


def test_decode_url_outside_scope_is_refused_before_any_client_is_built(ws, net, cli):
    from bughunt.core.workspace import explain_block

    result = cli(decode.main, OFF + "/")
    assert (result.rc, result.out, result.err) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )
    assert net.client_calls == [] and net.hits == []


def test_decode_fetches_prints_decoded_text_and_reports_status_and_url(ws, net, cli):
    net.add(
        LOOP + "/p",
        200,
        f'<a href="{data_uri("SGVsbG8=")}">x</a>',
        {"content-type": "text/html"},
    )
    result = cli(decode.main, LOOP + "/p")
    assert (result.rc, result.out) == (0, '<a href="Hello">x</a>\n')
    assert result.err == f"200 {LOOP}/p\ndecoded 1 block(s)\n"


def test_decode_prints_non_200_pages_too_and_follows_redirects_for_the_status_line(
    ws, net, cli
):
    net.add(LOOP + "/gone", 404, "missing")
    assert (
        cli(decode.main, LOOP + "/gone").err == f"404 {LOOP}/gone\ndecoded 0 block(s)\n"
    )
    net.redirect(LOOP + "/old", "/new", 301)
    net.add(LOOP + "/new", 200, "fresh")
    moved = cli(decode.main, LOOP + "/old")
    assert (
        moved.out == "fresh\n" and moved.err == f"200 {LOOP}/new\ndecoded 0 block(s)\n"
    )


def test_decode_min_option_reaches_the_unfolder(ws, net, cli):
    thirty = b64("0123456789abcdefghijklmnopqrst")
    net.add(LOOP + "/p", 200, f"x {thirty} y")
    assert cli(decode.main, LOOP + "/p").out == f"x {thirty} y\n"
    assert (
        cli(decode.main, LOOP + "/p", "--min", "16").out
        == "x 0123456789abcdefghijklmnopqrst y\n"
    )


@pytest.mark.parametrize(
    "content_type,body,expected",
    [
        ("text/html; charset=iso-8859-1", "café".encode("latin-1"), "café"),
        ("text/html; CHARSET=ISO-8859-1", "café".encode("latin-1"), "café"),
        ('text/html; charset="utf-16"', "café".encode("utf-16"), "café"),
        ("text/html; charset='utf-8'", "café".encode("utf-8"), "café"),
        ("text/html; charset=utf-8; boundary=x", "café".encode("utf-8"), "café"),
        ("text/html", "café".encode("utf-8"), "café"),
        ("", "café".encode("utf-8"), "café"),
        ("text/html; charset=no-such-codec", "café".encode("utf-8"), "café"),
        ("text/html; charset=rot13", "café".encode("utf-8"), "café"),
        ("text/html; charset=base64", "café".encode("utf-8"), "café"),
        ("text/html; charset=no-such-codec", b"bad \xff byte", "bad � byte"),
        ("text/html; charset=utf-8", b"bad \xff byte", "bad � byte"),
        ("text/html; charset=ascii", b"bad \xff byte", "bad � byte"),
    ],
)
def test_decode_remote_body_uses_the_declared_charset_with_a_utf8_fallback(
    ws, net, cli, content_type, body, expected
):
    net.add(
        LOOP + "/p", 200, body, {"content-type": content_type} if content_type else None
    )
    assert cli(decode.main, LOOP + "/p").out == expected + "\n"


def test_decode_remote_page_truncation_notice(ws, net, cli):
    net.add(LOOP + "/big", 200, b"a" * 1_000_001)
    result = cli(decode.main, LOOP + "/big")
    assert result.out == "a" * 1_000_000 + "\n"
    assert (
        result.err == f"200 {LOOP}/big\nThe page was truncated.\ndecoded 0 block(s)\n"
    )


def test_decode_stops_quietly_on_a_hostname_change_and_loudly_on_scope(ws, net, cli):
    from bughunt.core.workspace import explain_block

    net.redirect(LOOP + "/x", "http://localhost:8080/y")
    moved = cli(decode.main, LOOP + "/x")
    assert (moved.rc, moved.out, moved.err) == (
        0,
        "",
        "Stopped. http://localhost:8080/y leaves 127.0.0.1.\n",
    )
    net.redirect(LOOP + "/z", OFF + "/y")
    refused = cli(decode.main, LOOP + "/z")
    assert (refused.rc, refused.out, refused.err) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )


def test_decode_redirect_budget_is_three(ws, net, cli):
    redirect_chain(net, 3)
    ok = cli(decode.main, LOOP + "/r0")
    assert ok.rc == 0 and ok.out == "<p>done</p>\n"
    redirect_chain(net, 4)
    too_many = cli(decode.main, LOOP + "/r0")
    assert (too_many.rc, too_many.out, too_many.err) == (
        1,
        "",
        "Stopped after 3 redirects.\n",
    )


def test_decode_network_failures_exit_one_and_name_the_original_target(ws, net, cli):
    net.redirect(LOOP + "/a", "/b")
    net.fail(LOOP + "/b", httpx.ConnectError("boom"))
    result = cli(decode.main, LOOP + "/a")
    assert (result.rc, result.out, result.err) == (
        1,
        "",
        f"Could not fetch {LOOP}/a: ConnectError\n",
    )


def test_decode_policy_block_while_building_the_client_is_a_fetch_failure(
    ws, monkeypatch, cli
):
    def refuse(**_kwargs):
        raise egress.PolicyBlocked("policy-missing-or-invalid; no outbound action ran")

    monkeypatch.setattr(egress, "client", refuse)
    result = cli(decode.main, LOOP + "/a")
    assert (result.rc, result.out, result.err) == (
        1,
        "",
        f"Could not fetch {LOOP}/a: PolicyBlocked\n",
    )


def test_decode_builds_the_guarded_client_like_redirect_does(ws, net, cli):
    net.add(LOOP + "/p", 200, "x")
    cli(
        decode.main,
        LOOP + "/p",
        "--timeout",
        "4",
        "--cookie",
        "c=1",
        "--authorization",
        "Bearer t",
    )
    assert net.client_calls == [
        {
            "operation": "manual",
            "timeout": 4.0,
            "verify": True,
            "trust_env": False,
            "follow_redirects": False,
            "headers": {
                "User-Agent": f"Bughunt/{VERSION}",
                "Accept-Encoding": "identity",
                "Cookie": "c=1",
                "Authorization": "Bearer t",
            },
        }
    ]
    cli(decode.main, LOOP + "/p", "--insecure")
    assert net.client_calls[-1]["verify"] is False


def test_decode_saved_session_is_used_and_flags_replace_it(ws, net, cli):
    net.add(LOOP + "/p", 200, "x")
    ws.session(cookie="saved=1")
    cli(decode.main, LOOP + "/p")
    assert net.hits[-1].headers["cookie"] == "saved=1"
    cli(decode.main, LOOP + "/p", "--cookie", "")
    assert "cookie" not in net.hits[-1].headers


def test_decode_color_follows_the_terminal_and_the_environment(ws, net, tty):
    streams = tty()
    assert decode.main([ws.file("p.txt", data_uri("SGVsbG8="))]) == 0
    assert streams[0].getvalue() == f"{GREEN}Hello{RESET}\n"
    assert streams[1].getvalue().endswith(f"{GREEN}decoded 1 block(s){RESET}\n")


@pytest.mark.parametrize("setup", ["no-color", "dumb", "no-term"])
def test_decode_color_is_off_for_no_color_dumb_or_missing_term(
    ws, net, tty, monkeypatch, setup
):
    streams = tty()
    if setup == "no-color":
        monkeypatch.setenv("NO_COLOR", "1")
    elif setup == "dumb":
        monkeypatch.setenv("TERM", "dumb")
    else:
        monkeypatch.delenv("TERM")
    assert decode.main([ws.file("p.txt", data_uri("SGVsbG8="))]) == 0
    assert streams[0].getvalue() == "Hello\n"
    assert ESC not in streams[1].getvalue()


def test_decode_plain_flag_drops_the_banner_and_the_text_color_but_not_the_summary_color(
    ws, net, tty
):
    streams = tty()
    assert decode.main([ws.file("p.txt", data_uri("SGVsbG8=")), "--plain"]) == 0
    assert streams[0].getvalue() == "Hello\n"
    assert streams[1].getvalue() == f"{GREEN}decoded 1 block(s){RESET}\n"


def test_decode_banner_goes_to_a_terminal_stderr_only_unless_plain(
    ws, net, tty, monkeypatch
):
    streams = tty()
    path = ws.file("p.txt", "x")
    decode.main([path])
    assert streams[1].getvalue().startswith(decode.format_banner(True) + "\n\n")
    streams[1].seek(0)
    streams[1].truncate()
    decode.main([path, "--plain"])
    assert decode.format_banner(False).split("\n")[0] not in strip_ansi(
        streams[1].getvalue()
    )
    streams[1].seek(0)
    streams[1].truncate()
    monkeypatch.setenv("NO_COLOR", "1")
    decode.main([path])
    assert (
        streams[1].getvalue()
        == decode.format_banner(False) + "\n\ndecoded 0 block(s)\n"
    )


def test_decode_target_is_trimmed(ws, net, cli):
    assert cli(decode.main, f"  {ws.file('p.txt', 'plain')}  ").out == "plain\n"
    net.add(LOOP + "/p", 200, "web")
    assert cli(decode.main, f"  {LOOP}/p  ").out == "web\n"


def test_decode_unreadable_file_exits_one(ws, net, cli, monkeypatch):
    path = ws.file("p.txt", "x")

    def refuse(_self):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_bytes", refuse)
    result = cli(decode.main, path)
    assert (result.rc, result.out, result.err) == (
        1,
        "",
        f"Could not read {path}: PermissionError\n",
    )


def test_decode_plain_flag_also_skips_the_banner_for_urls(ws, net, tty):
    net.add(LOOP + "/p", 200, "x")
    streams = tty()
    assert decode.main([LOOP + "/p", "--plain"]) == 0
    assert "page source" not in strip_ansi(streams[1].getvalue())
    assert decode.main([LOOP + "/p"]) == 0
    assert streams[1].getvalue().count(decode.format_banner(True)) == 1


def test_decode_text_color_follows_stdout_while_the_summary_color_follows_stderr(
    ws, net, tty
):
    path = ws.file("p.txt", data_uri("SGVsbG8="))
    streams = tty(err=False)
    assert decode.main([path]) == 0
    assert (
        streams[0].getvalue() == f"{GREEN}Hello{RESET}\n"
        and ESC not in streams[1].getvalue()
    )
    streams = tty(out=False)
    assert decode.main([path]) == 0
    assert streams[0].getvalue() == "Hello\n"
    assert streams[1].getvalue().endswith(f"{GREEN}decoded 1 block(s){RESET}\n")


class FlushSpy(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flush_calls = 0

    def flush(self):
        self.flush_calls += 1
        super().flush()


def test_decode_flushes_stdout_when_done(ws, net, monkeypatch):
    spy = FlushSpy()
    monkeypatch.setattr(sys, "stdout", spy)
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    assert decode.main([ws.file("p.txt", "x")]) == 0
    assert spy.flush_calls >= 1 and spy.getvalue() == "x\n"


def test_decode_banner_is_not_printed_when_stderr_is_not_a_terminal(ws, net, cli):
    result = cli(decode.main, ws.file("p.txt", "x"))
    assert "page source, with non-image" not in result.err


# =========================================================================================================
# silk.py
# =========================================================================================================


def crawl(net, start=LOOP + "/", *, depth=2, limit=40):
    return silk.crawl(
        net.http(), start, silk.origin_key(start), depth=depth, limit=limit
    )


def listed(result):
    return [url for url, _source in result.endpoints]


def build_site(net):
    net.html(
        LOOP + "/",
        '<a href="/a">a</a><a href="/b.png">b</a><a href="https://other.example/x">o</a>'
        '<form action="/f"></form><script src="/s.js"></script><link rel="stylesheet" href="/c.css">',
    )
    net.html(LOOP + "/a", '<a href="/deep">d</a>')
    net.html(LOOP + "/deep", '<a href="/deeper">d</a>')
    net.add(
        LOOP + "/s.js",
        200,
        'fetch("/api/x"); var u="https://e.com/q?z=1"',
        {"content-type": "application/javascript"},
    )
    net.add(
        LOOP + "/c.css",
        200,
        "a{background:url(/img/bg.png)}",
        {"content-type": "text/css"},
    )
    net.add(
        LOOP + "/robots.txt",
        200,
        "User-agent: *\nDisallow: /secret/\nAllow: /pub\nSitemap: "
        + LOOP
        + "/map.xml\n",
        {"content-type": "text/plain"},
    )
    net.add(
        LOOP + "/map.xml",
        200,
        urlset(LOOP + "/m1", LOOP + "/m2"),
        {"content-type": "application/xml"},
    )
    net.html(LOOP + "/m1", "<html>m1</html>")


SITE_ENDPOINTS = [
    ("/", "start"),
    ("/a", "link"),
    ("/b.png", "asset"),
    ("/f", "form"),
    ("/s.js", "script"),
    ("/c.css", "style"),
    ("/robots.txt", "robots"),
    ("/secret/", "robots"),
    ("/pub", "robots"),
    ("/deep", "link"),
    ("/api/x", "script"),
    ("/img/bg.png", "asset"),
    ("/map.xml", "sitemap"),
    ("/m1", "sitemap"),
    ("/m2", "sitemap"),
    ("/deeper", "link"),
]
SITE_FETCHES = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/a",
    "/f",
    "/s.js",
    "/c.css",
    "/map.xml",
    "/deep",
    "/api/x",
    "/m1",
    "/m2",
]


def test_silk_data_contracts():
    assert [f.name for f in fields(silk.Response)] == [
        "status",
        "content_type",
        "body",
        "url",
        "left",
    ]
    assert [f.name for f in fields(silk.Job)] == ["url", "depth", "source", "kind"]
    assert [f.name for f in fields(silk.Result)] == [
        "endpoints",
        "fetched",
        "off_host",
        "left_server",
        "stopped",
        "robots_missing",
        "sitemap_missing",
    ]
    blank = silk.Result()
    assert (blank.endpoints, blank.fetched, blank.off_host, blank.left_server) == (
        [],
        0,
        0,
        0,
    )
    assert (blank.stopped, blank.robots_missing, blank.sitemap_missing) == (
        "",
        False,
        False,
    )
    assert blank.endpoints is not silk.Result().endpoints
    assert silk.Response(200, "t", "b", "u", left=False) == silk.Response(
        200, "t", "b", "u", False
    )
    assert silk.Job("u", 1, "link", "page").kind == "page"
    scope, fetch = silk.ScopeError("evil.example"), silk.FetchError("x")
    assert (
        scope.host == "evil.example"
        and str(scope) == "evil.example"
        and isinstance(fetch, Exception)
    )


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://Example.COM:80/A?b#c", "http://example.com/A?b"),
        ("HTTP://H/", "http://h/"),
        ("https://h:443", "https://h/"),
        ("https://h.:443/", "https://h/"),
        ("http://h:8080", "http://h:8080/"),
        ("http://h:443/", "http://h:443/"),
        ("https://h:80/", "https://h:80/"),
        ("http://u:p@h:8080/x", "http://h:8080/x"),
        ("http://h?x=1", "http://h/?x=1"),
        ("http://h/a%20b/../c", "http://h/a%20b/../c"),
        ("http://h/a b", "http://h/a b"),
        ("http://[::1]:8080/x", "http://[::1]:8080/x"),
        ("http://[::1]/x", "http://[::1]/x"),
        ("  http://h/ ", "http://h/"),
        ("http://h/?a=1&b=2#frag", "http://h/?a=1&b=2"),
        ("ftp://h/", None),
        ("/relative", None),
        ("http://", None),
        ("", None),
        ("mailto:a@b.example", None),
        ("javascript:alert(1)", None),
        ("h.example", None),
        ("//h.example/x", None),
    ],
)
def test_silk_canonicalize(url, expected):
    assert silk.canonicalize(url) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://H:80/x", ("http", "h", 80)),
        ("HTTP://H", ("http", "h", 80)),
        ("https://h/", ("https", "h", 443)),
        ("https://h:8443/", ("https", "h", 8443)),
        ("http://h.:8080", ("http", "h", 8080)),
        ("http://u:p@h/x", ("http", "h", 80)),
        ("http://[::1]:9/x", ("http", "::1", 9)),
        (" http://h/ ", ("http", "h", 80)),
        ("ftp://h", None),
        ("", None),
        ("http://", None),
        ("/x", None),
    ],
)
def test_silk_origin_key(url, expected):
    assert silk.origin_key(url) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://h:8080/x?y#z", "http://h:8080"),
        ("https://H/x", "https://H"),
        ("http://u:p@h/x", "http://u:p@h"),
        ("http://[::1]:1/", "http://[::1]:1"),
        ("ftp://h", None),
        ("/x", None),
        ("http://", None),
        ("", None),
    ],
)
def test_silk_origin_of_keeps_the_netloc_verbatim(url, expected):
    assert silk.origin_of(url) == expected


def refs(html):
    return silk.extract_html(html)[1]


@pytest.mark.parametrize(
    "html,expected",
    [
        ('<a href=" /a ">x</a>', [("/a", "link")]),
        ("<a>x</a><a href=''>y</a><a href='  '>z</a>", []),
        ('<A HREF="/up">x</A>', [("/up", "link")]),
        ('<a href="/p?a=1&amp;b=2">x</a>', [("/p?a=1&b=2", "link")]),
        ('<area href="/ar">', [("/ar", "link")]),
        (
            '<form action="/f"></form><form></form><form action=" "></form>',
            [("/f", "form")],
        ),
        (
            '<button formaction="/fa"></button><input formaction="/fi"><input name="x"><button>z</button>',
            [("/fa", "form"), ("/fi", "form")],
        ),
        ('<script src="/j.js"></script>', [("/j.js", "script")]),
        ('<script src="/j.js"/>text "/not/seen"', [("/j.js", "script")]),
        (
            "<script>var u=\"/inl/x\"; fetch('https://e.com/p?q=1')</script>",
            [("/inl/x", "script"), ("https://e.com/p?q=1", "script")],
        ),
        (
            '<script src="/a.js">var x="/b"</script>',
            [("/a.js", "script"), ("/b", "script")],
        ),
        (
            '<script>if (a < b && c > d) { x = "/lt/ok"; }</script>',
            [("/lt/ok", "script")],
        ),
        ('<link rel="stylesheet" href="/s.css">', [("/s.css", "style")]),
        ('<link rel="Alternate StyleSheet" href="/alt.css">', [("/alt.css", "style")]),
        (
            '<link rel="icon" href="/i.ico"><link href="/norel"><link rel="stylesheet">',
            [("/i.ico", "link"), ("/norel", "link")],
        ),
        (
            '<iframe src="/if"></iframe><frame src="/fr">',
            [("/if", "link"), ("/fr", "link")],
        ),
        (
            '<img src="/p.png"><source src="/so"><video src="/v.mp4"></video><audio src="/au"></audio><track src="/tr">',
            [
                ("/p.png", "asset"),
                ("/so", "asset"),
                ("/v.mp4", "asset"),
                ("/au", "asset"),
                ("/tr", "asset"),
            ],
        ),
        (
            '<img srcset="/a.png 1x" data-src="/b.png"><object data="/o"></object><embed src="/e">',
            [],
        ),
        ('<meta http-equiv="Refresh" content="0; URL=/m">', [("/m", "link")]),
        ('<meta http-equiv="refresh" content="5;url=\'/m2\'">', [("/m2", "link")]),
        (
            '<meta http-equiv="REFRESH" content="0 ; url = http://x.example/y?z=1">',
            [("http://x.example/y?z=1", "link")],
        ),
        (
            '<meta http-equiv="refresh" content="30"><meta http-equiv="content-type" content="url=/no"><meta name="x" content="url=/no">',
            [],
        ),
        (
            '<style>@import url("/c/y.css"); a{background:url(/img/x.png)}</style>',
            [("/c/y.css", "style"), ("/img/x.png", "style")],
        ),
        ("<style/>", []),
        ("<style/>a{background:url(/leaked)}</style>", []),
        ('<script src="/j.js"/><p>x="/leaked"</p></script>', [("/j.js", "script")]),
        ('<script>var a="/s1"</script><p>"/not"</p></script>', [("/s1", "script")]),
        ('<a href="/lost">x</a><script>var u="/lost-too"', [("/lost", "link")]),
        (
            '<a href="/1">1</a><img src="/2.png"><script src="/3.js"></script><a href="/4">4</a>',
            [("/1", "link"), ("/2.png", "asset"), ("/3.js", "script"), ("/4", "link")],
        ),
        ("", []),
        ("plain text with /slash/paths and no markup", []),
    ],
)
def test_silk_extract_html_references_and_their_sources(html, expected):
    assert refs(html) == expected


def test_silk_extract_html_base_href():
    assert silk.extract_html('<base href=" /b/ "><a href="/a">x</a>') == (
        "/b/",
        [("/a", "link")],
    )
    assert silk.extract_html('<base href="/one/"><base href="/two/">')[0] == "/one/"
    assert silk.extract_html('<base href=""><base href="/two/">')[0] == "/two/"
    assert (
        silk.extract_html("<base>")[0] == "" and silk.extract_html("no base")[0] == ""
    )
    assert silk.extract_html("<a href='/x'>")[1] == [("/x", "link")]


def test_silk_extract_html_keeps_at_most_two_hundred_references():
    many = "".join(f'<a href="/p{n}">x</a>' for n in range(250))
    found = refs(many)
    assert (
        len(found) == 200
        and found[0] == ("/p0", "link")
        and found[-1] == ("/p199", "link")
    )
    inline = "<script>" + "".join(f'x="/s{n}";' for n in range(250)) + "</script>"
    assert len(refs(inline)) == 200


@pytest.mark.parametrize(
    "code,expected",
    [
        ('var a="/api/v1/x"', ["/api/v1/x"]),
        ("var a='/single/quote'", ["/single/quote"]),
        ("\"/mixed'", ["/mixed"]),
        ('b="/api?x=1"', []),
        ('b="/a=b" c="/a&b" d="/a:b" e="/a#b"', []),
        ('b="/ok._~%+-/path"', ["/ok._~%+-/path"]),
        ('d="//cdn.example/x"', []),
        ('d="/"', []),
        ('d="/a b"', []),
        ('d="relative/path"', []),
        ('c="https://e.com/p?q=1&r=2"', ["https://e.com/p?q=1&r=2"]),
        ('c="http://e.com"', ["http://e.com"]),
        ('c="HTTP://e.com/x"', []),
        ('c="ftp://e.com/x"', []),
        ('e = url( "/img/a.png" )', ["/img/a.png"]),
        (
            "f=url(/z/y.css) g=url('https://e.com/i.png')",
            ["https://e.com/i.png", "/z/y.css"],
        ),
        ("f=URL(/up/y.css)", ["/up/y.css"]),
        ('x="/dup"; y="/dup"; z=url(/dup)', ["/dup"]),
        ('url(/css/first) then "/quoted/second"', ["/quoted/second", "/css/first"]),
        ("", []),
    ],
)
def test_silk_extract_code(code, expected):
    assert silk.extract_code(code) == expected


def test_silk_extract_code_length_limits_and_caps():
    assert silk.extract_code('"' + "/" + "a" * 200 + '"') == ["/" + "a" * 200]
    assert silk.extract_code('"' + "/" + "a" * 201 + '"') == []
    assert silk.extract_code('"http://' + "a" * 500 + '"') == ["http://" + "a" * 500]
    assert silk.extract_code('"http://' + "a" * 501 + '"') == []
    assert silk.extract_code("url(/" + "a" * 200 + ")") == ["/" + "a" * 200]
    assert silk.extract_code("url(/" + "a" * 201 + ")") == []
    assert silk.extract_code("url(http://" + "a" * 500 + ")") == ["http://" + "a" * 500]
    assert silk.extract_code("url(http://" + "a" * 501 + ")") == []
    many = "".join(f'x="/p{n}";' for n in range(250))
    found = silk.extract_code(many)
    assert len(found) == 200 and found[-1] == "/p199"
    assert silk.extract_code("x" * 200_000 + ' "/beyond"') == []
    assert silk.extract_code("x" * 199_980 + ' "/inside"') == ["/inside"]
    assert silk.extract_code("x" * 199_996 + '"/b"') == ["/b"]
    assert silk.extract_code("x" * 199_997 + '"/b"') == []


ROBOTS_TEXT = "User-agent: *\nDisallow: /a*$\nDisallow: /*\nAllow: /b/\nDisallow:\nDisallow: *\nSitemap: /s.xml\nSitemap:\nCrawl-delay: 3\nDisallow: /c # comment\n"


def test_silk_parse_robots():
    assert silk.parse_robots(ROBOTS_TEXT) == (["/a", "/", "/b/", "/c"], ["/s.xml"])
    assert silk.parse_robots("") == ([], [])
    assert silk.parse_robots(
        "Disallow: /a\r\nSITEMAP: https://o.example/s.xml#frag\r\n# Sitemap: /no\r\n"
    ) == (["/a"], ["https://o.example/s.xml"])
    assert silk.parse_robots(
        "Allow:\nDisallow:\nSitemap:   \nnonsense\nDisallow /x"
    ) == ([], [])
    assert silk.parse_robots("Disallow: /x:y") == (["/x:y"], [])
    assert silk.parse_robots(
        "Disallow: /a$ \nDisallow: /b* \nDisallow: $\nDisallow: /*.php$"
    ) == (["/a", "/b", "/*.php"], [])


@pytest.mark.parametrize(
    "text,expected",
    [
        ("<loc>http://a/</loc><LOC> http://b/ </LOC>", ["http://a/", "http://b/"]),
        ("<loc>http://a/?x=1&amp;y=2</loc>", ["http://a/?x=1&y=2"]),
        ("<loc></loc><loc>  </loc>", []),
        ("<loc><![CDATA[http://a/]]></loc>", []),
        ("", []),
    ],
)
def test_silk_sitemap_locs(text, expected):
    assert silk.sitemap_locs(text) == expected


SILK_ART = [
    "         \\    ^    /",
    "       .  \\   |   /  .",
    "     (     \\  |  /     )",
    "      ' .   --+--   . '",
    "         /    |    \\",
    "        /     |     \\",
    "           silk",
    "spins pages, robots.txt, and sitemaps into endpoints",
]


def test_silk_banner_plain_art():
    assert silk.format_banner(False).split("\n") == SILK_ART


def test_silk_banner_color_is_the_plain_banner_with_ansi_styling():
    colored = silk.format_banner(True)
    lines = colored.split("\n")
    assert strip_ansi(colored) == "\n".join(SILK_ART)
    assert lines[2].startswith("\x1b[1;96m") and lines[2].endswith("\x1b[0m")
    assert "\x1b[1;93m(" in lines[2] and "\x1b[1;93m)" in lines[2]
    assert lines[6] == "\x1b[1;96m           \x1b[1;95msilk\x1b[1;96m\x1b[0m"
    assert (
        lines[7]
        == "\x1b[2;96mspins pages, robots.txt, and sitemaps into endpoints\x1b[0m"
    )


@pytest.mark.parametrize(
    "source,code",
    [
        ("start", "\x1b[1;95m"),
        ("link", "\x1b[1;96m"),
        ("form", "\x1b[1;93m"),
        ("script", "\x1b[1;94m"),
        ("style", "\x1b[1;92m"),
        ("robots", "\x1b[1;32m"),
        ("sitemap", "\x1b[1;33m"),
        ("asset", "\x1b[2m"),
        ("mystery", "\x1b[1;96m"),
    ],
)
def test_silk_format_row(source, code):
    assert silk.format_row(source, "http://h/x", False) == "http://h/x"
    assert (
        silk.format_row(source, "http://h/x", True)
        == f"  {code}{source:<8}\x1b[0m \x1b[1;97mhttp://h/x\x1b[0m"
    )


# ---- silk.fetch_page -------------------------------------------------------------------------------------

ORIGIN = silk.origin_key(LOOP + "/")


def test_silk_fetch_page_returns_a_response_record(ws, net):
    net.add(LOOP + "/p", 200, "<p>x</p>", {"content-type": "text/html; charset=utf-8"})
    assert silk.fetch_page(net.http(), LOOP + "/p", ORIGIN) == silk.Response(
        200, "text/html; charset=utf-8", "<p>x</p>", LOOP + "/p", False
    )
    net.add(LOOP + "/bare", 200, "x")
    assert silk.fetch_page(net.http(), LOOP + "/bare", ORIGIN).content_type == ""


@pytest.mark.parametrize("status", [201, 204, 301, 404, 500])
def test_silk_fetch_page_does_not_raise_on_status(ws, net, status):
    net.add(LOOP + "/p", status, "body")
    result = silk.fetch_page(net.http(), LOOP + "/p", ORIGIN)
    assert result.status == status and result.left is False


def test_silk_fetch_page_follows_in_origin_redirects_up_to_three(ws, net):
    net.redirect(LOOP + "/a", "/b", 301)
    net.redirect(LOOP + "/b", LOOP + "/c", 307)
    net.redirect(LOOP + "/c", "/d", 308)
    net.add(LOOP + "/d", 200, "end", {"content-type": "text/plain"})
    assert silk.fetch_page(net.http(), LOOP + "/a", ORIGIN) == silk.Response(
        200, "text/plain", "end", LOOP + "/d", False
    )


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_silk_fetch_page_follows_each_redirect_status(ws, net, status):
    net.redirect(LOOP + "/a", "/b", status)
    net.add(LOOP + "/b", 200, "B")
    assert silk.fetch_page(net.http(), LOOP + "/a", ORIGIN) == silk.Response(
        200, "", "B", LOOP + "/b", False
    )


@pytest.mark.parametrize("status", [300, 304, 305])
def test_silk_fetch_page_does_not_follow_other_3xx(ws, net, status):
    net.add(LOOP + "/a", status, "body", {"location": "/b"})
    assert silk.fetch_page(net.http(), LOOP + "/a", ORIGIN) == silk.Response(
        status, "", "body", LOOP + "/a", False
    )
    assert net.urls() == [LOOP + "/a"]


def test_silk_fetch_page_correct_a_fourth_redirect_is_a_too_many_redirects_error(
    ws, net
):
    redirect_chain(net, 5)
    raised = None
    try:
        silk.fetch_page(net.http(), LOOP + "/r0", ORIGIN)
    except silk.FetchError as exc:
        raised = exc
    assert raised is not None and "too many redirects" in str(raised)


@pytest.mark.parametrize(
    "target",
    [
        OFF + "/x",
        "http://localhost:8080/x",
        "http://127.0.0.1:9999/x",
        "https://127.0.0.1:8080/x",
    ],
)
def test_silk_fetch_page_a_redirect_that_leaves_the_origin_is_reported_not_followed(
    ws, net, target
):
    net.add(
        LOOP + "/go", 302, "ignored", {"location": target, "content-type": "text/html"}
    )
    assert silk.fetch_page(net.http(), LOOP + "/go", ORIGIN) == silk.Response(
        302, "text/html", "", LOOP + "/go", True
    )
    assert net.urls() == [LOOP + "/go"]


def test_silk_fetch_page_a_later_hop_that_leaves_the_origin_reports_the_hop_that_redirected(
    ws, net
):
    net.redirect(LOOP + "/a", "/b")
    net.redirect(LOOP + "/b", OFF + "/x")
    assert silk.fetch_page(net.http(), LOOP + "/a", ORIGIN) == silk.Response(
        302, "", "", LOOP + "/b", True
    )


def test_silk_fetch_page_redirect_without_a_location_is_an_empty_response(ws, net):
    net.add(LOOP + "/n", 302, "moved", {"content-type": "text/plain"})
    net.add(LOOP + "/b", 301, "moved", {"location": "  "})
    assert silk.fetch_page(net.http(), LOOP + "/n", ORIGIN) == silk.Response(
        302, "text/plain", "", LOOP + "/n", False
    )
    assert silk.fetch_page(net.http(), LOOP + "/b", ORIGIN).body == ""


def test_silk_fetch_page_url_outside_the_origin_is_reported_without_a_request(ws, net):
    assert silk.fetch_page(
        net.http(), "http://localhost:8080/x", ORIGIN
    ) == silk.Response(0, "", "", "http://localhost:8080/x", True)
    assert net.hits == []


def test_silk_fetch_page_out_of_scope_origin_raises_scope_error(ws, net):
    with pytest.raises(silk.ScopeError) as stop:
        silk.fetch_page(net.http(), OFF + "/", silk.origin_key(OFF + "/"))
    assert stop.value.host == "other.example" and net.hits == []


@pytest.mark.parametrize(
    "error,name",
    [
        (httpx.ConnectError("boom"), "ConnectError"),
        (egress.PolicyBlocked("blocked"), "PolicyBlocked"),
    ],
)
def test_silk_fetch_page_errors_name_the_class_and_the_failing_hop(
    ws, net, error, name
):
    net.redirect(LOOP + "/a", "/b")
    net.fail(LOOP + "/b", error)
    with pytest.raises(silk.FetchError) as caught:
        silk.fetch_page(net.http(), LOOP + "/a", ORIGIN)
    assert (
        str(caught.value) == f"Could not fetch {LOOP}/b: {name}"
        and caught.value.__cause__ is error
    )


def test_silk_fetch_page_decodes_utf8_with_replacement_and_caps_at_one_million_bytes(
    ws, net
):
    net.add(LOOP + "/bad", 200, b"ok \xff end")
    net.add(LOOP + "/huge", 200, [b"a" * 700_000, b"a" * 700_000])
    assert silk.fetch_page(net.http(), LOOP + "/bad", ORIGIN).body == "ok � end"
    assert silk.fetch_page(net.http(), LOOP + "/huge", ORIGIN).body == "a" * 1_000_000


# ---- silk.crawl ------------------------------------------------------------------------------------------


def test_silk_crawl_golden_site_endpoints_sources_order_and_requests(ws, net):
    build_site(net)
    result = crawl(net)
    assert result.endpoints == [
        (LOOP + path, source) for path, source in SITE_ENDPOINTS
    ]
    assert net.urls() == [LOOP + path for path in SITE_FETCHES]
    assert (result.fetched, result.off_host, result.left_server, result.stopped) == (
        12,
        2,
        0,
        "",
    )
    assert (result.robots_missing, result.sitemap_missing) == (False, False)
    assert {hit.method for hit in net.hits} == {"GET"}


def test_silk_crawl_requests_the_start_page_then_robots_then_sitemap(ws, net):
    net.html(LOOP + "/", "<p>no links</p>")
    result = crawl(net)
    assert net.urls() == [LOOP + "/", LOOP + "/robots.txt", LOOP + "/sitemap.xml"]
    assert result.endpoints == [(LOOP + "/", "start")]
    assert (result.fetched, result.robots_missing, result.sitemap_missing) == (
        3,
        True,
        True,
    )


def chain(net, length):
    for number in range(length):
        net.html(
            LOOP + ("/" if number == 0 else f"/p{number}"),
            f'<a href="/p{number + 1}">next</a>',
        )
    net.html(LOOP + f"/p{length}", "<p>end</p>")


@pytest.mark.parametrize("depth,expected_pages", [(0, 0), (1, 1), (2, 2), (3, 3)])
def test_silk_crawl_depth_limits_how_far_links_are_followed_but_not_how_far_they_are_listed(
    ws, net, depth, expected_pages
):
    chain(net, 6)
    result = crawl(net, depth=depth)
    assert listed(result) == [LOOP + "/"] + [
        LOOP + f"/p{n}" for n in range(1, depth + 2)
    ]
    followed = [
        url
        for url in net.urls()
        if url not in (LOOP + "/", LOOP + "/robots.txt", LOOP + "/sitemap.xml")
    ]
    assert followed == [LOOP + f"/p{n}" for n in range(1, expected_pages + 1)]


def test_silk_crawl_limit_counts_every_fetch_and_reports_when_it_cut_the_queue(ws, net):
    net.html(LOOP + "/", '<a href="/a">a</a>')
    cut = crawl(net, limit=2)
    assert net.urls() == [LOOP + "/", LOOP + "/robots.txt"]
    assert (cut.fetched, cut.stopped) == (2, "Stopped after 2 pages.")
    assert listed(cut) == [LOOP + "/", LOOP + "/a"]
    net.hits.clear()
    one = crawl(net, limit=1)
    assert (one.fetched, one.stopped, one.robots_missing, one.sitemap_missing) == (
        1,
        "Stopped after 1 pages.",
        False,
        False,
    )
    net.hits.clear()
    net.html(LOOP + "/", "<p>x</p>")
    exact = crawl(net, limit=3)
    assert (exact.fetched, exact.stopped) == (3, "")


def test_silk_crawl_off_host_links_are_counted_and_ignorable_ones_are_not(ws, net):
    net.html(
        LOOP + "/",
        "".join(
            f'<a href="{href}">x</a>'
            for href in [
                "https://other.example/x",
                "http://127.0.0.1:9090/x",
                "https://127.0.0.1:8080/x",
                "//cdn.example/x",
                "javascript:void(0)",
                "JavaScript:void(0)",
                "mailto:a@b.example",
                "tel:123",
                "data:text/plain,hi",
                "blob:xyz",
                "about:blank",
                "#top",
                "",
                "/same",
            ]
        ),
    )
    result = crawl(net)
    assert (result.off_host, listed(result)) == (3, [LOOP + "/", LOOP + "/same"])


SKIP_EXTENSIONS = (
    "png jpg jpeg gif webp svg ico bmp avif woff woff2 ttf eot otf mp3 mp4 wav webm ogg pdf zip gz tgz rar 7z "
    "tar bz2 wasm map"
).split()
PAGE_EXTENSIONS = "html htm php asp aspx jsp js mjs css xml txt json xhtml".split()


def test_silk_crawl_extension_tables_are_exact(ws, net):
    assert len(SKIP_EXTENSIONS) == 29 and len(PAGE_EXTENSIONS) == 13
    net.html(
        LOOP + "/",
        "".join(
            f'<a href="/f.{ext}">x</a>' for ext in SKIP_EXTENSIONS + PAGE_EXTENSIONS
        ),
    )
    result = crawl(net, depth=1)
    sources = dict(result.endpoints)
    requested = set(net.urls())
    for ext in SKIP_EXTENSIONS:
        assert (
            sources[f"{LOOP}/f.{ext}"] == "asset" and f"{LOOP}/f.{ext}" not in requested
        ), ext
    for ext in PAGE_EXTENSIONS:
        assert (
            sources[f"{LOOP}/f.{ext}"] == "link" and f"{LOOP}/f.{ext}" in requested
        ), ext


def test_silk_crawl_extensions_decide_asset_labelling_and_fetching(ws, net):
    skipped = [
        "img.png",
        "doc.pdf",
        "archive.tar.gz",
        "font.woff2",
        "lib.wasm",
        "app.js.map",
        "s.svg",
        "movie.mp4",
        "x.ZIP",
    ]
    fetched = [
        "page.php",
        "noext",
        "a.b/c",
        "file.JS",
        "x.json",
        "y.html",
        "z.xml",
        "q.txt",
        "r.aspx",
    ]
    other = ["data.xyz"]
    net.html(
        LOOP + "/",
        "".join(f'<a href="/{name}">x</a>' for name in skipped + fetched + other),
    )
    result = crawl(net, depth=1)
    sources = dict(result.endpoints)
    assert all(sources[f"{LOOP}/{name}"] == "asset" for name in skipped)
    assert all(sources[f"{LOOP}/{name}"] == "link" for name in fetched + other)
    requested = set(net.urls())
    assert all(f"{LOOP}/{name}" not in requested for name in skipped + other)
    assert all(f"{LOOP}/{name}" in requested for name in fetched)


def test_silk_crawl_same_page_in_many_spellings_is_one_endpoint(ws, net):
    net.html(
        LOOP + "/",
        "".join(
            f'<a href="{href}">x</a>'
            for href in [
                "/a",
                "/a#frag",
                "HTTP://127.0.0.1:8080/a",
                "./a",
                "/b/../a",
                "http://127.0.0.1:8080/a?",
                "http://LOCALHOST/a",
                "/",
            ]
        ),
    )
    result = crawl(net)
    assert listed(result) == [LOOP + "/", LOOP + "/a"]
    assert (
        result.off_host == 1
    )  # http://localhost/a is another origin (host and default port)


PAGE_KINDS = [
    ("/page", "text/html", '<a href="/found">x</a>', "link"),
    ("/page", "text/html; charset=UTF-8", '<a href="/found">x</a>', "link"),
    ("/sniff", "text/plain", '<!doctype html><a href="/found">x</a>', "link"),
    ("/sniff", None, '<a href="/found">x</a>', "link"),
    ("/sniff", None, "x" * 560 + '<a href="/found">x</a>', "link"),
    ("/sniff", None, "\n\n  <body>" + '<a href="/found">x</a>', "link"),
    ("/sniff", None, "x" * 700 + '<a href="/found">x</a>', None),
    ("/json", "application/json", '{"u": "/found"}', None),
    ("/plain", "text/plain", 'see "/found"', None),
    ("/app.js", "text/html", 'var u="/found"', "script"),
    ("/app.mjs", "text/plain", 'var u="/found"', "script"),
    ("/lib", "application/javascript", 'var u="/found"', "script"),
    ("/lib", "text/javascript", 'var u="/found"', "script"),
    ("/lib", "application/x-javascript", 'var u="/found"', "script"),
    ("/site.css", "text/plain", "a{background:url(/found)}", "style"),
    ("/site.css?v=2", "text/plain", "a{background:url(/found)}", "style"),
    ("/styles", "text/css", "a{background:url(/found)}", "style"),
    ("/feed.xml", "text/plain", urlset(LOOP + "/found"), "sitemap"),
    ("/sm", "application/xml", urlset(LOOP + "/found"), "sitemap"),
    ("/my-sitemap", "text/plain", urlset(LOOP + "/found"), "sitemap"),
    ("/data", "text/plain", urlset(LOOP + "/found"), None),
    ("/x.xml", "application/xml", "<html><a href='/found'>x</a></html>", "link"),
    ("/page", "text/html", '<img src="/found">', "asset"),
    ("/page", "TEXT/HTML", '<img src="/found">', "asset"),
    ("/APP.JS", "text/plain", 'var u="/found"', "script"),
    ("/STYLE.CSS", "text/plain", "a{background:url(/found)}", "style"),
    ("/lib", "APPLICATION/JAVASCRIPT", 'var u="/found"', "script"),
    ("/lib", "TEXT/CSS", "a{background:url(/found)}", "style"),
]


def found_in_page(net, path, ctype, body):
    net.html(LOOP + "/", f'<a href="{path}">x</a>')
    net.add(LOOP + path, 200, body, {"content-type": ctype} if ctype else None)
    return [entry for entry in crawl(net).endpoints if entry[0] == LOOP + "/found"]


@pytest.mark.parametrize("path,ctype,body,source", PAGE_KINDS)
def test_silk_crawl_decides_how_to_read_a_page_from_content_type_path_and_body(
    ws, net, path, ctype, body, source
):
    assert found_in_page(net, path, ctype, body) == (
        [(LOOP + "/found", source)] if source else []
    )


@pytest.mark.parametrize(
    "opener",
    [
        "<!doctype html>",
        "<!DOCTYPE HTML>",
        "<html>",
        "<a>x</a>",
        "<a href='/zz'>x</a>",
        "<form>",
        "<script></script>",
        "<head>",
        "<body>",
        "\n\n   <HTML>",
    ],
)
def test_silk_crawl_sniffs_html_from_these_openers_when_there_is_no_content_type(
    ws, net, opener
):
    assert found_in_page(net, "/sniff", None, opener + '<img src="/found">') == [
        (LOOP + "/found", "asset")
    ]


def test_silk_crawl_html_sniff_window_is_six_hundred_characters_after_leading_whitespace(
    ws, net
):
    tail = ' html><img src="/found">'
    assert found_in_page(net, "/sniff", None, "x" * 591 + "<!doctype" + tail) == [
        (LOOP + "/found", "asset")
    ]
    assert found_in_page(net, "/sniff", None, "x" * 592 + "<!doctype" + tail) == []
    assert found_in_page(net, "/sniff", None, " " * 700 + "<!doctype" + tail) == [
        (LOOP + "/found", "asset")
    ]
    assert found_in_page(net, "/sniff", None, "x" * 700 + "<!doctype" + tail) == []


@pytest.mark.parametrize(
    "body",
    [
        "<urlset></urlset>",
        "<sitemapindex></sitemapindex>",
        f"<loc>{LOOP}/x</loc>",
        "<URLSET>",
        "  \n" + "<urlset>",
        " " * 900 + "<urlset>",
        "x" * 793 + "<urlset>",
        '<?xml version="1.0"?><urlset/>',
    ],
)
def test_silk_crawl_default_sitemap_is_recognised_by_its_opening_tokens(ws, net, body):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(LOOP + "/sitemap.xml", 200, body)
    result = crawl(net)
    assert (
        LOOP + "/sitemap.xml",
        "sitemap",
    ) in result.endpoints and result.sitemap_missing is False


@pytest.mark.parametrize(
    "body",
    [
        "x" * 794 + "<urlset>",
        "<html>no map</html>",
        "plain text",
        "",
        "<rss><channel/></rss>",
    ],
)
def test_silk_crawl_default_sitemap_is_not_recognised_without_those_tokens(
    ws, net, body
):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(LOOP + "/sitemap.xml", 200, body)
    result = crawl(net)
    assert (
        result.endpoints == [(LOOP + "/", "start")] and result.sitemap_missing is True
    )


def sitemap_index_at(position, token="<sitemapindex>"):
    head = f"<urlset><url><loc>{LOOP}/child</loc></url></urlset>"
    padding = "<!--" + "x" * (position - len(head) - 7) + "-->"
    text = head + padding + token
    assert text.index(token) == position
    return text


@pytest.mark.parametrize(
    "position,token,is_index",
    [
        (7987, "<sitemapindex>", True),
        (7988, "<sitemapindex>", False),
        (7987, "<SITEMAPINDEX>", True),
        (200, "<sitemapindex>", True),
    ],
)
def test_silk_crawl_sitemap_index_is_recognised_within_the_first_eight_thousand_characters(
    ws, net, position, token, is_index
):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(LOOP + "/sitemap.xml", 200, sitemap_index_at(position, token))
    crawl(net, depth=0)
    assert (LOOP + "/child" in net.urls()) is is_index


def test_silk_crawl_sitemap_index_children_keep_the_depth_of_the_index(ws, net):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(LOOP + "/sitemap.xml", 200, sitemapindex(LOOP + "/c.xml"))
    net.add(LOOP + "/c.xml", 200, urlset(LOOP + "/pg"))
    net.html(LOOP + "/pg", "<p>x</p>")
    crawl(net, depth=1)
    assert LOOP + "/pg" in net.urls()


def test_silk_crawl_redirect_targets_keep_the_source_of_the_job_that_found_them(
    ws, net
):
    net.html(LOOP + "/", '<script src="/j.js"></script><form action="/f"></form>')
    net.redirect(LOOP + "/j.js", "/j2.js")
    net.redirect(LOOP + "/f", "/f2")
    endpoints = crawl(net).endpoints
    assert (LOOP + "/j2.js", "script") in endpoints and (
        LOOP + "/f2",
        "form",
    ) in endpoints
    net.add(LOOP + "/sitemap.xml", 200, urlset(LOOP + "/old"))
    net.redirect(LOOP + "/old", "/new")
    assert (LOOP + "/new", "sitemap") in crawl(net).endpoints


def test_silk_crawl_robots_relative_entries_resolve_against_the_origin_even_after_a_redirect(
    ws, net
):
    net.html(LOOP + "/", "<p>x</p>")
    net.redirect(LOOP + "/robots.txt", "/sub/robots.txt")
    net.add(
        LOOP + "/sub/robots.txt",
        200,
        "User-agent: *\nDisallow: rel\nSitemap: map.xml\n",
    )
    net.add(LOOP + "/map.xml", 200, urlset(LOOP + "/m1"))
    result = crawl(net)
    assert (LOOP + "/sub/robots.txt", "robots") in result.endpoints and (
        LOOP + "/rel",
        "robots",
    ) in result.endpoints
    assert (
        LOOP + "/map.xml" in net.urls()
        and (LOOP + "/m1", "sitemap") in result.endpoints
    )


def test_silk_crawl_sitemap_relative_locs_resolve_against_the_sitemap_url(ws, net):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(LOOP + "/robots.txt", 200, "Sitemap: /dir/map.xml\n")
    net.add(LOOP + "/dir/map.xml", 200, urlset("rel"))
    assert (LOOP + "/dir/rel", "sitemap") in crawl(net).endpoints


def test_silk_crawl_foreign_origins_are_skipped_even_when_they_are_in_scope(ws, net):
    ws.scope("other.example")
    net.html(LOOP + "/", "<p>x</p>")
    net.add(LOOP + "/robots.txt", 200, f"Disallow: {OFF}/z\nDisallow: /ok\n")
    net.add(LOOP + "/sitemap.xml", 200, urlset(OFF + "/loc", LOOP + "/mine"))
    result = crawl(net)
    assert listed(result) == [
        LOOP + "/",
        LOOP + "/robots.txt",
        LOOP + "/ok",
        LOOP + "/sitemap.xml",
        LOOP + "/mine",
    ]
    assert result.off_host == 1


def test_silk_crawl_out_of_scope_hosts_are_never_listed_even_through_a_base_href(
    ws, net
):
    net.html(LOOP + "/", f'<base href="{OFF}/z/"><a href="p">x</a>')
    result = crawl(net, depth=0)
    assert listed(result) == [LOOP + "/"] and result.off_host == 1


def test_silk_crawl_ignores_error_and_empty_pages(ws, net):
    net.html(
        LOOP + "/", '<a href="/gone">g</a><a href="/boom">b</a><a href="/empty">e</a>'
    )
    net.html(LOOP + "/gone", '<a href="/hidden1">x</a>', status=404)
    net.html(LOOP + "/boom", '<a href="/hidden2">x</a>', status=500)
    net.html(LOOP + "/empty", "")
    assert listed(crawl(net)) == [
        LOOP + "/",
        LOOP + "/gone",
        LOOP + "/boom",
        LOOP + "/empty",
    ]
    net.html(LOOP + "/", '<a href="/bad">b</a><a href="/ok">o</a>')
    net.html(LOOP + "/bad", '<a href="/hidden3">x</a>', status=400)
    net.html(LOOP + "/ok", '<a href="/shown">x</a>', status=399)
    assert listed(crawl(net)) == [
        LOOP + "/",
        LOOP + "/bad",
        LOOP + "/ok",
        LOOP + "/shown",
    ]


def test_silk_crawl_in_origin_redirects_list_the_target_and_off_origin_ones_are_counted(
    ws, net
):
    net.html(
        LOOP + "/", '<a href="/old">o</a><a href="/out">x</a><a href="/nowhere">n</a>'
    )
    net.redirect(LOOP + "/old", "/new", 301)
    net.html(LOOP + "/new", '<a href="/from-new">n</a>')
    net.add(LOOP + "/out", 302, "", {"location": OFF + "/x"})
    net.add(LOOP + "/nowhere", 302, "")
    result = crawl(net)
    assert result.endpoints == [
        (LOOP + "/", "start"),
        (LOOP + "/old", "link"),
        (LOOP + "/out", "link"),
        (LOOP + "/nowhere", "link"),
        (LOOP + "/new", "link"),
        (LOOP + "/from-new", "link"),
    ]
    assert result.left_server == 1 and result.off_host == 0


def test_silk_crawl_start_page_redirect_is_listed_with_the_start_label(ws, net):
    net.redirect(LOOP + "/go", "/home")
    net.html(LOOP + "/home", '<a href="/x">x</a>')
    result = crawl(net, LOOP + "/go")
    assert result.endpoints[:3] == [
        (LOOP + "/go", "start"),
        (LOOP + "/home", "start"),
        (LOOP + "/x", "link"),
    ]


def test_silk_crawl_start_page_that_redirects_off_server_is_not_an_error(ws, net):
    net.add(LOOP + "/", 302, "", {"location": OFF + "/"})
    result = crawl(net)
    assert (
        listed(result) == [LOOP + "/"]
        and result.left_server == 1
        and result.fetched == 3
    )


def test_silk_crawl_failure_of_the_start_page_is_raised_but_other_failures_are_swallowed(
    ws, net
):
    net.fail(LOOP + "/", httpx.ConnectError("boom"))
    with pytest.raises(
        silk.FetchError, match=f"^Could not fetch {LOOP}/: ConnectError$"
    ):
        crawl(net)
    net.html(LOOP + "/", '<a href="/boom">b</a><a href="/fine">f</a>')
    net.fail(LOOP + "/boom", httpx.ReadTimeout("slow"))
    net.fail(LOOP + "/robots.txt", httpx.ConnectError("x"))
    net.fail(LOOP + "/sitemap.xml", httpx.ConnectError("x"))
    result = crawl(net)
    assert listed(result) == [LOOP + "/", LOOP + "/boom", LOOP + "/fine"]
    assert (result.fetched, result.robots_missing, result.sitemap_missing) == (
        2,
        True,
        True,
    )


@pytest.mark.parametrize(
    "status,body,present",
    [
        (200, "User-agent: *\nDisallow: /x", True),
        (200, "Sitemap: http://127.0.0.1:8080/s.xml", True),
        (200, "Allow: /x", True),
        (200, "DISALLOW /x", True),
        (200, "\n\n  User-agent: *", True),
        (200, "x" * 980 + "user-agent", True),
        (200, "x" * 990 + "user-agent", True),
        (200, "x" * 991 + "user-agent", False),
        (200, " " * 1100 + "user-agent", True),
        (200, "USER-AGENT: *", True),
        (200, "x" * 1001 + "user-agent", False),
        (200, "just some words", False),
        (200, "<html>User-agent: x</html>", False),
        (200, "", False),
        (404, "User-agent: *", False),
        (403, "User-agent: *", False),
        (301, "User-agent: *", False),
    ],
)
def test_silk_crawl_robots_txt_must_be_200_and_look_like_robots(
    ws, net, status, body, present
):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(LOOP + "/robots.txt", status, body)
    result = crawl(net)
    assert result.robots_missing is (not present)
    assert ((LOOP + "/robots.txt", "robots") in result.endpoints) is present


def test_silk_crawl_robots_paths_are_listed_cleaned_and_never_requested(ws, net):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(
        LOOP + "/robots.txt",
        200,
        "\n".join(
            [
                "User-agent: *",
                "Disallow: /a*$",
                "Disallow: /*",
                "Disallow: http://127.0.0.1:8080/abs",
                "Disallow: http://other.example/z",
                "Disallow: //cdn.example/q",
                "Disallow: rel",
                "Allow: /pub/",
                "Disallow: /dup",
                "Disallow: /dup",
                "Disallow:",
                "Disallow: *",
            ]
        ),
    )
    result = crawl(net)
    assert result.endpoints == [
        (LOOP + "/", "start"),
        (LOOP + "/robots.txt", "robots"),
    ] + [(LOOP + path, "robots") for path in ("/a", "/abs", "/rel", "/pub/", "/dup")]
    assert result.off_host == 0
    assert net.urls() == [LOOP + "/", LOOP + "/robots.txt", LOOP + "/sitemap.xml"]


def test_silk_crawl_robots_sitemap_lines_are_fetched_deduped_and_off_host_ones_counted(
    ws, net
):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(
        LOOP + "/robots.txt",
        200,
        f"Sitemap: /extra.xml\nSitemap: {LOOP}/sitemap.xml\nSitemap: {OFF}/s.xml\nSitemap: https://127.0.0.1:8080/t.xml\n",
    )
    net.add(LOOP + "/extra.xml", 200, urlset(LOOP + "/from-extra"))
    result = crawl(net)
    assert net.urls().count(LOOP + "/sitemap.xml") == 1
    assert LOOP + "/extra.xml" in net.urls() and OFF + "/s.xml" not in net.urls()
    assert result.off_host == 2
    assert (LOOP + "/from-extra", "sitemap") in result.endpoints


def test_silk_crawl_at_most_eight_sitemaps_are_fetched_including_the_default_one(
    ws, net
):
    net.html(LOOP + "/", "<p>x</p>")
    names = [f"/m{n}.xml" for n in range(1, 11)]
    net.add(LOOP + "/robots.txt", 200, "".join(f"Sitemap: {name}\n" for name in names))
    for number, name in enumerate(names, start=1):
        net.add(LOOP + name, 200, urlset(f"{LOOP}/page{number}"))
    result = crawl(net)
    fetched_maps = [url for url in net.urls() if url.endswith(".xml")]
    assert fetched_maps == [LOOP + "/sitemap.xml"] + [LOOP + name for name in names[:7]]
    assert (LOOP + "/page7", "sitemap") in result.endpoints and (
        LOOP + "/page8",
        "sitemap",
    ) not in result.endpoints


def test_silk_crawl_sitemap_urlset_locs_are_listed_and_followed_one_level_down(ws, net):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(
        LOOP + "/sitemap.xml",
        200,
        urlset(
            LOOP + "/one",
            "/two",
            "sub/three",
            OFF + "/off",
            LOOP + "/pic.png",
            "ftp://x/y",
        ),
        {"content-type": "application/xml"},
    )
    net.html(LOOP + "/one", '<a href="/from-one">x</a>')
    result = crawl(net)
    assert result.endpoints == [
        (LOOP + "/", "start"),
        (LOOP + "/sitemap.xml", "sitemap"),
        (LOOP + "/one", "sitemap"),
        (LOOP + "/two", "sitemap"),
        (LOOP + "/sub/three", "sitemap"),
        (LOOP + "/pic.png", "sitemap"),
        (LOOP + "/from-one", "link"),
    ]
    assert result.off_host == 1 and result.sitemap_missing is False
    assert LOOP + "/one" in net.urls() and LOOP + "/pic.png" not in net.urls()


def test_silk_crawl_sitemap_locs_are_not_fetched_at_depth_zero_and_capped_per_sitemap(
    ws, net
):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(LOOP + "/sitemap.xml", 200, urlset(*[f"{LOOP}/u{n}" for n in range(250)]))
    shallow = crawl(net, depth=0)
    assert len(shallow.endpoints) == 1 + 1 + 200
    assert not any(url.startswith(LOOP + "/u") for url in net.urls())


def test_silk_crawl_sitemap_index_children_are_fetched_even_at_depth_zero(ws, net):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(
        LOOP + "/sitemap.xml",
        200,
        sitemapindex(LOOP + "/c1.xml", LOOP + "/c2.xml", OFF + "/c3.xml"),
    )
    net.add(LOOP + "/c1.xml", 200, urlset(LOOP + "/page1"))
    net.add(LOOP + "/c2.xml", 200, sitemapindex(LOOP + "/c2a.xml"))
    net.add(LOOP + "/c2a.xml", 200, urlset(LOOP + "/page2"))
    result = crawl(net, depth=0)
    assert result.endpoints == [
        (LOOP + "/", "start"),
        (LOOP + "/sitemap.xml", "sitemap"),
        (LOOP + "/c1.xml", "sitemap"),
        (LOOP + "/c2.xml", "sitemap"),
        (LOOP + "/page1", "sitemap"),
        (LOOP + "/c2a.xml", "sitemap"),
        (LOOP + "/page2", "sitemap"),
    ]
    assert result.off_host == 1
    assert not any(url == LOOP + "/page1" for url in net.urls())


def test_silk_crawl_sitemap_index_budget_lists_every_child_but_fetches_only_seven_more(
    ws, net
):
    net.html(LOOP + "/", "<p>x</p>")
    children = [f"{LOOP}/c{n}.xml" for n in range(1, 13)]
    net.add(LOOP + "/sitemap.xml", 200, sitemapindex(*children))
    for child in children:
        net.add(child, 200, urlset(child + "/page"))
    result = crawl(net)
    assert [url for url in net.urls() if url.endswith(".xml")] == [
        LOOP + "/sitemap.xml"
    ] + children[:7]
    assert all((child, "sitemap") in result.endpoints for child in children)


def test_silk_crawl_sitemap_missing_cases(ws, net):
    net.html(LOOP + "/", "<p>x</p>")
    assert crawl(net).sitemap_missing is True
    net.html(
        LOOP + "/sitemap.xml", '<html>spa fallback <a href="/from-spa">x</a></html>'
    )
    spa = crawl(net)
    assert spa.sitemap_missing is True and listed(spa) == [LOOP + "/"]
    net.add(
        LOOP + "/sitemap.xml", 200, urlset(LOOP + "/a"), {"content-type": "text/html"}
    )
    assert crawl(net).sitemap_missing is False
    net.add(LOOP + "/sitemap.xml", 404, urlset(LOOP + "/a"))
    assert crawl(net).sitemap_missing is True


def test_silk_crawl_base_href_moves_relative_references_within_the_origin(ws, net):
    net.html(
        LOOP + "/dir/page", '<base href="/sub/"><a href="p">p</a><a href="/abs">a</a>'
    )
    result = crawl(net, LOOP + "/dir/page", depth=0)
    assert listed(result) == [LOOP + "/dir/page", LOOP + "/sub/p", LOOP + "/abs"]


def test_silk_crawl_forms_scripts_styles_and_assets_get_their_own_labels(ws, net):
    net.html(
        LOOP + "/",
        '<form action="/f"></form><button formaction="/fa"></button><script src="/j.js"></script>'
        '<link rel="stylesheet" href="/s.css"><img src="/i.png"><link rel="icon" href="/fav"><iframe src="/fr"></iframe>'
        '<meta http-equiv="refresh" content="0;url=/m"><script src="/lib.map"></script>',
    )
    result = crawl(net, depth=0)
    assert result.endpoints == [
        (LOOP + "/", "start"),
        (LOOP + "/f", "form"),
        (LOOP + "/fa", "form"),
        (LOOP + "/j.js", "script"),
        (LOOP + "/s.css", "style"),
        (LOOP + "/i.png", "asset"),
        (LOOP + "/fav", "link"),
        (LOOP + "/fr", "link"),
        (LOOP + "/m", "link"),
        (LOOP + "/lib.map", "asset"),
    ]


def test_silk_crawl_script_and_stylesheet_bodies_contribute_quoted_paths(ws, net):
    net.html(
        LOOP + "/", '<script src="/j.js"></script><link rel="stylesheet" href="/s.css">'
    )
    net.add(
        LOOP + "/j.js",
        200,
        'a("/api/one"); b("https://other.example/x"); c("/api/two?x=1")',
        {"content-type": "text/javascript"},
    )
    net.add(
        LOOP + "/s.css",
        200,
        "a{background:url(/img/a.png)} @import url('/more.css');",
        {"content-type": "text/css"},
    )
    result = crawl(net)
    assert (LOOP + "/api/one", "script") in result.endpoints
    assert not any("/api/two" in url for url in listed(result))
    assert (LOOP + "/img/a.png", "asset") in result.endpoints and (
        LOOP + "/more.css",
        "style",
    ) in result.endpoints
    assert result.off_host == 1


def wide_site(net):
    net.html(LOOP + "/", "".join(f'<a href="/page{n}">p</a>' for n in range(3)))
    for page in range(3):
        net.html(
            LOOP + f"/page{page}",
            "".join(f'<a href="/x{page}_{n}">x</a>' for n in range(200)),
        )


def test_silk_crawl_stops_at_five_hundred_endpoints(ws, net):
    wide_site(net)
    result = crawl(net, depth=2, limit=100)
    assert (
        len(result.endpoints) == 500
        and result.stopped == "Stopped after 500 endpoints."
    )
    assert not any(url.rsplit("/", 1)[-1].startswith("x") for url in net.urls())
    assert net.urls() == [
        LOOP + path
        for path in ("/", "/robots.txt", "/sitemap.xml", "/page0", "/page1", "/page2")
    ]


def test_silk_crawl_reports_only_the_first_reason_it_stopped(ws, net):
    wide_site(net)
    result = crawl(net, depth=2, limit=6)
    assert result.fetched == 6 and result.stopped == "Stopped after 500 endpoints."


def test_silk_crawl_a_robots_txt_that_redirects_off_server_is_counted_not_reported_missing(
    ws, net
):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(LOOP + "/robots.txt", 302, "", {"location": OFF + "/robots.txt"})
    result = crawl(net)
    assert (result.left_server, result.robots_missing) == (1, False)


@pytest.mark.parametrize("depth,followed", [(0, False), (1, True), (2, True)])
def test_silk_crawl_sitemap_locs_are_fetched_only_within_the_depth_setting(
    ws, net, depth, followed
):
    net.html(LOOP + "/", "<p>x</p>")
    net.add(LOOP + "/sitemap.xml", 200, urlset(LOOP + "/loc"))
    net.html(LOOP + "/loc", "<p>x</p>")
    crawl(net, depth=depth)
    assert (LOOP + "/loc" in net.urls()) is followed


def test_silk_crawl_relative_references_resolve_against_the_redirect_target(ws, net):
    net.html(LOOP + "/", '<a href="/old">o</a>')
    net.redirect(LOOP + "/old", "/dir/new")
    net.html(LOOP + "/dir/new", '<a href="x">x</a>')
    assert (LOOP + "/dir/x", "link") in crawl(net).endpoints


def test_silk_crawl_one_page_contributes_at_most_two_hundred_references(ws, net):
    net.html(LOOP + "/", "".join(f'<a href="/x{n}">x</a>' for n in range(250)))
    assert len(crawl(net, depth=0).endpoints) == 201


def test_silk_crawl_never_requests_another_origin_even_through_redirects(ws, net):
    build_site(net)
    net.html(
        LOOP + "/",
        net.routes[LOOP + "/"][2]
        + '<a href="/to-port">p</a><a href="/to-scheme">s</a><a href="/to-host">h</a>',
    )
    net.redirect(LOOP + "/to-port", "http://127.0.0.1:9999/x")
    net.redirect(LOOP + "/to-scheme", "https://127.0.0.1:8080/x")
    net.redirect(LOOP + "/to-host", "http://localhost:8080/x")
    result = crawl(net)
    assert {url.split("/")[2] for url in net.urls()} == {"127.0.0.1:8080"}
    assert result.left_server == 3


# ---- silk.main -------------------------------------------------------------------------------------------


def test_silk_main_prints_one_url_per_line_and_a_summary(ws, net, cli):
    build_site(net)
    result = cli(silk.main, LOOP + "/")
    assert result.rc == 0
    assert result.out == "".join(f"{LOOP}{path}\n" for path, _source in SITE_ENDPOINTS)
    assert result.err == "16 endpoint(s)  12 page(s)  2 left this server\n"


def test_silk_main_summary_parts(ws, net, cli):
    net.html(LOOP + "/", "<p>x</p>")
    assert (
        cli(silk.main, LOOP + "/").err
        == "1 endpoint(s)  3 page(s)  no robots.txt  no sitemap.xml\n"
    )
    net.html(LOOP + "/", '<a href="/out">o</a><a href="https://other.example/">x</a>')
    net.add(LOOP + "/out", 302, "", {"location": OFF + "/"})
    assert cli(silk.main, LOOP + "/").err == (
        "2 endpoint(s)  4 page(s)  1 left this server  1 redirect(s) stayed put  no robots.txt  no sitemap.xml\n"
    )


def test_silk_main_limit_notice_follows_the_summary(ws, net, cli):
    net.html(LOOP + "/", '<a href="/a">a</a>')
    result = cli(silk.main, LOOP + "/", "--limit", "2")
    assert result.out == f"{LOOP}/\n{LOOP}/a\n"
    assert (
        result.err
        == "2 endpoint(s)  2 page(s)  no robots.txt\nStopped after 2 pages.\n"
    )


def test_silk_main_normalises_the_start_url_and_depth_zero_is_allowed(ws, net, cli):
    net.html(LOOP + "/", '<a href="/a">a</a>')
    result = cli(silk.main, "HTTP://127.0.0.1:8080", "--depth", "0")
    assert result.rc == 0 and result.out.splitlines()[0] == LOOP + "/"


@pytest.mark.parametrize(
    "argv",
    [
        ["--limit", "0"],
        ["--limit", "-1"],
        ["--depth", "-1"],
        ["--timeout", "0"],
        ["--timeout", "-3"],
    ],
)
def test_silk_main_numeric_argument_errors(ws, net, cli, argv):
    result = cli(silk.main, LOOP + "/", *argv)
    assert (result.rc, result.out) == (2, "")
    assert (
        result.err
        == "Depth must be 0 or more. Limit and timeout must be greater than 0.\n"
    )
    assert net.client_calls == []


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1/",
        "127.0.0.1:8080",
        "http://",
        "/path",
        "mailto:a@b.example",
        "  ",
    ],
)
def test_silk_main_rejects_non_http_start_urls(ws, net, cli, url):
    result = cli(silk.main, url)
    assert (result.rc, result.out, result.err) == (
        2,
        "",
        "Give an http or https URL, such as http://127.0.0.1/.\n",
    )


def test_silk_main_start_outside_scope_is_refused_before_any_client_exists(
    ws, net, cli
):
    from bughunt.core.workspace import explain_block

    result = cli(silk.main, OFF + "/")
    assert (result.rc, result.out, result.err) == (
        2,
        "",
        explain_block("other.example") + "\n",
    )
    assert net.client_calls == [] and net.hits == []
    ws.scope("app.internal")
    net.html(APP + "/", "<p>x</p>")
    assert cli(silk.main, APP + "/").out == APP + "/\n"


def test_silk_main_start_page_failure_exits_one(ws, net, cli):
    net.fail(LOOP + "/", httpx.ConnectError("boom"))
    result = cli(silk.main, LOOP + "/")
    assert (result.rc, result.out, result.err) == (
        1,
        "",
        f"Could not fetch {LOOP}/: ConnectError\n",
    )


def test_silk_main_error_messages_are_not_read_as_rich_markup(ws, net, cli):
    start = LOOP + "/[red]x[/red]"
    net.fail(str(httpx.URL(start)), httpx.ConnectError("boom"))
    result = cli(silk.main, start)
    assert result.rc == 1 and result.err == f"Could not fetch {start}: ConnectError\n"


def test_silk_main_remembers_urls_in_scope_runs_only(ws, net, cli):
    build_site(net)
    plain = cli(silk.main, LOOP + "/")
    assert ws.urls() == [] and "new in" not in plain.err
    ws.scope("app.internal")
    first = cli(silk.main, LOOP + "/")
    assert (
        first.err
        == "16 endpoint(s)  12 page(s)  2 left this server  16 new in urls.txt\n"
    )
    assert ws.urls() == [f"{LOOP}{path}" for path, _source in SITE_ENDPOINTS]
    again = cli(silk.main, LOOP + "/")
    assert again.err.endswith("0 new in urls.txt\n") and len(ws.urls()) == 16
    (ws.root / "urls.txt").write_bytes(b"")
    skipped = cli(silk.main, LOOP + "/", "--no-workspace")
    assert "new in" not in skipped.err and ws.urls() == []


def test_silk_main_save_writes_the_plain_url_list(ws, net, cli):
    build_site(net)
    target = ws.base / "out.txt"
    result = cli(silk.main, LOOP + "/", "--save", str(target))
    assert result.rc == 0
    assert target.read_text(encoding="utf-8") == "".join(
        f"{LOOP}{path}\n" for path, _source in SITE_ENDPOINTS
    )


def test_silk_main_save_failure_exits_one_after_printing(ws, net, cli):
    net.html(LOOP + "/", "<p>x</p>")
    folder = ws.base / "dir"
    folder.mkdir()
    result = cli(silk.main, LOOP + "/", "--save", str(folder))
    assert result.rc == 1 and result.out == LOOP + "/\n"
    assert result.err.startswith(f"Could not write {folder}: ")


def test_silk_main_client_construction_and_credentials(ws, net, cli):
    net.html(LOOP + "/", "<p>x</p>")
    cli(
        silk.main,
        LOOP + "/",
        "--timeout",
        "2",
        "--cookie",
        "c=1",
        "--authorization",
        "Bearer t",
    )
    assert net.client_calls == [
        {
            "operation": "crawl",
            "timeout": 2.0,
            "follow_redirects": False,
            "trust_env": False,
            "headers": {
                "User-Agent": f"Bughunt/{VERSION}",
                "Accept-Encoding": "identity",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Cookie": "c=1",
                "Authorization": "Bearer t",
            },
        }
    ]
    assert all(
        hit.headers["cookie"] == "c=1" and hit.headers["authorization"] == "Bearer t"
        for hit in net.hits
    )


def test_silk_main_saved_session_is_used_unless_flags_replace_it(ws, net, cli):
    net.html(LOOP + "/", "<p>x</p>")
    ws.session(cookie="saved=1")
    cli(silk.main, LOOP + "/")
    assert net.hits[0].headers["cookie"] == "saved=1"
    cli(silk.main, LOOP + "/", "--cookie", "")
    assert "cookie" not in net.hits[-1].headers


def test_silk_main_terminal_output_is_colored_with_a_banner_and_a_silk_tag(
    ws, net, tty
):
    build_site(net)
    streams = tty()
    assert silk.main([LOOP + "/"]) == 0
    assert streams[0].getvalue() == "".join(
        silk.format_row(source, LOOP + path, True) + "\n"
        for path, source in SITE_ENDPOINTS
    )
    assert streams[1].getvalue().startswith(silk.format_banner(True) + "\n\n")
    assert (
        streams[1]
        .getvalue()
        .endswith(
            "\x1b[1;95msilk\x1b[0m  16 endpoint(s)  12 page(s)  2 left this server\n"
        )
    )


def test_silk_main_row_color_follows_stdout_and_banner_follows_stderr(ws, net, tty):
    net.html(LOOP + "/", "<p>x</p>")
    streams = tty(err=False)
    assert silk.main([LOOP + "/"]) == 0
    assert streams[0].getvalue() == silk.format_row("start", LOOP + "/", True) + "\n"
    assert (
        streams[1].getvalue()
        == "1 endpoint(s)  3 page(s)  no robots.txt  no sitemap.xml\n"
    )
    streams = tty(out=False)
    assert silk.main([LOOP + "/"]) == 0
    assert streams[0].getvalue() == LOOP + "/\n"
    assert streams[1].getvalue().startswith(silk.format_banner(True) + "\n\n")


def test_silk_main_plain_flag_keeps_rows_and_banner_plain_but_not_the_summary_tag(
    ws, net, tty
):
    build_site(net)
    streams = tty()
    assert silk.main([LOOP + "/", "--plain"]) == 0
    assert streams[0].getvalue() == "".join(
        f"{LOOP}{path}\n" for path, _source in SITE_ENDPOINTS
    )
    assert (
        streams[1].getvalue()
        == "\x1b[1;95msilk\x1b[0m  16 endpoint(s)  12 page(s)  2 left this server\n"
    )


@pytest.mark.parametrize("setup", ["no-color", "dumb", "no-term"])
def test_silk_main_environment_can_turn_color_off(ws, net, tty, monkeypatch, setup):
    net.html(LOOP + "/", "<p>x</p>")
    streams = tty()
    if setup == "no-color":
        monkeypatch.setenv("NO_COLOR", "1")
    elif setup == "dumb":
        monkeypatch.setenv("TERM", "dumb")
    else:
        monkeypatch.delenv("TERM")
    assert silk.main([LOOP + "/"]) == 0
    assert streams[0].getvalue() == LOOP + "/\n"
    assert (
        streams[1].getvalue()
        == silk.format_banner(False)
        + "\n\n1 endpoint(s)  3 page(s)  no robots.txt  no sitemap.xml\n"
    )


class BrokenIsatty(io.StringIO):
    def isatty(self):
        raise ValueError("I/O operation on closed file")

    def getvalue_text(self):
        return self.getvalue()


class NoIsatty:
    def __init__(self):
        self.buffer = io.StringIO()

    def write(self, text):
        return self.buffer.write(text)

    def flush(self):
        pass

    def getvalue_text(self):
        return self.buffer.getvalue()


@pytest.mark.parametrize("stream", [BrokenIsatty, NoIsatty])
def test_silk_and_decode_treat_a_stream_without_a_working_isatty_as_not_a_terminal(
    ws, net, monkeypatch, stream
):
    monkeypatch.setenv("TERM", "xterm")
    net.html(LOOP + "/", "<p>x</p>")
    out, err = stream(), stream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    assert silk.main([LOOP + "/"]) == 0
    assert (
        out.getvalue_text() == LOOP + "/\n"
        and ESC not in err.getvalue_text()
        and "spins pages" not in err.getvalue_text()
    )
    out, err = stream(), stream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    assert decode.main([ws.file("p.txt", data_uri("SGVsbG8="))]) == 0
    assert (
        out.getvalue_text() == "Hello\n"
        and ESC not in err.getvalue_text()
        and "page source" not in err.getvalue_text()
    )


def test_silk_main_prints_no_banner_or_color_when_not_on_a_terminal(ws, net, cli):
    net.html(LOOP + "/", "<p>x</p>")
    result = cli(silk.main, LOOP + "/")
    assert ESC not in result.out + result.err and "spins pages" not in result.err


# =========================================================================================================
# output-safety regressions (rich markup, header injection) and known defects
# =========================================================================================================


def test_forms_render_request_cannot_be_given_extra_header_lines_through_the_url():
    raw = forms.render_request(
        forms.Draft(
            "GET", "http://app.internal/a\r\nX-Evil: 1\r\n\r\nGET /smuggled", ""
        )
    )
    assert (
        raw.count(b"\r\n") == 4
        and b"\r\nX-Evil" not in raw
        and b"\nGET /smuggled" not in raw
    )
    host = forms.render_request(
        forms.Draft("GET", "http://app.internal\r\nX-Evil/a", "")
    )
    assert host.count(b"\r\n") == 4 and b"\r\nX-Evil" not in host


def test_forms_and_robots_echo_bracketed_file_names_literally(ws, net, cli):
    odd = str(ws.base / "[red]nofile[/red].html")
    assert cli(forms.main, odd).err == f"No file named {odd}.\n"
    assert cli(robots.main, odd).err == f"No file named {odd}.\n"


@pytest.mark.parametrize(
    "entry,module", [(redirect.main, "redirect"), (decode.main, "decode")]
)
def test_redirect_and_decode_echo_bracketed_urls_literally(ws, net, cli, entry, module):
    url = LOOP + "/[b]x[/b]"
    net.fail(str(httpx.URL(url)), httpx.ConnectError("boom"))
    assert cli(entry, url).err == f"Could not fetch {url}: ConnectError\n"


def refusing_client(monkeypatch):
    def refuse(**_kwargs):
        raise egress.PolicyBlocked("policy-missing-or-invalid; no outbound action ran")

    monkeypatch.setattr(egress, "client", refuse)


@pytest.mark.parametrize(
    "entry,argv",
    [
        (forms.main, ["--url", LOOP + "/p"]),
        (robots.main, ["--fetch", LOOP + "/robots.txt"]),
        (silk.main, [LOOP + "/"]),
    ],
)
def test_forms_robots_and_silk_let_a_policy_block_at_client_creation_escape_to_the_console(
    ws, monkeypatch, entry, argv
):
    refusing_client(monkeypatch)
    with pytest.raises(egress.PolicyBlocked):
        entry(argv)


def test_redirect_reports_a_policy_block_at_client_creation_as_a_fetch_failure(
    ws, monkeypatch, cli
):
    refusing_client(monkeypatch)
    result = cli(redirect.main, LOOP + "/a")
    assert (result.rc, result.out, result.err) == (
        1,
        "",
        f"Could not fetch {LOOP}/a: PolicyBlocked\n",
    )


# ---- forms ----------------------------------------------------------------------------------------------

UNSELECTED = (
    '<select name="s"><option value="1"><option value="2"><option value="3"></select>'
)


def test_forms_defect_correct_a_select_with_nothing_selected_posts_its_first_option():
    assert draft_query(UNSELECTED) == "s=1"


COLON_PAGE = (
    form_of('<input name="a">', "/do?x=a:b", "POST")
    + '<a href="/search?q=a:b">l</a><a href="/t?time=10:30">t</a>'
)


def test_forms_defect_correct_relative_urls_with_a_colon_are_resolved_like_any_other():
    page = parse(COLON_PAGE, APPBASE)
    assert [(item.url, item.name) for item in page.findings] == [
        ("http://app.internal/do?x=a:b", "a"),
        ("http://app.internal/search?q=a:b", "q"),
        ("http://app.internal/t?time=10:30", "time"),
    ]


def cross_host_redirect(ws, net):
    ws.scope("app.internal", "second.internal")
    net.redirect(APP + "/a", "http://second.internal/b")
    net.html("http://second.internal/b", "<p>x</p>")


def second_host_hits(net):
    return [hit for hit in net.hits if hit.url.startswith("http://second.internal")]


def test_forms_credentials_are_not_sent_to_a_different_host(ws, net, cli):
    cross_host_redirect(ws, net)
    cli(
        forms.main,
        "--url",
        APP + "/a",
        "--cookie",
        "s=1",
        "--authorization",
        "Bearer t",
    )
    assert all(
        "cookie" not in hit.headers and "authorization" not in hit.headers
        for hit in second_host_hits(net)
    )


INVALID_PORT_PAGE = form_of(
    '<input name="a">', "http://app.internal:99999/x"
) + form_of('<input name="b">', APP + "/ok")


def test_forms_defect_correct_a_bad_draft_is_skipped_and_the_good_ones_are_saved(
    ws, net, cli
):
    ws.scope("app.internal")
    cli(forms.main, ws.file("p.html", INVALID_PORT_PAGE), "--save")
    assert any(b"Host: app.internal\r\n" in raw for raw in ws.saved().values())


# ---- robots ---------------------------------------------------------------------------------------------


def test_robots_defect_correct_a_path_whose_query_holds_a_url_resolves_against_the_base():
    assert robots_of("Disallow: /go?u=http://x.example/y", "https://x") == (
        ["https://x/go?u=http://x.example/y"],
        0,
    )


# ---- redirect + decode ----------------------------------------------------------------------------------

DOWNGRADE_TARGETS = ["http://127.0.0.1:8080/next", "https://127.0.0.1:9443/next"]


def credentialed_follow_up(net, entry, target, cli):
    net.redirect("https://127.0.0.1:8443/start", target)
    net.add(target, 200, "plain")
    cli(
        entry,
        "https://127.0.0.1:8443/start",
        "--cookie",
        "s=1",
        "--authorization",
        "Bearer t",
    )
    (hit,) = [hit for hit in net.hits if hit.url == target]
    return hit


@pytest.mark.parametrize("entry", [redirect.main, decode.main])
@pytest.mark.parametrize("target", DOWNGRADE_TARGETS)
def test_redirect_and_decode_credentials_never_follow_a_scheme_or_port_change(
    ws, net, cli, entry, target
):
    net.redirect("https://127.0.0.1:8443/start", target)
    net.add(target, 200, "plain")
    cli(
        entry,
        "https://127.0.0.1:8443/start",
        "--cookie",
        "s=1",
        "--authorization",
        "Bearer t",
    )
    follow_ups = [hit for hit in net.hits if hit.url == target]
    assert follow_ups and all(
        "cookie" not in hit.headers and "authorization" not in hit.headers
        for hit in follow_ups
    )


@pytest.mark.parametrize("entry", [redirect.main, decode.main])
def test_redirect_and_decode_credentials_follow_a_same_origin_redirect(
    ws, net, cli, entry
):
    hit = credentialed_follow_up(net, entry, "https://127.0.0.1:8443/next", cli)
    assert hit.headers["cookie"] == "s=1" and hit.headers["authorization"] == "Bearer t"


# ---- decode ---------------------------------------------------------------------------------------------


def test_decode_defect_correct_text_that_follows_a_decoded_block_survives():
    assert (
        decode.unfold(f"before {ENC}\nnext line").text
        == f"before {SENTENCE}\nnext line"
    )


def test_decode_defect_correct_a_block_followed_by_a_word_is_still_decoded():
    assert decode.unfold(f"before {ENC} after").text == f"before {SENTENCE} after"


# ---- silk -----------------------------------------------------------------------------------------------

MALFORMED_LINKS = [
    "http://127.0.0.1:abc/x",
    "http://[bad/x",
    "http://127.0.0.1:99999/x",
]


@pytest.mark.parametrize("href", MALFORMED_LINKS)
def test_silk_defect_correct_a_malformed_link_is_skipped_and_the_crawl_continues(
    ws, net, href
):
    net.html(LOOP + "/", f'<a href="{href}">bad</a><a href="/ok">ok</a>')
    try:
        result = crawl(net, depth=0)
    except ValueError:
        result = None
    assert result is not None and LOOP + "/ok" in listed(result)


def test_silk_defect_pinned_current_a_start_url_with_a_malformed_authority_raises(
    ws, net
):
    with pytest.raises(ValueError):
        silk.main(["http://127.0.0.1:abc/"])
    with pytest.raises(ValueError):
        silk.canonicalize("http://[bad/")
    with pytest.raises(ValueError):
        silk.origin_key("http://h:abc/")


def base_href_site(net):
    net.html(
        LOOP + "/",
        '<base href="http://127.0.0.1:9999/z/"><a href="p">x</a><a href="http://127.0.0.1:8080/ok">ok</a>',
    )


def test_silk_foreign_base_excludes_foreign_urls_and_keeps_start_origin_urls(ws, net):
    base_href_site(net)
    result = crawl(net, depth=2)
    assert listed(result) == [LOOP + "/", LOOP + "/ok"]
    assert (result.off_host, result.left_server) == (1, 0)
    assert not any(":9999" in url for url in net.urls())


def test_silk_results_never_leave_the_start_origin(ws, net):
    base_href_site(net)
    result = crawl(net, depth=0)
    assert all(silk.origin_key(url) == ORIGIN for url in listed(result))


@pytest.mark.parametrize(
    "foreign_base",
    [
        "http://127.0.0.1:9999/z/",
        "https://127.0.0.1:8080/z/",
        "http://localhost:8080/z/",
    ],
)
def test_silk_foreign_base_only_keeps_explicit_start_origin_references(
    ws, net, foreign_base
):
    assert silk.allowed(foreign_base)
    net.html(
        LOOP + "/",
        f'<base href="{foreign_base}"><a href="p">foreign</a><a href="{LOOP}/ok">ok</a>',
    )
    result = crawl(net, depth=1)
    assert listed(result) == [LOOP + "/", LOOP + "/ok"]
    assert result.off_host == 1
    assert LOOP + "/ok" in net.urls()
    assert all(silk.origin_key(url) == ORIGIN for url in net.urls())


def test_silk_foreign_base_does_not_contaminate_stdout_save_or_workspace(ws, net, cli):
    ws.scope("127.0.0.1")
    base_href_site(net)
    destination = ws.base / "silk.txt"
    expected = [LOOP + "/", LOOP + "/ok"]
    result = cli(
        silk.main, LOOP + "/", "--plain", "--depth", "1", "--save", str(destination)
    )
    assert result.rc == 0
    assert result.out.splitlines() == expected
    assert destination.read_text(encoding="utf-8").splitlines() == expected
    assert ws.urls() == expected
    assert all(silk.origin_key(url) == ORIGIN for url in net.urls())
