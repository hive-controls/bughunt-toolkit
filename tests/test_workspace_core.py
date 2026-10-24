"""Characterization oracle for bughunt.core.workspace (M2 REST-OF-CORE).

Written BEFORE the clean-room rebuild so an implementer who never reads the
current file still has a real behavior contract. Every vector comes from the
M2 spec (Appendix A) or from running the tree this branch was cut from.

Labels used in test names:
  pinned_current_defect  the CURRENT behavior is wrong but is deliberately
                         reproduced by the rebuild (spec section 9); the matching
                         `test_defect_*` xfail states the correct behavior.
  test_defect_*          xfail(reason=...) asserting the CORRECT behavior. An
                         XPASS means the defect was fixed: delete the xfail marker
                         and its `pinned_current_defect` twin.

Isolation: every test runs against a scratch workspace through BUGHUNT_SCOPE with
a scratch cwd, never the real one.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from bughunt.core import workspace

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def ws(monkeypatch, tmp_path):
    root = tmp_path / "ws"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    monkeypatch.chdir(tmp_path)
    return root


@pytest.fixture
def header(monkeypatch, tmp_path_factory):
    """The comment-only header a fresh scope.txt gets (wording is FREE, so read it back)."""
    probe_root = tmp_path_factory.mktemp("header-probe") / "ws"
    with monkeypatch.context() as scoped:
        scoped.setenv("BUGHUNT_SCOPE", str(probe_root))
        workspace.init_workspace()
        return (probe_root / "scope.txt").read_text(encoding="utf-8")


def activate(root, *lines):
    root.mkdir(parents=True, exist_ok=True)
    (root / "scope.txt").write_text(
        "".join(line + "\n" for line in lines), encoding="utf-8"
    )


def scope_text(root):
    return (root / "scope.txt").read_text(encoding="utf-8")


def tree(root):
    return sorted(
        str(path.relative_to(root)).replace("\\", "/") for path in root.rglob("*")
    )


# --------------------------------------------------------------------------
# directory resolution and accessors (spec 3.2, A.1)
# --------------------------------------------------------------------------


def test_default_workspace_is_dot_bughunt_under_cwd(monkeypatch, tmp_path):
    monkeypatch.delenv("BUGHUNT_SCOPE", raising=False)
    monkeypatch.chdir(tmp_path)
    resolved = workspace.workspace_dir()
    assert resolved == Path.cwd() / ".bughunt"
    assert resolved.is_absolute()


def test_blank_override_falls_back_to_the_default(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("BUGHUNT_SCOPE", raising=False)
    default = workspace.workspace_dir()
    monkeypatch.setenv("BUGHUNT_SCOPE", "   ")
    assert workspace.workspace_dir() == default


def test_relative_override_is_stripped_and_left_unresolved(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BUGHUNT_SCOPE", " rel-dir ")
    resolved = workspace.workspace_dir()
    assert resolved == Path("rel-dir")
    assert not resolved.is_absolute()


def test_override_expands_the_home_directory(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("BUGHUNT_SCOPE", "~/xx")
    resolved = workspace.workspace_dir()
    assert "~" not in str(resolved)
    assert resolved == home / "xx"


def test_directory_follows_environment_and_cwd_at_call_time(monkeypatch, tmp_path):
    first, second = tmp_path / "one", tmp_path / "two"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(first))
    assert workspace.workspace_dir() == first
    monkeypatch.setenv("BUGHUNT_SCOPE", str(second))
    assert workspace.workspace_dir() == second
    monkeypatch.delenv("BUGHUNT_SCOPE")
    for name in ("cwd-a", "cwd-b"):
        (tmp_path / name).mkdir()
        monkeypatch.chdir(tmp_path / name)
        assert workspace.workspace_dir() == Path.cwd() / ".bughunt"


def test_accessors_name_the_fixed_children_and_touch_nothing(ws):
    root = workspace.workspace_dir()
    assert workspace.scope_path() == root / "scope.txt"
    assert workspace.urls_path() == root / "urls.txt"
    assert workspace.requests_dir() == root / "requests"
    assert workspace.responses_dir() == root / "responses"
    assert workspace.samples_dir() == root / "samples"
    assert (
        workspace.urls_path().name,
        workspace.requests_dir().name,
        workspace.responses_dir().name,
    ) == ("urls.txt", "requests", "responses")
    assert not ws.exists()


# --------------------------------------------------------------------------
# scope_is_active / init_workspace / read_entries (spec 3.4, A.1)
# --------------------------------------------------------------------------


def test_scope_is_active_needs_a_regular_file(ws):
    assert workspace.scope_is_active() is False
    ws.mkdir(parents=True)
    (ws / "scope.txt").mkdir()
    assert workspace.scope_is_active() is False
    (ws / "scope.txt").rmdir()
    (ws / "scope.txt").write_text("", encoding="utf-8")
    assert workspace.scope_is_active() is True


def test_init_creates_exactly_the_documented_tree(ws):
    returned = workspace.init_workspace()
    assert returned == ws
    assert tree(ws) == ["requests", "scope.txt", "urls.txt"]
    assert (ws / "urls.txt").stat().st_size == 0
    assert workspace.scope_is_active() is True


def test_init_creates_missing_parent_directories(monkeypatch, tmp_path):
    deep = tmp_path / "a" / "b" / "c"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(deep))
    assert workspace.init_workspace() == deep
    assert (deep / "requests").is_dir()


def test_init_header_is_comment_only_and_adds_no_entries(ws):
    workspace.init_workspace()
    lines = [line for line in scope_text(ws).splitlines() if line.strip()]
    assert lines
    assert all(line.lstrip().startswith("#") for line in lines)
    assert workspace.read_entries() == []


def test_init_leaves_existing_files_alone_even_when_empty(ws):
    ws.mkdir(parents=True)
    (ws / "scope.txt").write_text("", encoding="utf-8")
    (ws / "urls.txt").write_text("http://kept.example/\n", encoding="utf-8")
    workspace.init_workspace()
    workspace.init_workspace()
    assert scope_text(ws) == ""
    assert (ws / "urls.txt").read_text(encoding="utf-8") == "http://kept.example/\n"


def test_init_is_idempotent(ws):
    workspace.init_workspace()
    before = (ws / "scope.txt").read_bytes()
    workspace.init_workspace()
    assert (ws / "scope.txt").read_bytes() == before
    assert tree(ws) == ["requests", "scope.txt", "urls.txt"]


def test_read_entries_is_empty_without_a_scope_file(ws):
    assert workspace.read_entries() == []
    ws.mkdir(parents=True)
    (ws / "scope.txt").mkdir()
    assert workspace.read_entries() == []


def test_read_entries_strips_skips_comments_and_keeps_case_and_duplicates(ws):
    ws.mkdir(parents=True)
    (ws / "scope.txt").write_text(
        "# my own note\nKeep.Example\n\n   *.Wild.Example  \n  # indented comment\n"
        "Keep.Example\nhost.example # not a comment\n",
        encoding="utf-8",
    )
    assert workspace.read_entries() == [
        "Keep.Example",
        "*.Wild.Example",
        "Keep.Example",
        "host.example # not a comment",
    ]


def test_read_entries_accepts_crlf_and_replaces_invalid_utf8(ws):
    ws.mkdir(parents=True)
    (ws / "scope.txt").write_bytes(
        b"a.example\r\n# c\r\nb.example\r\n\xffbad.example\n"
    )
    entries = workspace.read_entries()
    assert entries[:2] == ["a.example", "b.example"]
    assert len(entries) == 3 and entries[2].endswith("bad.example")


# --------------------------------------------------------------------------
# normalize_entry (spec 3.4, A.2)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token, expected",
    [
        ("Example.COM.", "example.com"),
        ("a.example...", "a.example"),
        ("  pad.example  ", "pad.example"),
        ("http://Foo.Example:8080/x", "foo.example"),
        ("ftp://x.example", "x.example"),
        ("http://[::1]:80/", "::1"),
        ("http://user:pw@Host.Example:81/p?q=1#f", "host.example"),
        ("https://Trailing.Example./", "trailing.example"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("10.0.0.5/8", "10.0.0.0/8"),
        ("2001:DB8::/32", "2001:db8::/32"),
        ("*.Example.com", "*.example.com"),
        ("::1", "::1"),
        ("HOST:80", "host:80"),
    ],
)
def test_normalize_entry_vectors(token, expected):
    assert workspace.normalize_entry(token) == expected


def test_defect_bracketed_ipv6_entry_should_match_its_host():
    assert workspace.matches("::1", [workspace.normalize_entry("[::1]")])


@pytest.mark.parametrize(
    "token",
    ["", "   ", "a b", "a\tb", "https://", "10.0.0.5/33", "foo/bar", "http://[::1"],
)
def test_normalize_entry_rejects_with_value_error(token):
    with pytest.raises(ValueError):
        workspace.normalize_entry(token)


@pytest.mark.parametrize(
    "token", [" a b ", "a\tb", "https://", " 10.0.0.5/33 ", "foo/bar"]
)
def test_normalize_entry_error_shows_the_original_token(token):
    with pytest.raises(ValueError) as caught:
        workspace.normalize_entry(token)
    assert repr(token) in str(caught.value)


def test_normalize_entry_failure_kinds_read_differently():
    def message(token):
        with pytest.raises(ValueError) as caught:
            workspace.normalize_entry(token)
        return str(caught.value).replace(repr(token), "")

    texts = {message("a b"), message("https://"), message("10.0.0.5/33")}
    assert len(texts) == 3
    assert message("foo/bar") == message("10.0.0.5/33")


# --------------------------------------------------------------------------
# add_entries / remove_entries (spec 3.4, A.2)
# --------------------------------------------------------------------------


def test_add_entries_spec_vector_and_file_rewrite(ws, header):
    ws.mkdir(parents=True)
    (ws / "scope.txt").write_text(
        "# my own note\nKeep.Example\n\n  *.Wild.Example  \n", encoding="utf-8"
    )
    result = workspace.add_entries(
        [
            "keep.example",
            "New.Example.",
            "new.example",
            "http://Url.Example:81/p",
            "10.9.8.7/8",
        ]
    )
    assert result == (
        ["new.example", "url.example", "10.0.0.0/8"],
        ["keep.example", "new.example"],
    )
    assert scope_text(ws) == (
        header + "Keep.Example\n*.Wild.Example\nnew.example\nurl.example\n10.0.0.0/8\n"
    )
    assert "my own note" not in scope_text(ws)


def test_add_entries_on_a_fresh_workspace_initializes_it(ws, header):
    assert workspace.add_entries(["Fresh.Example"]) == (["fresh.example"], [])
    assert tree(ws) == ["requests", "scope.txt", "urls.txt"]
    assert scope_text(ws) == header + "fresh.example\n"


def test_add_entries_reports_the_normalized_value_not_the_stored_text(ws):
    activate(ws, "Keep.Example")
    assert workspace.add_entries(["KEEP.example."]) == ([], ["keep.example"])
    assert workspace.read_entries() == ["Keep.Example"]


def test_add_entries_rewrites_even_when_nothing_is_added(ws, header):
    ws.mkdir(parents=True)
    (ws / "scope.txt").write_text("# note\nKeep.Example\n", encoding="utf-8")
    assert workspace.add_entries(["keep.example"]) == ([], ["keep.example"])
    assert scope_text(ws) == header + "Keep.Example\n"
    assert workspace.add_entries([]) == ([], [])
    assert scope_text(ws) == header + "Keep.Example\n"


def test_add_entries_failed_batch_changes_no_entries(ws):
    activate(ws, "first.example")
    before = (ws / "scope.txt").read_bytes()
    with pytest.raises(ValueError):
        workspace.add_entries(["ok1.example", "bad token"])
    assert workspace.read_entries() == ["first.example"]
    assert (ws / "scope.txt").read_bytes() == before


def test_add_entries_initializes_before_validating(ws):
    with pytest.raises(ValueError):
        workspace.add_entries(["bad token"])
    assert workspace.scope_is_active() is True
    assert workspace.read_entries() == []


def test_remove_entries_inactive_scope_touches_nothing_and_skips_validation(ws):
    assert workspace.remove_entries(["a.example", " b.example ", "  "]) == (
        [],
        ["a.example", "b.example"],
    )
    assert workspace.remove_entries(["a b"]) == ([], ["a b"])
    assert workspace.remove_entries([]) == ([], [])
    assert not ws.exists()


def test_remove_entries_spec_vector(ws):
    activate(
        ws, "Keep.Example", "*.Wild.Example", "new.example", "url.example", "10.0.0.0/8"
    )
    removed, missing = workspace.remove_entries(
        ["NEW.example", "nothere.example", "10.1.1.1/8"]
    )
    assert (removed, missing) == (["new.example", "10.0.0.0/8"], ["nothere.example"])
    assert workspace.read_entries() == ["Keep.Example", "*.Wild.Example", "url.example"]


def test_remove_entries_returns_stored_case_every_duplicate_and_url_hosts(ws):
    activate(ws, "A.example", "b.example", "a.EXAMPLE", "c.example")
    removed, missing = workspace.remove_entries(
        ["a.example", "http://C.Example:8080/p"]
    )
    assert removed == ["A.example", "a.EXAMPLE", "c.example"]
    assert missing == []
    assert workspace.read_entries() == ["b.example"]


def test_remove_entries_missing_keeps_the_original_stripped_token(ws):
    activate(ws, "a.example")
    assert workspace.remove_entries(["  NoThere.Example.  "]) == (
        [],
        ["NoThere.Example."],
    )


def test_remove_entries_rewrites_even_when_nothing_matches(ws, header):
    ws.mkdir(parents=True)
    (ws / "scope.txt").write_text("# note\nkeep.example\n", encoding="utf-8")
    assert workspace.remove_entries(["other.example"]) == ([], ["other.example"])
    assert scope_text(ws) == header + "keep.example\n"
    assert workspace.remove_entries([]) == ([], [])


def test_remove_entries_validation_failure_changes_nothing(ws):
    ws.mkdir(parents=True)
    (ws / "scope.txt").write_text("# note\nkeep.example\n", encoding="utf-8")
    before = (ws / "scope.txt").read_bytes()
    with pytest.raises(ValueError):
        workspace.remove_entries(["keep.example", "a b"])
    assert (ws / "scope.txt").read_bytes() == before


def test_scope_round_trip_writes_platform_newlines_only(ws):
    workspace.add_entries(["one.example", "two.example"])
    raw = (ws / "scope.txt").read_bytes()
    assert b"\n" in raw
    assert raw.replace(os.linesep.encode(), b"").count(b"\n") == 0
    assert workspace.read_entries() == ["one.example", "two.example"]


# --------------------------------------------------------------------------
# read_urls / remember_urls (spec 3.4, A.1)
# --------------------------------------------------------------------------


def test_read_urls_is_empty_without_a_file(ws):
    assert workspace.read_urls() == []


def test_read_urls_strips_skips_comments_and_keeps_duplicates(ws):
    ws.mkdir(parents=True)
    (ws / "urls.txt").write_bytes(
        b"http://a/\r\n# note\r\n\r\n  http://b/  \r\n   # c\r\nhttp://a/\r\n"
    )
    assert workspace.read_urls() == ["http://a/", "http://b/", "http://a/"]


def test_remember_urls_without_scope_creates_nothing(ws):
    assert workspace.remember_urls(["http://x/"]) == 0
    assert not ws.exists()


def test_remember_urls_without_scope_leaves_an_existing_workspace_alone(ws):
    ws.mkdir(parents=True)
    (ws / "urls.txt").write_text("http://old/\n", encoding="utf-8")
    assert workspace.remember_urls(["http://x/"]) == 0
    assert tree(ws) == ["urls.txt"]
    assert (ws / "urls.txt").read_text(encoding="utf-8") == "http://old/\n"


def test_remember_urls_appends_new_in_order_and_skips_known(ws):
    activate(ws)
    (ws / "urls.txt").write_text("http://old/\n", encoding="utf-8")
    assert workspace.remember_urls(["http://new1/", "http://old/", "http://new2/"]) == 2
    assert workspace.read_urls() == ["http://old/", "http://new1/", "http://new2/"]


def test_remember_urls_with_nothing_new_returns_zero_and_writes_nothing(ws):
    activate(ws)
    (ws / "urls.txt").write_bytes(b"http://old/\n")
    assert workspace.remember_urls(["http://old/"]) == 0
    assert workspace.remember_urls([]) == 0
    assert (ws / "urls.txt").read_bytes() == b"http://old/\n"


def test_remember_urls_initializes_the_workspace_when_scope_is_active(ws):
    ws.mkdir(parents=True)
    (ws / "scope.txt").write_text("a.example\n", encoding="utf-8")
    assert workspace.remember_urls(["http://x/"]) == 1
    assert (ws / "requests").is_dir()
    assert workspace.read_urls() == ["http://x/"]
    assert workspace.read_entries() == ["a.example"]


def test_remember_urls_pinned_current_defect_compares_verbatim_and_appends_unstripped(
    ws,
):
    activate(ws)
    (ws / "urls.txt").write_text("http://x/\n", encoding="utf-8")
    assert workspace.remember_urls(["  http://x/  ", ""]) == 2
    assert workspace.read_urls() == ["http://x/", "http://x/"]


def test_defect_batch_duplicates_should_be_written_and_counted_once(ws):
    activate(ws)
    assert workspace.remember_urls(["http://x/", "http://x/"]) == 1
    assert workspace.read_urls() == ["http://x/"]


def test_defect_append_after_unterminated_last_line_should_start_a_new_line(ws):
    activate(ws)
    (ws / "urls.txt").write_bytes(b"http://a/")
    assert workspace.remember_urls(["http://b/"]) == 1
    assert workspace.read_urls() == ["http://a/", "http://b/"]


# --------------------------------------------------------------------------
# save_request (spec 3.4, A.1)
# --------------------------------------------------------------------------


def test_save_request_requires_an_active_scope(ws):
    with pytest.raises(ValueError) as caught:
        workspace.save_request("a", b"x")
    assert "scope init" in str(caught.value)
    assert not ws.exists()


@pytest.mark.parametrize(
    "name, saved_as",
    [
        ("plain.http", "plain.http"),
        ("../evil", "evil"),
        ("a/b/c.http", "c.http"),
        ("dir/", "dir"),
        ("./up", "up"),
    ],
)
def test_save_request_keeps_only_the_final_path_component(ws, name, saved_as):
    activate(ws)
    path = workspace.save_request(name, b"payload")
    assert path == workspace.requests_dir() / saved_as
    assert path.read_bytes() == b"payload"
    assert tree(ws) == sorted(
        ["requests", f"requests/{saved_as}", "scope.txt", "urls.txt"]
    )


@pytest.mark.parametrize("name", ["", ".", "..", "dir/..", "/"])
def test_save_request_rejects_names_without_a_file_component(ws, name):
    activate(ws)
    with pytest.raises(ValueError):
        workspace.save_request(name, b"x")
    requests = workspace.requests_dir()
    assert not requests.exists() or not list(requests.iterdir())


@pytest.mark.skipif(
    sys.platform != "win32", reason="spec D6: backslash separates only on Windows"
)
def test_save_request_windows_drive_path_keeps_the_last_component(ws):
    activate(ws)
    assert workspace.save_request("C:\\x\\y", b"1") == workspace.requests_dir() / "y"


def test_save_request_backslash_names_never_escape_the_requests_directory(ws):
    activate(ws)
    path = workspace.save_request("..\\evil", b"1")
    assert path.parent == workspace.requests_dir()


def test_save_request_overwrites_writes_exact_bytes_and_initializes(ws):
    ws.mkdir(parents=True)
    (ws / "scope.txt").write_text("keep.example\n", encoding="utf-8")
    first = workspace.save_request("req.http", b"GET / HTTP/1.1\r\n\r\n\x00\xff")
    assert first.read_bytes() == b"GET / HTTP/1.1\r\n\r\n\x00\xff"
    second = workspace.save_request("req.http", b"short")
    assert second == first and second.read_bytes() == b"short"
    assert (ws / "urls.txt").exists()
    assert workspace.read_entries() == ["keep.example"]


# --------------------------------------------------------------------------
# hostname_of / split_host / is_loopback (spec 3.4, A.3)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target, expected",
    [
        ("a.example", "a.example"),
        ("http://A.Example:80/x?y", "a.example"),
        ("a.example:80", "a.example"),
        ("a.example:80/path", "a.example"),
        ("[::1]:80", "::1"),
        ("[::1]", "::1"),
        ("[::1", "[::1"),
        ("::1", "::1"),
        ("", ""),
        ("  ", ""),
        ("http://", ""),
        ("HTTP://UP.example./", "up.example"),
        ("a.example.", "a.example"),
        ("1.2.3.4:5", "1.2.3.4"),
    ],
)
def test_hostname_of_vectors(target, expected):
    assert workspace.hostname_of(target) == expected


def test_hostname_of_malformed_bracketed_url_raises_value_error():
    with pytest.raises(ValueError):
        workspace.hostname_of("http://[::1")


def test_hostname_of_scheme_less_text_keeps_userinfo():
    assert workspace.hostname_of("user@h.example") == "user@h.example"


def test_defect_scheme_less_hostname_should_drop_the_path():
    assert workspace.hostname_of("a.example/path") == "a.example"


def test_defect_scheme_less_target_with_path_should_be_allowed(ws):
    activate(ws, "in.example")
    assert workspace.allowed("in.example/path") is True


@pytest.mark.parametrize(
    "value, expected",
    [
        ("[::1]:80", ("::1", "80")),
        ("[::1]", ("::1", None)),
        ("[::1", ("[::1", None)),
        ("[::1]:", ("::1", None)),
        ("a:b", ("a", "b")),
        ("a:", ("a", None)),
        (":80", ("", "80")),
        ("::1", ("::1", None)),
        ("", ("", None)),
        ("a:b:c", ("a:b:c", None)),
        (" a:1 ", ("a", "1")),
        ("[a]x", ("a", None)),
        ("bare.example", ("bare.example", None)),
    ],
)
def test_split_host_vectors(value, expected):
    assert workspace.split_host(value) == expected


@pytest.mark.parametrize(
    "host", ["localhost", "LOCALHOST.", "127.0.0.1", "127.9.9.9", "::1"]
)
def test_is_loopback_true(host):
    assert workspace.is_loopback(host) is True


@pytest.mark.parametrize("host", ["[::1]", "0.0.0.0", "foo.localhost", "1.2.3.4", ""])
def test_is_loopback_false(host):
    assert workspace.is_loopback(host) is False


# --------------------------------------------------------------------------
# matches: the rule ladder (spec 3.4, A.4)
# --------------------------------------------------------------------------

LADDER = [
    # rule 1: CIDR, host must be an IP of the same family inside the network
    ("10.2.3.4", ["10.0.0.0/8"], True),
    ("10.0.0.0", ["10.0.0.0/8"], True),
    ("10.255.255.255", ["10.0.0.0/8"], True),
    ("11.2.3.4", ["10.0.0.0/8"], False),
    ("10.2.3.4", ["10.0.0.5/8"], True),
    ("2001:db8::1", ["2001:db8::/32"], True),
    ("2001:db9::1", ["2001:db8::/32"], False),
    ("::1", ["10.0.0.0/8"], False),
    ("10.0.0.1", ["2001:db8::/32"], False),
    ("example.com", ["10.0.0.0/8"], False),
    ("10.0.0.0.example", ["10.0.0.0/8"], False),
    ("10.0.0.0", ["10.0.0.0/33"], False),
    # rule 2: IP entry or IP host means exact text equality only
    ("192.0.2.7", ["192.0.2.7"], True),
    ("192.0.2.7.", ["192.0.2.7"], True),
    ("192.0.2.77", ["192.0.2.7"], False),
    ("sub.192.0.2.7", ["192.0.2.7"], False),
    ("::1", ["::1"], True),
    ("0:0:0:0:0:0:0:1", ["::1"], False),
    ("1.2.3.4", ["3.4"], False),
    ("1.2.3.4", ["example.com"], False),
    # rule 3: wildcard is subdomains only
    ("x.wild.example", ["*.wild.example"], True),
    ("a.b.wild.example", ["*.wild.example"], True),
    ("X.WILD.EXAMPLE.", ["*.Wild.Example."], True),
    ("wild.example", ["*.wild.example"], False),
    ("xwild.example", ["*.wild.example"], False),
    ("anything.example", ["*."], False),
    # rule 4: domain includes its subdomains, on a label boundary
    ("example.com", ["example.com"], True),
    ("A.Example.Com.", ["example.com"], True),
    ("sub.example.com", ["example.com"], True),
    ("notexample.com", ["example.com"], False),
    ("example.com.evil.net", ["example.com"], False),
    ("com", ["example.com"], False),
    # entry hygiene: stripped, lowercased, trailing dots dropped; blanks and comments skipped
    ("spaced.example", ["  Spaced.Example.  "], True),
    ("x.spaced.example", ["  Spaced.Example.  "], True),
    ("comment.example", ["#comment.example"], False),
    ("foo", [""], False),
    ("foo", ["   "], False),
    ("foo", ["foo/bar"], False),
    ("", [""], False),
    ("", ["example.com"], False),
    # list semantics
    ("b.example", ["a.example", "b.example"], True),
    ("a.example", [], False),
]


@pytest.mark.parametrize("host, entries, expected", LADDER)
def test_matches_rule_ladder(host, entries, expected):
    assert workspace.matches(host, entries) is expected


SPEC_ENTRIES = [
    "example.com",
    "*.wild.example",
    "10.0.0.0/8",
    "2001:db8::/32",
    "192.0.2.7",
    "::1",
    "#comment.example",
    "  Spaced.Example.  ",
    "*.",
    "foo/bar",
    "",
]


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "A.Example.Com.",
        "sub.example.com",
        "x.wild.example",
        "10.2.3.4",
        "192.0.2.7",
        "2001:db8::1",
        "::1",
        "spaced.example",
        "x.spaced.example",
    ],
)
def test_matches_spec_entry_list_true(host):
    assert workspace.matches(host, SPEC_ENTRIES) is True


@pytest.mark.parametrize(
    "host",
    [
        "notexample.com",
        "wild.example",
        "11.2.3.4",
        "192.0.2.77",
        "sub.192.0.2.7",
        "2001:db9::1",
        "0:0:0:0:0:0:0:1",
        "comment.example",
        "foo",
        "10.0.0.0.example",
    ],
)
def test_matches_spec_entry_list_false(host):
    assert workspace.matches(host, SPEC_ENTRIES) is False


def test_matches_is_pure_no_loopback_exemption_no_scope_file(ws):
    assert workspace.matches("127.0.0.1", []) is False
    assert workspace.matches("localhost", ["example.com"]) is False
    assert not ws.exists()


def test_matches_requires_a_string_host():
    with pytest.raises(AttributeError):
        workspace.matches(None, ["example.com"])


# --------------------------------------------------------------------------
# allowed / explain_block (spec 3.4, A.4)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "localhost",
        "127.0.0.1",
        "http://[::1]:8/",
        "::1",
        "[::1]:80",
        "http://localhost:99/",
        "LOCALHOST",
        "127.9.9.9:8080",
    ],
)
def test_allowed_loopback_needs_no_scope_file(ws, target):
    assert workspace.allowed(target) is True
    assert not ws.exists()


@pytest.mark.parametrize(
    "target", ["foo.example", "", "   ", "http://", "0.0.0.0", "foo.localhost"]
)
def test_allowed_denies_without_a_scope_file(ws, target):
    assert workspace.allowed(target) is False


def test_allowed_loopback_stays_allowed_when_the_scope_file_omits_it(ws):
    activate(ws, "in.example")
    assert workspace.allowed("127.0.0.1") is True
    assert workspace.allowed("localhost:8080") is True
    assert workspace.allowed("0.0.0.0") is False


@pytest.mark.parametrize(
    "target",
    [
        "in.example",
        "IN.Example",
        "sub.in.example:80",
        "http://in.example/x",
        "10.1.1.1",
        "https://10.1.1.1:9/",
        "http://SUB.in.example./p",
    ],
)
def test_allowed_true_for_listed_targets(ws, target):
    activate(ws, "in.example", "10.0.0.0/8")
    assert workspace.allowed(target) is True


@pytest.mark.parametrize(
    "target",
    [
        "out.example",
        "evil-in.example",
        "11.1.1.1",
        "",
        "http://",
        "http://out.example/in.example",
    ],
)
def test_allowed_false_for_unlisted_targets(ws, target):
    activate(ws, "in.example", "10.0.0.0/8")
    assert workspace.allowed(target) is False


def test_allowed_accepts_bracketed_ipv6_with_port_against_a_cidr(ws):
    activate(ws, "2001:db8::/32")
    assert workspace.allowed("[2001:db8::1]:443") is True
    assert workspace.allowed("http://[2001:db9::1]/") is False


def test_allowed_ignores_commented_entries_and_reads_the_file_every_call(ws):
    activate(ws, "# comment.example")
    assert workspace.allowed("comment.example") is False
    workspace.add_entries(["comment.example"])
    assert workspace.allowed("comment.example") is True
    workspace.remove_entries(["comment.example"])
    assert workspace.allowed("comment.example") is False


def test_allowed_empty_scope_file_is_active_and_denies_everything_but_loopback(ws):
    activate(ws)
    assert workspace.allowed("foo.example") is False
    assert workspace.allowed("::1") is True


def test_allowed_raises_only_for_a_malformed_bracketed_url(ws):
    with pytest.raises(ValueError):
        workspace.allowed("http://[::1")


def test_explain_block_without_a_scope_file_names_host_and_both_commands(ws):
    text = workspace.explain_block("foo.example")
    lines = text.splitlines()
    assert isinstance(text, str) and len(lines) >= 2
    assert "foo.example" in lines[0]
    stripped = [line.strip() for line in lines]
    assert "bughunt scope init" in stripped
    assert "bughunt scope add foo.example" in stripped
    for command in ("bughunt scope init", "bughunt scope add foo.example"):
        assert next(line for line in lines if line.strip() == command) != command


def test_explain_block_with_a_scope_file_offers_only_add(ws):
    activate(ws, "in.example")
    text = workspace.explain_block("foo.example")
    stripped = [line.strip() for line in text.splitlines()]
    assert "foo.example" in text.splitlines()[0]
    assert "bughunt scope add foo.example" in stripped
    assert "scope init" not in text


def test_explain_block_substitutes_the_host_verbatim(ws):
    text = workspace.explain_block("[bold]Odd.Host:8080")
    assert "bughunt scope add [bold]Odd.Host:8080" in text


# --------------------------------------------------------------------------
# import contract (spec 2.1): no import-time effects, no bughunt imports
# --------------------------------------------------------------------------


def test_importing_workspace_has_no_effects_and_pulls_in_no_other_bughunt_module(
    tmp_path,
):
    probe = (
        "import os, sys\n"
        f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "before = set(os.listdir('.'))\n"
        "import bughunt.core.workspace\n"
        "assert set(os.listdir('.')) == before, 'import created files'\n"
        "extra = sorted(name for name in sys.modules if name.startswith('bughunt')\n"
        "               and name not in ('bughunt', 'bughunt.core', 'bughunt.core.workspace'))\n"
        "assert not extra, extra\n"
    )
    env = {key: value for key, value in os.environ.items() if key != "BUGHUNT_SCOPE"}
    done = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
