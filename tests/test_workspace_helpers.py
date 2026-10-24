"""The shared helpers in bughunt.core.workspace, and the module parsers that now lean on them.

Isolation: every test that touches files runs against a scratch workspace through BUGHUNT_SCOPE.
"""

import ipaddress

import pytest

from bughunt.core import workspace
from bughunt.modules import snare


@pytest.fixture
def ws(monkeypatch, tmp_path):
    root = tmp_path / "ws"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    monkeypatch.chdir(tmp_path)
    return root


@pytest.mark.parametrize(("raw", "expected"), [
    ("Example.ORG", "example.org"),
    ("example.org.", "example.org"),
    ("example.org...", "example.org"),
    ("", ""),
    ("::1", "::1"),
    ("HOST:80", "host:80"),
])
def test_fold_host(raw, expected):
    assert workspace.fold_host(raw) == expected


@pytest.mark.parametrize(("text", "expected"), [
    ("127.0.0.1", ipaddress.ip_address("127.0.0.1")),
    ("::1", ipaddress.ip_address("::1")),
    ("2001:db8::7", ipaddress.ip_address("2001:db8::7")),
    ("example.org", None),
    ("", None),
    ("1.2.3", None),
    ("[::1]", None),
    ("10.0.0.0/8", None),
])
def test_parse_ip(text, expected):
    assert workspace.parse_ip(text) == expected


@pytest.mark.parametrize(("host", "port", "omit", "expected"), [
    ("example.org", None, (), "example.org"),
    ("example.org", 8080, (), "example.org:8080"),
    ("example.org", 443, (443,), "example.org"),
    ("example.org", 443, (80,), "example.org:443"),
    ("example.org", 80, [80, 443], "example.org"),
    ("::1", None, (), "[::1]"),
    ("::1", 8080, (), "[::1]:8080"),
    ("2001:db8::7", 443, (443,), "[2001:db8::7]"),
    ("example.org", 0, (), "example.org:0"),
    ("", None, (), ""),
])
def test_authority(host, port, omit, expected):
    assert workspace.authority(host, port, omit=omit) == expected


def test_authority_omit_is_keyword_only():
    with pytest.raises(TypeError):
        workspace.authority("example.org", 80, (80,))


@pytest.mark.parametrize(("text", "expected"), [
    ("", []),
    ("   \n\t\n", []),
    ("a\nb\n", ["a", "b"]),
    ("  a  \n\n# comment\n  # indented comment\nb", ["a", "b"]),
    ("a\r\nb\r\n#c\r\n", ["a", "b"]),
    ("a #not-a-comment\n", ["a #not-a-comment"]),
    ("#only\n", []),
])
def test_live_lines(text, expected):
    assert workspace.live_lines(text) == expected


@pytest.mark.parametrize(("target", "listed_as"), [
    ("https://Example.ORG:8443/path?q=1", "example.org"),
    ("example.org:99", "example.org"),
    ("example.org.", "example.org"),
    ("[::1]:80", "::1"),
    ("  example.org  ", "example.org"),
])
def test_explain_target_names_the_hostname(ws, target, listed_as):
    assert workspace.explain_target(target) == workspace.explain_block(listed_as)


@pytest.mark.parametrize("target", ["", "   ", "http://", "https:///only-a-path"])
def test_explain_target_falls_back_to_the_text_itself(ws, target):
    assert workspace.hostname_of(target) == ""
    assert workspace.explain_target(target) == workspace.explain_block(target)


def test_explain_target_reports_scope_state(ws):
    assert "no scope file" in workspace.explain_target("http://elsewhere.test/")
    workspace.init_workspace()
    assert "outside this engagement's scope" in workspace.explain_target("http://elsewhere.test/")


def test_read_workspace_text_is_empty_until_the_file_exists(ws):
    assert workspace.read_workspace_text("notes.txt") == ""
    ws.mkdir()
    (ws / "dir.txt").mkdir()
    assert workspace.read_workspace_text("dir.txt") == ""


def test_store_workspace_text_creates_the_folder_and_round_trips(ws):
    assert not ws.exists()
    workspace.store_workspace_text("notes.txt", "line one\nline two\n")
    assert (ws / "notes.txt").read_text(encoding="utf-8") == "line one\nline two\n"
    assert workspace.read_workspace_text("notes.txt") == "line one\nline two\n"
    workspace.store_workspace_text("notes.txt", "")
    assert (ws / "notes.txt").read_bytes() == b""


def test_store_workspace_text_none_removes_the_file_and_tolerates_absence(ws):
    workspace.store_workspace_text("notes.txt", "x\n")
    workspace.store_workspace_text("notes.txt", None)
    assert not (ws / "notes.txt").exists()
    workspace.store_workspace_text("notes.txt", None)
    workspace.store_workspace_text("never.txt", None)
    assert not (ws / "never.txt").exists()


def test_read_workspace_text_replaces_undecodable_bytes(ws):
    ws.mkdir()
    (ws / "notes.txt").write_bytes(b"ok \xff\xfe end")
    assert workspace.read_workspace_text("notes.txt") == "ok �� end"


def test_scope_and_url_lists_still_skip_comments_and_blanks(ws):
    ws.mkdir()
    (ws / "scope.txt").write_text("# header\n\n  a.test  \n*.b.test\n", encoding="utf-8")
    (ws / "urls.txt").write_text("http://a.test/1\n\n#x\n  http://a.test/2  \n", encoding="utf-8")
    assert workspace.read_entries() == ["a.test", "*.b.test"]
    assert workspace.read_urls() == ["http://a.test/1", "http://a.test/2"]


# snare's CONNECT-target parser is split_host plus a port check; these vectors fix its edge behaviour.
@pytest.mark.parametrize(("value", "expected"), [
    ("", ("", None)),
    ("host", ("host", None)),
    ("host:443", ("host", 443)),
    ("host:", ("host", None)),
    (":443", ("", 443)),
    ("host:00080", ("host", 80)),
    ("host:http", ("host", None)),
    ("  host:8443  ", ("host", 8443)),
    ("a:b:c", ("a:b:c", None)),
    ("::1", ("::1", None)),
    ("[::1]", ("::1", None)),
    ("[::1]:8443", ("::1", 8443)),
    ("[x]:", ("x", None)),
    ("[x]:99999999999999999999", ("x", 99999999999999999999)),
    ("[x]:٣", ("x", None)),
    ("[x]:80:90", ("x", None)),
    ("[", ("", None)),
    ("[x", ("", None)),
    ("[abc:80", ("", None)),
    ("[[x]:1", ("[x", 1)),
])
def test_snare_authority_parts_vectors(value, expected):
    assert snare._authority_parts(value) == expected
