"""Characterization oracle for bughunt.core.session (M2 REST-OF-CORE).

Written BEFORE the clean-room rebuild. Vectors are the M2 spec (section 4, A.5)
plus runs of the tree this branch was cut from. Naming conventions are the same
as tests/test_workspace_core.py: `pinned_current_defect` reproduces a known
defect on purpose, `test_defect_*` is an xfail asserting the correct behavior.

Named-actor behavior goes through the real identity module (create_profile,
use_profile, set_credential); nothing here patches workspace/session/http.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from bughunt.core import identity, session

REPO_ROOT = Path(__file__).resolve().parents[1]
ORIGINS = ["https://allowed.example"]
SAVED = {"cookie": "a=1; b=2", "authorization": "Bearer t"}


@pytest.fixture
def ws(monkeypatch, tmp_path):
    root = tmp_path / "ws"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    monkeypatch.chdir(tmp_path)
    return root


def session_file(root):
    return root / "session.txt"


def write_raw(root, text):
    root.mkdir(parents=True, exist_ok=True)
    session_file(root).write_text(text, encoding="utf-8")


def make_actor(name, kind="owner", cookie=None, authorization=None):
    identity.create_profile(name, kind, ORIGINS, owned=True)
    if cookie:
        identity.set_credential(name, "cookie", cookie)
    if authorization:
        identity.set_credential(name, "authorization", authorization)


def corrupt_selected_actor(root):
    make_actor("owner", cookie="session=o")
    identity.use_profile("owner")
    (root / "identities" / "owner.json").write_text("{not json", encoding="utf-8")


# --------------------------------------------------------------------------
# session_path (spec 4.2)
# --------------------------------------------------------------------------


def test_session_path_default_actor_is_session_txt_and_pure(ws):
    assert session.session_path() == ws / "session.txt"
    assert not ws.exists()


def test_session_path_named_actor_is_its_profile(ws):
    make_actor("owner", cookie="session=o")
    identity.use_profile("owner")
    assert session.session_path() == ws / "identities" / "owner.json"


def test_session_path_propagates_an_unreadable_selection(ws):
    corrupt_selected_actor(ws)
    with pytest.raises(identity.IdentityError):
        session.session_path()


# --------------------------------------------------------------------------
# load_legacy_session (spec 4.2, A.5)
# --------------------------------------------------------------------------

LEGACY_SPEC_FILE = (
    "# c\n"
    "Cookie : a=b:c=d  \n"
    "AUTHORIZATION: Bearer x\n"
    "authorization:    \n"
    "noise\n"
    "other: 1\n"
    "Cookie: second=2\n"
    "\n"
    "  # indented comment\n"
)


def test_legacy_session_is_empty_without_a_file(ws):
    assert session.load_legacy_session() == {}


def test_legacy_session_spec_parse_vector(ws):
    write_raw(ws, LEGACY_SPEC_FILE)
    assert session.load_legacy_session() == {
        "cookie": "second=2",
        "authorization": "Bearer x",
    }


def test_legacy_session_later_blank_value_does_not_erase_an_earlier_one(ws):
    write_raw(ws, "authorization: Bearer x\nauthorization:   \n")
    assert session.load_legacy_session() == {"authorization": "Bearer x"}


def test_legacy_session_value_may_contain_colons_and_splits_at_the_first_colon(ws):
    write_raw(ws, "Cookie : a=b:c=d  \nauthorization: Basic dXNlcjpwdw==\n")
    assert session.load_legacy_session() == {
        "cookie": "a=b:c=d",
        "authorization": "Basic dXNlcjpwdw==",
    }


def test_legacy_session_ignores_lines_without_a_colon(ws):
    write_raw(ws, "cookie: a\nb\n")
    assert session.load_legacy_session() == {"cookie": "a"}


def test_legacy_session_keeps_only_the_two_credential_keys(ws):
    write_raw(ws, "x-api-key: k\nproxy-authorization: p\ncookie2: z\nCookie: c=1\n")
    loaded = session.load_legacy_session()
    assert loaded == {"cookie": "c=1"}
    assert set(loaded) <= {"cookie", "authorization"}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "# only a comment\n",
        "noise\n\n",
        "cookie:\nauthorization:   \n",
        "other: 1\n",
    ],
)
def test_legacy_session_is_falsy_exactly_when_no_credential_line_exists(ws, text):
    write_raw(ws, text)
    assert not session.load_legacy_session()


@pytest.mark.parametrize("text", ["cookie: c=1\n", "AUTHORIZATION: Bearer x\n"])
def test_legacy_session_is_truthy_for_a_hand_written_credential(ws, text):
    # desync and zap_active refuse a credentialed default actor on this truthiness.
    write_raw(ws, text)
    assert session.load_legacy_session()


def test_legacy_session_values_are_exactly_the_credential_texts(ws):
    write_raw(ws, "# n\ncookie:   a=1  \nauthorization: Bearer t\nother: leak\n")
    assert sorted(session.load_legacy_session().values()) == ["Bearer t", "a=1"]


def test_legacy_session_accepts_crlf_and_replaces_invalid_utf8(ws):
    ws.mkdir(parents=True)
    session_file(ws).write_bytes(b"cookie: a=1\r\n# n\r\nauthorization: tok\xff\r\n")
    loaded = session.load_legacy_session()
    assert loaded["cookie"] == "a=1"
    assert loaded["authorization"].startswith("tok")


def test_legacy_session_reads_session_txt_even_for_a_named_actor(ws):
    make_actor("owner", cookie="session=o")
    identity.use_profile("owner")
    write_raw(ws, "cookie: legacy=1\n")
    assert session.load_legacy_session() == {"cookie": "legacy=1"}


# --------------------------------------------------------------------------
# write_session: default actor (spec 4.2, A.5)
# --------------------------------------------------------------------------


def written_lines(root):
    return session_file(root).read_text(encoding="utf-8").splitlines()


def test_write_session_spec_vector_layout_and_round_trip(ws):
    session.write_session(
        {"cookie": "  a=1; b=2  ", "authorization": "Bearer t", "other": "z"}
    )
    lines = written_lines(ws)
    assert len(lines) == 4
    assert lines[0].startswith("#") and lines[1] == ""
    assert lines[2:] == ["cookie: a=1; b=2", "authorization: Bearer t"]
    assert session.load_session() == SAVED


def test_write_session_uses_platform_newlines_and_a_trailing_newline(ws):
    session.write_session(SAVED)
    raw = session_file(ws).read_bytes()
    assert raw.endswith(os.linesep.encode())
    assert raw.replace(os.linesep.encode(), b"").count(b"\n") == 0


def test_write_session_cookie_only_and_authorization_only(ws):
    session.write_session({"cookie": "c=1"})
    assert written_lines(ws)[2:] == ["cookie: c=1"]
    session.write_session({"authorization": "Bearer t"})
    assert written_lines(ws)[2:] == ["authorization: Bearer t"]


def test_write_session_order_is_fixed_cookie_first(ws):
    session.write_session({"authorization": "Basic zz", "cookie": "c=1"})
    assert written_lines(ws)[2:] == ["cookie: c=1", "authorization: Basic zz"]


def test_write_session_replaces_the_whole_file(ws):
    session.write_session(SAVED)
    session.write_session({"authorization": "Bearer new"})
    assert session.load_legacy_session() == {"authorization": "Bearer new"}


def test_write_session_creates_missing_workspace_directories(monkeypatch, tmp_path):
    deep = tmp_path / "a" / "b" / "ws"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(deep))
    session.write_session({"cookie": "c=1"})
    assert session.load_legacy_session() == {"cookie": "c=1"}


@pytest.mark.parametrize(
    "values",
    [
        {"Cookie": "A=1", "x-api-key": "k", "authorization": "   "},
        {"cookie": ""},
        {"COOKIE": "c=1", "Authorization": "Bearer t"},
        {},
    ],
)
def test_write_session_with_nothing_to_keep_creates_no_file(ws, values):
    session.write_session(values)
    assert not session_file(ws).exists()


@pytest.mark.parametrize(
    "values", [{}, {"cookie": ""}, {"cookie": "  ", "authorization": ""}]
)
def test_write_session_with_nothing_to_keep_deletes_an_existing_file(ws, values):
    session.write_session(SAVED)
    assert session_file(ws).exists()
    session.write_session(values)
    assert not session_file(ws).exists()
    assert session.load_session() == {}


def test_write_session_round_trip_contract_used_by_the_session_module(ws):
    session.write_session({"cookie": "c=1"})
    current = session.load_session()
    current["authorization"] = "Bearer new"
    session.write_session(current)
    assert session.load_session() == {"cookie": "c=1", "authorization": "Bearer new"}
    current = session.load_session()
    current.pop("cookie", None)
    session.write_session(current)
    assert session.load_session() == {"authorization": "Bearer new"}
    before = session_file(ws).read_bytes()
    session.write_session(session.load_session())
    assert session_file(ws).read_bytes() == before


# --------------------------------------------------------------------------
# write_session: line separators and candidate validation (spec D7, security)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("separator", ["\r\n", "\n", "\r"])
def test_write_session_default_actor_rejects_cr_lf_in_a_value(ws, separator):
    with pytest.raises(identity.IdentityError):
        session.write_session({"cookie": f"a=1{separator}authorization: injected"})
    assert not session_file(ws).exists()


@pytest.mark.parametrize("separator", ["\r\n", "\n", "\r"])
def test_write_session_default_actor_rejects_cr_lf_in_authorization(ws, separator):
    with pytest.raises(identity.IdentityError):
        session.write_session({"authorization": f"Bearer t{separator}cookie: x=1"})
    assert not session_file(ws).exists()


def test_named_actor_write_session_rejects_cr_and_lf(ws):
    make_actor("owner", cookie="session=o")
    identity.use_profile("owner")
    for bad in ("a=1\r\nauthorization: injected", "a=1\nb", "a=1\rb"):
        with pytest.raises(identity.IdentityError):
            session.write_session({"cookie": bad})
    assert session.load_session() == {"cookie": "session=o"}


@pytest.mark.parametrize(
    "separator",
    [
        "\r\n",
        "\r",
        "\n",
        "\v",
        "\f",
        "\x1c",
        "\x1d",
        "\x1e",
        "\x85",
        "\u2028",
        "\u2029",
    ],
)
def test_legacy_write_rejects_every_line_separator_without_changing_saved_bytes(
    ws, separator
):
    session.write_session(SAVED)
    before = session_file(ws).read_bytes()
    with pytest.raises(identity.IdentityError):
        session.write_session({"cookie": f"a=1{separator}authorization: injected"})
    assert session_file(ws).read_bytes() == before


@pytest.mark.parametrize(
    "values",
    [
        {"cookie": "replacement", "authorization": "bad\x00value"},
        {"cookie": "bad\tvalue", "authorization": "replacement"},
        {"cookie": "bad\u0100value"},
        {"authorization": "bad\u20acvalue"},
        {"cookie": 42},
    ],
)
def test_named_session_rejects_invalid_candidate_before_any_profile_write(ws, values):
    make_actor("owner", cookie="session=o", authorization="Bearer old")
    identity.set_credential("owner", "x-api-key", "existing-other-key")
    identity.use_profile("owner")
    path = session.session_path()
    before = path.read_bytes()
    profile = identity.read_profile("owner")
    with pytest.raises(identity.IdentityError):
        session.write_session(values)
    assert path.read_bytes() == before
    assert identity.read_profile("owner") == profile


def test_identity_replace_session_validates_the_whole_candidate_before_persisting(ws):
    make_actor("owner", cookie="session=o", authorization="Bearer old")
    path = ws / "identities" / "owner.json"
    before = path.read_bytes()
    with pytest.raises(identity.IdentityError):
        identity.replace_session(
            "owner", {"cookie": "replacement", "authorization": "bad\x00value"}
        )
    assert path.read_bytes() == before


@pytest.mark.parametrize("named", [False, True])
@pytest.mark.parametrize("character", ["\x84", "\xff"])
def test_session_values_keep_valid_latin1_boundary_characters(ws, named, character):
    if named:
        make_actor("owner")
        identity.use_profile("owner")
    session.write_session({"cookie": f"a{character}b"})
    assert session.load_session() == {"cookie": f"a{character}b"}


# --------------------------------------------------------------------------
# named actors (spec 4.2, A.5)
# --------------------------------------------------------------------------


def test_load_session_named_actor_reads_its_credential_headers(ws):
    make_actor("owner", cookie="session=o", authorization="Bearer o")
    make_actor("viewer", kind="lower_privilege", cookie="session=v")
    identity.use_profile("owner")
    assert session.load_session() == {
        "cookie": "session=o",
        "authorization": "Bearer o",
    }
    identity.use_profile("viewer")
    assert session.load_session() == {"cookie": "session=v"}


def test_load_session_anonymous_actor_is_empty(ws):
    make_actor("guest", kind="anonymous")
    identity.use_profile("guest")
    assert session.load_session() == {}


def test_load_session_named_actor_ignores_session_txt(ws):
    make_actor("owner", cookie="session=o")
    identity.use_profile("owner")
    write_raw(ws, "cookie: legacy=1\nauthorization: legacy\n")
    assert session.load_session() == {"cookie": "session=o"}


def test_load_session_default_actor_is_the_legacy_file(ws):
    write_raw(ws, "cookie: c=1\n")
    assert session.load_session() == session.load_legacy_session() == {"cookie": "c=1"}


def test_write_session_named_actor_updates_the_profile_and_never_session_txt(ws):
    make_actor("owner", cookie="session=o", authorization="Bearer o")
    identity.use_profile("owner")
    before = identity.read_profile("owner")["revision"]
    session.write_session({"cookie": "n=1"})
    assert session.load_session() == {"cookie": "n=1"}
    assert identity.read_profile("owner")["revision"] != before
    assert not session_file(ws).exists()


def test_write_session_named_actor_empty_values_clear_the_credentials(ws):
    make_actor("owner", cookie="session=o", authorization="Bearer o")
    identity.use_profile("owner")
    session.write_session({})
    assert session.load_session() == {}


def test_write_session_anonymous_actor_rejects_secrets_but_accepts_empty(ws):
    make_actor("guest", kind="anonymous")
    identity.use_profile("guest")
    with pytest.raises(identity.IdentityError):
        session.write_session({"cookie": "session=forbidden"})
    session.write_session({})
    session.write_session({"cookie": ""})
    assert session.load_session() == {}


def test_selecting_default_again_returns_to_session_txt(ws):
    make_actor("owner", cookie="session=o")
    identity.use_profile("owner")
    identity.use_profile("default")
    session.write_session({"cookie": "d=1"})
    assert session_file(ws).exists()
    assert session.load_session() == {"cookie": "d=1"}


# --------------------------------------------------------------------------
# apply_headers (spec 4.2, A.5): None = use saved, "" = drop, text = override
# --------------------------------------------------------------------------


@pytest.fixture
def saved(ws):
    session.write_session(SAVED)
    return SAVED


def test_apply_headers_none_uses_the_saved_session(saved):
    headers = {"X": "1"}
    merged = session.apply_headers(headers, cookie=None, authorization=None)
    assert merged == {"X": "1", "Cookie": "a=1; b=2", "Authorization": "Bearer t"}
    assert headers == {"X": "1"}
    assert merged is not headers


def test_apply_headers_returns_a_new_dict_even_when_nothing_changes(ws):
    headers = {"X": "1"}
    merged = session.apply_headers(headers, cookie=None, authorization=None)
    assert merged == {"X": "1"}
    assert merged is not headers
    merged["Y"] = "2"
    assert headers == {"X": "1"}


def test_apply_headers_text_overrides_only_that_header_and_is_stripped(saved):
    merged = session.apply_headers({"X": "1"}, cookie=" n=1 ", authorization=None)
    assert merged == {"X": "1", "Cookie": "n=1", "Authorization": "Bearer t"}
    merged = session.apply_headers({}, cookie=None, authorization="  Bearer o  ")
    assert merged == {"Cookie": "a=1; b=2", "Authorization": "Bearer o"}


def test_apply_headers_explicit_override_works_without_a_saved_session(ws):
    merged = session.apply_headers({}, cookie="c=1", authorization="Bearer o")
    assert merged == {"Cookie": "c=1", "Authorization": "Bearer o"}


def test_apply_headers_empty_or_blank_drops_the_saved_value(saved):
    merged = session.apply_headers({"X": "1"}, cookie="", authorization="  ")
    assert merged == {"X": "1"}
    merged = session.apply_headers({"X": "1"}, cookie="", authorization=None)
    assert merged == {"X": "1", "Authorization": "Bearer t"}


def test_apply_headers_empty_removes_exact_case_keys_but_not_other_casings(saved):
    merged = session.apply_headers(
        {
            "Cookie": "old",
            "Authorization": "old",
            "cookie": "kept",
            "authorization": "kept-too",
        },
        cookie="",
        authorization="",
    )
    assert merged == {"cookie": "kept", "authorization": "kept-too"}


def test_apply_headers_a_cookie_in_headers_is_dropped_unless_something_supplies_one(ws):
    merged = session.apply_headers(
        {"Cookie": "fromheaders=1", "X": "1"}, cookie=None, authorization=None
    )
    assert merged == {"X": "1"}


def test_apply_headers_a_saved_or_explicit_value_replaces_the_cookie_in_headers(saved):
    merged = session.apply_headers(
        {"Cookie": "fromheaders=1"}, cookie=None, authorization=None
    )
    assert merged["Cookie"] == "a=1; b=2"
    merged = session.apply_headers(
        {"Cookie": "fromheaders=1"}, cookie="x=9", authorization=""
    )
    assert merged == {"Cookie": "x=9"}


def test_apply_headers_none_with_nothing_saved_adds_neither(ws):
    assert session.apply_headers({"X": "1"}, cookie=None, authorization=None) == {
        "X": "1"
    }


def test_apply_headers_credentials_are_keyword_only_and_required(ws):
    with pytest.raises(TypeError):
        session.apply_headers({}, None, None)
    with pytest.raises(TypeError):
        session.apply_headers({}, cookie=None)
    with pytest.raises(TypeError):
        session.apply_headers({})


def test_apply_headers_named_actor_supplies_the_saved_values(ws):
    make_actor("owner", cookie="session=o", authorization="Bearer o")
    identity.use_profile("owner")
    write_raw(ws, "cookie: legacy=1\n")
    merged = session.apply_headers({}, cookie=None, authorization=None)
    assert merged == {"Cookie": "session=o", "Authorization": "Bearer o"}
    merged = session.apply_headers({}, cookie="", authorization="Bearer x")
    assert merged == {"Authorization": "Bearer x"}


@pytest.mark.parametrize("cookie,authorization", [(None, "y"), ("x=1", None)])
def test_apply_headers_partial_overrides_still_require_readable_saved_values(
    ws, cookie, authorization
):
    corrupt_selected_actor(ws)
    with pytest.raises(identity.IdentityError):
        session.apply_headers({}, cookie=cookie, authorization=authorization)


@pytest.mark.parametrize(
    "cookie,authorization,expected",
    [
        ("x=1", "y", {"X": "1", "Cookie": "x=1", "Authorization": "y"}),
        ("", "", {"X": "1"}),
    ],
)
def test_defect_explicit_values_should_not_need_a_readable_session(
    ws, cookie, authorization, expected
):
    corrupt_selected_actor(ws)
    merged = session.apply_headers(
        {"X": "1", "Cookie": "old", "Authorization": "old"},
        cookie=cookie,
        authorization=authorization,
    )
    assert merged == expected


def test_apply_headers_unreadable_actor_raises_when_a_saved_value_is_needed(ws):
    corrupt_selected_actor(ws)
    with pytest.raises(identity.IdentityError):
        session.apply_headers({}, cookie=None, authorization=None)


# --------------------------------------------------------------------------
# import contract (spec 2.1)
# --------------------------------------------------------------------------


def test_importing_session_has_no_effects(tmp_path):
    probe = (
        "import os, sys\n"
        f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "before = set(os.listdir('.'))\n"
        "import bughunt.core.session\n"
        "assert set(os.listdir('.')) == before, 'import created files'\n"
        "assert 'bughunt.core.http' not in sys.modules\n"
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
