"""Characterization oracle for bughunt.modules.jwt and bughunt.modules.session (M2 Wave-A, group G4).

Written BEFORE the clean-room rebuild of the two built-in modules. It pins the observable
behavior of the current tree: what comes out of each entry point for a given input, never how
it is computed. Tokens are built here with the standard library only.

Conventions (same as tests/test_session_core.py and tests/test_workspace_core.py):
  pinned_current_defect  the CURRENT behavior is wrong but is reproduced on purpose until the
                         field-fix milestone; its `test_defect_*` twin is an xfail asserting the
                         correct behavior. An XPASS means the defect was fixed: delete the xfail
                         marker and the pinned twin.
  pinned_current_quirk   current behavior that looks odd but is not clearly wrong; reproduce it.

Nothing here patches the module under test. Streams are swapped for in-memory ones (a stream
that reports isatty() is how the color and banner paths are reached); the clock is the real one
with generous margins; actors go through the real identity module.
"""

import base64
import inspect
import io
import json
import math
import socket
import sys
import time
from pathlib import Path
from typing import NamedTuple

import pytest

from bughunt import modules
from bughunt.console import options as console_options
from bughunt.core import identity, session as core_session
from bughunt.modules import jwt as jwt_module
from bughunt.modules import session as session_module

ORIGINS = ["https://allowed.example"]
FIXED_EPOCH = 1700000000
FIXED_TEXT = "2023-11-14 22:13:20Z"
CYAN, YELLOW, MAGENTA, WHITE, DIM, RESET = (
    "\x1b[1;96m",
    "\x1b[1;93m",
    "\x1b[1;95m",
    "\x1b[1;97m",
    "\x1b[2;96m",
    "\x1b[0m",
)
THREE_PARTS = "A token has three parts."
UNDECODABLE = "The token could not be decoded."
NOT_OBJECTS = "The token header and payload must be objects."
NO_AUTH_SAVED = "No Authorization value is saved."
NEED_TOKEN = "Give a token, or pass --session."
SINGLE_VALUE = "Give a single header value."
BAD_ACTOR = "Selected actor is invalid or cannot hold session credentials."

PLAIN_BANNER = (
    "          .----.\n"
    "         /  ()  \\\n"
    "        |  jwt  |\n"
    "         \\  ||  /\n"
    "          '----'\n"
    "            ||\n"
    "          [key]\n"
    "header and claims, with the signature left unchecked"
)
COLOR_BANNER = (
    f"{CYAN}          .----.{RESET}\n"
    f"{CYAN}         /  {YELLOW}({CYAN}{YELLOW}){CYAN}  \\{RESET}\n"
    f"{CYAN}        |  {MAGENTA}jwt{CYAN}  |{RESET}\n"
    f"{CYAN}         \\  ||  /{RESET}\n"
    f"{CYAN}          '----'{RESET}\n"
    f"{CYAN}            ||{RESET}\n"
    f"{CYAN}          {YELLOW}[{CYAN}key{YELLOW}]{CYAN}{RESET}\n"
    f"{DIM}header and claims, with the signature left unchecked{RESET}"
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


class Outcome(NamedTuple):
    code: object
    out: str
    err: str


class _Tty(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture(autouse=True)
def ws(monkeypatch, tmp_path):
    root = tmp_path / "ws"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    monkeypatch.chdir(tmp_path)
    return root


@pytest.fixture
def invoke(monkeypatch):
    def _invoke(module, argv, *, tty=False, term=None, no_color=None):
        out, err = (_Tty(), _Tty()) if tty else (io.StringIO(), io.StringIO())
        monkeypatch.delenv("TERM", raising=False)
        monkeypatch.delenv("NO_COLOR", raising=False)
        if term is not None:
            monkeypatch.setenv("TERM", term)
        if no_color is not None:
            monkeypatch.setenv("NO_COLOR", no_color)
        monkeypatch.setattr(sys, "stdout", out)
        monkeypatch.setattr(sys, "stderr", err)
        try:
            code = module.main(argv)
        except SystemExit as exit_request:
            code = exit_request.code
        return Outcome(code, out.getvalue(), err.getvalue())

    return _invoke


def seg(value, *, padded=False):
    raw = (
        value
        if isinstance(value, bytes)
        else json.dumps(value, separators=(",", ":")).encode()
    )
    text = base64.urlsafe_b64encode(raw).decode("ascii")
    return text if padded else text.rstrip("=")


def token(header, payload, signature="c2ln"):
    return f"{seg(header)}.{seg(payload)}.{signature}"


def future():
    return int(time.time()) + 86400


def past():
    return int(time.time()) - 86400


def good_token(**claims):
    return token(
        {"alg": "HS256", "typ": "JWT"}, {"sub": "u", "exp": future(), **claims}
    )


def make_actor(name, kind="owner", **credentials):
    identity.create_profile(name, kind, ORIGINS, owned=True)
    for header, value in credentials.items():
        identity.set_credential(name, header, value)


def select_corrupt_actor(root):
    make_actor("owner")
    identity.use_profile("owner")
    (root / "identities" / "owner.json").write_text("{not json", encoding="utf-8")


# --------------------------------------------------------------------------
# registry + public interface (cross-importer contract)
# --------------------------------------------------------------------------


def test_registry_descriptions_are_byte_identical():
    assert (
        modules.MODULES["jwt"]
        == "Inspect supplied JWT claims without authenticating the token's signature."
    )
    assert (
        modules.MODULES["session"]
        == "Store request authentication for reuse in this workspace."
    )


@pytest.mark.parametrize(
    "name,module", [("jwt", jwt_module), ("session", session_module)]
)
def test_load_builtin_resolves_each_module_to_its_importable_module(name, module):
    assert modules.load_builtin(name) is module
    assert callable(module.main) and callable(module.build_parser)


def test_console_loader_runs_both_modules_by_name(capsys):
    from bughunt.console import loader

    unused = Path("unused.py")
    assert (
        loader.run_named(
            "jwt", [good_token(), "--plain"], tool_file=unused, scan_main=None
        )
        == 0
    )
    assert capsys.readouterr().out.splitlines()[0] == "alg\tHS256"
    assert loader.run_named("session", ["show"], tool_file=unused, scan_main=None) == 0
    assert capsys.readouterr().out.startswith("No session headers saved.")
    assert loader.run_named("session", ["bogus"], tool_file=unused, scan_main=None) == 2
    assert loader.run_named("jwt", ["abc"], tool_file=unused, scan_main=None) == 2


def _shape(function):
    return [
        (p.name, p.kind.name, p.default)
        for p in inspect.signature(function).parameters.values()
    ]


def test_jwt_public_signatures():
    empty = inspect.Parameter.empty
    assert _shape(jwt_module.main) == [("argv", "POSITIONAL_OR_KEYWORD", None)]
    assert _shape(jwt_module.build_parser) == []
    assert _shape(jwt_module.decode_token) == [
        ("token", "POSITIONAL_OR_KEYWORD", empty)
    ]
    assert _shape(jwt_module.header_rows) == [
        ("header", "POSITIONAL_OR_KEYWORD", empty)
    ]
    assert _shape(jwt_module.claim_rows) == [
        ("payload", "POSITIONAL_OR_KEYWORD", empty)
    ]
    assert _shape(jwt_module.review_notes) == [
        ("header", "POSITIONAL_OR_KEYWORD", empty),
        ("payload", "POSITIONAL_OR_KEYWORD", empty),
    ]
    assert _shape(jwt_module.show_value) == [
        ("key", "POSITIONAL_OR_KEYWORD", empty),
        ("value", "POSITIONAL_OR_KEYWORD", empty),
    ]
    assert _shape(jwt_module.format_banner) == [
        ("color", "POSITIONAL_OR_KEYWORD", empty)
    ]
    assert _shape(jwt_module.format_field) == [
        ("key", "POSITIONAL_OR_KEYWORD", empty),
        ("value", "POSITIONAL_OR_KEYWORD", empty),
        ("color", "POSITIONAL_OR_KEYWORD", empty),
        ("dim", "KEYWORD_ONLY", False),
    ]


def test_session_public_signatures():
    assert _shape(session_module.main) == [("argv", "POSITIONAL_OR_KEYWORD", None)]
    assert _shape(session_module.build_parser) == []


# --------------------------------------------------------------------------
# jwt.decode_token
# --------------------------------------------------------------------------


def test_decode_token_returns_header_payload_and_a_signature_flag():
    header, payload, signed = jwt_module.decode_token(
        token({"alg": "HS256", "typ": "JWT"}, {"sub": "u", "n": 1})
    )
    assert header == {"alg": "HS256", "typ": "JWT"}
    assert payload == {"sub": "u", "n": 1}
    assert signed is True


def test_decode_token_signature_flag_is_presence_only():
    sample = ({"alg": "HS256"}, {"sub": "u"})
    assert jwt_module.decode_token(token(*sample, signature=""))[2] is False
    assert jwt_module.decode_token(token(*sample, signature="***"))[2] is True


def test_decode_token_keeps_key_order_of_the_json():
    header, payload, _ = jwt_module.decode_token(
        token({"z": 1, "a": 2}, {"y": 1, "b": 2})
    )
    assert list(header) == ["z", "a"] and list(payload) == ["y", "b"]


def test_decode_token_accepts_padded_and_unpadded_segments():
    for padded in (True, False):
        text = f"{seg({'a': 1}, padded=padded)}.{seg({'b': 2}, padded=padded)}.s"
        assert jwt_module.decode_token(text) == ({"a": 1}, {"b": 2}, True)


def test_decode_token_accepts_urlsafe_and_standard_alphabets():
    raw = b'{"a": "???>>>"}'
    for encoder in (base64.urlsafe_b64encode, base64.b64encode):
        text = encoder(raw).decode("ascii").rstrip("=")
        assert jwt_module.decode_token(f"{text}.e30.s") == ({"a": "???>>>"}, {}, True)


def test_decode_token_strips_outer_whitespace_only():
    plain = good_token()
    assert jwt_module.decode_token(f"  {plain}\n")[0] == {"alg": "HS256", "typ": "JWT"}
    for broken in (
        "e30 .e30.x",
        "e30.e3\t0.x",
        "e30.e30.x y",
        "e30.\ne30.x",
        "e30.e30.s\u00a0t",
    ):
        with pytest.raises(ValueError) as caught:
            jwt_module.decode_token(broken)
        assert str(caught.value) == THREE_PARTS


@pytest.mark.parametrize(
    "text",
    ["", "e30", "e30.e30", "e30.e30.s.t", "..", ".e30.s", "e30..s", "Bearer e30.e30.s"],
)
def test_decode_token_wrong_shape_is_three_parts_error(text):
    with pytest.raises(ValueError) as caught:
        jwt_module.decode_token(text)
    assert str(caught.value) == THREE_PARTS


def test_decode_token_empty_signature_segment_is_allowed():
    assert jwt_module.decode_token("e30.e30.") == ({}, {}, False)


NOT_JSON_SEGMENT = seg(b"not json")
INVALID_UTF8_SEGMENT = seg(b'{"a":"' + bytes([0xFF]) + b'"}')


@pytest.mark.parametrize(
    "text",
    [
        f"{NOT_JSON_SEGMENT}.e30.s",
        f"e30.{NOT_JSON_SEGMENT}.s",
        f"{INVALID_UTF8_SEGMENT}.e30.s",
        "e.e30.s",
        "abcde.e30.s",
        "\u00e9.e30.s",
        "!!!!.e30.s",
        "e30.%%%.s",
    ],
)
def test_decode_token_undecodable_segments(text):
    with pytest.raises(ValueError) as caught:
        jwt_module.decode_token(text)
    assert str(caught.value) == UNDECODABLE


@pytest.mark.parametrize(
    "header,payload",
    [
        ([1], {"a": 1}),
        ({"a": 1}, [1]),
        ({"a": 1}, "text"),
        ({"a": 1}, 5),
        (None, {"a": 1}),
        ({"a": 1}, None),
    ],
)
def test_decode_token_header_and_payload_must_be_objects(header, payload):
    with pytest.raises(ValueError) as caught:
        jwt_module.decode_token(token(header, payload))
    assert str(caught.value) == NOT_OBJECTS


def test_decode_token_does_not_judge_the_algorithm_or_claims():
    header, payload, signed = jwt_module.decode_token(
        token({"alg": "none"}, {"exp": 1}, "")
    )
    assert (header, payload, signed) == ({"alg": "none"}, {"exp": 1}, False)


def test_decode_token_pinned_current_quirk_json_leniency():
    duplicate_keys = seg(b'{"a":1,"a":2}')
    not_a_number = seg(b'{"a":NaN}')
    with_byte_order_mark = seg(b"\xef\xbb\xbf{}")
    assert jwt_module.decode_token(f"{duplicate_keys}.e30.s")[0] == {"a": 2}
    assert math.isnan(jwt_module.decode_token(f"{not_a_number}.e30.s")[0]["a"])
    assert jwt_module.decode_token(f"{with_byte_order_mark}.e30.s")[:2] == ({}, {})


def test_decode_token_pinned_current_padding_follows_stdlib_base64_behavior():
    # CPython gh-145264 changed whether interior padding terminates decoding.
    probe = base64.b64decode("YW==Jj")
    assert probe in {b"a", b"abc"}, "Unrecognized stdlib Base64 padding behavior"
    if probe == b"a":
        assert jwt_module.decode_token("e30=junk.e30.s") == ({}, {}, True)
    else:
        with pytest.raises(ValueError) as caught:
            jwt_module.decode_token("e30=junk.e30.s")
        assert str(caught.value) == UNDECODABLE


def test_decode_token_is_offline(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("decode must not touch the network")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refuse)
    assert jwt_module.decode_token(good_token())[0]["alg"] == "HS256"


# --------------------------------------------------------------------------
# jwt row builders and value rendering
# --------------------------------------------------------------------------


def test_header_rows_put_alg_then_typ_first_then_insertion_order():
    rows = jwt_module.header_rows(
        {"kid": "k", "typ": "JWT", "alg": "HS256", "extra": [1, 2]}
    )
    assert rows == [("alg", "HS256"), ("typ", "JWT"), ("kid", "k"), ("extra", "1, 2")]


def test_header_rows_skip_absent_leaders_and_handle_empty():
    assert jwt_module.header_rows({}) == []
    assert jwt_module.header_rows({"typ": "JWT", "x": 1}) == [
        ("typ", "JWT"),
        ("x", "1"),
    ]


def test_header_rows_render_time_keys_as_times_even_in_a_header():
    assert jwt_module.header_rows({"exp": FIXED_EPOCH, "alg": 1}) == [
        ("alg", "1"),
        ("exp", FIXED_TEXT),
    ]


def test_claim_rows_registered_claims_lead_in_fixed_order():
    rows = jwt_module.claim_rows(
        {
            "zzz": 1,
            "sub": "s",
            "exp": FIXED_EPOCH,
            "aud": ["a", "b"],
            "iss": "i",
            "iat": 0,
            "nbf": FIXED_EPOCH,
            "custom": {"k": True},
        }
    )
    assert rows == [
        ("exp", FIXED_TEXT),
        ("nbf", FIXED_TEXT),
        ("iat", "1970-01-01 00:00:00Z"),
        ("iss", "i"),
        ("sub", "s"),
        ("aud", "a, b"),
        ("zzz", "1"),
        ("custom", '{"k":true}'),
    ]


def test_claim_rows_empty_and_unlisted_keys():
    assert jwt_module.claim_rows({}) == []
    assert jwt_module.claim_rows({"typ": "y", "alg": "x"}) == [
        ("typ", "y"),
        ("alg", "x"),
    ]


@pytest.mark.parametrize(
    "key,value,shown",
    [
        ("exp", FIXED_EPOCH, FIXED_TEXT),
        ("nbf", FIXED_EPOCH, FIXED_TEXT),
        ("iat", 0, "1970-01-01 00:00:00Z"),
        ("exp", 1.9, "1970-01-01 00:00:01Z"),
        ("exp", FIXED_EPOCH + 0.9, FIXED_TEXT),
        ("exp", True, "true"),
        ("exp", False, "false"),
        ("exp", "1700000000", "1700000000"),
        ("exp", None, "None"),
        ("exp", 10**30, str(10**30)),
        ("exp", [1, 2], "1, 2"),
        ("other", FIXED_EPOCH, str(FIXED_EPOCH)),
        ("x", "text", "text"),
        ("x", 3, "3"),
        ("x", 1.5, "1.5"),
        ("x", True, "true"),
        ("x", False, "false"),
        ("x", None, "None"),
        ("aud", ["a", "b"], "a, b"),
        ("aud", [], ""),
        ("x", {}, "{}"),
        ("x", {"b": 1, "a": 2}, '{"b":1,"a":2}'),
        ("x", {"a": [1, "\u00e9"], "b": None}, '{"a":[1,"\\u00e9"],"b":null}'),
        ("x", {"\u00e9": "\u00fc"}, '{"\\u00e9":"\\u00fc"}'),
    ],
)
def test_show_value_rendering(key, value, shown):
    assert jwt_module.show_value(key, value) == shown


def test_show_value_time_keys_are_utc_with_a_z_suffix():
    assert jwt_module.show_value("exp", 86400) == "1970-01-02 00:00:00Z"


def test_show_value_list_items_render_like_scalars():
    assert jwt_module.show_value("aud", [True, None, {"a": 1}]) == 'true, None, {"a":1}'


def test_defect_show_value_list_items_should_render_like_top_level_values():
    assert jwt_module.show_value("aud", [True, False]) == "true, false"


# --------------------------------------------------------------------------
# jwt.review_notes (security-relevant: alg none, exp, nbf)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("alg", ["none", "None", "NONE", " none ", "\tNoNe\n"])
def test_review_notes_flags_alg_none_in_any_case_and_padding(alg):
    assert jwt_module.review_notes({"alg": alg}, {"exp": future()}) == [
        "review: algorithm is none"
    ]


@pytest.mark.parametrize(
    "header",
    [
        {},
        {"alg": "HS256"},
        {"alg": "RS256"},
        {"alg": 0},
        {"alg": "nonce"},
        {"alg": ["none"]},
    ],
)
def test_review_notes_other_algorithms_are_not_flagged(header):
    assert jwt_module.review_notes(header, {"exp": future()}) == []


def test_review_notes_pinned_current_quirk_json_null_alg_counts_as_none():
    assert jwt_module.review_notes({"alg": None}, {"exp": future()}) == [
        "review: algorithm is none"
    ]


def test_review_notes_missing_exp():
    assert jwt_module.review_notes({"alg": "HS256"}, {}) == ["review: no exp"]


def test_review_notes_past_and_future_exp():
    assert jwt_module.review_notes({"alg": "HS256"}, {"exp": past()}) == [
        "review: exp is in the past"
    ]
    assert jwt_module.review_notes({"alg": "HS256"}, {"exp": 0}) == [
        "review: exp is in the past"
    ]
    assert jwt_module.review_notes({"alg": "HS256"}, {"exp": future()}) == []


@pytest.mark.parametrize(
    "exp", ["1", True, False, None, [1], {"a": 1}, 10**30, float("inf"), float("nan")]
)
def test_review_notes_unparseable_exp_is_present_so_no_note(exp):
    assert jwt_module.review_notes({"alg": "HS256"}, {"exp": exp}) == []


def test_review_notes_future_nbf_only():
    assert jwt_module.review_notes(
        {"alg": "HS256"}, {"exp": future(), "nbf": future()}
    ) == ["review: nbf is in the future"]
    assert (
        jwt_module.review_notes({"alg": "HS256"}, {"exp": future(), "nbf": past()})
        == []
    )
    assert (
        jwt_module.review_notes({"alg": "HS256"}, {"exp": future(), "nbf": "x"}) == []
    )


def test_review_notes_iat_in_the_future_is_not_a_note():
    assert (
        jwt_module.review_notes(
            {"alg": "HS256"}, {"exp": future(), "iat": future() * 2}
        )
        == []
    )


def test_review_notes_order_is_alg_then_exp_then_nbf():
    assert jwt_module.review_notes(
        {"alg": "none"}, {"exp": past(), "nbf": future()}
    ) == [
        "review: algorithm is none",
        "review: exp is in the past",
        "review: nbf is in the future",
    ]
    assert jwt_module.review_notes({"alg": "none"}, {"nbf": future()}) == [
        "review: algorithm is none",
        "review: no exp",
        "review: nbf is in the future",
    ]


# --------------------------------------------------------------------------
# jwt formatting helpers
# --------------------------------------------------------------------------


def test_format_field_plain_is_tab_separated_and_ignores_dim():
    assert jwt_module.format_field("alg", "HS256", False) == "alg\tHS256"
    assert (
        jwt_module.format_field("signature", "absent", False, dim=True)
        == "signature\tabsent"
    )
    assert jwt_module.format_field("", "", False) == "\t"


def test_format_field_color_pads_key_to_twelve_and_uses_white_value():
    assert (
        jwt_module.format_field("alg", "HS256", True)
        == f"  {CYAN}alg         {RESET} {WHITE}HS256{RESET}"
    )
    long_key = "averyveryverylongkeyname"
    assert (
        jwt_module.format_field(long_key, "v", True)
        == f"  {CYAN}{long_key}{RESET} {WHITE}v{RESET}"
    )


def test_format_field_color_dim_value():
    assert jwt_module.format_field("signature", "absent", True, dim=True) == (
        f"  {CYAN}signature   {RESET} {DIM}absent{RESET}"
    )


def test_format_banner_plain_and_color():
    assert jwt_module.format_banner(False) == PLAIN_BANNER
    assert jwt_module.format_banner(True) == COLOR_BANNER


# --------------------------------------------------------------------------
# jwt command line
# --------------------------------------------------------------------------


def test_jwt_parser_contract():
    parser = jwt_module.build_parser()
    assert parser.prog == "bughunt jwt"
    assert (
        parser.description
        == "Inspect supplied JWT claims without authenticating the token's signature."
    )
    rows = [
        (a.dest, tuple(a.option_strings), a.nargs, a.default, a.help)
        for a in parser._actions
        if a.dest != "help"
    ]
    assert rows == [
        ("token", (), "?", None, "Token with a header, payload, and signature."),
        (
            "session",
            ("--session",),
            0,
            False,
            "Decode the saved Authorization value. A positional token wins.",
        ),
        ("plain", ("--plain",), 0, False, "Skip the banner."),
    ]


def test_jwt_console_spec_rows():
    spec = console_options.load_spec(
        "jwt", tool_file=Path("unused.py"), build_parser=None
    )
    assert spec.command_name == "" and spec.subcommands == ()
    assert [(o.name, o.flags, o.kind, o.required, o.help) for o in spec.options] == [
        (
            "TOKEN",
            (),
            "positional",
            False,
            "Token with a header, payload, and signature.",
        ),
        (
            "SESSION",
            ("--session",),
            "bool",
            False,
            "Decode the saved Authorization value. A positional token wins.",
        ),
        ("PLAIN", ("--plain",), "bool", False, "Skip the banner."),
    ]


def test_jwt_help_exits_zero_on_stdout(invoke):
    result = invoke(jwt_module, ["-h"])
    assert result.code == 0 and result.err == ""
    assert result.out.startswith("usage: bughunt jwt")


def test_jwt_argparse_errors_exit_two_with_no_stdout(invoke):
    for argv in (["--bogus"], [good_token(), good_token()]):
        result = invoke(jwt_module, argv)
        assert (
            result.code == 2
            and result.out == ""
            and "bughunt jwt: error:" in result.err
        )


def test_jwt_reads_sys_argv_when_argv_is_none(monkeypatch, invoke):
    monkeypatch.setattr(sys, "argv", ["bughunt jwt", good_token(), "--plain"])
    result = invoke(jwt_module, None)
    assert result.code == 0 and result.out.splitlines()[0] == "alg\tHS256"


def test_jwt_plain_output_layout(invoke):
    result = invoke(
        jwt_module,
        [
            token(
                {"alg": "HS256", "typ": "JWT", "kid": "k"},
                {"zz": 1, "sub": "u", "exp": FIXED_EPOCH},
            ),
            "--plain",
        ],
    )
    assert result.code == 0
    lines = result.out.splitlines()
    assert lines[:3] == ["alg\tHS256", "typ\tJWT", "kid\tk"]
    assert lines[3:] == [
        f"exp\t{FIXED_TEXT}",
        "sub\tu",
        "zz\t1",
        "signature\tpresent, not checked",
    ]


def test_jwt_missing_signature_reports_absent(invoke):
    result = invoke(
        jwt_module, [token({"alg": "HS256"}, {"exp": future()}, ""), "--plain"]
    )
    assert result.out.splitlines()[-1] == "signature\tabsent"


def test_jwt_review_notes_go_to_stderr_and_do_not_change_the_exit_code(invoke):
    result = invoke(
        jwt_module, [token({"alg": "none"}, {"nbf": future()}, ""), "--plain"]
    )
    assert result.code == 0
    assert result.err == (
        "review: algorithm is none\nreview: no exp\nreview: nbf is in the future\n"
    )
    assert "review" not in result.out


def test_jwt_needs_a_token_or_session(invoke):
    for argv in ([], ["--plain"], ["   "]):
        result = invoke(jwt_module, argv)
        assert (result.code, result.out, result.err) == (2, "", NEED_TOKEN + "\n")


def test_jwt_session_flag_without_saved_authorization(invoke):
    for argv in (["--session"], ["   ", "--session"]):
        result = invoke(jwt_module, argv)
        assert (result.code, result.out, result.err) == (2, "", NO_AUTH_SAVED + "\n")
    core_session.write_session({"cookie": "a=1"})
    assert invoke(jwt_module, ["--session"]).err == NO_AUTH_SAVED + "\n"


def test_jwt_decode_failures_exit_two_on_stderr(invoke):
    for text, message in (
        ("abc", THREE_PARTS),
        (f"{NOT_JSON_SEGMENT}.e30.s", UNDECODABLE),
        (token([1], {}), NOT_OBJECTS),
    ):
        result = invoke(jwt_module, [text])
        assert (result.code, result.out, result.err) == (2, "", message + "\n")


@pytest.mark.parametrize("saved", ["Bearer {t}", "bearer {t}", "BEARER   {t}  ", "{t}"])
def test_jwt_session_strips_a_leading_bearer_case_insensitively(invoke, saved):
    plain = good_token()
    core_session.write_session({"authorization": saved.format(t=plain)})
    result = invoke(jwt_module, ["--session", "--plain"])
    assert result.code == 0 and result.out.splitlines()[0] == "alg\tHS256"


@pytest.mark.parametrize("saved", ["Bearer", "Basic abc", "Bearer x"])
def test_jwt_session_value_that_is_not_a_token_fails_to_decode(invoke, saved):
    core_session.write_session({"authorization": saved})
    result = invoke(jwt_module, ["--session", "--plain"])
    assert (result.code, result.out, result.err) == (2, "", THREE_PARTS + "\n")


def test_jwt_positional_token_wins_over_session(invoke):
    core_session.write_session({"authorization": "Bearer " + good_token()})
    other = token({"alg": "none"}, {"sub": "other"}, "")
    result = invoke(jwt_module, [other, "--session", "--plain"])
    assert "sub\tother" in result.out.splitlines()


def test_jwt_session_reads_the_selected_named_actor(invoke):
    make_actor(
        "viewer",
        kind="lower_privilege",
        authorization="Bearer " + good_token(sub="viewer-sub"),
    )
    identity.use_profile("viewer")
    result = invoke(jwt_module, ["--session", "--plain"])
    assert result.code == 0 and "sub\tviewer-sub" in result.out.splitlines()


def test_jwt_session_with_a_token_argument_ignores_a_broken_actor(invoke, ws):
    select_corrupt_actor(ws)
    result = invoke(jwt_module, [good_token(), "--plain"])
    assert result.code == 0 and result.out.splitlines()[0] == "alg\tHS256"


def test_jwt_output_is_offline(monkeypatch, invoke):
    def refuse(*args, **kwargs):
        raise AssertionError("jwt must not touch the network")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refuse)
    assert invoke(jwt_module, [good_token(), "--plain"]).code == 0


# ---- color and banner paths ----


def _colored_rows(*pairs, dim_last=False):
    rows = []
    for index, (key, value) in enumerate(pairs):
        paint = DIM if dim_last and index == len(pairs) - 1 else WHITE
        rows.append(f"  {CYAN}{key:<12}{RESET} {paint}{value}{RESET}")
    return "\n".join(rows) + "\n"


def test_jwt_color_output_and_banner_on_a_color_terminal(invoke):
    result = invoke(
        jwt_module,
        [token({"alg": "none"}, {"sub": "u", "exp": FIXED_EPOCH}, "")],
        tty=True,
        term="xterm",
    )
    assert result.code == 0
    assert result.out == _colored_rows(
        ("alg", "none"),
        ("exp", FIXED_TEXT),
        ("sub", "u"),
        ("signature", "absent"),
        dim_last=True,
    )
    assert result.err == (
        COLOR_BANNER
        + "\n\n"
        + f"{YELLOW}review: algorithm is none{RESET}\n"
        + f"{YELLOW}review: exp is in the past{RESET}\n"
    )


def test_jwt_plain_flag_turns_off_row_color_and_banner(invoke):
    result = invoke(jwt_module, [good_token(), "--plain"], tty=True, term="xterm")
    assert "\x1b" not in result.out and result.err == ""


def test_jwt_plain_flag_does_not_turn_off_note_color(invoke):
    # pinned_current_quirk: notes are painted whenever stderr is a color terminal, --plain or not
    result = invoke(
        jwt_module,
        [token({"alg": "none"}, {"exp": future()}, ""), "--plain"],
        tty=True,
        term="xterm",
    )
    assert result.err == f"{YELLOW}review: algorithm is none{RESET}\n"


@pytest.mark.parametrize(
    "term,no_color", [("dumb", None), (None, None), ("", None), ("xterm", "1")]
)
def test_jwt_color_is_off_for_dumb_unset_or_no_color(invoke, term, no_color):
    result = invoke(jwt_module, [good_token()], tty=True, term=term, no_color=no_color)
    assert "\x1b" not in result.out
    assert result.err == PLAIN_BANNER + "\n\n"


def test_jwt_empty_no_color_variable_does_not_disable_color(invoke):
    result = invoke(jwt_module, [good_token()], tty=True, term="xterm", no_color="")
    assert result.out.startswith(f"  {CYAN}alg         {RESET}")


def test_jwt_nothing_is_colored_or_bannered_when_streams_are_not_terminals(invoke):
    result = invoke(jwt_module, [good_token()], tty=False, term="xterm")
    assert "\x1b" not in result.out and result.err == ""


def test_jwt_banner_goes_to_stderr_before_a_decode_error_but_not_before_a_usage_error(
    invoke,
):
    shown = invoke(jwt_module, ["abc"], tty=True, term="dumb")
    assert shown.out == "" and shown.err == PLAIN_BANNER + "\n\n" + THREE_PARTS + "\n"
    missing = invoke(jwt_module, [], tty=True, term="dumb")
    assert missing.err == NEED_TOKEN + "\n"


def test_jwt_stdout_and_stderr_color_are_decided_independently(monkeypatch):
    out, err = _Tty(), io.StringIO()
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    assert jwt_module.main([token({"alg": "none"}, {"exp": future()}, "")]) == 0
    assert out.getvalue().startswith(f"  {CYAN}alg         {RESET}")
    assert err.getvalue() == "review: algorithm is none\n"


# ---- known defects (security cluster: output injection) ----


def _hostile_lines(invoke, claim):
    result = invoke(
        jwt_module,
        [token({"alg": "HS256"}, {"exp": future(), "sub": claim}), "--plain"],
    )
    assert result.code == 0
    return result


def test_defect_jwt_claim_newline_must_not_forge_rows(invoke):
    result = _hostile_lines(invoke, "a\nsignature\tabsent")
    assert len(result.out.splitlines()) == 4


def test_defect_jwt_claim_escape_sequences_must_not_reach_the_terminal(invoke):
    assert "\x1b" not in _hostile_lines(invoke, "\x1b[31mred").out


def _deeply_nested_token():
    return f"{seg(b'[' * 100000)}.e30.s"


def test_defect_jwt_deeply_nested_json_must_be_a_decode_error():
    with pytest.raises(ValueError) as caught:
        jwt_module.decode_token(_deeply_nested_token())
    assert str(caught.value) == UNDECODABLE


def test_defect_jwt_session_flag_must_report_a_broken_actor_instead_of_raising(
    invoke, ws
):
    select_corrupt_actor(ws)
    result = invoke(jwt_module, ["--session"])
    assert result.code == 2 and result.out == "" and result.err.strip()


# --------------------------------------------------------------------------
# session command line
# --------------------------------------------------------------------------


def test_session_parser_contract():
    parser = session_module.build_parser()
    assert parser.prog == "bughunt session"
    assert (
        parser.description
        == "Save a Cookie or Authorization header for in-scope requests."
    )
    spec = console_options.load_spec(
        "session", tool_file=Path("unused.py"), build_parser=None
    )
    assert spec.command_name == "COMMAND"
    assert spec.subcommands == (
        ("show", "Print the saved headers."),
        ("set", "Save one header."),
        ("clear", "Remove one saved header, or both."),
    )
    assert [
        (
            o.name,
            o.dest,
            o.kind,
            o.required,
            o.help,
            o.choices,
            o.subcommand,
            o.repeatable,
        )
        for o in spec.options
    ] == [
        (
            "KIND",
            "kind",
            "positional",
            True,
            "",
            ("cookie", "authorization"),
            "set",
            False,
        ),
        (
            "VALUE",
            "value",
            "positional",
            True,
            "The header value you already have.",
            (),
            "set",
            True,
        ),
        (
            "KIND",
            "kind",
            "positional",
            False,
            "",
            ("cookie", "authorization"),
            "clear",
            False,
        ),
        (
            "COMMAND",
            "command",
            "positional",
            True,
            "Subcommand.",
            ("show", "set", "clear"),
            "",
            False,
        ),
    ]


def test_session_subcommand_is_required_and_unknown_ones_are_rejected(invoke):
    for argv in ([], ["bogus"]):
        result = invoke(session_module, argv)
        assert (
            result.code == 2
            and result.out == ""
            and "bughunt session: error:" in result.err
        )


def test_session_help_exits_zero_on_stdout(invoke):
    result = invoke(session_module, ["-h"])
    assert (
        result.code == 0
        and result.out.startswith("usage: bughunt session")
        and result.err == ""
    )


def test_session_kind_is_exactly_cookie_or_authorization(invoke):
    for argv in (
        ["set", "Cookie", "a"],
        ["set", "x-api-key", "a"],
        ["clear", "other"],
        ["set"],
        ["set", "cookie"],
    ):
        assert invoke(session_module, argv).code == 2
    assert core_session.load_session() == {}


def test_session_reads_sys_argv_when_argv_is_none(monkeypatch, invoke):
    monkeypatch.setattr(sys, "argv", ["bughunt session", "set", "cookie", "a=1"])
    assert invoke(session_module, None).code == 0
    assert core_session.load_session() == {"cookie": "a=1"}


def test_session_show_with_nothing_saved(invoke):
    result = invoke(session_module, ["show"])
    assert result.code == 0 and result.err == ""
    assert result.out == (
        "No session headers saved.\n"
        "  bughunt session set cookie 'session=abc'\n"
        "  bughunt session set authorization 'Bearer token'\n"
    )


def test_session_show_redacts_values_and_lists_cookie_first(invoke):
    core_session.write_session(
        {"authorization": "Bearer auth-secret", "cookie": "session=cookie-secret"}
    )
    result = invoke(session_module, ["show"])
    assert (result.code, result.out, result.err) == (
        0,
        "cookie: [REDACTED]\nauthorization: [REDACTED]\n",
        "",
    )


def test_session_show_lists_only_what_is_saved(invoke):
    core_session.write_session({"authorization": "Bearer t"})
    assert invoke(session_module, ["show"]).out == "authorization: [REDACTED]\n"
    core_session.write_session({"cookie": "c=1"})
    assert invoke(session_module, ["show"]).out == "cookie: [REDACTED]\n"


def test_session_set_saves_and_reports_the_storage_path(invoke, ws):
    result = invoke(session_module, ["set", "cookie", "a=1"])
    assert (result.code, result.out, result.err) == (
        0,
        f"cookie saved in {ws / 'session.txt'}\n",
        "",
    )
    assert core_session.load_session() == {"cookie": "a=1"}
    assert "a=1" not in result.out


def test_session_set_joins_words_with_one_space_and_strips(invoke):
    assert invoke(session_module, ["set", "cookie", "  a=1;", "b=2  "]).code == 0
    assert core_session.load_session() == {"cookie": "a=1; b=2"}
    assert invoke(session_module, ["set", "authorization", "Bearer", "tok"]).code == 0
    assert core_session.load_session()["authorization"] == "Bearer tok"


def test_session_set_keeps_the_other_header_and_replaces_the_same_kind(invoke):
    invoke(session_module, ["set", "cookie", "a=1"])
    invoke(session_module, ["set", "authorization", "Bearer one"])
    invoke(session_module, ["set", "authorization", "Bearer two"])
    assert core_session.load_session() == {
        "cookie": "a=1",
        "authorization": "Bearer two",
    }


@pytest.mark.parametrize(
    "words", [[" "], ["", ""], ["   ", "  "], ["a\nb"], ["a\rb"], ["a\r\nb"]]
)
def test_session_set_rejects_blank_and_cr_lf_values(invoke, words):
    invoke(session_module, ["set", "cookie", "keep=1"])
    result = invoke(session_module, ["set", "authorization", *words])
    assert (result.code, result.out, result.err) == (2, SINGLE_VALUE + "\n", "")
    assert core_session.load_session() == {"cookie": "keep=1"}


def test_session_set_trims_surrounding_newlines_but_rejects_inner_ones(invoke):
    assert invoke(session_module, ["set", "cookie", "\na=1\r\n"]).code == 0
    assert core_session.load_session() == {"cookie": "a=1"}


def test_session_set_pinned_current_quirk_default_actor_accepts_a_tab_in_the_value(
    invoke,
):
    assert invoke(session_module, ["set", "cookie", "a\tb"]).code == 0
    assert core_session.load_session() == {"cookie": "a\tb"}


def test_session_set_double_dash_allows_a_value_that_looks_like_an_option(invoke):
    assert invoke(session_module, ["set", "cookie", "--", "--x"]).code == 0
    assert core_session.load_session() == {"cookie": "--x"}
    assert invoke(session_module, ["set", "cookie", "--x"]).code == 2


def test_session_clear_one_kind(invoke):
    core_session.write_session({"cookie": "a=1", "authorization": "Bearer t"})
    result = invoke(session_module, ["clear", "cookie"])
    assert (result.code, result.out, result.err) == (0, "cookie cleared\n", "")
    assert core_session.load_session() == {"authorization": "Bearer t"}
    assert invoke(session_module, ["clear", "cookie"]).out == "cookie cleared\n"


def test_session_clear_everything_removes_the_saved_file(invoke, ws):
    core_session.write_session({"cookie": "a=1", "authorization": "Bearer t"})
    result = invoke(session_module, ["clear"])
    assert (result.code, result.out, result.err) == (0, "session cleared\n", "")
    assert core_session.load_session() == {} and not (ws / "session.txt").exists()
    assert invoke(session_module, ["clear"]).out == "session cleared\n"


def test_session_clearing_the_last_header_removes_the_file(invoke, ws):
    core_session.write_session({"cookie": "a=1"})
    invoke(session_module, ["clear", "cookie"])
    assert not (ws / "session.txt").exists()


def test_session_commands_work_on_the_selected_named_actor(invoke, ws):
    make_actor("owner")
    identity.use_profile("owner")
    result = invoke(session_module, ["set", "cookie", "o=1"])
    assert result.out == f"cookie saved in {ws / 'identities' / 'owner.json'}\n"
    invoke(session_module, ["set", "authorization", "Bearer o"])
    assert identity.read_profile("owner")["credentials"] == {
        "Cookie": "o=1",
        "Authorization": "Bearer o",
    }
    assert (
        invoke(session_module, ["show"]).out
        == "cookie: [REDACTED]\nauthorization: [REDACTED]\n"
    )
    assert not (ws / "session.txt").exists()
    invoke(session_module, ["clear", "cookie"])
    assert identity.read_profile("owner")["credentials"] == {
        "Authorization": "Bearer o"
    }
    assert invoke(session_module, ["clear"]).out == "session cleared\n"
    assert identity.read_profile("owner")["credentials"] == {}


def test_session_named_actor_leaves_the_default_session_untouched(invoke, ws):
    invoke(session_module, ["set", "cookie", "d=1"])
    make_actor("owner")
    identity.use_profile("owner")
    invoke(session_module, ["set", "cookie", "o=1"])
    identity.use_profile("default")
    assert core_session.load_session() == {"cookie": "d=1"}


def test_session_anonymous_actor_cannot_hold_credentials(invoke):
    make_actor("anon", kind="anonymous")
    identity.use_profile("anon")
    assert invoke(session_module, ["show"]).out.startswith("No session headers saved.")
    refused = invoke(session_module, ["set", "cookie", "x=1"])
    assert (refused.code, refused.out, refused.err) == (2, BAD_ACTOR + "\n", "")
    assert invoke(session_module, ["clear"]).code == 0


@pytest.mark.parametrize(
    "argv", [["show"], ["set", "cookie", "x=1"], ["clear"], ["clear", "cookie"]]
)
def test_session_invalid_selected_actor_is_reported_not_raised(invoke, ws, argv):
    select_corrupt_actor(ws)
    result = invoke(session_module, argv)
    assert (result.code, result.out, result.err) == (2, BAD_ACTOR + "\n", "")


def test_session_show_never_prints_a_secret(invoke):
    core_session.write_session(
        {"cookie": "session=cookie-secret", "authorization": "Bearer auth-secret"}
    )
    result = invoke(session_module, ["show"])
    assert "cookie-secret" not in result.out and "auth-secret" not in result.out
    assert result.out.count("[REDACTED]") == 2


# ---- known defects (security cluster: CRLF-class header injection, actor corruption) ----

SPLITTING_SEPARATORS = [
    "\x0b",
    "\x0c",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x85",
    "\u2028",
    "\u2029",
]


@pytest.mark.parametrize("separator", SPLITTING_SEPARATORS)
def test_session_rejects_line_separators_without_changing_saved_headers(
    invoke, separator
):
    invoke(session_module, ["set", "cookie", "keep=1"])
    before = core_session.session_path().read_bytes()
    result = invoke(
        session_module, ["set", "cookie", f"a=1{separator}authorization: Bearer evil"]
    )
    assert (result.code, result.out) == (2, SINGLE_VALUE + "\n")
    assert core_session.load_session() == {"cookie": "keep=1"}
    assert core_session.session_path().read_bytes() == before


@pytest.mark.parametrize("separator", SPLITTING_SEPARATORS)
def test_defect_session_set_must_not_let_a_value_forge_a_second_header(
    invoke, separator
):
    invoke(
        session_module, ["set", "cookie", f"a=1{separator}authorization: Bearer evil"]
    )
    assert "authorization" not in core_session.load_session()


@pytest.mark.parametrize("value", ["a\tb", "a\x0bb", "a\x00b", "a\u20acb"])
def test_session_rejects_invalid_named_actor_values_without_mutating_the_profile(
    invoke, value
):
    make_actor("owner", cookie="o=1")
    identity.use_profile("owner")
    path = core_session.session_path()
    before = path.read_bytes()
    result = invoke(session_module, ["set", "cookie", value])
    message = SINGLE_VALUE if core_session.has_line_separator(value) else BAD_ACTOR
    assert (result.code, result.out) == (2, message + "\n")
    assert path.read_bytes() == before
    assert identity.read_profile("owner")["credentials"] == {"Cookie": "o=1"}


@pytest.mark.parametrize("value", ["a\tb", "a\x0bb", "a\x00b", "a\u20acb"])
def test_defect_session_set_must_not_corrupt_a_named_actor(invoke, value):
    make_actor("owner", cookie="o=1")
    identity.use_profile("owner")
    invoke(session_module, ["set", "cookie", value])
    assert identity.read_profile("owner")["credentials"] == {"Cookie": "o=1"}
