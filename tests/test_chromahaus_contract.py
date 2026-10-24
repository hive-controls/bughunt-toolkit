"""Characterization oracle for addons/chromahaus, part 1: the contract (interfaces, CLI, keys, wire, egress).

Written BEFORE the clean-room rebuild (M2 Wave 2 Batch 2) from the behavior spec m2-chromahaus-spec.md and
verified by running it against the base tree (origin/main 2eb1935). chromahaus is NOT a browser tool: it is a
network-free-in-tests client for the abuse.ch community APIs (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker,
SSLBL). Every test here mocks at the egress edge (httpx.MockTransport behind the real api_client), trips DNS/TCP,
and makes no real abuse.ch call.

Reading guide for the three test files
  plain test             behavior the rebuild must keep (spec tiers [T]/[C]/[K]).
  *_pinned_current       (test_chromahaus_defects.py) asserts TODAY's behavior of a known defect D1-D22. It is green
                         on the base tree and goes red when the defect is fixed; delete it when the orchestrator
                         approves that deviation, keep it (the rebuild must reproduce it) otherwise.
  *_correct              (test_chromahaus_defects.py) asserts the CORRECT behavior, xfail(strict=True). It stays
                         xfail while the defect exists and turns into a hard failure (XPASS) when the defect is
                         fixed, so the marker is removed deliberately.
The subject is chosen by CHROMAHAUS_UNDER_TEST (default addons/chromahaus/chromahaus.py), see chromahaus_support.py.
"""

from __future__ import annotations

import argparse
import ast
import inspect
import re
import socket
import sys
from pathlib import Path

import httpx
import pytest

from bughunt.console import catalog, loader
from bughunt.core import scanner as bughunt_scanner

from chromahaus_support import (  # noqa: F401  (fixtures are imported so pytest registers them here)
    ADDON_DIR,
    BAZAAR,
    FEODO,
    FORM,
    FULL_GRANTS,
    JSON_TYPE,
    KEY,
    POLICY_REQUIRED_HEADERS,
    POLICY_UA,
    REAL_POPEN,
    H64,
    M32,
    REPO,
    SHA,
    SSLBL,
    SUBJECT,
    THREATFOX,
    URLHAUS,
    Fake,
    form_post,
    grants_without,
    json_documents,
    json_post,
    console_form_entry,
    load_fresh_subject,
    no_real_network,
    only_permitted,
    plain_get,
    reply_json,
    reply_text,
    rig,
    write_policy,
)

VERSION_LINE = "CHROMAHAUS 1.1.0"  # orchestrator-owned value (spec section 10); change here only on purpose
SIXTEEN = [
    "repl",
    "hunt",
    "url",
    "host",
    "hash",
    "recent",
    "payloads",
    "tag",
    "family",
    "iocs",
    "fox",
    "bazaar",
    "feodo",
    "sslbl",
    "watch",
    "download",
]
EVERY_SUBCOMMAND = [
    ["hunt", "x.example"],
    ["url", "http://x.example/"],
    ["host", "x.example"],
    ["hash", SHA],
    ["recent"],
    ["payloads"],
    ["tag", "mozi"],
    ["family", "Mozi"],
    ["iocs"],
    ["fox", "x"],
    ["bazaar"],
    ["feodo"],
    ["sslbl"],
    ["watch"],
    ["download", SHA, "--i-understand"],
    ["repl"],
    [],
]


# ---------------------------------------------------------------------------------------------------------------
# 1. Module surface and parser (spec 2.1, 3)
# ---------------------------------------------------------------------------------------------------------------


def test_import_builds_no_client_and_exposes_the_contract_surface():
    module = load_fresh_subject()
    try:
        assert module.HTTP is None
        assert module.API_HOSTS == frozenset({"abuse.ch"})
        for name in (
            "build_parser",
            "main",
            "_http",
            "fetch_text_list",
            "cmd_download",
        ):
            assert callable(getattr(module, name)), name
        assert not inspect.iscoroutinefunction(module.main)
        assert loader._accepts_positional(module.main)
        assert list(inspect.signature(module.cmd_download).parameters) == [
            "key",
            "sha256",
            "dest",
            "i_understand",
            "structured",
        ]
        assert list(inspect.signature(module.fetch_text_list).parameters) == [
            "url",
            "key",
        ]
    finally:
        sys.modules.pop(module.__name__, None)


def test_http_is_built_lazily_cached_and_hardened(rig):
    assert (
        rig.module.HTTP is None and rig.fake.client_builds == []
    )  # a fresh module has built nothing
    client = rig.module._http()
    assert rig.module.HTTP is client
    assert rig.module._http() is client
    assert rig.fake.client_builds == [
        (frozenset({"abuse.ch"}), 45)
    ]  # api_client(API_HOSTS, timeout=45), once
    assert client.trust_env is False
    assert client.follow_redirects is False
    assert client.timeout == httpx.Timeout(45)


def test_main_accepts_argv_and_returns_an_int_exit_code(rig):
    result = rig.cli("recent")
    assert not result.exited
    assert isinstance(result.returned, int) and not isinstance(result.returned, bool)
    assert result.returned == 0


def test_parser_global_options_have_the_pinned_dests_and_defaults(rig):
    namespace = rig.module.build_parser().parse_args(["recent"])
    assert vars(namespace) == {
        "key": None,
        "no_color": False,
        "raw": False,
        "out": None,
        "limit": 25,
        "cmd": "recent",
    }
    assert rig.module.build_parser().parse_args([]).cmd is None


PARSE_VECTORS = [
    (
        ["--key", "abc", "--no-color", "--json", "--out", "f.csv", "-n", "7", "recent"],
        {
            "key": "abc",
            "no_color": True,
            "raw": True,
            "out": "f.csv",
            "limit": 7,
            "cmd": "recent",
        },
    ),
    (["--limit", "3", "recent"], {"limit": 3}),
    (["hunt", "v"], {"cmd": "hunt", "indicator": "v"}),
    (["url", "v"], {"cmd": "url", "value": "v"}),
    (["host", "v"], {"cmd": "host", "value": "v"}),
    (["hash", "v"], {"cmd": "hash", "value": "v"}),
    (["tag", "v"], {"cmd": "tag", "value": "v"}),
    (["family", "v"], {"cmd": "family", "value": "v"}),
    (["fox", "v"], {"cmd": "fox", "value": "v"}),
    (["iocs"], {"cmd": "iocs", "days": 1}),
    (["iocs", "--days", "3"], {"days": 3}),
    (["watch"], {"cmd": "watch", "interval": 30}),
    (["watch", "--interval", "5"], {"interval": 5}),
    (
        ["download", SHA],
        {"cmd": "download", "sha256": SHA, "dest": ".", "i_understand": False},
    ),
    (
        ["download", SHA, "--dest", "d", "--i-understand"],
        {"dest": "d", "i_understand": True},
    ),
    (["repl"], {"cmd": "repl"}),
    (["payloads"], {"cmd": "payloads"}),
    (["bazaar"], {"cmd": "bazaar"}),
    (["feodo"], {"cmd": "feodo"}),
    (["sslbl"], {"cmd": "sslbl"}),
]


@pytest.mark.parametrize(
    ("argv", "expected"),
    PARSE_VECTORS,
    ids=lambda value: " ".join(value) if isinstance(value, list) else "",
)
def test_parser_dests_types_and_defaults(rig, argv, expected):
    namespace = rig.module.build_parser().parse_args(argv)
    for name, value in expected.items():
        assert getattr(namespace, name) == value, name
        assert type(getattr(namespace, name)) is type(value), name


def test_subcommand_group_has_dest_cmd_is_optional_and_lists_exactly_sixteen(rig):
    parser = rig.module.build_parser()
    groups = [
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    assert len(groups) == 1
    assert groups[0].dest == "cmd"
    assert groups[0].required is False
    assert sorted(groups[0].choices) == sorted(SIXTEEN)


@pytest.mark.parametrize(
    "argv",
    [
        ["--bogus"],
        ["recent", "--bogus"],
        ["url"],
        ["hunt"],
        ["--limit", "x", "recent"],
        ["-n", "x", "recent"],
        ["iocs", "--days", "x"],
        ["watch", "--interval", "x"],
        ["download"],
        ["frobnicate"],
    ],
    ids=lambda argv: " ".join(argv),
)
def test_argparse_errors_exit_2_with_usage_on_stderr_and_send_nothing(rig, argv):
    result = rig.cli(*argv)
    assert result.exited and result.exit_arg == 2 and result.rc == 2
    assert "usage" in result.err.lower()
    assert rig.fake.seen == []


@pytest.mark.parametrize("flag", ["-V", "--version"])
def test_version_flag_prints_name_and_version_then_exits_zero(rig, flag):
    result = rig.run([flag])
    assert result.exited and result.exit_arg == 0
    assert result.out.strip() == VERSION_LINE
    assert rig.fake.seen == []


def test_help_exits_zero_and_names_every_subcommand_and_global_flag(rig):
    result = rig.run(["-h"])
    assert result.exited and result.exit_arg == 0
    for token in [
        *SIXTEEN,
        "--key",
        "--no-color",
        "--json",
        "--out",
        "--limit",
        "--version",
    ]:
        assert token in result.out, token
    sub = rig.run(["download", "-h"])
    assert sub.exited and sub.exit_arg == 0
    assert "--i-understand" in sub.out and "--dest" in sub.out


def test_global_options_must_precede_the_subcommand_and_all_work_there(rig, tmp_path):
    out_file = tmp_path / "rows.json"
    rig.fake.default = reply_json(
        {"query_status": "ok", "urls": [{"id": "1", "url": "http://r.example/1"}]}
    )
    result = rig.cli(
        "--no-color", "--json", "--out", str(out_file), "-n", "3", "recent"
    )
    assert result.rc == 0, result.err
    assert rig.fake.urls == [f"{URLHAUS}/urls/recent/limit/3/"]
    assert out_file.is_file()


@pytest.mark.skipif(
    not str(SUBJECT).startswith(str(REPO)),
    reason="standalone fallback needs the file inside the repo",
)
def test_standalone_script_runs_outside_the_repo_and_exits_with_mains_return_value(
    tmp_path,
):
    """Spec 2.1: `python addons/chromahaus/chromahaus.py` works where `bughunt` is not importable; __main__ exits with main()."""
    import os
    import subprocess

    env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in (
            "PYTHONPATH",
            "ABUSECH_AUTH_KEY",
            "ABUSE_CH_KEY",
            "NO_COLOR",
            "BUGHUNT_SCOPE",
        )
    }
    env.update(HOME=str(tmp_path), USERPROFILE=str(tmp_path), PYTHONIOENCODING="utf-8")

    def run(*args):
        proc = REAL_POPEN(
            [sys.executable, str(SUBJECT), *args],
            cwd=tmp_path,
            env=env,
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out, err = proc.communicate(timeout=60)
        return proc.returncode, out, err

    code, out, err = run("-V")
    assert (code, out.strip()) == (0, VERSION_LINE), err
    code, out, err = run()
    assert code == 2 and "ABUSECH_AUTH_KEY" in out, err
    code, out, err = run(
        "--key", "k", "download", SHA
    )  # a SystemExit message goes to stderr with rc 1
    assert code == 1 and "--i-understand" in err and "infected" in out


# ---------------------------------------------------------------------------------------------------------------
# 2. Console form, catalog entry, loader (spec 3 "Console form", 7)
# ---------------------------------------------------------------------------------------------------------------

FORM_SNAPSHOT = [
    ("KEY", "value", False, ("--key",), "", (), ""),
    ("NO_COLOR", "bool", False, ("--no-color",), "", (), ""),
    ("RAW", "bool", False, ("--json",), "", (), ""),
    ("OUT", "value", False, ("--out",), "", (), ""),
    ("LIMIT", "value", False, ("-n", "--limit"), "25", (), ""),
    ("INDICATOR", "positional", True, (), "", (), "hunt"),
    ("VALUE", "positional", True, (), "", (), "url"),
    ("VALUE", "positional", True, (), "", (), "host"),
    ("VALUE", "positional", True, (), "", (), "hash"),
    ("VALUE", "positional", True, (), "", (), "tag"),
    ("VALUE", "positional", True, (), "", (), "family"),
    ("DAYS", "value", False, ("--days",), "1", (), "iocs"),
    ("VALUE", "positional", True, (), "", (), "fox"),
    ("INTERVAL", "value", False, ("--interval",), "30", (), "watch"),
    ("POLLS", "value", False, ("--polls",), "", (), "watch"),
    ("SHA256", "positional", True, (), "", (), "download"),
    ("DEST", "value", False, ("--dest",), ".", (), "download"),
    ("I_UNDERSTAND", "bool", False, ("--i-understand",), "", (), "download"),
    ("COMMAND", "positional", False, (), "", tuple(SIXTEEN), ""),
]


def test_catalog_form_snapshot_pins_option_names_kinds_defaults_and_order(monkeypatch):
    entry = console_form_entry(monkeypatch)
    assert entry["form"] is not None, entry.get("unavailable")
    options = [
        (
            o["name"],
            o["kind"],
            o["required"],
            tuple(o["flags"]),
            o["default"],
            tuple(o["choices"]),
            o["subcommand"],
        )
        for o in entry["form"]["options"]
    ]
    assert options == FORM_SNAPSHOT
    assert entry["form"]["command_name"] == "COMMAND"
    assert [row["name"] for row in entry["form"]["subcommands"]] == SIXTEEN


def test_catalog_entry_facts_for_the_chroma_reference_tool(monkeypatch):
    entry = console_form_entry(monkeypatch)
    tool = catalog.tool_by_command("chroma")
    assert (tool.command, tool.folder, tool.script, tool.aliases) == (
        "chroma",
        "chromahaus",
        "chromahaus.py",
        ("chromahaus",),
    )
    assert (
        entry["aliases"] == ["chromahaus"]
        and entry["reference"] is True
        and entry["disabled"] is False
    )
    assert "chroma" not in catalog.DISABLED_REFERENCES
    assert catalog.group_for("chroma") == "Intel"
    assert (
        catalog.reference_canonical("chromahaus")
        == "chroma"
        == catalog.reference_canonical("chroma")
    )


def test_loader_call_main_maps_returns_and_system_exit_to_exit_codes(rig, capsys):
    call = lambda argv: loader._call_main(rig.module, argv, "chroma", SUBJECT)  # noqa: E731
    assert call(["--key", KEY, "recent"]) == 0
    assert call([]) == 2  # no Auth-Key
    assert call(["--bogus"]) == 2  # argparse error
    assert call(["--key", KEY, "download", SHA]) == 1  # SystemExit(<message>) maps to 1
    assert call(["-V"]) == 0
    capsys.readouterr()


def test_loader_run_named_reaches_main_through_both_names(
    monkeypatch, tmp_path, capsys
):
    """End to end through run_named on the real addon file; both spellings load the same script."""
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "workspace"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    write_policy(tmp_path / "workspace")
    cached = loader.import_script(ADDON_DIR / "chromahaus.py")
    fake = Fake().install(monkeypatch)
    monkeypatch.setattr(
        cached, "api_client", fake.api_client
    )  # the cached module bound the real one at import
    monkeypatch.setattr(
        cached, "HTTP", None
    )  # other test files may have cached a client under another workspace
    monkeypatch.setattr(cached, "NO_COLOR", False, raising=False)
    tool_file = Path(bughunt_scanner.__file__).resolve()
    try:
        for name in ("chroma", "chromahaus"):
            rc = loader.run_named(
                name, ["--key", KEY, "recent"], tool_file=tool_file, scan_main=None
            )
            assert rc == 0
        assert fake.urls == [f"{URLHAUS}/urls/recent/limit/25/"] * 2
    finally:
        if cached.HTTP is not None:
            cached.HTTP.close()
        capsys.readouterr()


# ---------------------------------------------------------------------------------------------------------------
# 3. Auth-Key resolution (spec 4.2)
# ---------------------------------------------------------------------------------------------------------------

KEY_FILES = {
    "config": (".config", "chromahaus", "auth.key"),
    "home": (".chromahaus.key",),
    "cwd": (".chromahaus.key",),
}

KEY_SCENARIOS = [
    pytest.param(
        "cli",
        {"ABUSECH_AUTH_KEY": "env", "ABUSE_CH_KEY": "alias"},
        {"config": "file"},
        "cli",
        id="cli-beats-everything",
    ),
    pytest.param("  cli  ", {}, {}, "cli", id="cli-is-stripped"),
    pytest.param(
        "", {"ABUSECH_AUTH_KEY": "env"}, {}, "env", id="empty-cli-counts-as-absent"
    ),
    pytest.param(
        None,
        {"ABUSECH_AUTH_KEY": "env", "ABUSE_CH_KEY": "alias"},
        {"config": "file"},
        "env",
        id="main-env-beats-alias-and-files",
    ),
    pytest.param(
        None, {"ABUSECH_AUTH_KEY": " env \n"}, {}, "env", id="env-is-stripped"
    ),
    pytest.param(
        None,
        {"ABUSE_CH_KEY": " alias "},
        {"config": "file"},
        "alias",
        id="alias-env-beats-files",
    ),
    pytest.param(
        None,
        {"ABUSECH_AUTH_KEY": "", "ABUSE_CH_KEY": "alias"},
        {},
        "alias",
        id="empty-main-env-falls-to-alias",
    ),
    pytest.param(
        None,
        {},
        {"config": "  cfg  \n", "home": "home", "cwd": "cwd"},
        "cfg",
        id="config-file-first-and-stripped",
    ),
    pytest.param(
        None, {}, {"home": "home\n", "cwd": "cwd"}, "home", id="home-file-second"
    ),
    pytest.param(None, {}, {"cwd": "cwd"}, "cwd", id="cwd-file-last"),
    pytest.param(
        None, {}, {"config": "  \n", "home": "home"}, "home", id="blank-file-is-skipped"
    ),
]


def write_key_files(rig, files):
    for where, text in files.items():
        base = rig.cwd if where == "cwd" else rig.home
        path = base.joinpath(*KEY_FILES[where])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


@pytest.mark.parametrize(("cli_key", "env", "files", "expected"), KEY_SCENARIOS)
def test_auth_key_resolution_order(rig, monkeypatch, cli_key, env, files, expected):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    write_key_files(rig, files)
    result = rig.run(["recent"] if cli_key is None else ["--key", cli_key, "recent"])
    assert result.rc == 0, result.err
    assert [seen.headers["auth-key"] for seen in rig.fake.seen] == [expected]


def test_an_unreadable_key_file_is_skipped_not_fatal(rig):
    (rig.home / ".config" / "chromahaus" / "auth.key").mkdir(
        parents=True
    )  # opening a directory raises OSError
    (rig.home / ".chromahaus.key").write_text("fallback\n", encoding="utf-8")
    result = rig.run(["recent"])
    assert result.rc == 0, result.err
    assert rig.fake.seen[0].headers["auth-key"] == "fallback"


def test_the_key_is_only_ever_a_header_never_printed_or_in_a_url_or_body(rig):
    secret = "SECRET-KEY-VALUE-123"
    rig.fake.default = lambda seen: reply_json(
        {"query_status": "ok", "data": [], "urls": [], "payloads": []}
    )
    for argv in (
        ["recent"],
        ["url", "http://x.example/"],
        ["tag", "mozi"],
        ["family", "Mozi"],
        ["bazaar"],
        ["iocs"],
        ["hash", SHA],
    ):
        result = rig.run(["--key", secret, *argv])
        assert result.rc == 0, result.err
        assert secret not in result.out and secret not in result.err
    rig.fake.default = (401, {}, b"no")
    failed = rig.run(["--key", secret, "recent"])
    assert failed.rc == 1 and secret not in failed.out + failed.err
    assert rig.fake.seen
    for seen in rig.fake.seen:
        assert seen.headers["auth-key"] == secret
        assert secret not in seen.url and secret.encode() not in seen.body


@pytest.mark.parametrize(
    "argv", EVERY_SUBCOMMAND, ids=lambda argv: " ".join(argv) or "no-subcommand"
)
def test_no_key_exits_2_with_a_howto_on_stdout_before_any_request_or_prompt(rig, argv):
    result = rig.run(argv)
    assert result.exited and result.exit_arg == 2 and result.rc == 2
    assert "ABUSECH_AUTH_KEY" in result.out and "auth.abuse.ch" in result.out
    assert result.err == ""
    assert result.out.count("\n") <= 12  # a short message, not the banner
    assert rig.fake.seen == [] and result.prompts == []


# ---------------------------------------------------------------------------------------------------------------
# 4. Request catalog and wire headers (spec 4.3, 4.4)
# ---------------------------------------------------------------------------------------------------------------


def assert_wire_headers(seen, kind):
    headers = seen.headers
    assert headers["auth-key"] == KEY
    assert headers["accept"] == "*/*"
    assert headers["user-agent"] == POLICY_UA  # the policy UA overwrites the tool's own
    for name, value in POLICY_REQUIRED_HEADERS.items():
        assert headers[name] == value
    assert set(seen.timeout.values()) == {45}
    if kind == "form":
        assert headers["content-type"] == FORM
    elif kind == "json":
        assert headers["content-type"] == JSON_TYPE
    else:
        assert "content-type" not in headers


CATALOG = [
    pytest.param(
        ["recent"], [plain_get(f"{URLHAUS}/urls/recent/limit/25/")], id="recent-default"
    ),
    pytest.param(
        ["-n", "7", "recent"],
        [plain_get(f"{URLHAUS}/urls/recent/limit/7/")],
        id="recent-n7",
    ),
    pytest.param(
        ["-n", "0", "recent"],
        [plain_get(f"{URLHAUS}/urls/recent/")],
        id="recent-n0-has-no-limit-segment",
    ),
    pytest.param(
        ["-n", "-3", "recent"],
        [plain_get(f"{URLHAUS}/urls/recent/limit/-3/")],
        id="recent-negative-passes-through",
    ),
    pytest.param(
        ["payloads"],
        [plain_get(f"{URLHAUS}/payloads/recent/limit/25/")],
        id="payloads-default",
    ),
    pytest.param(
        ["-n", "3", "payloads"],
        [plain_get(f"{URLHAUS}/payloads/recent/limit/3/")],
        id="payloads-n3",
    ),
    pytest.param(
        ["-n", "0", "payloads"],
        [plain_get(f"{URLHAUS}/payloads/recent/")],
        id="payloads-n0",
    ),
    pytest.param(
        ["url", "http://x.example/a b&c=d"],
        [form_post(f"{URLHAUS}/url/", b"url=http%3A%2F%2Fx.example%2Fa+b%26c%3Dd")],
        id="url-form-encoding",
    ),
    pytest.param(
        ["host", "evil.example"],
        [form_post(f"{URLHAUS}/host/", b"host=evil.example")],
        id="host",
    ),
    pytest.param(
        ["hash", M32],
        [
            form_post(f"{URLHAUS}/payload/", b"md5_hash=" + M32.encode()),
            form_post(BAZAAR, b"query=get_info&hash=" + M32.encode()),
            json_post(
                THREATFOX, b'{"query": "search_hash", "hash": "' + M32.encode() + b'"}'
            ),
        ],
        id="hash-32-is-md5-for-urlhaus",
    ),
    pytest.param(
        ["hash", H64],
        [
            form_post(f"{URLHAUS}/payload/", b"sha256_hash=" + H64.encode()),
            form_post(BAZAAR, b"query=get_info&hash=" + H64.encode()),
            json_post(
                THREATFOX, b'{"query": "search_hash", "hash": "' + H64.encode() + b'"}'
            ),
        ],
        id="hash-64-is-sha256-for-urlhaus",
    ),
    pytest.param(
        ["hash", M32.upper()],
        [
            form_post(f"{URLHAUS}/payload/", b"md5_hash=" + M32.encode()),
            form_post(BAZAAR, b"query=get_info&hash=" + M32.upper().encode()),
            json_post(
                THREATFOX,
                b'{"query": "search_hash", "hash": "' + M32.upper().encode() + b'"}',
            ),
        ],
        id="hash-urlhaus-lowercases-bazaar-and-threatfox-keep-the-typed-case",
    ),
    pytest.param(
        ["tag", "mozi"],
        [
            form_post(f"{URLHAUS}/tag/", b"tag=mozi"),
            form_post(BAZAAR, b"query=get_taginfo&tag=mozi&limit=25"),
        ],
        id="tag-default-limit",
    ),
    pytest.param(
        ["-n", "7", "tag", "mozi"],
        [
            form_post(f"{URLHAUS}/tag/", b"tag=mozi"),
            form_post(BAZAAR, b"query=get_taginfo&tag=mozi&limit=7"),
        ],
        id="tag-limit-follows-n",
    ),
    pytest.param(
        ["-n", "7", "family", "Emotet"],
        [
            form_post(f"{URLHAUS}/signature/", b"signature=Emotet"),
            json_post(
                THREATFOX, b'{"query": "malwareinfo", "malware": "Emotet", "limit": 7}'
            ),
            form_post(BAZAAR, b"query=get_siginfo&signature=Emotet&limit=7"),
        ],
        id="family-n7",
    ),
    pytest.param(
        ["family", "Emotet"],
        [
            form_post(f"{URLHAUS}/signature/", b"signature=Emotet"),
            json_post(
                THREATFOX, b'{"query": "malwareinfo", "malware": "Emotet", "limit": 25}'
            ),
            form_post(BAZAAR, b"query=get_siginfo&signature=Emotet&limit=25"),
        ],
        id="family-default-limit",
    ),
    pytest.param(
        ["iocs"],
        [json_post(THREATFOX, b'{"query": "get_iocs", "days": 1}')],
        id="iocs-default-1",
    ),
    pytest.param(
        ["iocs", "--days", "0"],
        [json_post(THREATFOX, b'{"query": "get_iocs", "days": 1}')],
        id="iocs-0-clamps-to-1",
    ),
    pytest.param(
        ["iocs", "--days", "-5"],
        [json_post(THREATFOX, b'{"query": "get_iocs", "days": 1}')],
        id="iocs-negative-clamps-to-1",
    ),
    pytest.param(
        ["iocs", "--days", "3"],
        [json_post(THREATFOX, b'{"query": "get_iocs", "days": 3}')],
        id="iocs-3",
    ),
    pytest.param(
        ["iocs", "--days", "7"],
        [json_post(THREATFOX, b'{"query": "get_iocs", "days": 7}')],
        id="iocs-7",
    ),
    pytest.param(
        ["iocs", "--days", "99"],
        [json_post(THREATFOX, b'{"query": "get_iocs", "days": 7}')],
        id="iocs-99-clamps-to-7",
    ),
    pytest.param(
        ["fox", "1.2.3.4"],
        [json_post(THREATFOX, b'{"query": "search_ioc", "search_term": "1.2.3.4"}')],
        id="fox",
    ),
    pytest.param(
        ["bazaar"],
        [form_post(BAZAAR, b"query=get_recent&selector=25")],
        id="bazaar-default",
    ),
    pytest.param(
        ["-n", "9", "bazaar"],
        [form_post(BAZAAR, b"query=get_recent&selector=9")],
        id="bazaar-n9",
    ),
    pytest.param(["feodo"], [plain_get(FEODO)], id="feodo"),
    pytest.param(["sslbl"], [plain_get(SSLBL)], id="sslbl"),
]


@pytest.mark.parametrize(("argv", "expected"), CATALOG)
def test_request_catalog_matches_the_wire_byte_for_byte(rig, argv, expected):
    result = rig.cli(*argv)
    assert result.rc == 0, result.err
    assert [(s.method, s.url, s.body or None) for s in rig.fake.seen] == [
        (m, u, b) for m, u, b, _ in expected
    ]
    for seen, (_method, _url, _body, kind) in zip(rig.fake.seen, expected):
        assert_wire_headers(seen, kind)


# ---------------------------------------------------------------------------------------------------------------
# 5. hunt classification (spec 4.5), observed through the wire and the heading
# ---------------------------------------------------------------------------------------------------------------

FIRST_REQUEST = {
    "url": (f"{URLHAUS}/url/", 2),
    "hash": (f"{URLHAUS}/payload/", 3),
    "ip": (f"{URLHAUS}/host/", 2),
    "host": (f"{URLHAUS}/host/", 2),
    "term": (f"{URLHAUS}/tag/", 3),
}

HUNT_VECTORS = [
    ("http://x", "url"),
    ("HTTPS://X.EXAMPLE", "url"),
    ("ftp://x.example", "term"),
    ("a" * 32, "hash"),
    ("b" * 40, "hash"),
    ("c" * 64, "hash"),
    ("A" * 32, "hash"),
    ("a" * 31, "term"),
    ("1.2.3.4", "ip"),
    ("1.2.3.4:80", "ip"),
    ("1.2.3.4:999999", "term"),
    ("999.1.1.1", "ip"),
    ("1.2.3", "host"),
    ("1.2.3.4.5", "host"),
    ("evil.example", "host"),
    ("evil.example.", "host"),
    ("-bad.example", "term"),
    ("bad-.example", "term"),
    ("a_b.example", "term"),
    ("xn--bcher-kva.example", "host"),
    ("localhost", "term"),
    ("mozi", "term"),
    ("evil.example:80", "term"),
    ("[::1]", "term"),
    ("e" * 63 + ".example", "host"),
    ("e" * 64 + ".example", "term"),
    ("a.b", "host"),
    ("emotet family", "term"),
]


@pytest.mark.parametrize(
    ("indicator", "kind"), HUNT_VECTORS, ids=lambda value: value[:30]
)
def test_hunt_classifies_indicators_and_queries_the_matching_feeds(
    rig, indicator, kind
):
    result = (
        rig.cli("hunt", "--", indicator)
        if indicator.startswith("-")
        else rig.cli("hunt", indicator)
    )
    assert result.rc == 0, result.err
    first_url, request_count = FIRST_REQUEST[kind]
    assert len(rig.fake.seen) == request_count
    assert rig.fake.seen[0].url == first_url
    heading = next(line for line in result.out.splitlines() if indicator in line)
    assert re.search(rf"\b{kind}\b", heading.replace(indicator, " "), re.IGNORECASE), (
        heading
    )


HUNT_REQUEST_SETS = [
    pytest.param(
        "http://evil.example/x?a=1&b=2",
        [
            form_post(
                f"{URLHAUS}/url/", b"url=http%3A%2F%2Fevil.example%2Fx%3Fa%3D1%26b%3D2"
            ),
            json_post(
                THREATFOX,
                b'{"query": "search_ioc", "search_term": "http://evil.example/x?a=1&b=2"}',
            ),
        ],
        id="url",
    ),
    pytest.param(
        "8.8.8.8:8080",
        [
            form_post(f"{URLHAUS}/host/", b"host=8.8.8.8"),
            json_post(
                THREATFOX, b'{"query": "search_ioc", "search_term": "8.8.8.8:8080"}'
            ),
        ],
        id="ip-port-is-stripped-for-urlhaus-but-full-for-threatfox",
    ),
    pytest.param(
        "evil.example",
        [
            form_post(f"{URLHAUS}/host/", b"host=evil.example"),
            json_post(
                THREATFOX, b'{"query": "search_ioc", "search_term": "evil.example"}'
            ),
        ],
        id="host",
    ),
    pytest.param(
        "999.999.999.999",
        [
            form_post(f"{URLHAUS}/host/", b"host=999.999.999.999"),
            json_post(
                THREATFOX, b'{"query": "search_ioc", "search_term": "999.999.999.999"}'
            ),
        ],
        id="dotted-quad-has-no-range-check",
    ),
    pytest.param(
        "emotet",
        [
            form_post(f"{URLHAUS}/tag/", b"tag=emotet"),
            json_post(THREATFOX, b'{"query": "search_ioc", "search_term": "emotet"}'),
            form_post(BAZAAR, b"query=get_taginfo&tag=emotet&limit=25"),
        ],
        id="term-uses-fixed-bazaar-limit-25",
    ),
    pytest.param(
        "d" * 40,
        [
            form_post(f"{URLHAUS}/payload/", b"sha256_hash=" + b"d" * 40),
            form_post(BAZAAR, b"query=get_info&hash=" + b"d" * 40),
            json_post(
                THREATFOX, b'{"query": "search_hash", "hash": "' + b"d" * 40 + b'"}'
            ),
        ],
        id="sha1-length-goes-to-urlhaus-as-sha256_hash",
    ),
]


@pytest.mark.parametrize(("indicator", "expected"), HUNT_REQUEST_SETS)
def test_hunt_request_sets_per_kind_match_the_wire(rig, indicator, expected):
    result = rig.cli(
        "-n", "99", "hunt", indicator
    )  # -n must not leak into hunt's fixed limits
    assert result.rc == 0, result.err
    assert [(s.method, s.url, s.body) for s in rig.fake.seen] == [
        (m, u, b) for m, u, b, _ in expected
    ]
    for seen, (_m, _u, _b, kind) in zip(rig.fake.seen, expected):
        assert_wire_headers(seen, kind)


def test_the_hash_subcommand_is_the_same_as_hunt_on_a_digest(rig):
    rig.cli("hash", H64)
    hash_requests = [(s.method, s.url, s.body) for s in rig.fake.seen]
    rig.fake.seen.clear()
    rig.cli("hunt", H64)
    assert [(s.method, s.url, s.body) for s in rig.fake.seen] == hash_requests


# ---------------------------------------------------------------------------------------------------------------
# 6. Status mapping (spec 4.3)
# ---------------------------------------------------------------------------------------------------------------


def test_http_401_429_and_5xx_become_rc1_with_the_reason_on_stderr(rig):
    for status, needles in (
        (401, ["401", "auth.abuse.ch"]),
        (429, ["429", "rate"]),
        (500, ["HTTP 500", f"{URLHAUS}/url/", "boom line2"]),
        (403, ["HTTP 403", "denied"]),
    ):
        body = b"boom\nline2" if status == 500 else b"denied" if status == 403 else b"x"
        rig.fake.default = (status, {"content-type": "text/plain"}, body)
        result = rig.cli("url", "http://x.example/")
        assert result.rc == 1, status
        assert result.err.strip().startswith("!") and all(
            n in result.err for n in needles
        ), result.err


def test_error_body_snippet_is_cut_at_300_characters(rig):
    rig.fake.default = (502, {"content-type": "text/plain"}, b"x" * 400)
    result = rig.cli("recent")
    assert result.rc == 1
    assert "x" * 300 in result.err and "x" * 301 not in result.err


def test_get_endpoints_map_status_codes_the_same_way(rig):
    rig.fake.default = (401, {}, b"no")
    result = rig.cli("recent")
    assert result.rc == 1 and "401" in result.err


@pytest.mark.parametrize(
    "failure",
    [
        lambda request: httpx.ConnectError("connection refused", request=request),
        lambda request: httpx.ReadTimeout("timed out", request=request),
    ],
    ids=["connect-error", "timeout"],
)
def test_transport_errors_become_rc1_network_errors_naming_the_url(rig, failure):
    def handler(seen, number):
        raise failure(httpx.Request(seen.method, seen.url))

    rig.fake.handler = handler
    result = rig.cli("recent")
    assert result.rc == 1
    assert (
        "network error" in result.err
        and f"{URLHAUS}/urls/recent/limit/25/" in result.err
    )


@pytest.mark.parametrize(
    ("content_type", "body", "document"),
    [
        ("text/html", b"<html>", {"_raw": "<html>", "query_status": "ok"}),
        ("application/json", b"{bad", {"_raw": "{bad", "query_status": "parse_error"}),
        ("text/plain", b"[1,2]", [1, 2]),
        (
            "application/json; charset=utf-8",
            b'{"query_status":"ok","urls":[]}',
            {"query_status": "ok", "urls": []},
        ),
    ],
    ids=[
        "html-200",
        "bad-json",
        "json-array-without-json-type",
        "json-type-with-charset",
    ],
)
def test_json_endpoints_wrap_or_parse_bodies_as_documented(
    rig, content_type, body, document
):
    rig.fake.default = (200, {"content-type": content_type}, body)
    result = rig.cli("--json", "url", "http://x.example/")
    assert result.rc == 0, result.err
    assert json_documents(result.out) == [document]


# ---------------------------------------------------------------------------------------------------------------
# 7. fetch_text_list (spec 2.1) [T]
# ---------------------------------------------------------------------------------------------------------------


def test_fetch_text_list_returns_decoded_text_and_sends_the_key(rig):
    rig.fake.routes[FEODO] = reply_text("1.1.1.1\n2.2.2.2\n")
    assert rig.module.fetch_text_list(FEODO, "secret") == "1.1.1.1\n2.2.2.2\n"
    assert rig.fake.seen[0].headers["auth-key"] == "secret"


@pytest.mark.parametrize("status", [401, 403, 404, 500, 503])
def test_fetch_text_list_raises_runtimeerror_for_401_and_any_status_over_399(
    rig, status
):
    rig.fake.routes[FEODO] = (status, {}, b"x")
    with pytest.raises(RuntimeError) as raised:
        rig.module.fetch_text_list(FEODO, "k")
    assert str(status) in str(raised.value) and FEODO in str(raised.value)


def test_fetch_text_list_raises_runtimeerror_on_network_policy_and_host_guard_failures(
    rig,
):
    def refuse(seen, number):
        raise httpx.ConnectError("down", request=httpx.Request("GET", seen.url))

    rig.fake.handler = refuse
    with pytest.raises(RuntimeError, match="network error"):
        rig.module.fetch_text_list(FEODO, "k")
    rig.fake.handler = None
    rig.fake.seen.clear()
    rig.policy(grants_without("https://feodotracker.abuse.ch"))
    with pytest.raises(RuntimeError):
        rig.module.fetch_text_list(FEODO, "k")
    with pytest.raises(
        RuntimeError
    ):  # not an abuse.ch host at all: the allow-list refuses before anything is sent
        rig.module.fetch_text_list("https://evil.example/list.txt", "k")
    assert rig.fake.seen == []


# ---------------------------------------------------------------------------------------------------------------
# 8. Redirects (spec 4.3, 5.1) [T for the off-host key safety]
# ---------------------------------------------------------------------------------------------------------------


def test_an_in_policy_abuse_ch_redirect_is_followed_and_still_carries_the_key(rig):
    rig.fake.routes[FEODO] = (302, {"location": f"{URLHAUS}/hop"}, b"")
    rig.fake.routes[f"{URLHAUS}/hop"] = reply_text("9.9.9.9\n")
    result = rig.cli("feodo")
    assert result.rc == 0, result.err
    assert rig.fake.urls == [FEODO, f"{URLHAUS}/hop"]
    assert [s.headers["auth-key"] for s in rig.fake.seen] == [KEY, KEY]
    assert "9.9.9.9" in result.out


def test_a_relative_redirect_resolves_against_the_current_url(rig):
    rig.fake.routes[FEODO] = (301, {"location": "/downloads/other.txt"}, b"")
    rig.fake.routes["https://feodotracker.abuse.ch/downloads/other.txt"] = reply_text(
        "8.8.4.4\n"
    )
    result = rig.cli("feodo")
    assert result.rc == 0 and "8.8.4.4" in result.out


OFF_HOST_TARGETS = [
    "https://evil.example/x",
    "https://abuse.ch.evil.example/x",
    "https://evilabuse.ch/x",
    "https://abuse.ch@evil.example/x",
]


@pytest.mark.parametrize("target", OFF_HOST_TARGETS)
def test_an_off_host_redirect_is_blocked_by_the_host_allow_list_even_when_policy_would_allow_it(
    rig, target
):
    """Policy grants the hostile origins on purpose, so only the abuse.ch host guard stands between the key and them."""
    grants = dict(FULL_GRANTS)
    for origin in (
        "https://evil.example",
        "https://abuse.ch.evil.example",
        "https://evilabuse.ch",
    ):
        grants[origin] = ("GET",)
    rig.policy(grants)
    rig.fake.routes[FEODO] = (302, {"location": target}, b"")
    result = rig.cli("feodo")
    assert result.rc == 1
    assert "network error" in result.err and "request was not sent" in result.err
    assert rig.fake.urls == [FEODO]
    assert all(seen.host.endswith("abuse.ch") for seen in rig.fake.seen)


def redirect_chain(length):
    base = "https://feodotracker.abuse.ch"
    routes = {FEODO: (302, {"location": "/c1"}, b"")}
    for step in range(1, length):
        routes[f"{base}/c{step}"] = (302, {"location": f"/c{step + 1}"}, b"")
    routes[f"{base}/c{length}"] = reply_text("7.7.7.7\n")
    return routes


def test_get_redirects_are_followed_up_to_five_hops(rig):
    rig.fake.routes.update(redirect_chain(5))
    result = rig.cli("feodo")
    assert result.rc == 0 and len(rig.fake.seen) == 6 and "7.7.7.7" in result.out


def test_a_sixth_redirect_is_not_followed_and_ends_with_an_empty_listing(rig):
    rig.fake.routes.update(redirect_chain(6))
    result = rig.cli("feodo")
    assert result.rc == 0 and len(rig.fake.seen) == 6 and "7.7.7.7" not in result.out


# ---------------------------------------------------------------------------------------------------------------
# 9. Egress and policy posture (spec 5)
# ---------------------------------------------------------------------------------------------------------------

BATTERY = [
    ["recent"],
    ["bazaar"],
    ["iocs"],
    ["feodo"],
    ["sslbl"],
    ["hash", SHA],
    ["family", "Mozi"],
    ["tag", "mozi"],
    ["url", "http://x.example/"],
    ["host", "x.example"],
    ["payloads"],
    ["fox", "x"],
]


def test_every_request_is_a_passive_operation_on_one_of_the_five_origins_with_one_evidence_run_each(
    rig,
):
    for argv in BATTERY:
        assert rig.cli(*argv).rc == 0
    manifests = rig.manifests()
    assert (
        len(manifests) == len(rig.fake.seen) > 0
    )  # the egress ledger recorded every request
    origins = set()
    for manifest in manifests:
        assert (
            manifest["operation"] == "passive" and manifest["decision"] == "permitted"
        )
        parts = httpx.URL(manifest["target"])
        origins.add(f"{parts.scheme}://{parts.host}")
    assert origins == set(FULL_GRANTS)


def test_auth_key_and_policy_headers_only_ever_go_to_abuse_ch_hosts(rig):
    for argv in BATTERY:
        rig.cli(*argv)
    assert rig.fake.seen
    for seen in rig.fake.seen:
        assert seen.host == "abuse.ch" or seen.host.endswith(".abuse.ch")
        assert seen.headers["auth-key"] == KEY


EXACT_ORIGIN_CASES = [
    ("https://urlhaus-api.abuse.ch", ["recent"]),
    ("https://mb-api.abuse.ch", ["bazaar"]),
    ("https://threatfox-api.abuse.ch", ["iocs"]),
    ("https://feodotracker.abuse.ch", ["feodo"]),
    ("https://sslbl.abuse.ch", ["sslbl"]),
]


@pytest.mark.parametrize(
    ("origin", "argv"),
    EXACT_ORIGIN_CASES,
    ids=[origin for origin, _ in EXACT_ORIGIN_CASES],
)
def test_policy_must_grant_each_exact_origin_or_the_command_sends_nothing(
    rig, origin, argv
):
    rig.policy(grants_without(origin))
    result = rig.cli(*argv)
    assert result.rc == 1
    assert "asset-unknown" in result.err and "network error" in result.err
    assert rig.fake.seen == []


def test_an_apex_abuse_ch_grant_does_not_cover_the_api_subdomains(rig):
    rig.policy({"https://abuse.ch": ("GET", "POST")})
    for argv in (["recent"], ["bazaar"], ["iocs"], ["feodo"], ["sslbl"]):
        assert rig.cli(*argv).rc == 1
    assert rig.fake.seen == []


def test_only_the_passive_operation_is_required(rig):
    rig.policy(permissions=only_permitted("passive"))
    for argv in (["recent"], ["bazaar"], ["iocs"], ["feodo"], ["sslbl"]):
        result = rig.cli(*argv)
        assert result.rc == 0, (argv, result.err)
    assert len(rig.fake.seen) == 5


def test_without_the_passive_permission_nothing_is_sent(rig):
    rig.policy(permissions={op: op != "passive" for op in only_permitted()})
    for argv in (["recent"], ["bazaar"], ["iocs"], ["feodo"], ["sslbl"]):
        result = rig.cli(*argv)
        assert result.rc == 1 and "operation-disallowed" in result.err
    assert rig.fake.seen == []


@pytest.mark.parametrize(
    ("grants", "argv", "denied"),
    [
        (
            {**FULL_GRANTS, "https://urlhaus-api.abuse.ch": ("GET",)},
            ["url", "http://x.example/"],
            True,
        ),
        ({**FULL_GRANTS, "https://urlhaus-api.abuse.ch": ("GET",)}, ["recent"], False),
        ({**FULL_GRANTS, "https://urlhaus-api.abuse.ch": ("POST",)}, ["recent"], True),
        ({**FULL_GRANTS, "https://mb-api.abuse.ch": ("GET",)}, ["bazaar"], True),
        ({**FULL_GRANTS, "https://threatfox-api.abuse.ch": ("GET",)}, ["iocs"], True),
        ({**FULL_GRANTS, "https://feodotracker.abuse.ch": ("POST",)}, ["feodo"], True),
        ({**FULL_GRANTS, "https://sslbl.abuse.ch": ("POST",)}, ["sslbl"], True),
    ],
    ids=[
        "urlhaus-post-needs-post",
        "urlhaus-get-ok-on-get",
        "urlhaus-get-needs-get",
        "bazaar-is-post",
        "threatfox-is-post",
        "feodo-is-get",
        "sslbl-is-get",
    ],
)
def test_methods_used_per_origin_are_exactly_the_documented_ones(
    rig, grants, argv, denied
):
    rig.policy(grants)
    result = rig.cli(*argv)
    if denied:
        assert (
            result.rc == 1
            and "asset-method-disallowed" in result.err
            and rig.fake.seen == []
        )
    else:
        assert result.rc == 0, result.err


def test_missing_policy_blocks_every_command_before_anything_is_sent(rig):
    (rig.workspace / "policy.json").unlink()
    for argv in (["recent"], ["url", "http://x.example/"], ["feodo"]):
        result = rig.cli(*argv)
        assert result.rc == 1 and "policy-missing-or-invalid" in result.err
    assert rig.fake.seen == []


FORBIDDEN_MODULES = (
    "socket",
    "subprocess",
    "requests",
    "urllib3",
    "http.client",
    "urllib.request",
    "ssl",
    "playwright",
    "selenium",
    "zipfile",
    "tarfile",
    "ctypes",
    "pickle",
    "marshal",
    "webbrowser",
)
RAW_CLIENT_CALLS = {
    "Client",
    "AsyncClient",
    "get",
    "post",
    "put",
    "delete",
    "head",
    "options",
    "request",
    "stream",
}


def test_source_has_no_raw_network_browser_unpack_or_exec_primitives():
    """Spec 1 and 5.1: the only dependencies are httpx types and bughunt.core; samples are never unpacked or run."""
    tree = ast.parse(SUBJECT.read_text(encoding="utf-8"))
    imported, problems = set(), []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(f"{node.module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "httpx" and func.attr in RAW_CLIENT_CALLS:
                    problems.append(f"httpx.{func.attr}() at line {node.lineno}")
                if func.value.id == "os" and (
                    func.attr in {"system", "popen", "startfile"}
                    or func.attr.startswith(("spawn", "exec"))
                ):
                    problems.append(f"os.{func.attr}() at line {node.lineno}")
            if isinstance(func, ast.Name) and func.id in {
                "eval",
                "exec",
                "compile",
                "__import__",
            }:
                problems.append(f"{func.id}() at line {node.lineno}")
        elif isinstance(node, ast.keyword):
            if node.arg == "verify" and getattr(node.value, "value", True) is False:
                problems.append("verify=False")
            if node.arg == "trust_env" and getattr(node.value, "value", False) is True:
                problems.append("trust_env=True")
            if (
                node.arg == "follow_redirects"
                and getattr(node.value, "value", False) is True
            ):
                problems.append("follow_redirects=True")
    banned = sorted(
        name
        for name in imported
        if any(name == m or name.startswith(m + ".") for m in FORBIDDEN_MODULES)
    )
    assert not banned and not problems, (banned, problems)


def test_the_dns_and_tcp_tripwires_are_live(no_real_network):
    with pytest.raises(AssertionError):
        socket.getaddrinfo("abuse.ch", 443)
    with pytest.raises(AssertionError):
        socket.create_connection(("abuse.ch", 443))
    no_real_network.clear()  # these two trips were the point of this test
