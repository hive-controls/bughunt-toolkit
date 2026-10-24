"""Characterization oracle for `bughunt.console.catalog` and the catalog JSON contract
(M2 clean-room rebuild, spec sections 2.x and 9).

Taxonomy tables are facts (PINNED/CONTRACT); the prose copy (`summary`, `PHASE_PURPOSE`,
`MODULE_WHEN`, `BUILTIN_SUMMARIES`) is FREE and only checked for non-emptiness.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from collections import Counter
from pathlib import Path

import pytest

from bughunt import VERSION
from bughunt.console import catalog, readiness
from bughunt.console.catalog_export import SCHEMA_VERSION, export_catalog
from bughunt.console.options import load_spec
from bughunt.modules import MODULES

from console_support import (  # noqa: F401  (env is a pytest fixture)
    BUILD_PARSER,
    REPO_ROOT,
    SCANNER_FILE,
    clean_subprocess_env,
    env,
    make_project,
)

PHASES = [
    (
        "Engagement",
        [
            "scope",
            "policy",
            "identity",
            "session",
            "verify",
            "ledger",
            "roost",
            "route",
        ],
    ),
    (
        "Recon",
        [
            "scan",
            "silk",
            "ct",
            "dns",
            "whois",
            "mail",
            "cert",
            "vhost",
            "redirect",
            "robots",
            "pulse",
        ],
    ),
    ("Capture", ["snare", "clutch", "exchange", "carve", "blaze", "quill"]),
    (
        "Test",
        [
            "repeater",
            "replay",
            "discover",
            "idor",
            "forms",
            "diff",
            "jwt",
            "decode",
            "skiff",
        ],
    ),
    ("Labs", ["race", "desync", "ws"]),
    ("Engines", ["engine", "zap", "oast"]),
    ("Intel", ["phish", "ioc", "chroma", "urlscan", "tcurl"]),
]

# command, folder, script, aliases, disabled
REFERENCE_FACTS = [
    ("pulse", "pulse", "pulse.py", (), False),
    ("ct", "crt-scout", "crt-scout.py", ("crt-scout",), False),
    ("carve", "flowcarve", "flowcarve.py", ("flowcarve",), False),
    ("phish", "Lanternjaw", "lanternjaw.py", ("lanternjaw",), False),
    ("ioc", "IOCaw", "iocaw.py", ("iocaw",), False),
    ("chroma", "chromahaus", "chromahaus.py", ("chromahaus",), False),
    ("urlscan", "urlscan", "urlscan.py", (), False),
    ("tcurl", "tcurl", "tcurl.py", (), False),
    ("skiff", "skiff", "skiff.py", (), False),
]


# --------------------------------------------------------------------------------------
# 2.1 / 2.2 taxonomy tables
# --------------------------------------------------------------------------------------


def test_module_groups_are_the_seven_lifecycle_phases_in_order():
    assert [
        (title, list(members)) for title, members in catalog.MODULE_GROUPS
    ] == PHASES
    assert isinstance(catalog.MODULE_GROUPS, tuple)


def test_module_groups_cover_scan_every_builtin_module_and_every_reference_exactly_once():
    members = [name for _title, group in catalog.MODULE_GROUPS for name in group]
    assert len(members) == 45 == len(set(members))
    assert set(members) == {
        "scan",
        *MODULES,
        *(tool.command for tool in catalog.REFERENCES),
    }
    assert len(MODULES) == 35


def test_references_are_the_nine_tools_in_order_with_on_disk_facts():
    assert [
        (
            t.command,
            t.folder,
            t.script,
            tuple(t.aliases),
            t.command in catalog.DISABLED_REFERENCES,
        )
        for t in catalog.REFERENCES
    ] == REFERENCE_FACTS


def test_reference_summaries_are_one_non_empty_sentence_each():
    for tool in catalog.REFERENCES:
        assert isinstance(tool.summary, str) and tool.summary.strip(), tool.command
        assert "\n" not in tool.summary


def test_reference_records_are_immutable():
    tool = catalog.REFERENCES[0]
    with pytest.raises(Exception):
        tool.command = "other"


def test_no_reference_is_disabled():
    assert set(catalog.DISABLED_REFERENCES) == set()
    assert isinstance(catalog.DISABLED_REFERENCES, frozenset)
    for command in (
        "carve",
        "pulse",
        "ioc",
        "chroma",
        "phish",
        "urlscan",
        "ct",
        "skiff",
        "tcurl",
    ):
        assert command not in catalog.DISABLED_REFERENCES


@pytest.mark.parametrize("tool", catalog.REFERENCES, ids=lambda t: t.command)
def test_every_reference_script_ships_in_the_repo_addons(tool):
    assert (REPO_ROOT / "addons" / tool.folder / tool.script).is_file()


def test_phase_purpose_has_one_non_empty_line_per_phase():
    for title, _members in PHASES:
        purpose = catalog.phase_purpose(title)
        assert purpose.strip() and "\n" not in purpose, title
    assert catalog.phase_purpose("Nope") == ""
    assert catalog.phase_purpose("recon") == ""  # titles are matched exactly here


def test_module_when_has_a_line_for_every_member():
    for _title, members in PHASES:
        for name in members:
            assert catalog.module_when(name).strip(), name


def test_module_when_canonicalises_aliases_and_returns_empty_for_unknown():
    assert catalog.module_when("crt-scout") == catalog.module_when("ct") != ""
    assert catalog.module_when("lanternjaw") == catalog.module_when("phish")
    assert catalog.module_when("nope") == ""
    assert catalog.module_when("") == ""


def test_builtin_summaries_are_the_eleven_command_blurbs():
    assert set(catalog.BUILTIN_SUMMARIES) == {
        "scan",
        "console",
        "modules",
        "catalog",
        "guide",
        "doctor",
        "setup",
        "examples",
        "completion",
        "version",
        "help",
    }
    for name, text in catalog.BUILTIN_SUMMARIES.items():
        assert text.strip(), name


# --------------------------------------------------------------------------------------
# 2.5 functions
# --------------------------------------------------------------------------------------


def test_group_names_are_the_titles_in_order():
    assert catalog.group_names() == [title for title, _ in PHASES]


@pytest.mark.parametrize(
    "token,expected",
    [
        ("recon", "Recon"),
        ("RECON", "Recon"),
        ("Recon", "Recon"),
        ("  recon  ", "Recon"),
        ("\tintel\n", "Intel"),
        ("engagement", "Engagement"),
        ("", None),
        ("   ", None),
        ("recons", None),
        ("scan", None),
        ("pulse", None),
        ("rec on", None),
    ],
)
def test_match_group_is_case_insensitive_and_strips_whitespace(token, expected):
    assert catalog.match_group(token) == expected


def test_group_for_is_exact_and_case_sensitive():
    assert catalog.group_for("engine") == "Engines"
    assert catalog.group_for("replay") == "Test"
    assert catalog.group_for("scan") == "Recon"
    assert catalog.group_for("tcurl") == "Intel"
    assert catalog.group_for("Engine") is None
    assert catalog.group_for("crt-scout") is None  # aliases are not members
    assert catalog.group_for("nope") is None
    for title, members in PHASES:
        for name in members:
            assert catalog.group_for(name) == title


@pytest.mark.parametrize(
    "token,expected",
    [
        ("engine", "engine"),
        ("scope", "scope"),
        ("pulse", "pulse"),
        ("ct", "ct"),
        ("crt-scout", "ct"),
        ("flowcarve", "carve"),
        ("lanternjaw", "phish"),
        ("iocaw", "ioc"),
        ("chromahaus", "chroma"),
        ("scan", None),  # `scan` is not in MODULES; callers special-case it
        ("Pulse", None),
        ("nope", None),
        ("", None),
    ],
)
def test_reference_canonical(token, expected):
    assert catalog.reference_canonical(token) == expected


def test_tool_by_command_matches_command_only_not_aliases():
    assert catalog.tool_by_command("ct").folder == "crt-scout"
    assert catalog.tool_by_command("crt-scout") is None
    assert catalog.tool_by_command("scan") is None
    assert catalog.tool_by_command("engine") is None
    assert catalog.tool_by_command("tcurl").script == "tcurl.py"


# --------------------------------------------------------------------------------------
# 2.2 import-time invariant (a subprocess: it fires while importing, before any test)
# --------------------------------------------------------------------------------------

_DRIFT_SCRIPT = textwrap.dedent(
    """
    import sys
    import bughunt.modules as modules
    assert "bughunt.console.catalog" not in sys.modules
    {mutation}
    try:
        import bughunt.console.catalog
    except RuntimeError as exc:
        print("DRIFT", exc)
    else:
        print("IMPORTED")
    """
)


def _import_with(mutation: str, tmp_path: Path) -> str:
    done = subprocess.run(
        [sys.executable, "-c", _DRIFT_SCRIPT.format(mutation=mutation)],
        cwd=tmp_path,
        env=clean_subprocess_env(tmp_path),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr[-400:]
    return done.stdout.strip()


def test_import_succeeds_when_modules_and_groups_agree(tmp_path):
    assert _import_with("pass", tmp_path) == "IMPORTED"


def test_import_fails_when_a_module_is_missing_from_the_groups(tmp_path):
    assert _import_with(
        'modules.MODULES["brand_new_module"] = "x"', tmp_path
    ).startswith("DRIFT")


def test_import_fails_when_a_grouped_module_vanishes_from_modules(tmp_path):
    assert _import_with('modules.MODULES.pop("scope")', tmp_path).startswith("DRIFT")


# --------------------------------------------------------------------------------------
# 2.6 addon_roots / locate_script (post-M0: anchored at tool_file.resolve().parents[2])
# --------------------------------------------------------------------------------------


@pytest.fixture
def no_addon_env(monkeypatch):
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)


def test_addon_roots_for_the_real_scanner_is_repo_addons_then_the_parent_addons(
    no_addon_env,
):
    roots = catalog.addon_roots(SCANNER_FILE)
    assert roots == [REPO_ROOT / "addons", REPO_ROOT.parent / "addons"]


def test_addon_roots_anchor_is_two_directories_above_the_tool_files_folder(
    no_addon_env, tmp_path
):
    tool_file = tmp_path / "a" / "b" / "c" / "d.py"
    tool_file.parent.mkdir(parents=True)
    tool_file.write_text("", encoding="utf-8")
    anchor = tool_file.resolve().parents[2]
    assert anchor == (tmp_path / "a").resolve()
    assert catalog.addon_roots(tool_file) == [
        anchor / "addons",
        anchor.parent / "addons",
    ]


def test_addon_roots_works_for_a_tool_file_that_does_not_exist(no_addon_env, tmp_path):
    tool_file = tmp_path / "proj" / "bughunt" / "core" / "scanner.py"
    roots = catalog.addon_roots(tool_file)
    assert roots[0] == (tmp_path / "proj").resolve() / "addons"


def test_addon_roots_env_root_comes_first(monkeypatch, tmp_path):
    custom = tmp_path / "custom-addons"
    monkeypatch.setenv("BUGHUNT_ADDONS", str(custom))
    roots = catalog.addon_roots(SCANNER_FILE)
    assert roots == [custom, REPO_ROOT / "addons", REPO_ROOT.parent / "addons"]


def test_addon_roots_expands_user_in_the_env_root(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("BUGHUNT_ADDONS", "~/my-addons")
    assert catalog.addon_roots(SCANNER_FILE)[0] == tmp_path / "my-addons"


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_addon_roots_ignores_a_blank_env_value(monkeypatch, blank):
    monkeypatch.setenv("BUGHUNT_ADDONS", blank)
    assert catalog.addon_roots(SCANNER_FILE) == [
        REPO_ROOT / "addons",
        REPO_ROOT.parent / "addons",
    ]


def test_addon_roots_env_value_is_stripped(monkeypatch, tmp_path):
    monkeypatch.setenv("BUGHUNT_ADDONS", f"  {tmp_path / 'x'}  ")
    assert catalog.addon_roots(SCANNER_FILE)[0] == tmp_path / "x"


def test_addon_roots_deduplicates_by_resolved_path(monkeypatch):
    monkeypatch.setenv("BUGHUNT_ADDONS", str(REPO_ROOT / "addons"))
    roots = catalog.addon_roots(SCANNER_FILE)
    assert [r.resolve() for r in roots] == [
        (REPO_ROOT / "addons").resolve(),
        (REPO_ROOT.parent / "addons").resolve(),
    ]
    assert len(roots) == 2


def test_addon_roots_is_not_sensitive_to_a_dotdot_spelling_of_the_same_file(
    no_addon_env,
):
    spelled = SCANNER_FILE.parent / ".." / "core" / "scanner.py"
    assert catalog.addon_roots(spelled)[0] == REPO_ROOT / "addons"


@pytest.mark.parametrize("tool", catalog.REFERENCES, ids=lambda t: t.command)
def test_locate_script_finds_every_shipped_addon_without_env(no_addon_env, tool):
    located = catalog.locate_script(tool, SCANNER_FILE)
    assert located is not None
    assert (
        located.resolve()
        == (REPO_ROOT / "addons" / tool.folder / tool.script).resolve()
    )


def test_locate_script_returns_none_when_no_root_has_the_file(no_addon_env, tmp_path):
    tool_file = make_project(tmp_path)
    for tool in catalog.REFERENCES:
        assert catalog.locate_script(tool, tool_file) is None


def test_locate_script_requires_a_regular_file(no_addon_env, tmp_path):
    tool_file = make_project(tmp_path)
    tool = catalog.tool_by_command("pulse")
    (tmp_path / "proj" / "addons" / tool.folder / tool.script).mkdir(
        parents=True
    )  # a directory
    assert catalog.locate_script(tool, tool_file) is None


def test_locate_script_searches_the_parent_addons_after_the_project_addons(
    no_addon_env, tmp_path
):
    tool_file = make_project(tmp_path)
    tool = catalog.tool_by_command("pulse")
    sibling = tmp_path / "addons" / tool.folder / tool.script
    sibling.parent.mkdir(parents=True)
    sibling.write_text("# sibling clone\n", encoding="utf-8")
    assert catalog.locate_script(tool, tool_file).resolve() == sibling.resolve()
    inner = tmp_path / "proj" / "addons" / tool.folder / tool.script
    inner.parent.mkdir(parents=True)
    inner.write_text("# project clone\n", encoding="utf-8")
    assert catalog.locate_script(tool, tool_file).resolve() == inner.resolve()


def test_locate_script_prefers_the_env_root_over_the_checkout(monkeypatch, tmp_path):
    tool = catalog.tool_by_command("pulse")
    custom = tmp_path / "custom" / tool.folder / tool.script
    custom.parent.mkdir(parents=True)
    custom.write_text("# custom\n", encoding="utf-8")
    monkeypatch.setenv("BUGHUNT_ADDONS", str(tmp_path / "custom"))
    assert catalog.locate_script(tool, SCANNER_FILE) == custom


# --------------------------------------------------------------------------------------
# 9. the catalog JSON contract (catalog_export is original; the rebuilt files must keep
#    producing everything it serialises)
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def exported(tmp_path_factory):
    scope = tmp_path_factory.mktemp("catalog-scope")
    mp = pytest.MonkeyPatch()
    try:
        for name in list(__import__("os").environ):
            if name.startswith("BUGHUNT_"):
                mp.delenv(name, raising=False)
        mp.setenv("BUGHUNT_SCOPE", str(scope))
        yield export_catalog(tool_file=SCANNER_FILE, build_parser=BUILD_PARSER)
    finally:
        mp.undo()


def _modules(data):
    return [m for phase in data["phases"] for m in phase["modules"]]


def test_catalog_top_level_shape(exported):
    assert list(exported) == ["schema_version", "version", "readiness", "phases"]
    assert exported["schema_version"] == 2 == SCHEMA_VERSION
    assert exported["version"] == VERSION
    assert set(exported["readiness"]) == {
        "scope_ready",
        "policy_verified",
        "has_identity",
        "next_step",
    }
    assert set(exported["readiness"]["next_step"]) == {"module", "message"}
    json.dumps(exported)  # serialisable


def test_catalog_phases_follow_module_groups(exported):
    assert [p["title"] for p in exported["phases"]] == [t for t, _ in PHASES]
    assert [p["name"] for p in exported["phases"]] == [t.lower() for t, _ in PHASES]
    for phase, (title, members) in zip(exported["phases"], PHASES):
        assert set(phase) == {"name", "title", "purpose", "block", "modules"}
        assert phase["purpose"] == catalog.phase_purpose(title) != ""
        assert [m["name"] for m in phase["modules"]] == members


def test_catalog_phase_blocks_come_from_readiness(exported):
    state = readiness.gather()
    for phase in exported["phases"]:
        assert phase["block"] == state.phase_block(phase["title"])
    assert {p["block"] for p in exported["phases"]} <= {
        "",
        "needs scope",
        "needs an owned lab in scope",
        "needs a verified policy",
    }


def test_catalog_has_44_modules_each_with_guidance(exported):
    modules = _modules(exported)
    assert len(modules) == 45
    for module in modules:
        assert module["when"] == catalog.module_when(module["name"]) != ""
        assert module["summary"].strip()
        assert isinstance(module["aliases"], list)
        assert isinstance(module["reference"], bool)
        assert module["disabled"] is (module["name"] in catalog.DISABLED_REFERENCES)


def test_catalog_module_keys(exported):
    for module in _modules(exported):
        assert {
            "name",
            "summary",
            "when",
            "aliases",
            "reference",
            "disabled",
            "form",
        } <= set(module)
        if module["form"] is None:
            assert module["unavailable"].strip()
        else:
            assert "unavailable" not in module


def test_catalog_reference_modules_carry_aliases_and_reference_flag(exported):
    by_name = {m["name"]: m for m in _modules(exported)}
    for command, _folder, _script, aliases, disabled in REFERENCE_FACTS:
        assert by_name[command]["reference"] is True
        assert by_name[command]["aliases"] == list(aliases)
        assert by_name[command]["disabled"] is disabled
    for name in list(MODULES) + ["scan"]:
        assert by_name[name]["reference"] is False
        assert by_name[name]["aliases"] == []


def test_catalog_forms_are_null_only_for_disabled_tools(exported):
    null_forms = sorted(m["name"] for m in _modules(exported) if m["form"] is None)
    assert null_forms == []
    for module in _modules(exported):
        if module["form"] is None:
            assert module["disabled"] is True
            assert "disabled" in module["unavailable"]


def test_catalog_has_45_forms_and_779_options(exported):
    forms = [m["form"] for m in _modules(exported) if m["form"] is not None]
    assert len(forms) == 45
    options = [o for form in forms for o in form["options"]]
    assert len(options) == 779
    assert Counter(o["kind"] for o in options) == {
        "value": 454,
        "bool": 179,
        "positional": 146,
    }


def test_catalog_22_forms_are_subcommand_forms(exported):
    names = Counter(
        m["form"]["command_name"] for m in _modules(exported) if m["form"] is not None
    )
    assert names == {"COMMAND": 22, "": 23}


def test_catalog_form_and_option_keys(exported):
    for module in _modules(exported):
        form = module["form"]
        if form is None:
            continue
        assert set(form) == {"command_name", "options", "subcommands"}
        for sub in form["subcommands"]:
            assert set(sub) == {"name", "help"}
        for option in form["options"]:
            assert set(option) == {
                "name",
                "flags",
                "kind",
                "required",
                "help",
                "choices",
                "default",
                "repeatable",
                "subcommand",
            }
            assert option["kind"] in {"positional", "bool", "value"}
            assert isinstance(option["flags"], list) and isinstance(
                option["choices"], list
            )
            assert isinstance(option["required"], bool) and isinstance(
                option["repeatable"], bool
            )


def test_catalog_scan_form_has_the_60_scan_options(exported):
    scan = next(m for m in _modules(exported) if m["name"] == "scan")
    options = scan["form"]["options"]
    assert scan["form"]["command_name"] == "" and scan["form"]["subcommands"] == []
    assert len(options) == 60
    assert Counter(o["kind"] for o in options) == {
        "bool": 26,
        "value": 33,
        "positional": 1,
    }
    names = [o["name"] for o in options]
    assert names[:10] == [
        "TARGETS",
        "DRY_RUN",
        "TARGETS_FILE",
        "COMMON",
        "PORTS",
        "PORT_RANGE",
        "ALL",
        "PORTS_FILE",
        "EXCLUDE_PORTS",
        "AUTHORIZED",
    ]
    assert [o["name"] for o in options if o["repeatable"]] == ["TARGETS", "HEADER"]
    assert [(o["name"], o["choices"]) for o in options if o["choices"]] == [
        ("METHOD", ["GET", "HEAD", "OPTIONS", "POST"])
    ]
    assert not any(o["required"] for o in options)
    by_name = {o["name"]: o for o in options}
    assert by_name["AUTHORIZED"]["flags"] == ["--authorized", "--i-own-this"]
    assert by_name["TARGETS_FILE"]["flags"] == ["-l", "--targets-file"]
    assert by_name["HEADER"]["flags"] == ["-H", "--header"]
    assert by_name["TARGETS"]["flags"] == []


def test_catalog_scan_default_notes(exported):
    scan = next(m for m in _modules(exported) if m["name"] == "scan")
    defaults = {o["name"]: o["default"] for o in scan["form"]["options"]}
    assert (
        defaults["PATHS"] == ""
    )  # BH-3: --paths defaults to None (contextual "/"), so the catalog notes no static default
    assert defaults["CONCURRENCY"] == "256"
    assert defaults["CONNECT_TIMEOUT"] == "1.2"
    assert defaults["HTTP_TIMEOUT"] == "4.0"
    assert defaults["DELAY"] == "0"
    assert defaults["RETRIES"] == "0"
    assert defaults["METHOD"] == "GET"
    assert defaults["MAX_BODY"] == "262144"
    assert defaults["USER_AGENT"] == "Bughunt/2.3 (+authorized surface..."
    assert defaults["DRY_RUN"] == ""  # switches carry no default note


def test_catalog_policy_form_lists_subcommand_options_before_the_command_positional(
    exported,
):
    policy = next(m for m in _modules(exported) if m["name"] == "policy")
    form = policy["form"]
    assert form["command_name"] == "COMMAND"
    declared = [
        "example",
        "import",
        "validate",
        "status",
        "check",
    ]  # argparse declaration order
    assert [s["name"] for s in form["subcommands"]] == declared
    assert form["options"][-1]["name"] == "COMMAND"
    assert form["options"][-1]["choices"] == declared
    assert form["options"][-1]["subcommand"] == ""
    assert any(o["subcommand"] == "check" for o in form["options"][:-1])
    assert [o["name"] for o in form["options"] if o["name"] == "FILE"].count(
        "FILE"
    ) >= 2  # shared names


def test_catalog_forms_match_what_the_console_loads(exported):
    for module in _modules(exported):
        if module["form"] is None:
            continue
        spec = load_spec(
            module["name"], tool_file=SCANNER_FILE, build_parser=BUILD_PARSER
        )
        assert [o["name"] for o in module["form"]["options"]] == [
            o.name for o in spec.options
        ]
        assert [(s["name"], s["help"]) for s in module["form"]["subcommands"]] == list(
            spec.subcommands
        )
        assert module["form"]["command_name"] == spec.command_name


def test_catalog_without_addons_keeps_builtin_forms_and_explains_missing_references(
    env,
):
    """The installed-wheel layout: no addons on disk -> reference forms are null with a reason."""
    tool_file = make_project(env.root)
    data = export_catalog(tool_file=tool_file, build_parser=BUILD_PARSER)
    modules = {m["name"]: m for m in _modules(data)}
    for command, *_rest in REFERENCE_FACTS:
        assert modules[command]["form"] is None, command
        assert modules[command]["unavailable"].strip(), command
    for name in list(MODULES) + ["scan"]:
        assert modules[name]["form"] is not None, name
    assert len([m for m in modules.values() if m["form"] is None]) == 9


def test_catalog_without_a_scan_parser_marks_scan_unavailable(env):
    data = export_catalog(tool_file=SCANNER_FILE, build_parser=None)
    scan = next(m for m in _modules(data) if m["name"] == "scan")
    assert scan["form"] is None and scan["unavailable"].strip()
    assert (
        sum(1 for m in _modules(data) if m["form"] is None) == 1
    )  # scan only; no reference is disabled
