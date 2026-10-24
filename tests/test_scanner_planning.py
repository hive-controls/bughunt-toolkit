"""Characterization oracle (M2): input handling, request planning, safety rails and the CLI surface.

Everything here goes through the public entry points only (``scan_main``, ``build_parser``, ``main``).
The scan plan is observed through ``--dry-run``, which prints one policy decision per planned request
and performs no DNS, socket or process activity, so these tests pin target / port / path assembly,
the size rails, the exit codes and the argparse contract without relying on any internal helper name.

Vectors are the behavior-spec Section 11.5 vectors (verified against the current tree).
"""

from __future__ import annotations

import argparse
import dataclasses
import inspect
import itertools
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from bughunt import VERSION
from bughunt.core import scanner
from scanner_oracle_support import (  # noqa: F401  (fixtures are consumed by name)
    grant,
    make_hit,
    run_cli,
    squash,
    workspace,
)
from test_gate import boundaries  # noqa: F401  (fixture: DNS, sockets and processes all raise)

COMMON_PORTS = [
    80,
    81,
    443,
    591,
    2082,
    2083,
    2086,
    2087,
    2095,
    2096,
    3000,
    3001,
    3443,
    4000,
    4172,
    4443,
    4567,
    5000,
    5001,
    5443,
    5601,
    6000,
    6443,
    7000,
    7001,
    7443,
    8000,
    8001,
    8008,
    8010,
    8080,
    8081,
    8088,
    8181,
    8443,
    8484,
    8880,
    8888,
    9000,
    9001,
    9090,
    9091,
    9200,
    9443,
    10000,
    10443,
    12443,
    15672,
    18080,
    28080,
]
ARTIFACT_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.hg/requires",
    "/.env",
    "/.env.local",
    "/.htpasswd",
    "/.htaccess",
    "/.DS_Store",
    "/web.config",
    "/crossdomain.xml",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/backup.zip",
    "/backup.tar.gz",
    "/dump.sql",
]
MUTATION_SUFFIXES = [
    ".bak",
    ".old",
    ".orig",
    ".tmp",
    ".temp",
    ".copy",
    ".bak1",
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".7z",
    ".rar",
    ".sql",
    ".sql.gz",
    ".log",
    ".swp",
    ".swo",
    "~",
]
PARAMETER_NAMES = [
    "debug",
    "test",
    "admin",
    "dev",
    "staging",
    "redirect",
    "url",
    "next",
    "return",
    "dest",
    "callback",
    "jsonp",
    "api_key",
    "key",
    "token",
    "id",
    "file",
    "path",
    "page",
    "format",
]


@pytest.fixture
def scoped(workspace):
    """A workspace with NO policy (every decision is denied) whose scope lists two named hosts."""
    (workspace / "scope.txt").write_text("a.example\n10.0.0.5\n", encoding="utf-8")
    return workspace


def _json_from(output: str):
    """The dry-run document, even when a console warning was printed before it."""
    match = re.search(r"^\[\]?$", output, flags=re.M)
    assert match, f"no JSON document in: {output!r}"
    return json.loads(output[match.start() :])


def dry(*argv):
    code, output = run_cli([*argv, "--dry-run", "--quiet"])
    return code, _json_from(output), output


def planned(*argv) -> list[str]:
    return [row["target"] for row in dry(*argv)[1]]


def ports_of(*argv) -> list[int]:
    return [urlsplit(url).port for url in planned(*argv)]


def paths_of(*argv) -> list[str]:
    return [
        url.split(":80", 1)[1]
        for url in planned("127.0.0.1", "--ports", "80", "--http-only", *argv)
    ]


# ======================================================================================
# Dry-run document
# ======================================================================================


def test_dry_run_prints_one_decision_per_planned_request_and_nothing_else(scoped):
    code, output = run_cli(
        ["127.0.0.1", "--ports", "80", "--http-only", "--dry-run", "--quiet"]
    )
    rows = json.loads(output)  # the whole of stdout is one JSON document
    assert (
        code == 2
    )  # no policy: every decision is denied, so dry-run exits 2 after printing
    assert rows == [
        {
            "target": "http://127.0.0.1:80/",
            "operation": "active_scan",
            "method": "GET",
            "actor": "default",
            "permitted": False,
            "reason": "policy-missing-or-invalid",
            "rate": None,
            "concurrency": None,
        }
    ]
    assert output.startswith('[\n  {\n    "target"')  # indent of two spaces


def test_dry_run_exits_zero_only_when_every_decision_is_permitted(scoped):
    grant(scoped, http=[8080, 8081])
    code, rows, _ = dry("127.0.0.1", "--ports", "8080,8081", "--http-only")
    assert code == 0 and all(
        row["permitted"] and row["reason"] == "permitted" for row in rows
    )
    assert (
        rows[0]["rate"] == 1000000
        and rows[0]["concurrency"] == 100
        and rows[0]["policy_version"] == "1"
    )
    code, rows, _ = dry(
        "127.0.0.1", "--ports", "8080,9999", "--http-only"
    )  # 9999 is not granted
    assert code == 2 and [row["permitted"] for row in rows] == [True, False]
    assert rows[1]["reason"] == "asset-unknown"


def test_dry_run_decisions_use_the_chosen_method(scoped):
    for method in ("HEAD", "OPTIONS", "POST"):
        assert {
            row["method"]
            for row in dry(
                "127.0.0.1", "--ports", "80", "--http-only", "--method", method
            )[1]
        } == {method}
    assert dry("127.0.0.1", "--ports", "80", "--http-only")[1][0]["method"] == "GET"


def test_dry_run_touches_no_dns_socket_or_process_even_with_every_network_flag(
    scoped, boundaries
):
    code, rows, _ = dry(
        "127.0.0.1",
        "--ports",
        "80",
        "--http-only",
        "--banners",
        "--dns",
        "--ct",
        "--cors",
        "--screenshots",
        "shots",
        "--intel",
        "--proxy",
        "http://proxy.example:8080",
    )
    assert (
        code == 2 and rows
    )  # decisions printed; the boundary fixture would have raised otherwise


def test_planned_requests_nest_target_then_port_then_path_then_scheme(scoped):
    urls = planned("127.0.0.1", "127.0.0.2", "--ports", "80,81", "--paths", "/a,/b")
    expected = [
        f"{scheme}://{host}:{port}{path}"
        for host, port, path, scheme in itertools.product(
            ["127.0.0.1", "127.0.0.2"], [80, 81], ["/a", "/b"], ["http", "https"]
        )
    ]
    assert urls == expected  # http always precedes https for the same path


def test_scheme_restrictions_select_the_planned_schemes(scoped):
    assert {
        url.split(":")[0]
        for url in planned("127.0.0.1", "--ports", "80", "--http-only")
    } == {"http"}
    assert {
        url.split(":")[0]
        for url in planned("127.0.0.1", "--ports", "80", "--https-only")
    } == {"https"}
    assert [url.split(":")[0] for url in planned("127.0.0.1", "--ports", "80")] == [
        "http",
        "https",
    ]


def test_the_startup_banner_carries_the_version_and_a_rules_of_engagement_notice_unless_quiet(
    scoped,
):
    argv = ["127.0.0.1", "--ports", "80", "--http-only", "--dry-run"]
    _, loud = run_cli(argv)
    _, quiet = run_cli([*argv, "--quiet"])
    assert (
        VERSION in loud and "authorized" in loud.lower()
    )  # wording and art are free; these two facts are not
    assert VERSION not in quiet and "authorized" not in quiet.lower()
    assert not loud.lstrip().startswith("[") and quiet.lstrip().startswith(
        "["
    )  # why callers pass --quiet


def test_both_scheme_restrictions_together_is_exit_two(scoped):
    code, output = run_cli(
        ["127.0.0.1", "--ports", "80", "--http-only", "--https-only", "--quiet"]
    )
    assert code == 2 and "Nothing to do" in squash(output)


# ======================================================================================
# Port selection and rails
# ======================================================================================


def test_default_port_selection_is_the_fifty_common_web_ports_in_order(scoped):
    assert len(COMMON_PORTS) == 50
    assert ports_of("127.0.0.1", "--http-only") == COMMON_PORTS
    assert ports_of("127.0.0.1", "--http-only", "--common") == COMMON_PORTS


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["--ports", "80"], [80]),
        (["--ports", "80,443"], [80, 443]),
        (["--ports", "8000-8002"], [8000, 8001, 8002]),
        (["--ports", "9-7"], [7, 8, 9]),
        (["--ports", " 80 , 443 "], [80, 443]),
        (["--ports", "80,,443"], [80, 443]),
        (["--ports", "80, 80"], [80]),
        (["--ports", "443,80"], [80, 443]),  # sorted ascending whatever the input order
        (["--range", "8000-8002"], [8000, 8001, 8002]),
        (["--ports", "80,443,8080", "--exclude-ports", "443"], [80, 8080]),
        (
            ["--ports", "8000-8005", "--exclude-ports", "8001-8003,9"],
            [8000, 8004, 8005],
        ),
    ],
)
def test_port_selection_vectors(scoped, argv, expected):
    assert ports_of("127.0.0.1", "--http-only", *argv) == expected


def test_exclude_ports_applies_to_the_default_list_too(scoped):
    assert ports_of("127.0.0.1", "--http-only", "--exclude-ports", "80,443") == [
        port for port in COMMON_PORTS if port not in (80, 443)
    ]


@pytest.mark.parametrize(
    "argument, fragment",
    [
        (["--ports", "0"], "ports must be in 1-65535"),
        (["--ports", "65536"], "ports must be in 1-65535"),
        (["--ports", "1-70000"], "ports must be in 1-65535"),
        (["--ports", "abc"], "invalid literal for int()"),
        (["--ports", "80-"], "invalid literal for int()"),
        (["--ports=-80"], "invalid literal for int()"),
        (["--ports", "1-2-3"], "invalid literal for int()"),
    ],
)
def test_bad_port_specs_are_exit_two_with_a_message_not_a_traceback(
    scoped, argument, fragment
):
    code, output = run_cli(["127.0.0.1", *argument, "--quiet"])
    assert code == 2 and fragment in squash(output)


def test_ports_file_alone_replaces_the_common_list(scoped, tmp_path):
    listing = tmp_path / "ports.txt"
    listing.write_text("# c\n81, 82\n9000-9001\n", encoding="utf-8")
    assert ports_of("127.0.0.1", "--http-only", "--ports-file", str(listing)) == [
        81,
        82,
        9000,
        9001,
    ]


def test_ports_file_is_unioned_when_another_selector_is_given(scoped, tmp_path):
    listing = tmp_path / "ports.txt"
    listing.write_text("# c\n81, 82\n9000-9001\n", encoding="utf-8")
    assert ports_of(
        "127.0.0.1", "--http-only", "--ports", "80", "--ports-file", str(listing)
    ) == [80, 81, 82, 9000, 9001]
    assert ports_of(
        "127.0.0.1", "--http-only", "--range", "70-71", "--ports-file", str(listing)
    ) == [70, 71, 81, 82, 9000, 9001]


def test_an_empty_ports_file_falls_back_to_the_common_list(scoped, tmp_path):
    listing = tmp_path / "empty.txt"
    listing.write_text("# nothing here\n\n", encoding="utf-8")
    assert (
        ports_of("127.0.0.1", "--http-only", "--ports-file", str(listing))
        == COMMON_PORTS
    )


def test_a_missing_list_file_is_exit_two(scoped, tmp_path):
    code, output = run_cli(
        ["127.0.0.1", "--ports-file", str(tmp_path / "nope.txt"), "--quiet"]
    )
    assert code == 2 and "list file not found" in squash(output)


def test_the_port_selectors_are_mutually_exclusive(scoped):
    for first, second in itertools.combinations(
        [["--common"], ["--ports", "80"], ["--range", "80-81"], ["--all"]], 2
    ):
        with pytest.raises(SystemExit) as raised:
            scanner.scan_main(["127.0.0.1", *first, *second, "--quiet"])
        assert raised.value.code == 2


def test_all_ports_need_the_authorized_flag(scoped):
    code, output = run_cli(["127.0.0.1", "--all", "--dry-run", "--quiet"])
    assert (
        code == 2
        and "65535 ports" in squash(output)
        and "--authorized" in squash(output)
    )


@pytest.mark.parametrize("flag", ["--authorized", "--i-own-this"])
def test_authorized_alias_lifts_the_oversize_port_rail(scoped, flag):
    code, rows, _ = dry("127.0.0.1", "--http-only", "--range", "1-4097", flag)
    assert (
        len(rows) == 4097 and code == 2
    )  # exit 2 only because this workspace has no policy


def test_more_than_4096_ports_is_refused_without_authorization_and_4096_is_not(scoped):
    code, output = run_cli(
        ["127.0.0.1", "--range", "1-4097", "--http-only", "--dry-run", "--quiet"]
    )
    assert (
        code == 2
        and "4097 ports" in squash(output)
        and not output.lstrip().startswith("[")
    )
    code, rows, _ = dry("127.0.0.1", "--range", "1-4096", "--http-only")
    assert len(rows) == 4096


def test_skip_tcp_breadth_rail_is_1024_ports(scoped):
    code, output = run_cli(
        [
            "127.0.0.1",
            "--range",
            "1-1025",
            "--skip-tcp",
            "--http-only",
            "--dry-run",
            "--quiet",
        ]
    )
    assert code == 2 and "--skip-tcp on 1025 ports" in squash(output)
    assert (
        len(dry("127.0.0.1", "--range", "1-1024", "--skip-tcp", "--http-only")[1])
        == 1024
    )
    assert (
        len(
            dry(
                "127.0.0.1",
                "--range",
                "1-1025",
                "--skip-tcp",
                "--http-only",
                "--authorized",
            )[1]
        )
        == 1025
    )


# ======================================================================================
# Targets
# ======================================================================================


def test_target_normalization_and_dedupe_vector(scoped):
    # Host case is preserved and de-duplication is case sensitive; a bare IPv6 literal is dropped
    # (CURRENT/DEFECT, see test_scanner_known_defects) while a bracketed one is kept.
    urls = planned(
        "A.example",
        "http://a.example:81/x",
        "a.example",
        "10.0.0.5/32",
        "::1",
        "[::1]",
        "--ports",
        "80",
        "--http-only",
    )
    assert urls == [
        "http://A.example:80/",
        "http://a.example:80/",
        "http://10.0.0.5:80/",
        "http://[::1]:80/",
    ]


@pytest.mark.parametrize(
    "token, host",
    [
        ("example.com", "example.com"),
        ("http://Example.com:8080/x", "example.com"),
        ("https://[::1]:443/", "::1"),
        ("[::1]:80", "::1"),
        ("1.2.3.4:80", "1.2.3.4"),
        ("host/path", "host"),
        ("a.b/24", "a.b"),
    ],
)
def test_host_normalization_vectors(scoped, workspace, token, host):
    (workspace / "scope.txt").write_text(
        "example.com\n1.2.3.4\nhost\na.b\n", encoding="utf-8"
    )
    expected_host = f"[{host}]" if ":" in host else host
    assert planned(token, "--ports", "80", "--http-only") == [
        f"http://{expected_host}:80/"
    ]


def test_cidr_expansion_vectors(scoped):
    assert planned("127.0.0.0/30", "--ports", "80", "--http-only") == [
        "http://127.0.0.1:80/",
        "http://127.0.0.2:80/",
    ]
    assert planned("127.0.0.5/32", "--ports", "80", "--http-only") == [
        "http://127.0.0.5:80/"
    ]
    assert planned("127.0.0.0/31", "--ports", "80", "--http-only") == [
        "http://127.0.0.0:80/",
        "http://127.0.0.1:80/",
    ]
    assert planned("::1/128", "--ports", "80", "--http-only") == ["http://[::1]:80/"]
    assert len(planned("127.0.0.0/24", "--ports", "80", "--http-only")) == 254


def test_cidr_rails_soft_limit_hard_cap_and_the_authorized_flag(scoped):
    code, output = run_cli(
        ["127.0.0.0/23", "--ports", "80", "--http-only", "--dry-run", "--quiet"]
    )
    assert code == 2 and "CIDR 127.0.0.0/23 expands to 510 hosts" in squash(output)
    assert "Re-run with --authorized only if you own the range" in squash(output)
    assert (
        len(dry("127.0.0.0/23", "--ports", "80", "--http-only", "--authorized")[1])
        == 510
    )
    code, output = run_cli(
        [
            "127.0.0.0/21",
            "--ports",
            "80",
            "--http-only",
            "--authorized",
            "--dry-run",
            "--quiet",
        ]
    )
    assert code == 2 and "expands to 2046 hosts (hard cap 1024)" in squash(
        output
    )  # --authorized does not lift the cap


def test_no_targets_is_exit_two(scoped):
    code, output = run_cli(["--quiet"])
    assert code == 2 and "No targets given. Pass hosts or --targets-file." in squash(
        output
    )


def test_targets_file_lines_follow_positional_targets_and_skip_comments(
    scoped, tmp_path
):
    listing = tmp_path / "hosts.txt"
    listing.write_text(
        "# scope\n\n127.0.0.3\n  127.0.0.2  \n127.0.0.1\n", encoding="utf-8"
    )
    assert planned("127.0.0.9", "-l", str(listing), "--ports", "80", "--http-only") == [
        f"http://127.0.0.{n}:80/" for n in (9, 3, 2, 1)
    ]
    assert planned("--targets-file", str(listing), "--ports", "80", "--http-only") == [
        f"http://127.0.0.{n}:80/" for n in (3, 2, 1)
    ]


def test_out_of_scope_targets_are_all_explained_and_exit_two(scoped):
    code, output = run_cli(
        [
            "127.0.0.1",
            "outside.example",
            "other.example",
            "--ports",
            "80",
            "--http-only",
            "--dry-run",
            "--quiet",
        ]
    )
    text = squash(output)
    assert code == 2 and "outside.example" in text and "other.example" in text
    assert not output.lstrip().startswith("[")  # no plan was produced


def test_scope_is_checked_before_the_output_directory_is_created(scoped, tmp_path):
    out = tmp_path / "never"
    code, _ = run_cli(
        ["outside.example", "--ports", "80", "--output-dir", str(out), "--quiet"]
    )
    assert code == 2 and not out.exists()


def test_a_positional_file_is_refused_and_pointed_at_the_list_flag(
    scoped, tmp_path, monkeypatch
):
    monkeypatch.chdir(
        tmp_path
    )  # a short relative name keeps the console message on one line
    (tmp_path / "hosts.txt").write_text("127.0.0.1\n", encoding="utf-8")
    code, output = run_cli(["hosts.txt", "--ports", "80", "--quiet"])
    assert (
        code == 2
        and "hosts.txt is a file" in squash(output)
        and "No hosts were given." in squash(output)
    )
    assert "-l hosts.txt" in squash(output)


def test_a_positional_file_beside_real_hosts_warns_but_is_still_treated_as_a_host(
    scoped, tmp_path, monkeypatch
):
    # CURRENT, and it contradicts the spec prose ("the real hosts still scan", section 2.5 item 6): the warning
    # is printed, but the file token is NOT removed from the target list. It is normalized like any other
    # token, becomes the host "hosts.txt", fails the scope check and the whole command exits 2. (An absolute
    # POSIX path normalizes to an empty host and is dropped, which is the case the spec prose describes.)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hosts.txt").write_text("127.0.0.1\n", encoding="utf-8")
    code, output = run_cli(
        [
            "hosts.txt",
            "127.0.0.1",
            "--ports",
            "80",
            "--http-only",
            "--dry-run",
            "--quiet",
        ]
    )
    text = squash(output)
    assert (
        code == 2
        and "hosts.txt is a file" in text
        and "hosts.txt is outside this engagement's scope" in text
    )
    assert not output.lstrip().startswith("[")


def test_a_file_positional_plus_the_list_flag_still_exits_two(
    scoped, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hosts.txt").write_text("127.0.0.1\n", encoding="utf-8")
    code, _ = run_cli(["hosts.txt", "-l", "hosts.txt", "--ports", "80", "--quiet"])
    assert code == 2


def test_follow_redirects_is_refused_before_the_banner_and_before_target_collection(
    scoped,
):
    code, output = run_cli(
        ["--follow-redirects"]
    )  # no targets and no --quiet: the refusal comes first
    assert code == 2 and "Unscoped redirects are disabled in this fork." in squash(
        output
    )
    assert "No targets" not in output and "rules of engagement" not in output.lower()


# ======================================================================================
# Path assembly
# ======================================================================================


def test_default_path_is_the_root(scoped):
    assert paths_of() == ["/"]


@pytest.mark.parametrize(
    "argument, expected",
    [
        ("/admin", ["/admin"]),
        ("a, b,,/c", ["/a", "/b", "/c"]),
        ("", ["/"]),
        ("/a,a,/a", ["/a"]),
        ("x", ["/x"]),
        ("https://h/a?b=1", ["/a?b=1"]),
        ("http://h", ["/"]),
        ("?q=1", ["/?q=1"]),
        (" ,x", ["/x"]),
    ],
)
def test_path_argument_vectors(scoped, argument, expected):
    assert paths_of("--paths", argument) == expected


def test_paths_file_drops_the_implicit_root_unless_paths_is_explicit(scoped, tmp_path):
    listing = tmp_path / "paths.txt"
    listing.write_text(
        "# c\n\nadmin\n/login?x=1\nhttp://h.example/a/b?q=1\n", encoding="utf-8"
    )
    file_paths = ["/admin", "/login?x=1", "/a/b?q=1"]
    # BH-3 (spec section 10 item 2 opt-out): a --paths-file with no explicit --paths maps exactly its own
    # paths and never injects the implicit host root (granting "/" in policy would authorize the whole host).
    assert paths_of("--paths-file", str(listing)) == file_paths
    assert "/" not in paths_of("--paths-file", str(listing))
    assert (
        paths_of("--paths", str(listing)) == file_paths
    )  # the same file given as --paths: still no root
    assert paths_of("--paths", "/admin", "--paths-file", str(listing)) == [
        "/admin",
        "/login?x=1",
        "/a/b?q=1",
    ]
    assert paths_of("--paths", "/") == [
        "/"
    ]  # an explicit --paths "/" is honored: the operator asked for the root
    assert paths_of() == [
        "/"
    ]  # the default case (no file, no explicit paths) still scans the root


def test_discover_appends_the_artifact_paths_after_the_requested_ones(scoped):
    assert len(ARTIFACT_PATHS) == 22
    assert paths_of("--discover") == ["/", *ARTIFACT_PATHS]
    assert paths_of("--discover", "--paths", "/robots.txt,/x") == [
        "/robots.txt",
        "/x",
        *[p for p in ARTIFACT_PATHS if p != "/robots.txt"],
    ]


def test_favicon_flag_appends_one_favicon_path(scoped):
    assert paths_of("--favicon") == ["/", "/favicon.ico"]
    assert paths_of("--favicon", "--discover") == [
        "/",
        *ARTIFACT_PATHS,
    ]  # already present: not repeated


def test_intel_expands_to_discover_plus_favicon(scoped):
    assert paths_of("--intel") == ["/", *ARTIFACT_PATHS]


def test_mutate_paths_adds_backup_variants_only_to_file_like_paths(scoped):
    mutated = paths_of(
        "--paths", "/,/a,/b/,/c?x=1", "--mutate-paths", "--mutate-ext", "inc,.dist,~"
    )
    assert mutated == [
        "/",
        "/a",
        "/b/",
        "/c?x=1",
        *[f"/a{suffix}" for suffix in MUTATION_SUFFIXES],
        "/a.inc",
        "/a.dist",
    ]
    assert paths_of("--paths", "/a", "--mutate-paths") == [
        "/a",
        *[f"/a{suffix}" for suffix in MUTATION_SUFFIXES],
    ]


def test_mutate_ext_alone_does_nothing(scoped):
    assert paths_of("--paths", "/a", "--mutate-ext", "inc") == ["/a"]


def test_mutation_also_applies_to_discover_paths(scoped):
    mutated = paths_of(
        "--discover", "--mutate-paths", "--authorized"
    )  # ~440 paths: over the 400-path rail
    assert (
        "/robots.txt.bak" in mutated
        and "/.env~" in mutated
        and "/" in mutated
        and "/.bak" not in mutated
    )


def test_params_adds_the_first_twelve_names_to_endpoint_like_paths_and_root(scoped):
    result = paths_of("--paths", "/,/index.php?x=2,/about", "--params")
    names = PARAMETER_NAMES[:12]
    assert result == [
        "/",
        "/index.php?x=2",
        "/about",
        *[f"/?{name}=1" for name in names],
        *[f"/index.php?x=2&{name}=1" for name in names],
    ]  # existing query kept, new key appended


def test_endpoint_like_detection_vectors(scoped):
    result = paths_of(
        "--paths",
        "/a.php,/api,/api/v1/x,/graphql,/v2/,/x.php/y,/rest,/about",
        "--params",
    )
    varied = {path for path in result if path.endswith("?debug=1")}
    assert varied == {
        "/a.php?debug=1",
        "/api?debug=1",
        "/api/v1/x?debug=1",
        "/graphql?debug=1",
        "/v2/?debug=1",
        "/x.php/y?debug=1",
        "/rest?debug=1",
    }
    assert (
        "/about?debug=1" not in result and len(result) == 92
    )  # 8 originals + 7 endpoints x 12 names


def test_path_count_rail_is_400_without_authorization(scoped, tmp_path):
    many = tmp_path / "many.txt"
    many.write_text("\n".join(f"/p{n}" for n in range(401)) + "\n", encoding="utf-8")
    code, output = run_cli(
        [
            "127.0.0.1",
            "--ports",
            "80",
            "--http-only",
            "--paths",
            str(many),
            "--dry-run",
            "--quiet",
        ]
    )
    assert code == 2 and "Refusing 401 request paths" in squash(output)
    many.write_text("\n".join(f"/p{n}" for n in range(400)) + "\n", encoding="utf-8")
    assert (
        len(dry("127.0.0.1", "--ports", "80", "--http-only", "--paths", str(many))[1])
        == 400
    )
    many.write_text("\n".join(f"/p{n}" for n in range(401)) + "\n", encoding="utf-8")
    assert (
        len(
            dry(
                "127.0.0.1",
                "--ports",
                "80",
                "--http-only",
                "--paths",
                str(many),
                "--authorized",
            )[1]
        )
        == 401
    )


# ======================================================================================
# Value grammars that fail at validation time
# ======================================================================================


@pytest.mark.parametrize("delay", ["-1", "abc", "1-", "5--1"])
def test_bad_delay_is_exit_two(scoped, delay):
    code, output = run_cli(
        ["127.0.0.1", "--ports", "80", f"--delay={delay}", "--quiet"]
    )
    assert code == 2 and output.strip()


@pytest.mark.parametrize("delay", ["0", "1.5", "0.5-2.0", "2-0.5", ""])
def test_good_delays_pass_validation(scoped, delay):
    assert dry("127.0.0.1", "--ports", "80", "--http-only", f"--delay={delay}")[1]


def test_header_without_a_colon_is_exit_two(scoped):
    code, output = run_cli(["127.0.0.1", "--ports", "80", "-H", "nocolon", "--quiet"])
    assert code == 2 and "header must look like 'Name: value'" in squash(output)


def test_auth_without_a_colon_is_exit_two(scoped):
    code, output = run_cli(
        ["127.0.0.1", "--ports", "80", "--auth", "nocolon", "--quiet"]
    )
    assert code == 2 and "--auth must be USER:PASS" in squash(output)


def test_a_missing_headers_file_is_exit_two(scoped, tmp_path):
    code, output = run_cli(
        [
            "127.0.0.1",
            "--ports",
            "80",
            "--headers-file",
            str(tmp_path / "none.txt"),
            "--quiet",
        ]
    )
    assert code == 2 and "list file not found" in squash(output)


def test_output_dir_is_created_after_scope_but_before_port_validation(scoped, tmp_path):
    out = tmp_path / "left-behind"
    code, _ = run_cli(
        ["127.0.0.1", "--ports", "abc", "--output-dir", str(out), "--quiet"]
    )
    assert (
        code == 2 and out.is_dir()
    )  # CURRENT: a later validation failure leaves an empty directory behind


# ======================================================================================
# The argparse contract the console builds on
# ======================================================================================

# flags -> (dest, kind, default). kind: switch | str | int | float | append. Spec section 2.3.
OPTION_TABLE = {
    ("--dry-run",): ("dry_run", "switch", False),
    ("-l", "--targets-file"): ("targets_file", "str", None),
    ("--common",): ("common", "switch", False),
    ("--ports",): ("ports", "str", None),
    ("--range",): ("port_range", "str", None),
    ("--all",): ("all", "switch", False),
    ("--ports-file",): ("ports_file", "str", None),
    ("--exclude-ports",): ("exclude_ports", "str", None),
    ("--authorized", "--i-own-this"): ("authorized", "switch", False),
    ("--fast",): ("fast", "switch", False),
    ("--paths",): ("paths", "str", None),
    ("--paths-file",): ("paths_file", "str", None),
    ("--concurrency",): ("concurrency", "int", 256),
    ("--connect-timeout",): ("connect_timeout", "float", 1.2),
    ("--http-timeout",): ("http_timeout", "float", 4.0),
    ("--delay",): ("delay", "str", "0"),
    ("--discover",): ("discover", "switch", False),
    ("--mutate-paths",): ("mutate_paths", "switch", False),
    ("--mutate-ext",): ("mutate_ext", "str", None),
    ("--params",): ("params", "switch", False),
    ("--params-file",): ("params_file", "str", None),
    ("--score-headers",): ("score_headers", "switch", False),
    ("--cors",): ("cors", "switch", False),
    ("--extract-js",): ("extract_js", "switch", False),
    ("--favicon",): ("favicon", "switch", False),
    ("--dns",): ("dns", "switch", False),
    ("--ct",): ("ct", "switch", False),
    ("--banners",): ("banners", "switch", False),
    ("--md",): ("md", "str", None),
    ("--screenshots",): ("screenshots", "str", None),
    ("--intel",): ("intel", "switch", False),
    ("--retries",): ("retries", "int", 0),
    ("--http-only",): ("http_only", "switch", False),
    ("--https-only",): ("https_only", "switch", False),
    ("--follow-redirects",): ("follow_redirects", "switch", False),
    ("--insecure",): ("insecure", "switch", False),
    ("--no-cert",): ("no_cert", "switch", False),
    ("--skip-tcp",): ("skip_tcp", "switch", False),
    ("--method",): ("method", "str", "GET"),
    ("--host-header",): ("host_header", "str", None),
    ("-H", "--header"): ("header", "append", []),
    ("--headers-file",): ("headers_file", "str", None),
    ("--auth",): ("auth", "str", None),
    ("--user-agent",): ("user_agent", "str", "<default agent>"),
    ("--user-agents-file",): ("user_agents_file", "str", None),
    ("--random-agent",): ("random_agent", "switch", False),
    ("--rotate-agent",): ("rotate_agent", "switch", False),
    ("--proxy",): ("proxy", "str", None),
    ("--status",): ("status", "str", None),
    ("--grep",): ("grep", "str", None),
    ("--only-live",): ("only_live", "switch", False),
    ("--save-urls",): ("save_urls", "str", None),
    ("--save-source",): ("save_source", "str", None),
    ("--save-headers",): ("save_headers", "str", None),
    ("--output-dir",): ("output_dir", "str", None),
    ("--max-body",): ("max_body", "int", 262144),
    ("--json",): ("json", "str", None),
    ("--csv",): ("csv", "str", None),
    ("--quiet",): ("quiet", "switch", False),
}


def _option_actions(parser):
    return [
        action
        for action in parser._actions
        if action.option_strings
        and not isinstance(action, (argparse._HelpAction, argparse._VersionAction))
    ]


def _kind(action) -> str:
    if isinstance(action, argparse._StoreTrueAction):
        return "switch"
    if isinstance(action, argparse._AppendAction):
        return "append"
    return {int: "int", float: "float"}.get(action.type, "str")


@pytest.mark.parametrize("program", ["bughunt", "bughunt scan"])
def test_parser_exposes_exactly_the_documented_options(program):
    parser = scanner.build_parser(program)
    actions = _option_actions(parser)
    assert isinstance(parser, argparse.ArgumentParser) and len(actions) == 59
    assert sum(1 for entry in OPTION_TABLE.values() if entry[1] == "switch") == 26
    assert (
        sum(len(flags) for flags in OPTION_TABLE) == 62
    )  # 59 actions, three of them with two spellings
    found = {
        tuple(action.option_strings): (action.dest, _kind(action), action.default)
        for action in actions
    }
    assert set(found) == set(OPTION_TABLE)
    for flags, (dest, kind, default) in OPTION_TABLE.items():
        got_dest, got_kind, got_default = found[flags]
        assert (got_dest, got_kind) == (dest, kind), flags
        if default == "<default agent>":
            assert (
                isinstance(got_default, str) and got_default
            )  # the literal itself is an open decision (spec 10.12)
        else:
            assert got_default == default, flags


def test_parser_value_taking_option_count_and_method_choices():
    parser = scanner.build_parser("bughunt scan")
    actions = _option_actions(parser)
    assert sum(1 for action in actions if _kind(action) != "switch") == 33
    method = next(action for action in actions if action.dest == "method")
    assert set(method.choices) == {
        "GET",
        "HEAD",
        "OPTIONS",
        "POST",
    }  # case sensitive: "get" is a usage error


def test_positional_targets_take_zero_or_more_values():
    parser = scanner.build_parser("bughunt scan")
    positional = [
        action
        for action in parser._actions
        if not action.option_strings and action.dest == "targets"
    ]
    assert len(positional) == 1 and positional[0].nargs == "*"
    assert parser.parse_args([]).targets == []
    assert parser.parse_args(["--quiet", "a", "b"]).targets == ["a", "b"]


def test_parser_prog_and_abbreviations_follow_plain_argparse():
    parser = scanner.build_parser("bughunt scan")
    assert parser.format_usage().startswith("usage: bughunt scan")
    assert scanner.build_parser("bughunt").format_usage().startswith("usage: bughunt ")
    assert (
        parser.parse_args(["--conc", "8"]).concurrency == 8
    )  # abbreviation is enabled
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["--pa", "x"]
        )  # ambiguous: --paths / --paths-file / --params / ...


def test_parser_types_are_coerced_by_argparse():
    args = scanner.build_parser("bughunt").parse_args(
        [
            "--concurrency",
            "9",
            "--connect-timeout",
            "0.25",
            "--retries",
            "2",
            "--max-body",
            "4096",
            "-H",
            "A: 1",
            "-H",
            "B: 2",
        ]
    )
    assert (args.concurrency, args.connect_timeout, args.retries, args.max_body) == (
        9,
        0.25,
        2,
        4096,
    )
    assert args.header == ["A: 1", "B: 2"]
    with pytest.raises(SystemExit):
        scanner.build_parser("bughunt").parse_args(["--concurrency", "many"])


def test_version_flag_prints_the_product_and_package_version(capsys):
    with pytest.raises(SystemExit) as raised:
        scanner.scan_main(["--version"])
    assert (
        raised.value.code == 0
        and capsys.readouterr().out.strip() == f"Bughunt {VERSION}"
    )


def test_help_uses_the_program_name_passed_to_scan_main(capsys):
    with pytest.raises(SystemExit) as raised:
        scanner.scan_main(["--help"], prog="bughunt scan")
    out = capsys.readouterr().out
    assert raised.value.code == 0 and out.startswith("usage: bughunt scan")
    assert "--dry-run" in out and "--output-dir" in out


def test_usage_errors_surface_as_systemexit_two_not_a_return_value():
    with pytest.raises(SystemExit) as raised:
        scanner.scan_main(["--no-such-flag"])
    assert raised.value.code == 2


def test_main_hands_everything_to_the_console_dispatcher(monkeypatch):
    from bughunt.console import cli

    seen = {}

    def fake_dispatch(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return 17

    monkeypatch.setattr(
        cli, "dispatch", fake_dispatch
    )  # main imports dispatch lazily, at call time
    assert scanner.main(["engine", "map"]) == 17
    assert seen["argv"] == ["engine", "map"]
    assert (
        seen["scan_main"] is scanner.scan_main
        and seen["build_parser"] is scanner.build_parser
    )
    assert seen["tool_file"] == Path(scanner.__file__).resolve()


# ======================================================================================
# The public surface other code is written against (spec section 1.2)
# ======================================================================================


def test_public_names_exist_on_the_scanner_namespace():
    for name in (
        "scan_main",
        "main",
        "build_parser",
        "resolve_host",
        "tcp_probe",
        "banner_grab",
        "scan_host",
        "cors_probe",
        "error_hit",
        "ArtifactSink",
        "capture_screenshots",
        "browser_settings",
        "scope_route",
        "scope_socket",
        "HostReport",
        "PortResult",
        "write_csv",
        "write_markdown",
        "httpx",
        "VERSION",
    ):
        assert hasattr(scanner, name), name
    assert scanner.VERSION == VERSION and scanner.httpx.__name__ == "httpx"


def test_scanner_module_lives_at_the_repo_core_directory():
    path = Path(scanner.__file__).resolve()
    assert path.parts[-3:] == ("bughunt", "core", "scanner.py")
    assert (path.parents[2] / "addons").is_dir()


def test_policy_gated_functions_keep_the_parameter_names_the_guard_reads():
    assert list(inspect.signature(scanner.resolve_host).parameters) == ["host"]
    assert list(inspect.signature(scanner.tcp_probe).parameters) == [
        "host",
        "port",
        "timeout",
    ]
    assert list(inspect.signature(scanner.banner_grab).parameters) == [
        "host",
        "port",
        "timeout",
    ]
    assert inspect.iscoroutinefunction(
        scanner.tcp_probe
    ) and inspect.iscoroutinefunction(scanner.banner_grab)


def test_scan_host_takes_exactly_the_twenty_eight_documented_keywords():
    names = list(
        inspect.signature(scanner.scan_host).parameters
    )  # tests pass all of them by keyword
    assert len(names) == 28 and set(names) == {
        "target",
        "ports",
        "connect_timeout",
        "http_timeout",
        "concurrency",
        "paths",
        "follow_redirects",
        "try_http",
        "try_https",
        "verify_tls",
        "user_agents",
        "rotate_agent",
        "host_header",
        "custom_headers",
        "collect_certs",
        "keep_body",
        "max_body",
        "delay_lo",
        "delay_hi",
        "proxy",
        "sink",
        "status_allow",
        "grep",
        "skip_tcp",
        "method",
        "retries",
        "auth",
        "analyze",
    }
    assert inspect.iscoroutinefunction(scanner.scan_host)


def test_other_public_signatures():
    cors = list(
        inspect.signature(scanner.cors_probe).parameters
    )  # report positional, the rest by keyword
    assert cors[0] == "report" and set(cors) == {
        "report",
        "timeout",
        "verify_tls",
        "proxy",
    }
    assert list(inspect.signature(scanner.error_hit).parameters) == [
        "scheme",
        "url",
        "started",
        "error",
    ]
    assert list(inspect.signature(scanner.ArtifactSink).parameters) == [
        "urls_path",
        "source_dir",
        "header_dir",
    ]
    assert list(inspect.signature(scanner.ArtifactSink.capture).parameters) == [
        "self",
        "host",
        "port",
        "hit",
    ]
    assert list(inspect.signature(scanner.capture_screenshots).parameters) == [
        "report",
        "directory",
        "proxy",
    ]
    assert (
        inspect.signature(scanner.capture_screenshots).parameters["proxy"].default
        is None
    )
    assert list(inspect.signature(scanner.build_parser).parameters) == ["prog"]
    assert list(inspect.signature(scanner.scan_main).parameters) == ["argv", "prog"]
    assert inspect.signature(scanner.scan_main).parameters["prog"].default == "bughunt"
    assert (
        inspect.signature(scanner.build_parser).parameters["prog"].default == "bughunt"
    )


def test_record_field_order_is_part_of_the_contract():
    hit = scanner.error_hit("http", "http://x/", 0, "")
    assert [field.name for field in dataclasses.fields(type(hit))] == [
        "scheme",
        "url",
        "final_url",
        "status",
        "reason",
        "server",
        "powered_by",
        "content_type",
        "location",
        "title",
        "snippet",
        "bytes_read",
        "sha256",
        "elapsed_ms",
        "tags",
        "headers",
        "tls",
        "error",
        "body",
        "body_prefix",
    ]
    assert [field.name for field in dataclasses.fields(scanner.PortResult)] == [
        "port",
        "tcp_open",
        "hits",
        "tcp_error",
        "banner",
    ]
    assert [field.name for field in dataclasses.fields(scanner.HostReport)] == [
        "target",
        "resolved",
        "results",
        "elapsed",
        "findings",
        "dns",
        "ct_names",
        "banners",
        "js_urls",
        "favicon_hash",
        "favicon_hint",
    ]


def test_record_defaults_are_independent_per_instance():
    first, second = scanner.PortResult(1, True), scanner.PortResult(2, True)
    first.hits.append("x")
    assert second.hits == [] and first.tcp_error == "" and first.banner == ""
    one, two = (
        scanner.HostReport("a", [], [], 0.0),
        scanner.HostReport("b", [], [], 0.0),
    )
    one.findings.append("f")
    one.dns["A"] = ["1"]
    assert (
        two.findings == []
        and two.dns == {}
        and two.favicon_hash == ""
        and two.js_urls == []
    )
    hit_one, hit_two = (
        scanner.error_hit("http", "http://x/", 0, ""),
        scanner.error_hit("http", "http://x/", 0, ""),
    )
    hit_one.tags.append("t")
    hit_one.headers["k"] = "v"
    assert hit_two.tags == [] and hit_two.headers == {}
