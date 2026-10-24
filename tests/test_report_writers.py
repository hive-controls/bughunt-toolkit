"""Characterization oracle (M2): the report data model and the three serializers, on LIVE hits.

Before this file the Markdown writer was only ever run on a host with no live hit (which is how it kept a
``NameError`` for so long) and the JSON builder was never run at all. These tests feed the writers speaking
hits, error hits, filtered hits, explicit and default ports, and secrets, and compare against the byte-verified
golden shapes in the behavior spec (sections 6.3 to 6.5).

``Finding``, ``TlsInfo`` and ``reports_to_json`` are names the spec leaves FREE (nothing else imports them), so
they are imported in ONE place below. If the rebuild renames them, change that single import. Hits are built
through the pinned ``error_hit`` constructor (see ``make_hit``), never through the hit class by name.
"""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime

import pytest

from bughunt import VERSION
from bughunt.core import scanner
from bughunt.core.report import (
    Finding,
    TlsInfo,
    reports_to_json,
)  # FREE names in the spec: rename here only
from scanner_oracle_support import make_hit, squash, workspace  # noqa: F401  (workspace is a fixture)

CSV_HEADER = "target,port,scheme,url,final_url,status,server,title,tags,sha256,bytes,ms"

GOLDEN_MARKDOWN = """\
# Bughunt report

Generated `<TIMESTAMP>` by Bughunt <VERSION>.
Elapsed **2.50s** across **2** host(s).

Authorized assessment notes only. Confirm scope before acting on findings.

## app.example

Resolved: `10.0.0.5`, `10.0.0.6`

Favicon mmh3: `81586312` (Jenkins)

### DNS
- **A**: `10.0.0.5`
- **MX**: `mail.app.example.`

### Certificate transparency
- `a.app.example`
- `b.app.example`

### Live HTTP(S)
| Port | URL | Status | Server | Title | Tags |
| ---: | --- | --- | --- | --- | --- |
| 8080 | `http://app.example:8080/` | 200 | nginx | Home / Page | nginx, security-txt |
| 8443 | `https://app.example:8443/x` | None |  |  |  |

### Non-HTTP banners
- `443/tcp SSH-2.0`

### JavaScript / API URLs
- `http://app.example:8080/app.js`

### Findings
- **HIGH** Sensitive path responded \u2014 `http://app.example:8080/.env`. Artifact-style path returned a body
- **LOW** Missing X-Frame-Options \u2014 `http://app.example:8080/`. Missing X-Frame-Options (clickjacking)
- **INFO** Banner on port 443. SSH-2.0

## nohost.example

_No extra findings recorded for this host._
"""

GOLDEN_CSV = (
    f"{CSV_HEADER}\r\n"
    "app.example,8080,http,http://app.example:8080/,http://app.example:8080/,200,nginx,Home | Page,"
    '"nginx,security-txt",ab12cd34ef56ab12,1234,12.3\r\n'
    'app.example,443,https,https://app.example/admin,https://app.example/admin,403,,,"forbidden,filtered",,0,5.0\r\n'
    "app.example,8443,https,https://app.example:8443/x,https://app.example:8443/x,,,,,,0,1.0\r\n"
)


def golden_reports():
    """The input behind the spec's golden Markdown / CSV (section 6.4 and 6.5)."""
    live = make_hit(
        "http",
        "http://app.example:8080/",
        status=200,
        server="nginx",
        title="Home | Page",
        tags=["nginx", "security-txt"],
        sha256="ab12cd34ef56ab12",
        bytes_read=1234,
        elapsed_ms=12.3,
    )
    filtered = make_hit(
        "https",
        "https://app.example/admin",
        status=403,
        tags=["forbidden", "filtered"],
        elapsed_ms=5.0,
    )
    odd = make_hit(
        "https",
        "https://app.example:8443/x",
        error="something odd happened",
        elapsed_ms=1.0,
    )
    refused = make_hit(
        "https", "https://app.example:9443/", error="connect: refused", elapsed_ms=2.0
    )
    ports = [
        scanner.PortResult(8080, True, hits=[live]),
        scanner.PortResult(443, True, hits=[filtered]),
        scanner.PortResult(8443, True, hits=[odd]),
        scanner.PortResult(9443, True, hits=[refused]),
    ]
    findings = [
        Finding(
            "low",
            "Missing X-Frame-Options",
            "Missing X-Frame-Options (clickjacking)",
            url="http://app.example:8080/",
        ),
        Finding(
            "high",
            "Sensitive path responded",
            "Artifact-style path returned a body",
            url="http://app.example:8080/.env",
        ),
        Finding("info", "Banner on port 443", "SSH-2.0"),
    ]
    first = scanner.HostReport(
        "app.example",
        ["10.0.0.5", "10.0.0.6"],
        ports,
        2.0,
        findings=findings,
        dns={"A": ["10.0.0.5"], "MX": ["mail.app.example."]},
        ct_names=["a.app.example", "b.app.example"],
        banners=["443/tcp SSH-2.0"],
        js_urls=["http://app.example:8080/app.js"],
        favicon_hash="81586312",
        favicon_hint="Jenkins",
    )
    return [first, scanner.HostReport("nohost.example", [], [], 0.0)]


def read_text(path) -> str:
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def markdown_of(tmp_path, reports, elapsed=0.0) -> str:
    target = tmp_path / "report.md"
    scanner.write_markdown(target, reports, elapsed)
    return read_text(target)


def csv_of(tmp_path, reports):
    target = tmp_path / "report.csv"
    scanner.write_csv(target, reports)
    return target.read_bytes()


def one_host(*hits, port: int = 80, **extra):
    return scanner.HostReport(
        "h.example", [], [scanner.PortResult(port, True, hits=list(hits))], 0.0, **extra
    )


# ======================================================================================
# Markdown
# ======================================================================================


def test_markdown_matches_the_golden_document_line_for_line(workspace, tmp_path):
    text = markdown_of(tmp_path, golden_reports(), elapsed=2.5)
    expected = GOLDEN_MARKDOWN.replace("<VERSION>", VERSION).splitlines()
    actual = text.splitlines()
    assert len(actual) == len(expected)
    stamp_line = next(
        index for index, line in enumerate(expected) if "<TIMESTAMP>" in line
    )
    for index, (got, want) in enumerate(zip(actual, expected)):
        if index == stamp_line:
            assert re.fullmatch(
                rf"Generated `([^`]+)` by Bughunt {re.escape(VERSION)}\.", got
            )
            assert (
                datetime.fromisoformat(got.split("`")[1]).utcoffset().total_seconds()
                == 0
            )
        else:
            assert got == want, f"line {index + 1}"
    assert text.endswith("\n")


def test_markdown_is_utf8_without_a_byte_order_mark_and_creates_parent_directories(
    workspace, tmp_path
):
    target = tmp_path / "nested" / "deeper" / "report.md"
    scanner.write_markdown(target, golden_reports(), 2.5)
    raw = target.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf") and "\u2014".encode("utf-8") in raw


@pytest.mark.parametrize(
    "url, scheme, port_cell",
    [
        ("https://h.example:8443/", "https", "8443"),
        ("http://h.example:8080/x", "http", "8080"),
        ("https://h.example/", "https", "443"),
        ("http://h.example/", "http", "80"),
        ("http://h.example:80/", "http", "80"),
        ("http://[::1]:8081/", "http", "8081"),
        ("ftp://h.example/", "ftp", "80"),  # any scheme other than https defaults to 80
    ],
)
def test_markdown_port_column_comes_from_the_hit_url_not_the_port_record(
    workspace, tmp_path, url, scheme, port_cell
):
    hit = make_hit(scheme, url, status=200, server="s", title="t")
    text = markdown_of(tmp_path, [one_host(hit, port=9999)])
    assert f"| {port_cell} | `{url}` | 200 | s | t |  |" in text.splitlines()


def test_markdown_live_table_rules_pipe_escaping_empty_cells_none_status_and_tag_join(
    workspace, tmp_path
):
    hits = [
        make_hit(
            "http",
            "http://h.example/a",
            status=200,
            server="a|b",
            title="x | y | z",
            tags=["t1", "t2"],
        ),
        make_hit("http", "http://h.example/b", status=404),
        make_hit("http", "http://h.example/c", error="odd failure"),
    ]
    text = markdown_of(tmp_path, [one_host(*hits)])
    assert (
        "| 80 | `http://h.example/a` | 200 | a|b | x / y / z | t1, t2 |" in text
    )  # title escaped, server not
    assert "| 80 | `http://h.example/b` | 404 |  |  |  |" in text
    assert (
        "| 80 | `http://h.example/c` | None |  |  |  |" in text
    )  # a statusless live hit prints the word None


def test_markdown_omits_filtered_and_non_live_hits_and_the_table_when_none_are_live(
    workspace, tmp_path
):
    hits = [
        make_hit("http", "http://h.example/f", status=403, tags=["filtered"]),
        make_hit("http", "http://h.example/t", error="timeout"),
        make_hit("http", "http://h.example/e", error="connect: refused"),
        make_hit("http", "http://h.example/n", error=""),
    ]
    text = markdown_of(tmp_path, [one_host(*hits)])
    assert "### Live HTTP(S)" not in text and "h.example/f" not in text


def test_markdown_counts_hosts_and_formats_elapsed_with_two_decimals(
    workspace, tmp_path
):
    text = markdown_of(
        tmp_path, [scanner.HostReport("a", [], [], 0.0)] * 3, elapsed=0.126
    )
    assert "Elapsed **0.13s** across **3** host(s)." in text.splitlines()


def test_markdown_for_an_empty_run_has_only_the_header_block(workspace, tmp_path):
    text = markdown_of(tmp_path, [], elapsed=1.0)
    assert (
        text.splitlines()[3] == "Elapsed **1.00s** across **0** host(s)."
        and "## " not in text
    )


def test_markdown_optional_sections_appear_only_when_populated(workspace, tmp_path):
    bare = markdown_of(tmp_path, [scanner.HostReport("bare.example", [], [], 0.0)])
    for heading in (
        "Resolved:",
        "Favicon mmh3",
        "### DNS",
        "### Certificate transparency",
        "### Live HTTP(S)",
        "### Non-HTTP banners",
        "### JavaScript / API URLs",
        "### Findings",
    ):
        assert heading not in bare
    assert "_No extra findings recorded for this host._" in bare


def test_markdown_favicon_line_has_a_hint_only_when_one_is_known(workspace, tmp_path):
    with_hint = markdown_of(
        tmp_path,
        [
            scanner.HostReport(
                "h", [], [], 0.0, favicon_hash="1", favicon_hint="Grafana"
            )
        ],
    )
    without = markdown_of(
        tmp_path, [scanner.HostReport("h", [], [], 0.0, favicon_hash="2")]
    )
    assert (
        "Favicon mmh3: `1` (Grafana)" in with_hint.splitlines()
        and "Favicon mmh3: `2`" in without.splitlines()
    )


def test_markdown_list_sections_are_capped(workspace, tmp_path):
    report = scanner.HostReport(
        "h",
        [],
        [],
        0.0,
        dns={"TXT": [f"record{n}" for n in range(12)]},
        ct_names=[f"n{n}.example" for n in range(60)],
        js_urls=[f"http://h/{n}.js" for n in range(60)],
        banners=[f"{n}/tcp b" for n in range(50)],
    )
    lines = markdown_of(tmp_path, [report]).splitlines()
    assert [line for line in lines if line.startswith("- **TXT**")] == [
        "- **TXT**: " + ", ".join(f"`record{n}`" for n in range(8))
    ]  # first 8 records only
    assert sum(1 for line in lines if re.fullmatch(r"- `n\d+\.example`", line)) == 40
    assert sum(1 for line in lines if re.fullmatch(r"- `http://h/\d+\.js`", line)) == 40
    assert (
        sum(1 for line in lines if re.fullmatch(r"- `\d+/tcp b`", line)) == 50
    )  # banners are not capped


def test_markdown_findings_sort_by_severity_rank_stably_with_unknown_severities_last(
    workspace, tmp_path
):
    findings = [
        Finding("weird", "w1", "d"),
        Finding("info", "i1", "d"),
        Finding("critical", "c1", "d"),
        Finding("low", "l1", "d"),
        Finding("high", "h1", "d"),
        Finding("low", "l2", "d"),
        Finding("medium", "m1", "d"),
        Finding("info", "i2", "d"),
        Finding("mystery", "w2", "d"),
    ]
    lines = markdown_of(
        tmp_path, [scanner.HostReport("h", [], [], 0.0, findings=findings)]
    ).splitlines()
    order = [
        re.match(r"- \*\*(\w+)\*\* (\w+)\.", line).groups()
        for line in lines
        if line.startswith("- **")
    ]
    assert order == [
        ("CRITICAL", "c1"),
        ("HIGH", "h1"),
        ("MEDIUM", "m1"),
        ("LOW", "l1"),
        ("LOW", "l2"),
        ("INFO", "i1"),
        ("INFO", "i2"),
        ("WEIRD", "w1"),
        ("MYSTERY", "w2"),
    ]


def test_markdown_finding_line_shape_with_and_without_url_and_evidence(
    workspace, tmp_path
):
    findings = [
        Finding("high", "Title", "Detail", url="http://h/x", evidence="ev"),
        Finding("high", "Bare", "Plain detail"),
        Finding("high", "Url only", "Detail", url="http://h/y"),
        Finding("high", "Evidence only", "Detail", evidence="why"),
    ]
    lines = markdown_of(
        tmp_path, [scanner.HostReport("h", [], [], 0.0, findings=findings)]
    ).splitlines()
    assert "- **HIGH** Title \u2014 `http://h/x`. Detail (ev)" in lines
    assert "- **HIGH** Bare. Plain detail" in lines
    assert "- **HIGH** Url only \u2014 `http://h/y`. Detail" in lines
    assert "- **HIGH** Evidence only. Detail (why)" in lines


def test_markdown_dns_records_keep_insertion_order(workspace, tmp_path):
    report = scanner.HostReport(
        "h", [], [], 0.0, dns={"MX": ["m"], "A": ["a"], "DMARC": ["d"]}
    )
    lines = markdown_of(tmp_path, [report]).splitlines()
    first = lines.index("### DNS")
    assert lines[first + 1 : first + 4] == [
        "- **MX**: `m`",
        "- **A**: `a`",
        "- **DMARC**: `d`",
    ]


def test_markdown_redacts_configured_secrets_and_url_query_secrets(workspace, tmp_path):
    (workspace / "redaction.json").write_text(
        '{"patterns": ["artifact-secret"]}', encoding="utf-8"
    )
    hit = make_hit(
        "https",
        "https://h.example/?token=query-secret",
        status=200,
        server="artifact-secret",
        title="artifact-secret page",
    )
    finding = Finding(
        "high",
        "artifact-secret",
        "detail artifact-secret",
        url="https://h.example/?api_key=query-secret",
        evidence="artifact-secret",
    )
    text = markdown_of(tmp_path, [one_host(hit, findings=[finding])])
    assert (
        "artifact-secret" not in text
        and "query-secret" not in text
        and "[REDACTED]" in text
    )
    assert (
        "### Live HTTP(S)" in text
    )  # the secret-bearing row is still reported, just scrubbed


# ======================================================================================
# CSV
# ======================================================================================


def test_csv_matches_the_golden_bytes_exactly(workspace, tmp_path):
    assert csv_of(tmp_path, golden_reports()) == GOLDEN_CSV.encode("utf-8")


def test_csv_of_nothing_is_the_header_row_alone_with_a_crlf_terminator(
    workspace, tmp_path
):
    assert csv_of(tmp_path, []) == f"{CSV_HEADER}\r\n".encode("utf-8")
    assert csv_of(
        tmp_path, [scanner.HostReport("h", [], [], 0.0)]
    ) == f"{CSV_HEADER}\r\n".encode("utf-8")


def test_csv_creates_parent_directories(workspace, tmp_path):
    target = tmp_path / "a" / "b" / "report.csv"
    scanner.write_csv(target, [])
    assert target.read_text(encoding="utf-8").startswith(CSV_HEADER)


def test_csv_port_column_is_the_port_record_even_when_the_url_says_otherwise(
    workspace, tmp_path
):
    hit = make_hit("http", "http://h.example:8080/", status=200)
    rows = list(
        csv.reader(csv_of(tmp_path, [one_host(hit, port=9999)]).decode().splitlines())
    )
    assert rows[1][1] == "9999" and rows[1][3] == "http://h.example:8080/"


def test_csv_columns_status_blank_for_error_hits_final_url_and_ms_with_one_decimal(
    workspace, tmp_path
):
    hits = [
        make_hit(
            "http",
            "http://h/a",
            status=301,
            final_url="http://h/b",
            elapsed_ms=12.34,
            bytes_read=7,
            sha256="0123456789abcdef",
        ),
        make_hit("http", "http://h/c", error="odd failure", elapsed_ms=0.0),
        make_hit("http", "http://h/d", status=200, elapsed_ms=1234.5678),
    ]
    rows = list(csv.reader(csv_of(tmp_path, [one_host(*hits)]).decode().splitlines()))[
        1:
    ]
    assert rows[0] == [
        "h.example",
        "80",
        "http",
        "http://h/a",
        "http://h/b",
        "301",
        "",
        "",
        "",
        "0123456789abcdef",
        "7",
        "12.3",
    ]
    assert rows[1][5] == "" and rows[1][11] == "0.0" and rows[2][11] == "1234.6"


def test_csv_quotes_fields_that_need_it_and_leaves_pipes_alone(workspace, tmp_path):
    hit = make_hit(
        "http",
        "http://h/a",
        status=200,
        server="a, b",
        title='say "hi" | now',
        tags=["x", "y"],
    )
    raw = csv_of(tmp_path, [one_host(hit)]).decode()
    row = list(csv.reader(raw.splitlines()))[1]
    assert row[6] == "a, b" and row[7] == 'say "hi" | now' and row[8] == "x,y"
    assert '"say ""hi"" | now"' in raw and '"x,y"' in raw


def test_csv_includes_filtered_hits_unlike_markdown(workspace, tmp_path):
    hit = make_hit("http", "http://h/f", status=403, tags=["forbidden", "filtered"])
    assert (
        len(list(csv.reader(csv_of(tmp_path, [one_host(hit)]).decode().splitlines())))
        == 2
    )


def test_csv_walks_hosts_ports_and_hits_in_order(workspace, tmp_path):
    first = scanner.HostReport(
        "one",
        [],
        [
            scanner.PortResult(
                81,
                True,
                hits=[
                    make_hit("http", "http://one:81/a", status=200),
                    make_hit("http", "http://one:81/b", status=200),
                ],
            ),
            scanner.PortResult(
                80, True, hits=[make_hit("http", "http://one/", status=200)]
            ),
        ],
        0.0,
    )
    second = scanner.HostReport(
        "two",
        [],
        [
            scanner.PortResult(
                82, True, hits=[make_hit("http", "http://two:82/", status=200)]
            )
        ],
        0.0,
    )
    rows = list(csv.reader(csv_of(tmp_path, [first, second]).decode().splitlines()))[1:]
    assert [(row[0], row[1], row[3]) for row in rows] == [
        ("one", "81", "http://one:81/a"),
        ("one", "81", "http://one:81/b"),
        ("one", "80", "http://one/"),
        ("two", "82", "http://two:82/"),
    ]


@pytest.mark.parametrize(
    "error",
    [
        "timeout",
        "TIMEOUT",
        "connect: boom",
        "Server disconnected without sending a response.",
        "refused",
        "ssl: bad",
        "EOF occurred in violation of protocol",
        "wrong version number",
        "certificate verify failed",
        "handshake failure",
    ],
)
def test_csv_leaves_out_error_hits_whose_text_is_connection_or_tls_noise(
    workspace, tmp_path, error
):
    assert (
        len(
            csv_of(tmp_path, [one_host(make_hit("http", "http://h/", error=error))])
            .decode()
            .splitlines()
        )
        == 1
    )


@pytest.mark.parametrize(
    "error",
    [
        "something odd",
        "Invalid port: ':1:80'",
        "asset-excluded; no outbound action ran",
        "host-operation-disallowed",
    ],
)
def test_csv_keeps_error_hits_whose_text_is_not_noise_so_they_look_live(
    workspace, tmp_path, error
):
    # CURRENT / QUIRK (spec section 10 item 6): the "speaking" predicate treats these as live.
    rows = list(
        csv.reader(
            csv_of(tmp_path, [one_host(make_hit("http", "http://h/", error=error))])
            .decode()
            .splitlines()
        )
    )
    assert len(rows) == 2 and rows[1][5] == ""


def test_csv_a_hit_with_a_status_is_live_whatever_its_error_text_says(
    workspace, tmp_path
):
    hit = make_hit("http", "http://h/", status=200, error="timeout")
    assert len(csv_of(tmp_path, [one_host(hit)]).decode().splitlines()) == 2


def test_policy_denials_stay_in_json_diagnostics_but_not_live_reports(
    workspace, tmp_path
):
    hit = make_hit(
        "http", "http://h/private", error="asset-excluded", tags=["policy-blocked"]
    )
    reports = [one_host(hit)]
    assert len(csv_of(tmp_path, reports).decode().splitlines()) == 1
    assert "Live HTTP(S)" not in markdown_of(tmp_path, reports)
    stored = reports_to_json(reports, 0)["hosts"][0]["ports"][0]["hits"][0]
    assert stored["tags"] == ["policy-blocked"] and stored["error"] == "asset-excluded"


def test_csv_a_hit_with_neither_status_nor_error_text_is_not_live(workspace, tmp_path):
    assert (
        len(
            csv_of(tmp_path, [one_host(make_hit("http", "http://h/", error=""))])
            .decode()
            .splitlines()
        )
        == 1
    )


def test_csv_redacts_target_urls_server_and_title_per_field(workspace, tmp_path):
    (workspace / "redaction.json").write_text(
        '{"patterns": ["artifact-secret"]}', encoding="utf-8"
    )
    hit = make_hit(
        "https",
        "https://h.example/?token=query-secret",
        status=200,
        server="artifact-secret",
        title="artifact-secret",
        final_url="https://h.example/?token=query-secret",
    )
    report = one_host(hit)
    report.target = "artifact-secret.example"
    text = csv_of(tmp_path, [report]).decode()
    assert (
        "artifact-secret" not in text
        and "query-secret" not in text
        and "[REDACTED]" in text
    )
    row = list(csv.reader(text.splitlines()))[1]
    assert (
        row[5] == "200" and row[1] == "80" and row[2] == "https"
    )  # numeric / structural columns are untouched


# ======================================================================================
# JSON builder
# ======================================================================================

HIT_KEYS = [
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
]


def test_json_builder_top_level_and_host_shape_for_the_golden_input():
    document = reports_to_json(golden_reports(), 2.5)
    assert list(document) == [
        "tool",
        "version",
        "scanned_at",
        "elapsed_seconds",
        "hosts",
    ]
    assert (
        document["tool"] == "Bughunt"
        and document["version"] == VERSION
        and document["elapsed_seconds"] == 2.5
    )
    assert re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00", document["scanned_at"]
    )
    first, second = document["hosts"]
    assert list(first) == [
        "target",
        "resolved",
        "elapsed_seconds",
        "dns",
        "ct_names",
        "favicon_hash",
        "favicon_hint",
        "js_urls",
        "banners",
        "findings",
        "ports",
    ]
    assert first["target"] == "app.example" and first["resolved"] == [
        "10.0.0.5",
        "10.0.0.6",
    ]
    assert first["dns"] == {"A": ["10.0.0.5"], "MX": ["mail.app.example."]}
    assert first["favicon_hash"] == "81586312" and first["favicon_hint"] == "Jenkins"
    assert first["banners"] == ["443/tcp SSH-2.0"] and first["js_urls"] == [
        "http://app.example:8080/app.js"
    ]
    assert first["findings"] == [
        {
            "severity": "low",
            "title": "Missing X-Frame-Options",
            "detail": "Missing X-Frame-Options (clickjacking)",
            "url": "http://app.example:8080/",
            "evidence": "",
        },
        {
            "severity": "high",
            "title": "Sensitive path responded",
            "detail": "Artifact-style path returned a body",
            "url": "http://app.example:8080/.env",
            "evidence": "",
        },
        {
            "severity": "info",
            "title": "Banner on port 443",
            "detail": "SSH-2.0",
            "url": "",
            "evidence": "",
        },
    ]
    assert list(first["findings"][0]) == [
        "severity",
        "title",
        "detail",
        "url",
        "evidence",
    ]
    assert second == {
        "target": "nohost.example",
        "resolved": [],
        "elapsed_seconds": 0.0,
        "dns": {},
        "ct_names": [],
        "favicon_hash": "",
        "favicon_hint": "",
        "js_urls": [],
        "banners": [],
        "findings": [],
        "ports": [],
    }


def test_json_builder_lists_only_open_ports_and_every_hit_of_those_ports():
    closed = scanner.PortResult(81, False, tcp_error="timeout")
    still_closed = scanner.PortResult(
        82, False, hits=[make_hit("http", "http://h/", status=200)]
    )
    opened = scanner.PortResult(
        80,
        True,
        banner="SSH-2.0",
        hits=[
            make_hit("http", "http://h/a", status=200, tags=["x"]),
            make_hit(
                "http", "http://h/f", status=403, tags=["filtered"]
            ),  # filtered hits are NOT dropped from JSON
            make_hit("http", "http://h/e", error="timeout"),
        ],
    )
    report = scanner.HostReport("h", ["1.1.1.1"], [closed, opened, still_closed], 1.0)
    (host,) = reports_to_json([report], 1.0)["hosts"]
    assert [entry["port"] for entry in host["ports"]] == [80]
    entry = host["ports"][0]
    assert (
        list(entry) == ["port", "tcp_open", "tcp_error", "hits"]
        and entry["tcp_open"] is True
    )
    assert [hit["url"] for hit in entry["hits"]] == [
        "http://h/a",
        "http://h/f",
        "http://h/e",
    ]
    assert (
        "banner" not in entry
    )  # per-port banners reach the JSON only through the host-level list


def test_json_builder_hit_shape_drops_the_body_and_keeps_elapsed_unrounded():
    hit = make_hit(
        "https",
        "https://h/a",
        status=200,
        reason="OK",
        server="nginx",
        powered_by="PHP",
        content_type="text/html",
        location="/x",
        title="T",
        snippet="S",
        bytes_read=5,
        sha256="0123456789abcdef",
        elapsed_ms=12.345678,
        tags=["a", "b"],
        headers={"server": "nginx"},
        body=b"secret body",
    )
    (host,) = reports_to_json([one_host(hit)], 0.0)["hosts"]
    data = host["ports"][0]["hits"][0]
    assert list(data) == HIT_KEYS and "body" not in data
    assert (
        data["elapsed_ms"] == 12.345678 and data["tls"] is None and data["error"] == ""
    )
    assert (
        data["tags"] == ["a", "b"]
        and data["headers"] == {"server": "nginx"}
        and data["status"] == 200
    )
    assert "secret body" not in json.dumps(host)


def test_json_builder_error_hit_has_a_null_status():
    hit = make_hit("http", "http://h/", error="timeout")
    data = reports_to_json([one_host(hit)], 0.0)["hosts"][0]["ports"][0]["hits"][0]
    assert (
        data["status"] is None
        and data["error"] == "timeout"
        and data["final_url"] == "http://h/"
    )


def test_json_builder_serializes_tls_metadata_in_declaration_order():
    hit = make_hit("https", "https://h/", status=200)
    hit.tls = TlsInfo(
        version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        subject="commonName=h",
        issuer="commonName=ca",
        not_before="Jan  1 00:00:00 2026 GMT",
        not_after="Jan  1 00:00:00 2027 GMT",
        san=["DNS:h"],
        expired=False,
        error="",
    )
    data = reports_to_json([one_host(hit)], 0.0)["hosts"][0]["ports"][0]["hits"][0][
        "tls"
    ]
    assert list(data) == [
        "version",
        "cipher",
        "subject",
        "issuer",
        "not_before",
        "not_after",
        "san",
        "expired",
        "error",
    ]
    assert (
        data["version"] == "TLSv1.3"
        and data["san"] == ["DNS:h"]
        and data["expired"] is False
    )


def test_json_builder_rounds_elapsed_seconds_to_three_decimals():
    document = reports_to_json([scanner.HostReport("h", [], [], 0.123456)], 1.987654)
    assert (
        document["elapsed_seconds"] == 1.988
        and document["hosts"][0]["elapsed_seconds"] == 0.123
    )


def test_json_builder_keeps_host_order_and_a_dns_failed_host():
    reports = [
        scanner.HostReport("b", [], [], 0.0),
        scanner.HostReport("a", ["1.1.1.1"], [], 0.5),
    ]
    hosts = reports_to_json(reports, 0.0)["hosts"]
    assert (
        [host["target"] for host in hosts] == ["b", "a"]
        and hosts[0]["ports"] == []
        and hosts[0]["resolved"] == []
    )


def test_json_builder_output_is_plain_json_serializable_data():
    text = json.dumps(reports_to_json(golden_reports(), 2.5))
    assert json.loads(text)["hosts"][0]["target"] == "app.example"
