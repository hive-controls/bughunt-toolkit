"""Characterization oracle for addons/chromahaus, part 2: command behavior.

Export (--out), download, watch, the REPL, the display field sets and caps, --json, and the color rules.
See test_chromahaus_contract.py for the labels and the reading guide. Defects live in test_chromahaus_defects.py;
nothing here asserts a known-defective behavior. Display layout, glyphs, colors, banner art and wording are FREE
(spec 4.10, 10) so these tests assert VALUES, FIELD SETS, CAPS and thresholds, never labels or widths.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time

import pytest

from chromahaus_support import (  # noqa: F401  (fixtures are imported so pytest registers them here)
    ANSI,
    BAZAAR,
    FEODO,
    KEY,
    M32,
    SHA,
    SSLBL,
    THREATFOX,
    URLHAUS,
    ZIP,
    feed,
    form_post,
    json_documents,
    json_post,
    long_sleeps,
    no_real_network,
    plain_get,
    poll_script,
    repl,
    reply_json,
    reply_text,
    rig,
    shown_numbers,
    sleeps,
    url_row,
    write_policy,
)

# ---------------------------------------------------------------------------------------------------------------
# Export: --out (spec 4.7)
# ---------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["rows.json", "ROWS.JSON", "Rows.Json"])
def test_out_with_a_json_extension_any_case_writes_a_two_space_array_of_the_row_objects(
    rig, name
):
    rows = [url_row(1), url_row(2, note="é→")]
    rig.fake.default = reply_json({"query_status": "ok", "urls": rows})
    path = rig.cwd / name
    result = rig.cli("--out", str(path), "recent")
    assert result.rc == 0, result.err
    text = path.read_text(encoding="utf-8")
    assert json.loads(text) == rows
    assert text.startswith('[\n  {\n    "')
    assert re.search(r"wrote 2 rows", result.err) and str(path) in result.err


@pytest.mark.parametrize("name", ["rows.csv", "rows.CSV", "rows.txt", "rows"])
def test_out_with_any_other_extension_writes_crlf_csv_with_the_union_of_keys_in_first_seen_order(
    rig, name
):
    rows = [
        url_row(1),
        {"id": "2", "blacklists": {"a": "b"}, "note": None, "extra": "é→"},
    ]
    rig.fake.default = reply_json({"query_status": "ok", "urls": rows})
    path = rig.cwd / name
    result = rig.cli("--out", str(path), "recent")
    assert result.rc == 0, result.err
    raw = path.read_bytes()
    assert raw.count(b"\r\n") == 3 and raw.replace(b"\r\n", b"").count(b"\n") == 0
    table = list(csv.reader(io.StringIO(raw.decode("utf-8"), newline="")))
    header = table[0]
    assert header == [
        "id",
        "url",
        "url_status",
        "host",
        "date_added",
        "threat",
        "tags",
        "blacklists",
        "note",
        "extra",
    ]
    first, second = (dict(zip(header, row)) for row in table[1:])
    assert (
        first["tags"] == '["elf", "mozi"]'
        and first["note"] == ""
        and first["extra"] == ""
    )
    assert (
        second["blacklists"] == '{"a": "b"}'
        and second["note"] == ""
        and second["extra"] == "é→"
    )
    assert second["id"] == "2" and second["url"] == ""
    assert re.search(r"wrote 2 rows", result.err)


R1, R2 = url_row(1), url_row(2)
P1 = {
    "sha256_hash": SHA,
    "signature": "Mozi",
    "file_type": "elf",
    "firstseen": "2026-10-18",
}
T1 = {
    "ioc": "1.2.3.4:80",
    "confidence_level": 90,
    "malware": "win.x",
    "ioc_type": "ip:port",
}
B1 = {
    "sha256_hash": SHA,
    "signature": "Mozi",
    "file_type": "elf",
    "first_seen": "2026-10-18 01:02:03",
}
URL_DOC = {
    "query_status": "ok",
    "id": "7",
    "url": "http://u.example/",
    "url_status": "online",
    "host": "u.example",
    "threat": "malware_download",
    "tags": ["t"],
}

EXPORT_MATRIX = [
    pytest.param(
        ["recent"],
        {"query_status": "ok", "urls": [R1, R2]},
        [R1, R2],
        id="recent-exports-the-url-objects",
    ),
    pytest.param(
        ["payloads"],
        {"query_status": "ok", "payloads": [P1]},
        [P1],
        id="payloads-exports-the-payload-objects",
    ),
    pytest.param(
        ["url", "http://u.example/"],
        URL_DOC,
        [URL_DOC],
        id="url-exports-the-whole-response",
    ),
    pytest.param(
        ["url", "http://u.example/"],
        {"query_status": "no_results"},
        [{"query_status": "no_results"}],
        id="url-no-hit-still-exports-the-response",
    ),
    pytest.param(
        ["host", "h.example"],
        {"query_status": "ok", "host": "h.example", "urls": [R1]},
        [R1],
        id="host-exports-its-urls",
    ),
    pytest.param(
        ["host", "h.example"],
        {"query_status": "ok", "host": "h.example"},
        [{"query_status": "ok", "host": "h.example"}],
        id="host-without-urls-exports-the-response",
    ),
    pytest.param(
        ["iocs"], {"query_status": "ok", "data": [T1]}, [T1], id="iocs-exports-data"
    ),
    pytest.param(
        ["fox", "x"], {"query_status": "ok", "data": [T1]}, [T1], id="fox-exports-data"
    ),
    pytest.param(
        ["bazaar"], {"query_status": "ok", "data": [B1]}, [B1], id="bazaar-exports-data"
    ),
]


@pytest.mark.parametrize(("argv", "response", "expected_rows"), EXPORT_MATRIX)
def test_out_exports_the_documented_rows_per_command(
    rig, argv, response, expected_rows
):
    rig.fake.default = reply_json(response)
    path = rig.cwd / "rows.json"
    result = rig.cli("--out", str(path), *argv)
    assert result.rc == 0, result.err
    assert json.loads(path.read_text(encoding="utf-8")) == expected_rows


def test_json_mode_and_out_work_together(rig):
    rig.fake.default = reply_json({"query_status": "ok", "urls": [R1]})
    path = rig.cwd / "both.json"
    result = rig.cli("--json", "--out", str(path), "recent")
    assert result.rc == 0 and json.loads(path.read_text(encoding="utf-8")) == [R1]
    assert json_documents(result.out)[0] == {"query_status": "ok", "urls": [R1]}


# ---------------------------------------------------------------------------------------------------------------
# download (spec 4.6): the [T] safety properties plus the documented order and fallbacks
# ---------------------------------------------------------------------------------------------------------------

DOWNLOAD_URL = f"{URLHAUS}/download/{SHA}/"


def samples(rig):
    root = rig.workspace / "samples"
    return (
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
        )
        if root.is_dir()
        else []
    )


@pytest.mark.parametrize("digest", ["zz", "a" * 63, "g" * 64, "a" * 65, ""])
def test_download_needs_a_64_hex_digest_before_any_output_or_request(rig, digest):
    result = rig.cli("download", digest, "--i-understand")
    assert (
        result.exited
        and isinstance(result.exit_arg, str)
        and "sha256" in result.exit_arg.lower()
    )
    assert result.rc == 1
    assert "infected" not in result.out and rig.fake.seen == [] and samples(rig) == []


def test_download_without_consent_prints_the_warning_then_refuses_before_any_request(
    rig,
):
    result = rig.cli("download", SHA)
    assert (
        result.exited
        and isinstance(result.exit_arg, str)
        and "--i-understand" in result.exit_arg
    )
    assert result.rc == 1
    assert (
        "infected" in result.out
    )  # the warning (with the zip password) is printed first
    assert rig.fake.seen == [] and not (rig.workspace / "samples").exists()


def test_download_saves_the_raw_bytes_in_the_workspace_samples_folder_and_nothing_else(
    rig,
):
    rig.fake.routes[DOWNLOAD_URL] = (200, {"content-type": "application/zip"}, ZIP)
    result = rig.cli("download", SHA, "--i-understand")
    assert result.rc == 0, result.err
    assert (
        rig.workspace / "samples" / f"{SHA}.zip"
    ).read_bytes() == ZIP  # never unpacked or altered
    assert samples(rig) == [f"{SHA}.zip"]
    assert list(rig.cwd.iterdir()) == []  # nothing lands in the working directory
    assert (
        "infected" in result.out
        and str(len(ZIP)) in result.out
        and f"{SHA}.zip" in result.out
    )
    assert [(s.method, s.url) for s in rig.fake.seen] == [("GET", DOWNLOAD_URL)]
    assert rig.fake.seen[0].headers["auth-key"] == KEY


def test_download_lowercases_and_strips_the_digest(rig):
    rig.fake.routes[DOWNLOAD_URL] = (200, {}, ZIP)
    result = rig.cli("download", f"  {SHA.upper()}  ", "--i-understand")
    assert result.rc == 0, result.err
    assert rig.fake.urls == [DOWNLOAD_URL] and samples(rig) == [f"{SHA}.zip"]


@pytest.mark.parametrize(
    ("dest", "expected"),
    [(".", f"{SHA}.zip"), ("", f"{SHA}.zip"), ("./inside/../ok", f"ok/{SHA}.zip")],
)
def test_download_dest_inside_the_samples_folder_is_accepted(rig, dest, expected):
    rig.fake.routes[DOWNLOAD_URL] = (200, {}, ZIP)
    result = rig.cli("download", SHA, "--i-understand", "--dest", dest)
    assert result.rc == 0, result.err
    assert samples(rig) == [expected]


def test_download_dest_is_a_subfolder_created_on_demand(rig):
    rig.fake.routes[DOWNLOAD_URL] = (200, {}, ZIP)
    result = rig.cli("download", SHA, "--i-understand", "--dest", "sub/dir")
    assert result.rc == 0, result.err
    assert samples(rig) == [f"sub/dir/{SHA}.zip"]


@pytest.mark.parametrize("dest", ["..", "../..", "sub/../..", "../sibling"])
def test_download_dest_cannot_leave_the_samples_folder(rig, dest, tmp_path):
    result = rig.cli("download", SHA, "--i-understand", "--dest", dest)
    assert result.exited and isinstance(result.exit_arg, str) and result.rc == 1
    assert rig.fake.seen == []
    assert not list(tmp_path.rglob("*.zip"))


def test_download_absolute_dest_is_refused(rig, tmp_path):
    result = rig.cli(
        "download", SHA, "--i-understand", "--dest", str(tmp_path / "elsewhere")
    )
    assert result.exited and isinstance(result.exit_arg, str) and result.rc == 1
    assert rig.fake.seen == [] and not (tmp_path / "elsewhere").exists()


@pytest.mark.parametrize(
    ("first", "reason"),
    [
        ((404, {}, b"no"), "status-over-399"),
        ((200, {}, b"tiny"), "body-under-32-bytes"),
        ((200, {}, b"x" * 31), "body-of-31-bytes"),
        ((200, {}, b""), "empty-body"),
    ],
)
def test_download_falls_back_to_bazaar_get_file(rig, first, reason):
    rig.fake.routes[DOWNLOAD_URL] = first
    rig.fake.routes[BAZAAR] = (200, {"content-type": "application/zip"}, ZIP)
    result = rig.cli("download", SHA, "--i-understand")
    assert result.rc == 0, result.err
    assert [(s.method, s.url, s.body) for s in rig.fake.seen] == [
        ("GET", DOWNLOAD_URL, b""),
        ("POST", BAZAAR, f"query=get_file&sha256_hash={SHA}".encode()),
    ]
    assert (
        rig.fake.seen[1].headers["content-type"] == "application/x-www-form-urlencoded"
    )
    assert rig.fake.seen[1].headers["auth-key"] == KEY
    assert (rig.workspace / "samples" / f"{SHA}.zip").read_bytes() == ZIP


def test_a_32_byte_urlhaus_body_is_not_too_short_so_there_is_no_fallback(rig):
    rig.fake.routes[DOWNLOAD_URL] = (200, {}, b"x" * 32)
    result = rig.cli("download", SHA, "--i-understand")
    assert result.rc == 0 and len(rig.fake.seen) == 1
    assert (rig.workspace / "samples" / f"{SHA}.zip").read_bytes() == b"x" * 32


def test_download_fails_with_the_http_status_when_the_fallback_also_fails(rig):
    rig.fake.routes[DOWNLOAD_URL] = (404, {}, b"no")
    rig.fake.routes[BAZAAR] = (500, {}, b"boom")
    result = rig.cli("download", SHA, "--i-understand")
    assert result.exited and "500" in str(result.exit_arg) and result.rc == 1
    assert samples(rig) == []


def test_download_reports_a_json_error_body_instead_of_saving_it(rig):
    rig.fake.routes[DOWNLOAD_URL] = (
        200,
        {},
        b'{"query_status": "not_found"}' + b" " * 40,
    )
    result = rig.cli("download", SHA, "--i-understand")
    assert result.exited and "not_found" in str(result.exit_arg) and result.rc == 1
    assert samples(rig) == [] and len(rig.fake.seen) == 1


def test_download_reports_a_json_error_from_the_bazaar_fallback(rig):
    rig.fake.routes[DOWNLOAD_URL] = (404, {}, b"no")
    rig.fake.routes[BAZAAR] = reply_json({"query_status": "file_not_found"})
    result = rig.cli("download", SHA, "--i-understand")
    assert result.exited and "file_not_found" in str(result.exit_arg) and result.rc == 1
    assert samples(rig) == []


def test_cmd_download_called_directly_returns_none_and_refuses_with_systemexit(rig):
    rig.fake.routes[DOWNLOAD_URL] = (200, {}, ZIP)
    with pytest.raises(SystemExit):
        rig.module.cmd_download(KEY, SHA, ".", False)
    assert rig.fake.seen == []
    assert rig.module.cmd_download(KEY, SHA, ".", True) is None
    assert samples(rig) == [f"{SHA}.zip"]


def test_download_uses_dot_bughunt_in_the_cwd_when_no_workspace_is_configured(
    rig, monkeypatch
):
    monkeypatch.delenv("BUGHUNT_SCOPE")
    write_policy(rig.cwd / ".bughunt")
    rig.fake.routes[DOWNLOAD_URL] = (200, {}, ZIP)
    result = rig.cli("download", SHA, "--i-understand")
    assert result.rc == 0, result.err
    assert (rig.cwd / ".bughunt" / "samples" / f"{SHA}.zip").read_bytes() == ZIP


# ---------------------------------------------------------------------------------------------------------------
# watch (spec 4.9)
# ---------------------------------------------------------------------------------------------------------------


def test_watch_primes_then_reports_only_unseen_urls_and_stops_cleanly_on_ctrl_c(
    rig, sleeps
):
    rig.fake.handler = poll_script(
        [
            feed(("1", "http://a/"), ("2", "http://b/")),
            feed(("1", "http://a/"), ("3", "http://c/")),
            feed(("3", "http://c/")),
        ]
    )
    result = rig.cli("-n", "10", "watch", "--interval", "5")
    assert result.rc == 0, result.err
    assert rig.fake.urls == [f"{URLHAUS}/urls/recent/limit/10/"] * 4
    assert long_sleeps(sleeps) == [15, 15, 15]
    lowered = result.out.lower()
    assert (
        re.search(r"primed\D{0,20}2\b", lowered)
        and "+1" in result.out
        and "quiet" in lowered
    )
    assert "http://c/" in result.out
    assert (
        "http://a/" not in result.out and "http://b/" not in result.out
    )  # the primed set is never listed
    assert (
        len(re.findall(r"\b\d\d:\d\d:\d\d\b", result.out)) >= 3
    )  # one HH:MM:SS stamp per poll
    first_line = next(line for line in result.out.splitlines() if line.strip())
    assert re.search(
        r"(?<!\d)5(?!\d)", first_line
    )  # watch prints no banner: the heading (requested interval) leads


@pytest.mark.parametrize(
    ("interval", "expected_sleep"),
    [(0, 15), (5, 15), (15, 15), (16, 16), (99, 99), (-4, 15)],
)
def test_watch_sleeps_at_least_fifteen_seconds_between_polls(
    rig, sleeps, interval, expected_sleep
):
    rig.fake.handler = poll_script([feed(("1", "http://a/"))])
    result = rig.cli("watch", "--interval", str(interval))
    assert result.rc == 0, result.err
    assert long_sleeps(sleeps) == [expected_sleep]


def test_watch_defaults_are_a_30_second_interval_and_the_global_limit_of_25(
    rig, sleeps
):
    rig.fake.handler = poll_script([feed(("1", "http://a/"))])
    result = rig.cli("watch")
    assert result.rc == 0
    assert rig.fake.urls[0] == f"{URLHAUS}/urls/recent/limit/25/" and long_sleeps(
        sleeps
    ) == [30]


def test_watch_keys_seen_items_by_id_and_falls_back_to_the_url(rig, sleeps):
    rig.fake.handler = poll_script(
        [
            feed(("1", "http://one/"), (None, "http://noid/")),
            feed(("1", "http://one-moved/"), (None, "http://noid/")),
        ]
    )
    result = rig.cli("watch")
    assert result.rc == 0
    assert "http://one-moved/" not in result.out  # same id, new url: not new
    assert "quiet" in result.out.lower() and not re.search(
        r"\+\d+", result.out
    )  # no "+N new" stamp at all


def test_ctrl_c_in_the_very_first_poll_returns_zero(rig, sleeps):
    rig.fake.handler = poll_script([])
    result = rig.cli("watch")
    assert result.rc == 0 and len(rig.fake.seen) == 1 and long_sleeps(sleeps) == []


def test_ctrl_c_while_sleeping_returns_zero(rig, monkeypatch):
    rig.fake.handler = poll_script([feed(("1", "http://a/"))])

    def interrupted(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", interrupted)
    result = rig.cli("watch")
    assert result.rc == 0


# ---------------------------------------------------------------------------------------------------------------
# REPL (spec 4.8)
# ---------------------------------------------------------------------------------------------------------------

M32_REQUESTS = [
    form_post(f"{URLHAUS}/payload/", b"md5_hash=" + M32.encode()),
    form_post(BAZAAR, b"query=get_info&hash=" + M32.encode()),
    json_post(THREATFOX, b'{"query": "search_hash", "hash": "' + M32.encode() + b'"}'),
]
FAMILY_REQUESTS = [
    form_post(f"{URLHAUS}/signature/", b"signature=Emotet"),
    json_post(THREATFOX, b'{"query": "malwareinfo", "malware": "Emotet", "limit": 50}'),
    form_post(BAZAAR, b"query=get_siginfo&signature=Emotet&limit=25"),
]

REPL_REQUESTS = [
    pytest.param(
        "recent",
        [plain_get(f"{URLHAUS}/urls/recent/limit/25/")],
        id="recent-default-25",
    ),
    pytest.param(
        "recent 2", [plain_get(f"{URLHAUS}/urls/recent/limit/2/")], id="recent-n"
    ),
    pytest.param(
        "payloads",
        [plain_get(f"{URLHAUS}/payloads/recent/limit/25/")],
        id="payloads-default-25",
    ),
    pytest.param(
        "payloads 4",
        [plain_get(f"{URLHAUS}/payloads/recent/limit/4/")],
        id="payloads-n",
    ),
    pytest.param(
        "bazaar",
        [form_post(BAZAAR, b"query=get_recent&selector=25")],
        id="bazaar-default-25",
    ),
    pytest.param(
        "bazaar 6", [form_post(BAZAAR, b"query=get_recent&selector=6")], id="bazaar-n"
    ),
    pytest.param(
        "iocs",
        [json_post(THREATFOX, b'{"query": "get_iocs", "days": 1}')],
        id="iocs-default-1",
    ),
    pytest.param(
        "iocs 3",
        [json_post(THREATFOX, b'{"query": "get_iocs", "days": 3}')],
        id="iocs-3",
    ),
    pytest.param(
        "iocs 99",
        [json_post(THREATFOX, b'{"query": "get_iocs", "days": 7}')],
        id="iocs-clamped-to-7",
    ),
    pytest.param(
        "iocs 0",
        [json_post(THREATFOX, b'{"query": "get_iocs", "days": 1}')],
        id="iocs-clamped-to-1",
    ),
    pytest.param(
        "fox 1.2.3.4",
        [json_post(THREATFOX, b'{"query": "search_ioc", "search_term": "1.2.3.4"}')],
        id="fox",
    ),
    pytest.param(
        "url http://x.example/a",
        [form_post(f"{URLHAUS}/url/", b"url=http%3A%2F%2Fx.example%2Fa")],
        id="url",
    ),
    pytest.param(
        "host evil.example",
        [form_post(f"{URLHAUS}/host/", b"host=evil.example")],
        id="host",
    ),
    pytest.param(f"hash {M32}", M32_REQUESTS, id="hash-is-hunt"),
    pytest.param(
        "hunt evil.example",
        [
            form_post(f"{URLHAUS}/host/", b"host=evil.example"),
            json_post(
                THREATFOX, b'{"query": "search_ioc", "search_term": "evil.example"}'
            ),
        ],
        id="hunt",
    ),
    pytest.param(
        "tag mozi",
        [
            form_post(f"{URLHAUS}/tag/", b"tag=mozi"),
            form_post(BAZAAR, b"query=get_taginfo&tag=mozi&limit=25"),
        ],
        id="tag-fixed-limit-25",
    ),
    pytest.param("family Emotet", FAMILY_REQUESTS, id="family-fixed-limits-50-and-25"),
    pytest.param("sig Emotet", FAMILY_REQUESTS, id="sig-alias"),
    pytest.param("signature Emotet", FAMILY_REQUESTS, id="signature-alias"),
    pytest.param("feodo", [plain_get(FEODO)], id="feodo"),
    pytest.param("sslbl", [plain_get(SSLBL)], id="sslbl"),
    pytest.param(
        "RECENT 2",
        [plain_get(f"{URLHAUS}/urls/recent/limit/2/")],
        id="command-word-is-case-insensitive",
    ),
    pytest.param(
        "8.8.8.8",
        [
            form_post(f"{URLHAUS}/host/", b"host=8.8.8.8"),
            json_post(THREATFOX, b'{"query": "search_ioc", "search_term": "8.8.8.8"}'),
        ],
        id="bare-ip-runs-hunt",
    ),
]


@pytest.mark.parametrize(("line", "expected"), REPL_REQUESTS)
def test_repl_commands_send_the_documented_requests(rig, line, expected):
    result = repl(rig, line, "quit")
    assert result.rc == 0, result.err
    assert [(s.method, s.url, s.body or None) for s in rig.fake.seen] == [
        (m, u, b) for m, u, b, _ in expected
    ]
    assert all(s.headers["auth-key"] == KEY for s in rig.fake.seen)


@pytest.mark.parametrize(
    "script",
    [
        [],
        [KeyboardInterrupt()],
        ["", "   ", "quit"],
        ["quit"],
        ["q"],
        ["exit"],
        ["QUIT"],
    ],
    ids=["eof", "ctrl-c", "blank-lines-then-quit", "quit", "q", "exit", "QUIT"],
)
def test_repl_leaves_quietly_with_rc0_on_eof_ctrl_c_and_the_exit_words(rig, script):
    result = repl(rig, *script)
    assert result.rc == 0 and result.err == "" and rig.fake.seen == []


def test_repl_via_the_repl_subcommand_is_the_same_as_no_subcommand(rig):
    result = rig.run(["--key", KEY, "repl"], stdin=["quit"])
    assert result.rc == 0 and len(result.prompts) == 1


def test_repl_prompt_is_chroma_plus_a_glyph_and_a_space_colored_only_on_a_tty(rig):
    plain = repl(rig, "quit").prompts[0]
    assert plain.startswith("chroma") and plain.endswith(" ") and "\x1b" not in plain
    colored = repl(rig, "quit", tty=True).prompts[0]
    assert "\x1b[" in colored and ANSI.sub("", colored).startswith("chroma")


def test_repl_help_lists_every_command_word(rig):
    quiet = repl(rig, "quit").out
    helped = repl(rig, "help", "quit").out
    assert len(helped) > len(quiet)
    for word in [
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
        "export",
        "raw",
        "help",
        "quit",
    ]:
        assert helped.count(word) > quiet.count(word), word
    assert len(repl(rig, "?", "quit").out) > len(quiet)


def test_repl_raw_toggles_json_output_on_and_off(rig):
    response = {"query_status": "ok", "urls": [R1]}
    rig.fake.default = reply_json(response)
    result = repl(rig, "raw", "recent", "raw", "recent", "quit")
    assert result.rc == 0
    assert json_documents(result.out) == [
        response
    ]  # only the call made while raw was on
    assert re.search(r"\bon\b", result.out) and re.search(r"\boff\b", result.out)
    assert R1["url"] in result.out


def test_repl_bad_numbers_print_the_valueerror_and_keep_going(rig):
    result = repl(rig, "recent x", "iocs y", "help", "quit")
    assert result.rc == 0 and rig.fake.seen == []
    assert result.out.count("invalid literal for int()") == 2
    assert "hunt" in result.out  # help still ran afterwards


def test_repl_prints_a_failing_command_to_stdout_and_continues(rig):
    rig.fake.routes[f"{URLHAUS}/urls/recent/limit/25/"] = (500, {}, b"boom")
    result = repl(rig, "recent", "payloads", "quit")
    assert result.rc == 0 and result.err == ""
    assert "HTTP 500" in result.out
    assert len(rig.fake.seen) == 2  # the line after the failure was still executed


@pytest.mark.parametrize(
    "line",
    [
        "hunt",
        "url",
        "host",
        "hash",
        "tag",
        "family",
        "fox",
        "download",
        "export",
        "bogus",
        "mozi",
    ],
)
def test_repl_unknown_words_and_argument_commands_without_arguments_say_unknown_and_send_nothing(
    rig, line
):
    result = repl(rig, line, "quit")
    assert result.rc == 0 and rig.fake.seen == []
    assert "unknown" in result.out.lower()


def test_repl_spaced_bare_line_is_hunted_whole_with_its_case_preserved(rig):
    result = repl(rig, "http://X.example/A b", "quit")
    assert result.rc == 0
    assert rig.fake.seen[0].body == b"url=http%3A%2F%2FX.example%2FA+b"


def test_repl_command_arguments_keep_their_case(rig):
    repl(rig, "Hunt Mozi.EXAMPLE", "quit")
    assert rig.fake.seen[0].body == b"host=Mozi.EXAMPLE"


def test_repl_export_writes_the_last_recorded_rows_and_remembers_them_across_other_commands(
    rig,
):
    rig.fake.routes[f"{URLHAUS}/urls/recent/limit/25/"] = reply_json(
        {"query_status": "ok", "urls": [R1, R2]}
    )
    path = rig.cwd / "repl.csv"
    result = repl(rig, "recent", "tag mozi", f"export {path}", "quit")
    assert result.rc == 0 and re.search(r"wrote 2 rows", result.err)
    with path.open(encoding="utf-8", newline="") as handle:
        assert len(list(csv.reader(handle))) == 3  # header + 2 rows


def test_repl_export_with_no_rows_says_nothing_to_export_and_writes_no_file(rig):
    path = rig.cwd / "none.json"
    result = repl(rig, f"export {path}", "hunt evil.example", f"export {path}", "quit")
    assert result.out.lower().count("nothing to export") == 2 and not path.exists()


def test_repl_watch_ctrl_c_returns_to_the_prompt_and_uses_a_fixed_poll_size_of_50(
    rig, sleeps
):
    rig.fake.handler = poll_script([feed(("1", "http://a/"))])
    result = repl(rig, "watch 20", "help", "quit")
    assert result.rc == 0 and rig.fake.urls[0] == f"{URLHAUS}/urls/recent/limit/50/"
    assert long_sleeps(sleeps) == [20]
    assert "hunt" in result.out  # the prompt came back and help ran


def test_repl_watch_default_interval_is_30(rig, sleeps):
    rig.fake.handler = poll_script([feed(("1", "http://a/"))])
    repl(rig, "watch", "quit")
    assert long_sleeps(sleeps) == [30]


def test_repl_feodo_and_sslbl_display_caps_are_40_and_30(rig):
    rig.fake.routes[FEODO] = reply_text(
        "# c\n" + "".join(f"10.0.0.{i}\n" for i in range(1, 61))
    )
    rig.fake.routes[SSLBL] = reply_text(
        "# c\n" + "".join(f"2026-01-{i:02d},sha{i},reason{i}\n" for i in range(1, 51))
    )
    feodo = repl(rig, "feodo", "quit").out
    assert shown_numbers(r"10\.0\.0\.(\d+)", feodo) == set(range(1, 41)) and re.search(
        r"\b20 more", feodo
    )
    sslbl = repl(rig, "sslbl", "quit").out
    assert shown_numbers(r"sha(\d+)", sslbl) == set(range(1, 31)) and re.search(
        r"\b20 more", sslbl
    )


# ---------------------------------------------------------------------------------------------------------------
# Display: field sets, caps, thresholds, statuses (spec 4.10). VALUES and CAPS only; labels/widths are FREE.
# ---------------------------------------------------------------------------------------------------------------


def test_recent_rows_show_the_row_fields_numbered_from_one_and_stop_at_the_limit(rig):
    rows = [
        url_row(1),
        url_row(2, url_status=None, status="offline"),
        url_row(3, url_status=None),
        url_row(4, tags="alpha, beta"),
        url_row(5),
    ]
    rig.fake.default = reply_json({"query_status": "ok", "urls": rows})
    result = rig.cli("-n", "4", "recent")
    assert result.rc == 0
    out = result.out
    for needle in (
        "ONLINE",
        "OFFLINE",
        "?",
        "#elf",
        "#mozi",
        "#alpha",
        "#beta",
        "malware_download",
        "r.example",
        "2026-10-18 10:00:00",
    ):
        assert needle in out, needle
    assert shown_numbers(r"http://r\.example/(\d+)", out) == {1, 2, 3, 4}
    assert re.search(r"(?m)^\s*1\b", out) and re.search(r"(?m)^\s*4\b", out)


def test_url_detail_shows_its_fields_the_blacklists_and_at_most_25_payloads(rig):
    payloads = [
        {
            "signature": f"Sig{i:02d}",
            "file_type": "elf",
            "response_sha256": f"{i:02x}" + "b" * 62,
            "firstseen": "2026-10-18",
        }
        for i in range(30)
    ]
    payloads[0].update(sha256_hash="z" * 64)  # response_sha256 wins over sha256_hash
    detail = {
        "query_status": "ok",
        "id": "ID-77",
        "url": "http://detail.example/path",
        "url_status": "online",
        "host": "detail.example",
        "threat": "malware_download",
        "date_added": "2026-10-18T10:00:00",
        "last_online": "2026-10-19T11:12:13",
        "reporter": "reporter-x",
        "larted": "true",
        "tags": ["t1", "t2"],
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/77/",
        "blacklists": {"spamhaus_dbl": "spam-value", "surbl": "surbl-value"},
        "payloads": payloads,
    }
    rig.fake.default = reply_json(detail)
    out = rig.cli("url", "http://detail.example/path").out
    for needle in (
        "ID-77",
        "http://detail.example/path",
        "ONLINE",
        "detail.example",
        "malware_download",
        "2026-10-18 10:00:00",
        "2026-10-19 11:12:13",
        "reporter-x",
        "true",
        "#t1",
        "#t2",
        "https://urlhaus.abuse.ch/url/77/",
        "spam-value",
        "surbl-value",
        "elf",
        "2026-10-18",
    ):
        assert needle in out, needle
    shown = {i for i in range(30) if f"{i:02x}" + "b" * 14 in out}
    assert shown == set(range(25))
    assert (
        "00" + "b" * 15 not in out and "z" * 16 not in out
    )  # 16 characters of the hash, no more
    assert {f"Sig{i:02d}" for i in range(25)} <= set(
        re.findall(r"Sig\d\d", out)
    ) and "Sig25" not in out


def test_url_detail_falls_back_to_sha256_hash_and_unlabeled_for_payloads_without_them(
    rig,
):
    rig.fake.default = reply_json(
        {
            "query_status": "ok",
            "url": "http://d.example/",
            "payloads": [
                {
                    "signature": None,
                    "sha256_hash": "q" * 64,
                    "file_type": "exe",
                    "firstseen": "2026-01-01",
                }
            ],
        }
    )
    out = rig.cli("url", "http://d.example/").out
    assert (
        "unlabeled" in out and "q" * 16 in out and "q" * 17 not in out and "exe" in out
    )


def test_host_detail_shows_its_fields_and_at_most_40_url_rows_with_a_more_tail(rig):
    rig.fake.default = reply_json(
        {
            "query_status": "ok",
            "host": "h.example",
            "firstseen": "2026-01-02T03:04:05",
            "url_count": "45",
            "urlhaus_reference": "https://urlhaus.abuse.ch/host/h.example/",
            "blacklists": {"spamhaus_dbl": "spam-value", "surbl": "surbl-value"},
            "urls": [url_row(i) for i in range(1, 46)],
        }
    )
    out = rig.cli("host", "h.example").out
    for needle in (
        "h.example",
        "2026-01-02 03:04:05",
        "45",
        "https://urlhaus.abuse.ch/host/h.example/",
        "spam-value",
        "surbl-value",
    ):
        assert needle in out, needle
    assert shown_numbers(r"http://r\.example/(\d+)", out) == set(
        range(1, 41)
    ) and re.search(r"\b5 more", out)


def test_payload_detail_shows_its_fields_ssdeep_virustotal_and_at_most_20_distributing_urls(
    rig,
):
    rig.fake.routes[f"{URLHAUS}/payload/"] = reply_json(
        {
            "query_status": "ok",
            "md5_hash": "m" * 32,
            "sha256_hash": SHA,
            "file_type": "elf",
            "file_size": "4242",
            "signature": "MoziSig",
            "firstseen": "2026-10-18T01:02:03",
            "imphash": "imp-hash-x",
            "ssdeep": "s" * 90,
            "tlsh": "T1TLSHVALUE",
            "magika": "magika-x",
            "virustotal": {"result": "40/70", "percent": 57.1},
            "urls": [url_row(i) for i in range(1, 26)],
        }
    )
    out = rig.cli("hash", SHA).out
    for needle in (
        "m" * 32,
        SHA,
        "elf",
        "4242",
        "MoziSig",
        "2026-10-18 01:02:03",
        "imp-hash-x",
        "T1TLSHVALUE",
        "magika-x",
        "40/70",
        "57.1",
    ):
        assert needle in out, needle
    assert "s" * 50 in out and "s" * 90 not in out  # ssdeep is shortened
    assert shown_numbers(r"http://r\.example/(\d+)", out) == set(range(1, 21))


def test_bazaar_list_shows_the_fallback_fields_tags_and_at_most_40_rows(rig):
    rows = [
        {
            "signature": f"Sig{i:02d}",
            "file_type": "elf",
            "sha256_hash": f"{i:02x}" + "c" * 62,
            "first_seen": "2026-10-18 01:02:03",
            "tags": ["t1", "t2"],
        }
        for i in range(45)
    ]
    rows[0].update(signature=None, malware="MalFallback")
    rows[1].update(signature=None, malware=None)
    rows[2].update(file_type=None, file_type_mime="x/elf")
    rows[3].update(first_seen=None, firstseen="2001-02-03")
    rig.fake.default = reply_json(
        {"query_status": "success", "data": rows}
    )  # Bazaar accepts ok or success
    out = rig.cli("-n", "50", "bazaar").out
    for needle in (
        "MalFallback",
        "unlabeled",
        "x/elf",
        "2001-02-03",
        "#t1",
        "#t2",
        "elf",
        "2026-10-18 01:02:03",
    ):
        assert needle in out, needle
    assert shown_numbers(r"Sig(\d\d)", out) == set(range(2, 40))
    assert {i for i in range(45) if f"{i:02x}" + "c" * 14 in out} == set(range(40))
    assert "00" + "c" * 15 not in out  # 16 characters of the hash, no more


HUNT_SECTION_ORDER = [
    pytest.param(
        "http://u.example/x",
        {
            f"{URLHAUS}/url/": {
                "query_status": "ok",
                "id": "SECTION-1",
                "url": "http://u.example/x",
            },
            THREATFOX: {
                "query_status": "ok",
                "data": [{"ioc": "SECTION-2.example", "malware": "m"}],
            },
        },
        id="url",
    ),
    pytest.param(
        "u.example",
        {
            f"{URLHAUS}/host/": {"query_status": "ok", "host": "SECTION-1.example"},
            THREATFOX: {
                "query_status": "ok",
                "data": [{"ioc": "SECTION-2.example", "malware": "m"}],
            },
        },
        id="host",
    ),
    pytest.param(
        SHA,
        {
            f"{URLHAUS}/payload/": {
                "query_status": "ok",
                "signature": "SECTION-1",
                "sha256_hash": SHA,
            },
            BAZAAR: {
                "query_status": "ok",
                "data": [{"sha256_hash": SHA, "signature": "SECTION-2"}],
            },
            THREATFOX: {
                "query_status": "ok",
                "data": [{"ioc": "SECTION-3.example", "malware": "m"}],
            },
        },
        id="hash",
    ),
    pytest.param(
        "sectionterm",
        {
            f"{URLHAUS}/tag/": {"query_status": "ok", "tag": "SECTION-1", "urls": []},
            THREATFOX: {
                "query_status": "ok",
                "data": [{"ioc": "SECTION-2.example", "malware": "m"}],
            },
            BAZAAR: {
                "query_status": "ok",
                "data": [{"sha256_hash": SHA, "signature": "SECTION-3"}],
            },
        },
        id="term",
    ),
]


@pytest.mark.parametrize(("indicator", "answers"), HUNT_SECTION_ORDER)
def test_hunt_prints_one_section_per_feed_in_request_order(rig, indicator, answers):
    for url, answer in answers.items():
        rig.fake.routes[url] = reply_json(answer)
    out = rig.cli("hunt", indicator).out
    markers = [f"SECTION-{number}" for number in range(1, len(answers) + 1)]
    positions = [out.index(marker) for marker in markers]
    assert positions == sorted(positions)
    assert len(rig.fake.seen) == len(answers)


def test_bazaar_rows_may_arrive_as_a_dict_and_are_wrapped(rig):
    rig.fake.default = reply_json(
        {"query_status": "ok", "data": {"signature": "Single", "sha256_hash": SHA}}
    )
    assert "Single" in rig.cli("bazaar").out


def test_bazaar_info_for_a_hash_shows_the_first_row_fields_intelligence_8_yara_rules_and_the_sample_page(
    rig,
):
    yara = [{"rule_name": f"RULE{i}"} for i in range(10)]
    yara[2] = {"rule_name": None, "rule": "ALT_RULE"}
    first = {
        "sha256_hash": SHA,
        "sha1_hash": "sha1-x",
        "md5_hash": "md5-x",
        "signature": "MoziSig",
        "file_type": "elf",
        "file_type_mime": "application/x-executable",
        "file_size": "5151",
        "first_seen": "2026-10-18 01:02:03",
        "last_seen": "2026-10-19 04:05:06",
        "delivery_method": "web_download",
        "origin_country": "CH",
        "reporter": "reporter-x",
        "tags": ["elf", "mozi"],
        "intelligence": {"downloads": "11", "uploads": "22", "clamav": "clam-x"},
        "yara_rules": yara,
    }
    rig.fake.routes[BAZAAR] = reply_json(
        {"query_status": "ok", "data": [first, {"signature": "SecondRowSig"}]}
    )
    out = rig.cli("hash", SHA).out
    for needle in (
        "sha1-x",
        "md5-x",
        "MoziSig",
        "application/x-executable",
        "5151",
        "2026-10-19 04:05:06",
        "web_download",
        "CH",
        "reporter-x",
        "#elf",
        "#mozi",
        "11",
        "22",
        "clam-x",
        "ALT_RULE",
        f"https://bazaar.abuse.ch/sample/{SHA}/",
    ):
        assert needle in out, needle
    assert "SecondRowSig" not in out
    assert {
        name for name in ("RULE0", "RULE1", "RULE3", "RULE4", "RULE5", "RULE6", "RULE7")
    } <= set(re.findall(r"RULE\d", out))
    assert "RULE8" not in out and "RULE9" not in out


def test_bazaar_info_reads_the_yara_key_when_yara_rules_is_absent(rig):
    rig.fake.routes[BAZAAR] = reply_json(
        {
            "query_status": "ok",
            "data": [{"sha256_hash": SHA, "yara": [{"rule": "Y_RULE"}]}],
        }
    )
    assert "Y_RULE" in rig.cli("hash", SHA).out


def threatfox_rows(count):
    return [
        {
            "confidence_level": 75,
            "malware": f"M{i:02d}",
            "ioc_type": "ip:port",
            "ioc": f"ioc-{i:02d}.example",
        }
        for i in range(count)
    ]


@pytest.mark.parametrize("argv", [["fox", "x"], ["iocs"]], ids=["fox", "iocs"])
def test_threatfox_list_shows_at_most_50_rows_with_their_fields(rig, argv):
    rig.fake.default = reply_json({"query_status": "ok", "data": threatfox_rows(60)})
    out = rig.cli(*argv).out
    assert shown_numbers(r"ioc-(\d\d)\.example", out) == set(range(50))
    assert "M00" in out and "ip:port" in out and "75%" in out.replace(" ", "")


def test_threatfox_row_fallbacks_and_dict_data(rig):
    rows = [
        {
            "malware": None,
            "malware_printable": "PrintMal",
            "ioc_type": None,
            "threat_type": "botnet_cc",
            "ioc": "fallback.example",
            "confidence_level": "abc",
        },
        {"ioc": "unknown.example"},
    ]
    rig.fake.default = reply_json({"query_status": "ok", "data": rows})
    out = rig.cli("fox", "x").out
    for needle in ("PrintMal", "botnet_cc", "fallback.example", "unknown.example", "?"):
        assert needle in out, needle
    assert (
        len(re.findall(r"(?<!\d)0%", out)) == 2
    )  # non-numeric and missing confidence both read as 0
    rig.fake.default = reply_json(
        {"query_status": "ok", "data": {"ioc": "single.example", "malware": "Solo"}}
    )
    assert "single.example" in rig.cli("fox", "x").out


def test_threatfox_requires_status_ok_while_bazaar_also_accepts_success(rig):
    rig.fake.default = reply_json(
        {"query_status": "success", "data": threatfox_rows(2)}
    )
    fox = rig.cli("fox", "x")
    assert "ioc-00.example" not in fox.out and "success" in fox.out and fox.rc == 0
    rig.fake.default = reply_json(
        {
            "query_status": "success",
            "data": [{"signature": "BazaarRow", "sha256_hash": SHA}],
        }
    )
    assert "BazaarRow" in rig.cli("bazaar").out


def test_threatfox_confidence_has_three_tiers_split_at_90_and_50(rig):
    rows = [
        {
            "confidence_level": level,
            "malware": "m",
            "ioc_type": "t",
            "ioc": f"ioc-{level:03d}.example",
        }
        for level in (100, 90, 89, 50, 49, 0)
    ]
    rig.fake.default = reply_json({"query_status": "ok", "data": rows})
    out = rig.cli("fox", "x", tty=True).out
    style = {}
    for level in (100, 90, 89, 50, 49, 0):
        line = next(
            line for line in out.splitlines() if f"ioc-{level:03d}.example" in line
        )
        match = re.search(rf"((?:\x1b\[[0-9;]*m)*)\s*{level}%", line)
        assert match, line
        style[level] = match.group(1)
    assert style[100] == style[90] != style[89] == style[50] != style[49] == style[0]
    assert style[90] != style[50] and style[90] != style[0] and style[50] != style[0]


def test_urlhaus_tag_and_signature_show_firstseen_url_count_and_at_most_30_urls(rig):
    rig.fake.routes[f"{URLHAUS}/tag/"] = reply_json(
        {
            "query_status": "ok",
            "tag": "mozi",
            "firstseen": "2026-02-03T04:05:06",
            "url_count": "35",
            "urls": [url_row(i) for i in range(1, 36)],
        }
    )
    out = rig.cli("tag", "mozi").out
    assert "mozi" in out and "35" in out and "2026-02-03" in out
    assert shown_numbers(r"http://r\.example/(\d+)", out) == set(range(1, 31))
    rig.fake.routes[f"{URLHAUS}/signature/"] = reply_json(
        {
            "query_status": "ok",
            "signature": "Emotet",
            "firstseen": "2026-02-03",
            "url_count": "35",
            "urls": [url_row(i) for i in range(1, 36)],
        }
    )
    out = rig.cli("family", "Emotet").out
    assert "Emotet" in out and shown_numbers(r"http://r\.example/(\d+)", out) == set(
        range(1, 31)
    )


def test_recent_payloads_show_at_most_the_limit_with_their_fields(rig):
    rows = [
        {
            "signature": f"Sig{i}",
            "file_type": "elf",
            "sha256_hash": f"{i:02x}" + "d" * 62,
            "firstseen": "2026-10-1%d" % i,
        }
        for i in range(8)
    ]
    rows[1].update(signature=None)
    rig.fake.default = reply_json({"query_status": "ok", "payloads": rows})
    out = rig.cli("-n", "5", "payloads").out
    assert shown_numbers(r"Sig(\d)", out) == {0, 2, 3, 4} and "unlabeled" in out
    assert (
        "01" + "d" * 16 in out
        and "01" + "d" * 17 not in out
        and "2026-10-14" in out
        and "2026-10-15" not in out
    )


def test_feodo_lists_non_comment_lines_with_the_count_and_stops_at_the_limit(rig):
    body = (
        "# generated\n\n"
        + "  10.0.0.1  \n"
        + "".join(f"10.0.0.{i}\n" for i in range(2, 61))
        + "#trailer\n"
    )
    rig.fake.routes[FEODO] = reply_text(body)
    out = rig.cli("-n", "3", "feodo").out
    assert (
        shown_numbers(r"10\.0\.0\.(\d+)", out) == {1, 2, 3}
        and re.search(r"\b57 more", out)
        and "60" in out
    )
    assert "generated" not in out and "trailer" not in out
    assert not re.search(r"\d+ more", rig.cli("-n", "100", "feodo").out)


def test_sslbl_lists_csv_rows_with_their_first_four_columns_and_stops_at_the_limit(rig):
    rows = [
        "# Listingdate,SHA1,Reason",
        "",
        '"2026-10-17","ab,cd","Reason, with comma",c4-1,c5-1,c6-1',
    ]
    rows += [f"2026-10-{i:02d},sha{i},reason{i},c4-{i},c5-{i}" for i in range(2, 6)]
    rig.fake.routes[SSLBL] = reply_text("\n".join(rows) + "\n")
    out = rig.cli("-n", "2", "sslbl").out
    for needle in (
        "2026-10-17",
        "ab,cd",
        "Reason, with comma",
        "c4-1",
        "2026-10-02",
        "sha2",
        "c4-2",
    ):
        assert needle in out, needle
    assert "c5-1" not in out and "sha3" not in out and "Listingdate" not in out
    assert re.search(r"\b3 more", out) and "5" in out


@pytest.mark.parametrize(
    ("argv", "answer", "needle"),
    [
        (["url", "http://nohit.example/"], {"query_status": "no_results"}, "no hit"),
        (["host", "nohit.example"], {"query_status": "no_results"}, "no hit"),
        (["url", "nohit"], {"query_status": "invalid_url"}, "invalid_url"),
        (["host", "nohit"], {"query_status": "invalid_host"}, "invalid_host"),
        (
            ["fox", "x"],
            {
                "query_status": "no_result",
                "data": "Your search did not yield any results",
            },
            "no_result",
        ),
        (["bazaar"], {"query_status": "no_selector"}, "no_selector"),
    ],
    ids=[
        "url-no-hit",
        "host-no-hit",
        "url-other-status",
        "host-other-status",
        "threatfox-status",
        "bazaar-status",
    ],
)
def test_no_hit_and_other_statuses_are_reported_without_failing(
    rig, argv, answer, needle
):
    rig.fake.default = reply_json(answer)
    result = rig.cli(*argv)
    assert result.rc == 0 and needle in result.out.lower()


def test_missing_fields_render_a_placeholder_never_none_in_the_host_payload_and_bazaar_views(
    rig,
):
    rig.fake.default = reply_json({"query_status": "ok", "host": "only.example"})
    assert "None" not in rig.cli("host", "only.example").out
    rig.fake.routes[f"{URLHAUS}/payload/"] = reply_json(
        {"query_status": "ok", "signature": None, "sha256_hash": SHA}
    )
    rig.fake.routes[BAZAAR] = reply_json(
        {"query_status": "ok", "data": [{"sha256_hash": SHA}]}
    )
    out = rig.cli("hash", SHA).out
    assert "None" not in out and "unlabeled" in out


def test_iso_timestamps_are_shown_as_date_time_utc(rig):
    rig.fake.default = reply_json(
        {
            "query_status": "ok",
            "url": "http://t.example/",
            "date_added": "2026-10-18T10:00:00",
            "last_online": "2026-10-19T11:12:13",
        }
    )
    out = rig.cli("url", "http://t.example/").out
    assert "2026-10-18 10:00:00 UTC" in out and "2026-10-19 11:12:13 UTC" in out


# ---------------------------------------------------------------------------------------------------------------
# --json and color (spec 6.1, 4.10)
# ---------------------------------------------------------------------------------------------------------------


def echo_docs(seen):
    return reply_json(
        {
            "query_status": "ok",
            "marker": f"doc-{seen.method}-{seen.url[-12:]}",
            "urls": [],
            "data": [],
            "payloads": [],
        }
    )


JSON_MODE_CASES = [
    pytest.param(["recent"], 1, id="recent"),
    pytest.param(["payloads"], 1, id="payloads"),
    pytest.param(["url", "http://x.example/"], 1, id="url"),
    pytest.param(["host", "x.example"], 1, id="host"),
    pytest.param(["hash", SHA], 3, id="hash-three-feeds"),
    pytest.param(["tag", "mozi"], 2, id="tag-two-feeds"),
    pytest.param(["family", "Mozi"], 3, id="family-three-feeds"),
    pytest.param(["iocs"], 1, id="iocs"),
    pytest.param(["fox", "x"], 1, id="fox"),
    pytest.param(["bazaar"], 1, id="bazaar"),
    pytest.param(["hunt", "http://x.example/"], 2, id="hunt-url"),
    pytest.param(["hunt", SHA], 3, id="hunt-hash"),
    pytest.param(["hunt", "x.example"], 2, id="hunt-host"),
    pytest.param(["hunt", "mozi"], 3, id="hunt-term"),
]


@pytest.mark.parametrize(("argv", "documents"), JSON_MODE_CASES)
def test_json_mode_prints_each_api_response_as_a_document_in_request_order(
    rig, argv, documents
):
    """Layout [K]: indent-2 documents starting in column 0, one per request, in request order (see D1 for the caveats)."""
    rig.fake.default = echo_docs
    result = rig.cli("--json", *argv)
    assert result.rc == 0, result.err
    assert len(rig.fake.seen) == documents
    expected = [json.loads(echo_docs(seen)[2]) for seen in rig.fake.seen]
    assert json_documents(result.out) == expected


def test_json_mode_rejects_text_feeds_before_requesting_them(rig):
    rig.fake.routes[FEODO] = reply_text("10.0.0.1\n10.0.0.2\n")
    result = rig.cli("--json", "feodo")
    assert result.rc == 2 and result.out == "" and rig.fake.seen == []
    assert "--json is not supported for feodo" in result.err


def test_color_is_emitted_only_for_a_tty_without_no_color_env_or_flag(rig, monkeypatch):
    rig.fake.default = reply_json({"query_status": "ok", "urls": [R1]})
    assert "\x1b[" not in rig.cli("recent").out  # not a TTY
    assert "\x1b[" in rig.cli("recent", tty=True).out
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b[" not in rig.cli("recent", tty=True).out
    monkeypatch.delenv("NO_COLOR")
    assert "\x1b[" not in rig.cli("--no-color", "recent", tty=True).out
