"""Characterization oracle (M2): the documented defects of the current scanner (spec section 10).

The rebuild must NOT silently bake a fix in or silently preserve a defect. Each defect therefore has TWO kinds
of test here, and they are deliberately distinguishable by name:

* ``test_CURRENT_<item>``   pins today's (wrong) behavior. A rebuild that preserves the defect passes it.
* ``test_CORRECT_<item>``   asserts the behavior a fixed scanner would have and is marked ``xfail``. It reports as
                            "xfailed" today. If a rebuild fixes the defect it reports "xpassed" and the paired
                            CURRENT test goes red, which is the signal that the orchestrator's decision (spec
                            section 10) has to be recorded: delete the CURRENT test and drop the xfail marker.

Where a defect is also pinned inside another file (because the pin is part of a larger scenario) the pointer is
in the table below. Items the spec tells the orchestrator to reproduce as-is have only a CURRENT test.

  item 4  TLS metadata is empty ........... CURRENT in test_scanner_e2e.py::test_https_scan_with_insecure_collects_tls_...
  item 5  --banners alone shows nothing ... CURRENT in test_scanner_e2e.py::test_banners_flag_alone_leaves_...
  item 6  denials look like live hits ..... CURRENT in test_scanner_units.py (scan_host denial) and test_report_writers.py
  item 2  implicit root path .............. FIXED by BH-3 (the M6 opt-out): a --paths-file without an explicit
                                            --paths no longer injects the host root. New behavior is pinned in
                                            test_scanner_planning.py::test_paths_file_drops_the_implicit_root_...

Concurrency starvation of the egress guard (found by the first CI run) has two halves; the false negative is
FIXED by PR-3, the loop stall itself is still OPEN.

  The guard (bughunt/core/egress.py: _reserve_async, _dispatch_lease_async, _pace_async) runs synchronous
  policy re-verification and ledger file writes on the event-loop thread, and queued probes busy-poll every
  10 ms, so under high --concurrency with many closed ports the loop stalls for longer than --connect-timeout.
  The old tcp_probe used asyncio.wait_for, whose timer then cancelled probes whose TCP handshake had ALREADY
  completed but still needed a few call_soon hops to build the connection object, reporting an OPEN port as a
  timeout: a silent false negative in a recon tool. The CI triage reproduced it on a Windows dev box (10 open
  + 60 closed ports at --concurrency 256 --connect-timeout 1.2 lost 4-5 of the 10 open ports; --concurrency 8
  found all 10).

  FIXED (PR-3, scanner-only): tcp_probe now uses a bounded-yield wait (scanner._LOOP_GRACE_ITERATIONS) that
  lets the connection object finish building before concluding a timeout. The change sits entirely below the
  egress gate -- no egress/policy call added, removed or reordered. The regression is pinned deterministically
  (host-speed-independent, so the earlier "cannot be made deterministic across platforms" no longer holds) in
  test_scanner_units.py::test_tcp_probe_does_not_report_a_connected_port_as_timeout_after_a_loop_stall,
  parametrized over the proactor and selector event loops so the windows and ubuntu CI legs both gate it; the
  prior "Linux behavior at scale is UNVERIFIED" note is thereby superseded for the false negative -- the ubuntu
  leg exercises the real selector/epoll loop. Out-of-tree acceptance (scratchpad bucket6, not a CI test,
  host-speed dependent): --concurrency 256 --connect-timeout 1.2 now finds 10/10 open ports (was 0/10).

  STILL OPEN (perf; a SEPARATE security-reviewed hardening ticket that DOES touch egress.py): the ~9 s loop
  stall itself. PR-3 only stops it from being misread as closed ports. The hardening pass (digest-keyed
  read_document parse reuse + clamping the scanner fan-in to the policy concurrency) must keep the per-request
  TOCTOU re-checks ("policy-changed-before-dispatch", "actor-changed-*") intact, with a mutation proof that
  disabling one turns the policy tests red. Interim mitigation for a very large policy on a slow host: lower
  --concurrency. test_scanner_e2e.py::keystone still uses a generous --connect-timeout so CI does not depend on
  that residual stall.
"""

from __future__ import annotations

import json
import re
import socket

import pytest

from bughunt.core import egress, scanner
from scanner_oracle_support import (  # noqa: F401  (fixtures are consumed by name)
    csv_rows_for,
    grant,
    lab,
    make_hit,
    make_self_signed_certificate,
    run_cli,
    squash,
    workspace,
    LabServer,
)
from test_scanner_planning import paths_of, scoped  # noqa: F401  (scoped is a fixture)

# Item 7 --------------------------------------------------------------------------------------------------------


def _params_file_urls(scoped, tmp_path):
    names = tmp_path / "names.txt"
    names.write_text("zzfile\n", encoding="utf-8")
    return paths_of("--paths", "/api", "--params", "--params-file", str(names))


def test_params_file_names_extend_the_builtin_plan(scoped, tmp_path):
    result = _params_file_urls(scoped, tmp_path)
    assert result[0] == "/api" and len(result) == 14
    assert result[-1] == "/api?zzfile=1"


def test_CORRECT_params_file_names_are_probed(scoped, tmp_path):
    assert "/api?zzfile=1" in _params_file_urls(scoped, tmp_path)


# Item 8 --------------------------------------------------------------------------------------------------------


def _scan_args(lab, *extra):
    return [
        "127.0.0.1",
        "--ports",
        str(lab.port),
        "--http-only",
        "--quiet",
        "--concurrency",
        "4",
        *extra,
    ]


def test_CORRECT_invalid_status_filter_is_exit_two_with_a_message(lab):
    code, output = run_cli(_scan_args(lab, "--status", "abc"))
    assert code == 2 and output.strip()
    assert lab.requests == []


def test_CORRECT_invalid_grep_regex_is_exit_two_with_a_message(lab):
    code, output = run_cli(_scan_args(lab, "--grep", "("))
    assert code == 2 and output.strip()
    assert lab.requests == []


def test_json_parent_creation_also_preserves_later_csv_export(lab, tmp_path):
    target = tmp_path / "does" / "not" / "exist" / "report.json"
    csv_target = tmp_path / "later.csv"
    code, _ = run_cli(_scan_args(lab, "--json", str(target), "--csv", str(csv_target)))
    assert code == 0 and target.exists() and csv_target.exists()
    assert lab.requests  # the whole scan had already happened


def test_CORRECT_json_report_creates_its_parent_directory(lab, tmp_path):
    target = tmp_path / "does" / "not" / "exist" / "report.json"
    code, _ = run_cli(_scan_args(lab, "--json", str(target)))
    assert (
        code == 0
        and json.loads(target.read_text(encoding="utf-8"))["tool"] == "Bughunt"
    )


def test_policy_block_after_preflight_returns_exit_two_and_closes_artifacts(
    lab, monkeypatch, tmp_path
):
    def blocked(_target):
        raise egress.PolicyBlocked("late block; no outbound action ran")

    monkeypatch.setattr(scanner, "resolve_host", blocked)
    urls = tmp_path / "urls.txt"
    code, output = run_cli(_scan_args(lab, "--save-urls", str(urls)))
    assert code == 2 and "late block; no outbound action ran" in output
    assert lab.requests == []
    urls.unlink()


# Item 9 --------------------------------------------------------------------------------------------------------


def test_CORRECT_a_bare_ipv6_target_is_planned(scoped):
    code, output = run_cli(
        ["::1", "--ports", "80", "--http-only", "--dry-run", "--quiet"]
    )
    assert [row["target"] for row in json.loads(output)] == ["http://[::1]:80/"]


def _ipv6_hit(workspace, monkeypatch, tmp_path):
    document = grant(workspace, http=[1])
    document["assets"] = [
        {
            "id": "v6",
            "origin": "http://[::1]",
            "paths": ["/"],
            "operations": list(document["permissions"]),
            "methods": ["GET", "HEAD", "POST", "OPTIONS", "CONNECT"],
        }
    ]
    (workspace / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    real = socket.getaddrinfo

    def resolver(host, *args, **kwargs):
        if host == "::1":
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0))]
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    out = tmp_path / "v6.json"
    code, _ = run_cli(
        [
            "[::1]",
            "--ports",
            "80",
            "--http-only",
            "--skip-tcp",
            "--quiet",
            "--json",
            str(out),
        ]
    )
    assert code == 0
    (hit,) = json.loads(out.read_text(encoding="utf-8"))["hosts"][0]["ports"][0]["hits"]
    return hit


def test_CORRECT_ipv6_request_urls_are_bracketed(workspace, monkeypatch, tmp_path):
    assert _ipv6_hit(workspace, monkeypatch, tmp_path)["url"] == "http://[::1]:80/"


# Item 6 --------------------------------------------------------------------------------------------------------


def test_CORRECT_a_policy_denied_request_is_not_reported_as_live(lab, tmp_path):
    import asyncio

    grant(
        lab.workspace,
        http=[lab.port],
        exclusions=[(f"http://127.0.0.1:{lab.port}", ["/private"])],
    )
    (result,) = asyncio.run(
        scanner.scan_host(
            target="127.0.0.1",
            ports=[lab.port],
            connect_timeout=0.4,
            http_timeout=3.0,
            concurrency=4,
            paths=["/private"],
            follow_redirects=False,
            try_http=True,
            try_https=False,
            verify_tls=True,
            user_agents=[],
            rotate_agent=False,
            host_header=None,
            custom_headers={},
            collect_certs=False,
            keep_body=False,
            max_body=1024,
            delay_lo=0,
            delay_hi=0,
            proxy=None,
            sink=None,
            status_allow=None,
            grep=None,
            skip_tcp=False,
            method="GET",
            retries=0,
            auth=None,
        )
    )
    assert csv_rows_for(tmp_path, *result.hits, port=lab.port) == []


# Item 5 --------------------------------------------------------------------------------------------------------


def test_CORRECT_banners_flag_alone_reports_banners(workspace, tmp_path):
    from scanner_oracle_support import RawServer

    server = RawServer(banner=b"SSH-2.0-lab\r\n")
    try:
        grant(workspace, http=[server.port])
        out = tmp_path / "b.json"
        run_cli(
            [
                "127.0.0.1",
                "--ports",
                str(server.port),
                "--http-only",
                "--quiet",
                "--connect-timeout",
                "1",
                "--banners",
                "--json",
                str(out),
            ]
        )
        assert json.loads(out.read_text(encoding="utf-8"))["hosts"][0]["banners"] == [
            f"{server.port}/tcp SSH-2.0-lab"
        ]
    finally:
        server.close()


# Item 4 --------------------------------------------------------------------------------------------------------


def test_tls_metadata_decodes_an_unverified_peer_certificate(workspace, monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from test_oracle_mod_g1_recon import real_certificate_der

    grant(workspace, https=[8443])
    peer = SimpleNamespace(
        cipher=lambda: ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        version=lambda: "TLSv1.3",
        getpeercert=lambda binary_form=False: (
            real_certificate_der() if binary_form else {}
        ),
    )
    context = SimpleNamespace(wrap_socket=lambda *args, **kwargs: nullcontext(peer))
    monkeypatch.setattr(scanner.ssl, "SSLContext", lambda *args: context)
    monkeypatch.setattr(
        scanner.socket,
        "create_connection",
        lambda *args, **kwargs: nullcontext(object()),
    )

    result = scanner.collect_tls_info("127.0.0.1", 8443, 1)

    assert result.error == ""
    assert "CN=oracle.allowed.example" in result.subject
    assert result.issuer == result.subject
    assert result.not_after == "2036-10-16 22:41:12Z"
    assert "IP:2001:db8::1" in result.san


def test_CORRECT_tls_metadata_includes_the_certificate_subject(workspace, tmp_path):
    material = make_self_signed_certificate(tmp_path)
    if material is None:
        pytest.skip("openssl CLI not available to mint a throwaway certificate")
    server = LabServer(tls=material)
    try:
        grant(workspace, https=[server.port])
        out = tmp_path / "tls.json"
        run_cli(
            [
                "127.0.0.1",
                "--ports",
                str(server.port),
                "--https-only",
                "--insecure",
                "--quiet",
                "--connect-timeout",
                "2",
                "--http-timeout",
                "5",
                "--json",
                str(out),
            ]
        )
        tls = json.loads(out.read_text(encoding="utf-8"))["hosts"][0]["ports"][0][
            "hits"
        ][0]["tls"]
        assert "127.0.0.1" in tls["subject"] and tls["not_after"]
    finally:
        server.close()


# Item 13 -------------------------------------------------------------------------------------------------------


def _cookie_findings(lab, tmp_path):
    out = tmp_path / "cookie.json"
    code, _ = run_cli(
        _scan_args(lab, "--score-headers", "--paths", "/cookies", "--json", str(out))
    )
    assert code == 0
    return [
        item["title"]
        for item in json.loads(out.read_text(encoding="utf-8"))["hosts"][0]["findings"]
    ]


def test_CORRECT_cookie_flags_are_read_from_attributes_not_the_name(lab, tmp_path):
    titles = _cookie_findings(lab, tmp_path)
    assert "Cookie 'secure_httponly_samesite' missing HttpOnly" in titles
    assert "Cookie 'secure_httponly_samesite' missing SameSite" in titles
