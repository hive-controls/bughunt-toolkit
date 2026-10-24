"""Target-behavior acceptance oracle for the clean-room `skiff` rebuild (m2-skiff-spec.md).

skiff is a request-position fuzzer: it substitutes the placeholder FUZZ (in a URL, raw request
file, header, cookie or body) with entries from a USER-SUPPLIED wordlist file and sends each
resulting request. It ships no wordlist or attack-payload content of its own, and neither does
this test file -- every "payload" used below is a harmless placeholder word (digits, "zzz", short
tokens), never anything dual-use.

Written BEFORE the implementation existed (TDD): this file states the target behavior the
clean-room build must satisfy, built entirely from the spec -- never from the old skiff.py.

Network posture: NO real network call is made. Every URL is served by `httpx.MockTransport` at
the egress edge, and an autouse tripwire makes DNS and TCP connects raise.

Scope, in the spec's own words:
  * every request (including each redirect hop) routes through
    bughunt.core.egress.async_client(operation="fuzz")
  * per-request and per-hop scope/policy enforcement is automatic (egress's transport), and a
    mutation that skips it or loosens the policy's own rate must make the matching test go red
  * FUZZ substitution across the URL, headers, cookies and body, from a user wordlist
  * response filters: status / size / words / lines / regex / header
  * the typed JSON result envelope, outcomes referencing payloads by index/hash only
  * exit codes
  * re-enable: skiff is no longer in DISABLED_REFERENCES and has a live catalog form
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from bughunt.console import catalog, loader
from bughunt.console.catalog_export import export_catalog
from bughunt.core import egress, scanner
from test_gate import seed_policy

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "addons" / "skiff" / "skiff.py"

BASE = "https://allowed.example"


def u(path: str = "/") -> str:
    return BASE + path


# ---------------------------------------------------------------------------------------------
# Workspace (scope + policy) and the network-edge harness -- same shape as the other m2 oracles
# ---------------------------------------------------------------------------------------------


def build_workspace(path: Path, *, scope=("allowed.example",), policy=True, restrict=None,
                    limits=None, deny=()) -> dict:
    path.mkdir(parents=True, exist_ok=True)
    for stale in ("scope.txt", "policy.json"):
        (path / stale).unlink(missing_ok=True)
    document = seed_policy(path)
    for row in document["assets"]:
        if row["origin"] in (restrict or {}):
            row["operations"] = list(restrict[row["origin"]])
    for operation in deny:
        document["permissions"][operation] = False
    if limits is not None:
        document["limits"] = limits
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    if not policy:
        (path / "policy.json").unlink()
    if scope is not None:
        (path / "scope.txt").write_text("\n".join(scope) + "\n", encoding="utf-8")
    return document


class Wire:
    """Mock network edge. `routes`: url -> (status, body, headers); `handler` takes precedence."""

    def __init__(self, routes=None, *, default=None, handler=None, delay=0.0):
        self.routes, self.default, self.handler = dict(routes or {}), default, handler
        self.delay = delay
        self.requests: list[httpx.Request] = []
        self.in_flight = self.peak = 0

    @property
    def urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._respond)

    async def _respond(self, request):
        self.requests.append(request)
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.handler is not None:
                outcome = self.handler(request)
            else:
                outcome = self.routes.get(str(request.url), self.default)
        finally:
            self.in_flight -= 1
        if outcome is None:
            raise httpx.ConnectError("no route " + str(request.url), request=request)
        if isinstance(outcome, BaseException):
            raise outcome
        status, body, headers = outcome
        return httpx.Response(status, content=body, headers=headers or {}, request=request)


@dataclass
class Run:
    code: int
    out: str
    err: str


class World:
    def __init__(self, skiff, monkeypatch, tmp_path, capsys):
        self.skiff, self.mp, self.tmp, self.capsys = skiff, monkeypatch, tmp_path, capsys
        self.scope_dir = tmp_path / "scope"
        self.client_kwargs: list[dict] = []
        self.wire = Wire()
        monkeypatch.setenv("BUGHUNT_SCOPE", str(self.scope_dir))
        monkeypatch.setenv("COLUMNS", "250")
        self.workspace()

    def workspace(self, **options) -> dict:
        return build_workspace(self.scope_dir, **options)

    def serve(self, routes=None, **wire_options) -> Wire:
        self.wire = wire = Wire(routes, **wire_options)
        real_async_client = egress.async_client

        def guarded_over_mock(**kwargs):
            self.client_kwargs.append(dict(kwargs))
            kwargs["transport"] = wire.transport()
            return real_async_client(**kwargs)

        self.mp.setattr(egress, "async_client", guarded_over_mock)
        return wire

    def wordlist(self, *lines: str, name: str = "wl.txt") -> str:
        path = self.tmp / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)

    def run(self, *argv: str) -> Run:
        self.mp.setattr(sys, "argv", ["bughunt skiff", *argv])
        code = 0
        try:
            self.skiff.main()
        except SystemExit as exc:
            code = 0 if exc.code is None else exc.code
        out, err = self.capsys.readouterr()
        return Run(code, out, err)

    def run_main(self, *argv: str) -> tuple[Run, dict | None]:
        args = self.skiff.build_parser().parse_args(argv)
        code = self.skiff.run_main(args)
        out, err = self.capsys.readouterr()
        return Run(code, out, err), None

    def read_json(self, path) -> dict:
        return json.loads(Path(path).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def addons_root(tmp_path_factory):
    root = tmp_path_factory.mktemp("skiff-addons")
    (root / "skiff").mkdir()
    import shutil
    shutil.copyfile(SCRIPT, root / "skiff" / "skiff.py")
    return root


@pytest.fixture(scope="session")
def skiff(addons_root):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("COLUMNS", "250")
        return loader.import_script(addons_root / "skiff" / "skiff.py")


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("real network reached from a skiff characterization test")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture(autouse=True)
def scratch_scope(monkeypatch, tmp_path):
    monkeypatch.setenv("COLUMNS", "250")
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "default-scope"))
    build_workspace(tmp_path / "default-scope")


@pytest.fixture
def world(skiff, monkeypatch, tmp_path, capsys):
    return World(skiff, monkeypatch, tmp_path, capsys)


def policy_denial(url: str, method: str = "GET") -> str:
    verdict = egress.dry_run(url, "fuzz", method)
    assert verdict["permitted"] is False
    return f"{verdict['reason']}; no outbound action ran"


# ---------------------------------------------------------------------------------------------
# A. Target parsing, FUZZ positions, substitution
# ---------------------------------------------------------------------------------------------


def test_url_fuzz_is_located_and_substituted(skiff):
    target = skiff.Target("GET", u("/item?id=FUZZ"))
    positions = skiff.locate_positions(target)
    assert positions == [skiff.Position("url")]
    assigned = skiff.substitute(target, {skiff.Position("url"): "7"})
    assert assigned.url == u("/item?id=7")


def test_header_and_cookie_and_body_fuzz_positions_are_each_found(skiff):
    target = skiff.Target("POST", u("/"), headers=[("X-Id", "FUZZ"), ("X-Plain", "no-token-here")],
                          cookies=[("session", "FUZZ"), ("other", "static")], body="name=FUZZ")
    positions = set(skiff.locate_positions(target))
    assert positions == {skiff.Position("header", "X-Id"), skiff.Position("cookie", "session"),
                         skiff.Position("body")}


def test_no_fuzz_anywhere_means_no_positions(skiff):
    target = skiff.Target("GET", u("/plain"), headers=[("X-Id", "7")], cookies=[("a", "b")], body="x=1")
    assert skiff.locate_positions(target) == []


def test_multiple_fuzz_occurrences_in_one_field_get_the_same_payload(skiff):
    target = skiff.Target("GET", u("/FUZZ/again/FUZZ"))
    substituted = skiff.substitute(target, {skiff.Position("url"): "9"})
    assert substituted.url == u("/9/again/9")


def test_substitution_leaves_fields_without_fuzz_untouched(skiff):
    target = skiff.Target("GET", u("/x"), headers=[("X-Id", "FUZZ")], cookies=[("a", "static")], body="")
    substituted = skiff.substitute(target, {skiff.Position("header", "X-Id"): "payload"})
    assert substituted.url == u("/x")
    assert substituted.cookies == [("a", "static")]


def test_build_target_from_args_requires_exactly_one_of_url_or_request_file(skiff):
    class Args:
        url = None
        request_file = None
        header = []
        cookie = []
        data = None
    with pytest.raises(skiff.TargetError):
        skiff.build_target_from_args(Args())
    Args.url = u("/x")
    Args.request_file = "req.txt"
    with pytest.raises(skiff.TargetError):
        skiff.build_target_from_args(Args())


def test_build_target_from_url_merges_cli_headers_and_cookies(skiff):
    class Args:
        url = u("/FUZZ")
        request_file = None
        method = "get"
        header = ["X-Id: FUZZ", "X-Plain: 1"]
        cookie = ["sess=FUZZ"]
        data = None
    target = skiff.build_target_from_args(Args())
    assert target.method == "GET"
    assert target.headers == [("X-Id", "FUZZ"), ("X-Plain", "1")]
    assert target.cookies == [("sess", "FUZZ")]


def test_malformed_header_or_cookie_argument_is_a_target_error(skiff):
    with pytest.raises(skiff.TargetError):
        skiff.parse_header_argument("no-colon-here")
    with pytest.raises(skiff.TargetError):
        skiff.parse_cookie_argument("no-equals-here")


RAW_REQUEST = (
    "GET /path/FUZZ HTTP/1.1\n"
    "Host: allowed.example\n"
    "X-Token: FUZZ\n"
    "Cookie: a=1; b=FUZZ\n"
    "\n"
)


def test_raw_request_file_is_parsed_into_a_target(skiff):
    target = skiff.parse_raw_request(RAW_REQUEST, scheme="https")
    assert target.method == "GET"
    assert target.url == "https://allowed.example/path/FUZZ"
    assert target.headers == [("X-Token", "FUZZ")]
    assert target.cookies == [("a", "1"), ("b", "FUZZ")]
    assert target.body == ""


def test_raw_request_with_a_body_keeps_it_verbatim(skiff):
    raw = "POST /submit HTTP/1.1\nHost: allowed.example\n\nfield=FUZZ"
    target = skiff.parse_raw_request(raw, scheme="https")
    assert target.method == "POST" and target.body == "field=FUZZ"


def test_raw_request_without_a_host_header_is_rejected(skiff):
    with pytest.raises(skiff.TargetError):
        skiff.parse_raw_request("GET /x HTTP/1.1\n\n", scheme="https")


def test_raw_request_with_an_absolute_path_in_the_start_line_uses_it_directly(skiff):
    raw = "GET https://other.example/x?id=FUZZ HTTP/1.1\nHost: allowed.example\n\n"
    target = skiff.parse_raw_request(raw, scheme="https")
    assert target.url == "https://other.example/x?id=FUZZ"


# ---------------------------------------------------------------------------------------------
# B. Wordlist loading and payload construction (spec 1: case/affix/encoding variants)
# ---------------------------------------------------------------------------------------------


def test_wordlist_is_deduplicated_and_comments_and_blanks_are_dropped_by_default(skiff, tmp_path):
    path = tmp_path / "wl.txt"
    path.write_text("one\n# a comment\n\ntwo\none\n  \nthree\n", encoding="utf-8")
    words = skiff.load_wordlist(str(path), dedup=True, keep_comments=False)
    assert words == ["one", "two", "three"]


def test_no_dedup_and_keep_comments_flags_are_honored(skiff, tmp_path):
    path = tmp_path / "wl.txt"
    path.write_text("one\n# kept\none\n", encoding="utf-8")
    assert skiff.load_wordlist(str(path), dedup=False, keep_comments=True) == ["one", "# kept", "one"]


def test_wordlist_dash_reads_stdin(skiff, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("alpha\nbeta\n"))
    assert skiff.load_wordlist("-", dedup=True, keep_comments=False) == ["alpha", "beta"]


def test_missing_wordlist_file_raises_target_error(skiff, tmp_path):
    with pytest.raises(skiff.TargetError):
        skiff.load_wordlist(str(tmp_path / "nope.txt"), dedup=True, keep_comments=False)


def test_transform_prefix_suffix_and_default_url_encoding(skiff):
    payload = skiff.build_payload("ab c", transform="upper", prefix="p-", suffix="-s", encoding="url")
    assert payload == "p-AB%20C-s"


def test_transform_lower_and_no_encoding(skiff):
    assert skiff.build_payload("ABC", transform="lower", prefix="", suffix="", encoding="none") == "abc"


def test_base64_encoding_mode(skiff):
    import base64
    payload = skiff.build_payload("abc", transform="none", prefix="", suffix="", encoding="base64")
    assert base64.b64decode(payload) == b"abc"


def test_extensions_append_payload_variants_without_dropping_the_bare_word(skiff):
    expanded = skiff.apply_extensions(["one", "two"], ["bak", ".php"])
    assert expanded == ["one", "two", "one.bak", "one.php", "two.bak", "two.php"]


def test_no_extensions_leaves_the_wordlist_unchanged(skiff):
    assert skiff.apply_extensions(["one"], []) == ["one"]


def test_randomize_uses_the_seed_deterministically(skiff):
    payloads = ["1", "2", "3", "4", "5"]
    first = skiff.order_payloads(payloads, randomize=True, seed=42)
    second = skiff.order_payloads(payloads, randomize=True, seed=42)
    assert first == second
    assert sorted(first) == sorted(payloads)


def test_without_randomize_the_order_is_unchanged(skiff):
    payloads = ["1", "2", "3"]
    assert skiff.order_payloads(payloads, randomize=False, seed=None) is payloads


# ---------------------------------------------------------------------------------------------
# C. Request planning across one or more FUZZ positions (spec 3: --multi-fuzz)
# ---------------------------------------------------------------------------------------------


def test_single_position_plans_one_request_per_payload(skiff):
    combos = list(skiff.plan_index_tuples(1, 3, "same"))
    assert combos == [(0,), (1,), (2,)]


def test_same_mode_shares_one_index_across_every_position(skiff):
    combos = list(skiff.plan_index_tuples(3, 2, "same"))
    assert combos == [(0, 0, 0), (1, 1, 1)]


def test_combo_mode_is_the_full_cartesian_product(skiff):
    combos = list(skiff.plan_index_tuples(2, 2, "combo"))
    assert combos == [(0, 0), (0, 1), (1, 0), (1, 1)]


def test_combo_mode_with_a_single_position_behaves_like_same(skiff):
    assert list(skiff.plan_index_tuples(1, 3, "combo")) == [(0,), (1,), (2,)]


def test_zero_positions_or_zero_payloads_plans_nothing(skiff):
    assert list(skiff.plan_index_tuples(0, 5, "same")) == []
    assert list(skiff.plan_index_tuples(2, 0, "combo")) == []


# ---------------------------------------------------------------------------------------------
# D. payload_ref: index/hash only, never the raw payload string (spec 4)
# ---------------------------------------------------------------------------------------------


def test_payload_ref_carries_the_index_and_a_hash_not_the_raw_text(skiff):
    ref = skiff.payload_ref_for(3, "url:=super-secret-payload-text")
    assert ref.startswith("3:")
    assert "super-secret-payload-text" not in ref
    digest_part = ref.split(":", 1)[1]
    assert len(digest_part) == 12 and all(c in "0123456789abcdef" for c in digest_part)


def test_payload_ref_is_stable_for_the_same_index_and_text(skiff):
    assert skiff.payload_ref_for(1, "same") == skiff.payload_ref_for(1, "same")


def test_assignment_ref_text_orders_positions_deterministically(skiff):
    a = {skiff.Position("header", "B"): "2", skiff.Position("header", "A"): "1"}
    assert skiff.assignment_ref_text(a) == "header:A=1|header:B=2"


# ---------------------------------------------------------------------------------------------
# E. Response filters: status/size/words/lines/regex/header (spec 1) and auto-calibration
# ---------------------------------------------------------------------------------------------


def test_parse_ranges_reads_commas_and_dash_ranges(skiff):
    assert skiff.parse_ranges("200,301-303,404") == frozenset({200, 301, 302, 303, 404})
    assert skiff.parse_ranges(None) is None
    assert skiff.parse_ranges("") is None


def make_filters(skiff, **overrides):
    class Args:
        match_code = overrides.get("match_code")
        filter_code = overrides.get("filter_code")
        match_size = overrides.get("match_size")
        filter_size = overrides.get("filter_size")
        match_words = overrides.get("match_words")
        filter_words = overrides.get("filter_words")
        match_lines = overrides.get("match_lines")
        filter_lines = overrides.get("filter_lines")
        match_regex = overrides.get("match_regex")
        filter_regex = overrides.get("filter_regex")
        match_header = overrides.get("match_header")
    return skiff.build_filters(Args())


def test_no_filters_means_every_outcome_is_a_hit(skiff):
    filters = make_filters(skiff)
    result = skiff.classify(status=404, size=0, words=0, lines=0, body_text="", headers={},
                            filters=filters, noise_signature=None, signature=(404, 0))
    assert result == "hit"


def test_match_code_keeps_only_the_listed_statuses(skiff):
    filters = make_filters(skiff, match_code="200,201")
    hit = skiff.classify(status=200, size=1, words=1, lines=1, body_text="x", headers={},
                         filters=filters, noise_signature=None, signature=(200, 1))
    miss = skiff.classify(status=404, size=1, words=1, lines=1, body_text="x", headers={},
                          filters=filters, noise_signature=None, signature=(404, 1))
    assert hit == "hit" and miss == "filtered"


def test_filter_code_drops_the_listed_statuses(skiff):
    filters = make_filters(skiff, filter_code="404,500")
    kept = skiff.classify(status=200, size=1, words=1, lines=1, body_text="x", headers={},
                          filters=filters, noise_signature=None, signature=(200, 1))
    dropped = skiff.classify(status=404, size=1, words=1, lines=1, body_text="x", headers={},
                             filters=filters, noise_signature=None, signature=(404, 1))
    assert kept == "hit" and dropped == "filtered"


def test_match_criteria_combine_with_and_semantics(skiff):
    filters = make_filters(skiff, match_code="200", match_words="5")
    both = skiff.classify(status=200, size=1, words=5, lines=1, body_text="x", headers={},
                          filters=filters, noise_signature=None, signature=(200, 1))
    only_one = skiff.classify(status=200, size=1, words=9, lines=1, body_text="x", headers={},
                              filters=filters, noise_signature=None, signature=(200, 1))
    assert both == "hit" and only_one == "filtered"


def test_match_regex_and_filter_regex_check_the_body_text(skiff):
    match_filters = make_filters(skiff, match_regex="wel+come")
    assert skiff.classify(status=200, size=1, words=1, lines=1, body_text="welcome home", headers={},
                          filters=match_filters, noise_signature=None, signature=(200, 1)) == "hit"
    assert skiff.classify(status=200, size=1, words=1, lines=1, body_text="nope", headers={},
                          filters=match_filters, noise_signature=None, signature=(200, 1)) == "filtered"
    drop_filters = make_filters(skiff, filter_regex="error")
    assert skiff.classify(status=200, size=1, words=1, lines=1, body_text="internal error", headers={},
                          filters=drop_filters, noise_signature=None, signature=(200, 1)) == "filtered"


def test_match_header_checks_one_named_header_against_a_regex(skiff):
    filters = make_filters(skiff, match_header="X-Flag:^yes$")
    hit = skiff.classify(status=200, size=1, words=1, lines=1, body_text="", headers={"X-Flag": "yes"},
                         filters=filters, noise_signature=None, signature=(200, 1))
    miss = skiff.classify(status=200, size=1, words=1, lines=1, body_text="", headers={"X-Flag": "no"},
                          filters=filters, noise_signature=None, signature=(200, 1))
    assert hit == "hit" and miss == "filtered"


def test_match_header_without_a_colon_is_a_target_error(skiff):
    with pytest.raises(skiff.TargetError):
        make_filters(skiff, match_header="no-colon")


def test_noise_signature_from_auto_calibrate_is_filtered_out(skiff):
    filters = make_filters(skiff)
    result = skiff.classify(status=404, size=120, words=3, lines=1, body_text="not found", headers={},
                            filters=filters, noise_signature=(404, 120), signature=(404, 120))
    assert result == "filtered"


def test_size_words_lines_filters_use_the_same_range_syntax(skiff):
    filters = make_filters(skiff, match_size="100-200", match_words="1-5", match_lines="1")
    ok = skiff.classify(status=200, size=150, words=3, lines=1, body_text="x", headers={},
                        filters=filters, noise_signature=None, signature=(200, 150))
    bad = skiff.classify(status=200, size=999, words=3, lines=1, body_text="x", headers={},
                         filters=filters, noise_signature=None, signature=(200, 999))
    assert ok == "hit" and bad == "filtered"


# ---------------------------------------------------------------------------------------------
# F. Pacing: policy is a ceiling; skiff's own flags may only tighten it (mutation-proof unit tests)
# ---------------------------------------------------------------------------------------------


class _FakeProfile:
    def __init__(self, concurrency, rps):
        self.concurrency, self.requests_per_second = concurrency, rps


class _Args:
    def __init__(self, threads=10, rps=None, delay=0.0):
        self.threads, self.rps, self.delay = threads, rps, delay


def test_effective_concurrency_is_the_minimum_of_policy_and_flag(skiff):
    tight_policy = skiff.effective_limits(_FakeProfile(2, 1000), _Args(threads=999))
    tight_flag = skiff.effective_limits(_FakeProfile(999, 1000), _Args(threads=2))
    assert tight_policy[0] == 2
    assert tight_flag[0] == 2


def test_effective_rate_never_exceeds_the_policys_own_rate(skiff):
    concurrency, min_interval = skiff.effective_limits(_FakeProfile(10, 2), _Args(rps=1000))
    assert min_interval >= 1.0 / 2


def test_a_tighter_requested_rps_is_honored(skiff):
    concurrency, min_interval = skiff.effective_limits(_FakeProfile(10, 1000), _Args(rps=4))
    assert min_interval == pytest.approx(1.0 / 4)


def test_delay_flag_adds_a_floor_even_under_a_fast_policy(skiff):
    concurrency, min_interval = skiff.effective_limits(_FakeProfile(10, 1000), _Args(delay=0.25))
    assert min_interval >= 0.25


def test_mutation_proof_max_instead_of_min_would_loosen_the_policy_cap(skiff):
    """Demonstrates the test above is sensitive to the exact gate-not-weakened invariant: a
    deliberately loosened (max()) version of the policy/flag combine would produce a LARGER
    concurrency and a SMALLER min_interval than the policy allows, which the two tests above
    would catch (they assert the policy-tight values, not the flag's looser ones)."""
    loosened_concurrency = max(2, 999)  # what a "loosen" mutant would compute instead of min()
    real_concurrency, _ = skiff.effective_limits(_FakeProfile(2, 1000), _Args(threads=999))
    assert real_concurrency != loosened_concurrency
    assert real_concurrency == 2


# ---------------------------------------------------------------------------------------------
# G. Egress integration: operation "fuzz", automatic per-request and per-hop enforcement
# ---------------------------------------------------------------------------------------------


def test_build_client_routes_through_egress_with_operation_fuzz(world):
    world.serve({u("/FUZZ"): (200, b"ok", {})})

    class Args:
        timeout = 5.0
        user_agent = "UA/1"
        proxy = None
        follow_redirects = False

    asyncio.run(_use_client(world.skiff, Args()))
    assert len(world.client_kwargs) == 1
    assert world.client_kwargs[0]["operation"] == "fuzz"
    assert world.client_kwargs[0]["trust_env"] is False


async def _use_client(skiff, args):
    async with skiff.build_client(args, True) as client:
        pass


def test_a_full_run_only_ever_builds_fuzz_operation_clients(world):
    world.serve({u(f"/{i}"): (200, b"ok", {}) for i in range(3)})
    path = world.wordlist("0", "1", "2")
    run = world.run("-u", u("/FUZZ"), "-w", path, "-r" if False else "--timeout", "5")
    assert run.code in (0, 1)
    assert world.client_kwargs and all(k["operation"] == "fuzz" for k in world.client_kwargs)


def test_out_of_scope_target_is_never_contacted_and_exits_two(world):
    wire = world.serve({"https://outside.example/FUZZ": (200, b"ok", {})})
    path = world.wordlist("a")
    run = world.run("-u", "https://outside.example/FUZZ", "-w", path)
    assert run.code == 2 and wire.requests == []


def test_target_without_a_policy_grant_is_never_contacted(world):
    world.workspace(restrict={"https://allowed.example": ["manual"]})
    wire = world.serve({u("/FUZZ"): (200, b"ok", {})})
    path = world.wordlist("a")
    run = world.run("-u", u("/FUZZ"), "-w", path)
    assert run.code == 2 and wire.requests == []
    assert policy_denial(u("/FUZZ")) in run.out


def test_fuzz_operation_switched_off_blocks_every_request(world):
    world.workspace(deny=("fuzz",))
    wire = world.serve({u("/FUZZ"): (200, b"ok", {})})
    path = world.wordlist("a")
    run = world.run("-u", u("/FUZZ"), "-w", path)
    assert run.code == 2 and wire.requests == []


def test_an_unauthorized_redirect_hop_is_blocked_while_the_first_request_still_goes_out(world):
    """Proves PER-HOP enforcement: the first (in-scope, granted) request is sent; the hop to an
    ungranted origin is not -- egress authorizes each hop automatically via follow_redirects."""
    wire = world.serve({
        u("/a"): (301, b"", {"location": "https://notasset.allowed.example/x"}),
    })
    path = world.wordlist("a")
    run = world.run("-u", u("/FUZZ"), "-w", path, "--follow-redirects")
    assert wire.urls == [u("/a")]
    assert run.code == 1  # the attempt is recorded (requests_sent=1) but denied, so no hit


def test_proxy_is_authorized_the_same_way_as_the_target(world):
    """The target itself is granted, so the top-level preflight passes; the proxy grant is
    checked per-request inside the transport, so the denial surfaces as an error outcome rather
    than blocking before any attempt -- the wire itself never receives the request either way."""
    world.workspace(restrict={"http://proxy.example:8080": ["manual"]})
    wire = world.serve({u("/a"): (200, b"ok", {})})
    path = world.wordlist("a")
    run = world.run("-u", u("/FUZZ"), "-w", path, "-p", "http://proxy.example:8080")
    assert run.code == 1 and wire.requests == []


def test_tls_verification_is_on_by_default_and_ignore_ssl_turns_it_off(world):
    world.serve({u("/FUZZ"): (200, b"ok", {})})
    path = world.wordlist("a")
    world.run("-u", u("/FUZZ"), "-w", path)
    assert world.client_kwargs[0]["verify"] is True
    world.run("-u", u("/FUZZ"), "-w", path, "--ignore-ssl")
    assert world.client_kwargs[1]["verify"] is False


def test_follow_redirects_flag_reaches_the_client(world):
    world.serve({u("/FUZZ"): (200, b"ok", {})})
    path = world.wordlist("a")
    world.run("-u", u("/FUZZ"), "-w", path)
    assert world.client_kwargs[0]["follow_redirects"] is False
    world.run("-u", u("/FUZZ"), "-w", path, "--follow-redirects")
    assert world.client_kwargs[1]["follow_redirects"] is True


def test_missing_policy_file_blocks_before_any_request(world):
    world.workspace(policy=False)
    wire = world.serve({u("/FUZZ"): (200, b"ok", {})})
    path = world.wordlist("a")
    run = world.run("-u", u("/FUZZ"), "-w", path)
    assert run.code == 2 and wire.requests == []
    assert "policy-missing-or-invalid" in run.out


def test_policy_profile_paces_requests_regardless_of_the_threads_flag(world):
    world.workspace(limits={"requests_per_second": 4, "concurrency": 1})
    wire = world.serve({u(f"/p{i}"): (200, b"ok", {}) for i in range(4)}, delay=0.02)
    path = world.wordlist("p0", "p1", "p2", "p3")
    run = world.run("-u", u("/FUZZ"), "-w", path, "-t", "50", "--rps", "1000", "--timeout", "5")
    assert wire.peak == 1
    assert len(wire.requests) == 4
    assert run.code in (0, 1)


# ---------------------------------------------------------------------------------------------
# H. Engine-level run_fuzz: substitution + filters + outcomes end to end (mock transport)
# ---------------------------------------------------------------------------------------------


def run_fuzz_sync(skiff, target, positions, payloads, args, profile, filters):
    return asyncio.run(skiff.run_fuzz(target, positions, payloads, args, profile, filters))


class _RunArgs:
    def __init__(self, **overrides):
        self.threads = overrides.get("threads", 10)
        self.rps = overrides.get("rps", None)
        self.delay = overrides.get("delay", 0.0)
        self.timeout = overrides.get("timeout", 5.0)
        self.user_agent = overrides.get("user_agent", "UA/1")
        self.proxy = overrides.get("proxy", None)
        self.follow_redirects = overrides.get("follow_redirects", False)
        self.verify_ssl = overrides.get("verify_ssl", True)
        self.multi_fuzz = overrides.get("multi_fuzz", "same")
        self.auto_calibrate = overrides.get("auto_calibrate", False)
        self.seed = overrides.get("seed", 1)


def test_run_fuzz_sends_one_request_per_payload_and_classifies_hits(world):
    world.serve({u("/0"): (200, b"ok", {}), u("/1"): (404, b"missing", {}), u("/2"): (200, b"ok", {})})
    target = world.skiff.Target("GET", u("/FUZZ"))
    positions = world.skiff.locate_positions(target)
    filters = world.skiff.build_filters(_MatchArgs())
    profile = egress.authorize(u("/"), "fuzz", "GET")
    outcomes, sent, calibrated = run_fuzz_sync(
        world.skiff, target, positions, ["0", "1", "2"], _RunArgs(), profile, filters)
    assert sent == 3 and calibrated is False
    assert [row["status"] for row in outcomes] == [200, 404, 200]
    assert [row["classification"] for row in outcomes] == ["hit", "hit", "hit"]
    assert all("payload_ref" in row and str(row["payload_ref"]).count(":") == 1 for row in outcomes)
    assert all("0" != row["payload_ref"] and "1" != row["payload_ref"] for row in outcomes)


class _MatchArgs:
    match_code = match_size = match_words = match_lines = match_regex = match_header = None
    filter_code = filter_size = filter_words = filter_lines = filter_regex = None


def test_run_fuzz_marks_filtered_outcomes_without_dropping_them(world):
    world.serve({u("/0"): (200, b"ok", {}), u("/1"): (404, b"missing", {})})
    target = world.skiff.Target("GET", u("/FUZZ"))
    positions = world.skiff.locate_positions(target)

    class Args(_MatchArgs):
        match_code = "200"
    filters = world.skiff.build_filters(Args())
    profile = egress.authorize(u("/"), "fuzz", "GET")
    outcomes, sent, _ = run_fuzz_sync(world.skiff, target, positions, ["0", "1"], _RunArgs(), profile, filters)
    assert sent == 2
    assert [row["classification"] for row in outcomes] == ["hit", "filtered"]


def test_run_fuzz_combo_mode_sends_the_full_cartesian_product(world):
    def handler(request):
        return (200, str(request.url).encode(), {})
    world.serve(handler=handler)
    target = world.skiff.Target("GET", u("/FUZZ/FUZZ-does-not-collapse"),
                                headers=[("X-Id", "FUZZ")])
    positions = world.skiff.locate_positions(target)
    assert len(positions) == 2
    filters = world.skiff.build_filters(_MatchArgs())
    profile = egress.authorize(u("/"), "fuzz", "GET")
    outcomes, sent, _ = run_fuzz_sync(
        world.skiff, target, positions, ["a", "b"], _RunArgs(multi_fuzz="combo"), profile, filters)
    assert sent == 4  # 2 positions x 2 payloads, full combo


def test_run_fuzz_same_mode_sends_one_request_per_payload_even_with_two_positions(world):
    world.serve(default=(200, b"ok", {}))
    target = world.skiff.Target("GET", u("/FUZZ"), headers=[("X-Id", "FUZZ")])
    positions = world.skiff.locate_positions(target)
    filters = world.skiff.build_filters(_MatchArgs())
    profile = egress.authorize(u("/"), "fuzz", "GET")
    outcomes, sent, _ = run_fuzz_sync(
        world.skiff, target, positions, ["a", "b", "c"], _RunArgs(multi_fuzz="same"), profile, filters)
    assert sent == 3


def test_run_fuzz_records_network_failures_as_error_outcomes(world):
    world.serve({u("/0"): httpx.ConnectError("down")})
    target = world.skiff.Target("GET", u("/FUZZ"))
    positions = world.skiff.locate_positions(target)
    filters = world.skiff.build_filters(_MatchArgs())
    profile = egress.authorize(u("/"), "fuzz", "GET")
    outcomes, sent, _ = run_fuzz_sync(world.skiff, target, positions, ["0"], _RunArgs(), profile, filters)
    assert sent == 1
    assert outcomes[0]["classification"] == "error" and outcomes[0]["status"] is None
    assert "error" in outcomes[0] and outcomes[0]["error"]


def test_auto_calibrate_filters_out_a_shared_baseline_signature(world):
    def handler(request):
        if "zzcalibrate" in str(request.url):
            return (404, b"not found at all", {})
        if request.url.path.endswith("/real-hit"):
            return (200, b"ok", {})
        return (404, b"not found at all", {})
    world.serve(handler=handler)
    target = world.skiff.Target("GET", u("/FUZZ"))
    positions = world.skiff.locate_positions(target)
    filters = world.skiff.build_filters(_MatchArgs())
    profile = egress.authorize(u("/"), "fuzz", "GET")
    outcomes, sent, calibrated = run_fuzz_sync(
        world.skiff, target, positions, ["noise1", "real-hit", "noise2"],
        _RunArgs(auto_calibrate=True, seed=7), profile, filters)
    assert calibrated is True
    by_status = {row["status"]: row["classification"] for row in outcomes}
    hit_count = sum(1 for row in outcomes if row["classification"] == "hit")
    assert hit_count == 1
    assert any(row["classification"] == "hit" and row["status"] == 200 for row in outcomes)


# ---------------------------------------------------------------------------------------------
# I. The typed JSON result envelope and exit codes (spec 4)
# ---------------------------------------------------------------------------------------------


def test_envelope_has_the_documented_top_level_shape(world):
    world.serve({u("/0"): (200, b"ok", {})})
    path = world.wordlist("0")
    out = world.tmp / "r.json"
    run = world.run("-u", u("/FUZZ"), "-w", path, "-o", str(out), "-of", "json")
    assert run.code == 0
    document = world.read_json(out)
    assert document["schema_version"] == 1
    assert set(document) == {"schema_version", "run", "outcomes", "findings_summary", "exit_code"}
    run_block = document["run"]
    assert run_block["tool"] == "skiff" and run_block["operation"] == "fuzz"
    for key in ("run_id", "actor", "policy_version", "target", "method", "started_at", "finished_at",
               "requests_planned", "requests_sent", "requests_per_second_effective"):
        assert key in run_block
    assert document["findings_summary"].keys() == {"hit_count", "by_status", "auto_calibrated"}


def test_envelope_outcomes_never_carry_a_raw_payload_field(world):
    """FUZZ is in a header here (not the URL), so nothing in the response or the outcome needs
    to echo the wordlist entry back -- confirming the envelope never embeds it, only a ref."""
    world.serve({u("/static"): (200, b"ok", {})})
    path = world.wordlist("super-secret-marker-abc")
    out = world.tmp / "r.json"
    run = world.run("-u", u("/static"), "-H", "X-Id: FUZZ", "-w", path, "-o", str(out), "-of", "json")
    document = world.read_json(out)
    serialized = json.dumps(document["outcomes"])
    assert "super-secret-marker-abc" not in serialized
    assert "payload_ref" in document["outcomes"][0]
    assert "payload" not in document["outcomes"][0] and "word" not in document["outcomes"][0]


def test_exit_code_zero_when_a_hit_is_found(world):
    world.serve({u("/0"): (200, b"ok", {})})
    path = world.wordlist("0")
    assert world.run("-u", u("/FUZZ"), "-w", path).code == 0


def test_exit_code_one_when_no_hits_are_found(world):
    world.serve({u("/0"): (200, b"ok", {})})
    path = world.wordlist("0")

    class Args(_MatchArgs):
        pass
    run = world.run("-u", u("/FUZZ"), "-w", path, "-mc", "404")
    assert run.code == 1


def test_exit_code_one_for_a_missing_or_empty_wordlist(world):
    world.serve({u("/FUZZ"): (200, b"ok", {})})
    assert world.run("-u", u("/FUZZ"), "-w", str(world.tmp / "nope.txt")).code == 1
    empty = world.wordlist("", name="empty.txt")
    Path(empty).write_text("\n\n# only comments\n", encoding="utf-8")
    assert world.run("-u", u("/FUZZ"), "-w", empty).code == 1


def test_exit_code_two_when_no_fuzz_placeholder_is_present(world):
    world.serve({u("/plain"): (200, b"ok", {})})
    path = world.wordlist("0")
    run = world.run("-u", u("/plain"), "-w", path)
    assert run.code == 2


def test_exit_code_two_when_both_url_and_request_file_are_given(world):
    path = world.wordlist("0")
    req = world.tmp / "req.txt"
    req.write_text(RAW_REQUEST, encoding="utf-8")
    run = world.run("-u", u("/FUZZ"), "--request-file", str(req), "-w", path)
    assert run.code == 2


def test_dry_run_sends_nothing_and_exits_zero(world):
    wire = world.serve({u("/FUZZ"): (200, b"ok", {})})
    path = world.wordlist("0", "1", "2")
    run = world.run("-u", u("/FUZZ"), "-w", path, "--dry-run")
    assert run.code == 0 and wire.requests == []


# ---------------------------------------------------------------------------------------------
# J. Output formats
# ---------------------------------------------------------------------------------------------


def test_csv_export_has_the_documented_columns(world):
    world.serve({u("/0"): (200, b"ok", {})})
    path = world.wordlist("0")
    out = world.tmp / "r.csv"
    world.run("-u", u("/FUZZ"), "-w", path, "-o", str(out), "-of", "csv")
    rows = list(csv.DictReader(out.read_text(encoding="utf-8").splitlines()))
    assert rows[0]["status"] == "200" and rows[0]["classification"] == "hit"
    assert set(rows[0]) == set(world.skiff._CSV_COLUMNS)


def test_jsonl_export_is_one_outcome_per_line(world):
    world.serve({u("/0"): (200, b"ok", {}), u("/1"): (200, b"ok", {})})
    path = world.wordlist("0", "1")
    out = world.tmp / "r.jsonl"
    world.run("-u", u("/FUZZ"), "-w", path, "-o", str(out), "-of", "jsonl")
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["classification"] == "hit" for line in lines)


def test_txt_export_lists_hits_only(world):
    world.serve({u("/0"): (200, b"ok", {}), u("/1"): (200, b"ok", {})})
    path = world.wordlist("0", "1")
    out = world.tmp / "r.txt"
    world.run("-u", u("/FUZZ"), "-w", path, "-o", str(out), "-of", "txt", "-mc", "404")
    assert out.read_text(encoding="utf-8") == ""


# ---------------------------------------------------------------------------------------------
# K. CLI surface smoke (spec 3)
# ---------------------------------------------------------------------------------------------


def test_version_flag_prints_and_exits_zero(skiff, capsys):
    with pytest.raises(SystemExit) as exc:
        skiff.build_parser().parse_args(["-V"])
    assert exc.value.code == 0
    assert "skiff" in capsys.readouterr().out


def test_wordlist_flag_is_required(skiff):
    with pytest.raises(SystemExit):
        skiff.build_parser().parse_args(["-u", u("/FUZZ")])


def test_authorized_flag_is_accepted_and_is_a_no_op_echo(world):
    wire = world.serve({u("/0"): (200, b"ok", {})})
    path = world.wordlist("0")
    run = world.run("-u", u("/FUZZ"), "-w", path, "--authorized")
    assert run.code == 0 and len(wire.requests) == 1
    assert "no-op" in run.out


# ---------------------------------------------------------------------------------------------
# L. Re-enable: catalog, picker options, console form (spec 5)
# ---------------------------------------------------------------------------------------------


def test_skiff_is_no_longer_in_disabled_references():
    assert "skiff" not in catalog.DISABLED_REFERENCES


def test_catalog_still_lists_skiff_as_a_test_phase_tool():
    tool = catalog.tool_by_command("skiff")
    assert tool is not None and tool.folder == "skiff" and tool.script == "skiff.py"
    assert catalog.group_for("skiff") == "Test"


def test_console_form_rows_are_unique_so_every_option_is_settable(skiff):
    """The console resolves `set NAME value` by unique row name. Shorthand flags that share a dest
    (--base64/--no-encode, --no-ignore-ssl) and the version action must not add duplicate or
    stray rows, or `set ENCODING ...` / `set VERIFY_SSL ...` would be ambiguous."""
    from bughunt.console.options import spec_from_parser
    names = [option.name for option in spec_from_parser(skiff.build_parser()).options]
    assert len(names) == len(set(names)), sorted(n for n in set(names) if names.count(n) > 1)
    assert "VERSION" not in names and {"ENCODING", "VERIFY_SSL"} <= set(names)


def test_shorthand_flags_still_parse_to_the_primary_dest(skiff):
    parser = skiff.build_parser()
    base = ["-u", u("/FUZZ"), "-w", "wl.txt"]
    assert parser.parse_args(base).encoding == "url"
    assert parser.parse_args(base + ["--base64"]).encoding == "base64"
    assert parser.parse_args(base + ["--no-encode"]).encoding == "none"
    assert parser.parse_args(base + ["--encoding", "none"]).encoding == "none"
    assert parser.parse_args(base).verify_ssl is True
    assert parser.parse_args(base + ["--ignore-ssl"]).verify_ssl is False
    assert parser.parse_args(base + ["--ignore-ssl", "--no-ignore-ssl"]).verify_ssl is True


def test_catalog_export_gives_skiff_a_live_form(addons_root, monkeypatch):
    monkeypatch.setenv("BUGHUNT_ADDONS", str(addons_root))
    data = export_catalog(tool_file=Path(scanner.__file__), build_parser=scanner.build_parser)
    entry = next(m for p in data["phases"] for m in p["modules"] if m["name"] == "skiff")
    assert entry["disabled"] is False
    assert entry["form"] is not None
    option_names = {option["name"] for option in entry["form"]["options"]}
    assert {"URL", "WORDLIST", "THREADS", "FOLLOW_REDIRECTS"} <= option_names
