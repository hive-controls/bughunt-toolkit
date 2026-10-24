"""Characterization oracle for addons/Lanternjaw, written BEFORE the clean-room rebuild.

Scope: everything `tests/test_addons.py` leaves unpinned for the `phish` addon - the parser table and
catalog form, all 23 subcommands (rich text on stderr, JSON / `--values` / raw / Markdown on stdout),
the exit codes 0/1/2/130, the `Client.request` retry / redirect / status matrix, the feed cache, the
server-parameter wire vectors and paging, filters / sorts / limits, the scope-gated `analyze` and
`deep`, `match` (local-only matching), `watch`, `snapshot` / `diff`, the 18-column CSV export, the
Markdown report, the feed / blocklist raw modes, and the egress / policy posture.

Network posture: NO real phishunt.io call is made. Every response is served by `httpx.MockTransport`
at the egress edge (the addon's client is built by the real `bughunt.core.http.api_client`, so the real
policy gate, host guard and wire-header rules run in front of the mock), and an autouse tripwire makes
DNS and TCP connects raise. Every phishunt response shape here is INVENTED from what the code under
test reads (spec section 6.3): the live service's shapes, headers and rate-limit behavior are
UNVERIFIED (mock-only), and the tests that depend on them say so.

Tiers follow the spec (m2-lanternjaw-spec.md). Tests named for a defect (D1 ... D20) in the KNOWN
DEFECTS section assert the CORRECT behavior and are marked xfail(strict=True) until the rebuild
fixes them. Every other test pins CURRENT behavior the rebuild must reproduce. A few pins are
intentionally the OPPOSITE of a defect fix and say so (`*_PINNED_CURRENT_*` in the name): flip or
delete them if the orchestrator approves the matching deviation (D1, D2, D5, D14).

Point the suite at another copy of the script (mutation proofs, or the rebuilt file in a scratch
location) with `BUGHUNT_LJ_UNDER_TEST=<path to lanternjaw.py>`; the default is the repo's addon. Each
test imports its OWN copy of that file under its own workspace, so import-time behavior is exercised
every time. HOME, USERPROFILE and XDG_CACHE_HOME are redirected to a scratch directory for every test
(the feed cache lives under the user's cache dir, KIT-781/841 trap).
"""

from __future__ import annotations

import ast
import csv
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from rich.console import Console

from bughunt.console import catalog, loader, options, ui
from bughunt.console.catalog_export import export_catalog
from bughunt.core import egress
from bughunt.core import http as core_http
from bughunt.core import scanner
from bughunt.core.http import api_client
from test_gate import seed_policy

REPO = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT = REPO / "addons" / "Lanternjaw" / "lanternjaw.py"
SCRIPT = Path(os.environ.get("BUGHUNT_LJ_UNDER_TEST") or DEFAULT_SCRIPT).resolve()

BASE = "https://phishunt.io"
API_HOSTS = frozenset({"phishunt.io"})
ADDON_ACCEPT = "application/json, text/csv, text/plain;q=0.8, */*;q=0.5"
PROFILE_UA = "Bughunt-owned-lab"  # the User-Agent the test policy profile stamps on every request
VERDICTS = ("critical", "high", "medium", "low", "noise")
SORTS = ("first_seen", "score", "sources", "brand")
FEED_KINDS = ("json", "csv", "txt", "stix")
BLOCKLIST_KINDS = ("domains", "hosts", "adblock", "dnsmasq", "unbound", "rpz")
PIVOT_FIELDS = ("ip", "asn", "org", "cert", "country", "company", "registrar")
SUBCOMMANDS = (
    "about",
    "pulse",
    "hunt",
    "search",
    "analyze",
    "deep",
    "campaigns",
    "campaign",
    "related",
    "enrich",
    "brand",
    "cert",
    "feed",
    "blocklist",
    "pivot",
    "triage",
    "inspect",
    "match",
    "watch",
    "snapshot",
    "diff",
    "report",
    "self-test",
)
SOURCE_FIELDS = (
    "malicious_google",
    "malicious_openphish",
    "malicious_phishtank",
    "malicious_tweetfeed",
    "malicious_urlscan",
)
CSV_FIELDS = [
    "uuid",
    "first_seen",
    "date",
    "verdict",
    "score",
    "company",
    "domain",
    "url",
    "ip",
    "country",
    "asn",
    "org",
    "cert",
    *SOURCE_FIELDS,
]
EM_DASH = "—"


def uid(number: int) -> str:
    """A valid 8-4-4-4-12 hex uuid, distinct per number."""
    return f"{number:08x}-0000-4000-8000-{number:012x}"


def json_reply(payload, *, status=200, headers=None):
    return (
        status,
        {"content-type": "application/json", **(headers or {})},
        json.dumps(payload).encode(),
    )


def text_reply(text, *, status=200, ctype="text/plain", headers=None):
    body = text if isinstance(text, bytes) else text.encode("utf-8")
    return (status, {"content-type": ctype, **(headers or {})}, body)


def squash(text: str) -> str:
    """Collapse every whitespace run so content assertions do not depend on table layout."""
    return re.sub(r"\s+", " ", text)


# ---------------------------------------------------------------------------------------------
# Fixture data. INVENTED from the fields the code reads (spec 6.1); live shapes are UNVERIFIED.
# ---------------------------------------------------------------------------------------------

ROW_PAYPAL = {
    "uuid": uid(1),
    "domain": "paypal-login1.example.net",
    "url": "https://paypal-login1.example.net/signin/verify",
    "company": "paypal",
    "ip": "203.0.113.2",
    "country": "Germany",
    "asn": "13335",
    "org": "Cloudflare, Inc.",
    "cert": "R3",
    "first_seen": "2026-10-17T10:00:00Z",
    "date": "2026-10-18T06:30:00Z",
    "verdict": "critical",
    "score": 92,
    "malicious_google": True,
    "malicious_openphish": True,
    "malicious_phishtank": False,
    "malicious_tweetfeed": True,
    "malicious_urlscan": False,
    "sans_score": 5,
    "sans_scorereason": "dshield report",
    "top_signals": [
        {
            "signal": "brand-in-host",
            "kind": "lexical",
            "points": 30,
            "label": "paypal in hostname",
            "value": 1,
            "weight": 0.5,
        }
    ],
}
ROW_PAGES = {  # shared platform + credential-ish path token
    "uuid": uid(2),
    "domain": "kit.pages.dev",
    "url": "https://kit.pages.dev/account/update",
    "company": "microsoft",
    "ip": "198.51.100.7",
    "country": "United States",
    "asn": "13335",
    "org": "Cloudflare, Inc.",
    "cert": "Google Trust Services",
    "first_seen": "2026-10-17T12:00:00Z",
    "date": "2026-10-18T07:00:00Z",
    "verdict": "high",
    "score": 75,
    "malicious_google": False,
    "malicious_openphish": True,
    "malicious_phishtank": False,
    "malicious_tweetfeed": False,
    "malicious_urlscan": False,
}
ROW_PUNY = {  # punycode host, noise tier but flagged by one external feed
    "uuid": uid(3),
    "domain": "xn--pypal-4ve.example",
    "url": "http://xn--pypal-4ve.example/",
    "company": "paypal",
    "ip": "203.0.113.2",
    "country": "Germany",
    "asn": "24940",
    "org": "Hetzner Online GmbH",
    "cert": "R3",
    "first_seen": "2026-10-18T01:00:00Z",
    "date": "2026-10-18T08:00:00Z",
    "verdict": "noise",
    "score": 12,
    "malicious_google": False,
    "malicious_openphish": False,
    "malicious_phishtank": True,
    "malicious_tweetfeed": False,
    "malicious_urlscan": False,
}
ROW_BANK = {  # string score, two flags
    "uuid": uid(4),
    "domain": "bank-update.example.org",
    "url": "https://bank-update.example.org/p?x=1",
    "company": "chase",
    "ip": "192.0.2.44",
    "country": "France",
    "asn": "16276",
    "org": "OVH SAS",
    "cert": "Let's Encrypt",
    "first_seen": "2026-10-18T03:00:00Z",
    "date": "2026-10-18T09:00:00Z",
    "verdict": "medium",
    "score": "55",
    "malicious_google": False,
    "malicious_openphish": False,
    "malicious_phishtank": True,
    "malicious_tweetfeed": False,
    "malicious_urlscan": True,
}
ROW_PLAIN = {  # url_risk / phishunt_score fallbacks, no company, no sources
    "uuid": uid(5),
    "domain": "plain.example.com",
    "url": "https://plain.example.com/",
    "company": "",
    "ip": "",
    "country": "France",
    "asn": "",
    "org": "",
    "cert": "",
    "first_seen": "2026-10-16T09:00:00Z",
    "date": "2026-10-16T09:30:00Z",
    "url_risk": "low",
    "phishunt_score": 20,
}
ROW_NOUUID = {  # no uuid, no verdict at all
    "domain": "nouuid.example",
    "url": "https://nouuid.example/",
    "company": "paypal",
    "country": "Germany",
    "first_seen": "2026-10-15T00:00:00Z",
    "date": "2026-10-15T00:30:00Z",
    "score": 0,
}
FEED = [ROW_PAYPAL, ROW_PAGES, ROW_PUNY, ROW_BANK, ROW_PLAIN, ROW_NOUUID]
FEED_BY_FIRST_SEEN = [
    ROW_BANK,
    ROW_PUNY,
    ROW_PAGES,
    ROW_PAYPAL,
    ROW_PLAIN,
    ROW_NOUUID,
]  # newest first
TIES = [  # equal scores / source counts / first_seen, to pin "ties keep input order"
    {
        "uuid": uid(11),
        "domain": "t1.example",
        "company": "a",
        "score": 50,
        "first_seen": "2026-10-10T00:00:00Z",
    },
    {
        "uuid": uid(12),
        "domain": "t2.example",
        "company": "a",
        "score": 50,
        "first_seen": "2026-10-10T00:00:00Z",
    },
    {
        "uuid": uid(13),
        "domain": "t3.example",
        "company": "a",
        "score": 50,
        "first_seen": "2026-10-10T00:00:00Z",
    },
]

ANALYZE_PAYLOAD = {
    "query": {
        "url": "https://allowed.example/login",
        "host": "allowed.example",
        "apex": "allowed.example",
    },
    "live_analysis": {
        "url_risk_score": 64,
        "url_risk": "likely_phishing",
        "brand_match": "paypal",
        "kw_score": 7,
        "allowlisted": False,
        "impersonation": "brand-in-path",
        "why": [
            {
                "signal": "login-path",
                "kind": "path",
                "points": 12,
                "label": "login path",
                "value": 1,
                "weight": 0.5,
            },
            {"signal_id": "young-domain", "category": "whois", "score_contribution": 9},
        ],
        "url_signals": {"digits": 0, "hyphens": 2.5},
        "path_signals": {"depth": 3, "empty": 0},
    },
    "verdict": "suspicious",
    "verdict_confidence": "medium",
    "verdict_basis": ["lexical", "known-brand"],
    "known": {
        "in_active_feed": True,
        "previously_active": False,
        "in_new_registration_feed": False,
        "record": {
            "company": "paypal",
            "phishunt_score": 88,
            "verdict": "critical",
            "first_seen": "2026-10-01T00:00:00Z",
            "detail_url": "https://phishunt.io/suspicious/paypal/x/",
            "sources": {"openphish": True, "phishtank": False},
            "ai": {
                "summary": "Looks like a PayPal credential harvester.",
                "threat_type": "phishing",
            },
        },
    },
    "history": {
        "apex_prior_detections": 3,
        "apex_first_seen": "2026-09-01",
        "apex_last_seen": "2026-10-17",
        "brands_targeted": [
            {"company": "paypal", "count": 2},
            {"company": "ebay", "count": 1},
        ],
    },
    "external_feeds": {
        "openphish": True,
        "phishtank": False,
        "tweetfeed": False,
        "listed": True,
        "status": "fresh",
    },
    "action": {"queued_for_analysis": True, "reason": "new apex"},
    "meta": {"note": "scores are heuristics"},
}
DEEP_PAYLOAD = {
    **ANALYZE_PAYLOAD,
    "deep_analysis": {
        "detector_version": "d-2.1",
        "risk_score": 71,
        "verdict": "phishing",
        "classification": "credential-harvest",
        "layer_scores": {"content": 40, "network": 31},
        "signals": [
            {
                "signal_id": "login-form",
                "category": "content",
                "score_contribution": 25,
                "description": "password field",
                "normalized_value": 1,
                "detected": True,
            },
            {
                "signal_id": "cert-age",
                "category": "tls",
                "score_contribution": 3,
                "description": "fresh certificate",
                "normalized_value": 0.2,
                "detected": False,
            },
            {
                "signal_id": "quiet",
                "category": "x",
                "score_contribution": 0,
                "detected": False,
            },
            {
                "signal_id": "geo",
                "category": "net",
                "score_contribution": 0,
                "detected": False,
                "errors": ["geoip timeout"],
            },
        ],
        "analysis_failures": ["rdap: no answer", {"code": "dns-fail"}],
        "adjustments": ["allowlist -10"],
    },
    "budget": {"used": 3, "remaining": 47, "limit": 50},
}
CAMPAIGN_KEY = "cmp-3f9a1c0e22aa"
CAMPAIGN_LIST = {
    "results": [
        {
            "key": CAMPAIGN_KEY,
            "confidence": "possible campaign",
            "size": 12,
            "active_count": 4,
            "brands": ["paypal", "ebay"],
            "top_evidence": {"type": "shared_ip", "coverage": "0.80"},
            "last_activity": "2026-10-18T05:00:00Z",
        },
        {
            "key": "cmp-bbbbbbbbbbbb",
            "confidence": "suspected cluster",
            "size": 3,
            "active_count": 0,
            "brands": [],
            "top_evidence": {},
            "last_activity": "",
        },
    ],
    "count": 2,
    "total": 2,
    "data_status": "ok",
    "algorithm_version": "c-1",
    "generated_at": "2026-10-18T04:00:00Z",
}
CAMPAIGN_DETAIL = {
    "key": CAMPAIGN_KEY,
    "id": 77,
    "state": "live",
    "end_state": "",
    "successors": ["cmp-ccc"],
    "confidence": "possible campaign",
    "confidence_score": 0.91,
    "size": 12,
    "host_count": 9,
    "active_count": 4,
    "brands": ["paypal", "ebay"],
    "first_seen": "2026-10-01T00:00:00Z",
    "last_activity": "2026-10-18T05:00:00Z",
    "top_evidence": {"type": "shared_ip", "coverage": "0.80"},
    "algorithm_version": "c-1",
    "generated_at": "2026-10-18T04:00:00Z",
    "data_status": "ok",
    "url": "https://phishunt.io/campaigns/x",
    "evidence_summary": [
        {"type": "shared_ip", "value": "203.0.113.2", "members_matching": 7}
    ],
    "members": [
        {
            "status": "active",
            "score": 90,
            "company": "paypal",
            "domain": "a.example",
            "ip": "203.0.113.2",
            "malicious_google": "1",
            "malicious_openphish": "0",
        }
    ],
    "relationships": [
        {
            "domain_a": "a.example",
            "domain_b": "b.example",
            "score": 0.7,
            "tier": "strong",
        }
    ],
    "relationships_truncated": True,
    "history": [
        {
            "at": "2026-10-02T00:00:00Z",
            "event": "grew",
            "size": 5,
            "joined": ["b.example"],
            "left": [],
        }
    ],
}
RELATED_PAYLOAD = {
    "domain": "paypal-login1.example.net",
    "algorithm_version": "r-1",
    "generated_at": "2026-10-18T04:00:00Z",
    "cluster": {
        "key": CAMPAIGN_KEY,
        "size": 12,
        "host_count": 9,
        "url": "https://phishunt.io/campaigns/x",
    },
    "results": [
        {
            "relationship_score": 0.8,
            "status": "active",
            "company": "paypal",
            "domain": "sib.example",
            "evidence": [{"type": "shared_ip"}, {"type": "same_cert"}],
        }
    ],
}
ENRICH_PAYLOAD = {
    "whois": {
        "registrar": "Example Registrar LLC",
        "created": "2026-09-30",
        "updated": "2026-10-01",
        "expires": "2027-09-30",
        "status": ["clientTransferProhibited", "ok"],
    },
    "ipinfo": {
        "city": "Frankfurt",
        "region": "Hesse",
        "country": "DE",
        "postal": "60313",
        "loc": "50.1,8.6",
        "hostname": "static.example.net",
    },
}
BRAND_PAYLOAD = {
    "name": "PayPal",
    "slug": "paypal",
    "sector": "finance",
    "vertical": "payments",
    "domain": "paypal.com",
    "active_phishings": 41,
    "notes": "most targeted",
    "url": "https://phishunt.io/b/paypal",
}
CERT_PAYLOAD = {
    "cert": "R3",
    "operator": "Let's Encrypt",
    "root_ca": "ISRG Root X1",
    "since": "2020-09-04",
    "key_type": "RSA",
    "use_case": "free DV",
    "related": ["R10", "R11"],
    "active_phishings": 1200,
    "notes": "free CA",
    "url": "https://phishunt.io/c/r3",
}
STIX_PAYLOAD = {
    "type": "bundle",
    "objects": [
        {"type": "indicator", "confidence": 90, "labels": ["paypal"]},
        {"type": "indicator", "confidence": 60, "labels": ["paypal", "ebay"]},
        {"type": "indicator", "labels": ["chase"]},
        {"type": "identity", "name": "phishunt"},
    ],
}


# ---------------------------------------------------------------------------------------------
# Harness: scratch policy workspace + egress-edge mock + a private copy of the script under test
# ---------------------------------------------------------------------------------------------


@dataclass
class Run:
    code: object  # int exit code, or None when an exception escaped main()
    out: str
    err: str
    exc: BaseException | None = None

    @property
    def text(self) -> str:
        return squash(self.out)

    @property
    def etext(self) -> str:
        return squash(self.err)

    @property
    def lines(self) -> list[str]:
        return [line.rstrip("\r") for line in self.out.splitlines()]

    def json(self):
        return json.loads(self.out)

    def error_line(self) -> dict:
        return json.loads(self.err.strip().splitlines()[-1])


def clean(run: Run, code: int = 0) -> Run:
    """Assert the run ended normally with `code` and no exception escaped, then hand it back."""
    assert run.exc is None, repr(run.exc)
    assert run.code == code, (run.code, run.out[-300:], run.err[-300:])
    return run


class World:
    """A policy workspace, a mock phishunt behind the real guarded client, and one imported addon."""

    def __init__(self, monkeypatch, tmp_path, capsys):
        self.mp, self.tmp, self.capsys = (
            monkeypatch,
            tmp_path / "world",
            capsys,
        )  # tmp_path itself stays clean for exports
        self.tmp.mkdir()
        self.requests: list[httpx.Request] = []
        self.slept: list[float] = []
        self._routes: dict = {}
        self._default = None
        self._handler = None
        self._imports = 0
        self._stop_after: int | None = None
        self.lj = None
        self.real_client = None
        self.addons_root: Path | None = None
        self.transport = httpx.MockTransport(self._respond)
        self.workspace_dir = self.tmp / "workspace"
        self.cwd = self.tmp / "cwd"
        self.home = self.tmp / "home"
        self.cache_home = self.tmp / "xdg-cache"
        for folder in (self.cwd, self.home, self.cache_home):
            folder.mkdir()

        def factory(hosts, **kwargs):
            kwargs.setdefault("transport", self.transport)
            return api_client(hosts, **kwargs)

        monkeypatch.setattr(core_http, "api_client", factory)
        for name in (
            "FORCE_COLOR",
            "NO_COLOR",
            "BUGHUNT_ADDONS",
            "PHISHUNT_DEEP_TOKEN",
        ):
            monkeypatch.delenv(name, raising=False)
        # Isolation (KIT-781/841): the cache dir, HOME and the cwd are all scratch.
        monkeypatch.setenv("HOME", str(self.home))
        monkeypatch.setenv("USERPROFILE", str(self.home))
        monkeypatch.setenv("XDG_CACHE_HOME", str(self.cache_home))
        monkeypatch.chdir(self.cwd)
        monkeypatch.setattr(
            egress.clock, "sleep", time.sleep
        )  # must precede the sleep patch below: bind egress's pacing wait to the real time.sleep so the poll is not recorded (clock.now stays real perf_counter)
        monkeypatch.setattr(time, "sleep", self._sleep)
        self.workspace()
        self.load()

    # -- the mock edge -------------------------------------------------------------------------

    def _respond(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._handler is not None:
            spec = self._handler(request)
        else:
            spec = self._routes.get(str(request.url), self._default)
        if isinstance(spec, BaseException):
            raise spec
        if spec is None:
            raise AssertionError(f"unrouted request {request.url}")
        status, headers, body = spec
        return httpx.Response(status, headers=headers, content=body, request=request)

    def serve(self, default=None, *, routes=None, handler=None) -> None:
        """`default` answers every URL; `routes` maps exact URL -> reply; `handler(request)` wins."""
        self._default, self._routes, self._handler = (
            default,
            dict(routes or {}),
            handler,
        )

    def serve_paths(self, table: dict, *, default=None) -> None:
        """Route by URL path (query ignored). A value may be a reply tuple, an exception, or `fn(request)`."""

        def handler(request):
            spec = table.get(request.url.path, default)
            return spec(request) if callable(spec) else spec

        self.serve(handler=handler)

    def serve_sequence(self, replies) -> None:
        """Answer request N with replies[N] (the last one repeats)."""
        counter = {"n": 0}

        def handler(request):
            spec = replies[min(counter["n"], len(replies) - 1)]
            counter["n"] += 1
            return spec(request) if callable(spec) else spec

        self.serve(handler=handler)

    @property
    def urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    @property
    def paths(self) -> list[str]:
        return [request.url.path for request in self.requests]

    def query_keys(self, index: int = -1) -> list[str]:
        """The query parameter NAMES of one request, in wire order."""
        raw = self.requests[index].url.query.decode()
        return [pair.split("=", 1)[0] for pair in raw.split("&")] if raw else []

    def params(self, index: int = -1) -> dict[str, str]:
        return dict(self.requests[index].url.params)

    # -- workspace and module ------------------------------------------------------------------

    def workspace(
        self,
        directory: Path | None = None,
        *,
        drop=(),
        policy=True,
        mutate=None,
        scope="allowed.example\n",
    ) -> Path:
        """Seed a verified policy (phishunt.io granted for every operation) plus, unless `scope` is
        None, a scope file listing allowed.example. `drop` removes policy assets, `mutate(document)`
        edits the policy, `policy=False` removes it."""
        target = directory or self.workspace_dir
        target.mkdir(parents=True, exist_ok=True)
        (target / "policy.json").unlink(missing_ok=True)
        (target / "scope.txt").unlink(missing_ok=True)
        document = seed_policy(target)
        document["assets"] = [
            row for row in document["assets"] if row["origin"] not in set(drop)
        ]
        if mutate is not None:
            mutate(document)
        (target / "policy.json").write_text(json.dumps(document), encoding="utf-8")
        if not policy:
            (target / "policy.json").unlink()
        if scope is not None:
            (target / "scope.txt").write_text(scope, encoding="utf-8")
        self.mp.setenv("BUGHUNT_SCOPE", str(target))
        return target

    def load(self, columns: str | None = "140"):
        """Import a fresh private copy of the script. Rich reads COLUMNS when its console is built,
        so the width must be chosen here; `columns=None` means "not a terminal, no COLUMNS" (80).
        `Client` is swapped for a subclass with pacing off so tests never wait; the real class stays
        in `self.real_client`."""
        self._imports += 1
        if columns is None:
            self.mp.delenv("COLUMNS", raising=False)
        else:
            self.mp.setenv("COLUMNS", columns)
        self.addons_root = self.tmp / f"addons-{self._imports}"
        folder = self.addons_root / "Lanternjaw"
        folder.mkdir(parents=True)
        shutil.copyfile(SCRIPT, folder / "lanternjaw.py")
        self.lj = loader.import_script(folder / "lanternjaw.py")
        self.real_client = self.lj.Client

        class UnpacedClient(self.real_client):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.min_interval = 0

        self.mp.setattr(self.lj, "Client", UnpacedClient)
        return self.lj

    def forget_modules(self) -> None:
        for key in [
            key
            for key, module in sys.modules.items()
            if str(getattr(module, "__file__", "") or "").startswith(str(self.tmp))
        ]:
            sys.modules.pop(key, None)

    # -- running -------------------------------------------------------------------------------

    def run(self, *argv: str) -> Run:
        code, exc = None, None
        try:
            code = self.lj.main(list(argv))
        except SystemExit as stop:
            code = stop.code
        except Exception as raised:  # noqa: BLE001 - the oracle records what escapes main()
            exc = raised
        out, err = self.capsys.readouterr()
        return Run(code, out, err, exc)

    def via_loader(self, name: str, *argv: str):
        """`bughunt <name> ...` through loader.run_named with the loader's own console captured."""
        self.mp.setenv("BUGHUNT_ADDONS", str(self.addons_root))
        console_text = io.StringIO()
        self.mp.setattr(
            ui,
            "console",
            Console(theme=ui.THEME, highlight=False, file=console_text, width=200),
        )
        code = loader.run_named(
            name,
            list(argv),
            tool_file=Path(scanner.__file__).resolve(),
            scan_main=scanner.scan_main,
        )
        out, err = self.capsys.readouterr()
        return Run(code, out, err), console_text.getvalue()

    def _sleep(self, seconds):
        self.slept.append(seconds)
        if self._stop_after is not None and len(self.slept) >= self._stop_after:
            raise KeyboardInterrupt

    def stop_after_sleeps(self, count: int) -> None:
        """Make the `count`-th sleep raise KeyboardInterrupt (the `watch` loop's normal way out)."""
        self._stop_after = count

    @property
    def cache_file(self) -> Path:
        return self.cache_home / "lanternjaw" / "feed.json"

    def cache_rows(self, rows, *, age: float = 0.0) -> None:
        """Seed the active-feed cache with `rows`, `age` seconds old."""
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.cache_file.write_text(
            json.dumps(
                {"saved_at": "2026-10-18T00:00:00Z", "count": len(rows), "sites": rows}
            ),
            encoding="utf-8",
        )
        if age:
            stamp = time.time() - age
            os.utime(self.cache_file, (stamp, stamp))


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Tripwire: nothing in this module may resolve a name or open a socket."""

    def forbidden(*args, **kwargs):
        raise AssertionError(
            "real network reached from a Lanternjaw characterization test"
        )

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def world(monkeypatch, tmp_path, capsys):
    scene = World(monkeypatch, tmp_path, capsys)
    yield scene
    scene.forget_modules()


@pytest.fixture
def fed(world):
    """A world whose /feed.json answers FEED and whose other paths are unrouted (loud failure)."""
    world.serve_paths({"/feed.json": json_reply(FEED)})
    return world


# ---------------------------------------------------------------------------------------------
# A. Module surface and CLI parser table (spec 2.1, section 3)  [C1, C2]
# ---------------------------------------------------------------------------------------------


def parser_table(parser) -> dict:
    """dest -> (option strings, default, choices, nargs, type name) for every non-help action."""
    table = {}
    for action in parser._actions:
        if action.dest in ("help", "command"):
            continue
        table[action.dest] = (
            tuple(action.option_strings),
            action.default,
            tuple(action.choices) if action.choices else None,
            action.nargs,
            getattr(action.type, "__name__", None) if action.type else None,
        )
    return table


def flag(*names):
    return (names, False, None, 0, None)


def value(*names, default=None, choices=None, kind=None):
    return (names, default, choices, None, kind)


def positional(choices=None):
    return ((), None, choices, None, None)


JSON_FLAG = {"json": flag("--json")}
SERVER_FILTERS = {
    "company": value("--company"),
    "since": value("--since"),
    "contains": value("--contains"),
    "tier": value("--tier", choices=("all", "verified")),
    "asn": value("--asn"),
    "org": value("--org"),
    "registrar": value("--registrar"),
    "cert": value("--cert"),
    "country": value("--country"),
    "ip": value("--ip"),
}
CLIENT_FILTERS = {
    "verdict": value("--verdict", choices=VERDICTS),
    "min_score": value("--min-score", kind="int"),
    "min_sources": value("--min-sources", kind="int"),
}
SORT = value("--sort", default="first_seen", choices=SORTS)

EXPECTED_PARSER = {
    "about": {},
    "pulse": {**JSON_FLAG, **SERVER_FILTERS, **CLIENT_FILTERS},
    "hunt": {
        **JSON_FLAG,
        **SERVER_FILTERS,
        **CLIENT_FILTERS,
        "limit": value("--limit", default=25, kind="int"),
        "offset": value("--offset", kind="int"),
        "all": flag("--all"),
        "sort": SORT,
        "values": flag("--values"),
        "export": value("--export"),
    },
    "search": {
        **JSON_FLAG,
        "query": positional(),
        "limit": value("--limit", default=50, kind="int"),
        **CLIENT_FILTERS,
        "sort": SORT,
        "export": value("--export"),
    },
    "analyze": {**JSON_FLAG, "url": positional(), "yes": flag("--yes")},
    "deep": {
        **JSON_FLAG,
        "url": positional(),
        "token": value("--token"),
        "yes": flag("--yes"),
    },
    "campaigns": {
        **JSON_FLAG,
        "brand": value("--brand"),
        "status": value("--status", default="all", choices=("active", "all")),
        "min_size": value("--min-size", default=0, kind="int"),
        "limit": value("--limit", default=20, kind="int"),
        "offset": value("--offset", default=0, kind="int"),
        "all": flag("--all"),
    },
    "campaign": {
        **JSON_FLAG,
        "key": positional(),
        "export": value("--export", choices=("json", "csv", "txt")),
        "out": value("--out"),
    },
    "related": {
        **JSON_FLAG,
        "uuid": positional(),
        "limit": value("--limit", default=10, kind="int"),
        "min_score": value("--min-score", default=0, kind="int"),
    },
    "enrich": {**JSON_FLAG, "uuid": positional()},
    "brand": {**JSON_FLAG, "slug": positional()},
    "cert": {**JSON_FLAG, "name": positional()},
    "feed": {
        **JSON_FLAG,
        "kind": positional(FEED_KINDS),
        "out": value("--out"),
        "limit": value("--limit", default=15, kind="int"),
    },
    "blocklist": {
        **JSON_FLAG,
        "kind": positional(BLOCKLIST_KINDS),
        "out": value("--out"),
        "values": flag("--values"),
        "limit": value("--limit", default=20, kind="int"),
    },
    "pivot": {
        **JSON_FLAG,
        "field": positional(PIVOT_FIELDS),
        **SERVER_FILTERS,
        **CLIENT_FILTERS,
        "min_count": value("--min-count", default=2, kind="int"),
        "limit": value("--limit", default=25, kind="int"),
    },
    "triage": {
        **JSON_FLAG,
        **SERVER_FILTERS,
        **CLIENT_FILTERS,
        "limit": value("--limit", default=20, kind="int"),
        "all": flag("--all"),
        "export": value("--export"),
    },
    "inspect": {
        **JSON_FLAG,
        "uuid": positional(),
        "limit": value("--limit", default=10, kind="int"),
        "skip_related": flag("--skip-related"),
        "skip_enrich": flag("--skip-enrich"),
    },
    "match": {
        **JSON_FLAG,
        "file": positional(),
        "show_misses": flag("--show-misses"),
        "fail_on_hit": flag("--fail-on-hit"),
        "export": value("--export"),
    },
    "watch": {
        **JSON_FLAG,
        "since": value("--since"),
        "polls": value("--polls", kind="int"),
        "interval": value("--interval", default=300, kind="int"),
        "company": value("--company"),
        "country": value("--country"),
        "tier": value("--tier", choices=("all", "verified")),
        **CLIENT_FILTERS,
        "limit": value("--limit", default=50, kind="int"),
        "once": flag("--once"),
        "log": value("--log"),
    },
    "snapshot": {**JSON_FLAG, "out": value("--out")},
    "diff": {
        **JSON_FLAG,
        "snapshot": positional(),
        **SERVER_FILTERS,
        **CLIENT_FILTERS,
        "limit": value("--limit", default=20, kind="int"),
        "export": value("--export"),
    },
    "report": {
        **JSON_FLAG,
        **SERVER_FILTERS,
        **CLIENT_FILTERS,
        "limit": value("--limit", default=15, kind="int"),
        "out": value("--out"),
    },
    "self-test": {},
}
GLOBAL_PARSER = {
    "quiet": flag("-q", "--quiet"),
    "verbose": flag("-v", "--verbose"),
    "live": flag("--live"),
    "fresh": flag("--fresh"),
    "timeout": value("--timeout", default=45.0, kind="float"),
}
HIDDEN_DEFAULTS = {  # subparser set_defaults the user cannot see: (dest, value)
    "pulse": {"sort": "first_seen", "all": True, "offset": None},
    "pivot": {"sort": "first_seen", "all": True, "offset": None},
    "report": {"sort": "first_seen", "all": True, "offset": None},
    "diff": {"sort": "first_seen", "all": True, "offset": None},
    "triage": {"sort": "score"},
}


def subparsers_of(parser):
    return next(action for action in parser._actions if action.dest == "command")


def test_module_constants_and_exceptions(world):
    lj = world.lj
    assert lj.API_HOSTS == API_HOSTS and isinstance(lj.API_HOSTS, frozenset)
    assert (lj.NAME, lj.VERSION, lj.BASE, lj.DOCS) == (
        "Lanternjaw",
        "1.0.0",
        BASE,
        "https://phishunt.io/api/",
    )
    assert lj.CACHE_TTL == 600 and lj.RATE == 8.0
    assert isinstance(lj.USER_AGENT, str) and lj.USER_AGENT
    assert issubclass(lj.PhishuntError, RuntimeError)
    error = lj.PhishuntError("boom", status=404, payload={"a": 1})
    assert (str(error), error.status, error.payload) == ("boom", 404, {"a": 1})
    assert (
        lj.PhishuntError("x").status is None and lj.PhishuntError("x").payload is None
    )
    assert callable(lj.build_parser) and callable(lj.main)
    for name in SUBCOMMANDS:
        assert callable(getattr(lj, "cmd_" + name.replace("-", "_"))), name


def test_main_and_client_signatures(world):
    import inspect

    main = inspect.signature(world.lj.main)
    assert list(main.parameters) == ["argv"] and main.parameters["argv"].default is None
    request = inspect.signature(world.real_client.request)
    assert list(request.parameters) == ["self", "path", "params", "headers", "timeout"]
    assert request.parameters["headers"].kind is inspect.Parameter.KEYWORD_ONLY
    assert request.parameters["timeout"].kind is inspect.Parameter.KEYWORD_ONLY
    assert request.parameters["params"].default is None
    init = inspect.signature(world.real_client.__init__)
    assert list(init.parameters) == ["self", "timeout", "verbose"]
    assert (init.parameters["timeout"].default, init.parameters["verbose"].default) == (
        45.0,
        False,
    )
    for name in ("get_json", "get_text"):
        assert callable(getattr(world.real_client, name))


def test_no_import_time_network_or_client_construction(monkeypatch, tmp_path):
    """Importing the module (the console does it many times) builds no client and sends nothing."""
    calls = []
    monkeypatch.setattr(core_http, "api_client", lambda *a, **k: calls.append((a, k)))
    seed_policy(tmp_path / "ws")
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "ws"))
    folder = tmp_path / "Lanternjaw"
    folder.mkdir()
    shutil.copyfile(SCRIPT, folder / "lanternjaw.py")
    module = loader.import_script(folder / "lanternjaw.py")
    assert calls == [] and module.API_HOSTS == API_HOSTS


def test_parser_is_zero_arg_with_a_required_command_subparser_in_the_documented_order(
    world,
):
    parser = world.lj.build_parser()
    command = subparsers_of(parser)
    assert command.required is True and command.dest == "command"
    assert list(command.choices) == list(SUBCOMMANDS)
    assert len(SUBCOMMANDS) == 23


def test_top_level_options_are_exactly_the_five_globals(world):
    parser = world.lj.build_parser()
    top = parser_table(parser)
    top.pop("command", None)
    assert top == GLOBAL_PARSER


@pytest.mark.parametrize("command", list(EXPECTED_PARSER))
def test_subparser_dests_flags_defaults_choices_and_types(world, command):
    sub = subparsers_of(world.lj.build_parser()).choices[command]
    inherited = {
        name: (row[0], "==SUPPRESS==", *row[2:]) for name, row in GLOBAL_PARSER.items()
    }
    assert parser_table(sub) == {**inherited, **EXPECTED_PARSER[command]}


@pytest.mark.parametrize(
    "command", [name for name in EXPECTED_PARSER if name not in ("about", "self-test")]
)
def test_every_subcommand_but_about_and_self_test_has_json(world, command):
    args = world.lj.build_parser().parse_args(
        [command, *REQUIRED_ARGS.get(command, []), "--json"]
    )
    assert args.json is True


@pytest.mark.parametrize("command", ["about", "self-test"])
def test_about_and_self_test_have_no_json_flag_and_leave_json_mode_off(world, command):
    assert "json" not in EXPECTED_PARSER[command]
    assert not hasattr(world.lj.build_parser().parse_args([command]), "json")


REQUIRED_ARGS = {
    "search": ["abc"],
    "analyze": ["x.example"],
    "deep": ["x.example"],
    "campaign": ["k"],
    "related": [uid(1)],
    "enrich": [uid(1)],
    "brand": ["b"],
    "cert": ["c"],
    "feed": ["json"],
    "blocklist": ["domains"],
    "pivot": ["ip"],
    "inspect": [uid(1)],
    "match": ["f.txt"],
    "diff": ["s.json"],
}


@pytest.mark.parametrize("command,hidden", list(HIDDEN_DEFAULTS.items()))
def test_hidden_subparser_defaults(world, command, hidden):
    args = world.lj.build_parser().parse_args(
        [command, *REQUIRED_ARGS.get(command, [])]
    )
    assert {key: getattr(args, key) for key in hidden} == hidden


def test_parsed_defaults_match_the_table(world):
    parser = world.lj.build_parser()
    args = parser.parse_args(["hunt"])
    assert (
        args.command,
        args.limit,
        args.offset,
        args.all,
        args.sort,
        args.values,
        args.export,
        args.json,
    ) == ("hunt", 25, None, False, "first_seen", False, None, False)
    assert (args.quiet, args.verbose, args.live, args.fresh, args.timeout) == (
        False,
        False,
        False,
        False,
        45.0,
    )
    assert parser.parse_args(["--timeout", "7.5", "about"]).timeout == 7.5
    assert parser.parse_args(["-q", "-v", "--live", "--fresh", "about"]).fresh is True


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--bogus"],
        ["bogus"],
        ["hunt", "--limit", "x"],
        ["hunt", "--offset", "1.5"],
        ["hunt", "--sort", "bogus"],
        ["hunt", "--tier", "x"],
        ["hunt", "--verdict", "urgent"],
        ["hunt", "--min-score", "x"],
        ["--timeout", "x", "about"],
        ["feed"],
        ["feed", "bogus"],
        ["blocklist"],
        ["blocklist", "bogus"],
        ["pivot"],
        ["pivot", "bogus"],
        ["campaign"],
        ["campaign", "k", "--export", "pdf"],
        ["campaigns", "--status", "x"],
        ["search"],
        ["analyze"],
        ["deep"],
        ["related"],
        ["enrich"],
        ["brand"],
        ["cert"],
        ["inspect"],
        ["watch", "--interval", "x"],
        ["watch", "--tier", "x"],
        ["match"],
        ["diff"],
        ["about", "--json"],
        ["self-test", "--json"],
        ["pulse", "--limit", "3"],
        ["pulse", "--all"],
        ["snapshot", "--limit", "3"],
        ["watch", "--company"],
    ],
)
def test_argparse_errors_exit_2_with_text_on_stderr_only(world, argv):
    world.serve(json_reply([]))
    run = world.run(*argv)
    assert run.code == 2 and run.out == "" and run.err.strip()
    assert world.requests == []


def test_help_exits_0_prints_to_stdout_and_names_every_subcommand_without_a_request(
    world,
):
    run = world.run("--help")
    assert run.code == 0 and world.requests == []
    for name in SUBCOMMANDS:
        assert name in run.out, name
    for token in ("--quiet", "--verbose", "--live", "--fresh", "--timeout"):
        assert token in run.out


@pytest.mark.parametrize("command", [name for name in SUBCOMMANDS])
def test_each_subcommand_help_exits_0_on_stdout(world, command):
    run = world.run(command, "--help")
    assert run.code == 0 and run.out.strip() and world.requests == []


def test_globals_work_on_either_side_of_the_subcommand(world):
    world.serve_paths({"/feed.json": json_reply([ROW_PAYPAL])})
    for argv in (
        ("--quiet", "--fresh", "pulse", "--json"),
        ("pulse", "--quiet", "--fresh", "--json"),
    ):
        assert clean(world.run(*argv)).json()["count"] == 1


def test_session_attribute_is_read_at_call_time_and_the_real_session_is_locked_down(
    world,
):
    """Tests (and the console) REPLACE `Client.session`; every request must use the current value."""
    seen = []

    def other(request):
        seen.append(str(request.url))
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b"{}",
            request=request,
        )

    client = world.lj.Client()
    assert isinstance(client.session, httpx.Client)
    assert (
        client.session.trust_env is False and client.session.follow_redirects is False
    )
    client.session = api_client(
        world.lj.API_HOSTS, timeout=1, transport=httpx.MockTransport(other)
    )
    world.serve(json_reply({"from": "first"}))
    assert (
        client.get_json("/api/v1/x") == {}
        and seen == [f"{BASE}/api/v1/x"]
        and world.requests == []
    )


def test_client_is_looked_up_as_a_module_global_and_built_with_timeout_and_verbose_keywords(
    world,
):
    built = []

    class Spy(world.real_client):
        def __init__(self, *args, **kwargs):
            built.append((args, kwargs))
            super().__init__(*args, **kwargs)
            self.min_interval = 0

    world.mp.setattr(world.lj, "Client", Spy)
    world.serve_paths({"/feed.json": json_reply([])})
    clean(world.run("--quiet", "--timeout", "12", "--verbose", "pulse", "--json"))
    assert built == [((), {"timeout": 12.0, "verbose": True})]


def test_client_defaults_and_pacing_interval(world):
    client = world.real_client()
    assert client.timeout == 45.0 and client.verbose is False
    assert client.min_interval == pytest.approx(1 / 8)
    assert world.real_client(timeout=3, verbose=True).timeout == 3


# ---------------------------------------------------------------------------------------------
# B. Discovery: catalog entry, alias, option reader, catalog export, loader path  [C1, C3]
# ---------------------------------------------------------------------------------------------


def test_catalog_registers_phish_with_the_lanternjaw_alias_in_intel(world):
    tool = catalog.tool_by_command("phish")
    assert (tool.command, tool.folder, tool.script, tool.aliases) == (
        "phish",
        "Lanternjaw",
        "lanternjaw.py",
        ("lanternjaw",),
    )
    assert (
        tool.summary == "Read active phishing detections from the public phishunt feed."
    )
    assert (
        catalog.reference_canonical("lanternjaw") == "phish"
        and catalog.reference_canonical("phish") == "phish"
    )
    assert "phish" not in catalog.DISABLED_REFERENCES
    assert "phish" in dict(catalog.MODULE_GROUPS)["Intel"]


def test_default_addon_roots_locate_the_script_in_the_repo_addons_dir(monkeypatch):
    """D3 as filed in the spec (default roots missed `<repo>/addons`) is already FIXED at the base
    commit by the M0 quick-wins (#38); this pins the fixed behavior for the rebuild."""
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    found = catalog.locate_script(
        catalog.tool_by_command("phish"), Path(scanner.__file__).resolve()
    )
    assert found is not None and found.resolve() == DEFAULT_SCRIPT.resolve()


def catalog_rows(parser_spec: dict) -> list[tuple]:
    """The (subcommand, NAME, flags, kind, required, choices, default) rows the console flattening
    derives from the spec-3 parser table, in action order."""
    rows = []
    for dest, (flags, default, choices, nargs, kind) in parser_spec.items():
        if not flags:
            shown = ""
            rows.append(
                (dest.upper(), (), "positional", True, tuple(choices or ()), shown)
            )
        elif nargs == 0:
            rows.append((dest.upper(), flags, "bool", False, (), ""))
        else:
            rows.append(
                (
                    dest.upper(),
                    flags,
                    "value",
                    False,
                    tuple(choices or ()),
                    "" if default is None else str(default),
                )
            )
    return rows


def test_catalog_export_form_snapshot(world):
    world.mp.setenv("BUGHUNT_ADDONS", str(world.addons_root))
    data = export_catalog(
        tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    entry = next(
        module
        for phase in data["phases"]
        for module in phase["modules"]
        if module["name"] == "phish"
    )
    assert (
        entry["aliases"] == ["lanternjaw"]
        and entry["reference"] is True
        and entry["disabled"] is False
    )
    assert (
        entry["summary"]
        == "Read active phishing detections from the public phishunt feed."
    )
    assert (
        entry["when"] == "You want recent phishing detections from the phishunt feed."
    )
    form = entry["form"]
    assert form["command_name"] == "COMMAND"
    assert [row["name"] for row in form["subcommands"]] == list(SUBCOMMANDS)
    got = [
        (
            o["subcommand"],
            o["name"],
            tuple(o["flags"]),
            o["kind"],
            o["required"],
            tuple(o["choices"]),
            o["default"],
        )
        for o in form["options"]
    ]
    expected = [("", *row) for row in catalog_rows(GLOBAL_PARSER)]
    for command in SUBCOMMANDS:
        expected += [(command, *row) for row in catalog_rows(EXPECTED_PARSER[command])]
    expected.append(("", "COMMAND", (), "positional", True, tuple(SUBCOMMANDS), ""))
    assert len(got) == 177
    assert got == expected
    by_name = {(o[0], o[1]): o for o in got}
    assert (
        by_name[("", "TIMEOUT")][6] == "45.0" and by_name[("hunt", "LIMIT")][6] == "25"
    )
    assert (
        by_name[("deep", "TOKEN")][3] == "value"
        and by_name[("deep", "YES")][3] == "bool"
    )
    assert {
        o[0] for o in got if o[1] in ("QUIET", "VERBOSE", "LIVE", "FRESH", "TIMEOUT")
    } == {""}


def test_catalog_form_is_available_with_the_default_addon_roots_d3_is_fixed_at_base(
    world, monkeypatch
):
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    data = export_catalog(
        tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    entry = next(
        module
        for phase in data["phases"]
        for module in phase["modules"]
        if module["name"] == "phish"
    )
    assert entry["form"] is not None and not entry.get("unavailable")


def test_saved_console_options_render_to_argv_for_subcommand_options(world):
    world.mp.setenv("BUGHUNT_ADDONS", str(world.addons_root))
    spec = options.load_spec(
        "phish", tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    parser = world.lj.build_parser()
    for settings in (
        {"COMMAND": "hunt", "JSON": "true", "COMPANY": "paypal", "LIMIT": "5"},
        {"COMMAND": "pivot", "FIELD": "asn", "MIN_COUNT": "3"},
        {
            "COMMAND": "deep",
            "URL": "https://allowed.example/x",
            "TOKEN": "t",
            "YES": "true",
        },
        {"COMMAND": "about"},
    ):
        argv = options.render_argv(spec, settings, [])
        assert parser.parse_args(argv).command == settings["COMMAND"], argv


def test_alias_resolves_to_the_same_module_for_the_option_reader(world):
    world.mp.setenv("BUGHUNT_ADDONS", str(world.addons_root))
    first = options.load_spec(
        "phish", tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    second = options.load_spec(
        "lanternjaw",
        tool_file=Path(scanner.__file__),
        build_parser=scanner.build_parser,
    )
    assert first == second and len(first.options) == 177


@pytest.mark.parametrize("name", ["phish", "lanternjaw"])
def test_loader_runs_the_program_under_either_name(world, name):
    run, console = world.via_loader(name, "--quiet", "self-test")
    assert run.code == 0 and run.out.strip() == "lanternjaw self-test ok"
    assert world.requests == []


def test_loader_maps_exit_codes(world):
    world.serve_paths({"/feed.json": json_reply(FEED)})
    assert world.via_loader("phish", "--quiet", "about")[0].code == 0
    assert world.via_loader("phish")[0].code == 2
    assert world.via_loader("phish", "bogus")[0].code == 2
    assert (
        world.via_loader("phish", "--quiet", "match", "no-such-file.txt")[0].code == 1
    )
    run, _console = world.via_loader("phish", "--quiet", "related", "not-a-uuid")
    assert run.code == 2 and world.requests == []


def test_loader_ctrl_c_is_exit_130(world):
    world.serve(handler=lambda request: KeyboardInterrupt())
    run, _console = world.via_loader("phish", "--quiet", "brand", "paypal")
    assert run.code == 130


def test_loader_prints_an_escaped_policy_block_and_returns_2_when_main_raises_it(world):
    """`egress.PolicyBlocked` escaping `main` (e.g. at client construction) is the loader's rc 2."""
    world.workspace(policy=False)
    world.load()

    def refuse(*args, **kwargs):
        from bughunt.core import egress

        raise egress.PolicyBlocked("policy-missing-or-invalid; no outbound action ran")

    world.mp.setattr(core_http, "api_client", refuse)
    world.load()
    run, console = world.via_loader("phish", "--quiet", "brand", "paypal")
    assert run.code == 2 and "policy-missing-or-invalid" in (
        console + run.err + run.out
    )
    assert world.requests == []


# ---------------------------------------------------------------------------------------------
# C. main(): order of operations, exit codes, banner matrix, JSON error line  [C3]
# ---------------------------------------------------------------------------------------------

BRAND_PATH = "/api/v1/brands/paypal.json"


def serve_brand(world, reply=None):
    world.serve_paths({BRAND_PATH: reply or json_reply(BRAND_PAYLOAD)})


def banner_text(world, *argv) -> str:
    """The stderr text a run prints BEFORE its own output: run with and without --quiet and diff.
    The banner art is FREE, so only its presence/absence is pinned."""
    loud = world.run(*argv)
    quiet = world.run("--quiet", *argv)
    assert loud.exc is None and quiet.exc is None
    assert loud.out == quiet.out, "--quiet must not change stdout"
    assert loud.err.endswith(quiet.err), (loud.err[-200:], quiet.err[-200:])
    return loud.err[: len(loud.err) - len(quiet.err)]


def test_banner_goes_to_stderr_unless_quiet_json_or_self_test(world):
    world.serve_paths(
        {BRAND_PATH: json_reply(BRAND_PAYLOAD), "/feed.json": json_reply(FEED)}
    )
    assert banner_text(world, "about").strip(), "about prints a banner"
    assert banner_text(world, "brand", "paypal").strip(), (
        "a text-mode command prints a banner"
    )
    assert banner_text(world, "--fresh", "pulse").strip()
    assert not banner_text(world, "brand", "paypal", "--json").strip(), (
        "--json suppresses the banner"
    )
    assert not banner_text(world, "--fresh", "pulse", "--json").strip()
    assert not banner_text(world, "self-test").strip(), (
        "self-test never prints a banner"
    )


def test_banner_never_reaches_stdout(world):
    run = clean(world.run("about"))
    assert run.out == ""


def test_the_banner_names_the_tool_and_version(world):
    banner = banner_text(world, "about")
    assert "1.0.0" in banner


def test_quiet_suppresses_only_the_banner(world):
    serve_brand(world)
    loud = clean(world.run("brand", "paypal"))
    quiet = clean(world.run("--quiet", "brand", "paypal"))
    assert "PayPal" in quiet.err and "PayPal" in loud.err
    assert len(loud.err) > len(quiet.err)


def test_exit_code_is_a_plain_int_on_success(world):
    run = clean(world.run("--quiet", "about"))
    assert type(run.code) is int


def test_main_without_argv_reads_sys_argv(world, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["lanternjaw.py", "--quiet", "self-test"])
    code = world.lj.main()
    out, _err = world.capsys.readouterr()
    assert code == 0 and out.strip() == "lanternjaw self-test ok"


def test_state_does_not_leak_between_runs_json_and_live(world):
    world.serve_paths({"/feed.json": json_reply([ROW_PAYPAL])})
    clean(world.run("--quiet", "--live", "pulse", "--json"))
    after = clean(world.run("--quiet", "hunt", "--values"))
    assert after.out == "hxxps://paypal-login1[.]example[.]net/signin/verify\n"
    live = clean(world.run("--quiet", "--live", "hunt", "--values"))
    assert live.out == "https://paypal-login1.example.net/signin/verify\n"
    chatty = clean(world.run("--quiet", "hunt"))
    assert "feed" in chatty.err, (
        "after a --json run the next text run prints its notices again"
    )


@pytest.mark.parametrize(
    "status,code",
    [(400, 2), (404, 2), (401, 1), (403, 1), (422, 1), (500, 1), (502, 1), (429, 1)],
)
def test_http_error_status_maps_to_exit_code(world, status, code):
    serve_brand(
        world,
        json_reply(
            {"error": "denied by upstream"},
            status=status,
            headers={"retry-after": "9999"},
        ),
    )
    run = world.run("--quiet", "brand", "paypal")
    assert run.exc is None and run.code == code
    assert f"HTTP {status}" in run.etext and "denied by upstream" in run.etext
    assert run.out == ""


def test_error_is_a_json_line_on_stderr_in_json_mode_and_stdout_stays_empty(world):
    serve_brand(world, json_reply({"error": "no such brand"}, status=404))
    run = world.run("--quiet", "brand", "paypal", "--json")
    assert run.code == 2 and run.out == ""
    line = run.error_line()
    assert (
        set(line) == {"error", "status"}
        and line["status"] == 404
        and "no such brand" in line["error"]
    )
    assert "HTTP 404" in line["error"]


def test_error_json_line_has_a_null_status_for_non_http_failures(world):
    serve_brand(world, text_reply("<html>", ctype="text/html"))
    run = world.run("--quiet", "brand", "paypal", "--json")
    assert run.code == 1 and run.out == ""
    line = run.error_line()
    assert line["status"] is None and "invalid JSON" in line["error"]


def test_error_text_mode_has_no_json_line(world):
    serve_brand(world, json_reply({"error": "no such brand"}, status=404))
    run = world.run("--quiet", "brand", "paypal")
    assert run.code == 2 and "no such brand" in run.err
    assert not run.err.strip().startswith("{")


def test_banner_is_printed_before_an_error_in_text_mode(world):
    serve_brand(world, json_reply({"error": "no such brand"}, status=404))
    assert banner_text(world, "brand", "paypal").strip()


@pytest.mark.parametrize(
    "argv",
    [("brand", "paypal"), ("pulse",), ("hunt", "--company", "paypal"), ("campaigns",)],
)
def test_ctrl_c_exits_130_with_a_stop_notice(world, argv):
    world.serve(handler=lambda request: KeyboardInterrupt())
    run = world.run("--quiet", *argv)
    assert run.code == 130 and run.exc is None
    assert "stopped" in run.etext.lower()


def test_phishunt_error_status_other_than_400_404_is_exit_1_including_network_failures(
    world,
):
    world.serve(handler=lambda request: httpx.ConnectError("no route"))
    run = world.run("--quiet", "brand", "paypal")
    assert run.code == 1 and "network error talking to phishunt" in run.etext
    assert world.slept == pytest.approx([1.2, 2.4, 3.6])


# ---------------------------------------------------------------------------------------------
# D. Client.request: path rule, retries, 429, redirects, headers, timeouts  [C4, C22]
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["https://evil.example/", "nopath", "", "api/v1/x", "phishunt.io/x"]
)
def test_request_rejects_a_path_that_does_not_start_with_a_slash_and_sends_nothing(
    world, path
):
    world.serve(json_reply({}))
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request(path)
    assert caught.value.status == 400 and world.requests == []


def test_request_builds_the_url_from_base_plus_path_and_returns_the_response(world):
    world.serve(json_reply({"ok": 1}))
    response = world.lj.Client().request("/api/v1/x")
    assert isinstance(response, httpx.Response) and response.status_code == 200
    assert world.urls == [f"{BASE}/api/v1/x"] and world.requests[0].method == "GET"


def test_request_drops_none_and_empty_params_but_keeps_zero_and_false_in_order(world):
    world.serve(json_reply({}))
    world.lj.Client().request(
        "/p", {"a": None, "b": "", "c": 0, "d": False, "e": "x y", "f": 3}
    )
    assert world.query_keys() == ["c", "d", "e", "f"]
    assert world.params() == {"c": "0", "d": "false", "e": "x y", "f": "3"}


def test_request_with_only_dropped_params_sends_no_query(world):
    world.serve(json_reply({}))
    world.lj.Client().request("/p", {"a": None, "b": ""})
    assert world.urls == [f"{BASE}/p"]


def test_get_json_parses_and_rejects_invalid_json(world):
    world.serve(json_reply({"a": [1, 2]}))
    assert world.lj.Client().get_json("/x") == {"a": [1, 2]}
    world.serve(text_reply("not json"))
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().get_json("/x")
    assert "invalid JSON from" in str(caught.value) and caught.value.status is None
    world.serve(text_reply(""))
    with pytest.raises(world.lj.PhishuntError):
        world.lj.Client().get_json("/x")


def test_get_text_returns_utf8_text_and_the_response(world):
    world.serve(text_reply("café\nnext\n"))
    text, response = world.lj.Client().get_text("/x")
    assert text == "café\nnext\n" and isinstance(response, httpx.Response)


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ConnectError("no route"),
        httpx.ReadTimeout("slow"),
        httpx.RemoteProtocolError("bad"),
    ],
)
def test_transport_failures_are_retried_four_times_then_a_network_error(world, failure):
    world.serve(handler=lambda request: failure)
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/x")
    assert (
        str(caught.value).startswith("network error talking to phishunt:")
        and caught.value.status is None
    )
    assert len(world.requests) == 4 and world.slept == pytest.approx([1.2, 2.4, 3.6])


def test_a_transient_failure_then_success_returns_the_response(world):
    world.serve_sequence(
        [httpx.ConnectError("a"), httpx.ConnectError("b"), json_reply({"ok": True})]
    )
    assert world.lj.Client().get_json("/x") == {"ok": True}
    assert len(world.requests) == 3 and world.slept == [1.2, 2.4]


def test_5xx_is_retried_on_attempts_one_to_three_then_raised_on_the_fourth(world):
    world.serve(text_reply("upstream down", status=503))
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/x")
    assert (
        caught.value.status == 503
        and "HTTP 503" in str(caught.value)
        and "upstream down" in str(caught.value)
    )
    assert len(world.requests) == 4 and world.slept == pytest.approx([1.2, 2.4, 3.6])


def test_5xx_then_success(world):
    world.serve_sequence([text_reply("x", status=500), json_reply({"ok": 1})])
    assert world.lj.Client().get_json("/x") == {"ok": 1}
    assert len(world.requests) == 2 and world.slept == [1.2]


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410, 422])
def test_4xx_other_than_429_is_raised_at_once_without_retry_or_sleep(world, status):
    world.serve(json_reply({"error": "nope"}, status=status))
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/x")
    assert caught.value.status == status and caught.value.payload == {"error": "nope"}
    assert len(world.requests) == 1 and world.slept == []


def test_3xx_without_a_location_is_returned_as_a_success(world):
    world.serve((304, {}, b""))
    assert world.lj.Client().request("/x").status_code == 304
    assert len(world.requests) == 1


def test_429_with_a_numeric_retry_after_header_sleeps_that_long_and_prints_a_notice(
    world, capsys
):
    world.serve_sequence(
        [
            text_reply("slow down", status=429, headers={"retry-after": "7"}),
            json_reply({"ok": 1}),
        ]
    )
    assert world.lj.Client().get_json("/x") == {"ok": 1}
    assert world.slept == [7.0] and len(world.requests) == 2
    assert "429" in capsys.readouterr().err


def test_429_with_a_retry_after_in_the_json_body_uses_it(world):
    world.serve_sequence(
        [json_reply({"retry_after": 5}, status=429), json_reply({"ok": 1})]
    )
    world.lj.Client().get_json("/x")
    assert world.slept == [5.0]


def test_the_retry_after_header_wins_over_the_body_value(world):
    world.serve_sequence(
        [
            json_reply({"retry_after": 5}, status=429, headers={"retry-after": "3"}),
            json_reply({}),
        ]
    )
    world.lj.Client().get_json("/x")
    assert world.slept == [3.0]


def test_429_without_a_hint_backs_off_1_2_4_seconds_then_raises_on_the_fourth_attempt(
    world,
):
    world.serve(text_reply("busy", status=429))
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/x")
    assert caught.value.status == 429 and len(world.requests) == 4
    assert world.slept == [1.0, 2.0, 4.0]


def test_an_http_date_retry_after_is_not_parsed_and_falls_back_to_the_exponential_rule(
    world,
):
    world.serve_sequence(
        [
            text_reply(
                "busy",
                status=429,
                headers={"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"},
            ),
            json_reply({}),
        ]
    )
    world.lj.Client().get_json("/x")
    assert world.slept == [1.0]


@pytest.mark.parametrize(
    "wait,raises", [("90", False), ("91", True), ("3600", True), ("90.5", True)]
)
def test_429_waits_longer_than_90_seconds_are_raised_without_sleeping(
    world, wait, raises
):
    world.serve_sequence(
        [
            json_reply(
                {"error": "budget gone", "budget": {"used": 50}},
                status=429,
                headers={"retry-after": wait},
            ),
            json_reply({}),
        ]
    )
    if raises:
        with pytest.raises(world.lj.PhishuntError) as caught:
            world.lj.Client().request("/x")
        assert (
            caught.value.status == 429
            and world.slept == []
            and len(world.requests) == 1
        )
        assert "budget gone" in str(caught.value) and "budget=" in str(caught.value)
    else:
        world.lj.Client().request("/x")
        assert world.slept == [90.0]


def test_http_message_shape_for_json_errors_and_budget_suffix(world):
    world.serve(
        json_reply(
            {"error": "limit", "message": "ignored", "budget": 50, "retry_after": 4000},
            status=429,
        )
    )
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/x")
    message = str(caught.value)
    assert (
        message.startswith("HTTP 429")
        and "limit" in message
        and "ignored" not in message
    )
    assert "budget=50" in message and "retry_after=4000s" in message


def test_http_message_uses_the_message_key_when_there_is_no_error_key(world):
    world.serve(json_reply({"message": "bad parameter"}, status=400))
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/x")
    assert "HTTP 400" in str(caught.value) and "bad parameter" in str(caught.value)


def test_http_message_falls_back_to_the_first_180_characters_of_the_body_with_newlines_flattened(
    world,
):
    body = "line one\nline two " + "x" * 400
    world.serve(text_reply(body, status=400))
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/x")
    message = str(caught.value)
    assert "line one line two" in message and "\n" not in message
    assert ("line one line two " + "x" * 162) in message and (
        "line one line two " + "x" * 163
    ) not in message, "cut at 180 characters"


def test_a_json_looking_body_that_does_not_parse_is_treated_as_text(world):
    world.serve(text_reply("{broken json", status=400))
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/x")
    assert "{broken json" in str(caught.value) and caught.value.payload is None


def test_a_403_with_an_empty_body_carries_a_user_agent_hint(world):
    world.serve((403, {}, b""))
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/x")
    assert (
        caught.value.status == 403
        and "403" in str(caught.value)
        and "User-Agent" in str(caught.value)
    )


def test_a_403_with_a_body_shows_the_body_not_the_hint(world):
    world.serve(text_reply("blocked by edge", status=403))
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/x")
    assert "blocked by edge" in str(caught.value) and "User-Agent" not in str(
        caught.value
    )


# -- redirects (host AND policy are checked on every hop) ------------------------------------


def redirect_to(location, status=302):
    return (status, {"location": location}, b"")


def test_a_same_host_redirect_is_followed_params_ride_the_first_request_only_and_headers_ride_every_hop(
    world,
):
    def handler(request):
        if request.url.path == "/start":
            return redirect_to("/landed")
        return json_reply({"ok": 1})

    world.serve(handler=handler)
    client = world.lj.Client()
    assert client.get_json("/start", {"q": "1"}, headers={"X-Probe": "yes"}) == {
        "ok": 1
    }
    assert world.paths == ["/start", "/landed"]
    assert (
        world.requests[0].url.params["q"] == "1"
        and "q" not in world.requests[1].url.params
    )
    assert [r.headers["x-probe"] for r in world.requests] == ["yes", "yes"]


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/feed.json",
        "https://phishunt.io.evil.example/feed.json",
        "https://notphishunt.io/feed.json",
        "http://127.0.0.1/feed.json",
        "https://evil.example@phishunt.io.evil.example/",
    ],
)
def test_off_host_redirects_are_never_requested_and_are_not_retried(world, target):
    world.serve_paths({"/feed.json": redirect_to(target)})
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/feed.json")
    assert (
        "refusing to follow a redirect off phishunt.io" in str(caught.value)
        and caught.value.status is None
    )
    assert world.urls == [f"{BASE}/feed.json"] and world.slept == []


def test_a_redirect_to_a_second_hop_off_host_is_stopped_at_that_hop(world):
    def handler(request):
        return (
            redirect_to("/two")
            if request.url.path == "/one"
            else redirect_to("https://evil.example/three")
        )

    world.serve(handler=handler)
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/one")
    assert "refusing to follow a redirect" in str(caught.value)
    assert world.paths == ["/one", "/two"] and "evil.example" not in " ".join(
        world.urls
    )


def test_the_redirect_chain_is_capped_at_five_hops_and_the_last_response_is_returned(
    world,
):
    world.serve(handler=lambda request: redirect_to("/again"))
    response = world.lj.Client().request("/go")
    assert response.status_code == 302 and len(world.requests) == 6
    assert world.slept == []


def test_a_redirect_to_a_subdomain_the_policy_admits_fails_the_final_host_check(world):
    world.workspace(
        mutate=lambda document: document["assets"].append(
            {
                "id": "asset-cdn",
                "origin": "https://cdn.phishunt.io",
                "paths": ["/"],
                "operations": list(document["permissions"]),
                "methods": ["GET"],
            }
        )
    )
    world.load()
    world.serve_paths(
        {
            "/start": redirect_to("https://cdn.phishunt.io/landed"),
            "/landed": json_reply({"ok": 1}),
        }
    )
    with pytest.raises(world.lj.PhishuntError) as caught:
        world.lj.Client().request("/start")
    assert "refusing to follow a redirect off phishunt.io" in str(
        caught.value
    ) and "cdn.phishunt.io" in str(caught.value)
    assert [r.url.host for r in world.requests] == ["phishunt.io", "cdn.phishunt.io"]


def test_a_redirect_to_www_is_accepted_when_the_policy_has_an_asset_for_it(world):
    world.workspace(
        mutate=lambda document: document["assets"].append(
            {
                "id": "asset-www",
                "origin": "https://www.phishunt.io",
                "paths": ["/"],
                "operations": list(document["permissions"]),
                "methods": ["GET"],
            }
        )
    )
    world.load()
    world.serve_paths(
        {
            "/start": redirect_to("https://www.phishunt.io/landed"),
            "/landed": json_reply({"ok": 1}),
        }
    )
    assert world.lj.Client().get_json("/start") == {"ok": 1}
    assert [r.url.host for r in world.requests] == ["phishunt.io", "www.phishunt.io"]


def test_a_redirect_hop_the_policy_does_not_admit_is_never_sent(world):
    """Per-hop POLICY check: the second hop (www., no asset) is denied before the transport."""
    world.serve_paths({"/start": redirect_to("https://www.phishunt.io/landed")})
    with pytest.raises(world.lj.PhishuntError):
        world.lj.Client().request("/start")
    assert all(request.url.host == "phishunt.io" for request in world.requests)
    assert "www.phishunt.io" not in " ".join(world.urls)


# -- verbose, headers, timeouts, pacing -----------------------------------------------------


def test_verbose_prints_one_get_line_per_response_on_stderr(world):
    world.serve_sequence([text_reply("x", status=500), json_reply({})])
    world.lj.Client(verbose=True).request("/x")
    err = world.capsys.readouterr().err
    assert (
        "GET 500 https://phishunt.io/x" in err
        and "GET 200 https://phishunt.io/x" in err
    )
    world.serve(json_reply({}))
    world.lj.Client().request("/x")
    assert "GET 200" not in world.capsys.readouterr().err


def test_verbose_flag_flows_from_the_command_line(world):
    serve_brand(world)
    run = clean(world.run("--quiet", "--verbose", "brand", "paypal"))
    assert f"GET 200 {BASE}{BRAND_PATH}" in run.etext
    assert "GET 200" not in clean(world.run("--quiet", "brand", "paypal")).err


def read_timeout(request) -> float:
    return request.extensions["timeout"]["read"]


@pytest.mark.parametrize(
    "argv,expected",
    [
        (("brand", "paypal"), 45.0),
        (("--timeout", "7", "brand", "paypal"), 7.0),
    ],
)
def test_default_timeout_is_the_timeout_flag_applied_to_every_phase(
    world, argv, expected
):
    serve_brand(world)
    clean(world.run("--quiet", *argv))
    timeouts = world.requests[0].extensions["timeout"]
    assert set(timeouts) == {"connect", "read", "write", "pool"} and set(
        timeouts.values()
    ) == {expected}


@pytest.mark.parametrize(
    "argv,path,reply,expected",
    [
        (("feed", "json"), "/feed.json", json_reply([]), 90.0),
        (("--timeout", "5", "feed", "json"), "/feed.json", json_reply([]), 90.0),
        (("feed", "csv"), "/feed.csv", text_reply("a\n"), 90.0),
        (("feed", "stix"), "/stix/bundle.json", json_reply({}), 90.0),
        (("blocklist", "domains"), "/blocklist/domains.txt", text_reply("a\n"), 90.0),
        (("--timeout", "5", "pulse"), "/feed.json", json_reply([]), 90.0),
    ],
)
def test_full_feeds_and_blocklists_use_a_90_second_timeout(
    world, argv, path, reply, expected
):
    world.serve_paths({path: reply})
    clean(
        world.run("--quiet", *argv, "--json")
        if argv[0] in ("feed", "blocklist")
        else world.run("--quiet", *argv)
    )
    assert read_timeout(world.requests[0]) == expected


def test_wire_headers_policy_profile_replaces_the_user_agent_and_the_addon_accept_survives(
    world,
):
    serve_brand(world)
    clean(world.run("--quiet", "brand", "paypal"))
    request = world.requests[0]
    assert (
        request.method == "GET"
        and request.content == b""
        and request.url.scheme == "https"
    )
    assert request.headers["user-agent"] == PROFILE_UA, (
        "the policy profile overwrites the requested UA"
    )
    assert request.headers["x-researcher"] == "owned-lab", (
        "profile-required headers are added"
    )
    assert request.headers["accept"] == ADDON_ACCEPT
    assert "gzip" in request.headers["accept-encoding"]
    for forbidden in ("authorization", "cookie", "x-phishunt-deep-token"):
        assert forbidden not in request.headers


def test_pacing_waits_for_the_interval_between_attempts_of_one_client(world):
    world.serve(json_reply({}))
    client = world.real_client()
    client.min_interval = 1000.0
    client.request("/a")
    assert world.slept == []
    client.request("/b")
    assert len(world.slept) == 1 and 900 < world.slept[0] <= 1000


def test_min_interval_is_read_at_request_time(world):
    world.serve(json_reply({}))
    client = world.real_client()
    client.min_interval = 0
    client.request("/a")
    client.request("/b")
    assert world.slept == []


# ---------------------------------------------------------------------------------------------
# E. The active-feed cache  [C5]
# ---------------------------------------------------------------------------------------------


def test_a_cache_miss_fetches_feed_json_and_writes_the_cache_envelope(fed):
    run = clean(fed.run("--quiet", "hunt", "--limit", "1"))
    assert fed.urls == [f"{BASE}/feed.json"]
    envelope = json.loads(fed.cache_file.read_text("utf-8"))
    assert (
        set(envelope) == {"saved_at", "count", "sites"}
        and envelope["count"] == 6
        and envelope["sites"] == FEED
    )
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", envelope["saved_at"])
    assert re.search(r"\b6\b", run.err), (
        "the row count of a fetch is reported (text mode only)"
    )
    assert not fed.cache_file.with_suffix(".tmp").exists(), (
        "written to a .tmp sibling and replaced"
    )
    assert (
        clean(fed.run("--quiet", "hunt", "--json", "--all")).json()
        == FEED_BY_FIRST_SEEN
    )
    assert len(fed.requests) == 1, "the second run is a cache hit"


def test_notices_are_text_mode_only_json_mode_keeps_stderr_quiet(fed):
    assert clean(fed.run("--quiet", "hunt", "--json")).err == ""
    fed.cache_file.unlink()
    assert clean(fed.run("--quiet", "--fresh", "hunt", "--json")).err == ""


def test_a_fresh_cache_is_a_hit_with_no_request_and_a_notice_with_count_and_age(fed):
    clean(fed.run("--quiet", "hunt", "--json"))
    fed.requests.clear()
    fed.cache_rows(FEED, age=42)
    assert (
        clean(fed.run("--quiet", "hunt", "--json", "--all")).json()
        == FEED_BY_FIRST_SEEN
    )
    run = clean(fed.run("--quiet", "hunt", "--limit", "1"))
    assert fed.requests == []
    assert (
        re.search(r"\b6\b", run.err)
        and re.search(r"\b4[2-9]\b", run.err)
        and "--fresh" in run.err
    )


def test_fresh_flag_skips_the_read_but_still_rewrites_the_cache(fed):
    fed.cache_rows([ROW_PAYPAL])
    run = clean(fed.run("--quiet", "--fresh", "hunt", "--json", "--all"))
    assert len(fed.requests) == 1 and len(run.json()) == 6
    assert json.loads(fed.cache_file.read_text("utf-8"))["count"] == 6


@pytest.mark.parametrize(
    "age,hit", [(10, True), (590, True), (601, False), (700, False), (86400, False)]
)
def test_cache_expires_after_600_seconds(fed, age, hit):
    fed.cache_rows([ROW_PAYPAL], age=age)
    run = clean(fed.run("--quiet", "hunt", "--json"))
    assert (len(fed.requests) == 0) is hit
    assert len(run.json()) == (1 if hit else 6)


@pytest.mark.parametrize(
    "content",
    ["not json{", "", '{"sites": "nope"}', '{"foo": 1}', '"a string"', "null", "42"],
)
def test_a_corrupt_or_non_list_cache_is_ignored_and_refetched(fed, content):
    fed.cache_file.parent.mkdir(parents=True)
    fed.cache_file.write_text(content, encoding="utf-8")
    run = clean(fed.run("--quiet", "hunt", "--json"))
    assert len(fed.requests) == 1 and len(run.json()) == 6
    assert json.loads(fed.cache_file.read_text("utf-8"))["count"] == 6


def test_a_bare_array_cache_is_accepted(fed):
    fed.cache_file.parent.mkdir(parents=True)
    fed.cache_file.write_text(json.dumps([ROW_PAYPAL, ROW_PAGES]), encoding="utf-8")
    run = clean(fed.run("--quiet", "hunt", "--json"))
    assert fed.requests == [] and [row["uuid"] for row in run.json()] == [
        uid(2),
        uid(1),
    ]


def test_a_feed_that_is_not_an_array_is_an_error_and_writes_no_cache(world):
    world.serve_paths({"/feed.json": json_reply({"sites": []})})
    run = world.run("--quiet", "pulse")
    assert run.code == 1 and "not a JSON array" in run.etext
    assert not world.cache_file.exists()


def test_a_cache_write_failure_is_a_warning_not_an_error(fed):
    fed.cache_file.parent.parent.mkdir(parents=True, exist_ok=True)
    fed.cache_file.parent.write_text("i am a file, not a directory", encoding="utf-8")
    run = clean(fed.run("--quiet", "hunt", "--limit", "1"))
    assert "cache" in run.err.lower() and "could not" in run.err.lower()
    assert len(clean(fed.run("--quiet", "hunt", "--json")).json()) == 6


def test_the_cache_lives_under_xdg_cache_home_or_dot_cache_in_the_home_directory(fed):
    clean(fed.run("--quiet", "pulse", "--json"))
    assert fed.cache_file.is_file() and fed.cache_file.parent.name == "lanternjaw"
    fed.cache_file.unlink()
    fed.mp.delenv("XDG_CACHE_HOME")
    clean(fed.run("--quiet", "pulse", "--json"))
    assert (fed.home / ".cache" / "lanternjaw" / "feed.json").is_file()
    assert (
        not (fed.workspace_dir / "lanternjaw").exists()
        and list(fed.cwd.iterdir()) == []
    )


def test_the_cache_is_utf8_and_round_trips_non_ascii_rows(world):
    row = {**ROW_PAYPAL, "org": "Caf\u00e9 \u4e2d\u6587 GmbH"}
    world.serve_paths({"/feed.json": json_reply([row])})
    clean(world.run("--quiet", "pulse", "--json"))
    assert json.loads(world.cache_file.read_bytes().decode("utf-8"))["sites"] == [row]
    world.requests.clear()
    assert clean(world.run("--quiet", "hunt", "--json")).json() == [row]
    assert world.requests == []


def test_feed_json_does_not_read_or_write_the_cache(fed):
    fed.cache_rows([ROW_PAYPAL])
    before = fed.cache_file.read_bytes()
    run = clean(fed.run("--quiet", "feed", "json", "--json"))
    assert len(fed.requests) == 1 and run.json() == FEED
    assert fed.cache_file.read_bytes() == before


CACHE_USERS = [  # commands that take the unfiltered active feed from the cache when it is fresh
    ("pulse", "--json"),
    ("hunt", "--json"),
    ("triage", "--json"),
    ("pivot", "ip", "--json"),
    ("report",),
    ("inspect", uid(1), "--skip-related", "--skip-enrich", "--json"),
    ("snapshot", "--out", "snap.json"),
]


@pytest.mark.parametrize("argv", CACHE_USERS, ids=[argv[0] for argv in CACHE_USERS])
def test_commands_over_the_unfiltered_feed_share_one_cache(world, argv):
    world.cache_rows(FEED)
    world.serve(
        handler=lambda request: AssertionError("the cache should have answered")
    )
    clean(world.run("--quiet", *argv))
    assert world.requests == []


def test_match_reads_the_cache_too(world, tmp_path):
    world.cache_rows(FEED)
    indicators = tmp_path / "ind.txt"
    indicators.write_text("paypal-login1.example.net\n", encoding="utf-8")
    clean(world.run("--quiet", "match", str(indicators), "--json"))
    assert world.requests == []


# ---------------------------------------------------------------------------------------------
# F. Server parameters, gather(), paging  [C6]
# ---------------------------------------------------------------------------------------------


def many_rows(count: int, start: int = 0, **extra):
    return [
        {
            "uuid": uid(100000 + start + index),
            "domain": f"d{start + index}.example",
            "company": "paypal",
            "first_seen": f"2026-10-{1 + (start + index) % 28:02d}T00:00:00Z",
            "score": (start + index) % 100,
            **extra,
        }
        for index in range(count)
    ]


def domains_page(rows, total=None):
    return json_reply({"results": rows, "total": len(rows) if total is None else total})


def serve_domains(world, handler_or_reply):
    world.serve_paths({"/api/v1/domains": handler_or_reply})


ALL_SERVER_FLAGS = (
    "--company",
    " PayPal ",
    "--since",
    "2026-10-01",
    "--contains",
    "lo gin!!",
    "--tier",
    "verified",
    "--asn",
    "AS13335",
    "--org",
    "Cloudflare, Inc.",
    "--registrar",
    "Reg Inc",
    "--cert",
    "R3",
    "--country",
    "Germany",
    "--ip",
    "203.0.113.2",
)


def test_server_params_ride_the_wire_in_the_documented_order_with_normalized_values(
    world,
):
    serve_domains(world, domains_page([]))
    clean(world.run("--quiet", "hunt", "--json", *ALL_SERVER_FLAGS))
    assert world.paths == ["/api/v1/domains"]
    assert world.query_keys() == [
        "company",
        "since",
        "contains",
        "tier",
        "asn",
        "org",
        "registrar",
        "cert",
        "country",
        "ip",
        "limit",
        "offset",
    ]
    assert world.params() == {
        "company": "paypal",
        "since": "2026-10-01",
        "contains": "login",
        "tier": "verified",
        "asn": "13335",
        "org": "Cloudflare, Inc.",
        "registrar": "Reg Inc",
        "cert": "R3",
        "country": "Germany",
        "ip": "203.0.113.2",
        "limit": "1000",
        "offset": "0",
    }


@pytest.mark.parametrize(
    "given,sent", [("AS13335", "13335"), ("as7", "7"), ("13335", "13335"), ("ASX", "X")]
)
def test_asn_loses_a_leading_as_prefix(world, given, sent):
    serve_domains(world, domains_page([]))
    clean(world.run("--quiet", "hunt", "--json", "--asn", given))
    assert world.params()["asn"] == sent


@pytest.mark.parametrize(
    "given,sent",
    [
        ("lo gin!!", "login"),
        ("a-b_c.d9", "a-b_c.d9"),
        ("pay/pal?x=1", "paypalx1"),
        ("abc", "abc"),
    ],
)
def test_contains_keeps_only_letters_digits_dot_underscore_dash(world, given, sent):
    serve_domains(world, domains_page([]))
    clean(world.run("--quiet", "hunt", "--json", "--contains", given))
    assert world.params()["contains"] == sent


@pytest.mark.parametrize("given", ["ab", "!!!", "a" * 81, "a b"])
def test_contains_outside_3_to_80_characters_is_a_400_error_with_no_request(
    world, given
):
    serve_domains(world, domains_page([]))
    run = world.run("--quiet", "hunt", "--json", "--contains", given)
    assert run.code == 2 and "--contains" in run.etext and world.requests == []


def test_contains_at_the_bounds_is_accepted(world):
    serve_domains(world, domains_page([]))
    clean(world.run("--quiet", "hunt", "--json", "--contains", "a" * 80))
    clean(world.run("--quiet", "hunt", "--json", "--contains", "abc"))


def test_a_single_page_under_1000_rows_is_one_request_and_is_filtered_and_sorted_locally(
    world,
):
    rows = many_rows(30)
    serve_domains(world, domains_page(rows))
    run = clean(
        world.run(
            "--quiet",
            "hunt",
            "--json",
            "--company",
            "paypal",
            "--limit",
            "5",
            "--sort",
            "score",
        )
    )
    assert len(world.requests) == 1
    assert [row["score"] for row in run.json()] == [29, 28, 27, 26, 25]


def test_paging_collects_1000_row_pages_until_the_total_is_reached(world):
    rows = many_rows(1500)

    def handler(request):
        offset = int(request.url.params["offset"])
        return json_reply({"results": rows[offset : offset + 1000], "total": 1500})

    serve_domains(world, handler)
    run = clean(world.run("--quiet", "hunt", "--json", "--company", "paypal", "--all"))
    assert [dict(r.url.params)["offset"] for r in world.requests] == ["0", "1000"]
    assert [dict(r.url.params)["limit"] for r in world.requests] == ["1000", "1000"]
    assert len(run.json()) == 1500
    assert (
        "feed json"
        not in clean(
            world.run("--quiet", "hunt", "--company", "paypal", "--limit", "1")
        ).etext
    )


def test_paging_de_duplicates_by_uuid_and_keeps_rows_without_a_uuid(world):
    page_one = many_rows(1000)
    page_two = (
        page_one[:10]
        + many_rows(5, start=2000)
        + [{"domain": "nouuid-a.example"}, {"domain": "nouuid-a.example"}]
    )
    pages = {"0": page_one, "1000": page_two}
    serve_domains(
        world,
        lambda request: json_reply(
            {"results": pages[request.url.params["offset"]], "total": 1100}
        ),
    )
    run = clean(world.run("--quiet", "hunt", "--json", "--company", "paypal", "--all"))
    rows = run.json()
    assert len(rows) == 1000 + 5 + 2, (
        "10 repeated uuids dropped, the two uuid-less rows both kept"
    )
    assert len({row["uuid"] for row in rows if "uuid" in row}) == 1005


def test_paging_stops_when_a_page_adds_nothing_new(world):
    page = many_rows(1000)
    serve_domains(world, lambda request: json_reply({"results": page, "total": 5000}))
    run = clean(world.run("--quiet", "hunt", "--company", "paypal", "--all"))
    assert len(world.requests) == 2
    assert re.search(r"\b1000 of 5000\b", run.etext), (
        "short of the total: a warning names both numbers"
    )
    assert (
        len(
            clean(
                world.run("--quiet", "hunt", "--json", "--company", "paypal", "--all")
            ).json()
        )
        == 1000
    )


def test_paging_stops_on_an_empty_page(world):
    serve_domains(world, domains_page([], total=10))
    run = clean(world.run("--quiet", "hunt", "--json", "--company", "paypal"))
    assert len(world.requests) == 1 and run.json() == []


def test_paging_stops_when_the_offset_reaches_the_total_without_a_warning(world):
    rows = many_rows(1000)
    serve_domains(world, lambda request: json_reply({"results": rows, "total": 1000}))
    run = clean(world.run("--quiet", "hunt", "--json", "--company", "paypal", "--all"))
    assert len(world.requests) == 1 and len(run.json()) == 1000
    assert (
        "feed json"
        not in clean(
            world.run("--quiet", "hunt", "--company", "paypal", "--limit", "1")
        ).etext
    )


def test_paging_stops_after_the_request_at_offset_10000_and_warns(world):
    def handler(request):
        offset = int(request.url.params["offset"])
        return json_reply({"results": many_rows(1000, start=offset), "total": 50000})

    serve_domains(world, handler)
    run = clean(world.run("--quiet", "hunt", "--company", "paypal", "--limit", "1"))
    assert [int(r.url.params["offset"]) for r in world.requests] == list(
        range(0, 11000, 1000)
    )
    assert re.search(r"\b11000 of 50000\b", run.etext) and "feed json" in run.etext
    assert (
        len(
            clean(
                world.run("--quiet", "hunt", "--json", "--company", "paypal", "--all")
            ).json()
        )
        == 11000
    )


def test_a_short_page_with_a_larger_total_warns_about_the_shortfall(world):
    serve_domains(world, domains_page(many_rows(3), total=5))
    run = clean(world.run("--quiet", "hunt", "--company", "paypal"))
    assert re.search(r"\b3 of 5\b", run.etext)
    assert (
        len(clean(world.run("--quiet", "hunt", "--json", "--company", "paypal")).json())
        == 3
    )


def test_a_missing_results_key_is_an_empty_page(world):
    serve_domains(world, json_reply({"total": 0}))
    assert (
        clean(world.run("--quiet", "hunt", "--json", "--company", "paypal")).json()
        == []
    )


def test_offset_with_a_filter_fetches_exactly_one_raw_page_with_the_limit_and_shows_it_all(
    world,
):
    serve_domains(world, domains_page(many_rows(7), total=900))
    run = clean(
        world.run(
            "--quiet",
            "hunt",
            "--json",
            "--company",
            "paypal",
            "--offset",
            "40",
            "--limit",
            "5",
        )
    )
    assert len(world.requests) == 1
    assert world.params()["offset"] == "40" and world.params()["limit"] == "5"
    assert len(run.json()) == 7, (
        "an --offset page is shown whole, the --limit only sizes the API request"
    )


def test_offset_with_a_filter_and_limit_zero_asks_for_100(world):
    serve_domains(world, domains_page([]))
    clean(
        world.run(
            "--quiet",
            "hunt",
            "--json",
            "--company",
            "paypal",
            "--offset",
            "3",
            "--limit",
            "0",
        )
    )
    assert world.params()["limit"] == "100"


def test_without_a_server_filter_no_domains_request_is_made(fed):
    clean(
        fed.run(
            "--quiet",
            "hunt",
            "--json",
            "--verdict",
            "critical",
            "--min-score",
            "1",
            "--min-sources",
            "1",
        )
    )
    assert fed.paths == ["/feed.json"]


def test_hunt_offset_without_a_filter_is_rejected_before_fetch(fed):
    run = fed.run("--quiet", "hunt", "--json", "--offset", "3", "--limit", "2")
    assert run.code == 2 and "--offset requires a server filter" in run.err
    assert fed.paths == []


# ---------------------------------------------------------------------------------------------
# G. Client filters, sort modes, clip, and the composed JSON shapes  [C7]
# ---------------------------------------------------------------------------------------------

BY_SCORE = [ROW_PAYPAL, ROW_PAGES, ROW_BANK, ROW_PLAIN, ROW_PUNY, ROW_NOUUID]
BY_SOURCES = [ROW_PAYPAL, ROW_BANK, ROW_PAGES, ROW_PUNY, ROW_PLAIN, ROW_NOUUID]
BY_BRAND = [
    ROW_PUNY,
    ROW_PAYPAL,
    ROW_NOUUID,
    ROW_PAGES,
    ROW_BANK,
    ROW_PLAIN,
]  # company Z->A, newest first within


def uuids_of(rows):
    return [row.get("uuid") for row in rows]


@pytest.mark.parametrize(
    "sort,expected",
    [
        ("first_seen", FEED_BY_FIRST_SEEN),
        ("score", BY_SCORE),
        ("sources", BY_SOURCES),
        ("brand", BY_BRAND),
    ],
)
def test_hunt_sort_modes(fed, sort, expected):
    run = clean(fed.run("--quiet", "hunt", "--json", "--all", "--sort", sort))
    assert run.json() == expected


def test_default_sort_is_newest_first_seen_first(fed):
    assert clean(fed.run("--quiet", "hunt", "--json")).json() == FEED_BY_FIRST_SEEN


@pytest.mark.parametrize("sort", SORTS)
def test_equal_keys_keep_input_order(world, sort):
    world.serve_paths({"/feed.json": json_reply(TIES)})
    assert clean(world.run("--quiet", "hunt", "--json", "--sort", sort)).json() == TIES


def test_hunt_rows_are_passed_through_unmodified_including_unknown_keys(world):
    row = {**ROW_PAYPAL, "something_new": {"nested": [1, 2]}}
    world.serve_paths({"/feed.json": json_reply([row])})
    assert clean(world.run("--quiet", "hunt", "--json")).json() == [row]


@pytest.mark.parametrize(
    "argv,expected",
    [
        (("--verdict", "critical"), [ROW_PAYPAL]),
        (("--verdict", "low"), [ROW_PLAIN]),
        (("--verdict", "noise"), [ROW_PUNY]),
        (("--min-score", "55"), [ROW_PAYPAL, ROW_PAGES, ROW_BANK]),
        (("--min-score", "56"), [ROW_PAYPAL, ROW_PAGES]),
        (("--min-score", "0"), BY_SCORE),
        (("--min-sources", "2"), [ROW_PAYPAL, ROW_BANK]),
        (("--min-sources", "3"), [ROW_PAYPAL]),
        (("--min-sources", "0"), BY_SCORE),
        (("--min-sources", "9"), []),
        (("--verdict", "high", "--min-score", "80"), []),
        (
            ("--min-score", "10", "--min-sources", "1"),
            [ROW_PAYPAL, ROW_PAGES, ROW_BANK, ROW_PUNY],
        ),
    ],
)
def test_client_filters(fed, argv, expected):
    run = clean(fed.run("--quiet", "hunt", "--json", "--all", "--sort", "score", *argv))
    assert run.json() == expected


def test_the_verdict_filter_is_case_insensitive_on_the_row_and_falls_back_to_url_risk(
    world,
):
    rows = [{**ROW_PAYPAL, "verdict": "Critical"}, {"uuid": uid(7), "url_risk": "HIGH"}]
    world.serve_paths({"/feed.json": json_reply(rows)})
    assert uuids_of(
        clean(world.run("--quiet", "hunt", "--json", "--verdict", "critical")).json()
    ) == [uid(1)]
    assert uuids_of(
        clean(world.run("--quiet", "hunt", "--json", "--verdict", "high")).json()
    ) == [uid(7)]


@pytest.mark.parametrize(
    "argv,count",
    [
        ((), 6),
        (("--limit", "2"), 2),
        (("--limit", "0"), 6),
        (("--limit", "100"), 6),
        (("--limit", "2", "--all"), 6),
    ],
)
def test_hunt_limit_and_all(fed, argv, count):
    assert len(clean(fed.run("--quiet", "hunt", "--json", *argv)).json()) == count


def test_hunt_default_limit_is_25_rows(world):
    world.serve_paths({"/feed.json": json_reply(many_rows(40))})
    assert len(clean(world.run("--quiet", "hunt", "--json")).json()) == 25
    assert len(clean(world.run("--quiet", "hunt", "--json", "--all")).json()) == 40


def test_hunt_text_shows_shown_of_total_and_the_not_shown_hint(fed):
    run = clean(fed.run("--quiet", "hunt", "--limit", "2"))
    assert (
        run.out == ""
        and re.search(r"\b2 shown of 6\b", run.etext)
        and re.search(r"\b4 more\b", run.etext)
    )
    assert "--all" in run.err and "--limit" in run.err
    full = clean(fed.run("--quiet", "hunt", "--all"))
    assert (
        re.search(r"\b6 shown of 6\b", full.etext)
        and "more not shown" not in full.etext
    )


def test_hunt_text_table_shows_seen_brand_domain_and_source_glyphs_defanged(fed):
    run = clean(fed.run("--quiet", "hunt"))
    text = run.etext
    for needle in (
        "10-18 03:00",
        "bank-update[.]example[.]org",
        "paypal",
        "microsoft",
        "chase",
        "kit[.]pages[.]dev",
    ):
        assert needle in text, needle
    assert "bank-update.example.org" not in text and "203.0.113.2" not in text.replace(
        "203[.]0[.]113[.]2", ""
    )
    assert "GOpTu" not in text, (
        "the sources column of the TABLE shows the five glyphs G O P T U"
    )
    assert "G/O/P/T/U" in text, "the legend names the five source glyphs"


def test_hunt_text_shows_ip_and_geo_columns_only_on_a_wide_console(world):
    world.serve_paths({"/feed.json": json_reply([ROW_PAYPAL])})
    wide = clean(world.run("--quiet", "hunt"))
    assert "203[.]0[.]113[.]2" in wide.etext and "Germany" in wide.etext
    world.load(columns=None)
    narrow = clean(world.run("--quiet", "hunt"))
    assert "203[.]0[.]113[.]2" not in narrow.etext and "Germany" not in narrow.etext
    assert "paypal-login1[.]example[.]net" in narrow.etext.replace(" ", ""), (
        "an 80-column console keeps the domain"
    )


def test_live_shows_raw_indicators_on_screen_but_json_is_always_raw(fed):
    defanged = clean(fed.run("--quiet", "hunt", "--limit", "1"))
    live = clean(fed.run("--quiet", "--live", "hunt", "--limit", "1"))
    assert (
        "bank-update[.]example[.]org" in defanged.etext
        and "bank-update.example.org" in live.etext
    )
    assert (
        clean(fed.run("--quiet", "hunt", "--json", "--limit", "1")).json()[0]["domain"]
        == "bank-update.example.org"
    )


def test_hunt_values_prints_one_url_else_domain_per_shown_row_on_stdout_defanged_unless_live(
    world,
):
    rows = [
        ROW_PAYPAL,
        {
            "uuid": uid(9),
            "domain": "only-domain.example",
            "first_seen": "2026-10-01T00:00:00Z",
        },
    ]
    world.serve_paths({"/feed.json": json_reply(rows)})
    run = clean(world.run("--quiet", "hunt", "--values"))
    assert run.lines == [
        "hxxps://paypal-login1[.]example[.]net/signin/verify",
        "only-domain[.]example",
    ]
    live = clean(world.run("--quiet", "--live", "hunt", "--values"))
    assert live.lines == [
        "https://paypal-login1.example.net/signin/verify",
        "only-domain.example",
    ]
    limited = clean(world.run("--quiet", "hunt", "--values", "--limit", "1"))
    assert limited.lines == ["hxxps://paypal-login1[.]example[.]net/signin/verify"]


def test_hunt_with_nothing_matching_says_so_and_exits_0(fed):
    run = clean(fed.run("--quiet", "hunt", "--min-score", "99"))
    assert "nothing matched" in run.etext
    assert clean(fed.run("--quiet", "hunt", "--min-score", "99", "--json")).json() == []


PULSE_KEYS = [
    "count",
    "verdicts",
    "brands",
    "countries",
    "asns",
    "certs",
    "sources",
    "noise_flagged",
    "punycode",
    "paas_suffix",
    "credential_path",
    "median_score",
]


def ranked(pairs):
    """Counter.most_common output with each tie group sorted by name (tie order is its own pin)."""
    return sorted(
        ([name, count] for name, count in pairs), key=lambda pair: (-pair[1], pair[0])
    )


def test_pulse_json_shape_and_values(fed):
    data = clean(fed.run("--quiet", "pulse", "--json")).json()
    assert list(data) == PULSE_KEYS
    assert data["count"] == 6 and data["median_score"] == 37.5
    assert data["verdicts"] == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
        "noise": 1,
        EM_DASH: 1,
    }
    assert ranked(data["brands"]) == ranked(
        [["paypal", 3], ["chase", 1], ["microsoft", 1], [EM_DASH, 1]]
    )
    assert ranked(data["countries"]) == ranked(
        [["Germany", 3], ["France", 2], ["United States", 1]]
    )
    assert ranked(data["asns"]) == ranked(
        [
            [EM_DASH, 2],
            ["AS13335  Cloudflare, Inc.", 2],
            ["AS16276  OVH SAS", 1],
            ["AS24940  Hetzner Online GmbH", 1],
        ]
    )
    assert ranked(data["certs"]) == ranked(
        [["R3", 2], [EM_DASH, 2], ["Google Trust Services", 1], ["Let's Encrypt", 1]]
    )
    assert [pair[1] for pair in data["asns"]] == sorted(
        (pair[1] for pair in data["asns"]), reverse=True
    ), "most common first"
    assert data["sources"] == {
        "Google Safe Browsing": 1,
        "OpenPhish": 2,
        "PhishTank": 2,
        "TweetFeed": 1,
        "urlscan.io": 1,
    }
    assert (
        data["noise_flagged"],
        data["punycode"],
        data["paas_suffix"],
        data["credential_path"],
    ) == (1, 1, 1, 3)


def test_pulse_json_tie_order_is_first_seen_encounter_in_newest_first_order_PINNED_QUIRK(
    fed,
):
    data = clean(fed.run("--quiet", "pulse", "--json")).json()
    assert data["brands"] == [
        ["paypal", 3],
        ["chase", 1],
        ["microsoft", 1],
        [EM_DASH, 1],
    ]
    assert data["countries"][0] == ["Germany", 3]


def test_pulse_json_of_an_empty_slice_is_zeros_and_a_null_median_and_exits_0(fed):
    run = clean(fed.run("--quiet", "pulse", "--json", "--min-score", "99"))
    assert run.json() == {
        "count": 0,
        "verdicts": {},
        "brands": [],
        "countries": [],
        "asns": [],
        "certs": [],
        "sources": {},
        "noise_flagged": 0,
        "punycode": 0,
        "paas_suffix": 0,
        "credential_path": 0,
        "median_score": None,
    }
    assert list(run.json()) == PULSE_KEYS


def test_pulse_text_of_an_empty_slice_says_empty_and_exits_0(fed):
    run = clean(fed.run("--quiet", "pulse", "--min-score", "99"))
    assert "empty slice" in run.etext and run.out == ""


def test_pulse_json_caps_the_lists(world):
    rows = [
        {
            "uuid": uid(200 + i),
            "domain": f"d{i}.example",
            "company": f"brand{i:02d}",
            "country": f"C{i:02d}",
            "asn": str(1000 + i),
            "org": f"Org{i}",
            "cert": f"Cert{i:02d}",
            "first_seen": f"2026-10-01T00:{i:02d}:00Z",
        }
        for i in range(40)
    ]
    world.serve_paths({"/feed.json": json_reply(rows)})
    data = clean(world.run("--quiet", "pulse", "--json")).json()
    assert (
        len(data["brands"]),
        len(data["countries"]),
        len(data["asns"]),
        len(data["certs"]),
    ) == (30, 20, 20, 15)


def test_pulse_median_uses_the_middle_value_or_the_mean_of_the_middle_two(world):
    world.serve_paths(
        {
            "/feed.json": json_reply(
                [
                    {"uuid": uid(1), "score": 1},
                    {"uuid": uid(2), "score": 9},
                    {"uuid": uid(3), "score": 3},
                ]
            )
        }
    )
    assert clean(world.run("--quiet", "pulse", "--json")).json()["median_score"] == 3.0
    world.serve_paths(
        {
            "/feed.json": json_reply(
                [{"uuid": uid(1), "score": 1}, {"uuid": uid(2), "score": 9}]
            )
        }
    )
    world.cache_file.unlink()
    assert clean(world.run("--quiet", "pulse", "--json")).json()["median_score"] == 5.0


def test_pulse_with_a_server_filter_uses_the_domains_api_and_all_matches(world):
    serve_domains(world, domains_page(FEED[:3]))
    data = clean(world.run("--quiet", "pulse", "--json", "--company", "paypal")).json()
    assert world.paths == ["/api/v1/domains"] and data["count"] == 3


def test_pulse_ignores_a_limit_it_does_not_have_and_always_uses_every_row(world):
    world.serve_paths({"/feed.json": json_reply(many_rows(60))})
    assert clean(world.run("--quiet", "pulse", "--json")).json()["count"] == 60


def test_pulse_text_dashboard_content(fed):
    run = clean(fed.run("--quiet", "pulse"))
    text = run.etext
    assert run.out == ""
    for needle in (
        "paypal",
        "microsoft",
        "chase",
        "Germany",
        "France",
        "AS13335",
        "Cloudflare, Inc.",
        "Google Safe Browsing",
        "OpenPhish",
        "PhishTank",
        "TweetFeed",
        "urlscan.io",
        "critical",
        "noise",
        "R3",
        "Let's Encrypt",
        "kit[.]pages[.]dev",
        "xn--pypal-4ve[.]example",
        "bank-update[.]example[.]org",
    ):
        assert needle in text, needle
    assert re.search(r"punycode[^\n]*\b1\b", run.err) and re.search(
        r"credential[^\n]*\b3\b", run.err
    )
    assert re.search(r"noise[^\n]*\b1\b", run.err)
    assert "heuristic" in text and "false positives" in text.lower()
    assert "active feed" in text and "6 rows" in text
    assert "2026-10-15" in text.replace(" ", "") or "10-15" in text


def test_pulse_text_lists_8_hottest_and_8_newest_rows(world):
    world.serve_paths({"/feed.json": json_reply(many_rows(30))})
    run = clean(world.run("--quiet", "pulse"))
    assert run.etext.count("d29[.]example") >= 1


def test_pulse_label_names_the_source_of_the_slice(world):
    serve_domains(world, domains_page(FEED[:3]))
    run = clean(world.run("--quiet", "pulse", "--company", "paypal"))
    assert "api/v1/domains" in run.etext and "3 matches" in run.etext


# -- pivot -----------------------------------------------------------------------------------


def test_pivot_json_shape(fed):
    data = clean(fed.run("--quiet", "pivot", "ip", "--json")).json()
    assert data == [
        {
            "value": "203.0.113.2",
            "count": 2,
            "brands": [["paypal", 2]],
            "countries": [["Germany", 2]],
            "median_score": 52.0,
            "sample": "xn--pypal-4ve.example",
        }
    ]
    assert list(data[0]) == [
        "value",
        "count",
        "brands",
        "countries",
        "median_score",
        "sample",
    ]


def test_pivot_asn_adds_the_as_prefix_to_digit_strings_and_orders_by_count(fed):
    data = clean(fed.run("--quiet", "pivot", "asn", "--json")).json()
    assert [(row["value"], row["count"]) for row in data] == [("AS13335", 2)]
    assert data[0]["sample"] == "kit.pages.dev", (
        "the sample is the first domain in newest-first order"
    )
    assert ranked(data[0]["brands"]) == [["microsoft", 1], ["paypal", 1]]


@pytest.mark.parametrize(
    "field,expected",
    [
        ("country", [("Germany", 3), ("France", 2)]),
        ("company", [("paypal", 3)]),
        ("cert", [("R3", 2)]),
        ("org", [("Cloudflare, Inc.", 2)]),
        ("registrar", []),
    ],
)
def test_pivot_groups_by_each_field_dropping_buckets_under_the_minimum(
    fed, field, expected
):
    data = clean(fed.run("--quiet", "pivot", field, "--json")).json()
    assert [(row["value"], row["count"]) for row in data] == expected


@pytest.mark.parametrize("min_count,expected", [("1", 3), ("2", 1), ("3", 0), ("0", 1)])
def test_pivot_min_count(fed, min_count, expected):
    assert (
        len(
            clean(
                fed.run("--quiet", "pivot", "ip", "--json", "--min-count", min_count)
            ).json()
        )
        == expected
    )


def test_pivot_limit_default_is_25_and_zero_falls_back_to_30_for_json_and_25_for_text(
    world,
):
    rows = [
        {
            "uuid": uid(300 + i),
            "domain": f"d{i}.example",
            "country": f"C{i:02d}",
            "first_seen": f"2026-10-01T00:{i % 60:02d}:00Z",
        }
        for i in range(80)
        for _ in (0, 1)
    ]
    rows = [{**row, "uuid": uid(1000 + index)} for index, row in enumerate(rows)]
    world.serve_paths({"/feed.json": json_reply(rows)})
    assert len(clean(world.run("--quiet", "pivot", "country", "--json")).json()) == 25
    assert (
        len(
            clean(
                world.run("--quiet", "pivot", "country", "--json", "--limit", "0")
            ).json()
        )
        == 30
    )
    assert (
        len(
            clean(
                world.run("--quiet", "pivot", "country", "--json", "--limit", "7")
            ).json()
        )
        == 7
    )

    def shown(text):
        return len(set(re.findall(r"\bC\d\d\b", text)))

    assert shown(clean(world.run("--quiet", "pivot", "country")).err) == 25
    assert (
        shown(clean(world.run("--quiet", "pivot", "country", "--limit", "0")).err) == 25
    )
    assert (
        shown(clean(world.run("--quiet", "pivot", "country", "--limit", "4")).err) == 4
    )


def test_pivot_text_defangs_ip_values_and_names_the_field_and_missing_rows(fed):
    run = clean(fed.run("--quiet", "pivot", "ip"))
    assert "203[.]0[.]113[.]2" in run.etext and "203.0.113.2" not in run.etext
    assert "ip" in run.etext and re.search(r"\b2\b", run.etext)
    live = clean(fed.run("--quiet", "--live", "pivot", "ip"))
    assert "203.0.113.2" in live.etext


def test_pivot_registrar_warns_when_every_row_lacks_it(fed):
    run = clean(fed.run("--quiet", "pivot", "registrar"))
    assert "registrar" in run.etext and "--registrar" in run.etext


def test_pivot_uses_the_whole_working_set_with_server_filters_via_the_domains_api(
    world,
):
    serve_domains(world, domains_page(FEED))
    data = clean(
        world.run("--quiet", "pivot", "country", "--company", "paypal", "--json")
    ).json()
    assert world.paths == ["/api/v1/domains"] and data[0]["value"] == "Germany"


# -- triage ----------------------------------------------------------------------------------


def test_triage_sorts_by_score_then_source_count_and_limits_to_20(fed):
    run = clean(fed.run("--quiet", "triage", "--json"))
    assert run.json() == BY_SCORE
    assert clean(fed.run("--quiet", "triage", "--json", "--limit", "2")).json() == [
        ROW_PAYPAL,
        ROW_PAGES,
    ]
    assert (
        clean(fed.run("--quiet", "triage", "--json", "--limit", "0")).json() == BY_SCORE
    )


def test_triage_default_limit_is_20_and_all_lifts_it(world):
    world.serve_paths({"/feed.json": json_reply(many_rows(50))})
    assert len(clean(world.run("--quiet", "triage", "--json")).json()) == 20
    assert len(clean(world.run("--quiet", "triage", "--json", "--all")).json()) == 50


def test_triage_score_ties_break_on_source_count_then_first_seen(world):
    rows = [
        {
            "uuid": uid(1),
            "score": 50,
            "first_seen": "2026-10-01T00:00:00Z",
            "malicious_google": True,
        },
        {"uuid": uid(2), "score": 50, "first_seen": "2026-10-03T00:00:00Z"},
        {"uuid": uid(3), "score": 50, "first_seen": "2026-10-02T00:00:00Z"},
        {"uuid": uid(4), "score": 60, "first_seen": "2026-09-01T00:00:00Z"},
    ]
    world.serve_paths({"/feed.json": json_reply(rows)})
    assert uuids_of(clean(world.run("--quiet", "triage", "--json")).json()) == [
        uid(4),
        uid(1),
        uid(2),
        uid(3),
    ]


def test_triage_text_has_a_ranked_table_and_a_lead_row_card_with_the_full_detail(fed):
    run = clean(fed.run("--quiet", "triage", "--limit", "3"))
    text = run.etext
    assert run.out == ""
    assert re.search(r"\b3 shown of 6\b", text)
    assert text.index("paypal-login1[.]example[.]net") < text.index("kit[.]pages[.]dev")
    for needle in (
        uid(1),
        "critical",
        "92",
        "Germany",
        "13335",
        "Cloudflare, Inc.",
        "R3",
        "GOpTu",
        f"https://phishunt.io/suspicious/paypal/{uid(1)}/",
        "dshield report",
        "brand-in-host",
        "lexical",
        "30",
        "paypal in hostname",
        "value 1",
        "w 0.5",
        "2026-10-17T10:00:00Z",
        "2026-10-18T06:30:00Z",
    ):
        assert needle in text.replace("[.]", "."), needle
    assert "203[.]0[.]113[.]2" in text


def test_triage_detail_link_needs_a_valid_slug_and_uuid(world):
    rows = [{**ROW_PAYPAL, "company": "bad slug!"}, {**ROW_PAGES, "uuid": "not-a-uuid"}]
    world.serve_paths({"/feed.json": json_reply(rows)})
    assert (
        "suspicious" not in clean(world.run("--quiet", "triage", "--limit", "1")).etext
    )
    world.serve_paths({"/feed.json": json_reply([{**ROW_PAGES, "uuid": "not-a-uuid"}])})
    world.cache_file.unlink()
    assert (
        "suspicious" not in clean(world.run("--quiet", "triage", "--limit", "1")).etext
    )


def test_triage_source_glyphs_use_lower_case_for_unflagged_sources(world):
    world.serve_paths({"/feed.json": json_reply([ROW_PLAIN])})
    assert "goptu" in clean(world.run("--quiet", "triage")).etext
    world.cache_file.unlink()
    world.serve_paths(
        {
            "/feed.json": json_reply(
                [{**ROW_PLAIN, "malicious_phishtank": True, "malicious_urlscan": "1"}]
            )
        }
    )
    assert "goPtU" in clean(world.run("--quiet", "triage")).etext


def test_triage_with_no_rows_prints_nothing_matched_and_no_lead_card(fed):
    run = clean(fed.run("--quiet", "triage", "--min-score", "99"))
    assert "nothing matched" in run.etext and "lead row" not in run.etext


# -- search ----------------------------------------------------------------------------------

SEARCH_PAYLOAD = {
    "results": [ROW_PAGES, ROW_PAYPAL, ROW_BANK],
    "count": 3,
    "q": "login",
}


def test_search_requests_the_search_endpoint_with_query_then_limit(world):
    world.serve_paths({"/api/v1/search.json": json_reply(SEARCH_PAYLOAD)})
    clean(world.run("--quiet", "search", "login", "--json"))
    assert world.paths == ["/api/v1/search.json"] and world.query_keys() == [
        "q",
        "limit",
    ]
    assert world.params() == {"q": "login", "limit": "50"}


@pytest.mark.parametrize("limit,sent", [("7", "7"), ("0", "50"), ("500", "500")])
def test_search_limit(world, limit, sent):
    world.serve_paths({"/api/v1/search.json": json_reply(SEARCH_PAYLOAD)})
    clean(world.run("--quiet", "search", "login", "--limit", limit, "--json"))
    assert world.params()["limit"] == sent


@pytest.mark.parametrize("query", ["ab", "  ab  ", " a ", "", "   "])
def test_search_needs_three_characters_after_stripping_and_sends_nothing(world, query):
    world.serve_paths({"/api/v1/search.json": json_reply(SEARCH_PAYLOAD)})
    run = world.run("--quiet", "search", query)
    assert run.code == 2 and "3" in run.etext and world.requests == []


def test_search_json_without_client_filters_is_the_raw_server_object(world):
    world.serve_paths({"/api/v1/search.json": json_reply(SEARCH_PAYLOAD)})
    assert (
        clean(world.run("--quiet", "search", "login", "--json")).json()
        == SEARCH_PAYLOAD
    )


def test_search_json_with_a_client_filter_flips_to_the_filtered_sorted_rows_array_PINNED_QUIRK(
    world,
):
    world.serve_paths({"/api/v1/search.json": json_reply(SEARCH_PAYLOAD)})
    run = clean(
        world.run(
            "--quiet",
            "search",
            "login",
            "--json",
            "--min-score",
            "60",
            "--sort",
            "score",
        )
    )
    assert run.json() == [ROW_PAYPAL, ROW_PAGES]
    assert clean(
        world.run("--quiet", "search", "login", "--json", "--verdict", "medium")
    ).json() == [ROW_BANK]
    assert clean(
        world.run("--quiet", "search", "login", "--json", "--min-sources", "2")
    ).json() == [ROW_BANK, ROW_PAYPAL]


def test_search_json_min_score_zero_counts_as_unset_PINNED_QUIRK(world):
    world.serve_paths({"/api/v1/search.json": json_reply(SEARCH_PAYLOAD)})
    assert (
        clean(
            world.run("--quiet", "search", "login", "--json", "--min-score", "0")
        ).json()
        == SEARCH_PAYLOAD
    )


def test_search_text_shows_the_query_the_api_count_and_the_sorted_rows(world):
    world.serve_paths({"/api/v1/search.json": json_reply(SEARCH_PAYLOAD)})
    run = clean(world.run("--quiet", "search", "login", "--sort", "score"))
    assert run.out == "" and "login" in run.etext and re.search(r"\b3\b", run.etext)
    assert (
        run.etext.index("paypal-login1[.]example[.]net")
        < run.etext.index("kit[.]pages[.]dev")
        < run.etext.index("bank-update[.]example[.]org")
    )


def test_search_with_no_results_says_nothing_matched(world):
    world.serve_paths({"/api/v1/search.json": json_reply({"results": [], "count": 0})})
    assert "nothing matched" in clean(world.run("--quiet", "search", "zzzzz")).etext


# ---------------------------------------------------------------------------------------------
# I. analyze / deep: URL normalization, the share gate, headers, views  [C9]
# ---------------------------------------------------------------------------------------------

TARGET = "https://allowed.example/login"
ANALYZE_REQUEST = f"{BASE}/api/v1/analyze?url=https%3A%2F%2Fallowed.example%2Flogin"
DEEP_REQUEST = f"{BASE}/api/v1/analyze/deep?url=https%3A%2F%2Fallowed.example%2Flogin"
TOKEN = "tok-SECRET-1234"


class TtyInput(io.StringIO):
    """A stdin that claims to be a terminal, to drive the interactive confirmation prompt."""

    def isatty(self):
        return True


def type_answer(world, text: str) -> None:
    world.mp.setattr(sys, "stdin", TtyInput(text))


def serve_analysis(world, payload=None, deep=None):
    world.serve_paths(
        {
            "/api/v1/analyze": json_reply(
                ANALYZE_PAYLOAD if payload is None else payload
            ),
            "/api/v1/analyze/deep": json_reply(DEEP_PAYLOAD if deep is None else deep),
        }
    )


@pytest.fixture(autouse=True)
def non_interactive_stdin(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))


def test_analyze_in_scope_with_yes_sends_exactly_one_get_with_the_percent_encoded_url(
    world,
):
    serve_analysis(world, {"ok": True})
    run = clean(world.run("--quiet", "analyze", TARGET, "--yes", "--json"))
    assert world.urls == [ANALYZE_REQUEST] and run.json() == {"ok": True}
    assert {request.url.host for request in world.requests} == {"phishunt.io"}, (
        "the target host is never contacted"
    )


def test_analyze_out_of_scope_url_is_refused_with_the_scope_hint_and_nothing_is_sent(
    world,
):
    serve_analysis(world)
    run = world.run("--quiet", "analyze", "https://outside.example/login", "--yes")
    assert run.code == 2 and world.requests == []
    assert (
        "outside.example is outside this engagement's scope" in run.etext
        and "bughunt scope add outside.example" in run.etext
    )


def test_analyze_without_any_scope_file_says_how_to_create_one(world):
    world.workspace(scope=None)
    serve_analysis(world)
    run = world.run("--quiet", "analyze", TARGET, "--yes")
    assert run.code == 2 and world.requests == []
    assert (
        "no scope file" in run.etext.lower()
        and "bughunt scope init" in run.etext
        and "bughunt scope add allowed.example" in run.etext
    )


def drop_active_scan_from_the_asset(document):
    for asset in document["assets"]:
        if asset["origin"] == "https://allowed.example":
            asset["operations"] = [
                op for op in asset["operations"] if op != "active_scan"
            ]


def turn_active_scan_off_globally(document):
    document["permissions"]["active_scan"] = False


LACKING_ACTIVE_SCAN = [
    (drop_active_scan_from_the_asset, "asset-method-disallowed"),
    (turn_active_scan_off_globally, "operation-disallowed"),
]


@pytest.mark.parametrize(
    "mutate,reason", LACKING_ACTIVE_SCAN, ids=["asset-lacks-it", "policy-forbids-it"]
)
def test_analyze_needs_the_active_scan_grant_on_the_submitted_url_PINNED_FAIL_CLOSED_d15(
    world, mutate, reason
):
    world.workspace(mutate=mutate)
    world.load()
    serve_analysis(world)
    run = world.run("--quiet", "analyze", TARGET, "--yes")
    assert run.code == 2 and world.requests == []
    assert reason in run.etext and "no outbound action ran" in run.etext


@pytest.mark.parametrize(
    "url,reason",
    [
        ("https://allowed.example/a%20b", "invalid-target"),
        ("https://allowed.example/x#frag", "invalid-target"),
        ("https://user:pw@allowed.example/x", "invalid-target"),
        ("https://allowed.example/a//b", "invalid-target"),
        ("https://allowed.example:8443/x", "asset-unknown"),
    ],
)
def test_analyze_refuses_urls_the_policy_cannot_authorize_before_sending_anything(
    world, url, reason
):
    serve_analysis(world)
    run = world.run("--quiet", "analyze", url, "--yes")
    assert (
        run.code == 2
        and world.requests == []
        and reason in run.etext
        and "no outbound action ran" in run.etext
    )


def test_analyze_allows_a_query_string_in_the_users_url(world):
    serve_analysis(world, {})
    clean(
        world.run(
            "--quiet",
            "analyze",
            "https://allowed.example/login?next=/home&x=1",
            "--yes",
            "--json",
        )
    )
    assert world.params()["url"] == "https://allowed.example/login?next=/home&x=1"


def test_analyze_for_a_host_in_scope_but_not_a_policy_asset_is_refused(world):
    world.workspace(scope="allowed.example\nunlisted.example\n")
    serve_analysis(world)
    run = world.run("--quiet", "analyze", "https://unlisted.example/x", "--yes")
    assert run.code == 2 and "asset-unknown" in run.etext and world.requests == []


def test_analyze_non_interactive_without_yes_is_not_sent(world):
    serve_analysis(world)
    run = world.run("--quiet", "analyze", TARGET)
    assert (
        run.code == 2
        and world.requests == []
        and "not sent" in run.etext
        and "--yes" in run.etext
    )


@pytest.mark.parametrize("answer", ["y\n", "yes\n", "Y\n", " YES \n"])
def test_analyze_interactive_yes_sends(world, answer):
    serve_analysis(world, {})
    type_answer(world, answer)
    clean(world.run("--quiet", "analyze", TARGET, "--json"))
    assert world.urls == [ANALYZE_REQUEST]


@pytest.mark.parametrize("answer", ["n\n", "\n", "maybe\n", "", "no\n", "yy\n"])
def test_analyze_interactive_anything_but_yes_does_not_send(world, answer):
    serve_analysis(world, {})
    type_answer(world, answer)
    run = world.run("--quiet", "analyze", TARGET, "--json")
    assert run.code == 2 and world.requests == [] and "not sent" in run.etext


def test_the_confirmation_prompt_names_the_url(world):
    serve_analysis(world, {})
    type_answer(world, "y\n")
    run = clean(world.run("--quiet", "analyze", TARGET, "--json"))
    assert TARGET in run.out + run.err and "phishunt.io" in run.out + run.err


def test_scope_policy_and_confirmation_are_checked_in_that_order(world):
    serve_analysis(world)
    type_answer(world, "")
    assert (
        "outside this engagement's scope"
        in world.run("--quiet", "analyze", "https://outside.example/a").etext
    ), "scope first"
    assert (
        "invalid-target"
        in world.run("--quiet", "analyze", "https://allowed.example/a%20b").etext
    ), "policy second"
    assert "not sent" in world.run("--quiet", "analyze", TARGET).etext, (
        "confirmation last"
    )


@pytest.mark.parametrize(
    "raw,sent",
    [
        ("hxxps://allowed[.]example/login", "https://allowed.example/login"),
        ("allowed.example/login", "https://allowed.example/login"),
        ("  https://allowed.example/login  ", "https://allowed.example/login"),
        ("'https://allowed.example/login'", "https://allowed.example/login"),
        ("allowed(.)example/login", "https://allowed.example/login"),
    ],
)
def test_analyze_refangs_trims_and_defaults_the_scheme_to_https(world, raw, sent):
    serve_analysis(world, {})
    clean(world.run("--quiet", "analyze", raw, "--yes", "--json"))
    assert world.params()["url"] == sent


def test_a_scheme_less_url_prints_an_assuming_https_notice_in_text_mode_only(world):
    serve_analysis(world)
    assert (
        "https"
        in clean(world.run("--quiet", "analyze", "allowed.example/login", "--yes")).err
    )
    assert (
        clean(
            world.run("--quiet", "analyze", "allowed.example/login", "--yes", "--json")
        ).err
        == ""
    )


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://allowed.example/x",
        "https://localhost/",
        "   ",
        "",
        "https://",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://allowed/",
        "http://127.0.0.1/",
        "https://" + "a" * 2100 + ".example/",
    ],
)
def test_analyze_rejects_malformed_urls_with_exit_2_and_no_request(world, raw):
    serve_analysis(world)
    run = world.run("--quiet", "analyze", raw, "--yes")
    assert run.code == 2 and world.requests == [], raw[:40]


def test_analyze_url_length_limit_is_2048_characters(world):
    serve_analysis(world, {})
    exact = "https://allowed.example/" + "a" * (2048 - len("https://allowed.example/"))
    assert len(exact) == 2048
    clean(world.run("--quiet", "analyze", exact, "--yes", "--json"))
    assert len(world.requests) == 1
    run = world.run("--quiet", "analyze", exact + "a", "--yes", "--json")
    assert run.code == 2 and len(world.requests) == 1


def test_analyze_json_is_the_server_object_verbatim_and_a_text_view_has_no_stdout(
    world,
):
    serve_analysis(world)
    assert (
        clean(world.run("--quiet", "analyze", TARGET, "--yes", "--json")).json()
        == ANALYZE_PAYLOAD
    )
    assert clean(world.run("--quiet", "analyze", TARGET, "--yes")).out == ""


def test_analyze_view_content(world):
    serve_analysis(world)
    text = clean(world.run("--quiet", "analyze", TARGET, "--yes")).etext
    for needle in (
        "PASSIVE ANALYZE",
        "suspicious",
        "64",
        "allowed[.]example/login",
        "paypal",
        "likely_phishing",
        "brand-in-path",
        "medium",
        "lexical; known-brand",
        "why this score",
        "login-path",
        "path",
        "12",
        "login path",
        "value 1",
        "w 0.5",
        "young-domain",
        "whois",
        "9",
        "non-zero shape signals",
        "url_signals.hyphens",
        "2.50",
        "path_signals.depth",
        "3.00",
        "in active feed",
        "stored brand",
        "88",
        "critical",
        "2026-10-01T00:00:00Z",
        "https://phishunt.io/suspicious/paypal/x/",
        "openphish",
        "Looks like a PayPal credential harvester.",
        "untrusted",
        "paypal (2), ebay (1)",
        "2026-09-01",
        "2026-10-17",
        "new apex",
        "scores are heuristics",
        "sent to phishunt",
    ):
        assert needle in text, needle
    assert "url_signals.digits" not in text and "path_signals.empty" not in text, (
        "only non-zero shape signals are listed"
    )


def test_analyze_view_shows_only_the_first_eight_why_items(world):
    payload = {
        "live_analysis": {
            "why": [{"signal": f"sig{i}", "points": i} for i in range(12)]
        }
    }
    serve_analysis(world, payload)
    text = clean(world.run("--quiet", "analyze", TARGET, "--yes")).etext
    assert "sig7" in text and "sig8" not in text


def test_analyze_view_renders_an_empty_object(world):
    serve_analysis(world, {})
    run = clean(world.run("--quiet", "analyze", TARGET, "--yes"))
    assert "PASSIVE ANALYZE" in run.etext and EM_DASH in run.etext and run.exc is None


def test_analyze_live_flag_shows_the_raw_url_in_the_view(world):
    serve_analysis(world)
    assert (
        "https://allowed.example/login"
        in clean(world.run("--quiet", "--live", "analyze", TARGET, "--yes")).etext
    )


# -- deep ------------------------------------------------------------------------------------


def test_deep_in_scope_sends_one_get_with_the_token_header_and_a_90_second_floor_timeout(
    world,
):
    serve_analysis(world)
    run = clean(
        world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes", "--json")
    )
    assert world.urls == [DEEP_REQUEST] and run.json() == DEEP_PAYLOAD
    assert world.requests[0].headers["x-phishunt-deep-token"] == TOKEN
    assert read_timeout(world.requests[0]) == 90.0 and {
        r.url.host for r in world.requests
    } == {"phishunt.io"}


@pytest.mark.parametrize(
    "timeout,expected", [("10", 90.0), ("90", 90.0), ("120", 120.0)]
)
def test_deep_timeout_is_the_larger_of_the_flag_and_90(world, timeout, expected):
    serve_analysis(world)
    clean(
        world.run(
            "--quiet",
            "--timeout",
            timeout,
            "deep",
            TARGET,
            "--token",
            TOKEN,
            "--yes",
            "--json",
        )
    )
    assert read_timeout(world.requests[0]) == expected


def test_the_deep_token_comes_from_the_environment_and_the_flag_wins(world):
    serve_analysis(world)
    world.mp.setenv("PHISHUNT_DEEP_TOKEN", "from-env")
    clean(world.run("--quiet", "deep", TARGET, "--yes", "--json"))
    assert world.requests[-1].headers["x-phishunt-deep-token"] == "from-env"
    clean(
        world.run("--quiet", "deep", TARGET, "--token", "from-flag", "--yes", "--json")
    )
    assert world.requests[-1].headers["x-phishunt-deep-token"] == "from-flag"


def test_the_deep_token_is_sent_on_the_deep_request_only(world):
    serve_analysis(world)
    clean(
        world.run(
            "--quiet",
            "analyze",
            TARGET,
            "--yes",
            "--json",
        )
    )
    clean(world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes", "--json"))
    assert "x-phishunt-deep-token" not in world.requests[0].headers


def test_deep_refusals_are_checked_in_order_token_then_yes_then_url_then_the_share_gate(
    world,
):
    serve_analysis(world)
    no_token = world.run("--quiet", "deep", "https://outside.example/x")
    assert (
        no_token.code == 2
        and "PHISHUNT_DEEP_TOKEN" in no_token.etext
        and "--token" in no_token.etext
    )
    no_yes = world.run("--quiet", "deep", "https://outside.example/x", "--token", TOKEN)
    assert no_yes.code == 2 and "--yes" in no_yes.etext and "50" in no_yes.etext
    bad_url = world.run(
        "--quiet", "deep", "ftp://x.example/", "--token", TOKEN, "--yes"
    )
    assert bad_url.code == 2
    outside = world.run(
        "--quiet", "deep", "https://outside.example/x", "--token", TOKEN, "--yes"
    )
    assert outside.code == 2 and "outside this engagement's scope" in outside.etext
    assert world.requests == []


def test_deep_never_prompts_it_is_pre_answered_by_yes(world):
    serve_analysis(world)
    type_answer(world, "n\n")
    clean(world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes", "--json"))
    assert len(world.requests) == 1


@pytest.mark.parametrize(
    "mutate,reason", LACKING_ACTIVE_SCAN, ids=["asset-lacks-it", "policy-forbids-it"]
)
def test_deep_respects_the_active_scan_policy_grant_like_analyze(world, mutate, reason):
    world.workspace(mutate=mutate)
    world.load()
    serve_analysis(world)
    run = world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes")
    assert run.code == 2 and world.requests == [] and reason in run.etext


def test_the_deep_token_is_resent_on_a_same_host_redirect_hop_and_never_to_another_host(
    world,
):
    def handler(request):
        if request.url.path == "/api/v1/analyze/deep":
            return redirect_to("/api/v1/landed")
        return json_reply({"done": True})

    world.serve(handler=handler)
    clean(world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes", "--json"))
    assert [r.headers.get("x-phishunt-deep-token") for r in world.requests] == [
        TOKEN,
        TOKEN,
    ]
    world.requests.clear()
    world.serve_paths(
        {"/api/v1/analyze/deep": redirect_to("https://evil.example/steal")}
    )
    run = world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes", "--json")
    assert run.code == 1 and [r.url.host for r in world.requests] == ["phishunt.io"]


def test_deep_json_is_the_server_object_verbatim(world):
    serve_analysis(world)
    assert (
        clean(
            world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes", "--json")
        ).json()
        == DEEP_PAYLOAD
    )


def test_deep_view_content(world):
    serve_analysis(world)
    text = clean(world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes")).etext
    for needle in (
        "ACTIVE MODE",
        "DEEP ANALYZE",
        "phishunt contacted this URL",
        "attacker-controlled",
        "not a clean result",
        "d-2.1",
        "71",
        "phishing",
        "credential-harvest",
        "content",
        "network",
        "signals that fired",
        "login-form",
        "password field",
        "25",
        "cert-age",
        "fresh certificate",
        "not fully evaluated",
        "rdap: no answer",
        "dns-fail",
        "geo: geoip timeout",
        "allowlist -10",
        "used 3",
        "remaining 47",
        "limit 50",
    ):
        assert needle in text, needle
    assert text.index("login-form") < text.index("cert-age"), (
        "fired signals sort by contribution, highest first"
    )
    assert (
        "quiet"
        not in text.split("signals that fired")[1].split("not fully evaluated")[0]
    )


def test_deep_view_caps_signals_at_eight_failures_at_25_and_adjustments_at_8_PINNED_QUIRK_spec_said_12(
    world,
):
    """The spec reads `fired[:12]` but the shared signals table shows only its first 8, so 8 is what a
    user sees today. Pinned as observed."""
    deep = {
        "signals": [
            {"signal_id": f"s{i:02d}", "score_contribution": 100 - i, "detected": True}
            for i in range(20)
        ],
        "analysis_failures": [f"fail{i:02d}" for i in range(40)],
        "adjustments": [f"adj{i}" for i in range(12)],
    }
    serve_analysis(world, deep={"deep_analysis": deep})
    text = clean(world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes")).etext
    assert "s07" in text and "s08" not in text
    assert "fail24" in text and "fail25" not in text
    assert "adj7" in text and "adj8" not in text


def test_deep_view_accepts_analysis_failures_as_a_mapping(world):
    serve_analysis(
        world,
        deep={
            "deep_analysis": {
                "analysis_failures": {"dns": "timed out", "tls": "refused"}
            }
        },
    )
    text = clean(world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes")).etext
    assert "dns: timed out" in text and "tls: refused" in text


# ---------------------------------------------------------------------------------------------
# J. campaigns, campaign, related, enrich, brand, cert, inspect  [C10]
# ---------------------------------------------------------------------------------------------


def serve_campaigns(world, listing=None, detail=None):
    world.serve_paths(
        {
            "/api/v1/campaigns": json_reply(
                CAMPAIGN_LIST if listing is None else listing
            ),
            f"/api/v1/campaigns/{CAMPAIGN_KEY}": json_reply(
                CAMPAIGN_DETAIL if detail is None else detail
            ),
        }
    )


def test_campaigns_default_request_has_the_documented_query_order_and_values(world):
    serve_campaigns(world)
    run = clean(world.run("--quiet", "campaigns", "--json"))
    assert world.paths == ["/api/v1/campaigns"] and run.json() == CAMPAIGN_LIST
    assert world.query_keys() == ["limit", "offset", "status", "min_size"]
    assert world.params() == {
        "limit": "20",
        "offset": "0",
        "status": "all",
        "min_size": "0",
    }


def test_campaigns_filters_ride_the_wire_with_the_brand_lower_cased(world):
    serve_campaigns(world)
    clean(
        world.run(
            "--quiet",
            "campaigns",
            "--json",
            "--brand",
            "PayPal",
            "--status",
            "active",
            "--min-size",
            "5",
            "--limit",
            "7",
            "--offset",
            "40",
        )
    )
    assert world.query_keys() == ["limit", "offset", "brand", "status", "min_size"]
    assert world.params() == {
        "limit": "7",
        "offset": "40",
        "brand": "paypal",
        "status": "active",
        "min_size": "5",
    }


def test_campaigns_all_pages_with_the_same_normalized_filters_in_the_same_order(world):
    world.serve_paths({"/api/v1/campaigns": json_reply({"results": [], "total": 0})})
    clean(
        world.run(
            "--quiet",
            "campaigns",
            "--all",
            "--json",
            "--brand",
            "PayPal",
            "--status",
            "active",
            "--min-size",
            "3",
        )
    )
    assert world.query_keys() == ["limit", "offset", "brand", "status", "min_size"]
    assert world.params() == {
        "limit": "200",
        "offset": "0",
        "brand": "paypal",
        "status": "active",
        "min_size": "3",
    }


def test_campaigns_limit_zero_means_20(world):
    serve_campaigns(world)
    clean(world.run("--quiet", "campaigns", "--json", "--limit", "0"))
    assert world.params()["limit"] == "20"


def test_campaigns_all_pages_by_200_until_the_total_and_returns_the_last_page_metadata_with_all_rows(
    world,
):
    rows = [
        {"key": f"cmp-{i:012d}", "confidence": "possible campaign", "size": 3}
        for i in range(450)
    ]

    def handler(request):
        offset = int(request.url.params["offset"])
        return json_reply(
            {
                "results": rows[offset : offset + 200],
                "count": 200,
                "total": 450,
                "data_status": "ok",
                "algorithm_version": "c-1",
                "generated_at": f"page-{offset}",
            }
        )

    world.serve_paths({"/api/v1/campaigns": handler})
    data = clean(world.run("--quiet", "campaigns", "--all", "--json")).json()
    assert [r.url.params["offset"] for r in world.requests] == ["0", "200", "400"]
    assert {r.url.params["limit"] for r in world.requests} == {"200"}
    assert len(data["results"]) == 450 and data["count"] == 450 and data["total"] == 450
    assert data["generated_at"] == "page-400", "the metadata is the last page's"


def test_campaigns_all_stops_on_an_empty_page(world):
    world.serve_paths({"/api/v1/campaigns": json_reply({"results": [], "total": 99})})
    data = clean(world.run("--quiet", "campaigns", "--all", "--json")).json()
    assert len(world.requests) == 1 and data["results"] == [] and data["count"] == 0


def test_campaigns_all_with_an_explicit_offset_is_a_single_page_PINNED_QUIRK(world):
    serve_campaigns(world)
    clean(world.run("--quiet", "campaigns", "--all", "--offset", "5", "--json"))
    assert (
        len(world.requests) == 1
        and world.params()["offset"] == "5"
        and world.params()["limit"] == "20"
    )


def test_campaigns_text_view(world):
    serve_campaigns(world)
    run = clean(world.run("--quiet", "campaigns"))
    text = run.etext
    assert run.out == ""
    for needle in (
        "c-1",
        "2026-10-18T04:00:00Z",
        CAMPAIGN_KEY,
        "cmp-bbbbbbbbbbbb",
        "possible campaign",
        "suspected cluster",
        "12",
        "paypal, ebay",
        "shared_ip 0.80",
        "2026-10-18 05:00",
        "campaign KEY",
    ):
        assert needle in text, needle
    assert re.search(r"\b2 on this page\b", text) and re.search(r"\b2 matched\b", text)
    assert "stale" not in text.lower()


def test_campaigns_text_warns_when_the_correlation_data_is_not_ok(world):
    serve_campaigns(world, {**CAMPAIGN_LIST, "data_status": "stale"})
    assert "stale" in clean(world.run("--quiet", "campaigns")).etext.lower()


def test_campaign_detail_request_json_and_key_is_stripped(world):
    serve_campaigns(world)
    run = clean(world.run("--quiet", "campaign", f"  {CAMPAIGN_KEY} ", "--json"))
    assert (
        world.paths == [f"/api/v1/campaigns/{CAMPAIGN_KEY}"]
        and run.json() == CAMPAIGN_DETAIL
    )


def test_campaign_detail_view_content(world):
    serve_campaigns(world)
    text = clean(world.run("--quiet", "campaign", CAMPAIGN_KEY)).etext
    for needle in (
        CAMPAIGN_KEY,
        "77",
        "live",
        "cmp-ccc",
        "possible campaign",
        "0.91",
        "12",
        "9",
        "4",
        "paypal, ebay",
        "2026-10-01T00:00:00Z",
        "2026-10-18T05:00:00Z",
        "shared_ip (0.80)",
        "c-1",
        "https://phishunt.io/campaigns/x",
        "evidence",
        "203[.]0[.]113[.]2",
        "members (1)",
        "active",
        "90",
        "a[.]example",
        "GOPTU",
        "strongest pairs",
        "b[.]example",
        "0.7",
        "strong",
        "history",
        "2026-10-02 00:00",
        "grew",
        "size 5",
        "+b[.]example",
        "attribution",
    ):
        assert needle in text, needle
    assert (
        "capped" in text
        or "truncated" in text.lower()
        or "strongest relationships" in text
    ), "relationships_truncated is noted"


def test_campaign_detail_view_caps_evidence_members_pairs_and_history(world):
    big = {
        **CAMPAIGN_DETAIL,
        "evidence_summary": [
            {"type": f"ev{i:02d}", "value": f"v{i}", "members_matching": 1}
            for i in range(30)
        ],
        "members": [
            {
                "status": "active",
                "score": i,
                "company": "m",
                "domain": f"m{i:02d}.example",
            }
            for i in range(55)
        ],
        "relationships": [
            {
                "domain_a": f"pa{i:02d}.example",
                "domain_b": "x.example",
                "score": 1,
                "tier": "t",
            }
            for i in range(20)
        ],
        "history": [
            {"at": f"2026-10-{i + 1:02d}T00:00:00Z", "event": f"evt{i:02d}", "size": i}
            for i in range(12)
        ],
    }
    serve_campaigns(world, detail=big)
    text = clean(world.run("--quiet", "campaign", CAMPAIGN_KEY)).etext
    assert "ev19" in text and "ev20" not in text
    assert (
        "m39[.]example" in text
        and "m40[.]example" not in text
        and "members (55)" in text
    )
    assert "pa11[.]example" in text and "pa12[.]example" not in text
    assert "evt07" in text and "evt08" not in text
    assert "40" in text and ("truncated" in text.lower() or "--json" in text), (
        "a member-table truncation note"
    )


def test_campaign_evidence_values_are_cut_to_140_characters(world):
    long_value = "Q" * 300
    serve_campaigns(
        world,
        detail={
            **CAMPAIGN_DETAIL,
            "evidence_summary": [
                {"type": "t", "value": long_value, "members_matching": 1}
            ],
        },
    )
    assert clean(world.run("--quiet", "campaign", CAMPAIGN_KEY)).err.count("Q") == 140


@pytest.mark.parametrize("fmt", ["csv", "txt"])
def test_campaign_export_csv_and_txt_go_raw_to_stdout_with_a_trailing_newline(
    world, fmt
):
    world.serve_paths(
        {
            f"/api/v1/campaigns/{CAMPAIGN_KEY}/export": text_reply(
                "domain\na.example\nb.example", ctype="text/csv"
            )
        }
    )
    run = clean(world.run("--quiet", "campaign", CAMPAIGN_KEY, "--export", fmt))
    assert run.out == "domain\na.example\nb.example\n" and world.params() == {
        "format": fmt
    }
    assert world.paths == [f"/api/v1/campaigns/{CAMPAIGN_KEY}/export"]


def test_campaign_export_csv_with_out_writes_the_file_and_not_stdout(world, tmp_path):
    world.serve_paths(
        {f"/api/v1/campaigns/{CAMPAIGN_KEY}/export": text_reply("a,b\n1,2\n")}
    )
    target = tmp_path / "deep" / "dir" / "c.csv"
    run = clean(
        world.run(
            "--quiet", "campaign", CAMPAIGN_KEY, "--export", "csv", "--out", str(target)
        )
    )
    assert (
        run.out == "" and target.read_bytes().replace(b"\r\n", b"\n") == b"a,b\n1,2\n"
    )
    assert str(target) in run.err.replace("\n", "") or target.name in run.etext


def test_campaign_export_json_parses_saves_pretty_and_renders_the_view(world, tmp_path):
    world.serve_paths(
        {f"/api/v1/campaigns/{CAMPAIGN_KEY}/export": json_reply(CAMPAIGN_DETAIL)}
    )
    target = tmp_path / "c.json"
    run = clean(
        world.run(
            "--quiet",
            "campaign",
            CAMPAIGN_KEY,
            "--export",
            "json",
            "--out",
            str(target),
        )
    )
    assert run.out == "" and CAMPAIGN_KEY in run.etext
    saved = target.read_bytes().decode("utf-8").replace("\r\n", "\n")
    assert (
        json.loads(saved) == CAMPAIGN_DETAIL
        and saved.startswith('{\n  "key"')
        and saved.endswith("}\n")
    )


def test_campaign_export_json_with_the_json_flag_prints_the_object(world):
    world.serve_paths(
        {f"/api/v1/campaigns/{CAMPAIGN_KEY}/export": json_reply(CAMPAIGN_DETAIL)}
    )
    assert (
        clean(
            world.run("--quiet", "campaign", CAMPAIGN_KEY, "--export", "json", "--json")
        ).json()
        == CAMPAIGN_DETAIL
    )


def test_campaign_export_json_that_is_not_json_is_an_error(world):
    world.serve_paths(
        {f"/api/v1/campaigns/{CAMPAIGN_KEY}/export": text_reply("not json")}
    )
    run = world.run("--quiet", "campaign", CAMPAIGN_KEY, "--export", "json", "--json")
    assert run.code == 1 and "export was not JSON" in run.etext


@pytest.mark.parametrize("fmt", ["csv", "txt"])
def test_campaign_export_csv_or_txt_combined_with_json_always_fails_PINNED_QUIRK(
    world, fmt
):
    world.serve_paths(
        {f"/api/v1/campaigns/{CAMPAIGN_KEY}/export": text_reply("a,b\n1,2\n")}
    )
    run = world.run("--quiet", "campaign", CAMPAIGN_KEY, "--export", fmt, "--json")
    assert run.code == 1 and "export was not JSON" in run.etext and run.out == ""


# -- related, enrich ----------------------------------------------------------------------


@pytest.mark.parametrize("command", ["related", "enrich"])
@pytest.mark.parametrize(
    "bad",
    [
        "not-a-uuid",
        "",
        uid(1)[:-1],
        uid(1) + "0",
        uid(1).replace("-", ""),
        "zzzzzzzz-0000-4000-8000-000000000001",
        f"{uid(1)}/../x",
        f" {uid(1)}",
    ],
)
def test_uuid_arguments_are_validated_before_any_request(world, command, bad):
    world.serve(json_reply({}))
    run = world.run("--quiet", command, bad)
    assert run.code == 2 and world.requests == [] and "uuid" in run.etext


def test_related_request_and_json(world):
    world.serve_paths(
        {f"/api/v1/domains/{uid(1)}/related": json_reply(RELATED_PAYLOAD)}
    )
    run = clean(world.run("--quiet", "related", uid(1), "--json"))
    assert run.json() == RELATED_PAYLOAD and world.query_keys() == [
        "limit",
        "min_score",
    ]
    assert world.params() == {"limit": "10", "min_score": "0"}


@pytest.mark.parametrize(
    "argv,params",
    [
        (("--limit", "3", "--min-score", "40"), {"limit": "3", "min_score": "40"}),
        (
            (
                "--limit",
                "0",
            ),
            {"limit": "10", "min_score": "0"},
        ),
    ],
)
def test_related_limit_and_min_score(world, argv, params):
    world.serve_paths(
        {f"/api/v1/domains/{uid(1)}/related": json_reply(RELATED_PAYLOAD)}
    )
    clean(world.run("--quiet", "related", uid(1), "--json", *argv))
    assert world.params() == params


def test_related_accepts_an_upper_case_uuid(world):
    world.serve(json_reply(RELATED_PAYLOAD))
    clean(world.run("--quiet", "related", uid(255).upper(), "--json"))
    assert world.paths == [f"/api/v1/domains/{uid(255).upper()}/related"]


def test_related_view_content(world):
    world.serve_paths(
        {f"/api/v1/domains/{uid(1)}/related": json_reply(RELATED_PAYLOAD)}
    )
    text = clean(world.run("--quiet", "related", uid(1))).etext
    for needle in (
        "paypal-login1[.]example[.]net",
        "r-1",
        "2026-10-18T04:00:00Z",
        CAMPAIGN_KEY,
        "12",
        "9",
        "https://phishunt.io/campaigns/x",
        "0.8",
        "active",
        "paypal",
        "sib[.]example",
        "shared_ip, same_cert",
        "attribution",
    ):
        assert needle in text, needle


def test_related_view_without_a_cluster_or_results(world):
    world.serve_paths(
        {
            f"/api/v1/domains/{uid(1)}/related": json_reply(
                {"domain": "a.example", "results": []}
            )
        }
    )
    text = clean(world.run("--quiet", "related", uid(1))).etext
    assert (
        "not currently in a surfaced cluster" in text
        and "no related indicators at this threshold" in text
    )


def test_enrich_request_has_a_trailing_slash_and_json_is_the_object(world):
    world.serve_paths({f"/api/v1/enrich/{uid(1)}/": json_reply(ENRICH_PAYLOAD)})
    run = clean(world.run("--quiet", "enrich", uid(1), "--json"))
    assert run.json() == ENRICH_PAYLOAD and world.paths == [f"/api/v1/enrich/{uid(1)}/"]


def test_enrich_view_content_and_absent_blocks_are_skipped(world):
    world.serve_paths({f"/api/v1/enrich/{uid(1)}/": json_reply(ENRICH_PAYLOAD)})
    text = clean(world.run("--quiet", "enrich", uid(1))).etext
    for needle in (
        "Example Registrar LLC",
        "2026-09-30",
        "2026-10-01",
        "2027-09-30",
        "clientTransferProhibited, ok",
        "Frankfurt",
        "Hesse",
        "DE",
        "60313",
        "50.1,8.6",
        "static[.]example[.]net",
        "not identity",
    ):
        assert needle in text, needle
    world.serve_paths(
        {
            f"/api/v1/enrich/{uid(1)}/": json_reply(
                {"whois": "garbage", "ipinfo": {"city": "Oslo", "error": "partial"}}
            )
        }
    )
    text = clean(world.run("--quiet", "enrich", uid(1))).etext
    assert "Oslo" in text and "partial" in text and "garbage" not in text


# -- brand, cert -------------------------------------------------------------------------


def test_brand_request_json_and_view(world):
    world.serve_paths({"/api/v1/brands/paypal.json": json_reply(BRAND_PAYLOAD)})
    assert (
        clean(world.run("--quiet", "brand", "  PayPal ", "--json")).json()
        == BRAND_PAYLOAD
    )
    assert world.paths == ["/api/v1/brands/paypal.json"]
    text = clean(world.run("--quiet", "brand", "paypal")).etext
    for needle in (
        "PayPal",
        "paypal",
        "finance",
        "payments",
        "paypal.com",
        "41",
        "most targeted",
        "https://phishunt.io/b/paypal",
    ):
        assert needle in text, needle


def test_brand_vertical_falls_back_to_category(world):
    world.serve_paths(
        {
            "/api/v1/brands/paypal.json": json_reply(
                {"name": "PayPal", "category": "fintech"}
            )
        }
    )
    assert "fintech" in clean(world.run("--quiet", "brand", "paypal")).etext


def test_cert_request_json_and_view(world):
    world.serve_paths({"/api/v1/certs/R3.json": json_reply(CERT_PAYLOAD)})
    assert clean(world.run("--quiet", "cert", "  R3 ", "--json")).json() == CERT_PAYLOAD
    assert world.paths == ["/api/v1/certs/R3.json"]
    text = clean(world.run("--quiet", "cert", "R3")).etext
    for needle in (
        "R3",
        "Let's Encrypt",
        "ISRG Root X1",
        "2020-09-04",
        "RSA",
        "free DV",
        "R10, R11",
        "1200",
        "free CA",
        "https://phishunt.io/c/r3",
        "common",
    ):
        assert needle in text, needle


# -- inspect -----------------------------------------------------------------------------------


def serve_inspect(world, *, related=None, enrich=None, rows=None):
    world.serve_paths(
        {
            "/feed.json": json_reply(FEED if rows is None else rows),
            f"/api/v1/domains/{uid(1)}/related": related or json_reply(RELATED_PAYLOAD),
            f"/api/v1/enrich/{uid(1)}/": enrich or json_reply(ENRICH_PAYLOAD),
        }
    )


def test_inspect_json_shape_and_request_order(world):
    serve_inspect(world)
    run = clean(world.run("--quiet", "inspect", uid(1), "--json"))
    assert run.json() == {
        "active": ROW_PAYPAL,
        "related": RELATED_PAYLOAD,
        "enrich": ENRICH_PAYLOAD,
    }
    assert world.paths == [
        "/feed.json",
        f"/api/v1/domains/{uid(1)}/related",
        f"/api/v1/enrich/{uid(1)}/",
    ]
    assert (
        world.requests[1].url.params["limit"] == "10"
        and world.requests[1].url.params["min_score"] == "0"
    )
    assert list(run.json()) == ["active", "related", "enrich"]


def test_inspect_limit_sizes_the_related_request_and_zero_means_10(world):
    serve_inspect(world)
    clean(world.run("--quiet", "inspect", uid(1), "--json", "--limit", "4"))
    assert world.requests[1].url.params["limit"] == "4"
    clean(world.run("--quiet", "inspect", uid(1), "--json", "--limit", "0"))
    assert world.requests[-2].url.params["limit"] == "10"


def test_inspect_skip_flags_make_the_sections_null_and_send_nothing(world):
    serve_inspect(world)
    run = clean(
        world.run(
            "--quiet", "inspect", uid(1), "--json", "--skip-related", "--skip-enrich"
        )
    )
    assert run.json() == {
        "active": ROW_PAYPAL,
        "related": None,
        "enrich": None,
    } and world.paths == ["/feed.json"]
    run = clean(world.run("--quiet", "inspect", uid(1), "--json", "--skip-enrich"))
    assert run.json()["enrich"] is None and run.json()["related"] == RELATED_PAYLOAD


def test_inspect_finds_the_row_case_insensitively_and_null_when_not_in_the_feed(world):
    serve_inspect(world, rows=[{**ROW_PAYPAL, "uuid": uid(1).upper()}])
    assert (
        clean(
            world.run(
                "--quiet",
                "inspect",
                uid(1),
                "--json",
                "--skip-related",
                "--skip-enrich",
            )
        ).json()["active"]["uuid"]
        == uid(1).upper()
    )
    serve_inspect(world, rows=[ROW_PAGES])
    world.cache_file.unlink()
    assert (
        clean(
            world.run(
                "--quiet",
                "inspect",
                uid(1),
                "--json",
                "--skip-related",
                "--skip-enrich",
            )
        ).json()["active"]
        is None
    )


def test_inspect_captures_a_failing_section_as_an_error_object_instead_of_failing(
    world,
):
    serve_inspect(
        world,
        related=json_reply({"error": "no relations"}, status=404),
        enrich=text_reply("boom", status=500),
    )
    run = clean(world.run("--quiet", "inspect", uid(1), "--json"))
    data = run.json()
    assert data["active"] == ROW_PAYPAL
    assert (
        set(data["related"]) == {"error"}
        and "HTTP 404" in data["related"]["error"]
        and "no relations" in data["related"]["error"]
    )
    assert set(data["enrich"]) == {"error"} and "HTTP 500" in data["enrich"]["error"]
    assert world.paths.count(f"/api/v1/enrich/{uid(1)}/") == 4, (
        "a failing enrich is retried 4 times before it is captured"
    )


def test_inspect_text_view_shows_the_card_the_related_view_and_the_enrich_view(world):
    serve_inspect(world)
    text = clean(world.run("--quiet", "inspect", uid(1))).etext
    for needle in (
        uid(1),
        "paypal-login1[.]example[.]net",
        "critical",
        "92",
        "sib[.]example",
        "Example Registrar LLC",
        "Frankfurt",
    ):
        assert needle in text, needle


def test_inspect_text_warns_when_the_uuid_is_not_in_the_feed_and_names_the_related_domain(
    world,
):
    serve_inspect(world, rows=[ROW_PAGES])
    text = clean(world.run("--quiet", "inspect", uid(1))).etext
    assert (
        "not in the current active feed" in text
        and "paypal-login1[.]example[.]net" in text
        and "sib[.]example" in text
    )


def test_inspect_text_prints_section_warnings_for_failures(world):
    serve_inspect(
        world,
        related=json_reply({"error": "gone"}, status=404),
        enrich=json_reply({"error": "rate"}, status=403),
    )
    text = clean(world.run("--quiet", "inspect", uid(1))).etext
    assert (
        "related:" in text and "gone" in text and "enrich:" in text and "rate" in text
    )


def test_inspect_enrich_with_whois_renders_even_when_it_has_an_error_key(world):
    serve_inspect(
        world, enrich=json_reply({**ENRICH_PAYLOAD, "error": "partial lookup"})
    )
    text = clean(world.run("--quiet", "inspect", uid(1))).etext
    assert "Example Registrar LLC" in text and "enrich:" not in text


@pytest.mark.parametrize("bad", ["nope", uid(1)[:-1]])
def test_inspect_validates_the_uuid_before_any_request(world, bad):
    serve_inspect(world)
    run = world.run("--quiet", "inspect", bad)
    assert run.code == 2 and world.requests == []


# ---------------------------------------------------------------------------------------------
# K. match: local-only matching, indicator grammar, exit code  [C11]
# ---------------------------------------------------------------------------------------------


def indicators_file(tmp_path, *lines, name="ind.txt", raw: bytes | None = None) -> str:
    path = tmp_path / name
    path.write_bytes(
        raw if raw is not None else ("\n".join(lines) + "\n").encode("utf-8")
    )
    return str(path)


MATCH_VECTORS = [  # (indicator as written, reason, matching row uuids in feed order)
    ("paypal-login1[.]example[.]net", "exact-domain", [uid(1)]),
    ("PAYPAL-LOGIN1.EXAMPLE.NET.", "exact-domain", [uid(1)]),
    ("xn--pypal-4ve.example", "exact-domain", [uid(3)]),
    ("203.0.113.2", "ip", [uid(1), uid(3)]),
    ("203[.]0[.]113[.]2", "ip", [uid(1), uid(3)]),
    ("http://203.0.113.2/login", "ip", [uid(1), uid(3)]),
    ("192.0.2.44", "ip", [uid(4)]),
    ("hxxps://kit[.]pages[.]dev/account/update", "exact-url", [uid(2)]),
    ("https://kit.pages.dev/account/update", "exact-url", [uid(2)]),
    ("HTTPS://KIT.PAGES.DEV/ACCOUNT/UPDATE", "exact-url", [uid(2)]),
    ("https://paypal-login1.example.net/signin/verify", "exact-url", [uid(1)]),
    ("https://kit.pages.dev/other", "exact-domain", [uid(2)]),
    ("kit.pages.dev/account", "exact-domain", [uid(2)]),
    ("sub.paypal-login1.example.net", "under-known-phish-host", [uid(1)]),
    ("example.net", "subdomain-of-indicator", [uid(1)]),
    ("pages.dev", "subdomain-of-indicator", [uid(2)]),
    ("com", None, []),
    ("www.safe.example", None, []),
    ("999.1.1.1", None, []),
    ("192.0.2.45", None, []),
    ("https://unknown.example/x", None, []),
    ("example", None, []),
]


@pytest.mark.parametrize(
    "indicator,reason,uuids", MATCH_VECTORS, ids=[v[0] for v in MATCH_VECTORS]
)
def test_match_rules_each_indicator_takes_the_first_applicable_rule(
    fed, tmp_path, indicator, reason, uuids
):
    data = clean(
        fed.run(
            "--quiet",
            "match",
            indicators_file(tmp_path, indicator),
            "--json",
            "--show-misses",
        )
    ).json()
    if reason is None:
        assert data["hits"] == [] and data["misses"] == [indicator]
    else:
        assert data["hits"] == [
            {
                "indicator": indicator,
                "reason": reason,
                "uuids": uuids,
                "domains": [
                    next(r["domain"] for r in FEED if r.get("uuid") == u) for u in uuids
                ],
            }
        ]
        assert data["misses"] == []


def test_match_json_shape_key_order_and_counts(fed, tmp_path):
    path = indicators_file(
        tmp_path, "paypal-login1[.]example[.]net", "nothing.example", "203.0.113.2"
    )
    data = clean(fed.run("--quiet", "match", path, "--json")).json()
    assert list(data) == [
        "indicators",
        "hit_indicators",
        "miss_indicators",
        "hits",
        "misses",
    ]
    assert (data["indicators"], data["hit_indicators"], data["miss_indicators"]) == (
        3,
        2,
        1,
    )
    assert data["misses"] == [] and list(data["hits"][0]) == [
        "indicator",
        "reason",
        "uuids",
        "domains",
    ]
    shown = clean(fed.run("--quiet", "match", path, "--json", "--show-misses")).json()
    assert shown["misses"] == ["nothing.example"] and shown["miss_indicators"] == 1


def test_match_is_local_only_only_the_unfiltered_feed_is_requested_and_no_indicator_is_sent(
    fed, tmp_path
):
    path = indicators_file(
        tmp_path,
        "secret-internal-host.corp.example",
        "10.1.2.3",
        "https://intranet.corp.example/login",
    )
    clean(fed.run("--quiet", "match", path, "--json"))
    assert fed.urls == [f"{BASE}/feed.json"]
    assert "corp" not in " ".join(fed.urls) and "10.1.2.3" not in " ".join(fed.urls)


def test_match_exit_code_is_1_only_with_fail_on_hit_and_a_hit(fed, tmp_path):
    hit = indicators_file(tmp_path, "paypal-login1.example.net", name="hit.txt")
    miss = indicators_file(tmp_path, "nothing.example", name="miss.txt")
    assert clean(fed.run("--quiet", "match", hit)).code == 0
    assert clean(fed.run("--quiet", "match", hit, "--json")).code == 0
    for extra in ((), ("--json",)):
        run = fed.run("--quiet", "match", hit, "--fail-on-hit", *extra)
        assert run.exc is None and run.code == 1, extra
    assert clean(fed.run("--quiet", "match", miss, "--fail-on-hit")).code == 0
    assert clean(fed.run("--quiet", "match", miss, "--fail-on-hit", "--json")).code == 0


def test_match_json_output_is_still_printed_when_fail_on_hit_returns_1(fed, tmp_path):
    run = fed.run(
        "--quiet",
        "match",
        indicators_file(tmp_path, "203.0.113.2"),
        "--fail-on-hit",
        "--json",
    )
    assert run.code == 1 and run.json()["hit_indicators"] == 1 and run.err == ""


def test_match_reads_indicators_from_stdin_with_a_dash(fed, monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO("paypal-login1[.]example[.]net\n# comment\n\nnothing.example\n"),
    )
    data = clean(fed.run("--quiet", "match", "-", "--json")).json()
    assert (data["indicators"], data["hit_indicators"]) == (2, 1)


@pytest.mark.parametrize(
    "lines,expected",
    [
        (["# only a comment", "", "   ", "a.example"], ["a.example"]),
        (["  a.example  "], ["a.example"]),
        (["a.example,some note", "b.example, x ,y"], ["a.example", "b.example"]),
        (['"a.example",note', "'b.example',note"], ["a.example", "b.example"]),
        (["https://x.example/a,b"], ["https://x.example/a,b"]),
        (["hxxps://x[.]example/a,b"], ["hxxps://x[.]example/a,b"]),
        (["#a.example", "  # indented comment is a comment too"], []),
        (
            ["a.example # trailing text is part of the value"],
            ["a.example # trailing text is part of the value"],
        ),
    ],
)
def test_match_indicator_file_grammar(fed, tmp_path, lines, expected):
    data = clean(
        fed.run(
            "--quiet",
            "match",
            indicators_file(tmp_path, *lines),
            "--json",
            "--show-misses",
        )
    ).json()
    assert data["indicators"] == len(expected)
    assert sorted(
        data["misses"] + [hit["indicator"] for hit in data["hits"]]
    ) == sorted(expected)


def test_match_accepts_a_non_utf8_file_by_replacing_bad_bytes(fed, tmp_path):
    path = indicators_file(
        tmp_path, name="latin.txt", raw=b"caf\xe9.example\npaypal-login1.example.net\n"
    )
    data = clean(fed.run("--quiet", "match", path, "--json")).json()
    assert data["indicators"] == 2 and data["hit_indicators"] == 1


@pytest.mark.parametrize("target", ["no-such-file.txt", "."])
def test_match_unreadable_input_is_exit_1_with_the_path_in_the_message(
    fed, tmp_path, target
):
    run = fed.run("--quiet", "match", target)
    assert (
        run.exc is None
        and run.code == 1
        and "could not read" in run.etext
        and target in run.etext
    )
    assert fed.requests == [], "the file is read before the feed is requested"


def test_match_exact_domain_returns_every_row_and_suffix_matches_dedupe_by_uuid(
    world, tmp_path
):
    rows = [
        {"uuid": uid(50), "domain": "dup.example"},
        {"uuid": uid(51), "domain": "dup.example"},
        {"uuid": uid(60), "domain": "p.parent.example"},
        {"uuid": uid(60), "domain": "q.parent.example"},
        {"uuid": uid(53)},
    ]
    world.serve_paths({"/feed.json": json_reply(rows)})
    path = indicators_file(tmp_path, "dup.example", "x.dup.example", "parent.example")
    hits = clean(world.run("--quiet", "match", path, "--json")).json()["hits"]
    assert [(h["reason"], h["uuids"]) for h in hits] == [
        ("exact-domain", [uid(50), uid(51)]),
        ("under-known-phish-host", [uid(50), uid(51)]),
        ("subdomain-of-indicator", [uid(60)]),
    ]


def test_match_text_view(fed, tmp_path):
    path = indicators_file(
        tmp_path,
        "203.0.113.2",
        "https://kit.pages.dev/account/update",
        "nothing.example",
    )
    run = clean(fed.run("--quiet", "match", path))
    text = run.etext
    assert run.out == ""
    assert re.search(r"\b3 indicators\b", text) and re.search(
        r"\b6 active detections\b", text
    )
    assert re.search(r"\b2 hit\b", text) and re.search(r"\b1 miss\b", text)
    for needle in (
        "203[.]0[.]113[.]2",
        "ip",
        "exact-url",
        "hxxps://kit[.]pages[.]dev/account/update",
        "paypal",
        "microsoft",
        "paypal-login1[.]example[.]net +1",
        "92",
        "75",
    ):
        assert needle in text, needle
    assert "nothing[.]example" not in text, "misses are listed only with --show-misses"
    assert (
        "nothing[.]example"
        in clean(fed.run("--quiet", "match", path, "--show-misses")).etext
    )


def test_match_export_writes_every_matched_row_with_the_extra_json_keys(fed, tmp_path):
    path = indicators_file(
        tmp_path,
        "203.0.113.2",
        "https://kit.pages.dev/account/update",
        "nothing.example",
    )
    clean(fed.run("--quiet", "match", path, "--export", "hits.json"))
    rows = json.loads((fed.cwd / "hits.json").read_bytes().decode("utf-8"))
    assert [(r["uuid"], r["matched_indicator"], r["match_reason"]) for r in rows] == [
        (uid(1), "203.0.113.2", "ip"),
        (uid(3), "203.0.113.2", "ip"),
        (uid(2), "https://kit.pages.dev/account/update", "exact-url"),
    ]
    assert (
        rows[0]["domain"] == "paypal-login1.example.net" and rows[0]["top_signals"]
    ), "full rows, unmodified"
    clean(
        fed.run(
            "--quiet",
            "match",
            indicators_file(tmp_path, "nothing.example", name="m.txt"),
            "--export",
            "none.json",
        )
    )
    assert json.loads((fed.cwd / "none.json").read_text(encoding="utf-8")) == []
    clean(fed.run("--quiet", "match", path, "--export", "json-mode.json", "--json"))
    assert json.loads((fed.cwd / "json-mode.json").read_text(encoding="utf-8")) == rows


@pytest.mark.parametrize("extension", ["json", "csv", "txt"])
@pytest.mark.parametrize("json_mode", [False, True])
def test_match_without_hits_writes_the_requested_empty_export(
    fed, tmp_path, extension, json_mode
):
    arguments = [
        "--quiet",
        "match",
        indicators_file(tmp_path, "nothing.example"),
        "--export",
        f"empty.{extension}",
    ]
    if json_mode:
        arguments.append("--json")
    run = clean(fed.run(*arguments))
    destination = fed.cwd / f"empty.{extension}"
    assert destination.is_file()
    if extension == "json":
        assert json.loads(destination.read_text(encoding="utf-8")) == []
    elif extension == "csv":
        with destination.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            assert reader.fieldnames == CSV_FIELDS and list(reader) == []
    else:
        assert destination.read_bytes() == b""
    if json_mode:
        assert run.json()["hit_indicators"] == 0


def test_match_csv_export_preserves_match_columns(fed, tmp_path):
    clean(
        fed.run(
            "--quiet",
            "match",
            indicators_file(tmp_path, "203.0.113.2"),
            "--export",
            "hits.csv",
        )
    )
    with (fed.cwd / "hits.csv").open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == [*CSV_FIELDS, "matched_indicator", "match_reason"]
        rows = list(reader)
        assert len(rows) == 2
        assert all(
            row["matched_indicator"] == "203.0.113.2" and row["match_reason"] == "ip"
            for row in rows
        )


# ---------------------------------------------------------------------------------------------
# L. watch: polling, cursor, de-duplication, interval floor, Ctrl-C  [C12]
# ---------------------------------------------------------------------------------------------

SINCE = "2026-10-12T00:00:00Z"
NEW_A = {
    "uuid": uid(61),
    "domain": "new-a.example",
    "company": "paypal",
    "score": 70,
    "first_seen": "2026-10-12T05:00:00Z",
    "date": "2026-10-12T06:00:00Z",
}
NEW_B = {
    "uuid": uid(62),
    "domain": "new-b.example",
    "company": "ebay",
    "score": 30,
    "first_seen": "2026-10-12T08:00:00Z",
    "date": "2026-10-12T09:00:00Z",
}
OLD_RECHECK = {
    "uuid": uid(63),
    "domain": "old.example",
    "first_seen": "2026-10-01T00:00:00Z",
    "date": "2026-10-12T07:00:00Z",
}


def watch_page(*rows):
    return json_reply({"results": list(rows), "total": len(rows)})


def json_documents(text: str) -> list:
    """Every back-to-back JSON document in `text` (watch --json prints one pretty object per poll)."""
    decoder, position, documents = json.JSONDecoder(), 0, []
    while True:
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            return documents
        document, position = decoder.raw_decode(text, position)
        documents.append(document)


def test_watch_requests_since_limit_then_filters_in_that_order_with_the_company_lower_cased(
    world,
):
    serve_domains(world, watch_page())
    clean(
        world.run(
            "--quiet",
            "watch",
            "--once",
            "--json",
            "--since",
            SINCE,
            "--company",
            "PayPal",
            "--country",
            "Germany",
            "--tier",
            "verified",
        )
    )
    assert world.query_keys() == ["since", "limit", "company", "country", "tier"]
    assert world.params() == {
        "since": SINCE,
        "limit": "1000",
        "company": "paypal",
        "country": "Germany",
        "tier": "verified",
    }
    assert world.paths == ["/api/v1/domains"]


def test_watch_without_filters_sends_only_since_and_limit(world):
    serve_domains(world, watch_page())
    clean(world.run("--quiet", "watch", "--once", "--json", "--since", SINCE))
    assert world.query_keys() == ["since", "limit"]


def test_watch_default_since_is_now_in_utc_second_precision(world):
    serve_domains(world, watch_page())
    clean(world.run("--quiet", "watch", "--once", "--json"))
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", world.params()["since"])


def test_watch_prints_its_panel_on_stderr_even_in_json_mode_with_the_since_and_floored_interval(
    world,
):
    serve_domains(world, watch_page())
    run = clean(
        world.run(
            "--quiet", "watch", "--once", "--json", "--since", SINCE, "--interval", "5"
        )
    )
    assert (
        SINCE in run.err and re.search(r"\b30(?!\d)", run.err) and "Ctrl-C" in run.err
    )
    assert run.out == "", "a quiet poll prints nothing on stdout in JSON mode"


@pytest.mark.parametrize(
    "interval,slept",
    [
        ("5", 30),
        ("29", 30),
        ("30", 30),
        ("45", 45),
        ("300", 300),
        ("0", 300),
        ("-9", 30),
    ],
)
def test_watch_interval_has_a_30_second_floor_and_zero_means_300(
    world, interval, slept
):
    serve_domains(world, watch_page())
    world.stop_after_sleeps(1)
    run = world.run(
        "--quiet", "watch", "--json", "--since", SINCE, "--interval", interval
    )
    assert run.code == 130 and world.slept == [slept]


def test_watch_default_interval_is_300_seconds(world):
    serve_domains(world, watch_page())
    world.stop_after_sleeps(1)
    assert world.run(
        "--quiet", "watch", "--json", "--since", SINCE
    ).code == 130 and world.slept == [300]


def test_watch_once_returns_0_after_one_poll_without_sleeping(world):
    serve_domains(world, watch_page(NEW_A))
    clean(world.run("--quiet", "watch", "--once", "--json", "--since", SINCE))
    assert len(world.requests) == 1 and world.slept == []


def test_watch_json_prints_since_count_results_for_the_new_rows_only(world):
    serve_domains(world, watch_page(NEW_A, OLD_RECHECK))
    data = clean(
        world.run("--quiet", "watch", "--once", "--json", "--since", SINCE)
    ).json()
    assert list(data) == ["since", "count", "results"] and data == {
        "since": SINCE,
        "count": 1,
        "results": [NEW_A],
    }


def test_watch_skips_rows_first_seen_before_since_compared_on_19_characters(world):
    rows = [
        {"uuid": uid(70), "first_seen": "2026-10-11T23:59:59Z"},
        {"uuid": uid(71), "first_seen": "2026-10-12T00:00:00+00:00"},
        {"uuid": uid(72), "first_seen": "2026-10-12T00:00:00Z"},
        {"uuid": uid(73)},
    ]
    serve_domains(world, watch_page(*rows))
    data = clean(
        world.run("--quiet", "watch", "--once", "--json", "--since", SINCE)
    ).json()
    assert sorted(r["uuid"] for r in data["results"]) == [uid(71), uid(72), uid(73)]


def test_watch_sorts_new_rows_newest_first_seen_first(world):
    serve_domains(world, watch_page(NEW_A, NEW_B))
    assert [
        r["uuid"]
        for r in clean(
            world.run("--quiet", "watch", "--once", "--json", "--since", SINCE)
        ).json()["results"]
    ] == [uid(62), uid(61)]


def test_watch_applies_client_filters(world):
    serve_domains(world, watch_page(NEW_A, NEW_B))
    data = clean(
        world.run(
            "--quiet",
            "watch",
            "--once",
            "--json",
            "--since",
            SINCE,
            "--min-score",
            "50",
        )
    ).json()
    assert [r["uuid"] for r in data["results"]] == [uid(61)]


def test_watch_cursor_moves_to_the_newest_stamp_even_from_a_skipped_old_recheck_and_rows_are_not_repeated(
    world,
):
    world.serve_sequence(
        [watch_page(NEW_A, OLD_RECHECK), watch_page(NEW_A, NEW_B), watch_page()]
    )
    world.stop_after_sleeps(3)
    run = world.run("--quiet", "watch", "--json", "--since", SINCE, "--interval", "30")
    assert run.code == 130 and len(world.requests) == 3 and world.slept == [30, 30, 30]
    assert [r.url.params["since"] for r in world.requests] == [
        SINCE,
        "2026-10-12T07:00:00Z",
        "2026-10-12T09:00:00Z",
    ]
    documents = json_documents(run.out)
    assert [
        (d["since"], d["count"], [r["uuid"] for r in d["results"]]) for d in documents
    ] == [(SINCE, 1, [uid(61)]), ("2026-10-12T07:00:00Z", 1, [uid(62)])], (
        "back-to-back JSON documents, not JSON lines"
    )


def test_watch_rows_without_a_uuid_are_reported_on_every_poll(world):
    row = {"domain": "anon.example", "first_seen": "2026-10-12T05:00:00Z"}
    serve_domains(world, watch_page(row))
    world.stop_after_sleeps(2)
    run = world.run("--quiet", "watch", "--json", "--since", SINCE)
    assert run.out.count('"anon.example"') == 2


def test_watch_text_mode_prints_a_count_and_the_table_or_a_quiet_line(world):
    world.serve_sequence([watch_page(NEW_A), watch_page()])
    world.stop_after_sleeps(2)
    run = world.run("--quiet", "watch", "--since", SINCE)
    assert run.code == 130 and run.out == ""
    assert (
        re.search(r"\b1 new\b", run.etext)
        and "new-a[.]example" in run.etext
        and "quiet" in run.etext.lower()
    )


def test_watch_text_table_is_limited_by_limit_but_json_and_log_are_not(world, tmp_path):
    rows = [
        {
            "uuid": uid(80 + i),
            "domain": f"w{i}.example",
            "first_seen": f"2026-10-12T0{i}:00:00Z",
        }
        for i in range(5)
    ]
    serve_domains(world, watch_page(*rows))
    log = tmp_path / "w.log"
    text = clean(
        world.run(
            "--quiet",
            "watch",
            "--once",
            "--since",
            SINCE,
            "--limit",
            "2",
            "--log",
            str(log),
        )
    )
    assert (
        "w4[.]example" in text.etext
        and "w3[.]example" in text.etext
        and "w2[.]example" not in text.etext
    )
    assert len(log.read_text("utf-8").splitlines()) == 5
    data = clean(
        world.run(
            "--quiet", "watch", "--once", "--json", "--since", SINCE, "--limit", "2"
        )
    ).json()
    assert data["count"] == 5 and len(data["results"]) == 5


def test_watch_log_appends_compact_json_lines_in_utf8_across_polls(world, tmp_path):
    row_a = {**NEW_A, "org": "Caf\u00e9 \u4e2d\u6587"}
    world.serve_sequence([watch_page(row_a), watch_page(NEW_B)])
    world.stop_after_sleeps(2)
    log = tmp_path / "nested.log"
    log.write_text('{"earlier": true}\n', encoding="utf-8")
    run = world.run("--quiet", "watch", "--json", "--since", SINCE, "--log", str(log))
    assert run.code == 130
    lines = log.read_bytes().decode("utf-8").splitlines()
    assert lines[0] == '{"earlier": true}' and len(lines) == 3
    assert json.loads(lines[1]) == row_a and json.loads(lines[2]) == NEW_B
    assert (
        "Caf\u00e9" in lines[1] and "\\u" not in lines[1] and "\n  " not in lines[1]
    ), "compact, not escaped"


@pytest.mark.parametrize("status,code", [(500, 1), (404, 2), (403, 1)])
def test_watch_a_phishunt_error_ends_the_command_with_the_usual_exit_code(
    world, status, code
):
    serve_domains(world, text_reply("nope", status=status))
    run = world.run("--quiet", "watch", "--since", SINCE)
    assert run.exc is None and run.code == code and f"HTTP {status}" in run.etext


def test_watch_ctrl_c_during_the_poll_or_the_sleep_is_exit_130(world):
    serve_domains(world, watch_page())
    world.stop_after_sleeps(1)
    run = world.run("--quiet", "watch", "--since", SINCE)
    assert run.code == 130 and "stopped" in run.etext.lower()
    world.serve(handler=lambda request: KeyboardInterrupt())
    assert world.run("--quiet", "watch", "--since", SINCE).code == 130


def test_watch_has_a_json_flag_and_no_server_filters_beyond_company_country_tier(world):
    sub = subparsers_of(world.lj.build_parser()).choices["watch"]
    options_seen = {opt for action in sub._actions for opt in action.option_strings}
    assert (
        "--json" in options_seen
        and "--asn" not in options_seen
        and "--contains" not in options_seen
        and "--org" not in options_seen
    )


# ---------------------------------------------------------------------------------------------
# M. snapshot and diff  [C13]
# ---------------------------------------------------------------------------------------------

OLD_ONLY = {
    "uuid": uid(90),
    "domain": "gone.example",
    "company": "ebay",
    "country": "Spain",
    "first_seen": "2026-09-01T00:00:00Z",
}


def snapshot_file(directory: Path, sites, *, bare=False, name="snap.json") -> str:
    path = directory / name
    payload = (
        list(sites)
        if bare
        else {
            "tool": "Lanternjaw",
            "version": "1.0.0",
            "saved_at": "2026-10-10T00:00:00Z",
            "count": len(sites),
            "sites": list(sites),
        }
    )
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_snapshot_writes_one_compact_line_with_the_documented_envelope(fed):
    run = clean(fed.run("--quiet", "snapshot", "--out", "snap.json"))
    raw = (fed.cwd / "snap.json").read_bytes()
    assert raw.endswith(b"\n") and raw.count(b"\n") == 1, (
        "one compact line plus a newline"
    )
    envelope = json.loads(raw.decode("utf-8"))
    assert list(envelope) == ["tool", "version", "saved_at", "count", "sites"]
    assert (
        envelope["tool"] == "Lanternjaw"
        and envelope["version"] == "1.0.0"
        and envelope["count"] == 6
        and envelope["sites"] == FEED
    )
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", envelope["saved_at"])
    assert run.out == "" and "snap.json" in run.etext.replace(" ", "")


def test_snapshot_default_name_is_utc_timestamped_in_the_working_directory(fed):
    clean(fed.run("--quiet", "snapshot"))
    names = [path.name for path in fed.cwd.iterdir()]
    assert len(names) == 1 and re.fullmatch(
        r"lanternjaw-snapshot-\d{8}T\d{6}Z\.json", names[0]
    )


def test_snapshot_out_creates_parent_directories(fed, tmp_path):
    target = tmp_path / "a" / "b" / "s.json"
    clean(fed.run("--quiet", "snapshot", "--out", str(target)))
    assert json.loads(target.read_text("utf-8"))["count"] == 6


def test_snapshot_json_prints_path_count_saved_at_and_suppresses_notices(fed):
    run = clean(fed.run("--quiet", "snapshot", "--out", "snap.json", "--json"))
    data = run.json()
    assert (
        list(data) == ["path", "count", "saved_at"]
        and data["path"] == "snap.json"
        and data["count"] == 6
    )
    assert (
        data["saved_at"]
        == json.loads((fed.cwd / "snap.json").read_text("utf-8"))["saved_at"]
        and run.err == ""
    )


def test_snapshot_fresh_refetches_and_otherwise_uses_the_cache(fed):
    fed.cache_rows([ROW_PAYPAL])
    clean(fed.run("--quiet", "snapshot", "--out", "a.json"))
    assert (
        json.loads((fed.cwd / "a.json").read_text("utf-8"))["count"] == 1
        and fed.requests == []
    )
    clean(fed.run("--quiet", "--fresh", "snapshot", "--out", "b.json"))
    assert json.loads((fed.cwd / "b.json").read_text("utf-8"))["count"] == 6


def test_diff_json_shape_and_values(fed, tmp_path):
    path = snapshot_file(tmp_path, [ROW_PAYPAL, ROW_PLAIN, OLD_ONLY])
    data = clean(fed.run("--quiet", "diff", path, "--json")).json()
    assert list(data) == ["before", "now", "added", "gone", "added_rows", "gone_rows"]
    assert (data["before"], data["now"], data["added"], data["gone"]) == (3, 5, 3, 1)
    assert data["added_rows"] == [ROW_BANK, ROW_PUNY, ROW_PAGES] and data[
        "gone_rows"
    ] == [OLD_ONLY]


def test_diff_accepts_a_bare_array_snapshot_and_ignores_rows_without_a_uuid(
    fed, tmp_path
):
    path = snapshot_file(tmp_path, [ROW_PAYPAL, ROW_NOUUID], bare=True)
    data = clean(fed.run("--quiet", "diff", path, "--json")).json()
    assert (
        data["before"] == 1
        and data["now"] == 5
        and data["added"] == 4
        and data["gone"] == 0
    )


def test_diff_always_fetches_a_fresh_feed_even_when_the_cache_is_warm(fed, tmp_path):
    fed.cache_rows([ROW_PAYPAL])
    clean(fed.run("--quiet", "diff", snapshot_file(tmp_path, [ROW_PAYPAL]), "--json"))
    assert fed.paths == ["/feed.json"]


@pytest.mark.parametrize(
    "content,needle",
    [
        ("not json{", "could not read snapshot"),
        ('{"tool": "x"}', "sites array"),
        ('{"sites": "nope"}', "sites array"),
        ('"a string"', "sites array"),
        ("42", "sites array"),
    ],
)
def test_diff_unreadable_or_malformed_snapshots_are_exit_1(
    fed, tmp_path, content, needle
):
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    run = fed.run("--quiet", "diff", str(path))
    assert run.exc is None and run.code == 1 and needle in run.etext
    assert fed.requests == [], "the snapshot is read before the feed is requested"


def test_diff_missing_snapshot_is_exit_1(fed):
    run = fed.run("--quiet", "diff", "nope.json")
    assert (
        run.code == 1 and "could not read snapshot" in run.etext and fed.requests == []
    )


NARROWING = [  # (flags, uuids kept from the full FEED)
    (("--company", "PayPal"), [uid(1), uid(3)]),
    (("--company", "paypal"), [uid(1), uid(3)]),
    (("--country", "France"), [uid(4), uid(5)]),
    (("--country", "france"), []),
    (("--org", "OVH SAS"), [uid(4)]),
    (("--cert", "R3"), [uid(1), uid(3)]),
    (("--ip", "203.0.113.2"), [uid(1), uid(3)]),
    (("--asn", "AS13335"), [uid(1), uid(2)]),
    (("--asn", "13335"), [uid(1), uid(2)]),
    (("--asn", "as16276"), [uid(4)]),
    (("--contains", "PAGES"), [uid(2)]),
    (("--contains", "bank-update"), [uid(4)]),
    (("--contains", "kit.pages"), [uid(2)]),
    (("--since", "2026-10-18"), [uid(3), uid(4)]),
    (("--since", "2026-10-17T12:00:00+00:00"), [uid(2), uid(3), uid(4)]),
    (("--verdict", "critical"), [uid(1)]),
    (("--min-score", "70"), [uid(1), uid(2)]),
    (("--min-sources", "2"), [uid(1), uid(4)]),
    (("--company", "paypal", "--country", "Germany", "--min-score", "50"), [uid(1)]),
]


@pytest.mark.parametrize(
    "flags,kept", NARROWING, ids=[" ".join(f) for f, _ in NARROWING]
)
def test_diff_narrows_both_sides_with_the_same_local_filters(
    fed, tmp_path, flags, kept
):
    path = snapshot_file(tmp_path, [{**row} for row in FEED if row.get("uuid")])
    data = clean(fed.run("--quiet", "diff", path, "--json", *flags)).json()
    assert (
        data["before"] == len(kept)
        and data["now"] == len(kept)
        and data["added"] == 0
        and data["gone"] == 0
    )
    assert fed.paths == ["/feed.json"], "narrowing is local: never a domains request"


def test_diff_registrar_narrowing_uses_exact_string_equality(world, tmp_path):
    rows = [{**ROW_PAYPAL, "registrar": "Reg A"}, {**ROW_PAGES, "registrar": "Reg B"}]
    world.serve_paths({"/feed.json": json_reply(rows)})
    data = clean(
        world.run(
            "--quiet",
            "diff",
            snapshot_file(tmp_path, rows),
            "--json",
            "--registrar",
            "Reg A",
        )
    ).json()
    assert data["before"] == 1 and data["now"] == 1


def test_a_brand_scoped_diff_does_not_mark_other_brands_gone(fed, tmp_path):
    path = snapshot_file(tmp_path, [ROW_PAYPAL, ROW_PAGES])
    data = clean(
        fed.run("--quiet", "diff", path, "--company", "paypal", "--json")
    ).json()
    assert (data["gone"], data["added"]) == (0, 1) and data["added_rows"] == [ROW_PUNY]


def test_diff_contains_is_validated_like_the_server_filter(fed, tmp_path):
    run = fed.run(
        "--quiet", "diff", snapshot_file(tmp_path, [ROW_PAYPAL]), "--contains", "ab"
    )
    assert run.code == 2 and "--contains" in run.etext


def test_diff_tier_is_not_applicable_to_snapshots_and_warns_once_per_side(
    fed, tmp_path
):
    path = snapshot_file(tmp_path, [ROW_PAYPAL])
    run = clean(fed.run("--quiet", "diff", path, "--tier", "verified"))
    assert run.etext.count("--tier") == 2
    quiet = clean(fed.run("--quiet", "diff", path, "--tier", "verified", "--json"))
    assert quiet.err == "" and quiet.json()["before"] == 1, (
        "no filtering happens and JSON mode keeps stderr empty"
    )


def test_diff_text_view_and_limit(fed, tmp_path):
    path = snapshot_file(tmp_path, [ROW_PAYPAL, ROW_PLAIN, OLD_ONLY])
    run = clean(fed.run("--quiet", "diff", path))
    text = run.etext
    assert run.out == ""
    assert re.search(r"\+3\b", text) and re.search(r"-1\b", text)
    for needle in (
        "added",
        "gone",
        "bank-update[.]example[.]org",
        "xn--pypal-4ve[.]example",
        "kit[.]pages[.]dev",
        "gone[.]example",
    ):
        assert needle in text, needle
    limited = clean(fed.run("--quiet", "diff", path, "--limit", "1")).etext
    assert (
        "bank-update[.]example[.]org" in limited and "kit[.]pages[.]dev" not in limited
    )


def test_diff_export_writes_the_added_rows_in_text_and_json_modes(fed, tmp_path):
    path = snapshot_file(tmp_path, [ROW_PAYPAL, ROW_PLAIN, OLD_ONLY])
    clean(fed.run("--quiet", "diff", path, "--export", "added.json"))
    assert [
        r["uuid"] for r in json.loads((fed.cwd / "added.json").read_text("utf-8"))
    ] == [uid(4), uid(3), uid(2)]
    clean(fed.run("--quiet", "diff", path, "--export", "skipped.json", "--json"))
    assert json.loads((fed.cwd / "skipped.json").read_text("utf-8")) == json.loads(
        (fed.cwd / "added.json").read_text("utf-8")
    )


# ---------------------------------------------------------------------------------------------
# N. --export: formats, extension rules, row selection, the 18-column CSV  [C14]
# ---------------------------------------------------------------------------------------------

EXPORT_FIRST = {
    **ROW_PAYPAL,
    "org": "Caf\u00e9 \u4e2d\u6587 GmbH",
    "extra_key": {"ignored": True},
    "first_seen": "2026-10-18T12:00:00Z",
}
EXPORT_SPARSE = {
    "uuid": uid(7),
    "domain": "sparse.example",
    "first_seen": "2026-10-17T00:00:00Z",
}
EXPORT_ROWS = [EXPORT_FIRST, EXPORT_SPARSE]


@pytest.fixture
def exporting(world):
    world.serve_paths({"/feed.json": json_reply(EXPORT_ROWS)})
    return world


def exported(world, name) -> bytes:
    return (world.cwd / name).read_bytes()


def test_export_json_is_the_shown_rows_as_a_pretty_utf8_array_with_a_trailing_newline(
    exporting,
):
    run = clean(exporting.run("--quiet", "hunt", "--export", "out.json"))
    text = exported(exporting, "out.json").decode("utf-8")
    assert (
        text.replace("\r\n", "\n")
        == json.dumps(EXPORT_ROWS, indent=2, ensure_ascii=False) + "\n"
    )
    assert "Caf\u00e9 \u4e2d\u6587" in text and "\\u" not in text, (
        "non-ASCII is written as is"
    )
    assert json.loads(text) == EXPORT_ROWS, "rows are unmodified, extra keys retained"
    assert "out.json" in run.etext.replace(" ", "")


def test_export_txt_is_one_raw_url_else_domain_per_line_never_defanged(exporting):
    clean(exporting.run("--quiet", "hunt", "--export", "out.txt"))
    assert exported(exporting, "out.txt").decode("utf-8").splitlines() == [
        EXPORT_FIRST["url"],
        "sparse.example",
    ]


def test_export_csv_has_the_18_columns_in_order_and_str_values(exporting):
    clean(exporting.run("--quiet", "hunt", "--export", "out.csv"))
    with (exporting.cwd / "out.csv").open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == CSV_FIELDS and len(CSV_FIELDS) == 18
        first, second = list(reader)
    assert (
        first["uuid"] == uid(1)
        and first["score"] == "92"
        and first["asn"] == "13335"
        and first["org"] == "Caf\u00e9 \u4e2d\u6587 GmbH"
    )
    assert (first["malicious_google"], first["malicious_phishtank"]) == (
        "True",
        "False",
    ), "booleans are written with str()"
    assert first["domain"] == "paypal-login1.example.net" and first["url"].startswith(
        "https://"
    ), "live, not defanged"
    assert "extra_key" not in first and "sans_score" not in first, (
        "extra keys are ignored"
    )
    assert (
        second["uuid"] == uid(7)
        and second["score"] == ""
        and second["company"] == ""
        and second["malicious_google"] == ""
    )


def test_export_csv_uses_crlf_row_endings(exporting):
    clean(exporting.run("--quiet", "hunt", "--export", "out.csv"))
    raw = exported(exporting, "out.csv")
    assert raw.count(b"\r\n") == 3 and raw.count(b"\n") == 3, (
        "header + 2 rows, every newline is CRLF"
    )


@pytest.mark.parametrize(
    "given,written",
    [
        ("out", "out.csv"),
        ("out.xlsx", "out.xlsx.csv"),
        ("out.tsv", "out.tsv.csv"),
        ("out.csv", "out.csv"),
        ("OUT.CSV", "OUT.CSV"),
        ("out.json.bak", "out.json.bak.csv"),
    ],
)
def test_export_other_extensions_become_csv_and_csv_is_appended_unless_present(
    exporting, given, written
):
    run = clean(exporting.run("--quiet", "hunt", "--export", given))
    assert (exporting.cwd / written).is_file()
    assert exported(exporting, written).startswith(
        b"uuid,first_seen,date,verdict,score"
    )
    assert written in run.etext.replace(" ", ""), "the printed path is the appended one"


@pytest.mark.parametrize(
    "given,kind", [("OUT.JSON", "json"), ("out.Json", "json"), ("OUT.TXT", "txt")]
)
def test_export_extension_match_is_case_insensitive(exporting, given, kind):
    clean(exporting.run("--quiet", "hunt", "--export", given))
    text = exported(exporting, given).decode("utf-8")
    assert (text.lstrip().startswith("[")) is (kind == "json")


def test_export_creates_parent_directories(exporting):
    clean(exporting.run("--quiet", "hunt", "--export", "deep/er/out.json"))
    assert (exporting.cwd / "deep" / "er" / "out.json").is_file()


def test_export_notice_names_the_row_count_and_that_the_indicators_are_live(exporting):
    run = clean(exporting.run("--quiet", "hunt", "--export", "out.json"))
    assert re.search(r"\b2 rows\b", run.etext) and "live" in run.etext


def test_export_limit_applies_all_lifts_it(exporting):
    clean(exporting.run("--quiet", "hunt", "--limit", "1", "--export", "one.json"))
    assert len(json.loads(exported(exporting, "one.json"))) == 1
    clean(
        exporting.run(
            "--quiet", "hunt", "--limit", "1", "--all", "--export", "all.json"
        )
    )
    assert len(json.loads(exported(exporting, "all.json"))) == 2


def test_export_with_values_writes_the_shown_rows_and_still_prints_the_values(
    exporting,
):
    run = clean(exporting.run("--quiet", "hunt", "--values", "--export", "v.txt"))
    assert (
        len(run.lines) == 2
        and exported(exporting, "v.txt").decode("utf-8").splitlines()[0]
        == EXPORT_FIRST["url"]
    )


def test_export_of_an_empty_result_is_a_header_only_csv_and_an_empty_json_array(
    exporting,
):
    clean(
        exporting.run("--quiet", "hunt", "--min-score", "99", "--export", "empty.csv")
    )
    assert exported(exporting, "empty.csv").decode("utf-8").strip() == ",".join(
        CSV_FIELDS
    )
    clean(
        exporting.run("--quiet", "hunt", "--min-score", "99", "--export", "empty.json")
    )
    assert json.loads(exported(exporting, "empty.json")) == []


def test_export_is_written_when_json_is_also_given(exporting):
    run = clean(exporting.run("--quiet", "hunt", "--json", "--export", "skipped.json"))
    assert json.loads(exported(exporting, "skipped.json")) == run.json() == EXPORT_ROWS
    for argv in (
        ("search", "abcd", "--json", "--export", "s.json"),
        ("triage", "--json", "--export", "t.json"),
    ):
        exporting.serve_paths(
            {
                "/feed.json": json_reply(EXPORT_ROWS),
                "/api/v1/search.json": json_reply({"results": EXPORT_ROWS, "count": 2}),
            }
        )
        clean(exporting.run("--quiet", *argv))
        assert json.loads(exported(exporting, argv[-1])) == EXPORT_ROWS, argv


def test_search_and_triage_exports_hold_the_filtered_sorted_rows(world):
    world.serve_paths(
        {
            "/api/v1/search.json": json_reply(SEARCH_PAYLOAD),
            "/feed.json": json_reply(FEED),
        }
    )
    clean(
        world.run(
            "--quiet",
            "search",
            "login",
            "--min-score",
            "60",
            "--sort",
            "score",
            "--export",
            "s.json",
        )
    )
    assert [r["uuid"] for r in json.loads(exported(world, "s.json"))] == [
        uid(1),
        uid(2),
    ]
    clean(world.run("--quiet", "triage", "--limit", "2", "--export", "t.json"))
    assert [r["uuid"] for r in json.loads(exported(world, "t.json"))] == [
        uid(1),
        uid(2),
    ]


def test_export_text_files_use_the_platform_newline_PINNED_CURRENT_PLATFORM(exporting):
    """json/txt exports are written in text mode, so Windows gets CRLF (spec 4.7). Delete if the rebuild writes LF everywhere."""
    clean(exporting.run("--quiet", "hunt", "--export", "nl.txt"))
    assert exported(exporting, "nl.txt").endswith(os.linesep.encode())


def test_export_rows_stay_live_even_though_the_screen_is_defanged(exporting):
    run = clean(exporting.run("--quiet", "hunt", "--export", "live.json"))
    assert (
        "paypal-login1[.]example[.]net" in run.etext
        and "https://paypal-login1.example.net/signin/verify"
        in exported(exporting, "live.json").decode()
    )


# ---------------------------------------------------------------------------------------------
# O. report: the Markdown brief  [C15]
# ---------------------------------------------------------------------------------------------

HEADINGS = [
    "# Lanternjaw brief",
    "## Snapshot",
    "## Verdicts",
    "## Targeted brands",
    "## Hosting",
    "## Hottest",
    "## Newest",
    "## Defanged indicators (hottest)",
]


def report_of(world, *extra) -> str:
    run = clean(world.run("--quiet", "report", *extra))
    assert run.err == "" or run.err
    return run.out


def test_report_goes_to_stdout_with_the_documented_headings_in_order(fed):
    markdown = report_of(fed)
    positions = [
        markdown.index(f"\n{heading}\n")
        if heading != HEADINGS[0]
        else markdown.index(heading)
        for heading in HEADINGS
    ]
    assert (
        positions == sorted(positions)
        and markdown.startswith("# Lanternjaw brief\n")
        and markdown.endswith("Upstream docs: https://phishunt.io/api/\n")
    )
    assert not clean(fed.run("--quiet", "report")).err.strip().startswith("#")


def test_report_header_lines_and_disclaimer(fed):
    markdown = report_of(fed)
    assert re.search(
        r"^Generated \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ by Lanternjaw 1\.0\.0\.$",
        markdown,
        re.M,
    )
    assert re.search(r"^Source slice: .*6.*\.$", markdown, re.M)
    lowered = markdown.lower()
    for needle in ("cc0", "false positive", "heuristic", "attribution", "clean"):
        assert needle in lowered, needle


def test_report_snapshot_bullets(fed):
    markdown = report_of(fed)
    section = markdown.split("## Snapshot\n", 1)[1].split("\n## Verdicts", 1)[0]
    bullets = [line for line in section.splitlines() if line.startswith("- ")]
    assert bullets == [
        "- Rows: 6",
        "- Median score: 37.5",
        "- First seen: 2026-10-15T00:00:00Z",
        "- Newest first-seen: 2026-10-18T03:00:00Z",
        "- Latest recheck: 2026-10-18T09:00:00Z",
        "- Noise-tier but feed-flagged: 1",
        "- Punycode hosts: 1",
        "- Shared-platform suffixes: 1",
        "- Credential-ish paths: 3",
    ]


def test_report_verdict_and_brand_lists_are_most_common_first(fed):
    markdown = report_of(fed)
    verdicts = (
        markdown.split("## Verdicts\n", 1)[1]
        .split("\n## Targeted brands", 1)[0]
        .strip()
        .splitlines()
    )
    assert sorted(verdicts) == sorted(
        [
            "- critical: 1",
            "- high: 1",
            "- medium: 1",
            "- low: 1",
            "- noise: 1",
            f"- {EM_DASH}: 1",
        ]
    )
    brands = (
        markdown.split("## Targeted brands\n", 1)[1]
        .split("\n## Hosting", 1)[0]
        .strip()
        .splitlines()
    )
    assert brands[0] == "- paypal: 3" and sorted(brands[1:]) == sorted(
        ["- chase: 1", "- microsoft: 1", f"- {EM_DASH}: 1"]
    )


def test_report_hosting_lines(fed):
    hosting = report_of(fed).split("## Hosting\n", 1)[1].split("\n## Hottest", 1)[0]
    lines = [line for line in hosting.splitlines() if line.strip()]
    assert [line.split(":")[0] for line in lines] == [
        "Countries",
        "Networks",
        "Issuers",
    ]
    assert lines[0].startswith("Countries: Germany (3), France (2), United States (1)")
    assert "AS13335  Cloudflare, Inc. (2)" in lines[1] and lines[2].startswith(
        "Issuers: R3 (2)"
    )


def test_report_hottest_table_columns_rows_and_five_character_source_strings(fed):
    section = report_of(fed).split("## Hottest\n", 1)[1].split("\n## Newest", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("|")]
    assert (
        rows[0] == "| score | verdict | brand | domain | ip | sources |"
        and rows[1] == "| --- | --- | --- | --- | --- | --- |"
    )
    assert (
        rows[2]
        == "| 92 | critical | paypal | paypal-login1[.]example[.]net | 203[.]0[.]113[.]2 | GO-T- |"
    )
    assert (
        rows[3]
        == "| 75 | high | microsoft | kit[.]pages[.]dev | 198[.]51[.]100[.]7 | -O--- |"
    )
    assert (
        rows[4]
        == "| 55 | medium | chase | bank-update[.]example[.]org | 192[.]0[.]2[.]44 | --P-U |"
    )
    assert (
        rows[5]
        == f"| 20 | low | {EM_DASH} | plain[.]example[.]com | {EM_DASH} | ----- |"
    )
    assert len(rows) == 2 + 6


def test_report_newest_table_columns_and_order(fed):
    section = report_of(fed).split("## Newest\n", 1)[1].split("\n## Defanged", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("|")]
    assert (
        rows[0] == "| first seen | brand | domain | score |"
        and rows[1] == "| --- | --- | --- | --- |"
    )
    assert rows[2] == "| 2026-10-18 03:00 | chase | bank-update[.]example[.]org | 55 |"
    assert rows[3] == "| 2026-10-18 01:00 | paypal | xn--pypal-4ve[.]example | 12 |"
    assert len(rows) == 2 + 6


def test_report_defanged_indicator_block_is_fenced_and_lists_the_hottest_urls(fed):
    block = (
        report_of(fed)
        .split("## Defanged indicators (hottest)\n", 1)[1]
        .split("```")[1]
        .strip()
        .splitlines()
    )
    assert (
        block[:3]
        == [
            "hxxps://paypal-login1[.]example[.]net/signin/verify",
            "hxxps://kit[.]pages[.]dev/account/update",
            "hxxps://bank-update[.]example[.]org/p?x=1",
        ]
        and len(block) == 6
    )


def test_report_limit_bounds_both_tables_and_the_indicator_block(fed):
    markdown = report_of(fed, "--limit", "2")
    assert (
        len(
            [
                l
                for l in markdown.split("## Hottest\n", 1)[1]
                .split("\n## Newest", 1)[0]
                .splitlines()
                if l.startswith("|")
            ]
        )
        == 4
    )
    assert (
        len(
            [
                l
                for l in markdown.split("## Newest\n", 1)[1]
                .split("\n## Defanged", 1)[0]
                .splitlines()
                if l.startswith("|")
            ]
        )
        == 4
    )
    assert len(markdown.split("```")[1].strip().splitlines()) == 2


def test_report_live_leaves_table_cells_raw_but_the_indicator_block_stays_defanged(fed):
    markdown = clean(fed.run("--quiet", "--live", "report")).out
    assert "| paypal-login1.example.net | 203.0.113.2 |" in markdown
    assert (
        "hxxps://paypal-login1[.]example[.]net/signin/verify"
        in markdown.split("```")[1]
    )


def test_report_escapes_pipes_and_flattens_newlines_in_cells(world):
    row = {**ROW_PAYPAL, "company": "a|b\nc", "verdict": "x|y"}
    world.serve_paths({"/feed.json": json_reply([row])})
    markdown = clean(world.run("--quiet", "report")).out
    assert "| x\\|y | a\\|b c |" in markdown


def test_report_out_writes_the_file_and_leaves_stdout_empty(fed, tmp_path):
    target = tmp_path / "sub" / "brief.md"
    run = clean(fed.run("--quiet", "report", "--out", str(target)))
    assert run.out == "" and "brief.md" in run.etext.replace(" ", "")
    written = target.read_bytes().decode("utf-8").replace("\r\n", "\n")
    assert written.startswith("# Lanternjaw brief\n") and "## Hottest" in written


def test_report_uses_the_domains_api_for_server_filters_and_names_it_in_the_source_slice(
    world,
):
    serve_domains(world, domains_page(FEED[:2]))
    markdown = clean(world.run("--quiet", "report", "--company", "paypal")).out
    assert world.paths == ["/api/v1/domains"] and re.search(
        r"^Source slice: .*api/v1/domains.*2.*\.$", markdown, re.M
    )
    assert "- Rows: 2" in markdown


def test_report_of_an_empty_slice_uses_a_none_median_and_dashes(fed):
    markdown = report_of(fed, "--min-score", "99")
    assert (
        "- Rows: 0" in markdown
        and "- Median score: None" in markdown
        and f"- First seen: {EM_DASH}" in markdown
    )
    assert f"- Latest recheck: {EM_DASH}" in markdown and markdown.startswith(
        "# Lanternjaw brief"
    )


def test_report_json_flag_still_prints_the_markdown_PINNED_QUIRK(fed):
    run = clean(fed.run("--quiet", "report", "--json"))
    assert run.out.startswith("# Lanternjaw brief\n") and run.err == ""


# ---------------------------------------------------------------------------------------------
# P. feed and blocklist: paths, raw modes, previews  [C16]
# ---------------------------------------------------------------------------------------------

FEED_PATHS = {
    "json": "/feed.json",
    "csv": "/feed.csv",
    "txt": "/feed.txt",
    "stix": "/stix/bundle.json",
}
BLOCKLIST_PATHS = {
    "domains": "/blocklist/domains.txt",
    "hosts": "/blocklist/hosts.txt",
    "adblock": "/blocklist/adblock.txt",
    "dnsmasq": "/blocklist/dnsmasq.conf",
    "unbound": "/blocklist/unbound.conf",
    "rpz": "/blocklist/rpz.zone",
}
FEED_CSV = (
    "domain,ip\n"
    + "\n".join(f"host{i}.example,203.0.113.{i}" for i in range(20))
    + "\n"
)


@pytest.mark.parametrize("kind", FEED_KINDS)
def test_feed_kinds_request_their_path(world, kind):
    world.serve_paths(
        {
            FEED_PATHS[kind]: json_reply(FEED if kind == "json" else STIX_PAYLOAD)
            if kind in ("json", "stix")
            else text_reply("a\n")
        }
    )
    clean(world.run("--quiet", "feed", kind, "--json"))
    assert world.paths == [FEED_PATHS[kind]] and world.urls[0].count("?") == 0


def test_feed_json_json_prints_the_feed_and_out_writes_it_pretty(world, tmp_path):
    world.serve_paths({"/feed.json": json_reply(FEED)})
    target = tmp_path / "f" / "feed.json"
    run = clean(world.run("--quiet", "feed", "json", "--json", "--out", str(target)))
    assert run.json() == FEED
    assert (
        target.read_bytes().decode("utf-8").replace("\r\n", "\n")
        == json.dumps(FEED, indent=2, ensure_ascii=False) + "\n"
    )


def test_feed_json_text_renders_the_pulse_dashboard_for_the_whole_feed(world):
    world.serve_paths({"/feed.json": json_reply(FEED)})
    run = clean(world.run("--quiet", "feed", "json"))
    assert (
        run.out == ""
        and "feed.json" in run.etext
        and "paypal" in run.etext
        and "Germany" in run.etext
    )
    assert re.search(r"punycode[^\n]*\b1\b", run.err)


def test_feed_stix_text_summary(world):
    world.serve_paths({"/stix/bundle.json": json_reply(STIX_PAYLOAD)})
    text = clean(world.run("--quiet", "feed", "stix")).etext
    assert (
        re.search(r"\b3 indicators\b", text)
        and re.search(r"\b4 bundle objects\b", text)
        and re.search(r"present on 2\b", text)
    )
    assert re.search(r"min 60\b.*median 75\b.*max 90\b", text) and "TLP:CLEAR" in text
    assert (
        text.index("paypal") < text.index("ebay") and "chase" in text and "ebay" in text
    )


def test_feed_stix_json_and_out(world, tmp_path):
    world.serve_paths({"/stix/bundle.json": json_reply(STIX_PAYLOAD)})
    target = tmp_path / "bundle.json"
    assert (
        clean(
            world.run("--quiet", "feed", "stix", "--json", "--out", str(target))
        ).json()
        == STIX_PAYLOAD
    )
    assert json.loads(target.read_text("utf-8")) == STIX_PAYLOAD


@pytest.mark.parametrize("kind", ["csv", "txt"])
def test_feed_raw_text_json_mode_writes_the_text_to_stdout_with_a_newline_ensured(
    world, kind
):
    world.serve_paths({FEED_PATHS[kind]: text_reply("a,b\n1,2")})
    run = clean(world.run("--quiet", "feed", kind, "--json"))
    assert run.out == "a,b\n1,2\n" and run.err == ""


def test_feed_raw_text_out_writes_the_file_and_still_prints_the_preview(
    world, tmp_path
):
    world.serve_paths({"/feed.csv": text_reply(FEED_CSV)})
    target = tmp_path / "feed.csv"
    run = clean(world.run("--quiet", "feed", "csv", "--out", str(target)))
    assert target.read_bytes().decode("utf-8").replace("\r\n", "\n") == FEED_CSV
    assert run.out == "" and "host0[.]example" in run.etext


@pytest.mark.parametrize(
    "argv,path",
    [
        (("feed", "csv"), "/feed.csv"),
        (("feed", "txt"), "/feed.txt"),
        (("blocklist", "domains"), "/blocklist/domains.txt"),
    ],
)
def test_out_files_for_raw_text_always_end_with_a_newline_and_never_gain_a_second_one(
    world, tmp_path, argv, path
):
    target = tmp_path / "raw.out"
    for given in ("a.example\nb.example", "a.example\nb.example\n"):
        world.serve_paths({path: text_reply(given)})
        clean(world.run("--quiet", *argv, "--out", str(target)))
        assert (
            target.read_bytes().decode("utf-8").replace("\r\n", "\n")
            == "a.example\nb.example\n"
        )


def test_feed_csv_preview_counts_lines_and_bytes_defangs_and_limits(world):
    world.serve_paths({"/feed.csv": text_reply(FEED_CSV)})
    text = clean(world.run("--quiet", "feed", "csv")).etext
    assert re.search(r"\b21\b", text) and str(len(FEED_CSV)) in text.replace(",", "")
    assert (
        "host0[.]example,203[.]0[.]113[.]0" in text
        and "host13[.]example" in text
        and "host14[.]example" not in text
    )
    assert re.search(r"\b6 more lines\b", text)
    live = clean(world.run("--quiet", "--live", "feed", "csv", "--limit", "2")).etext
    assert (
        "host0.example,203.0.113.0" in live
        and "host2.example" not in live
        and re.search(r"\b19 more lines\b", live)
    )
    assert (
        "more lines"
        not in clean(world.run("--quiet", "feed", "csv", "--limit", "100")).etext
    )


def test_feed_limit_zero_falls_back_to_15_preview_lines(world):
    world.serve_paths({"/feed.csv": text_reply(FEED_CSV)})
    text = clean(world.run("--quiet", "feed", "csv", "--limit", "0")).etext
    assert "host13[.]example" in text and "host14[.]example" not in text


@pytest.mark.parametrize("kind", list(BLOCKLIST_PATHS))
def test_blocklist_kinds_request_their_path(world, kind):
    world.serve_paths({BLOCKLIST_PATHS[kind]: text_reply("evil.example\n")})
    clean(world.run("--quiet", "blocklist", kind, "--values"))
    assert world.paths == [BLOCKLIST_PATHS[kind]]


def test_blocklist_values_and_json_write_the_raw_text_to_stdout_unchanged_with_a_newline_ensured(
    world,
):
    text = "# header\nevil.example\n!comment\nbad.example"
    world.serve_paths({"/blocklist/domains.txt": text_reply(text)})
    assert (
        clean(world.run("--quiet", "blocklist", "domains", "--values")).out
        == text + "\n"
    )
    assert (
        clean(world.run("--quiet", "blocklist", "domains", "--json")).out == text + "\n"
    )
    assert clean(world.run("--quiet", "blocklist", "domains", "--values")).err == ""


def test_blocklist_out_writes_the_raw_list_and_prints_nothing_to_stdout(
    world, tmp_path
):
    world.serve_paths({"/blocklist/hosts.txt": text_reply("0.0.0.0 evil.example\n")})
    target = tmp_path / "b" / "hosts.txt"
    run = clean(world.run("--quiet", "blocklist", "hosts", "--out", str(target)))
    assert (
        run.out == ""
        and target.read_bytes().decode("utf-8").replace("\r\n", "\n")
        == "0.0.0.0 evil.example\n"
    )
    assert (
        "hosts.txt" in run.etext.replace(" ", "") and "0[.]0[.]0[.]0" not in run.etext
    ), "--out returns before any preview"


def test_blocklist_preview_counts_usable_lines_skips_comments_and_blanks_and_defangs(
    world,
):
    text = (
        "# comment\n\n! adblock comment\n"
        + "\n".join(f"e{i}.example" for i in range(30))
        + "\n   \n"
    )
    world.serve_paths({"/blocklist/domains.txt": text_reply(text)})
    run = clean(world.run("--quiet", "blocklist", "domains"))
    assert run.out == "" and re.search(r"\b30 usable\b", run.etext), (
        "comments, blanks and whitespace-only lines are not usable lines"
    )
    assert (
        "e0[.]example" in run.etext
        and "e19[.]example" in run.etext
        and "e20[.]example" not in run.etext
    )
    assert "comment" not in run.etext.replace("collapse", "")


def test_blocklist_preview_limit_zero_means_20_and_live_shows_raw_lines(world):
    world.serve_paths(
        {
            "/blocklist/dnsmasq.conf": text_reply(
                "\n".join(f"address=/e{i}.example/0.0.0.0" for i in range(30)) + "\n"
            )
        }
    )
    text = clean(world.run("--quiet", "blocklist", "dnsmasq", "--limit", "0")).etext
    assert (
        "address=/e0[.]example/0[.]0[.]0[.]0" in text
        and "e19[.]example" in text
        and "e20[.]example" not in text
    )
    live = clean(
        world.run("--quiet", "--live", "blocklist", "dnsmasq", "--limit", "1")
    ).etext
    assert "address=/e0.example/0.0.0.0" in live and "e1.example" not in live


# ---------------------------------------------------------------------------------------------
# U. about and self-test: offline, no policy, no client  [C21]
# ---------------------------------------------------------------------------------------------


def test_about_needs_no_network_no_policy_and_no_client(world):
    world.workspace(policy=False)
    world.load()

    def boom(*args, **kwargs):
        raise AssertionError("about must not build a client")

    world.mp.setattr(world.lj, "Client", boom)
    run = clean(world.run("--quiet", "about"))
    assert world.requests == [] and run.out == ""


def test_about_content_names_the_service_sources_limits_and_the_endpoint_map(world):
    text = clean(world.run("--quiet", "about")).etext
    for needle in (
        "phishunt",
        "key",
        "Certificate Transparency",
        "Google Safe Browsing",
        "OpenPhish",
        "PhishTank",
        "TweetFeed",
        "urlscan.io",
        "ipinfo",
        "10 requests",
        "deep",
        "campaign",
        "/api/v1/analyze/deep",
        "/api/v1/analyze",
        "/api/v1/search.json",
        "/api/v1/campaigns",
        "/api/v1/domains",
        "/api/v1/enrich",
        "/api/v1/brands",
        "/api/v1/certs",
        "/feed.json",
        "/feed.csv",
        "/feed.txt",
        "/stix/bundle.json",
        "/blocklist/",
        "https://phishunt.io/api/",
    ):
        assert needle in text, needle


def test_self_test_is_offline_policy_free_and_prints_exactly_one_line_on_stdout(world):
    world.workspace(policy=False)
    world.load()
    run = clean(world.run("self-test"))
    assert (
        run.out == "lanternjaw self-test ok\n"
        and run.err == ""
        and world.requests == []
    )


def test_self_test_runs_without_a_banner_even_without_quiet(world):
    assert clean(world.run("self-test")).err == ""


# ---------------------------------------------------------------------------------------------
# V. Egress and policy posture  [C22]
# ---------------------------------------------------------------------------------------------


def posture_handler(request):
    path = request.url.path
    if path == "/feed.json":
        return json_reply(FEED)
    if path == "/api/v1/domains":
        return json_reply({"results": FEED, "total": len(FEED)})
    if path == "/api/v1/search.json":
        return json_reply(SEARCH_PAYLOAD)
    if path == "/api/v1/analyze":
        return json_reply(ANALYZE_PAYLOAD)
    if path == "/api/v1/analyze/deep":
        return json_reply(DEEP_PAYLOAD)
    if path == "/api/v1/campaigns":
        return json_reply(CAMPAIGN_LIST)
    if path.startswith("/api/v1/campaigns/"):
        return json_reply(CAMPAIGN_DETAIL)
    if path.endswith("/related"):
        return json_reply(RELATED_PAYLOAD)
    if path.startswith("/api/v1/enrich/"):
        return json_reply(ENRICH_PAYLOAD)
    if path.startswith("/api/v1/brands/"):
        return json_reply(BRAND_PAYLOAD)
    if path.startswith("/api/v1/certs/"):
        return json_reply(CERT_PAYLOAD)
    if path.startswith("/stix/"):
        return json_reply(STIX_PAYLOAD)
    if path.startswith("/blocklist/") or path in ("/feed.csv", "/feed.txt"):
        return text_reply("evil.example\n")
    return None


def registry(world, tmp_path) -> dict:
    indicators = indicators_file(
        tmp_path, "paypal-login1.example.net", name="posture-ind.txt"
    )
    snapshot = snapshot_file(tmp_path, [ROW_PAYPAL], name="posture-snap.json")
    return {
        "pulse": ("pulse",),
        "hunt": ("hunt",),
        "search": ("search", "login"),
        "analyze": ("analyze", TARGET, "--yes"),
        "deep": ("deep", TARGET, "--token", TOKEN, "--yes"),
        "campaigns": ("campaigns",),
        "campaign": ("campaign", CAMPAIGN_KEY),
        "related": ("related", uid(1)),
        "enrich": ("enrich", uid(1)),
        "brand": ("brand", "paypal"),
        "cert": ("cert", "R3"),
        "feed": ("feed", "json"),
        "blocklist": ("blocklist", "domains"),
        "pivot": ("pivot", "ip"),
        "triage": ("triage",),
        "inspect": ("inspect", uid(1)),
        "match": ("match", indicators),
        "watch": ("watch", "--once", "--since", SINCE),
        "snapshot": ("snapshot", "--out", "posture-out.json"),
        "diff": ("diff", snapshot),
        "report": ("report",),
    }


@pytest.fixture
def battery(world, tmp_path):
    world.serve(handler=posture_handler)
    return world, registry(world, tmp_path)


def test_the_registry_covers_every_networked_subcommand(battery):
    _world, commands = battery
    assert set(commands) == set(SUBCOMMANDS) - {"about", "self-test"}


def test_every_command_sends_only_get_requests_to_https_phishunt_io(battery):
    world, commands = battery
    for name, argv in commands.items():
        before = len(world.requests)
        clean(world.run("--quiet", "--fresh", *argv))
        assert len(world.requests) > before, name
    assert {request.method for request in world.requests} == {"GET"}
    assert {request.url.host for request in world.requests} == {"phishunt.io"}
    assert {request.url.scheme for request in world.requests} == {"https"}
    assert all(request.content == b"" for request in world.requests)
    assert {request.url.port for request in world.requests} == {None}


def test_the_target_url_never_becomes_a_request_host(battery):
    world, commands = battery
    clean(world.run("--quiet", *commands["analyze"]))
    clean(world.run("--quiet", *commands["deep"]))
    assert all("allowed.example" not in request.url.host for request in world.requests)


def test_every_request_is_recorded_by_egress_as_a_passive_run_with_the_full_url(
    battery,
):
    world, commands = battery
    clean(world.run("--quiet", "--fresh", *commands["search"]))
    clean(world.run("--quiet", *commands["analyze"]))
    manifests = [
        json.loads(path.read_text("utf-8"))
        for path in sorted((world.workspace_dir / "runs").glob("*/manifest.json"))
    ]
    assert len(manifests) == len(world.requests) == 2
    assert {(m["operation"], m["decision"]) for m in manifests} == {
        ("passive", "permitted")
    }
    assert sorted(m["target"] for m in manifests) == sorted(
        [f"{BASE}/api/v1/search.json?q=login&limit=50", ANALYZE_REQUEST]
    )
    for run_dir in (world.workspace_dir / "runs").iterdir():
        assert {path.name for path in run_dir.iterdir()} >= {
            "manifest.json",
            "request.http",
            "response.http",
        }


def test_the_share_gate_authorization_sends_nothing_and_leaves_no_run_record(world):
    serve_analysis(world)
    run = world.run("--quiet", "analyze", "https://allowed.example/a%20b", "--yes")
    assert (
        run.code == 2
        and world.requests == []
        and not (world.workspace_dir / "runs").exists()
    )


def test_requests_are_admitted_under_the_passive_operation_only(battery):
    world, commands = battery

    def only(operation):
        def edit(document):
            for asset in document["assets"]:
                if asset["origin"] == BASE:
                    asset["operations"] = [operation]

        return edit

    world.workspace(mutate=only("passive"))
    world.load()
    for name in ("pulse", "analyze", "deep", "campaigns", "brand"):
        clean(world.run("--quiet", "--fresh", *commands[name]))
    world.requests.clear()
    world.workspace(mutate=only("manual"))
    world.load()
    run = world.run("--quiet", "brand", "paypal")
    assert (
        run.code in (1, 2)
        and world.requests == []
        and "no outbound action ran" in run.etext
    )


def test_only_analyze_and_deep_are_scope_gated_every_other_command_works_with_no_scope_file(
    battery,
):
    world, commands = battery
    world.workspace(scope=None)
    world.load()
    for name, argv in commands.items():
        run = world.run("--quiet", "--fresh", *argv)
        if name in ("analyze", "deep"):
            assert run.code == 2 and "scope" in run.etext, name
        else:
            assert run.code == 0 and run.exc is None, (name, run.etext[-200:])


@pytest.mark.parametrize(
    "name",
    [
        "pulse",
        "hunt",
        "search",
        "campaigns",
        "campaign",
        "related",
        "brand",
        "cert",
        "feed",
        "blocklist",
        "pivot",
        "triage",
        "inspect",
        "match",
        "watch",
        "snapshot",
        "diff",
        "report",
        "analyze",
        "deep",
    ],
)
def test_without_an_asset_for_phishunt_the_request_is_denied_before_the_transport(
    battery, name
):
    world, commands = battery
    world.workspace(drop=(BASE,))
    world.load()
    run = world.run("--quiet", "--fresh", *commands[name])
    assert run.exc is None and run.code in (1, 2), (name, run.code)
    assert "asset-unknown" in run.etext and "no outbound action ran" in run.etext
    assert world.requests == []
    assert not (world.workspace_dir / "runs").exists(), (
        "a denied request leaves no run record"
    )


@pytest.mark.parametrize("name", ["pulse", "brand", "report", "watch", "analyze"])
def test_without_a_policy_the_request_is_denied_before_the_transport(battery, name):
    world, commands = battery
    world.workspace(policy=False)
    world.load()
    run = world.run("--quiet", "--fresh", *commands[name])
    assert run.exc is None and run.code in (1, 2)
    assert (
        "policy-missing-or-invalid" in run.etext
        and "no outbound action ran" in run.etext
        and world.requests == []
    )


def test_a_client_built_in_one_workspace_is_refused_in_another(world):
    world.serve(json_reply({}))
    client = world.lj.Client()
    world.workspace(world.tmp / "other-workspace")
    with pytest.raises(world.lj.PhishuntError) as caught:
        client.request("/api/v1/x")
    assert "client-workspace-changed" in str(caught.value) and world.requests == []


def test_documentation_states_the_posture_the_code_keeps():
    manual = (REPO / "docs" / "manual.md").read_text("utf-8")
    assert (
        "| `phish` | Talks only to `phishunt.io`." in manual
        and "the URL must be in scope and confirmed" in manual
    )
    assert (
        "Phishunt feed, campaigns, and a passive URL score" in manual
        and "`bughunt phish --help`" in manual
    )
    assert "`lanternjaw` is `phish`" in manual


BANNED_MODULES = {
    "socket",
    "subprocess",
    "requests",
    "aiohttp",
    "urllib3",
    "http.client",
    "urllib.request",
    "ssl",
    "ftplib",
    "smtplib",
    "telnetlib",
    "asyncio",
}
BANNED_CLIENT_KEYWORDS = {
    "verify",
    "proxy",
    "proxies",
    "trust_env",
    "follow_redirects",
    "mounts",
}  # `cert` is a data field here


def test_the_script_has_no_network_path_other_than_the_guarded_client():
    tree = ast.parse(SCRIPT.read_text("utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not imported & BANNED_MODULES, imported & BANNED_MODULES
    direct_httpx_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "httpx"
    ]
    assert direct_httpx_calls == [], (
        "all traffic must go through bughunt.core.http.api_client"
    )
    weakened = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.keyword) and node.arg in BANNED_CLIENT_KEYWORDS
    ]
    assert weakened == [], "no TLS/proxy/redirect override on any call"
    assert "bughunt.core.http" in imported


def test_the_script_never_sends_anything_but_get(world):
    tree = ast.parse(SCRIPT.read_text("utf-8"))
    verbs = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr
        in {
            "post",
            "put",
            "delete",
            "patch",
            "head",
            "options",
            "stream",
            "send",
            "request",
        }
    }
    assert verbs <= {"request"}, verbs


# ---------------------------------------------------------------------------------------------
# W. Standalone launch from the repo (works) - the foreign-cwd failure is D4 below
# ---------------------------------------------------------------------------------------------


def standalone_env(world, **extra):
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "BUGHUNT_ADDONS", "PYTHONUTF8", "PYTHONIOENCODING")
    }
    env.update(
        BUGHUNT_SCOPE=str(world.workspace_dir),
        HOME=str(world.home),
        USERPROFILE=str(world.home),
        XDG_CACHE_HOME=str(world.cache_home),
    )
    env.update(extra)
    return env


def run_standalone(
    world, cwd, *argv, pythonpath=None, extra_env=None, python_command=None
):
    env = standalone_env(world, **(extra_env or {}))
    if pythonpath:
        env["PYTHONPATH"] = str(pythonpath)
    command = python_command if python_command is not None else [sys.executable]
    return subprocess.run(
        [*command, str(SCRIPT), *argv],
        cwd=cwd,
        env=env,
        timeout=120,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_standalone_self_test_works_when_bughunt_is_importable(world, tmp_path):
    done = run_standalone(world, tmp_path, "self-test", pythonpath=REPO)
    assert done.returncode == 0 and done.stdout == "lanternjaw self-test ok\n", (
        done.stderr[-400:]
    )


def test_standalone_about_needs_no_policy_and_exits_0_when_bughunt_is_importable(
    world, tmp_path
):
    empty = world.workspace(world.tmp / "no-policy", policy=False)
    done = run_standalone(
        world,
        tmp_path,
        "--quiet",
        "about",
        pythonpath=REPO,
        extra_env={"BUGHUNT_SCOPE": str(empty)},
    )
    assert done.returncode == 0 and done.stdout == "", done.stderr[-400:]


STANDALONE_DRIVER = textwrap.dedent("""
    import runpy, socket, sys
    def forbidden(*args, **kwargs):
        raise AssertionError("real network reached")
    socket.getaddrinfo = forbidden
    socket.create_connection = forbidden
    script = sys.argv[1]
    sys.argv = [script, *sys.argv[2:]]
    runpy.run_path(script, run_name="__main__")
""")


def test_standalone_run_without_a_policy_fails_closed_with_no_network(world, tmp_path):
    """A real `python lanternjaw.py brand x` with no policy: denied before any socket (DNS/TCP tripwired)."""
    empty = world.workspace(world.tmp / "no-policy", policy=False)
    driver = tmp_path / "driver.py"
    driver.write_text(STANDALONE_DRIVER, encoding="utf-8")
    env = standalone_env(world, BUGHUNT_SCOPE=str(empty))
    env["PYTHONPATH"] = str(REPO)
    done = subprocess.run(
        [sys.executable, str(driver), str(SCRIPT), "--quiet", "brand", "paypal"],
        cwd=tmp_path,
        env=env,
        timeout=120,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert done.returncode in (1, 2), done.stderr[-600:]
    assert (
        "policy-missing-or-invalid" in done.stdout + done.stderr
        and "AssertionError" not in done.stderr
    )


# ---------------------------------------------------------------------------------------------
# X. Hostile data: API strings render literally and never crash  [C17]  (spec D8)
# ---------------------------------------------------------------------------------------------

HOSTILE = ["[/x]", "[red]x[/red]"]


def feed_with(**fields):
    return {"/feed.json": json_reply([{**ROW_PAYPAL, **fields}])}


def analyze_with(**live):
    return {
        "/api/v1/analyze": json_reply(
            {
                **ANALYZE_PAYLOAD,
                "live_analysis": {**ANALYZE_PAYLOAD["live_analysis"], **live},
            }
        )
    }


def deep_with(**deep):
    return {
        "/api/v1/analyze/deep": json_reply(
            {**DEEP_PAYLOAD, "deep_analysis": {**DEEP_PAYLOAD["deep_analysis"], **deep}}
        )
    }


def campaign_with(**fields):
    return {
        f"/api/v1/campaigns/{CAMPAIGN_KEY}": json_reply({**CAMPAIGN_DETAIL, **fields})
    }


D8_CASES = {  # name -> (argv, lambda bad -> routes)
    "hunt-brand": (("hunt",), lambda bad: feed_with(company=bad)),
    "hunt-domain": (("hunt",), lambda bad: feed_with(domain=bad)),
    "hunt-geo": (("hunt",), lambda bad: feed_with(country=bad, ip=bad)),
    "hunt-values": (("hunt", "--values"), lambda bad: feed_with(url=bad)),
    "pulse-brand": (("pulse",), lambda bad: feed_with(company=bad)),
    "pulse-network": (
        ("pulse",),
        lambda bad: feed_with(org=bad, cert=bad, country=bad),
    ),
    "pivot-value-and-sample": (
        ("pivot", "country", "--min-count", "1"),
        lambda bad: feed_with(country=bad, domain=bad),
    ),
    "triage-card-url": (
        ("triage",),
        lambda bad: feed_with(url=f"https://h.example/{bad}"),
    ),
    "triage-card-domain": (
        ("triage",),
        lambda bad: feed_with(domain=f"h{bad}.example"),
    ),
    "triage-card-fields": (
        ("triage",),
        lambda bad: feed_with(org=bad, cert=bad, sans_scorereason=bad),
    ),
    "triage-card-signal": (
        ("triage",),
        lambda bad: feed_with(
            top_signals=[{"signal": bad, "kind": bad, "points": 1, "label": bad}]
        ),
    ),
    "inspect-card-url": (
        ("inspect", uid(1), "--skip-related", "--skip-enrich"),
        lambda bad: feed_with(url=f"https://h.example/{bad}"),
    ),
    "inspect-card-domain": (
        ("inspect", uid(1), "--skip-related", "--skip-enrich"),
        lambda bad: feed_with(domain=f"h{bad}.example"),
    ),
    "hunt-export-path": (("hunt", "--export", "o{bad}.json"), lambda bad: feed_with()),
    "snapshot-out-path": (
        ("snapshot", "--out", "s{bad}.json"),
        lambda bad: feed_with(),
    ),
    "report-out-path": (("report", "--out", "r{bad}.md"), lambda bad: feed_with()),
    "search-query": (
        ("search", "{bad}abc"),
        lambda bad: {"/api/v1/search.json": json_reply({"results": [], "count": 0})},
    ),
    "http-error-body": (
        ("brand", "paypal"),
        lambda bad: {BRAND_PATH: text_reply(f"upstream said {bad}", status=500)},
    ),
    "analyze-why": (
        ("analyze", TARGET, "--yes"),
        lambda bad: analyze_with(
            why=[{"signal": bad, "kind": bad, "points": 1, "label": bad}]
        ),
    ),
    "analyze-shape-signal": (
        ("analyze", TARGET, "--yes"),
        lambda bad: analyze_with(url_signals={bad: 1}),
    ),
    "analyze-facts": (
        ("analyze", TARGET, "--yes"),
        lambda bad: analyze_with(brand_match=bad, impersonation=bad, url_risk=bad),
    ),
    "analyze-ai-and-note": (
        ("analyze", TARGET, "--yes"),
        lambda bad: {
            "/api/v1/analyze": json_reply(
                {
                    **ANALYZE_PAYLOAD,
                    "meta": {"note": bad},
                    "known": {"record": {"ai": {"summary": bad, "threat_type": bad}}},
                }
            )
        },
    ),
    "deep-signal": (
        ("deep", TARGET, "--token", TOKEN, "--yes"),
        lambda bad: deep_with(
            signals=[
                {
                    "signal_id": bad,
                    "category": bad,
                    "score_contribution": 5,
                    "description": bad,
                    "detected": True,
                }
            ]
        ),
    ),
    "deep-failures": (
        ("deep", TARGET, "--token", TOKEN, "--yes"),
        lambda bad: deep_with(analysis_failures=[bad], adjustments=[bad]),
    ),
    "campaigns-list-key": (
        ("campaigns",),
        lambda bad: {
            "/api/v1/campaigns": json_reply(
                {
                    "results": [{"key": bad, "confidence": bad, "brands": [bad]}],
                    "count": 1,
                }
            )
        },
    ),
    "campaigns-header": (
        ("campaigns",),
        lambda bad: {
            "/api/v1/campaigns": json_reply(
                {"results": [], "algorithm_version": bad, "data_status": bad}
            )
        },
    ),
    "campaign-detail-status": (
        ("campaign", CAMPAIGN_KEY),
        lambda bad: campaign_with(data_status=bad),
    ),
    "campaign-detail-fields": (
        ("campaign", CAMPAIGN_KEY),
        lambda bad: campaign_with(state=bad, confidence=bad, brands=[bad], key=bad),
    ),
    "campaign-detail-pair-tier": (
        ("campaign", CAMPAIGN_KEY),
        lambda bad: campaign_with(
            relationships=[{"domain_a": bad, "domain_b": bad, "score": 1, "tier": bad}]
        ),
    ),
    "campaign-detail-members": (
        ("campaign", CAMPAIGN_KEY),
        lambda bad: campaign_with(
            members=[{"status": bad, "company": bad, "domain": bad, "ip": bad}],
            history=[{"at": "x", "event": bad, "joined": [bad], "left": [bad]}],
        ),
    ),
    "related-view": (
        ("related", uid(1)),
        lambda bad: {
            f"/api/v1/domains/{uid(1)}/related": json_reply(
                {
                    "domain": bad,
                    "algorithm_version": bad,
                    "results": [
                        {
                            "status": bad,
                            "company": bad,
                            "domain": bad,
                            "evidence": [{"type": bad}],
                        }
                    ],
                }
            )
        },
    ),
    "enrich-view": (
        ("enrich", uid(1)),
        lambda bad: {
            f"/api/v1/enrich/{uid(1)}/": json_reply(
                {
                    "whois": {"registrar": bad, "status": [bad]},
                    "ipinfo": {"city": bad, "hostname": bad},
                }
            )
        },
    ),
    "brand-vertical": (
        ("brand", "paypal"),
        lambda bad: {BRAND_PATH: json_reply({**BRAND_PAYLOAD, "vertical": bad})},
    ),
    "brand-name": (
        ("brand", "paypal"),
        lambda bad: {
            BRAND_PATH: json_reply({**BRAND_PAYLOAD, "name": bad, "notes": bad})
        },
    ),
    "cert-view": (
        ("cert", "R3"),
        lambda bad: {
            "/api/v1/certs/R3.json": json_reply(
                {**CERT_PAYLOAD, "cert": bad, "notes": bad}
            )
        },
    ),
    "stix-labels": (
        ("feed", "stix"),
        lambda bad: {
            "/stix/bundle.json": json_reply(
                {"objects": [{"type": "indicator", "labels": [bad]}]}
            )
        },
    ),
    "feed-csv-preview": (
        ("feed", "csv"),
        lambda bad: {"/feed.csv": text_reply(f"{bad}\n")},
    ),
    "blocklist-preview": (
        ("blocklist", "domains"),
        lambda bad: {"/blocklist/domains.txt": text_reply(f"{bad}\n")},
    ),
    "inspect-section-errors": (
        ("inspect", uid(1)),
        lambda bad: {
            "/feed.json": json_reply([ROW_PAYPAL]),
            f"/api/v1/domains/{uid(1)}/related": json_reply({"error": bad}, status=404),
            f"/api/v1/enrich/{uid(1)}/": json_reply({"error": bad}, status=403),
        },
    ),
}
D8_PATH_CASES = {
    "hunt-export-path",
    "snapshot-out-path",
    "report-out-path",
}  # the hostile text is part of a file name
D8_UNSAFE = {  # observed (rich 15.0.0): these renderers hand untrusted text to rich's markup parser
    "triage-card-url",
    "triage-card-domain",
    "triage-card-signal",
    "inspect-card-url",
    "inspect-card-domain",
    "analyze-why",
    "analyze-shape-signal",
    "analyze-ai-and-note",
    "deep-signal",
    "campaigns-list-key",
    "campaign-detail-status",
    "campaign-detail-pair-tier",
    "brand-vertical",
}
D8_ALREADY_SAFE = (
    set(D8_CASES) - D8_UNSAFE - D8_PATH_CASES
)  # built from Text objects or escape(): literal today, pinned as regressions
D8_EXPECTED_CODE = {"http-error-body": 1}


def hostile_run(world, case, token) -> Run:
    argv, routes = D8_CASES[case]
    world.serve_paths(routes(token))
    return world.run(
        "--quiet", "--fresh", *(part.replace("{bad}", token) for part in argv)
    )


def occurrences(run: Run, token: str) -> int:
    return squash(run.out + run.err).count(token)


@pytest.mark.parametrize("bad", HOSTILE)
@pytest.mark.parametrize(
    "case",
    [name for name in D8_CASES if name not in D8_PATH_CASES],
)
def test_hostile_data_renders_literally_and_does_not_crash(world, case, bad):
    """Each place a value is displayed must show it exactly as received. The expected number of
    places is measured with a benign control value in the same position, run first."""
    control = hostile_run(world, case, "QQQ")
    assert control.exc is None and control.code == D8_EXPECTED_CODE.get(case, 0)
    places = occurrences(control, "QQQ")
    assert places >= 1, "the control value is displayed somewhere"
    run = hostile_run(world, case, bad)
    assert run.exc is None, run.exc
    assert run.code == D8_EXPECTED_CODE.get(case, 0)
    assert occurrences(run, bad) == places, "every displayed copy must be literal"


@pytest.mark.parametrize("bad", ["[red]", "[bold]x"])
@pytest.mark.parametrize(
    "case",
    [name for name in sorted(D8_PATH_CASES)],
)
def test_hostile_file_names_are_shown_literally_in_the_wrote_notice(world, case, bad):
    run = hostile_run(world, case, bad)
    assert run.exc is None, run.exc
    assert run.code == 0 and occurrences(run, bad) >= 1, (
        "the notice must name the file exactly as written"
    )


# ---------------------------------------------------------------------------------------------
# Y. KNOWN DEFECTS (spec section 9). Every `test_dN_*` asserts the CORRECT behavior and is
#    xfail(strict=True) until the rebuild fixes it. `*_PINNED_CURRENT_*` tests pin today's behavior
#    where the spec's default is "reproduce" or the deviation still needs orchestrator approval;
#    they contradict the matching xfail test on purpose - flip or delete them with the deviation.
#    D3 (default addon roots) is already fixed at the base commit: see section B.
#    D8 is the hostile-data matrix above (X). D21 is new (found while writing this oracle).
# ---------------------------------------------------------------------------------------------


def defect(tag: str, why: str):
    return pytest.mark.xfail(strict=True, reason=f"{tag}: {why}")


# -- D1: hunt --offset without a filter ------------------------------------------------------


def test_d1_hunt_offset_without_a_filter_is_a_raw_page_or_a_clear_error_and_limit_is_honored(
    world,
):
    world.serve_paths(
        {
            "/feed.json": json_reply(FEED),
            "/api/v1/domains": domains_page(FEED[2:4], total=6),
        }
    )
    run = world.run("--quiet", "hunt", "--json", "--offset", "2", "--limit", "2")
    assert run.exc is None
    if run.code == 0:
        assert len(run.json()) <= 2, "--limit must still be honored"
    else:
        assert run.code == 2 and "offset" in run.etext.lower()


# -- D2: global flags only before the subcommand ----------------------------------------------


@pytest.mark.parametrize(
    "argv,dest",
    [
        (["pulse", "--fresh"], "fresh"),
        (["hunt", "--quiet"], "quiet"),
        (["hunt", "-q"], "quiet"),
        (["hunt", "--live"], "live"),
        (["hunt", "-v"], "verbose"),
        (["about", "--quiet"], "quiet"),
        (["match", "f.txt", "--fresh", "--fail-on-hit"], "fresh"),
    ],
)
def test_d2_globals_are_accepted_after_the_subcommand(world, argv, dest):
    assert getattr(world.lj.build_parser().parse_args(argv), dest) is True


def test_d2_timeout_is_accepted_after_the_subcommand(world):
    assert world.lj.build_parser().parse_args(["hunt", "--timeout", "7"]).timeout == 7.0


def test_d2_saved_console_globals_render_argv_the_parser_accepts(world):
    world.mp.setenv("BUGHUNT_ADDONS", str(world.addons_root))
    spec = options.load_spec(
        "phish", tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    argv = options.render_argv(
        spec, {"COMMAND": "hunt", "QUIET": "true", "FRESH": "true"}, []
    )
    args = world.lj.build_parser().parse_args(argv)
    assert args.quiet is True and args.fresh is True


@pytest.mark.parametrize(
    "argv",
    [["--quiet", "hunt"], ["--fresh", "pulse"], ["--live", "--timeout", "9", "hunt"]],
)
def test_a_global_before_the_subcommand_is_not_overwritten_by_the_subparser_defaults(
    world, argv
):
    """Regression guard for the D2 fix: accepting globals on subparsers must not reset a True given before the subcommand."""
    args = world.lj.build_parser().parse_args(argv)
    assert (args.quiet or args.fresh or args.live) is True and (
        args.timeout == 9.0 or "--timeout" not in argv
    )


# -- D4: standalone launch from a foreign cwd ------------------------------------------------------


def test_d4_standalone_launch_does_not_need_bughunt_on_the_path(
    world, tmp_path, standalone_python
):
    foreign = tmp_path / "elsewhere"
    foreign.mkdir()
    done = run_standalone(
        world, foreign, "--quiet", "about", python_command=standalone_python
    )
    assert done.returncode == 0, done.stderr[-400:]


# -- D5: policy denials are retried like network blips -----------------------------------------------


def denied_world(world, **kwargs):
    world.workspace(**kwargs)
    world.load()
    world.serve(json_reply({}))
    return world


@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"drop": (BASE,)}, "asset-unknown"),
        ({"policy": False}, "policy-missing-or-invalid"),
    ],
)
def test_d5_a_policy_denial_fails_fast_with_the_reason(world, kwargs, reason):
    denied_world(world, **kwargs)
    run = world.run("--quiet", "brand", "paypal")
    assert run.exc is None and run.code in (1, 2) and reason in run.etext
    assert world.slept == [] and world.requests == []


def test_d5_a_denied_redirect_hop_is_not_retried(world):
    world.serve_paths({"/start": redirect_to("https://www.phishunt.io/landed")})
    with pytest.raises(world.lj.PhishuntError):
        world.lj.Client().request("/start")
    assert len(world.requests) == 1 and world.slept == []


# -- D6: certificate names the policy path grammar rejects -------------------------------------------


def test_cert_single_token_names_work_under_an_active_policy(world):
    world.serve_paths({"/api/v1/certs/R3.json": json_reply(CERT_PAYLOAD)})
    clean(world.run("--quiet", "cert", "R3", "--json"))
    assert world.urls == [f"{BASE}/api/v1/certs/R3.json"]


@pytest.mark.parametrize("name", ["Google Trust Services", "Let's Encrypt"])
def test_d6_multi_word_issuer_names_fail_fast_or_are_queried_in_a_policy_valid_form(
    world, name
):
    world.serve(json_reply(CERT_PAYLOAD))
    run = world.run("--quiet", "cert", name)
    assert run.exc is None and world.slept == [], "no retries"
    assert world.requests or run.code in (1, 2)
    if not world.requests:
        assert "invalid-target" in run.etext
    for request in world.requests:
        assert "%" not in request.url.path


# -- D7: path parameters can climb out of their API path ----------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ("campaign", "../../admin"),
        ("campaign", "a/b"),
        ("campaign", ".."),
        ("campaign", "../../admin", "--export", "csv"),
        ("brand", "../../admin"),
        ("brand", "a/b"),
        ("brand", ".."),
        ("cert", "../../admin"),
        ("cert", "a/b"),
        ("cert", ".."),
    ],
)
def test_d7_hostile_path_identifiers_are_rejected_with_zero_requests(world, argv):
    world.serve(json_reply({}))
    run = world.run("--quiet", *argv)
    assert run.exc is None and run.code in (1, 2) and world.requests == [], world.urls


def test_d7_ordinary_identifiers_still_ride_the_path_unchanged(world):
    world.serve(json_reply({}))
    clean(world.run("--quiet", "campaign", CAMPAIGN_KEY, "--json"))
    clean(world.run("--quiet", "brand", "paypal", "--json"))
    clean(world.run("--quiet", "brand", "amazon-web-services", "--json"))
    clean(world.run("--quiet", "cert", "R3", "--json"))
    assert world.paths == [
        f"/api/v1/campaigns/{CAMPAIGN_KEY}",
        "/api/v1/brands/paypal.json",
        "/api/v1/brands/amazon-web-services.json",
        "/api/v1/certs/R3.json",
    ]


# -- D9: non-UTF-8 stdout -----------------------------------------------------------------------------

CP1252_DRIVER = textwrap.dedent("""
    import json, sys
    from pathlib import Path
    sys.path.insert(0, sys.argv[1])
    sys.path.insert(0, sys.argv[1] + "/tests")
    import httpx
    from bughunt.core import http as core_http
    from bughunt.console import loader
    real = core_http.api_client
    payload = json.loads(sys.argv[3])
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, headers={"content-type": "application/json"}, content=json.dumps(payload).encode(), request=request))
    core_http.api_client = lambda hosts, **kwargs: real(hosts, transport=transport, **kwargs)
    module = loader.import_script(Path(sys.argv[2]))
    sys.exit(module.main(sys.argv[4:]))
""")
NON_CP1252_ROW = {
    **ROW_PAYPAL,
    "org": "Café 中文 GmbH",
    "company": "中文",
    "url": "https://paypal-login1.example.net/中",
}


@pytest.mark.parametrize(
    "argv",
    [
        ("--quiet", "hunt", "--json"),
        ("--quiet", "report"),
        ("--quiet", "hunt", "--values", "--live"),
        ("--quiet", "triage", "--json"),
    ],
    ids=["hunt-json", "report", "hunt-values", "triage-json"],
)
def test_d9_stdout_output_survives_a_cp1252_stream(world, tmp_path, argv):
    driver = tmp_path / "cp1252_driver.py"
    driver.write_text(CP1252_DRIVER, encoding="utf-8")
    env = standalone_env(world, PYTHONIOENCODING="cp1252", COLUMNS="140")
    done = subprocess.run(
        [
            sys.executable,
            "-X",
            "utf8=0",
            str(driver),
            str(REPO),
            str(SCRIPT),
            json.dumps([NON_CP1252_ROW]),
            *argv,
        ],
        cwd=tmp_path,
        env=env,
        timeout=120,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert done.returncode == 0, done.stderr[-400:]


def test_a_cp1252_stream_is_fine_for_data_it_can_encode(world, tmp_path):
    """Control for the D9 matrix: the same harness succeeds when the row is encodable, so the xfail is about the data."""
    driver = tmp_path / "cp1252_driver.py"
    driver.write_text(CP1252_DRIVER, encoding="utf-8")
    env = standalone_env(world, PYTHONIOENCODING="cp1252", COLUMNS="140")
    done = subprocess.run(
        [
            sys.executable,
            "-X",
            "utf8=0",
            str(driver),
            str(REPO),
            str(SCRIPT),
            json.dumps([ROW_PAYPAL]),
            "--quiet",
            "hunt",
            "--json",
        ],
        cwd=tmp_path,
        env=env,
        timeout=120,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert done.returncode == 0, done.stderr[-400:]
    assert json.loads(done.stdout) == [ROW_PAYPAL]


# -- D10: --export silently skipped with --json -------------------------------------------------------


def test_d10_export_with_json_is_not_silently_ignored(exporting):
    run = clean(exporting.run("--quiet", "hunt", "--json", "--export", "maybe.json"))
    assert (exporting.cwd / "maybe.json").exists() or "export" in run.err.lower()


def test_d10_match_csv_export_carries_the_match_columns(fed, tmp_path):
    clean(
        fed.run(
            "--quiet",
            "match",
            indicators_file(tmp_path, "203.0.113.2"),
            "--export",
            "hits.csv",
        )
    )
    with (fed.cwd / "hits.csv").open(encoding="utf-8", newline="") as handle:
        assert {"matched_indicator", "match_reason"} <= set(
            csv.DictReader(handle).fieldnames
        )


# -- D11: non-object payloads --------------------------------------------------------------------------

D11_PAYLOADS = [[], "text", 5]
D11_COMMANDS = {  # name -> (argv, path that carries the payload)
    "brand": (("brand", "paypal"), BRAND_PATH),
    "cert": (("cert", "R3"), "/api/v1/certs/R3.json"),
    "campaign": (("campaign", CAMPAIGN_KEY), f"/api/v1/campaigns/{CAMPAIGN_KEY}"),
    "campaigns": (("campaigns",), "/api/v1/campaigns"),
    "related": (("related", uid(1)), f"/api/v1/domains/{uid(1)}/related"),
    "enrich": (("enrich", uid(1)), f"/api/v1/enrich/{uid(1)}/"),
    "analyze": (("analyze", TARGET, "--yes"), "/api/v1/analyze"),
    "deep": (("deep", TARGET, "--token", TOKEN, "--yes"), "/api/v1/analyze/deep"),
    "search": (("search", "login"), "/api/v1/search.json"),
    "hunt-filtered": (("hunt", "--company", "paypal"), "/api/v1/domains"),
    "watch": (("watch", "--once", "--since", SINCE), "/api/v1/domains"),
}


@pytest.mark.parametrize("payload", D11_PAYLOADS, ids=["list", "string", "number"])
@pytest.mark.parametrize("name", list(D11_COMMANDS))
@pytest.mark.parametrize("machine", [False, True])
def test_d11_a_non_object_payload_is_a_phishunt_error_not_a_crash(
    world, name, payload, machine
):
    argv, path = D11_COMMANDS[name]
    world.serve_paths({path: json_reply(payload)})
    run = world.run("--quiet", *argv, *(["--json"] if machine else []))
    assert run.exc is None, repr(run.exc)
    assert run.code == 1 and "JSON object" in run.etext


D11_FEED_COMMANDS = {
    "pulse": ("pulse",),
    "hunt": ("hunt",),
    "triage": ("triage",),
    "pivot": ("pivot", "country"),
    "report": ("report",),
    "inspect": ("inspect", uid(1), "--skip-related", "--skip-enrich"),
    "diff": ("diff", "{snapshot}"),
    "match": ("match", "{indicators}"),
    "feed-json": ("feed", "json"),
}


@pytest.mark.parametrize(
    "junk", [5, "text", None, [1]], ids=["number", "string", "null", "list"]
)
@pytest.mark.parametrize("name", list(D11_FEED_COMMANDS))
def test_d11_a_non_object_feed_element_is_skipped_not_a_crash(
    world, tmp_path, name, junk
):
    world.serve_paths({"/feed.json": json_reply([junk, ROW_PAYPAL, ROW_PAGES])})
    snapshot = snapshot_file(tmp_path, [ROW_PAYPAL])
    indicators = indicators_file(tmp_path, "paypal-login1.example.net")
    argv = tuple(
        part.replace("{snapshot}", snapshot).replace("{indicators}", indicators)
        for part in D11_FEED_COMMANDS[name]
    )
    run = world.run("--quiet", *argv)
    assert run.exc is None, repr(run.exc)
    assert run.code in (0, 1)
    assert "skipped 1 non-object feed rows" in run.etext


def test_json_projection_reports_skipped_rows_without_contaminating_stdout(world):
    world.serve_paths({"/feed.json": json_reply([5, ROW_PAYPAL, None])})
    run = clean(world.run("--quiet", "hunt", "--json"))
    assert run.json() == [ROW_PAYPAL]
    assert "skipped 2 non-object feed rows" in run.etext
    assert json.loads(world.cache_file.read_text("utf-8"))["sites"] == [
        5,
        ROW_PAYPAL,
        None,
    ]


def test_snapshot_copies_non_object_feed_elements_verbatim_without_reading_them(world):
    world.serve_paths({"/feed.json": json_reply([5, ROW_PAYPAL, None])})
    clean(world.run("--quiet", "snapshot", "--out", "junk.json"))
    assert json.loads((world.cwd / "junk.json").read_text("utf-8"))["sites"] == [
        5,
        ROW_PAYPAL,
        None,
    ]


# -- D12: exit-code inconsistencies (preserved) ------------------------------------------------------------


def test_exit_codes_distinguish_deep_usage_errors_from_runtime_failures(
    world, tmp_path
):
    serve_analysis(world)
    world.serve_paths(
        {"/api/v1/analyze": json_reply({}), "/feed.json": json_reply(FEED)}
    )
    assert world.run("--quiet", "deep", TARGET).code == 2, "deep without a token"
    assert world.run("--quiet", "deep", TARGET, "--token", TOKEN).code == 2, (
        "deep without --yes"
    )
    assert world.run("--quiet", "analyze", TARGET).code == 2, "analyze not confirmed"
    assert world.run("--quiet", "match", str(tmp_path / "missing.txt")).code == 1, (
        "unreadable match input"
    )
    assert world.run("--quiet", "diff", str(tmp_path / "missing.json")).code == 1, (
        "unreadable diff input"
    )
    hit = indicators_file(tmp_path, "203.0.113.2")
    assert world.run("--quiet", "match", hit, "--fail-on-hit").code == 1, (
        "a hit under --fail-on-hit shares the error code"
    )


def test_d12_deep_refusals_exit_2_like_the_analyze_refusal(world):
    assert world.run("--quiet", "deep", TARGET).code == 2
    assert world.run("--quiet", "deep", TARGET, "--token", TOKEN).code == 2


# -- D13: the confirmation prompt pollutes stdout -----------------------------------------------------------


def test_d13_the_prompt_does_not_contaminate_json_on_stdout(world):
    serve_analysis(world, {"ok": True})
    type_answer(world, "y\n")
    run = clean(world.run("--quiet", "analyze", TARGET, "--json"))
    assert run.json() == {"ok": True}
    assert TARGET in run.err and "Continue?" in run.err


# -- D14: an empty indicator from a stray comma line ---------------------------------------------------------


def test_a_comma_only_line_is_not_counted_as_an_indicator(fed, tmp_path):
    path = indicators_file(tmp_path, "paypal-login1.example.net", ",")
    data = clean(fed.run("--quiet", "match", path, "--json", "--show-misses")).json()
    assert (
        data["indicators"] == 1
        and data["misses"] == []
        and data["miss_indicators"] == 0
    )


def test_d14_empty_indicators_are_skipped(fed, tmp_path):
    path = indicators_file(tmp_path, "paypal-login1.example.net", ",", '"",x')
    data = clean(fed.run("--quiet", "match", path, "--json", "--show-misses")).json()
    assert data["indicators"] == 1 and data["misses"] == []


# -- D15: analyze needs the active_scan grant (preserved) and the manual says so ------------------------------


def test_d15_the_manual_states_the_active_scan_requirement():
    manual = (REPO / "docs" / "manual.md").read_text("utf-8")
    row = next(
        line
        for line in manual.splitlines()
        if line.startswith("| `phish` | Talks only to")
    )
    assert "active_scan" in row


# -- D16: the deep token lands in the private run ledger --------------------------------------------------------


def test_d16_the_deep_token_is_not_stored_in_clear_text_in_the_run_ledger(world):
    serve_analysis(world)
    clean(world.run("--quiet", "deep", TARGET, "--token", TOKEN, "--yes", "--json"))
    blobs = [
        path.read_bytes()
        for path in (world.workspace_dir / "runs").rglob("*")
        if path.is_file()
    ]
    assert blobs, "the ledger recorded the request"
    assert not any(TOKEN.encode() in blob for blob in blobs)


def test_the_deep_token_never_appears_on_stdout_or_stderr(world):
    serve_analysis(world)
    run = clean(
        world.run("--quiet", "--verbose", "deep", TARGET, "--token", TOKEN, "--yes")
    )
    assert TOKEN not in run.out + run.err
    failing = world.run("--quiet", "deep", TARGET, "--token", TOKEN)
    assert TOKEN not in failing.out + failing.err


# -- D17 / D18: packaging facts -----------------------------------------------------------------------------------


# D17 (accepted fix, orchestrator decision: the rebuild pins httpx==0.28.1 to match pyproject, since egress relies on 0.28.1 internals).
def test_d17_requirements_pin_the_same_httpx_as_the_project():
    lines = {
        line.strip()
        for line in (DEFAULT_SCRIPT.parent / "requirements.txt")
        .read_text("utf-8")
        .splitlines()
        if line.strip()
    }
    assert "httpx==0.28.1" in lines and "rich>=13.7.0" in lines


def test_requirements_list_httpx_and_rich_and_nothing_else_PINNED():
    names = {
        re.split(r"[<>=!~ ]", line.strip())[0]
        for line in (DEFAULT_SCRIPT.parent / "requirements.txt")
        .read_text("utf-8")
        .splitlines()
        if line.strip()
    }
    assert names == {"httpx", "rich"}


# D17 (accepted fix, orchestrator decision: the rewritten README no longer names the `requests` library; the dependency is httpx).
def test_d17_readme_does_not_claim_the_requests_library():
    readme = (DEFAULT_SCRIPT.parent / "README.md").read_text("utf-8")
    assert "`requests`" not in readme and "requests, rich" not in readme


# D17 (accepted fix, orchestrator decision: a clean-room README hotlinks no upstream-hosted images).
def test_d17_readme_hotlinks_no_images():
    readme = (DEFAULT_SCRIPT.parent / "README.md").read_text("utf-8")
    assert not re.search(r"!\[|<img|user-attachments", readme)


# D18 (accepted fix, orchestrator decision: the byte-identical upstream addon .gitignore is deleted).
def test_d18_the_addon_gitignore_is_not_the_upstream_file():
    path = DEFAULT_SCRIPT.parent / ".gitignore"
    assert (
        not path.exists()
        or path.read_bytes().replace(b"\r\n", b"\n")
        != b"__pycache__/\n*.pyc\n.cache/\n"
    )


# -- D19: cosmetics ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ("--quiet", "--help"),
        ("--quiet", "hunt", "--help"),
        ("hunt", "--quiet", "--help"),
    ],
)
def test_d19_quiet_help_prints_no_banner(world, monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["lanternjaw.py"])
    run = world.run(*argv)
    assert run.code == 0 and run.out.strip() and run.err == ""
    following = world.run("--help")
    assert following.code == 0 and following.err.strip()


def test_d19_the_wrote_notice_reports_real_bytes(world):
    row = {**ROW_PAYPAL, "org": "é" * 40}
    world.serve_paths({"/feed.json": json_reply([row])})
    run = clean(world.run("--quiet", "snapshot", "--out", "bytes.json"))
    reported = int(
        re.search(r"\(([\d,]+) bytes\)", run.etext).group(1).replace(",", "")
    )
    assert reported == (world.cwd / "bytes.json").stat().st_size


# -- D20: the 60-line function rule -----------------------------------------------------------------------------


# D20 (accepted fix, orchestrator decision: the rebuild splits long functions so none exceeds the project's 60-line rule).
def test_d20_no_function_exceeds_60_lines():
    tree = ast.parse(SCRIPT.read_text("utf-8"))
    long = {
        node.name: node.end_lineno - node.lineno + 1
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.end_lineno - node.lineno + 1 > 60
    }
    assert long == {}


# -- D21 (NEW, found writing this oracle): a trailing newline passes uuid validation ----------------------------------


@pytest.mark.parametrize("argv", [("related",), ("enrich",), ("inspect",)])
def test_d21_a_uuid_with_a_trailing_newline_is_rejected_cleanly(world, argv):
    world.serve(json_reply({}))
    run = world.run("--quiet", *argv, uid(1) + "\n")
    assert run.exc is None and run.code == 2 and world.requests == []


# ---------------------------------------------------------------------------------------------
# Z. Small pure rules through their observable edges (spec 4.4): defang, refang, flags, scores
# ---------------------------------------------------------------------------------------------

DEFANG_VECTORS = [
    ("https://evil.example/a", "hxxps://evil[.]example/a"),
    ("http://a.b", "hxxp://a[.]b"),
    ("hxxp://a[.]b", "hxxp://a[.]b"),
    ("hxxps://x[.]y/z.html", "hxxps://x[.]y/z[.]html"),
    ("https:evil.example", "hxxps:evil[.]example"),
    ("http:evil.example", "hxxp:evil[.]example"),
    ("evil.example", "evil[.]example"),
    ("1.2.3.4", "1[.]2[.]3[.]4"),
    ("HTTPS://Evil.Example/", "HTTPS://Evil[.]Example/"),
    ("https://a.b/http://c.d", "hxxps://a[.]b/hxxp://c[.]d"),
    ("ftp://a.b", "ftp://a[.]b"),
    ("see http:foo.bar", "see hxxp:foo[.]bar"),
    ("no-dots-here", "no-dots-here"),
]


@pytest.mark.parametrize("raw,defanged", DEFANG_VECTORS)
def test_defang_vectors_through_hunt_values(world, raw, defanged):
    world.serve_paths(
        {
            "/feed.json": json_reply(
                [{"uuid": uid(1), "url": raw, "first_seen": "2026-10-01T00:00:00Z"}]
            )
        }
    )
    assert clean(world.run("--quiet", "hunt", "--values")).out == defanged + "\n"
    assert clean(world.run("--quiet", "--live", "hunt", "--values")).out == raw + "\n"


def test_defang_is_applied_once_to_already_defanged_input_and_empty_values_show_a_dash(
    world,
):
    rows = [
        {
            "uuid": uid(1),
            "url": "hxxps://a[.]b[.]c/x",
            "first_seen": "2026-10-03T00:00:00Z",
        },
        {"uuid": uid(2), "first_seen": "2026-10-02T00:00:00Z"},
        {"uuid": uid(3), "domain": "d.example", "first_seen": "2026-10-01T00:00:00Z"},
    ]
    world.serve_paths({"/feed.json": json_reply(rows)})
    assert clean(world.run("--quiet", "hunt", "--values")).lines == [
        "hxxps://a[.]b[.]c/x",
        EM_DASH,
        "d[.]example",
    ]


REFANG_VECTORS = [  # indicator as the user pastes it -> the reason it matches the feed row evil.example / https://evil.example/a
    ("hxxps://evil[.]example/a", "exact-url"),
    ("evil(.)example", "exact-domain"),
    ("evil{.}example", "exact-domain"),
    ("'evil.example'", "exact-domain"),
    ("  evil.example  ", "exact-domain"),
    ("hxxp://evil[.]example/zzz", "exact-domain"),
    ("https://evil.example/a", "exact-url"),
    ("EVIL.EXAMPLE", "exact-domain"),
]


@pytest.mark.parametrize("indicator,reason", REFANG_VECTORS)
def test_refang_vectors_through_match(world, tmp_path, indicator, reason):
    world.serve_paths(
        {
            "/feed.json": json_reply(
                [
                    {
                        "uuid": uid(1),
                        "domain": "evil.example",
                        "url": "https://evil.example/a",
                    }
                ]
            )
        }
    )
    path = tmp_path / "ind.txt"
    path.write_text(indicator + "\n", encoding="utf-8")
    data = clean(world.run("--quiet", "match", str(path), "--json")).json()
    assert [(h["reason"], h["uuids"]) for h in data["hits"]] == [(reason, [uid(1)])]


@pytest.mark.parametrize(
    "value,flagged",
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        (2.5, True),
        (0.0, False),
        ("1", True),
        ("0", False),
        ("true", True),
        ("TRUE", True),
        (" yes ", True),
        ("Y", True),
        ("y", True),
        ("false", False),
        ("no", False),
        ("n", False),
        ("", False),
        ("on", False),
        ("2", False),
        (None, False),
        ([1], False),
        ({"a": 1}, False),
    ],
)
def test_source_flag_truthiness_through_the_pulse_source_counts(world, value, flagged):
    world.serve_paths(
        {"/feed.json": json_reply([{"uuid": uid(1), "malicious_google": value}])}
    )
    data = clean(world.run("--quiet", "pulse", "--json")).json()
    assert data["sources"] == ({"Google Safe Browsing": 1} if flagged else {})


def test_each_of_the_five_source_fields_maps_to_its_label(world):
    rows = [{"uuid": uid(i + 1), field: True} for i, field in enumerate(SOURCE_FIELDS)]
    world.serve_paths({"/feed.json": json_reply(rows)})
    data = clean(world.run("--quiet", "pulse", "--json")).json()
    assert data["sources"] == {
        "Google Safe Browsing": 1,
        "OpenPhish": 1,
        "PhishTank": 1,
        "TweetFeed": 1,
        "urlscan.io": 1,
    }


@pytest.mark.parametrize(
    "row,score",
    [
        ({"score": 40}, 40),
        ({"score": "40"}, 40),
        ({"score": "40.9"}, 40),
        ({"score": 40.9}, 40),
        ({"score": "abc", "phishunt_score": 33}, 33),
        ({"score": "", "url_risk_score": "41.9"}, 41),
        ({"score": None, "phishunt_score": None}, 0),
        ({}, 0),
        ({"phishunt_score": 7, "url_risk_score": 9}, 7),
        ({"score": 0, "phishunt_score": 50}, 0),
        ({"score": [1], "url_risk_score": 8}, 8),
        ({"url_risk_score": "12"}, 12),
    ],
)
def test_score_fallback_chain_through_the_pulse_median(world, row, score):
    world.serve_paths({"/feed.json": json_reply([{"uuid": uid(1), **row}])})
    assert clean(world.run("--quiet", "pulse", "--json")).json()[
        "median_score"
    ] == float(score)


@pytest.mark.parametrize(
    "row,tier",
    [
        ({"verdict": "high"}, "high"),
        ({"verdict": "", "url_risk": "low"}, "low"),
        ({"url_risk": "medium"}, "medium"),
        ({}, EM_DASH),
        ({"verdict": None, "url_risk": None}, EM_DASH),
        ({"verdict": "high", "url_risk": "low"}, "high"),
    ],
)
def test_verdict_falls_back_to_url_risk_then_a_dash(world, row, tier):
    world.serve_paths({"/feed.json": json_reply([{"uuid": uid(1), **row}])})
    assert clean(world.run("--quiet", "pulse", "--json")).json()["verdicts"] == {
        tier: 1
    }


@pytest.mark.parametrize(
    "domain,counts",
    [
        ("kit.pages.dev", "paas_suffix"),
        ("pages.dev", "paas_suffix"),
        ("evilpages.dev", None),
        ("a.b.vercel.app", "paas_suffix"),
        ("xn--abc.example", "punycode"),
        ("XN--ABC.EXAMPLE", "punycode"),
        ("a.github.io", "paas_suffix"),
        ("github.io.evil.example", None),
        ("x.godaddysites.com", "paas_suffix"),
    ],
)
def test_platform_suffix_and_punycode_counters(world, domain, counts):
    world.serve_paths({"/feed.json": json_reply([{"uuid": uid(1), "domain": domain}])})
    data = clean(world.run("--quiet", "pulse", "--json")).json()
    assert {key: data[key] for key in ("punycode", "paas_suffix")} == {
        "punycode": int(counts == "punycode"),
        "paas_suffix": int(counts == "paas_suffix"),
    }


APPENDIX_A_SUFFIXES = [
    "pages.dev",
    "vercel.app",
    "github.io",
    "blogspot.com",
    "web.app",
    "firebaseapp.com",
    "workers.dev",
    "netlify.app",
    "azurewebsites.net",
    "herokuapp.com",
    "glitch.me",
    "r2.dev",
    "webflow.io",
    "myshopify.com",
    "square.site",
    "teachable.com",
    "godaddysites.com",
]
APPENDIX_A_TOKENS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "wallet",
    "account",
    "password",
    "update",
]


def test_every_appendix_a_shared_platform_suffix_is_counted(world):
    rows = [
        {"uuid": uid(i + 1), "domain": f"x.{suffix}"}
        for i, suffix in enumerate(APPENDIX_A_SUFFIXES)
    ]
    world.serve_paths({"/feed.json": json_reply(rows)})
    assert clean(world.run("--quiet", "pulse", "--json")).json()["paas_suffix"] == 17


def test_every_appendix_a_path_token_is_counted_case_insensitively_over_the_whole_url(
    world,
):
    rows = [
        {"uuid": uid(i + 1), "url": f"https://h.example/{token.upper()}"}
        for i, token in enumerate(APPENDIX_A_TOKENS)
    ]
    rows.append({"uuid": uid(99), "url": "https://h.example/nothing-here"})
    world.serve_paths({"/feed.json": json_reply(rows)})
    assert (
        clean(world.run("--quiet", "pulse", "--json")).json()["credential_path"] == 10
    )


def test_noise_flagged_counts_noise_or_missing_verdicts_that_a_source_flagged(world):
    rows = [
        {"uuid": uid(1), "verdict": "noise", "malicious_google": True},
        {"uuid": uid(2), "malicious_openphish": True},
        {"uuid": uid(3), "verdict": "noise"},
        {"uuid": uid(4), "verdict": "high", "malicious_google": True},
        {"uuid": uid(5), "verdict": "NOISE", "malicious_urlscan": True},
    ]
    world.serve_paths({"/feed.json": json_reply(rows)})
    assert clean(world.run("--quiet", "pulse", "--json")).json()["noise_flagged"] == 3


def test_hunt_json_ignores_values_and_the_rows_array_wins_PINNED(fed):
    run = clean(fed.run("--quiet", "hunt", "--json", "--values", "--limit", "1"))
    assert run.json() == [ROW_BANK]


def test_search_passes_the_query_through_unstripped_PINNED_QUIRK(world):
    world.serve_paths({"/api/v1/search.json": json_reply({"results": [], "count": 0})})
    clean(world.run("--quiet", "search", "  abcd ", "--json"))
    assert world.params()["q"] == "  abcd "


# SENTINEL-NEXT-SECTION


@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("through_loader", [False, True])
@pytest.mark.parametrize("mode, expected", [("ok", 0), ("usage", 2), ("refusal", 2)])
def test_output_encoding_policy_is_restored(
    world, shared, through_loader, mode, expected
):
    module = world.lj
    world.mp.setenv("BUGHUNT_ADDONS", str(world.addons_root))
    output = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    error = (
        output
        if shared
        else io.TextIOWrapper(
            io.BytesIO(), encoding="cp1252", errors="xmlcharrefreplace"
        )
    )
    arguments = (
        ["--quiet", "about"]
        if mode == "ok"
        else ["bad-command"]
        if mode == "usage"
        else ["--quiet", "deep", TARGET]
    )
    with world.mp.context() as patch:
        patch.setattr(sys, "stdout", output)
        patch.setattr(sys, "stderr", error)
        try:
            code = (
                loader.run_named(
                    "phish",
                    arguments,
                    tool_file=Path(scanner.__file__),
                    scan_main=scanner.main,
                )
                if through_loader
                else module.main(arguments)
            )
        except SystemExit as problem:
            code = problem.code
        assert code == expected
        assert output.errors == "strict"
        assert error.errors == ("strict" if shared else "xmlcharrefreplace")
        print(json.dumps({"next": "🙂"}, ensure_ascii=True))
        output.flush()
        assert json.loads(
            output.buffer.getvalue().decode("cp1252").splitlines()[-1]
        ) == {"next": "🙂"}


def test_machine_json_on_cp1252_preserves_non_bmp_unicode(world):
    module = world.lj
    output = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    payload = {"value": "café 中文 🙂"}
    with world.mp.context() as patch:
        patch.setattr(sys, "stdout", output)
        module.emit_json(payload)
        output.flush()
    assert json.loads(output.buffer.getvalue().decode("cp1252")) == payload
