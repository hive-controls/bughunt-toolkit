"""BH-9: silk --actor authenticated crawl — boundary tests (identity + egress + ledger).

These drive the REAL guarded egress transport (so apply_request credential binding and the
per-request ledger receipt both run for real); only the inner network is a MockTransport. The
`policy` fixture (from test_gate) seeds a verified policy whose assets permit the crawl origin.
"""

from __future__ import annotations

import json

import httpx
import pytest

from bughunt.core import egress, identity, ledger
from bughunt.modules import silk
from test_gate import policy  # noqa: F401  (fixture: scratch workspace + seeded verified policy)

LOOP = "http://allowed.example"
# Two companions whose cookies the actor carries:
#   Case A (x-csrftoken) -- a name the ledger credential-name regex matches, so its value is
#     redacted by _KEY/_HEADER regardless of remember_secret.
#   Case B (x-double-submit) -- a name the regex does NOT match (the allowlist permits arbitrary
#     names), so its value is redacted ONLY because _bind_companions calls remember_secret.
COOKIE = "session=sess-abc; csrftoken=csrf-xyz; double-submit=plainvalue123"
COMPANION_VALUE = "csrf-xyz"       # Case A value
CASE_B_VALUE = "plainvalue123"     # Case B value -- redaction is load-bearing on remember_secret


def _owner(origins=(LOOP,)):
    identity.create_profile("owner", "owner", list(origins), owned=True)
    identity.set_credential("owner", "cookie", COOKIE)
    identity.set_companion_headers("owner", ["x-csrftoken", "x-double-submit"])


def _mock_net(monkeypatch):
    """Route silk's egress client through a recording MockTransport, keeping the guarded transport."""
    seen = []

    def handler(request):
        seen.append((str(request.url), dict(request.headers)))
        return httpx.Response(200, headers={"content-type": "text/html"}, content=b"<p>x</p>")

    real_client = egress.client

    def client(*, operation="manual", **kwargs):
        kwargs.setdefault("transport", httpx.MockTransport(handler))
        return real_client(operation=operation, **kwargs)

    monkeypatch.setattr(egress, "client", client)
    return seen


def _runs():
    return [json.loads(path.read_text()) for path in ledger.runs_dir().glob("*/manifest.json")]


def test_silk_actor_applies_credentials_and_companions_on_in_origin_requests(policy, monkeypatch):
    _owner()
    seen = _mock_net(monkeypatch)
    assert silk.main([LOOP + "/", "--actor", "owner", "--depth", "0"]) == 0
    start = [headers for url, headers in seen if url == LOOP + "/"]
    assert start, "the start page was fetched"
    assert start[0]["cookie"] == COOKIE
    assert start[0]["x-csrftoken"] == COMPANION_VALUE


def test_silk_actor_cross_origin_request_is_blocked_with_no_credentials(policy, monkeypatch):
    # The actor owns a DIFFERENT origin than the one being crawled; apply_request must refuse it.
    _owner(origins=("https://api.example",))
    seen = _mock_net(monkeypatch)
    assert identity.companion_supplements("owner", LOOP + "/") == {}
    assert silk.main([LOOP + "/", "--actor", "owner", "--depth", "0"]) == 1
    assert seen == []  # nothing reached the wire: no credentials, no companions


def test_silk_actor_records_redacted_per_request_ledger_receipts(policy, monkeypatch):
    _owner()
    _mock_net(monkeypatch)
    assert silk.main([LOOP + "/", "--actor", "owner", "--depth", "0"]) == 0
    runs = _runs()
    assert runs, "a ledger receipt exists for the crawl"
    assert all(run["actor"] == "owner" and run["operation"] == "crawl" for run in runs)
    case_b_recorded = False
    for run in runs:
        text = ledger.export_run(run["run_id"])["captures"]["request"]["text"]
        assert "sess-abc" not in text        # session cookie value
        assert COMPANION_VALUE not in text   # Case A companion value (regex-redacted anyway)
        assert CASE_B_VALUE not in text       # Case B companion value -- proves remember_secret fired
        if "x-double-submit" in text.lower():
            case_b_recorded = True            # companion was recorded, then redacted (value gone)
    assert case_b_recorded, "the Case-B companion header reached a receipt and was redacted"


def test_silk_actor_respects_the_page_limit(policy, monkeypatch):
    _owner()
    seen = _mock_net(monkeypatch)
    assert silk.main([LOOP + "/", "--actor", "owner", "--limit", "1"]) == 0
    assert len(seen) == 1 and seen[0][0] == LOOP + "/"


def test_silk_actor_unknown_name_errors_without_crawling(policy, monkeypatch, capsys):
    seen = _mock_net(monkeypatch)
    assert silk.main([LOOP + "/", "--actor", "ghost"]) == 2
    assert seen == []
    assert "No usable actor named ghost." in capsys.readouterr().err


def test_silk_actor_conflicts_with_cookie_and_authorization(policy, monkeypatch, capsys):
    _owner()
    seen = _mock_net(monkeypatch)
    assert silk.main([LOOP + "/", "--actor", "owner", "--cookie", "x=1"]) == 2
    assert seen == []
    assert "Use --actor, or --cookie/--authorization, but not both." in capsys.readouterr().err
