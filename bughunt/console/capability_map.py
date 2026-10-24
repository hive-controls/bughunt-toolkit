"""Versioned fixture coverage, not an executable registry or authority grant."""

from pathlib import Path
import sys

from bughunt import VERSION
from bughunt.integrations import browser_actor, zap

# id, mission need, owner, status, story, versions, tests, tested scope, gap
_ROWS = (
    ("native-foundation", "Bound authorized traffic and retain private evidence", "Bughunt", "delivered", "CAP-01",
     [VERSION, "Python 3.14.3", "HTTPX 0.28.1", "httpcore 1.0.9"],
     ["test_policy.py", "test_gate.py", "test_ledger.py", "test_identity.py", "test_verification.py"],
     "Exact mission/operation/origin/path, named actors and server-side principal proofs; pre-boundary rejection",
     "Saved credentials alone do not prove authentication; write assurance is bounded by the dispatch-spacing profile below"),
    ("dispatch-spacing", "Prevent preparation delays from compressing supported outbound writes", "Bughunt", "delivered", "CAP-28",
     [VERSION, "HTTPX 0.28.1", "httpcore 1.0.9"],
     ["test_final_dispatch.py", "test_native_dispatch.py", "test_dispatch_wire.py"],
     "In-process workspace-shared native HTTP header/raw write leases; actual owned HTTP/1.1 sync, async and mixed arrival controls",
     "No remote-arrival/processing or cross-process guarantee; opaque/legacy raw paths are admission-only; "
     "actual HTTP/2/TLS/proxy wire coverage is not established and managed HTTPS proxy routing is unavailable"),
    ("authorization-differential", "Compare owned owner/lower-privilege/anonymous responses", "Bughunt", "delivered", "CAP-06",
     [VERSION, "HTTPX 0.28.1"], ["test_replay.py"],
     "One verified bounded baseline; negative/lead/invalid/inconclusive outcomes with linked captures",
     "A matching response is a lead, not automatic impact, severity or a confirmed finding"),
    ("http-interchange", "Select and preserve captured HTTP evidence", "Bughunt", "delivered", "CAP-07",
     [VERSION], ["test_exchange.py"], "Hash-checked ledger/raw/HAR/native records; inert sanitized derivatives",
     "Logical HTTP records are not general wire-byte or proprietary-project parity"),
    ("input-discovery", "Test explicitly selected hidden input candidates", "Bughunt", "delivered", "CAP-11",
     [VERSION], ["test_discovery.py", "test_job.py"], "Bounded explicit query/header/cookie candidates with controls",
     "No full Param Miner wordlist harvesting or automatic candidate crawl"),
    ("zap-passive", "Analyze recorded HTTP without additional target sends", "ZAP managed by Bughunt", "delivered", "CAP-18",
     [zap.SUPPORTED_VERSION, zap.SUPPORTED_IMAGE], ["test_zap_passive_consumer.py"],
     "Pinned network-none consumer, sanitized recorded HTTP/HTML, automatic H1 report import and cleanup",
     "Recorded-evidence correspondence is not a clean bill of health or broad rule coverage"),
    ("zap-active", "Run an explicitly approved bounded active laboratory job", "ZAP managed by Bughunt", "lab-only", "CAP-12",
     [zap.SUPPORTED_VERSION, zap.SUPPORTED_IMAGE], ["test_zap_active_consumer.py"],
     "Owned literal 127.0.0.1 HTTP/Python GET query, credential-free default actor, rule 40012; Bughunt final sends",
     "No production-domain, HTTPS, authenticated or general scanner profile"),
    ("burp-xml", "Import selected Community messages without project parsing", "Bughunt", "delivered", "CAP-10",
     ["Community 2026.9.2"], ["test_burp.py"], "Bounded inert Save-items XML with source hash and explicit capture zone",
     "Manual export remains an optional interchange path, not general extension control"),
    ("burp-intake", "Select Community history directly from Bughunt", "Burp Community read by Bughunt", "delivered", "CAP-24",
     ["Community 2026.9.2", "BApp 1.3.0", "server self-report 1.1.2"], ["test_burp_consumer.py"],
     "One approved bounded HTTP history page; incomplete SDK-text records, original private hashes and zero target sends",
     "No send/editor/config/task tools, wire/binary parity, verified actor or general specialist dispatcher"),
    ("oast-correlation", "Link approved imported callbacks to initiating evidence", "Bughunt", "delivered", "CAP-13",
     [VERSION, "normalized callback bundle v1"], ["test_oast.py"], "Inert approved-domain normalized callback correlation",
     "No provider registration, polling or authenticated native-provider format acceptance"),
    ("race-lab", "Observe controlled concurrent request effects", "Bughunt", "lab-only", "CAP-14",
     [VERSION], ["test_race.py"], "Named owned-loopback mission; two workers/four attempts and physical budget controls",
     "No HTTP/2 single-packet Turbo Intruder equivalence"),
    ("websocket-lab", "Capture/replay owned text WebSocket messages", "Bughunt", "lab-only", "CAP-15",
     [VERSION, "websockets 15.0.1"], ["test_websocket.py"], "Named bounded owned-loopback text and protocol-write laboratory",
     "No general WSS/binary/fragmentation/compression workbench"),
    ("desync-lab", "Observe parser disagreement and response queues", "Bughunt", "lab-only", "CAP-16",
     [VERSION], ["test_desync.py"], "Fixed owned HTTP/1.1 front/back parser and queue fixtures with wire counters",
     "No production desync scan or Request Smuggler parity"),
    ("authenticated-exploration", "Explore owned authenticated and JavaScript routes", "ZAP managed by Bughunt", "planned", "CAP-19",
     ["not accepted"], [], "Not implemented", "Requires pinned login/browser components and enforced final-send containment"),
    ("burp-specialist", "Invoke a useful specialist operation programmatically", "Curated adapter", "unavailable", "CAP-20",
     ["not accepted"], [], "Installed inventory and entry-point assessment only",
     "No accepted inbound specialist job API or physical-send containment; schema is design, not an executable adapter"),
    ("live-oast", "Register and poll self-hosted callback payloads", "Approved self-hosted provider", "planned", "CAP-21",
     ["not accepted"], [], "Not implemented", "Owned provider/domain/DNS/TLS authority and native format acceptance required"),
    ("general-websocket", "Manage broader WebSocket capture, replay and bounded fuzz", "Bughunt with supporting engines", "planned", "CAP-22",
     ["not accepted"], [], "Not implemented", "Initial passive intake and general protocol/socket containment still pending"),
    ("offline-triage", "Group responses, extract HTML candidates and summarize flows", "Bughunt", "delivered", "CAP-25",
     [VERSION], ["test_triage.py"], "Offline 1-32 selected hash-checked exchanges; exact/whitespace groups, inert HTML hints and timestamp-qualified flow links",
     "Digest grouping is not proof of equivalent authorization or impact; no crawl, extension parity or automatic probing"),
    ("request-minimization", "Reduce known request elements with measured controls", "Bughunt", "planned", "CAP-26",
     ["not accepted"], [], "Not implemented", "No Packet Purifier UI-send bypass; interactions and final validation need accounting"),
    ("browser-actors", "Launch isolated owned browser sessions", "Bughunt managing Chromium", "lab-only", "CAP-27",
     ["Chromium 151.0.7922.34", "Playwright 1.62.1", browser_actor.IMAGE],
     ["test_browser_actor.py", "test_browser_runtime.py", "test_browser_consumer.py"],
     "Owned literal-loopback HTTP; one named actor/job, fresh private profile, sandboxed network-none consumer; verified host GETs and physical caps including probes",
     "No production-domain, HTTPS, interactive login/crawl or reusable browser storage export; WS/service workers blocked; strict header spacing remains the dispatch-spacing capability"),
    ("api-schema", "Import API schemas and exercise schema-derived coverage", "No accepted owner", "unavailable", "CAP-23",
     ["not accepted"], [], "No accepted API/schema adapter", "Track a demonstrated owned need before adding a bounded story"),
    ("paid-burp", "Use Scanner, Collaborator or other paid-only dependencies", "Burp Professional", "excluded", "CAP-23",
     ["excluded by product direction"], [], "Intentionally excluded", "No required workflow may depend on paid Burp features"),
)

_ENVIRONMENT = {
    "dispatch-spacing": {"BUGHUNT_RUN_DISPATCH_CONSUMER": "1"},
    "zap-passive": {"BUGHUNT_ZAP_PASSIVE_INTEGRATION": "1"},
    "zap-active": {"BUGHUNT_ZAP_ACTIVE_INTEGRATION": "1"},
    "burp-intake": {"BUGHUNT_BURP_INTEGRATION": "1"},
    "race-lab": {"BUGHUNT_RACE_INTEGRATION": "1"},
    "websocket-lab": {"BUGHUNT_WS_INTEGRATION": "1"},
    "desync-lab": {"BUGHUNT_DESYNC_INTEGRATION": "1"},
    "browser-actors": {"BUGHUNT_BROWSER_INTEGRATION": "1"},
}


def acceptance(tests: list[str], *, identifier: str = "") -> dict:
    """Describe checkout commands lexically; never probe or execute the runtime."""
    root = Path(__file__).absolute().parents[2]
    python = root / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    prerequisites = ["Source checkout with a prepared project virtual environment and pytest dependencies"]
    if identifier == "burp-intake":
        prerequisites += ["BUGHUNT_BURP_PROFILE: inspected private local profile",
            "BUGHUNT_BURP_XML_FIXTURE: owned original fixture", "Explicit operator Deny/Allow Once for manual cases"]
    elif identifier == "browser-actors":
        prerequisites += ["Local Docker daemon and exact pinned Playwright 1.62.1 image; no automatic pull",
            "Matching fingerprinted driver archive and upstream seccomp profile; see the project documentation for setup",
            "Optional BUGHUNT_BROWSER_RUNTIME points to that private dependency directory"]
    elif identifier == "owned-workflow":
        prerequisites += ["Local Docker daemon with the pinned ZAP image; no automatic pull",
            "Optional BUGHUNT_BURP_PROFILE: existing inspected absolute local profile for configured-no-use; "
            "unset skips only that comparison, not the unconfigured core or native actor controls"]
    return {"tests": list(tests), "environment": dict(_ENVIRONMENT.get(identifier, {})),
        "prerequisites": prerequisites, "cwd": str(root),
        "argv": [str(python), "-m", "pytest", "-q", *tests] if tests else []}


def describe() -> dict:
    """Return a fresh public coverage map; it cannot change engine permissions."""
    capabilities = []
    for identifier, need, owner, status, story, versions, tests, scope, gap in _ROWS:
        capabilities.append({"capability_id": identifier, "mission_need": need, "owner": owner,
            "status": status, "story": story,
            "supported_versions": list(versions), "tested_scope": scope, "remaining_gap": gap,
            "acceptance": acceptance(tests, identifier=identifier)})
    return {"schema_version": 1, "revision": "dispatch-v1", "execution_authority": False,
        "physical_requests": 0, "capabilities": capabilities,
        "scope": "Dated fixture coverage, not runtime availability or permission; see CHANGELOG.md for delivery status",
        "owned_workflow_acceptance": {**acceptance(["test_workbench_consumer.py"], identifier="owned-workflow"),
            "environment": {"BUGHUNT_WORKBENCH_INTEGRATION": "1"}}}
