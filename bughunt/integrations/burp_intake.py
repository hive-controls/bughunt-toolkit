"""Selected read-only Community history into existing incomplete exchange receipts."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import signal
import threading
import time
from urllib.parse import urlsplit

import httpx

from bughunt.core import egress, exchange, job, ledger
from bughunt.integrations import burp_mcp, burp_profile, burp_transport, zap_active
from bughunt.core.policy import parse_profile
from bughunt.core.workspace import workspace_dir

REPRESENTATION = "burp-sdk-text; incomplete; not wire bytes"


class IntakeBudget(job.Budget):
    def __init__(self, method: str, url: str, config: Path, installed: dict, seconds: int):
        self.operator_interrupted, self.interruption_active = False, False
        self.config, self.installed = config, installed
        self.fingerprint = burp_profile.stamps(installed, config)
        self.listener = None
        paths = [config, Path(__file__), Path(burp_mcp.__file__), Path(burp_profile.__file__), Path(burp_transport.__file__)]
        self.sources = {path: zap_active.ActiveBudget._hash(path, ledger.CAPTURE_LIMIT) for path in paths}
        super().__init__(frozenset({(method, url)}), 1, seconds, strict_scope=True)

    def check(self, request: httpx.Request) -> None:
        if self.interruption_active and self.operator_interrupted:
            self.cancelled.set()
        super().check(request)
        profile = egress.current_profile()
        if any(not profile.decide(str(request.url), operation, method=request.method).permitted
               for operation in ("passive", "process")):
            raise egress.PolicyBlocked("burp-intake-permission-revoked")
        if (burp_profile.stamps(self.installed, self.config) != self.fingerprint
                or any(zap_active.ActiveBudget._hash(path, ledger.CAPTURE_LIMIT) != digest
                       for path, digest in self.sources.items())):
            raise egress.PolicyBlocked("burp-intake-source-or-component-changed")
        if self.listener is not None and burp_profile.listener(self.installed) != self.listener:
            raise egress.PolicyBlocked("burp-intake-listener-changed")

    def check_all(self) -> None:
        method, url = next(iter(self.targets))
        self.check(httpx.Request(method, url))

    def admit(self, _request):
        raise egress.PolicyBlocked("burp-intake-target-sends-forbidden")

    def activate(self):
        super().activate()
        path = self.stop_path().parent / "job.json"
        exchange._write(path, dict(job._load(path), request_cap=0, claim="Inert selected source intake; no target sends"))


@dataclass(frozen=True)
class Plan:
    config: Path
    installed: dict
    budget: IntakeBudget
    profile: object
    source_id: str
    offset: int
    count: int


def prepare(*, mission: str, url: str, source_id: str, method="GET", offset=0, count=1,
            seconds=30, config=None) -> Plan:
    if (type(offset) is not int or not 0 <= offset <= 500 or type(count) is not int or not 1 <= count <= 10
            or type(seconds) not in {int, float}
            or (type(seconds) is float and not seconds.is_integer())):
        raise ValueError("Select a bounded explicit history page and integral deadline")
    if type(seconds) not in {int, float} or not 1 <= seconds <= 120:
        raise ValueError("Intake deadline must be 1..120 seconds")
    exchange.text(source_id, maximum=128)
    if str(httpx.URL(url)) != url:
        raise ValueError("Canonical exact selected URL required")
    path = Path(config) if config is not None else workspace_dir() / "burp-mcp.json"
    path = path.absolute()
    installed = burp_profile.load(path)
    profile = parse_profile(exchange.load_json(burp_profile.private_file(workspace_dir() / "policy.json", ledger.CAPTURE_LIMIT)))
    if profile.mission != mission:
        raise ValueError("Exact current intake mission required")
    budget = IntakeBudget(method, url, path, installed, int(seconds))
    budget.check_all()
    return Plan(path, installed, budget, profile, source_id, offset, count)


def descriptor(plan: Plan) -> dict:
    return {"profile_id": "burp-mcp-intake", "engine": "burp-intake", "operation": "passive",
        "target": next(iter(plan.budget.targets))[1], "targets": sorted(plan.budget.targets),
        "installed": burp_profile.summary(plan.installed), "source_hashes": list(plan.budget.sources.values()),
        "source_id": plan.source_id, "offset": plan.offset, "count": plan.count,
        "page_cap": 1, "byte_cap": burp_transport.LIMIT, "duration_cap": plan.budget.seconds,
        "request_cap": 0, "mission": plan.profile.mission, "policy_sha256": plan.budget.state[1],
        "claim": "Selected SDK text is incomplete evidence; no capture time, byte-losslessness or verified actor claim"}


def preview(plan: Plan) -> dict:
    plan.budget.check_all()
    return ledger.redact(dict(descriptor(plan), inert=True, process_launch=False))


def doctor(*, config=None) -> dict:
    path = Path(config).absolute() if config is not None else (workspace_dir() / "burp-mcp.json").absolute()
    try:
        installed = burp_profile.load(path)
        return dict(burp_profile.summary(installed), available=True,
                    unavailable_reason=None, permitted="Requires current passive/process permission and exact source selection")
    except FileNotFoundError:
        reason = "Inspected profile or installed Community component missing; no automatic install/launch"
    except (OSError, ValueError, TypeError, KeyError):
        reason = "Inspected Community profile, paths, versions or fingerprints invalid/changed"
    return {"profile_id": "burp-mcp-intake", "engine": "Burp Community", "available": False,
        "configured": burp_profile.configured_file(path), "connected": False, "loaded": "unprobed", "permitted": False,
        "unavailable_reason": reason, "request_execution": False,
        "tool_allowlist": [burp_transport.HISTORY]}


def _items(result: dict, count: int) -> list[dict]:
    if (set(result) not in ({"content", "isError"}, {"content", "isError", "_meta"})
            or result.get("isError") is not False or result.get("_meta", {}) != {}
            or not isinstance(result["content"], list) or len(result["content"]) != 1
            or set(result["content"][0]) != {"type", "text"} or result["content"][0]["type"] != "text"):
        raise ValueError("Unsupported or denied MCP history result")
    text = result["content"][0]["text"]
    if not isinstance(text, str) or len(text.encode()) > burp_transport.LIMIT:
        raise ValueError("History text exceeds cap")
    decoder = json.JSONDecoder(object_pairs_hook=exchange.unique_pairs)
    values = []
    while text.strip() and len(values) < count:
        value, length = decoder.raw_decode(text.lstrip())
        values.append(value)
        text = text.lstrip()[length:]
    if text.strip() or len(values) != count:
        raise ValueError("Selected history count changed or result incomplete")
    return values


def _record(item: dict, plan: Plan, index: int, source_hash: str, run_id: str) -> dict:
    if not isinstance(item, dict) or set(item) != {"request", "response", "notes"}:
        raise ValueError("Unsupported SDK history schema")
    request_text, response_text = item["request"], item["response"]
    if not isinstance(request_text, str) or not isinstance(response_text, str):
        raise ValueError("Missing SDK messages")
    if any("... (truncated)" in value or not value.isascii() for value in (request_text, response_text)):
        raise ValueError("SDK text encoding or truncation unknown")
    method, url = next(iter(plan.budget.targets))
    request = exchange.message(request_text.encode("ascii"), request=True, url=url, truncated=True, representation=REPRESENTATION)
    if request["method"] != method or request["url"] != url or exchange.header_values(request, "host") != [urlsplit(url).netloc]:
        raise ValueError("SDK message differs from explicit source selection")
    response = None if response_text == "<no response>" else exchange.message(response_text.encode("ascii"), request=False,
        head_response=method == "HEAD", truncated=True, representation=REPRESENTATION)
    provenance = exchange.source("burp", f"{plan.source_id}:sdk:item-{plan.offset + index}", source_hash, run_id=run_id)
    return exchange.record(request, response, [provenance])


def _import(plan: Plan, raw: bytes, result: dict, run_id: str, root: Path) -> dict:
    records, quarantined = [], []
    for index, item in enumerate(_items(result, plan.count), 1):
        try:
            records.append(_record(item, plan, index, exchange.digest(raw), run_id))
        except (ValueError, TypeError, KeyError):
            quarantined.append({"index": plan.offset + index, "reason": "unverifiable SDK schema, encoding, message or source selection"})
    encoded = exchange.canonical({"records": records, "quarantined": quarantined})
    if len(encoded) > exchange.INPUT_LIMIT:
        raise ValueError("Normalized selected batch exceeds cap")
    ledger._write_private(root / "normalized.json", encoded)
    plan.budget.check_all()
    identifiers = exchange.save(records, source_id=plan.source_id, source_bytes=raw, kind="burp") if records else []
    return {"exchange_ids": identifiers, "incomplete_count": len(records), "quarantined_count": len(quarantined)}


def _job_root(plan: Plan) -> Path:
    root = plan.budget.stop_path().parent
    if burp_profile.inspect_path(root, missing=True) is not None or root != job._root(plan.budget.job_id):
        raise ValueError("Fresh intake job directory required")
    root.mkdir(parents=True)
    return root


@contextmanager
def _interrupt_owner(budget: IntakeBudget):
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.getsignal(signal.SIGINT)
    def cancel(_number, _frame):
        # A signal callback must not acquire Event/Condition locks, even reentrantly.
        budget.operator_interrupted = True
    try:
        signal.signal(signal.SIGINT, cancel)
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def _finalize(plan: Plan, client, result: dict, state: str, reason: str, root: Path) -> dict:
    cleanup, receipts = True, []
    if client is not None:
        cleanup = False
        for _attempt in range(2):
            try:
                cleanup = client.close()
                break
            except KeyboardInterrupt:
                plan.budget.cancelled.set()
            except (OSError, ValueError, RuntimeError):
                break
        for identifier, raw in client.receipts.items():
            name = "rpc-" + identifier + ".json"
            ledger._write_private(root / name, raw)
            receipts.append(name)
    if plan.budget.operator_interrupted or plan.budget.cancelled.is_set():
        state, reason, result["classification"] = "cancelled", "Intake cancelled by operator", "inconclusive"
    if not cleanup:
        state, reason, result["classification"] = "failed", "Bridge cleanup unconfirmed", "inconclusive"
    result.update(cleanup_confirmed=cleanup, reason=reason)
    artifacts = receipts + [name for name in ("source.json", "normalized.json") if (root / name).exists()]
    # After this snapshot, bounded terminal receipt writing completes even on SIGINT.
    return job.finish_engine(plan.budget.job_id, result, result, state=state, artifacts=artifacts)


def run(plan: Plan, *, on_start=None, probe=False) -> dict:
    with _interrupt_owner(plan.budget):
        return _run_owned(plan, on_start=on_start, probe=probe)


def _run_owned(plan: Plan, *, on_start=None, probe=False) -> dict:
    root = _job_root(plan)
    plan.budget.activate()
    job.start_engine(plan.budget, plan.profile, descriptor(plan))
    plan.budget.interruption_active = True
    client = None
    result = {"job_id": plan.budget.job_id, "classification": "inconclusive", "admitted_count": 0,
        "exchange_ids": [], "incomplete_count": 0, "quarantined_count": 0, "report_run_id": None,
        "request_execution": False, "manual_controls_required": True,
        "claim": "SDK text intake only; unknown capture time and byte encoding; no replay authority or findings"}
    state, reason = "failed", "Intake blocked or interrupted"
    try:
        if on_start:
            on_start(plan.budget.job_id)
        plan.budget.check_all()
        if burp_profile.load(plan.config) != plan.installed:
            raise ValueError("Inspected component/profile drift")
        plan.budget.listener = burp_profile.listener(plan.installed)
        client = burp_mcp.Client(plan.installed["endpoint"], deadline=plan.budget.deadline, check=plan.budget.check_all)
        connected = client.handshake(plan.installed["tools_sha256"])
        plan.budget.check_all()
        job.mark_running(plan.budget.job_id)
        result["connection"] = connected
        if not probe:
            history = client.history(plan.count, plan.offset)
            raw = client.receipts["3"]
            ledger._write_private(root / "source.json", raw)
            result.update(_import(plan, raw, history, job.status(plan.budget.job_id)["run_id"], root))
        plan.budget.check_all()
        state = "partial" if result["quarantined_count"] else "success"
        result["classification"] = "inconclusive" if state == "partial" else "observation"
        reason = "Some selected items require manual source review" if state == "partial" else "Selected read-only intake completed"
    except KeyboardInterrupt:
        plan.budget.cancelled.set()
        state, reason = "cancelled", "Intake cancelled by operator"
    except (OSError, ValueError, TypeError, KeyError, RecursionError, RuntimeError):
        state = "cancelled" if plan.budget.cancelled.is_set() or plan.budget.stop_path().exists() else "failed"
    finally:
        result = _finalize(plan, client, result, state, reason, root)
    return result
