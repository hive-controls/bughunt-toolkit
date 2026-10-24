"""Four-attempt, two-worker scheduler restricted to an explicitly owned lab."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from dataclasses import dataclass
import ipaddress
import re
import threading
import time
from urllib.parse import urlsplit

import httpx

from bughunt.core import egress, exchange, job, ledger
from bughunt.core.workspace import matches, read_entries


@dataclass(frozen=True)
class Plan:
    source_id: str
    method: str
    url: str
    headers: tuple
    body: bytes
    budget: job.Budget
    max_bytes: int


def prepare(
    record: dict, *, mission: str, owned_lab=False, seconds=5, max_bytes=65536
) -> Plan:
    exchange.validate(record)
    request = record["request"]
    parsed = urlsplit(request["url"])
    if (
        owned_lab is not True
        or not ipaddress.ip_address(parsed.hostname).is_loopback
        or not parsed.path.startswith("/__bughunt_lab__/")
    ):
        raise ValueError(
            "Only explicitly owned literal-loopback laboratory paths are supported"
        )
    if (
        request["truncated"]
        or request["body_size"] > 65536
        or request["method"] not in {"GET", "HEAD", "POST"}
    ):
        raise ValueError("Require a complete bounded GET/HEAD/POST source")
    if (
        type(seconds) not in (int, float)
        or not 0 < seconds <= 10
        or type(max_bytes) is not int
        or not 1 <= max_bytes <= 65536
    ):
        raise ValueError("Invalid laboratory duration/body bounds")
    profile = egress.authorize(request["url"], "active_scan", request["method"])
    if (
        profile.mission != mission
        or profile.mission != "whk014-owned-race"
        or profile.concurrency < 2
        or not matches(parsed.hostname, read_entries())
    ):
        raise ValueError(
            "Named race mission, two-worker grant and workspace scope are required"
        )
    headers = tuple(
        (name, value)
        for name, value in request["headers"]
        if not re.search(
            r"cookie|auth|token|api[-_]?key|secret|session|csrf", name, re.I
        )
        and name.lower()
        not in {
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "upgrade",
            "expect",
        }
    )
    ledger.redact_text("")
    budget = job.Budget(
        frozenset({(request["method"], request["url"])}), 4, seconds, strict_scope=True
    )
    return Plan(
        record["exchange_id"],
        request["method"],
        request["url"],
        headers,
        exchange.decode(request["body_b64"], 65536),
        budget,
        max_bytes,
    )


def preview(plan: Plan) -> dict:
    return {
        "job_id": plan.budget.job_id,
        "source_exchange_id": plan.source_id,
        "target": plan.url,
        "method": plan.method,
        "operation": "active_scan",
        "request_cap": 4,
        "workers": 2,
        "duration_cap": plan.budget.seconds,
        "actor": plan.budget.state[0][1],
        "dry_run": True,
        "warning": "Two controls plus two probes may change lab state; cleanup is manual; timing is best-effort",
    }


def _attempt(plan: Plan, role: str, barrier, transport_factory) -> dict:
    token = ledger.CURRENT_TOOL.set("race")
    try:
        if barrier is not None:
            barrier.wait(timeout=max(0.001, plan.budget.deadline - time.monotonic()))
        inner = transport_factory() if transport_factory is not None else None
        with egress.client(
            operation="active_scan",
            transport=job.Transport(plan.budget, inner),
            follow_redirects=False,
        ) as client:
            request = httpx.Request(
                plan.method, plan.url, headers=plan.headers, content=plan.body
            )
            request.extensions["bughunt_job_guard"] = plan.budget.check
            response = client.send(request, stream=True)
            try:
                body = bytearray()
                complete = True
                for chunk in response.iter_raw():
                    plan.budget.check(request)
                    if len(body) + len(chunk) > plan.max_bytes:
                        complete = False
                        break
                    body.extend(chunk)
                plan.budget.check(request)
                return {
                    "role": role,
                    "run_id": response.extensions["bughunt_run_id"],
                    "status": response.status_code,
                    "body_sha256": exchange.digest(bytes(body)),
                    "complete": complete,
                    "finished_monotonic": time.monotonic(),
                }
            finally:
                response.close()
    except (ValueError, OSError, httpx.HTTPError, threading.BrokenBarrierError) as exc:
        return {"role": role, "error": type(exc).__name__}
    finally:
        ledger.CURRENT_TOOL.reset(token)


def execute(plan: Plan, *, transport_factory=None) -> dict:
    profile = egress.authorize(plan.url, "active_scan", plan.method)
    plan.budget.activate()
    samples = [_attempt(plan, "control-before", None, transport_factory)]
    interrupted = False
    if "error" not in samples[0] and samples[0]["complete"]:
        with ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="bughunt-owned-race"
        ) as pool:
            barrier = threading.Barrier(2)
            futures = [
                pool.submit(
                    copy_context().run,
                    _attempt,
                    plan,
                    "probe",
                    barrier,
                    transport_factory,
                )
                for _ in range(2)
            ]
            try:
                samples.extend(future.result() for future in futures)
            except KeyboardInterrupt:
                interrupted = True
                plan.budget.cancelled.set()
                samples.extend(future.result() for future in futures)
        if (
            all("error" not in value and value["complete"] for value in samples)
            and not interrupted
        ):
            samples.append(_attempt(plan, "control-after", None, transport_factory))
    invalid = (
        interrupted
        or len(samples) != 4
        or any("error" in row or not row.get("complete", False) for row in samples)
    )
    result = {
        **preview(plan),
        "dry_run": False,
        "classification": "invalid" if invalid else "observation",
        "samples": samples,
        "requests": list(plan.budget.sent),
        "cleanup": "pending",
        "claim": "Owned lab scheduler observations; admission times are not synchronized wire sends or impact proof",
    }
    result["run_id"] = ledger.record_analysis(
        profile,
        tool="race",
        operation="active_scan",
        target=plan.url,
        actor=plan.budget.state[0][1],
        value=result,
        classification=result["classification"],
    )
    return ledger.redact(result)
