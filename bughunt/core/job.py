"""Final-send bounds for sequential owned HTTP jobs; no autonomous retries."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import threading
import time
import uuid

import httpx

from bughunt.core import egress, exchange, identity, ledger, pipeline_context
from bughunt.core.policy import Profile
from bughunt.core.workspace import (
    allowed,
    hostname_of,
    matches,
    read_entries,
    workspace_dir,
)


@dataclass
class Budget:
    targets: frozenset[tuple[str, str]]
    maximum: int
    seconds: float
    strict_scope: bool = False
    state: tuple = field(init=False)
    deadline: float = field(init=False)
    sent: list[dict] = field(default_factory=list, init=False)
    cancelled: threading.Event = field(default_factory=threading.Event, init=False)
    lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()), init=False)

    def __post_init__(self):
        if type(self.maximum) is not int or not 1 <= self.maximum <= 100:
            raise ValueError("Request cap must be 1..100")
        if type(self.seconds) not in (int, float) or not 0 < self.seconds <= 300:
            raise ValueError("Duration must be finite and at most 300 seconds")
        if not isinstance(self.targets, frozenset) or not 1 <= len(self.targets) <= 100:
            raise ValueError("Name exact method/URL targets")
        if type(self.strict_scope) is not bool:
            raise ValueError("Invalid strict workspace scope mode")
        for method, url in self.targets:
            exchange.text(method, maximum=16)
            if not method.isupper():
                raise ValueError("Uppercase methods required")
            exchange.text(url, maximum=8192)
            exchange.target_parts(url)
        self.state = self.snapshot()
        self.deadline = time.monotonic() + self.seconds
        governor = pipeline_context.current()
        if governor is not None:
            governor.check()
            self.deadline = min(
                self.deadline,
                time.monotonic() + max(0, governor.deadline - time.time()),
            )

    def snapshot(self) -> tuple:
        return identity.selection_signature(), exchange.digest(
            (workspace_dir() / "policy.json").read_bytes()
        )

    def check(self, request: httpx.Request) -> None:
        governor = pipeline_context.current()
        if governor is not None:
            governor.check()
        ledger.redact_text("")
        if (
            self.cancelled.is_set()
            or self.stop_path().exists()
            or time.monotonic() >= self.deadline
        ):
            raise egress.PolicyBlocked("job-cancelled-or-expired")
        if self.snapshot() != self.state:
            raise egress.PolicyBlocked("job-policy-or-actor-changed")
        if egress.current_profile().freshness() != "verified":
            raise egress.PolicyBlocked("job-policy-expired")
        target = request.method, str(request.url)
        if target not in self.targets or not allowed(target[1]):
            raise egress.PolicyBlocked("job-target-not-approved")
        if self.strict_scope and not matches(hostname_of(target[1]), read_entries()):
            raise egress.PolicyBlocked("job-explicit-workspace-scope-required")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise egress.PolicyBlocked("job-cancelled-or-expired")
        request.extensions["timeout"] = {
            name: min(remaining, 10) for name in ("connect", "read", "write", "pool")
        }

    def admit(self, request: httpx.Request) -> None:
        with self.lock:
            self.check(request)
            if len(self.sent) >= self.maximum:
                raise egress.PolicyBlocked("job-request-cap")
            self.sent.append(
                {
                    "index": len(self.sent) + 1,
                    "run_id": request.extensions["bughunt_run_id"],
                    "method": request.method,
                    "url": str(request.url),
                    "admitted_monotonic": time.monotonic(),
                }
            )

    def stop_path(self):
        return Path(self.state[0][0]) / "jobs" / self.job_id / "STOP"

    def activate(self):
        value = {
            "job_id": self.job_id,
            "request_cap": self.maximum,
            "duration_cap": self.seconds,
            "targets": sorted(self.targets),
            "claim": "Stop prevents new attempts; not in-flight revocation",
        }
        exchange._write(self.stop_path().parent / "job.json", value)


def cancel(job_id: str) -> None:
    root = _root(job_id)
    value = _load(root / "job.json")
    if value["job_id"] != job_id:
        raise ValueError("Job ID mismatch")
    if value.get("run_id") and status(job_id)["state"] in {
        "success",
        "partial",
        "failed",
        "cancelled",
    }:
        return
    if (root / "STOP").is_symlink():
        raise ValueError("Job stop file must not be a symlink")
    ledger._write_private(root / "STOP", b"stop\n")


def _root(job_id: str) -> Path:
    if str(uuid.UUID(job_id)) != job_id:
        raise ValueError("Expected canonical job ID")
    root = workspace_dir() / "jobs" / job_id
    if root.is_symlink() or root.parent.is_symlink():
        raise ValueError("Job directory must not be a symlink")
    return root


def _load(path: Path) -> dict:
    if path.is_symlink() or path.stat().st_size > ledger.CAPTURE_LIMIT:
        raise ValueError("Job metadata path or size")
    with path.open("rb") as handle:
        raw = handle.read(ledger.CAPTURE_LIMIT + 1)
    value = exchange.load_json(raw)
    if len(raw) > ledger.CAPTURE_LIMIT or not isinstance(value, dict):
        raise ValueError("Job metadata schema or size")
    return value


def _capture(job_id: str) -> tuple[Path, dict, ledger.Capture]:
    root = _root(job_id)
    metadata = _load(root / "job.json")
    run_id = metadata["run_id"]
    if metadata["job_id"] != job_id or str(uuid.UUID(run_id)) != run_id:
        raise ValueError("Job/run identity mismatch")
    run_root = ledger.runs_dir() / run_id
    manifest = _load(run_root / "manifest.json")
    if (
        run_root.is_symlink()
        or manifest.get("job_id") != job_id
        or manifest.get("run_id") != run_id
        or manifest.get("representation") != "managed-engine-job; linked request runs"
    ):
        raise ValueError("Engine receipt mismatch")
    return root, metadata, ledger.Capture(run_root, manifest)


def start_engine(budget: Budget, profile: Profile, descriptor: dict) -> str:
    root = _root(budget.job_id)
    metadata = _load(root / "job.json")
    if metadata["job_id"] != budget.job_id or metadata.get("run_id"):
        raise ValueError("Engine job already bound or identity changed")
    for method, url in budget.targets:
        budget.check(httpx.Request(method, url))
    capture = ledger.begin(
        profile,
        tool=descriptor["engine"],
        operation=descriptor["operation"],
        target=descriptor["target"],
        request=exchange.canonical(descriptor),
        actor=budget.state[0][1],
    )
    run_id = capture.manifest["run_id"]
    capture.manifest.update(
        representation="managed-engine-job; linked request runs",
        job_id=budget.job_id,
        job_state="starting",
        analysis=descriptor,
    )
    exchange._write(capture.root / "manifest.json", capture.manifest)
    metadata.update(run_id=run_id, engine_profile=descriptor["profile_id"])
    exchange._write(root / "job.json", metadata)
    return run_id


def mark_running(job_id: str) -> None:
    _root_path, _metadata, capture = _capture(job_id)
    if capture.manifest["job_state"] != "starting":
        raise ValueError("Invalid engine lifecycle transition")
    capture.manifest["job_state"] = "running"
    exchange._write(capture.root / "manifest.json", capture.manifest)


def _artifact(root: Path, relative: str) -> dict:
    if (
        not isinstance(relative, str)
        or len(relative) > 200
        or "\\" in relative
        or ":" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise ValueError("Invalid job artifact path")
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Job artifact escapes its directory")
    current = path
    while current != root:
        if current.is_symlink():
            raise ValueError("Job artifact symlink")
        current = current.parent
    if path.stat().st_size > exchange.INPUT_LIMIT:
        raise ValueError("Job artifact size cap")
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            size += len(chunk)
            if size > exchange.INPUT_LIMIT:
                raise ValueError("Job artifact grew beyond cap")
            digest.update(chunk)
    return {"path": relative, "size": size, "sha256": digest.hexdigest()}


def finish_engine(
    job_id: str, analysis: dict, result: dict, *, state: str, artifacts: list[str]
) -> dict:
    root, metadata, capture = _capture(job_id)
    if (
        state not in {"success", "partial", "failed", "cancelled"}
        or capture.manifest["job_state"] not in {"starting", "running"}
        or result.get("job_id") != job_id
        or len(artifacts) > 20
        or result.get("classification")
        not in {"observation", "inconclusive", "invalid"}
    ):
        raise ValueError("Invalid engine completion")
    if state == "success" and (
        result.get("classification") != "observation"
        or result.get("cleanup_confirmed") is not True
    ):
        raise ValueError("Incomplete engine job cannot succeed")
    evidence = [_artifact(root, relative) for relative in artifacts]
    report_id = result.get("report_run_id")
    linked = (
        {
            "run_id": report_id,
            "sha256": _linked_import_digest(
                report_id, job_id, capture.manifest["tool"]
            ),
        }
        if report_id
        else None
    )
    run_id = capture.manifest["run_id"]
    result = dict(
        result,
        run_id=run_id,
        analysis_run_id=run_id,
        state=state,
        engine_profile=metadata["engine_profile"],
        artifacts=evidence,
    )
    capture.manifest.update(
        analysis=dict(analysis, engine_plan=capture.manifest["analysis"]),
        job_result=result,
        job_state=state,
        job_artifacts=evidence,
        job_linked_import=linked,
        cleanup="confirmed" if result.get("cleanup_confirmed") else "unconfirmed",
    )
    capture.finish(
        classification=result["classification"],
        error=result.get("reason", "") if state != "success" else "",
    )
    exchange._write(root / "result.json", result)
    return result


def _linked_import_digest(run_id: str, job_id: str, engine: str) -> str:
    """Seal current ZAP import meaning without freezing its mutable cleanup marker."""
    if not isinstance(run_id, str) or str(uuid.UUID(run_id)) != run_id:
        raise ValueError("Invalid linked report identity")
    root = ledger.runs_dir() / run_id
    if root.is_symlink() or root.parent.is_symlink():
        raise ValueError("Linked import directory redirected")
    manifest = _load(root / "manifest.json")
    if (
        manifest.get("run_id") != run_id
        or manifest.get("tool") != "zap"
        or manifest.get("decision") != "inert-import"
        or manifest.get("representation")
        != "external-json-observations; not HTTP capture"
        or manifest.get("classification")
        not in {"hypothesis", "observation", "invalid"}
        or manifest.get("import_metadata", {}).get("source", {}).get("source_id")
        != engine + "-" + job_id
    ):
        raise ValueError("Linked report source or classification differs from job")
    ledger.export_run(run_id)
    receipt = {key: value for key, value in manifest.items() if key != "cleanup"}
    return exchange.digest(exchange.canonical(receipt))


def verify_engine_evidence(manifest: dict) -> None:
    """Apply the same managed receipt integrity checks at every export boundary."""
    root, _metadata, capture = _capture(manifest["job_id"])
    if capture.manifest != manifest:
        raise ValueError("Engine receipt changed during verification")
    if "job_result" not in manifest:
        return
    result = manifest["job_result"]
    evidence = manifest["job_artifacts"]
    if (
        not isinstance(evidence, list)
        or len(evidence) > 20
        or result.get("artifacts") != evidence
    ):
        raise ValueError("Invalid engine artifact receipt")
    if (root / "result.json").exists() and _load(root / "result.json") != result:
        raise ValueError("Job result differs from ledger")
    if any(
        not isinstance(item, dict) or _artifact(root, item["path"]) != item
        for item in evidence
    ):
        raise ValueError("Job evidence changed; export blocked")
    report_id, linked = result.get("report_run_id"), manifest.get("job_linked_import")
    if report_id:
        digest = _linked_import_digest(report_id, manifest["job_id"], manifest["tool"])
        if linked is not None and linked != {"run_id": report_id, "sha256": digest}:
            raise ValueError("Linked import receipt changed; export blocked")
    elif linked is not None:
        raise ValueError("Unexpected linked import receipt")


def status(job_id: str) -> dict:
    root = _root(job_id)
    metadata = _load(root / "job.json")
    if metadata["job_id"] != job_id:
        raise ValueError("Job identity mismatch")
    if metadata.get("run_id"):
        _root_path, _metadata, capture = _capture(job_id)
        if "job_result" in capture.manifest:
            result = capture.manifest["job_result"]
            ledger.export_run(capture.manifest["run_id"])
            return ledger.redact(result)
        state = capture.manifest["job_state"]
    else:
        if (root / "result.json").exists():
            result = _load(root / "result.json")
            if result.get("job_id") != job_id:
                raise ValueError("Legacy job result identity mismatch")
            return ledger.redact(result)
        state = "running-or-starting"
    return ledger.redact(
        {
            "job_id": job_id,
            "run_id": metadata.get("run_id"),
            "state": state,
            "engine_profile": metadata.get("engine_profile"),
            "targets": [
                [method, url.split("?", 1)[0]] for method, url in metadata["targets"]
            ],
            "request_cap": metadata["request_cap"],
            "duration_cap": metadata["duration_cap"],
            "cancel_requested": (root / "STOP").exists(),
        }
    )


class Transport(egress.PreparedTransport):
    """Wrap the physical transport INSIDE egress.client's policy wrapper."""

    def __init__(self, budget: Budget, inner: httpx.BaseTransport | None = None):
        self.budget = budget
        self.inner = (
            inner
            if inner is not None
            else httpx.HTTPTransport(retries=0, trust_env=False)
        )

    def prepare_request(self, request):
        egress.prepare_dispatch(
            request, check=self.budget.check, commit=self.budget.admit
        )
