"""Start, mediate, cancel and retain one pinned, network-disabled ZAP lab job."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Callable
from urllib.parse import urlsplit

import httpx

from bughunt.core import egress, engine, exchange, job, ledger
from bughunt.integrations import zap, zap_active, zap_import


def _write(path: Path, value: object) -> None:
    exchange._write(path, value)


def command(plan: zap_active.Plan, root: Path, name: str) -> list[str]:
    helper = Path(__file__).with_name("zap_consumer.py").resolve()
    return [
        "docker",
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        name,
        "--label",
        f"bughunt.job={plan.budget.job_id}",
        "--network",
        "none",
        "--memory",
        "2g",
        "--cpus",
        "1",
        "--pids-limit",
        "256",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--hostname",
        "whk012-zap",
        "--add-host",
        "whk012-zap:127.0.0.1",
        "--mount",
        f"type=bind,source={helper},target=/bughunt/consumer.py,readonly",
        "--mount",
        f"type=bind,source={root / 'input'},target=/bughunt/input,readonly",
        "--mount",
        f"type=bind,source={root / 'engine'},target=/proof",
        zap.SUPPORTED_IMAGE,
        "python",
        "/bughunt/consumer.py",
        "/bughunt/input/plan.json",
        "/bughunt/input/bounds.json",
    ]


def _decode(path: Path, plan: zap_active.Plan) -> tuple[dict, bytes]:
    if path.is_symlink() or path.stat().st_size > 200000:
        raise ValueError("RPC input size or path")
    raw = path.read_bytes()
    if len(raw) > 200000:
        raise ValueError("RPC input grew")
    parts = raw.splitlines()
    if len(parts) != 2:
        raise ValueError("RPC input schema")
    url = exchange.decode(parts[0].decode(), 8192).decode("utf-8")
    request = exchange.decode(parts[1].decode(), 65536)
    message = exchange.message(request, request=True, url=url)
    if exchange.header_values(message, "host") != [urlsplit(plan.url).netloc]:
        raise ValueError("RPC Host differs from approved target")
    return message, raw


class _CappedStream(httpx.SyncByteStream):
    def __init__(self, stream: httpx.SyncByteStream, maximum: int):
        self.stream, self.remaining = stream, maximum + 1

    def __iter__(self):
        for chunk in self.stream:
            if not chunk:
                continue
            part = chunk[: self.remaining]
            self.remaining -= len(part)
            yield part
            if self.remaining == 0:
                return

    def close(self):
        self.stream.close()


class _CappedTransport(egress.PreparedTransport):
    def __init__(self, inner: httpx.BaseTransport, maximum: int):
        self.inner, self.maximum = inner, maximum

    def prepare_request(self, request):
        guard = request.extensions.get("bughunt_job_guard")
        if guard is not None:
            guard(request)

    def finish_response(self, response):
        if response.is_closed:
            if len(response.content) > self.maximum:
                raise ValueError("Active response cap")
        else:
            response.stream = _CappedStream(response.stream, self.maximum)
        return response


def mediate(path: Path, client: httpx.Client, plan: zap_active.Plan) -> dict:
    result = {
        "sequence": path.stem,
        "sent": False,
        "run_id": None,
        "input_representation": "container-proxy parsed HTTP; not wire bytes",
    }
    request = None
    try:
        message, raw = _decode(path, plan)
        result.update(
            rpc_sha256=exchange.digest(raw),
            method=message["method"],
            url=message["url"],
        )
        if message["body_size"] or message["method"] != "GET":
            raise ValueError("Unsupported active profile request")
        client.cookies.clear()
        request = client.build_request("GET", message["url"])

        def checked(candidate: httpx.Request) -> None:
            if (path.parent / "STOP").exists():
                raise egress.PolicyBlocked("Consumer stopped; no further host sends")
            plan.budget.check(candidate)

        request.extensions["bughunt_job_guard"] = checked
        checked(request)
        response = client.send(request, stream=True, follow_redirects=False)
        result.update(sent=True, run_id=request.extensions.get("bughunt_run_id"))
        try:
            body = bytearray()
            for chunk in response.iter_raw(chunk_size=plan.max_bytes + 1):
                plan.budget.check(request)
                body.extend(chunk)
                if len(body) > plan.max_bytes:
                    raise ValueError("Active response cap")
        finally:
            response.close()
        result.update(status=response.status_code, body_sha256=exchange.digest(body))
        reply = (
            base64.b64encode(ledger.response_head(response))
            + b"\n"
            + base64.b64encode(body)
            + b"\n"
        )
    except (OSError, ValueError, httpx.HTTPError) as error:
        result.update(
            error=type(error).__name__,
            run_id=request.extensions.get("bughunt_run_id")
            if request is not None
            else None,
        )
        reply = b"ERROR\n\n"
    temporary = path.with_suffix(".reply-tmp")
    ledger._write_private(temporary, reply)
    temporary.replace(path.with_suffix(".resp"))
    return result


def _preflight(plan: zap_active.Plan) -> None:
    plan.budget.check(httpx.Request("GET", plan.url))
    egress.authorize(plan.url, "process", "GET")
    _preflight_docker(
        lambda: plan.budget.check(httpx.Request("GET", plan.url)), plan.budget.deadline
    )


def _preflight_docker(check: Callable[[], None], deadline: float) -> None:
    check()
    if os.environ.get("DOCKER_HOST") or os.environ.get("DOCKER_CONTEXT"):
        raise ValueError(
            "Docker environment overrides are unsupported; use a local current context"
        )
    context = subprocess.run(
        ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
        capture_output=True,
        text=True,
        timeout=max(0.001, min(10, deadline - time.monotonic())),
    )
    if context.returncode or not context.stdout.strip().startswith(("npipe:", "unix:")):
        raise ValueError(
            "A local Docker daemon is required; remote contexts are unsupported"
        )
    check()
    inspected = subprocess.run(
        ["docker", "image", "inspect", zap.SUPPORTED_IMAGE, "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
        timeout=max(0.001, min(10, deadline - time.monotonic())),
    )
    if (
        inspected.returncode
        or inspected.stdout.strip() != zap.SUPPORTED_IMAGE.split("@", 1)[1]
    ):
        raise ValueError("Pinned ZAP image missing or changed; no automatic pull")


def _timeout_diagnostic(error: subprocess.TimeoutExpired) -> str:
    command = (
        error.cmd if isinstance(error.cmd, (list, tuple)) else str(error.cmd).split()
    )
    operation = " ".join(str(part) for part in command[:3]) or "docker preflight"
    return f"preflight timed out: {operation} exceeded {error.timeout:g}s (retryable)"


def _files(plan: zap_active.Plan) -> Path:
    descriptor = engine.descriptor(plan)
    root = plan.budget.stop_path().parent
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    (root / "input").mkdir()
    (root / "engine" / "rpc").mkdir(parents=True)
    (root / "engine" / "reports").mkdir()
    _write(root / "input" / "plan.json", zap_active.automation_plan(plan))
    _write(root / "input" / "bounds.json", {"seconds": plan.budget.seconds})
    helper = Path(__file__).with_name("zap_consumer.py").resolve()
    plan.budget.bind_artifacts(
        [helper, root / "input" / "plan.json", root / "input" / "bounds.json"]
    )
    if (
        plan.budget.artifacts[helper] != descriptor["consumer_sha256"]
        or exchange.digest(
            exchange.canonical(
                exchange.load_json((root / "input" / "plan.json").read_bytes())
            )
        )
        != descriptor["plan_sha256"]
    ):
        raise ValueError(
            "Declared engine plan/helper fingerprints differ from bound artifacts"
        )
    plan.budget.activate()
    _write(
        root / "provenance.json",
        {
            "image": zap.SUPPORTED_IMAGE,
            "source_exchange_id": plan.source_id,
            "source_sha256": plan.budget.source_hash,
            "artifacts": {
                str(path): digest for path, digest in plan.budget.artifacts.items()
            },
        },
    )
    job.start_engine(plan.budget, plan.profile, descriptor)
    return root


def _ready(root: Path, plan: zap_active.Plan) -> bool:
    path = root / "engine" / "rpc" / "READY"
    if not path.exists():
        return False
    if path.is_symlink() or path.stat().st_size > 65536:
        raise ValueError("Consumer readiness size/path")
    metadata = exchange.load_json(path.read_bytes())
    inventory, proxy = metadata["inventory"], metadata["proxy"]
    if (
        inventory != engine.inventory()
        or proxy["enabled"] is not True
        or proxy["excluded"] != []
        or proxy["proxy"]["host"] != "127.0.0.1"
        or not 1 <= int(proxy["proxy"]["port"]) <= 65535
        or any(
            proxy["proxy"].get(name) not in (None, "")
            for name in ("username", "password", "realm")
        )
        or proxy.get("disabled")
        != {
            name: True
            for name in (
                "isSocksProxyEnabled",
                "isHttpProxyAuthEnabled",
                "isUseGlobalHttpState",
            )
        }
    ):
        raise ValueError("Pinned consumer readiness drift")
    if path not in plan.budget.artifacts:
        plan.budget.bind_artifacts([path])
    return True


def _loop(process, root: Path, plan: zap_active.Plan, attempts: list) -> str:
    processed = set()
    rpc = root / "engine" / "rpc"
    ready = False
    bounded = _CappedTransport(job.Transport(plan.budget), plan.max_bytes)
    with egress.client(
        operation="active_scan", transport=bounded, follow_redirects=False
    ) as client:
        while True:
            try:
                plan.budget.check(httpx.Request("GET", plan.url))
            except (OSError, ValueError):
                return _stop_reason(plan)
            if (rpc / "STOP").exists():
                return "consumer-stopped"
            if (root / "consumer.log").exists() and (
                root / "consumer.log"
            ).stat().st_size > 1000000:
                return "consumer-log-cap"
            if not ready:
                ready = _ready(root, plan)
                if ready:
                    job.mark_running(plan.budget.job_id)
            if process.poll() is not None:
                return "consumer-completed" if ready else "consumer-not-ready"
            if not ready:
                time.sleep(0.02)
                continue
            for path in sorted(rpc.glob("*.req")):
                if (rpc / "STOP").exists():
                    return "consumer-stopped"
                if path.name not in processed:
                    if (
                        not re.fullmatch(r"[0-9]{6}\.req", path.name)
                        or len(processed) >= 500
                    ):
                        return "consumer-rpc-cap-or-schema"
                    result = mediate(path, client, plan)
                    attempts.append(result)
                    processed.add(path.name)
                    if result.get("error"):
                        return "generated-request-denied"
            time.sleep(0.02)


def _stop_reason(plan: zap_active.Plan) -> str:
    if plan.budget.cancelled.is_set() or plan.budget.stop_path().exists():
        return "job-cancelled"
    if time.monotonic() >= plan.budget.deadline:
        return "job-deadline"
    return "job-authority-or-input-revoked"


def _wait_for_removal(name: str) -> bool:
    deadline = time.monotonic() + 3
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            inspected = subprocess.run(
                [
                    "docker",
                    "ps",
                    "-a",
                    "--filter",
                    f"name=^{name}$",
                    "--format",
                    "{{.Names}}",
                ],
                capture_output=True,
                text=True,
                timeout=min(1, remaining),
            )
            if inspected.returncode == 0 and not inspected.stdout.strip():
                return True
        except (OSError, subprocess.SubprocessError):
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def _cleanup(process, name: str, root: Path) -> bool:
    try:
        ledger._write_private(root / "engine" / "rpc" / "STOP", b"stop\n")
    except OSError:
        pass
    if process.poll() is None:
        try:
            subprocess.run(
                ["docker", "stop", "--time", "2", name], capture_output=True, timeout=10
            )
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        subprocess.run(
            ["docker", "rm", "--force", name], capture_output=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        pass
    absent = _wait_for_removal(name)
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
    return absent and process.poll() is not None


def _report(plan: zap_active.Plan, root: Path, captures: list) -> str | None:
    report = root / "engine" / "reports" / "active.json"
    if not report.exists():
        return None
    if report.is_symlink():
        raise ValueError("Consumer report path")
    with report.open("rb") as handle:
        raw = handle.read(exchange.INPUT_LIMIT + 1)
    records = {value["exchange_id"]: value for value in captures}
    return zap_import.import_report(
        raw,
        source_id=f"zap-active-{plan.budget.job_id}",
        records=list(records.values()),
    )


def _denied(root: Path) -> list[dict]:
    records = []
    for path in sorted((root / "engine" / "rpc").glob("*.denied")):
        if len(records) >= 500 or path.is_symlink() or path.stat().st_size > 4096:
            raise ValueError("Consumer denial cap/path")
        records.append(exchange.load_json(path.read_bytes()))
    return records


def _finish(
    plan: zap_active.Plan,
    root: Path,
    attempts: list,
    reason: str,
    status,
    cleaned: bool,
    diagnostic: str | None = None,
) -> dict:
    processed = {item["sequence"] for item in attempts}
    for path in sorted((root / "engine" / "rpc").glob("*.req")):
        if path.stem in processed:
            continue
        if len(attempts) >= 500:
            reason = "consumer-rpc-evidence-invalid"
            break
        pending = {
            "sequence": path.stem,
            "sent": False,
            "run_id": None,
            "error": "consumer-stopped-before-response",
        }
        try:
            pending["rpc_sha256"] = zap_active.ActiveBudget._hash(path, 200000)
        except (OSError, ValueError):
            pending["error"] = "invalid-rpc-evidence"
            reason = "consumer-rpc-evidence-invalid"
        attempts.append(pending)
    captures = []
    for attempt in plan.budget.sent:
        try:
            captures.append(exchange.from_run(attempt["run_id"]))
        except (OSError, ValueError):
            reason = "incomplete-request-capture"
    report_id = None
    try:
        report_id = _report(plan, root, captures)
    except (OSError, ValueError, TypeError, KeyError):
        reason = "report-import-failed"
    try:
        denied = _denied(root)
    except (OSError, ValueError, TypeError):
        denied, reason = [], "consumer-denial-evidence-invalid"
    private = {
        "attempts": attempts,
        "admitted": plan.budget.sent,
        "consumer_denied": denied,
    }
    _write(root / "attempts.json", private)
    raw = (root / "attempts.json").read_bytes()
    if reason == "consumer-completed" and (
        not attempts or not captures or not report_id or denied
    ):
        reason = "incomplete-consumer-evidence"
    admitted_ids = [item["run_id"] for item in plan.budget.sent]
    attempted_ids = [item["run_id"] for item in attempts if item.get("sent")]
    if reason == "consumer-completed" and (
        attempted_ids != admitted_ids
        or len(captures) != len(admitted_ids)
        or len(set(admitted_ids)) != len(admitted_ids)
        or len({item["sequence"] for item in attempts}) != len(attempts)
    ):
        reason = "request-accounting-mismatch"
    value = {
        "job_id": plan.budget.job_id,
        "source_exchange_id": plan.source_id,
        "target": plan.url.split("?", 1)[0],
        "technology": plan.technology,
        "rule_ids": list(zap_active.RULE_IDS),
        "request_cap": plan.budget.maximum,
        "duration_cap": plan.budget.seconds,
        "attempt_artifact": {
            "path": "attempts.json",
            "sha256": exchange.digest(raw),
            "size": len(raw),
        },
        "attempts": [
            {
                key: item[key]
                for key in ("sequence", "sent", "run_id", "error")
                if key in item
            }
            for item in attempts
        ],
        "admitted_run_ids": [item["run_id"] for item in plan.budget.sent],
        "consumer_denied_count": len(denied),
        "reason": reason,
        "consumer_status": status,
        "cleanup_confirmed": cleaned,
        "report_run_id": report_id,
        "manual_controls_required": True,
    }
    classification = (
        "observation"
        if reason == "consumer-completed"
        and status == 0
        and cleaned
        and all(item.get("sent") and not item.get("error") for item in attempts)
        else "inconclusive"
    )
    result = {
        "job_id": plan.budget.job_id,
        "report_run_id": report_id,
        "classification": classification,
        "admitted_count": len(plan.budget.sent),
        "attempt_count": len(attempts),
        "cleanup_confirmed": cleaned,
        "reason": reason,
        "consumer_status": status,
        "exit_diagnostic": diagnostic or reason,
    }
    return _receipt(plan, root, value, result)


def _receipt(plan: zap_active.Plan, root: Path, analysis: dict, result: dict) -> dict:
    artifacts, invalid = [], []
    for relative in (
        "attempts.json",
        "provenance.json",
        "consumer.log",
        "input/plan.json",
        "input/bounds.json",
        "engine/rpc/READY",
        "engine/plan-progress.json",
        "engine/reports/active.json",
    ):
        if (root / relative).exists():
            try:
                job._artifact(root, relative)
                artifacts.append(relative)
            except (OSError, ValueError):
                invalid.append(relative)
    if invalid:
        analysis["invalid_artifacts"] = invalid
        result.update(
            classification="inconclusive", reason="job-artifact-integrity-failed"
        )
    cancelled = plan.budget.cancelled.is_set() or plan.budget.stop_path().exists()
    if cancelled:
        result.update(classification="inconclusive", reason="job-cancelled")
    if analysis["reason"] != result["reason"]:
        analysis["consumer_reason"] = analysis["reason"]
        analysis["reason"] = result["reason"]
    state = (
        "cancelled"
        if cancelled
        else "success"
        if result["classification"] == "observation"
        else ("partial" if plan.budget.sent else "failed")
    )
    return job.finish_engine(
        plan.budget.job_id, analysis, result, state=state, artifacts=artifacts
    )


def run(plan: zap_active.Plan, on_start: Callable[[str], None] | None = None) -> dict:
    root = _files(plan)
    name = "whk012-" + plan.budget.job_id
    process, log, attempts = None, None, []
    reason, cleaned, status, diagnostic = "consumer-preflight-failed", False, None, None
    token = ledger.CURRENT_TOOL.set("zap-active")
    try:
        if on_start is not None:
            on_start(plan.budget.job_id)
        log = (root / "consumer.log").open("xb")
        (root / "consumer.log").chmod(0o600)
        _preflight(plan)
        reason = "consumer-launch-failed"
        plan.budget.check(httpx.Request("GET", plan.url))
        process = subprocess.Popen(
            command(plan, root, name), stdout=log, stderr=subprocess.STDOUT
        )
        reason = _loop(process, root, plan, attempts)
        status = process.poll()
    except KeyboardInterrupt:
        plan.budget.cancelled.set()
        reason, diagnostic = "job-cancelled", "KeyboardInterrupt"
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        if reason == "consumer-preflight-failed" and type(error) is ValueError:
            diagnostic = str(error)
        elif isinstance(error, subprocess.TimeoutExpired):
            diagnostic = _timeout_diagnostic(error)
        else:
            diagnostic = type(error).__name__
        if process is not None:
            reason = "consumer-runtime-failed"
        if (
            plan.budget.cancelled.is_set()
            or plan.budget.stop_path().exists()
            or time.monotonic() >= plan.budget.deadline
        ):
            reason = _stop_reason(plan)
    finally:
        try:
            if process is not None:
                cleaned = _cleanup(process, name, root)
                status = process.poll()
            else:
                cleaned = True
        finally:
            if log is not None:
                log.close()
            ledger.CURRENT_TOOL.reset(token)
    return _finish(plan, root, attempts, reason, status, cleaned, diagnostic)


def status(job_id: str) -> dict:
    return job.status(job_id)
