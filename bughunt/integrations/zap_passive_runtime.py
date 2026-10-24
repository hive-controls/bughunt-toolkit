"""Launch and reap the pinned passive consumer through existing job/ledger contracts."""

from __future__ import annotations

from pathlib import Path
import subprocess
import threading
import time

from bughunt.core import engine, exchange, job, ledger
from bughunt.integrations import zap, zap_import, zap_passive, zap_runtime


def command(plan: zap_passive.Plan, root: Path, name: str) -> list[str]:
    arguments = ["docker", "run", "--rm", "--pull", "never", "--name", name,
        "--label", f"bughunt.job={plan.budget.job_id}", "--network", "none", "--memory", "2g",
        "--cpus", "1", "--pids-limit", "256", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m",
        "--tmpfs", "/reports:rw,nosuid,nodev,size=16m",
        "--hostname", "whk018-zap", "--add-host", "whk018-zap:127.0.0.1"]
    for filename in ("zap_passive_consumer.py", "zap_consumer.py"):
        helper = Path(__file__).with_name(filename).resolve()
        arguments.extend(["--mount", f"type=bind,source={helper},target=/bughunt/{filename},readonly"])
    return arguments + ["--mount", f"type=bind,source={root / 'input'},target=/bughunt/input,readonly",
        "--mount", f"type=bind,source={root / 'engine'},target=/proof", zap.SUPPORTED_IMAGE,
        "python", "/bughunt/zap_passive_consumer.py", "/bughunt/input/plan.yaml", "/bughunt/input/bounds.json"]


def _files(plan: zap_passive.Plan) -> Path:
    descriptor = zap_passive.descriptor(plan)
    root = job._root(plan.budget.job_id)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    (root / "input").mkdir(mode=0o700)
    (root / "engine" / "rpc").mkdir(parents=True, mode=0o700)
    (root / "engine" / "reports").mkdir(mode=0o700)
    for name, raw in plan.files.items():
        ledger._write_private(root / "input" / name, raw)
    exchange._write(root / "input" / "bounds.json", {"seconds": plan.budget.seconds})
    helpers = [Path(__file__).with_name(name).resolve() for name in descriptor["consumer_helpers"]]
    plan.budget.bind_artifacts(helpers + list((root / "input").iterdir()))
    if any(plan.budget.artifacts[path] != descriptor["consumer_helpers"][path.name] for path in helpers):
        raise ValueError("Passive helper changed before binding")
    if any(plan.budget.artifacts[root / "input" / name] != digest for name, digest in descriptor["files"].items()):
        raise ValueError("Passive inputs changed before binding")
    plan.budget.activate()
    exchange._write(root / "provenance.json", descriptor)
    job.start_engine(plan.budget, plan.profile, descriptor)
    return root


def _containment(plan: zap_passive.Plan, name: str) -> dict:
    plan.budget.check_all()
    result = subprocess.run(["docker", "inspect", name], capture_output=True, text=True,
                            timeout=max(0.001, min(10, plan.budget.deadline - time.monotonic())))
    if result.returncode or len(result.stdout) > ledger.CAPTURE_LIMIT:
        raise ValueError("Passive container inspection failed")
    inspected = exchange.load_json(result.stdout.encode())
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise ValueError("Passive container inspection schema")
    container = inspected[0]
    host = container["HostConfig"]
    if (container["Name"] != "/" + name or container["Image"] != zap.SUPPORTED_IMAGE.split("@", 1)[1]
            or container["Config"]["Labels"].get("bughunt.job") != plan.budget.job_id
            or host["NetworkMode"] != "none" or host.get("PortBindings")
            or host["ReadonlyRootfs"] is not True or host["Memory"] != 2 * 1024 ** 3
            or host["NanoCpus"] != 1000000000 or host["PidsLimit"] != 256
            or host.get("Privileged") or host.get("CapAdd") or host.get("CapDrop") != ["ALL"]
            or host.get("Tmpfs") != {"/tmp": "rw,nosuid,nodev,size=512m", "/reports": "rw,nosuid,nodev,size=16m"}
            or not any("no-new-privileges" in value for value in host["SecurityOpt"])):
        raise ValueError("Passive process containment differs from authorized command")
    return {"name": name, "image": container["Image"], "network": "none", "ports": [],
            "read_only_root": True, "memory_bytes": host["Memory"], "cpus": 1, "pids": 256,
            "temporary_filesystems": host["Tmpfs"]}


def _ready(root: Path, plan: zap_passive.Plan, name: str) -> bool:
    path = root / "engine" / "rpc" / "READY"
    if not path.exists():
        return False
    metadata = job._load(path)
    proxy = metadata["proxy"]
    if (metadata["inventory"] != engine.inventory() or metadata["mode"] != "protect"
            or metadata["profile_id"] != "zap-passive" or proxy["enabled"] is not True
            or proxy["excluded"] != [] or proxy["proxy"]["host"] != "127.0.0.1"
            or int(proxy["proxy"]["port"]) != 65535
            or any(proxy["proxy"].get(key) not in (None, "") for key in ("username", "password", "realm"))
            or proxy["disabled"] != {key: True for key in (
                "isSocksProxyEnabled", "isHttpProxyAuthEnabled", "isUseGlobalHttpState")}):
        raise ValueError("Passive readiness version, hook or network-control drift")
    containment = _containment(plan, name)
    exchange._write(root / "engine" / "containment.json", containment)
    plan.budget.bind_artifacts([path, root / "engine" / "containment.json"])
    plan.budget.check_all()
    job.mark_running(plan.budget.job_id)
    ledger._write_private(root / "engine" / "rpc" / "APPROVED", b"approved\n")
    return True


def _output_bounds(root: Path) -> None:
    log = root / "consumer.log"
    if log.is_symlink() or log.stat().st_size > ledger.CAPTURE_LIMIT:
        raise ValueError("Passive consumer log cap/path")
    total, count = 0, 0
    for path in (root / "engine").rglob("*"):
        count += 1
        if count > 32 or path.is_symlink():
            raise ValueError("Passive output path/count cap")
        if path.is_file():
            total += path.stat().st_size
            if path.stat().st_size > exchange.INPUT_LIMIT or total > exchange.INPUT_LIMIT:
                raise ValueError("Passive output byte cap")


def _loop(process, root: Path, plan: zap_passive.Plan, name: str, overflow: threading.Event) -> str:
    ready = False
    while True:
        plan.budget.check_all()
        if overflow.is_set():
            raise ValueError("Passive log byte cap reached")
        _output_bounds(root)
        if not ready:
            ready = _ready(root, plan, name)
        if process.poll() is not None:
            return "consumer-completed" if ready else "consumer-not-ready"
        time.sleep(0.02)


def _report(plan: zap_passive.Plan, root: Path) -> str:
    metadata = job._load(root / "engine" / "consumer-metadata.json")
    if (metadata.get("imported_messages") != len(plan.records)
            or metadata.get("unexpected_history") != 0 or metadata.get("target_network_enabled") is not False):
        raise ValueError("Passive imported-capture accounting differs")
    progress = job._load(root / "engine" / "plan-progress.json")
    if not progress.get("finished") or any(progress.get(key) for key in ("errors", "warnings", "error", "warn")):
        raise ValueError("Passive plan incomplete or invalid")
    path = root / "engine" / "reports" / "passive-report.json"
    if path.is_symlink() or path.stat().st_size > exchange.INPUT_LIMIT:
        raise ValueError("Passive report path/size")
    with path.open("rb") as handle:
        raw = handle.read(exchange.INPUT_LIMIT + 1)
    if len(raw) > exchange.INPUT_LIMIT or exchange.load_json(raw).get("@version") != zap.SUPPORTED_VERSION:
        raise ValueError("Passive report version/size differs")
    return zap_import.import_report(raw, source_id="zap-passive-" + plan.budget.job_id, records=plan.records)


def _receipt(plan: zap_passive.Plan, root: Path, reason: str, status, cleaned: bool, diagnostic: str) -> dict:
    report_id = None
    if reason == "consumer-completed" and status == 0:
        try:
            plan.budget.check_all()
            report_id = _report(plan, root)
        except (OSError, ValueError, KeyError, TypeError):
            reason = "passive-report-or-accounting-invalid"
    elif reason == "consumer-completed":
        reason = "consumer-nonzero-exit"
    artifacts, invalid = [], []
    candidates = ["provenance.json", "consumer.log"] + ["input/" + name for name in plan.files]
    candidates += ["input/bounds.json", "engine/rpc/READY", "engine/containment.json",
                   "engine/plan-progress.json", "engine/consumer-metadata.json", "engine/reports/passive-report.json"]
    for relative in candidates:
        if (root / relative).exists():
            try:
                job._artifact(root, relative)
                artifacts.append(relative)
            except (OSError, ValueError):
                invalid.append(relative)
    cancelled = plan.budget.cancelled.is_set() or plan.budget.stop_path().exists()
    if cancelled:
        reason = "job-cancelled"
    if invalid and not cancelled:
        reason = "passive-artifact-integrity-failed"
    succeeded = reason == "consumer-completed" and status == 0 and cleaned and report_id is not None
    summary = zap_import.summary(report_id) if report_id is not None else {}
    result = {"job_id": plan.budget.job_id, "classification": "observation" if succeeded else "inconclusive",
        "report_run_id": report_id, "observation_count": summary.get("observation_count"),
        "consumer_status": status, "cleanup_confirmed": cleaned, "reason": reason,
        "exit_diagnostic": diagnostic or reason, "target_network_enabled": False, "admitted_count": 0,
        "manual_controls_required": True, "claim": "Alerts are hypotheses; empty report is not a negative finding"}
    analysis = {"source_exchange_ids": [value["exchange_id"] for value in plan.records],
        "report_run_id": report_id, "reason": reason, "invalid_artifacts": invalid,
        "consumer_image": zap.SUPPORTED_IMAGE, "target_requests": 0, "capture_association": "URL/method candidates only"}
    state = "cancelled" if cancelled else "success" if succeeded else "partial" if report_id is not None else "failed"
    return job.finish_engine(plan.budget.job_id, analysis, result, state=state, artifacts=artifacts)


def _capture_log(stream, log, overflow: threading.Event) -> None:
    remaining = ledger.CAPTURE_LIMIT
    try:
        while chunk := stream.read(65536):
            kept = chunk[:remaining]
            log.write(kept)
            remaining -= len(kept)
            log.flush()
            if len(kept) != len(chunk):
                overflow.set()
                return
    finally:
        stream.close()


def _paths(root: Path) -> None:
    for relative in ("input", "engine", "engine/rpc", "engine/reports"):
        path = root / relative
        if not path.is_dir() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("Passive job directory redirected")


def run(plan: zap_passive.Plan, on_start=None) -> dict:
    root = _files(plan)
    name = "whk018-" + plan.budget.job_id
    process, log, status, reader = None, None, None, None
    overflow = threading.Event()
    reason, cleaned, diagnostic = "consumer-preflight-failed", False, ""
    try:
        if on_start is not None:
            on_start(plan.budget.job_id)
        log = (root / "consumer.log").open("xb")
        (root / "consumer.log").chmod(0o600)
        zap_runtime._preflight_docker(plan.budget.check_all, plan.budget.deadline)
        reason = "consumer-launch-failed"
        plan.budget.check_all()
        _paths(root)
        process = subprocess.Popen(command(plan, root, name), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        reader = threading.Thread(target=_capture_log, args=(process.stdout, log, overflow), daemon=True)
        reader.start()
        reason = _loop(process, root, plan, name, overflow)
        status = process.poll()
    except KeyboardInterrupt:
        plan.budget.cancelled.set()
        reason, diagnostic = "job-cancelled", "KeyboardInterrupt"
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        diagnostic = (zap_runtime._timeout_diagnostic(error) if isinstance(error, subprocess.TimeoutExpired)
                      else type(error).__name__)
        if plan.budget.cancelled.is_set() or plan.budget.stop_path().exists():
            reason = "job-cancelled"
        elif time.monotonic() >= plan.budget.deadline:
            reason = "job-deadline"
        elif process is not None:
            reason = "consumer-runtime-failed"
    finally:
        try:
            cleaned = zap_runtime._cleanup(process, name, root) if process is not None else True
            status = process.poll() if process is not None else None
        finally:
            if reader is not None:
                reader.join(timeout=5)
                cleaned = cleaned and not reader.is_alive()
            if log is not None:
                log.close()
    if overflow.is_set():
        reason = "consumer-log-cap"
    return _receipt(plan, root, reason, status, cleaned, diagnostic)
