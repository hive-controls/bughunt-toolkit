"""Contained owned browser consumer; all permitted target sends remain on the host."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from urllib.parse import urljoin

import httpx

from bughunt.core import egress, exchange, identity, job, ledger, verification
from bughunt.integrations import browser_actor, zap_runtime


def dependencies() -> tuple[Path, Path]:
    directory = Path(os.environ.get("BUGHUNT_BROWSER_RUNTIME", str(Path(__file__).resolve().parents[2] / ".bughunt")))
    archive = directory / "playwright-core-1.62.1.tgz"
    source = directory / "playwright-seccomp-1.62.1.json"
    if browser_actor.fingerprint(archive) != browser_actor.DRIVER_SHA256:
        raise ValueError("Pinned browser driver missing or changed; no automatic install")
    browser_actor.seccomp_profile(source)
    return archive, source


def command(plan: browser_actor.Plan, root: Path, name: str, archive: Path) -> list[str]:
    helper = Path(__file__).with_name("browser_consumer.cjs").resolve()
    return ["docker", "run", "--rm", "--pull", "never", "--init", "--name", name,
        "--cidfile", str(root / "consumer.cid"),
        "--label", f"bughunt.job={plan.budget.job_id}", "--network", "none", "--read-only",
        "--user", "1000:1000", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={root / 'input' / 'seccomp.json'}", "--memory", "2g", "--cpus", "1",
        "--pids-limit", "256", "--shm-size", "128m",
        "--tmpfs", "/tmp:rw,size=128m,mode=1777", "--tmpfs", "/runtime:rw,size=64m,mode=1777",
        "--tmpfs", "/profiles:rw,size=64m,mode=0700,uid=1000,gid=1000",
        "--mount", f"type=bind,source={helper},target=/bughunt/consumer.cjs,readonly",
        "--mount", f"type=bind,source={archive.resolve()},target=/bughunt/driver.tgz,readonly",
        "--mount", f"type=bind,source={root / 'input'},target=/bughunt/input,readonly",
        "--mount", f"type=bind,source={root / 'engine'},target=/proof",
        "--entrypoint", "node", browser_actor.IMAGE, "/bughunt/consumer.cjs"]


def _files(plan: browser_actor.Plan, archive: Path, source: Path) -> Path:
    root = plan.budget.stop_path().parent
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    (root / "input").mkdir(mode=0o700)
    (root / "engine" / "rpc").mkdir(parents=True, mode=0o700)
    descriptor = browser_actor.descriptor(plan)
    value = {"job_id": plan.budget.job_id, "actor": plan.actor, "actor_revision": plan.budget.state[0][2],
             "urls": list(plan.urls), "seconds": plan.budget.seconds, "max_bytes": plan.max_bytes}
    exchange._write(root / "input" / "browser.json", value)
    exchange._write(root / "input" / "seccomp.json", browser_actor.seccomp_profile(source))
    helper = Path(__file__).with_name("browser_consumer.cjs").resolve()
    plan.budget.bind_artifacts([helper, archive, source, root / "input" / "browser.json", root / "input" / "seccomp.json"])
    plan.budget.activate()
    exchange._write(root / "provenance.json", dict(descriptor,
        consumer_sha256=browser_actor.fingerprint(helper), driver_sha256=browser_actor.DRIVER_SHA256,
        upstream_seccomp_sha256=browser_actor.UPSTREAM_SECCOMP_SHA256,
        seccomp_sha256=browser_actor.fingerprint(root / "input" / "seccomp.json")))
    job.start_engine(plan.budget, plan.profile, descriptor)
    return root


def _preflight(plan: browser_actor.Plan) -> None:
    if os.environ.get("DOCKER_HOST") or os.environ.get("DOCKER_CONTEXT"):
        raise ValueError("Browser requires a local Docker current context; overrides unavailable")
    for args in (["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                 ["image", "inspect", browser_actor.IMAGE, "--format", "{{.Id}}"]):
        plan.budget.check(httpx.Request("GET", plan.urls[0]))
        result = subprocess.run(["docker", *args], capture_output=True, text=True,
            timeout=max(0.001, min(10, plan.budget.deadline - time.monotonic())))
        value = result.stdout.strip()
        if result.returncode or (args[0] == "context" and not value.startswith(("npipe:", "unix:"))):
            raise ValueError("Browser requires a local Docker daemon and pinned installed image")
        if args[0] == "image" and value != browser_actor.IMAGE.split("@", 1)[1]:
            raise ValueError("Pinned browser image drift; no automatic pull")


def _container_id(root: Path) -> str:
    path = root / "consumer.cid"
    if path.is_symlink() or path.stat().st_size > 128:
        raise ValueError("Browser container identity path/size")
    identifier = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", identifier):
        raise ValueError("Browser container identity invalid")
    return identifier


def _container(name: str, root: Path) -> dict:
    identifier = _container_id(root)
    if name != "whk027-" + root.name:
        raise ValueError("Browser container name differs from job")
    result = subprocess.run(["docker", "inspect", "--format", "{{json .}}", identifier],
                            capture_output=True, timeout=5)
    if result.returncode or len(result.stdout) > 200000:
        raise ValueError("Browser container inspection unavailable")
    value = exchange.load_json(result.stdout)
    host, config = value["HostConfig"], value["Config"]
    security = host["SecurityOpt"]
    seccomp = [item.split("=", 1)[1] for item in security if item.startswith("seccomp=")]
    if (value["Id"] != identifier or value["Image"] != browser_actor.IMAGE.split("@", 1)[1]
            or config["Labels"].get("bughunt.job") != root.name
            or host["NetworkMode"] != "none" or not host["ReadonlyRootfs"] or host["Privileged"]
            or config["User"] != "1000:1000" or host["CapAdd"]
            or [item.upper() for item in host["CapDrop"]] != ["ALL"]
            or not any(item in {"no-new-privileges", "no-new-privileges:true"} for item in security)
            or len(seccomp) != 1 or exchange.load_json(seccomp[0].encode()) != job._load(root / "input" / "seccomp.json")
            or host["PidMode"] == "host" or host["IpcMode"] == "host" or host["PortBindings"]
            or host["Memory"] != 2147483648 or host["NanoCpus"] != 1000000000
            or host["PidsLimit"] != 256 or host["ShmSize"] != 134217728):
        raise ValueError("Browser containment differs from approved command")
    mounts = {row["Destination"]: row for row in value["Mounts"] if row["Type"] == "bind"}
    expected = {"/bughunt/consumer.cjs": False, "/bughunt/driver.tgz": False,
                "/bughunt/input": False, "/proof": True}
    if set(mounts) != set(expected) or any(mounts[key]["RW"] != writable for key, writable in expected.items()):
        raise ValueError("Unexpected browser host mounts")
    return {"container_id": identifier, "network": "none", "readonly_root": True, "user": config["User"],
            "host_capabilities": [], "no_new_privileges": True, "seccomp_default_deny": True,
            "personal_profile_access": False, "published_ports": False, "memory_bytes": host["Memory"],
            "nanocpus": host["NanoCpus"], "pids_limit": host["PidsLimit"]}


def _ready(plan: browser_actor.Plan, root: Path, name: str) -> bool:
    path = root / "engine" / "rpc" / "READY"
    if not path.exists():
        return False
    metadata = job._load(path)
    profile = f"/profiles/{plan.budget.job_id}/{plan.budget.state[0][2]}"
    if (metadata.get("job_id") != plan.budget.job_id or metadata.get("actor") != plan.actor
            or metadata.get("actor_revision") != plan.budget.state[0][2]
            or metadata.get("driver_version") != browser_actor.DRIVER_VERSION
            or metadata.get("chromium_version") != "151.0.7922.34"
            or metadata.get("network_interfaces") != ["lo"]
            or metadata.get("profile_directory") != profile or metadata.get("profile_mode") != 0o700
            or metadata.get("sandbox_enabled") is not True or metadata.get("initial_storage_empty") is not True):
        raise ValueError("Browser readiness or private profile drift")
    proof = _container(name, root)
    exchange._write(root / "containment.json", proof)
    plan.budget.container_id = proof["container_id"]
    plan.budget.bind_artifacts([path, root / "consumer.cid"])
    job.mark_running(plan.budget.job_id)
    return True


def _outputs(root: Path) -> None:
    size = 0
    for index, path in enumerate((root / "engine").rglob("*")):
        if index >= 300:
            raise ValueError("Browser output path/count cap")
        relative = path.relative_to(root / "engine").as_posix()
        request = re.fullmatch(r"rpc/([0-9]{6})\.req\.tmp", relative)
        temporary = relative in {"rpc/READY.tmp", "browser-result.json.tmp"} or (
            request is not None and 1 <= int(request[1]) <= 128)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if not temporary:
                raise
            metadata = path.with_suffix("").lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("Browser publication is not a regular file")
        if stat.S_ISLNK(metadata.st_mode) or (temporary and not stat.S_ISREG(metadata.st_mode)):
            raise ValueError("Browser output path/type cap")
        if stat.S_ISREG(metadata.st_mode):
            size += metadata.st_size
            if metadata.st_size > 200000 or size > 16000000:
                raise ValueError("Browser output byte cap")
    log = root / "consumer.log"
    if log.exists() and (log.is_symlink() or log.stat().st_size > 1000000):
        raise ValueError("Browser log cap")


def _decode(path: Path) -> dict:
    if not re.fullmatch(r"[0-9]{6}\.req", path.name) or path.stat().st_size > 32768:
        raise ValueError("Browser request size/name cap")
    value = job._load(path)
    if (set(value) != {"sequence", "method", "url", "headers"} or value["sequence"] != path.stem
            or not isinstance(value["headers"], dict)
            or set(value["headers"]) - {"accept", "accept-language", "cache-control"}):
        raise ValueError("Browser request schema")
    for header in value["headers"].values():
        exchange.text(header, maximum=4096)
    return value


def _read(response: httpx.Response, plan: browser_actor.Plan, request: httpx.Request) -> bytes:
    body = bytearray()
    try:
        if response.headers.get("content-encoding", "identity") != "identity":
            raise ValueError("Browser bridge requires identity response encoding")
        chunks = [response.content] if response.is_closed else response.iter_raw(chunk_size=plan.max_bytes + 1)
        for chunk in chunks:
            plan.budget.check(request)
            body.extend(chunk[:plan.max_bytes + 1 - len(body)])
            if len(body) > plan.max_bytes:
                raise ValueError("Browser response cap")
        return bytes(body)
    finally:
        response.close()


def _fetch(client: httpx.Client, plan: browser_actor.Plan, value: dict, attempt: dict) -> dict:
    target = value["url"]
    for _hop in range(6):
        if target not in plan.urls:
            return {"denied": True}
        client.cookies.clear()
        request = client.build_request("GET", target, headers=dict(value["headers"], **{"Accept-Encoding": "identity"}))
        request.extensions["bughunt_job_guard"] = plan.budget.check
        response = verification.verify_and_send(client, request, stream=True)
        attempt["run_ids"].append(request.extensions["bughunt_run_id"])
        body = _read(response, plan, request)
        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("location")
            if not location:
                return {"denied": True}
            target = urljoin(target, location)
            continue
        headers = {key: item for key, item in response.headers.items() if key.lower() not in
                   {"content-length", "transfer-encoding", "connection", "keep-alive", "upgrade"}}
        return {"status": response.status_code, "headers": headers, "body": base64.b64encode(body).decode()}
    return {"denied": True}


def mediate(path: Path, client: httpx.Client, plan: browser_actor.Plan) -> dict:
    attempt = {"sequence": path.stem, "run_ids": [], "denied": False, "fatal": False}
    try:
        value = _decode(path)
        attempt["request_sha256"] = browser_actor.fingerprint(path, 32768)
        if value["method"] != "GET" or value["url"] not in plan.urls:
            reply = {"denied": True}
        else:
            plan.budget.check(httpx.Request("GET", value["url"]))
            reply = _fetch(client, plan, value, attempt)
    except (OSError, ValueError, TypeError, KeyError, httpx.HTTPError) as error:
        reply = {"fatal": True}
        attempt["error"] = type(error).__name__
    attempt.update(denied=bool(reply.get("denied")), fatal=bool(reply.get("fatal")))
    exchange._write(path.with_suffix(".resp"), reply)
    return attempt


def _loop(process, root: Path, plan: browser_actor.Plan, name: str, attempts: list) -> str:
    processed, ready = set(), False
    bounded = zap_runtime._CappedTransport(job.Transport(plan.budget), plan.max_bytes)
    with egress.client(operation="active_scan", transport=bounded, follow_redirects=False, trust_env=False) as client:
        while True:
            plan.budget.check(httpx.Request("GET", plan.urls[0]))
            _outputs(root)
            if (root / "engine" / "rpc").is_symlink() or (root / "engine").is_symlink():
                raise ValueError("Browser mailbox redirected")
            if not ready:
                ready = _ready(plan, root, name)
            if process.poll() is not None:
                return "consumer-completed" if ready else "consumer-not-ready"
            if ready:
                for path in sorted((root / "engine" / "rpc").glob("*.req")):
                    if path.name in processed:
                        continue
                    if len(processed) >= 128:
                        return "consumer-rpc-cap"
                    attempt = mediate(path, client, plan)
                    attempts.append(attempt)
                    processed.add(path.name)
                    if attempt["fatal"]:
                        return "browser-request-failed"
            time.sleep(0.02)


def _reap(process) -> bool:
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            return False
    return process.poll() is not None


def _cleanup_id(process, root: Path, plan: browser_actor.Plan) -> str:
    if getattr(plan.budget, "container_id", None):
        return plan.budget.container_id
    deadline = time.monotonic() + 5
    while True:
        try:
            return _container_id(root)
        except (FileNotFoundError, ValueError):
            if process.poll() is not None or time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def _cleanup(process, root: Path, plan: browser_actor.Plan) -> bool:
    try:
        ledger._write_private(root / "engine" / "rpc" / "STOP", b"stop\n")
    except OSError:
        pass
    cleaned = False
    try:
        identifier = _cleanup_id(process, root, plan)
        inspected = subprocess.run(["docker", "inspect", "--format", "{{json .}}", identifier],
                                   capture_output=True, timeout=5)
        if inspected.returncode == 0:
            value = exchange.load_json(inspected.stdout)
            if (value["Id"] != identifier or value["Config"]["Labels"].get("bughunt.job") != plan.budget.job_id
                    or value["Image"] != browser_actor.IMAGE.split("@", 1)[1]):
                raise ValueError("Browser cleanup refuses a foreign container")
            for args in (["stop", "--time", "2", identifier], ["rm", "--force", identifier]):
                subprocess.run(["docker", *args], capture_output=True, timeout=10)
        absent = subprocess.run(["docker", "ps", "-a", "--no-trunc", "--filter", "id=" + identifier,
                                 "--format", "{{.ID}}"], capture_output=True, timeout=5)
        cleaned = absent.returncode == 0 and not absent.stdout.strip()
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        pass
    reaped = _reap(process)
    return cleaned and reaped


def _observation(value: dict, plan: browser_actor.Plan, count: int) -> None:
    fields = {"body_sha256", "storage_sha256", "final_url", "renderers", "job_id", "actor",
              "initial_storage_empty", "generated_requests", "blocked_websockets", "complete"}
    if (set(value) != fields or value["job_id"] != plan.budget.job_id or value["actor"] != plan.actor
            or value["final_url"] != plan.urls[0] or value["initial_storage_empty"] is not True
            or value["complete"] is not True or type(value["generated_requests"]) is not int
            or value["generated_requests"] != count or not 1 <= count <= 128
            or type(value["blocked_websockets"]) is not int or not 0 <= value["blocked_websockets"] <= 128
            or any(not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key])
                   for key in ("body_sha256", "storage_sha256"))):
        raise ValueError("Browser result binding/schema differs")
    renderers = value["renderers"]
    if (not isinstance(renderers, list) or not 1 <= len(renderers) <= 32 or any(
            not isinstance(row, dict) or set(row) != {"no_sandbox_flag", "seccomp", "no_new_privileges"}
            or row["no_sandbox_flag"] is not False or type(row["seccomp"]) is not int or row["seccomp"] != 2
            or type(row["no_new_privileges"]) is not int or row["no_new_privileges"] != 1 for row in renderers)):
        raise ValueError("Browser renderer sandbox evidence unavailable")


def _artifacts(root: Path) -> tuple[list[str], list[dict]]:
    accepted, rejected = [], []
    candidates = ("input/browser.json", "input/seccomp.json", "provenance.json", "attempts.json",
        "containment.json", "consumer.log", "consumer.cid", "engine/rpc/READY", "engine/browser-result.json")
    for relative in candidates:
        try:
            (root / relative).lstat()
        except FileNotFoundError:
            continue
        except OSError:
            rejected.append({"path": relative, "reason": "unsealable-artifact"})
            continue
        try:
            job._artifact(root, relative)
        except (OSError, ValueError):
            rejected.append({"path": relative, "reason": "unsealable-artifact"})
        else:
            accepted.append(relative)
    return accepted, rejected


def _finish(plan: browser_actor.Plan, root: Path, attempts: list, reason: str, status, cleaned: bool) -> dict:
    observed = None
    try:
        _outputs(root)
        path = root / "engine" / "browser-result.json"
        observed = job._load(path) if path.exists() else None
        if observed is not None:
            _observation(observed, plan, len(attempts))
        for item in plan.budget.sent:
            manifest = ledger.manifest_for(item["run_id"])
            if manifest.get("actor") != plan.actor or not manifest.get("finished_at"):
                raise ValueError("Browser request capture incomplete")
    except (OSError, ValueError, TypeError, KeyError):
        observed = None
        reason = "browser-evidence-incomplete"
    exchange._write(root / "attempts.json", {"generated": attempts, "physical": plan.budget.sent})
    artifacts, rejected = _artifacts(root)
    if rejected:
        observed, reason = None, "browser-evidence-incomplete"
    cancelled = plan.budget.cancelled.is_set() or plan.budget.stop_path().exists()
    complete = (not cancelled and reason == "consumer-completed" and status == 0 and cleaned and observed is not None
                and plan.budget.sent and not any(item["fatal"] for item in attempts))
    result = {"job_id": plan.budget.job_id, "classification": "observation" if complete else "inconclusive",
        "reason": "job-cancelled" if cancelled else reason, "cleanup_confirmed": cleaned,
        "admitted_count": len(plan.budget.sent), "attempt_count": len(attempts),
        "denied_count": sum(item["denied"] for item in attempts), "consumer_status": status,
        "actor": plan.actor, "admitted_run_ids": [item["run_id"] for item in plan.budget.sent],
        "manual_controls_required": True, "browser_network_enabled": False, "rejected_artifacts": rejected}
    public_observed = dict(observed, final_url=observed["final_url"].split("?", 1)[0],
                           final_url_sha256=exchange.digest(observed["final_url"].encode())) if observed is not None else None
    analysis = {"observation": public_observed, "reason": result["reason"], "physical_budget_includes_probes": True}
    state = "cancelled" if cancelled else "success" if complete else "partial" if plan.budget.sent else "failed"
    return job.finish_engine(plan.budget.job_id, analysis, result, state=state, artifacts=artifacts)


def run(plan: browser_actor.Plan, on_start=None) -> dict:
    with identity.actor_context(plan.actor):
        archive, source = dependencies()
        root = _files(plan, archive, source)
        name = "whk027-" + plan.budget.job_id
        process, log, attempts, status = None, None, [], None
        reason, cleaned = "consumer-preflight-failed", True
        token = ledger.CURRENT_TOOL.set("browser-actors")
        try:
            if on_start is not None:
                on_start(plan.budget.job_id)
            _preflight(plan)
            log = (root / "consumer.log").open("xb")
            (root / "consumer.log").chmod(0o600)
            plan.budget.check(httpx.Request("GET", plan.urls[0]))
            egress.authorize(plan.urls[0], "process", "GET")
            process = subprocess.Popen(command(plan, root, name, archive), stdout=log, stderr=subprocess.STDOUT)
            reason = _loop(process, root, plan, name, attempts)
            status = process.poll()
        except KeyboardInterrupt:
            plan.budget.cancelled.set()
            reason = "job-cancelled"
        except (OSError, ValueError, TypeError, KeyError, httpx.HTTPError, subprocess.SubprocessError):
            reason = ("job-cancelled" if plan.budget.cancelled.is_set() or plan.budget.stop_path().exists()
                      else "job-deadline" if time.monotonic() >= plan.budget.deadline else "consumer-runtime-failed")
        finally:
            if process is not None:
                cleaned = _cleanup(process, root, plan)
                status = process.poll()
            if log is not None:
                log.close()
            ledger.CURRENT_TOOL.reset(token)
        return _finish(plan, root, attempts, reason, status, cleaned)
