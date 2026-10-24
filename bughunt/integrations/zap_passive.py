"""Bounded recorded-traffic plans; no target transport is available to this job."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx

from bughunt.core import egress, exchange, identity, job, ledger
from bughunt.integrations import zap, zap_active
from bughunt.core.policy import Profile, parse_profile
from bughunt.core.workspace import workspace_dir


class PassiveBudget(job.Budget):
    def __init__(self, targets, sources: dict[Path, str], actors: list[str], seconds: int):
        self.sources = dict(sources)
        self.artifacts = {}
        self.actors = {identity._profile_path(name): zap_active.ActiveBudget._hash(
            identity._profile_path(name), ledger.CAPTURE_LIMIT) for name in actors}
        super().__init__(frozenset(targets), 1, seconds, strict_scope=True)

    def check(self, request: httpx.Request) -> None:
        super().check(request)
        profile = egress.current_profile()
        for method, url in self.targets:
            if any(not profile.decide(url, operation, method=method).permitted
                   for operation in ("passive", "process")):
                raise egress.PolicyBlocked("passive-job-permission-revoked")
        for paths, maximum in ((self.sources, exchange.INPUT_LIMIT),
                               (self.actors, ledger.CAPTURE_LIMIT), (self.artifacts, exchange.INPUT_LIMIT)):
            if any(zap_active.ActiveBudget._hash(path, maximum) != digest for path, digest in paths.items()):
                raise egress.PolicyBlocked("passive-job-source-actor-or-input-changed")

    def bind_artifacts(self, paths: list[Path]) -> None:
        self.artifacts.update({path: zap_active.ActiveBudget._hash(path, exchange.INPUT_LIMIT) for path in paths})

    def admit(self, _request: httpx.Request) -> None:
        raise egress.PolicyBlocked("passive-job-target-sends-forbidden")

    def activate(self) -> None:
        super().activate()
        path = self.stop_path().parent / "job.json"
        metadata = job._load(path)
        metadata.update(request_cap=0, claim="Recorded traffic only; no target network route or sends")
        exchange._write(path, metadata)

    def check_all(self) -> None:
        method, url = next(iter(self.targets))
        self.check(httpx.Request(method, url))


@dataclass(frozen=True)
class Plan:
    records: list[dict]
    files: dict[str, bytes]
    file_hashes: tuple[tuple[str, str], ...]
    budget: PassiveBudget
    profile: Profile


def _sources(exchange_ids: list[str]) -> tuple[list[dict], dict[Path, str]]:
    if not isinstance(exchange_ids, list) or not 1 <= len(exchange_ids) <= exchange.ENTRY_LIMIT:
        raise ValueError("Select 1..500 distinct complete captures")
    records, sources, total = [], {}, 0
    for identifier in exchange_ids:
        path = exchange._path(identifier)
        if path.is_symlink() or path.stat().st_size > exchange.INPUT_LIMIT - total:
            raise ValueError("Selected capture batch exceeds 16 MiB")
        with path.open("rb") as handle:
            raw = handle.read(exchange.INPUT_LIMIT - total + 1)
        total += len(raw)
        if total > exchange.INPUT_LIMIT:
            raise ValueError("Selected capture batch grew beyond 16 MiB")
        record = exchange.validate(exchange.load_json(raw))
        if record["exchange_id"] != identifier:
            raise ValueError("Selected capture identity mismatch")
        records.append(record)
        sources[path] = exchange.digest(raw)
    return records, sources


def prepare(exchange_ids: list[str], *, actors: list[str], mission: str,
            seconds=120, alerts=10, max_bytes=65536) -> Plan:
    seconds = zap._bounded(seconds, 300)
    records, sources = _sources(exchange_ids)
    policy_bytes = (workspace_dir() / "policy.json").read_bytes()
    profile = parse_profile(exchange.load_json(policy_bytes))
    if profile.mission != mission:
        raise ValueError("Current passive mission must match")
    targets = {(record["request"]["method"], record["request"]["url"]) for record in records}
    if any(str(httpx.URL(url)) != url for _method, url in targets):
        raise ValueError("Managed recorded targets must be canonical HTTPX URLs")
    budget = PassiveBudget(targets, sources, actors, seconds)
    if budget.state[1] != exchange.digest(policy_bytes):
        raise ValueError("Passive policy changed while preparing")
    budget.check_all()
    files = zap.build(records, actors, Path("/bughunt/input"),
                      seconds=seconds, alerts=alerts, body_limit=max_bytes)
    plan = exchange.load_json(files["plan.yaml"])
    plan["env"]["vars"]["BUGHUNT_BUNDLE_DIR"] = "/bughunt/input"
    plan["jobs"][-1]["parameters"]["reportDir"] = "/reports"
    files["plan.yaml"] = exchange.canonical(plan) + b"\n"
    files["GUIDANCE.md"] += ("\nThis derivative is owned by the managed passive runner. The standalone-export\n"
        "instructions above are historical context, not a separate launch step.\n"
        "Bughunt launches this isolated consumer with enforced process/resource bounds.\n").encode()
    manifest = exchange.load_json(files["manifest.json"])
    manifest["files"].update({name: exchange.digest(files[name]) for name in ("plan.yaml", "GUIDANCE.md")})
    files["manifest.json"] = exchange.canonical(manifest) + b"\n"
    if any(len(data) > exchange.INPUT_LIMIT for data in files.values()) or sum(map(len, files.values())) > exchange.INPUT_LIMIT:
        raise ValueError("Passive bundle exceeds 16 MiB")
    budget.check_all()
    return Plan(records, files, tuple((name, exchange.digest(raw)) for name, raw in files.items()), budget, profile)


def descriptor(plan: Plan) -> dict:
    from bughunt.core import engine
    plan.budget.check_all()
    if {name: exchange.digest(raw) for name, raw in plan.files.items()} != dict(plan.file_hashes):
        raise ValueError("Passive prepared bundle changed")
    manifest = exchange.load_json(plan.files["manifest.json"])
    helpers = {name: zap_active.ActiveBudget._hash(Path(__file__).with_name(name), ledger.CAPTURE_LIMIT)
               for name in ("zap_passive_consumer.py", "zap_consumer.py")}
    return {"profile_id": "zap-passive", "engine": "zap-passive", "version": zap.SUPPORTED_VERSION,
        "image": zap.SUPPORTED_IMAGE, "operation": "process", "target": "recorded:zap-passive",
        "actor": plan.budget.state[0][1], "actor_revision": plan.budget.state[0][2],
        "actors": manifest["actors"], "authentication_ready": False,
        "source_exchanges": [{"exchange_id": path.stem, "sha256": digest}
                             for path, digest in plan.budget.sources.items()],
        "policy_sha256": plan.budget.state[1], "files": {name: exchange.digest(raw) for name, raw in plan.files.items()},
        "consumer_helpers": helpers, "addon_inventory_sha256": exchange.digest(exchange.canonical(engine.inventory())),
        "network": "Docker network none; no published ports; HAR sendRequests=false; no target sends",
        "credentials": "sanitized recordings; no engine credentials/login; named users are unverified labels",
        "background_fetch": "updates/telemetry disabled; isolated fresh session; outgoing proxy has no listener",
        "budgets": {"physical_requests": 0, "seconds": plan.budget.seconds, "concurrency": 1,
                    "source_routes": len(plan.budget.targets), "maximum_routes": 100,
                    "input_bytes": exchange.INPUT_LIMIT, "report_bytes": exchange.INPUT_LIMIT,
                    "log_bytes": ledger.CAPTURE_LIMIT, "memory": "2g", "cpus": 1, "pids": 256,
                    "temporary_filesystems": {"/tmp": "512m", "/reports": "16m"}},
        "expected_artifacts": ["provenance.json", "consumer.log", "input/manifest.json", "input/plan.yaml",
            "input/context.context", "input/traffic.har", "engine/rpc/READY", "engine/plan-progress.json",
            "engine/consumer-metadata.json", "engine/reports/passive-report.json"],
        "claim": "Recorded sanitized evidence only; report alerts are hypotheses; empty is not a negative finding"}


def preview(plan: Plan) -> dict:
    return {"job_id": plan.budget.job_id, "dry_run": True, "engine_plan": descriptor(plan),
            "automation_plan": exchange.load_json(plan.files["plan.yaml"]), "target_network_enabled": False}


def run(plan: Plan, on_start=None) -> dict:
    from bughunt.integrations import zap_passive_runtime
    return zap_passive_runtime.run(plan, on_start=on_start)
