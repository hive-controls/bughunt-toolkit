"""Locked pipeline intents and hash-linked receipts in the existing jobs store."""

from contextlib import contextmanager, nullcontext
import json
import math
import os
from pathlib import Path
import uuid

from bughunt.core import adapters, exchange, job, ledger
from bughunt.core.pipeline import (
    MAX_PLAN_BYTES,
    _IDENTIFIER,
    _closed,
    _input_bytes,
    _limits,
    load_pipeline,
)
from bughunt.core.pipeline_budget import Governor
from bughunt.core.results import Result


def _safe(path):
    absolute = path.absolute()
    if any(
        parent.is_symlink() or parent.is_junction()
        for parent in (absolute, *absolute.parents)
    ):
        raise ValueError("Pipeline journal path traverses a link")
    return absolute


def _read(path):
    path = _safe(path)
    if not path.is_file() or path.stat().st_size > 2 * MAX_PLAN_BYTES:
        raise ValueError("Missing or oversized pipeline journal")
    with path.open("rb") as handle:
        raw = handle.read(2 * MAX_PLAN_BYTES + 1)
    if len(raw) > 2 * MAX_PLAN_BYTES:
        raise ValueError("Pipeline journal grew beyond its bound")
    return raw


def _write(path, value):
    _safe(path)
    encoded = exchange.canonical(value)
    if len(encoded) > 2 * MAX_PLAN_BYTES:
        raise ValueError("Pipeline journal size limit")
    exchange._write(path, value)
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())


def _file_lock(handle, *, unlock=False):
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(
            handle.fileno(), msvcrt.LK_UNLCK if unlock else msvcrt.LK_NBLCK, 1
        )
    else:
        import fcntl

        fcntl.flock(
            handle.fileno(), fcntl.LOCK_UN if unlock else fcntl.LOCK_EX | fcntl.LOCK_NB
        )


def _snapshot_hash(data):
    value = {
        key: item
        for key, item in data.items()
        if key not in {"sequence", "events_sha256"}
    }
    return exchange.digest(exchange.canonical(value))


def _restore_plan(document, trusted):
    source = json.loads(exchange.canonical(document))
    used = set()
    for step in source["steps"]:
        for name, value in step["options"].items():
            step["options"][name] = _restore_input(value, trusted, used)
    if used != set(trusted):
        raise ValueError("Pipeline private input coverage changed")
    plan = load_pipeline(source)
    if plan.document != document or plan.trusted_inputs != trusted:
        raise ValueError("Pipeline input or plan changed")
    return plan


def _restore_input(value, trusted, used):
    if isinstance(value, list):
        return [_restore_input(item, trusted, used) for item in value]
    if not isinstance(value, dict):
        return value
    _closed(value, {"trusted_input", "sha256", "bytes"})
    identifier = value["trusted_input"]
    metadata = trusted[identifier]
    _closed(metadata, {"path", "sha256", "bytes"})
    if metadata["sha256"] != value["sha256"] or metadata["bytes"] != value["bytes"]:
        raise ValueError("Pipeline private input binding changed")
    used.add(identifier)
    return metadata["path"]


def _digest(value):
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("Invalid pipeline digest")


def _validate_steps(data):
    definitions = data["plan"]["steps"]
    if not isinstance(definitions, list) or not 1 <= len(definitions) <= 32:
        raise ValueError("Invalid pipeline step inventory")
    names = []
    for definition in definitions:
        _closed(
            definition, {"id", "module", "operation", "options"}, {"inputs", "limits"}
        )
        _validate_outputs(definition)
        name = definition["id"]
        if (
            not isinstance(name, str)
            or not _IDENTIFIER.fullmatch(name)
            or name in names
        ):
            raise ValueError("Invalid pipeline step identity")
        names.append(name)
    _closed(data["steps"], names)
    unfinished = False
    for name in names:
        step = data["steps"][name]
        if not isinstance(step, dict) or not isinstance(step.get("state"), str):
            raise ValueError("Invalid pipeline step state")
        state = step["state"]
        if unfinished and state != "pending":
            raise ValueError("Pipeline sequential step order changed")
        unfinished |= state != "completed"
        fields = {"state"} if state == "pending" else {"state", "attempt_id"}
        if state not in {
            "pending",
            "running",
            "completed",
            "partial",
            "blocked",
            "failed",
            "cancelled",
            "invalid",
            "unsupported",
            "planned",
        }:
            raise ValueError("Invalid pipeline step state")
        if state not in {"pending", "running"}:
            fields.add("result_sha256")
        _closed(step, fields)
        if "attempt_id" in step:
            attempt = step["attempt_id"]
            if not isinstance(attempt, str) or str(uuid.UUID(attempt)) != attempt:
                raise ValueError("Invalid pipeline attempt identity")
        if "result_sha256" in step:
            _digest(step["result_sha256"])
    if data["state"] == "success" and any(
        step["state"] != "completed" for step in data["steps"].values()
    ):
        raise ValueError("Incomplete pipeline cannot succeed")


def _validate_outputs(definition):
    options = definition["options"]
    if not isinstance(options, dict):
        raise ValueError("Invalid pipeline step options")
    if adapters._output_restriction(
        definition["module"], options, definition["operation"]
    ):
        raise ValueError("Persisted output options are not pipeline eligible")


def _validate_snapshot(data):
    if (
        type(data["schema_version"]) is not int
        or type(data["registry_version"]) is not int
    ):
        raise ValueError("Invalid pipeline schema version")
    if not isinstance(data["state"], str) or data["state"] not in {
        "planned",
        "running",
        "success",
        "partial",
        "blocked",
        "failed",
        "cancelled",
        "invalid",
        "unsupported",
    }:
        raise ValueError("Invalid pipeline lifecycle state")
    if (
        type(data["deadline"]) not in {int, float}
        or not math.isfinite(data["deadline"])
        or data["deadline"] <= 0
    ):
        raise ValueError("Invalid pipeline deadline")
    _closed(data["plan"], {"schema_version", "mission", "limits", "steps"})
    limits = _limits(data["plan"]["limits"], complete=True)
    _closed(data["counters"], {"requests_admitted", "bytes_retained"})
    for name, maximum in (
        ("requests_admitted", limits["requests"]),
        ("bytes_retained", limits["bytes"]),
    ):
        value = data["counters"][name]
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError("Invalid pipeline cumulative counter")
    _digest(data["plan_sha256"])
    _digest(data["events_sha256"])
    _validate_steps(data)
    _validate_authority(data["authority"])
    _validate_inputs(data["trusted_inputs"])


def _validate_authority(authority):
    _closed(authority, {"workspace", "files", "actor"})
    root = authority["workspace"]
    if not isinstance(root, str) or not Path(root).is_absolute():
        raise ValueError("Invalid pipeline workspace identity")
    _closed(authority["files"], {"policy.json", "scope.txt"})
    for digest in authority["files"].values():
        if digest is not None:
            _digest(digest)
    actor = authority["actor"]
    if (
        not isinstance(actor, list)
        or len(actor) != 3
        or any(not isinstance(item, str) for item in actor)
    ):
        raise ValueError("Invalid pipeline actor identity")
    if actor[0] != root:
        raise ValueError("Pipeline actor workspace differs")


def _validate_inputs(trusted):
    if not isinstance(trusted, dict) or len(trusted) > 1000:
        raise ValueError("Invalid pipeline input inventory")
    total = 0
    for identifier, metadata in trusted.items():
        if not isinstance(identifier, str) or not identifier.startswith("input-"):
            raise ValueError("Invalid pipeline input identity")
        _digest(identifier[6:])
        _closed(metadata, {"path", "sha256", "bytes"})
        _digest(metadata["sha256"])
        if (
            type(metadata["bytes"]) is not int
            or not 0 <= metadata["bytes"] <= MAX_PLAN_BYTES
        ):
            raise ValueError("Invalid pipeline input byte count")
        path = metadata["path"]
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise ValueError("Invalid pipeline input path")
        total += metadata["bytes"]
    if total > MAX_PLAN_BYTES:
        raise ValueError("Pipeline total input size limit")


class Journal:
    def __init__(self, identifier):
        if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
            raise ValueError("Expected canonical pipeline ID")
        self.identifier = identifier
        self.root = _safe(job._root(identifier))
        self.data = None
        self._handle = None

    @classmethod
    def create(cls, plan, governor):
        plan = _restore_plan(plan.document, plan.trusted_inputs)
        governor.check()
        journal = cls(str(uuid.uuid4()))
        journal.root.mkdir(parents=True, mode=0o700, exist_ok=False)
        with journal.locked():
            journal.data = {
                "schema_version": 1,
                "pipeline_id": journal.identifier,
                "registry_version": adapters.CONTRACT_VERSION,
                "plan": plan.document,
                "plan_sha256": plan.sha256,
                "trusted_inputs": plan.trusted_inputs,
                "authority": governor.authority,
                "deadline": governor.deadline,
                "state": "planned",
                "counters": {"requests_admitted": 0, "bytes_retained": 0},
                "steps": {
                    step["id"]: {"state": "pending"} for step in plan.document["steps"]
                },
                "sequence": 0,
                "events_sha256": "",
            }
            (journal.root / "events.jsonl").touch(mode=0o600, exist_ok=False)
            journal._event("created", {"plan_sha256": plan.sha256})
        return journal

    @contextmanager
    def locked(self):
        if self._handle is not None:
            raise ValueError("Pipeline journal is already owned")
        path = _safe(self.root / "LOCK")
        with path.open("a+b") as handle:
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"\0")
                handle.flush()
            try:
                _file_lock(handle)
            except OSError as error:
                raise ValueError("Pipeline journal is already owned") from error
            self._handle = handle
            try:
                yield self
            finally:
                self._handle = None
                _file_lock(handle, unlock=True)

    def _require_lock(self):
        if self._handle is None:
            raise ValueError("Pipeline journal writes require ownership")
        _safe(self.root)

    def _event(self, kind, payload):
        self._require_lock()
        event = {
            "sequence": self.data["sequence"] + 1,
            "kind": kind,
            "previous_sha256": self.data["events_sha256"],
            "payload": payload,
            "snapshot_sha256": _snapshot_hash(self.data),
        }
        raw = exchange.canonical(event)
        path = _safe(self.root / "events.jsonl")
        if path.stat().st_size + len(raw) + 1 > MAX_PLAN_BYTES:
            raise ValueError("Pipeline journal event limit")
        with path.open("ab") as handle:
            handle.write(raw + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.data["sequence"] = event["sequence"]
        self.data["events_sha256"] = exchange.digest(raw)
        _write(self.root / "pipeline.json", self.data)

    def _load(self, *, allow_tail=False):
        data = exchange.load_json(_read(self.root / "pipeline.json"))
        _closed(
            data,
            {
                "schema_version",
                "pipeline_id",
                "registry_version",
                "plan",
                "plan_sha256",
                "trusted_inputs",
                "authority",
                "deadline",
                "state",
                "counters",
                "steps",
                "sequence",
                "events_sha256",
            },
        )
        if data["schema_version"] != 1 or data["pipeline_id"] != self.identifier:
            raise ValueError("Pipeline journal identity mismatch")
        if data["registry_version"] != adapters.CONTRACT_VERSION:
            raise ValueError("Pipeline registry changed")
        _validate_snapshot(data)
        if exchange.digest(exchange.canonical(data["plan"])) != data["plan_sha256"]:
            raise ValueError("Pipeline plan hash mismatch")
        self._verify_events(data, allow_tail=allow_tail)
        self.data = data
        return data

    def _verify_events(self, data, *, allow_tail=False):
        previous, sequence, snapshot = "", 0, None
        rows = _read(self.root / "events.jsonl").splitlines()
        if type(data["sequence"]) is not int or data["sequence"] < 1:
            raise ValueError("Invalid pipeline event sequence")
        if allow_tail:
            rows = rows[: data["sequence"]]
        for sequence, raw in enumerate(rows, 1):
            event = exchange.load_json(raw)
            _closed(
                event,
                {"sequence", "kind", "previous_sha256", "payload", "snapshot_sha256"},
            )
            if event["sequence"] != sequence or event["previous_sha256"] != previous:
                raise ValueError("Pipeline journal event chain mismatch")
            previous = exchange.digest(exchange.canonical(event))
            snapshot = event["snapshot_sha256"]
        if previous != data["events_sha256"] or sequence != data["sequence"]:
            raise ValueError("Pipeline journal has an uncommitted event tail")
        if snapshot != _snapshot_hash(data):
            raise ValueError("Pipeline journal snapshot differs from its event receipt")

    def start_step(self, identifier):
        self._require_lock()
        if self.data is None:
            self._load()
        steps = self.data["steps"]
        order = [step["id"] for step in self.data["plan"]["steps"]]
        if set(order) != set(steps):
            raise ValueError("Pipeline step inventory changed")
        pending = next(
            (key for key in order if steps[key]["state"] != "completed"), None
        )
        if identifier != pending or steps[identifier]["state"] != "pending":
            raise ValueError("Pipeline step cannot be replayed or reordered")
        attempt = str(uuid.uuid4())
        steps[identifier] = {"state": "running", "attempt_id": attempt}
        self.data["state"] = "running"
        self._event("step-intent", {"step": identifier, "attempt_id": attempt})
        return attempt

    def finish_step(self, identifier, result: Result):
        self._require_lock()
        step = self.data["steps"][identifier]
        if step["state"] != "running":
            raise ValueError("Pipeline step has no active intent")
        value = result.to_dict()
        if value["execution_id"] != step["attempt_id"]:
            raise ValueError("Pipeline receipt attempt mismatch")
        definition = next(
            row for row in self.data["plan"]["steps"] if row["id"] == identifier
        )
        if (value["module_id"], value["operation"]) != (
            definition["module"],
            definition["operation"],
        ):
            raise ValueError("Pipeline receipt producer mismatch")
        state = "completed" if result.status == "success" else result.status
        _write(self.root / "steps" / identifier / "result.json", value)
        step.update(
            state=state, result_sha256=exchange.digest(exchange.canonical(value))
        )
        self.data["state"] = "running" if state == "completed" else result.status
        self._event(
            "step-result",
            {"step": identifier, "state": state, "sha256": step["result_sha256"]},
        )

    def counters(self, values):
        self._require_lock()
        self.data["counters"] = dict(values)
        self._event("admission-counters", dict(values))

    def input_paths(self, plan, governor):
        self._require_lock()
        selected = {}
        for identifier, metadata in plan.trusted_inputs.items():
            path = _safe(self.root / "inputs" / identifier)
            if path.exists():
                raw = _read(path)
            else:
                _, raw = _input_bytes(Path(metadata["path"]))
            if (
                exchange.digest(raw) != metadata["sha256"]
                or len(raw) != metadata["bytes"]
            ):
                raise ValueError("Pipeline immutable input changed")
            if not path.exists():
                governor.retain(len(raw))
                path.parent.mkdir(mode=0o700, exist_ok=True)
                with path.open("xb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                path.chmod(0o600)
            selected[identifier] = str(path)
        return selected

    def finish(self, state):
        self._require_lock()
        if state not in {"success", "partial", "blocked", "failed", "cancelled"}:
            raise ValueError("Invalid pipeline terminal state")
        if state == "success" and any(
            step["state"] != "completed" for step in self.data["steps"].values()
        ):
            raise ValueError("Incomplete pipeline cannot succeed")
        self.data["state"] = state
        self._event("finished", {"state": state})

    def cancel(self):
        if not (self.root / "pipeline.json").is_file():
            raise ValueError("Unknown pipeline")
        _write(self.root / "STOP", {"cancelled": True})

    def status(self):
        data = self._load(allow_tail=True)
        return {
            "pipeline_id": self.identifier,
            "state": data["state"],
            "counters": dict(data["counters"]),
            "deadline": data["deadline"],
            "cancel_requested": (self.root / "STOP").exists(),
            "steps": [
                {"id": step["id"], "state": data["steps"][step["id"]]["state"]}
                for step in data["plan"]["steps"]
            ],
        }

    def _results(self):
        results = {}
        for definition in self.data["plan"]["steps"]:
            identifier = definition["id"]
            step = self.data["steps"][identifier]
            if step["state"] == "running":
                raise ValueError("Pipeline intent is indeterminate; create a new run")
            if step["state"] not in {"pending", "completed"}:
                raise ValueError(
                    "Pipeline non-completed step cannot be automatically replayed"
                )
            if step["state"] != "completed":
                continue
            value = exchange.load_json(
                _read(self.root / "steps" / identifier / "result.json")
            )
            if exchange.digest(exchange.canonical(value)) != step["result_sha256"]:
                raise ValueError("Pipeline step receipt changed")
            value = Result.from_dict(value).to_dict()
            if (
                value["execution_id"],
                value["module_id"],
                value["operation"],
                value["status"],
            ) != (
                step["attempt_id"],
                definition["module"],
                definition["operation"],
                "success",
            ):
                raise ValueError("Pipeline completed receipt producer or state changed")
            for evidence in value["evidence"]:
                exported = ledger.export_run(evidence["run_id"])
                if exchange.digest(exchange.canonical(exported)) != evidence["sha256"]:
                    raise ValueError("Pipeline evidence receipt changed")
            results[identifier] = value
        return results

    def restore(self):
        with self.locked() if self._handle is None else nullcontext():
            self._load()
            if (self.root / "STOP").exists():
                raise ValueError("Pipeline is cancelled")
            plan = _restore_plan(self.data["plan"], self.data["trusted_inputs"])
            Governor(
                plan.limits,
                mission=plan.document["mission"],
                deadline=self.data["deadline"],
                counters=self.data["counters"],
                authority=self.data["authority"],
            ).check()
            return plan, self._results()
