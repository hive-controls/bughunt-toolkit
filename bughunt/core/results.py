"""Versioned, bounded structured results shared by embedding and command adapters."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit
import uuid

from bughunt.core import exchange, ledger
from bughunt.core import result_schema as contract

SCHEMA_VERSION = 1
OUTPUT_LIMIT = 1_048_576
EXIT_CODES = {
    "success": 0,
    "planned": 0,
    "partial": 1,
    "failed": 1,
    "blocked": 2,
    "invalid": 2,
    "unsupported": 2,
    "cancelled": 130,
}
_PAYLOADS = contract.PAYLOADS
_SELECTION_KEYS = {
    "urls": "urls",
    "hosts": "hosts",
    "exchanges": "exchange_ids",
    "runs": "run_ids",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def artifact_schema(kind: str) -> dict:
    if kind not in _PAYLOADS:
        raise ValueError("Unknown artifact kind")
    return json.loads(
        json.dumps(
            {
                "$id": f"urn:bughunt:artifact:{kind}:1",
                "type": "object",
                "properties": _PAYLOADS[kind],
                "required": list(_PAYLOADS[kind]),
                "additionalProperties": False,
            }
        )
    )


def _bounded(value: Any, depth: int = 0) -> None:
    if depth > 20:
        raise ValueError("Result nesting limit")
    if isinstance(value, dict):
        if len(value) > 1000 or any(not isinstance(key, str) for key in value):
            raise ValueError("Result object limit")
        for item in value.values():
            _bounded(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 1000:
            raise ValueError("Result collection limit")
        for item in value:
            _bounded(item, depth + 1)
    elif isinstance(value, str) and len(value) > OUTPUT_LIMIT:
        raise ValueError("Result text limit")
    elif value is not None and not isinstance(value, (str, bool, int, float)):
        raise ValueError("Result must contain JSON values")


def _validate_payload(kind: str, payload: dict) -> None:
    schema = artifact_schema(kind)
    _bounded(payload)
    contract.validate(payload, schema)
    if len(exchange.canonical(payload)) > OUTPUT_LIMIT:
        raise ValueError("Artifact size limit")


def safe_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        parsed.port
        return bool(
            parsed.scheme in {"http", "https"}
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
            and not any(
                ord(character) < 33 or ord(character) == 127 for character in value
            )
            and ledger.redact_text(value) == value
            and "[REDACTED" not in value
            and not any(
                re.search(r"(?i)token|auth|key|secret|session|csrf", key)
                for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
            )
        )
    except (TypeError, ValueError):
        return False


@dataclass(frozen=True, init=False)
class Artifact:
    kind: str
    _payload_json: bytes = field(repr=False)
    sha256: str
    handoff: bool
    artifact_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: int = SCHEMA_VERSION
    _producer_json: bytes = field(default=b"null", repr=False)

    def __init__(
        self,
        kind: str,
        payload: dict,
        sha256: str | None = None,
        handoff: bool | None = None,
        artifact_id: str | None = None,
        schema_version: int = SCHEMA_VERSION,
        producer: dict | None = None,
    ):
        if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
            raise ValueError("Unsupported artifact version")
        _validate_payload(kind, payload)
        sanitized = ledger.redact(payload)
        eligible = kind in _SELECTION_KEYS and sanitized == payload
        if kind == "urls":
            if not eligible or not all(safe_url(value) for value in payload["urls"]):
                raise ValueError(
                    "Credential-bearing or redacted URL cannot convey authority"
                )
        _validate_payload(kind, sanitized)
        encoded = exchange.canonical(sanitized)
        digest = exchange.digest(encoded)
        if sha256 is not None and sha256 != digest:
            raise ValueError("Artifact hash mismatch")
        if handoff is not None and (type(handoff) is not bool or handoff != eligible):
            raise ValueError("Artifact handoff eligibility mismatch")
        identifier = artifact_id or str(uuid.uuid4())
        if str(uuid.UUID(identifier)) != identifier:
            raise ValueError("Invalid artifact ID")
        if producer is not None:
            contract.validate(producer, contract.PRODUCER)
        for name, value in {
            "kind": kind,
            "_payload_json": encoded,
            "sha256": digest,
            "handoff": eligible,
            "artifact_id": identifier,
            "schema_version": schema_version,
            "_producer_json": exchange.canonical(producer),
        }.items():
            object.__setattr__(self, name, value)

    @classmethod
    def create(cls, kind: str, payload: dict) -> Artifact:
        return cls(kind, payload)

    @property
    def payload(self) -> dict:
        return json.loads(self._payload_json)

    @property
    def producer(self) -> dict | None:
        return json.loads(self._producer_json)

    def produced_by(self, execution_id, module_id, operation):
        value = self.to_dict()
        if self.producer is None:
            value["producer"] = {
                "execution_id": execution_id,
                "module_id": module_id,
                "operation": operation,
            }
        return Artifact(**value)

    def validate(self) -> None:
        Artifact(
            self.kind,
            self.payload,
            self.sha256,
            self.handoff,
            self.artifact_id,
            self.schema_version,
            self.producer,
        )

    def to_dict(self) -> dict:
        self.validate()
        return {
            "kind": self.kind,
            "payload": self.payload,
            "sha256": self.sha256,
            "handoff": self.handoff,
            "artifact_id": self.artifact_id,
            "schema_version": self.schema_version,
            "producer": self.producer,
        }

    def select(self, index: int) -> str:
        self.validate()
        if not self.handoff or self.kind not in _SELECTION_KEYS:
            raise ValueError("Artifact is not eligible for handoff")
        if type(index) is not int or index < 0:
            raise ValueError("Invalid artifact selection")
        if exchange.digest(exchange.canonical(self.payload)) != self.sha256:
            raise ValueError("Artifact hash mismatch")
        values = self.payload[_SELECTION_KEYS[self.kind]]
        if index >= len(values):
            raise ValueError("Artifact selection outside bounds")
        return values[index]


@dataclass
class ModuleOutput:
    artifacts: list[Artifact] = field(default_factory=list)
    run_ids: list[str] = field(default_factory=list)
    status: str = "success"
    warnings: list[str] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class ExecutionContext:
    dry_run: bool = False
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    pipeline: bool = False


@dataclass(frozen=True)
class Result:
    module_id: str
    operation: str
    execution_id: str
    status: str
    exit_code: int
    started_at: str
    finished_at: str
    dry_run: bool
    artifacts: list[Artifact]
    evidence: list[dict]
    policy: dict | None
    errors: list[dict]
    warnings: list[str]
    metrics: dict
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        self.to_dict()

    @classmethod
    def from_dict(cls, value):
        _bounded(value)
        contract.validate(value, result_schema())
        restored = dict(value)
        restored["artifacts"] = [Artifact(**item) for item in value["artifacts"]]
        return cls(**restored)

    @classmethod
    def create(
        cls,
        module_id: str,
        operation: str,
        output: ModuleOutput,
        *,
        context: ExecutionContext | None = None,
        started_at: str | None = None,
        policy: dict | None = None,
        metrics: dict | None = None,
    ) -> Result:
        context = context or ExecutionContext()
        if output.status not in EXIT_CODES or len(output.artifacts) > 100:
            raise ValueError("Invalid result status or artifact bound")
        for artifact in output.artifacts:
            artifact.validate()
        evidence = []
        for run_id in dict.fromkeys(output.run_ids):
            exported = ledger.export_run(run_id)
            evidence.append(
                {
                    "run_id": run_id,
                    "sha256": exchange.digest(exchange.canonical(exported)),
                    "representation": exported["manifest"].get(
                        "representation", "ledger"
                    ),
                }
            )
        return cls(
            module_id,
            operation,
            context.execution_id,
            output.status,
            EXIT_CODES[output.status],
            started_at or now(),
            now(),
            context.dry_run,
            [
                artifact.produced_by(context.execution_id, module_id, operation)
                for artifact in output.artifacts
            ],
            evidence,
            ledger.redact(policy),
            ledger.redact(output.errors),
            ledger.redact(output.warnings),
            metrics
            or {
                "requests_admitted": 0,
                "bytes_retained": 0,
                "elapsed_seconds": 0,
                "limits": {},
            },
        )

    def to_dict(self) -> dict:
        value = {
            item.name: getattr(self, item.name)
            for item in fields(self)
            if item.name != "artifacts"
        }
        value["artifacts"] = [artifact.to_dict() for artifact in self.artifacts]
        _bounded(value)
        contract.validate(value, result_schema())
        if value["exit_code"] != EXIT_CODES[value["status"]]:
            raise ValueError("Result exit code differs from status")
        if datetime.fromisoformat(value["finished_at"]) < datetime.fromisoformat(
            value["started_at"]
        ):
            raise ValueError("Result timestamps are reversed")
        raw = exchange.canonical(value)
        if len(raw) > OUTPUT_LIMIT:
            raise ValueError("Result size limit")
        return json.loads(raw)


def result_schema() -> dict:
    return contract.schema(EXIT_CODES)
