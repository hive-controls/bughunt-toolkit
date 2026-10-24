"""Shared runtime and published schemas for bounded structured receipts."""

from datetime import datetime
import math
import re
import uuid


def closed(properties, required=None):
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties) if required is None else required,
        "additionalProperties": False,
    }


def array(items=None, maximum=1000):
    return {
        "type": "array",
        "items": {} if items is None else items,
        "maxItems": maximum,
    }


STRING = {"type": "string", "maxLength": 8192}
STRINGS = array(STRING)
UUID = {"type": "string", "format": "uuid"}
HASH = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
TIME = {"type": "string", "format": "date-time"}
NUMBER = {"type": "number", "minimum": 0}
INTEGER = {"type": "integer", "minimum": 0}
IDENTIFIER = {"type": "string", "pattern": "^[a-z0-9_/-]{1,100}$"}
PRODUCER = closed(
    {"execution_id": UUID, "module_id": IDENTIFIER, "operation": IDENTIFIER}
)
PAYLOADS = {
    "urls": {"urls": STRINGS},
    "hosts": {"hosts": STRINGS},
    "exchanges": {"exchange_ids": array(HASH)},
    "runs": {"run_ids": array(UUID)},
    "dns": {
        "name": STRING,
        "resolver": STRING,
        "records": array(
            closed(
                {
                    "name": STRING,
                    "type": STRING,
                    "ttl": INTEGER,
                    "value": STRING,
                }
            )
        ),
        "errors": STRINGS,
    },
    "tls": {
        "host": STRING,
        "port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "subject": {"type": "object"},
        "issuer": {"type": "object"},
        "dns_names": STRINGS,
        "ip_names": STRINGS,
        "not_before": {"anyOf": [STRING, {"type": "null"}]},
        "not_after": {"anyOf": [STRING, {"type": "null"}]},
    },
    "observations": {
        "classification": STRING,
        "items": array(
            closed(
                {
                    "kind": STRING,
                    "subject": STRING,
                    "attributes": {"type": "object"},
                }
            )
        ),
        "source_run_ids": array(UUID),
    },
    "job": {
        "job_id": UUID,
        "state": STRING,
        "profile_id": {"anyOf": [STRING, {"type": "null"}]},
        "run_ids": array(UUID),
        "cleanup_confirmed": {"type": "boolean"},
    },
    "effect": {
        "resource": STRING,
        "action": STRING,
        "changed": {"type": "boolean"},
        "identifiers": STRINGS,
    },
    "inventory": {"resource": STRING, "items": array()},
    "document": {
        "media_type": STRING,
        "text": {"type": "string", "maxLength": 1048576},
        "truncated": {"type": "boolean"},
    },
    "external": {
        "provider": STRING,
        "operation": STRING,
        "records": array(),
        "source_run_ids": array(UUID),
    },
}


def _matches(value, specification):
    try:
        validate(value, specification)
        return True
    except ValueError:
        return False


def _scalar(value, specification):
    if "const" in specification and value != specification["const"]:
        raise ValueError("Unexpected schema constant")
    if "enum" in specification and value not in specification["enum"]:
        raise ValueError("Unexpected schema value")
    if type(value) in {int, float}:
        if not math.isfinite(value):
            raise ValueError("Nonfinite receipt number")
        if value < specification.get("minimum", -math.inf) or value > specification.get(
            "maximum", math.inf
        ):
            raise ValueError("Receipt number outside bounds")
    if isinstance(value, str):
        if len(value) > specification.get("maxLength", 1048576):
            raise ValueError("Receipt string outside bounds")
        if "pattern" in specification and not re.fullmatch(
            specification["pattern"], value
        ):
            raise ValueError("Invalid receipt identifier")
        if specification.get("format") == "uuid" and str(uuid.UUID(value)) != value:
            raise ValueError("Expected canonical receipt UUID")
        if specification.get("format") == "date-time":
            if datetime.fromisoformat(value).tzinfo is None:
                raise ValueError("Receipt timestamp requires timezone")


def validate(value, specification):
    if "anyOf" in specification:
        if not any(_matches(value, option) for option in specification["anyOf"]):
            raise ValueError("Receipt does not match a permitted shape")
    types = {
        "string": (str,),
        "object": (dict,),
        "array": (list,),
        "integer": (int,),
        "number": (int, float),
        "boolean": (bool,),
        "null": (type(None),),
    }
    expected = specification.get("type")
    if expected is not None and type(value) not in types[expected]:
        raise ValueError("Receipt field type differs from schema")
    _scalar(value, specification)
    if isinstance(value, dict):
        properties = specification.get("properties", {})
        if not set(specification.get("required", ())) <= set(value):
            raise ValueError("Missing receipt fields")
        if specification.get("additionalProperties") is False and set(value) - set(
            properties
        ):
            raise ValueError("Unexpected receipt fields")
        for key, item in value.items():
            validate(item, properties.get(key, {}))
    elif isinstance(value, list):
        if len(value) > specification.get("maxItems", 1000):
            raise ValueError("Receipt collection outside bounds")
        for item in value:
            validate(item, specification.get("items", {}))


def artifact_envelope(kind):
    return closed(
        {
            "artifact_id": UUID,
            "kind": {"const": kind},
            "schema_version": {"type": "integer", "const": 1},
            "producer": PRODUCER,
            "sha256": HASH,
            "handoff": {"type": "boolean"},
            "payload": closed(PAYLOADS[kind]),
        }
    )


def policy_schema():
    return closed(
        {
            "mission": STRING,
            "policy_version": STRING,
            "policy_sha256": HASH,
            "actor_revision": {"anyOf": [STRING, INTEGER, {"type": "null"}]},
            "scope_sha256": {"anyOf": [HASH, {"type": "null"}]},
            "verified_at": {"anyOf": [TIME, {"type": "null"}]},
            "checked_at": TIME,
        }
    )


def limits_schema():
    return closed(
        {
            name: {"anyOf": [kind, {"type": "null"}]}
            for name, kind in {
                "requests": INTEGER,
                "seconds": NUMBER,
                "concurrency": INTEGER,
                "requests_per_second": NUMBER,
                "bytes": INTEGER,
            }.items()
        },
        [],
    )


def schema(exit_codes):
    result = closed(
        {
            "schema_version": {"type": "integer", "const": 1},
            "module_id": IDENTIFIER,
            "operation": IDENTIFIER,
            "execution_id": UUID,
            "status": {"type": "string", "enum": list(exit_codes)},
            "exit_code": {"type": "integer", "enum": sorted(set(exit_codes.values()))},
            "started_at": TIME,
            "finished_at": TIME,
            "dry_run": {"type": "boolean"},
            "artifacts": array(
                {"anyOf": [artifact_envelope(kind) for kind in PAYLOADS]}, 100
            ),
            "evidence": array(
                closed({"run_id": UUID, "sha256": HASH, "representation": STRING})
            ),
            "policy": {"anyOf": [policy_schema(), {"type": "null"}]},
            "errors": array(
                closed(
                    {
                        "code": STRING,
                        "message": STRING,
                        "retryable": {"type": "boolean"},
                    }
                )
            ),
            "warnings": STRINGS,
            "metrics": closed(
                {
                    "requests_admitted": {"anyOf": [INTEGER, {"type": "null"}]},
                    "bytes_retained": INTEGER,
                    "elapsed_seconds": NUMBER,
                    "limits": limits_schema(),
                }
            ),
        }
    )
    result.update(
        {
            "$id": "urn:bughunt:result:1",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "anyOf": [
                {
                    "properties": {
                        "status": {"const": status},
                        "exit_code": {"const": code},
                    }
                }
                for status, code in exit_codes.items()
            ],
        }
    )
    return result
