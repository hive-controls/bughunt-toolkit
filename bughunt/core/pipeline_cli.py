"""Explicit pipeline commands and the declarative input schema."""

from bughunt.core.pipeline import run_pipeline, resume_pipeline
from bughunt.core.results import Artifact, ModuleOutput, Result


def _object(properties, required=None):
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(properties) if required is None else required,
    }


def _limit_schema(*, complete):
    properties = {
        "requests": {"type": "integer", "minimum": 1, "maximum": 100},
        "seconds": {"type": "number", "exclusiveMinimum": 0, "maximum": 300},
        "concurrency": {"type": "integer", "const": 1},
        "requests_per_second": {"type": "number", "exclusiveMinimum": 0},
        "bytes": {"type": "integer", "minimum": 1, "maximum": 16777216},
    }
    return _object(properties, None if complete else [])


def pipeline_schema():
    identifier = {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$"}
    reference = _object(
        {
            "step": identifier,
            "artifact": {"enum": ["urls", "hosts", "exchanges"]},
            "index": {"type": "integer", "minimum": 0, "maximum": 999},
            "indices": {
                "type": "array",
                "minItems": 1,
                "maxItems": 32,
                "uniqueItems": True,
                "items": {"type": "integer", "minimum": 0, "maximum": 999},
            },
        },
        ["step", "artifact"],
    )
    reference["oneOf"] = [{"required": ["index"]}, {"required": ["indices"]}]
    scalar = {"type": ["string", "boolean", "integer", "number", "null"]}
    step = _object(
        {
            "id": identifier,
            "module": {"type": "string", "minLength": 1},
            "operation": {"type": "string", "default": "default"},
            "options": {
                "type": "object",
                "additionalProperties": {
                    "anyOf": [
                        scalar,
                        {"type": "array", "maxItems": 1000, "items": scalar},
                    ]
                },
            },
            "inputs": {"type": "object", "additionalProperties": reference},
            "limits": _limit_schema(complete=False),
        },
        ["id", "module"],
    )
    schema = _object(
        {
            "schema_version": {"type": "integer", "const": 1},
            "mission": identifier,
            "limits": _limit_schema(complete=True),
            "steps": {"type": "array", "minItems": 1, "maxItems": 32, "items": step},
        }
    )
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["description"] = (
        "Sequential inert plan. Module options, backward artifact references, "
        "input hashes and current authority are additionally validated at runtime."
    )
    return schema


def cli_result(words):
    if len(words) == 2 and words[0] in {"validate", "dry-run", "run"}:
        return run_pipeline(words[1])
    if len(words) == 3 and words[0] in {"run", "resume"}:
        if words[2] != "--execute":
            raise ValueError("Pipeline execution requires --execute")
        function = run_pipeline if words[0] == "run" else resume_pipeline
        return function(words[1], execute=True)
    if len(words) == 2 and words[0] in {"status", "cancel"}:
        from bughunt.core.pipeline_store import Journal

        journal = Journal(words[1])
        value = journal.status()
        if words[0] == "cancel":
            journal.cancel()
            value["cancel_requested"] = True
        artifact = Artifact.create(
            "inventory", {"resource": "pipeline", "items": [value]}
        )
        return Result.create("pipeline", words[0], ModuleOutput([artifact]))
    raise ValueError(
        "Expected validate/dry-run FILE, run/resume TARGET --execute, or status/cancel ID"
    )
