import json

import pytest

from bughunt.core.results import Artifact, ModuleOutput, Result, artifact_schema


def test_artifact_hash_covers_sanitized_payload_and_never_grants_redacted_url():
    with pytest.raises(ValueError, match="authority"):
        Artifact.create("urls", {"urls": ["https://user:password@example.test/"]})
    artifact = Artifact.create(
        "document",
        {
            "media_type": "text/plain",
            "text": "https://user:password@example.test/",
            "truncated": False,
        },
    )
    restored = Artifact(**json.loads(json.dumps(artifact.to_dict())))
    assert "password" not in json.dumps(restored.to_dict())
    with pytest.raises(ValueError, match="handoff"):
        restored.select(0)


def test_exchange_ids_are_content_hashes_not_run_uuids():
    artifact = Artifact.create("exchanges", {"exchange_ids": ["a" * 64]})
    assert artifact.select(0) == "a" * 64
    with pytest.raises(ValueError):
        Artifact.create("exchanges", {"exchange_ids": ["wrong"]})


def test_result_returns_typed_data_without_inventing_evidence():
    output = ModuleOutput(
        [Artifact.create("inventory", {"resource": "test", "items": []})]
    )
    result = Result.create("scope", "list", output)
    document = result.to_dict()
    assert document["schema_version"] == 1
    assert document["exit_code"] == 0
    assert document["evidence"] == []
    assert document["artifacts"][0]["payload"]["items"] == []
    assert artifact_schema("inventory")["properties"]["resource"]["type"] == "string"


def test_unknown_artifact_and_nonfinite_output_are_rejected():
    with pytest.raises(ValueError):
        Artifact.create("invented", {})
    with pytest.raises(ValueError):
        Artifact.create("inventory", {"resource": "test", "items": [float("nan")]})


def test_public_artifact_constructor_and_rehashed_reload_validate_authority():
    from bughunt.core import exchange

    payload = {"urls": ["https://user:secret@example.test/"]}
    with pytest.raises(ValueError):
        Artifact(
            kind="urls",
            payload=payload,
            sha256=exchange.digest(exchange.canonical(payload)),
            handoff=True,
        )
    valid = Artifact.create("urls", {"urls": ["https://example.test/"]}).to_dict()
    valid["schema_version"] = 2
    with pytest.raises(ValueError):
        Artifact(**valid)
    valid = Artifact.create("exchanges", {"exchange_ids": ["a" * 64]}).to_dict()
    valid["payload"]["exchange_ids"] = ["00000000-0000-0000-0000-000000000000"]
    valid["sha256"] = exchange.digest(exchange.canonical(valid["payload"]))
    with pytest.raises(ValueError):
        Artifact(**valid)


def test_artifact_payload_cannot_be_changed_after_validation():
    artifact = Artifact.create("urls", {"urls": ["https://example.test/"]})
    artifact.payload["urls"][0] = "https://attacker.test/"
    assert artifact.select(0) == "https://example.test/"


@pytest.mark.parametrize(
    "status,code", [("planned", 0), ("partial", 1), ("blocked", 2), ("cancelled", 130)]
)
def test_exit_mapping_is_explicit(status, code):
    result = Result.create("test", "default", ModuleOutput(status=status))
    assert result.exit_code == code


@pytest.mark.parametrize(
    "field,value",
    [
        ("exit_code", 130),
        ("schema_version", True),
        ("execution_id", "not-a-uuid"),
        ("dry_run", "false"),
        ("started_at", "yesterday"),
        ("errors", [{"code": "test", "message": "test", "retryable": "yes"}]),
        (
            "metrics",
            {
                "requests_admitted": True,
                "bytes_retained": 0,
                "elapsed_seconds": 0,
                "limits": {},
            },
        ),
    ],
)
def test_result_constructor_rejects_invalid_root_fields(field, value):
    from dataclasses import replace

    valid = Result.create("scope", "urls", ModuleOutput())
    with pytest.raises(ValueError):
        replace(valid, **{field: value})


@pytest.mark.parametrize(
    "kind,payload",
    [
        (
            "dns",
            {
                "name": "example.test",
                "resolver": "system",
                "records": [{"type": "A", "value": 123}],
                "errors": [],
            },
        ),
        (
            "observations",
            {
                "classification": "observation",
                "items": [
                    {
                        "kind": "analysis",
                        "subject": "selected",
                        "attributes": {},
                        "unknown": True,
                    }
                ],
                "source_run_ids": [],
            },
        ),
        (
            "tls",
            {
                "host": "example.test",
                "port": 65536,
                "subject": {},
                "issuer": {},
                "dns_names": [],
                "ip_names": [],
                "not_before": None,
                "not_after": None,
            },
        ),
    ],
)
def test_artifact_nested_fields_are_validated(kind, payload):
    with pytest.raises(ValueError):
        Artifact.create(kind, payload)


def test_result_round_trip_binds_artifact_to_actual_producer():
    output = ModuleOutput(
        [Artifact.create("urls", {"urls": ["https://example.test/"]})]
    )
    result = Result.create("scope", "urls", output)
    value = result.to_dict()
    assert value["artifacts"][0]["producer"] == {
        "execution_id": result.execution_id,
        "module_id": "scope",
        "operation": "urls",
    }
    assert Result.from_dict(value).to_dict() == value


def test_mutated_nested_result_field_cannot_be_serialized():
    result = Result.create("scope", "urls", ModuleOutput())
    result.metrics["requests_admitted"] = -1
    with pytest.raises(ValueError):
        result.to_dict()


@pytest.mark.parametrize(
    "status",
    [
        "success",
        "planned",
        "partial",
        "blocked",
        "invalid",
        "unsupported",
        "failed",
        "cancelled",
    ],
)
def test_published_schema_enforces_status_exit_relationship(status):
    from bughunt.core import result_schema
    from bughunt.core.results import EXIT_CODES

    value = Result.create("scope", "list", ModuleOutput(status=status)).to_dict()
    specification = result_schema.schema(EXIT_CODES)
    result_schema.validate(value, specification)
    value["exit_code"] = 130 if value["exit_code"] != 130 else 0
    with pytest.raises(ValueError):
        result_schema.validate(value, specification)
