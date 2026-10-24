import copy
import json

import pytest

from bughunt.core.pipeline import load_pipeline
from test_gate import policy


@pytest.mark.parametrize(
    "module,key",
    [
        ("pulse", "json_out"),
        ("pulse", "csv_out"),
        ("ct", "output"),
        ("ct", "wordlist"),
        ("carve", "save"),
        ("tcurl", "output"),
        ("skiff", "output"),
        ("urlscan", "save"),
        ("urlscan", "output"),
        ("ioc", "export"),
        ("phish", "export"),
        ("phish", "out"),
        ("phish", "log"),
        ("chroma", "out"),
        ("robots", "save"),
        ("silk", "save"),
        ("forms", "save_requests"),
        ("repeater", "save_request"),
        ("repeater", "output"),
    ],
)
def test_pipeline_rejects_unmetered_output_destinations(module, key):
    from bughunt.core import adapters

    assert (
        adapters.pipeline_restriction(
            module, "default", {key: "owned-output", "no_workspace": True}
        )
        == "unmetered-output-destination"
    )


def test_pipeline_allows_stdout_and_requires_explicit_workspace_write_opt_out():
    from bughunt.core import adapters

    assert adapters.pipeline_restriction("tcurl", "default", {"output": "-"}) == ""
    for name in ("robots", "silk"):
        assert (
            adapters.pipeline_restriction(name, "default", {})
            == "workspace-url-write-unmetered"
        )
        assert (
            adapters.pipeline_restriction(name, "default", {"no_workspace": True}) == ""
        )


def test_phish_format_selection_is_inert_but_default_snapshot_writes():
    from bughunt.core import adapters

    assert adapters.pipeline_restriction("phish", "campaign", {"export": "json"}) == ""
    assert (
        adapters.pipeline_restriction("phish", "snapshot", {})
        == "unmetered-output-destination"
    )


def document():
    return {
        "schema_version": 1,
        "mission": "owned-test",
        "limits": {
            "requests": 20,
            "seconds": 60,
            "concurrency": 1,
            "requests_per_second": 2,
            "bytes": 1000000,
        },
        "steps": [
            {"id": "read", "module": "scope", "operation": "urls", "options": {}}
        ],
    }


def test_plan_is_inert_and_step_limits_tighten_whole_chain(tmp_path, monkeypatch):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "absent"))
    value = document()
    value["steps"][0]["limits"] = {
        "requests": 3,
        "seconds": 10,
        "requests_per_second": 1,
    }
    plan = load_pipeline(value)
    assert plan.limits["requests"] == 3
    assert plan.limits["seconds"] == 10
    assert not (tmp_path / "absent").exists()


@pytest.mark.parametrize(
    "change",
    [
        {"authorization": "Bearer inline-secret"},
        {"header": ["Cookie: session=inline-secret"]},
        {"url": "https://user:password@example.test/"},
        {"url": "https://example.test/?token=secret"},
    ],
)
def test_plan_rejects_inline_credentials_before_any_work(change):
    value = document()
    value["steps"][0]["options"] = change
    with pytest.raises(ValueError):
        load_pipeline(value)


@pytest.mark.parametrize(
    "header",
    [
        "X-CSRF-Token",
        "X-XSRF-Token",
        "X-Session-Id",
        "X-Custom-Auth",
        "X-Custom-Secret",
        "Password",
        "Credentials",
    ],
)
def test_custom_credential_headers_rejected_before_journal_persistence(
    policy, tmp_path, header
):
    from bughunt.core.pipeline_budget import Governor
    from bughunt.core.pipeline_store import Journal

    raw = tmp_path / "owned.http"
    raw.write_text("GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
    value = document()
    value["steps"] = [
        {
            "id": "send",
            "module": "repeater",
            "options": {
                "request": str(raw),
                "header": [header + ": owned-credential-marker"],
            },
        }
    ]
    with pytest.raises(ValueError, match="credential"):
        plan = load_pipeline(value)
        Journal.create(plan, Governor(plan.limits))
    assert not (tmp_path / "jobs").exists()
    assert all(
        b"owned-credential-marker" not in path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    )


@pytest.mark.parametrize(
    "assignment",
    [
        "access_token=owned-credential-marker",
        "csrf_token: owned-credential-marker",
        "client_secret=owned-credential-marker",
    ],
)
def test_credential_assignments_cannot_hide_in_arbitrary_option_strings(
    tmp_path, assignment
):
    raw = tmp_path / "owned.http"
    raw.write_text("GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
    value = document()
    value["steps"] = [
        {
            "id": "send",
            "module": "repeater",
            "options": {"request": str(raw), "header": ["X-Owned: " + assignment]},
        }
    ]
    with pytest.raises(ValueError, match="credential"):
        load_pipeline(value)


def test_forward_reference_and_wrong_artifact_type_are_rejected():
    value = document()
    value["steps"][0]["inputs"] = {
        "target": {"step": "later", "artifact": "urls", "index": 0}
    }
    with pytest.raises(ValueError):
        load_pipeline(value)
    value = document()
    value["steps"].append(
        {
            "id": "test",
            "module": "discover",
            "options": {},
            "inputs": {"exchange_id": {"step": "read", "artifact": "runs", "index": 0}},
        }
    )
    with pytest.raises(ValueError):
        load_pipeline(value)


def test_input_file_becomes_private_trusted_reference_with_immutable_digest(tmp_path):
    raw = tmp_path / "request.http"
    raw.write_text("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    value = document()
    value["steps"] = [
        {
            "id": "capture",
            "module": "exchange",
            "operation": "import-raw",
            "options": {"request": str(raw), "source_id": "owned"},
        }
    ]
    plan = load_pipeline(value)
    assert str(raw) not in json.dumps(plan.document)
    assert next(iter(plan.trusted_inputs.values()))["sha256"]
    raw.write_text("changed")
    with pytest.raises(ValueError):
        plan.verify_inputs()


def test_unknown_keys_and_nonsequential_concurrency_are_rejected():
    value = document()
    value["command"] = "execute arbitrary process"
    with pytest.raises(ValueError):
        load_pipeline(value)
    value = document()
    value["limits"]["concurrency"] = 2
    with pytest.raises(ValueError):
        load_pipeline(value)


@pytest.mark.parametrize(
    "limits",
    [
        {"requests": True},
        {"requests": 0},
        {"requests": 101},
        {"seconds": float("inf")},
        {"seconds": 301},
        {"bytes": 0},
        {"requests_per_second": 0},
        {"unknown": 1},
    ],
)
def test_invalid_limits_fail_before_plan_creation(limits):
    value = document()
    value["limits"].update(limits)
    with pytest.raises(ValueError):
        load_pipeline(value)


def test_plan_documents_and_input_metadata_are_defensive_copies(tmp_path):
    value = document()
    plan = load_pipeline(value)
    value["limits"]["requests"] = 99
    plan.document["limits"]["requests"] = 99
    plan.limits["requests"] = 99
    assert plan.limits["requests"] == 20


def test_duplicate_json_keys_are_rejected(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError):
        load_pipeline(path)


def test_nested_or_unknown_option_is_not_an_execution_language():
    value = document()
    value["steps"][0]["options"] = {"command": {"eval": "anything"}}
    with pytest.raises(ValueError):
        load_pipeline(value)


def test_declared_file_input_cannot_change_via_metadata_copy(tmp_path):
    raw = tmp_path / "request.http"
    raw.write_text("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    value = document()
    value["steps"] = [
        {
            "id": "capture",
            "module": "exchange",
            "operation": "import-raw",
            "options": {"request": str(raw), "source_id": "owned"},
        }
    ]
    plan = load_pipeline(value)
    reference = next(iter(plan.trusted_inputs))
    plan.trusted_inputs[reference]["sha256"] = "invalid"
    plan.verify_inputs()
    assert plan.trusted_inputs[reference]["sha256"] != "invalid"


def test_plan_hash_commits_to_input_bytes(tmp_path):
    raw = tmp_path / "request.http"
    raw.write_text("first owned input")
    value = document()
    value["steps"] = [
        {
            "id": "capture",
            "module": "exchange",
            "operation": "import-raw",
            "options": {"request": str(raw), "source_id": "owned"},
        }
    ]
    before = load_pipeline(value)
    assert raw.name not in repr(before)
    raw.write_text("second owned input")
    after = load_pipeline(value)
    assert before.sha256 != after.sha256


@pytest.mark.parametrize(
    "raw",
    [
        "schema_version: [",
        "a: &a [*a]",
        "schema_version: !!int 1",
        "schema_version: 1\nschema_version: 1",
        "a: {<<: {key: value}}",
    ],
)
def test_yaml_rejects_malformed_duplicate_alias_tag_or_merge(tmp_path, raw):
    path = tmp_path / "plan.yaml"
    path.write_text(raw)
    with pytest.raises(ValueError):
        load_pipeline(path)


def test_yaml_matches_json_plan(tmp_path):
    import yaml

    value = document()
    path = tmp_path / "plan.yaml"
    path.write_text(yaml.safe_dump(value))
    assert load_pipeline(path).sha256 == load_pipeline(value).sha256


def test_file_list_inputs_are_sealed_individually_and_preserve_order(tmp_path):
    from bughunt.core.pipeline_store import _restore_plan
    from bughunt.core.pipeline_runner import _options

    files = [tmp_path / name for name in ("second.txt", "first.txt")]
    for index, path in enumerate(files):
        path.write_text(f"Disallow: /owned-{index}\n")
    value = document()
    value["steps"] = [
        {
            "id": "read",
            "module": "robots",
            "options": {"inputs": [str(path) for path in files], "no_workspace": True},
        }
    ]
    selected = load_pipeline(value)
    assert len(selected.trusted_inputs) == 2
    assert all(str(path) not in json.dumps(selected.document) for path in files)
    restored = _restore_plan(selected.document, selected.trusted_inputs)
    paths = {
        identifier: metadata["path"]
        for identifier, metadata in restored.trusted_inputs.items()
    }
    assert _options(restored.document["steps"][0], {}, paths)["inputs"] == [
        str(path) for path in files
    ]
    files[1].write_text("changed")
    with pytest.raises(ValueError, match="changed"):
        selected.verify_inputs()


def test_file_list_total_byte_limit_is_cumulative(tmp_path):
    files = [tmp_path / f"{index}.txt" for index in range(2)]
    for path in files:
        path.write_bytes(b"x" * 600000)
    value = document()
    value["steps"] = [
        {
            "id": "read",
            "module": "robots",
            "options": {"inputs": [str(path) for path in files], "no_workspace": True},
        }
    ]
    with pytest.raises(ValueError, match="total input size"):
        load_pipeline(value)


def test_native_limits_tighten_chain_before_first_step():
    value = document()
    value["steps"].append(
        {
            "id": "discover",
            "module": "discover",
            "options": {
                "exchange_id": "a" * 64,
                "requests": 8,
                "seconds": 12,
                "header": ["X-Owned"],
            },
        }
    )
    selected = load_pipeline(value)
    assert selected.limits["requests"] == 8
    assert selected.limits["seconds"] == 12


def test_native_default_limits_are_part_of_chain():
    value = document()
    value["limits"]["requests"] = 100
    value["steps"] = [
        {
            "id": "discover",
            "module": "discover",
            "options": {"exchange_id": "a" * 64, "header": ["X-Owned"]},
        }
    ]
    assert load_pipeline(value).limits["requests"] == 30


def test_browser_profile_native_default_uses_curated_profile_identifier():
    from bughunt.integrations.browser_actor import PROFILE_ID

    value = document()
    value["limits"]["requests"] = 100
    value["steps"] = [
        {
            "id": "browser",
            "module": "engine",
            "operation": "dry-run",
            "options": {
                "profile_id": PROFILE_ID,
                "exchange_id": ["http://127.0.0.1/"],
                "mission": "owned-test",
                "actor": ["default"],
                "owned_lab": True,
            },
        }
    ]
    assert load_pipeline(value).limits["requests"] == 20


@pytest.mark.parametrize(
    "selection",
    [
        {"indices": []},
        {"indices": [0, 0]},
        {"indices": [True]},
        {"indices": list(range(33))},
        {"index": 0, "indices": [0]},
        {"indices": [1000]},
        {"indices": "0"},
    ],
)
def test_set_reference_selection_is_explicit_unique_and_bounded(selection):
    value = document()
    value["steps"].append(
        {
            "id": "capture",
            "module": "exchange",
            "operation": "import-run",
            "options": {"run_id": "a" * 64},
        }
    )
    value["steps"].append(
        {
            "id": "flow",
            "module": "exchange",
            "operation": "flow",
            "inputs": {
                "exchange_ids": {
                    "step": "capture",
                    "artifact": "exchanges",
                    **selection,
                }
            },
        }
    )
    with pytest.raises(ValueError):
        load_pipeline(value)
