import json

import pytest

import bughunt
from bughunt.core.pipeline import load_pipeline
from bughunt.core.pipeline_budget import Governor
from bughunt.core.pipeline_store import Journal
from bughunt.core.results import ExecutionContext
from test_gate import policy


def plan():
    return load_pipeline(
        {
            "schema_version": 1,
            "mission": "owned-lab",
            "limits": {
                "requests": 2,
                "seconds": 60,
                "concurrency": 1,
                "requests_per_second": 10,
                "bytes": 100000,
            },
            "steps": [{"id": "read", "module": "scope", "operation": "urls"}],
        }
    )


def test_completed_step_can_be_verified_and_reused(policy):
    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with journal.locked():
        attempt = journal.start_step("read")
        result = bughunt.run_module(
            "scope", operation="urls", context=ExecutionContext(execution_id=attempt)
        )
        journal.finish_step("read", result)
    restored, values = Journal(journal.identifier).restore()
    assert restored.sha256 == selected.sha256
    assert values["read"]["artifacts"] == result.to_dict()["artifacts"]


def test_interrupted_intent_is_not_automatically_replayed(policy):
    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with journal.locked():
        journal.start_step("read")
    with pytest.raises(ValueError, match="indeterminate"):
        Journal(journal.identifier).restore()


def test_modified_step_receipt_blocks_resume(policy):
    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with journal.locked():
        attempt = journal.start_step("read")
        journal.finish_step(
            "read",
            bughunt.run_module(
                "scope",
                operation="urls",
                context=ExecutionContext(execution_id=attempt),
            ),
        )
    receipt = journal.root / "steps" / "read" / "result.json"
    value = json.loads(receipt.read_text())
    value["status"] = "failed"
    receipt.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="receipt"):
        Journal(journal.identifier).restore()


def test_journal_lock_has_one_owner_and_releases_after_exit(policy):
    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with journal.locked():
        with pytest.raises(ValueError, match="owned"):
            with Journal(journal.identifier).locked():
                pytest.fail("Concurrent owner admitted")
    with Journal(journal.identifier).locked():
        pass


def test_event_tail_without_snapshot_commit_blocks_resume(policy):
    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with (journal.root / "events.jsonl").open("ab") as handle:
        handle.write(b'{"uncommitted":"tail"}\n')
    with pytest.raises(ValueError):
        Journal(journal.identifier).restore()


def test_cancellation_persists_stop_and_blocks_restore(policy):
    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    journal.cancel()
    assert (journal.root / "STOP").is_file()
    with pytest.raises(ValueError, match="cancelled"):
        Journal(journal.identifier).restore()


def test_reloaded_steps_follow_declaration_order_not_sorted_keys(policy):
    value = plan().document
    value["steps"] = [
        {"id": identifier, "module": "scope", "operation": "urls"}
        for identifier in ("z_first", "a_second")
    ]
    selected = load_pipeline(value)
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    restored = Journal(journal.identifier)
    with restored.locked():
        restored.start_step("z_first")


def test_completed_resume_preserves_declared_summary_and_final_artifact_order(policy):
    from bughunt.core.pipeline import run_pipeline, resume_pipeline

    value = plan().document
    value["steps"] = [
        {"id": "z_first", "module": "scope", "operation": "list"},
        {"id": "a_final", "module": "scope", "operation": "urls"},
    ]
    original = run_pipeline(value, execute=True)
    assert original.status == "success"
    resumed = resume_pipeline(original.execution_id, execute=True)
    assert resumed.status == "success"
    assert resumed.artifacts[-1].to_dict() == original.artifacts[-1].to_dict()
    assert (
        resumed.artifacts[0].payload["items"] == original.artifacts[0].payload["items"]
    )
    assert [row["id"] for row in resumed.artifacts[0].payload["items"]] == [
        "z_first",
        "a_final",
    ]


def test_cumulative_counter_snapshot_is_bound_to_event_receipt(policy):
    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    path = journal.root / "pipeline.json"
    value = json.loads(path.read_text())
    value["counters"]["requests_admitted"] = 1
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        Journal(journal.identifier).restore()


def test_status_reads_committed_snapshot_while_event_tail_is_incomplete(policy):
    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with journal.locked():
        with (journal.root / "events.jsonl").open("ab") as handle:
            handle.write(b'{"partial":')
        status = Journal(journal.identifier).status()
    assert status["state"] == "planned"
    assert status["steps"] == [{"id": "read", "state": "pending"}]
    assert "plan" not in status and "trusted_inputs" not in status
    with pytest.raises(ValueError):
        Journal(journal.identifier).restore()


def test_receipt_from_another_attempt_cannot_complete_intent(policy):
    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with journal.locked():
        journal.start_step("read")
        unrelated = bughunt.run_module("scope", operation="urls")
        with pytest.raises(ValueError, match="attempt"):
            journal.finish_step("read", unrelated)
    assert not (journal.root / "steps" / "read" / "result.json").exists()


def test_restore_rejects_structurally_invalid_result_even_with_consistent_hash(policy):
    from bughunt.core import exchange

    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with journal.locked():
        attempt = journal.start_step("read")
        journal.finish_step(
            "read",
            bughunt.run_module(
                "scope",
                operation="urls",
                context=ExecutionContext(execution_id=attempt),
            ),
        )
        receipt = journal.root / "steps" / "read" / "result.json"
        value = json.loads(receipt.read_text())
        value["exit_code"] = 130
        receipt.write_bytes(exchange.canonical(value))
        journal.data["steps"]["read"]["result_sha256"] = exchange.digest(
            exchange.canonical(value)
        )
        journal._event("test-corrupt-receipt", {})
    with pytest.raises(ValueError):
        Journal(journal.identifier).restore()


def test_process_exit_releases_lock_but_never_replays_unfinished_intent(policy):
    import subprocess
    import sys

    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    script = (
        "import os,sys; from bughunt.core.pipeline_store import Journal; "
        "journal=Journal(sys.argv[1]); lock=journal.locked(); lock.__enter__(); "
        "journal.start_step('read'); os._exit(7)"
    )
    child = subprocess.run(
        [sys.executable, "-c", script, journal.identifier],
        capture_output=True,
        timeout=20,
    )
    assert child.returncode == 7, child.stderr.decode()
    with Journal(journal.identifier).locked():
        pass
    with pytest.raises(ValueError, match="indeterminate"):
        Journal(journal.identifier).restore()


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"registry_version": True},
        {"state": "invented"},
        {"deadline": "tomorrow"},
        {"deadline": False},
        {"counters": {"requests_admitted": 0, "bytes_retained": 0, "extra": 1}},
        {"steps": {}},
        {"steps": {"read": {"state": "pending", "attempt_id": "unexpected"}}},
        {"steps": {"../escape": {"state": "completed"}}},
        {"state": "success"},
        {"authority": {}},
        {"trusted_inputs": []},
        {
            "trusted_inputs": {
                "../escape": {"path": "/owned", "sha256": "a" * 64, "bytes": 1}
            }
        },
    ],
)
def test_snapshot_shape_is_checked_even_with_matching_event_hash(policy, changes):
    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with journal.locked():
        journal.data.update(changes)
        journal._event("test-invalid-snapshot", {})
    with pytest.raises(ValueError):
        Journal(journal.identifier).restore()
    with pytest.raises(ValueError):
        Journal(journal.identifier).status()


def test_input_path_cannot_be_replaced_by_a_symlink_before_resume(policy, tmp_path):
    raw = tmp_path / "owned.txt"
    raw.write_text("Disallow: /owned\n")
    value = plan().document
    value["steps"] = [
        {
            "id": "read",
            "module": "robots",
            "options": {"inputs": [str(raw)], "no_workspace": True},
        }
    ]
    selected = load_pipeline(value)
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    replacement = tmp_path / "replacement.txt"
    replacement.write_bytes(raw.read_bytes())
    raw.unlink()
    raw.symlink_to(replacement)
    with pytest.raises(ValueError, match="links"):
        Journal(journal.identifier).restore()


@pytest.mark.parametrize(
    "states", [("pending", "running"), ("running", "running"), ("blocked", "running")]
)
def test_consistent_snapshot_cannot_reorder_sequential_steps(policy, states):
    import uuid

    value = plan().document
    value["steps"] = [
        {"id": name, "module": "scope", "operation": "urls"}
        for name in ("first", "later")
    ]
    selected = load_pipeline(value)
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with journal.locked():
        for name, state in zip(("first", "later"), states):
            entry = {"state": state}
            if state != "pending":
                entry["attempt_id"] = str(uuid.uuid4())
            if state == "blocked":
                entry["result_sha256"] = "a" * 64
            journal.data["steps"][name] = entry
        journal.data["state"] = "running"
        journal._event("test-reordered", {})
    with pytest.raises(ValueError, match="order"):
        Journal(journal.identifier).status()


def test_status_rejects_handcrafted_output_plan_even_with_valid_hashes(policy):
    from bughunt.core import exchange

    selected = plan()
    journal = Journal.create(selected, Governor(selected.limits, mission="owned-lab"))
    with journal.locked():
        journal.data["plan"]["steps"][0] = {
            "id": "read",
            "module": "robots",
            "operation": "default",
            "options": {
                "fetch": "https://allowed.example/robots.txt",
                "no_workspace": True,
                "save": "unmetered.txt",
            },
        }
        journal.data["plan_sha256"] = exchange.digest(
            exchange.canonical(journal.data["plan"])
        )
        journal._event("test-unmetered-output", {})
    with pytest.raises(ValueError, match="eligible"):
        Journal(journal.identifier).status()
    with pytest.raises(ValueError):
        Journal(journal.identifier).restore()
