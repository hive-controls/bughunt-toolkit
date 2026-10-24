import pytest

from bughunt.core import adapters


@pytest.mark.parametrize(
    "module,operation,values,reason",
    [
        ("scan", "default", {}, "raw-dispatch-unmetered"),
        ("snare", "capture", {}, "capture-deadline-unproven"),
        ("snare", "ca", {}, "configuration-mutation"),
        ("race", "run", {}, "requires-concurrency-two"),
        ("replay", "default", {}, "changes-pinned-actor"),
        ("idor", "default", {}, "changes-pinned-actor"),
        (
            "engine",
            "start",
            {"profile_id": "burp-mcp-intake"},
            "child-transport-unmetered",
        ),
        ("engine", "doctor", {"probe": True}, "child-transport-unmetered"),
        ("verify", "configure", {}, "configuration-mutation"),
    ],
)
def test_pipeline_restrictions_match_audited_physical_boundaries(
    module, operation, values, reason
):
    assert adapters.pipeline_restriction(module, operation, values) == reason


def test_finite_watch_is_distinct_from_an_unbounded_listener():
    assert adapters.pipeline_restriction("ioc", "watch", {})
    assert adapters.pipeline_restriction("ioc", "watch", {"polls": 2}) == ""
    assert adapters.pipeline_restriction("ioc", "watch", {"polls": True})
    assert adapters.pipeline_restriction("ioc", "watch", {"polls": -1})


@pytest.mark.parametrize(
    "module,operation,options",
    [
        ("engine", "start", {"profile_id": "zap-passive"}),
        ("engine", "start", {"profile_id": "zap-owned-active"}),
        ("engine", "start", {"profile_id": "browser-owned", "actor": ["default"]}),
        ("zap", "active", {}),
        ("desync", "run", {}),
        ("ws", "capture", {}),
        ("ws", "replay", {}),
    ],
)
def test_pipeline_cannot_execute_unmetered_managed_or_lab_retention(
    module, operation, options
):
    assert (
        adapters.pipeline_restriction(module, operation, options)
        == "managed-retention-unmetered"
    )


@pytest.mark.parametrize(
    "module,operation",
    [("zap", "active"), ("desync", "run"), ("ws", "capture"), ("ws", "replay")],
)
def test_explicit_inert_lab_previews_remain_pipeline_eligible(module, operation):
    assert adapters.pipeline_restriction(module, operation, {"dry_run": True}) == ""


@pytest.mark.parametrize("module", ["exchange", "zap"])
def test_pipeline_export_destinations_cannot_bypass_retention(module):
    assert (
        adapters.pipeline_restriction(module, "export", {"output": "owned-export"})
        == "unmetered-output-destination"
    )
