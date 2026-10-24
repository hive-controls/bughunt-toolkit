"""Offline process-edge controls; these are not real-engine acceptance proofs."""

import json
import io
import subprocess
from types import SimpleNamespace
import uuid

import pytest

from bughunt.integrations import zap
import test_workbench_consumer as consumer


class FakeProcess:
    def __init__(self, events, hangs):
        self.events, self.hangs, self.returncode = events, hangs, None

    def poll(self):
        return self.returncode

    def communicate(self, timeout):
        self.events.append("communicate")
        if self.hangs:
            raise subprocess.TimeoutExpired("fixture-cli", timeout)
        self.returncode = 2
        return "", ""

    def terminate(self):
        self.events.append("terminate")
        self.returncode = 2

    def wait(self, timeout):
        self.events.append("wait")
        return self.returncode


def fixture_job(monkeypatch, tmp_path, events, *, source="selected", profile="zap-owned-active"):
    identifier = str(uuid.uuid4())
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    root = tmp_path / "jobs" / identifier
    root.mkdir(parents=True)
    metadata = {"job_id": identifier, "run_id": str(uuid.uuid4()), "engine_profile": profile}
    manifest = {"tool": "zap-active", "analysis": {"profile_id": profile,
        "source_exchange_id": source, "image": zap.SUPPORTED_IMAGE, "actor": "default"}}
    monkeypatch.setattr(consumer.job, "_capture", lambda candidate: (root, metadata, SimpleNamespace(manifest=manifest)))
    monkeypatch.setattr(consumer.job, "cancel", lambda candidate: events.append("cancel:" + candidate))
    return identifier


@pytest.mark.parametrize("hangs", [False, True])
def test_failed_cli_cancels_then_waits_and_reaps_only_the_new_owned_job(monkeypatch, tmp_path, hangs):
    events = []
    identifier = fixture_job(monkeypatch, tmp_path, events)
    monkeypatch.setattr(consumer, "reap_owned_container", lambda candidate: events.append("container:" + candidate))
    consumer.reap_failed_active(FakeProcess(events, hangs), tmp_path, set(), "selected")
    assert events[:2] == ["cancel:" + identifier, "communicate"]
    assert ("terminate" in events) is hangs
    assert events[-1] == "container:" + identifier


@pytest.mark.parametrize("mismatch", ["old", "source", "profile"])
def test_failure_cleanup_does_not_reap_unowned_jobs(monkeypatch, tmp_path, mismatch):
    events = []
    identifier = fixture_job(monkeypatch, tmp_path, events,
        source="other" if mismatch == "source" else "selected",
        profile="zap-passive" if mismatch == "profile" else "zap-owned-active")
    monkeypatch.setattr(consumer, "reap_owned_container", lambda candidate: events.append("container:" + candidate))
    consumer.reap_failed_active(FakeProcess(events, True), tmp_path,
                                {identifier} if mismatch == "old" else set(), "selected")
    assert events == ["communicate", "terminate", "wait"]


@pytest.mark.parametrize("mismatch", [None, "image", "label"])
def test_container_fallback_requires_pinned_image_label_and_exact_removal(monkeypatch, mismatch):
    identifier = str(uuid.uuid4())
    name, calls = "whk012-" + identifier, []
    for key in ("DOCKER_HOST", "DOCKER_CONTEXT"):
        monkeypatch.delenv(key, raising=False)
    def run(arguments, **_options):
        calls.append(arguments)
        if arguments[1] == "context":
            output = "npipe:////./pipe/docker_engine"
        elif arguments[1] == "inspect":
            output = json.dumps([{"Name": "/" + name, "Config": {
                "Image": "other" if mismatch == "image" else zap.SUPPORTED_IMAGE,
                "Labels": {"bughunt.job": "other" if mismatch == "label" else identifier}}}])
        elif arguments[1] == "ps":
            output = "" if any(call[1] == "rm" for call in calls) else name
        else:
            output = ""
        return SimpleNamespace(returncode=0, stdout=output)
    monkeypatch.setattr(consumer.subprocess, "run", run)
    if mismatch:
        with pytest.raises(AssertionError, match="ownership"):
            consumer.reap_owned_container(identifier)
        assert not any(call[1] == "rm" for call in calls)
    else:
        consumer.reap_owned_container(identifier)
        assert [call for call in calls if call[1] == "rm"] == [["docker", "rm", "--force", name]]
        assert calls[-1][1] == "ps"


def test_bad_cli_announcement_still_reaches_owned_job_cleanup(monkeypatch, tmp_path, capsys):
    events, identifiers = [], []
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    def launch(*_arguments, **_options):
        identifiers.append(fixture_job(monkeypatch, tmp_path, events))
        process = FakeProcess(events, False)
        process.stdout, process.stderr = io.StringIO("not-json\n"), io.StringIO("")
        return process
    monkeypatch.setattr(consumer.subprocess, "Popen", launch)
    monkeypatch.setattr(consumer, "reap_owned_container", lambda candidate: events.append("container:" + candidate))
    with pytest.raises(json.JSONDecodeError):
        consumer.cancel_real_active(capsys, SimpleNamespace(wire=[]), "selected")
    assert events == ["cancel:" + identifiers[0], "communicate", "container:" + identifiers[0]]


@pytest.mark.parametrize("edge", ["queue-construction", "reader-construction", "reader-start"])
def test_reader_acquisition_failure_still_reaches_owned_cleanup(monkeypatch, tmp_path, capsys, edge):
    events, identifiers = [], []
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    def launch(*_arguments, **_options):
        identifiers.append(fixture_job(monkeypatch, tmp_path, events))
        process = FakeProcess(events, False)
        process.stdout, process.stderr = io.StringIO(""), io.StringIO("")
        return process
    def broken(*_arguments, **_options):
        raise RuntimeError("fixture-reader-acquisition")
    monkeypatch.setattr(consumer.subprocess, "Popen", launch)
    monkeypatch.setattr(consumer, "reap_owned_container", lambda candidate: events.append("container:" + candidate))
    if edge == "queue-construction":
        monkeypatch.setattr(consumer.queue, "Queue", broken)
    elif edge == "reader-construction":
        monkeypatch.setattr(consumer.threading, "Thread", broken)
    else:
        monkeypatch.setattr(consumer.threading, "Thread", lambda **_options: SimpleNamespace(start=broken, ident=None))
    with pytest.raises(RuntimeError, match="fixture-reader-acquisition"):
        consumer.cancel_real_active(capsys, SimpleNamespace(wire=[]), "selected")
    assert events == ["cancel:" + identifiers[0], "communicate", "container:" + identifiers[0]]


def test_job_discovery_failure_cannot_leave_the_acquired_cli_alive(monkeypatch, tmp_path):
    events = []
    def broken(*_arguments):
        raise RuntimeError("fixture-job-discovery")
    monkeypatch.setattr(consumer, "new_owned_jobs", broken)
    with pytest.raises(RuntimeError, match="fixture-job-discovery"):
        consumer.reap_failed_active(FakeProcess(events, True), tmp_path, set(), "selected")
    assert events == ["terminate", "wait"]


def test_failed_rescan_still_reaps_the_previously_identified_owned_container(monkeypatch, tmp_path):
    events, scans = [], []
    identifier = fixture_job(monkeypatch, tmp_path, events)
    def discover(*_arguments):
        scans.append(True)
        if len(scans) == 1:
            return {identifier}
        raise RuntimeError("fixture-job-rescan")
    monkeypatch.setattr(consumer, "new_owned_jobs", discover)
    monkeypatch.setattr(consumer, "reap_owned_container", lambda candidate: events.append("container:" + candidate))
    with pytest.raises(RuntimeError, match="fixture-job-rescan"):
        consumer.reap_failed_active(FakeProcess(events, False), tmp_path, set(), "selected")
    assert events == ["cancel:" + identifier, "communicate", "container:" + identifier]
