"""Offline intake contracts; fake MCP clients provide lifecycle-only PROXY evidence."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import httpx
import pytest

from bughunt.core import exchange, job, ledger
from bughunt.integrations import burp_intake as intake, burp_profile
from test_gate import policy


@pytest.fixture
def configured(policy, monkeypatch):
    files, hashes = {}, {}
    for role, name in burp_profile.NAMES.items():
        path = policy[1] / role / name
        path.parent.mkdir()
        path.write_bytes(role.encode())
        files[role], hashes[role] = str(path), exchange.digest(role.encode())
    monkeypatch.setattr(burp_profile, "FINGERPRINTS", hashes)
    monkeypatch.setattr(sys, "executable", os.path.realpath(sys.executable))
    value = {"schema_version": 1, "endpoint": "http://127.0.0.1:9876", "versions": burp_profile.VERSIONS,
             "files": files, "tools_sha256": burp_profile.TOOLS_SHA256}
    path = policy[1] / "burp-mcp.json"
    path.write_bytes(exchange.canonical(value))
    monkeypatch.setattr(burp_profile, "listener", lambda _profile: {"address": "127.0.0.1", "port": 9876, "pid": 1234})
    return path


def plan(configured, **options):
    return intake.prepare(mission="owned-lab", url="https://allowed.example/a", source_id="owned-source",
                          config=configured, **options)


def history_item():
    return {"request": "GET /a HTTP/1.1\r\nHost: allowed.example\r\nCookie: fixture-cookie\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "notes": "fixture-note"}


class FakeClient:
    def __init__(self, url, *, deadline, check):
        check()
        self.check = check
        self.receipts = {"1": b"{}", "2": b"{}"}
        self.closed = False

    def handshake(self, expected):
        self.check()
        return {"connected": True, "tools_sha256": expected, "tool_allowlist": ["get_proxy_http_history"]}

    def history(self, count, offset):
        self.check()
        value = {"content": [{"type": "text", "text": json.dumps(history_item())}], "isError": False, "_meta": {}}
        self.receipts["3"] = exchange.canonical({"jsonrpc": "2.0", "id": 3, "result": value})
        return value

    def close(self):
        self.closed = True
        return True


@pytest.mark.parametrize("options", [{"count": 0}, {"count": 11}, {"count": True}, {"offset": -1},
    {"offset": 501}, {"offset": True}, {"seconds": 0}, {"seconds": 121},
    {"seconds": True}, {"seconds": float("nan")}, {"seconds": 1.5}])
def test_invalid_selection_bounds_block_before_process(configured, options):
    with pytest.raises(ValueError):
        plan(configured, **options)


def test_preview_inert_zero_sends_and_preserves_burp_missing_state(configured, monkeypatch):
    value = plan(configured)
    monkeypatch.setattr(intake.burp_mcp, "Client", lambda *_args, **_kwargs: pytest.fail("Preview launched a bridge"))
    preview = intake.preview(value)
    assert preview["inert"] and not preview["process_launch"] and preview["request_cap"] == 0
    with pytest.raises(ValueError):
        value.budget.admit(httpx.Request("GET", "https://allowed.example/a"))
    assert not value.budget.stop_path().parent.exists()


def test_import_is_explicitly_incomplete_and_linked_to_one_original_job(configured, monkeypatch):
    monkeypatch.setattr(intake.burp_mcp, "Client", FakeClient)
    value = plan(configured)
    initial = []
    result = intake.run(value, on_start=lambda identifier: initial.append(job.status(identifier)))
    assert result["state"] == "success" and result["classification"] == "observation"
    assert result["cleanup_confirmed"] and result["admitted_count"] == 0 and result["incomplete_count"] == 1
    assert initial[0]["run_id"] == result["run_id"] and initial[0]["state"] == "starting"
    record = exchange.read(result["exchange_ids"][0])
    assert record["request"]["truncated"] and record["response"]["truncated"]
    assert record["sources"][0]["captured_at"] is None and record["sources"][0]["actor"] is None
    assert record["sources"][0]["run_id"] == result["run_id"]
    assert record["sources"][0]["sha256"] == exchange.digest((value.budget.stop_path().parent / "source.json").read_bytes())
    assert job.status(value.budget.job_id) == result
    assert ledger.export_run(result["run_id"])["manifest"]["job_state"] == "success"


@pytest.mark.parametrize("failure", ["denied", "malformed", "oversized", "missing-burp", "cancel", "deadline", "policy", "drift"])
def test_intake_failures_are_retained_without_replay_authority(configured, policy, monkeypatch, failure):
    value = plan(configured)
    class FailingClient(FakeClient):
        def history(self, count, offset):
            result = super().history(count, offset)
            if failure == "denied":
                result["content"][0]["text"] = "HTTP history access denied by Burp Suite"
            elif failure == "malformed":
                result["content"][0]["text"] = "not-json"
            elif failure == "oversized":
                result["content"][0]["text"] = "x" * (intake.burp_transport.LIMIT + 1)
            elif failure == "cancel":
                job.cancel(value.budget.job_id)
            elif failure == "deadline":
                value.budget.deadline = time.monotonic() - 1
            elif failure == "policy":
                (policy[1] / "policy.json").unlink()
            elif failure == "drift":
                configured.write_bytes(b"changed-profile")
            if failure != "oversized":
                self.receipts["3"] = exchange.canonical({"jsonrpc": "2.0", "id": 3, "result": result})
            return result
    monkeypatch.setattr(intake.burp_mcp, "Client", FailingClient)
    if failure == "missing-burp":
        monkeypatch.setattr(burp_profile, "listener", lambda _profile: (_ for _ in ()).throw(ValueError("missing")))
    result = intake.run(value)
    assert result["classification"] == "inconclusive" and not result["exchange_ids"]
    assert result["state"] == ("cancelled" if failure == "cancel" else "failed")
    assert result["cleanup_confirmed"] and result["admitted_count"] == 0
    assert job.status(value.budget.job_id) == result


@pytest.mark.parametrize("change", ["source", "unicode", "schema", "no-response"])
def test_unknown_source_or_encoding_is_quarantined_or_incomplete(configured, monkeypatch, change):
    class ChangedClient(FakeClient):
        def history(self, count, offset):
            item = history_item()
            if change == "source":
                item["request"] = item["request"].replace("/a ", "/other ")
            elif change == "unicode":
                item["response"] += "é"
            elif change == "schema":
                item["uninspected-field"] = True
            else:
                item["response"] = "<no response>"
            result = {"content": [{"type": "text", "text": json.dumps(item)}], "isError": False, "_meta": {}}
            self.receipts["3"] = exchange.canonical({"jsonrpc": "2.0", "id": 3, "result": result})
            return result
    monkeypatch.setattr(intake.burp_mcp, "Client", ChangedClient)
    result = intake.run(plan(configured))
    assert result["cleanup_confirmed"] and result["admitted_count"] == 0
    assert result["incomplete_count"] == (1 if change == "no-response" else 0)
    assert result["quarantined_count"] == (0 if change == "no-response" else 1)
    assert result["state"] == ("success" if change == "no-response" else "partial")


def test_default_exchange_views_and_job_exports_do_not_emit_cookie(configured, monkeypatch):
    monkeypatch.setattr(intake.burp_mcp, "Client", FakeClient)
    result = intake.run(plan(configured))
    record = exchange.read(result["exchange_ids"][0])
    public = json.dumps([job.status(result["job_id"]), ledger.export_run(result["run_id"]), exchange.project(record)])
    assert "fixture-cookie" not in public


def test_common_cli_and_doctor_are_inert_until_authorized_start(configured, monkeypatch, capsys):
    from bughunt.modules import engine as command
    monkeypatch.setattr(intake.burp_mcp, "Client", lambda *_args, **_kwargs: pytest.fail("Inert CLI launched"))
    assert command.main(["doctor", "burp-mcp-intake", "--config", str(configured)]) == 0
    doctor = json.loads(capsys.readouterr().out)
    assert doctor["configured"] and not doctor["connected"] and not doctor["request_execution"]
    assert command.main(["dry-run", "burp-mcp-intake", "https://allowed.example/a", "--mission", "owned-lab",
                         "--source-id", "owned-source", "--config", str(configured)]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["inert"] and preview["count"] == 1 and preview["request_cap"] == 0


def test_job_parent_reparse_point_is_rejected_before_writing(configured, monkeypatch):
    value = plan(configured)
    parent = value.budget.stop_path().parent.parent
    parent.mkdir()
    original = Path.lstat
    def redirected(path, *arguments, **options):
        metadata = original(path, *arguments, **options)
        if path == parent:
            return SimpleNamespace(st_mode=metadata.st_mode, st_file_attributes=0x400)
        return metadata
    monkeypatch.setattr(Path, "lstat", redirected)
    monkeypatch.setattr(intake.burp_mcp, "Client", FakeClient)
    with pytest.raises(ValueError):
        intake.run(value)
    assert not value.budget.stop_path().parent.exists()


@pytest.mark.parametrize("stage", ["announcement", "history"])
def test_keyboard_interrupt_finishes_cancelled_receipt_and_cleanup(configured, monkeypatch, stage):
    value = plan(configured)
    clients, announced = [], []
    class InterruptedClient(FakeClient):
        def __init__(self, *arguments, **options):
            super().__init__(*arguments, **options)
            clients.append(self)
        def history(self, count, offset):
            raise KeyboardInterrupt
    def announce(identifier):
        announced.append(job.status(identifier))
        if stage == "announcement":
            raise KeyboardInterrupt
    monkeypatch.setattr(intake.burp_mcp, "Client", InterruptedClient)
    try:
        result = intake.run(value, on_start=announce)
    except KeyboardInterrupt:
        pytest.fail("Ctrl-C escaped without a terminal job receipt")
    assert result["state"] == "cancelled" and result["classification"] == "inconclusive"
    assert result["cleanup_confirmed"] and not result["exchange_ids"] and result["admitted_count"] == 0
    assert all(client.closed for client in clients) and len(clients) == (stage == "history")
    assert announced[0]["run_id"] == result["run_id"] and announced[0]["state"] == "starting"
    assert job.status(value.budget.job_id) == result
    assert ledger.export_run(result["run_id"])["manifest"]["job_state"] == "cancelled"


def test_announcement_failure_finishes_failed_receipt_before_launch(configured, monkeypatch):
    value = plan(configured)
    def announce(_identifier):
        raise RuntimeError("Owned unavailable output stream")
    monkeypatch.setattr(intake.burp_mcp, "Client", lambda *_args, **_kwargs: pytest.fail("Failed announcement launched bridge"))
    try:
        result = intake.run(value, on_start=announce)
    except RuntimeError:
        pytest.fail("Announcement failure escaped without a terminal job receipt")
    assert result["state"] == "failed" and result["classification"] == "inconclusive" and result["cleanup_confirmed"]
    assert not result["exchange_ids"] and result["admitted_count"] == 0 and job.status(value.budget.job_id) == result


@pytest.mark.parametrize("interrupts", [1, 2])
def test_cleanup_interrupt_retries_once_and_finishes_receipt(configured, monkeypatch, interrupts):
    clients, previous = [], signal.getsignal(signal.SIGINT)
    class InterruptedCleanup(FakeClient):
        def __init__(self, *arguments, **options):
            super().__init__(*arguments, **options)
            self.attempts = 0
            clients.append(self)
        def close(self):
            self.attempts += 1
            if self.attempts <= interrupts:
                raise KeyboardInterrupt
            return super().close()
    monkeypatch.setattr(intake.burp_mcp, "Client", InterruptedCleanup)
    value = plan(configured)
    try:
        result = intake.run(value, probe=True)
    except KeyboardInterrupt:
        pytest.fail("Cleanup interruption escaped without a terminal receipt")
    assert clients[0].attempts == 2 and clients[0].closed == (interrupts == 1)
    assert result["state"] == ("cancelled" if interrupts == 1 else "failed")
    assert result["classification"] == "inconclusive" and result["cleanup_confirmed"] == (interrupts == 1)
    assert not result["exchange_ids"] and result["admitted_count"] == 0
    assert job.status(value.budget.job_id) == result
    assert ledger.export_run(result["run_id"])["manifest"]["job_state"] == result["state"]
    assert signal.getsignal(signal.SIGINT) == previous


@pytest.mark.parametrize("stage", ["artifact", "receipt", "failure"])
def test_finalization_defers_sigint_and_restores_handler(configured, monkeypatch, stage):
    previous = signal.getsignal(signal.SIGINT)
    monkeypatch.setattr(intake.burp_mcp, "Client", FakeClient)
    write, finish = ledger._write_private, job.finish_engine
    def interrupted_write(path, raw):
        if stage == "artifact" and path.name == "rpc-1.json":
            signal.raise_signal(signal.SIGINT)
        return write(path, raw)
    def interrupted_finish(*arguments, **options):
        if stage == "failure":
            raise RuntimeError("Owned simulated receipt storage failure")
        if stage == "receipt":
            signal.raise_signal(signal.SIGINT)
        return finish(*arguments, **options)
    monkeypatch.setattr(ledger, "_write_private", interrupted_write)
    monkeypatch.setattr(job, "finish_engine", interrupted_finish)
    value = plan(configured)
    if stage == "failure":
        with pytest.raises(RuntimeError):
            intake.run(value, probe=True)
    else:
        try:
            result = intake.run(value, probe=True)
        except KeyboardInterrupt:
            pytest.fail("Finalization SIGINT escaped without a terminal receipt")
        assert result["state"] == ("cancelled" if stage == "artifact" else "success")
        assert result["cleanup_confirmed"] and job.status(value.budget.job_id) == result
        assert ledger.export_run(result["run_id"])["manifest"]["job_state"] == result["state"]
    assert signal.getsignal(signal.SIGINT) == previous


@pytest.mark.parametrize("stage", ["handler", "job-start"])
def test_interrupt_ownership_precedes_job_and_process_resources(configured, monkeypatch, stage):
    value, clients = plan(configured), []
    previous, original_signal = signal.getsignal(signal.SIGINT), signal.getsignal
    def create_client(*arguments, **options):
        clients.append(True)
        return FakeClient(*arguments, **options)
    monkeypatch.setattr(intake.burp_mcp, "Client", create_client)
    if stage == "handler":
        calls = []
        def acquire_handler(number):
            if not calls:
                calls.append(True)
                signal.raise_signal(signal.SIGINT)
            return original_signal(number)
        monkeypatch.setattr(signal, "getsignal", acquire_handler)
        with pytest.raises(KeyboardInterrupt):
            intake.run(value, probe=True)
        assert not value.budget.stop_path().parent.exists(), "Interrupted handler acquisition left owned job resources"
    else:
        start = job.start_engine
        def interrupted_start(*arguments, **options):
            signal.raise_signal(signal.SIGINT)
            return start(*arguments, **options)
        monkeypatch.setattr(job, "start_engine", interrupted_start)
        try:
            result = intake.run(value, probe=True)
        except KeyboardInterrupt:
            pytest.fail("Job setup interruption escaped before a terminal receipt")
        assert result["state"] == "cancelled" and result["cleanup_confirmed"]
        assert job.status(value.budget.job_id) == result
        assert ledger.export_run(result["run_id"])["manifest"]["job_state"] == "cancelled"
    assert not clients and original_signal(signal.SIGINT) == previous


@pytest.mark.parametrize("mode", ["lock-held", "notify-reentry"])
def test_signal_callback_does_not_acquire_cancellation_locks(mode):
    """Owned isolated signal probe; lock-window timing is PROXY, no engine or target."""
    program = f"""
import signal, sys, threading
from types import SimpleNamespace
sys.path.insert(0, {str(Path(__file__).absolute().parent.parent)!r})
from bughunt.integrations import burp_intake
budget = SimpleNamespace(cancelled=threading.Event(), operator_interrupted=False)
mode, notifications = {mode!r}, []
original = budget.cancelled._cond.notify_all
def notify():
    if not notifications:
        notifications.append(True)
        signal.raise_signal(signal.SIGINT)
    return original()
if mode == 'notify-reentry':
    budget.cancelled._cond.notify_all = notify
with burp_intake._interrupt_owner(budget) as setup:
    if setup is not None:
        setup[1].set()
    if mode == 'lock-held':
        with budget.cancelled._cond:
            signal.raise_signal(signal.SIGINT)
            signal.raise_signal(signal.SIGINT)
    else:
        signal.raise_signal(signal.SIGINT)
        budget.cancelled.set()
    assert budget.operator_interrupted
assert mode != 'notify-reentry' or notifications == [True]
print('signal-safe')
"""
    try:
        result = subprocess.run([sys.executable, "-I", "-B", "-c", program], capture_output=True,
            timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        pytest.fail("Signal callback deadlocked; isolated diagnostic was killed and reaped")
    assert result.returncode == 0 and result.stdout.strip() == b"signal-safe", result.stderr.decode(errors="replace")


def inspect_path_boundary(operation, path, configured):
    if operation == "doctor":
        result = intake.doctor(config=path)
        assert not result["available"] and not result["configured"]
        return
    with pytest.raises((OSError, ValueError)):
        if operation == "private":
            burp_profile.private_file(path, 1024)
        elif operation == "fingerprint":
            burp_profile.fingerprint(path)
        else:
            burp_profile.stamps({"files": {"burp": str(path)}}, configured)


@pytest.mark.parametrize("value", ["//outside.invalid/share/burpsuite.jar", "//?/UNC/outside.invalid/share/burpsuite.jar",
    "//?/C:/burpsuite.jar", "//./C:/burpsuite.jar"])
@pytest.mark.parametrize("operation", ["private", "fingerprint", "doctor", "stamps"])
def test_unc_and_device_paths_block_before_any_path_metadata(configured, monkeypatch, value, operation):
    path, touched = Path(value), []
    original_lstat, original_stat = Path.lstat, Path.stat
    def inspect(candidate, original, *arguments, **options):
        if str(candidate).replace("\\", "/").startswith("//"):
            touched.append(str(candidate))
            raise OSError("Owned intercepted remote metadata boundary")
        return original(candidate, *arguments, **options)
    with monkeypatch.context() as guard:
        guard.setattr(Path, "lstat", lambda candidate, *args, **kwargs: inspect(candidate, original_lstat, *args, **kwargs))
        guard.setattr(Path, "stat", lambda candidate, *args, **kwargs: inspect(candidate, original_stat, *args, **kwargs))
        inspect_path_boundary(operation, path, configured)
    assert not touched, "Rejected source contacted an UNC/device metadata boundary"


@pytest.mark.skipif(burp_profile.sys.platform != "win32", reason="Windows device namespace control")
@pytest.mark.parametrize("mapping", [r"\Device\Mup\owned-model", r"\Device\LanmanRedirector\owned-model",
    r"\??\UNC\owned-model\share", r"\??\C:\substituted", r"\Device\Unknown"])
@pytest.mark.parametrize("operation", ["private", "fingerprint", "doctor", "stamps"])
def test_nonlocal_drive_mapping_blocks_before_filesystem_metadata(configured, monkeypatch, mapping, operation):
    touched = []
    def mapping_query(drive, output, maximum):
        assert drive == configured.drive and maximum == 4096
        output.value = mapping
        return len(mapping) + 2
    def inspect(candidate, *_arguments, **_options):
        touched.append(str(candidate))
        raise OSError("Owned intercepted mapped-drive metadata boundary")
    with monkeypatch.context() as guard:
        guard.setattr(burp_profile.ctypes, "WinDLL", lambda *_args, **_kwargs: SimpleNamespace(QueryDosDeviceW=mapping_query))
        guard.setattr(Path, "lstat", inspect)
        guard.setattr(Path, "stat", inspect)
        inspect_path_boundary(operation, configured, configured)
    assert not touched, "Nonlocal device classification happened after filesystem inspection"


def test_unc_component_is_blocked_even_before_invalid_policy(configured, policy, monkeypatch):
    profile = exchange.load_json(configured.read_bytes())
    profile["files"]["burp"] = "//outside.invalid/share/burpsuite.jar"
    configured.write_bytes(exchange.canonical(profile))
    (policy[1] / "policy.json").write_bytes(b"invalid-policy")
    touched, original = [], Path.lstat
    def inspect(path, *arguments, **options):
        if str(path).replace("\\", "/").startswith("//"):
            touched.append(str(path))
            raise OSError("Owned intercepted component metadata boundary")
        return original(path, *arguments, **options)
    monkeypatch.setattr(Path, "lstat", inspect)
    with pytest.raises((OSError, ValueError)):
        plan(configured)
    assert not touched


@pytest.mark.parametrize("name", ["CON", "NUL.txt", "COM1.jar", "burp.jar:stream", "../burpsuite.jar",
    "CON .txt", "NUL .json", "COM1 .jar", "CONIN$", "CONOUT$"])
def test_reserved_device_stream_and_parent_paths_block_before_metadata(configured, monkeypatch, name):
    path, touched = configured.parent / name, []
    def inspect(candidate, *_arguments, **_options):
        touched.append(str(candidate))
        raise OSError("Owned intercepted lexical boundary")
    with monkeypatch.context() as guard:
        guard.setattr(Path, "lstat", inspect)
        guard.setattr(Path, "stat", inspect)
        inspect_path_boundary("private", path, configured)
    assert not touched


@pytest.mark.parametrize("operation", ["private", "fingerprint", "stamps"])
def test_redirected_parent_blocks_before_child_metadata(configured, monkeypatch, operation):
    touched, original_lstat, original_stat = [], Path.lstat, Path.stat
    parent = configured.parent
    def inspect(path, original, *arguments, **options):
        if path == configured:
            touched.append(str(path))
            raise OSError("Owned intercepted redirected child boundary")
        metadata = original(path, *arguments, **options)
        if path == parent:
            return SimpleNamespace(st_mode=metadata.st_mode, st_file_attributes=0x400)
        return metadata
    with monkeypatch.context() as guard:
        guard.setattr(Path, "lstat", lambda path, *args, **kwargs: inspect(path, original_lstat, *args, **kwargs))
        guard.setattr(Path, "stat", lambda path, *args, **kwargs: inspect(path, original_stat, *args, **kwargs))
        inspect_path_boundary(operation, configured, configured)
    assert not touched


def test_redirected_job_parent_blocks_before_probing_child(configured, monkeypatch):
    value = plan(configured)
    parent = value.budget.stop_path().parent.parent
    parent.mkdir()
    touched, original_lstat, original_stat = [], Path.lstat, Path.stat
    def inspect(path, original, *arguments, **options):
        if path.is_relative_to(parent) and path != parent:
            touched.append(str(path))
            raise OSError("Owned intercepted redirected job child")
        metadata = original(path, *arguments, **options)
        if path == parent:
            return SimpleNamespace(st_mode=metadata.st_mode, st_file_attributes=0x400)
        return metadata
    monkeypatch.setattr(Path, "lstat", lambda path, *args, **kwargs: inspect(path, original_lstat, *args, **kwargs))
    monkeypatch.setattr(Path, "stat", lambda path, *args, **kwargs: inspect(path, original_stat, *args, **kwargs))
    original_exists, original_islink = os.path.exists, os.path.islink
    def probe(candidate, original):
        path = Path(candidate)
        if path.is_relative_to(parent) and path != parent:
            touched.append(str(path))
            raise OSError("Owned intercepted accelerated child probe")
        return original(candidate)
    monkeypatch.setattr(os.path, "exists", lambda path: probe(path, original_exists))
    monkeypatch.setattr(os.path, "islink", lambda path: probe(path, original_islink))
    with pytest.raises((OSError, ValueError)):
        intake.run(value)
    assert not touched
