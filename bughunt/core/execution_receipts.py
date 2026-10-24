"""Context-scoped measurements from actual admissions and evidence writes."""

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import threading

from bughunt.core import exchange, identity, pipeline_context, policy, workspace

_COLLECTORS = ContextVar("bughunt_execution_receipts", default=())


def _authority(profile):
    root = workspace.workspace_dir()
    raw = (root / "policy.json").read_bytes()
    if policy.parse_profile(exchange.load_json(raw)) != profile:
        raise ValueError("Policy changed before admission receipt")
    scope = root / "scope.txt"
    return {
        "mission": profile.mission,
        "policy_version": profile.policy_version,
        "policy_sha256": exchange.digest(raw),
        "actor_revision": identity.selection_signature()[2],
        "scope_sha256": exchange.digest(scope.read_bytes())
        if scope.is_file()
        else None,
        "verified_at": profile.verified_at.isoformat(),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


class Measurements:
    def __init__(self):
        self.lock = threading.RLock()
        self.requests = 0
        self.files = {}
        self.policy = None
        self.mixed_authority = False
        self.incomplete_admissions = False
        governor = pipeline_context.current()
        self.limits = dict(governor.limits) if governor is not None else {}

    def admitted(self, profile, receipt):
        with self.lock:
            self.requests += 1
            previous = self.policy
            if previous is None:
                self.policy = receipt
            elif any(
                previous[key] != value
                for key, value in receipt.items()
                if key != "checked_at"
            ):
                self.mixed_authority = True
            for key, value in {
                "concurrency": profile.concurrency,
                "requests_per_second": profile.requests_per_second,
            }.items():
                self.limits[key] = min(self.limits.get(key, value), value)

    def retained(self, path, amount):
        with self.lock:
            self.files[str(path.resolve())] = amount

    def metrics(self, elapsed):
        with self.lock:
            return {
                "requests_admitted": None
                if self.incomplete_admissions
                else self.requests,
                "bytes_retained": sum(self.files.values()),
                "elapsed_seconds": elapsed,
                "limits": dict(self.limits),
            }

    def authority(self):
        with self.lock:
            return (
                None
                if self.mixed_authority or self.incomplete_admissions
                else self.policy
            )


@contextmanager
def collect():
    measurement = Measurements()
    token = _COLLECTORS.set((*_COLLECTORS.get(), measurement))
    try:
        yield measurement
    finally:
        _COLLECTORS.reset(token)


def admit(profile):
    collectors = _COLLECTORS.get()
    if not collectors:
        return
    receipt = _authority(profile)
    for collector in collectors:
        collector.admitted(profile, receipt)


def retain(path, amount):
    for collector in _COLLECTORS.get():
        collector.retained(path, amount)


def child_admission_observer():
    collectors = _COLLECTORS.get()
    if not collectors:
        return None
    profile = policy.read_document(workspace.workspace_dir() / "policy.json")[1]
    pinned = _authority(profile)

    def admitted(*, incomplete=False):
        if incomplete:
            for collector in collectors:
                with collector.lock:
                    collector.incomplete_admissions = True
            return
        try:
            current = _authority(profile)
            changed = any(
                current[key] != value
                for key, value in pinned.items()
                if key != "checked_at"
            )
        except (OSError, ValueError):
            changed = True
        for collector in collectors:
            with collector.lock:
                collector.mixed_authority |= changed
                collector.admitted(profile, pinned)

    return admitted
