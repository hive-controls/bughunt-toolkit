"""One cumulative authority, rate and retention bound per active workspace chain."""

from pathlib import Path
import threading
import time
from types import MappingProxyType

from bughunt.core import clock, egress, exchange, identity, workspace
from bughunt.core.pipeline_context import bind as bind, current as current


def _snapshot():
    root = workspace.workspace_dir().resolve()
    hashes = {}
    for name in ("policy.json", "scope.txt"):
        path = root / name
        hashes[name] = exchange.digest(path.read_bytes()) if path.is_file() else None
    return {
        "workspace": str(root),
        "files": hashes,
        "actor": list(identity.selection_signature()),
    }


class Governor:
    def __init__(
        self,
        limits,
        *,
        mission=None,
        deadline=None,
        counters=None,
        authority=None,
        stop_path=None,
        persist=None,
    ):
        from bughunt.core.pipeline import _limits

        self.limits = MappingProxyType(_limits(limits, complete=True))
        self.authority = (
            _snapshot()
            if authority is None
            else exchange.load_json(exchange.canonical(authority))
        )
        self.mission = mission
        self.deadline = (
            time.time() + limits["seconds"] if deadline is None else deadline
        )
        self.monotonic_deadline = clock.now() + min(
            limits["seconds"], max(0, self.deadline - time.time())
        )
        self.stop_path = Path(stop_path) if stop_path is not None else None
        self.cancelled = threading.Event()
        self.lock = threading.RLock()
        self.persist = persist
        counters = counters or {"requests_admitted": 0, "bytes_retained": 0}
        self.requests_admitted = counters["requests_admitted"]
        self.bytes_retained = counters["bytes_retained"]
        self.interval = 1 / self.limits["requests_per_second"]
        self._validate_counters()
        self.next_admission = (
            clock.now() + self.interval if self.requests_admitted else 0.0
        )

    def _validate_counters(self):
        for value, maximum in (
            (self.requests_admitted, self.limits["requests"]),
            (self.bytes_retained, self.limits["bytes"]),
        ):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError("Invalid cumulative pipeline counters")

    def check(self):
        if (
            self.cancelled.is_set()
            or self.stop_path is not None
            and self.stop_path.exists()
        ):
            raise egress.PolicyBlocked("pipeline-cancelled")
        if clock.now() >= self.monotonic_deadline or time.time() >= self.deadline:
            raise egress.PolicyBlocked("pipeline-expired")
        if _snapshot() != self.authority:
            raise egress.PolicyBlocked("pipeline-authority-changed")
        profile = egress.current_profile()
        if (
            profile.freshness() != "verified"
            or self.mission is not None
            and profile.mission != self.mission
        ):
            raise egress.PolicyBlocked("pipeline-policy-not-current")

    def ready(self):
        with self.lock:
            self.check()
            if self.requests_admitted >= self.limits["requests"]:
                raise egress.PolicyBlocked("pipeline-request-cap")
            return clock.now() >= self.next_admission

    def admit(self, target, operation, method, *, recheck=None):
        with self.lock:
            while not self.ready():
                clock.sleep(min(0.01, max(0, self.next_admission - clock.now())))
            if recheck is not None:
                recheck()
            self.check()
            self.requests_admitted += 1
            self.next_admission = clock.now() + self.interval
            self._persist()

    def retain(self, amount):
        if type(amount) is not int or amount < 0:
            raise ValueError("Invalid retained-byte count")
        with self.lock:
            self.check()
            if self.bytes_retained + amount > self.limits["bytes"]:
                raise egress.PolicyBlocked("pipeline-byte-cap")
            self.bytes_retained += amount
            self._persist()

    def retain_receipt(self, amount: int) -> None:
        """Charge a returned receipt without authorizing further producer activity."""
        if type(amount) is not int or amount < 0:
            raise ValueError("Invalid retained-byte count")
        with self.lock:
            if self.bytes_retained + amount > self.limits["bytes"]:
                raise egress.PolicyBlocked("pipeline-byte-cap")
            self.bytes_retained += amount
            self._persist()

    def completed(self, timestamp):
        with self.lock:
            self.next_admission = max(self.next_admission, timestamp + self.interval)

    def _persist(self):
        if self.persist is not None:
            try:
                self.persist(
                    {
                        "requests_admitted": self.requests_admitted,
                        "bytes_retained": self.bytes_retained,
                    }
                )
            except Exception:
                self.cancelled.set()
                raise
