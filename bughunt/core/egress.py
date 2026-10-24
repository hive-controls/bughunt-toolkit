"""Single pre-transport mission-policy decision for HTTP, sockets and processes."""

from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
import asyncio
import inspect
import threading
from urllib.parse import urlsplit

import httpx
import httpcore
from bughunt.core import clock, identity, ledger, pipeline_context

from bughunt.core.policy import PolicyError, Profile, read_document
from bughunt.core.workspace import workspace_dir


class PolicyBlocked(httpx.HTTPError, ValueError):
    """A policy block; no downstream action is authorized."""


def current_profile() -> Profile:
    try:
        return read_document(workspace_dir() / "policy.json")[1]
    except PolicyError as exc:
        raise PolicyBlocked(
            "policy-missing-or-invalid; no outbound action ran"
        ) from exc


def endpoint(host: str, port: int, scheme: str = "https", path: str = "/") -> str:
    authority = f"[{host}]" if ":" in host else host
    return f"{scheme}://{authority}:{port}{path}"


def host_target(host: str, operation: str, port: int | None = None) -> str:
    profile = current_profile()
    candidates = [
        row.origin + "/"
        for row in profile.assets
        if urlsplit(row.origin).hostname == host.lower()
        and (
            port is None
            or (
                urlsplit(row.origin).port
                or (443 if row.origin.startswith("https:") else 80)
            )
            == port
        )
    ]
    for target in candidates:
        if profile.decide(target, operation).permitted:
            return target
    raise PolicyBlocked("host-operation-disallowed; exact origin/root grant required")


def authorize(target: str, operation: str, method: str = "GET") -> Profile:
    profile = current_profile()
    decision = profile.decide(target, operation, method=method)
    if not decision.permitted:
        raise PolicyBlocked(f"{decision.reason}; no outbound action ran")
    return profile


def _actor_signature() -> tuple[str, str, str]:
    try:
        return identity.selection_signature()
    except identity.IdentityError as exc:
        raise PolicyBlocked("actor-missing-or-invalid; no outbound action ran") from exc


def dry_run(
    target: str, operation: str, method: str = "GET", actor: str | None = None
) -> dict:
    try:
        actor = actor or _actor_signature()[1]
        profile = current_profile()
        decision = profile.decide(target, operation, method=method)
        return {
            "target": target,
            "operation": operation,
            "method": method,
            "actor": actor,
            "permitted": decision.permitted,
            "reason": decision.reason,
            "policy_version": profile.policy_version,
            "rate": profile.requests_per_second,
            "concurrency": profile.concurrency,
        }
    except PolicyBlocked:
        return {
            "target": target,
            "operation": operation,
            "method": method,
            "actor": actor or "invalid",
            "permitted": False,
            "reason": "policy-missing-or-invalid",
            "rate": None,
            "concurrency": None,
        }


_lock = threading.Lock()
_budgets: dict[str, list[float]] = {}
_dispatch_locks: dict[str, threading.Lock] = {}
_dispatch_history: dict[str, tuple[float, float]] = {}

# Deny-loop pacing bounds. A wait only spaces the next re-check between denials; the gate
# re-runs check()->authorize()->compare under _lock on every wake, so a wait's duration never
# changes the enforced rate. The cap bounds how stale a queued request's policy/scope view gets
# before the mandatory re-check; the floor keeps a near-elapsed interval from hot-looping
# authorize() (sleep(0) would starve the async loop).
_WAIT_FLOOR = 0.0005
_WAIT_CAP = 0.01


def _bounded_wait(remaining: float) -> float:
    """Clamp a remaining-interval hint to [floor, cap]; a non-positive hint waits the floor."""
    return min(max(remaining, _WAIT_FLOOR), _WAIT_CAP)


def _try_reserve(profile: Profile) -> bool:
    key = str(workspace_dir().resolve())
    governor = pipeline_context.current()
    concurrency = profile.concurrency
    if governor is not None:
        governor.check()
        concurrency = min(concurrency, governor.limits["concurrency"])
    with _lock:
        budget = _budgets.setdefault(key, [0, 0.0])
        now = clock.now()
        if budget[0] >= concurrency or now < budget[1]:
            return False
        budget[0] += 1
        budget[1] = now + 1 / profile.requests_per_second
        return True


def _reserve_delay(profile: Profile) -> float:
    """Bounded wait before a denied reservation is re-checked, computed under _lock from the same
    state _try_reserve's gate used. A concurrency-cap denial has no time target (wait the cap); a
    rate denial waits the remaining fraction of the interval, clamped."""
    key = str(workspace_dir().resolve())
    with _lock:
        budget = _budgets.get(key)
        if budget is None or budget[0] >= profile.concurrency:
            return _WAIT_CAP
        return _bounded_wait(budget[1] - clock.now())


def _release(key: str | None = None) -> None:
    with _lock:
        _budgets[key or str(workspace_dir().resolve())][0] -= 1


class _DispatchLease:
    def __init__(self, key, dispatch_lock, started, interval, governor=None):
        self.key, self.dispatch_lock = key, dispatch_lock
        self.started, self.interval, self.completed = started, interval, None
        self.governor = governor

    def close(self):
        if self.completed is None:
            self.completed = clock.now()
            with _lock:
                _dispatch_history[self.key] = (self.completed, self.interval)
            if self.governor is not None:
                self.governor.completed(self.completed)
            self.dispatch_lock.release()


def _try_dispatch(
    key: str,
    target: str,
    operation: str,
    method: str,
    check,
    commit,
    *,
    wait: float = 0.0,
    physical: bool = True,
):
    from bughunt.core.pipeline_context import current

    governor = current()
    if governor is not None:
        governor.check()
    with _lock:
        dispatch_lock = _dispatch_locks.setdefault(key, threading.Lock())
    acquired = (
        dispatch_lock.acquire(timeout=wait)
        if wait > 0
        else dispatch_lock.acquire(blocking=False)
    )
    if not acquired:
        return None
    lease = None
    try:
        if check is not None:
            check()
        profile = authorize(target, operation, method)
        if physical and governor is not None and not governor.ready():
            return None
        with _lock:
            previous = _dispatch_history.get(key)
            if previous is not None:
                completed, interval = previous
                if clock.now() < completed + max(
                    interval, 1 / profile.requests_per_second
                ):
                    return None
        if physical and governor is not None:
            governor.admit(target, operation, method, recheck=check)
        if commit is not None:
            commit()
        if str(workspace_dir().resolve()) != key:
            raise PolicyBlocked("workspace-changed-before-dispatch")
        if authorize(target, operation, method) != profile:
            raise PolicyBlocked("policy-changed-before-dispatch")
        if physical:
            from bughunt.core import execution_receipts

            try:
                execution_receipts.admit(profile)
            except ValueError as error:
                raise PolicyBlocked("execution-receipt-authority-changed") from error
        dispatched = clock.now()
        lease = _DispatchLease(
            key,
            dispatch_lock,
            dispatched,
            1 / profile.requests_per_second,
            governor if physical else None,
        )
        return lease
    finally:
        if lease is None:
            dispatch_lock.release()


def _dispatch_delay(key: str, profile: Profile) -> float:
    """Bounded wait before a denied dispatch slot is re-checked, computed under _lock from the
    same history _try_dispatch's gate used. A positive remaining spacing is a genuine rate wait
    (clamp to [floor, cap]); a non-positive remaining means the history compare did NOT deny, so
    the denial was a dispatch-lock miss with no time target -- wait the cap, not the floor, so an
    async loser does not poll ~20x faster and worsen loop starvation. No prior completion (first
    slot, or a lock miss with no history) likewise has no time target -- wait the cap."""
    with _lock:
        previous = _dispatch_history.get(key)
        if previous is None:
            return _WAIT_CAP
        completed, interval = previous
        remaining = (
            completed + max(interval, 1 / profile.requests_per_second) - clock.now()
        )
    return _bounded_wait(remaining) if remaining > 0 else _WAIT_CAP


def _dispatch_lease(
    target: str, operation: str, method: str, *, check=None, commit=None, physical=True
):
    key = str(workspace_dir().resolve())
    while True:
        if check is not None:
            check()
        profile = authorize(target, operation, method)
        # Sync path: acquire(timeout=cap) wakes on the holder's release instead of always sleeping
        # the cap. On a lock miss the gap between authorize() re-checks can reach ~2*cap (~20ms: the
        # acquire timeout plus the bounded sleep below) -- not a security hole (admission always
        # re-authorizes under the lock), only a looser revoke-detection bound while queued.
        lease = _try_dispatch(
            key,
            target,
            operation,
            method,
            check,
            commit,
            wait=_WAIT_CAP,
            physical=physical,
        )
        if lease is not None:
            return lease
        clock.sleep(_dispatch_delay(key, profile))


async def _dispatch_lease_async(
    target: str, operation: str, method: str, *, check, commit=None, physical=True
):
    key = str(workspace_dir().resolve())
    while True:
        check()
        profile = authorize(target, operation, method)
        # Async path keeps the non-blocking acquire (never block the loop) and paces re-checks.
        lease = _try_dispatch(
            key, target, operation, method, check, commit, physical=physical
        )
        if lease is not None:
            return lease
        await clock.async_sleep(_dispatch_delay(key, profile))


def pace(
    target: str, operation: str, method: str = "GET", *, check=None, commit=None
) -> float:
    """Pace coarse operation entry; use dispatch() to hold a raw write lease."""
    lease = _dispatch_lease(
        target, operation, method, check=check, commit=commit, physical=False
    )
    lease.close()
    return lease.started


async def _pace_async(
    target: str, operation: str, method: str, *, check, commit=None
) -> float:
    lease = await _dispatch_lease_async(
        target, operation, method, check=check, commit=commit, physical=False
    )
    lease.close()
    return lease.started


def dispatch(
    target: str,
    operation: str,
    method: str,
    callback,
    *,
    check=None,
    commit=None,
    capture=None,
):
    """Invoke one raw write immediately after its shared local dispatch slot."""
    lease = _dispatch_lease(target, operation, method, check=check, commit=commit)
    if capture is not None:
        capture.manifest["dispatch"] = {
            "monotonic": lease.started,
            "clock": clock.FAMILY,
            "basis": "local raw-write invocation; not wire arrival",
        }
    try:
        return callback()
    finally:
        lease.close()
        if capture is not None:
            capture.manifest["dispatch"]["completed_monotonic"] = lease.completed


def authorize_proxy(proxy: str, operation: str) -> None:
    parsed = urlsplit(proxy)
    if not parsed.hostname or parsed.scheme not in {"http", "https", "socks5h"}:
        raise PolicyBlocked("proxy-invalid-or-unsupported")
    if parsed.scheme == "socks5h":
        # The policy row is the http://host:port endpoint identifier; URL credentials never reach it.
        authorize(endpoint(parsed.hostname, parsed.port or 1080, "http"), operation)
        return
    authorize(
        endpoint(
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            parsed.scheme,
        ),
        operation,
    )


def _reserve(target: str, operation: str, method: str, *, check=None) -> Profile:
    while True:
        if check is not None:
            check()
        profile = authorize(target, operation, method)
        if _try_reserve(profile):
            return profile
        clock.sleep(_reserve_delay(profile))


async def _reserve_async(
    target: str, operation: str, method: str, *, check=None
) -> Profile:
    while True:
        if check is not None:
            check()
        profile = authorize(target, operation, method)
        if _try_reserve(profile):
            return profile
        await clock.async_sleep(_reserve_delay(profile))


def _raw_ready(
    profile: Profile,
    signature: tuple,
    targets: tuple,
    operation: str,
    method: str,
    check=None,
) -> None:
    if check is not None:
        check()
    for target in targets:
        if authorize(target, operation, method) != profile:
            raise PolicyBlocked("policy-changed-before-dispatch")
    if _actor_signature() != signature:
        raise PolicyBlocked("actor-changed-before-dispatch")


@contextmanager
def action(target: str, operation: str, method: str = "GET", *, check=None):
    signature = _actor_signature()
    profile = (
        _reserve(target, operation, method)
        if check is None
        else _reserve(target, operation, method, check=check)
    )
    key = str(workspace_dir().resolve())
    capture = None
    try:
        if _actor_signature() != signature:
            raise PolicyBlocked("actor-changed-while-queued; no outbound action ran")
        capture = ledger.begin(
            profile,
            tool=ledger.CURRENT_TOOL.get(),
            operation=operation,
            target=target,
            request=b"",
            actor=signature[1],
        )
        capture.manifest["representation"] = "action-only; no raw exchange captured"
        pace(
            target,
            operation,
            method,
            check=lambda: _raw_ready(
                profile, signature, (target,), operation, method, check
            ),
        )
        yield profile
    except BaseException as exc:
        if capture is not None:
            capture.finish(classification="invalid", error=type(exc).__name__)
        raise
    finally:
        try:
            if capture is not None:
                capture.finish()
        finally:
            _release(key)


def guarded(operation: str, targets):
    """Gate a raw boundary before executing its body, including DNS/process setup."""

    def decorate(function):
        signature = inspect.signature(function)

        def target_list(args, kwargs):
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            selected = tuple(targets(bound.arguments))
            for target in selected:
                authorize(target, operation)
            return selected

        if inspect.iscoroutinefunction(function):

            @wraps(function)
            async def asynchronous(*args, **kwargs):
                selected_targets = target_list(args, kwargs)
                target = selected_targets[0]
                signature = _actor_signature()
                profile = await _reserve_async(target, operation, "GET")
                key = str(workspace_dir().resolve())
                capture = None
                try:
                    if _actor_signature() != signature:
                        raise PolicyBlocked(
                            "actor-changed-while-queued; no outbound action ran"
                        )
                    for selected_target in selected_targets:
                        authorize(selected_target, operation)
                    capture = ledger.begin(
                        profile,
                        tool=function.__module__,
                        operation=operation,
                        target=target,
                        request=b"",
                        actor=signature[1],
                    )
                    capture.manifest["representation"] = (
                        "action-only; no raw exchange captured"
                    )
                    await _pace_async(
                        target,
                        operation,
                        "GET",
                        check=lambda: _raw_ready(
                            profile, signature, selected_targets, operation, "GET"
                        ),
                    )
                    return await function(*args, **kwargs)
                except BaseException as exc:
                    if capture is not None:
                        capture.finish(
                            classification="invalid", error=type(exc).__name__
                        )
                    raise
                finally:
                    try:
                        if capture is not None:
                            capture.finish()
                    finally:
                        _release(key)

            return asynchronous

        @wraps(function)
        def synchronous(*args, **kwargs):
            selected_targets = target_list(args, kwargs)
            with action(selected_targets[0], operation):
                for selected_target in selected_targets:
                    authorize(selected_target, operation)
                return function(*args, **kwargs)

        return synchronous

    return decorate


def _prepare(
    request: httpx.Request,
    operation: str,
    proxy: str | None,
    actor_state: dict | None = None,
) -> Profile:
    if (
        actor_state is not None
        and str(workspace_dir().resolve()) != actor_state["workspace"]
    ):
        raise PolicyBlocked("client-workspace-changed; no outbound action ran")
    profile = authorize(str(request.url), operation, request.method)
    host = request.headers.get("host", "")
    if host and host != request.url.netloc.decode():
        authorize(
            f"{request.url.scheme}://{host}{request.url.raw_path.decode()}",
            operation,
            request.method,
        )
    if proxy:
        authorize_proxy(proxy, operation)
    try:
        actor = identity.apply_request(
            request, strip_default=bool(actor_state and actor_state["named_used"])
        )
        if actor_state is not None and actor != "default":
            actor_state["named_used"] = True
    except identity.IdentityError as exc:
        if "bughunt_require_verified" in request.extensions:
            prior = request.extensions.get(
                "bughunt_actor_snapshot", ("", "default", "")
            )
            ledger.invalid_verification_attempt(
                profile, request, prior[1], "actor-changed"
            )
        raise PolicyBlocked(
            "actor-missing-invalid-or-changed; no outbound action ran"
        ) from exc
    for name, value in profile.required_headers:
        request.headers[name] = value
    request.headers["User-Agent"] = profile.user_agent
    _probe_decision(request, profile)
    _verification_decision(request, profile)
    return profile


def _probe_decision(
    request: httpx.Request, profile: Profile, *, claim: bool = False
) -> bool:
    if "bughunt_verification_probe" not in request.extensions:
        return False
    from bughunt.core import verification

    try:
        return (
            verification.claim_probe(request, profile)
            if claim
            else verification.validate_probe(request, profile)
        )
    except verification.VerificationError as exc:
        actor = request.extensions.get("bughunt_actor_snapshot", ("", "default", ""))[1]
        ledger.invalid_verification_attempt(profile, request, actor, str(exc))
        raise PolicyBlocked(
            "identity-verification-probe-invalid; no outbound action ran"
        ) from exc


def _verification_decision(
    request: httpx.Request, profile: Profile, *, claim: bool = False
) -> None:
    if "bughunt_require_verified" not in request.extensions:
        return
    from bughunt.core import verification

    try:
        run_id = (
            verification.claim_request(request, profile)
            if claim
            else verification.validate_request(request, profile)
        )
        request.extensions["bughunt_verification_run_id"] = run_id
    except verification.VerificationError as exc:
        actor = request.extensions.get("bughunt_actor_snapshot", ("", "default", ""))[1]
        ledger.invalid_verification_attempt(profile, request, actor, str(exc))
        raise PolicyBlocked(
            "identity-verification-invalid; no outbound action ran"
        ) from exc


class _SyncStream(httpx.SyncByteStream):
    def __init__(self, stream, capture):
        self.stream = stream
        self.closed = False
        self.capture, self.complete = capture, False

    def __iter__(self):
        for chunk in self.stream:
            self.capture.feed(chunk)
            yield chunk
        self.complete = True

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.stream.close()
            finally:
                try:
                    self.capture.finish(complete=self.complete)
                finally:
                    _release(str(self.capture.root.parent.parent.resolve()))


async def _off_loop(function, *args, on_cancel=None, **kwargs):
    # Awaited thread offload (copies contextvars). A cancel never abandons a started write:
    # wait for it, then let on_cancel settle its result, so no record is lost or left in_progress.
    task = asyncio.ensure_future(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.wait({task})
            except asyncio.CancelledError:
                pass  # absorb repeat cancels: a started write must still settle
        if on_cancel is not None and not task.cancelled() and task.exception() is None:
            try:
                on_cancel(task.result())
            except Exception:
                pass  # on_cancel's own failure must not mask the CancelledError
        raise


class _AsyncStream(httpx.AsyncByteStream):
    def __init__(self, stream, capture):
        self.stream = stream
        self.closed = False
        self.capture, self.complete = capture, False

    async def __aiter__(self):
        async for chunk in self.stream:
            self.capture.feed(chunk)
            yield chunk
        self.complete = True

    async def aclose(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                await self.stream.aclose()
            finally:
                try:
                    await _off_loop(self.capture.finish, complete=self.complete)
                finally:
                    _release(str(self.capture.root.parent.parent.resolve()))


class _Dispatch:
    def __init__(self, request, profile, operation, proxy, actor_state, capture):
        self.request, self.profile, self.operation = request, profile, operation
        self.proxy, self.actor_state, self.capture = proxy, actor_state, capture
        self.target, self.method = str(request.url), request.method
        self.signature = request.extensions["bughunt_actor_snapshot"]
        self.checks, self.preparations = [], []
        self.used, self.prepared, self.protocol_used = False, False, False
        self.header_lease, self.header_row = None, None

    def _binding(self):
        if (str(self.request.url), self.request.method) != (self.target, self.method):
            raise PolicyBlocked("request-changed-before-dispatch")
        guard = self.request.extensions.get("bughunt_job_guard")
        if guard is not None:
            guard(self.request)
        for check in self.checks:
            check(self.request)
        if authorize(self.target, self.operation, self.method) != self.profile:
            raise PolicyBlocked("policy-changed-before-dispatch")
        if (
            _actor_signature() != self.signature
            or self.request.extensions["bughunt_actor_snapshot"] != self.signature
        ):
            raise PolicyBlocked("actor-changed-before-dispatch")

    def check(self):
        if self.used:
            raise PolicyBlocked("dispatch-context-already-used")
        profile = _prepare(self.request, self.operation, self.proxy, self.actor_state)
        if profile != self.profile:
            raise PolicyBlocked("policy-changed-before-dispatch")
        self._binding()

    def prepare(self):
        if self.prepared:
            raise PolicyBlocked("dispatch-preparation-already-used")
        self.check()
        for prepare in self.preparations:
            prepare(self.request)
        self.check()
        self.prepared = True

    def commit(self):
        _verification_decision(self.request, self.profile, claim=True)
        _probe_decision(self.request, self.profile, claim=True)
        self._binding()
        self.used = True

    def _stamp(self, lease, basis, *, protocol=False):
        row = {"monotonic": lease.started, "clock": clock.FAMILY, "basis": basis}
        if protocol:
            self.capture.manifest.setdefault("protocol_dispatches", []).append(row)
        else:
            self.request.extensions["bughunt_dispatch_monotonic"] = lease.started
            self.capture.manifest["dispatch"] = row
        return row

    def _native_setup(self, transport):
        if httpx.__version__ != "0.28.1" or httpcore.__version__ != "1.0.9":
            raise PolicyBlocked("native-dispatch-version-unsupported")
        pool = getattr(transport, "_pool", None)
        if (
            getattr(pool, "_retries", None) != 0
            or getattr(pool, "_uds", None) is not None
        ):
            raise PolicyBlocked("native-dispatch-retry-or-socket-route-unsupported")
        proxy = getattr(pool, "_proxy_url", None)
        if proxy is not None:
            if proxy.scheme not in {b"http", b"https", b"socks5h"}:
                raise PolicyBlocked("native-dispatch-proxy-unsupported")
            port = proxy.port or {b"https": 443, b"socks5h": 1080}.get(proxy.scheme, 80)
            self.proxy = endpoint(
                proxy.host.decode("ascii"), port, proxy.scheme.decode("ascii")
            )
            authorize_proxy(self.proxy, self.operation)
            self.capture.manifest["route"] = {
                "kind": "socks5h" if proxy.scheme == b"socks5h" else "http-proxy",
                "endpoint": self.proxy.split("://", 1)[1].rstrip("/"),
            }
            if self.preparations and self.request.url.scheme == "https":
                raise PolicyBlocked("managed-proxy-connect-budget-unsupported")
        if self.proxy and self.method == "CONNECT":
            raise PolicyBlocked("nested-proxy-connect-unsupported")

    def _header_kind(self, info):
        request = info.get("request")
        extensions = getattr(request, "extensions", {})
        if extensions.get("bughunt_run_id") != self.capture.manifest["run_id"]:
            raise PolicyBlocked("native-header-dispatch-request-mismatch")
        method = getattr(request, "method", None)
        if method == self.method.encode("ascii"):
            return False
        if method == b"CONNECT" and self.proxy and not self.protocol_used:
            if self.preparations:
                raise PolicyBlocked("managed-proxy-connect-budget-unsupported")
            return True
        raise PolicyBlocked("native-header-dispatch-unexpected")

    def _finish_header(self):
        if self.header_lease is not None:
            self.header_lease.close()
            self.header_row["completed_monotonic"] = self.header_lease.completed
            self.header_lease, self.header_row = None, None

    def _start_header(self, lease, protocol):
        self.header_lease = lease
        self.header_row = self._stamp(
            lease, "native request-header write; not wire arrival", protocol=protocol
        )
        if protocol:
            self.protocol_used = True

    def _native_send(self, transport):
        previous = self.request.extensions.get("trace")

        def traced(event, info):
            if event.endswith(
                (".send_request_headers.complete", ".send_request_headers.failed")
            ):
                self._finish_header()
            if previous is not None:
                result = previous(event, info)
                if inspect.iscoroutine(result):
                    result.close()
                    raise TypeError(
                        "Synchronous native trace callback must be synchronous"
                    )
            if event in {
                "http11.send_request_headers.started",
                "http2.send_request_headers.started",
            }:
                protocol = self._header_kind(info)
                lease = _dispatch_lease(
                    self.target,
                    self.operation,
                    self.method,
                    check=self.check,
                    commit=None if protocol else self.commit,
                )
                self._start_header(lease, protocol)

        self.request.extensions["trace"] = traced
        try:
            response = transport.handle_request(self.request)
            if not self.used:
                response.close()
                raise PolicyBlocked("native-header-dispatch-not-observed")
            return response
        finally:
            self._finish_header()
            self._restore_trace(previous)

    async def _native_send_async(self, transport):
        previous = self.request.extensions.get("trace")

        async def traced(event, info):
            if event.endswith(
                (".send_request_headers.complete", ".send_request_headers.failed")
            ):
                self._finish_header()
            if previous is not None:
                await previous(event, info)
            if event in {
                "http11.send_request_headers.started",
                "http2.send_request_headers.started",
            }:
                protocol = self._header_kind(info)
                lease = await _dispatch_lease_async(
                    self.target,
                    self.operation,
                    self.method,
                    check=self.check,
                    commit=None if protocol else self.commit,
                )
                self._start_header(lease, protocol)

        self.request.extensions["trace"] = traced
        try:
            response = await transport.handle_async_request(self.request)
            if not self.used:
                await response.aclose()
                raise PolicyBlocked("native-header-dispatch-not-observed")
            return response
        finally:
            self._finish_header()
            self._restore_trace(previous)

    def _restore_trace(self, previous):
        if previous is None:
            self.request.extensions.pop("trace", None)
        else:
            self.request.extensions["trace"] = previous

    def send(self, callback):
        self.prepare()
        lease = _dispatch_lease(
            self.target,
            self.operation,
            self.method,
            check=self.check,
            commit=self.commit,
        )
        row = self._stamp(
            lease, "opaque transport admission; no write-spacing assurance"
        )
        lease.close()
        row["completed_monotonic"] = lease.completed
        return callback()

    async def send_async(self, transport):
        if type(transport) is httpx.AsyncHTTPTransport:
            self._native_setup(transport)
            self.prepare()
            return await self._native_send_async(transport)
        self.prepare()
        lease = await _dispatch_lease_async(
            self.target,
            self.operation,
            self.method,
            check=self.check,
            commit=self.commit,
        )
        row = self._stamp(
            lease, "opaque async transport admission; no write-spacing assurance"
        )
        lease.close()
        row["completed_monotonic"] = lease.completed
        return await transport.handle_async_request(self.request)


def prepare_dispatch(request, *, check, commit):
    context = request.extensions.get("bughunt_dispatch_context")
    if not isinstance(context, _Dispatch) or context.request is not request:
        raise PolicyBlocked("guarded-dispatch-context-required")
    context.checks.append(check)
    context.preparations.append(commit)


def dispatch_request(transport, request):
    if isinstance(transport, PreparedTransport):
        return transport.handle_request(request)
    context = request.extensions.pop("bughunt_dispatch_context", None)
    if not isinstance(context, _Dispatch) or context.request is not request:
        raise PolicyBlocked("guarded-dispatch-context-required")
    if type(transport) is httpx.HTTPTransport:
        context._native_setup(transport)
        context.prepare()
        return context._native_send(transport)
    return context.send(lambda: transport.handle_request(request))


class PreparedTransport(httpx.BaseTransport):
    """Keep trusted wrapper preparation before the shared final dispatch slot."""

    def prepare_request(self, request):
        pass

    def finish_response(self, response):
        return response

    def handle_request(self, request):
        self.prepare_request(request)
        return self.finish_response(dispatch_request(self.inner, request))

    def close(self):
        self.inner.close()


class _SyncTransport(httpx.BaseTransport):
    def __init__(self, transport, operation: str, proxy: str | None, actor_state: dict):
        self.transport, self.operation, self.proxy = transport, operation, proxy
        self.actor_state = actor_state

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request.extensions.pop("bughunt_dispatch_monotonic", None)
        initial_profile = _prepare(
            request, self.operation, self.proxy, self.actor_state
        )
        try:
            guard = request.extensions.get("bughunt_job_guard")
            if guard is None:
                _reserve(str(request.url), self.operation, request.method)
            else:
                _reserve(
                    str(request.url),
                    self.operation,
                    request.method,
                    check=lambda: guard(request),
                )
        except PolicyBlocked:
            if "bughunt_require_verified" in request.extensions:
                actor = request.extensions["bughunt_actor_snapshot"][1]
                ledger.invalid_verification_attempt(
                    initial_profile, request, actor, "policy-changed"
                )
            raise
        key = str(workspace_dir().resolve())
        try:
            profile = _prepare(request, self.operation, self.proxy, self.actor_state)
            probe = _probe_decision(request, profile)
            capture = (
                ledger.begin_verification_probe(profile, request, self.operation)
                if probe
                else ledger.begin_http(profile, request, self.operation)
            )
            request.extensions["bughunt_run_id"] = capture.manifest["run_id"]
            request.extensions["bughunt_dispatch_context"] = _Dispatch(
                request, profile, self.operation, self.proxy, self.actor_state, capture
            )
            response = dispatch_request(self.transport, request)
            response.extensions["bughunt_run_id"] = capture.manifest["run_id"]
            if probe:
                response.extensions["bughunt_verification_run_id"] = capture.manifest[
                    "run_id"
                ]
            else:
                capture.response_prefix = ledger.response_head(response)
            if response.is_closed:
                capture.feed(response.content)
                capture.finish()
                _release(key)
            else:
                response.stream = _SyncStream(response.stream, capture)
            return response
        except BaseException as exc:
            try:
                if "capture" in locals():
                    capture.finish(
                        classification="invalid",
                        complete=False,
                        error=type(exc).__name__,
                    )
            finally:
                _release(key)
            raise


class _AsyncTransport(httpx.AsyncBaseTransport):
    def __init__(self, transport, operation: str, proxy: str | None, actor_state: dict):
        self.transport, self.operation, self.proxy = transport, operation, proxy
        self.actor_state = actor_state

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request.extensions.pop("bughunt_dispatch_monotonic", None)
        initial_profile = _prepare(
            request, self.operation, self.proxy, self.actor_state
        )
        try:
            guard = request.extensions.get("bughunt_job_guard")
            if guard is None:
                await _reserve_async(str(request.url), self.operation, request.method)
            else:
                await _reserve_async(
                    str(request.url),
                    self.operation,
                    request.method,
                    check=lambda: guard(request),
                )
        except PolicyBlocked:
            if "bughunt_require_verified" in request.extensions:
                actor = request.extensions["bughunt_actor_snapshot"][1]
                ledger.invalid_verification_attempt(
                    initial_profile, request, actor, "policy-changed"
                )
            raise
        key = str(workspace_dir().resolve())
        try:
            profile = _prepare(request, self.operation, self.proxy, self.actor_state)
            probe = _probe_decision(request, profile)
            begin = ledger.begin_verification_probe if probe else ledger.begin_http
            capture = await _off_loop(
                begin,
                profile,
                request,
                self.operation,
                on_cancel=lambda late: late.finish(
                    classification="invalid", complete=False, error="CancelledError"
                ),
            )
            request.extensions["bughunt_run_id"] = capture.manifest["run_id"]
            dispatch = _Dispatch(
                request, profile, self.operation, self.proxy, self.actor_state, capture
            )
            response = await dispatch.send_async(self.transport)
            response.extensions["bughunt_run_id"] = capture.manifest["run_id"]
            if probe:
                response.extensions["bughunt_verification_run_id"] = capture.manifest[
                    "run_id"
                ]
            else:
                capture.response_prefix = ledger.response_head(response)
            if response.is_closed:
                capture.feed(response.content)
                await _off_loop(capture.finish)
                _release(key)
            else:
                response.stream = _AsyncStream(response.stream, capture)
            return response
        except BaseException as exc:
            try:
                if "capture" in locals():
                    await _off_loop(
                        capture.finish,
                        classification="invalid",
                        complete=False,
                        error=type(exc).__name__,
                    )
            finally:
                _release(key)
            raise


def _wrap(instance, operation: str, proxy: str | None, wrapper):
    # Pinned HTTPX 0.28.1 routes every hop through this seam, including proxy mounts.
    original = instance._transport_for_url
    cache = {}
    signature = _actor_signature()
    actor_state = {"workspace": signature[0], "named_used": signature[1] != "default"}

    def transport_for_url(url):
        transport = original(url)
        if transport not in cache:
            cache[transport] = wrapper(transport, operation, proxy, actor_state)
        return cache[transport]

    instance._transport_for_url = transport_for_url
    instance._bughunt_guarded = True
    return instance


def client(*, operation: str = "manual", **kwargs) -> httpx.Client:
    if isinstance(kwargs.get("transport"), PreparedTransport) and (
        kwargs.get("proxy") or kwargs.get("mounts")
    ):
        raise PolicyBlocked("managed-transport-proxy-or-mount-routing-unsupported")
    kwargs["trust_env"] = False
    return _wrap(httpx.Client(**kwargs), operation, kwargs.get("proxy"), _SyncTransport)


def async_client(*, operation: str = "manual", **kwargs) -> httpx.AsyncClient:
    if isinstance(kwargs.get("transport"), PreparedTransport) and (
        kwargs.get("proxy") or kwargs.get("mounts")
    ):
        raise PolicyBlocked("managed-transport-proxy-or-mount-routing-unsupported")
    kwargs["trust_env"] = False
    return _wrap(
        httpx.AsyncClient(**kwargs), operation, kwargs.get("proxy"), _AsyncTransport
    )
