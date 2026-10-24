"""Workspace ownership for a pipeline bound, including its worker threads."""

from contextlib import contextmanager
from contextvars import ContextVar
import threading

from bughunt.core import workspace

_BOUND = ContextVar("bughunt_pipeline_governor", default=None)
_ACTIVE = {}
_ACTIVE_LOCK = threading.Lock()


def current():
    bound = _BOUND.get()
    if bound is not None:
        return bound
    with _ACTIVE_LOCK:
        return next(iter(_ACTIVE.values()), None)


@contextmanager
def bind(governor):
    key = governor.authority["workspace"]
    if str(workspace.workspace_dir().resolve()) != key:
        raise ValueError("Pipeline workspace changed")
    with _ACTIVE_LOCK:
        if _ACTIVE:
            raise ValueError("A pipeline already owns this process workspace")
        _ACTIVE[key] = governor
    token = _BOUND.set(governor)
    try:
        yield governor
    finally:
        _BOUND.reset(token)
        with _ACTIVE_LOCK:
            if _ACTIVE.get(key) is governor:
                del _ACTIVE[key]
