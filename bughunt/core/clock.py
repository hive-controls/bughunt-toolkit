"""Single monotonic clock seam for egress pacing state.

Every egress rate/dispatch pacing read goes through ``now()``, backed by
``time.perf_counter()`` rather than ``time.monotonic()``. On CPython <= 3.12 Windows
``time.monotonic()`` is ``GetTickCount64`` (15.625 ms resolution), so two pacing reads
inside one tick compare equal and the strict ``<`` gate denies on a spurious tie;
``time.perf_counter()`` is the high-resolution QPC clock on every platform, which makes
the gate's elapsed comparison faithful. The waits (``sleep``/``async_sleep``) only pace
re-checks between denials; the gate re-runs under its lock on every wake, so a wait's
duration never widens or narrows the enforced rate.

This is a self-contained seam (stdlib ``time``/``asyncio`` only) so egress stays on one
clock family. ``FAMILY`` labels the family stamped into each dispatch row.
"""

from __future__ import annotations

import asyncio
import time

FAMILY = "perf_counter"


def now() -> float:
    """High-resolution monotonic read for rate/dispatch pacing state."""
    return time.perf_counter()


def sleep(seconds: float) -> None:
    """Bounded blocking wait between pacing re-checks (sync path)."""
    time.sleep(seconds)


async def async_sleep(seconds: float) -> None:
    """Bounded cooperative wait between pacing re-checks (async path)."""
    await asyncio.sleep(seconds)
