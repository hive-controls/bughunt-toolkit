"""Pytest plugin: emulate the CPython <=3.12 Windows ``time.monotonic`` coarse clock.

On Windows, CPython <=3.12 backed ``time.monotonic()`` with ``GetTickCount64``, whose resolution is
~15.625 ms (the default system timer tick, 1000/64 ms). CPython 3.13 switched ``monotonic`` to QPC
(sub-microsecond), so modern dev boxes -- and this repo's ubuntu / 3.14 CI legs -- never see the
coarse clock locally. The GetTickCount64 clock-tie flake class (two reads inside one 15.625 ms tick
comparing equal) therefore only reproduces on the windows-latest 3.12 CI leg, which is a slow place
to discover it.

This plugin floors ``time.monotonic`` to 15.625 ms steps process-wide so the coarse clock can be
exercised on ANY machine, surfacing timing-fragile tests before windows-latest does. It is a
diagnostic / CI-gate aid and is OFF BY DEFAULT: it patches the clock ONLY when the environment
variable ``BUGHUNT_TEST_COARSE_CLOCK=1`` is set. With the variable unset the plugin is completely
inert -- so ``python -m pytest`` behaves identically whether or not the plugin is loaded.

``time.perf_counter`` is deliberately NOT floored: on real 3.12 Windows it is QPC (fine) too, so the
egress clock seam (which PR-1 moved onto ``perf_counter``) stays fine under emulation, exactly as it
would on the real 3.12 runner. Flooring it would misrepresent the target environment.

Run it::

    BUGHUNT_TEST_COARSE_CLOCK=1 python -m pytest -p coarse_clock_plugin

(from the repo root, so the plugin module is importable via the current directory).
"""
from __future__ import annotations

import math
import os
import time

ENV_FLAG = "BUGHUNT_TEST_COARSE_CLOCK"
TICK_SECONDS = 0.015625  # GetTickCount64 default resolution: 1000 / 64 ms.

_REAL_MONOTONIC = time.monotonic


def _coarse_monotonic() -> float:
    """Floor the real monotonic clock to GetTickCount64-sized steps."""
    return math.floor(_REAL_MONOTONIC() / TICK_SECONDS) * TICK_SECONDS


def _enabled() -> bool:
    return os.environ.get(ENV_FLAG) == "1"


def pytest_configure(config) -> None:
    if not _enabled():
        return
    native = time.get_clock_info("monotonic")
    time.monotonic = _coarse_monotonic
    print(
        f"\n[coarse-clock] {ENV_FLAG}=1: time.monotonic floored to {TICK_SECONDS * 1000:.3f} ms "
        f"(emulating CPython<=3.12 Windows GetTickCount64). "
        f"Native monotonic resolution here: {native.resolution * 1000:.6f} ms. "
        f"time.perf_counter left untouched (fine, as on real 3.12 Windows)."
    )


def pytest_unconfigure(config) -> None:
    if not _enabled():
        return
    time.monotonic = _REAL_MONOTONIC
