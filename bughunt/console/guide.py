"""Guided walkthrough: the next steps of a hunt, in order, from where you are.

Tier 3 of the console guidance. `plan()` turns the current engagement state
into an ordered list of recommended steps — first any setup gate that is not
yet satisfied (scope, a verified policy, an owned identity), then the hunt
phases in order with a sensible starting module and the reason to run it.
`follow_ons()` names the natural next move after a module, so once a step runs
the console can point at what usually comes next.

These are suggestions. The user still chooses, and the modules themselves
enforce the real scope/policy gates — a step marked ready here only means the
guidance gate is satisfied.
"""

from __future__ import annotations

from dataclasses import dataclass

from bughunt.console import readiness as _readiness


@dataclass(frozen=True)
class Step:
    module: str
    why: str
    ready: bool
    blocked_reason: str = ""


# After this module, these usually come next: (module, why).
CHAINS: dict[str, tuple[tuple[str, str], ...]] = {
    "scope": (("policy", "Authorize test traffic with a verified mission policy."),),
    "policy": (
        ("identity", "Register an owned account if a test will need one."),
        ("scan", "Start mapping the surface."),
    ),
    "identity": (("scan", "Start mapping the surface."),),
    "scan": (
        ("silk", "Spider the endpoints the scan surfaced."),
        ("pulse", "Check which discovered URLs are live."),
    ),
    "silk": (
        ("forms", "Inspect the inputs on an interesting page."),
        ("snare", "Capture traffic while you browse it."),
    ),
    "forms": (
        ("repeater", "Hand-craft and send a request against an input."),
        ("discover", "Probe a few specific hidden inputs."),
    ),
    "repeater": (
        ("replay", "Compare the response across owner, lower-privilege, and anonymous."),
        ("diff", "Diff two responses to see exactly what changed."),
    ),
    "snare": (
        ("clutch", "List what the proxy captured."),
        ("repeater", "Replay a captured request."),
    ),
    "cert": (
        ("mail", "Check the domain's mail posture too."),
        ("dns", "Resolve the domain's records."),
    ),
}

# The starting module for each hunt phase, in hunt order, with the reason.
_HUNT_START: tuple[tuple[str, str, str], ...] = (
    ("Recon", "scan", "Map the host: open ports, live HTTP(S), headers, and intel."),
    ("Capture", "snare", "Record in-scope traffic while you browse the target."),
    ("Test", "repeater", "Probe a captured request by hand."),
)


def plan(readiness: _readiness.Readiness | None = None) -> list[Step]:
    """Ordered recommended steps: unmet setup gates first, then the hunt."""
    state = readiness if readiness is not None else _readiness.gather()
    steps: list[Step] = []
    if not state.scope_ready:
        steps.append(Step("scope", "Declare the hosts you are authorized to test.", True))
    if not state.policy_verified:
        reason = "" if state.scope_ready else "set scope first"
        steps.append(
            Step("policy", "Import and verify a mission policy before any test traffic.", state.scope_ready, reason)
        )
    if not state.has_identity:
        steps.append(Step("identity", "Register an owned account if a test will need one (optional).", True))
    for phase, module, why in _HUNT_START:
        block = state.phase_block(phase)
        steps.append(Step(module, why, block == "", block))
    return steps


def follow_ons(module: str) -> list[tuple[str, str]]:
    """Suggested next moves after a module, as (module, why); empty when none."""
    return list(CHAINS.get(module, ()))
