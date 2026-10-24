"""Engagement readiness: what is set up, and the single next guided step.

The console uses this to tell a newcomer what to do next instead of leaving
them to guess. It reads workspace state only — scope, an imported mission
policy, and owned identities — and every read is defensive: a missing or
unreadable workspace simply reads as "not set up yet". These are guidance
hints; the modules themselves still enforce the real scope/policy gates.
"""

from __future__ import annotations

from dataclasses import dataclass

# Phase titles that cannot send target traffic until scope (and, for active
# tests, a verified policy) is in place. Kept here so the gate stays in one spot.
_NEEDS_SCOPE = {"Recon", "Labs"}
_NEEDS_POLICY = {"Test"}


@dataclass(frozen=True)
class Readiness:
    scope_ready: bool
    policy_verified: bool
    has_identity: bool

    @property
    def can_recon(self) -> bool:
        return self.scope_ready

    @property
    def can_test(self) -> bool:
        return self.scope_ready and self.policy_verified

    def next_step(self) -> tuple[str, str]:
        """(module, message) for the most important next action; module "" means ready."""
        if not self.scope_ready:
            return ("scope", "Start here: declare the hosts you may test — Engagement > scope.")
        if not self.policy_verified:
            return ("policy", "Next: import and verify a mission policy before any test traffic — Engagement > policy.")
        if not self.has_identity:
            return ("identity", "Optional: register an owned account if a test needs one — Engagement > identity.")
        return ("", "Ready to hunt: scope and a verified policy are in place.")

    def phase_block(self, title: str) -> str:
        """Short reason a phase is not ready yet, or "" when it is good to go."""
        if title in _NEEDS_SCOPE and not self.scope_ready:
            return "needs scope" if title == "Recon" else "needs an owned lab in scope"
        if title in _NEEDS_POLICY and not self.can_test:
            return "needs scope" if not self.scope_ready else "needs a verified policy"
        return ""


def gather() -> Readiness:
    return Readiness(_scope_ready(), _policy_verified(), _has_identity())


def _scope_ready() -> bool:
    try:
        from bughunt.core.workspace import scope_is_active

        return bool(scope_is_active())
    except Exception:
        return False


def _policy_verified() -> bool:
    try:
        from bughunt.core.policy import read_document
        from bughunt.modules.policy import policy_path

        path = policy_path()
        if not path.exists():
            return False
        _document, profile = read_document(path)
        return profile.freshness() == "verified"
    except Exception:
        return False


def _has_identity() -> bool:
    try:
        from bughunt.core.identity import list_profiles

        return bool(list_profiles())
    except Exception:
        return False
