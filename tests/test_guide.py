"""The guided walkthrough: ordered plan and follow-on chains."""

from bughunt.console import guide
from bughunt.console.readiness import Readiness


def _modules(steps):
    return [s.module for s in steps]


def test_nothing_set_up_leads_with_the_three_setup_gates():
    steps = guide.plan(Readiness(scope_ready=False, policy_verified=False, has_identity=False))
    # Setup gates come first, in order, then the hunt starts.
    assert _modules(steps)[:3] == ["scope", "policy", "identity"]
    by_module = {s.module: s for s in steps}
    assert by_module["scope"].ready is True
    # Policy cannot be done until scope exists.
    assert by_module["policy"].ready is False
    assert by_module["policy"].blocked_reason == "set scope first"
    # Recon is gated on scope; Capture is never gated.
    assert by_module["scan"].ready is False and by_module["scan"].blocked_reason == "needs scope"
    assert by_module["snare"].ready is True


def test_scope_set_unblocks_policy_and_recon():
    steps = guide.plan(Readiness(scope_ready=True, policy_verified=False, has_identity=False))
    by_module = {s.module: s for s in steps}
    assert by_module["policy"].ready is True and by_module["policy"].blocked_reason == ""
    assert by_module["scan"].ready is True
    # Test still needs a verified policy.
    assert by_module["repeater"].ready is False
    assert by_module["repeater"].blocked_reason == "needs a verified policy"


def test_fully_ready_skips_setup_and_opens_the_hunt():
    steps = guide.plan(Readiness(scope_ready=True, policy_verified=True, has_identity=True))
    mods = _modules(steps)
    # No setup gates left; the plan is the hunt phases, all ready.
    assert mods == ["scan", "snare", "repeater"]
    assert all(s.ready for s in steps)


def test_follow_ons_are_curated_and_safe_for_unknowns():
    assert [m for m, _why in guide.follow_ons("scan")] == ["silk", "pulse"]
    assert guide.follow_ons("nonexistent-module") == []
    # Every chain target names a why.
    for _module, chain in guide.CHAINS.items():
        assert all(why for _next, why in chain)
