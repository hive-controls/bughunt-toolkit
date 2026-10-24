"""Readiness guidance logic: the next step and per-phase gates."""

from bughunt.console import readiness
from bughunt.console.readiness import Readiness


def test_nothing_set_up_starts_at_scope():
    state = Readiness(scope_ready=False, policy_verified=False, has_identity=False)
    module, message = state.next_step()
    assert module == "scope"
    assert "scope" in message.lower()
    assert state.phase_block("Recon") == "needs scope"
    assert state.phase_block("Test") == "needs scope"
    assert state.phase_block("Labs") == "needs an owned lab in scope"
    # Offline phases are never gated.
    assert state.phase_block("Capture") == ""
    assert state.phase_block("Intel") == ""
    assert state.phase_block("Engagement") == ""


def test_scope_without_policy_blocks_tests_not_recon():
    state = Readiness(scope_ready=True, policy_verified=False, has_identity=False)
    module, _message = state.next_step()
    assert module == "policy"
    assert state.can_recon is True
    assert state.can_test is False
    assert state.phase_block("Recon") == ""
    assert state.phase_block("Test") == "needs a verified policy"
    assert state.phase_block("Labs") == ""


def test_scope_and_policy_ready_suggests_identity_then_clears():
    state = Readiness(scope_ready=True, policy_verified=True, has_identity=False)
    assert state.can_test is True
    assert state.next_step()[0] == "identity"
    assert all(state.phase_block(title) == "" for title in ("Recon", "Test", "Labs"))

    full = Readiness(scope_ready=True, policy_verified=True, has_identity=True)
    module, message = full.next_step()
    assert module == ""
    assert "ready" in message.lower()


def test_gather_is_defensive_without_a_workspace(tmp_path, monkeypatch):
    # No scope/policy/identity set up: every reader degrades to False, never raises.
    monkeypatch.setattr(readiness, "_scope_ready", lambda: False)
    monkeypatch.setattr(readiness, "_policy_verified", lambda: False)
    monkeypatch.setattr(readiness, "_has_identity", lambda: False)
    state = readiness.gather()
    assert isinstance(state, Readiness)
    assert state.next_step()[0] == "scope"
