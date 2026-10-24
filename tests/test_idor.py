"""Bounded owned-object body-reference ID-differential for BH-7.

Two owned accounts (owner `A`, second `B`) and an optional anonymous actor; the probe changes one
JSON field from A's own id to B's object id and compares what the origin-bound `--actor A` sees.
Sample ids are owned fixtures, never real targets.
"""

import json

import httpx
import pytest

from bughunt.core import egress, identity, ledger, verification
from bughunt.modules import idor, load_builtin
from bughunt.modules.repeater import parse_raw
from bughunt.console.catalog import group_for
from test_gate import policy
from test_verification import _configure


def _setup(*, array_role=False):
    owner_overrides = {"role_contains": True} if array_role else {}
    _configure("owner", "owner", expected_principal="person-owner", expected_role="owner",
               **owner_overrides)
    _configure("second", "owner", expected_principal="person-second", expected_role="owner")
    _configure("guest", "anonymous", expected_status=401, expected_principal=None, expected_role=None)


def _lab(outcome="secure", *, array_role=False):
    seen = []

    def respond(request):
        authorization = request.headers.get("authorization")
        actor = ("owner" if authorization == "Bearer private-token-owner"
                 else "second" if authorization == "Bearer private-token-second" else "guest")
        body = request.content
        seen.append((actor, request.url.path, request.method, body, dict(request.headers)))
        if request.url.path == "/whoami":
            if actor == "guest":
                return httpx.Response(401)
            role = ["owner", "admin"] if array_role else "owner"
            return httpx.Response(200, json={"user": {"id": "person-" + actor, "role": role}})
        reference = json.loads(body)["ref"]["id"] if body else None
        headers = {"Content-Type": "application/json"}
        if actor == "owner" and reference == "obj-owner":
            return httpx.Response(200, headers=headers, content=b'{"ok":true,"secret":"owner-object"}')
        if outcome == "idor":
            return httpx.Response(200, headers=headers, content=b'{"ok":true,"secret":"second-object"}')
        return httpx.Response(403, headers=headers, content=b'{"error":"denied"}')

    return httpx.MockTransport(respond), seen


def _source(method="GET", body=None, host="allowed.example"):
    body = b'{"ref":{"id":"obj-owner"},"n":1}' if body is None else body
    return (f"{method} https://{host}/records/owned HTTP/1.1\r\nHost: {host}\r\n"
            "Content-Type: application/json\r\nCookie: captured-secret\r\n"
            f"Authorization: captured-token\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body


def _plan(method="GET", body=None, *, anonymous="guest", field="ref.id",
          compare="second/obj-second", array_role=False):
    _setup(array_role=array_role)
    source = _source(method, body)
    return idor.prepare(parse_raw(source), source, actor="owner", compare=compare,
                        field_paths=[field], anonymous=anonymous)


# --------------------------------------------------------------------------------------
# dry-run: the preview lists exactly the planned requests and sends nothing
# --------------------------------------------------------------------------------------

def test_dry_run_previews_exactly_the_planned_requests_and_sends_nothing(policy, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Dry-run reached the network")
    monkeypatch.setattr(egress, "client", forbidden)
    result = idor.preview(_plan())
    assert result["network_requests"] == 0
    assert result["field_path"] == "ref.id"
    assert [(entry["role"], entry["actor"]) for entry in result["planned_requests"]] == [
        ("owner-positive", "owner"), ("compare-negative", "owner"), ("anonymous-negative", "guest")]
    owner_value, compare_value = (entry["value_sha256"] for entry in result["planned_requests"][:2])
    assert owner_value != compare_value  # exactly one field changed, to a distinct id
    assert not ledger.runs_dir().exists()


def test_dry_run_without_an_anonymous_actor_plans_only_owner_and_compare(policy):
    result = idor.preview(_plan(anonymous=None))
    assert [entry["role"] for entry in result["planned_requests"]] == ["owner-positive", "compare-negative"]


# --------------------------------------------------------------------------------------
# execute: the owner-vs-second differential over the bounded set only
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("outcome,expected", [("secure", "negative"), ("idor", "lead")])
def test_execute_sends_only_the_bounded_set_and_computes_owner_vs_second(policy, outcome, expected):
    transport, seen = _lab(outcome)
    result = idor.execute(_plan(), transport=transport)
    assert result["classification"] == expected
    assert result["automatic_finding"] is False
    assert result["positive_control_run_id"]
    targets = [entry for entry in seen if entry[1] == "/records/owned"]
    sent = [(actor, json.loads(body)["ref"]["id"]) for actor, _p, _m, body, _h in targets]
    assert sent == [("owner", "obj-owner"), ("owner", "obj-second"), ("guest", "obj-second")]


def test_execute_honours_array_role_membership_through_the_reused_oracle(policy):
    transport, _seen = _lab("secure", array_role=True)
    result = idor.execute(_plan(array_role=True), transport=transport)
    assert result["classification"] == "negative"  # reached the comparisons: the oracle accepted the array role


def test_execute_bounded_set_is_exactly_owner_positive_and_the_negatives(policy):
    transport, seen = _lab("secure")
    idor.execute(_plan(anonymous=None), transport=transport)
    assert [entry[1] for entry in seen] == ["/whoami", "/records/owned"] * 2


# --------------------------------------------------------------------------------------
# write gate: a potentially-mutating method needs explicit --allow-write under --execute
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_execute_refuses_a_mutating_method_without_allow_write(policy, method):
    transport, seen = _lab("secure")
    plan = _plan(method, anonymous=None)
    with pytest.raises(idor.IdorError, match="may mutate state"):
        idor.execute(plan, transport=transport)
    assert seen == []  # zero outbound: refused before any send
    assert not ledger.runs_dir().exists()


@pytest.mark.parametrize("outcome,expected", [("secure", "negative"), ("idor", "lead")])
def test_execute_runs_a_mutating_method_with_allow_write(policy, outcome, expected):
    transport, seen = _lab(outcome)
    result = idor.execute(_plan("POST", anonymous=None), allow_write=True, transport=transport)
    assert result["classification"] == expected
    targets = [entry for entry in seen if entry[1] == "/records/owned"]
    assert [entry[2] for entry in targets] == ["POST", "POST"]  # the captured method is replayed


def test_dry_run_previews_a_mutating_method_without_allow_write(policy, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Dry-run reached the network")
    monkeypatch.setattr(egress, "client", forbidden)
    result = idor.preview(_plan("POST", anonymous=None))
    assert result["network_requests"] == 0 and result["requires_allow_write"] is True
    assert not ledger.runs_dir().exists()


def test_get_is_read_safe_and_needs_no_allow_write(policy):
    transport, _seen = _lab("secure")
    plan = _plan("GET", anonymous=None)
    assert idor.preview(plan)["requires_allow_write"] is False
    assert idor.execute(plan, transport=transport)["classification"] == "negative"


def test_coerce_like_rejects_a_malformed_integer_id_as_idor_error(policy):
    _setup()
    source = _source(body=b'{"ref":{"id":123}}')
    with pytest.raises(idor.IdorError, match="field-not-scalar-id"):
        idor.prepare(parse_raw(source), source, actor="owner", compare="second/--5",
                     field_paths=["ref.id"])


# --------------------------------------------------------------------------------------
# refusals (the mutation-provable safety bounds) -- each raises before any outbound action
# --------------------------------------------------------------------------------------

def test_refuses_more_than_one_field_path(policy):
    _setup()
    source = _source()
    with pytest.raises(idor.IdorError, match="exactly-one-field-required"):
        idor.prepare(parse_raw(source), source, actor="owner", compare="second/obj-second",
                     field_paths=["ref.id", "n"])


def test_refuses_a_missing_or_invalid_actor(policy):
    _setup()
    source = _source()
    with pytest.raises(idor.IdorError, match="actor-invalid"):
        idor.prepare(parse_raw(source), source, actor="ghost", compare="second/obj-second",
                     field_paths=["ref.id"])


def test_refuses_a_non_owned_id(policy):
    _setup()
    source = _source()
    with pytest.raises(idor.IdorError, match="non-owned-id"):
        idor.prepare(parse_raw(source), source, actor="owner", compare="ghost/obj-second",
                     field_paths=["ref.id"])
    with pytest.raises(idor.IdorError, match="non-owned-id"):  # an anonymous actor owns no object
        idor.prepare(parse_raw(source), source, actor="owner", compare="guest/obj-second",
                     field_paths=["ref.id"])


@pytest.mark.parametrize("unbounded", ["second/1-100", "second/a,b,c", "second/obj*", "second/a..z"])
def test_refuses_an_unbounded_or_range_id(policy, unbounded):
    _setup()
    source = _source()
    with pytest.raises(idor.IdorError, match="unbounded-id"):
        idor.prepare(parse_raw(source), source, actor="owner", compare=unbounded,
                     field_paths=["ref.id"])


@pytest.mark.parametrize("body", [b"", b"not json at all", b'["a","list"]'])
def test_refuses_a_body_less_or_non_json_target(policy, body):
    _setup()
    source = _source(body=body)
    with pytest.raises(idor.IdorError, match="body-not-json"):
        idor.prepare(parse_raw(source), source, actor="owner", compare="second/obj-second",
                     field_paths=["ref.id"])


def test_refuses_a_field_that_is_absent_or_not_a_scalar_id(policy):
    _setup()
    missing = _source(body=b'{"ref":{"other":1}}')
    with pytest.raises(idor.IdorError, match="field-not-found"):
        idor.prepare(parse_raw(missing), missing, actor="owner", compare="second/obj-second",
                     field_paths=["ref.id"])
    container = _source(body=b'{"ref":{"id":{"nested":1}}}')
    with pytest.raises(idor.IdorError, match="field-not-scalar-id"):
        idor.prepare(parse_raw(container), container, actor="owner", compare="second/obj-second",
                     field_paths=["ref.id"])


def test_refuses_when_the_changed_id_equals_the_owner_id(policy):
    _setup()
    source = _source()
    with pytest.raises(idor.IdorError, match="ids-not-distinct"):
        idor.prepare(parse_raw(source), source, actor="owner", compare="second/obj-owner",
                     field_paths=["ref.id"])


# --------------------------------------------------------------------------------------
# origin binding: credentials/companions ride only in-origin
# --------------------------------------------------------------------------------------

def test_actor_credentials_ride_only_on_in_origin_requests(policy):
    transport, seen = _lab("secure")
    idor.execute(_plan(anonymous=None), transport=transport)
    targets = [entry for entry in seen if entry[1] == "/records/owned"]
    assert len(targets) == 2
    for actor, _path, _method, _body, headers in targets:
        assert actor == "owner"  # owner's stored credential was applied
        assert "cookie" not in headers  # the captured cookie was stripped, not forwarded


def test_refuses_a_cross_origin_target_the_actor_does_not_own(policy):
    _setup()
    _document, workspace = policy
    (workspace / "scope.txt").write_text("allowed.example\napi.example\n")
    source = _source(host="api.example")
    with pytest.raises(idor.IdorError, match="actor-origin-mismatch"):
        idor.prepare(parse_raw(source), source, actor="owner", compare="second/obj-second",
                     field_paths=["ref.id"], anonymous=None)


# --------------------------------------------------------------------------------------
# receipts: one sanitized ledger receipt per request; raw ids redacted
# --------------------------------------------------------------------------------------

def test_ledger_receipt_per_request_and_raw_ids_are_redacted(policy):
    transport, _seen = _lab("idor")
    result = idor.execute(_plan(anonymous=None), transport=transport)
    dumped = json.dumps(result)
    assert "obj-owner" not in dumped and "obj-second" not in dumped and "captured-secret" not in dumped
    assert result["cleanup_note"]
    assert len(result["attempts"]) == 2
    for attempt in result["attempts"]:
        manifest = ledger.manifest_for(attempt["run_id"])
        assert manifest["response"] and manifest["verification_run_id"]
        request_text = ledger.export_run(attempt["run_id"])["captures"]["request"]["text"]
        assert "obj-owner" not in request_text and "obj-second" not in request_text


# --------------------------------------------------------------------------------------
# catalog wiring + CLI
# --------------------------------------------------------------------------------------

def test_idor_is_registered_in_the_test_phase(policy):
    assert load_builtin("idor") is idor
    assert group_for("idor") == "Test"


def test_cli_dry_run_is_registered_and_secret_safe(policy, monkeypatch, capsys):
    _setup()
    path = policy[1] / "request.http"
    path.write_bytes(_source())

    def forbidden(*args, **kwargs):
        raise AssertionError("Dry-run sent a request")
    monkeypatch.setattr(egress, "client", forbidden)
    status = idor.main([str(path), "--actor", "owner", "--compare", "second/obj-second",
                        "--field", "ref.id", "--anonymous", "guest"])
    assert status == 0
    output = capsys.readouterr().out
    assert json.loads(output)["network_requests"] == 0
    assert "captured-secret" not in output and "obj-second" not in output
    assert not ledger.runs_dir().exists()
