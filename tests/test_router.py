"""S1 action-type Router. Complexity tiering is gone."""
import ast
import json
from pathlib import Path

import pytest

import octo.governor as governor_mod
import octo.router as router_mod
from octo.governor import FULL_ACTIONS, Governor, LOCAL_ACTIONS, POLICY, ROUTES, Denied
from octo.router import (
    N9_MIN,
    N9_MINIMAL_SAFETY_PRECHECK,
    S1_STANDARD_ACTIONS,
    S1_STANDARD_NODES,
    RouteDecision,
    is_n9_precheck,
    route,
    signal_upgrade,
)

GRANT = "grant-ref-s1-test"
FORBIDDEN_STATUSES = (
    "DEGRADED_SKIP_N6N7",
    "DEGRADED_SKIP_N6",
    "DEGRADED_SKIP_N7",
    "DEGRADED_SKIP",
)


def _assert_clean(decision: RouteDecision) -> None:
    blob = json.dumps(decision.to_dict())
    for token in FORBIDDEN_STATUSES:
        assert decision.status != token
        assert token not in blob
    assert "N6" not in decision.nodes
    assert "N7" not in decision.nodes
    assert decision.executed_nodes == ()
    assert "output" not in decision.to_dict()


def test_internal_readonly_routes_s1_standard_sequence():
    decision = route({"action_type": "internal_readonly", "grant_ref": GRANT})
    assert decision.status == "OK"
    assert decision.code == "ROUTED_STANDARD"
    assert decision.tier == "Standard"
    assert decision.execution_authorized is True
    assert decision.nodes == S1_STANDARD_NODES
    assert decision.nodes == (
        "N1",
        "N2",
        "N3",
        "N4",
        "N5",
        "N8",
        "N9_MIN",
        "N10",
        "N11",
        "N12",
        "N13",
    )
    assert decision.nodes.index(N9_MIN) < decision.nodes.index("N10")
    assert decision.nodes[decision.nodes.index("N8") + 1] == N9_MIN
    assert decision.nodes[decision.nodes.index(N9_MIN) + 1] == "N10"
    assert is_n9_precheck(N9_MIN)
    assert is_n9_precheck(N9_MINIMAL_SAFETY_PRECHECK)
    assert N9_MINIMAL_SAFETY_PRECHECK == "N9_MINIMAL_SAFETY_PRECHECK"
    assert decision.grant_scope_draft is None
    _assert_clean(decision)


def test_unknown_action_type_is_blocked():
    decision = route({"action_type": "not_a_real_action", "grant_ref": GRANT})
    assert decision.status == "BLOCKED"
    assert decision.code == "UNKNOWN_ACTION_TYPE"
    assert decision.tier is None
    assert decision.nodes == ()
    assert decision.execution_authorized is False
    _assert_clean(decision)


def test_local_write_actions_are_not_s1_standard():
    assert LOCAL_ACTIONS.isdisjoint(S1_STANDARD_ACTIONS)
    for action in sorted(LOCAL_ACTIONS):
        decision = route({"action_type": action, "grant_ref": GRANT})
        assert decision.status == "BLOCKED"
        assert decision.code == "UNKNOWN_ACTION_TYPE"
        assert decision.nodes == ()
        _assert_clean(decision)


@pytest.mark.parametrize("action", sorted(FULL_ACTIONS))
def test_full_actions_are_blocked_not_standard(action):
    decision = route({"action_type": action, "grant_ref": GRANT})
    assert action in {"delete", "publish", "payment", "production_change", "eval_change", "cross_account", "irreversible"}
    assert decision.status == "BLOCKED"
    assert decision.code == "FULL_NOT_IMPLEMENTED"
    assert decision.tier == "Full"
    assert decision.tier != "Standard"
    assert decision.nodes == ()
    assert decision.nodes != S1_STANDARD_NODES
    assert decision.execution_authorized is False
    assert decision.grant_scope_draft is None
    _assert_clean(decision)


def test_upgrade_signal_is_blocked():
    request = {"action_type": "internal_readonly", "grant_ref": GRANT}
    direct = route(request, upgrade=True)
    signaled = signal_upgrade(request, reason="discovered payment side effect")
    for decision in (direct, signaled):
        assert decision.status == "BLOCKED"
        assert decision.code == "UPGRADE_NOT_IMPLEMENTED"
        assert decision.tier == "Full"
        assert decision.nodes == ()
        assert decision.execution_authorized is False
        assert decision.nodes != S1_STANDARD_NODES
        _assert_clean(decision)
    assert "payment" in signaled.reason
    with pytest.raises(Denied, match="upgrade"):
        route({**request, "upgrade": True})


@pytest.mark.parametrize(
    "payload",
    [
        {"action_type": "internal_readonly"},
        {"action_type": "internal_readonly", "grant_ref": None},
        {"action_type": "internal_readonly", "grant_ref": ""},
        {"action_type": "internal_readonly", "grant_ref": "   "},
    ],
)
def test_missing_grant_is_authorization_required(payload):
    decision = route(payload)
    assert decision.status == "AUTHORIZATION_REQUIRED"
    assert decision.execution_authorized is False
    assert decision.executed_nodes == ()
    assert decision.nodes == S1_STANDARD_NODES
    assert decision.nodes.index("N9_MIN") < decision.nodes.index("N10")
    draft = decision.grant_scope_draft
    assert draft is not None
    assert draft["kind"] == "grant_scope_draft"
    assert draft["action_type"] == "internal_readonly"
    assert draft["actions"] == ("internal_readonly",)
    assert draft["executable"] is False
    assert draft["n9_precheck"] == "N9_MIN"
    assert draft["n9_precheck_alias"] == "N9_MINIMAL_SAFETY_PRECHECK"
    assert draft["amount_limit"] == POLICY["amount_limit"]
    assert draft["chat_text_authorizes"] is False
    payload = decision.to_dict()
    assert payload["grant_scope_draft"]["actions"] == ["internal_readonly"]
    assert payload["execution_authorized"] is False
    _assert_clean(decision)


def test_complexity_and_unknown_routing_fields_are_rejected():
    granted = {"action_type": "internal_readonly", "grant_ref": GRANT}
    with pytest.raises(Denied, match="complexity"):
        route({**granted, "complexity": "simple"})
    with pytest.raises(Denied, match="tier"):
        route({**granted, "tier": "Fast"})
    with pytest.raises(Denied, match="select_tier"):
        route({**granted, "select_tier": "simple"})
    with pytest.raises(Denied, match="complexity"):
        route({**granted, "complexity": "simple", "tone": "urgent"})
    with pytest.raises(Denied, match="MISSING_ACTION_TYPE"):
        route({})
    with pytest.raises(Denied, match="REQUEST_MUST_BE_OBJECT"):
        route("simple")
    with pytest.raises(Denied, match="GRANT_REF_MUST_BE_STRING"):
        route({"action_type": "internal_readonly", "grant_ref": 1})


def test_never_emits_degraded_skip_status():
    samples = [
        route({"action_type": "internal_readonly", "grant_ref": GRANT}),
        route({"action_type": "internal_readonly"}),
        route({"action_type": "unknown-action"}),
        route({"action_type": "delete"}),
        route({"action_type": "publish"}),
        route({"action_type": "payment"}, upgrade=True),
        signal_upgrade({"action_type": "internal_readonly", "grant_ref": GRANT}),
    ]
    assert samples
    for decision in samples:
        _assert_clean(decision)
        assert decision.status in {"OK", "BLOCKED", "AUTHORIZATION_REQUIRED"}
    with pytest.raises(ValueError, match="not allowed"):
        RouteDecision(
            status="DEGRADED_SKIP_N6N7",
            action_type="internal_readonly",
            tier=None,
            nodes=(),
            reason="no",
            code="NO",
            execution_authorized=False,
        )


def test_complexity_router_symbols_are_gone():
    for module in (router_mod, governor_mod):
        assert not hasattr(module, "select_tier")
        assert not hasattr(module, "Tier")
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        assert "select_tier" not in names
        assert "Tier" not in names
    assert not hasattr(Governor, "route")
    router_source = Path(router_mod.__file__).read_text(encoding="utf-8")
    assert "def select_tier" not in router_source
    assert "complexity ==" not in router_source


def test_source_routes_are_primitives_not_the_s1_sequence():
    assert ROUTES["Fast"] == (1, 2, 10, 12)
    assert ROUTES["Standard"] == (1, 2, 3, 4, 5, 8, 10, 11, 12, 13)
    assert ROUTES["Full"] == tuple(range(1, 14))
    assert 9 not in ROUTES["Standard"]
    assert tuple(f"N{number}" for number in ROUTES["Standard"]) != S1_STANDARD_NODES
    assert S1_STANDARD_ACTIONS == frozenset({"internal_readonly"})


def test_governor_denial_helpers():
    Governor.check_action("object.create", "actor-a", "actor-a")
    with pytest.raises(Denied, match="SUBJECT_MISMATCH"):
        Governor.check_action("object.create", "actor-a", "actor-b")
    with pytest.raises(Denied, match="ACTION_NOT_ALLOWLISTED"):
        Governor.check_action("internal_readonly", "actor-a", "actor-a")
    Governor.check_outcome({"kind": "Outcome", "verifier_result": "NOT_RUN", "verifier_identity": None})
    with pytest.raises(Denied, match="VERIFIER_INGRESS_NOT_CONFIGURED"):
        Governor.check_outcome({"kind": "Outcome", "verifier_result": "PASS", "verifier_identity": None})
    with pytest.raises(TypeError):
        POLICY["amount_limit"] = 5
