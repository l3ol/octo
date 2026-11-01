"""Action-type Router for S1 (T-01 §3, A2-5).

Input is only ``{action_type, grant_ref?}``. Any other routing key is
rejected, including ``complexity``. There is no complexity tier and no
compatibility path.

S1 implements one Standard route, ``internal_readonly``:

``N1, N2, N3, N4, N5, N8, N9_MIN, N10, N11, N12, N13``

``N9_MIN`` and ``N9_MINIMAL_SAFETY_PRECHECK`` name that same precheck step.
The precheck sits before ``N10``. Envelope ``node_id`` values stay N1..N13;
this module does not run node bodies.

An action in ``FULL_ACTIONS``, any other unknown ``action_type``, or a
mid-run upgrade stops with ``BLOCKED``. Full needs N6, N7, and full N9,
which S1 does not implement, so the Router returns no node sequence and no
node output. A Standard action whose N9 precheck has no usable ``grant_ref``
returns ``AUTHORIZATION_REQUIRED`` plus a grant-scope draft and does not
authorize execution. This module does not perform Grant's six checks.

Statuses emitted here are only ``OK``, ``BLOCKED``, and
``AUTHORIZATION_REQUIRED``.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from octo.governor import FULL_ACTIONS, POLICY, ROUTES, Denied

N9_MIN = "N9_MIN"
N9_MINIMAL_SAFETY_PRECHECK = "N9_MINIMAL_SAFETY_PRECHECK"
N9_PRECHECK_NAMES = frozenset({N9_MIN, N9_MINIMAL_SAFETY_PRECHECK})

# CCI S1 scope is Standard internal_readonly. Mac LOCAL_ACTIONS are writes
# and are not added here.
S1_STANDARD_ACTIONS = frozenset({"internal_readonly"})

S1_STANDARD_NODES = (
    "N1",
    "N2",
    "N3",
    "N4",
    "N5",
    "N8",
    N9_MIN,
    "N10",
    "N11",
    "N12",
    "N13",
)

ALLOWED_ROUTING_FIELDS = frozenset({"action_type", "grant_ref"})
ROUTE_STATUSES = frozenset({"OK", "BLOCKED", "AUTHORIZATION_REQUIRED"})

_SOURCE_STANDARD_IDS = tuple(f"N{number}" for number in ROUTES["Standard"])
if S1_STANDARD_NODES == _SOURCE_STANDARD_IDS or N9_MIN in _SOURCE_STANDARD_IDS:
    raise RuntimeError("S1 node sequence must not be copied from source ROUTES")
if S1_STANDARD_ACTIONS & FULL_ACTIONS:
    raise RuntimeError("S1 Standard allowlist overlaps FULL_ACTIONS")
if S1_STANDARD_NODES.index(N9_MIN) > S1_STANDARD_NODES.index("N10"):
    raise RuntimeError("N9_MIN must run before N10")
if "N6" in S1_STANDARD_NODES or "N7" in S1_STANDARD_NODES:
    raise RuntimeError("S1 Standard sequence must not include N6 or N7")


def is_n9_precheck(step: str) -> bool:
    """True for ``N9_MIN`` and its ``N9_MINIMAL_SAFETY_PRECHECK`` alias."""
    return step in N9_PRECHECK_NAMES


@dataclass(frozen=True)
class RouteDecision:
    """One Router outcome. ``nodes`` is the selected sequence, not a run."""

    status: str
    action_type: str
    tier: str | None
    nodes: tuple[str, ...]
    reason: str
    code: str
    execution_authorized: bool = False
    executed_nodes: tuple[str, ...] = ()
    grant_scope_draft: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.status not in ROUTE_STATUSES or "DEGRADED_SKIP" in self.status:
            raise ValueError(f"router status not allowed: {self.status}")
        if self.executed_nodes:
            raise ValueError("router does not execute nodes")
        if self.execution_authorized is not (self.status == "OK"):
            raise ValueError("execution_authorized is true only for status OK")
        if self.status == "OK":
            if self.tier != "Standard" or self.nodes != S1_STANDARD_NODES:
                raise ValueError("OK is only the S1 Standard sequence")
            if self.grant_scope_draft is not None:
                raise ValueError("OK does not carry a grant-scope draft")
        elif self.status == "BLOCKED":
            if self.nodes or self.grant_scope_draft is not None:
                raise ValueError("BLOCKED carries no sequence and no draft")
            if self.code == "UNKNOWN_ACTION_TYPE" and self.tier is not None:
                raise ValueError("unknown action_type has no tier")
            if self.code in {"FULL_NOT_IMPLEMENTED", "UPGRADE_NOT_IMPLEMENTED"} and self.tier != "Full":
                raise ValueError("Full stop must record tier Full")
        elif self.status == "AUTHORIZATION_REQUIRED":
            if self.tier != "Standard" or self.nodes != S1_STANDARD_NODES:
                raise ValueError("authorization stop is the S1 Standard sequence")
            if not self.grant_scope_draft or self.grant_scope_draft.get("executable") is not False:
                raise ValueError("AUTHORIZATION_REQUIRED requires a non-executable draft")

    def to_dict(self) -> dict[str, Any]:
        draft = self.grant_scope_draft
        return {
            "status": self.status,
            "action_type": self.action_type,
            "tier": self.tier,
            "nodes": list(self.nodes),
            "executed_nodes": list(self.executed_nodes),
            "reason": self.reason,
            "code": self.code,
            "execution_authorized": self.execution_authorized,
            "grant_scope_draft": None if draft is None else _jsonable(dict(draft)),
        }


def route(
    request: Mapping[str, Any],
    *,
    upgrade: bool = False,
    upgrade_reason: str = "",
) -> RouteDecision:
    """Route ``request`` by ``action_type``.

    ``upgrade`` / ``upgrade_reason`` are call signals, not routing fields.
    A mapping that itself contains ``upgrade`` or ``complexity`` is rejected.
    """
    _reject_malformed(request, upgrade=upgrade, upgrade_reason=upgrade_reason)
    action_type = request["action_type"]

    if upgrade or upgrade_reason:
        reason = upgrade_reason.strip() or (
            "mid-run upgrade requires Full (N6, N7, full N9); Full is not implemented in S1"
        )
        return _blocked(action_type, "Full", "UPGRADE_NOT_IMPLEMENTED", reason)

    if action_type in FULL_ACTIONS:
        return _blocked(
            action_type,
            "Full",
            "FULL_NOT_IMPLEMENTED",
            "action_type maps to Full and needs N6, N7, and full N9; S1 stops with no partial route",
        )
    if action_type not in S1_STANDARD_ACTIONS:
        return _blocked(
            action_type,
            None,
            "UNKNOWN_ACTION_TYPE",
            "action_type is not in the S1 Standard allowlist",
        )
    if not _has_grant_ref(request):
        return RouteDecision(
            status="AUTHORIZATION_REQUIRED",
            action_type=action_type,
            tier="Standard",
            nodes=S1_STANDARD_NODES,
            reason="N9 precheck lacks a valid grant_ref; execution is not authorized",
            code="AUTHORIZATION_REQUIRED",
            execution_authorized=False,
            grant_scope_draft=_grant_scope_draft(action_type),
        )
    return RouteDecision(
        status="OK",
        action_type=action_type,
        tier="Standard",
        nodes=S1_STANDARD_NODES,
        reason="routed S1 Standard",
        code="ROUTED_STANDARD",
        execution_authorized=True,
    )


def signal_upgrade(request: Mapping[str, Any], *, reason: str = "") -> RouteDecision:
    """Record a mid-run upgrade. S1 has no Full route, so the result is BLOCKED."""
    return route(request, upgrade=True, upgrade_reason=reason)


def _reject_malformed(
    request: Mapping[str, Any],
    *,
    upgrade: bool,
    upgrade_reason: str,
) -> None:
    if not isinstance(request, Mapping):
        raise Denied("REQUEST_MUST_BE_OBJECT")
    extra = sorted(set(request) - ALLOWED_ROUTING_FIELDS)
    if extra:
        raise Denied("UNKNOWN_ROUTING_FIELD:" + ",".join(extra))
    if "action_type" not in request:
        raise Denied("MISSING_ACTION_TYPE")
    if not isinstance(request["action_type"], str):
        raise Denied("ACTION_TYPE_MUST_BE_STRING")
    if "grant_ref" in request and request["grant_ref"] is not None and not isinstance(request["grant_ref"], str):
        raise Denied("GRANT_REF_MUST_BE_STRING")
    if not isinstance(upgrade, bool):
        raise Denied("UPGRADE_SIGNAL_MUST_BE_BOOL")
    if not isinstance(upgrade_reason, str):
        raise Denied("UPGRADE_REASON_MUST_BE_STRING")


def _has_grant_ref(request: Mapping[str, Any]) -> bool:
    """A usable reference is a non-empty string. Six-check validation is T-05."""
    ref = request.get("grant_ref")
    return isinstance(ref, str) and ref.strip() != ""


def _grant_scope_draft(action_type: str) -> Mapping[str, Any]:
    return MappingProxyType({
        "kind": "grant_scope_draft",
        "action_type": action_type,
        "actions": (action_type,),
        "amount_limit": POLICY["amount_limit"],
        "chat_text_authorizes": POLICY["chat_text_authorizes"],
        "resources": (action_type,),
        "n9_precheck": N9_MIN,
        "n9_precheck_alias": N9_MINIMAL_SAFETY_PRECHECK,
        "executable": False,
    })


def _blocked(
    action_type: str,
    tier: str | None,
    code: str,
    reason: str,
) -> RouteDecision:
    return RouteDecision(
        status="BLOCKED",
        action_type=action_type,
        tier=tier,
        nodes=(),
        reason=reason,
        code=code,
        execution_authorized=False,
        grant_scope_draft=None,
    )


def _jsonable(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    return value
