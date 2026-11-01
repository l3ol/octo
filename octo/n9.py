"""N9 minimal precheck. Six validators, then ALLOW or DENY.

The envelope node id is ``N9``. The route step name remains ``N9_MIN``.
A failed precheck is ``AUTHORIZATION_REQUIRED`` with output null. No N6 or N7
envelope is produced.

Builder selftest support only.
"""

from __future__ import annotations

from typing import Any, Mapping

from octo.grant import SIX_VALIDATORS, AuthorizationRequest, GrantDenied, GrantStore
from octo.nodes import emit_envelope

N9_INPUT_KEYS = {
    "actor",
    "action",
    "resource",
    "parameters",
    "intent_id",
    "idempotency_key",
    "git_candidate_sha",
    "tree_sha",
    "grant_ref",
}


def precheck(store: GrantStore, request: AuthorizationRequest, *, now=None) -> dict[str, Any]:
    """Run the six validators. Persist one DENY or ALLOW receipt."""
    try:
        grant = store.validate(request.grant_id, request, now=now)
    except GrantDenied as exc:
        receipt = store.write_receipt(
            decision="DENY",
            validator=exc.validator,
            reason=exc.code,
            grant_id=request.grant_id,
        )
        return {
            "status": "AUTHORIZATION_REQUIRED",
            "grant_ref": None,
            "grant": None,
            "receipt": receipt,
            "reason": exc.code,
            "validator": exc.validator,
        }
    receipt = store.write_receipt(
        decision="ALLOW",
        validator=None,
        reason="N9_SIX_OK",
        grant_id=grant["grant_id"],
    )
    return {
        "status": "OK",
        "grant_ref": grant["grant_id"],
        "grant": grant,
        "receipt": receipt,
        "reason": "N9_SIX_OK",
        "validator": None,
        "validators": list(SIX_VALIDATORS),
    }


def run_n9(inputs: Mapping[str, Any], *, at: str, store: GrantStore, now=None) -> dict:
    """Envelope for the N9 precheck. ``inputs`` are the hashed authorization fields."""
    if set(inputs) != N9_INPUT_KEYS:
        raise ValueError(f"N9 input keys {sorted(inputs)} != {sorted(N9_INPUT_KEYS)}")
    request = AuthorizationRequest(
        actor=inputs["actor"],
        action=inputs["action"],
        resource=inputs["resource"],
        parameters=dict(inputs["parameters"]),
        intent_id=inputs["intent_id"],
        idempotency_key=inputs["idempotency_key"],
        git_candidate_sha=inputs["git_candidate_sha"],
        tree_sha=inputs["tree_sha"],
        grant_id=inputs["grant_ref"],
    )
    result = precheck(store, request, now=now)
    if result["status"] != "OK":
        output = None
        status = "AUTHORIZATION_REQUIRED"
    else:
        status = "OK"
        output = {
            "grant_ref": result["grant_ref"],
            "decision": "ALLOW",
            "precheck": "N9_MIN",
            "validators": list(SIX_VALIDATORS),
        }
    return emit_envelope(
        node_id="N9",
        at=at,
        inputs=dict(inputs),
        status=status,
        output=output,
    )
