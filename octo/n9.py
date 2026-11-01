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

N9_INPUT_KEYS = {"action", "grant_id", "request_digest"}


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


def run_n9(inputs: Mapping[str, Any], *, at: str, store: GrantStore, request: AuthorizationRequest, now=None) -> dict:
    """Frozen N9 envelope. Inputs are exactly action, grant_id, request_digest."""
    if set(inputs) != N9_INPUT_KEYS:
        raise ValueError("FROZEN_KEY_DRIFT")
    if inputs["action"] != request.action or inputs.get("grant_id") != request.grant_id:
        raise ValueError("FROZEN_KEY_DRIFT")
    if inputs["request_digest"] != request.digest:
        output = {
            "verdict": "DENY",
            "reason": "ALLOW_ON_DIGEST_MISMATCH grant_scope_draft action=internal_readonly",
            "grant_ref": None,
        }
        return emit_envelope(node_id="N9", at=at, inputs=dict(inputs), status="AUTHORIZATION_REQUIRED", output=output)
    result = precheck(store, request, now=now)
    if result["status"] != "OK":
        reason = result.get("reason") or "DENY"
        output = {
            "verdict": "DENY",
            "reason": f"{reason}; grant_scope_draft action=internal_readonly amount_limit=0",
            "grant_ref": None,
        }
        if not output["reason"]:
            raise ValueError("DENY_WITHOUT_REASON")
        if "grant_scope_draft" not in output["reason"]:
            raise ValueError("GRANT_DRAFT_MISSING")
        status = "AUTHORIZATION_REQUIRED"
    else:
        status = "OK"
        output = {
            "verdict": "ALLOW",
            "reason": result.get("reason") or "N9_SIX_OK",
            "grant_ref": result["grant_ref"],
        }
    if set(output) != {"verdict", "reason", "grant_ref"}:
        raise ValueError("FROZEN_KEY_DRIFT")
    return emit_envelope(
        node_id="N9",
        at=at,
        inputs=dict(inputs),
        status=status,
        output=output,
    )
