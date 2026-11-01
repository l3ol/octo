"""N10 execution gate. N9 runs before dispatch. Chat text has no authority.

Re-entry returns the existing effect. UNKNOWN_COMMIT reconciles before any
further dispatch and never retries blindly.

Builder selftest support only.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from octo.governor import FULL_ACTIONS, Denied
from octo.grant import S1_GRANT_ACTIONS, AuthorizationRequest, GrantDenied, GrantStore
from octo.journal import Blocked, Journal
from octo.nodes import emit_envelope

N10_INPUT_KEYS = {"action", "grant_ref", "context_pack"}


class Gateway:
    def __init__(self, journal: Journal, grants: GrantStore, *, dispatch: Callable | None = None):
        self.journal = journal
        self.grants = grants
        self.dispatch_impl = dispatch if dispatch is not None else self._read_granted_fixture
        self.dispatch_count = 0

    def _read_granted_fixture(self, request: AuthorizationRequest) -> dict:
        """Default N10 handler: read the isolation fixture and record the effect."""
        return self.journal.apply(request)

    def _authorize(self, request: AuthorizationRequest, *, now=None):
        if request.action in FULL_ACTIONS or request.action not in S1_GRANT_ACTIONS:
            return self.journal.record(request, "BLOCKED", "blocked", reason="FULL_OR_UNKNOWN_ACTION")
        if set(request.parameters) != {"op"} or request.parameters.get("op") != "read":
            return self.journal.record(request, "DENIED", "denied", reason="ACTION_PARAMETERS_INVALID")
        try:
            self.grants.validate(request.grant_id, request, now=now)
        except GrantDenied as exc:
            return self.journal.record(request, "DENIED", "denied", reason=str(exc))
        return None

    def _dispatch(self, request: AuthorizationRequest) -> dict:
        self.dispatch_count += 1
        return self.dispatch_impl(request)

    def execute(self, request: AuthorizationRequest, *, chat_text: str = "", now=None) -> dict:
        """Dispatch only after N9. ``chat_text`` is ignored and is not a grant."""
        del chat_text
        with self.journal.writer():
            denied = self._authorize(request, now=now)
            if denied is not None:
                return denied
            latest = self.journal.latest(request.idempotency_key)
            if latest and latest["request_digest"] != request.digest:
                return self.journal.record(
                    request, "DENIED", "denied", reason="IDEMPOTENCY_DIGEST_CONFLICT",
                )
            if latest and latest["state"] in {"SUCCEEDED", "RECONCILED_APPLIED"}:
                return latest
            if latest and latest["state"] == "BLOCKED":
                raise Blocked("PREVIOUSLY_BLOCKED_REQUIRES_REVIEW")
            if latest and latest["state"] in {
                "UNKNOWN_COMMIT", "DISPATCHED", "PREPARED", "RECONCILED_NOT_APPLIED",
            }:
                try:
                    state, _effect = self.journal.reconcile(request)
                except Blocked as exc:
                    self.journal.record(request, "BLOCKED", "blocked", reason=f"RECONCILIATION_UNKNOWN: {exc}")
                    raise Blocked("RECONCILIATION_UNKNOWN_STOP") from exc
                if state == "APPLIED":
                    return self.journal.record(
                        request,
                        "RECONCILED_APPLIED",
                        "reconciled",
                        reason="effect already present; no redispatch",
                    )
                if state != "NOT_APPLIED":
                    self.journal.record(request, "BLOCKED", "blocked", reason="RECONCILIATION_UNKNOWN")
                    raise Blocked("RECONCILIATION_UNKNOWN_STOP")
                self.journal.record(
                    request,
                    "RECONCILED_NOT_APPLIED",
                    "reconciled",
                    reason="effect ledger confirms absence; retry follows reconcile",
                )
            elif latest is None:
                self.journal.record(request, "PREPARED", "not_dispatched")
            denied = self._authorize(request, now=now)
            if denied is not None:
                return denied
            self.journal.record(request, "DISPATCHED", "dispatched")
            try:
                effect = self._dispatch(request)
            except Denied as exc:
                return self.journal.record(request, "DENIED", "denied", reason=str(exc))
            except FileNotFoundError as exc:
                return self.journal.record(request, "BLOCKED", "blocked", reason=str(exc) or "ARTIFACT_MISSING")
            except Exception as exc:
                return self.journal.record(
                    request,
                    "UNKNOWN_COMMIT",
                    "unknown_commit",
                    reason=f"{type(exc).__name__}: {exc}",
                )
            if not isinstance(effect, dict) or not effect.get("object_id"):
                return self.journal.record(request, "BLOCKED", "blocked", reason="READ_RESULT_MISSING")
            if "op" in effect and "content_sha256" not in effect:
                return self.journal.record(request, "BLOCKED", "blocked", reason="OP_IS_NOT_A_RESULT")
            refs = []
            if effect.get("evidence_ref"):
                refs.append(effect["evidence_ref"])
            refs.append(effect["object_id"])
            return self.journal.record(
                request,
                "SUCCEEDED",
                "success",
                evidence_refs=refs,
            )


def run_n10(
    inputs: Mapping[str, Any],
    *,
    at: str,
    gateway: Gateway,
    request: AuthorizationRequest,
    now=None,
) -> dict:
    """N10 envelope. Chat text is not an input and cannot authorize dispatch."""
    if "context_pack" not in inputs:
        raise ValueError("CONTEXT_PACK_MISSING")
    if set(inputs) != N10_INPUT_KEYS:
        raise ValueError("FROZEN_KEY_DRIFT")
    if inputs["grant_ref"] != request.grant_id:
        raise ValueError("GRANT_REF_NOT_ALLOW")
    result = gateway.execute(request, chat_text="", now=now)
    state = result["state"]
    notes = result.get("notes", "")
    evidence = list(result.get("evidence_refs") or [])
    if state == "UNKNOWN_COMMIT":
        return emit_envelope(
            node_id="N10",
            at=at,
            inputs=dict(inputs),
            status="BLOCKED",
            output={
                "receipt_id": result["receipt_id"],
                "result": "UNKNOWN_COMMIT",
                "evidence_refs": evidence,
            },
        )
    if state == "BLOCKED":
        status, output = "BLOCKED", None
    elif state == "DENIED" and str(notes).startswith("GRANT"):
        status, output = "AUTHORIZATION_REQUIRED", None
    elif state == "DENIED":
        status, output = "BLOCKED", None
    else:
        output = {"receipt_id": result["receipt_id"], "result": state, "evidence_refs": evidence}
        if "result" not in output or "evidence_refs" not in output:
            raise ValueError("RESULT_OR_EVIDENCE_MISSING")
        status = "OK"
    return emit_envelope(node_id="N10", at=at, inputs=dict(inputs), status=status, output=output)
