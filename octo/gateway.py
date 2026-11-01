"""N10 execution gate. N9 runs before dispatch. Chat text has no authority.

Re-entry returns the existing effect. UNKNOWN_COMMIT reconciles before any
further dispatch and never retries blindly.

Builder selftest support only.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from octo.governor import FULL_ACTIONS
from octo.grant import S1_GRANT_ACTIONS, AuthorizationRequest, GrantDenied, GrantStore
from octo.journal import Blocked, Journal
from octo.nodes import emit_envelope

N10_INPUT_KEYS = {
    "action",
    "grant_ref",
    "idempotency_key",
    "request_digest",
    "git_candidate_sha",
    "tree_sha",
}


class Gateway:
    def __init__(self, journal: Journal, grants: GrantStore, *, dispatch: Callable | None = None):
        self.journal = journal
        self.grants = grants
        self.dispatch_impl = dispatch
        self.dispatch_count = 0

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
        if self.dispatch_impl is not None:
            return self.dispatch_impl(request)
        return self.journal.apply(request)

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
            except Exception as exc:
                return self.journal.record(
                    request,
                    "UNKNOWN_COMMIT",
                    "unknown_commit",
                    reason=f"{type(exc).__name__}: {exc}",
                )
            return self.journal.record(
                request,
                "SUCCEEDED",
                "success",
                evidence_refs=[effect["object_id"]],
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
    if set(inputs) != N10_INPUT_KEYS:
        raise ValueError("N10 inputs must be the dispatch identity, without chat_text")
    if "chat_text" in inputs:
        raise ValueError("chat_text is not authoritative")
    result = gateway.execute(request, chat_text="", now=now)
    state = result["state"]
    notes = result.get("notes", "")
    if state == "BLOCKED":
        status, output = "BLOCKED", None
    elif state == "DENIED" and notes.startswith("GRANT"):
        status, output = "AUTHORIZATION_REQUIRED", None
    elif state == "DENIED":
        status, output = "BLOCKED", None
    else:
        status, output = "OK", {
            "state": state,
            "receipt_id": result["receipt_id"],
            "request_digest": result["request_digest"],
            "idempotency_key": result["idempotency_key"],
            "grant_ref": result.get("grant_id"),
        }
    return emit_envelope(node_id="N10", at=at, inputs=dict(inputs), status=status, output=output)
