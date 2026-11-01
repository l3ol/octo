"""Activation control A-1..A-10. Production Path B stays hard-disabled."""

from __future__ import annotations

from gates.activation.state import ActivationState
from gates.types import GateResult, first_rejection, make_result
from gates.verification.receipt import activation_signature_valid


def _result(state: ActivationState, decision: str, reason: str | None, checks: list[dict], details: dict, *, candidate_sha: str, base_sha: str, task_id: str | None, rule_version: str, rule_digest: str) -> GateResult:
    return make_result(
        gate="activation",
        decision=decision,
        reason_code=reason,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        task_id=task_id,
        checks=checks,
        details=details,
        rule_digest=rule_digest,
    )


def signal_emergency_stop(state: ActivationState, *, actor: str, candidate_sha: str, base_sha: str, task_id: str | None, rule_version: str, rule_digest: str) -> GateResult:
    state.emergency_stop = True
    state.path_b_enabled = False
    return _result(
        state,
        "REJECT",
        "ACTIVATION_EMERGENCY_STOP",
        [{"name": "emergency_stop", "decision": "REJECT", "reason_code": "ACTIVATION_EMERGENCY_STOP", "evaluated": True}],
        {"frozen": True, "actor": actor},
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        task_id=task_id,
        rule_version=rule_version,
        rule_digest=rule_digest,
    )


def evaluate_for_landing(
    state: ActivationState,
    *,
    irreversible: bool,
    kill_category: str | None,
    candidate_sha: str,
    base_sha: str,
    task_id: str | None,
    rule_version: str,
    rule_digest: str,
) -> GateResult:
    checks = []
    if state.emergency_stop:
        checks.append({"name": "emergency_stop", "decision": "REJECT", "reason_code": "ACTIVATION_EMERGENCY_STOP", "evaluated": True})
    else:
        checks.append({"name": "emergency_stop", "decision": "PASS", "reason_code": None, "evaluated": True})
    category = kill_category or state.kill_line_category
    if state.kill_line_tripped or kill_category:
        if category:
            state.trip_kill(category)
        checks.append(
            {
                "name": "kill_line",
                "decision": "REJECT",
                "reason_code": "ACTIVATION_KILL_LINE",
                "evaluated": True,
                "category": category,
            }
        )
    else:
        checks.append({"name": "kill_line", "decision": "PASS", "reason_code": None, "evaluated": True, "category": None})
    if irreversible:
        checks.append(
            {
                "name": "irreversible",
                "decision": "REJECT",
                "reason_code": "ACTIVATION_IRREVERSIBLE_REQUIRES_HUMAN",
                "evaluated": True,
            }
        )
    else:
        checks.append({"name": "irreversible", "decision": "PASS", "reason_code": None, "evaluated": True})
    if state.environment != "isolated" or not state.path_b_enabled:
        checks.append(
            {
                "name": "path_b",
                "decision": "REJECT",
                "reason_code": "ACTIVATION_PATH_B_DISABLED",
                "evaluated": True,
                "message": "Path B disabled",
                "self_closed": state.self_closed,
            }
        )
    else:
        checks.append({"name": "path_b", "decision": "PASS", "reason_code": None, "evaluated": True, "message": None})
    decision, reason = first_rejection(checks)
    details = {"self_closed": state.self_closed, "environment": state.environment}
    if reason == "ACTIVATION_PATH_B_DISABLED":
        details["message"] = "Path B disabled"
    if reason == "ACTIVATION_KILL_LINE":
        details["category"] = category
        details["escalated_to"] = "founder"
    return _result(
        state,
        decision,
        reason,
        checks,
        details,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        task_id=task_id,
        rule_version=rule_version,
        rule_digest=rule_digest,
    )


def check_separation(state: ActivationState, *, candidate_sha: str, base_sha: str, task_id: str | None, rule_version: str, rule_digest: str) -> GateResult:
    overlap = set(state.builder_ids) & set(state.acceptance_ids)
    shared = set(state.shared_write_principals)
    ok = bool(state.builder_ids) and bool(state.acceptance_ids) and not overlap and not shared
    decision = "PASS" if ok else "REJECT"
    return _result(
        state,
        decision,
        None,
        [{"name": "separation", "decision": decision, "reason_code": None, "evaluated": True}],
        {
            "separation_ok": ok,
            "program_result": decision,
            "reason_note": "N/A",
            "builder_ids": sorted(state.builder_ids),
            "acceptance_ids": sorted(state.acceptance_ids),
            "shared_write_principals": sorted(shared),
            "overlap": sorted(overlap),
        },
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        task_id=task_id,
        rule_version=rule_version,
        rule_digest=rule_digest,
    )


def _reject_enable(state, reason, checks, details, **ids):
    return _result(state, "REJECT", reason, checks, details, **ids)


def enable_path_b(
    state: ActivationState,
    *,
    actor: str,
    founder_written_approval: bool,
    activation_receipt: dict | None,
    gate_version: str,
    evidence_digest: str,
    isomorphism_result: GateResult | None,
    candidate_sha: str,
    base_sha: str,
    task_id: str | None,
    rule_version: str,
    rule_digest: str,
) -> GateResult:
    ids = dict(
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        task_id=task_id,
        rule_version=rule_version,
        rule_digest=rule_digest,
    )
    if state.environment != "isolated":
        return _reject_enable(
            state,
            "ACTIVATION_PATH_B_DISABLED",
            [{"name": "production_hard_close", "decision": "REJECT", "reason_code": "ACTIVATION_PATH_B_DISABLED", "evaluated": True}],
            {"message": "Path B disabled", "environment": state.environment},
            **ids,
        )
    if actor not in state.founder_ids:
        return _reject_enable(
            state,
            "ACTIVATION_NON_FOUNDER",
            [{"name": "founder", "decision": "REJECT", "reason_code": "ACTIVATION_NON_FOUNDER", "evaluated": True}],
            {"actor": actor},
            **ids,
        )
    if activation_receipt is None:
        return _reject_enable(
            state,
            "ACTIVATION_MISSING_RECEIPT",
            [{"name": "activation_receipt", "decision": "REJECT", "reason_code": "ACTIVATION_MISSING_RECEIPT", "evaluated": True}],
            {"founder_written_approval": founder_written_approval},
            **ids,
        )
    sig_ok = activation_signature_valid(activation_receipt, state.founder_receipt_secret)
    version_ok = activation_receipt.get("gate_version") == gate_version
    digest_ok = activation_receipt.get("evidence_digest") == evidence_digest
    if not sig_ok or not version_ok or not digest_ok:
        return _reject_enable(
            state,
            "ACTIVATION_RECEIPT_MISMATCH",
            [{"name": "activation_receipt", "decision": "REJECT", "reason_code": "ACTIVATION_RECEIPT_MISMATCH", "evaluated": True}],
            {"signature_ok": sig_ok, "gate_version_ok": version_ok, "evidence_digest_ok": digest_ok},
            **ids,
        )
    if not founder_written_approval:
        return _reject_enable(
            state,
            "ACTIVATION_MISSING_RECEIPT",
            [{"name": "founder_written_approval", "decision": "REJECT", "reason_code": "ACTIVATION_MISSING_RECEIPT", "evaluated": True}],
            {"missing": ["founder_written_approval"]},
            **ids,
        )
    if isomorphism_result is None or isomorphism_result.decision != "PASS":
        reason = "ISOMORPHISM_DIGEST_MISMATCH" if isomorphism_result is None else (isomorphism_result.reason_code or "ISOMORPHISM_DIGEST_MISMATCH")
        return _reject_enable(
            state,
            reason,
            [{"name": "isomorphism", "decision": "REJECT", "reason_code": reason, "evaluated": True}],
            {"i2": "fail"},
            **ids,
        )
    state.path_b_enabled = True
    return _result(
        state,
        "PASS",
        None,
        [{"name": "enable_path_b", "decision": "PASS", "reason_code": None, "evaluated": True}],
        {"environment": "isolated", "path_b_enabled": True},
        **ids,
    )


def reopen(
    state: ActivationState,
    *,
    actor: str,
    root_cause_eliminated: bool,
    gates_reverified: bool,
    evidence_bound_to_new_gate_version: bool,
    founder_written_approval: bool,
    activation_receipt: dict | None,
    gate_version: str,
    evidence_digest: str,
    candidate_sha: str,
    base_sha: str,
    task_id: str | None,
    rule_version: str,
    rule_digest: str,
) -> GateResult:
    ids = dict(
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        task_id=task_id,
        rule_version=rule_version,
        rule_digest=rule_digest,
    )
    if actor not in state.founder_ids:
        return _reject_enable(
            state,
            "ACTIVATION_NON_FOUNDER",
            [{"name": "founder", "decision": "REJECT", "reason_code": "ACTIVATION_NON_FOUNDER", "evaluated": True}],
            {"actor": actor},
            **ids,
        )
    if state.environment != "isolated":
        return _reject_enable(
            state,
            "ACTIVATION_PATH_B_DISABLED",
            [{"name": "production_hard_close", "decision": "REJECT", "reason_code": "ACTIVATION_PATH_B_DISABLED", "evaluated": True}],
            {"message": "Path B disabled", "environment": state.environment},
            **ids,
        )
    missing = []
    if not root_cause_eliminated:
        missing.append("root_cause_eliminated")
    if not gates_reverified:
        missing.append("gates_reverified")
    if not evidence_bound_to_new_gate_version:
        missing.append("evidence_bound_to_new_gate_version")
    if not founder_written_approval:
        missing.append("founder_written_approval")
    if activation_receipt is None:
        missing.append("activation_receipt")
    else:
        if not activation_signature_valid(activation_receipt, state.founder_receipt_secret):
            missing.append("activation_receipt_integrity")
        if activation_receipt.get("gate_version") != gate_version:
            missing.append("gate_version")
        if activation_receipt.get("evidence_digest") != evidence_digest:
            missing.append("evidence_digest")
    if missing:
        return _reject_enable(
            state,
            "ACTIVATION_REOPEN_INCOMPLETE",
            [{"name": "reopen", "decision": "REJECT", "reason_code": "ACTIVATION_REOPEN_INCOMPLETE", "evaluated": True}],
            {"missing": missing},
            **ids,
        )
    state.self_closed = False
    state.path_b_enabled = True
    return _result(
        state,
        "PASS",
        None,
        [{"name": "reopen", "decision": "PASS", "reason_code": None, "evaluated": True}],
        {"environment": "isolated", "path_b_enabled": True, "self_closed": False},
        **ids,
    )


def request(
    actor: str,
    action: str,
    activation_receipt: dict | None,
    gate_version: str,
    evidence_digest: str,
    state: ActivationState,
    **kwargs,
) -> GateResult:
    """Dispatcher matching the spec activation.request signature."""
    common = dict(
        actor=actor,
        candidate_sha=kwargs.get("candidate_sha", "0" * 40),
        base_sha=kwargs.get("base_sha", "0" * 40),
        task_id=kwargs.get("task_id"),
        rule_version=kwargs.get("rule_version", gate_version),
        rule_digest=kwargs.get("rule_digest", ""),
    )
    if action == "emergency_stop":
        return signal_emergency_stop(state, **common)
    if action == "separation_check":
        return check_separation(
            state,
            candidate_sha=common["candidate_sha"],
            base_sha=common["base_sha"],
            task_id=common["task_id"],
            rule_version=common["rule_version"],
            rule_digest=common["rule_digest"],
        )
    if action == "enable_path_b":
        return enable_path_b(
            state,
            actor=actor,
            founder_written_approval=kwargs.get("founder_written_approval", False),
            activation_receipt=activation_receipt,
            gate_version=gate_version,
            evidence_digest=evidence_digest,
            isomorphism_result=kwargs.get("isomorphism_result"),
            candidate_sha=common["candidate_sha"],
            base_sha=common["base_sha"],
            task_id=common["task_id"],
            rule_version=common["rule_version"],
            rule_digest=common["rule_digest"],
        )
    if action == "reopen_path_b":
        return reopen(
            state,
            actor=actor,
            root_cause_eliminated=kwargs.get("root_cause_eliminated", False),
            gates_reverified=kwargs.get("gates_reverified", False),
            evidence_bound_to_new_gate_version=kwargs.get("evidence_bound_to_new_gate_version", False),
            founder_written_approval=kwargs.get("founder_written_approval", False),
            activation_receipt=activation_receipt,
            gate_version=gate_version,
            evidence_digest=evidence_digest,
            candidate_sha=common["candidate_sha"],
            base_sha=common["base_sha"],
            task_id=common["task_id"],
            rule_version=common["rule_version"],
            rule_digest=common["rule_digest"],
        )
    return _result(
        state,
        "REJECT",
        "GATE_INTERNAL_ERROR",
        [{"name": "action", "decision": "REJECT", "reason_code": "GATE_INTERNAL_ERROR", "evaluated": True}],
        {"action": action},
        candidate_sha=common["candidate_sha"],
        base_sha=common["base_sha"],
        task_id=common["task_id"],
        rule_version=common["rule_version"],
        rule_digest=common["rule_digest"],
    )
