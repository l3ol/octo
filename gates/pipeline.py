"""Landing pipeline. First REJECT is the primary reason; other checks stay in evidence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from gates.activation.request import evaluate_for_landing
from gates.activation.state import ActivationState
from gates.atomic_merge.compare import compare_and_merge
from gates.binding.decide import decide as binding_decide
from gates.integrity.board import Board, publish_board
from gates.integrity.recovery import verify_recovery
from gates.policy.audit import RuleAuditLog
from gates.policy.decide import decide as policy_decide
from gates.policy.size import measure_tree
from gates.rules import RULES
from gates.scope.decide import decide as scope_decide
from gates.tamper.loader import load_pin
from gates.tamper.path_filter import path_filter
from gates.types import GateResult, make_result, now_cst
from gates.verification.decide import decide as verification_decide
from gates.verification.ledger import ConsumptionLedger


@dataclass
class LandingRequest:
    task_id: str | None
    candidate_sha: str
    base_sha: str
    changed_paths: list[str]
    blobs: list[tuple[str, bytes]]
    receipt: dict | None
    registry: dict
    trusted_issuers: dict
    ledger: ConsumptionLedger
    target_branch_config: dict
    current_head_sha: str
    activation_state: ActivationState
    board: Board
    external_manifest: dict | None
    object_store: object
    rule_version: str = RULES.version
    lineage: list[str] = field(default_factory=list)
    recovery_plan: dict | None = None
    irreversible: bool = False
    audit_log: RuleAuditLog | None = None
    candidate_rules: dict | None = None
    commit_exists: Callable[[str], bool] | None = None
    candidate_claimed_pin: str | None = None
    head_sha: str | None = None
    tags: dict | None = None
    merge_candidate_sha: str | None = None
    publisher: object | None = None
    recovery_repo: str | None = None


def _summary(result: GateResult) -> dict:
    return {
        "decision": result.decision,
        "reason_code": result.reason_code,
        "timestamp": result.evidence.get("timestamp"),
        "result_digest": result.result_digest,
        "candidate_sha": result.candidate_sha,
        "base_sha": result.base_sha,
        "rule_version": result.rule_version,
    }


def _primary(results: list[GateResult]) -> tuple[str, str | None]:
    for item in results:
        if item.decision == "REJECT":
            return "REJECT", item.reason_code
    return "PASS", None


def _pipeline_result(
    *,
    decision: str,
    reason: str | None,
    request: LandingRequest,
    checks: dict,
    details: dict,
) -> GateResult:
    return make_result(
        gate="pipeline",
        decision=decision,
        reason_code=reason,
        candidate_sha=request.candidate_sha,
        base_sha=request.base_sha,
        rule_version=request.rule_version,
        task_id=request.task_id if isinstance(request.task_id, str) else None,
        checks=checks,
        details=details,
        rule_digest=RULES.digest,
    )


def evaluate_landing(request: LandingRequest) -> GateResult:
    state = request.activation_state
    try:
        pin = load_pin(
            request.external_manifest,
            object_store=request.object_store,
            candidate_claimed_pin=request.candidate_claimed_pin,
            head_sha=request.head_sha,
            tags=request.tags,
            candidate_sha=request.candidate_sha,
            base_sha=request.base_sha,
            task_id=request.task_id if isinstance(request.task_id, str) else None,
            rule_version=request.rule_version,
        )
    except Exception as exc:
        state.self_close()
        return _internal(request, exc)
    if not pin.ok:
        return _pipeline_result(
            decision="REJECT",
            reason="TAMPER_PIN_UNSET_OR_INVALID",
            request=request,
            checks={"tamper_pin": pin.result.public_dict()},
            details={
                "merged": False,
                "merge_attempted": False,
                "fallback_used": False,
                "other_gates": "not_executed",
                "pin": pin.result.evidence.get("details"),
                "intercept_record": {
                    "decision": "REJECT",
                    "reason_code": "TAMPER_PIN_UNSET_OR_INVALID",
                    "merged": False,
                    "timestamp": now_cst(),
                },
            },
        )
    try:
        return _evaluate_pinned(request, pin.runtime)
    except Exception as exc:
        state.self_close()
        return _internal(request, exc)


def _internal(request: LandingRequest, exc: Exception) -> GateResult:
    return _pipeline_result(
        decision="REJECT",
        reason="GATE_INTERNAL_ERROR",
        request=request,
        checks={},
        details={
            "exception_type": type(exc).__name__,
            "fail_closed": True,
            "path_b_self_closed": True,
            "merged": False,
            "message": "injected fault" if "injected fault" in str(exc) else "gate failure",
        },
    )


def _evaluate_pinned(request: LandingRequest, runtime) -> GateResult:
    rules = runtime.rules
    scope_result = scope_decide(
        request.task_id,
        request.candidate_sha,
        request.base_sha,
        request.changed_paths,
        request.registry,
        rule_version=request.rule_version,
        rule_digest=rules.digest,
    )
    verification_result = verification_decide(
        request.receipt,
        request.candidate_sha,
        request.base_sha,
        request.task_id,
        request.rule_version,
        request.trusted_issuers,
        request.ledger,
        lineage=request.lineage,
        rule_digest=rules.digest,
    )
    tree = measure_tree(request.blobs)
    policy_result = policy_decide(
        tree["tree_sha"],
        request.candidate_sha,
        request.base_sha,
        request.target_branch_config,
        rules,
        blobs=request.blobs,
        changed_paths=request.changed_paths,
        task_id=request.task_id if isinstance(request.task_id, str) else None,
        candidate_rules=request.candidate_rules,
        audit=request.audit_log,
        rule_version=request.rule_version,
    )
    tamper_result = path_filter(
        request.changed_paths,
        candidate_sha=request.candidate_sha,
        base_sha=request.base_sha,
        task_id=request.task_id if isinstance(request.task_id, str) else None,
        rule_version=request.rule_version,
        rule_digest=rules.digest,
    )
    binding_result = binding_decide([scope_result, verification_result, policy_result])
    recovery_result = verify_recovery(
        request.recovery_plan,
        request.candidate_sha,
        request.base_sha,
        repo=request.recovery_repo,
        board=request.board,
        rule_version=request.rule_version,
        task_id=request.task_id if isinstance(request.task_id, str) else None,
        rule_digest=rules.digest,
    )
    kill_category = None
    policy_details = policy_result.evidence["details"]
    if policy_details.get("kill_line_event"):
        kill_category = policy_details["kill_line_event"]["category"]
    elif policy_details.get("kill_hits"):
        kill_category = policy_details["kill_hits"][0]["category"]
    activation_result = evaluate_for_landing(
        request.activation_state,
        irreversible=request.irreversible,
        kill_category=kill_category,
        candidate_sha=request.candidate_sha,
        base_sha=request.base_sha,
        task_id=request.task_id if isinstance(request.task_id, str) else None,
        rule_version=request.rule_version,
        rule_digest=rules.digest,
    )
    ordered = [
        scope_result,
        verification_result,
        policy_result,
        tamper_result,
        binding_result,
        recovery_result,
        activation_result,
    ]
    decision, reason = _primary(ordered)
    verified_candidate = binding_result.candidate_sha
    verified_base = binding_result.base_sha
    merge_candidate = request.merge_candidate_sha or request.candidate_sha
    head_ok = request.current_head_sha == verified_base and merge_candidate == verified_candidate
    checks = {
        "scope": scope_result.public_dict(),
        "verification": verification_result.public_dict(),
        "policy": policy_result.public_dict(),
        "tamper_path": tamper_result.public_dict(),
        "binding": binding_result.public_dict(),
        "recovery": recovery_result.public_dict(),
        "activation": activation_result.public_dict(),
        "tamper_pin": {"decision": "PASS", "reason_code": None, "runtime_source": "pin"},
    }
    merged = False
    merge_attempted = False
    merge_public = None
    if decision == "PASS":
        merge_attempted = True
        receipt_id = request.receipt.get("receipt_id") if isinstance(request.receipt, dict) else ""
        land_evidence = {
            "gate_records": {
                "scope": _summary(scope_result),
                "verification": _summary(verification_result),
                "policy": _summary(policy_result),
                "binding": _summary(binding_result),
                "recovery": _summary(recovery_result),
            },
            "timestamp": now_cst(),
            "receipt_id": receipt_id,
            "candidate_sha": verified_candidate,
            "base_sha": verified_base,
        }
        holder: dict = {}

        def publish() -> bool:
            holder["board"] = publish_board(
                land_evidence,
                request.board,
                candidate_sha=verified_candidate,
                base_sha=verified_base,
                rule_version=request.rule_version,
                task_id=request.task_id if isinstance(request.task_id, str) else None,
                rule_digest=rules.digest,
            )
            return holder["board"].decision == "PASS"

        merge_result = compare_and_merge(
            verified_candidate,
            verified_base,
            receipt_id,
            current_head_sha=request.current_head_sha,
            merge_candidate_sha=merge_candidate,
            ledger=request.ledger,
            task_id=request.task_id if isinstance(request.task_id, str) else None,
            rule_version=request.rule_version,
            rule_digest=rules.digest,
            publish=request.publisher,
            board_publish=publish,
        )
        checks["atomic_merge"] = merge_result.public_dict()
        if "board" in holder:
            checks["board"] = holder["board"].public_dict()
        decision, reason = merge_result.decision, merge_result.reason_code
        merged = merge_result.decision == "PASS"
        merge_public = merge_result
    details = {
        "merged": merged,
        "merge_attempted": merge_attempted,
        "fallback_used": False,
        "runtime_source": getattr(runtime, "source", "pin"),
        "evidence_class": "REAL_ISOLATION_EVIDENCE" if getattr(runtime, "source", "") == "pin_loadpath" else "STACK_OK_BUILDER_EVIDENCE",
        "candidate_code_used": None,
        "gates_pin_sha_source": "external_manifest",
        "kill_line_event": policy_details.get("kill_line_event"),
        "head_observation": {
            "evaluated": True,
            "current_head_sha": request.current_head_sha,
            "verified_base_sha": verified_base,
            "verified_candidate_sha": verified_candidate,
            "merge_candidate_sha": merge_candidate,
            "decision": "PASS" if head_ok else "REJECT",
            "reason_code": None if head_ok else "ATOMIC_MERGE_HEAD_MISMATCH",
            "consumed": merged,
        },
    }
    if reason == "ACTIVATION_PATH_B_DISABLED":
        details["message"] = "Path B disabled"
    if reason == "ACTIVATION_KILL_LINE":
        details["category"] = activation_result.evidence["details"].get("category")
    if reason == "INTEGRITY_RECOVERY_MISSING":
        details["message"] = recovery_result.evidence["details"].get("message")
    if reason == "INTEGRITY_RECOVERY_UNVERIFIED":
        details["message"] = recovery_result.evidence["details"].get("message")
    if decision == "REJECT":
        details["intercept_record"] = {
            "decision": "REJECT",
            "reason_code": reason,
            "merged": False,
            "timestamp": now_cst(),
        }
    if merge_public is not None:
        details["final_slot"] = merge_public.evidence["details"].get("compared")
    return _pipeline_result(decision=decision, reason=reason, request=request, checks=checks, details=details)
