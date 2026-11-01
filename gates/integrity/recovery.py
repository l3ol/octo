"""L-1 verified recovery plan."""

from __future__ import annotations

from collections.abc import Callable

from gates.types import is_sha40, make_result

MISSING_MESSAGE = "缺失经验证的恢复方案"
UNVERIFIED_MESSAGE = "恢复方案未通过验证"


def verify_recovery(
    recovery_plan: dict | None,
    candidate_sha: str,
    base_sha: str,
    *,
    commit_exists: Callable[[str], bool],
    rule_version: str,
    task_id: str | None,
    rule_digest: str,
):
    has_body = isinstance(recovery_plan, dict) and (
        recovery_plan.get("rollback_commit") or recovery_plan.get("forward_fix")
    )
    if not has_body:
        return make_result(
            gate="integrity",
            decision="REJECT",
            reason_code="INTEGRITY_RECOVERY_MISSING",
            candidate_sha=candidate_sha,
            base_sha=base_sha,
            rule_version=rule_version,
            task_id=task_id,
            checks=[
                {
                    "name": "recovery_present",
                    "decision": "REJECT",
                    "reason_code": "INTEGRITY_RECOVERY_MISSING",
                    "evaluated": True,
                }
            ],
            details={"message": MISSING_MESSAGE},
            rule_digest=rule_digest,
        )
    problems: list[str] = []
    rollback = recovery_plan.get("rollback_commit")
    if rollback:
        if not is_sha40(rollback) or not commit_exists(rollback):
            problems.append("rollback_missing")
    elif not recovery_plan.get("forward_fix"):
        problems.append("rollback_missing")
    if recovery_plan.get("drill_passed") is not True:
        problems.append("drill_failed")
    if recovery_plan.get("bound_candidate_sha") != candidate_sha or recovery_plan.get("bound_base_sha") != base_sha:
        problems.append("binding_mismatch")
    if problems:
        return make_result(
            gate="integrity",
            decision="REJECT",
            reason_code="INTEGRITY_RECOVERY_UNVERIFIED",
            candidate_sha=candidate_sha,
            base_sha=base_sha,
            rule_version=rule_version,
            task_id=task_id,
            checks=[
                {
                    "name": "recovery_verified",
                    "decision": "REJECT",
                    "reason_code": "INTEGRITY_RECOVERY_UNVERIFIED",
                    "evaluated": True,
                    "problems": problems,
                }
            ],
            details={"message": UNVERIFIED_MESSAGE, "problems": problems},
            rule_digest=rule_digest,
        )
    return make_result(
        gate="integrity",
        decision="PASS",
        reason_code=None,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        task_id=task_id,
        checks=[{"name": "recovery_verified", "decision": "PASS", "reason_code": None, "evaluated": True}],
        details={"message": None, "drill_passed": True},
        rule_digest=rule_digest,
    )
