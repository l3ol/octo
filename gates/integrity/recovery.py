"""L-1 recovery. drill_passed is derived from a readable drill receipt, not a hand-filled bool."""

from __future__ import annotations

import json
from pathlib import Path

from gates.gitcmd import cat_file_commit
from gates.types import is_sha40, make_result

MISSING_MESSAGE = "缺失经验证的恢复方案"
UNVERIFIED_MESSAGE = "恢复方案未通过验证"
_RECEIPT_FIELDS = (
    "receipt_id",
    "result",
    "started_at",
    "ended_at",
    "operations",
    "ref_before",
    "ref_after",
    "candidate_sha",
    "base_sha",
    "rollback_commit",
)


def _load_json(path: str | None) -> dict | None:
    if not path:
        return None
    file_path = Path(path)
    if not file_path.is_file():
        return None
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def verify_recovery(
    recovery_plan: dict | None,
    candidate_sha: str,
    base_sha: str,
    *,
    commit_exists=None,
    repo: str | None = None,
    board=None,
    rule_version: str,
    task_id: str | None,
    rule_digest: str,
):
    del commit_exists  # a caller lambda is not proof of a commit or a drill
    has_body = isinstance(recovery_plan, dict) and (
        recovery_plan.get("rollback_commit") or recovery_plan.get("forward_fix") or recovery_plan.get("drill_receipt_path")
    )
    if not isinstance(recovery_plan, dict) or not has_body:
        return _result(
            "REJECT",
            "INTEGRITY_RECOVERY_MISSING",
            candidate_sha,
            base_sha,
            rule_version,
            task_id,
            rule_digest,
            {"message": MISSING_MESSAGE},
            "recovery_present",
        )
    problems: list[str] = []
    on_disk = _load_json(recovery_plan.get("drill_receipt_path"))
    embedded = recovery_plan.get("drill_receipt") if isinstance(recovery_plan.get("drill_receipt"), dict) else None
    receipt = on_disk or embedded
    derived = bool(receipt) and receipt.get("result") == "PASS"
    if "drill_passed" in recovery_plan and bool(recovery_plan.get("drill_passed")) != derived:
        problems.append("drill_passed_not_derived")
    if receipt is None:
        problems.append("drill_receipt_missing")
    else:
        for field in _RECEIPT_FIELDS:
            if field not in receipt:
                problems.append(f"receipt_field:{field}")
        if receipt.get("result") != "PASS":
            problems.append("drill_result_not_pass")
        if not str(receipt.get("started_at", "")).endswith("+08:00") or not str(receipt.get("ended_at", "")).endswith("+08:00"):
            problems.append("drill_timestamp")
        if not isinstance(receipt.get("operations"), list) or not receipt["operations"]:
            problems.append("drill_operations")
    rollback = recovery_plan.get("rollback_commit")
    if not is_sha40(rollback):
        problems.append("rollback_missing")
    elif repo is None or not cat_file_commit(repo, rollback):
        problems.append("rollback_missing")
    if recovery_plan.get("bound_candidate_sha") != candidate_sha or recovery_plan.get("bound_base_sha") != base_sha:
        problems.append("binding_mismatch")
    if receipt is not None and (
        receipt.get("candidate_sha") != candidate_sha or receipt.get("base_sha") != base_sha or receipt.get("rollback_commit") != rollback
    ):
        problems.append("receipt_binding")
    entry_id = recovery_plan.get("drill_board_entry_id")
    entry = board.read_drill(entry_id) if board is not None and entry_id else None
    board_file = _load_json(recovery_plan.get("drill_board_path"))
    if entry is None or board_file is None:
        problems.append("board_missing")
    elif entry.get("result") != (receipt or {}).get("result") or board_file.get("receipt_id") != (receipt or {}).get("receipt_id"):
        problems.append("board_mismatch")
    if problems:
        return _result(
            "REJECT",
            "INTEGRITY_RECOVERY_UNVERIFIED",
            candidate_sha,
            base_sha,
            rule_version,
            task_id,
            rule_digest,
            {"message": UNVERIFIED_MESSAGE, "problems": problems, "drill_passed": derived, "drill_passed_source": "drill_receipt.result"},
            "recovery_verified",
        )
    return _result(
        "PASS",
        None,
        candidate_sha,
        base_sha,
        rule_version,
        task_id,
        rule_digest,
        {"message": None, "drill_passed": True, "drill_passed_source": "drill_receipt.result", "drill_receipt_id": receipt["receipt_id"]},
        "recovery_verified",
    )


def _result(decision, reason, candidate_sha, base_sha, rule_version, task_id, rule_digest, details, check_name):
    return make_result(
        gate="integrity",
        decision=decision,
        reason_code=reason,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        task_id=task_id,
        checks=[{"name": check_name, "decision": decision, "reason_code": reason, "evaluated": True}],
        details=details,
        rule_digest=rule_digest,
    )
