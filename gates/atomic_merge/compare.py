"""M-1 final-slot compare. Uses the candidate and base the three gates already verified."""

from __future__ import annotations

from typing import Callable

from gates.types import make_result
from gates.verification.ledger import ConsumptionLedger


def compare_and_merge(
    verified_candidate_sha: str,
    verified_base_sha: str,
    receipt_id: str,
    *,
    current_head_sha: str,
    merge_candidate_sha: str,
    ledger: ConsumptionLedger,
    task_id: str | None,
    rule_version: str,
    rule_digest: str,
    publish: Callable[[], bool] | None = None,
):
    """Compare verified candidate SHA and verified base SHA at the merge slot.

    Canonical parameter line 55 is left unchanged. This slot does not read a
    candidate-supplied replacement for that comparison.
    """
    head_ok = (
        current_head_sha == verified_base_sha
        and merge_candidate_sha == verified_candidate_sha
    )
    fields = []
    if current_head_sha != verified_base_sha:
        fields.append("base")
    if merge_candidate_sha != verified_candidate_sha:
        fields.append("candidate")
    record = {
        "receipt_id": receipt_id,
        "verified_candidate_sha": verified_candidate_sha,
        "verified_base_sha": verified_base_sha,
        "merge_candidate_sha": merge_candidate_sha,
        "current_head_sha": current_head_sha,
    }

    def _publish() -> bool:
        if publish is None:
            return True
        return publish() is True

    outcome = ledger.finalize(
        head_ok=head_ok,
        receipt_id=receipt_id,
        record=record,
        publish=_publish,
    )
    compared = {
        "verified_candidate_sha": verified_candidate_sha,
        "verified_base_sha": verified_base_sha,
        "current_head_sha": current_head_sha,
        "merge_candidate_sha": merge_candidate_sha,
        "slot": "final",
    }
    if outcome == "head_mismatch":
        reason = "ATOMIC_MERGE_HEAD_MISMATCH"
        decision = "REJECT"
    elif outcome == "conflict":
        reason = "VERIFICATION_RECEIPT_CONFLICT"
        decision = "REJECT"
    elif outcome == "board_invisible":
        reason = "INTEGRITY_BOARD_INVISIBLE"
        decision = "REJECT"
    elif outcome == "merged":
        reason = None
        decision = "PASS"
    else:
        reason = "GATE_INTERNAL_ERROR"
        decision = "REJECT"
    return make_result(
        gate="atomic_merge",
        decision=decision,
        reason_code=reason,
        candidate_sha=verified_candidate_sha,
        base_sha=verified_base_sha,
        rule_version=rule_version,
        task_id=task_id,
        checks=[
            {
                "name": "final_slot",
                "decision": decision,
                "reason_code": reason,
                "evaluated": True,
                "outcome": outcome,
            }
        ],
        details={"compared": compared, "mismatch_fields": fields, "merged": outcome == "merged"},
        rule_digest=rule_digest,
    )
