"""M-1 final-slot compare. Uses the candidate and base the three gates already verified."""

from __future__ import annotations

from typing import Callable

from gates.types import make_result
from gates.verification.ledger import ConsumptionLedger


def _is_cas_publisher(publish) -> bool:
    return callable(getattr(publish, "compare_and_swap", None)) and callable(getattr(publish, "read_ref", None)) and callable(getattr(publish, "transaction", None))


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
    board_publish: Callable[[], bool] | None = None,
):
    """Compare verified candidate SHA and verified base SHA at the merge slot.

    `publish is None` is fail-closed. It does not merge and it does not move a ref.
    A real publisher is an isolated git update-ref adapter.
    """
    del current_head_sha  # the slot reads the publisher ref; a caller-supplied head is not authority
    fields = []
    if merge_candidate_sha != verified_candidate_sha:
        fields.append("candidate")
    compared = {
        "verified_candidate_sha": verified_candidate_sha,
        "verified_base_sha": verified_base_sha,
        "merge_candidate_sha": merge_candidate_sha,
        "slot": "final",
    }
    if publish is None or not _is_cas_publisher(publish):
        return _finish(
            decision="REJECT",
            reason="ATOMIC_MERGE_PUBLISHER_MISSING",
            verified_candidate_sha=verified_candidate_sha,
            verified_base_sha=verified_base_sha,
            task_id=task_id,
            rule_version=rule_version,
            rule_digest=rule_digest,
            outcome="publisher_missing",
            details={
                "compared": compared,
                "mismatch_fields": fields,
                "publisher": "missing",
                "merged": False,
                "landing_ref_before": None,
                "landing_ref_after": None,
            },
        )
    if fields:
        before = publish.read_ref()
        return _finish(
            decision="REJECT",
            reason="ATOMIC_MERGE_HEAD_MISMATCH",
            verified_candidate_sha=verified_candidate_sha,
            verified_base_sha=verified_base_sha,
            task_id=task_id,
            rule_version=rule_version,
            rule_digest=rule_digest,
            outcome="head_mismatch",
            details={
                "compared": compared,
                "mismatch_fields": fields,
                "publisher": "git-update-ref",
                "merged": False,
                "landing_ref_before": before,
                "landing_ref_after": before,
            },
        )
    try:
        outcome, before, after = publish.transaction(
            receipt_id=receipt_id,
            expected_base=verified_base_sha,
            new_commit=merge_candidate_sha,
            board_fn=board_publish,
        )
    except Exception:
        after = publish.read_ref()
        return _finish(
            decision="REJECT",
            reason="GATE_INTERNAL_ERROR",
            verified_candidate_sha=verified_candidate_sha,
            verified_base_sha=verified_base_sha,
            task_id=task_id,
            rule_version=rule_version,
            rule_digest=rule_digest,
            outcome="publisher_exception",
            details={
                "compared": compared,
                "mismatch_fields": fields,
                "publisher": "git-update-ref",
                "merged": False,
                "landing_ref_before": None,
                "landing_ref_after": after,
                "path_b": False,
            },
        )
    if outcome == "merged":
        record = {
            "receipt_id": receipt_id,
            "verified_candidate_sha": verified_candidate_sha,
            "verified_base_sha": verified_base_sha,
            "merge_candidate_sha": merge_candidate_sha,
            "landing_ref_after": after,
        }
        with ledger._lock:
            ledger._consumed[receipt_id] = record
            ledger.merges.append(record)
        decision, reason = "PASS", None
    elif outcome == "conflict":
        decision, reason = "REJECT", "VERIFICATION_RECEIPT_CONFLICT"
    elif outcome == "board_invisible":
        decision, reason = "REJECT", "INTEGRITY_BOARD_INVISIBLE"
    elif outcome == "head_mismatch":
        decision, reason = "REJECT", "ATOMIC_MERGE_HEAD_MISMATCH"
    else:
        decision, reason = "REJECT", "GATE_INTERNAL_ERROR"
    return _finish(
        decision=decision,
        reason=reason,
        verified_candidate_sha=verified_candidate_sha,
        verified_base_sha=verified_base_sha,
        task_id=task_id,
        rule_version=rule_version,
        rule_digest=rule_digest,
        outcome=outcome,
        details={
            "compared": compared,
            "mismatch_fields": fields,
            "publisher": "git-update-ref",
            "merged": outcome == "merged",
            "landing_ref_before": before,
            "landing_ref_after": after,
        },
    )


def _finish(*, decision, reason, verified_candidate_sha, verified_base_sha, task_id, rule_version, rule_digest, outcome, details):
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
        details=details,
        rule_digest=rule_digest,
    )
