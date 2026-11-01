"""L-2 board visibility for a landing evidence bundle."""

from __future__ import annotations

from dataclasses import dataclass, field

from gates.types import make_result

REQUIRED_FIELDS = ("gate_records", "timestamp", "receipt_id", "candidate_sha", "base_sha")
REQUIRED_GATES = ("scope", "verification", "policy")


@dataclass
class Board:
    visible: bool = True
    entries: list = field(default_factory=list)

    def read_all(self) -> list:
        if not self.visible:
            return []
        return list(self.entries)


def publish_board(
    land_evidence: dict,
    board: Board,
    *,
    candidate_sha: str,
    base_sha: str,
    rule_version: str,
    task_id: str | None,
    rule_digest: str,
):
    missing = [key for key in REQUIRED_FIELDS if not land_evidence.get(key)]
    records = land_evidence.get("gate_records") if isinstance(land_evidence.get("gate_records"), dict) else {}
    for name in REQUIRED_GATES:
        record = records.get(name) if isinstance(records, dict) else None
        if not isinstance(record, dict) or "decision" not in record or "timestamp" not in record:
            missing.append(f"gate_records.{name}")
    if not board.visible or missing:
        return make_result(
            gate="integrity",
            decision="REJECT",
            reason_code="INTEGRITY_BOARD_INVISIBLE",
            candidate_sha=candidate_sha,
            base_sha=base_sha,
            rule_version=rule_version,
            task_id=task_id,
            checks=[
                {
                    "name": "board_visible",
                    "decision": "REJECT",
                    "reason_code": "INTEGRITY_BOARD_INVISIBLE",
                    "evaluated": True,
                }
            ],
            details={"missing": missing, "visible": board.visible},
            rule_digest=rule_digest,
        )
    board.entries.append(dict(land_evidence))
    shown = board.read_all()
    if not shown or shown[-1].get("receipt_id") != land_evidence.get("receipt_id"):
        return make_result(
            gate="integrity",
            decision="REJECT",
            reason_code="INTEGRITY_BOARD_INVISIBLE",
            candidate_sha=candidate_sha,
            base_sha=base_sha,
            rule_version=rule_version,
            task_id=task_id,
            checks=[
                {
                    "name": "board_visible",
                    "decision": "REJECT",
                    "reason_code": "INTEGRITY_BOARD_INVISIBLE",
                    "evaluated": True,
                }
            ],
            details={"missing": ["readback"], "visible": board.visible},
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
        checks=[{"name": "board_visible", "decision": "PASS", "reason_code": None, "evaluated": True}],
        details={"visible": True, "entry_count": len(board.entries)},
        rule_digest=rule_digest,
    )
