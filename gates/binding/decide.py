"""J-1 / J-2. Three gate results must share candidate, base, rule version, and digests."""

from __future__ import annotations

from gates.types import GateResult, first_rejection, make_result, result_digest


def _digest_matches(result: GateResult) -> bool:
    expect = result_digest(
        result.gate,
        result.decision,
        result.reason_code,
        result.candidate_sha,
        result.base_sha,
        result.rule_version,
        result.evidence,
    )
    return expect == result.result_digest


def decide(results: list[GateResult]):
    mismatched: list[str] = []
    if len(results) < 3:
        mismatched.append("count")
    comparable = results[:3] if results else []
    if comparable:
        groups = {
            "candidate_sha": {item.candidate_sha for item in comparable},
            "base_sha": {item.base_sha for item in comparable},
            "rule_version": {item.rule_version for item in comparable},
            "rule_digest": {item.evidence.get("rule_digest") for item in comparable},
        }
        for name, values in groups.items():
            if len(values) != 1:
                mismatched.append(name)
        if any(not _digest_matches(item) for item in comparable):
            mismatched.append("result_digest")
    anchor = comparable[0] if comparable else None
    candidate_sha = anchor.candidate_sha if anchor else "0" * 40
    base_sha = anchor.base_sha if anchor else "0" * 40
    rule_version = anchor.rule_version if anchor else ""
    task_id = anchor.task_id if anchor else None
    rule_digest = anchor.evidence.get("rule_digest") if anchor else ""
    if mismatched:
        check = {
            "name": "binding",
            "decision": "REJECT",
            "reason_code": "BINDING_INCONSISTENT",
            "evaluated": True,
        }
        decision, reason = "REJECT", "BINDING_INCONSISTENT"
    else:
        check = {"name": "binding", "decision": "PASS", "reason_code": None, "evaluated": True}
        decision, reason = first_rejection([check])
    per_gate = [
        {
            "gate": item.gate,
            "decision": item.decision,
            "reason_code": item.reason_code,
            "candidate_sha": item.candidate_sha,
            "base_sha": item.base_sha,
            "rule_version": item.rule_version,
            "result_digest": item.result_digest,
        }
        for item in comparable
    ]
    return make_result(
        gate="binding",
        decision=decision,
        reason_code=reason,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        task_id=task_id,
        checks=[check],
        details={
            "mismatched_fields": mismatched,
            "per_gate": per_gate,
            "shared": {
                "candidate_sha": candidate_sha,
                "base_sha": base_sha,
                "rule_version": rule_version,
                "rule_digest": rule_digest,
            },
        },
        rule_digest=rule_digest or "",
    )
