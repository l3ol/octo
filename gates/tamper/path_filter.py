"""G-2 / M-2 path filter. Running logic is this module, not candidate bytes."""

from __future__ import annotations

from gates.pathmatch import is_gates_protected, is_merge_bypass_path, normalize_repo_path
from gates.types import make_result, now_cst


def path_filter(
    changed_paths: list[str],
    *,
    candidate_sha: str,
    base_sha: str,
    task_id: str | None,
    rule_version: str,
    rule_digest: str,
):
    protected: list[str] = []
    bypass: list[str] = []
    for raw in changed_paths:
        norm, err = normalize_repo_path(raw)
        if err or norm is None:
            continue
        if is_merge_bypass_path(norm):
            bypass.append(norm)
        if is_gates_protected(norm):
            protected.append(norm)
    hit = protected or bypass
    details = {
        "protected_paths": protected,
        "bypass_paths": bypass,
        "bypass_attempt": bool(bypass),
        "runtime_source": "pin",
        "candidate_code_used": False,
        "runtime_unaffected": True,
    }
    if hit:
        details["attack_record"] = {
            "detected": True,
            "paths": protected or bypass,
            "timestamp": now_cst(),
        }
        return make_result(
            gate="tamper",
            decision="REJECT",
            reason_code="TAMPER_GATES_PATH_TOUCHED",
            candidate_sha=candidate_sha,
            base_sha=base_sha,
            rule_version=rule_version,
            task_id=task_id,
            checks=[
                {
                    "name": "gates_path",
                    "decision": "REJECT",
                    "reason_code": "TAMPER_GATES_PATH_TOUCHED",
                    "evaluated": True,
                }
            ],
            details=details,
            rule_digest=rule_digest,
        )
    return make_result(
        gate="tamper",
        decision="PASS",
        reason_code=None,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        task_id=task_id,
        checks=[
            {
                "name": "gates_path",
                "decision": "PASS",
                "reason_code": None,
                "evaluated": True,
            }
        ],
        details=details,
        rule_digest=rule_digest,
    )
