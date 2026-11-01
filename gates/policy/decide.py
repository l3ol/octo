"""Policy gate P-1..P-6. Decisions use the pinned rule set, never candidate rules."""

from __future__ import annotations

from gates.policy.audit import RuleAuditLog, record_policy_decision
from gates.policy.content import scan_brain_or_backup, scan_kill_lines, scan_secrets
from gates.policy.forbidden import evaluate_paths
from gates.policy.size import measure_tree
from gates.rules import RULES, RuleSet
from gates.tamper.downgrade import detect_downgrade
from gates.types import failed, first_rejection, make_result, passed


def check_downstream(target_branch_config: dict | None) -> dict:
    config = target_branch_config or {}
    webhooks = list(config.get("webhooks") or [])
    workflows = []
    for step in config.get("workflows") or []:
        if step.get("auto_deploy") or step.get("kind") in {"deploy", "notify", "billing", "migration", "delete"}:
            workflows.append(step.get("name") or step.get("kind") or "workflow")
    if webhooks or workflows:
        return failed(
            "downstream",
            "POLICY_DOWNSTREAM_SIDE_EFFECT",
            path_b_fail_closed=True,
            webhooks=len(webhooks),
            workflows=workflows,
        )
    return passed("downstream", path_b_fail_closed=False)


def decide(
    candidate_tree_sha: str,
    candidate_sha: str,
    base_sha: str,
    target_branch_config: dict | None,
    rules: RuleSet | None = None,
    *,
    blobs: list[tuple[str, bytes]],
    changed_paths: list[str],
    task_id: str | None,
    candidate_rules: dict | None = None,
    audit: RuleAuditLog | None = None,
    rule_version: str | None = None,
):
    rules = rules or RULES
    version = rule_version or rules.version
    measurement = measure_tree(blobs)
    checks = []
    if candidate_tree_sha != measurement["tree_sha"]:
        checks.append(failed("tree_identity", "GATE_INTERNAL_ERROR"))
    else:
        checks.append(passed("tree_identity"))

    secret_hits = []
    brain_hits = []
    kill_hits = []
    for path, content in blobs:
        secret_hits.extend(scan_secrets(path, content))
        brain_hits.extend(scan_brain_or_backup(path, content))
        kill_hits.extend(scan_kill_lines(path, content))
    if secret_hits:
        checks.append(failed("secrets", "POLICY_SECRET_PATTERN", hits=[{"path": h["path"], "pattern_id": h["pattern_id"]} for h in secret_hits]))
    else:
        checks.append(passed("secrets"))
    if brain_hits:
        checks.append(failed("brain_or_backup", "POLICY_BRAIN_OR_BACKUP", hits=[{"path": h["path"], "kind": h["kind"]} for h in brain_hits]))
    else:
        checks.append(passed("brain_or_backup"))
    size_view = {
        "candidate_sha": candidate_sha,
        "candidate_tree_sha": measurement["tree_sha"],
        "blobs": measurement["blobs"],
        "total_bytes": measurement["total_bytes"],
        "threshold": measurement["threshold"],
        "comparison": measurement["comparison"],
        "rule_version": version,
    }
    if measurement["rejected"]:
        checks.append(failed("size", "POLICY_SIZE_EXCEEDED", **{"measurement": size_view}))
    else:
        checks.append(passed("size", measurement=size_view))

    path_inputs = list(changed_paths) + [path for path, _content in blobs]
    path_check = evaluate_paths(path_inputs, rules.patterns, rules.digest)
    checks.append(path_check)
    checks.append(check_downstream(target_branch_config))
    checks.append(detect_downgrade(rules, candidate_rules))

    decision, reason = first_rejection(checks)
    matched = []
    for item in checks:
        if item["decision"] != "REJECT":
            continue
        code = item["reason_code"]
        if code == "POLICY_SECRET_PATTERN":
            matched.append("P-1")
        elif code == "POLICY_BRAIN_OR_BACKUP":
            matched.append("P-2")
        elif code == "POLICY_SIZE_EXCEEDED":
            matched.append("P-3")
        elif code == "POLICY_FORBIDDEN_PATH":
            matched.append("P-4")
        elif code == "POLICY_DOWNSTREAM_SIDE_EFFECT":
            matched.append("P-5")
        elif code == "POLICY_RULE_DOWNGRADE":
            matched.append("P-6")
    p4_rows = path_check.get("paths") or []
    focus = next((row for row in p4_rows if row.get("matched_pattern") or row.get("normalization_error")), None)
    kill_event = None
    if secret_hits:
        kill_event = {
            "reason_code": "ACTIVATION_KILL_LINE",
            "category": "secret",
            "escalated_to": "founder",
        }
    details = {
        "matched_rules": matched,
        "package_sha": candidate_sha,
        "policy_evidence": {
            "matched_rules": matched,
            "package_sha": candidate_sha,
            "timestamp": None,
            "decision": decision,
            "rule_version": version,
            "rule_digest": rules.digest,
        },
        "size": size_view,
        "p4": p4_rows,
        "normalized_path": None if focus is None else focus.get("normalized_path"),
        "matched_pattern": None if focus is None else focus.get("matched_pattern"),
        "exception_applied": False if focus is None else focus.get("exception_applied"),
        "rule_digest": rules.digest,
        "normalization_error": None if focus is None else focus.get("normalization_error"),
        "kill_line_event": kill_event,
        "kill_hits": kill_hits,
        "path_b_fail_closed": reason == "POLICY_DOWNSTREAM_SIDE_EFFECT",
        "rules_source": "pin",
    }
    result = make_result(
        gate="policy",
        decision=decision,
        reason_code=reason,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=version,
        task_id=task_id,
        checks=checks,
        details=details,
        rule_digest=rules.digest,
    )
    evidence_row = dict(details["policy_evidence"])
    evidence_row["timestamp"] = result.evidence["timestamp"]
    result.evidence["details"]["policy_evidence"] = evidence_row
    # Digest was computed before the timestamp fill-in. Recompute so evidence matches.
    from gates.types import result_digest

    result = _with_digest(result)
    if audit is not None:
        record_policy_decision(audit, evidence_row)
    return result


def _with_digest(result):
    from gates.types import GateResult, result_digest

    digest = result_digest(
        result.gate,
        result.decision,
        result.reason_code,
        result.candidate_sha,
        result.base_sha,
        result.rule_version,
        result.evidence,
    )
    return GateResult(
        gate=result.gate,
        decision=result.decision,
        reason_code=result.reason_code,
        candidate_sha=result.candidate_sha,
        base_sha=result.base_sha,
        rule_version=result.rule_version,
        evidence=result.evidence,
        result_digest=digest,
        task_id=result.task_id,
    )
