"""Scope gate R-1..R-5."""

from __future__ import annotations

from gates.pathmatch import first_wildmatch, normalize_repo_path
from gates.types import failed, first_rejection, make_result, passed, skipped


def check_task_id_present(task_id: object) -> dict:
    if task_id is None or (isinstance(task_id, str) and task_id.strip() == ""):
        return failed("task_id_present", "SCOPE_MISSING_TASK_ID")
    if not isinstance(task_id, str):
        return failed("task_id_present", "SCOPE_MISSING_TASK_ID")
    return passed("task_id_present")


def check_task_active(task_id: str, registry: dict) -> tuple[dict, dict | None]:
    tasks = registry.get("tasks") if isinstance(registry, dict) else None
    task = tasks.get(task_id) if isinstance(tasks, dict) else None
    if not isinstance(task, dict) or task.get("status") != "active":
        return failed("task_active", "SCOPE_UNKNOWN_OR_CLOSED_TASK"), None
    return passed("task_active"), task


def check_paths_in_range(changed_paths: list[str], allowed_paths: list[str]) -> dict:
    outside: list[str] = []
    for raw in changed_paths:
        norm, err = normalize_repo_path(raw)
        target = norm or raw
        if err or first_wildmatch(target, allowed_paths) is None:
            outside.append(raw)
    if outside:
        return failed("paths_in_range", "SCOPE_OUT_OF_RANGE", paths=outside)
    return passed("paths_in_range")


def decide(
    task_id,
    candidate_sha: str,
    base_sha: str,
    changed_paths: list[str],
    registry: dict,
    *,
    rule_version: str,
    rule_digest: str,
) -> object:
    checks = [check_task_id_present(task_id)]
    task = None
    if checks[0]["decision"] == "PASS":
        active, task = check_task_active(task_id, registry)
        checks.append(active)
    else:
        checks.append(skipped("task_active"))
    if task is not None:
        checks.append(check_paths_in_range(changed_paths, list(task.get("allowed_paths") or [])))
    else:
        checks.append(skipped("paths_in_range"))
    decision, reason = first_rejection(checks)
    return make_result(
        gate="scope",
        decision=decision,
        reason_code=reason,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        task_id=task_id if isinstance(task_id, str) else None,
        checks=checks,
        details={"registry_machine_readable": isinstance(registry.get("tasks"), dict)},
        rule_digest=rule_digest,
    )
