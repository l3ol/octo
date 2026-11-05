"""Scope and handoff metadata checks for the current Formal Reviewer.

This module does not sign, does not migrate an old agent signature, and does
not mark tip f95 FINAL. ``runtime_pass`` stays false. Old PASS invalidation
stays the A2 quadruple: base_sha, candidate_sha, scope_digest, fixture_digest.
"""

from __future__ import annotations

from typing import Any, Mapping

FORMAL_REVIEWER_ID = "TA-CHAT-REVIEWER-OCTO-20261101-01"
HISTORICAL_AGENT_ID = "agt_6ae61c44e54081918e81a0adea556ef8"
TIP_F95 = "f95c76bf4a3c22e201b2a8e5efff7f07c77a02a3"
TIP_F95_TREE = "9dd4337daabcfd38ee5325ad38c4edc81eeb8ce8"
A2_INVALIDATION_FIELDS = ("base_sha", "candidate_sha", "scope_digest", "fixture_digest")
INDEPENDENCE_FLAGS = {
    "builder_may_sign_pass": False,
    "g3_requires_reviewer_qualification_after_candidate_freeze": True,
    "review_entry_issues_pass": False,
    "squad_reviewer_prepares_entry_only": True,
}
_NOT_REVIEWER = frozenset({"TB", "BUILDER", "DEVSPACE_VERIFIER"})
_RULE_KEYS = frozenset({"issuer_allowlist", "source_allowlist"})
_CUSTODY_KEYS = frozenset({
    "custody_ref",
    "raw_bytes",
    "bytes_sha256",
    "reviewer_original",
    "source_session",
})
_REWRITE_PURPOSES = frozenset({"hash_cycle", "reconcile_hash"})


def _dedupe(reasons: list[str]) -> list[str]:
    seen: list[str] = []
    for reason in reasons:
        if reason not in seen:
            seen.append(reason)
    return seen


def _result(reasons: list[str], **extra: Any) -> dict[str, Any]:
    unique = _dedupe(reasons)
    body = {"ok": not unique, "reasons": unique}
    body.update(extra)
    return body


def _migration_claimed(obj: Mapping[str, Any]) -> bool:
    if obj.get("signature_migration_claimed") is True:
        return True
    if obj.get("signed_on_behalf_of"):
        return True
    if obj.get("migrated_from_agent"):
        return True
    return False


def assess_scope_reviewer(scope: Mapping[str, Any]) -> dict[str, Any]:
    """Current Formal Reviewer binding, independence flags, and non-FINAL seal."""
    reasons: list[str] = []
    if not isinstance(scope, Mapping):
        return _result(["SCOPE_REVIEWER_STALE", "INDEPENDENCE_REGRESSED", "NONFINAL_FALSE_SEAL"])
    separation = scope.get("reviewer_separation")
    handoff = scope.get("handoff")
    if not isinstance(separation, Mapping):
        separation = {}
        reasons.append("SCOPE_REVIEWER_STALE")
        reasons.append("INDEPENDENCE_REGRESSED")
    if not isinstance(handoff, Mapping):
        handoff = {}
        reasons.append("SCOPE_REVIEWER_STALE")
    slots = (
        separation.get("formal_reviewer_id"),
        separation.get("g3_reviewer_agent_id"),
        handoff.get("formal_reviewer_id"),
    )
    note = separation.get("historical_reviewer_note")
    if isinstance(note, Mapping) and note.get("current_formal_reviewer") is True:
        reasons.append("SCOPE_REVIEWER_STALE")
    from octo.trusted_original import current_appointment
    appointment = current_appointment()
    issuer = appointment.get("issuer_id") if isinstance(appointment, dict) else None
    if not isinstance(issuer, str) or not issuer:
        reasons.append("SCOPE_REVIEWER_STALE")
    elif any(slot == HISTORICAL_AGENT_ID or slot in _NOT_REVIEWER or slot != issuer for slot in slots):
        reasons.append("SCOPE_REVIEWER_STALE")
    if any(slot in _NOT_REVIEWER for slot in slots):
        reasons.append("INDEPENDENCE_REGRESSED")
    for key, expected in INDEPENDENCE_FLAGS.items():
        if separation.get(key) is not expected:
            reasons.append("INDEPENDENCE_REGRESSED")
            break
    if _migration_claimed(separation) or _migration_claimed(handoff) or (
        isinstance(note, Mapping) and _migration_claimed(note)
    ):
        reasons.append("SIGNATURE_MIGRATION_CLAIM")
    strategy = scope.get("isolation_strategy")
    strategy = strategy if isinstance(strategy, Mapping) else {}
    if strategy.get("final_sha") is True or (
        "freeze_status" in strategy and strategy.get("freeze_status") != "NONFINAL_HOLD_AE"
    ):
        reasons.append("NONFINAL_FALSE_SEAL")
    if handoff.get("final_sha") is True or handoff.get("tip_f95_final") is True:
        reasons.append("NONFINAL_FALSE_SEAL")
    if "freeze_status" in handoff and handoff.get("freeze_status") != "NONFINAL_HOLD_AE":
        reasons.append("NONFINAL_FALSE_SEAL")
    return _result(reasons)


def assess_product_scope() -> dict[str, Any]:
    from octo.g3_review import product_scope

    return assess_scope_reviewer(product_scope())


def assess_tip_seal(record: Mapping[str, Any]) -> dict[str, Any]:
    """tip f95 stays mechanism-retest evidence. A final seal on it is refused."""
    reasons: list[str] = []
    if not isinstance(record, Mapping):
        return _result(["NONFINAL_FALSE_SEAL"])
    identified = record.get("sha", record.get("tip"))
    if identified != TIP_F95:
        return _result(reasons)
    if record.get("final") is True or record.get("final_sha") is True or record.get("tip_f95_final") is True:
        reasons.append("NONFINAL_FALSE_SEAL")
    if record.get("treated_as_final_tuple") is True or record.get("role") in {"final_tuple", "final_candidate"}:
        reasons.append("NONFINAL_FALSE_SEAL")
    freeze = record.get("freeze_status")
    if freeze is not None and freeze != "NONFINAL_HOLD_AE":
        reasons.append("NONFINAL_FALSE_SEAL")
    return _result(reasons)


def assess_freeze_order(steps: list[Any]) -> dict[str, Any]:
    """Static scope/handoff bytes commit before a new tuple. Do not FINAL f95 first."""
    reasons: list[str] = []
    f95_marked_final = False
    static_committed = False
    for step in steps:
        if not isinstance(step, Mapping):
            reasons.append("FREEZE_ORDER_VIOLATION")
            continue
        op = step.get("op")
        tip = step.get("tip")
        if op == "mark_final" and tip == TIP_F95:
            f95_marked_final = True
            reasons.append("NONFINAL_FALSE_SEAL")
        elif op == "patch_scope" and f95_marked_final:
            reasons.append("FREEZE_ORDER_VIOLATION")
        elif op == "commit_static":
            if step.get("includes_scope_reviewer") is True and step.get("includes_handoff") is True:
                static_committed = True
            else:
                reasons.append("FREEZE_ORDER_VIOLATION")
        elif op == "bind_tuple":
            if not static_committed or step.get("static_bytes_committed") is not True:
                reasons.append("FREEZE_ORDER_VIOLATION")
            if tip == TIP_F95 and (step.get("final") is True or f95_marked_final):
                reasons.append("NONFINAL_FALSE_SEAL")
        elif op == "false_seal":
            reasons.append("NONFINAL_FALSE_SEAL")
    return _result(reasons)


def register_external_inputs(entries: list[Any]) -> dict[str, Any]:
    """Rule config and reviewer custody stay in separate logs. Neither rewrites the candidate."""
    reasons: list[str] = []
    rule_log: list[dict[str, Any]] = []
    custody_log: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            reasons.append("INPUT_CLASS_MIXED")
            continue
        if entry.get("rewrite_candidate") is True or entry.get("purpose") in _REWRITE_PURPOSES:
            reasons.append("CANDIDATE_REWRITE_FORBIDDEN")
            continue
        rule_keys = _RULE_KEYS & set(entry)
        custody_keys = _CUSTODY_KEYS & set(entry)
        declared = entry.get("input_class")
        if declared in {"temp_log", "mixed"} or (rule_keys and custody_keys):
            reasons.append("INPUT_CLASS_MIXED")
            continue
        if rule_keys or declared == "rule_config":
            sha = entry.get("sha256")
            if not isinstance(sha, str) or not sha:
                reasons.append("INPUT_CLASS_MIXED")
                continue
            rule_log.append({
                "class": "rule_config",
                "sha256": sha,
                "issuer_allowlist": "issuer_allowlist" in entry,
                "source_allowlist": "source_allowlist" in entry,
            })
            continue
        if custody_keys or declared == "reviewer_original_custody":
            if entry.get("inside_candidate") is True or entry.get("outside_candidate") is not True:
                reasons.append("CANDIDATE_REWRITE_FORBIDDEN")
                continue
            digest = entry.get("bytes_sha256")
            if not isinstance(digest, str) or not digest:
                reasons.append("CANDIDATE_REWRITE_FORBIDDEN")
                continue
            custody_log.append({
                "class": "reviewer_original_custody",
                "bytes_sha256": digest,
                "outside_candidate": True,
                "not_issuer": True,
            })
            continue
        reasons.append("INPUT_CLASS_MIXED")
    return _result(reasons, rule_config_log=rule_log, custody_log=custody_log)


def refuse_candidate_rewrite(candidate: Mapping[str, Any], action: Mapping[str, Any]) -> dict[str, Any]:
    """Refuse a rewrite that exists to break a hash cycle. The candidate bytes stay as given."""
    reasons: list[str] = []
    if not isinstance(action, Mapping) or action.get("rewrite_candidate") is True or action.get("purpose") in _REWRITE_PURPOSES:
        reasons.append("CANDIDATE_REWRITE_FORBIDDEN")
    return _result(reasons, candidate=dict(candidate))


def assess_pass_after_rule_change(
    stored: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    still_accepted: bool,
) -> dict[str, Any]:
    """A changed A2 field invalidates the old PASS. No fifth gate is added."""
    from octo.g3_review import invalidate_stored_pass

    invalidation = invalidate_stored_pass(stored, current)
    reasons: list[str] = []
    if invalidation["status"] == "INVALID" and still_accepted:
        reasons.append("STALE_PASS")
    if any(name not in A2_INVALIDATION_FIELDS for name in invalidation["reasons"]):
        reasons.append("STALE_PASS")
    return _result(
        reasons,
        invalidation=invalidation,
        invalidate_fields=list(A2_INVALIDATION_FIELDS),
    )
