"""P-6 rule-change trace. Candidate landings cannot apply a new rule set."""

from __future__ import annotations

from dataclasses import dataclass, field

from gates.types import now_cst


@dataclass
class RuleAuditLog:
    changes: list = field(default_factory=list)
    decisions: list = field(default_factory=list)


def record_rule_change(
    audit: RuleAuditLog,
    *,
    actor: str,
    before_digest: str,
    after_digest: str,
    rule_version_before: str,
    rule_version_after: str,
    timestamp: str | None = None,
) -> dict:
    entry = {
        "actor": actor,
        "timestamp": timestamp or now_cst(),
        "before_digest": before_digest,
        "after_digest": after_digest,
        "rule_version_before": rule_version_before,
        "rule_version_after": rule_version_after,
    }
    audit.changes.append(entry)
    return entry


def record_policy_decision(audit: RuleAuditLog, entry: dict) -> dict:
    audit.decisions.append(entry)
    return entry
