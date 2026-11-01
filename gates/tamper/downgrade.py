"""G-3 rule downgrade: removal or relaxation relative to the pinned rule set."""

from __future__ import annotations

from gates.rules import RuleSet
from gates.types import failed, passed


def detect_downgrade(pinned: RuleSet, candidate_rules: dict | None) -> dict:
    if candidate_rules is None:
        return passed("rule_downgrade")
    proposed = list(candidate_rules.get("forbidden_patterns") or [])
    removed = [pattern for pattern in pinned.patterns if pattern not in set(proposed)]
    limit = candidate_rules.get("size_limit_bytes", pinned.size_limit)
    relaxed_size = isinstance(limit, int) and limit > pinned.size_limit
    removed_signatures: list[str] = []
    if "brain_signatures" in candidate_rules:
        have = set(candidate_rules.get("brain_signatures") or [])
        removed_signatures.extend(sig for sig in pinned.brain_signatures if sig not in have)
    if "backup_signatures" in candidate_rules:
        have = set(candidate_rules.get("backup_signatures") or [])
        removed_signatures.extend(sig for sig in pinned.backup_signatures if sig not in have)
    removed_secret_ids: list[str] = []
    if "secret_pattern_ids" in candidate_rules:
        have = set(candidate_rules.get("secret_pattern_ids") or [])
        removed_secret_ids = [item for item in pinned.secret_pattern_ids if item not in have]
    if removed or relaxed_size or removed_signatures or removed_secret_ids:
        return failed(
            "rule_downgrade",
            "POLICY_RULE_DOWNGRADE",
            removed_patterns=removed,
            relaxed_size=relaxed_size,
            removed_signatures=removed_signatures,
            removed_secret_ids=removed_secret_ids,
        )
    return passed("rule_downgrade")
