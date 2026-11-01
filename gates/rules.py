"""Pinned rule set. Forbidden patterns are the canonical 21 lines, unreadacted."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from gates.types import canonical_json, sha256_hex

SIZE_LIMIT_BYTES = 10 * 1024 * 1024
RULE_VERSION = "6.0.0"
CANONICAL_PATH = Path(__file__).with_name("policy") / "GATES-PARAMETERS-CANONICAL.txt"
CANONICAL_SHA256 = "cff01a57e38b16af6bc5545789949575b1cbcc3078cdf5bf3158cee4b56fd884"
CANONICAL_BYTES = 4332

SECRET_PATTERN_IDS = (
    "aws_access_key_id",
    "private_key_header",
    "github_token",
    "slack_token",
    "stripe_live_secret",
)
BRAIN_SIGNATURES = ("OCTO-BRAIN-RAW-v1",)
BACKUP_SIGNATURES = ("OCTO-BACKUP-RAW-v1",)
KILL_CATEGORIES = ("funds", "publish", "send", "delete")


def load_forbidden_patterns(text: str | None = None) -> tuple[str, ...]:
    if text is None:
        text = CANONICAL_PATH.read_text(encoding="utf-8")
    marker = text.find("完整 patterns：")
    if marker < 0:
        raise RuntimeError("canonical pattern block missing")
    fence = text.find("```text", marker)
    if fence < 0:
        raise RuntimeError("canonical pattern fence missing")
    start = text.find("\n", fence) + 1
    end = text.find("```", start)
    if end < 0:
        raise RuntimeError("canonical pattern fence not closed")
    lines = text[start:end].split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if any(line == "" for line in lines):
        raise RuntimeError("blank line inside canonical pattern block")
    if len(lines) != 21:
        raise RuntimeError(f"expected 21 patterns, found {len(lines)}")
    return tuple(lines)


def canonical_parameter_bytes() -> bytes:
    data = CANONICAL_PATH.read_bytes()
    if len(data) != CANONICAL_BYTES or sha256_hex(data) != CANONICAL_SHA256:
        raise RuntimeError("canonical parameter bytes were altered")
    return data


@dataclass(frozen=True)
class RuleSet:
    version: str
    patterns: tuple[str, ...]
    size_limit: int
    secret_pattern_ids: tuple[str, ...]
    brain_signatures: tuple[str, ...]
    backup_signatures: tuple[str, ...]
    digest: str


def build_rule_set() -> RuleSet:
    canonical_parameter_bytes()
    patterns = load_forbidden_patterns()
    payload = {
        "version": RULE_VERSION,
        "size_limit_bytes": SIZE_LIMIT_BYTES,
        "forbidden_patterns": list(patterns),
        "secret_pattern_ids": list(SECRET_PATTERN_IDS),
        "brain_signatures": list(BRAIN_SIGNATURES),
        "backup_signatures": list(BACKUP_SIGNATURES),
        "kill_categories": list(KILL_CATEGORIES),
    }
    return RuleSet(
        version=RULE_VERSION,
        patterns=patterns,
        size_limit=SIZE_LIMIT_BYTES,
        secret_pattern_ids=SECRET_PATTERN_IDS,
        brain_signatures=BRAIN_SIGNATURES,
        backup_signatures=BACKUP_SIGNATURES,
        digest=sha256_hex(canonical_json(payload)),
    )


RULES = build_rule_set()
FORBIDDEN_PATTERNS = RULES.patterns
RULE_DIGEST = RULES.digest
