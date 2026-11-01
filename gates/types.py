"""Shared decision types, canonical JSON, and result digests."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
DECISIONS = ("PASS", "REJECT")


def is_sha40(value: object) -> bool:
    return isinstance(value, str) and SHA40_RE.fullmatch(value) is not None


def now_cst() -> str:
    """ISO-8601 timestamp in UTC+08:00."""
    return datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def result_digest(
    gate: str,
    decision: str,
    reason_code: str | None,
    candidate_sha: str,
    base_sha: str,
    rule_version: str,
    evidence: dict,
) -> str:
    body = {
        "gate": gate,
        "decision": decision,
        "reason_code": reason_code,
        "candidate_sha": candidate_sha,
        "base_sha": base_sha,
        "rule_version": rule_version,
        "evidence": evidence,
    }
    return sha256_hex(canonical_json(body))


def passed(name: str, **extra: Any) -> dict:
    item: dict[str, Any] = {
        "name": name,
        "decision": "PASS",
        "reason_code": None,
        "evaluated": True,
    }
    item.update(extra)
    return item


def failed(name: str, reason: str, **extra: Any) -> dict:
    item: dict[str, Any] = {
        "name": name,
        "decision": "REJECT",
        "reason_code": reason,
        "evaluated": True,
    }
    item.update(extra)
    return item


def skipped(name: str, **extra: Any) -> dict:
    item: dict[str, Any] = {
        "name": name,
        "decision": None,
        "reason_code": None,
        "evaluated": False,
    }
    item.update(extra)
    return item


def first_rejection(checks: list[dict]) -> tuple[str, str | None]:
    for item in checks:
        if item.get("decision") == "REJECT":
            return "REJECT", item.get("reason_code")
    return "PASS", None


@dataclass(frozen=True)
class GateResult:
    gate: str
    decision: str
    reason_code: str | None
    candidate_sha: str
    base_sha: str
    rule_version: str
    evidence: dict
    result_digest: str
    task_id: str | None = None

    def public_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "gate": self.gate,
            "timestamp": self.evidence.get("timestamp"),
            "decision": self.decision,
            "reason_code": self.reason_code,
            "candidate_sha": self.candidate_sha,
            "base_sha": self.base_sha,
            "rule_version": self.rule_version,
            "result_digest": self.result_digest,
            "evidence": self.evidence,
        }


def make_result(
    *,
    gate: str,
    decision: str,
    reason_code: str | None,
    candidate_sha: str,
    base_sha: str,
    rule_version: str,
    task_id: str | None,
    checks: list[dict] | dict,
    details: dict,
    rule_digest: str,
) -> GateResult:
    if decision not in DECISIONS:
        raise ValueError(f"invalid decision {decision}")
    evidence = {
        "task_id": task_id,
        "gate": gate,
        "timestamp": now_cst(),
        "decision": decision,
        "reason_code": reason_code,
        "candidate_sha": candidate_sha,
        "base_sha": base_sha,
        "rule_version": rule_version,
        "rule_digest": rule_digest,
        "checks": checks,
        "details": details,
    }
    digest = result_digest(
        gate,
        decision,
        reason_code,
        candidate_sha,
        base_sha,
        rule_version,
        evidence,
    )
    return GateResult(
        gate=gate,
        decision=decision,
        reason_code=reason_code,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        evidence=evidence,
        result_digest=digest,
        task_id=task_id,
    )
