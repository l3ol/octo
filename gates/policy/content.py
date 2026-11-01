"""P-1 / P-2 / A-3 content scanners. Findings cite rule ids, not secret bytes."""

from __future__ import annotations

import re

from gates.rules import BACKUP_SIGNATURES, BRAIN_SIGNATURES

_SECRET_REGEXES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("aws_access_key_id", re.compile(br"AKIA[0-9A-Z]{16}")),
    ("private_key_header", re.compile(br"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("github_token", re.compile(br"ghp_[A-Za-z0-9]{36}")),
    ("slack_token", re.compile(br"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("stripe_live_secret", re.compile(br"sk_live_[0-9a-zA-Z]{16,}")),
)

_KILL_REGEXES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("funds", re.compile(br"stripe\.PaymentIntent\.create|stripe\.Charge\.create|send_payment\s*\(")),
    ("publish", re.compile(br"deploy_to_production\s*\(|production_deploy\b")),
    ("send", re.compile(br"send_email\s*\(|smtplib\.SMTP\b|notify_external\s*\(")),
    ("delete", re.compile(br"\bDROP\s+(?:TABLE|DATABASE)\b|\bDELETE\s+FROM\s+[A-Za-z0-9_]+\s*;", re.IGNORECASE)),
)


def scan_secrets(path: str, content: bytes) -> list[dict]:
    hits = []
    for pattern_id, pattern in _SECRET_REGEXES:
        if pattern.search(content):
            hits.append({"path": path, "pattern_id": pattern_id, "rule": "P-1"})
    return hits


def scan_brain_or_backup(path: str, content: bytes) -> list[dict]:
    hits = []
    for signature in BRAIN_SIGNATURES:
        if signature.encode("utf-8") in content:
            hits.append({"path": path, "signature": signature, "kind": "brain", "rule": "P-2"})
    for signature in BACKUP_SIGNATURES:
        if signature.encode("utf-8") in content:
            hits.append({"path": path, "signature": signature, "kind": "backup", "rule": "P-2"})
    return hits


def scan_kill_lines(path: str, content: bytes) -> list[dict]:
    hits = []
    for category, pattern in _KILL_REGEXES:
        if pattern.search(content):
            hits.append({"path": path, "category": category, "rule": "A-3"})
    return hits
