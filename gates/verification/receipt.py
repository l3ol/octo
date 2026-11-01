"""Reviewer receipt body and HMAC integrity."""

from __future__ import annotations

import hmac
import hashlib
from typing import Any

from gates.types import canonical_json

RECEIPT_FIELDS = (
    "receipt_id",
    "issuer",
    "decision",
    "task_id",
    "candidate_sha",
    "base_sha",
    "rule_version",
    "issued_at",
)


def receipt_body(fields: dict) -> dict:
    return {key: fields[key] for key in RECEIPT_FIELDS}


def sign_receipt(fields: dict, secret: bytes) -> dict:
    body = receipt_body(fields)
    signed = dict(body)
    signed["signature"] = hmac.new(secret, canonical_json(body), hashlib.sha256).hexdigest()
    return signed


def signature_valid(receipt: dict, secret: bytes) -> bool:
    signature = receipt.get("signature")
    if not isinstance(signature, str) or not signature:
        return False
    try:
        body = receipt_body(receipt)
    except KeyError:
        return False
    expected = hmac.new(secret, canonical_json(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def sign_activation_receipt(fields: dict, secret: bytes) -> dict:
    body = {
        "receipt_id": fields["receipt_id"],
        "approver": fields["approver"],
        "gate_version": fields["gate_version"],
        "evidence_digest": fields["evidence_digest"],
        "environment": fields["environment"],
        "issued_at": fields["issued_at"],
    }
    signed = dict(body)
    signed["signature"] = hmac.new(secret, canonical_json(body), hashlib.sha256).hexdigest()
    return signed


def activation_signature_valid(receipt: dict, secret: bytes) -> bool:
    signature = receipt.get("signature")
    if not isinstance(signature, str) or not signature:
        return False
    try:
        body = {
            "receipt_id": receipt["receipt_id"],
            "approver": receipt["approver"],
            "gate_version": receipt["gate_version"],
            "evidence_digest": receipt["evidence_digest"],
            "environment": receipt["environment"],
            "issued_at": receipt["issued_at"],
        }
    except KeyError:
        return False
    expected = hmac.new(secret, canonical_json(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
