"""I-1 seal and I-2 digest verification."""

from __future__ import annotations

import hmac
import hashlib

from gates.types import canonical_json, failed, first_rejection, make_result, now_cst, passed


def seal(artifact_digest: str, config_digest: str, *, secret: bytes, sealed_at: str | None = None) -> dict:
    body = {
        "artifact_digest": artifact_digest,
        "config_digest": config_digest,
        "sealed_at": sealed_at or now_cst(),
    }
    signed = dict(body)
    signed["signature"] = hmac.new(secret, canonical_json(body), hashlib.sha256).hexdigest()
    return signed


def _signature_ok(sealed: dict, secret: bytes) -> bool:
    signature = sealed.get("signature") if isinstance(sealed, dict) else None
    if not isinstance(signature, str):
        return False
    try:
        body = {
            "artifact_digest": sealed["artifact_digest"],
            "config_digest": sealed["config_digest"],
            "sealed_at": sealed["sealed_at"],
        }
    except KeyError:
        return False
    expected = hmac.new(secret, canonical_json(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify(
    deployed_artifact_digest: str,
    deployed_config_digest: str,
    sealed: dict,
    *,
    secret: bytes,
    candidate_sha: str,
    base_sha: str,
    task_id: str | None,
    rule_version: str,
    rule_digest: str,
):
    checks = []
    if _signature_ok(sealed, secret):
        checks.append(passed("seal_integrity"))
    else:
        checks.append(failed("seal_integrity", "ISOMORPHISM_SEAL_TAMPERED"))
    artifact_ok = isinstance(sealed, dict) and sealed.get("artifact_digest") == deployed_artifact_digest
    config_ok = isinstance(sealed, dict) and sealed.get("config_digest") == deployed_config_digest
    if artifact_ok and config_ok:
        checks.append(passed("digests"))
        field = None
    else:
        field = "artifact_digest" if not artifact_ok else "config_digest"
        checks.append(
            failed(
                "digests",
                "ISOMORPHISM_DIGEST_MISMATCH",
                field=field,
                artifact_match=artifact_ok,
                config_match=config_ok,
            )
        )
    decision, reason = first_rejection(checks)
    details = {
        "field": field,
        "artifact_match": artifact_ok,
        "config_match": config_ok,
    }
    if reason == "ISOMORPHISM_SEAL_TAMPERED":
        details["tamper_record"] = {"detected": True, "timestamp": now_cst()}
    return make_result(
        gate="isomorphism",
        decision=decision,
        reason_code=reason,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        task_id=task_id,
        checks=checks,
        details=details,
        rule_digest=rule_digest,
    )
