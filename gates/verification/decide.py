"""Verification gate V-1..V-9. V-10 is enforced by atomic compare-and-merge."""

from __future__ import annotations

from gates.types import failed, first_rejection, make_result, passed, skipped
from gates.verification.ledger import ConsumptionLedger
from gates.verification.receipt import signature_valid


def check_pass_present(receipt: dict | None) -> dict:
    if isinstance(receipt, dict) and receipt.get("decision") == "PASS":
        return passed("pass_present")
    return failed("pass_present", "VERIFICATION_NO_PASS")


def check_trusted_issuer(receipt: dict | None, trusted_issuers: dict) -> tuple[dict, bytes | None]:
    if not isinstance(receipt, dict):
        return skipped("trusted_issuer"), None
    issuer = receipt.get("issuer")
    secret = trusted_issuers.get(issuer) if isinstance(issuer, str) else None
    if not isinstance(secret, (bytes, bytearray)):
        return failed("trusted_issuer", "VERIFICATION_UNTRUSTED_ISSUER"), None
    return passed("trusted_issuer"), bytes(secret)


def check_integrity(receipt: dict | None, secret: bytes | None) -> dict:
    if secret is None or not isinstance(receipt, dict):
        return skipped("integrity")
    if signature_valid(receipt, secret):
        return passed("integrity")
    return failed("integrity", "VERIFICATION_RECEIPT_TAMPERED")


def check_replay_binding(receipt: dict | None, *, task_id: str | None, rule_version: str) -> list[dict]:
    if not isinstance(receipt, dict):
        return [skipped("task_binding"), skipped("rule_binding")]
    checks = []
    if receipt.get("task_id") != task_id:
        checks.append(failed("task_binding", "VERIFICATION_REPLAY_BINDING"))
    else:
        checks.append(passed("task_binding"))
    if receipt.get("rule_version") != rule_version:
        checks.append(failed("rule_binding", "VERIFICATION_REPLAY_BINDING"))
    else:
        checks.append(passed("rule_binding"))
    return checks


def check_candidate_binding(receipt: dict | None, candidate_sha: str, lineage: list[str] | None) -> dict:
    if not isinstance(receipt, dict):
        return skipped("candidate_binding")
    bound = receipt.get("candidate_sha")
    if bound == candidate_sha:
        return passed("candidate_binding")
    ancestors = set(lineage or [])
    if isinstance(bound, str) and bound in ancestors:
        return failed("candidate_binding", "VERIFICATION_CANDIDATE_DRIFT")
    return failed("candidate_binding", "VERIFICATION_SHA_MISMATCH")


def check_base_binding(receipt: dict | None, base_sha: str) -> dict:
    if not isinstance(receipt, dict):
        return skipped("base_binding")
    if receipt.get("base_sha") != base_sha:
        return failed("base_binding", "VERIFICATION_BASE_STALE")
    return passed("base_binding")


def check_unconsumed(receipt: dict | None, ledger: ConsumptionLedger) -> dict:
    if not isinstance(receipt, dict):
        return skipped("receipt_unconsumed")
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or receipt_id == "":
        return failed("receipt_unconsumed", "VERIFICATION_RECEIPT_TAMPERED")
    if ledger.is_consumed(receipt_id):
        return failed("receipt_unconsumed", "VERIFICATION_RECEIPT_ALREADY_CONSUMED")
    return passed("receipt_unconsumed")


def decide(
    receipt,
    candidate_sha: str,
    base_sha: str,
    task_id,
    rule_version: str,
    trusted_issuers: dict,
    consumption_ledger: ConsumptionLedger,
    *,
    lineage: list[str] | None = None,
    rule_digest: str,
):
    checks: list[dict] = [check_pass_present(receipt)]
    issuer_check, secret = check_trusted_issuer(receipt, trusted_issuers)
    checks.append(issuer_check)
    checks.append(check_integrity(receipt, secret))
    checks.extend(check_replay_binding(receipt, task_id=task_id if isinstance(task_id, str) else None, rule_version=rule_version))
    checks.append(check_candidate_binding(receipt, candidate_sha, lineage))
    checks.append(check_base_binding(receipt, base_sha))
    checks.append(check_unconsumed(receipt, consumption_ledger))
    decision, reason = first_rejection(checks)
    independent = {
        item["name"]: {"decision": item["decision"], "reason_code": item["reason_code"], "evaluated": item["evaluated"]}
        for item in checks
    }
    return make_result(
        gate="verification",
        decision=decision,
        reason_code=reason,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        task_id=task_id if isinstance(task_id, str) else None,
        checks=checks,
        details={"independent_checks": independent},
        rule_digest=rule_digest,
    )
