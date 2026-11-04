"""N11 contract gaps MF-N11-01/02/03. Builder selftest only. Not a PASS."""
import hashlib
import json
import os
from pathlib import Path

from octo.closing import run_n11
from octo.g3_review import product_scope_digest
from octo.trusted_original import (
    DEFAULT_EXPECTED_ISSUER,
    ORIGINAL_REVIEWER_SESSION_ID,
    _CONSUMED_RECEIPTS,
    Found,
    consume_trusted_original,
    fixture_set_digest,
    runner_base_sha,
)

AT = "2026-11-01T12:00:00+00:00"
CANDIDATE = "a" * 40
FIXTURE = "b" * 64
ROUTE = "internal_readonly"
TASK = "g2-s1"
RULE = "t255"


def _binding() -> dict:
    return {
        "route": ROUTE,
        "scope_digest": product_scope_digest(),
        "base_sha": runner_base_sha(),
        "candidate_sha": CANDIDATE,
        "fixture_digest": FIXTURE,
        "task": TASK,
        "rule_version": RULE,
    }


def _production(root: Path, records: list[dict]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "registry.json").write_text(json.dumps({"records": records}), encoding="utf-8")
    for path in root.rglob("*"):
        if path.is_symlink() or path.is_dir():
            continue
        path.chmod(0o444)
    root.chmod(0o555)


def _unseal(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o755)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        path.chmod(0o755 if path.is_dir() else 0o644)


def _review_row(root: Path, raw: bytes, *, receipt_id: str) -> dict:
    blob = root / "bytes" / receipt_id
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(raw)
    return {
        "registration_id": receipt_id,
        "receipt_id": receipt_id,
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes_ref": f"bytes/{receipt_id}",
        "source_evidence": {
            "transfer_receipt_id": "transfer-1",
            "issuer_agent_id": DEFAULT_EXPECTED_ISSUER,
            "issuer_session_id": ORIGINAL_REVIEWER_SESSION_ID,
            "relay_proof": "control-plane-shape",
        },
        "issuer_id": DEFAULT_EXPECTED_ISSUER,
        "issued_at": AT,
        "verdict": "PASS",
        "binding_tuple": _binding(),
        "content_kind": "REVIEW_RECEIPT",
        "test_only": False,
        "excluded_fixture_hashes_proof": {
            "fixture_set_digest": fixture_set_digest(set()),
            "checked": True,
        },
    }


def _allow(path: Path) -> Path:
    path.write_text(json.dumps({
        "issuer_allowlist": [DEFAULT_EXPECTED_ISSUER],
        "source_allowlist": [ORIGINAL_REVIEWER_SESSION_ID],
    }), encoding="utf-8")
    return path


def _open(root: Path):
    from octo.trusted_original import open_registry
    opened = open_registry(root)
    assert not hasattr(opened, "reason")
    return opened


def test_mf_n11_01_runner_carries_task_and_rule_version(tmp_path, monkeypatch):
    root = tmp_path / "tuple"
    raw = b"task-rule-bytes"
    row = _review_row(root, raw, receipt_id="rcpt-task")
    allow = _allow(tmp_path / "allow.json")
    _production(root, [row])
    monkeypatch.setenv("OCTO_TRUST_ALLOWLIST", str(allow))
    try:
        missing = run_n11(
            {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
            at=AT,
            registry_root=root,
            fixture_digest=FIXTURE,
        )
        assert "TUPLE_MISMATCH" in missing["output"]["evidence"][0]["note"]
        _CONSUMED_RECEIPTS.pop(str(root.resolve()), None)
        reached = run_n11(
            {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE, "task": TASK, "rule_version": RULE}},
            at=AT,
            registry_root=root,
            fixture_digest=FIXTURE,
        )
    finally:
        _unseal(root)
        monkeypatch.delenv("OCTO_TRUST_ALLOWLIST", raising=False)
    note = reached["output"]["evidence"][0]["note"]
    assert "TUPLE_MISMATCH" not in note
    assert note == "EVIDENCE_UNVERIFIED GAP-03"
    assert reached["status"] == "BLOCKED"
    assert reached["output"]["verdict"] != "PASS"


def test_mf_n11_03_gap03_failure_can_retry_and_success_is_once(tmp_path):
    root = tmp_path / "retry"
    raw = b"custody-retry-bytes"
    row = _review_row(root, raw, receipt_id="rcpt-retry")
    allow = _allow(tmp_path / "allow-retry.json")
    _production(root, [row])
    try:
        view = _open(root)
        _CONSUMED_RECEIPTS.pop(str(view.root), None)
        first = consume_trusted_original(_binding(), view, set(), allowlist_path=allow)
        assert first.reason_code == "EVIDENCE_UNVERIFIED"
        assert first.detail == "GAP-03"
        assert "rcpt-retry" not in _CONSUMED_RECEIPTS.get(str(view.root), set())
        _unseal(root)
        (root / "custody.json").write_text(json.dumps({
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "not_issuer": True,
        }), encoding="utf-8")
        row["custody_ref"] = "custody.json"
        _production(root, [row])
        view = _open(root)
        accepted = consume_trusted_original(_binding(), view, set(), allowlist_path=allow)
        assert isinstance(accepted, Found)
        assert accepted.mechanism_accept is True
        assert accepted.test_only is False
        again = consume_trusted_original(_binding(), view, set(), allowlist_path=allow)
        assert isinstance(again, Found)
        assert again.mechanism_accept is True
    finally:
        _unseal(root)


def test_mf_n11_02_single_consume_reaches_mechanism_accept_blocked(tmp_path, monkeypatch):
    root = tmp_path / "once"
    raw = b"mechanism-accept-bytes"
    row = _review_row(root, raw, receipt_id="rcpt-once")
    (root / "custody.json").parent.mkdir(parents=True, exist_ok=True)
    (root / "custody.json").write_text(json.dumps({
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "not_issuer": True,
    }), encoding="utf-8")
    row["custody_ref"] = "custody.json"
    allow = _allow(tmp_path / "allow-once.json")
    _production(root, [row])
    monkeypatch.setenv("OCTO_TRUST_ALLOWLIST", str(allow))
    try:
        _CONSUMED_RECEIPTS.pop(str(root.resolve()), None)
        envelope = run_n11(
            {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE, "task": TASK, "rule_version": RULE}},
            at=AT,
            registry_root=root,
            fixture_digest=FIXTURE,
        )
    finally:
        _unseal(root)
        monkeypatch.delenv("OCTO_TRUST_ALLOWLIST", raising=False)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    note = envelope["output"]["evidence"][0]["note"]
    assert note == "MECHANISM_ACCEPT"
    assert "no trusted reviewer registration" not in note
    assert envelope["output"]["evidence"][0]["runtime_pass"] is False
    assert os.environ.get("OCTO_TRUST_ALLOWLIST") is None
