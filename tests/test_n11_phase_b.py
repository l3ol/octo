"""Phase B verdict gate. Contract vectors only. runtime_pass stays false."""
import hashlib
import json
from pathlib import Path

from octo.closing import TA_REVIEWER_ID, _from_consume, run_n11
from octo.g3_review import product_scope_digest
from octo.trusted_original import (
    ORIGINAL_REVIEWER_SESSION_ID,
    _CONSUMED_RECEIPTS,
    Found,
    fixture_set_digest,
    runner_base_sha,
)

AT = "2026-11-01T12:00:00+00:00"
CANDIDATE = "c" * 40
FIXTURE = "d" * 64
ROUTE = "internal_readonly"
TASK = "g2-s1"
RULE = "t255"
SESSION = "6ae7886b-bbec-83e8-87dc-c3edd9027bcc"


def _runner() -> dict:
    return {
        "route": ROUTE,
        "scope_digest": product_scope_digest(),
        "base_sha": runner_base_sha(),
        "candidate_sha": CANDIDATE,
        "fixture_digest": FIXTURE,
        "task": TASK,
        "rule_version": RULE,
    }


def _original(verdict: str, **overrides) -> dict:
    document = {
        "verdict": verdict,
        "binding_tuple": _runner(),
        "source_authenticity": {
            "kind": "read_thread",
            "appointment_session": SESSION,
            "reviewer_id": TA_REVIEWER_ID,
            "endorsed": True,
        },
    }
    document.update(overrides)
    return document


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


def _install(root: Path, raw: bytes, *, receipt_id: str, metadata_verdict: str = "FAIL") -> None:
    blob = root / "bytes" / receipt_id
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(raw)
    (root / "custody.json").write_text(json.dumps({
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "not_issuer": True,
    }), encoding="utf-8")
    row = {
        "registration_id": receipt_id,
        "receipt_id": receipt_id,
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes_ref": f"bytes/{receipt_id}",
        "custody_ref": "custody.json",
        "source_evidence": {
            "transfer_receipt_id": "transfer-1",
            "issuer_agent_id": TA_REVIEWER_ID,
            "issuer_session_id": ORIGINAL_REVIEWER_SESSION_ID,
            "relay_proof": "control-plane-shape",
        },
        "issuer_id": TA_REVIEWER_ID,
        "issued_at": AT,
        "verdict": metadata_verdict,
        "binding_tuple": _runner(),
        "content_kind": "REVIEW_RECEIPT",
        "test_only": False,
        "excluded_fixture_hashes_proof": {
            "fixture_set_digest": fixture_set_digest(set()),
            "checked": True,
        },
    }
    _production(root, [row])


def _allow(path: Path) -> Path:
    path.write_text(json.dumps({
        "issuer_allowlist": [TA_REVIEWER_ID],
        "source_allowlist": [ORIGINAL_REVIEWER_SESSION_ID],
    }), encoding="utf-8")
    return path


def _run(tmp_path: Path, monkeypatch, raw: bytes, *, receipt_id: str, metadata_verdict: str = "FAIL"):
    root = tmp_path / "reg"
    _install(root, raw, receipt_id=receipt_id, metadata_verdict=metadata_verdict)
    allow = _allow(tmp_path / "allow.json")
    monkeypatch.setenv("OCTO_TRUST_ALLOWLIST", str(allow))
    _CONSUMED_RECEIPTS.pop(str(root.resolve()), None)
    try:
        return run_n11(
            {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE, "task": TASK, "rule_version": RULE}},
            at=AT,
            registry_root=root,
            fixture_digest=FIXTURE,
        )
    finally:
        _unseal(root)
        monkeypatch.delenv("OCTO_TRUST_ALLOWLIST", raising=False)


def _evidence(envelope: dict) -> dict:
    assert envelope["output"]["evidence"][0]["runtime_pass"] is False
    return envelope["output"]["evidence"][0]


def test_phase_a_mechanism_and_fixture_stay_blocked():
    scope = {"route": ROUTE}
    mechanism = _from_consume(Found(record={}, test_only=False, mechanism_accept=True), scope)
    assert mechanism[1] == "BLOCKED"
    assert mechanism[0]["verdict"] == "BLOCKED"
    assert mechanism[0]["evidence"][0]["note"] == "MECHANISM_ACCEPT"
    fixture = _from_consume(Found(record={}, test_only=True), scope)
    assert fixture[1] == "BLOCKED"
    assert fixture[0]["verdict"] != "PASS"
    assert fixture[0]["evidence"][0]["note"] == "TEST_FIXTURE_ONLY"


def test_test_fixture_raw_pass_does_not_enter_phase_b(tmp_path):
    root = tmp_path / "fixture"
    raw = json.dumps(_original("PASS")).encode()
    blob = root / "bytes" / "fx"
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(raw)
    row = {
        "registration_id": "fx",
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes_ref": "bytes/fx",
        "source_evidence": {
            "transfer_receipt_id": "transfer-1",
            "issuer_agent_id": TA_REVIEWER_ID,
            "issuer_session_id": ORIGINAL_REVIEWER_SESSION_ID,
            "relay_proof": "control-plane-shape",
        },
        "issuer_id": TA_REVIEWER_ID,
        "binding_tuple": _runner(),
        "content_kind": "TEST_FIXTURE",
        "test_only": True,
        "excluded_fixture_hashes_proof": {
            "fixture_set_digest": fixture_set_digest(set()),
            "checked": True,
        },
    }
    root.mkdir(parents=True, exist_ok=True)
    (root / "registry.json").write_text(
        json.dumps({"registry_class": "TEST_FIXTURE", "records": [row]}),
        encoding="utf-8",
    )
    for path in root.rglob("*"):
        if path.is_file():
            path.chmod(0o444)
    root.chmod(0o555)
    try:
        envelope = run_n11(
            {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE, "task": TASK, "rule_version": RULE}},
            at=AT,
            registry_root=root,
            fixture_digest=FIXTURE,
        )
    finally:
        _unseal(root)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert envelope["output"]["evidence"][0]["note"] == "TEST_FIXTURE_ONLY"
    assert envelope["output"]["evidence"][0]["runtime_pass"] is False


def test_phase_b_maps_pass_revise_and_fail(tmp_path, monkeypatch):
    passed = _run(tmp_path / "pass", monkeypatch, json.dumps(_original("PASS")).encode(), receipt_id="rcpt-pass")
    assert passed["status"] == "OK"
    assert passed["output"]["verdict"] == "PASS"
    assert _evidence(passed)["original_verdict"] == "PASS"
    assert _evidence(passed)["mechanism_accept"] is False
    revised = _run(tmp_path / "revise", monkeypatch, json.dumps(_original("REVISE")).encode(), receipt_id="rcpt-revise")
    assert revised["status"] == "BLOCKED"
    assert revised["output"]["verdict"] == "REVISE"
    assert _evidence(revised)["original_verdict"] == "REVISE"
    failed = _run(tmp_path / "fail", monkeypatch, json.dumps(_original("FAIL")).encode(), receipt_id="rcpt-fail")
    assert failed["status"] == "BLOCKED"
    assert failed["output"]["verdict"] == "BLOCKED"
    assert _evidence(failed)["original_verdict"] == "FAIL"
    blocked = _run(tmp_path / "blocked", monkeypatch, json.dumps(_original("BLOCKED")).encode(), receipt_id="rcpt-blocked")
    assert blocked["status"] == "BLOCKED"
    assert blocked["output"]["verdict"] == "BLOCKED"
    assert _evidence(blocked)["original_verdict"] == "BLOCKED"


def test_phase_b_ignores_metadata_and_rejects_bad_binding_or_source(tmp_path, monkeypatch):
    copied = _run(
        tmp_path / "copy",
        monkeypatch,
        json.dumps(_original("REVISE")).encode(),
        receipt_id="rcpt-copy",
        metadata_verdict="PASS",
    )
    assert copied["output"]["verdict"] == "REVISE"
    assert copied["status"] == "BLOCKED"
    mismatched = _original("PASS")
    mismatched["binding_tuple"] = dict(_runner(), route="other-route")
    mismatch = _run(tmp_path / "mismatch", monkeypatch, json.dumps(mismatched).encode(), receipt_id="rcpt-mismatch")
    assert mismatch["status"] == "BLOCKED"
    assert mismatch["output"]["verdict"] != "PASS"
    assert _evidence(mismatch)["note"] == "BINDING_MISMATCH"
    unproven = _original("PASS", source_authenticity={"kind": "public_id", "reviewer_id": TA_REVIEWER_ID})
    unproven_env = _run(tmp_path / "unproven", monkeypatch, json.dumps(unproven).encode(), receipt_id="rcpt-unproven")
    assert unproven_env["status"] == "BLOCKED"
    assert unproven_env["output"]["verdict"] != "PASS"
    assert _evidence(unproven_env)["note"] == "SOURCE_UNPROVEN"
    broken = {"verdict": "APPROVED", "binding_tuple": _runner()}
    parsed = _run(tmp_path / "parse", monkeypatch, json.dumps(broken).encode(), receipt_id="rcpt-parse")
    assert parsed["status"] == "BLOCKED"
    assert parsed["output"]["verdict"] != "PASS"
    assert _evidence(parsed)["note"] == "PHASE_B_PARSE_FAILED"
