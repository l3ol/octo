"""Phase B verdict gate. Contract vectors only. runtime_pass stays false."""
import hashlib
import json
from pathlib import Path

from octo.closing import OWNER_APPOINTMENT_THREAD, TA_REVIEWER_ID, _from_consume, run_n11
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
    document = {"verdict": verdict, "binding_tuple": _runner()}
    document.update(overrides)
    return document


def _service(raw: bytes, **overrides) -> dict:
    body = {
        "thread_id": OWNER_APPOINTMENT_THREAD,
        "turn": {"status": "completed"},
        "agentMessage": {"type": "text", "text": raw.decode("utf-8")},
        "message_sha256": hashlib.sha256(raw).hexdigest(),
    }
    body.update(overrides)
    return body


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


def _install(
    root: Path,
    raw: bytes,
    *,
    receipt_id: str,
    metadata_verdict: str = "FAIL",
    proof: bool = True,
    service: dict | None = None,
) -> None:
    blob = root / "bytes" / receipt_id
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    (root / "custody.json").write_text(json.dumps({
        "raw_sha256": digest,
        "not_issuer": True,
    }), encoding="utf-8")
    if proof or service is not None:
        stored = _service(raw) if service is None else service
        (root / "service-response.json").write_text(json.dumps(stored), encoding="utf-8")
        (root / "transfers").mkdir(parents=True, exist_ok=True)
        (root / "transfers" / "transfer-1.json").write_text(json.dumps({
            "transfer_receipt_id": "transfer-1",
            "raw_sha256": digest,
            "thread_id": OWNER_APPOINTMENT_THREAD,
        }), encoding="utf-8")
    row = {
        "registration_id": receipt_id,
        "receipt_id": receipt_id,
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes_ref": f"bytes/{receipt_id}",
        "custody_ref": "custody.json",
        "service_response_ref": "service-response.json",
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


def _run(
    tmp_path: Path,
    monkeypatch,
    raw: bytes,
    *,
    receipt_id: str,
    metadata_verdict: str = "FAIL",
    proof: bool = True,
    service: dict | None = None,
    clear_seen: bool = True,
):
    root = tmp_path / "reg"
    _install(
        root,
        raw,
        receipt_id=receipt_id,
        metadata_verdict=metadata_verdict,
        proof=proof,
        service=service,
    )
    allow = _allow(tmp_path / "allow.json")
    monkeypatch.setenv("OCTO_TRUST_ALLOWLIST", str(allow))
    if clear_seen:
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
    unproven = _original("PASS", source_authenticity={"kind": "public_id", "reviewer_id": TA_REVIEWER_ID, "endorsed": True})
    unproven_env = _run(
        tmp_path / "unproven",
        monkeypatch,
        json.dumps(unproven).encode(),
        receipt_id="rcpt-unproven",
        proof=False,
    )
    assert unproven_env["status"] == "BLOCKED"
    assert unproven_env["output"]["verdict"] != "PASS"
    assert _evidence(unproven_env)["note"] == "SOURCE_UNPROVEN"
    broken = {"verdict": "APPROVED", "binding_tuple": _runner()}
    parsed = _run(tmp_path / "parse", monkeypatch, json.dumps(broken).encode(), receipt_id="rcpt-parse")
    assert parsed["status"] == "BLOCKED"
    assert parsed["output"]["verdict"] != "PASS"
    assert _evidence(parsed)["note"] == "PHASE_B_PARSE_FAILED"


def test_cx1_fake_endorsement_without_ro_proof_is_blocked(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS", source_authenticity={
        "kind": "read_thread",
        "endorsed": True,
        "appointment_session": OWNER_APPOINTMENT_THREAD,
        "reviewer_id": TA_REVIEWER_ID,
    })).encode()
    envelope = _run(tmp_path, monkeypatch, raw, receipt_id="cx1", proof=False)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["note"] == "SOURCE_UNPROVEN"


def test_cx2_prefix_session_is_not_the_owner_thread(tmp_path, monkeypatch):
    raw_doc = json.dumps(_original("PASS")).encode()
    service = _service(raw_doc, thread_id="6ae7886b-bbec-83e8-87dc-c3edd9027bcc")
    envelope = _run(tmp_path, monkeypatch, raw_doc, receipt_id="cx2", service=service)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["note"] == "SOURCE_UNPROVEN"


def test_cx3_bad_service_response_is_blocked(tmp_path, monkeypatch):
    raw_doc = json.dumps(_original("PASS")).encode()
    wrong_hash = _service(raw_doc, message_sha256="ab" * 32)
    wrong_type = _service(raw_doc)
    wrong_type["agentMessage"] = {"type": "image", "text": raw_doc.decode("utf-8")}
    not_completed = _service(raw_doc)
    not_completed["turn"] = {"status": "in_progress"}
    for name, service in (("hash", wrong_hash), ("type", wrong_type), ("turn", not_completed)):
        envelope = _run(tmp_path / name, monkeypatch, raw_doc, receipt_id=f"cx3-{name}", service=service)
        assert envelope["status"] == "BLOCKED"
        assert envelope["output"]["verdict"] != "PASS"
        assert _evidence(envelope)["note"] == "SOURCE_UNPROVEN"


def test_cx4_phase_b_failure_can_retry_same_receipt(tmp_path, monkeypatch):
    raw_doc = json.dumps(_original("PASS")).encode()
    first = _run(tmp_path, monkeypatch, raw_doc, receipt_id="cx4", proof=False)
    assert first["status"] == "BLOCKED"
    assert _evidence(first)["note"] == "SOURCE_UNPROVEN"
    root = tmp_path / "reg"
    assert "cx4" not in _CONSUMED_RECEIPTS.get(str(root.resolve()), set())
    second = _run(tmp_path, monkeypatch, raw_doc, receipt_id="cx4", proof=True, clear_seen=False)
    assert second["status"] == "OK"
    assert second["output"]["verdict"] == "PASS"
    assert _evidence(second)["runtime_pass"] is False
    third = _run(tmp_path, monkeypatch, raw_doc, receipt_id="cx4", proof=True, clear_seen=False)
    assert third["status"] == "BLOCKED"
    assert "EVIDENCE_UNVERIFIED" in third["output"]["evidence"][0]["note"]


def test_cx5_unverified_source_stays_blocked_when_test_only_is_false(tmp_path, monkeypatch):
    raw_doc = json.dumps(_original("PASS")).encode()
    envelope = _run(tmp_path, monkeypatch, raw_doc, receipt_id="cx5", proof=False)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["runtime_pass"] is False
    assert _evidence(envelope)["test_only"] is False
