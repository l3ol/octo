"""Phase B verdict gate. Contract vectors only. runtime_pass stays false."""
import hashlib
import json
from pathlib import Path

import threading

from octo.closing import (
    OWNER_APPOINTMENT_THREAD,
    TA_REVIEWER_ID,
    _from_consume,
    _collector_matches,
    describe_read_thread,
    parse_authenticated_read_thread,
    run_n11,
)
from octo.trusted_original import CONTROL_PLANE_ENV, CANDIDATE_ROOT, load_control_plane
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
ROUND_TURN = "ca-round-turn"
ROUND_MESSAGE = "ca-round-message"
APPOINTMENT_ORIGINAL = hashlib.sha256(b"registrar-appointment-original-v1").hexdigest()
# GPT Chief private-chat ids. Intent citation only. Not Reviewer pins.
GPT_PRIVATE_TURN = "86b72901-5322-400a-be4c-063f80a6eb0b"
GPT_PRIVATE_MESSAGE = "20c53a68-b7f0-4d98-ba11-966b5f24eadb"


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
    text = raw.decode("utf-8")
    item = {
        "type": overrides.pop("message_type", "agentMessage"),
        "id": overrides.pop("message_id", ROUND_MESSAGE),
        "text": overrides.pop("text", text),
    }
    if overrides.pop("omit_text", False):
        item.pop("text", None)
    body = {
        "schemaVersion": 1,
        "thread": {"id": overrides.pop("thread_id", OWNER_APPOINTMENT_THREAD)},
        "turns": [{
            "id": overrides.pop("turn_id", ROUND_TURN),
            "status": overrides.pop("status", "completed"),
            "items": [item],
        }],
    }
    if "message_sha256" in overrides:
        body["message_sha256"] = overrides.pop("message_sha256")
    body.update(overrides)
    return body


def _projection(raw: bytes, **overrides) -> dict:
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
    transfer_overrides: dict | None = None,
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
        service_bytes = json.dumps(stored, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        (root / "service-response.json").write_bytes(service_bytes)
        thread = stored.get("thread") if isinstance(stored.get("thread"), dict) else {}
        turn = stored["turns"][0] if isinstance(stored.get("turns"), list) and stored["turns"] else {}
        item = turn["items"][0] if isinstance(turn.get("items"), list) and turn.get("items") else {}
        text = item.get("text") if isinstance(item, dict) else None
        runner = _runner()
        transfer = {
            "collector_receipt_id": "transfer-1",
            "transfer_receipt_id": "transfer-1",
            "collected_at": AT,
            "raw_sha256": digest,
            "service_response_sha256": hashlib.sha256(service_bytes).hexdigest(),
            "message_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if isinstance(text, str) else None,
            "thread_id": thread.get("id", stored.get("thread_id")),
            "turn_id": turn.get("id"),
            "message_id": item.get("id") if isinstance(item, dict) else None,
            "role": "agentMessage",
            "turn_status": turn.get("status", stored.get("turn", {}).get("status") if isinstance(stored.get("turn"), dict) else None),
            "appointment_digest": APPOINTMENT_ORIGINAL,
            "allowlist_sha256": hashlib.sha256(_allow_bytes()).hexdigest(),
            "base_sha": runner["base_sha"],
            "candidate_sha": runner["candidate_sha"],
            "scope_digest": runner["scope_digest"],
            "fixture_digest": runner["fixture_digest"],
        }
        if transfer_overrides:
            transfer.update(transfer_overrides)
        (root / "transfers").mkdir(parents=True, exist_ok=True)
        (root / "transfers" / "transfer-1.json").write_text(json.dumps(transfer), encoding="utf-8")
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


def _allow_bytes() -> bytes:
    return json.dumps({
        "issuer_allowlist": [TA_REVIEWER_ID],
        "source_allowlist": [ORIGINAL_REVIEWER_SESSION_ID],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _allow(path: Path) -> Path:
    path.write_bytes(_allow_bytes())
    return path


def _control_plane() -> dict:
    runner = _runner()
    return {
        "kind": "REGISTRAR_RELAY",
        "not_issuer": True,
        "current_reviewer_conclusion": True,
        "thread_id": OWNER_APPOINTMENT_THREAD,
        "turn_id": ROUND_TURN,
        "message_id": ROUND_MESSAGE,
        "appointment_original_digest": APPOINTMENT_ORIGINAL,
        "base_sha": runner["base_sha"],
        "candidate_sha": runner["candidate_sha"],
        "scope_digest": runner["scope_digest"],
        "fixture_digest": runner["fixture_digest"],
        "allowlist_sha256": hashlib.sha256(_allow_bytes()).hexdigest(),
    }


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
    transfer_overrides: dict | None = None,
    plane_overrides: dict | None = None,
    control: bool = True,
    control_path: Path | None = None,
):
    root = tmp_path / "reg"
    _install(
        root,
        raw,
        receipt_id=receipt_id,
        metadata_verdict=metadata_verdict,
        proof=proof,
        service=service,
        transfer_overrides=transfer_overrides,
    )
    allow = _allow(tmp_path / "allow.json")
    monkeypatch.setenv("OCTO_TRUST_ALLOWLIST", str(allow))
    if control:
        if control_path is None:
            plane = dict(_control_plane())
            if plane_overrides:
                plane.update(plane_overrides)
            control_path = tmp_path / "control-plane.json"
            control_path.write_text(json.dumps(plane), encoding="utf-8")
        monkeypatch.setenv(CONTROL_PLANE_ENV, str(control_path))
    else:
        monkeypatch.delenv(CONTROL_PLANE_ENV, raising=False)
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
        monkeypatch.delenv(CONTROL_PLANE_ENV, raising=False)


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
    wrong_type = _service(raw_doc, message_type="userMessage")
    not_completed = _service(raw_doc, status="in_progress")
    for name, service in (("hash", wrong_hash), ("type", wrong_type), ("turn", not_completed)):
        envelope = _run(tmp_path / name, monkeypatch, raw_doc, receipt_id=f"cx3-{name}", service=service)
        assert envelope["status"] == "BLOCKED"
        assert envelope["output"]["verdict"] != "PASS"
        assert _evidence(envelope)["note"] == "SOURCE_UNPROVEN"


def test_corrective_requires_pinned_agent_message_bytes(tmp_path, monkeypatch):
    raw_doc = json.dumps(_original("PASS")).encode()
    wrong_turn = _run(
        tmp_path / "turn",
        monkeypatch,
        raw_doc,
        receipt_id="pin-turn",
        service=_service(raw_doc, turn_id="00000000-0000-4000-8000-000000000001"),
    )
    user_item = _service(raw_doc, message_type="userMessage")
    preview = _service(raw_doc, message_type="content-reference")
    wrong_text = _service(raw_doc, text="not-the-review-receipt")
    assert wrong_turn["status"] == "BLOCKED" and wrong_turn["output"]["verdict"] != "PASS"
    for name, service in (("user", user_item), ("preview", preview), ("text", wrong_text)):
        envelope = _run(tmp_path / name, monkeypatch, raw_doc, receipt_id=f"pin-{name}", service=service)
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


def test_rf_cx1_projection_only_is_blocked(tmp_path, monkeypatch):
    raw_doc = json.dumps(_original("PASS")).encode()
    envelope = _run(tmp_path, monkeypatch, raw_doc, receipt_id="rf1", service=_projection(raw_doc))
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["note"] == "SOURCE_UNPROVEN"


def test_rf_cx3_hash_without_message_body_is_blocked(tmp_path, monkeypatch):
    raw_doc = json.dumps(_original("PASS")).encode()
    service = _service(raw_doc, omit_text=True, message_sha256=hashlib.sha256(raw_doc).hexdigest())
    envelope = _run(tmp_path, monkeypatch, raw_doc, receipt_id="rf3", service=service)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["note"] == "SOURCE_UNPROVEN"


def test_rf_cx4_real_shape_is_format_compat_and_historical_business_stays_blocked(tmp_path, monkeypatch):
    fixture = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "n11-read-thread"
    service_bytes = (fixture / "service-response.exact.nolf").read_bytes()
    message_bytes = (fixture / "agent-message.exact.nolf").read_bytes()
    assert hashlib.sha256(service_bytes).hexdigest() == "cf3deb9e7d709b4b1c43468dbf1af0f4bb559e6e29c165fae2b58292ed0f39eb"
    assert hashlib.sha256(message_bytes).hexdigest() == "bd2ff242bbff293779b482ed0a90640174560b28783b919e1c90f377ea5edeb0"
    historical = json.loads(service_bytes.decode("utf-8"))
    parsed = describe_read_thread(historical)
    assert parsed is not None
    assert parse_authenticated_read_thread(historical, {
        "thread_id": OWNER_APPOINTMENT_THREAD,
        "turn_id": ROUND_TURN,
        "message_id": ROUND_MESSAGE,
    }) is None
    assert parsed["thread_id"] == OWNER_APPOINTMENT_THREAD
    assert parsed["turn_id"] == "3c9945f6-aece-4a2e-87a0-ed2a11722424"
    assert parsed["message_id"] == "feee2cda-befb-4183-9e48-9da3fc53130b"
    assert parsed["text"].encode("utf-8") == message_bytes
    current = json.dumps(_original("PASS")).encode()
    envelope = _run(
        tmp_path,
        monkeypatch,
        current,
        receipt_id="rf4",
        service=json.loads(service_bytes.decode("utf-8")),
    )
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["runtime_pass"] is False


def test_rf_cx2_fake_service_without_message_body_is_blocked(tmp_path, monkeypatch):
    raw_doc = json.dumps(_original("PASS")).encode()
    service = _service(raw_doc, omit_text=True)
    envelope = _run(tmp_path, monkeypatch, raw_doc, receipt_id="rf2", service=service)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["note"] == "SOURCE_UNPROVEN"


def test_rf_cx5_format_pack_is_not_current_pass(tmp_path, monkeypatch):
    fixture = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "n11-read-thread"
    historical = json.loads((fixture / "service-response.exact.nolf").read_text(encoding="utf-8"))
    current = json.dumps(_original("PASS")).encode()
    envelope = _run(tmp_path, monkeypatch, current, receipt_id="rf5", service=historical)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["runtime_pass"] is False
    assert envelope["output"]["verdict"] != "OK"


def test_rf_cx6_moved_self_report_is_not_proof(tmp_path, monkeypatch):
    raw_doc = json.dumps(_original("PASS")).encode()
    envelope = _run(tmp_path, monkeypatch, raw_doc, receipt_id="rf6", service=_projection(raw_doc))
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["note"] == "SOURCE_UNPROVEN"


def test_cx5_unverified_source_stays_blocked_when_test_only_is_false(tmp_path, monkeypatch):
    raw_doc = json.dumps(_original("PASS")).encode()
    envelope = _run(tmp_path, monkeypatch, raw_doc, receipt_id="cx5", proof=False)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["runtime_pass"] is False
    assert _evidence(envelope)["test_only"] is False


def _blocked_note(tmp_path, monkeypatch, **kwargs) -> str:
    raw_doc = kwargs.pop("raw", json.dumps(_original("PASS")).encode())
    envelope = _run(tmp_path, monkeypatch, raw_doc, **kwargs)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    return _evidence(envelope)["note"]


def test_adn01_projection_is_not_the_original_return(tmp_path, monkeypatch):
    assert _blocked_note(tmp_path, monkeypatch, receipt_id="adn01", service=_projection(json.dumps(_original("PASS")).encode())) == "SOURCE_UNPROVEN"


def test_adn02_wrong_full_thread_is_blocked(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    assert _blocked_note(tmp_path, monkeypatch, raw=raw, receipt_id="adn02", service=_service(raw, thread_id="6ae7886b-ffff-83e8-a136-f1b52b33d01f")) == "SOURCE_UNPROVEN"


def test_adn03_wrong_turn_or_message_is_blocked(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    assert _blocked_note(tmp_path, monkeypatch, raw=raw, receipt_id="adn03", service=_service(raw, message_id="00000000-0000-4000-8000-000000000099")) == "SOURCE_UNPROVEN"


def test_adn04_turn_not_completed_is_blocked(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    assert _blocked_note(tmp_path, monkeypatch, raw=raw, receipt_id="adn04", service=_service(raw, status="in_progress")) == "SOURCE_UNPROVEN"


def test_adn05_user_preview_and_content_reference_are_blocked(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    for kind in ("userMessage", "preview", "content-reference"):
        assert _blocked_note(tmp_path / kind, monkeypatch, raw=raw, receipt_id=f"adn05-{kind}", service=_service(raw, message_type=kind)) == "SOURCE_UNPROVEN"


def test_adn06_claimed_hash_without_text_is_blocked(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    service = _service(raw, omit_text=True, message_sha256=hashlib.sha256(raw).hexdigest())
    assert _blocked_note(tmp_path, monkeypatch, raw=raw, receipt_id="adn06", service=service) == "SOURCE_UNPROVEN"


def test_adn07_text_bytes_must_equal_the_review_receipt(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    assert _blocked_note(tmp_path, monkeypatch, raw=raw, receipt_id="adn07", service=_service(raw, text="different-body")) == "SOURCE_UNPROVEN"


def test_adn08_collector_sha_or_fake_server_id_is_blocked(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    assert _blocked_note(tmp_path / "sha", monkeypatch, raw=raw, receipt_id="adn08-sha", transfer_overrides={"service_response_sha256": "ab" * 32}) == "SOURCE_UNPROVEN"
    assert _blocked_note(tmp_path / "id", monkeypatch, raw=raw, receipt_id="adn08-id", transfer_overrides={"server_call_id": "srv-not-returned"}) == "SOURCE_UNPROVEN"


def test_adn09_stale_appointment_or_tuple_is_blocked(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    assert _blocked_note(tmp_path / "apt", monkeypatch, raw=raw, receipt_id="adn09-apt", transfer_overrides={"appointment_digest": "cd" * 32}) == "SOURCE_UNPROVEN"
    assert _blocked_note(tmp_path / "tuple", monkeypatch, raw=raw, receipt_id="adn09-tuple", transfer_overrides={"fixture_digest": "ee" * 32}) == "SOURCE_UNPROVEN"


def test_adn10_and_adn11_failure_retries_and_success_replay_is_rejected(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    first = _run(tmp_path, monkeypatch, raw, receipt_id="adn10", proof=False)
    assert first["status"] == "BLOCKED"
    second = _run(tmp_path, monkeypatch, raw, receipt_id="adn10", proof=True, clear_seen=False)
    assert second["status"] == "OK" and second["output"]["verdict"] == "PASS"
    assert _evidence(second)["runtime_pass"] is False
    third = _run(tmp_path, monkeypatch, raw, receipt_id="adn10", proof=True, clear_seen=False)
    assert third["status"] == "BLOCKED"
    assert "EVIDENCE_UNVERIFIED" in third["output"]["evidence"][0]["note"]


def test_adn12_discard_compensation_is_absent():
    root = Path(__file__).resolve().parents[1]
    closing = (root / "octo" / "closing.py").read_text(encoding="utf-8")
    trusted = (root / "octo" / "trusted_original.py").read_text(encoding="utf-8")
    assert "release_consumed_receipt" not in closing
    assert "release_consumed_receipt" not in trusted
    assert "seen.discard" not in closing
    assert "seen.discard" not in trusted


def test_adn13_historical_source_bytes_do_not_become_the_current_verdict(tmp_path, monkeypatch):
    fixture = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "n11-read-thread"
    historical = json.loads((fixture / "service-response.exact.nolf").read_text(encoding="utf-8"))
    assert describe_read_thread(historical) is not None
    envelope = _run(tmp_path, monkeypatch, json.dumps(_original("PASS")).encode(), receipt_id="adn13", service=historical)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    assert _evidence(envelope)["runtime_pass"] is False


def _candidate_sources() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in (CANDIDATE_ROOT / "octo").glob("*.py"))


def test_ca01_gpt_private_ids_are_not_reviewer_pins(tmp_path, monkeypatch):
    source = _candidate_sources()
    assert GPT_PRIVATE_TURN not in source
    assert GPT_PRIVATE_MESSAGE not in source
    raw = json.dumps(_original("PASS")).encode()
    service = _service(raw, turn_id=GPT_PRIVATE_TURN, message_id=GPT_PRIVATE_MESSAGE)
    assert _blocked_note(tmp_path, monkeypatch, raw=raw, receipt_id="ca01", service=service) == "SOURCE_UNPROVEN"


def test_ca02_historical_raw_does_not_require_cross_chat_splice(tmp_path, monkeypatch):
    fixture = CANDIDATE_ROOT / "tests" / "fixtures" / "n11-read-thread"
    historical = json.loads((fixture / "service-response.exact.nolf").read_text(encoding="utf-8"))
    described = describe_read_thread(historical)
    assert described is not None
    assert described["turn_id"] == "3c9945f6-aece-4a2e-87a0-ed2a11722424"
    assert described["message_id"] == "feee2cda-befb-4183-9e48-9da3fc53130b"
    assert parse_authenticated_read_thread(historical, {
        "thread_id": OWNER_APPOINTMENT_THREAD,
        "turn_id": GPT_PRIVATE_TURN,
        "message_id": GPT_PRIVATE_MESSAGE,
    }) is None
    raw = json.dumps(_original("PASS")).encode()
    assert _blocked_note(tmp_path, monkeypatch, raw=raw, receipt_id="ca02", service=historical) == "SOURCE_UNPROVEN"


def test_ca03_thread_id_hash_is_not_an_appointment_original(tmp_path, monkeypatch):
    source = (CANDIDATE_ROOT / "octo" / "closing.py").read_text(encoding="utf-8")
    trusted = (CANDIDATE_ROOT / "octo" / "trusted_original.py").read_text(encoding="utf-8")
    assert "APPOINTMENT_DIGEST" not in source
    assert "APPOINTMENT_DIGEST" not in trusted
    fake = hashlib.sha256(OWNER_APPOINTMENT_THREAD.encode("utf-8")).hexdigest()
    assert fake != APPOINTMENT_ORIGINAL
    raw = json.dumps(_original("PASS")).encode()
    note = _blocked_note(
        tmp_path,
        monkeypatch,
        raw=raw,
        receipt_id="ca03",
        plane_overrides={"appointment_original_digest": fake},
        transfer_overrides={"appointment_digest": fake},
    )
    assert note == "SOURCE_UNPROVEN"
    assert load_control_plane(tmp_path / "control-plane.json") is None


def test_ca04_self_selected_pins_are_not_the_control_plane(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    assert _blocked_note(tmp_path / "missing", monkeypatch, raw=raw, receipt_id="ca04-missing", control=False) == "SOURCE_UNPROVEN"
    inside = CANDIDATE_ROOT / ".ca04-control-plane.json"
    inside.write_text(json.dumps(_control_plane()), encoding="utf-8")
    try:
        note = _blocked_note(
            tmp_path / "inside",
            monkeypatch,
            raw=raw,
            receipt_id="ca04-inside",
            control_path=inside,
        )
    finally:
        inside.unlink(missing_ok=True)
    assert note == "SOURCE_UNPROVEN"


def test_ca05_no_current_reviewer_conclusion_stays_blocked(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    service = _service(raw, turn_id=GPT_PRIVATE_TURN, message_id=GPT_PRIVATE_MESSAGE)
    note = _blocked_note(
        tmp_path,
        monkeypatch,
        raw=raw,
        receipt_id="ca05",
        service=service,
        plane_overrides={"current_reviewer_conclusion": False, "turn_id": GPT_PRIVATE_TURN, "message_id": GPT_PRIVATE_MESSAGE},
    )
    assert note == "SOURCE_UNPROVEN"


def test_ca06_synthetic_fixture_does_not_upgrade(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    marks = (
        {"fixture_class": "TEST_ONLY"},
        {"fixture_class": "TEST_FIXTURE"},
        {"synthetic": True},
    )
    for index, mark in enumerate(marks):
        note = _blocked_note(
            tmp_path / str(index),
            monkeypatch,
            raw=raw,
            receipt_id=f"ca06-{index}",
            plane_overrides=mark,
        )
        assert note == "SOURCE_UNPROVEN"


def test_ca07_concurrent_interleaving_consumes_once(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    root = tmp_path / "reg"
    _install(root, raw, receipt_id="ca07")
    monkeypatch.setenv("OCTO_TRUST_ALLOWLIST", str(_allow(tmp_path / "allow.json")))
    plane_path = tmp_path / "control-plane.json"
    plane_path.write_text(json.dumps(_control_plane()), encoding="utf-8")
    monkeypatch.setenv(CONTROL_PLANE_ENV, str(plane_path))
    resolved = str(root.resolve())
    _CONSUMED_RECEIPTS.pop(resolved, None)
    barrier = threading.Barrier(8)
    results: list[tuple[str, str, str]] = []
    errors: list[BaseException] = []
    guard = threading.Lock()

    def worker() -> None:
        try:
            barrier.wait(timeout=5)
            envelope = run_n11(
                {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE, "task": TASK, "rule_version": RULE}},
                at=AT,
                registry_root=root,
                fixture_digest=FIXTURE,
            )
            row = (
                envelope["status"],
                envelope["output"]["verdict"],
                envelope["output"]["evidence"][0]["note"],
            )
            with guard:
                results.append(row)
        except BaseException as exc:
            with guard:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
    finally:
        _unseal(root)
        monkeypatch.delenv("OCTO_TRUST_ALLOWLIST", raising=False)
        monkeypatch.delenv(CONTROL_PLANE_ENV, raising=False)
    assert errors == []
    assert len(results) == 8
    assert all(not thread.is_alive() for thread in threads)
    wins = [row for row in results if row[0] == "OK" and row[1] == "PASS"]
    assert len(wins) == 1
    assert wins[0][2] == "PHASE_B"
    for status, verdict, note in results:
        if status == "OK" and verdict == "PASS":
            continue
        assert status == "BLOCKED"
        assert verdict != "PASS"
        assert "EVIDENCE_UNVERIFIED" in note
    assert _CONSUMED_RECEIPTS.get(resolved) == {"ca07"}


def test_ca08_failure_does_not_consume_and_replay_is_rejected(tmp_path, monkeypatch):
    source = _candidate_sources()
    assert "release_consumed_receipt" not in source
    assert "seen.discard" not in source
    assert "mark_receipt_consumed" not in source
    raw = json.dumps(_original("PASS")).encode()
    first = _run(tmp_path, monkeypatch, raw, receipt_id="ca08", proof=False)
    assert first["status"] == "BLOCKED"
    resolved = str((tmp_path / "reg").resolve())
    assert "ca08" not in _CONSUMED_RECEIPTS.get(resolved, set())
    second = _run(tmp_path, monkeypatch, raw, receipt_id="ca08", proof=True, clear_seen=False)
    assert second["status"] == "OK" and second["output"]["verdict"] == "PASS"
    assert _evidence(second)["runtime_pass"] is False
    third = _run(tmp_path, monkeypatch, raw, receipt_id="ca08", proof=True, clear_seen=False)
    assert third["status"] == "BLOCKED"
    assert "EVIDENCE_UNVERIFIED" in third["output"]["evidence"][0]["note"]


def test_ca09_historical_tips_stay_unrewritten():
    import subprocess
    parent = "896e3e5073dbb83def6950c8096356eca979188f"
    ancestor = "019681fc92173d28e2e140da2c79d3f7764a5321"
    trees = {
        parent: "af3c7a13226126f0c579d1e2e15e8ade600618bb",
        ancestor: "ebf8351ef11bbcc359a27d9ca3281708790af8eb",
    }
    for sha, tree in trees.items():
        got = subprocess.check_output(
            ["git", "rev-parse", f"{sha}^{{tree}}"],
            cwd=CANDIDATE_ROOT,
            text=True,
        ).strip()
        assert got == tree
        subprocess.check_call(["git", "merge-base", "--is-ancestor", sha, "HEAD"], cwd=CANDIDATE_ROOT)
    source = _candidate_sources()
    assert GPT_PRIVATE_TURN not in source
    assert GPT_PRIVATE_MESSAGE not in source


def test_registered_round_rereads_control_plane(tmp_path, monkeypatch):
    raw = json.dumps(_original("PASS")).encode()
    plane = _control_plane()
    plane_path = tmp_path / "control-plane.json"
    plane_path.write_text(json.dumps(plane), encoding="utf-8")
    envelope = _run(tmp_path / "round", monkeypatch, raw, receipt_id="ca-round", control_path=plane_path)
    assert envelope["status"] == "OK"
    assert envelope["output"]["verdict"] == "PASS"
    assert _evidence(envelope)["runtime_pass"] is False
    reread = json.loads(plane_path.read_bytes().decode("utf-8"))
    loaded = load_control_plane(plane_path)
    assert loaded is not None
    assert loaded["appointment_original_digest"] == reread["appointment_original_digest"] == APPOINTMENT_ORIGINAL
    assert loaded["appointment_original_digest"] != hashlib.sha256(OWNER_APPOINTMENT_THREAD.encode("utf-8")).hexdigest()
    assert loaded["thread_id"] == reread["thread_id"] == OWNER_APPOINTMENT_THREAD
    assert loaded["turn_id"] == ROUND_TURN
    assert loaded["message_id"] == ROUND_MESSAGE
    for key in ("base_sha", "candidate_sha", "scope_digest", "fixture_digest", "allowlist_sha256"):
        assert loaded[key] == reread[key] == plane[key]


ALLOWLIST_PIN_A = "65cd874ef43fdb68b27ccef5e78189c54cde59085e63ce11a7f663ac81571b09"
ALLOWLIST_RUNTIME_B = "3d6a613b21cab50d1dd609a3a4c899bf8f425a1da089a336a776ed1f950eb539"


def test_ca10_allowlist_pin_runtime_and_transfer_must_match(tmp_path, monkeypatch):
    assert hashlib.sha256(b"allowlist-A-mismatch").hexdigest() == ALLOWLIST_PIN_A
    assert hashlib.sha256(_allow_bytes()).hexdigest() == ALLOWLIST_RUNTIME_B
    assert ALLOWLIST_PIN_A != ALLOWLIST_RUNTIME_B
    runner = _runner()
    parsed = {
        "thread_id": OWNER_APPOINTMENT_THREAD,
        "turn_id": ROUND_TURN,
        "message_id": ROUND_MESSAGE,
    }
    transfer = {
        "collector_receipt_id": "transfer-1",
        "collected_at": AT,
        "allowlist_sha256": ALLOWLIST_RUNTIME_B,
        "appointment_digest": APPOINTMENT_ORIGINAL,
        "base_sha": runner["base_sha"],
        "candidate_sha": runner["candidate_sha"],
        "scope_digest": runner["scope_digest"],
        "fixture_digest": runner["fixture_digest"],
        "raw_sha256": "11" * 32,
        "service_response_sha256": "22" * 32,
        "message_sha256": "33" * 32,
        "thread_id": OWNER_APPOINTMENT_THREAD,
        "turn_id": ROUND_TURN,
        "message_id": ROUND_MESSAGE,
        "role": "agentMessage",
        "turn_status": "completed",
    }
    pin = dict(_control_plane())
    assert _collector_matches(
        transfer,
        actual="11" * 32,
        service_sha="22" * 32,
        text_sha="33" * 32,
        parsed=parsed,
        allowlist_sha=ALLOWLIST_RUNTIME_B,
        runner_binding=runner,
        pin=pin,
    ) is True
    pin["allowlist_sha256"] = ALLOWLIST_PIN_A
    assert _collector_matches(
        transfer,
        actual="11" * 32,
        service_sha="22" * 32,
        text_sha="33" * 32,
        parsed=parsed,
        allowlist_sha=ALLOWLIST_RUNTIME_B,
        runner_binding=runner,
        pin=pin,
    ) is False
    raw = json.dumps(_original("PASS")).encode()
    note = _blocked_note(
        tmp_path,
        monkeypatch,
        raw=raw,
        receipt_id="ca10",
        plane_overrides={"allowlist_sha256": ALLOWLIST_PIN_A},
    )
    assert note == "SOURCE_UNPROVEN"
