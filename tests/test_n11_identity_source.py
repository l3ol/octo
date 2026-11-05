"""Synthetic identity-source negatives. runtime_pass stays false."""
import copy
import hashlib
import json
from pathlib import Path

from octo.closing import _phase_b_source_authentic
from octo.g3_review import product_scope
from octo.scope_metadata import (
    FORMAL_REVIEWER_ID,
    HISTORICAL_AGENT_ID,
    assess_scope_reviewer,
)
from octo.trusted_original import (
    CANDIDATE_ROOT,
    CONTROL_PLANE_ENV,
    current_appointment,
    _review_allowlist,
)

ISSUER = "synthetic-reviewer-round"
SESSION = "synthetic-session-round"
THREAD = "synthetic-thread-round"
TURN = "synthetic-turn-round"
MESSAGE = "synthetic-message-round"
OLD_THREAD = "6ae7886b-23c8-83e8-a136-f1b52b33d01f"
_ORIGINAL = b"synthetic-appointment-original-v1"


def _install(tmp_path: Path, monkeypatch, **overrides):
    raw = overrides.pop("original_bytes", _ORIGINAL)
    digest = hashlib.sha256(raw).hexdigest()
    document = {
        "kind": "REGISTRAR_RELAY",
        "not_issuer": True,
        "current_reviewer_conclusion": True,
        "issuer_id": ISSUER,
        "issuer_session_id": SESSION,
        "thread_id": THREAD,
        "turn_id": TURN,
        "message_id": MESSAGE,
        "appointment_original_digest": digest,
        "appointment_raw_sha256": digest,
        "issuer_allowlist": [ISSUER],
        "source_allowlist": [SESSION],
    }
    document.update(overrides)
    path = tmp_path / "control-plane.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    if raw is not None:
        (tmp_path / "appointment-original.bin").write_bytes(raw)
    monkeypatch.setenv(CONTROL_PLANE_ENV, str(path))
    return document


def _record(issuer=ISSUER, session=SESSION, agent=None):
    return {
        "issuer_id": issuer,
        "source_evidence": {
            "issuer_session_id": session,
            "issuer_agent_id": ISSUER if agent is None else agent,
            "thread_id": THREAD,
        },
    }


def _allow():
    return {"issuer_allowlist": [ISSUER], "source_allowlist": [SESSION]}


def test_n1_issuer_mismatch(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    assert _review_allowlist(_record(issuer="other-issuer"), _allow()) == "ISSUER_MISMATCH"


def test_n2_session_mismatch(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    assert _review_allowlist(_record(session="other-session"), _allow()) == "ISSUER_MISMATCH"


def test_n3_thread_mismatch(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    pin = {
        "thread_id": "other-thread",
        "turn_id": TURN,
        "message_id": MESSAGE,
        "appointment_original_digest": hashlib.sha256(_ORIGINAL).hexdigest(),
    }
    from octo.closing import parse_authenticated_read_thread
    service = {"thread": {"id": THREAD}, "turns": []}
    assert parse_authenticated_read_thread(service, pin) is None
    assert pin["thread_id"] != current_appointment()["thread_id"]


def test_n4_new_thread_is_not_the_old_constant(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    found = current_appointment()
    assert found is not None
    assert found["thread_id"] == THREAD
    assert found["thread_id"] != OLD_THREAD
    _install(tmp_path, monkeypatch, appointment_original_digest="ab" * 32, appointment_raw_sha256="ab" * 32)
    assert current_appointment() is None


def test_n5_appointment_digest_recompute(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch, original_bytes=b"different-bytes")
    assert current_appointment()["appointment_raw_sha256"] == hashlib.sha256(b"different-bytes").hexdigest()
    document = json.loads((tmp_path / "control-plane.json").read_text(encoding="utf-8"))
    document["appointment_raw_sha256"] = "cd" * 32
    document["appointment_original_digest"] = "cd" * 32
    (tmp_path / "control-plane.json").write_text(json.dumps(document), encoding="utf-8")
    assert current_appointment() is None


def test_n6_turn_and_message_follow_the_appointment(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    found = current_appointment()
    assert found["turn_id"] == TURN
    assert found["message_id"] == MESSAGE
    _install(tmp_path, monkeypatch, turn_id="", message_id=MESSAGE)
    assert current_appointment() is None


def test_n7_old_scope_identity_is_stale(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    scope = copy.deepcopy(product_scope())
    result = assess_scope_reviewer(scope)
    assert result["ok"] is False
    assert "SCOPE_REVIEWER_STALE" in result["reasons"]
    assert scope["reviewer_separation"]["formal_reviewer_id"] == FORMAL_REVIEWER_ID
    assert FORMAL_REVIEWER_ID != ISSUER


def test_n8_migration_claim_stays(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch, issuer_id=FORMAL_REVIEWER_ID, issuer_allowlist=[FORMAL_REVIEWER_ID])
    scope = copy.deepcopy(product_scope())
    scope["reviewer_separation"]["signature_migration_claimed"] = True
    result = assess_scope_reviewer(scope)
    assert "SIGNATURE_MIGRATION_CLAIM" in result["reasons"]


def test_n9_historical_builder_and_test_only_reject(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    assert _review_allowlist(_record(issuer=HISTORICAL_AGENT_ID, agent=HISTORICAL_AGENT_ID), _allow()) == "ISSUER_MISMATCH"
    assert _review_allowlist(_record(issuer="BUILDER", agent="BUILDER"), _allow()) == "ISSUER_MISMATCH"
    assert _review_allowlist(_record(issuer="TB", agent="TB"), _allow()) == "ISSUER_MISMATCH"


def test_n10_writer_supplied_path_is_not_the_source(tmp_path, monkeypatch):
    decoy = tmp_path / "writer-pin.json"
    decoy.write_text("{}", encoding="utf-8")
    monkeypatch.delenv(CONTROL_PLANE_ENV, raising=False)
    assert current_appointment() is None


def test_n11_missing_pin_fields_fail_closed(tmp_path, monkeypatch):
    monkeypatch.delenv(CONTROL_PLANE_ENV, raising=False)
    assert current_appointment() is None
    _install(tmp_path, monkeypatch, issuer_id="")
    assert current_appointment() is None


def test_n12_identity_is_not_a_constant_swap():
    closing = (CANDIDATE_ROOT / "octo" / "closing.py").read_text(encoding="utf-8")
    trusted = (CANDIDATE_ROOT / "octo" / "trusted_original.py").read_text(encoding="utf-8")
    scope = (CANDIDATE_ROOT / "octo" / "scope_metadata.py").read_text(encoding="utf-8")
    combined = "\n".join((closing, trusted, scope))
    assert "OWNER_APPOINTMENT_THREAD" not in combined
    assert "ORIGINAL_SESSION_ID" not in combined
    for banned in ("!= TA_REVIEWER_ID", "!= FORMAL_REVIEWER_ID", "!= ORIGINAL_AGENT_ID", "== ORIGINAL_SESSION_ID"):
        assert banned not in combined
    manifest = json.loads((CANDIDATE_ROOT / "octo" / "scope" / "SCOPE-MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["handoff"]["formal_reviewer_id"] == FORMAL_REVIEWER_ID
    assert manifest["reviewer_separation"]["formal_reviewer_id"] == FORMAL_REVIEWER_ID


def test_p1_synthetic_appointment_matches(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    found = current_appointment()
    assert found is not None
    assert found["issuer_id"] == ISSUER
    assert found["issuer_session_id"] == SESSION
    assert found["appointment_raw_sha256"] == hashlib.sha256(_ORIGINAL).hexdigest()
    assert _review_allowlist(_record(), _allow()) is None
    scope = copy.deepcopy(product_scope())
    scope["reviewer_separation"]["formal_reviewer_id"] = ISSUER
    scope["reviewer_separation"]["g3_reviewer_agent_id"] = ISSUER
    scope["handoff"]["formal_reviewer_id"] = ISSUER
    result = assess_scope_reviewer(scope)
    assert result["ok"] is True
    assert result["reasons"] == []
    assert _phase_b_source_authentic.__doc__
