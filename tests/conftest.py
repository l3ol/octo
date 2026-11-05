"""Default synthetic appointment for tests. Not an Owner original."""
import hashlib
import json

import pytest

from octo.scope_metadata import FORMAL_REVIEWER_ID
from octo.trusted_original import CONTROL_PLANE_ENV, ORIGINAL_REVIEWER_SESSION_ID

_THREAD = "6ae7886b-23c8-83e8-a136-f1b52b33d01f"
_ORIGINAL = b"registrar-appointment-original-v1"


@pytest.fixture(autouse=True)
def _protected_appointment(tmp_path_factory, monkeypatch):
    raw = _ORIGINAL
    digest = hashlib.sha256(raw).hexdigest()
    directory = tmp_path_factory.mktemp("appointment")
    (directory / "appointment-original.bin").write_bytes(raw)
    document = {
        "kind": "REGISTRAR_RELAY",
        "not_issuer": True,
        "current_reviewer_conclusion": True,
        "issuer_id": FORMAL_REVIEWER_ID,
        "issuer_session_id": ORIGINAL_REVIEWER_SESSION_ID,
        "thread_id": _THREAD,
        "turn_id": "ca-round-turn",
        "message_id": "ca-round-message",
        "appointment_original_digest": digest,
        "appointment_raw_sha256": digest,
        "issuer_allowlist": [FORMAL_REVIEWER_ID],
        "source_allowlist": [ORIGINAL_REVIEWER_SESSION_ID],
        "base_sha": "b" * 40,
        "candidate_sha": "c" * 40,
        "scope_digest": "d" * 64,
        "fixture_digest": "e" * 64,
        "allowlist_sha256": "f" * 64,
        "collection_source": "read_thread",
        "collected_at": "2026-11-01T12:00:00+00:00",
        "expected_service_response_sha256": "1" * 64,
    }
    path = directory / "control-plane.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setenv(CONTROL_PLANE_ENV, str(path))
