"""Basic tests for core objects and SHA. Synthetic only."""
from dataclasses import fields

import pytest
from octo.models import (
    Decision,
    Evidence,
    Grant,
    Intent,
    Journal,
    Outcome,
    Receipt,
    compute_candidate_sha,
    reject_self_sign,
    validate_prd_record,
)

def test_intent_creation():
    i = Intent(intent_id="i1", text="test", created_at="2026-10-30", source="founder")
    assert i.intent_id == "i1"
    assert "私人" not in i.text  # synthetic only

def test_candidate_sha_reproducible():
    m = {"a.txt": "abc", "b.txt": "def"}
    s1 = compute_candidate_sha(m)
    s2 = compute_candidate_sha(m)
    assert s1 == s2
    assert len(s1) == 64

def test_builder_cannot_self_sign_pass():
    assert reject_self_sign("dev-bot", "dev-bot", "PASS") is True
    assert reject_self_sign("dev-bot", "reviewer-bot", "PASS") is False

def test_candidate_sha_matches_frozen_canonical():
    assert compute_candidate_sha({"a.txt": "abc", "b.txt": "def"}) == (
        "857e2054b9b382f27d59b879a942a809690c2334ac0be6fa1cb92d766f0b3f4d"
    )

def test_prd_section5_field_names_unchanged():
    assert [f.name for f in fields(Intent)] == ["intent_id", "text", "created_at", "source"]
    assert [f.name for f in fields(Decision)] == [
        "decision_id", "intent_id", "content", "decider", "decided_at", "supersedes_id",
    ]
    assert [f.name for f in fields(Evidence)] == [
        "evidence_id", "decision_id", "type", "uri_or_hash", "collected_at",
    ]
    assert [f.name for f in fields(Grant)] == [
        "grant_id", "request_digest", "actions", "amount_limit", "resources",
        "subject", "issued_at", "expires_at", "issued_via", "revoked",
    ]
    assert [f.name for f in fields(Outcome)] == [
        "outcome_id", "decision_id", "receipt_id", "state",
    ]
    assert [f.name for f in fields(Receipt)] == [
        "receipt_id", "grant_id", "request_digest", "candidate_sha", "action",
        "object_id", "idempotency_key", "started_at", "finished_at", "state", "verifier",
    ]
    assert [f.name for f in fields(Journal)] == ["journal_id", "receipt_id", "event", "at"]

def test_validate_prd_record_uses_object_primitives():
    good = Intent(
        intent_id="intent-1",
        text="synthetic",
        created_at="2026-11-01T12:00:00+00:00",
        source="founder",
    )
    assert validate_prd_record(good) is good
    bad_id = Intent(
        intent_id="has space",
        text="x",
        created_at="2026-11-01T12:00:00+00:00",
        source="founder",
    )
    with pytest.raises(ValueError, match="invalid identifier"):
        validate_prd_record(bad_id)
    naive = Intent(
        intent_id="intent-1",
        text="x",
        created_at="2026-11-01T12:00:00",
        source="founder",
    )
    with pytest.raises(ValueError, match="timezone required"):
        validate_prd_record(naive)
    grant = Grant(grant_id="g1", request_digest="ab", actions=["read"])
    with pytest.raises(ValueError, match="SHA-256"):
        validate_prd_record(grant)
