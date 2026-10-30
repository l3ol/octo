"""Basic tests for core objects and SHA. Synthetic only."""
import pytest
from octo.models import Intent, compute_candidate_sha

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
