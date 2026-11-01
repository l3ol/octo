"""Builder selftest only. Not product acceptance, independent verification, or runtime_pass."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from octo.g3_review import fixture_digest, invalidate_stored_pass, review_entry
from octo.models import reject_self_sign
from octo.objects import digest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "g2s1"


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _quadruple(**overrides) -> dict:
    body = {
        "base_sha": "5443c9b4dde7fc208a0a72457c87904650829f77",
        "candidate_sha": _git("rev-parse", "HEAD"),
        "scope": {"route": "internal_readonly", "selftest": "builder"},
        "fixture_digest": fixture_digest(FIXTURES),
    }
    body.update(overrides)
    return body


def test_fixture_digest_recomputes_plan_section_1():
    lines = []
    for path in sorted(p for p in FIXTURES.rglob("*") if p.is_file()):
        relative = path.relative_to(FIXTURES).as_posix()
        file_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{relative}={file_sha}")
    material = "\n".join(lines).encode("utf-8")
    assert not material.endswith(b"\n")
    assert fixture_digest(FIXTURES) == hashlib.sha256(material).hexdigest()
    assert (FIXTURES / "marker.txt").read_text(encoding="utf-8") == "TEST_FIXTURE\n"


def test_matching_quadruple_validates_shape():
    payload = _quadruple()
    receipt = review_entry(payload)
    assert receipt["kind"] == "g3_review_receipt"
    assert receipt["base_sha"] == payload["base_sha"]
    assert receipt["candidate_sha"] == payload["candidate_sha"]
    assert receipt["scope_digest"] == digest(payload["scope"])
    assert receipt["fixture_digest"] == payload["fixture_digest"]
    assert receipt["scope"] == payload["scope"]
    assert receipt["decision"] == "RECEIVED"
    assert receipt["decision"] != "PASS"
    assert receipt["product_pass"] is False
    stored = {
        "decision": "PASS",
        "candidate_sha": receipt["candidate_sha"],
        "fixture_digest": receipt["fixture_digest"],
    }
    unchanged = invalidate_stored_pass(stored, receipt)
    assert unchanged["status"] == "UNCHANGED"
    assert unchanged["product_pass"] is False
    with pytest.raises(ValueError):
        review_entry({"base_sha": payload["base_sha"]})
    with pytest.raises(ValueError, match="40 lowercase hex"):
        review_entry(_quadruple(candidate_sha="ab" * 32))


def test_changed_candidate_sha_invalidates_stored_pass():
    current = review_entry(_quadruple())
    stored = {
        "decision": "PASS",
        "candidate_sha": "0" * 40,
        "fixture_digest": current["fixture_digest"],
    }
    result = invalidate_stored_pass(stored, current)
    assert result["status"] == "INVALID"
    assert result["reasons"] == ["candidate_sha"]
    assert result["product_pass"] is False
    assert result.get("decision") != "PASS"


def test_changed_fixture_digest_invalidates_stored_pass():
    current = review_entry(_quadruple())
    stored = {
        "decision": "PASS",
        "candidate_sha": current["candidate_sha"],
        "fixture_digest": "cd" * 32,
    }
    result = invalidate_stored_pass(stored, current)
    assert result["status"] == "INVALID"
    assert result["reasons"] == ["fixture_digest"]
    assert result["product_pass"] is False


def test_builder_self_sign_path_blocked():
    assert reject_self_sign("builder-selftest", "builder-selftest", "PASS") is True
    with pytest.raises(PermissionError, match="self-sign"):
        review_entry(_quadruple(
            builder_id="builder-selftest",
            verifier_id="builder-selftest",
            claimed_state="PASS",
        ))
    with pytest.raises(PermissionError, match="does not issue PASS"):
        review_entry(_quadruple(
            decision="PASS",
            builder_id="builder-selftest",
            verifier_id="not-the-builder",
        ))
    script = ROOT / "scripts" / "g3_review_entry"
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(_quadruple(claimed_state="PASS", builder_id="same", verifier_id="same")),
        text=True,
        capture_output=True,
        cwd=ROOT,
        env={**dict(**{k: v for k, v in __import__("os").environ.items()}), "PYTHONPATH": "."},
    )
    assert proc.returncode == 2
    assert "PASS" not in proc.stdout
