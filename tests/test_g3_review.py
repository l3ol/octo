"""Builder selftest only. Not product acceptance, independent verification, or runtime_pass."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

from octo.g3_review import (
    column_digests,
    fixture_digest,
    handoff_binding,
    invalidate_stored_pass,
    product_scope,
    product_scope_digest,
    review_entry,
    template_inventory,
)
from octo.models import reject_self_sign
from octo.objects import canonical, digest

ROOT = Path(__file__).resolve().parents[1]
SCOPE_PATH = ROOT / "octo" / "scope" / "SCOPE-MANIFEST.json"


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _quadruple(**overrides) -> dict:
    body = {
        "base_sha": "5443c9b4dde7fc208a0a72457c87904650829f77",
        "candidate_sha": _git("rev-parse", "HEAD"),
        "scope_digest": product_scope_digest(),
        "fixture_digest": fixture_digest(),
    }
    body.update(overrides)
    return body


def test_product_scope_and_three_column_fixture_digest_recompute():
    scope = product_scope()
    assert scope["kind"] == "SCOPE-MANIFEST"
    assert set(scope["frozen_basis"]) == {"entry", "io13", "readme"}
    assert scope["nodes"][0] == "N1" and scope["nodes"][-1] == "N13"
    assert "N6" in scope["exclusions"]["nodes_not_emitted"]
    assert scope["acceptance"]
    assert scope["test_commands"] == ["PYTHONPATH=. pytest tests/ -q"]
    assert scope["isolation_strategy"]["deny_egress"] == "NOT_READY"
    assert scope["reviewer_separation"]["builder_may_sign_pass"] is False
    raw_manifest = (ROOT / "SOURCE-IMPORT-MANIFEST-G2-S1.json").read_bytes()
    assert scope["source_import_manifest"]["sha256"] == hashlib.sha256(raw_manifest).hexdigest()
    assert product_scope_digest() == digest(json.loads(SCOPE_PATH.read_text(encoding="utf-8")))
    assert re.search(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", canonical(scope).decode()) is None
    columns = column_digests()
    assert columns["fixture_digest"] == digest({
        "template_digest": columns["template_digest"],
        "runtime_artifact_digest": columns["runtime_artifact_digest"],
        "isolation_policy_digest": columns["isolation_policy_digest"],
    })
    inventory = template_inventory()
    assert inventory["files"]
    for row in inventory["files"]:
        assert hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest() == row["sha256"]
    assert columns["template_digest"] == digest(inventory)
    assert "candidate_sha" not in json.dumps(json.loads(
        (ROOT / "tests/fixtures/g2s1/runtime-artifact-inventory.json").read_text(encoding="utf-8")
    ))
    binding = handoff_binding(
        base_sha="5443c9b4dde7fc208a0a72457c87904650829f77",
        candidate_sha=_git("rev-parse", "HEAD"),
    )
    assert binding["scope_digest"] == product_scope_digest()
    assert binding["fixture_digest"] == fixture_digest()
    assert binding["runtime_pass"] is False
    assert binding["product_pass"] is False
    assert binding["decision"] != "PASS"


def test_matching_quadruple_validates_shape():
    payload = _quadruple()
    receipt = review_entry(payload)
    assert receipt["kind"] == "g3_review_receipt"
    assert receipt["base_sha"] == payload["base_sha"]
    assert receipt["candidate_sha"] == payload["candidate_sha"]
    assert receipt["scope_digest"] == product_scope_digest()
    assert receipt["fixture_digest"] == payload["fixture_digest"]
    assert receipt["scope_source"] == "octo/scope/SCOPE-MANIFEST.json"
    assert receipt["decision"] == "RECEIVED"
    assert receipt["decision"] != "PASS"
    assert receipt["product_pass"] is False
    assert receipt["runtime_pass"] is False
    stored = {
        "decision": "PASS",
        "base_sha": receipt["base_sha"],
        "candidate_sha": receipt["candidate_sha"],
        "scope_digest": receipt["scope_digest"],
        "fixture_digest": receipt["fixture_digest"],
    }
    unchanged = invalidate_stored_pass(stored, receipt)
    assert unchanged["status"] == "UNCHANGED"
    assert unchanged["reasons"] == []
    assert unchanged["runtime_pass"] is False
    with pytest.raises(ValueError):
        review_entry({"base_sha": payload["base_sha"]})
    with pytest.raises(ValueError, match="40 lowercase hex"):
        review_entry(_quadruple(candidate_sha="ab" * 32))
    with pytest.raises(ValueError, match="product SCOPE-MANIFEST"):
        review_entry(_quadruple(scope={"route": "internal_readonly", "selftest": "builder"}))


def test_changed_candidate_sha_invalidates_stored_pass():
    current = review_entry(_quadruple())
    stored = {
        "decision": "PASS",
        "base_sha": current["base_sha"],
        "candidate_sha": "0" * 40,
        "scope_digest": current["scope_digest"],
        "fixture_digest": current["fixture_digest"],
    }
    result = invalidate_stored_pass(stored, current)
    assert result["status"] == "INVALID"
    assert result["reasons"] == ["candidate_sha"]
    assert result["product_pass"] is False
    assert result["runtime_pass"] is False


def test_changed_fixture_digest_invalidates_stored_pass():
    current = review_entry(_quadruple())
    stored = {
        "decision": "PASS",
        "base_sha": current["base_sha"],
        "candidate_sha": current["candidate_sha"],
        "scope_digest": current["scope_digest"],
        "fixture_digest": "cd" * 32,
    }
    result = invalidate_stored_pass(stored, current)
    assert result["status"] == "INVALID"
    assert result["reasons"] == ["fixture_digest"]
    assert result["runtime_pass"] is False


def test_changed_scope_or_base_invalidates_stored_pass():
    current = review_entry(_quadruple())
    changed_scope = dict(current)
    stored_scope = {
        "decision": "PASS",
        "base_sha": current["base_sha"],
        "candidate_sha": current["candidate_sha"],
        "scope_digest": "ab" * 32,
        "fixture_digest": current["fixture_digest"],
    }
    scope_result = invalidate_stored_pass(stored_scope, changed_scope)
    assert scope_result["status"] == "INVALID"
    assert scope_result["reasons"] == ["scope_digest"]
    stored_base = {
        "decision": "PASS",
        "base_sha": "1" * 40,
        "candidate_sha": current["candidate_sha"],
        "scope_digest": current["scope_digest"],
        "fixture_digest": current["fixture_digest"],
    }
    base_result = invalidate_stored_pass(stored_base, current)
    assert base_result["status"] == "INVALID"
    assert base_result["reasons"] == ["base_sha"]


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
