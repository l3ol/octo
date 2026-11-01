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
    isolation_policy_digest,
    product_scope,
    product_scope_digest,
    review_entry,
    runtime_artifact_digest,
    template_digest,
    template_inventory,
    verified_runtime_inventory,
)
from octo.models import reject_self_sign
from octo.objects import canonical, digest

ROOT = Path(__file__).resolve().parents[1]
SCOPE_PATH = ROOT / "octo" / "scope" / "SCOPE-MANIFEST.json"


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _write_manifest(path: Path, store: Path, candidate_sha: str, items: list[dict], *, sealed: bool = False) -> None:
    path.write_text(json.dumps({
        "kind": "external_runtime_artifact_inventory",
        "bound_candidate_sha": candidate_sha,
        "store_root": str(store.resolve()),
        "sealed": sealed,
        "items": items,
    }), encoding="utf-8")


def _external(tmp_path: Path, candidate_sha: str, *, bodies: dict[str, bytes] | None = None) -> Path:
    store = tmp_path / "isolation-store"
    store.mkdir(parents=True)
    payloads = bodies or {
        "grant": b'{"test_only":true,"issued_via":"TEST_FIXTURE"}\n',
        "request": b'{"action":"internal_readonly"}\n',
        "receipt": b'{"decision":"ALLOW","test_only":true}\n',
        "log": b"TEST_FIXTURE log\n",
    }
    items = []
    for kind, body in payloads.items():
        artifact = store / f"{kind}.json"
        artifact.write_bytes(body)
        items.append({
            "kind": kind,
            "path": artifact.name,
            "content_sha256": hashlib.sha256(body).hexdigest(),
            "bytes": len(body),
            "bound_candidate_sha": candidate_sha,
        })
    manifest = tmp_path / "runtime-manifest.json"
    _write_manifest(manifest, store, candidate_sha, items)
    return manifest


def _quadruple(tmp_path: Path, **overrides) -> dict:
    candidate_sha = overrides.get("candidate_sha", _git("rev-parse", "HEAD"))
    if len(candidate_sha) != 40:
        candidate_sha = _git("rev-parse", "HEAD")
    manifest = _external(tmp_path, candidate_sha)
    body = {
        "base_sha": "5443c9b4dde7fc208a0a72457c87904650829f77",
        "candidate_sha": overrides.get("candidate_sha", candidate_sha),
        "scope_digest": product_scope_digest(),
        "runtime_manifest": str(manifest),
        "fixture_digest": fixture_digest(runtime_manifest=manifest, candidate_sha=candidate_sha),
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
    strategy = scope["isolation_strategy"]
    policy = json.loads((ROOT / "tests/fixtures/g2s1/isolation-policy.json").read_text(encoding="utf-8"))
    assert {key: value for key, value in policy.items() if key != "kind"} == strategy
    assert strategy["readiness"] == "READY_FOR_ISOLATED_RUN"
    assert strategy["readiness_conditional"] is True
    assert strategy["runtime_pass"] is False
    assert strategy["full_sandbox"] is False
    assert strategy["deny_egress"]["claimed"] is True
    assert strategy["deny_egress"]["method"] == "bwrap 0.12.0 --unshare-net"
    assert strategy["deny_egress"]["connect_errno"] == 101
    assert strategy["deny_egress"]["app_layer_equals_deny_egress"] is False
    assert strategy["ops_evidence"]["md_sha256"] == (
        "dca8c880e1e458afd52ecc687c417366ce9af7eb069aaf0a7cb79005c4ff089b"
    )
    assert strategy["ops_evidence"]["json_sha256"] == (
        "64a817afa5643940104df1cab7e64628102a139de3fe38be5ce43aab87039086"
    )
    assert scope["reviewer_separation"]["builder_may_sign_pass"] is False
    raw_manifest = (ROOT / "SOURCE-IMPORT-MANIFEST-G2-S1.json").read_bytes()
    assert scope["source_import_manifest"]["sha256"] == hashlib.sha256(raw_manifest).hexdigest()
    assert product_scope_digest() == digest(json.loads(SCOPE_PATH.read_text(encoding="utf-8")))
    assert re.search(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", canonical(scope).decode()) is None
    inventory = template_inventory()
    assert inventory["files"]
    for row in inventory["files"]:
        assert hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest() == row["sha256"]
    assert template_digest() == digest(inventory)
    schema = json.loads((ROOT / "tests/fixtures/g2s1/runtime-artifact-inventory.json").read_text(encoding="utf-8"))
    assert schema["acceptance_input"] is False
    assert schema["kind"] == "runtime_artifact_inventory_schema"
    assert "candidate_sha" not in schema
    with pytest.raises(ValueError, match="RUNTIME_SCHEMA_NOT_EVIDENCE"):
        runtime_artifact_digest(ROOT / "tests/fixtures/g2s1/runtime-artifact-inventory.json", candidate_sha=_git("rev-parse", "HEAD"))
    with pytest.raises(TypeError):
        fixture_digest()


def test_matching_quadruple_validates_shape(tmp_path):
    payload = _quadruple(tmp_path)
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
    binding = handoff_binding(
        base_sha=payload["base_sha"],
        candidate_sha=payload["candidate_sha"],
        runtime_manifest=payload["runtime_manifest"],
    )
    assert binding["fixture_digest"] == receipt["fixture_digest"]
    assert binding["runtime_pass"] is False
    assert binding["decision"] != "PASS"
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
        review_entry(_quadruple(tmp_path / "bad-sha", candidate_sha="ab" * 32))
    with pytest.raises(ValueError, match="product SCOPE-MANIFEST"):
        review_entry(_quadruple(tmp_path / "bad-scope", scope={"route": "internal_readonly", "selftest": "builder"}))
    with pytest.raises(ValueError, match="external runtime manifest is required"):
        review_entry({
            "base_sha": payload["base_sha"],
            "candidate_sha": payload["candidate_sha"],
            "scope_digest": payload["scope_digest"],
            "fixture_digest": payload["fixture_digest"],
        })


def test_changed_candidate_sha_invalidates_stored_pass(tmp_path):
    current = review_entry(_quadruple(tmp_path))
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


def test_changed_fixture_digest_invalidates_stored_pass(tmp_path):
    current = review_entry(_quadruple(tmp_path))
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


def test_changed_scope_or_base_invalidates_stored_pass(tmp_path):
    current = review_entry(_quadruple(tmp_path))
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


def test_one_byte_change_moves_runtime_and_fixture_digests(tmp_path):
    candidate_sha = _git("rev-parse", "HEAD")
    manifest = _external(tmp_path, candidate_sha)
    before = column_digests(runtime_manifest=manifest, candidate_sha=candidate_sha)
    rows = verified_runtime_inventory(manifest, candidate_sha=candidate_sha)
    assert before["runtime_artifact_digest"] == digest(rows)
    assert [row["path"] for row in rows] == sorted(row["path"] for row in rows)
    assert before["fixture_digest"] == digest({
        "template_digest": before["template_digest"],
        "runtime_artifact_digest": before["runtime_artifact_digest"],
        "isolation_policy_digest": before["isolation_policy_digest"],
    })
    grant = tmp_path / "isolation-store" / "grant.json"
    original = grant.read_bytes()
    grant.write_bytes(original[:-1] + bytes([original[-1] ^ 0x01]))
    with pytest.raises(ValueError, match="CONTENT_SHA_MISMATCH"):
        runtime_artifact_digest(manifest, candidate_sha=candidate_sha)
    rebound = _external(tmp_path / "rebound", candidate_sha, bodies={
        "grant": grant.read_bytes(),
        "request": (tmp_path / "isolation-store" / "request.json").read_bytes(),
        "receipt": (tmp_path / "isolation-store" / "receipt.json").read_bytes(),
        "log": (tmp_path / "isolation-store" / "log.json").read_bytes(),
    })
    after = column_digests(runtime_manifest=rebound, candidate_sha=candidate_sha)
    assert after["runtime_artifact_digest"] != before["runtime_artifact_digest"]
    assert after["fixture_digest"] != before["fixture_digest"]
    assert after["template_digest"] == before["template_digest"] == template_digest()
    assert after["isolation_policy_digest"] == before["isolation_policy_digest"] == isolation_policy_digest()


def test_fail_closed_on_missing_escape_mismatch_and_empty(tmp_path):
    candidate_sha = _git("rev-parse", "HEAD")
    manifest = _external(tmp_path, candidate_sha)
    (tmp_path / "isolation-store" / "log.json").unlink()
    with pytest.raises(ValueError, match="ARTIFACT_MISSING"):
        runtime_artifact_digest(manifest, candidate_sha=candidate_sha)
    store = tmp_path / "escape-store"
    store.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"outside\n")
    escaped = tmp_path / "escaped-manifest.json"
    _write_manifest(escaped, store, candidate_sha, [{
        "kind": "grant",
        "path": str(outside.resolve()),
        "content_sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
        "bound_candidate_sha": candidate_sha,
        "bytes": outside.stat().st_size,
    }])
    with pytest.raises(ValueError, match="PATH_ESCAPE"):
        runtime_artifact_digest(escaped, candidate_sha=candidate_sha)
    mismatch = _external(tmp_path / "mismatch", candidate_sha)
    with pytest.raises(ValueError, match="CANDIDATE_SHA_MISMATCH"):
        runtime_artifact_digest(mismatch, candidate_sha="1" * 40)
    empty = tmp_path / "empty-manifest.json"
    _write_manifest(empty, store, candidate_sha, [])
    with pytest.raises(ValueError, match="EXTERNAL_MANIFEST_EMPTY"):
        runtime_artifact_digest(empty, candidate_sha=candidate_sha)
    schema_copy = tmp_path / "schema-copy.json"
    schema_copy.write_bytes((ROOT / "tests/fixtures/g2s1/runtime-artifact-inventory.json").read_bytes())
    with pytest.raises(ValueError, match="RUNTIME_SCHEMA_NOT_EVIDENCE"):
        runtime_artifact_digest(schema_copy, candidate_sha=candidate_sha)


def test_rewrite_and_cycle_members_are_rejected(tmp_path):
    candidate_sha = _git("rev-parse", "HEAD")
    manifest = _external(tmp_path, candidate_sha)
    inventory = verified_runtime_inventory(manifest, candidate_sha=candidate_sha)
    assert isinstance(inventory, list)
    assert all(set(row) == {"bound_candidate_sha", "bytes", "content_sha256", "kind", "path"} for row in inventory)
    assert "runtime-manifest.json" not in {row["path"] for row in inventory}
    sealed = tmp_path / "sealed-manifest.json"
    sealed.write_text(manifest.read_text(encoding="utf-8").replace('"sealed": false', '"sealed": true'), encoding="utf-8")
    frozen = (tmp_path / "isolation-store" / "receipt.json").read_bytes()
    (tmp_path / "isolation-store" / "receipt.json").write_bytes(frozen + b" ")
    with pytest.raises(ValueError, match="POST_FREEZE_REWRITE"):
        runtime_artifact_digest(sealed, candidate_sha=candidate_sha)
    store = tmp_path / "cycle-store"
    store.mkdir()
    receipt = store / "review-receipt.json"
    receipt.write_bytes(b'{"decision":"RECEIVED"}\n')
    cycle = tmp_path / "cycle-manifest.json"
    _write_manifest(cycle, store, candidate_sha, [{
        "kind": "receipt",
        "path": receipt.name,
        "content_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        "bound_candidate_sha": candidate_sha,
        "bytes": receipt.stat().st_size,
    }])
    with pytest.raises(ValueError, match="CYCLE_INPUT_FORBIDDEN"):
        runtime_artifact_digest(cycle, candidate_sha=candidate_sha)
    snapshot = store / "handoff-snapshot.json"
    snapshot.write_bytes(b"{}\n")
    listed = json.loads(cycle.read_text(encoding="utf-8"))
    listed["items"] = [{
        "kind": "log",
        "path": snapshot.name,
        "content_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
        "bound_candidate_sha": candidate_sha,
        "bytes": snapshot.stat().st_size,
    }]
    cycle.write_text(json.dumps(listed), encoding="utf-8")
    with pytest.raises(ValueError, match="CYCLE_INPUT_FORBIDDEN"):
        runtime_artifact_digest(cycle, candidate_sha=candidate_sha)


def test_builder_self_sign_path_blocked(tmp_path):
    assert reject_self_sign("builder-selftest", "builder-selftest", "PASS") is True
    with pytest.raises(PermissionError, match="self-sign"):
        review_entry(_quadruple(
            tmp_path / "self-sign",
            builder_id="builder-selftest",
            verifier_id="builder-selftest",
            claimed_state="PASS",
        ))
    with pytest.raises(PermissionError, match="does not issue PASS"):
        review_entry(_quadruple(
            tmp_path / "no-pass",
            decision="PASS",
            builder_id="builder-selftest",
            verifier_id="not-the-builder",
        ))
    script = ROOT / "scripts" / "g3_review_entry"
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(_quadruple(tmp_path / "cli", claimed_state="PASS", builder_id="same", verifier_id="same")),
        text=True,
        capture_output=True,
        cwd=ROOT,
        env={**dict(**{k: v for k, v in __import__("os").environ.items()}), "PYTHONPATH": "."},
    )
    assert proc.returncode == 2
    assert "PASS" not in proc.stdout
