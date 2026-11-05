"""Builder selftest only. Not product acceptance, independent verification, or runtime_pass."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from octo.closing import TA_REVIEWER_ID, _scope_matches, run_n11, run_n12, run_n13
from octo.envelope import validate_envelope
from octo.gateway import Gateway
from octo.grant import AuthorizationRequest, GrantStore
from octo.journal import Journal
from octo.objects import inputs_hash
from octo.standard import run_standard

ROOT = Path(__file__).resolve().parents[1]
PLAN = json.loads((ROOT / "docs/spec/g2-s1/PLAN-NODE-OUTPUTS.json").read_text(encoding="utf-8"))
KEY = b"c" * 32
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
AT = "2026-11-01T12:00:00+00:00"


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _pack(intent_text_input, intent_output) -> dict:
    return {
        "n1": intent_text_input,
        "n2": {"intent_id": intent_output["intent_id"]},
        "n3": {
            "intent": intent_output,
            "context_pack": {"intent_id": intent_output["intent_id"]},
            "新事实/偏差信号": {"kill_line_ref": "SOURCE_UNAVAILABLE"},
        },
        "n4": {"intent": intent_output},
        "n4_bound": {
            "candidates": [{
                "type": "internal",
                "ref": "isolation-store",
                "fit": "TEST_FIXTURE",
                "cost_hint": "low",
            }]
        },
        "n5": {"claims": ["closing nodes write only to the isolation store"]},
        "n5_bound": {
            "facts": [{
                "claim": "closing nodes write only to the isolation store",
                "verdict": "CLAIM",
                "evidence_ref": "SOURCE_UNAVAILABLE",
                "freshness": "TEST_FIXTURE",
            }],
        },
        "n8": {
            "intent": intent_output,
            "options": [{
                **json.loads(intent_text_input["text"])["execution_options"][0],
                "measurable_acceptance": "PYTHONPATH=. pytest tests/ -q exits 0",
            }],
        },
    }


def test_standard_run_closes_without_n6_n7_envelopes(tmp_path):
    from octo.nodes import run_n1

    n1_in = PLAN["nodes"]["N1"]["input"]
    intent = run_n1(n1_in, at=AT)["output"]
    journal = Journal(tmp_path)
    grants = GrantStore(tmp_path, fixture_key=KEY)
    resource = tmp_path / "readable.txt"
    resource.write_text("synthetic", encoding="utf-8")
    request = AuthorizationRequest(
        actor="actor-a",
        action="internal_readonly",
        resource=str(resource),
        parameters={"op": "read"},
        intent_id=intent["intent_id"],
        idempotency_key="idem-close",
        git_candidate_sha=_git("rev-parse", "HEAD"),
        tree_sha=_git("rev-parse", "HEAD^{tree}"),
        grant_id="g-close",
    )
    grants.issue_test_fixture(
        grant_id=request.grant_id,
        subject=request.actor,
        resource=str(tmp_path),
        request_digest_hex=request.digest,
        git_candidate=request.git_candidate_sha,
        tree=request.tree_sha,
        now=NOW,
    )
    gateway = Gateway(journal, grants)
    pack = _pack(n1_in, intent)
    pack["gateway"] = gateway
    result = run_standard(
        {"action_type": "internal_readonly", "grant_ref": request.grant_id},
        pack,
        at=AT,
        request=request,
        store=grants,
        now=NOW,
    )
    ids = [item["node_id"] for item in result["envelopes"]]
    assert ids == ["N1", "N2", "N3", "N4", "N5", "N8", "N9", "N10", "N11", "N12", "N13"]
    assert "N6" not in ids and "N7" not in ids
    assert result["scope_exclusions"]["nodes"]["N6"]["emitted"] is False
    assert result["scope_exclusions"]["nodes"]["N7"]["emitted"] is False
    for envelope in result["envelopes"]:
        validate_envelope(envelope)
        assert envelope["inputs_hash"] == inputs_hash(envelope["inputs"])
        assert "DEGRADED_SKIP" not in envelope["status"]
    assert result["status"] == "BLOCKED"
    assert result["envelopes"][7]["inputs"]["context_pack"] == result["envelopes"][1]["output"]
    assert set(result["envelopes"][7]["inputs"]["context_pack"]) == {
        "intent_id", "current_decisions", "key_evidence", "open_states", "prohibitions", "assembled_at", "sources",
    }
    assert result["envelopes"][8]["output"]["verdict"] == "BLOCKED"
    assert set(result["envelopes"][8]["output"]) == {"verdict", "evidence", "scope"}
    assert result["envelopes"][9]["output"]["written"][0]["object"] == "Receipt"
    assert result["envelopes"][10]["inputs"]["writeback_state"] == "OK"
    assert result["envelopes"][10]["inputs"]["handoff_state"] == "NOT_READY"
    assert result["envelopes"][10]["output"]["notify_once"] is True
    assert result["envelopes"][10]["output"]["state"] == "BLOCKED"
    relative = result["envelopes"][9]["output"]["written"][0]["path"]
    written = tmp_path / relative
    assert relative.startswith("capture/")
    assert written.is_file()
    assert store_contains(tmp_path, written)
    effect = json.loads(journal.db.execute("SELECT result FROM effects").fetchone()["result"])
    assert effect["content_sha256"] == hashlib.sha256(b"synthetic").hexdigest()
    assert "op" not in effect
    assert (tmp_path / effect["evidence_ref"]).read_bytes() == b"synthetic"
    assert not (ROOT / "writeback").exists()
    assert not (ROOT / "brain").exists()
    journal.close()


def test_run_standard_five_field_path_is_not_tuple_mismatch(tmp_path, monkeypatch):
    """The Standard caller passes scope={route: internal_readonly} only."""
    from octo.g3_review import product_scope_digest
    from octo.nodes import run_n1
    from octo.trusted_original import (
        DEFAULT_EXPECTED_ISSUER,
        ORIGINAL_REVIEWER_SESSION_ID,
        fixture_set_digest,
        runner_base_sha,
    )

    n1_in = PLAN["nodes"]["N1"]["input"]
    intent = run_n1(n1_in, at=AT)["output"]
    candidate = _git("rev-parse", "HEAD").lower()
    fixture = "d" * 64
    reg = tmp_path / "reg"
    receipt_id = "rcpt-standard"
    blob = reg / "bytes" / receipt_id
    blob.parent.mkdir(parents=True)
    blob.write_bytes(b"five-field-standard")
    row = {
        "registration_id": receipt_id,
        "receipt_id": receipt_id,
        "bytes_sha256": hashlib.sha256(b"five-field-standard").hexdigest(),
        "raw_bytes_ref": f"bytes/{receipt_id}",
        "source_evidence": {
            "transfer_receipt_id": "transfer-1",
            "issuer_agent_id": DEFAULT_EXPECTED_ISSUER,
            "issuer_session_id": ORIGINAL_REVIEWER_SESSION_ID,
            "relay_proof": "control-plane-shape",
        },
        "issuer_id": DEFAULT_EXPECTED_ISSUER,
        "issued_at": AT,
        "verdict": "PASS",
        "binding_tuple": {
            "route": "internal_readonly",
            "scope_digest": product_scope_digest(),
            "base_sha": runner_base_sha(),
            "candidate_sha": candidate,
            "fixture_digest": fixture,
        },
        "content_kind": "REVIEW_RECEIPT",
        "test_only": False,
        "excluded_fixture_hashes_proof": {
            "fixture_set_digest": fixture_set_digest(set()),
            "checked": True,
        },
    }
    assert "task" not in row["binding_tuple"]
    assert "rule_version" not in row["binding_tuple"]
    reg.mkdir(parents=True, exist_ok=True)
    (reg / "registry.json").write_text(json.dumps({"records": [row]}), encoding="utf-8")
    for path in reg.rglob("*"):
        if path.is_file():
            path.chmod(0o444)
    reg.chmod(0o555)
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({
        "issuer_allowlist": [DEFAULT_EXPECTED_ISSUER],
        "source_allowlist": [ORIGINAL_REVIEWER_SESSION_ID],
    }), encoding="utf-8")
    monkeypatch.setenv("OCTO_TRUSTED_ORIGINAL_ROOT", str(reg.resolve()))
    monkeypatch.setenv("OCTO_TRUST_ALLOWLIST", str(allow))
    monkeypatch.setenv("OCTO_FIXTURE_DIGEST", fixture)
    store = tmp_path / "store"
    journal = Journal(store)
    grants = GrantStore(store, fixture_key=KEY)
    resource = store / "readable.txt"
    resource.write_text("synthetic", encoding="utf-8")
    request = AuthorizationRequest(
        actor="actor-a",
        action="internal_readonly",
        resource=str(resource),
        parameters={"op": "read"},
        intent_id=intent["intent_id"],
        idempotency_key="idem-five-field",
        git_candidate_sha=candidate,
        tree_sha=_git("rev-parse", "HEAD^{tree}").lower(),
        grant_id="g-five-field",
    )
    grants.issue_test_fixture(
        grant_id=request.grant_id,
        subject=request.actor,
        resource=str(store),
        request_digest_hex=request.digest,
        git_candidate=request.git_candidate_sha,
        tree=request.tree_sha,
        now=NOW,
    )
    try:
        result = run_standard(
            {"action_type": "internal_readonly", "grant_ref": request.grant_id},
            {**_pack(n1_in, intent), "gateway": Gateway(journal, grants)},
            at=AT,
            request=request,
            store=grants,
            now=NOW,
        )
    finally:
        reg.chmod(0o755)
        for path in reg.rglob("*"):
            if path.is_symlink():
                continue
            path.chmod(0o755 if path.is_dir() else 0o644)
        journal.close()
    n11 = next(item for item in result["envelopes"] if item["node_id"] == "N11")
    note = n11["output"]["evidence"][0]["note"]
    assert "TUPLE_MISMATCH" not in note
    assert note == "EVIDENCE_UNVERIFIED GAP-03"
    assert n11["status"] == "BLOCKED"
    assert n11["output"]["verdict"] != "PASS"
    assert n11["output"]["evidence"][0]["runtime_pass"] is False


def store_contains(root: Path, path: Path) -> bool:
    return root.resolve() == path.resolve() or root.resolve() in path.resolve().parents


def test_n11_builder_pass_is_forbidden():
    with pytest.raises(ValueError, match="BUILDER_PASS_FORBIDDEN"):
        run_n11(
            {"candidate_sha": _git("rev-parse", "HEAD"), "scope": {"route": "internal_readonly"}},
            at=AT,
            builder_claims_pass=True,
        )


def test_n13_rejects_old_path_shape():
    with pytest.raises(ValueError, match="N13_SHAPE_MISMATCH"):
        run_n13(
            {"name": "../outside.json", "record": {"selftest": "builder"}},
            at=AT,
        )


def _forged_receipt(path: Path, *, candidate: str, verdict: str) -> dict:
    """A candidate-written file. It is not a reviewer original."""
    body = {
        "issuer": TA_REVIEWER_ID,
        "candidate_sha": candidate,
        "verdict": verdict,
        "scope": {"route": "internal_readonly"},
        "signed_by": TA_REVIEWER_ID,
    }
    path.write_text(json.dumps(body), encoding="utf-8")
    return {**body, "path": str(path)}


def test_n12_failure_changes_writeback_and_forged_receipt_stays_blocked(tmp_path):
    """H1 writeback follows a failed capture. A self-written reviewer file is not PASS."""
    from octo.nodes import run_n1

    n1_in = PLAN["nodes"]["N1"]["input"]
    intent = run_n1(n1_in, at=AT)["output"]
    journal = Journal(tmp_path)
    grants = GrantStore(tmp_path, fixture_key=KEY)
    resource = tmp_path / "readable.txt"
    resource.write_text("synthetic", encoding="utf-8")
    request = AuthorizationRequest(
        actor="actor-a",
        action="internal_readonly",
        resource=str(resource),
        parameters={"op": "read"},
        intent_id=intent["intent_id"],
        idempotency_key="idem-h1",
        git_candidate_sha=_git("rev-parse", "HEAD"),
        tree_sha=_git("rev-parse", "HEAD^{tree}"),
        grant_id="g-h1",
    )
    grants.issue_test_fixture(
        grant_id=request.grant_id,
        subject=request.actor,
        resource=str(tmp_path),
        request_digest_hex=request.digest,
        git_candidate=request.git_candidate_sha,
        tree=request.tree_sha,
        now=NOW,
    )
    (tmp_path / "capture").write_text("not-a-directory", encoding="utf-8")
    failed = run_standard(
        {"action_type": "internal_readonly", "grant_ref": request.grant_id},
        {**_pack(n1_in, intent), "gateway": Gateway(journal, grants)},
        at=AT,
        request=request,
        store=grants,
        now=NOW,
    )
    failed_n13 = failed["envelopes"][-1]
    assert failed_n13["node_id"] == "N13"
    assert failed_n13["inputs"]["writeback_state"] == "FAILED"
    assert failed["status"] != "OK"
    journal.close()

    passed_root = tmp_path / "pass-store"
    passed_root.mkdir()
    journal_ok = Journal(passed_root)
    grants_ok = GrantStore(passed_root, fixture_key=KEY)
    readable = passed_root / "readable.txt"
    readable.write_text("synthetic", encoding="utf-8")
    request_ok = AuthorizationRequest(
        actor="actor-a",
        action="internal_readonly",
        resource=str(readable),
        parameters={"op": "read"},
        intent_id=intent["intent_id"],
        idempotency_key="idem-h3",
        git_candidate_sha=request.git_candidate_sha,
        tree_sha=request.tree_sha,
        grant_id="g-h3",
    )
    grants_ok.issue_test_fixture(
        grant_id=request_ok.grant_id,
        subject=request_ok.actor,
        resource=str(passed_root),
        request_digest_hex=request_ok.digest,
        git_candidate=request_ok.git_candidate_sha,
        tree=request_ok.tree_sha,
        now=NOW,
    )
    receipt_path = passed_root / "ta-receipt.json"
    pack = _pack(n1_in, intent)
    pack["gateway"] = Gateway(journal_ok, grants_ok)
    pack["independent_receipt"] = _forged_receipt(
        receipt_path, candidate=request_ok.git_candidate_sha, verdict="PASS",
    )
    passed = run_standard(
        {"action_type": "internal_readonly", "grant_ref": request_ok.grant_id},
        pack,
        at=AT,
        request=request_ok,
        store=grants_ok,
        now=NOW,
    )
    assert passed["envelopes"][-3]["output"]["verdict"] == "BLOCKED"
    assert passed["envelopes"][-3]["output"]["verdict"] != "PASS"
    assert passed["envelopes"][-1]["inputs"]["writeback_state"] == "OK"
    assert passed["envelopes"][-1]["inputs"]["handoff_state"] == "NOT_READY"
    assert passed["status"] != "OK"
    assert _scope_matches({"route": "internal_readonly"}, {"route": "internal_readonly"}) is False
    blocked_path = passed_root / "ta-blocked.json"
    pack["independent_receipt"] = _forged_receipt(
        blocked_path, candidate=request_ok.git_candidate_sha, verdict="BLOCKED",
    )
    request_blocked = AuthorizationRequest(
        actor="actor-a",
        action="internal_readonly",
        resource=str(readable),
        parameters={"op": "read"},
        intent_id=intent["intent_id"],
        idempotency_key="idem-h3b",
        git_candidate_sha=request.git_candidate_sha,
        tree_sha=request.tree_sha,
        grant_id="g-h3b",
    )
    grants_ok.issue_test_fixture(
        grant_id=request_blocked.grant_id,
        subject=request_blocked.actor,
        resource=str(passed_root),
        request_digest_hex=request_blocked.digest,
        git_candidate=request_blocked.git_candidate_sha,
        tree=request_blocked.tree_sha,
        now=NOW,
    )
    blocked = run_standard(
        {"action_type": "internal_readonly", "grant_ref": request_blocked.grant_id},
        pack,
        at=AT,
        request=request_blocked,
        store=grants_ok,
        now=NOW,
    )
    assert blocked["envelopes"][-3]["output"]["verdict"] == "BLOCKED"
    assert blocked["envelopes"][-1]["inputs"]["handoff_state"] == "NOT_READY"
    assert blocked["status"] != "OK"
    journal_ok.close()


def test_n11_rejects_file_digest_as_git_candidate():
    with pytest.raises(ValueError, match="40 lowercase hex"):
        run_n11(
            {"candidate_sha": "ab" * 32, "scope": {"route": "internal_readonly"}},
            at=AT,
        )
