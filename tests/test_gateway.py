"""Builder selftest only. Not product acceptance, independent verification, or runtime_pass."""
from datetime import datetime, timezone
from pathlib import Path
import subprocess

from octo.envelope import validate_envelope
from octo.gateway import run_n10
from octo.grant import AuthorizationRequest, GrantStore
from octo.journal import Journal
from octo.gateway import Gateway
from octo.objects import inputs_hash

ROOT = Path(__file__).resolve().parents[1]
KEY = b"g" * 32
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
AT = "2026-11-01T12:00:00+00:00"


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _ready(tmp_path: Path, *, idempotency_key: str = "idem-n10"):
    journal = Journal(tmp_path)
    grants = GrantStore(tmp_path, fixture_key=KEY)
    resource = tmp_path / "readable.txt"
    resource.write_text("synthetic", encoding="utf-8")
    request = AuthorizationRequest(
        actor="actor-a",
        action="internal_readonly",
        resource=str(resource),
        parameters={"op": "read"},
        intent_id="intent-1",
        idempotency_key=idempotency_key,
        git_candidate_sha=_git("rev-parse", "HEAD"),
        tree_sha=_git("rev-parse", "HEAD^{tree}"),
        grant_id="g-n10",
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
    return journal, grants, request


def _n10_inputs(request: AuthorizationRequest) -> dict:
    return {
        "action": request.action,
        "grant_ref": request.grant_id,
        "idempotency_key": request.idempotency_key,
        "request_digest": request.digest,
        "git_candidate_sha": request.git_candidate_sha,
        "tree_sha": request.tree_sha,
    }


def test_reentry_does_not_repeat_the_effect(tmp_path):
    journal, grants, request = _ready(tmp_path)
    gateway = Gateway(journal, grants)
    first = gateway.execute(request, chat_text="APPROVE " + request.digest, now=NOW)
    second = gateway.execute(request, chat_text="ignore this chat", now=NOW)
    assert first["state"] == "SUCCEEDED"
    assert second["receipt_id"] == first["receipt_id"]
    assert second["state"] == "SUCCEEDED"
    assert gateway.dispatch_count == 1
    assert journal.effect_count() == 1
    assert journal.reconcile_count == 0
    assert (tmp_path / "ledger.sqlite").exists()
    assert not (tmp_path / "octo.db").exists()
    assert not (tmp_path / "brain").exists()
    assert not (ROOT / "brain").exists()
    journal.close()


def test_unknown_commit_reconciles_applied_without_redispatch(tmp_path):
    journal, grants, request = _ready(tmp_path)
    calls = {"n": 0}

    def dispatch(req):
        calls["n"] += 1
        journal.apply(req)
        raise RuntimeError("commit uncertain")

    gateway = Gateway(journal, grants, dispatch=dispatch)
    unknown = gateway.execute(request, now=NOW)
    assert unknown["state"] == "UNKNOWN_COMMIT"
    assert journal.effect_count() == 1
    assert calls["n"] == 1
    replay = gateway.execute(request, chat_text="retry anyway", now=NOW)
    assert replay["state"] == "RECONCILED_APPLIED"
    assert "no redispatch" in replay["notes"]
    assert calls["n"] == 1
    assert gateway.dispatch_count == 1
    assert journal.reconcile_count == 1
    assert journal.effect_count() == 1
    journal.close()


def test_unknown_commit_without_effect_reconciles_before_retry(tmp_path):
    journal, grants, request = _ready(tmp_path, idempotency_key="idem-miss")
    calls = {"n": 0}

    def dispatch(req):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("failed before effect")
        assert journal.reconcile_count >= 1
        return journal.apply(req)

    gateway = Gateway(journal, grants, dispatch=dispatch)
    unknown = gateway.execute(request, now=NOW)
    assert unknown["state"] == "UNKNOWN_COMMIT"
    assert journal.effect_count() == 0
    done = gateway.execute(request, now=NOW)
    assert done["state"] == "SUCCEEDED"
    assert calls["n"] == 2
    assert journal.reconcile_count == 1
    assert journal.effect_count() == 1
    states = [item["state"] for item in journal.events(request.idempotency_key)]
    assert states.index("RECONCILED_NOT_APPLIED") < states.index("SUCCEEDED")
    assert "PREPARED" in states
    journal.close()


def test_n9_failure_does_not_dispatch(tmp_path):
    journal, grants, request = _ready(tmp_path, idempotency_key="idem-deny")
    request = AuthorizationRequest(
        actor=request.actor,
        action=request.action,
        resource=request.resource,
        parameters=request.parameters,
        intent_id=request.intent_id,
        idempotency_key=request.idempotency_key,
        git_candidate_sha=request.git_candidate_sha,
        tree_sha=request.tree_sha,
        grant_id="missing-grant",
    )
    gateway = Gateway(journal, grants)
    envelope = run_n10(_n10_inputs(request), at=AT, gateway=gateway, request=request, now=NOW)
    assert envelope["status"] == "AUTHORIZATION_REQUIRED"
    assert envelope["output"] is None
    assert envelope["node_id"] == "N10"
    assert gateway.dispatch_count == 0
    assert journal.effect_count() == 0
    validate_envelope(envelope)
    assert envelope["inputs_hash"] == inputs_hash(envelope["inputs"])
    journal.close()


def test_n10_ok_envelope_has_no_chat_authority(tmp_path):
    journal, grants, request = _ready(tmp_path, idempotency_key="idem-env")
    gateway = Gateway(journal, grants)
    envelope = run_n10(_n10_inputs(request), at=AT, gateway=gateway, request=request, now=NOW)
    sealed = validate_envelope(envelope)
    assert sealed.status == "OK"
    assert envelope["output"]["state"] == "SUCCEEDED"
    assert "chat_text" not in envelope["inputs"]
    assert gateway.dispatch_count == 1
    journal.close()
