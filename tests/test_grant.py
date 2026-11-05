"""Builder selftest only. Not product acceptance, independent verification, or runtime_pass."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess

import pytest

from octo.envelope import validate_envelope
from octo.grant import SIX_VALIDATORS, AuthorizationRequest, GrantStore, write_once
from octo.n9 import precheck, run_n9
from octo.objects import inputs_hash
from octo.router import S1_STANDARD_ACTIONS, route

ROOT = Path(__file__).resolve().parents[1]
KEY = b"k" * 32
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
AT = "2026-11-01T12:00:00+00:00"


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _request(tmp_path: Path, **overrides) -> AuthorizationRequest:
    resource = tmp_path / "readable.txt"
    resource.write_text("synthetic", encoding="utf-8")
    fields = {
        "actor": "actor-a",
        "action": "internal_readonly",
        "resource": str(resource),
        "parameters": {"op": "read"},
        "intent_id": "intent-1",
        "idempotency_key": "idem-1",
        "git_candidate_sha": _git("rev-parse", "HEAD"),
        "tree_sha": _git("rev-parse", "HEAD^{tree}"),
        "grant_id": "g-allow",
    }
    fields.update(overrides)
    return AuthorizationRequest(**fields)


def _store(tmp_path: Path) -> GrantStore:
    return GrantStore(tmp_path, fixture_key=KEY)


def _issue(store: GrantStore, request: AuthorizationRequest, **overrides) -> dict:
    fields = {
        "grant_id": request.grant_id,
        "subject": request.actor,
        "resource": str(store.root),
        "request_digest_hex": request.digest,
        "git_candidate": request.git_candidate_sha,
        "tree": request.tree_sha,
        "now": NOW,
    }
    fields.update(overrides)
    return store.issue_test_fixture(**fields)


def _inputs(request: AuthorizationRequest) -> dict:
    return {
        "action": request.action,
        "grant_id": request.grant_id,
        "request_digest": request.digest,
    }


def test_template_is_static_and_source_has_no_founder_cli():
    template = json.loads((ROOT / "octo/fixtures/grant-template.json").read_text(encoding="utf-8"))
    assert template["test_only"] is True
    assert template["issued_via"] == "TEST_FIXTURE"
    assert template["action_type"] == "internal_readonly"
    assert template["git_candidate_sha"].startswith("<")
    assert "mac" not in template
    source = (ROOT / "octo/grant.py").read_text(encoding="utf-8")
    assert "FOUNDER_LOCAL_CLI" not in source
    assert "token_bytes" not in source
    assert "brain/grants" not in source
    assert "def main" not in source
    assert ".founder-key" in source
    assert S1_STANDARD_ACTIONS == frozenset({"internal_readonly"})


def test_positive_allow_grant_ref_is_usable_by_router(tmp_path):
    store = _store(tmp_path)
    request = _request(tmp_path)
    _issue(store, request)
    result = precheck(store, request, now=NOW)
    assert result["status"] == "OK"
    assert result["receipt"]["decision"] == "ALLOW"
    assert result["receipt"]["test_only"] is True
    assert result["validators"] == list(SIX_VALIDATORS)
    decision = route(
        {"action_type": "internal_readonly", "grant_ref": result["grant_ref"]},
        n9=result,
    )
    assert decision.status == "OK"
    assert decision.execution_authorized is True
    envelope = run_n9(_inputs(request), at=AT, store=store, request=request, now=NOW)
    sealed = validate_envelope(envelope)
    assert sealed.node_id == "N9"
    assert sealed.inputs_hash == inputs_hash(envelope["inputs"])
    assert envelope["output"]["verdict"] == "ALLOW"
    assert envelope["output"]["grant_ref"] == "g-allow"
    assert envelope["node_id"] not in {"N6", "N7"}


@pytest.mark.parametrize(
    ("validator", "mutate"),
    [
        ("subject", lambda request, kwargs: {**kwargs, "actor": "actor-b"}),
        ("action", lambda request, kwargs: {**kwargs, "action": "delete"}),
        ("resource", lambda request, kwargs: {**kwargs, "resource": "/etc/hosts"}),
        ("amount", lambda request, kwargs: kwargs),
        ("time", lambda request, kwargs: kwargs),
        ("request_digest", lambda request, kwargs: {**kwargs, "idempotency_key": "idem-2"}),
    ],
)
def test_six_validators_each_write_one_deny_receipt(tmp_path, validator, mutate):
    store = _store(tmp_path)
    base = _request(tmp_path, grant_id=f"g-{validator}")
    issue_kwargs = {}
    if validator == "amount":
        issue_kwargs["amount_limit"] = 1
    issued = _issue(store, base, **issue_kwargs)
    assert issued["test_only"] is True
    fields = {
        "actor": base.actor,
        "action": base.action,
        "resource": base.resource,
        "parameters": base.parameters,
        "intent_id": base.intent_id,
        "idempotency_key": base.idempotency_key,
        "git_candidate_sha": base.git_candidate_sha,
        "tree_sha": base.tree_sha,
        "grant_id": base.grant_id,
    }
    request = AuthorizationRequest(**mutate(base, fields))
    when = NOW + timedelta(hours=3) if validator == "time" else NOW
    result = precheck(store, request, now=when)
    assert result["status"] == "AUTHORIZATION_REQUIRED"
    assert result["receipt"]["decision"] == "DENY"
    assert result["receipt"]["validator"] == validator
    assert result["grant_ref"] is None
    decision = route(
        {"action_type": "internal_readonly", "grant_ref": base.grant_id},
        n9=result,
    )
    assert decision.status == "AUTHORIZATION_REQUIRED"
    assert decision.execution_authorized is False
    envelope = run_n9(_inputs(request), at=AT, store=store, request=request, now=when)
    assert envelope["status"] == "AUTHORIZATION_REQUIRED"
    assert envelope["output"]["verdict"] == "DENY"
    assert "grant_scope_draft" in envelope["output"]["reason"]
    assert envelope["node_id"] == "N9"


def test_missing_grant_and_upgrade_stop(tmp_path):
    store = _store(tmp_path)
    request = _request(tmp_path, grant_id=None)
    missing = precheck(store, request, now=NOW)
    assert missing["status"] == "AUTHORIZATION_REQUIRED"
    assert missing["receipt"]["decision"] == "DENY"
    assert missing["receipt"]["reason"] == "GRANT_REQUIRED"
    allowed = _request(tmp_path)
    _issue(store, allowed)
    good = precheck(store, allowed, now=NOW)
    upgraded = route(
        {"action_type": "internal_readonly", "grant_ref": good["grant_ref"]},
        upgrade=True,
        n9=good,
    )
    assert upgraded.status == "BLOCKED"
    assert upgraded.nodes == ()


def test_ttl_and_bad_signature_deny(tmp_path):
    store = _store(tmp_path)
    request = _request(tmp_path, grant_id="g-ttl")
    _issue(store, request, ttl_hours=9)
    ttl = precheck(store, request, now=NOW)
    assert ttl["receipt"]["decision"] == "DENY"
    assert ttl["receipt"]["validator"] == "time"
    assert ttl["receipt"]["reason"] == "GRANT_TTL_INVALID"
    signed = _request(tmp_path, grant_id="g-sig")
    _issue(store, signed)
    path = store.directory / "g-sig.json"
    forged = json.loads(path.read_text(encoding="utf-8"))
    forged["grant"]["grant_id"] = "g-forged"
    forged["mac"] = "0" * 64
    write_once(store.directory / "g-forged.json", forged)
    forged_request = _request(tmp_path, grant_id="g-forged")
    bad = precheck(store, forged_request, now=NOW)
    assert bad["receipt"]["reason"] == "GRANT_SIGNATURE_INVALID"


def test_presented_digest_mismatch_writes_deny_receipt(tmp_path):
    store = _store(tmp_path)
    request = _request(tmp_path)
    _issue(store, request)
    inputs = _inputs(request)
    inputs["request_digest"] = "ab" * 32
    envelope = run_n9(inputs, at=AT, store=store, request=request, now=NOW)
    assert envelope["output"]["verdict"] == "DENY"
    assert envelope["output"]["grant_ref"] is None
    assert set(envelope["output"]) == {"verdict", "reason", "grant_ref"}
    reason = envelope["output"]["reason"]
    assert request.actor in reason
    assert request.resource in reason
    assert request.intent_id in reason
    assert request.digest in reason
    assert inputs["request_digest"] in reason
    assert request.git_candidate_sha in reason
    files = list(store.receipts.glob("*.json"))
    assert len(files) == 1
    saved = json.loads(files[0].read_text(encoding="utf-8"))
    assert saved["decision"] == "DENY"


def test_sixty_four_hex_is_not_a_git_candidate(tmp_path):
    store = _store(tmp_path)
    request = _request(tmp_path)
    with pytest.raises(ValueError, match="40 lowercase hex"):
        store.issue_test_fixture(
            grant_id="g-legacy",
            subject=request.actor,
            resource=str(store.root),
            request_digest_hex=request.digest,
            git_candidate="a" * 64,
            tree=request.tree_sha,
            now=NOW,
        )
