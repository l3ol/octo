"""N11 trusted-original cases. Builder selftest only. Not a real PASS.

Spec sha256 c9341bf7b3c149655de865953d03f46c19377e4a796e606590ae590adfc9bebf.
Cases sha256 cf651b3610580247ae70367fa54d5f123647b79cde1f0905ba3ca4e228342ad3.
runtime_pass stays false. TEST_FIXTURE is not a reviewer original.
"""
import hashlib
import json
import os
from pathlib import Path

import pytest

from octo.closing import TA_REVIEWER_ID, _verified_original, run_n11
from octo.g3_review import product_scope_digest
from octo.scope_metadata import FORMAL_REVIEWER_ID, HISTORICAL_AGENT_ID
from octo.trusted_original import (
    ORIGINAL_AGENT_ID,
    ORIGINAL_REVIEWER_SESSION_ID,
    BindingTuple,
    Found,
    consume_trusted_original,
    fixture_set_digest,
    normalize_binding,
    runner_base_sha,
)

AT = "2026-11-01T12:00:00+00:00"
CANDIDATE = "a" * 40
BASE = "5443c9b4dde7fc208a0a72457c87904650829f77"
FIXTURE = "b" * 64
ROUTE = "internal_readonly"


def _tuple(**overrides) -> dict:
    raw = {
        "route": ROUTE,
        "scope_digest": product_scope_digest(),
        "base_sha": BASE,
        "candidate_sha": CANDIDATE,
        "fixture_digest": FIXTURE,
    }
    raw.update(overrides)
    return raw


def _record(root: Path, *, registration_id: str = "reg-1", raw: bytes = b"fixture-bytes", **overrides) -> dict:
    blob = root / "bytes" / registration_id
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(raw)
    binding = overrides.pop("binding_tuple", _tuple())
    record = {
        "registration_id": registration_id,
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_bytes_ref": f"bytes/{registration_id}",
        "source_evidence": {
            "transfer_receipt_id": "transfer-1",
            "issuer_agent_id": TA_REVIEWER_ID,
            "issuer_session_id": ORIGINAL_REVIEWER_SESSION_ID,
            "relay_proof": "control-plane-shape",
        },
        "issuer_id": TA_REVIEWER_ID,
        "issued_at": AT,
        "verdict": "PASS",
        "binding_tuple": binding,
        "content_kind": "TEST_FIXTURE",
        "test_only": True,
        "excluded_fixture_hashes_proof": {
            "fixture_set_digest": fixture_set_digest(set()),
            "checked": True,
        },
    }
    record.update(overrides)
    return record


def _seal(root: Path, records: list[dict]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "registry.json").write_text(
        json.dumps({"registry_class": "TEST_FIXTURE", "records": records}),
        encoding="utf-8",
    )
    for path in root.rglob("*"):
        if path.is_symlink() or path.is_dir():
            continue
        path.chmod(0o444)
    root.chmod(0o555)


def _unseal(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o755)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        path.chmod(0o755 if path.is_dir() else 0o644)


def _view(root: Path):
    from octo.trusted_original import open_registry
    opened = open_registry(root)
    assert not hasattr(opened, "reason")
    return opened


def test_empty_registry_is_blocked(tmp_path):
    root = tmp_path / "empty"
    _seal(root, [])
    try:
        envelope = run_n11(
            {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
            at=AT,
            registry_root=root,
        )
    finally:
        _unseal(root)
    note = envelope["output"]["evidence"][0]["note"]
    assert envelope["status"] == "BLOCKED"
    assert "EMPTY_REGISTRY" in note
    assert "no trusted reviewer registration" in note


def test_missing_or_writable_root_is_unavailable(tmp_path):
    missing = run_n11(
        {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
        at=AT,
        registry_root=None,
    )
    assert missing["status"] == "BLOCKED"
    assert missing["output"]["evidence"][0]["note"] == "ROOT_UNAVAILABLE"
    writable = tmp_path / "writable"
    writable.mkdir()
    envelope = run_n11(
        {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
        at=AT,
        registry_root=writable,
    )
    assert envelope["output"]["evidence"][0]["note"] == "ROOT_UNAVAILABLE"


def test_self_written_public_reviewer_file_is_not_trusted(tmp_path):
    forged = tmp_path / "self.json"
    forged.write_text(json.dumps({
        "issuer": TA_REVIEWER_ID,
        "verdict": "PASS",
        "candidate_sha": CANDIDATE,
    }), encoding="utf-8")
    envelope = run_n11(
        {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
        at=AT,
        independent_receipt={"path": str(forged), "issuer": TA_REVIEWER_ID, "verdict": "PASS", "candidate_sha": CANDIDATE},
    )
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"


def test_builder_signed_and_self_report_stay_blocked():
    signed = run_n11(
        {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
        at=AT,
        independent_receipt={"builder_signed": True, "candidate_sha": CANDIDATE},
    )
    assert signed["status"] == "BLOCKED"
    assert "BUILDER_PASS_FORBIDDEN" in signed["output"]["evidence"][0]["note"]
    report = run_n11(
        {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
        at=AT,
        independent_receipt={"signed_by": "candidate-self-report", "candidate_sha": CANDIDATE},
    )
    assert report["status"] == "BLOCKED"
    assert "candidate self-report" in report["output"]["evidence"][0]["note"]


def test_tuple_field_changes_are_stale(tmp_path):
    root = tmp_path / "tuple"
    binding = normalize_binding(_tuple())
    assert binding is not None
    _seal(root, [_record(root, binding_tuple=binding.as_dict())])
    try:
        view = _view(root)
        assert isinstance(consume_trusted_original(binding, view, set()), Found)
        changes = {
            "route": {"route": "other-route"},
            "scope_digest": {"scope_digest": "c" * 64},
            "base_sha": {"base_sha": "d" * 40},
            "candidate_sha": {"candidate_sha": "e" * 40},
            "fixture_digest": {"fixture_digest": "f" * 64},
        }
        for name, patch in changes.items():
            moved = normalize_binding(_tuple(**patch))
            result = consume_trusted_original(moved, view, set())
            assert getattr(result, "reason_code", "") == "TUPLE_MISMATCH", name
    finally:
        _unseal(root)


def test_short_sha_is_rejected_and_uppercase_matches(tmp_path):
    root = tmp_path / "case"
    upper = _tuple()
    upper["base_sha"] = BASE.upper()
    upper["fixture_digest"] = FIXTURE.upper()
    _seal(root, [_record(root, binding_tuple=upper)])
    try:
        view = _view(root)
        query = normalize_binding(_tuple())
        found = consume_trusted_original(query, view, set())
        assert isinstance(found, Found) and found.test_only is True
        short = _tuple(base_sha="ab")
        assert normalize_binding(short) is None
        rejected = consume_trusted_original(short, view, set())
        assert getattr(rejected, "reason_code", "") == "TUPLE_MISMATCH"
    finally:
        _unseal(root)


def test_test_fixture_is_found_but_not_a_real_pass(tmp_path):
    root = tmp_path / "fixture"
    binding = normalize_binding(_tuple())
    _seal(root, [_record(root, binding_tuple=binding.as_dict())])
    try:
        view = _view(root)
        found = consume_trusted_original(binding, view, set())
        assert isinstance(found, Found) and found.test_only is True
        verified = _verified_original(
            None, CANDIDATE, {}, binding=binding, registry_view=view, fixture_hashes=set(),
        )
        assert verified is not None
        envelope = run_n11(
            {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
            at=AT,
            registry_root=root,
            fixture_digest=FIXTURE,
        )
    finally:
        _unseal(root)
    assert envelope["status"] == "BLOCKED"
    assert envelope["output"]["verdict"] != "PASS"
    evidence = envelope["output"]["evidence"][0]
    assert evidence["note"] == "TEST_FIXTURE_ONLY"
    assert evidence["test_only"] is True
    assert evidence["runtime_pass"] is False


def test_zero_change_consume_does_not_edit_trust_source(tmp_path):
    closing = Path("octo/closing.py").read_bytes()
    module = Path("octo/trusted_original.py").read_bytes()
    before = hashlib.sha256(closing + module).hexdigest()
    root = tmp_path / "later"
    binding = normalize_binding(_tuple())
    _seal(root, [_record(root, raw=b"placed-later", binding_tuple=binding.as_dict())])
    try:
        found = consume_trusted_original(binding, _view(root), set())
    finally:
        _unseal(root)
    after = hashlib.sha256(Path("octo/closing.py").read_bytes() + Path("octo/trusted_original.py").read_bytes()).hexdigest()
    assert before == after
    assert isinstance(found, Found) and found.test_only is True


def test_fixture_loop_hash_mismatch_escape_evidence_and_ambiguous(tmp_path):
    root = tmp_path / "faults"
    raw = b"loop-bytes"
    digest_hex = hashlib.sha256(raw).hexdigest()
    hashes = {digest_hex}
    binding = normalize_binding(_tuple())
    looped = _record(root, raw=raw, binding_tuple=binding.as_dict())
    looped["excluded_fixture_hashes_proof"] = {
        "fixture_set_digest": fixture_set_digest(hashes),
        "checked": True,
    }
    _seal(root, [looped])
    try:
        view = _view(root)
        assert getattr(consume_trusted_original(binding, view, hashes), "reason_code", "") == "FIXTURE_LOOP"
    finally:
        _unseal(root)

    tampered = tmp_path / "tamper"
    row = _record(tampered, raw=b"original", binding_tuple=binding.as_dict())
    _unseal(tampered)
    (tampered / "bytes" / "reg-1").write_bytes(b"changed")
    _seal(tampered, [row])
    try:
        assert getattr(consume_trusted_original(binding, _view(tampered), set()), "reason_code", "") == "HASH_MISMATCH"
    finally:
        _unseal(tampered)

    escaped = tmp_path / "escape"
    bad = _record(escaped, binding_tuple=binding.as_dict())
    bad["raw_bytes_ref"] = "../outside"
    _seal(escaped, [bad])
    try:
        assert getattr(consume_trusted_original(binding, _view(escaped), set()), "reason_code", "") == "PATH_ESCAPE"
    finally:
        _unseal(escaped)

    outside = tmp_path / "outside-target"
    outside.write_bytes(b"secret")
    linked = tmp_path / "linked"
    row = _record(linked, registration_id="link", binding_tuple=binding.as_dict())
    link = linked / "bytes" / "link"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(outside)
    row["bytes_sha256"] = hashlib.sha256(b"secret").hexdigest()
    _seal(linked, [row])
    try:
        assert getattr(consume_trusted_original(binding, _view(linked), set()), "reason_code", "") == "PATH_ESCAPE"
    finally:
        _unseal(linked)

    unverified = tmp_path / "evidence"
    weak = _record(unverified, binding_tuple=binding.as_dict())
    weak["source_evidence"] = {"transfer_receipt_id": "t", "issuer_session_id": TA_REVIEWER_ID}
    _seal(unverified, [weak])
    try:
        assert getattr(consume_trusted_original(binding, _view(unverified), set()), "reason_code", "") == "EVIDENCE_UNVERIFIED"
    finally:
        _unseal(unverified)

    mismatched = tmp_path / "issuer"
    wrong = _record(mismatched, binding_tuple=binding.as_dict(), issuer_id="forged-not-a-ta-reviewer")
    wrong["source_evidence"]["issuer_session_id"] = "forged-not-a-ta-reviewer"
    _seal(mismatched, [wrong])
    try:
        assert getattr(consume_trusted_original(binding, _view(mismatched), set()), "reason_code", "") == "ISSUER_MISMATCH"
    finally:
        _unseal(mismatched)

    many = tmp_path / "many"
    first = _record(many, registration_id="one", binding_tuple=binding.as_dict())
    second = _record(many, registration_id="two", raw=b"other", binding_tuple=binding.as_dict())
    _seal(many, [first, second])
    try:
        assert getattr(consume_trusted_original(binding, _view(many), set()), "reason_code", "") == "AMBIGUOUS"
    finally:
        _unseal(many)


def test_agent_id_in_the_session_field_is_a_collision(tmp_path):
    root = tmp_path / "session"
    binding = normalize_binding(_tuple())
    stuffed = _record(root, binding_tuple=binding.as_dict())
    stuffed["source_evidence"]["issuer_session_id"] = TA_REVIEWER_ID
    _seal(root, [stuffed])
    try:
        result = consume_trusted_original(binding, _view(root), set())
    finally:
        _unseal(root)
    assert getattr(result, "reason_code", "") == "ISSUER_SESSION_COLLISION"


def test_wrong_session_and_wrong_issuer_stay_mismatches(tmp_path):
    binding = normalize_binding(_tuple())
    wrong_session = tmp_path / "wrong-session"
    row = _record(wrong_session, binding_tuple=binding.as_dict())
    row["source_evidence"]["issuer_session_id"] = "not-the-original-session"
    _seal(wrong_session, [row])
    try:
        assert getattr(consume_trusted_original(binding, _view(wrong_session), set()), "reason_code", "") == "ISSUER_MISMATCH"
    finally:
        _unseal(wrong_session)
    wrong_issuer = tmp_path / "wrong-issuer"
    other = _record(wrong_issuer, binding_tuple=binding.as_dict(), issuer_id="not-the-agent")
    _seal(wrong_issuer, [other])
    try:
        assert getattr(consume_trusted_original(binding, _view(wrong_issuer), set()), "reason_code", "") == "ISSUER_MISMATCH"
    finally:
        _unseal(wrong_issuer)


def test_symlinked_registry_index_is_not_read(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"records": [{
        "registration_id": "escaped",
        "issuer_id": TA_REVIEWER_ID,
        "verdict": "PASS",
    }]}), encoding="utf-8")
    root = tmp_path / "link-root"
    root.mkdir()
    (root / "registry.json").symlink_to(outside)
    root.chmod(0o555)
    try:
        from octo.trusted_original import open_registry
        opened = open_registry(root)
    finally:
        root.chmod(0o755)
    assert getattr(opened, "reason", "") == "PATH_ESCAPE"
    assert not hasattr(opened, "records") or "escaped" not in getattr(opened, "records", {})


def test_registry_index_is_confined_and_chmod_is_not_a_bind():
    import inspect
    from octo.trusted_original import _read_confined, open_registry, registry_index_review, ro_bind_assessment
    source = inspect.getsource(open_registry)
    assert "read_text" not in source
    assert registry_index_review(source) is None
    assert registry_index_review("document = index.read_text(encoding='utf-8')") == "REGISTRY_INDEX_UNCONFINED"
    assert ro_bind_assessment({"method": "chmod"}) == "RO_BIND_UNPROVEN"
    assert ro_bind_assessment({"method": "os.access"}) == "RO_BIND_UNPROVEN"
    proven = ro_bind_assessment({
        "method": "bwrap-ro-bind",
        "operations": [
            {"op": "open", "exception": "OSError", "errno": "EROFS"},
            {"op": "replace", "exception": "OSError", "errno": "EROFS"},
            {"op": "unlink", "exception": "OSError", "errno": "EPERM"},
            {"op": "rename", "exception": "OSError", "errno": "EACCES"},
        ],
    })
    assert proven == "RO_BIND_PROVEN"
    root = Path("/tmp")
    assert _read_confined(root, "/etc/passwd") == "PATH_ESCAPE"
    assert _read_confined(root, "../outside") == "PATH_ESCAPE"


def test_candidate_self_report_does_not_select_the_record(tmp_path):
    root = tmp_path / "by-tuple"
    binding = normalize_binding(_tuple())
    row = _record(root, binding_tuple=binding.as_dict())
    _seal(root, [row])
    try:
        envelope = run_n11(
            {"candidate_sha": CANDIDATE, "scope": {"route": "other-route"}},
            at=AT,
            registry_root=root,
            fixture_digest=FIXTURE,
            independent_receipt={
                "registration_id": "reg-1",
                "path": str(root / "bytes" / "reg-1"),
                "bytes_sha256": row["bytes_sha256"],
                "issuer": TA_REVIEWER_ID,
                "candidate_sha": CANDIDATE,
            },
        )
    finally:
        _unseal(root)
    assert envelope["status"] == "BLOCKED"
    assert "TUPLE_MISMATCH" in envelope["output"]["evidence"][0]["note"]
    assert envelope["output"]["evidence"][0]["note"] != "TEST_FIXTURE_ONLY"


def test_non_pass_review_receipt_stays_blocked_and_pass_is_only_ok_when_not_a_fixture(tmp_path):
    binding = normalize_binding(_tuple())
    failed = tmp_path / "fail"
    row = _record(failed, raw=b"not-pass", binding_tuple=binding.as_dict(), content_kind="REVIEW_RECEIPT", test_only=False, verdict="FAIL")
    _seal(failed, [row])
    try:
        envelope = run_n11(
            {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
            at=AT,
            registry_root=failed,
            fixture_digest=FIXTURE,
        )
    finally:
        _unseal(failed)
    assert envelope["status"] != "OK"
    assert envelope["output"]["verdict"] != "PASS"

    forged = tmp_path / "forged-review"
    passed = _record(
        forged,
        raw=b"shape-only-not-an-original",
        binding_tuple=binding.as_dict(),
        content_kind="REVIEW_RECEIPT",
        test_only=False,
        verdict="PASS",
    )
    _seal(forged, [passed])
    try:
        hit = run_n11(
            {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
            at=AT,
            registry_root=forged,
            fixture_digest=FIXTURE,
        )
    finally:
        _unseal(forged)
    assert hit["status"] == "SOURCE_UNAVAILABLE"
    assert hit["output"]["verdict"] != "PASS"
    assert hit["output"]["evidence"][0]["note"] == "SOURCE_UNAVAILABLE"
    assert hit["output"]["evidence"][0]["runtime_pass"] is False
    assert runner_base_sha() == BASE
    assert isinstance(binding, BindingTuple)


def _allowlist(path: Path, issuers: list[str], sources: list[str]) -> Path:
    path.write_text(json.dumps({
        "issuer_allowlist": issuers,
        "source_allowlist": sources,
    }), encoding="utf-8")
    return path


def _production(root: Path, records: list[dict]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "registry.json").write_text(json.dumps({"records": records}), encoding="utf-8")
    for path in root.rglob("*"):
        if path.is_symlink() or path.is_dir():
            continue
        path.chmod(0o444)
    root.chmod(0o555)


def _review_binding() -> dict:
    raw = _tuple()
    raw["task"] = "g2-s1"
    raw["rule_version"] = "t255"
    return raw


def test_allowlisted_review_stops_at_gap03_until_custody_matches(tmp_path):
    from octo.trusted_original import ALLOWLIST_RUN_LOG, DEFAULT_EXPECTED_ISSUER, load_allowlists
    binding = _review_binding()
    root = tmp_path / "review"
    raw = b"ta-chat-bytes"
    row = _record(
        root,
        raw=raw,
        binding_tuple=binding,
        content_kind="REVIEW_RECEIPT",
        test_only=False,
        verdict="PASS",
        issuer_id=DEFAULT_EXPECTED_ISSUER,
        receipt_id="rcpt-1",
    )
    row["source_evidence"]["issuer_agent_id"] = DEFAULT_EXPECTED_ISSUER
    row["source_evidence"]["issuer_session_id"] = ORIGINAL_REVIEWER_SESSION_ID
    allow = _allowlist(
        tmp_path / "allow.json",
        [DEFAULT_EXPECTED_ISSUER],
        [ORIGINAL_REVIEWER_SESSION_ID],
    )
    _production(root, [row])
    try:
        view = _view(root)
        waiting = consume_trusted_original(binding, view, set(), allowlist_path=allow)
        assert waiting.reason_code == "EVIDENCE_UNVERIFIED"
        assert waiting.detail == "GAP-03"
        assert "ISSUER_" not in waiting.reason_code
        _unseal(root)
        (root / "custody.json").write_text(json.dumps({
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "not_issuer": True,
        }), encoding="utf-8")
        row["custody_ref"] = "custody.json"
        (root / "registry.json").write_text(json.dumps({"records": [row]}), encoding="utf-8")
        _production(root, [row])
        _CONSUMED = __import__("octo.trusted_original", fromlist=["_CONSUMED_RECEIPTS"])._CONSUMED_RECEIPTS
        _CONSUMED.pop(str(root.resolve()), None)
        accepted = consume_trusted_original(binding, _view(root), set(), allowlist_path=allow)
        assert isinstance(accepted, Found)
        assert accepted.mechanism_accept is True
        assert accepted.test_only is False
        again = consume_trusted_original(binding, _view(root), set(), allowlist_path=allow)
        assert isinstance(again, Found)
        assert again.mechanism_accept is True
    finally:
        _unseal(root)
    logged = load_allowlists(allow)
    assert logged is not None
    assert logged[1] in {item["sha256"] for item in ALLOWLIST_RUN_LOG}


def test_allowlist_miss_public_id_and_tb_custody_are_not_issuers(tmp_path):
    from octo.trusted_original import DEFAULT_EXPECTED_ISSUER
    binding = _review_binding()
    root = tmp_path / "miss"
    row = _record(
        root,
        binding_tuple=binding,
        content_kind="REVIEW_RECEIPT",
        test_only=False,
        issuer_id=DEFAULT_EXPECTED_ISSUER,
        receipt_id="rcpt-miss",
    )
    row["source_evidence"]["issuer_agent_id"] = DEFAULT_EXPECTED_ISSUER
    row["source_evidence"]["issuer_session_id"] = ORIGINAL_REVIEWER_SESSION_ID
    allow = _allowlist(tmp_path / "old-only.json", [HISTORICAL_AGENT_ID], [ORIGINAL_REVIEWER_SESSION_ID])
    _production(root, [row])
    try:
        view = _view(root)
        missed = consume_trusted_original(binding, view, set(), allowlist_path=allow)
        assert missed.reason_code == "ISSUER_MISMATCH"
        absent = consume_trusted_original(binding, view, set(), allowlist_path=tmp_path / "missing-allow.json")
        assert absent.reason_code == "SOURCE_UNAVAILABLE"
    finally:
        _unseal(root)
    stuffed = tmp_path / "stuff"
    bad = _record(
        stuffed,
        binding_tuple=binding,
        content_kind="REVIEW_RECEIPT",
        test_only=False,
        issuer_id=DEFAULT_EXPECTED_ISSUER,
        receipt_id="rcpt-tb",
    )
    bad["source_evidence"]["issuer_agent_id"] = DEFAULT_EXPECTED_ISSUER
    bad["source_evidence"]["issuer_session_id"] = ORIGINAL_REVIEWER_SESSION_ID
    bad["issuer_id"] = "TB"
    bad["source_evidence"]["issuer_agent_id"] = "TB"
    _production(stuffed, [bad])
    both = _allowlist(tmp_path / "both.json", [DEFAULT_EXPECTED_ISSUER, "TB"], [ORIGINAL_REVIEWER_SESSION_ID])
    try:
        tb = consume_trusted_original(binding, _view(stuffed), set(), allowlist_path=both)
        assert tb.reason_code == "ISSUER_MISMATCH"
    finally:
        _unseal(stuffed)


def test_formal_reviewer_is_not_the_historical_agent(tmp_path):
    """MF-T281-01. The old agent id is not the runtime issuer, and a migration claim is not a signature."""
    root = Path(__file__).resolve().parents[1]
    source = (root / "octo" / "trusted_original.py").read_text(encoding="utf-8")
    closing = (root / "octo" / "closing.py").read_text(encoding="utf-8")
    assert HISTORICAL_AGENT_ID not in source
    assert HISTORICAL_AGENT_ID not in closing
    assert TA_REVIEWER_ID == ORIGINAL_AGENT_ID == FORMAL_REVIEWER_ID
    assert TA_REVIEWER_ID == "TA-CHAT-REVIEWER-OCTO-20261101-01"
    historical = run_n11(
        {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
        at=AT,
        independent_receipt={"issuer": HISTORICAL_AGENT_ID, "candidate_sha": CANDIDATE, "verdict": "PASS"},
    )
    assert historical["status"] == "BLOCKED"
    assert "forged issuer" in historical["output"]["evidence"][0]["note"]
    assert historical["output"]["verdict"] != "PASS"
    migrated = run_n11(
        {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
        at=AT,
        independent_receipt={
            "issuer": TA_REVIEWER_ID,
            "candidate_sha": CANDIDATE,
            "verdict": "PASS",
            "signature_migration_claimed": True,
            "migrated_from_agent": HISTORICAL_AGENT_ID,
            "signed_on_behalf_of": HISTORICAL_AGENT_ID,
        },
    )
    assert migrated["status"] == "BLOCKED"
    assert "SIGNATURE_MIGRATION_CLAIM" in migrated["output"]["evidence"][0]["note"]
    assert migrated["output"]["verdict"] != "PASS"
    current = run_n11(
        {"candidate_sha": CANDIDATE, "scope": {"route": ROUTE}},
        at=AT,
        independent_receipt={"issuer": TA_REVIEWER_ID, "candidate_sha": CANDIDATE, "verdict": "PASS"},
    )
    assert "forged issuer" not in current["output"]["evidence"][0]["note"]
    assert "SIGNATURE_MIGRATION_CLAIM" not in current["output"]["evidence"][0]["note"]
    assert current["output"]["verdict"] != "PASS"
    binding = normalize_binding(_tuple())
    root = tmp_path / "migrate"
    row = _record(root, binding_tuple=binding.as_dict())
    row["signature_migration_claimed"] = True
    _seal(root, [row])
    try:
        claimed = consume_trusted_original(binding, _view(root), set())
    finally:
        _unseal(root)
    assert getattr(claimed, "reason_code", "") == "SIGNATURE_MIGRATION_CLAIM"
    listed = tmp_path / "historical-issuer"
    old = _record(
        listed,
        binding_tuple=_review_binding(),
        content_kind="REVIEW_RECEIPT",
        test_only=False,
        issuer_id=HISTORICAL_AGENT_ID,
        receipt_id="rcpt-old",
    )
    old["source_evidence"]["issuer_agent_id"] = HISTORICAL_AGENT_ID
    old["source_evidence"]["issuer_session_id"] = ORIGINAL_REVIEWER_SESSION_ID
    allow = _allowlist(tmp_path / "historical-allow.json", [HISTORICAL_AGENT_ID, FORMAL_REVIEWER_ID], [ORIGINAL_REVIEWER_SESSION_ID])
    _production(listed, [old])
    try:
        refused = consume_trusted_original(_review_binding(), _view(listed), set(), allowlist_path=allow)
    finally:
        _unseal(listed)
    assert getattr(refused, "reason_code", "") == "ISSUER_MISMATCH"


def test_production_fixture_is_not_a_real_receipt(tmp_path):
    binding = normalize_binding(_tuple())
    root = tmp_path / "prod-fixture"
    row = _record(root, binding_tuple=binding.as_dict())
    _production(root, [row])
    try:
        result = consume_trusted_original(binding, _view(root), set())
        assert result.reason_code == "EVIDENCE_UNVERIFIED"
    finally:
        _unseal(root)
