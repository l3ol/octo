"""Builder selftests for the 43 landing scenes.

STACK_OK_BUILDER_EVIDENCE only. These runs are not independent acceptance.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

import pytest

from gates.activation.request import (
    check_separation,
    enable_path_b,
    reopen,
    signal_emergency_stop,
)
from gates.activation.state import ActivationState
from gates.atomic_merge.compare import compare_and_merge
from gates.binding.decide import decide as binding_decide
from gates.integrity.recovery import MISSING_MESSAGE, UNVERIFIED_MESSAGE, verify_recovery
from gates.isomorphism.seal import seal, verify
from gates.pipeline import evaluate_landing
from gates.policy.audit import record_rule_change
from gates.policy.decide import decide as policy_decide
from gates.policy.forbidden import evaluate_paths
from gates.policy.size import measure_tree
from gates.rules import FORBIDDEN_PATTERNS, RULE_DIGEST, RULE_VERSION, SIZE_LIMIT_BYTES
from gates.scope.decide import decide as scope_decide
from gates.tamper.loader import load_default_manifest, load_pin
from gates.types import result_digest
from tests.gates.support import (
    BASE,
    CANDIDATE,
    OTHER,
    PARENT,
    PIN,
    ROLLBACK,
    RULE_VERSION as _RULE_VERSION,
    TASK,
    TREE,
    MemoryObjectStore,
    activation_receipt,
    assert_machine_readable,
    commit_exists,
    pin_material,
    recovery_plan,
    registry,
    reviewer_receipt,
    valid_request,
)

assert _RULE_VERSION == RULE_VERSION


def land(req):
    result = evaluate_landing(req)
    assert_machine_readable(result)
    checks = result.evidence.get("checks") or {}
    for key, child in checks.items():
        if not isinstance(child, dict) or "result_digest" not in child:
            continue
        expect = result_digest(
            child["gate"],
            child["decision"],
            child["reason_code"],
            child["candidate_sha"],
            child["base_sha"],
            child["rule_version"],
            child["evidence"],
        )
        assert expect == child["result_digest"], key
    return result


def _ids(**kwargs):
    return dict(
        candidate_sha=CANDIDATE,
        base_sha=BASE,
        task_id=TASK,
        rule_version=RULE_VERSION,
        rule_digest=RULE_DIGEST,
        **kwargs,
    )


def test_scene_01_missing_task_id():
    req = valid_request(task_id=None)
    result = land(req)
    assert result.reason_code == "SCOPE_MISSING_TASK_ID"
    assert result.evidence["details"]["merged"] is False
    assert result.evidence["details"]["intercept_record"]["reason_code"] == "SCOPE_MISSING_TASK_ID"
    assert req.ledger.merges == []


def test_scene_02_secret_trips_kill_line():
    req = valid_request(
        changed_paths=["src/config.py"],
        blobs=[("src/config.py", b'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n')],
    )
    result = land(req)
    assert result.reason_code == "POLICY_SECRET_PATTERN"
    event = result.evidence["details"]["kill_line_event"]
    assert event["reason_code"] == "ACTIVATION_KILL_LINE"
    assert event["category"] == "secret"
    assert event["escalated_to"] == "founder"
    assert req.activation_state.kill_line_tripped is True
    assert req.activation_state.path_b_enabled is False
    follow = valid_request(activation_state=req.activation_state)
    follow.receipt = reviewer_receipt(candidate=follow.candidate_sha, base=follow.base_sha, receipt_id="rcpt-after-kill")
    assert land(follow).reason_code == "ACTIVATION_KILL_LINE"


def test_scene_03_candidate_drift():
    req = valid_request(lineage=[PARENT], receipt=reviewer_receipt(candidate=PARENT))
    assert land(req).reason_code == "VERIFICATION_CANDIDATE_DRIFT"


def test_scene_04_base_stale():
    req = valid_request()
    old_base = req.base_sha
    req.base_sha = OTHER
    req.current_head_sha = OTHER
    req.receipt = reviewer_receipt(candidate=req.candidate_sha, base=old_base)
    req.recovery_plan = recovery_plan(candidate=req.candidate_sha, base=OTHER)
    result = land(req)
    assert result.reason_code == "VERIFICATION_BASE_STALE"
    assert result.evidence["details"]["head_observation"]["reason_code"] != "ATOMIC_MERGE_HEAD_MISMATCH"


def test_scene_05_downstream_side_effect():
    req = valid_request(target_branch_config={"webhooks": [{"url": "https://example.invalid/hook"}]})
    result = land(req)
    assert result.reason_code == "POLICY_DOWNSTREAM_SIDE_EFFECT"
    details = result.evidence["checks"]["policy"]["evidence"]["details"]
    assert details["path_b_fail_closed"] is True


def test_scene_06_positive_and_reverse_without_pass():
    req = valid_request()
    result = land(req)
    assert result.decision == "PASS"
    assert result.reason_code is None
    assert result.evidence["details"]["merged"] is True
    assert req.publisher.read_ref() == req.candidate_sha
    assert result.evidence["checks"]["scope"]["decision"] == "PASS"
    assert result.evidence["checks"]["verification"]["decision"] == "PASS"
    assert result.evidence["checks"]["binding"]["decision"] == "PASS"
    assert result.evidence["checks"]["recovery"]["decision"] == "PASS"
    entry = req.board.read_all()[-1]
    assert entry["receipt_id"] == req.receipt["receipt_id"]
    for gate in ("scope", "verification", "policy"):
        assert entry["gate_records"][gate]["decision"] == "PASS"
        assert entry["gate_records"][gate]["timestamp"].endswith("+08:00")
    assert len(req.ledger.merges) == 1

    reverse = valid_request(receipt=None)
    assert land(reverse).reason_code == "VERIFICATION_NO_PASS"


def test_scene_07_emergency_stop_freezes_later_packages():
    state = ActivationState(path_b_enabled=True, environment="isolated")
    signal = signal_emergency_stop(state, actor="founder", **_ids())
    assert signal.reason_code == "ACTIVATION_EMERGENCY_STOP"
    first = land(valid_request(activation_state=state))
    second_req = valid_request(activation_state=state)
    second_req.receipt = reviewer_receipt(candidate=second_req.candidate_sha, base=second_req.base_sha, receipt_id="rcpt-2")
    second = land(second_req)
    assert first.reason_code == "ACTIVATION_EMERGENCY_STOP"
    assert second.reason_code == "ACTIVATION_EMERGENCY_STOP"
    assert first.evidence["details"]["merged"] is False


def test_scene_08_fault_self_close_and_incomplete_reopen(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("injected fault:policy")

    monkeypatch.setattr("gates.pipeline.policy_decide", boom)
    req = valid_request()
    result = land(req)
    assert result.reason_code == "GATE_INTERNAL_ERROR"
    assert result.evidence["details"]["path_b_self_closed"] is True
    assert req.activation_state.self_closed is True
    assert req.activation_state.path_b_enabled is False

    signed, digest = activation_receipt()
    denied = reopen(
        req.activation_state,
        actor="intruder",
        root_cause_eliminated=True,
        gates_reverified=True,
        evidence_bound_to_new_gate_version=True,
        founder_written_approval=True,
        activation_receipt=signed,
        gate_version=RULE_VERSION,
        evidence_digest=digest,
        **_ids(),
    )
    assert denied.reason_code == "ACTIVATION_NON_FOUNDER"
    assert req.activation_state.path_b_enabled is False

    full = dict(
        root_cause_eliminated=True,
        gates_reverified=True,
        evidence_bound_to_new_gate_version=True,
        founder_written_approval=True,
    )
    for key in list(full):
        state = ActivationState(path_b_enabled=False, environment="isolated", self_closed=True)
        kwargs = dict(full)
        kwargs[key] = False
        rejected = reopen(
            state,
            actor="founder",
            activation_receipt=signed,
            gate_version=RULE_VERSION,
            evidence_digest=digest,
            **kwargs,
            **_ids(),
        )
        assert rejected.reason_code == "ACTIVATION_REOPEN_INCOMPLETE"
        assert key in rejected.evidence["details"]["missing"]
        assert state.path_b_enabled is False


@pytest.mark.parametrize("task_id", ["no-such-task", "GATES-CLOSED-EXAMPLE"])
def test_scene_09_unknown_or_closed_task(task_id):
    tasks = {
        TASK: {"status": "active", "allowed_paths": ["src/**"]},
        "GATES-CLOSED-EXAMPLE": {"status": "closed", "allowed_paths": ["src/**"]},
    }
    req = valid_request(task_id=task_id, registry=registry(tasks=tasks), receipt=reviewer_receipt(task=task_id))
    assert land(req).reason_code == "SCOPE_UNKNOWN_OR_CLOSED_TASK"


def test_scene_10_path_outside_task_range():
    req = valid_request(
        changed_paths=["ops/outside.py"],
        blobs=[("ops/outside.py", b"x\n")],
        registry=registry(["src/**"]),
    )
    assert land(req).reason_code == "SCOPE_OUT_OF_RANGE"


@pytest.mark.parametrize(
    "content",
    [b"notes\nOCTO-BRAIN-RAW-v1\n", b"notes\nOCTO-BACKUP-RAW-v1\n"],
)
def test_scene_11_brain_or_backup_content(content):
    req = valid_request(changed_paths=["docs/notes.md"], blobs=[("docs/notes.md", content)])
    assert land(req).reason_code == "POLICY_BRAIN_OR_BACKUP"


def test_scene_12_size_threshold_boundary():
    small = measure_tree([("a.txt", b"hi")])
    again = measure_tree([("a.txt", b"hi")])
    assert small == again
    assert small["rejected"] is False
    assert small["threshold"] == 10485760 == SIZE_LIMIT_BYTES

    over = b"\0" * (SIZE_LIMIT_BYTES + 1)
    exact = b"\0" * SIZE_LIMIT_BYTES
    over_measured = measure_tree([("payload.bin", over)])
    exact_measured = measure_tree([("payload.bin", exact)])
    assert over_measured["total_bytes"] == 10485761
    assert over_measured["rejected"] is True
    assert over_measured["comparison"] == "gt"
    assert exact_measured["total_bytes"] == 10485760
    assert exact_measured["rejected"] is False
    assert exact_measured["comparison"] == "eq"
    assert measure_tree([("payload.bin", exact)])["blobs"] == exact_measured["blobs"]

    rejected = land(
        valid_request(changed_paths=["payload.bin"], blobs=[("payload.bin", over)])
    )
    assert rejected.reason_code == "POLICY_SIZE_EXCEEDED"
    size_details = rejected.evidence["checks"]["policy"]["evidence"]["details"]["size"]
    assert size_details["total_bytes"] == 10485761
    assert size_details["threshold"] == 10485760
    assert size_details["candidate_tree_sha"]

    allowed = land(
        valid_request(changed_paths=["payload.bin"], blobs=[("payload.bin", exact)])
    )
    assert allowed.decision == "PASS"
    assert allowed.reason_code is None


def test_scene_13_forbidden_paths_and_manifest_exception():
    wallet = land(
        valid_request(
            changed_paths=["tools/wallet/readme.txt"],
            blobs=[("tools/wallet/readme.txt", b"readme\n")],
        )
    )
    assert wallet.reason_code == "POLICY_FORBIDDEN_PATH"
    agent = land(
        valid_request(
            changed_paths=["x/agent-data/a.txt"],
            blobs=[("x/agent-data/a.txt", b"a\n")],
        )
    )
    assert agent.reason_code == "POLICY_FORBIDDEN_PATH"

    allowed = land(
        valid_request(
            changed_paths=["release/secret-manifest.json"],
            blobs=[("release/secret-manifest.json", b"notes\n")],
        )
    )
    assert allowed.decision == "PASS"
    details = allowed.evidence["checks"]["policy"]["evidence"]["details"]
    assert details["exception_applied"] is True
    assert details["matched_pattern"] == "**/*secret*"
    assert details["normalized_path"] == "release/secret-manifest.json"

    secret_inside = land(
        valid_request(
            changed_paths=["release/secret-manifest.json"],
            blobs=[("release/secret-manifest.json", b'key = "AKIAIOSFODNN7EXAMPLE"\n')],
        )
    )
    assert secret_inside.reason_code == "POLICY_SECRET_PATTERN"
    rows = secret_inside.evidence["checks"]["policy"]["evidence"]["details"]["p4"]
    matched = [row for row in rows if row["normalized_path"] == "release/secret-manifest.json"]
    assert matched[0]["exception_applied"] is True
    assert matched[0]["matched_pattern"] == "**/*secret*"


def test_p4_normalization_and_case():
    traversal = evaluate_paths(["../etc/passwd"], FORBIDDEN_PATTERNS, RULE_DIGEST)
    assert traversal["reason_code"] == "POLICY_FORBIDDEN_PATH"
    assert traversal["paths"][0]["normalization_error"] == "traversal"
    absolute = evaluate_paths(["/etc/passwd"], FORBIDDEN_PATTERNS, RULE_DIGEST)
    assert absolute["paths"][0]["normalization_error"] == "absolute"
    backslash = evaluate_paths(["foo\\bar"], FORBIDDEN_PATTERNS, RULE_DIGEST)
    assert backslash["paths"][0]["normalization_error"] == "backslash"
    empty = evaluate_paths(["foo//bar"], FORBIDDEN_PATTERNS, RULE_DIGEST)
    assert empty["paths"][0]["normalization_error"] == "empty_segment"
    dotted = evaluate_paths(["./.env"], FORBIDDEN_PATTERNS, RULE_DIGEST)
    assert dotted["reason_code"] == "POLICY_FORBIDDEN_PATH"
    assert dotted["paths"][0]["normalized_path"] == ".env"
    assert not any(
        row["matched_pattern"]
        for row in evaluate_paths(["Brain/a.txt"], ("**/brain/**",), RULE_DIGEST)["paths"]
    )
    upper = evaluate_paths(["release/secret-Manifest.json"], FORBIDDEN_PATTERNS, RULE_DIGEST)
    assert upper["reason_code"] == "POLICY_FORBIDDEN_PATH"
    sha = evaluate_paths(["release/secret-manifest.sha256"], FORBIDDEN_PATTERNS, RULE_DIGEST)
    assert sha["decision"] == "PASS"
    assert sha["paths"][0]["exception_applied"] is True


def test_scene_14_irreversible_requires_human():
    assert land(valid_request(irreversible=True)).reason_code == "ACTIVATION_IRREVERSIBLE_REQUIRES_HUMAN"


def test_scene_15_untrusted_issuer_and_tampered_receipt():
    forged = reviewer_receipt(issuer="mallory", secret=b"mallory-secret")
    untrusted = land(valid_request(receipt=forged, trusted_issuers={"reviewer-bot": b"reviewer-test-secret"}))
    assert untrusted.reason_code == "VERIFICATION_UNTRUSTED_ISSUER"

    signed = reviewer_receipt()
    signed["signature"] = signed["signature"][:-1] + ("0" if signed["signature"][-1] != "0" else "1")
    tampered = land(valid_request(receipt=signed))
    assert tampered.reason_code == "VERIFICATION_RECEIPT_TAMPERED"


def test_scene_16_replay_other_task():
    assert land(valid_request(receipt=reviewer_receipt(task="OTHER-TASK"))).reason_code == "VERIFICATION_REPLAY_BINDING"


def test_scene_17_gate_tamper_downgrade_and_audit():
    wide = registry(["**"])
    touched = land(
        valid_request(
            registry=wide,
            changed_paths=["gates/verification/decide.py"],
            blobs=[("src/app.py", b"print('ok')\n"), ("gates/verification/decide.py", b"x\n")],
        )
    )
    assert touched.reason_code == "TAMPER_GATES_PATH_TOUCHED"
    assert touched.evidence["checks"]["tamper_path"]["evidence"]["details"]["attack_record"]["detected"] is True
    assert touched.evidence["checks"]["tamper_path"]["evidence"]["details"]["candidate_code_used"] is False

    removed = [pattern for pattern in FORBIDDEN_PATTERNS if pattern != "**/wallet/**"]
    downgrade = land(
        valid_request(
            registry=wide,
            changed_paths=["gates/policy/ruleset.json"],
            blobs=[("src/app.py", b"print('ok')\n"), ("gates/policy/ruleset.json", b"{}\n")],
            candidate_rules={"forbidden_patterns": removed},
        )
    )
    assert downgrade.reason_code == "POLICY_RULE_DOWNGRADE"
    assert downgrade.evidence["checks"]["tamper_path"]["reason_code"] == "TAMPER_GATES_PATH_TOUCHED"

    injected = land(
        valid_request(
            registry=wide,
            changed_paths=["gates/task_registry/injected.json"],
            blobs=[("src/app.py", b"print('ok')\n"), ("gates/task_registry/injected.json", b"{}\n")],
        )
    )
    assert injected.reason_code == "TAMPER_GATES_PATH_TOUCHED"

    still = land(
        valid_request(
            changed_paths=["tools/wallet/readme.txt"],
            blobs=[("tools/wallet/readme.txt", b"readme\n")],
            candidate_rules={"forbidden_patterns": removed, "size_limit_bytes": SIZE_LIMIT_BYTES * 2},
        )
    )
    assert still.reason_code == "POLICY_FORBIDDEN_PATH"

    audit = valid_request().audit_log
    record_rule_change(
        audit,
        actor="maintainer",
        before_digest=RULE_DIGEST,
        after_digest=RULE_DIGEST,
        rule_version_before=RULE_VERSION,
        rule_version_after=RULE_VERSION,
    )
    from gates.policy.size import measure_tree as measure

    blobs = [("src/app.py", b"print('ok')\n")]
    tree = measure(blobs)["tree_sha"]
    for _ in range(3):
        policy_decide(
            tree,
            CANDIDATE,
            BASE,
            {},
            blobs=blobs,
            changed_paths=["src/app.py"],
            task_id=TASK,
            audit=audit,
            rule_version=RULE_VERSION,
        )
    assert len(audit.decisions) >= 3
    for row in audit.decisions[:3]:
        assert {"matched_rules", "package_sha", "timestamp", "decision", "rule_version", "rule_digest"} <= set(row)
        assert row["timestamp"].endswith("+08:00")
    change = audit.changes[0]
    assert change["actor"] == "maintainer"
    assert change["before_digest"] == RULE_DIGEST
    assert change["after_digest"] == RULE_DIGEST


def test_scene_18_head_moved_before_merge():
    req = valid_request()
    before = req.publisher.read_ref()
    racer = req.publisher.make_other_commit()
    assert req.publisher.read_ref() == before

    def _advance():
        req.publisher.force_ref(racer)

    req.publisher.before_update = _advance
    moved = land(req)
    assert moved.reason_code == "ATOMIC_MERGE_HEAD_MISMATCH"
    assert moved.evidence["details"]["merged"] is False
    assert moved.evidence["checks"]["binding"]["decision"] == "PASS"
    merge_details = moved.evidence["checks"]["atomic_merge"]["evidence"]["details"]
    assert merge_details["landing_ref_after"] == racer
    assert merge_details["merged"] is False
    assert req.publisher.read_ref() == racer
    assert req.ledger.is_consumed(req.receipt["receipt_id"]) is False

    parked = valid_request(merge_candidate_sha="9" * 40)
    ref_before = parked.publisher.read_ref()
    swapped = land(parked)
    assert swapped.reason_code == "ATOMIC_MERGE_HEAD_MISMATCH"
    assert "candidate" in swapped.evidence["checks"]["atomic_merge"]["evidence"]["details"]["mismatch_fields"]
    assert parked.publisher.read_ref() == ref_before
    assert swapped.evidence["details"]["merged"] is False


def test_scene_19_already_consumed_is_the_only_failure():
    req = valid_request()
    req.ledger.mark_consumed(req.receipt["receipt_id"], {"source": "preexisting"})
    result = land(req)
    assert result.reason_code == "VERIFICATION_RECEIPT_ALREADY_CONSUMED"
    checks = {item["name"]: item for item in result.evidence["checks"]["verification"]["evidence"]["checks"]}
    assert checks["receipt_unconsumed"]["reason_code"] == "VERIFICATION_RECEIPT_ALREADY_CONSUMED"
    for name in (
        "pass_present",
        "trusted_issuer",
        "integrity",
        "task_binding",
        "rule_binding",
        "candidate_binding",
        "base_binding",
    ):
        assert checks[name]["decision"] == "PASS", name
    assert result.evidence["details"]["head_observation"]["decision"] == "PASS"
    assert result.evidence["details"]["merged"] is False
    assert result.reason_code not in {"VERIFICATION_BASE_STALE", "ATOMIC_MERGE_HEAD_MISMATCH", "VERIFICATION_RECEIPT_CONFLICT"}


def test_scene_20_concurrent_receipt_one_winner():
    from tests.gates.test_real_evidence import assert_scene_20_real_race

    assert_scene_20_real_race()


def test_scene_21_sha_mismatch_substitution():
    assert land(valid_request(receipt=reviewer_receipt(candidate=OTHER))).reason_code == "VERIFICATION_SHA_MISMATCH"


def test_scene_22_binding_inconsistent():
    left = scope_decide(TASK, CANDIDATE, BASE, ["src/app.py"], registry(), rule_version=RULE_VERSION, rule_digest=RULE_DIGEST)
    right = scope_decide(TASK, OTHER, BASE, ["src/app.py"], registry(), rule_version=RULE_VERSION, rule_digest=RULE_DIGEST)
    middle = scope_decide(TASK, CANDIDATE, BASE, ["src/app.py"], registry(), rule_version=RULE_VERSION, rule_digest=RULE_DIGEST)
    result = binding_decide([left, middle, right])
    assert_machine_readable(result)
    assert result.reason_code == "BINDING_INCONSISTENT"
    assert "candidate_sha" in result.evidence["details"]["mismatched_fields"]


def _seal_ids():
    return dict(candidate_sha=CANDIDATE, base_sha=BASE, task_id=TASK, rule_version=RULE_VERSION, rule_digest=RULE_DIGEST)


def test_scene_23_30_31_32_isomorphism():
    secret = b"seal-test-secret"
    artifact = hashlib.sha256(b"artifact").hexdigest()
    config = hashlib.sha256(b"config").hexdigest()
    sealed = seal(artifact, config, secret=secret, sealed_at="2026-11-01T12:00:00+08:00")
    mismatch = verify(hashlib.sha256(b"other-artifact").hexdigest(), config, sealed, secret=secret, **_seal_ids())
    assert mismatch.reason_code == "ISOMORPHISM_DIGEST_MISMATCH"
    assert mismatch.evidence["details"]["field"] == "artifact_digest"
    config_mismatch = verify(artifact, hashlib.sha256(b"other-config").hexdigest(), sealed, secret=secret, **_seal_ids())
    assert config_mismatch.reason_code == "ISOMORPHISM_DIGEST_MISMATCH"
    assert config_mismatch.evidence["details"]["field"] == "config_digest"
    tampered = dict(sealed)
    tampered["artifact_digest"] = hashlib.sha256(b"forged").hexdigest()
    detected = verify(tampered["artifact_digest"], config, tampered, secret=secret, **_seal_ids())
    assert detected.reason_code == "ISOMORPHISM_SEAL_TAMPERED"
    assert detected.evidence["details"]["tamper_record"]["detected"] is True
    matched = verify(artifact, config, sealed, secret=secret, **_seal_ids())
    assert matched.decision == "PASS"
    assert matched.reason_code is None


def test_scene_24_path_b_disabled_by_default_and_on_production():
    state = ActivationState()
    assert state.path_b_enabled is False
    result = land(valid_request(activation_state=state))
    assert result.reason_code == "ACTIVATION_PATH_B_DISABLED"
    assert result.evidence["details"]["message"] == "Path B disabled"
    assert "+08:00" in result.evidence["timestamp"]
    assert result.evidence["details"]["merged"] is False

    production = ActivationState(environment="production", path_b_enabled=True)
    blocked = land(valid_request(activation_state=production))
    assert blocked.reason_code == "ACTIVATION_PATH_B_DISABLED"
    assert blocked.evidence["details"]["merged"] is False


def test_scene_25_builder_acceptance_separation():
    separated = check_separation(ActivationState(), **_ids())
    assert separated.decision == "PASS"
    assert separated.reason_code is None
    assert separated.evidence["details"]["separation_ok"] is True
    assert separated.evidence["details"]["program_result"] == "PASS"
    overlap = ActivationState(
        builder_ids=frozenset({"same-bot"}),
        acceptance_ids=frozenset({"same-bot"}),
    )
    collapsed = check_separation(overlap, **_ids())
    assert collapsed.decision == "REJECT"
    assert collapsed.evidence["details"]["separation_ok"] is False
    shared = ActivationState(shared_write_principals=frozenset({"shared-writer"}))
    assert check_separation(shared, **_ids()).decision == "REJECT"


def test_scene_26_pin_fail_closed_and_path_filter():
    from gates import GATES_PIN_SHA

    assert GATES_PIN_SHA == "UNSET_FAIL_CLOSED"
    manifest, store = pin_material()
    store.add("ab" * 20, object_type="commit", tree_sha=TREE, artifact_digest=manifest["artifact_digest"], config_digest=manifest["config_digest"])
    default = load_default_manifest()
    unset = load_pin(
        default,
        object_store=store,
        candidate_claimed_pin=PIN,
        head_sha=PIN,
        tags={"v6": PIN},
        candidate_sha=CANDIDATE,
        base_sha=BASE,
        task_id=TASK,
    )
    assert unset.ok is False
    assert unset.result.reason_code == "TAMPER_PIN_UNSET_OR_INVALID"
    assert unset.result.evidence["details"]["fallback_used"] is False
    assert unset.result.evidence["details"]["pin_value_class"] == "unset"
    assert store.lookups == []

    cases = []
    bad_format = dict(manifest)
    bad_format["gates_pin_sha"] = "A" * 40
    cases.append(bad_format)
    short = dict(manifest)
    short["gates_pin_sha"] = "abcd"
    cases.append(short)
    missing = dict(manifest)
    missing["gates_pin_sha"] = "9" * 40
    cases.append(missing)
    for item in cases:
        loaded = load_pin(item, object_store=store, head_sha=PIN, candidate_claimed_pin=PIN, candidate_sha=CANDIDATE, base_sha=BASE)
        assert loaded.ok is False
        assert loaded.result.reason_code == "TAMPER_PIN_UNSET_OR_INVALID"
        assert loaded.result.evidence["details"]["fallback_used"] is False
    assert PIN not in store.lookups

    blob_store = MemoryObjectStore()
    blob_store.add(PIN, object_type="blob", tree_sha=TREE, artifact_digest=manifest["artifact_digest"], config_digest=manifest["config_digest"])
    not_commit = load_pin(manifest, object_store=blob_store, head_sha="1" * 40, candidate_sha=CANDIDATE, base_sha=BASE)
    assert not_commit.result.evidence["details"]["pin_value_class"] == "not_commit"
    assert blob_store.lookups == [PIN]

    for field, value in (
        ("gate_tree_sha", "2" * 40),
        ("artifact_digest", "3" * 64),
        ("config_digest", "4" * 64),
    ):
        broken = dict(manifest)
        broken[field] = value
        loaded = load_pin(broken, object_store=store, head_sha=PIN, candidate_claimed_pin=PIN, candidate_sha=CANDIDATE, base_sha=BASE)
        assert loaded.result.reason_code == "TAMPER_PIN_UNSET_OR_INVALID"
        assert loaded.result.evidence["details"]["pin_value_class"] == "digest_mismatch"

    pipeline = land(valid_request(external_manifest=default, candidate_claimed_pin=PIN, head_sha=PIN, tags={"v6": PIN}))
    assert pipeline.reason_code == "TAMPER_PIN_UNSET_OR_INVALID"
    assert pipeline.evidence["details"]["other_gates"] == "not_executed"
    assert pipeline.evidence["details"]["fallback_used"] is False

    touched = land(
        valid_request(
            registry=registry(["**"]),
            changed_paths=["gates/loader/default_manifest.json"],
            blobs=[("src/app.py", b"print('ok')\n"), ("gates/loader/default_manifest.json", b"{}\n")],
        )
    )
    assert touched.reason_code == "TAMPER_GATES_PATH_TOUCHED"
    assert touched.evidence["details"]["evidence_class"] == "STACK_OK_BUILDER_EVIDENCE"


def test_scene_27_compare_and_merge_bypass_rejected():
    edited = land(
        valid_request(
            registry=registry(["**"]),
            changed_paths=["gates/atomic_merge/compare.py"],
            blobs=[("src/app.py", b"print('ok')\n"), ("gates/atomic_merge/compare.py", b"return PASS\n")],
        )
    )
    assert edited.reason_code == "TAMPER_GATES_PATH_TOUCHED"
    assert edited.evidence["checks"]["tamper_path"]["evidence"]["details"]["bypass_attempt"] is True
    hook = land(
        valid_request(
            registry=registry(["**"]),
            changed_paths=[".git/hooks/pre-receive"],
            blobs=[("src/app.py", b"print('ok')\n"), (".git/hooks/pre-receive", b"#!/bin/sh\n")],
        )
    )
    assert hook.reason_code == "TAMPER_GATES_PATH_TOUCHED"
    assert hook.evidence["checks"]["tamper_path"]["evidence"]["details"]["runtime_unaffected"] is True


def test_scene_28_recovery_missing():
    result = land(valid_request(recovery_plan=None))
    assert result.reason_code == "INTEGRITY_RECOVERY_MISSING"
    assert result.evidence["details"]["message"] == MISSING_MESSAGE


def test_scene_29_board_invisible():
    req = valid_request()
    req.board.visible = False
    result = land(req)
    assert result.reason_code == "INTEGRITY_BOARD_INVISIBLE"
    assert req.ledger.merges == []
    assert req.board.read_all() == []


def test_scene_33_reopen_when_four_conditions_hold():
    state = ActivationState(path_b_enabled=False, environment="isolated", self_closed=True)
    signed, digest = activation_receipt()
    result = reopen(
        state,
        actor="founder",
        root_cause_eliminated=True,
        gates_reverified=True,
        evidence_bound_to_new_gate_version=True,
        founder_written_approval=True,
        activation_receipt=signed,
        gate_version=RULE_VERSION,
        evidence_digest=digest,
        **_ids(),
    )
    assert result.decision == "PASS"
    assert state.path_b_enabled is True
    assert state.self_closed is False
    production = ActivationState(environment="production", self_closed=True)
    blocked = reopen(
        production,
        actor="founder",
        root_cause_eliminated=True,
        gates_reverified=True,
        evidence_bound_to_new_gate_version=True,
        founder_written_approval=True,
        activation_receipt=signed,
        gate_version=RULE_VERSION,
        evidence_digest=digest,
        **_ids(),
    )
    assert blocked.reason_code == "ACTIVATION_PATH_B_DISABLED"
    assert production.path_b_enabled is False


def test_scene_34_and_35_recovery_verification():
    req = valid_request()
    missing_commit = verify_recovery(
        {"rollback_commit": "f" * 40, "bound_candidate_sha": req.candidate_sha, "bound_base_sha": req.base_sha, "drill_passed": True},
        req.candidate_sha,
        req.base_sha,
        repo=req.recovery_repo,
        board=req.board,
        rule_version=RULE_VERSION,
        task_id=TASK,
        rule_digest=RULE_DIGEST,
    )
    assert missing_commit.reason_code == "INTEGRITY_RECOVERY_UNVERIFIED"
    assert missing_commit.evidence["details"]["message"] == UNVERIFIED_MESSAGE
    hand_filled = verify_recovery(
        {
            "rollback_commit": req.recovery_plan["rollback_commit"],
            "bound_candidate_sha": req.candidate_sha,
            "bound_base_sha": req.base_sha,
            "drill_passed": True,
        },
        req.candidate_sha,
        req.base_sha,
        repo=req.recovery_repo,
        board=req.board,
        rule_version=RULE_VERSION,
        task_id=TASK,
        rule_digest=RULE_DIGEST,
    )
    assert hand_filled.reason_code == "INTEGRITY_RECOVERY_UNVERIFIED"
    failed = json.loads(Path(req.recovery_plan["drill_receipt_path"]).read_text(encoding="utf-8"))
    failed["result"] = "FAIL"
    failed_path = Path(req.recovery_plan["drill_receipt_path"]).with_name("drill-fail.json")
    failed_path.write_text(json.dumps(failed), encoding="utf-8")
    failed_plan = dict(req.recovery_plan)
    failed_plan["drill_receipt_path"] = str(failed_path)
    failed_plan["drill_receipt"] = failed
    failed_drill = verify_recovery(
        failed_plan,
        req.candidate_sha,
        req.base_sha,
        repo=req.recovery_repo,
        board=req.board,
        rule_version=RULE_VERSION,
        task_id=TASK,
        rule_digest=RULE_DIGEST,
    )
    assert failed_drill.reason_code == "INTEGRITY_RECOVERY_UNVERIFIED"
    unbound = dict(req.recovery_plan)
    unbound["bound_candidate_sha"] = OTHER
    assert verify_recovery(
        unbound,
        req.candidate_sha,
        req.base_sha,
        repo=req.recovery_repo,
        board=req.board,
        rule_version=RULE_VERSION,
        task_id=TASK,
        rule_digest=RULE_DIGEST,
    ).reason_code == "INTEGRITY_RECOVERY_UNVERIFIED"
    no_board = dict(req.recovery_plan)
    no_board["drill_board_entry_id"] = "missing-entry"
    assert verify_recovery(
        no_board,
        req.candidate_sha,
        req.base_sha,
        repo=req.recovery_repo,
        board=req.board,
        rule_version=RULE_VERSION,
        task_id=TASK,
        rule_digest=RULE_DIGEST,
    ).reason_code == "INTEGRITY_RECOVERY_UNVERIFIED"
    passed = verify_recovery(
        req.recovery_plan,
        req.candidate_sha,
        req.base_sha,
        repo=req.recovery_repo,
        board=req.board,
        rule_version=RULE_VERSION,
        task_id=TASK,
        rule_digest=RULE_DIGEST,
    )
    assert passed.decision == "PASS"
    assert passed.evidence["details"]["drill_passed"] is True
    assert passed.evidence["details"]["drill_passed_source"] == "drill_receipt.result"


@pytest.mark.parametrize(
    "content,category",
    [
        (b"stripe.PaymentIntent.create(amount=1)\n", "funds"),
        (b"deploy_to_production()\n", "publish"),
        (b"send_email(to='ops@example.com')\n", "send"),
        (b"DROP TABLE users;\n", "delete"),
        (b"DELETE FROM users;\n", "delete"),
    ],
)
def test_scenes_36_to_39_kill_lines(content, category):
    req = valid_request(changed_paths=["src/hot.py"], blobs=[("src/hot.py", content)])
    result = land(req)
    assert result.reason_code == "ACTIVATION_KILL_LINE"
    assert result.evidence["details"]["category"] == category
    assert req.activation_state.kill_line_tripped is True
    assert req.activation_state.path_b_enabled is False
    assert result.evidence["details"]["merged"] is False


def test_scenes_40_to_43_initial_activation():
    signed, digest = activation_receipt()
    secret = b"seal-test-secret"
    artifact = hashlib.sha256(b"artifact").hexdigest()
    config = hashlib.sha256(b"config").hexdigest()
    sealed = seal(artifact, config, secret=secret)
    iso = verify(artifact, config, sealed, secret=secret, **_seal_ids())
    assert iso.decision == "PASS"

    outsider = ActivationState()
    denied = enable_path_b(
        outsider,
        actor="intruder",
        founder_written_approval=True,
        activation_receipt=signed,
        gate_version=RULE_VERSION,
        evidence_digest=digest,
        isomorphism_result=iso,
        **_ids(),
    )
    assert denied.reason_code == "ACTIVATION_NON_FOUNDER"
    assert outsider.path_b_enabled is False

    missing = enable_path_b(
        ActivationState(),
        actor="founder",
        founder_written_approval=True,
        activation_receipt=None,
        gate_version=RULE_VERSION,
        evidence_digest=digest,
        isomorphism_result=iso,
        **_ids(),
    )
    assert missing.reason_code == "ACTIVATION_MISSING_RECEIPT"

    mismatched, _other = activation_receipt(gate_version="5.0.0")
    mismatch = enable_path_b(
        ActivationState(),
        actor="founder",
        founder_written_approval=True,
        activation_receipt=mismatched,
        gate_version=RULE_VERSION,
        evidence_digest=digest,
        isomorphism_result=iso,
        **_ids(),
    )
    assert mismatch.reason_code == "ACTIVATION_RECEIPT_MISMATCH"

    opened_state = ActivationState()
    opened = enable_path_b(
        opened_state,
        actor="founder",
        founder_written_approval=True,
        activation_receipt=signed,
        gate_version=RULE_VERSION,
        evidence_digest=digest,
        isomorphism_result=iso,
        **_ids(),
    )
    assert opened.decision == "PASS"
    assert opened_state.path_b_enabled is True
    assert opened_state.environment == "isolated"

    production = ActivationState(environment="production")
    blocked = enable_path_b(
        production,
        actor="founder",
        founder_written_approval=True,
        activation_receipt=signed,
        gate_version=RULE_VERSION,
        evidence_digest=digest,
        isomorphism_result=iso,
        **_ids(),
    )
    assert blocked.reason_code == "ACTIVATION_PATH_B_DISABLED"
    assert blocked.evidence["details"]["message"] == "Path B disabled"
    assert production.path_b_enabled is False


def test_registry_file_is_machine_readable():
    from gates.task_registry.load import load_registry

    data = load_registry()
    assert data["tasks"]["GATES-BUILD-2026-11-01"]["status"] == "active"
    assert data["tasks"]["GATES-CLOSED-EXAMPLE"]["status"] == "closed"


def test_scope_active_task_passes_r1():
    result = scope_decide(
        TASK,
        CANDIDATE,
        BASE,
        ["src/app.py"],
        registry(),
        rule_version=RULE_VERSION,
        rule_digest=RULE_DIGEST,
    )
    assert result.decision == "PASS"
    assert result.evidence["task_id"] == TASK
    assert result.evidence["timestamp"].endswith("+08:00")
