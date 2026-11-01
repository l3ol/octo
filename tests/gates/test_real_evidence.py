"""REAL_ISOLATION_EVIDENCE for SPEC-GATES-REAL-EVIDENCE-v1. Not an independent Reviewer PASS."""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import tempfile
from pathlib import Path

from gates.atomic_merge.compare import compare_and_merge
from gates.cas import GitCasPublisher
from gates.gitcmd import rev_parse
from gates.integrity.recovery import verify_recovery
from gates.isolation_bed import (
    OPS_ROOT,
    authoritative_paths,
    build_twin_bed,
    materialize_pin_manifest,
    resolved_paths,
    snapshot_pin_commit,
)
from gates.rules import CANONICAL_SHA256, RULE_DIGEST, RULE_VERSION
from gates.tamper.loader import load_default_manifest, load_pin
from gates.verification.ledger import ConsumptionLedger
from tests.gates.support import TASK

_SHA40 = __import__("re").compile(r"^[0-9a-f]{40}$")


def _workspace() -> Path:
    return Path(__file__).resolve().parents[2]


def _bind_env(paths: dict) -> dict:
    previous = {key: os.environ.get(key) for key in (
        "GATES_ISOLATION_BED_ROOT",
        "GATES_PIN_LOADPATH",
        "GATES_CAS_SLOT",
        "GATES_L1_DRILL_ROOT",
        "GATES_DISPOSABLE_GIT",
    )}
    os.environ["GATES_ISOLATION_BED_ROOT"] = str(paths["root"])
    os.environ["GATES_PIN_LOADPATH"] = str(paths["pin_loadpath"])
    os.environ["GATES_CAS_SLOT"] = str(paths["cas_slot"])
    os.environ["GATES_L1_DRILL_ROOT"] = str(paths["l1_drill"])
    os.environ["GATES_DISPOSABLE_GIT"] = str(paths["disposable_git"])
    return previous


def _restore_env(previous: dict) -> None:
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def test_real_evidence_bed_and_pin_load():
    assert authoritative_paths()["root"] == OPS_ROOT
    ops_visible = OPS_ROOT.exists()
    root = Path(tempfile.mkdtemp(prefix="gates-twin-bed-"))
    workspace = _workspace()
    build_candidate = rev_parse(workspace, "HEAD")
    test_base = "5443c9b4dde7fc208a0a72457c87904650829f77"
    paths = build_twin_bed(root, workspace, build_candidate)
    previous = _bind_env(paths)
    try:
        resolved = resolved_paths()
        assert resolved["ops_root_visible"] is ops_visible
        assert resolved["pin_loadpath"] == paths["pin_loadpath"]
        assert not ops_visible
        head = rev_parse(paths["candidate_worktree"], "HEAD")
        tree = rev_parse(paths["candidate_worktree"], "HEAD^{tree}")
        assert head == paths["resolved_tip"] == build_candidate
        assert tree == rev_parse(workspace, "HEAD^{tree}")
        bare = paths["disposable_git"]
        proof = snapshot_pin_commit(
            bare,
            workspace,
            build_candidate,
            test_base_sha=test_base,
        )
        assert proof["status"] == "OK"
        assert proof["method"] == "git-archive"
        assert proof["source_commit"] == build_candidate
        assert proof["pin_tree_sha"] == tree
        assert proof["runtime_gates_pin_sha"] != build_candidate
        assert proof["runtime_gates_pin_sha"] != test_base
        pin_sha = proof["runtime_gates_pin_sha"]
        assert _SHA40.fullmatch(pin_sha)
        assert not pin_sha.startswith("0123456789abcdef0123")
        assert pin_sha != "a" * 40
        extract = paths["pin_loadpath"] / "pins" / pin_sha
        manifest_path = paths["pin_loadpath"] / "manifests" / f"{pin_sha}.json"
        manifest = materialize_pin_manifest(
            bare,
            pin_sha,
            manifest_path=manifest_path,
            extract_root=extract,
            candidate_worktree=paths["candidate_worktree"],
            build_candidate_sha=build_candidate,
            test_base_sha=test_base,
        )
        assert manifest["gate_tree_sha"] == rev_parse(bare, f"{pin_sha}:gates")
        assert manifest["pin_tree_sha"] == rev_parse(bare, f"{pin_sha}^{{tree}}")
        assert manifest["config_digest"] != CANONICAL_SHA256
        assert manifest["parameters_canonical_sha256"] == CANONICAL_SHA256
        assert oct(manifest_path.stat().st_mode & 0o777) == "0o444"
        default_text = (paths["pin_loadpath"] / "manifests" / "default_manifest.UNSET_FAIL_CLOSED.json").read_text(encoding="utf-8")
        assert "UNSET_FAIL_CLOSED" in default_text
        assert load_default_manifest()["gates_pin_sha"] == "UNSET_FAIL_CLOSED"
        loaded = load_pin(
            manifest,
            pin_loadpath=extract,
            manifest_path=manifest_path,
            candidate_worktree=paths["candidate_worktree"],
            git_repo=bare,
            candidate_sha=head,
            base_sha="5443c9b4dde7fc208a0a72457c87904650829f77",
            task_id=TASK,
        )
        assert loaded.ok is True
        details = loaded.result.evidence["details"]
        assert details["evidence_class"] == "REAL_ISOLATION_EVIDENCE"
        assert details["gates_pin_sha"] == pin_sha
        assert details["gate_tree_sha"] == manifest["gate_tree_sha"]
        assert details["pin_loadpath"] == str(extract.resolve())
        assert details["sys_path_gates_entry"] == str(extract.resolve())
        assert details["candidate_code_used"] is False
        assert details["manifest_path"] == str(manifest_path.resolve())
        assert len(details["manifest_sha256"]) == 64
        for path in details["module_origin"].values():
            assert path.startswith(str(extract.resolve()) + "/")
        compare_file = Path(details["module_origin"]["gates.atomic_merge.compare"])
        pin_hash = compare_file.read_bytes()
        candidate_compare = paths["candidate_worktree"] / "gates" / "atomic_merge" / "compare.py"
        original = candidate_compare.read_bytes()
        candidate_compare.write_bytes(original + b"\n# candidate edit\n")
        again = load_pin(
            manifest,
            pin_loadpath=extract,
            manifest_path=manifest_path,
            candidate_worktree=paths["candidate_worktree"],
            git_repo=bare,
            candidate_sha=head,
            base_sha="5443c9b4dde7fc208a0a72457c87904650829f77",
            task_id=TASK,
        )
        assert again.ok is True
        assert Path(again.result.evidence["details"]["module_origin"]["gates.atomic_merge.compare"]).read_bytes() == pin_hash
        candidate_compare.write_bytes(original)
        unset = load_pin(
            json.loads(default_text),
            pin_loadpath=extract,
            manifest_path=paths["pin_loadpath"] / "manifests" / "default_manifest.UNSET_FAIL_CLOSED.json",
            candidate_worktree=paths["candidate_worktree"],
            git_repo=bare,
            candidate_claimed_pin=pin_sha,
            head_sha=head,
        )
        assert unset.result.reason_code == "TAMPER_PIN_UNSET_OR_INVALID"
        assert unset.result.evidence["details"]["fallback_used"] is False
        missing = dict(manifest)
        missing["gates_pin_sha"] = "9" * 40
        assert load_pin(missing, pin_loadpath=extract, manifest_path=manifest_path, git_repo=bare, candidate_worktree=paths["candidate_worktree"]).result.reason_code == "TAMPER_PIN_UNSET_OR_INVALID"
        bad_tree = dict(manifest)
        bad_tree["gate_tree_sha"] = "2" * 40
        assert load_pin(bad_tree, pin_loadpath=extract, manifest_path=manifest_path, git_repo=bare, candidate_worktree=paths["candidate_worktree"]).result.evidence["details"]["pin_value_class"] == "digest_mismatch"
        only_cff = dict(manifest)
        only_cff["config_digest"] = CANONICAL_SHA256
        only_canonical = load_pin(only_cff, pin_loadpath=extract, manifest_path=manifest_path, git_repo=bare, candidate_worktree=paths["candidate_worktree"])
        assert only_canonical.result.reason_code == "CONFIG_DIGEST_INCOMPLETE"
        link_parent = root / "symlink-load"
        link_parent.mkdir()
        (link_parent / "gates").symlink_to(paths["candidate_worktree"] / "gates")
        violated = load_pin(
            manifest,
            pin_loadpath=link_parent,
            manifest_path=manifest_path,
            candidate_worktree=paths["candidate_worktree"],
            git_repo=bare,
            candidate_sha=head,
            base_sha="5443c9b4dde7fc208a0a72457c87904650829f77",
            task_id=TASK,
        )
        assert violated.result.reason_code == "TAMPER_PIN_UNSET_OR_INVALID"
        assert violated.result.evidence["details"]["module_origin_violation"] is True
    finally:
        _restore_env(previous)
        shutil.rmtree(root, ignore_errors=True)


def test_publisher_missing_does_not_move_ref_or_merge():
    from tests.gates.support import valid_request

    req = valid_request()
    before = req.publisher.read_ref()
    result = compare_and_merge(
        req.candidate_sha,
        req.base_sha,
        req.receipt["receipt_id"],
        current_head_sha=req.base_sha,
        merge_candidate_sha=req.candidate_sha,
        ledger=req.ledger,
        task_id=TASK,
        rule_version=RULE_VERSION,
        rule_digest=RULE_DIGEST,
        publish=None,
    )
    assert result.reason_code == "ATOMIC_MERGE_PUBLISHER_MISSING"
    assert result.evidence["details"]["publisher"] == "missing"
    assert result.evidence["details"]["merged"] is False
    assert req.ledger.merges == []
    assert req.publisher.read_ref() == before
    assert req.activation_state.path_b_enabled is True
    assert req.activation_state.self_closed is False


def test_publisher_exception_does_not_merge():
    from tests.gates.support import valid_request

    req = valid_request()
    before = req.publisher.read_ref()

    def _boom():
        raise RuntimeError("cas broke")

    req.publisher.before_update = _boom
    from gates.pipeline import evaluate_landing

    result = evaluate_landing(req)
    assert result.reason_code == "GATE_INTERNAL_ERROR"
    assert result.evidence["details"]["merged"] is False
    assert req.publisher.read_ref() == before
    assert req.ledger.merges == []


def _scene20_worker(repo, ref, base, candidate, receipt_id, barrier, queue):
    barrier.wait()
    publisher = GitCasPublisher(repo, ref)
    result = compare_and_merge(
        candidate,
        base,
        receipt_id,
        current_head_sha=base,
        merge_candidate_sha=candidate,
        ledger=ConsumptionLedger(),
        task_id=TASK,
        rule_version=RULE_VERSION,
        rule_digest=RULE_DIGEST,
        publish=publisher,
    )
    queue.put({"decision": result.decision, "reason_code": result.reason_code, "merged": result.evidence["details"]["merged"]})


def assert_scene_20_real_race():
    from tests.gates.support import prepare_real_landing

    landing = prepare_real_landing()
    ctx = multiprocessing.get_context("fork")
    barrier = ctx.Barrier(2)
    queue = ctx.Queue()
    args = (
        landing["repo"],
        "refs/heads/gates-isolated-slot",
        landing["base"],
        landing["candidate"],
        "rcpt-race",
        barrier,
        queue,
    )
    procs = [ctx.Process(target=_scene20_worker, args=args) for _ in range(2)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(30)
        assert proc.exitcode == 0
    rows = [queue.get() for _ in range(2)]
    decisions = sorted(row["decision"] for row in rows)
    reasons = [row["reason_code"] for row in rows]
    assert decisions == ["PASS", "REJECT"]
    assert reasons.count(None) == 1
    assert reasons.count("VERIFICATION_RECEIPT_CONFLICT") == 1
    assert sum(1 for row in rows if row["merged"]) == 1
    publisher = GitCasPublisher(landing["repo"], "refs/heads/gates-isolated-slot")
    assert publisher.read_ref() == landing["candidate"]
    ledger = json.loads(Path(landing["repo"], ".cas-ledger.json").read_text(encoding="utf-8"))
    assert len(ledger["merges"]) == 1
    assert list(ledger["consumed"]) == ["rcpt-race"]


def test_scene_20_and_l1_real_paths():
    assert_scene_20_real_race()
    from tests.gates.support import valid_request

    req = valid_request()
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
    receipt = json.loads(Path(req.recovery_plan["drill_receipt_path"]).read_text(encoding="utf-8"))
    assert receipt["result"] == "PASS"
    assert receipt["ref_after"] == req.recovery_plan["rollback_commit"]
    assert req.board.read_drill(req.recovery_plan["drill_board_entry_id"])["result"] == "PASS"
