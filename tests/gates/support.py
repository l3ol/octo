"""Isolated fixture builders for builder selftests. Not an external pin manifest."""

from __future__ import annotations

import hashlib
import json

from gates.activation.state import ActivationState
from gates.integrity.board import Board
from gates.policy.audit import RuleAuditLog
from gates.rules import RULE_VERSION
from gates.types import result_digest
from gates.verification.ledger import ConsumptionLedger
from gates.verification.receipt import sign_activation_receipt, sign_receipt

CANDIDATE = "a" * 40
BASE = "b" * 40
OTHER = "c" * 40
PARENT = "d" * 40
ROLLBACK = "e" * 40
TASK = "GATES-BUILD-2026-11-01"
REVIEWER_SECRET = b"reviewer-test-secret"
FOUNDER_SECRET = b"founder-activation-test-secret"
# STACK_OK_BUILDER only. Not a real pin and not valid REAL_ISOLATION_EVIDENCE.
PIN = "0123456789abcdef0123456789abcdef01234567"
TREE = "fedcba9876543210fedcba9876543210fedcba98"


class MemoryObjectStore:
    def __init__(self) -> None:
        self.objects: dict[str, dict] = {}
        self.lookups: list[str] = []

    def add(self, sha: str, **fields) -> None:
        self.objects[sha] = fields

    def lookup(self, sha: str):
        if sha in {"HEAD", "main"} or str(sha).startswith("refs/"):
            raise AssertionError(f"ref fallback attempted: {sha}")
        self.lookups.append(sha)
        return self.objects.get(sha)


def pin_material():
    artifact = hashlib.sha256(b"gates-artifact-v6").hexdigest()
    config = hashlib.sha256(b"gates-config-v6").hexdigest()
    store = MemoryObjectStore()
    store.add(
        PIN,
        object_type="commit",
        tree_sha=TREE,
        artifact_digest=artifact,
        config_digest=config,
    )
    manifest = {
        "gates_pin_sha": PIN,
        "gate_tree_sha": TREE,
        "rule_version": RULE_VERSION,
        "artifact_digest": artifact,
        "config_digest": config,
        "generated_at": "2026-11-01T12:00:00+08:00",
        "receipt_id": "pin-fixture-receipt",
    }
    return manifest, store


def registry(allowed: list[str] | None = None, tasks: dict | None = None) -> dict:
    if tasks is not None:
        return {"tasks": tasks}
    return {
        "tasks": {
            TASK: {
                "status": "active",
                "allowed_paths": allowed
                or ["src/**", "docs/**", "tools/**", "x/**", "release/**", "payload.bin"],
            }
        }
    }


def reviewer_receipt(
    *,
    candidate: str = CANDIDATE,
    base: str = BASE,
    task: str = TASK,
    issuer: str = "reviewer-bot",
    decision: str = "PASS",
    receipt_id: str = "rcpt-1",
    secret: bytes = REVIEWER_SECRET,
) -> dict:
    return sign_receipt(
        {
            "receipt_id": receipt_id,
            "issuer": issuer,
            "decision": decision,
            "task_id": task,
            "candidate_sha": candidate,
            "base_sha": base,
            "rule_version": RULE_VERSION,
            "issued_at": "2026-11-01T10:00:00+08:00",
        },
        secret,
    )


def activation_receipt(
    *,
    gate_version: str = RULE_VERSION,
    evidence_digest: str | None = None,
    environment: str = "isolated",
    secret: bytes = FOUNDER_SECRET,
    receipt_id: str = "act-1",
) -> tuple[dict, str]:
    digest = evidence_digest or hashlib.sha256(b"activation-evidence").hexdigest()
    signed = sign_activation_receipt(
        {
            "receipt_id": receipt_id,
            "approver": "founder",
            "gate_version": gate_version,
            "evidence_digest": digest,
            "environment": environment,
            "issued_at": "2026-11-01T11:00:00+08:00",
        },
        secret,
    )
    return signed, digest


def recovery_plan(
    *,
    candidate: str = CANDIDATE,
    base: str = BASE,
    rollback: str = ROLLBACK,
    drill_passed: bool = True,
    forward_fix: str | None = None,
) -> dict:
    return {
        "rollback_commit": rollback,
        "forward_fix": forward_fix,
        "drill_passed": drill_passed,
        "bound_candidate_sha": candidate,
        "bound_base_sha": base,
    }


def commit_exists(sha: str) -> bool:
    """Legacy predicate. Not proof for verify_recovery (REAL drills use git cat-file)."""
    return sha == ROLLBACK


def prepare_real_landing():
    """Isolated git slot + executed L1 drill. Landing SHAs are real commits."""
    import tempfile
    from pathlib import Path

    from gates.cas import GitCasPublisher
    from gates.gitcmd import rev_parse, run_git, update_ref
    from gates.integrity.drill import execute_recovery_drill

    root = Path(tempfile.mkdtemp(prefix="gates-landing-"))
    repo = root / "repo"
    repo.mkdir()
    run_git(repo, "init", "-q", "-b", "main")
    (repo / "drills").mkdir()
    (repo / "drills" / "recover.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    run_git(repo, "add", "drills/recover.sh")
    run_git(repo, "commit", "-q", "-m", "rollback")
    rollback = rev_parse(repo, "HEAD")
    (repo / "base.txt").write_text("base\n", encoding="utf-8")
    run_git(repo, "add", "base.txt")
    run_git(repo, "commit", "-q", "-m", "base")
    base = rev_parse(repo, "HEAD")
    (repo / "candidate.txt").write_text("candidate\n", encoding="utf-8")
    run_git(repo, "add", "candidate.txt")
    run_git(repo, "commit", "-q", "-m", "candidate")
    candidate = rev_parse(repo, "HEAD")
    update_ref(repo, "refs/heads/gates-isolated-slot", base)
    plan = execute_recovery_drill(
        repo,
        candidate_sha=candidate,
        base_sha=base,
        rollback_sha=rollback,
        evidence_dir=root / "l1-recovery-drill" / "evidence",
        board_dir=root / "l1-recovery-drill" / "board",
    )
    board = Board()
    board.remember_drill(plan["drill_board_entry_id"], json.loads(Path(plan["drill_board_path"]).read_text(encoding="utf-8")))
    return {
        "repo": str(repo),
        "candidate": candidate,
        "base": base,
        "publisher": GitCasPublisher(repo, "refs/heads/gates-isolated-slot"),
        "plan": plan,
        "board": board,
    }


def assert_machine_readable(result) -> None:
    assert result.decision in {"PASS", "REJECT"}
    assert str(result.evidence["timestamp"]).endswith("+08:00")
    assert result.evidence["candidate_sha"] == result.candidate_sha
    assert result.evidence["base_sha"] == result.base_sha
    assert result.evidence["rule_version"] == result.rule_version
    assert len(result.result_digest) == 64
    recomputed = result_digest(
        result.gate,
        result.decision,
        result.reason_code,
        result.candidate_sha,
        result.base_sha,
        result.rule_version,
        result.evidence,
    )
    assert recomputed == result.result_digest


def valid_request(**overrides):
    from gates.pipeline import LandingRequest

    landing = prepare_real_landing()
    manifest, store = pin_material()
    state = ActivationState(path_b_enabled=True, environment="isolated")
    payload = dict(
        task_id=TASK,
        candidate_sha=landing["candidate"],
        base_sha=landing["base"],
        changed_paths=["src/app.py"],
        blobs=[("src/app.py", b"print('ok')\n")],
        receipt=reviewer_receipt(candidate=landing["candidate"], base=landing["base"]),
        registry=registry(),
        trusted_issuers={"reviewer-bot": REVIEWER_SECRET},
        ledger=ConsumptionLedger(),
        target_branch_config={},
        current_head_sha=landing["base"],
        activation_state=state,
        board=landing["board"],
        external_manifest=manifest,
        object_store=store,
        rule_version=RULE_VERSION,
        lineage=[],
        recovery_plan=landing["plan"],
        irreversible=False,
        audit_log=RuleAuditLog(),
        candidate_rules=None,
        commit_exists=commit_exists,
        candidate_claimed_pin=None,
        head_sha=None,
        tags=None,
        merge_candidate_sha=None,
        publisher=landing["publisher"],
        recovery_repo=landing["repo"],
    )
    payload.update(overrides)
    return LandingRequest(**payload)
