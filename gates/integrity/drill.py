"""Execute an L1 rollback drill in an isolated git repo and write a readable receipt."""

from __future__ import annotations

import json
from pathlib import Path

from gates.gitcmd import rev_parse, run_git, update_ref
from gates.types import now_cst

DRILL_REF = "refs/drill/l1"


def execute_recovery_drill(
    repo: str | Path,
    *,
    candidate_sha: str,
    base_sha: str,
    rollback_sha: str,
    evidence_dir: Path,
    board_dir: Path,
    receipt_id: str = "drill-1",
) -> dict:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    board_dir.mkdir(parents=True, exist_ok=True)
    started = now_cst()
    update_ref(repo, DRILL_REF, base_sha)
    ref_before = rev_parse(repo, DRILL_REF)
    operations = [f"update-ref {DRILL_REF} {base_sha} (start)"]
    landed = update_ref(repo, DRILL_REF, candidate_sha, base_sha)
    operations.append(f"update-ref {DRILL_REF} {candidate_sha} {base_sha} ok={landed}")
    rolled = update_ref(repo, DRILL_REF, rollback_sha, candidate_sha) if landed else False
    operations.append(f"update-ref {DRILL_REF} {rollback_sha} {candidate_sha} ok={rolled}")
    ref_after = rev_parse(repo, DRILL_REF)
    scratch = Path(repo).parent / f"drill-scratch-{receipt_id}"
    if scratch.exists():
        run_git(repo, "worktree", "remove", "--force", str(scratch), check=False)
    run_git(repo, "worktree", "add", "--detach", "--quiet", str(scratch), rollback_sha)
    observed = rev_parse(scratch, "HEAD")
    operations.append(f"worktree HEAD {observed}")
    run_git(repo, "worktree", "remove", "--force", str(scratch))
    restored = update_ref(repo, DRILL_REF, base_sha)
    operations.append(f"restore {DRILL_REF} {base_sha} ok={restored}")
    ended = now_cst()
    ok = landed and rolled and ref_after == rollback_sha and observed == rollback_sha
    receipt = {
        "receipt_id": receipt_id,
        "result": "PASS" if ok else "FAIL",
        "started_at": started,
        "ended_at": ended,
        "operations": operations,
        "ref_before": ref_before,
        "ref_after": ref_after,
        "candidate_sha": candidate_sha,
        "base_sha": base_sha,
        "rollback_commit": rollback_sha,
        "worktree_head": observed,
    }
    receipt_path = evidence_dir / f"{receipt_id}.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    entry_id = f"board-{receipt_id}"
    entry = {
        "entry_id": entry_id,
        "receipt_id": receipt_id,
        "result": receipt["result"],
        "candidate_sha": candidate_sha,
        "base_sha": base_sha,
        "rollback_commit": rollback_sha,
        "ref_before": ref_before,
        "ref_after": ref_after,
        "started_at": started,
        "ended_at": ended,
    }
    board_path = board_dir / f"{entry_id}.json"
    board_path.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "rollback_commit": rollback_sha,
        "forward_fix": None,
        "bound_candidate_sha": candidate_sha,
        "bound_base_sha": base_sha,
        "drill_receipt_id": receipt_id,
        "drill_receipt_path": str(receipt_path),
        "drill_board_entry_id": entry_id,
        "drill_board_path": str(board_path),
        "drill_receipt": receipt,
    }
