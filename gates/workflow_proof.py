"""Prove a CI checkout is the candidate commit, not a merge ref.

Metadata `head_sha` is not proof. Historical CI 41325626443 is not a G4 re-freeze.
This module does not install packages, change kernel settings, merge, or rebase.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from gates.gitcmd import cat_file_commit, rev_parse, run_git
from gates.types import is_sha40

HISTORICAL_CI_RUN = "41325626443"
G4_REFROZEN = False
RUNTIME_PASS = False

_FORBIDDEN_WORKFLOW = (
    re.compile(r"\bapt(-get)?\b"),
    re.compile(r"\bsudo\b"),
    re.compile(r"\bsysctl\b"),
    re.compile(r"\bgit\s+merge\b"),
    re.compile(r"\bgit\s+rebase\b"),
)


def historical_ci_is_refreeze_evidence(run_id: str) -> bool:
    """No CI run is G4 re-freeze evidence. 41325626443 is historical only."""
    del run_id
    return False


def workflow_privilege_or_rewrite_hits(text: str) -> list[str]:
    return [pattern.pattern for pattern in _FORBIDDEN_WORKFLOW if pattern.search(text)]


def prove_checkout(
    *,
    expected_sha: str,
    actual_head: str,
    expected_tree: str,
    actual_tree: str,
    base_sha: str,
    checkout_ref: str,
    metadata_head_sha: str | None = None,
) -> dict:
    """Return OK only when the workspace commit and tree are the candidate SHA.

    `metadata_head_sha` is ignored. A matching metadata value does not prove
    the worktree.
    """
    _ = metadata_head_sha
    recorded = {
        "expected_sha": expected_sha,
        "actual_head": actual_head,
        "expected_tree": expected_tree,
        "actual_tree": actual_tree,
        "base_sha": base_sha,
        "checkout_ref": checkout_ref,
        "proven": False,
    }
    values = (expected_sha, actual_head, expected_tree, actual_tree, base_sha, checkout_ref)
    if not all(is_sha40(value) for value in values):
        return {**recorded, "status": "FAIL", "reason_code": "WORKFLOW_HEAD_UNPROVEN"}
    if checkout_ref != expected_sha or actual_head != expected_sha or actual_tree != expected_tree:
        return {**recorded, "status": "FAIL", "reason_code": "WORKFLOW_HEAD_UNPROVEN"}
    recorded["proven"] = True
    recorded["status"] = "OK"
    return recorded


def _parent_sha(repo: Path, head: str) -> str:
    proc = run_git(repo, "rev-parse", "--verify", f"{head}^", check=False)
    if proc.returncode != 0:
        return ""
    return proc.stdout.decode().strip()


def main() -> int:
    event = os.environ.get("EVENT_NAME", "")
    pr_head = os.environ.get("PR_HEAD_SHA", "")
    pr_base = os.environ.get("PR_BASE_SHA", "")
    trigger = os.environ.get("TRIGGER_SHA", "")
    checkout_ref = os.environ.get("CHECKOUT_REF", "")
    repo = Path.cwd()
    actual_head = rev_parse(repo, "HEAD")
    actual_tree = rev_parse(repo, "HEAD^{tree}")
    if event == "pull_request":
        expected = pr_head
        base = pr_base
        if is_sha40(trigger) and (expected == trigger or actual_head == trigger):
            print("WORKFLOW_HEAD_UNPROVEN")
            print("workspace or checkout ref is the pull_request trigger object")
            return 1
    else:
        expected = trigger
        base = _parent_sha(repo, actual_head)
    if is_sha40(expected) and cat_file_commit(repo, expected):
        expected_tree = rev_parse(repo, f"{expected}^{{tree}}")
    else:
        expected_tree = ""
    result = prove_checkout(
        expected_sha=expected,
        actual_head=actual_head,
        expected_tree=expected_tree,
        actual_tree=actual_tree,
        base_sha=base,
        checkout_ref=checkout_ref or expected,
        metadata_head_sha=trigger,
    )
    print(f"checkout_ref={result['checkout_ref']}")
    print(f"expected_sha={result['expected_sha']}")
    print(f"actual_head={result['actual_head']}")
    print(f"expected_tree={result['expected_tree']}")
    print(f"actual_tree={result['actual_tree']}")
    print(f"base_sha={result['base_sha']}")
    if result["status"] != "OK":
        print("WORKFLOW_HEAD_UNPROVEN")
        return 1
    print("WORKFLOW_HEAD_PROVEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
