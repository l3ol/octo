"""Builder selftest only. Not product acceptance, independent verification, or runtime_pass."""
from pathlib import Path
import subprocess

import pytest

from octo.candidate import file_digest, git_candidate_sha, tree_sha
from octo.models import Receipt, compute_candidate_sha, validate_prd_record
from octo.objects import sha256

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def test_git_candidate_sha_accepts_real_commit():
    commit = _git("rev-parse", "HEAD")
    tree = _git("rev-parse", "HEAD^{tree}")
    kind = _git("cat-file", "-t", commit)
    assert kind == "commit"
    assert git_candidate_sha(commit) == commit
    assert len(commit) == 40
    assert tree_sha(tree) == tree
    assert len(tree) == 40


def test_git_and_file_digest_cross_use_rejected():
    commit = _git("rev-parse", "HEAD")
    legacy = compute_candidate_sha({"a.txt": "abc", "b.txt": "def"})
    assert len(legacy) == 64
    assert file_digest(legacy) == legacy
    assert sha256(legacy) == legacy
    with pytest.raises(ValueError, match="40 lowercase hex"):
        git_candidate_sha(legacy)
    with pytest.raises(ValueError, match="40 lowercase hex"):
        tree_sha(legacy)
    with pytest.raises(ValueError, match="SHA-256"):
        file_digest(commit)
    with pytest.raises(ValueError, match="SHA-256"):
        sha256(commit)
    receipt = Receipt(
        receipt_id="r1",
        grant_id="g1",
        request_digest=legacy,
        candidate_sha=commit,
        action="internal_readonly",
        object_id="o1",
        idempotency_key="k1",
        started_at="2026-11-01T00:00:00+00:00",
        finished_at="2026-11-01T00:00:00+00:00",
        state="SUCCEEDED",
    )
    with pytest.raises(ValueError, match="SHA-256"):
        validate_prd_record(receipt)
