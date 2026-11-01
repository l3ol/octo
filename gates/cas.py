"""Isolated git compare-and-swap. Not a production Path B channel."""

from __future__ import annotations

import fcntl
import json
from pathlib import Path

from gates.gitcmd import rev_parse, run_git, update_ref


class GitCasPublisher:
    def __init__(self, repo: str | Path, ref: str = "refs/heads/gates-isolated-slot") -> None:
        self.repo = str(repo)
        self.ref = ref
        self.before_update = None
        self.ledger_path = Path(self.repo) / ".cas-ledger.json"
        self.lock_path = Path(self.repo) / ".cas.lock"

    def read_ref(self) -> str:
        return rev_parse(self.repo, self.ref)

    def force_ref(self, sha: str) -> None:
        if not update_ref(self.repo, self.ref, sha):
            raise RuntimeError("force-ref failed")

    def compare_and_swap(self, new: str, old: str) -> bool:
        return update_ref(self.repo, self.ref, new, old)

    def make_other_commit(self, message: str = "racer") -> str:
        path = Path(self.repo) / "racer.txt"
        path.write_text(message + "\n", encoding="utf-8")
        run_git(self.repo, "add", "racer.txt")
        run_git(self.repo, "commit", "-q", "-m", message)
        return rev_parse(self.repo, "HEAD")

    def transaction(self, *, receipt_id: str, expected_base: str, new_commit: str, board_fn) -> tuple[str, str, str]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                return self._locked(receipt_id, expected_base, new_commit, board_fn)
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _locked(self, receipt_id: str, expected_base: str, new_commit: str, board_fn) -> tuple[str, str, str]:
        state = {"consumed": {}, "merges": []}
        if self.ledger_path.exists():
            state = json.loads(self.ledger_path.read_text(encoding="utf-8"))
        if receipt_id in state["consumed"]:
            current = self.read_ref()
            return "conflict", current, current
        before = self.read_ref()
        if before != expected_base:
            return "head_mismatch", before, before
        if self.before_update is not None:
            self.before_update()
        ok = self.compare_and_swap(new_commit, expected_base)
        after = self.read_ref()
        if not ok or after != new_commit:
            return "head_mismatch", before, after
        if board_fn is not None and board_fn() is not True:
            self.compare_and_swap(expected_base, new_commit)
            restored = self.read_ref()
            return "board_invisible", before, restored
        state["consumed"][receipt_id] = {"at_ref": after}
        state["merges"].append({"receipt_id": receipt_id, "ref": self.ref, "sha": after})
        self.ledger_path.write_text(json.dumps(state), encoding="utf-8")
        return "merged", before, after
