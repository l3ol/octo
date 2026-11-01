"""Small git helpers for the disposable isolation bed. Never pushes."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def run_git(repo: str | Path, *args: str, check: bool = True, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    command = ["git", "-C", str(repo), "-c", "user.email=gates-drill@example.invalid", "-c", "user.name=gates-drill", *args]
    return subprocess.run(command, check=check, input=input_bytes, capture_output=True)


def rev_parse(repo: str | Path, rev: str) -> str:
    return run_git(repo, "rev-parse", rev).stdout.decode().strip()


def cat_file_commit(repo: str | Path, sha: str) -> bool:
    proc = run_git(repo, "cat-file", "-e", f"{sha}^{{commit}}", check=False)
    return proc.returncode == 0


def object_type(repo: str | Path, sha: str) -> str | None:
    proc = run_git(repo, "cat-file", "-t", sha, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.decode().strip()


def archive_sha256(repo: str | Path, commit: str) -> str:
    data = run_git(repo, "archive", "--format=tar", commit).stdout
    return hashlib.sha256(data).hexdigest()


def show_bytes(repo: str | Path, spec: str) -> bytes:
    return run_git(repo, "show", spec).stdout


def update_ref(repo: str | Path, ref: str, new: str, old: str | None = None) -> bool:
    args = ["update-ref", ref, new]
    if old is not None:
        args.append(old)
    proc = run_git(repo, *args, check=False)
    return proc.returncode == 0
