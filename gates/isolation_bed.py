"""Isolation-bed paths.

Authoritative Ops root (may be absent on a Dev VM):

    /home/box/ops-isolation/gates/source-qa-isolation-bed-2026-11-01

Env overrides, when set, are the disposable twin for this VM or CI:

    GATES_ISOLATION_BED_ROOT
    GATES_PIN_LOADPATH
    GATES_CAS_SLOT
    GATES_L1_DRILL_ROOT
    GATES_DISPOSABLE_GIT
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

from gates.gitcmd import archive_sha256, object_type, rev_parse, run_git, show_bytes
from gates.types import now_cst

OPS_ROOT = Path("/home/box/ops-isolation/gates/source-qa-isolation-bed-2026-11-01")
TIP_BINDING = "d50148d9d84e42ac6cd3359d598f0ec7c600e834"
TREE_BINDING = "03b23bf69839c1eb059b553ca027c13e0b342096"


def authoritative_paths() -> dict[str, Path]:
    root = OPS_ROOT
    return {
        "root": root,
        "disposable_git": root / "git" / "octo-gates-DISPOSABLE.git",
        "candidate_worktree": root / "worktrees" / "candidate-ro-checkout",
        "pin_loadpath": root / "pin-loadpath-readonly",
        "cas_slot": root / "cas-slot",
        "l1_drill": root / "l1-recovery-drill",
    }


def resolved_paths() -> dict[str, Path | bool]:
    """Prefer env (the twin). Otherwise return the authoritative Ops paths."""
    auth = authoritative_paths()
    root = Path(os.environ["GATES_ISOLATION_BED_ROOT"]) if os.environ.get("GATES_ISOLATION_BED_ROOT") else auth["root"]
    mapping = {
        "pin_loadpath": "GATES_PIN_LOADPATH",
        "cas_slot": "GATES_CAS_SLOT",
        "l1_drill": "GATES_L1_DRILL_ROOT",
        "disposable_git": "GATES_DISPOSABLE_GIT",
    }
    resolved: dict[str, Path | bool] = {"root": root, "ops_root_visible": OPS_ROOT.exists()}
    for key, env_name in mapping.items():
        resolved[key] = Path(os.environ[env_name]) if os.environ.get(env_name) else auth[key]
    return resolved


def _ignore_junk(_dir: str, names: list[str]) -> set[str]:
    return {name for name in names if name == "__pycache__" or name.endswith(".pyc")}


def build_twin_bed(root: Path, workspace: Path, tip: str = TIP_BINDING) -> dict[str, Path]:
    """Create an isomorphic disposable bed. Does not touch the Ops root or GitHub."""
    root.mkdir(parents=True, exist_ok=True)
    bare = root / "git" / "octo-gates-DISPOSABLE.git"
    if not bare.exists():
        bare.parent.mkdir(parents=True, exist_ok=True)
        run_git(workspace, "clone", "--bare", "--quiet", str(workspace), str(bare))
        run_git(bare, "remote", "set-url", "--push", "origin", "DISABLED-DO-NOT-PUSH")
    candidate = root / "worktrees" / "candidate-ro-checkout"
    if not candidate.exists():
        run_git(bare, "worktree", "add", "--detach", "--quiet", str(candidate), tip)
        (candidate / ".DISPOSABLE_ISOLATION_BED").write_text("twin\n", encoding="utf-8")
    pin_root = root / "pin-loadpath-readonly"
    (pin_root / "manifests").mkdir(parents=True, exist_ok=True)
    (pin_root / "pins").mkdir(parents=True, exist_ok=True)
    default_src = workspace / "gates" / "loader" / "default_manifest.json"
    default_dst = pin_root / "manifests" / "default_manifest.UNSET_FAIL_CLOSED.json"
    if not default_dst.exists():
        default_dst.write_bytes(default_src.read_bytes())
    cas = root / "cas-slot"
    for name in ("locks", "objects", "publish-log", "staging"):
        (cas / name).mkdir(parents=True, exist_ok=True)
    l1 = root / "l1-recovery-drill"
    for name in ("board", "evidence", "plans", "rollback-refs"):
        (l1 / name).mkdir(parents=True, exist_ok=True)
    status = l1 / "evidence" / "DRILL_STATUS.json"
    if not status.exists():
        status.write_text(
            json.dumps({"drill_passed": False, "state": "NOT_RUN", "bound_candidate_sha": None, "bound_base_sha": None}) + "\n",
            encoding="utf-8",
        )
    (root / "LAYOUT.txt").write_text("twin of source-qa-isolation-bed\n", encoding="utf-8")
    return {
        "root": root,
        "disposable_git": bare,
        "candidate_worktree": candidate,
        "pin_loadpath": pin_root,
        "cas_slot": cas,
        "l1_drill": l1,
    }


def snapshot_pin_commit(bare: Path, workspace: Path, tip: str = TIP_BINDING) -> str:
    """Commit the workspace gates tree onto a disposable ref. Returns a real 40-hex SHA."""
    build = bare.parent.parent / "worktrees" / "pin-build"
    if build.exists():
        run_git(bare, "worktree", "remove", "--force", str(build), check=False)
        shutil.rmtree(build, ignore_errors=True)
    run_git(bare, "worktree", "add", "--detach", "--quiet", str(build), tip)
    dest = build / "gates"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(workspace / "gates", dest, ignore=_ignore_junk)
    run_git(build, "add", "-A", "gates")
    proc = run_git(build, "commit", "-q", "-m", "disposable pin snapshot", check=False)
    if proc.returncode != 0 and b"nothing to commit" not in proc.stdout + proc.stderr:
        raise RuntimeError(proc.stderr.decode())
    sha = rev_parse(build, "HEAD")
    run_git(bare, "update-ref", "refs/disposable/gates-qa/pin-snapshot", sha)
    return sha


def materialize_pin_manifest(
    bare: Path,
    pin_sha: str,
    *,
    manifest_path: Path,
    extract_root: Path,
    candidate_worktree: Path,
) -> dict:
    if object_type(bare, pin_sha) != "commit":
        raise RuntimeError("pin sha is not a commit")
    tree = rev_parse(bare, f"{pin_sha}^{{tree}}")
    artifact = archive_sha256(bare, pin_sha)
    config = hashlib.sha256(show_bytes(bare, f"{pin_sha}:gates/policy/GATES-PARAMETERS-CANONICAL.txt")).hexdigest()
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True)
    data = run_git(bare, "archive", "--format=tar", pin_sha).stdout
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        archive.extractall(extract_root, filter="data")
    manifest = {
        "gates_pin_sha": pin_sha,
        "gate_tree_sha": tree,
        "rule_version": "6.0.0",
        "artifact_digest": artifact,
        "config_digest": config,
        "generated_at": now_cst(),
        "receipt_id": f"pin-{pin_sha[:12]}",
        "git_repo": str(bare.resolve()),
        "extract_root": str(extract_root.resolve()),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(manifest_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    cand = candidate_worktree.resolve()
    man = manifest_path.resolve()
    if cand == man or cand in man.parents:
        raise RuntimeError("manifest landed inside the candidate worktree")
    return manifest
