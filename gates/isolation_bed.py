"""Isolation-bed paths.

Authoritative Ops root (may be absent on a Dev VM):

    /home/box/ops-isolation/gates/source-qa-isolation-bed-2026-11-01

Env overrides, when set, are the disposable twin for this VM or CI:

    GATES_ISOLATION_BED_ROOT
    GATES_PIN_LOADPATH
    GATES_CAS_SLOT
    GATES_L1_DRILL_ROOT
    GATES_DISPOSABLE_GIT
    GATES_TIP_BINDING

`GATES_TIP_BINDING` may name the current authoritative tip. The historical
commit d50148d9… is not that tip and is never a missing-object fallback.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import tarfile
from pathlib import Path

from gates.config_inventory import InventoryError, evaluate_pinned_config
from gates.gitcmd import archive_sha256, cat_file_commit, object_type, rev_parse, run_git
from gates.types import is_sha40, now_cst

OPS_ROOT = Path("/home/box/ops-isolation/gates/source-qa-isolation-bed-2026-11-01")
# Historical G3 tip. Not the tip24 authority and not a fallback target.
HISTORICAL_D501_TIP = "d50148d9d84e42ac6cd3359d598f0ec7c600e834"
HISTORICAL_D501_TREE = "03b23bf69839c1eb059b553ca027c13e0b342096"
SNAPSHOT_METHODS = {"git-archive", "object-read", "equivalent-proven"}


class FailClosed(Exception):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


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


def resolve_tip_binding(explicit: str | None = None) -> dict:
    """Name the authoritative tip. Never substitute a ref or the historical d501 tip."""
    if explicit is not None:
        if not is_sha40(explicit):
            return {"status": "FAIL", "reason_code": "TAMPER_PIN_UNSET_OR_INVALID"}
        return {"status": "OK", "sha": explicit, "source": "explicit"}
    env = os.environ.get("GATES_TIP_BINDING", "").strip()
    if is_sha40(env):
        return {"status": "OK", "sha": env, "source": "GATES_TIP_BINDING"}
    return {"status": "FAIL", "reason_code": "PIN_OBJECT_MISSING"}


def ensure_commit(workspace: Path, sha: str) -> dict:
    """Return the named commit or fail closed.

    A shallow clone may deepen, then the same full SHA is checked again.
    The result sha is the input string. A missing object is `PIN_OBJECT_MISSING`.
    """
    if not isinstance(sha, str) or not is_sha40(sha):
        return {"status": "FAIL", "reason_code": "TAMPER_PIN_UNSET_OR_INVALID"}
    if cat_file_commit(workspace, sha):
        return {"status": "OK", "sha": sha}
    run_git(workspace, "fetch", "--deepen=50", "origin", check=False)
    if not cat_file_commit(workspace, sha):
        run_git(workspace, "fetch", "origin", sha, check=False)
    if cat_file_commit(workspace, sha):
        return {"status": "OK", "sha": sha}
    return {"status": "FAIL", "reason_code": "PIN_OBJECT_MISSING"}


def _require_commit(workspace: Path, sha: str) -> str:
    resolved = ensure_commit(workspace, sha)
    if resolved.get("status") != "OK" or resolved.get("sha") != sha:
        raise FailClosed(str(resolved.get("reason_code") or "PIN_OBJECT_MISSING"))
    return sha


def build_twin_bed(root: Path, workspace: Path, tip: str) -> dict[str, Path | str | bool]:
    """Create an isomorphic disposable bed. Does not touch the Ops root or GitHub."""
    tip = _require_commit(workspace, tip)
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
        "resolved_tip": tip,
        "build_candidate_sha": tip,
    }


def reject_snapshot_method(method: str) -> dict:
    if method == "workspace-copytree" or method not in SNAPSHOT_METHODS:
        return {"status": "FAIL", "reason_code": "PIN_SNAPSHOT_TREE_MISMATCH", "method": method}
    return {"status": "OK", "method": method}


def _gates_diverged(workspace: Path, sha: str) -> bool:
    checks = (
        ("diff", "--quiet", sha, "--", "gates"),
        ("diff", "--cached", "--quiet", sha, "--", "gates"),
    )
    for args in checks:
        proc = run_git(workspace, *args, check=False)
        if proc.returncode == 1:
            return True
        if proc.returncode != 0:
            raise FailClosed("GATE_INTERNAL_ERROR")
    return False


def _archive_gates(repo: Path, sha: str) -> dict[str, str]:
    proc = run_git(repo, "archive", "--format=tar", sha, "gates", check=False)
    if proc.returncode != 0:
        raise FailClosed("PIN_SNAPSHOT_TREE_MISMATCH")
    found: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            name = member.name[2:] if member.name.startswith("./") else member.name
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            found[name] = hashlib.sha256(extracted.read()).hexdigest()
    return found


def _prove_gates_blobs(repo: Path, sha: str) -> dict:
    listed = run_git(repo, "ls-tree", "-r", sha, "gates", check=False)
    if listed.returncode != 0:
        return {"status": "FAIL", "reason_code": "PIN_SNAPSHOT_TREE_MISMATCH"}
    blobs = []
    for line in listed.stdout.decode().splitlines():
        if line == "":
            continue
        meta, path = line.split("\t", 1)
        _mode, kind, oid = meta.split()
        if kind != "blob":
            return {"status": "FAIL", "reason_code": "PIN_SNAPSHOT_TREE_MISMATCH"}
        data = run_git(repo, "cat-file", "blob", oid).stdout
        blobs.append({"path": path, "blob_oid": oid, "sha256": hashlib.sha256(data).hexdigest()})
    archived = _archive_gates(repo, sha)
    proven = {item["path"]: item for item in blobs}
    if set(archived) != set(proven):
        return {"status": "FAIL", "reason_code": "PIN_SNAPSHOT_TREE_MISMATCH"}
    for path, digest in archived.items():
        if proven[path]["sha256"] != digest:
            return {"status": "FAIL", "reason_code": "PIN_SNAPSHOT_TREE_MISMATCH"}
    blobs.sort(key=lambda item: item["path"])
    return {
        "status": "OK",
        "blobs": blobs,
        "gate_tree_sha": rev_parse(repo, f"{sha}:gates"),
        "method": "git-archive",
    }


def _roles_distinct(build_candidate_sha: str, land_candidate_sha: str | None, test_base_sha: str | None) -> dict | None:
    if land_candidate_sha is not None and not is_sha40(land_candidate_sha):
        return {"status": "FAIL", "reason_code": "TAMPER_PIN_UNSET_OR_INVALID"}
    if test_base_sha is not None and not is_sha40(test_base_sha):
        return {"status": "FAIL", "reason_code": "TAMPER_PIN_UNSET_OR_INVALID"}
    named = {
        "build_candidate_sha": build_candidate_sha,
        "land_candidate_sha": land_candidate_sha,
        "test_base_sha": test_base_sha,
    }
    present = {name: value for name, value in named.items() if value is not None}
    if len(set(present.values())) != len(present):
        return {"status": "FAIL", "reason_code": "PIN_SNAPSHOT_TREE_MISMATCH", "roles": named}
    return None


def snapshot_pin_commit(
    bare: Path,
    workspace: Path,
    build_candidate_sha: str,
    *,
    land_candidate_sha: str | None = None,
    test_base_sha: str | None = None,
) -> dict:
    """Materialize a runtime pin from the build candidate's git objects.

    The worktree is not the source. Uncommitted tracked `gates/**` changes fail
    `PIN_SNAPSHOT_TREE_MISMATCH`. Untracked files are not part of the pin tree.
    """
    if not is_sha40(build_candidate_sha):
        return {"status": "FAIL", "reason_code": "TAMPER_PIN_UNSET_OR_INVALID"}
    conflict = _roles_distinct(build_candidate_sha, land_candidate_sha, test_base_sha)
    if conflict is not None:
        return conflict
    method = reject_snapshot_method("git-archive")
    if method["status"] != "OK":
        return method
    ensured = ensure_commit(workspace, build_candidate_sha)
    if ensured.get("status") != "OK" or ensured.get("sha") != build_candidate_sha:
        return {"status": "FAIL", "reason_code": str(ensured.get("reason_code") or "PIN_OBJECT_MISSING")}
    if not cat_file_commit(bare, build_candidate_sha):
        return {"status": "FAIL", "reason_code": "PIN_OBJECT_MISSING"}
    if _gates_diverged(workspace, build_candidate_sha):
        return {"status": "FAIL", "reason_code": "PIN_SNAPSHOT_TREE_MISMATCH"}
    proof = _prove_gates_blobs(bare, build_candidate_sha)
    if proof["status"] != "OK":
        return proof
    source_tree = rev_parse(bare, f"{build_candidate_sha}^{{tree}}")
    pin = run_git(
        bare,
        "commit-tree",
        source_tree,
        "-m",
        f"runtime gate pin from build candidate {build_candidate_sha}",
    ).stdout.decode().strip()
    pin_tree = rev_parse(bare, f"{pin}^{{tree}}")
    gate_tree = proof["gate_tree_sha"]
    if pin_tree != source_tree or rev_parse(bare, f"{pin}:gates") != gate_tree:
        return {"status": "FAIL", "reason_code": "PIN_SNAPSHOT_TREE_MISMATCH"}
    if pin in {build_candidate_sha, land_candidate_sha, test_base_sha}:
        return {"status": "FAIL", "reason_code": "PIN_SNAPSHOT_TREE_MISMATCH"}
    run_git(bare, "update-ref", "refs/disposable/gates-qa/pin-snapshot", pin)
    return {
        "status": "OK",
        "method": "git-archive",
        "source_commit": build_candidate_sha,
        "build_candidate_sha": build_candidate_sha,
        "land_candidate_sha": land_candidate_sha,
        "test_base_sha": test_base_sha,
        "runtime_gates_pin_sha": pin,
        "pin_tree_sha": pin_tree,
        "gate_tree_sha": gate_tree,
        "blobs": proof["blobs"],
    }


def materialize_pin_manifest(
    bare: Path,
    pin_sha: str,
    *,
    manifest_path: Path,
    extract_root: Path,
    candidate_worktree: Path,
    build_candidate_sha: str | None = None,
    land_candidate_sha: str | None = None,
    test_base_sha: str | None = None,
) -> dict:
    if object_type(bare, pin_sha) != "commit":
        raise FailClosed("PIN_OBJECT_MISSING")
    if build_candidate_sha is not None:
        conflict = _roles_distinct(build_candidate_sha, land_candidate_sha, test_base_sha)
        if conflict is not None:
            raise FailClosed(str(conflict["reason_code"]))
        if rev_parse(bare, f"{build_candidate_sha}^{{tree}}") != rev_parse(bare, f"{pin_sha}^{{tree}}"):
            raise FailClosed("PIN_SNAPSHOT_TREE_MISMATCH")
    tree = rev_parse(bare, f"{pin_sha}^{{tree}}")
    artifact = archive_sha256(bare, pin_sha)
    try:
        config = evaluate_pinned_config(bare, pin_sha)
    except InventoryError as exc:
        raise FailClosed(exc.reason_code) from exc
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True)
    data = run_git(bare, "archive", "--format=tar", pin_sha).stdout
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        archive.extractall(extract_root, filter="data")
    fields = config["config_manifest"]
    manifest = {
        "gates_pin_sha": pin_sha,
        "runtime_gates_pin_sha": pin_sha,
        "build_candidate_sha": build_candidate_sha,
        "land_candidate_sha": land_candidate_sha,
        "test_base_sha": test_base_sha,
        "source_commit": build_candidate_sha,
        "gate_tree_sha": rev_parse(bare, f"{pin_sha}:gates"),
        "pin_tree_sha": tree,
        "rule_version": fields["rule_version"],
        "artifact_digest": artifact,
        "config_digest": config["config_digest"],
        "parameters_canonical_sha256": fields["parameters_canonical_sha256"],
        "policy_config_digest": fields["policy_config_digest"],
        "protection_settings_digest": fields["protection_settings_digest"],
        "config_manifest_canonical": config["config_manifest_canonical"],
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
