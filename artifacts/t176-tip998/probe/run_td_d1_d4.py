#!/usr/bin/env python3
"""Independent TD-D1..D4 probe for tip998.

This file is tester evidence. It does not patch product code.
case_result PASS means the spec expectation for that negative held.
It is not runtime_pass, not acceptance, and not a G4 re-freeze.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import traceback
from pathlib import Path

ROOT = Path("/workspace")
OUT = ROOT / "artifacts" / "t176-tip998"
TIP = "998784b3e6cc0e6e6597cde76ce018331d924a72"
TREE = "62fd51cb0b31eeed130007201cfd36bbca081c44"
PARENT = "24d558e193be6225aa2bb71bde3a75a2f7851b78"
CFF = "cff01a57e38b16af6bc5545789949575b1cbcc3078cdf5bf3158cee4b56fd884"
CFF_BYTES = 4332
OPS_ROOT = Path("/home/box/ops-isolation/gates/source-qa-isolation-bed-2026-11-01")
HISTORICAL_CI = "41325626443"
CONTEXT_CI = "41329214806"

sys.path.insert(0, str(ROOT))

from gates.config_inventory import (  # noqa: E402
    InventoryError,
    digest_config_manifest,
    evaluate_pinned_config,
    judge_config_digest,
)
from gates.gitcmd import cat_file_commit, rev_parse, run_git  # noqa: E402
from gates.isolation_bed import (  # noqa: E402
    ensure_commit,
    reject_snapshot_method,
    snapshot_pin_commit,
)
from gates.rules import CANONICAL_SHA256  # noqa: E402
from gates.workflow_proof import (  # noqa: E402
    G4_REFROZEN,
    RUNTIME_PASS,
    historical_ci_is_refreeze_evidence,
    prove_checkout,
    workflow_privilege_or_rewrite_hits,
)


def git_out(repo: Path, *args: str) -> str:
    proc = run_git(repo, *args, check=False)
    return proc.stdout.decode().strip()


def independent_manifest_digest(manifest: dict) -> tuple[str, str]:
    keys = (
        "parameters_canonical_sha256",
        "policy_config_digest",
        "protection_settings_digest",
        "rule_version",
    )
    body = {key: manifest[key] for key in keys}
    raw = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    return hashlib.sha256(raw).hexdigest(), raw.decode("utf-8")


def forbidden_command_hits(text: str) -> list[str]:
    """Tester-side scan. Not the product helper."""
    import re

    patterns = {
        "apt": re.compile(r"(?m)^(?!\s*#).*\bapt(-get)?\b"),
        "sudo": re.compile(r"(?m)^(?!\s*#).*\bsudo\b"),
        "sysctl": re.compile(r"(?m)^(?!\s*#).*\bsysctl\b"),
        "git_merge": re.compile(r"(?m)^(?!\s*#).*\bgit\s+merge\b"),
        "git_rebase": re.compile(r"(?m)^(?!\s*#).*\bgit\s+rebase\b"),
    }
    return [name for name, pattern in patterns.items() if pattern.search(text)]


def init_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    run_git(path, "init", "-q")
    return path


def commit_file(repo: Path, rel: str, text: str, message: str) -> str:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    run_git(repo, "add", rel)
    run_git(repo, "commit", "-q", "-m", message)
    return rev_parse(repo, "HEAD")


def empty_bare(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    run_git(path.parent, "init", "--bare", "-q", str(path))
    return path


def workflow_cli(repo: Path, env_extra: dict[str, str]) -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    env["GIT_TERMINAL_PROMPT"] = "0"
    for key in list(env):
        if key.startswith("GATES_"):
            env.pop(key, None)
    for key in ("EVENT_NAME", "PR_HEAD_SHA", "PR_BASE_SHA", "TRIGGER_SHA", "CHECKOUT_REF"):
        env.pop(key, None)
    env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, "-m", "gates.workflow_proof"],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "exit": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "env": env_extra,
    }


CASES: list[dict] = []


def record(case_id: str, expectation: str, fn) -> None:
    try:
        observed = fn()
        result = observed.pop("case_result")
        reason = observed.pop("reason_code", None)
        notes = observed.pop("notes", "")
        error = None
    except Exception:
        result = "OPEN"
        reason = None
        notes = "probe exception; case not closed"
        observed = {}
        error = traceback.format_exc()
    CASES.append(
        {
            "id": case_id,
            "case_result": result,
            "expectation": expectation,
            "reason_code": reason,
            "notes": notes,
            "observed": observed,
            "error": error,
            "runtime_pass": False,
            "acceptance": False,
            "g4_refrozen": False,
            "stack_ok_is_not_pass": True,
        }
    )


def case_d1_01(bed: Path) -> dict:
    repo = init_repo(bed / "d1-01")
    commit_file(repo, "gates/mod.py", "print('one')\n", "one")
    empty_bare(bed / "d1-01-empty.git")
    run_git(repo, "remote", "add", "origin", str(bed / "d1-01-empty.git"))
    head_before = rev_parse(repo, "HEAD")
    missing = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    result = ensure_commit(repo, missing)
    head_after = rev_parse(repo, "HEAD")
    strings = [value for value in result.values() if isinstance(value, str)]
    ok = (
        result.get("status") == "FAIL"
        and result.get("reason_code") == "PIN_OBJECT_MISSING"
        and "sha" not in result
        and head_before not in strings
        and head_after == head_before
        and result != head_before
    )
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": result.get("reason_code"),
        "result": result,
        "head_before": head_before,
        "head_after": head_after,
        "returned_sha_equals_head": result.get("sha") == head_before,
        "notes": "missing 40hex on a disposable repo whose origin has no objects",
    }


def case_d1_02(bed: Path) -> dict:
    origin = init_repo(bed / "d1-02-origin")
    commit_file(origin, "gates/mod.py", "print('first')\n", "first")
    commit_file(origin, "gates/mod.py", "print('second')\n", "second")
    parent = rev_parse(origin, "HEAD^")
    tip = rev_parse(origin, "HEAD")
    shallow = bed / "d1-02-shallow"
    run_git(bed, "clone", "--depth", "1", "--quiet", f"file://{origin}", str(shallow))
    shallow_flag = git_out(shallow, "rev-parse", "--is-shallow-repository")
    parent_present_before = cat_file_commit(shallow, parent)
    empty = empty_bare(bed / "d1-02-empty.git")
    run_git(shallow, "remote", "set-url", "origin", str(empty))
    head_before = rev_parse(shallow, "HEAD")
    refs_before = git_out(shallow, "show-ref")
    result = ensure_commit(shallow, parent)
    head_after = rev_parse(shallow, "HEAD")
    parent_present_after = cat_file_commit(shallow, parent)
    ok = (
        shallow_flag == "true"
        and parent_present_before is False
        and result.get("status") == "FAIL"
        and result.get("reason_code") == "PIN_OBJECT_MISSING"
        and "sha" not in result
        and result.get("sha") not in {head_before, parent, tip}
        and head_after == head_before == tip
        and parent_present_after is False
    )
    if shallow_flag != "true" or parent_present_before:
        return {
            "case_result": "OPEN",
            "reason_code": result.get("reason_code"),
            "result": result,
            "shallow": shallow_flag,
            "parent": parent,
            "parent_present_before": parent_present_before,
            "notes": "could not build a shallow clone that still lacks the parent",
        }
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": result.get("reason_code"),
        "result": result,
        "shallow": shallow_flag,
        "parent": parent,
        "tip": tip,
        "head_before": head_before,
        "head_after": head_after,
        "refs_before": refs_before,
        "parent_present_after": parent_present_after,
        "notes": "deepen/fetch against an empty origin left the object missing and did not return HEAD",
    }


def case_d1_03(bed: Path) -> dict:
    origin = init_repo(bed / "d1-03-origin")
    commit_file(origin, "gates/mod.py", "print('first')\n", "first")
    tip = commit_file(origin, "gates/mod.py", "print('tip')\n", "tip")
    parent = rev_parse(origin, "HEAD^")
    shallow = bed / "d1-03-shallow"
    run_git(bed, "clone", "--depth", "1", "--quiet", f"file://{origin}", str(shallow))
    shallow_flag = git_out(shallow, "rev-parse", "--is-shallow-repository")
    parent_present = cat_file_commit(shallow, parent)
    tip_present = cat_file_commit(shallow, tip)
    result = ensure_commit(shallow, tip)
    ok = (
        shallow_flag == "true"
        and tip_present is True
        and parent_present is False
        and result == {"status": "OK", "sha": tip}
    )
    if shallow_flag != "true" or not tip_present:
        return {
            "case_result": "OPEN",
            "reason_code": result.get("reason_code"),
            "result": result,
            "shallow": shallow_flag,
            "tip_present": tip_present,
            "notes": "shallow clone did not contain the complete tip object",
        }
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": result.get("reason_code"),
        "result": result,
        "shallow": shallow_flag,
        "tip": tip,
        "parent_absent": parent_present is False,
        "returned_sha_equals_input": result.get("sha") == tip,
        "notes": "shallow clone whose tip object is present returns that same sha",
    }


def case_d1_04() -> dict:
    samples = ["", "abc", "998784b3", "main", "HEAD", "24d558e"]
    rows = []
    ok = True
    for value in samples:
        result = ensure_commit(ROOT, value)
        row_ok = result.get("status") == "FAIL" and result.get("reason_code") == "TAMPER_PIN_UNSET_OR_INVALID" and "sha" not in result
        ok = ok and row_ok
        rows.append({"input": value, "result": result, "held": row_ok})
    uppercase = TIP.upper()
    upper_result = ensure_commit(ROOT, uppercase)
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": "TAMPER_PIN_UNSET_OR_INVALID" if ok else "MISMATCH",
        "samples": rows,
        "uppercase_full_sha_observation": upper_result,
        "notes": "short sha, empty string, and branch/HEAD names fail closed before any fetch; uppercase noted separately",
    }


def case_d2_01(bed: Path) -> dict:
    repo = init_repo(bed / "d2-01")
    sha = commit_file(repo, "gates/mod.py", "print('tracked')\n", "build")
    untracked = repo / "gates" / "untracked.txt"
    untracked.write_text("not tracked\n", encoding="utf-8")
    proof = snapshot_pin_commit(repo, repo, sha)
    paths = {item["path"] for item in proof.get("blobs", [])}
    pin = proof.get("runtime_gates_pin_sha")
    pin_paths = []
    if isinstance(pin, str):
        listed = git_out(repo, "ls-tree", "-r", "--name-only", pin, "gates")
        pin_paths = [line for line in listed.splitlines() if line]
    source_tree = rev_parse(repo, f"{sha}^{{tree}}")
    excluded = "gates/untracked.txt" not in paths and "gates/untracked.txt" not in pin_paths
    rejected = proof.get("status") == "FAIL" and proof.get("reason_code") == "PIN_SNAPSHOT_TREE_MISMATCH"
    ok = (proof.get("status") == "OK" and excluded and proof.get("pin_tree_sha") == source_tree) or rejected
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": proof.get("reason_code") or ("EXCLUDED" if excluded else None),
        "status": proof.get("status"),
        "method": proof.get("method"),
        "blob_paths": sorted(paths),
        "pin_paths": pin_paths,
        "untracked_in_pin": "gates/untracked.txt" in paths or "gates/untracked.txt" in pin_paths,
        "pin_tree_sha": proof.get("pin_tree_sha"),
        "source_tree": source_tree,
        "notes": "untracked gates file stayed out of the pin tree" if excluded and proof.get("status") == "OK" else "rejection path",
    }


def case_d2_02(bed: Path) -> dict:
    repo = init_repo(bed / "d2-02")
    sha = commit_file(repo, "gates/mod.py", "print('tracked')\n", "build")
    (repo / "gates" / "mod.py").write_text("print('dirty')\n", encoding="utf-8")
    diff = git_out(repo, "diff", "--", "gates/mod.py")
    proof = snapshot_pin_commit(repo, repo, sha)
    ref = run_git(repo, "rev-parse", "--verify", "refs/disposable/gates-qa/pin-snapshot", check=False)
    ok = (
        proof.get("status") == "FAIL"
        and proof.get("reason_code") == "PIN_SNAPSHOT_TREE_MISMATCH"
        and ref.returncode != 0
        and "print('dirty')" in diff
    )
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": proof.get("reason_code"),
        "result": {key: proof.get(key) for key in ("status", "reason_code", "method", "runtime_gates_pin_sha")},
        "pin_ref_created": ref.returncode == 0,
        "notes": "uncommitted tracked gates edit rejected; pin ref not written",
    }


def case_d2_03(bed: Path) -> dict:
    repo = init_repo(bed / "d2-03")
    base = commit_file(repo, "gates/mod.py", "print('base')\n", "base")
    commit_file(repo, "gates/other.py", "print('other')\n", "more")
    build = rev_parse(repo, "HEAD")
    land = commit_file(repo, "README.txt", "land\n", "land")
    proof = snapshot_pin_commit(repo, repo, build, land_candidate_sha=land, test_base_sha=base)
    listed = run_git(repo, "ls-tree", "-r", build, "gates").stdout.decode().splitlines()
    expected = {}
    for line in listed:
        if line == "":
            continue
        meta, path = line.split("\t", 1)
        oid = meta.split()[2]
        blob = run_git(repo, "cat-file", "blob", oid).stdout
        expected[path] = {"blob_oid": oid, "sha256": hashlib.sha256(blob).hexdigest()}
    actual = {item["path"]: {"blob_oid": item["blob_oid"], "sha256": item["sha256"]} for item in proof.get("blobs", [])}
    archive = run_git(repo, "archive", "--format=tar", build, "gates")
    import io
    import tarfile

    archived = {}
    with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name[2:] if member.name.startswith("./") else member.name
            extracted = tar.extractfile(member)
            archived[name] = hashlib.sha256(extracted.read()).hexdigest()
    pin = proof.get("runtime_gates_pin_sha")
    pin_gate = rev_parse(repo, f"{pin}:gates") if isinstance(pin, str) else ""
    ok = (
        proof.get("status") == "OK"
        and proof.get("method") == "git-archive"
        and proof.get("source_commit") == build
        and proof.get("gate_tree_sha") == rev_parse(repo, f"{build}:gates")
        and actual == expected
        and set(archived) == set(expected)
        and all(archived[path] == expected[path]["sha256"] for path in expected)
        and pin_gate == proof.get("gate_tree_sha")
        and pin not in {build, land, base}
    )
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": proof.get("reason_code") or "MATCH",
        "method": proof.get("method"),
        "source_commit": proof.get("source_commit"),
        "gate_tree_sha": proof.get("gate_tree_sha"),
        "expected_gate_tree": rev_parse(repo, f"{build}:gates"),
        "blob_count": len(actual),
        "sets_equal": set(actual) == set(expected) == set(archived),
        "oid_and_sha256_equal": actual == expected,
        "roles": {
            "build": build,
            "land": land,
            "test_base": base,
            "pin": pin,
        },
        "notes": "archive file set and ls-tree oid/sha256 recomputed outside the snapshot helper",
    }


def case_d2_04() -> dict:
    rejected = reject_snapshot_method("workspace-copytree")
    source = (ROOT / "gates" / "isolation_bed.py").read_text(encoding="utf-8")
    copytree_calls = "copytree(" in source
    allowed = reject_snapshot_method("git-archive")
    ok = (
        rejected.get("status") == "FAIL"
        and rejected.get("reason_code") == "PIN_SNAPSHOT_TREE_MISMATCH"
        and copytree_calls is False
        and allowed.get("status") == "OK"
    )
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": rejected.get("reason_code"),
        "reject_result": rejected,
        "snapshot_source_contains_copytree_call": copytree_calls,
        "git_archive_method": allowed,
        "notes": "workspace-copytree is a spec-check failure; octo/backup.py is outside this snapshot path and was not used",
    }


def case_d3_01() -> dict:
    fresh = evaluate_pinned_config(ROOT, TIP)
    judged = judge_config_digest(CANONICAL_SHA256, fresh["config_manifest"])
    own_digest, own_text = independent_manifest_digest(fresh["config_manifest"])
    ok = (
        judged == {"status": "FAIL", "reason_code": "CONFIG_DIGEST_INCOMPLETE"}
        and fresh["config_digest"] != CANONICAL_SHA256
        and fresh["config_manifest"]["parameters_canonical_sha256"] == CANONICAL_SHA256
        and own_digest == fresh["config_digest"]
        and own_digest != CANONICAL_SHA256
    )
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": judged.get("reason_code"),
        "judge": judged,
        "config_digest": fresh["config_digest"],
        "independent_digest": own_digest,
        "manifest": fresh["config_manifest"],
        "manifest_canonical": own_text,
        "cff_equals_config_digest": fresh["config_digest"] == CANONICAL_SHA256,
        "notes": "presenting the cff file hash as config_digest fails; recomputed manifest digest differs",
    }


def case_d3_02() -> dict:
    fresh = evaluate_pinned_config(ROOT, TIP)
    mutated = dict(fresh["config_manifest"])
    mutated["protection_settings_digest"] = "ab" * 32
    changed = digest_config_manifest(mutated)
    own_changed, _raw = independent_manifest_digest(mutated)
    ok = changed != fresh["config_digest"] and own_changed == changed and own_changed != fresh["config_digest"]
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": "DIGEST_CHANGED" if ok else "UNCHANGED",
        "original": fresh["config_digest"],
        "changed": changed,
        "independent_changed": own_changed,
        "protection_settings_digest": fresh["config_manifest"]["protection_settings_digest"],
        "mutated_protection_settings_digest": mutated["protection_settings_digest"],
        "notes": "one manifest field change changes config_digest; digest recomputed with hashlib",
    }


def case_d3_03() -> dict:
    path = ROOT / "gates" / "policy" / "GATES-PARAMETERS-CANONICAL.txt"
    data = path.read_bytes()
    blob = run_git(ROOT, "show", f"{TIP}:gates/policy/GATES-PARAMETERS-CANONICAL.txt").stdout
    digest = hashlib.sha256(data).hexdigest()
    blob_digest = hashlib.sha256(blob).hexdigest()
    ok = len(data) == CFF_BYTES and digest == CFF and data == blob and blob_digest == CFF
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": "CFF_UNCHANGED" if ok else "CFF_MISMATCH",
        "bytes": len(data),
        "sha256": digest,
        "head_blob_sha256": blob_digest,
        "worktree_equals_head_blob": data == blob,
        "notes": "canonical parameter file bytes were not rewritten on this tip",
    }


def case_d3_04() -> dict:
    fresh = evaluate_pinned_config(ROOT, TIP)
    broken = dict(fresh["config_manifest"])
    del broken["rule_version"]
    try:
        digest_config_manifest(broken)
        raised = None
    except InventoryError as exc:
        raised = exc.reason_code
    judged = judge_config_digest(fresh["config_digest"], broken)
    ok = raised == "CONFIG_DIGEST_INCOMPLETE" and judged.get("status") == "FAIL" and judged.get("reason_code") == "CONFIG_DIGEST_INCOMPLETE"
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": raised,
        "judge": judged,
        "notes": "manifest without rule_version is CONFIG_DIGEST_INCOMPLETE",
    }


def case_d4_01(bed: Path) -> dict:
    repo = init_repo(bed / "d4-01")
    base = commit_file(repo, "README.txt", "base\n", "base")
    run_git(repo, "branch", "candidate")
    run_git(repo, "checkout", "-q", "candidate")
    tip = commit_file(repo, "gates/mod.py", "print('tip')\n", "tip")
    run_git(repo, "checkout", "-q", "master" if cat_file_commit(repo, "master") else "main")
    # init defaults to master or main depending on git. Detect.
    return _d4_01_merge(repo, base, tip)


def _current_branch(repo: Path) -> str:
    return git_out(repo, "branch", "--show-current") or "HEAD"


def _d4_01_merge(repo: Path, base: str, tip: str) -> dict:
    # Rebuild explicitly so the default branch name cannot skew the merge.
    shutil.rmtree(repo)
    repo = init_repo(repo)
    run_git(repo, "checkout", "-q", "-b", "base")
    base = commit_file(repo, "README.txt", "base\n", "base")
    run_git(repo, "checkout", "-q", "-b", "candidate")
    tip = commit_file(repo, "gates/mod.py", "print('tip')\n", "tip")
    tip_tree = rev_parse(repo, "HEAD^{tree}")
    run_git(repo, "checkout", "-q", "base")
    commit_file(repo, "OTHER.txt", "side\n", "side")
    run_git(repo, "merge", "--no-ff", "-q", "-m", "merge ref", "candidate")
    merge = rev_parse(repo, "HEAD")
    merge_tree = rev_parse(repo, "HEAD^{tree}")
    run_git(repo, "update-ref", "refs/pull/12/merge", merge)
    direct = prove_checkout(
        expected_sha=tip,
        actual_head=merge,
        expected_tree=tip_tree,
        actual_tree=merge_tree,
        base_sha=base,
        checkout_ref="refs/pull/12/merge",
        metadata_head_sha=tip,
    )
    cli_metadata = workflow_cli(
        repo,
        {
            "EVENT_NAME": "workflow_dispatch",
            "TRIGGER_SHA": tip,
            "CHECKOUT_REF": tip,
        },
    )
    cli_pull = workflow_cli(
        repo,
        {
            "EVENT_NAME": "pull_request",
            "PR_HEAD_SHA": tip,
            "PR_BASE_SHA": base,
            "TRIGGER_SHA": merge,
            "CHECKOUT_REF": merge,
        },
    )
    ok = (
        merge != tip
        and merge_tree != tip_tree
        and direct.get("status") == "FAIL"
        and direct.get("reason_code") == "WORKFLOW_HEAD_UNPROVEN"
        and direct.get("proven") is False
        and cli_metadata["exit"] == 1
        and "WORKFLOW_HEAD_UNPROVEN" in cli_metadata["stdout"]
        and "WORKFLOW_HEAD_PROVEN" not in cli_metadata["stdout"]
        and cli_pull["exit"] == 1
        and "WORKFLOW_HEAD_UNPROVEN" in cli_pull["stdout"]
        and "WORKFLOW_HEAD_PROVEN" not in cli_pull["stdout"]
    )
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": direct.get("reason_code"),
        "tip": tip,
        "merge": merge,
        "trees_differ": merge_tree != tip_tree,
        "prove_checkout": direct,
        "cli_metadata_claims_tip": cli_metadata,
        "cli_pull_request_merge_ref": cli_pull,
        "notes": "merge-ref workspace was not treated as the tip on metadata head_sha alone",
    }


def case_d4_02(bed: Path) -> dict:
    clone = bed / "d4-02-checkout"
    run_git(ROOT, "clone", "--shared", "--quiet", str(ROOT), str(clone))
    run_git(clone, "checkout", "--detach", "--quiet", TIP)
    head = rev_parse(clone, "HEAD")
    tree = rev_parse(clone, "HEAD^{tree}")
    parent = rev_parse(clone, "HEAD^")
    cli = workflow_cli(
        clone,
        {
            "EVENT_NAME": "workflow_dispatch",
            "TRIGGER_SHA": TIP,
            "CHECKOUT_REF": TIP,
        },
    )
    library = prove_checkout(
        expected_sha=TIP,
        actual_head=head,
        expected_tree=TREE,
        actual_tree=tree,
        base_sha=parent,
        checkout_ref=TIP,
        metadata_head_sha=CONTEXT_CI,
    )
    ok = (
        head == TIP
        and tree == TREE
        and parent == PARENT
        and cli["exit"] == 0
        and "WORKFLOW_HEAD_PROVEN" in cli["stdout"]
        and f"actual_head={TIP}" in cli["stdout"]
        and f"actual_tree={TREE}" in cli["stdout"]
        and f"base_sha={PARENT}" in cli["stdout"]
        and f"checkout_ref={TIP}" in cli["stdout"]
        and library.get("status") == "OK"
        and library.get("proven") is True
        and library.get("base_sha") == PARENT
    )
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": "MATCH" if ok else library.get("reason_code"),
        "head": head,
        "tree": tree,
        "base_sha": parent,
        "cli": cli,
        "library": library,
        "notes": "explicit SHA checkout of tip998; HEAD, tree, and base recorded",
    }


def case_d4_03() -> dict:
    historical = historical_ci_is_refreeze_evidence(HISTORICAL_CI)
    context = historical_ci_is_refreeze_evidence(CONTEXT_CI)
    ok = historical is False and context is False and G4_REFROZEN is False and RUNTIME_PASS is False
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": "NOT_REFREEZE_EVIDENCE" if ok else "ADOPTED",
        "historical_ci": HISTORICAL_CI,
        "historical_is_refreeze_evidence": historical,
        "context_ci": CONTEXT_CI,
        "context_ci_is_refreeze_evidence": context,
        "module_G4_REFROZEN": G4_REFROZEN,
        "module_RUNTIME_PASS": RUNTIME_PASS,
        "tester_adopts_historical_ci": False,
        "tester_adopts_context_ci_as_acceptance": False,
        "notes": "41325626443 is not re-freeze evidence; 41329214806 success is context only",
    }


def case_d4_04() -> dict:
    parent_tree = rev_parse(ROOT, f"{PARENT}^{{tree}}")
    result = prove_checkout(
        expected_sha=TIP,
        actual_head=TIP,
        expected_tree=parent_tree,
        actual_tree=TREE,
        base_sha=PARENT,
        checkout_ref=TIP,
    )
    ok = (
        parent_tree != TREE
        and result.get("status") == "FAIL"
        and result.get("reason_code") == "WORKFLOW_HEAD_UNPROVEN"
        and result.get("proven") is False
    )
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": result.get("reason_code"),
        "expected_tree": parent_tree,
        "actual_tree": TREE,
        "result": result,
        "notes": "HEAD matches tip998 and HEAD^{tree} does not match the expected tree",
    }


def case_d4_05() -> dict:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    product_hits = workflow_privilege_or_rewrite_hits(text)
    tester_hits = forbidden_command_hits(text)
    injected = "\n".join(
        [
            "sudo apt-get install git",
            "sysctl -w kernel.unprivileged_userns_clone=1",
            "git merge origin/main",
            "git rebase main",
        ]
    )
    injected_product = workflow_privilege_or_rewrite_hits(injected)
    injected_tester = forbidden_command_hits(injected)
    has_ref = "ref:" in text and "fetch-depth: 0" in text and "gates.workflow_proof" in text
    ok = product_hits == [] and tester_hits == [] and injected_product != [] and injected_tester != [] and has_ref
    return {
        "case_result": "PASS" if ok else "FAIL",
        "reason_code": "SPEC_CHECK_FAIL_ON_INJECTED" if ok else "REVIEW",
        "candidate_product_hits": product_hits,
        "candidate_tester_hits": tester_hits,
        "injected_spec_check": "FAIL" if injected_product and injected_tester else "NOT_FAIL",
        "injected_product_hits": injected_product,
        "injected_tester_hits": injected_tester,
        "candidate_has_explicit_ref_and_proof": has_ref,
        "notes": "candidate ci.yml has no apt/sudo/sysctl/git merge/git rebase; injected additions fail the spec check",
    }


def main() -> int:
    head = rev_parse(ROOT, "HEAD")
    tree = rev_parse(ROOT, "HEAD^{tree}")
    parent = rev_parse(ROOT, "HEAD^")
    if (head, tree, parent) != (TIP, TREE, PARENT):
        print(json.dumps({"error": "tip binding mismatch", "head": head, "tree": tree, "parent": parent}))
        return 2
    bed = Path("/tmp/tip998-td-bed")
    if bed.exists():
        shutil.rmtree(bed)
    bed.mkdir(parents=True)
    record("TD-D1-01", "FAIL PIN_OBJECT_MISSING; return value is not HEAD", lambda: case_d1_01(bed))
    record("TD-D1-02", "shallow clone still missing after deepen/fetch → FAIL PIN_OBJECT_MISSING; do not return HEAD/tag/branch", lambda: case_d1_02(bed))
    record("TD-D1-03", "shallow clone that contains the full tip → OK and sha equals the input", lambda: case_d1_03(bed))
    record("TD-D1-04", "short sha / empty / branch name → FAIL TAMPER_PIN_UNSET_OR_INVALID", case_d1_04)
    record("TD-D2-01", "untracked gates file stays out of the pin tree, or FAIL PIN_SNAPSHOT_TREE_MISMATCH", lambda: case_d2_01(bed))
    record("TD-D2-02", "uncommitted tracked gates edit → FAIL PIN_SNAPSHOT_TREE_MISMATCH", lambda: case_d2_02(bed))
    record("TD-D2-03", "git archive of build_candidate_sha matches gate_tree_sha and every blob oid+sha256; sets equal", lambda: case_d2_03(bed))
    record("TD-D2-04", "method=workspace-copytree → spec check FAIL", case_d2_04)
    record("TD-D3-01", "config_digest equal to the cff hash → FAIL CONFIG_DIGEST_INCOMPLETE", case_d3_01)
    record("TD-D3-02", "changing protection_settings_digest changes config_digest", case_d3_02)
    record("TD-D3-03", "cff bytes remain cff01a57… and 4332 bytes", case_d3_03)
    record("TD-D3-04", "manifest without rule_version → FAIL CONFIG_DIGEST_INCOMPLETE", case_d3_04)
    record("TD-D4-01", "merge-ref workspace is not proven by metadata head_sha; WORKFLOW_HEAD_UNPROVEN", lambda: case_d4_01(bed))
    record("TD-D4-02", "explicit SHA checkout asserts HEAD and tree; base_sha recorded", lambda: case_d4_02(bed))
    record("TD-D4-03", "CI 41325626443 is not G4 re-freeze evidence", case_d4_03)
    record("TD-D4-04", "HEAD^{tree} mismatch → FAIL WORKFLOW_HEAD_UNPROVEN", case_d4_04)
    record("TD-D4-05", "workflow text that adds apt/sudo/sysctl or git merge/rebase fails the spec check", case_d4_05)
    end_head = rev_parse(ROOT, "HEAD")
    end_tree = rev_parse(ROOT, "HEAD^{tree}")
    counts = {"PASS": 0, "FAIL": 0, "OPEN": 0}
    for case in CASES:
        counts[case["case_result"]] = counts.get(case["case_result"], 0) + 1
    summary = {
        "tip": end_head,
        "tree": end_tree,
        "parent": parent,
        "tip_unchanged": end_head == TIP and end_tree == TREE,
        "ops_root": str(OPS_ROOT),
        "ops_root_visible": OPS_ROOT.exists(),
        "capability_gap": ["OPS_BED_BOX_LOCAL_ONLY", "PIN_NOT_PREMATERIALIZED"],
        "real_iso_authority": "BOX",
        "real_iso_cloud": "NOT_EXECUTED_FORMAL_SEAL",
        "twin_supplementary": False,
        "runtime_pass": False,
        "g4_refrozen": False,
        "merge": False,
        "counts": counts,
        "cases": CASES,
    }
    raw_dir = OUT / "logs"
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "td-d1-d4-observations.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    decisions = OUT / "decisions"
    decisions.mkdir(parents=True, exist_ok=True)
    for case in CASES:
        (decisions / f"{case['id']}.json").write_text(json.dumps(case, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"counts": counts, "tip_unchanged": summary["tip_unchanged"], "ops_root_visible": summary["ops_root_visible"], "ids": [c["id"] + ":" + c["case_result"] for c in CASES]}, indent=2))
    return 0 if counts["FAIL"] == 0 and counts["OPEN"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
