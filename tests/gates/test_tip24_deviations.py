"""Negative cases for SPEC-GATES-TIP24-DEVIATIONS-v1. STACK_OK_BUILDER only.

Not an independent acceptance and not a G4 re-freeze.
"""

from __future__ import annotations

import hashlib
import inspect
from pathlib import Path

import pytest

from gates.config_inventory import (
    CANONICAL_SHA256,
    InventoryError,
    config_manifest_bytes,
    digest_config_manifest,
    evaluate_pinned_config,
    judge_config_digest,
)
from gates.gitcmd import cat_file_commit, rev_parse, run_git
from gates.isolation_bed import (
    HISTORICAL_D501_TIP,
    ensure_commit,
    reject_snapshot_method,
    resolve_tip_binding,
    snapshot_pin_commit,
)
from gates.rules import CANONICAL_BYTES
from gates.workflow_proof import (
    G4_REFROZEN,
    HISTORICAL_CI_RUN,
    RUNTIME_PASS,
    historical_ci_is_refreeze_evidence,
    prove_checkout,
    workflow_privilege_or_rewrite_hits,
)

DEADBEEF = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
ROOT = Path(__file__).resolve().parents[2]


def _init(path: Path) -> Path:
    path.mkdir()
    run_git(path, "init", "-q")
    return path


def _commit_file(repo: Path, rel: str, text: str, message: str) -> str:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    run_git(repo, "add", rel)
    run_git(repo, "commit", "-q", "-m", message)
    return rev_parse(repo, "HEAD")


def _gates_repo(path: Path, text: str = "print('tracked')\n") -> tuple[Path, str]:
    repo = _init(path)
    sha = _commit_file(repo, "gates/mod.py", text, "build")
    return repo, sha


def test_td_d1_01_missing_object_does_not_return_head(tmp_path: Path):
    repo, _sha = _gates_repo(tmp_path / "repo")
    head = rev_parse(repo, "HEAD")
    result = ensure_commit(repo, DEADBEEF)
    assert result["status"] == "FAIL"
    assert result["reason_code"] == "PIN_OBJECT_MISSING"
    assert "sha" not in result
    assert result.get("sha") != head
    assert rev_parse(repo, "HEAD") == head


def test_td_d1_02_shallow_clone_still_missing_after_fetch(tmp_path: Path):
    origin, _sha = _gates_repo(tmp_path / "origin")
    _commit_file(origin, "gates/mod.py", "print('second')\n", "second")
    parent = rev_parse(origin, "HEAD^")
    shallow = tmp_path / "shallow"
    run_git(origin, "clone", "--depth", "1", "--no-local", "--quiet", str(origin), str(shallow))
    assert cat_file_commit(shallow, parent) is False
    empty = tmp_path / "empty.git"
    run_git(tmp_path, "init", "--bare", "-q", str(empty))
    run_git(shallow, "remote", "set-url", "origin", str(empty))
    head = rev_parse(shallow, "HEAD")
    result = ensure_commit(shallow, parent)
    assert result["status"] == "FAIL"
    assert result["reason_code"] == "PIN_OBJECT_MISSING"
    assert "sha" not in result
    assert result.get("sha") not in {head, parent}
    assert rev_parse(shallow, "HEAD") == head


def test_td_d1_03_present_full_sha_returns_the_same_bytes(tmp_path: Path):
    repo, sha = _gates_repo(tmp_path / "repo")
    result = ensure_commit(repo, sha)
    assert result == {"status": "OK", "sha": sha}


def test_td_d1_04_short_empty_and_branch_names_are_invalid():
    repo = ROOT
    for value in ("", "abc", "main", "HEAD", "24d558e", "d50148d9"):
        result = ensure_commit(repo, value)
        assert result["status"] == "FAIL"
        assert result["reason_code"] == "TAMPER_PIN_UNSET_OR_INVALID"
        assert "sha" not in result


def test_td_d1_source_has_no_head_fallback():
    source = inspect.getsource(ensure_commit)
    assert "HEAD" not in source
    assert "rev_parse" not in source


def test_tip_binding_is_explicit_and_not_historical_d501(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GATES_TIP_BINDING", raising=False)
    missing = resolve_tip_binding()
    assert missing["status"] == "FAIL"
    assert missing["reason_code"] == "PIN_OBJECT_MISSING"
    assert missing.get("sha") != HISTORICAL_D501_TIP
    named = "24d558e193be6225aa2bb71bde3a75a2f7851b78"
    assert resolve_tip_binding(named) == {"status": "OK", "sha": named, "source": "explicit"}


def test_td_d2_01_untracked_file_stays_out_of_the_pin(tmp_path: Path):
    repo, sha = _gates_repo(tmp_path / "repo")
    (repo / "gates" / "untracked.txt").write_text("not tracked\n", encoding="utf-8")
    proof = snapshot_pin_commit(repo, repo, sha)
    assert proof["status"] == "OK"
    paths = {item["path"] for item in proof["blobs"]}
    assert "gates/untracked.txt" not in paths
    assert proof["pin_tree_sha"] == rev_parse(repo, f"{sha}^{{tree}}")


def test_td_d2_02_uncommitted_tracked_edit_is_rejected(tmp_path: Path):
    repo, sha = _gates_repo(tmp_path / "repo")
    (repo / "gates" / "mod.py").write_text("print('dirty')\n", encoding="utf-8")
    proof = snapshot_pin_commit(repo, repo, sha)
    assert proof["status"] == "FAIL"
    assert proof["reason_code"] == "PIN_SNAPSHOT_TREE_MISMATCH"
    assert run_git(repo, "rev-parse", "--verify", "refs/disposable/gates-qa/pin-snapshot", check=False).returncode != 0


def test_td_d2_03_archive_blobs_match_the_build_commit(tmp_path: Path):
    repo, _sha = _gates_repo(tmp_path / "repo")
    _commit_file(repo, "gates/other.py", "print('other')\n", "more")
    land = _commit_file(repo, "README.txt", "land\n", "land")
    build = rev_parse(repo, f"{land}^")
    base = rev_parse(repo, f"{build}^")
    proof = snapshot_pin_commit(repo, repo, build, land_candidate_sha=land, test_base_sha=base)
    assert proof["status"] == "OK"
    assert proof["method"] == "git-archive"
    assert proof["source_commit"] == build
    assert proof["gate_tree_sha"] == rev_parse(repo, f"{build}:gates")
    assert proof["pin_tree_sha"] == rev_parse(repo, f"{build}^{{tree}}")
    assert proof["runtime_gates_pin_sha"] not in {build, land, base}
    listed = run_git(repo, "ls-tree", "-r", build, "gates").stdout.decode().splitlines()
    expected = {}
    for line in listed:
        meta, path = line.split("\t", 1)
        oid = meta.split()[2]
        blob = run_git(repo, "cat-file", "blob", oid).stdout
        expected[path] = (oid, hashlib.sha256(blob).hexdigest())
    actual = {item["path"]: (item["blob_oid"], item["sha256"]) for item in proof["blobs"]}
    assert actual == expected


def test_td_d2_04_workspace_copytree_method_is_rejected():
    assert reject_snapshot_method("workspace-copytree")["status"] == "FAIL"
    assert reject_snapshot_method("workspace-copytree")["reason_code"] == "PIN_SNAPSHOT_TREE_MISMATCH"
    source = (ROOT / "gates" / "isolation_bed.py").read_text(encoding="utf-8")
    assert "copytree(" not in source


def test_td_d3_01_canonical_file_hash_is_not_the_config_digest():
    fresh = evaluate_pinned_config(ROOT, rev_parse(ROOT, "HEAD"))
    judged = judge_config_digest(CANONICAL_SHA256, fresh["config_manifest"])
    assert judged == {"status": "FAIL", "reason_code": "CONFIG_DIGEST_INCOMPLETE"}
    assert fresh["config_digest"] != CANONICAL_SHA256
    assert fresh["config_manifest"]["parameters_canonical_sha256"] == CANONICAL_SHA256


def test_td_d3_02_protection_change_changes_the_digest():
    fresh = evaluate_pinned_config(ROOT, rev_parse(ROOT, "HEAD"))
    mutated = dict(fresh["config_manifest"])
    mutated["protection_settings_digest"] = "ab" * 32
    assert digest_config_manifest(mutated) != fresh["config_digest"]


def test_td_d3_03_canonical_bytes_stay_cff():
    data = (ROOT / "gates" / "policy" / "GATES-PARAMETERS-CANONICAL.txt").read_bytes()
    assert len(data) == CANONICAL_BYTES == 4332
    assert hashlib.sha256(data).hexdigest() == CANONICAL_SHA256


def test_td_d3_04_missing_rule_version_is_incomplete():
    fresh = evaluate_pinned_config(ROOT, rev_parse(ROOT, "HEAD"))
    broken = dict(fresh["config_manifest"])
    del broken["rule_version"]
    with pytest.raises(InventoryError) as caught:
        digest_config_manifest(broken)
    assert caught.value.reason_code == "CONFIG_DIGEST_INCOMPLETE"


def test_td_d3_manifest_bytes_are_canonical():
    fresh = evaluate_pinned_config(ROOT, rev_parse(ROOT, "HEAD"))
    raw = config_manifest_bytes(fresh["config_manifest"])
    assert raw.endswith(b"\n")
    assert b" " not in raw
    assert hashlib.sha256(raw).hexdigest() == fresh["config_digest"]
    assert fresh["config_manifest_canonical"].encode("utf-8") == raw


def test_td_d4_01_metadata_head_sha_does_not_prove_a_merge_workspace():
    tip = "24d558e193be6225aa2bb71bde3a75a2f7851b78"
    result = prove_checkout(
        expected_sha=tip,
        actual_head="a" * 40,
        expected_tree="b" * 40,
        actual_tree="c" * 40,
        base_sha="d" * 40,
        checkout_ref="",
        metadata_head_sha=tip,
    )
    assert result["status"] == "FAIL"
    assert result["reason_code"] == "WORKFLOW_HEAD_UNPROVEN"
    assert result["proven"] is False


def test_td_d4_02_explicit_sha_records_head_tree_and_base(tmp_path: Path):
    repo, sha = _gates_repo(tmp_path / "repo")
    tree = rev_parse(repo, "HEAD^{tree}")
    result = prove_checkout(
        expected_sha=sha,
        actual_head=rev_parse(repo, "HEAD"),
        expected_tree=tree,
        actual_tree=rev_parse(repo, "HEAD^{tree}"),
        base_sha="5443c9b4dde7fc208a0a72457c87904650829f77",
        checkout_ref=sha,
        metadata_head_sha="f" * 40,
    )
    assert result["status"] == "OK"
    assert result["proven"] is True
    assert result["actual_head"] == sha
    assert result["actual_tree"] == tree
    assert result["base_sha"] == "5443c9b4dde7fc208a0a72457c87904650829f77"


def test_td_d4_03_historical_ci_is_not_refreeze_evidence():
    assert historical_ci_is_refreeze_evidence(HISTORICAL_CI_RUN) is False
    assert historical_ci_is_refreeze_evidence("41325626443") is False
    assert G4_REFROZEN is False
    assert RUNTIME_PASS is False


def test_td_d4_04_tree_mismatch_is_unproven():
    sha = "a" * 40
    result = prove_checkout(
        expected_sha=sha,
        actual_head=sha,
        expected_tree="b" * 40,
        actual_tree="c" * 40,
        base_sha="d" * 40,
        checkout_ref=sha,
    )
    assert result["status"] == "FAIL"
    assert result["reason_code"] == "WORKFLOW_HEAD_UNPROVEN"


def test_td_d4_05_workflow_has_no_privilege_or_rewrite_commands():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert workflow_privilege_or_rewrite_hits(text) == []
    assert "ref:" in text
    assert "fetch-depth: 0" in text
    assert "gates.workflow_proof" in text
    assert workflow_privilege_or_rewrite_hits("sudo apt-get install git\n")
    assert workflow_privilege_or_rewrite_hits("sysctl -w kernel.unprivileged_userns_clone=1\n")
    assert workflow_privilege_or_rewrite_hits("git merge origin/main\n")
    assert workflow_privilege_or_rewrite_hits("git rebase main\n")
    proof = (ROOT / "gates" / "workflow_proof.py").read_text(encoding="utf-8")
    assert "HEAD^{tree}" in proof
    assert "WORKFLOW_HEAD_UNPROVEN" in proof
