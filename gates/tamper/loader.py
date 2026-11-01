"""External pin loader. Never falls back to tag, HEAD, worktree, or a candidate pin."""

from __future__ import annotations

import importlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from gates.gitcmd import archive_sha256, object_type, rev_parse, show_bytes
from gates.rules import RULES, RULE_VERSION, RuleSet
from gates.types import failed, is_sha40, make_result, passed, sha256_hex

DEFAULT_MANIFEST_PATH = Path(__file__).resolve().parent.parent / "loader" / "default_manifest.json"
GATES_PIN_SHA = "UNSET_FAIL_CLOSED"


@dataclass(frozen=True)
class PinnedRuntime:
    gates_pin_sha: str
    gate_tree_sha: str
    rule_version: str
    artifact_digest: str
    config_digest: str
    rules: RuleSet
    source: str = "external_pin"


@dataclass(frozen=True)
class PinLoad:
    ok: bool
    runtime: PinnedRuntime | None
    result: object


def load_default_manifest() -> dict:
    return json.loads(DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8"))


def _record_field(record: object, name: str):
    if isinstance(record, dict):
        return record.get(name)
    return getattr(record, name, None)


def load_pin(
    external_manifest: dict | None = None,
    *,
    object_store=None,
    candidate_claimed_pin: str | None = None,
    head_sha: str | None = None,
    tags: dict | None = None,
    candidate_sha: str = "0" * 40,
    base_sha: str = "0" * 40,
    task_id: str | None = None,
    rule_version: str = RULE_VERSION,
    rules: RuleSet | None = None,
    pin_loadpath: str | Path | None = None,
    manifest_path: str | Path | None = None,
    candidate_worktree: str | Path | None = None,
    git_repo: str | Path | None = None,
):
    """Load a readonly runtime from an external manifest.

    `candidate_claimed_pin`, `head_sha`, and `tags` are accepted only so callers
    can prove they are ignored. They are never resolved.
    """
    rules = rules or RULES
    manifest = load_default_manifest() if external_manifest is None else external_manifest
    ignored = [
        "candidate_claimed_pin",
        "head_sha",
        "tags",
        "branch_head",
        "worktree",
        "candidate_self_reported_pin",
    ]
    base_details = {
        "fallback_used": False,
        "consulted": ["external_manifest.gates_pin_sha"],
        "ignored": ignored,
        "candidate_claimed_pin_ignored": candidate_claimed_pin,
        "head_sha_ignored": head_sha,
        "tags_ignored": sorted(tags) if isinstance(tags, dict) else [],
        "worktree_consulted": False,
        "loaded_from": None,
    }

    def reject(pin_class: str, **extra):
        details = dict(base_details)
        details["pin_value_class"] = pin_class
        details.update(extra)
        result = make_result(
            gate="tamper",
            decision="REJECT",
            reason_code="TAMPER_PIN_UNSET_OR_INVALID",
            candidate_sha=candidate_sha,
            base_sha=base_sha,
            rule_version=rule_version,
            task_id=task_id,
            checks=[failed("pin_load", "TAMPER_PIN_UNSET_OR_INVALID", pin_value_class=pin_class)],
            details=details,
            rule_digest=rules.digest,
        )
        return PinLoad(False, None, result)

    if not isinstance(manifest, dict):
        return reject("missing")
    if pin_loadpath is not None:
        return _load_real_pin(
            manifest,
            pin_loadpath=Path(pin_loadpath),
            manifest_path=Path(manifest_path) if manifest_path is not None else None,
            candidate_worktree=Path(candidate_worktree) if candidate_worktree is not None else None,
            git_repo=Path(git_repo) if git_repo is not None else None,
            candidate_sha=candidate_sha,
            base_sha=base_sha,
            task_id=task_id,
            rule_version=rule_version,
            ignored=ignored,
            candidate_claimed_pin=candidate_claimed_pin,
            head_sha=head_sha,
            tags=tags,
        )
    pin = manifest.get("gates_pin_sha")
    if not is_sha40(pin):
        pin_class = "unset" if pin in (None, "", GATES_PIN_SHA) else "invalid_format"
        return reject(pin_class)
    if object_store is None or not hasattr(object_store, "lookup"):
        return reject("object_missing", lookup_attempted=False)
    record = object_store.lookup(pin)
    if record is None:
        return reject("object_missing", lookup_sha=pin)
    if _record_field(record, "object_type") != "commit":
        return reject("not_commit", lookup_sha=pin, object_type=_record_field(record, "object_type"))
    mismatches = []
    if _record_field(record, "tree_sha") != manifest.get("gate_tree_sha"):
        mismatches.append("tree")
    if _record_field(record, "artifact_digest") != manifest.get("artifact_digest"):
        mismatches.append("artifact")
    if _record_field(record, "config_digest") != manifest.get("config_digest"):
        mismatches.append("config")
    if manifest.get("rule_version") != rule_version:
        mismatches.append("rule_version")
    if mismatches:
        return reject("digest_mismatch", lookup_sha=pin, mismatches=mismatches)
    runtime = PinnedRuntime(
        gates_pin_sha=pin,
        gate_tree_sha=manifest["gate_tree_sha"],
        rule_version=rule_version,
        artifact_digest=manifest["artifact_digest"],
        config_digest=manifest["config_digest"],
        rules=rules,
        source="external_pin",
    )
    details = dict(base_details)
    details.update(
        {
            "pin_value_class": "pinned_commit",
            "loaded_from": "external_pin_object",
            "lookup_sha": pin,
            "runtime_source": "object_store_metadata",
            "evidence_class": "STACK_OK_BUILDER_EVIDENCE",
            "real_module_load": False,
        }
    )
    result = make_result(
        gate="tamper",
        decision="PASS",
        reason_code=None,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        task_id=task_id,
        checks=[passed("pin_load")],
        details=details,
        rule_digest=rules.digest,
    )
    return PinLoad(True, runtime, result)


_PIN_MODULES = (
    "gates",
    "gates.rules",
    "gates.tamper.loader",
    "gates.atomic_merge.compare",
    "gates.integrity.recovery",
    "gates.pipeline",
)


def _under(root: Path, file_path: str) -> bool:
    resolved = Path(file_path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        return False
    return True


def _load_modules(tree_root: Path):
    root = tree_root.resolve()
    saved_path = list(sys.path)
    saved = {key: sys.modules.pop(key) for key in list(sys.modules) if key == "gates" or key.startswith("gates.")}
    sys.path.insert(0, str(root))
    try:
        origin = {}
        for name in _PIN_MODULES:
            module = importlib.import_module(name)
            file_path = getattr(module, "__file__", None)
            if not file_path:
                raise RuntimeError(f"missing file for {name}")
            origin[name] = os.path.realpath(file_path)
        rules = sys.modules["gates.rules"].RULES
        entry = os.path.realpath(sys.path[0])
        return origin, entry, rules
    finally:
        sys.path[:] = saved_path
        for key in list(sys.modules):
            if key == "gates" or key.startswith("gates."):
                sys.modules.pop(key, None)
        sys.modules.update(saved)


def _load_real_pin(
    manifest,
    *,
    pin_loadpath: Path,
    manifest_path: Path | None,
    candidate_worktree: Path | None,
    git_repo: Path | None,
    candidate_sha: str,
    base_sha: str,
    task_id: str | None,
    rule_version: str,
    ignored: list[str],
    candidate_claimed_pin,
    head_sha,
    tags,
):
    rules = RULES

    def reject(pin_class: str, **extra):
        details = {
            "fallback_used": False,
            "consulted": ["external_manifest.gates_pin_sha"],
            "ignored": ignored,
            "candidate_claimed_pin_ignored": candidate_claimed_pin,
            "head_sha_ignored": head_sha,
            "tags_ignored": sorted(tags) if isinstance(tags, dict) else [],
            "worktree_consulted": False,
            "pin_value_class": pin_class,
            "evidence_class": "REAL_ISOLATION_EVIDENCE",
        }
        details.update(extra)
        result = make_result(
            gate="tamper",
            decision="REJECT",
            reason_code="TAMPER_PIN_UNSET_OR_INVALID",
            candidate_sha=candidate_sha,
            base_sha=base_sha,
            rule_version=rule_version,
            task_id=task_id,
            checks=[failed("pin_load", "TAMPER_PIN_UNSET_OR_INVALID", pin_value_class=pin_class)],
            details=details,
            rule_digest=rules.digest,
        )
        return PinLoad(False, None, result)

    pin = manifest.get("gates_pin_sha")
    if not is_sha40(pin):
        pin_class = "unset" if pin in (None, "", GATES_PIN_SHA) else "invalid_format"
        return reject(pin_class)
    if git_repo is None or manifest_path is None:
        return reject("object_missing", lookup_attempted=False)
    if candidate_worktree is not None:
        cand = candidate_worktree.resolve()
        man = manifest_path.resolve()
        if cand == man or cand in man.parents:
            return reject("manifest_inside_candidate")
        load_root = pin_loadpath.resolve()
        if cand == load_root or cand in load_root.parents:
            return reject("loadpath_inside_candidate")
    if object_type(git_repo, pin) is None:
        return reject("object_missing", lookup_sha=pin)
    if object_type(git_repo, pin) != "commit":
        return reject("not_commit", lookup_sha=pin, object_type=object_type(git_repo, pin))
    tree = rev_parse(git_repo, f"{pin}^{{tree}}")
    artifact = archive_sha256(git_repo, pin)
    config = sha256_hex(show_bytes(git_repo, f"{pin}:gates/policy/GATES-PARAMETERS-CANONICAL.txt"))
    mismatches = []
    if tree != manifest.get("gate_tree_sha"):
        mismatches.append("tree")
    if artifact != manifest.get("artifact_digest"):
        mismatches.append("artifact")
    if config != manifest.get("config_digest"):
        mismatches.append("config")
    if manifest.get("rule_version") != rule_version:
        mismatches.append("rule_version")
    if mismatches:
        return reject("digest_mismatch", lookup_sha=pin, mismatches=mismatches)
    gates_dir = pin_loadpath / "gates"
    if gates_dir.is_symlink() and not _under(pin_loadpath.resolve(), str(gates_dir.resolve())):
        return reject("symlink_escape", module_origin_violation=True)
    try:
        origin, entry, loaded_rules = _load_modules(pin_loadpath)
    except Exception as exc:
        return reject("module_load_failed", error=type(exc).__name__)
    root = str(pin_loadpath.resolve())
    candidate_code_used = any(not _under(pin_loadpath.resolve(), path) for path in origin.values())
    if candidate_code_used or entry != root:
        return reject("module_origin_violation", module_origin_violation=True, module_origin=origin, sys_path_gates_entry=entry)
    manifest_bytes = manifest_path.read_bytes()
    runtime = PinnedRuntime(
        gates_pin_sha=pin,
        gate_tree_sha=tree,
        rule_version=rule_version,
        artifact_digest=artifact,
        config_digest=config,
        rules=loaded_rules,
        source="pin_loadpath",
    )
    details = {
        "fallback_used": False,
        "consulted": ["external_manifest.gates_pin_sha"],
        "ignored": ignored,
        "candidate_claimed_pin_ignored": candidate_claimed_pin,
        "head_sha_ignored": head_sha,
        "worktree_consulted": False,
        "pin_value_class": "pinned_commit",
        "gates_pin_sha": pin,
        "gate_tree_sha": tree,
        "pin_loadpath": root,
        "module_origin": origin,
        "sys_path_gates_entry": entry,
        "candidate_code_used": candidate_code_used,
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": sha256_hex(manifest_bytes),
        "evidence_class": "REAL_ISOLATION_EVIDENCE",
        "real_module_load": True,
    }
    result = make_result(
        gate="tamper",
        decision="PASS",
        reason_code=None,
        candidate_sha=candidate_sha,
        base_sha=base_sha,
        rule_version=rule_version,
        task_id=task_id,
        checks=[passed("pin_load")],
        details=details,
        rule_digest=loaded_rules.digest,
    )
    return PinLoad(True, runtime, result)
