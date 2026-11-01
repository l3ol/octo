"""External pin loader. Never falls back to tag, HEAD, worktree, or a candidate pin."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from gates.rules import RULES, RULE_VERSION, RuleSet
from gates.types import failed, is_sha40, make_result, passed

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
            "runtime_source": "pin",
            "candidate_code_used": False,
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
