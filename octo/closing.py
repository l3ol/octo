"""N11 verify, N12 capture, and N13 board entry.

Builder selftest support only. N11 does not issue an independent PASS.
runtime_pass stays false. A readable file that copies the public reviewer id
is not an issuance. There is no candidate-writable control plane that can
accept PASS, so the verdict stays BLOCKED until that source exists.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from octo.candidate import git_candidate_sha
from octo.g3_review import invalidate_stored_pass, product_scope_digest
from octo.grant import safe_path, write_once
from octo.nodes import emit_envelope
from octo.objects import canonical, digest

N11_KEYS = {"candidate_sha", "scope"}
N12_KEYS = {"decisions", "evidence", "receipts", "failures"}
N13_KEYS = {"outcome", "verify_state", "writeback_state", "handoff_state"}
WRITTEN_OBJECTS = frozenset({"Decision", "Evidence", "Receipt"})
TA_REVIEWER_ID = "agt_6ae61c44e54081918e81a0adea556ef8"
_READY = frozenset({"READY", "OK", "PASS"})


def _blocked(scope: Any, note: str, verdict: str = "BLOCKED") -> tuple[dict, str]:
    return {
        "verdict": verdict,
        "evidence": [{"note": note, "test_only": True, "runtime_pass": False}],
        "scope": scope,
    }, "BLOCKED"


def _scope_matches(receipt_scope: Any, caller_scope: Any) -> bool:
    """True only for a fully bound quadruple that a trusted source registered.

    Route equality is not enough. A missing tuple is not a match. A candidate
    cannot register that source by writing the file, so this stays false.
    """
    return _scope_gap(receipt_scope, caller_scope) is None


def _scope_gap(receipt_scope: Any, caller_scope: Any) -> str:
    if not isinstance(receipt_scope, dict) or not isinstance(caller_scope, dict):
        return "scope binding incomplete"
    if "tuple" not in receipt_scope or "tuple" not in caller_scope:
        return "scope binding incomplete"
    if receipt_scope.get("tuple") != caller_scope.get("tuple"):
        return "tuple mismatch"
    if receipt_scope.get("route") != caller_scope.get("route"):
        return "route mismatch"
    expected_scope = product_scope_digest()
    if receipt_scope.get("scope_digest") != expected_scope or caller_scope.get("scope_digest") != expected_scope:
        return "scope digest mismatch"
    for name in ("base_sha", "candidate_sha", "fixture_digest"):
        if not receipt_scope.get(name) or not caller_scope.get(name):
            return "scope binding incomplete"
        if receipt_scope.get(name) != caller_scope.get(name):
            return f"{name} mismatch"
    try:
        invalidation = invalidate_stored_pass(
            {
                "base_sha": receipt_scope["base_sha"],
                "candidate_sha": receipt_scope["candidate_sha"],
                "scope_digest": receipt_scope["scope_digest"],
                "fixture_digest": receipt_scope["fixture_digest"],
            },
            {
                "base_sha": caller_scope["base_sha"],
                "candidate_sha": caller_scope["candidate_sha"],
                "scope_digest": caller_scope["scope_digest"],
                "fixture_digest": caller_scope["fixture_digest"],
            },
        )
    except ValueError:
        return "scope binding incomplete"
    if invalidation["status"] != "UNCHANGED":
        return "stale binding"
    return "no trusted reviewer registration"


def _load_receipt_file(path_value: Any) -> dict | None:
    """Read bytes for inspection. A readable path is not a trusted issuance."""
    if not isinstance(path_value, str) or not path_value.strip():
        return None
    path = Path(path_value)
    try:
        if not path.is_file():
            return None
        payload = json_loads(path.read_bytes())
    except (OSError, ValueError, UnicodeError):
        return None
    return payload if isinstance(payload, dict) else None


def json_loads(data: bytes) -> Any:
    import json
    return json.loads(data.decode("utf-8"))


def _verified_original(opened: Mapping[str, Any], candidate: str, scope: Any) -> str | None:
    """No candidate-supplied file is an original. Public id plus bytes is not issuance."""
    del opened, candidate, scope
    return None


def _judge_receipt(receipt: Mapping[str, Any], candidate: str, scope: Any) -> tuple[dict, str]:
    """Untrusted material stays BLOCKED. This entry cannot mint a reviewer PASS."""
    if receipt.get("builder_signed") is True:
        raise ValueError("BUILDER_PASS_FORBIDDEN")
    if receipt.get("signed_by") == "candidate-self-report":
        return _blocked(scope, "candidate self-report is not a TA reviewer receipt")
    issuer = receipt.get("issuer") or receipt.get("reviewer")
    if isinstance(issuer, str) and issuer != TA_REVIEWER_ID:
        return _blocked(scope, "forged issuer")
    presented = receipt.get("candidate_sha")
    if isinstance(presented, str) and presented != candidate:
        return _blocked(scope, "STALE_PASS_CANDIDATE_CHANGED")
    receipt_scope = receipt.get("scope")
    if isinstance(receipt_scope, dict):
        gap = _scope_gap(receipt_scope, scope if isinstance(scope, dict) else {})
        if gap != "no trusted reviewer registration":
            return _blocked(scope, gap)
    if receipt.get("test_only") is True:
        return _blocked(scope, "TEST_ONLY evidence is not a PASS")
    opened = _load_receipt_file(receipt.get("path"))
    if _verified_original(opened or receipt, candidate, scope) is not None:
        raise RuntimeError("candidate material must not become a reviewer verdict")
    if opened is None:
        return _blocked(scope, "untrusted or empty proof")
    return _blocked(scope, "readable file is not a reviewer issuance")


def run_n11(
    inputs: Mapping[str, Any],
    *,
    at: str,
    independent_receipt: Mapping[str, Any] | None = None,
    builder_claims_pass: bool = False,
) -> dict:
    """Frozen N11. No traceable TA receipt → BLOCKED. Builder PASS is rejected."""
    if builder_claims_pass:
        raise ValueError("BUILDER_PASS_FORBIDDEN")
    if set(inputs) != N11_KEYS:
        raise ValueError("N11_SHAPE_MISMATCH")
    candidate = git_candidate_sha(inputs["candidate_sha"])
    scope = inputs["scope"]
    if independent_receipt is None:
        output, status = _blocked(scope, "no independent verifier receipt")
    elif not isinstance(independent_receipt, Mapping):
        output, status = _blocked(scope, "empty or unopenable proof")
    else:
        output, status = _judge_receipt(independent_receipt, candidate, scope)
    if set(output) != {"verdict", "evidence", "scope"}:
        raise ValueError("N11_SHAPE_MISMATCH")
    if output["verdict"] == "PASS" and status != "OK":
        raise ValueError("N11_SHAPE_MISMATCH")
    if output["verdict"] != "PASS" and status == "OK":
        raise ValueError("N11_SHAPE_MISMATCH")
    return emit_envelope(node_id="N11", at=at, inputs=dict(inputs), status=status, output=output)


def _object_id(row: Mapping[str, Any]) -> str:
    return str(row.get("id") or row.get("receipt_id") or row.get("decision_id") or row.get("evidence_id"))


def _relative(path: Path, store_root: Path) -> str:
    return path.resolve().relative_to(store_root.resolve()).as_posix()


def _existing_record(store: Path, object_id: str) -> Path | None:
    if not object_id or object_id == "None" or any(char in object_id for char in "*/"):
        return None
    matches = [path for path in store.glob(f"*-{object_id}.json") if path.is_file()]
    return sorted(matches)[0] if matches else None


def _write_row(store: Path, store_root: Path, kind: str, row: Mapping[str, Any], written: list[dict]) -> None:
    if kind not in WRITTEN_OBJECTS:
        raise ValueError("WRITTEN_OBJECT_FORBIDDEN")
    object_id = _object_id(row)
    path = safe_path(store / f"{kind}-{object_id}.json", store_root)
    payload = canonical(dict(row)) + b"\n"
    digest_hex = hashlib.sha256(payload).hexdigest()
    relative = _relative(path, store_root)
    if path.exists():
        existing = path.read_bytes()
        if existing == payload:
            written.append({"object": kind, "path": relative, "sha256": hashlib.sha256(existing).hexdigest()})
            return
        raise ValueError(f"CONTENT_CONFLICT:{relative}")
    write_once(path, dict(row))
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest_hex:
        raise ValueError("WRITTEN_SHA_MISMATCH")
    written.append({"object": kind, "path": relative, "sha256": actual})


def run_n12(inputs: Mapping[str, Any], *, at: str, store_root: Path) -> dict:
    """Capture decisions, evidence, and receipts. Failures are Receipt rows."""
    if set(inputs) != N12_KEYS:
        raise ValueError("N12_SHAPE_MISMATCH")
    store_root = Path(store_root)
    store = store_root / "capture"
    store.mkdir(parents=True, exist_ok=True)
    written: list[dict] = []
    superseded = []
    groups = (
        ("Receipt", list(inputs["receipts"])),
        ("Decision", list(inputs["decisions"])),
        ("Evidence", list(inputs["evidence"])),
        ("Receipt", list(inputs["failures"])),
    )
    if groups[0][0] != "Receipt":
        raise ValueError("RECEIPT_NOT_FIRST")
    for kind, rows in groups:
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("N12_SHAPE_MISMATCH")
            if row.get("kind") == "log":
                raise ValueError("LOG_NOISE_WRITTEN")
            _write_row(store, store_root, kind, row, written)
            old_id = row.get("supersedes")
            if old_id:
                old_path = _existing_record(store, str(old_id))
                if old_path is None:
                    raise ValueError("SUPERSEDE_LINK_UNOPENABLE")
                superseded.append({
                    "old_id": old_id,
                    "new_id": row.get("id") or row.get("receipt_id"),
                    "link": _relative(old_path, store_root),
                })
    if any(row["object"] not in WRITTEN_OBJECTS for row in written):
        raise ValueError("WRITTEN_OBJECT_FORBIDDEN")
    output = {"written": written, "superseded": superseded}
    if set(output) != {"written", "superseded"}:
        raise ValueError("N12_SHAPE_MISMATCH")
    return emit_envelope(node_id="N12", at=at, inputs=dict(inputs), status="OK", output=output)


def _pointer(field: str, value: Any) -> str:
    return "sha256:" + digest({"field": field, "value": value})


def _notification_path(store_root: Path) -> Path:
    return Path(store_root) / "board" / "notifications.json"


def _load_notification_keys(store_root: Path) -> set[str]:
    path = _notification_path(store_root)
    if not path.is_file():
        return set()
    try:
        payload = json_loads(path.read_bytes())
    except (OSError, ValueError, UnicodeError):
        return set()
    keys = payload.get("keys") if isinstance(payload, dict) else None
    if not isinstance(keys, list):
        return set()
    return {item for item in keys if isinstance(item, str)}


def _save_notification_keys(store_root: Path, keys: set[str]) -> None:
    path = _notification_path(store_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical({"keys": sorted(keys)}) + b"\n")


def _unfinished(outcome: Any, verify_state: Any, writeback_state: Any, handoff_state: Any) -> list[str]:
    pending = []
    if verify_state not in _READY:
        pending.append("verify")
    if writeback_state not in _READY:
        pending.append("writeback")
    if handoff_state not in _READY:
        pending.append("handoff")
    if outcome not in {"SUCCEEDED", "OK"}:
        pending.append("outcome")
    return pending


def _owner_and_next(pending: list[str]) -> tuple[str, str]:
    if "verify" in pending:
        return "reviewer", "wait-for-independent-verify"
    if "writeback" in pending:
        return "builder", "repair-writeback"
    if "handoff" in pending:
        return "handoff", "complete-handoff"
    if "outcome" in pending:
        return "builder", "repair-outcome"
    return "builder", "handoff"


def run_n13(
    inputs: Mapping[str, Any],
    *,
    at: str,
    notified: set[str] | None = None,
    evidence_refs: tuple[str, ...] | list[str] = (),
    store_root: Path | None = None,
    intent_id: str | None = None,
) -> dict:
    """Board entry. Dedup is store + intent + blocker, persisted on the store."""
    if set(inputs) != N13_KEYS:
        raise ValueError("N13_SHAPE_MISMATCH")
    if "path" in inputs or "sha256" in inputs:
        raise ValueError("N13_SHAPE_MISMATCH")
    outcome = inputs["outcome"]
    verify_state = inputs["verify_state"]
    writeback_state = inputs["writeback_state"]
    handoff_state = inputs["handoff_state"]
    if outcome in {"verified", "done"} and verify_state == "BLOCKED":
        raise ValueError("STATES_CONFLATED")
    pending = _unfinished(outcome, verify_state, writeback_state, handoff_state)
    blocked = bool(pending)
    state = "BLOCKED" if blocked else str(outcome)
    owner, next_action = _owner_and_next(pending)
    if not owner or not next_action:
        raise ValueError("NEXT_ACTION_MISSING")
    blocker = f"{outcome}|{verify_state}|{writeback_state}|{handoff_state}"
    persist_root: Path | None = None
    if notified is not None:
        seen: set[str] | None = notified
        key = blocker
    elif store_root is not None and intent_id:
        seen = _load_notification_keys(store_root)
        key = f"{intent_id}|{blocker}"
        persist_root = Path(store_root)
    else:
        seen = None
        key = ""
    if blocked and seen is not None and key in seen:
        notify_once = False
    else:
        if blocked and seen is not None:
            seen.add(key)
            if persist_root is not None:
                _save_notification_keys(persist_root, seen)
        notify_once = True
    links = [ref for ref in evidence_refs if isinstance(ref, str) and ref]
    for field in ("outcome", "verify_state", "writeback_state", "handoff_state"):
        links.append(_pointer(field, inputs[field]))
    if any(link.startswith(("outcome:", "verify_state:", "writeback_state:", "handoff_state:")) for link in links):
        raise ValueError("EVIDENCE_LINK_NOT_OPENABLE")
    output = {
        "state": state,
        "evidence_links": links,
        "next_legal_action": next_action,
        "owner": owner,
        "notify_once": notify_once,
    }
    if set(output) != {"state", "evidence_links", "next_legal_action", "owner", "notify_once"}:
        raise ValueError("N13_SHAPE_MISMATCH")
    status = "BLOCKED" if blocked else "OK"
    return emit_envelope(node_id="N13", at=at, inputs=dict(inputs), status=status, output=output)


def writeback_state_from_n12(envelope: Mapping[str, Any]) -> str:
    """Read the capture result. A constant OK is not a writeback result."""
    output = envelope.get("output") or {}
    written = output.get("written") if isinstance(output, dict) else None
    if envelope.get("status") != "OK" or not isinstance(written, list) or not written:
        return "FAILED"
    if any(not isinstance(row, dict) or row.get("object") not in WRITTEN_OBJECTS or not row.get("path") for row in written):
        return "FAILED"
    return "OK"


def handoff_state_from_n11(envelope: Mapping[str, Any]) -> str:
    """Handoff follows the N11 verdict. BLOCKED is not a hardcoded NOT_READY."""
    output = envelope.get("output") or {}
    if envelope.get("status") == "OK" and isinstance(output, dict) and output.get("verdict") == "PASS":
        return "READY"
    return "NOT_READY"
