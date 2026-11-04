"""N11 verify, N12 capture, and N13 board entry.

Builder selftest support only. runtime_pass stays false.
Phase A ``TEST_FIXTURE_ONLY`` and ``MECHANISM_ACCEPT`` stay BLOCKED.
Phase B maps a verdict re-parsed from trusted raw bytes and is not that ceiling.
Trust comes only from ``consume_trusted_original``.
A readable file that copies the public reviewer id is not an issuance.

Spec SPEC-N11-TRUSTED-ORIGINAL-INTERFACE-v1
sha256 ``c9341bf7b3c149655de865953d03f46c19377e4a796e606590ae590adfc9bebf``.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from octo.candidate import git_candidate_sha
from octo.g3_review import product_scope_digest
from octo.grant import safe_path, write_once
from octo.nodes import emit_envelope
from octo.objects import canonical
from octo.trusted_original import (
    TA_REVIEWER_ID,
    FIXTURE_DIGEST_ENV,
    BindingTuple,
    ConsumeResult,
    Empty,
    Found,
    ReadOnlyRegistry,
    Rejected,
    consume_trusted_original,
    load_trusted_raw,
    migration_claimed,
    normalize_binding,
    open_registry,
    mark_receipt_consumed,
    read_stored_bytes,
    read_stored_json,
    runner_base_sha,
)

N11_KEYS = {"candidate_sha", "scope"}
N12_KEYS = {"decisions", "evidence", "receipts", "failures"}
N13_KEYS = {"outcome", "verify_state", "writeback_state", "handoff_state"}
WRITTEN_OBJECTS = frozenset({"Decision", "Evidence", "Receipt"})
_READY = frozenset({"READY", "OK", "PASS"})


def _blocked(scope: Any, note: str, verdict: str = "BLOCKED") -> tuple[dict, str]:
    return {
        "verdict": verdict,
        "evidence": [{"note": note, "test_only": True, "runtime_pass": False}],
        "scope": scope,
    }, "BLOCKED"


def _scope_matches(receipt_scope: Any, caller_scope: Any) -> bool:
    """True only when both sides are the same normalized five-field tuple.

    Route equality is not enough. A missing field is not a match.
    """
    return _scope_gap(receipt_scope, caller_scope) is None


def _scope_gap(receipt_scope: Any, caller_scope: Any) -> str | None:
    left = normalize_binding(receipt_scope if isinstance(receipt_scope, Mapping) else None)
    right = normalize_binding(caller_scope if isinstance(caller_scope, Mapping) else None)
    if left is None or right is None:
        return "scope binding incomplete"
    if left.route != right.route:
        return "route mismatch"
    if left.scope_digest != right.scope_digest or left.scope_digest != product_scope_digest():
        return "scope digest mismatch"
    if left.base_sha != right.base_sha:
        return "base_sha mismatch"
    if left.candidate_sha != right.candidate_sha:
        return "candidate_sha mismatch"
    if left.fixture_digest != right.fixture_digest:
        return "fixture_digest mismatch"
    return None


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


def _verified_original(
    opened: Mapping[str, Any] | None,
    candidate: str,
    scope: Any,
    *,
    binding: BindingTuple | None = None,
    registry_view: ReadOnlyRegistry | None = None,
    fixture_hashes: set[str] | None = None,
) -> Found | None:
    """Return a Found original. Candidate file bytes are never the source."""
    del opened, candidate, scope
    if binding is None or registry_view is None:
        return None
    found = consume_trusted_original(binding, registry_view, fixture_hashes or set())
    return found if isinstance(found, Found) else None


def _empty_note(result: Empty) -> str:
    if result.reason == "BLOCKED_WAITING_REAL_DATA":
        return "BLOCKED_WAITING_REAL_DATA EMPTY_REGISTRY no trusted reviewer registration"
    if result.reason == "EMPTY_REGISTRY":
        return "EMPTY_REGISTRY no trusted reviewer registration"
    return result.reason


def _from_consume(result: ConsumeResult, scope: Any) -> tuple[dict, str]:
    if isinstance(result, Empty):
        return _blocked(scope, _empty_note(result))
    if isinstance(result, Rejected):
        note = result.reason_code if not result.detail else f"{result.reason_code} {result.detail}"
        status = "SOURCE_UNAVAILABLE" if result.reason_code == "SOURCE_UNAVAILABLE" else "BLOCKED"
        output = {
            "verdict": "BLOCKED",
            "evidence": [{"note": note, "test_only": True, "runtime_pass": False}],
            "scope": scope,
        }
        return output, status
    if result.test_only:
        return _blocked(scope, "TEST_FIXTURE_ONLY")
    if result.mechanism_accept:
        return _blocked(scope, "MECHANISM_ACCEPT")
    return _blocked(scope, "verdict not PASS")


_PHASE_B_MARKS = frozenset({"verdict", "binding_tuple", "source_authenticity"})
_PHASE_B_VERDICTS = frozenset({"PASS", "REVISE", "BLOCKED", "FAIL"})
OWNER_APPOINTMENT_THREAD = "6ae7886b-23c8-83e8-a136-f1b52b33d01f"
PINNED_TURN_ID = "86b72901-5322-400a-be4c-063f80a6eb0b"
PINNED_MESSAGE_ID = "20c53a68-b7f0-4d98-ba11-966b5f24eadb"
APPOINTMENT_DIGEST = hashlib.sha256(OWNER_APPOINTMENT_THREAD.encode("utf-8")).hexdigest()
_FAKE_SERVER_IDS = frozenset({"server_call_id", "server_native_id", "tool_call_id"})


def _phase_b_blocked(scope: Any, note: str, *, original_verdict: str | None = None) -> tuple[dict, str]:
    evidence = {
        "note": note,
        "test_only": False,
        "runtime_pass": False,
        "mechanism_accept": False,
    }
    if original_verdict is not None:
        evidence["original_verdict"] = original_verdict
    return {"verdict": "BLOCKED", "evidence": [evidence], "scope": scope}, "BLOCKED"


def _phase_b_binding_matches(raw_binding: Any, runner_binding: Mapping[str, Any] | None) -> bool:
    if not isinstance(raw_binding, Mapping) or not isinstance(runner_binding, Mapping):
        return False
    parsed = normalize_binding(raw_binding)
    runner = normalize_binding(runner_binding)
    if parsed is None or runner is None or parsed != runner:
        return False
    for key in ("task", "rule_version"):
        if runner_binding.get(key) and raw_binding.get(key) != runner_binding.get(key):
            return False
    return True


def _message_matches_original(text: Any, raw: bytes) -> bool:
    """Review-receipt bytes must equal the authenticated message text. A local hash cannot replace that."""
    return isinstance(text, str) and text != "" and text.encode("utf-8") == raw


def describe_read_thread(service: Mapping[str, Any]) -> dict[str, str] | None:
    """Shape of a stored read_thread return. This does not grant a current verdict."""
    thread = service.get("thread")
    turns = service.get("turns")
    if not isinstance(thread, dict) or not isinstance(thread.get("id"), str) or not isinstance(turns, list):
        return None
    for turn in turns:
        if not isinstance(turn, dict) or turn.get("status") != "completed":
            continue
        turn_id = turn.get("id")
        items = turn.get("items")
        if not isinstance(turn_id, str) or not turn_id or not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict) or item.get("type") != "agentMessage":
                continue
            message_id = item.get("id")
            text = item.get("text")
            if not isinstance(message_id, str) or not message_id or not isinstance(text, str) or text == "":
                continue
            return {
                "thread_id": thread["id"],
                "turn_id": turn_id,
                "message_id": message_id,
                "role": "agentMessage",
                "text": text,
            }
    return None


def parse_authenticated_read_thread(service: Mapping[str, Any]) -> dict[str, str] | None:
    """The pinned completed turn and agentMessage. User, preview, and content-reference items are ignored."""
    thread = service.get("thread")
    turns = service.get("turns")
    if not isinstance(thread, dict) or thread.get("id") != OWNER_APPOINTMENT_THREAD or not isinstance(turns, list):
        return None
    for turn in turns:
        if not isinstance(turn, dict) or turn.get("id") != PINNED_TURN_ID or turn.get("status") != "completed":
            continue
        items = turn.get("items")
        if not isinstance(items, list):
            return None
        for item in items:
            if not isinstance(item, dict) or item.get("type") != "agentMessage" or item.get("id") != PINNED_MESSAGE_ID:
                continue
            text = item.get("text")
            if not isinstance(text, str) or text == "":
                return None
            return {
                "thread_id": OWNER_APPOINTMENT_THREAD,
                "turn_id": PINNED_TURN_ID,
                "message_id": PINNED_MESSAGE_ID,
                "role": "agentMessage",
                "text": text,
            }
        return None
    return None


def _allowlist_digest() -> str | None:
    from octo.trusted_original import ALLOWLIST_ENV
    env = os.environ.get(ALLOWLIST_ENV)
    if not env:
        return None
    path = Path(env)
    if path.is_symlink() or not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _collector_matches(
    transfer: Mapping[str, Any],
    *,
    actual: str,
    service_sha: str,
    text_sha: str,
    parsed: Mapping[str, str],
    allowlist_sha: str | None,
    runner_binding: Mapping[str, Any] | None,
) -> bool:
    if not isinstance(transfer.get("collector_receipt_id"), str) or not transfer["collector_receipt_id"]:
        return False
    if not isinstance(transfer.get("collected_at"), str) or not transfer["collected_at"]:
        return False
    if allowlist_sha is None or transfer.get("allowlist_sha256") != allowlist_sha:
        return False
    if transfer.get("appointment_digest") != APPOINTMENT_DIGEST:
        return False
    if not isinstance(runner_binding, Mapping):
        return False
    for key in ("base_sha", "candidate_sha", "scope_digest", "fixture_digest"):
        if transfer.get(key) != runner_binding.get(key):
            return False
    return (
        transfer.get("raw_sha256") == actual
        and transfer.get("service_response_sha256") == service_sha
        and transfer.get("message_sha256") == text_sha
        and transfer.get("thread_id") == parsed["thread_id"]
        and transfer.get("turn_id") == parsed["turn_id"]
        and transfer.get("message_id") == parsed["message_id"]
        and transfer.get("role") == "agentMessage"
        and transfer.get("turn_status") == "completed"
    )


def _phase_b_source_authentic(
    registry_view: ReadOnlyRegistry,
    record: Mapping[str, Any],
    raw: bytes,
    runner_binding: Mapping[str, Any] | None,
) -> bool:
    """Stored read_thread return plus transfer and custody. Projection fields are not proof."""
    actual = hashlib.sha256(raw).hexdigest()
    custody = read_stored_json(registry_view, record.get("custody_ref"))
    if not isinstance(custody, dict) or custody.get("not_issuer") is not True or custody.get("raw_sha256") != actual:
        return False
    if custody.get("issuer") or custody.get("verdict") or custody.get("signed_by"):
        return False
    evidence = record.get("source_evidence") if isinstance(record.get("source_evidence"), dict) else {}
    transfer_id = evidence.get("transfer_receipt_id")
    if not isinstance(transfer_id, str) or not transfer_id or any(part in {"", ".", ".."} for part in Path(transfer_id).parts):
        return False
    service_bytes = read_stored_bytes(registry_view, record.get("service_response_ref"))
    if service_bytes is None:
        return False
    try:
        service = json.loads(service_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(service, dict):
        return False
    parsed = parse_authenticated_read_thread(service)
    if parsed is None or not _message_matches_original(parsed["text"], raw):
        return False
    claimed = service.get("message_sha256")
    if isinstance(claimed, str) and claimed != actual:
        return False
    if record.get("bytes_sha256") != actual:
        return False
    transfer = read_stored_json(registry_view, f"transfers/{transfer_id}.json")
    if not isinstance(transfer, dict) or _FAKE_SERVER_IDS.intersection(transfer):
        return False
    service_sha = hashlib.sha256(service_bytes).hexdigest()
    text_sha = hashlib.sha256(parsed["text"].encode("utf-8")).hexdigest()
    return _collector_matches(
        transfer,
        actual=actual,
        service_sha=service_sha,
        text_sha=text_sha,
        parsed=parsed,
        allowlist_sha=_allowlist_digest(),
        runner_binding=runner_binding,
    )


def phase_b_from_raw(
    raw: bytes,
    runner_binding: Mapping[str, Any] | None,
    scope: Any,
    *,
    registry_view: ReadOnlyRegistry,
    record: Mapping[str, Any],
) -> tuple[dict, str] | None:
    """Map a re-parsed original. None means these bytes are not a Phase B document.

    TEST_FIXTURE and MECHANISM_ACCEPT never enter here. runtime_pass stays false.
    """
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict) or not _PHASE_B_MARKS.intersection(document):
        return None
    verdict = document.get("verdict")
    if verdict not in _PHASE_B_VERDICTS:
        return _phase_b_blocked(scope, "PHASE_B_PARSE_FAILED")
    if not _phase_b_binding_matches(document.get("binding_tuple"), runner_binding):
        return _phase_b_blocked(scope, "BINDING_MISMATCH", original_verdict=verdict)
    if not _phase_b_source_authentic(registry_view, record, raw, runner_binding):
        return _phase_b_blocked(scope, "SOURCE_UNPROVEN", original_verdict=verdict)
    evidence = {
        "note": "PHASE_B",
        "original_verdict": verdict,
        "test_only": False,
        "runtime_pass": False,
        "mechanism_accept": False,
    }
    if verdict == "PASS":
        return {"verdict": "PASS", "evidence": [evidence], "scope": scope}, "OK"
    if verdict == "REVISE":
        return {"verdict": "REVISE", "evidence": [evidence], "scope": scope}, "BLOCKED"
    return {"verdict": "BLOCKED", "evidence": [evidence], "scope": scope}, "BLOCKED"


def _judge_receipt(
    receipt: Mapping[str, Any] | None,
    candidate: str,
    scope: Any,
    *,
    binding: BindingTuple | Mapping[str, Any] | None,
    registry_view: ReadOnlyRegistry | None,
    fixture_hashes: set[str],
    registry_empty: Empty | None = None,
) -> tuple[dict, str]:
    """Candidate claims can only reject. The grant of trust is the registry."""
    if isinstance(receipt, Mapping):
        if receipt.get("builder_signed") is True:
            return _blocked(scope, "BUILDER_PASS_FORBIDDEN")
        if receipt.get("signed_by") == "candidate-self-report":
            return _blocked(scope, "candidate self-report is not a TA reviewer receipt")
        if migration_claimed(receipt):
            return _blocked(scope, "SIGNATURE_MIGRATION_CLAIM")
        issuer = receipt.get("issuer") or receipt.get("reviewer")
        if isinstance(issuer, str) and issuer != TA_REVIEWER_ID:
            return _blocked(scope, "forged issuer")
        presented = receipt.get("candidate_sha")
        if isinstance(presented, str) and presented != candidate:
            return _blocked(scope, "STALE_PASS_CANDIDATE_CHANGED")
        if receipt.get("test_only") is True:
            return _blocked(scope, "TEST_ONLY evidence is not a PASS")
        _load_receipt_file(receipt.get("path"))
    if registry_empty is not None:
        return _from_consume(registry_empty, scope)
    result = consume_trusted_original(binding, registry_view, fixture_hashes)
    if (
        isinstance(result, Found)
        and result.mechanism_accept
        and not result.test_only
        and isinstance(registry_view, ReadOnlyRegistry)
        and registry_view.production
        and result.record.get("content_kind") != "TEST_FIXTURE"
        and result.record.get("test_only") is not True
    ):
        raw = load_trusted_raw(registry_view, result.record)
        if isinstance(raw, bytes):
            gated = phase_b_from_raw(
                raw,
                binding if isinstance(binding, Mapping) else None,
                scope,
                registry_view=registry_view,
                record=result.record,
            )
            if gated is not None:
                if gated[0]["evidence"][0].get("note") == "PHASE_B":
                    mark_receipt_consumed(registry_view, result.record)
                return gated
    return _from_consume(result, scope)


def _runner_binding(inputs: Mapping[str, Any], fixture_digest: str | None) -> dict[str, str] | None:
    """Five-field tuple plus the recorded task and rule_version. Not a new envelope key."""
    scope = inputs.get("scope") if isinstance(inputs.get("scope"), dict) else {}
    route = scope.get("route")
    chosen = fixture_digest if fixture_digest is not None else os.environ.get(FIXTURE_DIGEST_ENV)
    normalized = normalize_binding({
        "route": route,
        "scope_digest": product_scope_digest(),
        "base_sha": runner_base_sha() or "",
        "candidate_sha": inputs.get("candidate_sha"),
        "fixture_digest": chosen or "",
    })
    if normalized is None:
        return None
    raw = normalized.as_dict()
    for key in ("task", "rule_version"):
        value = scope.get(key)
        if isinstance(value, str) and value.strip():
            raw[key] = value.strip()
    return raw


def run_n11(
    inputs: Mapping[str, Any],
    *,
    at: str,
    independent_receipt: Mapping[str, Any] | None = None,
    builder_claims_pass: bool = False,
    registry_root: Path | None = None,
    fixture_hashes: set[str] | None = None,
    fixture_digest: str | None = None,
    store_root: Path | None = None,
) -> dict:
    """Frozen N11. Trust is the read-only registry, not the candidate receipt."""
    if builder_claims_pass:
        raise ValueError("BUILDER_PASS_FORBIDDEN")
    if set(inputs) != N11_KEYS:
        raise ValueError("N11_SHAPE_MISMATCH")
    candidate = git_candidate_sha(inputs["candidate_sha"])
    scope = inputs["scope"]
    if independent_receipt is not None and not isinstance(independent_receipt, Mapping):
        output, status = _blocked(scope, "empty or unopenable proof")
    else:
        if registry_root is None and os.environ.get("OCTO_TRUSTED_ORIGINAL_ROOT"):
            registry_root = Path(os.environ["OCTO_TRUSTED_ORIGINAL_ROOT"])
        opened = open_registry(registry_root, store_root=store_root)
        hashes = set(fixture_hashes or ())
        binding = _runner_binding(inputs, fixture_digest)
        output, status = _judge_receipt(
            independent_receipt,
            candidate,
            scope,
            binding=binding,
            registry_view=opened if isinstance(opened, ReadOnlyRegistry) else None,
            fixture_hashes=hashes,
            registry_empty=opened if isinstance(opened, Empty) else None,
        )
    if set(output) != {"verdict", "evidence", "scope"}:
        raise ValueError("N11_SHAPE_MISMATCH")
    if output["verdict"] == "PASS" and status != "OK":
        raise ValueError("N11_SHAPE_MISMATCH")
    if output["verdict"] != "PASS" and status == "OK":
        raise ValueError("N11_SHAPE_MISMATCH")
    return emit_envelope(node_id="N11", at=at, inputs=dict(inputs), status=status, output=output)


_AUTHORITY_FIELD = {"Receipt": "receipt_id", "Decision": "decision_id", "Evidence": "evidence_id"}
_RECEIPT_REQUIRED = (
    "receipt_id",
    "grant_id",
    "request_digest",
    "candidate_sha",
    "action",
    "object_id",
    "idempotency_key",
    "started_at",
    "finished_at",
    "state",
    "verifier",
)
_EVIDENCE_FIELDS = ("evidence_id", "decision_id", "type", "uri_or_hash", "collected_at")


def _authority_id(kind: str, row: Mapping[str, Any]) -> str:
    """PRD id for this kind. ``id`` is only an alias and cannot replace the authority field."""
    field = _AUTHORITY_FIELD[kind]
    if field not in row or row[field] is None or row[field] == "":
        raise ValueError("OBJECT_ID_MISSING")
    value = row[field]
    if not isinstance(value, str):
        raise ValueError("OBJECT_ID_TYPE_INVALID")
    if "id" in row:
        alias = row["id"]
        if not isinstance(alias, str):
            raise ValueError("OBJECT_ID_TYPE_INVALID")
        if alias != value:
            raise ValueError("CONTENT_CONFLICT")
    return value


def _prepare_row(kind: str, row: Mapping[str, Any]) -> dict:
    data = dict(row)
    if kind == "Evidence":
        for key in _EVIDENCE_FIELDS:
            if key not in data:
                data[key] = None
    if kind == "Receipt":
        missing = [key for key in _RECEIPT_REQUIRED if key not in data]
        if missing:
            raise ValueError("RECEIPT_REQUIRED_FIELD_MISSING:" + ",".join(missing))
    return data


def _supersede_target(row: Mapping[str, Any]) -> Any:
    """Read both PRD ``supersedes_id`` and the documented alias ``supersedes``."""
    has_alias = "supersedes" in row
    has_authority = "supersedes_id" in row
    if has_alias and has_authority and row["supersedes"] != row["supersedes_id"]:
        raise ValueError("CONTENT_CONFLICT")
    if has_authority:
        return row["supersedes_id"]
    if has_alias:
        return row["supersedes"]
    return None


def _relative(path: Path, store_root: Path) -> str:
    return path.resolve().relative_to(store_root.resolve()).as_posix()


def _existing_record(store: Path, object_id: str) -> Path | None:
    if not object_id or object_id == "None" or any(char in object_id for char in "*/"):
        return None
    matches = [path for path in store.glob(f"*-{object_id}.json") if path.is_file()]
    return sorted(matches)[0] if matches else None


def _write_row(store: Path, store_root: Path, kind: str, row: Mapping[str, Any], written: list[dict], object_id: str) -> None:
    if kind not in WRITTEN_OBJECTS:
        raise ValueError("WRITTEN_OBJECT_FORBIDDEN")
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


def _consume_evidence_refs(rows: list[tuple[str, dict]], required: list) -> None:
    if not required:
        return
    for kind, row in rows:
        if kind != "Receipt":
            continue
        got = row.get("evidence_refs")
        if isinstance(got, list) and all(item in got for item in required):
            return
    raise ValueError("N10_EVIDENCE_REFS_UNCONSUMED")


def run_n12(
    inputs: Mapping[str, Any],
    *,
    at: str,
    store_root: Path,
    required_evidence_refs: list | None = None,
) -> dict:
    """Capture decisions, evidence, and receipts. Failures are Receipt rows.

    ``id`` is a documented alias of the kind's authority id and must match it.
    ``supersedes`` is a documented alias of PRD ``supersedes_id``; both are read.
    """
    if set(inputs) != N12_KEYS:
        raise ValueError("N12_SHAPE_MISMATCH")
    store_root = Path(store_root)
    prepared: list[tuple[str, dict, str, Any]] = []
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
            object_id = _authority_id(kind, row)
            data = _prepare_row(kind, row)
            target = _supersede_target(data)
            if target is not None and not object_id:
                raise ValueError("SUPERSEDE_NEW_ID_EMPTY")
            prepared.append((kind, data, object_id, target))
    _consume_evidence_refs([(kind, data) for kind, data, _oid, _target in prepared], list(required_evidence_refs or []))
    store = store_root / "capture"
    store.mkdir(parents=True, exist_ok=True)
    written: list[dict] = []
    superseded = []
    for kind, data, object_id, target in prepared:
        _write_row(store, store_root, kind, data, written, object_id)
        if target is None:
            continue
        if target == "":
            raise ValueError("SUPERSEDE_NEW_ID_EMPTY")
        old_path = _existing_record(store, str(target))
        if old_path is None:
            raise ValueError("SUPERSEDE_LINK_UNOPENABLE")
        superseded.append({
            "old_id": target,
            "new_id": object_id,
            "link": _relative(old_path, store_root),
        })
    if any(row["object"] not in WRITTEN_OBJECTS for row in written):
        raise ValueError("WRITTEN_OBJECT_FORBIDDEN")
    output = {"written": written, "superseded": superseded}
    if set(output) != {"written", "superseded"}:
        raise ValueError("N12_SHAPE_MISMATCH")
    return emit_envelope(node_id="N12", at=at, inputs=dict(inputs), status="OK", output=output)


def _confine_store(store_root: Path, ref: str) -> Path:
    if not isinstance(ref, str) or not ref or ref.startswith(("/", "\\")) or ".." in Path(ref).parts:
        raise ValueError("PATH_ESCAPE")
    current = store_root.resolve()
    for part in Path(ref).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("PATH_ESCAPE")
    resolved = current.resolve()
    root = store_root.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("PATH_ESCAPE")
    return resolved


def _file_with_sha(store_root: Path, hexdigest: str) -> bool:
    for path in store_root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() == hexdigest:
            return True
    return False


def _resolve_evidence_link(ref: str, store_root: Path | None) -> str:
    """Open a confined path or a content-addressed original. Label hashes do not resolve."""
    if not isinstance(ref, str) or not ref:
        raise ValueError("EVIDENCE_LINK_NOT_OPENABLE")
    if ref.startswith(("outcome:", "verify_state:", "writeback_state:", "handoff_state:")):
        raise ValueError("EVIDENCE_POINTER_UNRESOLVED")
    if ref.startswith("sha256:"):
        hexpart = ref.split(":", 1)[1]
        if store_root is None or len(hexpart) != 64 or not _file_with_sha(store_root, hexpart):
            raise ValueError("EVIDENCE_POINTER_UNRESOLVED")
        return ref
    if store_root is None:
        raise ValueError("EVIDENCE_LINK_NOT_OPENABLE")
    path = _confine_store(store_root, ref)
    if not path.is_file():
        raise ValueError("EVIDENCE_LINK_NOT_OPENABLE")
    hashlib.sha256(path.read_bytes()).hexdigest()
    return ref


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
    links = [_resolve_evidence_link(ref, store_root) for ref in evidence_refs]
    evidence_missing = not links
    output = {
        "state": state,
        "evidence_links": links,
        "next_legal_action": next_action,
        "owner": owner,
        "notify_once": notify_once,
    }
    if set(output) != {"state", "evidence_links", "next_legal_action", "owner", "notify_once"}:
        raise ValueError("N13_SHAPE_MISMATCH")
    status = "BLOCKED" if blocked or evidence_missing else "OK"
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
