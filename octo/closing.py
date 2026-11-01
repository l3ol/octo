"""N11 verify, N12 capture, and N13 board entry.

Builder selftest support only. N11 does not issue an independent PASS.
runtime_pass stays false.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from octo.candidate import git_candidate_sha
from octo.grant import Denied, safe_path, write_once
from octo.nodes import emit_envelope
from octo.objects import canonical

N11_KEYS = {"candidate_sha", "scope"}
N12_KEYS = {"decisions", "evidence", "receipts", "failures"}
N13_KEYS = {"outcome", "verify_state", "writeback_state", "handoff_state"}


def run_n11(
    inputs: Mapping[str, Any],
    *,
    at: str,
    independent_receipt: Mapping[str, Any] | None = None,
    builder_claims_pass: bool = False,
) -> dict:
    """Frozen N11. No independent receipt → BLOCKED. Builder PASS is rejected."""
    if set(inputs) != N11_KEYS:
        raise ValueError("N11_SHAPE_MISMATCH")
    candidate = git_candidate_sha(inputs["candidate_sha"])
    if builder_claims_pass:
        raise ValueError("BUILDER_PASS_FORBIDDEN")
    if independent_receipt is None:
        output = {
            "verdict": "BLOCKED",
            "evidence": [{"note": "no independent verifier receipt", "test_only": True}],
            "scope": inputs["scope"],
        }
        status = "BLOCKED"
    else:
        if independent_receipt.get("builder_signed") is True:
            raise ValueError("BUILDER_PASS_FORBIDDEN")
        if independent_receipt.get("candidate_sha") != candidate:
            output = {
                "verdict": "BLOCKED",
                "evidence": [{"note": "STALE_PASS_CANDIDATE_CHANGED", "test_only": True}],
                "scope": inputs["scope"],
            }
            status = "BLOCKED"
        else:
            output = {
                "verdict": "PASS",
                "evidence": [{"note": "independent receipt", "test_only": True, "runtime_pass": False}],
                "scope": inputs["scope"],
            }
            status = "OK"
    if set(output) != {"verdict", "evidence", "scope"}:
        raise ValueError("N11_SHAPE_MISMATCH")
    return emit_envelope(node_id="N11", at=at, inputs=dict(inputs), status=status, output=output)


def _write_row(store: Path, kind: str, row: Mapping[str, Any], written: list[dict]) -> None:
    object_id = str(row.get("id") or row.get("receipt_id") or row.get("decision_id") or row.get("evidence_id"))
    path = safe_path(store / f"{kind}-{object_id}.json", store)
    if path.exists():
        raise ValueError("SUPERSEDE_OVERWRITE")
    payload = canonical(dict(row)) + b"\n"
    write_once(path, dict(row))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("WRITTEN_SHA_MISMATCH")
    written.append({"object": kind, "path": path.name, "sha256": digest})


def run_n12(inputs: Mapping[str, Any], *, at: str, store_root: Path) -> dict:
    """Capture decisions, evidence, and receipts. Receipts are written first."""
    if set(inputs) != N12_KEYS:
        raise ValueError("N12_SHAPE_MISMATCH")
    store = store_root / "capture"
    store.mkdir(parents=True, exist_ok=True)
    written: list[dict] = []
    superseded = []
    groups = (
        ("Receipt", list(inputs["receipts"])),
        ("Decision", list(inputs["decisions"])),
        ("Evidence", list(inputs["evidence"])),
        ("Failure", list(inputs["failures"])),
    )
    if written and groups[0][0] != "Receipt":
        raise ValueError("RECEIPT_NOT_FIRST")
    for kind, rows in groups:
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("N12_SHAPE_MISMATCH")
            if row.get("kind") == "log":
                raise ValueError("LOG_NOISE_WRITTEN")
            _write_row(store, kind, row, written)
            old_id = row.get("supersedes")
            if old_id:
                superseded.append({"old_id": old_id, "new_id": row.get("id"), "link": f"supersedes:{old_id}"})
    output = {"written": written, "superseded": superseded}
    if set(output) != {"written", "superseded"}:
        raise ValueError("N12_SHAPE_MISMATCH")
    return emit_envelope(node_id="N12", at=at, inputs=dict(inputs), status="OK", output=output)


def run_n13(inputs: Mapping[str, Any], *, at: str, notified: set[str] | None = None) -> dict:
    """Board entry. The four states stay separate. Each blocker is notified once."""
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
    blocked = verify_state == "BLOCKED" or handoff_state not in {"READY", "OK"}
    state = "BLOCKED" if blocked else str(outcome)
    owner = "reviewer" if verify_state == "BLOCKED" else "builder"
    if not owner:
        raise ValueError("NEXT_ACTION_MISSING")
    blocker = f"{verify_state}|{handoff_state}"
    seen = notified if notified is not None else set()
    if blocker in seen and blocked:
        notify_once = False
    else:
        if blocked:
            seen.add(blocker)
        notify_once = True
    if blocked and blocker in seen and notify_once is False:
        pass
    output = {
        "state": state,
        "evidence_links": [
            f"outcome:{outcome}",
            f"verify_state:{verify_state}",
            f"writeback_state:{writeback_state}",
            f"handoff_state:{handoff_state}",
        ],
        "next_legal_action": "wait-for-independent-verify" if verify_state == "BLOCKED" else "handoff",
        "owner": owner,
        "notify_once": notify_once,
    }
    if not output["next_legal_action"] or not output["owner"]:
        raise ValueError("NEXT_ACTION_MISSING")
    if set(output) != {"state", "evidence_links", "next_legal_action", "owner", "notify_once"}:
        raise ValueError("N13_SHAPE_MISMATCH")
    return emit_envelope(node_id="N13", at=at, inputs=dict(inputs), status="OK" if not blocked else "BLOCKED", output=output)
