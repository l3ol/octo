"""Standard prefix: N1, N2, N3, N4, N5, N8.

The run metadata names N6 and N7 in ``scope_exclusions``. It does not build
envelopes for them. A route that is not OK yields no node envelopes.

Builder selftest support only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from octo.closing import handoff_state_from_n11, run_n11, run_n12, run_n13, writeback_state_from_n12
from octo.gateway import run_n10
from octo.n9 import run_n9
from octo.nodes import (
    EXCLUDED_NODE_IDS,
    emit_envelope,
    guard_consequential,
    run_n1,
    run_n2,
    run_n3,
    run_n4,
    run_n5,
    run_n8,
    scope_exclusions,
)
from octo.router import route

PREFIX_NODE_IDS = ("N1", "N2", "N3", "N4", "N5", "N8")
N2_PACK_KEYS = frozenset({
    "intent_id",
    "current_decisions",
    "key_evidence",
    "open_states",
    "prohibitions",
    "assembled_at",
    "sources",
})
_READONLY = frozenset({"internal_readonly", "read"})


def reject_excluded_envelopes(envelopes: list[dict]) -> None:
    for envelope in envelopes:
        if envelope.get("node_id") in EXCLUDED_NODE_IDS:
            raise RuntimeError("Standard run yielded an N6 or N7 envelope")
        if envelope.get("status") == "NOT_RUN_THIS_STAGE":
            raise RuntimeError("NOT_RUN_THIS_STAGE is not emitted as a Standard placeholder")


def _foreign_intent(value: Any, intent_id: str) -> bool:
    if not isinstance(value, dict):
        return False
    found = value.get("intent_id")
    return isinstance(found, str) and found != intent_id


def _stop(body: dict[str, Any], envelopes: list[dict], status: str) -> dict[str, Any]:
    reject_excluded_envelopes(envelopes)
    body["envelopes"] = envelopes
    body["status"] = status
    body["readonly_continue"] = False
    return body


def run_prefix(route_request: Mapping[str, Any], pack: Mapping[str, Any], *, at: str) -> dict[str, Any]:
    """Run the Standard prefix. A degraded node stops the chain instead of staying OK."""
    decision = route(
        route_request,
        upgrade=bool(pack.get("upgrade", False)),
        upgrade_reason=str(pack.get("upgrade_reason", "")),
    )
    exclusions = scope_exclusions()
    body = {
        "status": decision.status,
        "envelopes": [],
        "scope_exclusions": exclusions,
        "decision": decision.to_dict(),
        "selftest": "builder",
        "readonly_continue": False,
    }
    if decision.status != "OK":
        return body
    action = str(route_request.get("action_type", ""))
    n1 = run_n1(pack["n1"], at=at)
    envelopes = [n1]
    if n1["status"] != "OK":
        return _stop(body, envelopes, n1["status"])
    intent = n1["output"]
    intent_id = intent["intent_id"]
    if _foreign_intent(pack.get("n2"), intent_id):
        return _stop(body, envelopes, "BLOCKED")
    n2 = run_n2({"intent_id": intent_id}, at=at, bound=pack.get("n2_bound"))
    envelopes.append(n2)
    if set(n2["output"]) != N2_PACK_KEYS:
        raise RuntimeError("N2 pack is missing the seven frozen fields")
    degraded = n2["status"] == "PARTIAL"
    if degraded:
        try:
            guard_consequential(n2["status"], action)
        except ValueError:
            return _stop(body, envelopes, "PARTIAL")
    n3_in = pack.get("n3") or {}
    if _foreign_intent(n3_in.get("intent"), intent_id) or _foreign_intent(n3_in.get("context_pack"), intent_id):
        return _stop(body, envelopes, "BLOCKED")
    n3 = run_n3(
        {
            "intent": intent,
            "context_pack": n2["output"],
            "新事实/偏差信号": n3_in["新事实/偏差信号"],
        },
        at=at,
    )
    envelopes.append(n3)
    if n3["output"].get("still_worth_it") is False:
        return _stop(body, envelopes, "BLOCKED")
    if _foreign_intent(pack.get("n4", {}).get("intent") if isinstance(pack.get("n4"), dict) else None, intent_id):
        return _stop(body, envelopes, "BLOCKED")
    n4 = run_n4({"intent": intent}, at=at, bound=pack.get("n4_bound"))
    envelopes.append(n4)
    n5 = run_n5(pack["n5"], at=at, bound=pack.get("n5_bound"))
    envelopes.append(n5)
    if n5["status"] != "OK":
        return _stop(body, envelopes, n5["status"])
    n8_in = pack.get("n8") if isinstance(pack.get("n8"), dict) else {}
    if _foreign_intent(n8_in.get("intent"), intent_id):
        return _stop(body, envelopes, "BLOCKED")
    n8 = run_n8({"intent": intent, "options": n8_in["options"]}, at=at)
    envelopes.append(n8)
    reject_excluded_envelopes(envelopes)
    if tuple(item["node_id"] for item in envelopes) != PREFIX_NODE_IDS:
        raise RuntimeError("Standard prefix node order drifted")
    if n8["status"] != "OK":
        return _stop(body, envelopes, n8["status"])
    body["envelopes"] = envelopes
    body["status"] = "PARTIAL" if degraded else "OK"
    body["readonly_continue"] = bool(degraded and action in _READONLY)
    return body


def _guard_emitter() -> None:
    """Import-time proof that the shared emitter rejects N6 and N7."""
    try:
        emit_envelope(node_id="N6", at="2026-11-01T00:00:00+00:00", inputs={}, status="NOT_RUN_THIS_STAGE", output=None)
    except RuntimeError:
        return
    raise RuntimeError("N6 emitter guard failed")


_guard_emitter()


def _n9_inputs(request) -> dict:
    return {
        "action": request.action,
        "grant_id": request.grant_id,
        "request_digest": request.digest,
    }


def _n10_inputs(request, context_pack: dict) -> dict:
    return {
        "action": request.action,
        "grant_ref": request.grant_id,
        "context_pack": context_pack,
    }


def _n12_receipt_from_n10(n10_env: dict, request, store_root: Path, evidence_refs: list) -> dict:
    """Copy fields the run already has. Missing §5 keys are not invented."""
    receipt_id = (n10_env.get("output") or {}).get("receipt_id")
    journal = {}
    if isinstance(receipt_id, str) and receipt_id:
        path = Path(store_root) / "journal" / f"{receipt_id}.json"
        if path.is_file():
            journal = json.loads(path.read_text(encoding="utf-8"))
    object_id = next((item for item in evidence_refs if isinstance(item, str) and item.startswith("read-")), None)
    row = {
        "receipt_id": receipt_id,
        "grant_id": journal.get("grant_id", getattr(request, "grant_id", None)),
        "request_digest": journal.get("request_digest", getattr(request, "digest", None)),
        "candidate_sha": journal.get("candidate_sha") or journal.get("git_candidate_sha") or getattr(request, "git_candidate_sha", None),
        "action": journal.get("action", getattr(request, "action", None)),
        "object_id": object_id,
        "idempotency_key": journal.get("idempotency_key", getattr(request, "idempotency_key", None)),
        "evidence_refs": list(evidence_refs),
    }
    for key in ("started_at", "finished_at", "state", "verifier"):
        if key in journal:
            row[key] = journal[key]
    return row


def _n2_pack(envelopes: list[dict]) -> dict:
    n2 = next(item for item in envelopes if item["node_id"] == "N2")
    pack = n2["output"]
    if set(pack) != N2_PACK_KEYS:
        raise RuntimeError("N10 context_pack must be the N2 seven-field pack")
    return pack


def run_standard(route_request, pack, *, at: str, request, store, now=None) -> dict[str, Any]:
    """Full S1 run. N6 and N7 stay in scope_exclusions and are never envelopes."""
    body = run_prefix(route_request, pack, at=at)
    proceed = body["status"] == "OK" or (body["status"] == "PARTIAL" and body.get("readonly_continue"))
    if not proceed:
        return body
    held = body["status"]
    gateway = pack["gateway"]
    envelopes = list(body["envelopes"])
    if request.intent_id != envelopes[0]["output"]["intent_id"]:
        body["envelopes"] = envelopes
        body["status"] = "BLOCKED"
        body["readonly_continue"] = False
        return body
    n9_env = run_n9(_n9_inputs(request), at=at, store=store, request=request, now=now)
    envelopes.append(n9_env)
    if n9_env["status"] != "OK":
        body["envelopes"] = envelopes
        body["status"] = n9_env["status"]
        reject_excluded_envelopes(envelopes)
        return body
    context_pack = _n2_pack(envelopes)
    n10_env = run_n10(
        _n10_inputs(request, context_pack),
        at=at,
        gateway=gateway,
        request=request,
        now=now,
    )
    envelopes.append(n10_env)
    if n10_env["status"] != "OK" or n10_env["output"] is None:
        body["envelopes"] = envelopes
        body["status"] = n10_env["status"]
        reject_excluded_envelopes(envelopes)
        return body
    n11_env = run_n11(
        {"candidate_sha": request.git_candidate_sha, "scope": {"route": "internal_readonly"}},
        at=at,
        independent_receipt=pack.get("independent_receipt"),
        store_root=store.root,
    )
    envelopes.append(n11_env)
    evidence_refs = list((n10_env.get("output") or {}).get("evidence_refs") or [])
    n12_inputs = {
        "decisions": [],
        "evidence": [],
        "receipts": [_n12_receipt_from_n10(n10_env, request, store.root, evidence_refs)],
        "failures": [],
    }
    try:
        if not evidence_refs:
            raise ValueError("N10_EVIDENCE_REFS_UNCONSUMED")
        n12_env = run_n12(
            n12_inputs,
            at=at,
            store_root=store.root,
            required_evidence_refs=evidence_refs,
        )
    except (OSError, ValueError):
        n12_env = emit_envelope(
            node_id="N12",
            at=at,
            inputs=n12_inputs,
            status="BLOCKED",
            output={"written": [], "superseded": []},
        )
    envelopes.append(n12_env)
    written = n12_env["output"]["written"] if isinstance(n12_env.get("output"), dict) else []
    written_paths = tuple(row["path"] for row in written if isinstance(row, dict) and row.get("path"))
    writeback_state = writeback_state_from_n12(n12_env)
    handoff_state = handoff_state_from_n11(n11_env)
    n13_env = run_n13(
        {
            "outcome": n10_env["output"]["result"],
            "verify_state": n11_env["output"]["verdict"],
            "writeback_state": writeback_state,
            "handoff_state": handoff_state,
        },
        at=at,
        evidence_refs=written_paths,
        store_root=store.root,
        intent_id=envelopes[0]["output"]["intent_id"],
    )
    envelopes.append(n13_env)
    reject_excluded_envelopes(envelopes)
    body["envelopes"] = envelopes
    if n11_env["status"] != "OK" or n11_env["output"]["verdict"] != "PASS" or writeback_state != "OK":
        body["status"] = "BLOCKED"
    elif held == "PARTIAL":
        body["status"] = "PARTIAL"
    else:
        body["status"] = "OK"
    return body
