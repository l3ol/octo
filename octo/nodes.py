"""Standard node runners N1, N2, N3, N4, N5, and N8.

Each runner returns a validated T-01 envelope. N6 and N7 are not runners:
this module refuses to build an envelope for either id. Their exclusion is
metadata on the standard run, not a node output.

Builder selftest support only. This module does not claim runtime acceptance.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from octo.envelope import build_envelope, validate_envelope

EXCLUDED_NODE_IDS = ("N6", "N7")
_VERDICTS = frozenset({"FACT", "CLAIM", "STALE"})
_CANDIDATE_TYPES = frozenset({"internal", "oss", "saas", "api", "mcp"})


def scope_exclusions() -> dict[str, Any]:
    """Non-node metadata. Not an envelope and not a degrade status."""
    return {
        "kind": "scope_exclusions",
        "emitted_envelopes": False,
        "nodes": {
            "N6": {"emitted": False, "reason": "not run this stage"},
            "N7": {"emitted": False, "reason": "not run this stage"},
        },
    }


def _exact_keys(inputs: Mapping[str, Any], keys: set[str]) -> None:
    if set(inputs) != keys:
        raise ValueError(f"input keys {sorted(inputs)} != {sorted(keys)}")


def emit_envelope(
    *,
    node_id: str,
    at: str,
    inputs: dict,
    status: str,
    output: dict | None,
) -> dict:
    """Build and validate one envelope. N6 and N7 cannot be emitted."""
    if node_id in EXCLUDED_NODE_IDS:
        raise RuntimeError(f"{node_id} envelope is not emitted on the Standard path")
    if isinstance(status, str) and "DEGRADED_SKIP" in status:
        raise RuntimeError("invented degrade status")
    envelope = build_envelope(
        node_id=node_id,
        at=at,
        inputs=inputs,
        status=status,
        output=output,
    )
    validate_envelope(envelope)
    return envelope


def _clarification(inputs: dict, *, at: str, intent_id: str) -> dict:
    output = {
        "intent_id": intent_id,
        "normalized_goal": "intent unclear",
        "expected_output": [
            {"choice": "restate one observable goal"},
            {"choice": "stop this request"},
        ],
        "project": "",
        "state": "NEEDS_CLARIFICATION",
    }
    return emit_envelope(
        node_id="N1",
        at=at,
        inputs=inputs,
        status="NEEDS_CLARIFICATION",
        output=output,
    )


def run_n1(inputs: Mapping[str, Any], *, at: str) -> dict:
    """N1 input ``{text, source}``. Unclear text is NEEDS_CLARIFICATION, never ACTIVE."""
    _exact_keys(inputs, {"text", "source"})
    text = inputs["text"]
    source = inputs["source"]
    if not isinstance(source, dict) or not source:
        return emit_envelope(
            node_id="N1",
            at=at,
            inputs=dict(inputs),
            status="BLOCKED",
            output={
                "intent_id": "intent-unspecified",
                "normalized_goal": "source missing",
                "expected_output": "",
                "project": "",
                "state": "BLOCKED",
            },
        )
    if not isinstance(text, str) or not text.strip():
        return _clarification(dict(inputs), at=at, intent_id="intent-unspecified")
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = None
    if not isinstance(document, dict) or not document.get("dispatch_id"):
        return _clarification(dict(inputs), at=at, intent_id="intent-unspecified")
    scope = document.get("scope") if isinstance(document.get("scope"), dict) else {}
    nodes = scope.get("nodes") if isinstance(scope.get("nodes"), list) else []
    goal = f"Standard {scope.get('route', 'internal_readonly')} on {scope.get('implementation_branch', 'unspecified')}"
    if nodes:
        goal = f"{goal}; nodes={','.join(str(node) for node in nodes)}"
    output = {
        "intent_id": f"intent-{document['dispatch_id']}",
        "normalized_goal": goal,
        "expected_output": document.get("stop") or "",
        "project": document.get("product") or "",
        "state": "ACTIVE",
    }
    return emit_envelope(node_id="N1", at=at, inputs=dict(inputs), status="OK", output=output)


def run_n2(inputs: Mapping[str, Any], *, at: str, bound: Mapping[str, Any] | None = None) -> dict:
    """N2 input is only ``{intent_id}``. Bound context is not part of the hash."""
    _exact_keys(inputs, {"intent_id"})
    if not isinstance(inputs["intent_id"], str) or not inputs["intent_id"]:
        raise ValueError("intent_id required")
    material = dict(bound or {})
    gaps = list(material.get("gaps", []))
    decisions = []
    for index, row in enumerate(material.get("current_decisions", [])):
        if isinstance(row, str):
            decisions.append({
                "decision_id": f"d{index}",
                "content": row,
                "decided_at": at,
                "decider": "TEST_FIXTURE",
                "supersedes": None,
            })
        else:
            decisions.append(dict(row))
    evidence = []
    for index, row in enumerate(material.get("key_evidence", [])):
        if isinstance(row, str):
            evidence.append({
                "evidence_id": f"e{index}",
                "uri_or_hash": row,
                "freshness": "fresh",
                "collected_at": at,
            })
        else:
            evidence.append(dict(row))
    open_states = list(material.get("open_states", ["N6/N7 not run this stage"]))
    status = "OK"
    if gaps or material.get("source_unavailable"):
        status = "PARTIAL"
        for gap in gaps:
            label = f"gap:{gap}"
            if label not in open_states:
                open_states.append(label)
        if not gaps:
            open_states.append("gap:SOURCE_UNAVAILABLE")
    output = {
        "intent_id": inputs["intent_id"],
        "current_decisions": decisions,
        "key_evidence": evidence,
        "open_states": open_states,
        "prohibitions": list(material.get("prohibitions", [])),
        "assembled_at": material.get("assembled_at", at),
        "sources": list(material.get("sources", [])),
    }
    return emit_envelope(
        node_id="N2",
        at=at,
        inputs={"intent_id": inputs["intent_id"]},
        status=status,
        output=output,
    )


def guard_consequential(pack_status: str, action: str) -> None:
    """A consequential action must not proceed on a PARTIAL context pack."""
    if pack_status == "PARTIAL" and action not in {"internal_readonly", "read"}:
        raise ValueError("CONSEQUENTIAL_ON_PARTIAL")


def run_n3(inputs: Mapping[str, Any], *, at: str) -> dict:
    """SOURCE_UNAVAILABLE continues the frozen worth judgment. Mark TEST_FIXTURE."""
    _exact_keys(inputs, {"intent", "context_pack", "新事实/偏差信号"})
    signal = inputs["新事实/偏差信号"]
    if not isinstance(inputs["intent"], dict) or not isinstance(inputs["context_pack"], dict):
        raise ValueError("N3 intent and context_pack must be objects")
    if not isinstance(signal, dict):
        raise ValueError("N3 deviation signal must be an object")
    kill = signal.get("kill_line", signal.get("kill_line_ref", "SOURCE_UNAVAILABLE"))
    if kill in (None, "", "SOURCE_UNAVAILABLE"):
        output = {
            "still_worth_it": True,
            "reason": "criteria insufficient; frozen worth judgment continues. TEST_FIXTURE",
            "kill_line": "SOURCE_UNAVAILABLE",
        }
    elif isinstance(kill, str):
        raise ValueError("NO_TOUCH_COMPARISON")
    elif not isinstance(kill, dict) or kill.get("label") != "TEST_FIXTURE" or "threshold" not in kill:
        raise ValueError("KILL_LINE_PRESENCE_ONLY")
    elif "observed" not in signal:
        raise ValueError("NO_TOUCH_COMPARISON")
    elif signal["observed"] >= kill["threshold"]:
        output = {
            "still_worth_it": False,
            "reason": "signal crosses TEST_FIXTURE kill_line. Chief choice: continue or stop. Project is not killed.",
            "kill_line": kill,
        }
    else:
        output = {
            "still_worth_it": True,
            "reason": "signal is below TEST_FIXTURE kill_line. Presence alone did not decide.",
            "kill_line": kill,
        }
    return emit_envelope(
        node_id="N3",
        at=at,
        inputs=dict(inputs),
        status="OK",
        output=output,
    )


def run_n4(inputs: Mapping[str, Any], *, at: str, bound: Mapping[str, Any] | None = None) -> dict:
    """N4 is a candidate inventory. It does not adjudicate evidence."""
    _exact_keys(inputs, {"intent"})
    if not isinstance(inputs["intent"], dict):
        raise ValueError("N4 intent must be an object")
    rows = list((bound or {}).get("candidates", []))
    candidates = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"type", "ref", "fit", "cost_hint"}:
            raise ValueError("candidate shape is type, ref, fit, cost_hint")
        if row["type"] not in _CANDIDATE_TYPES:
            raise ValueError("candidate type is not in the inventory set")
        candidates.append(dict(row))
    return emit_envelope(
        node_id="N4",
        at=at,
        inputs={"intent": dict(inputs["intent"])},
        status="OK",
        output={"candidates": candidates},
    )


def _readable_evidence(evidence_ref: str) -> Path | None:
    """A FACT source has to be a file that opens. Labels and the string ``fresh`` do not."""
    if not isinstance(evidence_ref, str):
        return None
    text = evidence_ref.strip()
    if text in {"", "fresh", "UNADJUDICATED", "SOURCE_UNAVAILABLE"}:
        return None
    path = Path(text)
    try:
        if path.is_file() and path.stat().st_size >= 0:
            path.read_bytes()
            return path
    except OSError:
        return None
    return None


def _mark_source_unavailable(gaps: list, node_status: str) -> str:
    if "SOURCE_UNAVAILABLE" not in gaps:
        gaps.append("SOURCE_UNAVAILABLE")
    return "SOURCE_UNAVAILABLE"


def _start_recollect(path: Path, claim: str, gaps: list) -> str:
    """Re-read a stale file and write a recollect marker beside it.

    If the marker cannot be written, the source stays SOURCE_UNAVAILABLE.
    A ``recollect:`` label alone is not a completed recollect.
    """
    try:
        data = path.read_bytes()
        marker = path.with_name(path.name + ".recollect.json")
        if marker.parent.resolve() != path.parent.resolve():
            return _mark_source_unavailable(gaps, "SOURCE_UNAVAILABLE")
        if not marker.exists():
            payload = json.dumps(
                {
                    "claim": claim,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "recollect": True,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            marker.write_bytes(payload)
        elif marker.read_bytes() == b"":
            return _mark_source_unavailable(gaps, "SOURCE_UNAVAILABLE")
    except OSError:
        return _mark_source_unavailable(gaps, "SOURCE_UNAVAILABLE")
    return "PARTIAL"


def run_n5(inputs: Mapping[str, Any], *, at: str, bound: Mapping[str, Any] | None = None) -> dict:
    """N5 adjudicates claims as FACT, CLAIM, or STALE. Unlisted claims stay CLAIM."""
    _exact_keys(inputs, {"claims"})
    claims = inputs["claims"]
    if not isinstance(claims, list) or not all(isinstance(item, str) for item in claims):
        raise ValueError("claims must be a list of strings")
    supplied = {
        row["claim"]: row
        for row in (bound or {}).get("facts", [])
        if isinstance(row, dict) and "claim" in row
    }
    facts = []
    gaps = list((bound or {}).get("gaps", []))
    node_status = "OK"
    for claim in claims:
        row = supplied.get(claim)
        if row is None:
            facts.append({
                "claim": claim,
                "verdict": "CLAIM",
                "evidence_ref": "UNADJUDICATED",
                "freshness": "TEST_FIXTURE",
            })
            if claim not in gaps:
                gaps.append(claim)
            if node_status == "OK":
                node_status = "PARTIAL"
            continue
        verdict = row.get("verdict")
        evidence_ref = row.get("evidence_ref") or ""
        freshness = row.get("freshness", "")
        if freshness in {"stale", "expired"}:
            verdict = "STALE"
        if verdict == "FACT" and (not evidence_ref or freshness != "fresh"):
            raise ValueError("FACT_WITHOUT_EVIDENCE")
        if verdict not in _VERDICTS:
            raise ValueError("verdict must be FACT, CLAIM, or STALE")
        if verdict == "STALE":
            token = f"recollect:{claim}"
            if token not in gaps:
                gaps.append(token)
            opened = _readable_evidence(evidence_ref)
            if opened is None:
                node_status = _mark_source_unavailable(gaps, node_status)
            else:
                recollect_status = _start_recollect(opened, claim, gaps)
                if recollect_status == "SOURCE_UNAVAILABLE" or node_status != "SOURCE_UNAVAILABLE":
                    node_status = recollect_status
        elif verdict == "FACT":
            opened = _readable_evidence(evidence_ref)
            if opened is None:
                verdict = "CLAIM"
                node_status = _mark_source_unavailable(gaps, node_status)
        facts.append({
            "claim": claim,
            "verdict": verdict,
            "evidence_ref": evidence_ref,
            "freshness": freshness or "TEST_FIXTURE",
        })
    return emit_envelope(
        node_id="N5",
        at=at,
        inputs={"claims": list(claims)},
        status=node_status,
        output={"facts": facts, "gaps": gaps},
    )


def run_n8(inputs: Mapping[str, Any], *, at: str) -> dict:
    """N8 options are the caller's execution_options. They are not an N6 output."""
    _exact_keys(inputs, {"intent", "options"})
    if not isinstance(inputs["intent"], dict):
        raise ValueError("N8 intent must be an object")
    options = inputs["options"]
    if not isinstance(options, list) or not options:
        raise ValueError("execution_options required")
    for option in options:
        if not isinstance(option, dict):
            raise ValueError("execution option must be an object")
        if option.get("node_id") in EXCLUDED_NODE_IDS or "n6_output" in option:
            raise ValueError("N6 output cannot be used as N8 options")
    acceptance = []
    for option in options:
        proposed = option.get("measurable_acceptance", option.get("acceptance", option.get("description", "")))
        if proposed == option.get("id"):
            raise ValueError("OPTION_ID_AS_ACCEPTANCE")
        if isinstance(proposed, str) and _measurable(proposed):
            acceptance.append(proposed)
        elif str(proposed).strip().lower() == "works well":
            return emit_envelope(
                node_id="N8",
                at=at,
                inputs={"intent": dict(inputs["intent"]), "options": json.loads(json.dumps(options))},
                status="NEEDS_CLARIFICATION",
                output={"mvp": {"scope": {"option_ids": [option.get("id")]}, "acceptance": [], "not_in_scope": ["N6", "N7"]}},
            )
    if not acceptance:
        raise ValueError("ACCEPTANCE_NOT_MEASURABLE")
    output = {
        "mvp": {
            "scope": {"route": "Standard internal_readonly", "option_ids": [option.get("id") for option in options]},
            "acceptance": acceptance,
            "not_in_scope": ["N6", "N7"],
        }
    }
    return emit_envelope(
        node_id="N8",
        at=at,
        inputs={"intent": dict(inputs["intent"]), "options": json.loads(json.dumps(options))},
        status="OK",
        output=output,
    )


def _measurable(text: str) -> bool:
    if not isinstance(text, str):
        return False
    lowered = text.strip().lower()
    if lowered in {"", "works well"}:
        return False
    return any(token in lowered for token in ("exit", "sha256", "pytest", "bytes", "==", ">=", "count"))
