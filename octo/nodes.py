"""Standard node runners N1, N2, N3, N4, N5, and N8.

Each runner returns a validated T-01 envelope. N6 and N7 are not runners:
this module refuses to build an envelope for either id. Their exclusion is
metadata on the standard run, not a node output.

Builder selftest support only. This module does not claim runtime acceptance.
"""

from __future__ import annotations

import json
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


def run_n1(inputs: Mapping[str, Any], *, at: str) -> dict:
    """N1 input ``{text, source}``; output intent fields from the CCI text."""
    _exact_keys(inputs, {"text", "source"})
    text = inputs["text"]
    source = inputs["source"]
    if not isinstance(text, str) or not isinstance(source, dict):
        raise ValueError("N1 text and source are required")
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = {}
    if not isinstance(document, dict):
        document = {}
    dispatch = document.get("dispatch_id") or "unscoped"
    scope = document.get("scope") if isinstance(document.get("scope"), dict) else {}
    nodes = scope.get("nodes") if isinstance(scope.get("nodes"), list) else []
    output = {
        "intent_id": f"intent-{dispatch}",
        "normalized_goal": (
            f"Standard {scope.get('route', 'internal_readonly')} "
            f"on {scope.get('implementation_branch', 'unspecified')}"
        ),
        "expected_output": document.get("stop") or "",
        "project": document.get("product") or "",
        "state": "ACTIVE",
    }
    if nodes:
        output["normalized_goal"] = (
            f"{output['normalized_goal']}; nodes={','.join(str(node) for node in nodes)}"
        )
    return emit_envelope(
        node_id="N1",
        at=at,
        inputs=dict(inputs),
        status="OK",
        output=output,
    )


def run_n2(inputs: Mapping[str, Any], *, at: str, bound: Mapping[str, Any] | None = None) -> dict:
    """N2 input is only ``{intent_id}``. Bound context is not part of the hash."""
    _exact_keys(inputs, {"intent_id"})
    if not isinstance(inputs["intent_id"], str) or not inputs["intent_id"]:
        raise ValueError("intent_id required")
    material = dict(bound or {})
    output = {
        "intent_id": inputs["intent_id"],
        "current_decisions": list(material.get("current_decisions", [])),
        "key_evidence": list(material.get("key_evidence", [])),
        "open_states": list(material.get("open_states", ["N6/N7 not run this stage"])),
        "prohibitions": list(material.get("prohibitions", [])),
        "assembled_at": material.get("assembled_at", at),
        "sources": list(material.get("sources", [])),
    }
    return emit_envelope(
        node_id="N2",
        at=at,
        inputs={"intent_id": inputs["intent_id"]},
        status="OK",
        output=output,
    )


def run_n3(inputs: Mapping[str, Any], *, at: str) -> dict:
    """SOURCE_UNAVAILABLE continues the frozen worth judgment. Mark TEST_FIXTURE."""
    _exact_keys(inputs, {"intent", "context_pack", "新事实/偏差信号"})
    signal = inputs["新事实/偏差信号"]
    if not isinstance(inputs["intent"], dict) or not isinstance(inputs["context_pack"], dict):
        raise ValueError("N3 intent and context_pack must be objects")
    if not isinstance(signal, dict):
        raise ValueError("N3 deviation signal must be an object")
    kill = signal.get("kill_line_ref", signal.get("kill_line"))
    if kill in (None, "", "SOURCE_UNAVAILABLE"):
        output = {
            "still_worth_it": True,
            "reason": (
                "kill_line SOURCE_UNAVAILABLE; frozen worth judgment continues. "
                "payload TEST_FIXTURE"
            ),
            "kill_line": "SOURCE_UNAVAILABLE",
            "fixture": "TEST_FIXTURE",
        }
        status = "OK"
    else:
        output = {
            "still_worth_it": False,
            "reason": "kill line is present; continuation is not assumed. payload TEST_FIXTURE",
            "kill_line": kill,
            "fixture": "TEST_FIXTURE",
        }
        status = "OK"
    return emit_envelope(
        node_id="N3",
        at=at,
        inputs=dict(inputs),
        status=status,
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
            continue
        verdict = row.get("verdict")
        if verdict not in _VERDICTS:
            raise ValueError("verdict must be FACT, CLAIM, or STALE")
        facts.append({
            "claim": claim,
            "verdict": verdict,
            "evidence_ref": row.get("evidence_ref", ""),
            "freshness": row.get("freshness", "TEST_FIXTURE"),
        })
    return emit_envelope(
        node_id="N5",
        at=at,
        inputs={"claims": list(claims)},
        status="OK",
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
    output = {
        "mvp": {
            "scope": {
                "route": "Standard internal_readonly",
                "option_ids": [option.get("id") for option in options],
            },
            "acceptance": [str(option.get("id", "")) for option in options],
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
