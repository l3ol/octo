"""Builder selftest only. Not product acceptance, independent verification, or runtime_pass."""
import json
from pathlib import Path

import pytest

from octo.envelope import validate_envelope
from octo.nodes import emit_envelope, run_n1, run_n3, run_n8
from octo.objects import inputs_hash
from octo.standard import run_prefix

ROOT = Path(__file__).resolve().parents[1]
PLAN = json.loads((ROOT / "docs/spec/g2-s1/PLAN-NODE-OUTPUTS.json").read_text(encoding="utf-8"))
AT = "2026-11-01T12:00:00+00:00"


def _assert_envelope(envelope: dict) -> None:
    sealed = validate_envelope(envelope)
    assert sealed.inputs_hash == inputs_hash(envelope["inputs"]) == envelope["inputs_hash"]
    assert envelope["node_id"] not in {"N6", "N7"}
    assert "DEGRADED_SKIP" not in envelope["status"]
    assert envelope["output"] is None or "N6" != envelope["output"].get("node_id")


def _pack() -> dict:
    n1_in = PLAN["nodes"]["N1"]["input"]
    n1 = run_n1(n1_in, at=AT)
    intent = n1["output"]
    return {
        "n1": n1_in,
        "n2": {"intent_id": intent["intent_id"]},
        "n2_bound": {
            "current_decisions": ["S1_CONTROLLED_REUSE"],
            "key_evidence": ["CCI"],
            "open_states": ["kill_line SOURCE_UNAVAILABLE", "N6/N7 not run this stage"],
            "prohibitions": ["No merge"],
            "assembled_at": "TEST_FIXTURE",
            "sources": ["CHIEF-CONSENSUS-INSTRUCTION-G2-S1.json"],
        },
        "n3": {
            "intent": intent,
            "context_pack": {"intent_id": intent["intent_id"]},
            "新事实/偏差信号": {"kill_line_ref": "SOURCE_UNAVAILABLE"},
        },
        "n4": {"intent": intent},
        "n4_bound": {
            "candidates": [
                {
                    "type": "internal",
                    "ref": "repo",
                    "fit": "TEST_FIXTURE inventory",
                    "cost_hint": "low",
                }
            ]
        },
        "n5": {"claims": ["kill_line frozen business value exists"]},
        "n5_bound": {
            "facts": [
                {
                    "claim": "kill_line frozen business value exists",
                    "verdict": "CLAIM",
                    "evidence_ref": "SOURCE_UNAVAILABLE",
                    "freshness": "TEST_FIXTURE",
                }
            ],
            "gaps": ["kill_line source"],
        },
        "n8": {
            "intent": intent,
            "options": json.loads(n1_in["text"])["execution_options"],
        },
    }


def test_each_prefix_node_envelope_recomputes_inputs_hash():
    result = run_prefix(
        {"action_type": "internal_readonly", "grant_ref": "grant-ref-s1-test"},
        _pack(),
        at=AT,
    )
    assert result["status"] == "OK"
    assert result["selftest"] == "builder"
    ids = [item["node_id"] for item in result["envelopes"]]
    assert ids == ["N1", "N2", "N3", "N4", "N5", "N8"]
    for envelope in result["envelopes"]:
        _assert_envelope(envelope)
    n1 = result["envelopes"][0]["output"]
    assert n1["intent_id"] == "intent-PRODUCT-BUILD-2026-11-01-G2-S1-TB-01"
    assert set(n1) == {"intent_id", "normalized_goal", "expected_output", "project", "state"}
    n3 = result["envelopes"][2]["output"]
    assert n3["still_worth_it"] is True
    assert n3["kill_line"] == "SOURCE_UNAVAILABLE"
    assert n3["fixture"] == "TEST_FIXTURE"
    n5 = result["envelopes"][4]["output"]
    assert n5["facts"][0]["verdict"] == "CLAIM"
    n8 = result["envelopes"][5]
    assert n8["inputs"]["options"][0]["id"] == "S1_CONTROLLED_REUSE"
    assert n8["inputs"]["options"][0]["not_a_node_N6_output"] is True
    assert n8["output"]["mvp"]["not_in_scope"] == ["N6", "N7"]
    assert "n6_output" not in n8["output"]["mvp"]


def test_standard_run_emits_no_n6_n7_envelopes():
    result = run_prefix(
        {"action_type": "internal_readonly", "grant_ref": "grant-ref-s1-test"},
        _pack(),
        at=AT,
    )
    assert [item["node_id"] for item in result["envelopes"]] == ["N1", "N2", "N3", "N4", "N5", "N8"]
    assert all(item["node_id"] not in {"N6", "N7"} for item in result["envelopes"])
    exclusions = result["scope_exclusions"]
    assert exclusions["kind"] == "scope_exclusions"
    assert exclusions["nodes"]["N6"]["emitted"] is False
    assert exclusions["nodes"]["N7"]["emitted"] is False
    with pytest.raises(Exception):
        validate_envelope(exclusions)
    with pytest.raises(RuntimeError, match="N6"):
        emit_envelope(
            node_id="N6",
            at=AT,
            inputs={},
            status="NOT_RUN_THIS_STAGE",
            output=None,
        )
    with pytest.raises(RuntimeError, match="N7"):
        emit_envelope(
            node_id="N7",
            at=AT,
            inputs={},
            status="NOT_RUN_THIS_STAGE",
            output=None,
        )


def test_full_action_stops_without_node_envelopes():
    result = run_prefix({"action_type": "delete", "grant_ref": "grant-ref-s1-test"}, _pack(), at=AT)
    assert result["status"] == "BLOCKED"
    assert result["envelopes"] == []
    assert result["scope_exclusions"]["nodes"]["N6"]["emitted"] is False


def test_n8_rejects_fake_n6_options():
    intent = run_n1(PLAN["nodes"]["N1"]["input"], at=AT)["output"]
    with pytest.raises(ValueError, match="N6"):
        run_n8({"intent": intent, "options": [{"id": "x", "n6_output": {"fake": True}}]}, at=AT)


def test_n3_named_kill_line_does_not_invent_continuation():
    intent = {"intent_id": "intent-1", "state": "ACTIVE"}
    envelope = run_n3(
        {
            "intent": intent,
            "context_pack": {"intent_id": "intent-1"},
            "新事实/偏差信号": {"kill_line": "budget-exhausted"},
        },
        at=AT,
    )
    assert envelope["output"]["still_worth_it"] is False
    assert envelope["output"]["fixture"] == "TEST_FIXTURE"
