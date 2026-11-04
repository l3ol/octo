"""N1 bad-input negatives. Builder selftest only. runtime_pass stays false."""
import json
from pathlib import Path

import pytest

from octo.nodes import run_n1

ROOT = Path(__file__).resolve().parents[1]
PLAN = json.loads((ROOT / "docs/spec/g2-s1/PLAN-NODE-OUTPUTS.json").read_text(encoding="utf-8"))
AT = "2026-11-01T12:00:00+00:00"
CCI_SHA = "958fa84d417ff13eab55dfd32e30f329f365f86e41bb8a9d8f91c91a82745d0b"
N1_OUTPUT = {"intent_id", "normalized_goal", "expected_output", "project", "state"}
SOURCE = {"kind": "cci_sha256", "sha256": CCI_SHA}


def _not_active(envelope: dict) -> None:
    assert envelope["output"]["state"] != "ACTIVE"
    assert envelope["status"] != "OK"
    assert envelope["node_id"] == "N1"
    assert set(envelope["output"]) == N1_OUTPUT


def test_ac_n1_01_exact_keys_do_not_emit_active():
    with pytest.raises(ValueError, match="input keys"):
        run_n1({"text": "{}", "source": SOURCE, "extra": 1}, at=AT)
    with pytest.raises(ValueError, match="input keys"):
        run_n1({"text": "{}"}, at=AT)


def test_ac_n1_02_empty_or_non_dict_source_is_blocked():
    for source in ({}, "cci", None, []):
        envelope = run_n1({"text": "{\"dispatch_id\":\"x\"}", "source": source}, at=AT)
        assert envelope["status"] == "BLOCKED"
        assert envelope["output"]["state"] == "BLOCKED"
        _not_active(envelope)


def test_ac_n1_03_empty_or_non_str_text_needs_clarification():
    for text in ("", "   ", None, 12):
        envelope = run_n1({"text": text, "source": SOURCE}, at=AT)
        assert envelope["status"] == "NEEDS_CLARIFICATION"
        assert envelope["output"]["state"] == "NEEDS_CLARIFICATION"
        _not_active(envelope)


def test_ac_n1_04_bad_json_or_missing_dispatch_needs_clarification():
    for text in ("not-json", "[1,2]", "{\"product\":\"Octo\"}", "null"):
        envelope = run_n1({"text": text, "source": SOURCE}, at=AT)
        assert envelope["status"] == "NEEDS_CLARIFICATION"
        assert envelope["output"]["state"] == "NEEDS_CLARIFICATION"
        _not_active(envelope)


def test_ac_n1_05_cci_like_text_and_source_is_active():
    text = json.dumps({"dispatch_id": "PRODUCT-BUILD-2026-11-01-G2-S1-TB-01", "product": "Octo"})
    envelope = run_n1({"text": text, "source": dict(SOURCE)}, at=AT)
    assert envelope["status"] == "OK"
    assert envelope["output"]["state"] == "ACTIVE"
    assert envelope["output"]["intent_id"] == "intent-PRODUCT-BUILD-2026-11-01-G2-S1-TB-01"
    assert set(envelope["inputs"]) == {"text", "source"}
    assert set(envelope["output"]) == N1_OUTPUT


def test_ac_n1_06_plan_text_is_cci_utf8_and_source_binds_sha():
    recorded = PLAN["nodes"]["N1"]
    assert recorded["notes"] == "text = exact UTF-8 decode of CCI bytes; source object binds CCI sha256."
    assert recorded["input"]["source"]["sha256"] == CCI_SHA
    text = recorded["input"]["text"]
    assert isinstance(text, str)
    document = json.loads(text)
    assert document["dispatch_id"] == "PRODUCT-BUILD-2026-11-01-G2-S1-TB-01"
    envelope = run_n1(recorded["input"], at=AT)
    assert envelope["status"] == "OK"
    assert envelope["output"]["state"] == "ACTIVE"
    assert envelope["output"]["intent_id"] == "intent-PRODUCT-BUILD-2026-11-01-G2-S1-TB-01"
    assert envelope["output"]["project"] == "Octo Company Continuity Layer"
    assert set(envelope["output"]) == N1_OUTPUT
    assert envelope["node_id"] not in {"N6", "N7"}
