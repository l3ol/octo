"""N5 stale and missing-evidence negatives. Builder selftest only. runtime_pass stays false."""
import json
from pathlib import Path

import pytest

from octo.nodes import run_n5

ROOT = Path(__file__).resolve().parents[1]
PLAN = json.loads((ROOT / "docs/spec/g2-s1/PLAN-NODE-OUTPUTS.json").read_text(encoding="utf-8"))
AT = "2026-11-01T12:00:00+00:00"
FACT_KEYS = {"claim", "verdict", "evidence_ref", "freshness"}
OUTPUT_KEYS = {"facts", "gaps"}


def _row(envelope: dict) -> dict:
    assert envelope["node_id"] == "N5"
    assert set(envelope["output"]) == OUTPUT_KEYS
    fact = envelope["output"]["facts"][0]
    assert set(fact) == FACT_KEYS
    assert fact["verdict"] in {"FACT", "CLAIM", "STALE"}
    return fact


def test_ac_n5_01_fact_requires_fresh_readable_ref():
    with pytest.raises(ValueError, match="FACT_WITHOUT_EVIDENCE"):
        run_n5(
            {"claims": ["bare"]},
            at=AT,
            bound={"facts": [{"claim": "bare", "verdict": "FACT", "evidence_ref": "", "freshness": "fresh"}]},
        )
    with pytest.raises(ValueError, match="FACT_WITHOUT_EVIDENCE"):
        run_n5(
            {"claims": ["warm"]},
            at=AT,
            bound={"facts": [{"claim": "warm", "verdict": "FACT", "evidence_ref": "notes/a.txt", "freshness": "warm"}]},
        )


def test_ac_n5_02_stale_or_expired_is_not_fact(tmp_path):
    missing = run_n5(
        {"claims": ["old"]},
        at=AT,
        bound={"facts": [{"claim": "old", "verdict": "FACT", "evidence_ref": "missing-note", "freshness": "stale"}]},
    )
    row = _row(missing)
    assert row["verdict"] == "STALE"
    assert row["verdict"] != "FACT"
    assert "recollect:old" in missing["output"]["gaps"]
    assert "SOURCE_UNAVAILABLE" in missing["output"]["gaps"]
    assert missing["status"] == "SOURCE_UNAVAILABLE"
    opened = tmp_path / "aged.txt"
    opened.write_text("still here", encoding="utf-8")
    expired = run_n5(
        {"claims": ["aged"]},
        at=AT,
        bound={"facts": [{"claim": "aged", "verdict": "FACT", "evidence_ref": str(opened), "freshness": "expired"}]},
    )
    expired_row = _row(expired)
    assert expired_row["verdict"] == "STALE"
    assert expired_row["verdict"] != "FACT"
    assert "recollect:aged" in expired["output"]["gaps"]
    assert (tmp_path / "aged.txt.recollect.json").is_file()


def test_ac_n5_03_unreadable_fact_is_demoted_to_claim():
    envelope = run_n5(
        {"claims": ["dark"]},
        at=AT,
        bound={"facts": [{"claim": "dark", "verdict": "FACT", "evidence_ref": "no-such-evidence", "freshness": "fresh"}]},
    )
    row = _row(envelope)
    assert row["verdict"] == "CLAIM"
    assert row["verdict"] != "FACT"
    assert "SOURCE_UNAVAILABLE" in envelope["output"]["gaps"]
    assert envelope["status"] == "SOURCE_UNAVAILABLE"


def test_ac_n5_04_unlisted_claim_is_partial():
    envelope = run_n5({"claims": ["not-listed"]}, at=AT)
    row = _row(envelope)
    assert row["verdict"] == "CLAIM"
    assert "not-listed" in envelope["output"]["gaps"]
    assert envelope["status"] == "PARTIAL"
    assert envelope["node_id"] not in {"N6", "N7"}


def test_ac_n5_05_output_fields_stay_the_plan_names(tmp_path):
    notes = PLAN["nodes"]["N5"]["notes"]
    assert "FACT/CLAIM/STALE" in notes
    opened = tmp_path / "fresh.txt"
    opened.write_text("open", encoding="utf-8")
    envelope = run_n5(
        {"claims": ["seen"]},
        at=AT,
        bound={"facts": [{"claim": "seen", "verdict": "FACT", "evidence_ref": str(opened), "freshness": "fresh"}]},
    )
    row = _row(envelope)
    assert row["verdict"] == "FACT"
    assert envelope["status"] == "OK"
    assert set(envelope["inputs"]) == {"claims"}
    assert envelope["node_id"] not in {"N6", "N7"}
