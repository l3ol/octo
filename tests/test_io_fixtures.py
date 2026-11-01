"""MATRIX fixtures F-N*. Builder selftest only. Not independent acceptance."""
import hashlib
import json
from pathlib import Path

import pytest

from octo.closing import run_n11, run_n12, run_n13
from octo.nodes import guard_consequential, run_n1, run_n2, run_n3, run_n5, run_n8
from octo.objects import digest

AT = "2026-11-01T12:00:00+00:00"
ROOT = Path(__file__).resolve().parents[1]
PLAN = json.loads((ROOT / "docs/spec/g2-s1/PLAN-NODE-OUTPUTS.json").read_text(encoding="utf-8"))


def test_f_n1_01_clear_intent_is_active():
    envelope = run_n1(PLAN["nodes"]["N1"]["input"], at=AT)
    assert envelope["status"] == "OK"
    assert envelope["output"]["state"] == "ACTIVE"
    assert envelope["inputs"]["text"] == PLAN["nodes"]["N1"]["input"]["text"]


def test_f_n1_02_ambiguous_text_needs_choices():
    envelope = run_n1({"text": "maybe later?", "source": {"kind": "note"}}, at=AT)
    assert envelope["status"] == "NEEDS_CLARIFICATION"
    assert envelope["output"]["state"] == "NEEDS_CLARIFICATION"
    assert len(envelope["output"]["expected_output"]) >= 2


def test_f_n1_03_empty_text_is_not_active():
    envelope = run_n1({"text": "  ", "source": {"kind": "note"}}, at=AT)
    assert envelope["output"]["state"] != "ACTIVE"
    assert envelope["status"] == "NEEDS_CLARIFICATION"


def test_f_n2_02_gap_is_partial_and_consequential_blocks():
    envelope = run_n2({"intent_id": "intent-1"}, at=AT, bound={"gaps": ["source-b"]})
    assert envelope["status"] == "PARTIAL"
    assert any(item.startswith("gap:") for item in envelope["output"]["open_states"])
    guard_consequential("PARTIAL", "internal_readonly")
    with pytest.raises(ValueError, match="CONSEQUENTIAL_ON_PARTIAL"):
        guard_consequential(envelope["status"], "delete")


def test_f_n3_01_and_02_compare_threshold_not_presence():
    base = {"intent": {"intent_id": "i"}, "context_pack": {"intent_id": "i"}}
    below = run_n3({**base, "新事实/偏差信号": {"observed": 1, "kill_line": {"label": "TEST_FIXTURE", "threshold": 5}}}, at=AT)
    above = run_n3({**base, "新事实/偏差信号": {"observed": 9, "kill_line": {"label": "TEST_FIXTURE", "threshold": 5}}}, at=AT)
    assert below["output"]["still_worth_it"] is True
    assert above["output"]["still_worth_it"] is False
    assert "Chief choice" in above["output"]["reason"]
    assert "killed" in above["output"]["reason"]


def test_f_n3_03_missing_kill_line_continues():
    envelope = run_n3(
        {"intent": {"intent_id": "i"}, "context_pack": {}, "新事实/偏差信号": {"kill_line_ref": "SOURCE_UNAVAILABLE"}},
        at=AT,
    )
    assert envelope["output"]["still_worth_it"] is True
    assert "TEST_FIXTURE" in envelope["output"]["reason"]


def test_f_n5_02_and_03_claim_and_stale_recollect(tmp_path):
    missing = run_n5({"claims": ["no evidence"]}, at=AT)
    assert missing["output"]["facts"][0]["verdict"] == "CLAIM"
    assert "no evidence" in missing["output"]["gaps"]
    assert missing["status"] == "PARTIAL"
    stale = run_n5(
        {"claims": ["old"]},
        at=AT,
        bound={"facts": [{"claim": "old", "verdict": "FACT", "evidence_ref": "e1", "freshness": "expired"}]},
    )
    assert stale["output"]["facts"][0]["verdict"] == "STALE"
    assert "recollect:old" in stale["output"]["gaps"]
    assert "SOURCE_UNAVAILABLE" in stale["output"]["gaps"]
    assert stale["status"] == "SOURCE_UNAVAILABLE"
    fresh_label = run_n5(
        {"claims": ["label"]},
        at=AT,
        bound={"facts": [{"claim": "label", "verdict": "FACT", "evidence_ref": "fresh", "freshness": "fresh"}]},
    )
    assert fresh_label["output"]["facts"][0]["verdict"] != "FACT"
    assert fresh_label["status"] != "OK"
    opened = tmp_path / "evidence.txt"
    opened.write_text("readable", encoding="utf-8")
    fact = run_n5(
        {"claims": ["seen"]},
        at=AT,
        bound={"facts": [{"claim": "seen", "verdict": "FACT", "evidence_ref": str(opened), "freshness": "fresh"}]},
    )
    assert fact["status"] == "OK"
    assert fact["output"]["facts"][0]["verdict"] == "FACT"
    with pytest.raises(ValueError, match="FACT_WITHOUT_EVIDENCE"):
        run_n5({"claims": ["bare"]}, at=AT, bound={"facts": [{"claim": "bare", "verdict": "FACT", "evidence_ref": "", "freshness": "fresh"}]})


def test_f_n8_option_id_is_not_acceptance():
    intent = {"intent_id": "i"}
    ok = run_n8({"intent": intent, "options": [{"id": "opt-1", "measurable_acceptance": "pytest exits 0"}]}, at=AT)
    assert ok["output"]["mvp"]["acceptance"] == ["pytest exits 0"]
    with pytest.raises(ValueError, match="OPTION_ID_AS_ACCEPTANCE"):
        run_n8({"intent": intent, "options": [{"id": "opt-2", "acceptance": "opt-2"}]}, at=AT)
    vague = run_n8({"intent": intent, "options": [{"id": "opt-3", "acceptance": "works well"}]}, at=AT)
    assert vague["status"] == "NEEDS_CLARIFICATION"


def test_f_n11_no_independent_receipt_is_blocked():
    envelope = run_n11({"candidate_sha": "a" * 40, "scope": {"route": "internal_readonly"}}, at=AT)
    assert envelope["output"]["verdict"] == "BLOCKED"
    assert envelope["status"] != "OK"
    untrusted = run_n11(
        {"candidate_sha": "a" * 40, "scope": {"route": "internal_readonly"}},
        at=AT,
        independent_receipt={"candidate_sha": "a" * 40, "verdict": "REVISE", "evidence": [{"note": "revise me"}]},
    )
    assert untrusted["output"]["verdict"] == "BLOCKED"
    assert untrusted["output"]["verdict"] != "PASS"
    assert untrusted["status"] != "OK"
    forged = run_n11(
        {"candidate_sha": "a" * 40, "scope": {"route": "internal_readonly"}},
        at=AT,
        independent_receipt={
            "candidate_sha": "a" * 40,
            "verdict": "PASS",
            "issuer": "forged-not-a-ta-reviewer",
            "path": "/tmp/ae-no-such-ta-reviewer-receipt.json",
        },
    )
    assert forged["output"]["verdict"] == "BLOCKED"
    assert forged["status"] != "OK"


def test_f_n12_receipt_is_first(tmp_path):
    envelope = run_n12(
        {
            "decisions": [{"id": "d0", "content": "original"}, {"id": "d1", "content": "keep", "supersedes": "d0"}],
            "evidence": [{"id": "e1", "uri_or_hash": "h"}],
            "receipts": [{"receipt_id": "r1", "result": "SUCCEEDED"}],
            "failures": [{"id": "f1", "reason": "disk write failed"}],
        },
        at=AT,
        store_root=tmp_path,
    )
    written = envelope["output"]["written"]
    assert written[0]["object"] == "Receipt"
    assert "Failure" not in {row["object"] for row in written}
    assert all(row["object"] in {"Decision", "Evidence", "Receipt"} for row in written)
    for row in written:
        path = tmp_path / row["path"]
        assert row["path"].startswith("capture/")
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
    link = envelope["output"]["superseded"][0]["link"]
    assert envelope["output"]["superseded"][0]["old_id"] == "d0"
    assert (tmp_path / link).is_file()
    assert not link.startswith("supersedes:")
    again = run_n12(
        {
            "decisions": [],
            "evidence": [],
            "receipts": [{"receipt_id": "r1", "result": "SUCCEEDED"}],
            "failures": [],
        },
        at=AT,
        store_root=tmp_path,
    )
    assert again["output"]["written"][0]["sha256"] == written[0]["sha256"]
    kept = (tmp_path / again["output"]["written"][0]["path"]).read_bytes()
    with pytest.raises(ValueError, match="CONTENT_CONFLICT") as raised:
        run_n12(
            {
                "decisions": [],
                "evidence": [],
                "receipts": [{"receipt_id": "r1", "result": "OTHER"}],
                "failures": [],
            },
            at=AT,
            store_root=tmp_path,
        )
    conflict_path = str(raised.value).split("CONTENT_CONFLICT:", 1)[1]
    assert (tmp_path / conflict_path).is_file()
    assert (tmp_path / conflict_path).read_bytes() == kept


def test_f_n13_states_stay_separate_and_notify_once():
    seen: set[str] = set()
    first = run_n13(
        {"outcome": "SUCCEEDED", "verify_state": "BLOCKED", "writeback_state": "OK", "handoff_state": "NOT_READY"},
        at=AT,
        notified=seen,
    )
    second = run_n13(
        {"outcome": "SUCCEEDED", "verify_state": "BLOCKED", "writeback_state": "OK", "handoff_state": "NOT_READY"},
        at=AT,
        notified=seen,
    )
    assert first["output"]["state"] == "BLOCKED"
    assert first["output"]["state"] != "verified"
    assert first["output"]["notify_once"] is True
    assert second["output"]["notify_once"] is False
    assert "path" not in first["output"]
    assert "sha256" not in first["output"]
    assert first["output"]["evidence_links"][0] == "sha256:" + digest({"field": "outcome", "value": "SUCCEEDED"})
    changed = run_n13(
        {"outcome": "FAILED", "verify_state": "BLOCKED", "writeback_state": "FAILED", "handoff_state": "NOT_READY"},
        at=AT,
        notified=seen,
    )
    assert changed["output"]["notify_once"] is True
    failed_write = run_n13(
        {"outcome": "SUCCEEDED", "verify_state": "READY", "writeback_state": "FAILED", "handoff_state": "READY"},
        at=AT,
    )
    assert failed_write["output"]["state"] != "SUCCEEDED"
    assert failed_write["status"] != "OK"
    assert failed_write["output"]["next_legal_action"] == "repair-writeback"


def test_f_n13_dedup_is_per_store_and_intent(tmp_path):
    states = {"outcome": "SUCCEEDED", "verify_state": "BLOCKED", "writeback_state": "OK", "handoff_state": "NOT_READY"}
    store_a = tmp_path / "a"
    store_b = tmp_path / "b"
    store_a.mkdir()
    store_b.mkdir()
    first = run_n13(states, at=AT, store_root=store_a, intent_id="intent-a")
    second = run_n13(states, at=AT, store_root=store_a, intent_id="intent-a")
    changed = run_n13(
        {"outcome": "FAILED", "verify_state": "BLOCKED", "writeback_state": "FAILED", "handoff_state": "NOT_READY"},
        at=AT,
        store_root=store_a,
        intent_id="intent-a",
    )
    other_intent = run_n13(states, at=AT, store_root=store_a, intent_id="intent-b")
    other_store = run_n13(states, at=AT, store_root=store_b, intent_id="intent-a")
    assert first["output"]["notify_once"] is True
    assert second["output"]["notify_once"] is False
    assert changed["output"]["notify_once"] is True
    assert other_intent["output"]["notify_once"] is True
    assert other_store["output"]["notify_once"] is True
    assert (store_a / "board" / "notifications.json").is_file()
