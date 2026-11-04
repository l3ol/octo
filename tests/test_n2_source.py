"""N2 source-proof status. Builder selftest only. runtime_pass stays false."""
import json
from pathlib import Path

import pytest

from octo.nodes import guard_consequential, run_n2
from octo.objects import digest, inputs_hash
from octo.router import S1_STANDARD_NODES, RouteDecision
from octo.standard import run_prefix, run_standard

ROOT = Path(__file__).resolve().parents[1]
PLAN = json.loads((ROOT / "docs/spec/g2-s1/PLAN-NODE-OUTPUTS.json").read_text(encoding="utf-8"))
AT = "2026-11-01T19:56:28.429492+00:00"
INTENT = "intent-PRODUCT-BUILD-2026-11-01-G2-S1-TB-01"
N2_KEYS = {
    "intent_id",
    "current_decisions",
    "key_evidence",
    "open_states",
    "prohibitions",
    "assembled_at",
    "sources",
}


def _receipt(source: str, **extra) -> dict:
    body = {"source": source, "queried": True, "ok": True, "result_count": 0}
    body.update(extra)
    return body


def _evidence(source: str, **extra) -> dict:
    body = _receipt(source, **extra)
    return {"uri_or_hash": digest(body), "receipt": body, "freshness": "fresh"}


def _proven(*sources: str, decisions: list | None = None) -> dict:
    return {
        "required_sources": list(sources),
        "sources": list(sources),
        "current_decisions": [] if decisions is None else decisions,
        "key_evidence": [_evidence(source) for source in sources],
    }


def _run(bound):
    return run_n2({"intent_id": INTENT}, at=AT, bound=bound)


def _assert_partial(envelope: dict) -> None:
    assert envelope["status"] == "PARTIAL"
    assert "gap:SOURCE_UNAVAILABLE" in envelope["output"]["open_states"]
    assert set(envelope["output"]) == N2_KEYS
    assert envelope["inputs"] == {"intent_id": INTENT}
    assert envelope["inputs_hash"] == inputs_hash({"intent_id": INTENT})
    assert "required_sources" not in envelope["output"]
    assert "query_succeeded" not in envelope["output"]


def test_tm01_missing_source_is_partial():
    envelope = run_n2({"intent_id": INTENT}, at=AT, bound=None)
    _assert_partial(envelope)
    assert envelope["output"]["sources"] == []
    assert envelope["output"]["key_evidence"] == []


def test_tm02_explicit_unavailable_stays_partial():
    envelope = _run({"source_unavailable": True, **_proven("src-a")})
    _assert_partial(envelope)


def test_tm03_proven_empty_is_ok():
    envelope = _run(_proven("src-a"))
    assert envelope["status"] == "OK"
    assert envelope["output"]["current_decisions"] == []
    assert envelope["output"]["sources"] == ["src-a"]
    assert envelope["output"]["key_evidence"][0]["uri_or_hash"] == digest(envelope["output"]["key_evidence"][0]["receipt"])
    assert "gap:SOURCE_UNAVAILABLE" not in envelope["output"]["open_states"]
    assert set(envelope["output"]) == N2_KEYS
    assert envelope["inputs"] == {"intent_id": INTENT}
    assert envelope["inputs_hash"] == inputs_hash(envelope["inputs"])


def test_tm03b_recomputable_receipt_ok_and_fake_success_is_partial():
    envelope = _run(_proven("src-a", "src-b"))
    assert envelope["status"] == "OK"
    assert set(envelope["output"]["sources"]) == {"src-a", "src-b"}
    fake = {
        "required_sources": ["src-a"],
        "sources": ["src-a"],
        "current_decisions": [],
        "query_succeeded": True,
        "key_evidence": [{"query_succeeded": True, "uri_or_hash": "success"}],
    }
    _assert_partial(_run(fake))
    tampered = _proven("src-a")
    tampered["key_evidence"][0]["uri_or_hash"] = "a" * 64
    _assert_partial(_run(tampered))


def test_tm04_empty_without_proof_is_partial():
    _assert_partial(_run({}))
    _assert_partial(_run({"current_decisions": [], "sources": [], "key_evidence": []}))


def test_tm05_mixed_partial_missing_is_partial():
    bound = _proven("src-a")
    bound["required_sources"] = ["src-a", "src-b"]
    bound["sources"] = ["src-a", "src-b"]
    _assert_partial(_run(bound))


def test_tm06_query_failure_is_partial():
    bound = _proven("src-a")
    bound["key_evidence"] = [_evidence("src-a", ok=False, status="timeout")]
    _assert_partial(_run(bound))


def test_tm07_unregistered_source_is_partial():
    bound = _proven("unregistered-source")
    bound["required_sources"] = ["registered-source"]
    _assert_partial(_run(bound))


def test_tm08_empty_required_set_is_partial():
    bound = _proven("src-a")
    bound["required_sources"] = []
    bound["sources"] = []
    bound["key_evidence"] = []
    _assert_partial(_run(bound))


def test_tm_hash_bound_does_not_change_inputs_hash():
    missing = run_n2({"intent_id": INTENT}, at=AT, bound=None)
    proven = _run(_proven("src-a"))
    assert missing["inputs_hash"] == proven["inputs_hash"] == inputs_hash({"intent_id": INTENT})
    assert "bound" not in missing["inputs"]
    assert set(missing["inputs"]) == {"intent_id"}


def test_ac_n2_05_partial_blocks_consequential_action():
    envelope = run_n2({"intent_id": INTENT}, at=AT, bound=None)
    assert envelope["status"] == "PARTIAL"
    guard_consequential(envelope["status"], "internal_readonly")
    guard_consequential(envelope["status"], "read")
    with pytest.raises(ValueError, match="CONSEQUENTIAL_ON_PARTIAL"):
        guard_consequential(envelope["status"], "delete")


def test_tm_i5_partial_consequential_stops_before_n9(monkeypatch):
    def allow(request, **_kwargs):
        return RouteDecision(
            status="OK",
            action_type=request["action_type"],
            tier="Standard",
            nodes=S1_STANDARD_NODES,
            reason="TEST_FIXTURE route only",
            code="OK",
            execution_authorized=True,
        )

    monkeypatch.setattr("octo.standard.route", allow)
    pack = {"n1": PLAN["nodes"]["N1"]["input"]}
    prefix = run_prefix({"action_type": "delete", "grant_ref": "grant-ref-s1-test"}, pack, at=AT)
    assert [item["node_id"] for item in prefix["envelopes"]] == ["N1", "N2"]
    assert prefix["envelopes"][1]["status"] == "PARTIAL"
    assert prefix["status"] == "PARTIAL"
    assert prefix["readonly_continue"] is False
    stopped = run_standard(
        {"action_type": "delete", "grant_ref": "grant-ref-s1-test"},
        pack,
        at=AT,
        request=None,
        store=None,
    )
    assert [item["node_id"] for item in stopped["envelopes"]] == ["N1", "N2"]
    assert "N9" not in {item["node_id"] for item in stopped["envelopes"]}
    assert "N10" not in {item["node_id"] for item in stopped["envelopes"]}
