"""N8 node-level acceptance checklist. Builder selftest only.

A green pytest or CI run is not this checklist. runtime_pass stays false.
"""
import pytest

from octo.nodes import _measurable, emit_envelope, run_n8

AT = "2026-11-01T12:00:00+00:00"
INTENT = {"intent_id": "intent-1"}


def _run(options):
    return run_n8({"intent": INTENT, "options": options}, at=AT)


def test_ac_n8_01_options_required_and_n6_forbidden():
    with pytest.raises(ValueError, match="execution_options required"):
        _run([])
    with pytest.raises(ValueError, match="execution_options required"):
        run_n8({"intent": INTENT, "options": "not-a-list"}, at=AT)
    with pytest.raises(ValueError, match="N6 output cannot be used as N8 options"):
        _run([{"id": "opt", "n6_output": {"fake": True}, "measurable_acceptance": "pytest exits 0"}])
    with pytest.raises(ValueError, match="N6 output cannot be used as N8 options"):
        _run([{"id": "opt", "node_id": "N6", "measurable_acceptance": "pytest exits 0"}])
    with pytest.raises(ValueError, match="N6 output cannot be used as N8 options"):
        _run([{"id": "opt", "node_id": "N7", "measurable_acceptance": "pytest exits 0"}])


def test_ac_n8_02_acceptance_must_be_measurable_and_not_the_option_id():
    for token in ("exit", "sha256", "pytest", "bytes", "==", ">=", "count"):
        assert _measurable(f"check {token} 1") is True
    assert _measurable("works well") is False
    assert _measurable("looks fine") is False
    with pytest.raises(ValueError, match="OPTION_ID_AS_ACCEPTANCE"):
        _run([{"id": "opt-2", "acceptance": "opt-2"}])
    with pytest.raises(ValueError, match="ACCEPTANCE_NOT_MEASURABLE"):
        _run([{"id": "opt-vague", "acceptance": "looks fine"}])


def test_ac_n8_03_works_well_needs_clarification():
    envelope = _run([{"id": "opt-3", "acceptance": "works well"}])
    assert envelope["status"] == "NEEDS_CLARIFICATION"
    assert envelope["output"]["mvp"]["acceptance"] == []
    assert envelope["output"]["mvp"]["not_in_scope"] == ["N6", "N7"]
    assert envelope["node_id"] == "N8"


def test_ac_n8_04_ok_requires_one_measurable_and_excludes_n6_n7():
    envelope = _run([{"id": "opt-1", "measurable_acceptance": "pytest exits 0"}])
    assert envelope["status"] == "OK"
    assert envelope["output"]["mvp"]["acceptance"] == ["pytest exits 0"]
    assert "N6" in envelope["output"]["mvp"]["not_in_scope"]
    assert "N7" in envelope["output"]["mvp"]["not_in_scope"]
    assert set(envelope["inputs"]) == {"intent", "options"}
    assert set(envelope["output"]) == {"mvp"}


def test_ac_n8_05_ci_green_alone_is_not_n8_ac_pass():
    """Suite exit 0 does not close N8. The checklist tests above are the node AC."""
    ci_record = {
        "pytest_exit_0": True,
        "ci_conclusion": "success",
        "n8_ac_pass": False,
        "reason": "CI green alone is not N8 AC pass",
    }
    assert ci_record["pytest_exit_0"] is True
    assert ci_record["ci_conclusion"] == "success"
    assert ci_record["n8_ac_pass"] is False


def test_ac_n8_06_n6_and_n7_stay_unemitted():
    with pytest.raises(RuntimeError, match="N6"):
        emit_envelope(node_id="N6", at=AT, inputs={}, status="NOT_RUN_THIS_STAGE", output=None)
    with pytest.raises(RuntimeError, match="N7"):
        emit_envelope(node_id="N7", at=AT, inputs={}, status="NOT_RUN_THIS_STAGE", output=None)
    envelope = _run([{"id": "opt-1", "measurable_acceptance": "sha256 matches"}])
    assert envelope["status"] == "OK"
    assert envelope["status"] != "PASS"
    assert envelope["node_id"] not in {"N6", "N7"}
    assert envelope["output"]["mvp"]["not_in_scope"] == ["N6", "N7"]
