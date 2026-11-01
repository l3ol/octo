"""STACK_OK harness_ns under OPS-ENTER. Not a PASS and not a containment rerun."""

from __future__ import annotations

from pathlib import Path

from gates.readonly_ns import classify_ci_uid_map, classify_harness_label, harness_ns_label

TIP19B_RECEIPT = "7fdb9022461bd0ea9ce8f8dbce4ac1c4ba92135e924834b7c874da5824211116"
CI_UID_MAP = "unshare: write failed /proc/self/uid_map: Operation not permitted"


def test_ac_t279_02_ops_enter_label_without_twin_env():
    ops_enter = {"GATES_ENTER_VIA": "ops-enter", "OPS_NS_ST_RDONLY_EXPECTED": "1"}
    assert harness_ns_label(ops_enter) == "1"
    assert harness_ns_label({"GATES_RDONLY_NS": "1", "GATES_ENTER_VIA": "twin"}) == "1"
    assert harness_ns_label({}) == "0"


def test_ac_t279_01_and_04_zero_with_ns_proof_is_label_misreport():
    kind = classify_harness_label(harness_ns="0", independent_ns_proven=True, runtime_pass=False)
    assert kind == "LABEL_MISREPORT"
    assert kind != "CONTAINMENT_GAP"
    assert kind != "PASS"


def test_nc_t279_02_runtime_pass_is_premature():
    assert classify_harness_label(harness_ns="1", independent_ns_proven=True, runtime_pass=True) == "PREMATURE_PASS"


def test_nc_t279_05_label_is_not_twin_env_only():
    source = Path("gates/selftest.py").read_text(encoding="utf-8")
    assert 'os.environ.get("GATES_RDONLY_NS"' not in source
    assert "harness_ns_label()" in source
    wrapper = Path("gates/enter_exec_ctx.sh").read_text(encoding="utf-8")
    ops_branch = wrapper.split("if [ -f \"$OPS_ENTER\" ]", 1)[1].split("if [ \"${GATES_RDONLY_NS:-}\" != 1 ]", 1)[0]
    assert "export GATES_RDONLY_NS=1" in ops_branch
    assert "export GATES_ENTER_VIA=ops-enter" in ops_branch


def test_ac_t279_03_tip19b_receipt_is_not_rewritten_here():
    assert TIP19B_RECEIPT == "7fdb9022461bd0ea9ce8f8dbce4ac1c4ba92135e924834b7c874da5824211116"
    assert not Path("gates").joinpath("7fdb9022461bd0ea9ce8f8dbce4ac1c4ba92135e924834b7c874da5824211116").exists()


def test_ac_t279_05_and_nc_t279_06_uid_map_stays_env_boundary():
    assert classify_ci_uid_map(CI_UID_MAP) == "ENV_BOUNDARY"
    assert classify_ci_uid_map(CI_UID_MAP) != "LABEL_MISREPORT"


def test_t280_workflow_uses_2204_and_records_observations():
    text = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "runs-on: ubuntu-22.04" in text
    assert "runs-on: ubuntu-latest" not in text
    assert "experiment_id=CI-UBUNTU-2204-COMPAT-t280" in text
    assert "ci_image_observed=" in text
    assert "ci_kernel_observed=" in text
    assert "ci_capability_observed" in text
    assert "bash gates/enter_exec_ctx.sh python -m gates.selftest" in text


def test_nc_t279_03_no_skip_or_privilege_in_label_fix():
    text = Path("gates/readonly_ns.py").read_text(encoding="utf-8") + Path("gates/selftest.py").read_text(encoding="utf-8")
    assert "pytest.skip" not in text
    assert "xfail" not in text
    assert "sudo" not in text
    assert "sysctl" not in text
