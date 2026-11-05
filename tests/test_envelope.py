"""Node envelope schema, A2-2 inputs_hash, and T-00A recomputation."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from octo.envelope import (
    NODE_IDS,
    STATUSES,
    EnvelopeValidationError,
    build_envelope,
    load_schema,
    validate_envelope,
)
from octo.objects import canonical, digest, inputs_hash

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs" / "spec" / "g2-s1" / "PLAN-NODE-OUTPUTS.json"
RECOMPUTE = ROOT / "docs" / "spec" / "g2-s1" / "recompute_inputs_hash.py"
AT = "2026-11-01T20:57:38+08:00"

# Published T-00A MATCH table. Independent of the JSON file's own fields.
T00A_INPUTS_HASH = {
    "N1": "eac558dfd8e711cfa265045134697e7cc71264d1833e5c0ad6acd57dba82ead2",
    "N2": "46c64b983b0c0c1a1a26702a4aa0451ac54f76592972478bb7e5106c70c178e1",
    "N3": "c34ecbc0fc8c8c169fd47f5c325ce61503612986aaaefe3dacf11e9045e6b622",
    "N4": "0ac13220a9099ce844bd60125df75419385dbc812bef2e26e968182fdfe1b477",
    "N5": "07c5b6678d1d2d7c23f934427be1db6367663d5717d509b09479c6f42cf29221",
    "N8": "02f7f3bad5cdd4fa6fcdb987e195c091834368e8ee079ca6696ca85da1f9eeac",
}


def test_schema_matches_t01_sketch():
    schema = load_schema()
    assert schema["$id"] == "octo/node-envelope.schema.json"
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["node_id", "at", "inputs", "inputs_hash", "status", "output"]
    assert tuple(schema["properties"]["node_id"]["enum"]) == NODE_IDS
    assert tuple(schema["properties"]["status"]["enum"]) == STATUSES
    assert "DEGRADED_SKIP_N6N7" not in schema["properties"]["status"]["enum"]
    branch = schema["allOf"][0]
    assert branch["if"]["properties"]["status"]["const"] == "NOT_RUN_THIS_STAGE"
    then_props = branch["then"]["properties"]
    assert then_props["node_id"]["enum"] == ["N6", "N7"]
    assert then_props["output"]["type"] == "null"


def test_canonical_spec_algorithm_bytes():
    raw = canonical({"b": 1, "a": "字"})
    assert raw == '{"a":"字","b":1}'.encode("utf-8")
    assert not raw.endswith(b"\n")
    assert b" " not in raw
    assert digest({"b": 1, "a": "字"}) == (
        "f9cc05ae4df0369ae25a2bb41458d696fb0d6de31cadb502f626857c689f8e0f"
    )
    nested = canonical({"b": {"d": 1, "c": 2}, "a": 0})
    assert nested == b'{"a":0,"b":{"c":2,"d":1}}'
    assert not nested.endswith(b"\n")
    with pytest.raises(ValueError):
        canonical({"a": float("nan")})
    with pytest.raises(ValueError):
        canonical({"a": float("inf")})


def test_plan_file_and_recompute_script():
    assert hashlib.sha256(PLAN.read_bytes()).hexdigest() == (
        "fc004c4fa2fb215914e82644b69ce846a2a04c5413de084030cb86df14366bbb"
    )
    proc = subprocess.run(
        [sys.executable, str(RECOMPUTE)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "MISMATCH" not in proc.stdout
    for node_id in T00A_INPUTS_HASH:
        assert "MATCH" in proc.stdout
        assert node_id in proc.stdout


def test_t00a_inputs_hash_and_good_envelopes():
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    for node_id, expected in T00A_INPUTS_HASH.items():
        node = plan["nodes"][node_id]
        assert inputs_hash(node["input"]) == node["inputs_hash"] == expected
        env = build_envelope(
            node_id=node_id,
            at=AT,
            inputs=node["input"],
            status="OK",
            output=node["output_sample"],
        )
        sealed = validate_envelope(env)
        assert sealed.node_id == node_id
        assert sealed.status == "OK"
        assert sealed.inputs_hash == expected
        assert sealed.to_dict()["output"] == node["output_sample"]
        later = dict(env)
        later["at"] = "2026-11-02T01:02:03Z"
        assert later["inputs_hash"] == expected
        assert validate_envelope(later).inputs_hash == expected
    for node_id in ("N6", "N7"):
        assert plan["nodes"][node_id] == {"status": "NOT_RUN_THIS_STAGE", "output": None}
        skipped = build_envelope(
            node_id=node_id,
            at=AT,
            inputs={},
            status="NOT_RUN_THIS_STAGE",
            output=None,
        )
        assert skipped["inputs_hash"] == (
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        )
        sealed = validate_envelope(skipped)
        assert sealed.output is None
        assert sealed.status == "NOT_RUN_THIS_STAGE"


@pytest.mark.parametrize(
    "status",
    [
        "OK",
        "PARTIAL",
        "NEEDS_CLARIFICATION",
        "BLOCKED",
        "AUTHORIZATION_REQUIRED",
        "SOURCE_UNAVAILABLE",
    ],
)
def test_allowed_statuses_validate(status):
    env = build_envelope(
        node_id="N1",
        at=AT,
        inputs={"b": 1, "a": "字"},
        status=status,
        output={"note": "synthetic"} if status == "OK" else None,
    )
    assert validate_envelope(env).status == status


@pytest.mark.parametrize(
    "status",
    ["DEGRADED_SKIP_N6N7", "DEGRADED_SKIP_N6", "DEGRADED", "PLAN_MATERIALIZED", "SKIPPED"],
)
def test_reject_invented_status(status):
    env = build_envelope(
        node_id="N6",
        at=AT,
        inputs={"x": 1},
        status=status,
        output=None,
    )
    with pytest.raises(EnvelopeValidationError, match=status):
        validate_envelope(env)


@pytest.mark.parametrize("node_id", ["N0", "N14", "n1", "N6N7"])
def test_reject_bad_node_id(node_id):
    env = build_envelope(
        node_id=node_id,
        at=AT,
        inputs={"x": 1},
        status="OK",
        output={"ok": True},
    )
    with pytest.raises(EnvelopeValidationError, match=node_id):
        validate_envelope(env)


def test_reject_hash_mismatch():
    env = build_envelope(
        node_id="N2",
        at=AT,
        inputs={"intent_id": "intent-1"},
        status="OK",
        output={"intent_id": "intent-1"},
    )
    env["inputs_hash"] = "0" * 64
    assert env["inputs_hash"] != inputs_hash(env["inputs"])
    with pytest.raises(EnvelopeValidationError, match="inputs_hash mismatch"):
        validate_envelope(env)


def test_reject_not_run_outside_n6_n7():
    for node_id in ("N1", "N5", "N8", "N13"):
        env = build_envelope(
            node_id=node_id,
            at=AT,
            inputs={},
            status="NOT_RUN_THIS_STAGE",
            output=None,
        )
        with pytest.raises(EnvelopeValidationError):
            validate_envelope(env)


def test_reject_not_run_with_non_null_output():
    for node_id in ("N6", "N7"):
        env = build_envelope(
            node_id=node_id,
            at=AT,
            inputs={},
            status="NOT_RUN_THIS_STAGE",
            output={"fabricated": True},
        )
        with pytest.raises(EnvelopeValidationError):
            validate_envelope(env)


def test_schema_date_time_format_requires_offset():
    """``format: date-time`` is asserted, not left as an annotation."""
    from octo.envelope import _validator

    naive = build_envelope(
        node_id="N4",
        at="2026-11-01T20:57:38",
        inputs={"k": "v"},
        status="OK",
        output={"candidates": []},
    )
    messages = [err.message for err in _validator().iter_errors(naive)]
    assert messages
    assert any("date-time" in msg for msg in messages)
    dated = build_envelope(
        node_id="N4",
        at="2026-10-30",
        inputs={"k": "v"},
        status="OK",
        output={"candidates": []},
    )
    assert list(_validator().iter_errors(dated))
    ok = build_envelope(
        node_id="N4",
        at=AT,
        inputs={"k": "v"},
        status="OK",
        output={"candidates": []},
    )
    assert list(_validator().iter_errors(ok)) == []
    zulu = dict(ok)
    zulu["at"] = "2026-11-02T01:02:03Z"
    assert list(_validator().iter_errors(zulu)) == []


def test_reject_at_without_offset_and_extra_fields():
    env = build_envelope(
        node_id="N4",
        at="2026-11-01T20:57:38",
        inputs={"k": "v"},
        status="OK",
        output={"candidates": []},
    )
    with pytest.raises(EnvelopeValidationError):
        validate_envelope(env)
    dated = build_envelope(
        node_id="N4",
        at="2026-10-30",
        inputs={"k": "v"},
        status="OK",
        output={"candidates": []},
    )
    with pytest.raises(EnvelopeValidationError):
        validate_envelope(dated)
    extra = build_envelope(
        node_id="N4",
        at=AT,
        inputs={"k": "v"},
        status="OK",
        output={"candidates": []},
    )
    extra["complexity"] = "simple"
    with pytest.raises(EnvelopeValidationError):
        validate_envelope(extra)


def test_objects_module_does_not_adopt_mac_field_shapes():
    import octo.objects as objects

    for name in ("Intent", "Decision", "Evidence", "Grant", "Outcome", "from_dict", "Object"):
        assert not hasattr(objects, name)
