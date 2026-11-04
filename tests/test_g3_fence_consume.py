"""G3 fence parse and durable consume. TEST_ONLY. runtime_pass stays false.

The Ops control-plane directory is read when present and is never created here.
"""
import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

from octo.closing import phase_b_from_raw, phase_b_json_bytes
from octo.nodes import run_n2
from octo.trusted_original import (
    OPS_CONTROL_PLANE_ROOT,
    OPS_CONTROL_PLANE_SHA256,
    ReadOnlyRegistry,
    _CONSUMED_RECEIPTS,
    commit_receipt_consume,
    load_control_plane,
    ops_control_plane_status,
    receipt_is_consumed,
)

ROOT = Path(__file__).resolve().parents[1]
FENCED = ROOT / "tests" / "fixtures" / "n11-fenced" / "test-only-fenced-blocked.txt"
ESCAPED = ROOT / "tests" / "fixtures" / "n11-fenced" / "test-only-escaped-blocked.txt"
FENCED_SHA = "9f107fcc73a9cd4a092a6c3797cd19a34781386fc0df71a3c43d14b2495d8b77"
FENCED_LEN = 234
ESCAPED_SHA = "6b1f9c371f593aeb0c7b813ef91c6f8a2b87ba69b6d0554e9b71631b6caee75c"
ESCAPED_LEN = 45
FAKE_CANDIDATE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
# Published originals must not be the bytes under test.
LEAKED_FENCED_SHA = "97f9fd4bb5812ca39aff0386aa025e8d9260fd06c0ff6b82831a90fe6097af12"
LEAKED_ESCAPED_SHA = "3f74a3ecbb4421bc9e62d2ce6c20546a86fa7ed5f30613ddab51de8e7a03322c"
SYNTHETIC_APPOINTMENT = "ab" * 32
SYNTHETIC_THREAD = "test-only-thread"
AT = "2026-11-04T00:00:00+00:00"


def _view(root: Path) -> ReadOnlyRegistry:
    return ReadOnlyRegistry(root=root, records={})


def _phase(raw: bytes, root: Path):
    return phase_b_from_raw(
        raw,
        None,
        {"route": "internal_readonly"},
        registry_view=_view(root),
        record={},
    )


def test_fenced_test_fixture_parses_and_stays_blocked():
    raw = FENCED.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == FENCED_SHA
    assert len(raw) == FENCED_LEN
    assert digest != LEAKED_FENCED_SHA
    body = phase_b_json_bytes(raw)
    assert hashlib.sha256(body).hexdigest() != digest
    document = json.loads(body.decode("utf-8"))
    assert document["kind"] == "TEST_FIXTURE"
    assert document["test_only"] is True
    assert document["verdict"] == "BLOCKED"
    assert document["runtime_pass"] is False
    assert document["binding_tuple"]["candidate_sha"] == FAKE_CANDIDATE
    gated = _phase(raw, Path("/tmp"))
    assert gated is not None
    assert gated[1] == "BLOCKED"
    assert gated[0]["verdict"] == "BLOCKED"
    assert gated[0]["evidence"][0]["runtime_pass"] is False
    assert gated[0]["evidence"][0]["original_verdict"] == "BLOCKED"
    assert hashlib.sha256(raw).hexdigest() == FENCED_SHA


def test_escaped_test_fixture_is_format_blocked_without_unescape():
    raw = ESCAPED.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == ESCAPED_SHA
    assert len(raw) == ESCAPED_LEN
    assert digest != LEAKED_ESCAPED_SHA
    assert b"```" not in raw
    assert phase_b_json_bytes(raw) == raw
    try:
        json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        assert exc.msg == "Invalid \\escape"
    else:
        raise AssertionError("escaped fixture must not parse")
    gated = _phase(raw, Path("/tmp"))
    assert gated is not None
    assert gated[0]["verdict"] == "BLOCKED"
    assert gated[0]["evidence"][0]["note"] == "FORMAT_BLOCKED"
    assert gated[0]["evidence"][0]["runtime_pass"] is False
    assert "original_verdict" not in gated[0]["evidence"][0]
    assert hashlib.sha256(raw).hexdigest() == ESCAPED_SHA


def test_fence_shape_rejects_zero_many_and_outside_junk(tmp_path):
    body = b'{"verdict":"BLOCKED","binding_tuple":{"route":"internal_readonly"}}'
    two = b"```json\n" + body + b"\n```\n```json\n" + body + b"\n```\n"
    junk = b"note\n```json\n" + body + b"\n```\n"
    bare = b"not-a-receipt"
    for raw in (two, junk):
        gated = _phase(raw, tmp_path)
        assert gated is not None
        assert gated[0]["evidence"][0]["note"] == "FORMAT_BLOCKED"
        assert hashlib.sha256(raw).hexdigest() == hashlib.sha256(raw).hexdigest()
    assert _phase(bare, tmp_path) is None


def test_appointment_digest_is_not_the_thread_hash(tmp_path):
    thread_hash = hashlib.sha256(SYNTHETIC_THREAD.encode("utf-8")).hexdigest()
    assert thread_hash != SYNTHETIC_APPOINTMENT
    plane = {
        "kind": "REGISTRAR_RELAY",
        "not_issuer": True,
        "current_reviewer_conclusion": True,
        "thread_id": SYNTHETIC_THREAD,
        "turn_id": "turn-test-only",
        "message_id": "message-test-only",
        "appointment_original_digest": SYNTHETIC_APPOINTMENT,
        "base_sha": "b" * 40,
        "candidate_sha": "c" * 40,
        "scope_digest": "d" * 64,
        "fixture_digest": "e" * 64,
        "allowlist_sha256": "f" * 64,
        "collection_source": "read_thread",
        "collected_at": AT,
        "expected_service_response_sha256": "1" * 64,
    }
    path = tmp_path / "control-plane.json"
    path.write_text(json.dumps(plane), encoding="utf-8")
    loaded = load_control_plane(path)
    assert loaded is not None
    assert loaded["appointment_original_digest"] == SYNTHETIC_APPOINTMENT
    plane["appointment_original_digest"] = thread_hash
    path.write_text(json.dumps(plane), encoding="utf-8")
    assert load_control_plane(path) is None


def test_durable_consume_survives_memory_clear_and_a_new_process(tmp_path):
    root = tmp_path / "reg"
    root.mkdir()
    view = _view(root)
    record = {"receipt_id": "rcpt-durable"}
    assert receipt_is_consumed(root, "rcpt-durable") is False
    assert commit_receipt_consume(view, record) is True
    assert receipt_is_consumed(root, "rcpt-durable") is True
    journal = [path for path in root.parent.glob(".octo-receipt-consume/**/*") if path.is_file()]
    assert journal
    assert all(root.resolve() not in path.resolve().parents for path in journal)
    assert commit_receipt_consume(view, record) is False
    _CONSUMED_RECEIPTS.clear()
    assert commit_receipt_consume(view, record) is False
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from pathlib import Path; from octo.trusted_original import receipt_is_consumed; "
            "raise SystemExit(0 if receipt_is_consumed(Path(sys.argv[1]), sys.argv[2]) else 1)",
            str(root),
            "rcpt-durable",
        ],
        cwd=str(ROOT),
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr
    failed = {"receipt_id": "rcpt-uncommitted"}
    assert receipt_is_consumed(root, failed["receipt_id"]) is False


def test_durable_consume_commits_once_under_threads(tmp_path):
    root = tmp_path / "reg"
    root.mkdir()
    view = _view(root)
    results: list[bool] = []
    guard = threading.Lock()

    def claim() -> None:
        value = commit_receipt_consume(view, {"receipt_id": "rcpt-race"})
        with guard:
            results.append(value)

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(True) == 1
    assert receipt_is_consumed(root, "rcpt-race") is True


def test_empty_n2_sources_are_not_ok_and_ops_pin_is_not_written(tmp_path):
    envelope = run_n2(
        {"intent_id": "g3-coverage"},
        at=AT,
        bound={"sources": [], "key_evidence": [], "current_decisions": []},
    )
    assert envelope["status"] != "OK"
    assert envelope["output"]["sources"] == []
    missing = tmp_path / "not-the-ops-root"
    assert ops_control_plane_status(missing) == "ABSENT"
    assert not missing.exists()
    bad = tmp_path / "mismatch"
    bad.mkdir()
    (bad / "pin.json").write_bytes(b"test-only-not-the-ops-pin")
    assert ops_control_plane_status(bad) == "MISMATCH"
    existed = OPS_CONTROL_PLANE_ROOT.exists()
    status = ops_control_plane_status()
    assert OPS_CONTROL_PLANE_ROOT.exists() is existed
    if existed:
        assert status == "MATCH"
    else:
        assert status == "ABSENT"
    assert set(OPS_CONTROL_PLANE_SHA256) == {
        "allowlist",
        "controlplane_pin",
        "registry",
        "evidence_tar",
    }
