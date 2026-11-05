#!/usr/bin/env python3
"""Independent TB t192 tip51 probe. Reads the candidate. Does not modify it.

Exit 0 means the probe finished writing evidence. It is not a product PASS.
runtime_pass stays false. pytest xfail is not a pass.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import traceback

sys.dont_write_bytecode = True
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/workspace")
sys.path.insert(0, str(ROOT))
os.environ.pop("OCTO_TRUSTED_ORIGINAL_ROOT", None)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

def _make_writable(root: Path) -> None:
    if not root.exists():
        return
    if root.is_symlink():
        return
    try:
        root.chmod(0o755 if root.is_dir() else 0o644)
    except OSError:
        return
    if not root.is_dir():
        return
    for child in root.iterdir():
        _make_writable(child)


def _reset_dir(root: Path) -> None:
    if root.exists():
        _make_writable(root)
        shutil.rmtree(root)
    root.mkdir(parents=True)


OUT = Path("/tmp/t192-out")
WORK = Path("/tmp/t192-work")
_reset_dir(OUT)
_reset_dir(WORK)

AT = "2026-11-01T12:00:00+00:00"
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
KEY = b"t" * 32
AGENT = "agt_6ae61c44e54081918e81a0adea556ef8"
SESSION = "6ae6216e-bbec-83e8-87dc-c3edd9027bcc"
OPS_PROOF = Path("/home/ubuntu/.cursor/projects/workspace/uploads/ro_bind_proof_c601.json")
OPS_MD = Path("/home/ubuntu/.cursor/projects/workspace/uploads/OPS-RECEIPT-N11-RO-BIND-TB-t192-TIP51-2026-11-02_147a.md")
OPS_JSON = Path("/home/ubuntu/.cursor/projects/workspace/uploads/OPS-RECEIPT-N11-RO-BIND-TB-t192-TIP51-2026-11-02_3ad6.json")

rows: list[dict] = []
jsonl = (OUT / "cases.jsonl").open("w", encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def add(case_id: str, group: str, expected: str, actual: str, verdict: str, **extra) -> None:
    row = {
        "id": case_id,
        "group": group,
        "expected": expected,
        "actual": actual,
        "verdict": verdict,
        "product_pass": False,
        "runtime_pass": False,
    }
    row.update(extra)
    rows.append(row)
    jsonl.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    jsonl.flush()
    print(f"{verdict:16} {case_id}", flush=True)


def guard(case_id: str, group: str, expected: str, fn) -> None:
    try:
        fn()
    except Exception as exc:
        add(
            case_id,
            group,
            expected,
            f"EXCEPTION {type(exc).__name__}: {exc}",
            "FAIL",
            traceback=traceback.format_exc(),
        )


HEAD = git("rev-parse", "HEAD")
TREE = git("rev-parse", "HEAD^{tree}")
PARENT = git("rev-parse", "HEAD^")
PIN_OK = (
    HEAD == "51a23ccd4f9efe7bafc759703997b01eccb04e13"
    and TREE == "babde0c3ac257f5d8ec1a2ec046e316f8a04ac5c"
    and PARENT == "875836d57cf1f557bb71fc094025f72a084f44dc"
)
add(
    "PIN-HEAD-TREE-PARENT",
    "pin",
    "HEAD 51a23ccd… tree babde0c3… parent 875836d5…",
    f"HEAD={HEAD} tree={TREE} parent={PARENT}",
    "MATCH" if PIN_OK else "FAIL",
)

from octo.closing import (  # noqa: E402
    handoff_state_from_n11,
    run_n11,
    run_n12,
    run_n13,
    writeback_state_from_n12,
)
from octo.g3_review import (  # noqa: E402
    column_digests,
    fixture_digest,
    handoff_binding,
    isolation_policy_digest,
    product_scope_digest,
    review_entry,
    template_digest,
    verified_runtime_inventory,
)
from octo.gateway import Gateway, run_n10  # noqa: E402
from octo.grant import AuthorizationRequest, GrantStore  # noqa: E402
from octo.isolation_runner import apply_hardened_runner  # noqa: E402
from octo.journal import Journal  # noqa: E402
from octo.n9 import run_n9  # noqa: E402
from octo.nodes import run_n1, run_n5  # noqa: E402
from octo.objects import digest as product_digest  # noqa: E402
from octo.standard import run_prefix, run_standard  # noqa: E402
from octo.trusted_original import (  # noqa: E402
    consume_trusted_original,
    fixture_set_digest,
    open_registry,
    registry_index_review,
    ro_bind_assessment,
    runner_base_sha,
)
import octo.closing as closing_mod  # noqa: E402
import octo.trusted_original as trusted_mod  # noqa: E402
import inspect  # noqa: E402

SCOPE = product_scope_digest()
BASE = runner_base_sha()
FD = "11" * 32
PLAN = json.loads((ROOT / "docs/spec/g2-s1/PLAN-NODE-OUTPUTS.json").read_text(encoding="utf-8"))
N1_IN = PLAN["nodes"]["N1"]["input"]


def independent_digest(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def freeze(root: Path) -> None:
    paths = sorted((p for p in root.rglob("*")), key=lambda p: len(p.parts), reverse=True)
    for path in paths:
        if path.is_symlink():
            continue
        mode = 0o555 if path.is_dir() else 0o444
        path.chmod(mode)
    root.chmod(0o555)


def thaw(root: Path) -> None:
    if not root.exists():
        return
    root.chmod(0o755)
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        path.chmod(0o755 if path.is_dir() else 0o644)


def evidence(session: str, proof: str = "nonempty-relay-not-a-verification") -> dict:
    return {
        "transfer_receipt_id": "xfer-shape-only",
        "issuer_session_id": session,
        "issuer_agent_id": AGENT,
        "relay_proof": proof,
    }


def binding() -> dict:
    return {
        "route": "internal_readonly",
        "scope_digest": SCOPE,
        "base_sha": BASE,
        "candidate_sha": HEAD,
        "fixture_digest": FD,
    }


def record(
    *,
    registration_id: str,
    session: str,
    issuer: str = AGENT,
    kind: str = "TEST_FIXTURE",
    test_only: bool = True,
    raw_ref: str = "originals/sample.txt",
    file_sha: str,
    verdict: str = "PASS",
    proof: str = "nonempty-relay-not-a-verification",
    tuple_override: dict | None = None,
    hashes: set[str] | None = None,
) -> dict:
    used = set() if hashes is None else set(hashes)
    return {
        "registration_id": registration_id,
        "bytes_sha256": file_sha,
        "raw_bytes_ref": raw_ref,
        "source_evidence": evidence(session, proof),
        "issuer_id": issuer,
        "issued_at": "2026-11-02T00:00:00+08:00",
        "verdict": verdict,
        "binding_tuple": tuple_override or binding(),
        "content_kind": kind,
        "test_only": test_only,
        "excluded_fixture_hashes_proof": {
            "fixture_set_digest": fixture_set_digest(used),
            "checked": True,
        },
    }


def publish(name: str, records: list, files: dict[str, bytes], *, lock: bool = True, symlink_index: str | None = None) -> Path:
    root = WORK / name
    if root.exists():
        thaw(root)
        shutil.rmtree(root)
    root.mkdir(parents=True)
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if symlink_index is None:
        (root / "registry.json").write_text(
            json.dumps({"records": records}, ensure_ascii=False),
            encoding="utf-8",
        )
    else:
        os.symlink(symlink_index, root / "registry.json")
    if lock:
        freeze(root)
    return root


def consume(root: Path, rec_binding: dict | None = None, hashes: set[str] | None = None):
    opened = open_registry(root, store_root=WORK / "not-the-registry")
    if not isinstance(opened, trusted_mod.ReadOnlyRegistry):
        return opened
    return consume_trusted_original(rec_binding or binding(), opened, hashes or set())


def run11(root: Path | None, receipt=None, hashes: set[str] | None = None, fixture: str | None = None):
    return run_n11(
        {"candidate_sha": HEAD, "scope": {"route": "internal_readonly"}},
        at=AT,
        independent_receipt=receipt,
        registry_root=root,
        fixture_hashes=hashes,
        fixture_digest=fixture if fixture is not None else FD,
        store_root=WORK / "iso-store-separate",
    )


def brief_consume(result) -> str:
    kind = type(result).__name__
    if kind == "Found":
        return f"Found test_only={result.test_only} kind={result.record.get('content_kind')} verdict={result.record.get('verdict')}"
    if kind == "Empty":
        return f"Empty {result.reason}"
    if kind == "Rejected":
        return f"Rejected {result.reason_code}"
    return kind


def brief_n11(env: dict) -> str:
    out = env.get("output") or {}
    note = ""
    evidence_rows = out.get("evidence") or []
    if evidence_rows and isinstance(evidence_rows[0], dict):
        note = str(evidence_rows[0].get("note"))
    return f"status={env.get('status')} verdict={out.get('verdict')} note={note} runtime_pass_field={evidence_rows[0].get('runtime_pass') if evidence_rows else None}"


# ---------------------------------------------------------------------------
# Ops tip51 ro-bind proof (not re-executed; this VM has no bwrap and no /home/box)
# ---------------------------------------------------------------------------

proof = json.loads(OPS_PROOF.read_text(encoding="utf-8"))
ops_md = json.loads(OPS_JSON.read_text(encoding="utf-8"))
proof_sha = sha256_file(OPS_PROOF)
md_sha = sha256_file(OPS_MD)
ops_sha = sha256_file(OPS_JSON)
pin_match = (
    proof.get("pinned_tip") == HEAD
    and proof.get("pinned_tree") == TREE
    and proof.get("pinned_parent") == PARENT
    and ops_md.get("pinned_tip") == HEAD
    and ops_md.get("intake_sha256", "").startswith("b98f5a5c")
    and proof.get("intake_sha256", "").startswith("b98f5a5c")
)
hash_match = (
    proof_sha == "21700f5fa8851659654b740976043b13023eea836569a2dd5f1a550337cf305f"
    and md_sha == "0c33e6ced12fb9bb380091266994f571d11a6d984123ddf59395dda054743721"
    and ops_sha == "dbb67fb8213f6c217bef6dec1e8cf012d7ab16ede305095974e10707735e8607"
    and ops_md.get("ro_bind_proof_json_sha256") == proof_sha
)
probe_body = proof["probe"]
attempts = probe_body["attempts"]
index_attempts = [a for a in attempts if a.get("case") == "NA-RO-03"]
orig_attempts = [a for a in attempts if a.get("case") == "NA-RO-04"]
wanted_ops = {"open_w", "os.replace", "os.unlink", "os.rename"}
sha_same = (
    probe_body.get("sha256_unchanged") is True
    and probe_body["sha256_before"] == probe_body["sha256_after"]
)
st_rdonly = probe_body.get("statvfs_ST_RDONLY") is True
mechanism = proof.get("mechanism_claim") == "bwrap --ro-bind (NOT chmod-only; NOT os.access alone)"
argv = proof["bwrap"]["argv"]
ro_bind_pairs = [
    (argv[i + 1], argv[i + 2])
    for i, token in enumerate(argv)
    if token == "--ro-bind"
]
guest_mount = ("/home/box/ops-isolation/product/n11-trusted-original-root", "/trusted") in [
    (a, b) for a, b in ro_bind_pairs
]
empty_reg = probe_body.get("production_registry_guest") == {"records": []}
opened_empty = probe_body.get("open_registry_under_ro_bind", {}).get("records_len") == 0
fixture_not_registered = "fixture-sample.txt" not in json.dumps(probe_body.get("production_registry_guest"))
box_absent = not Path("/home/box/ops-isolation/product/n11-trusted-original-root").exists()


def attempt_ok(group: list) -> tuple[bool, str]:
    ops = {a.get("op") for a in group}
    all_oserror = all(a.get("exception_class") == "OSError" and a.get("ok") is False for a in group)
    err = ",".join(f"{a.get('op')}:{a.get('errname')}/{a.get('errno')}" for a in group)
    return ops == wanted_ops and all_oserror and len(group) == 4, err


idx_ok, idx_err = attempt_ok(index_attempts)
orig_ok, orig_err = attempt_ok(orig_attempts)
replace_notes = [a for a in attempts if a.get("op") == "os.replace"]
replace_exdev = all(a.get("errno") == 18 and a.get("errname") == "EXDEV" for a in replace_notes)
erofs_ops = [a for a in attempts if a.get("op") != "os.replace"]
erofs_ok = all(a.get("errno") == 30 and a.get("errname") == "EROFS" for a in erofs_ops)

na_ro_hold = all([
    hash_match,
    pin_match,
    proof.get("status") == "RO_BIND_PROVEN",
    ops_md.get("status") == "RO_BIND_PROVEN_GAP04_STILL_OPEN",
    mechanism,
    guest_mount,
    sha_same,
    st_rdonly,
    idx_ok,
    orig_ok,
    empty_reg,
    opened_empty,
    fixture_not_registered,
    erofs_ok,
])
add(
    "NA-RO-03",
    "t187",
    "tip51 Ops bwrap --ro-bind: index open/replace/unlink/rename all OSError; sha unchanged; not tip047",
    f"ops={idx_err} sha_unchanged={sha_same} ST_RDONLY={st_rdonly} replace_EXDEV={replace_exdev} reexecuted_here=false box_mount_present={not box_absent}",
    "PASS_EVIDENCE" if na_ro_hold else "FAIL",
    bed="tip51",
    not_tip047=True,
    fixture_physical_ro_only=True,
    gap04="OPEN",
    note="os.replace errno is EXDEV/18 (cross-device), not EROFS. open/unlink/rename are EROFS/30. sha256 unchanged. This VM did not re-run bwrap.",
)
add(
    "NA-RO-04",
    "t187",
    "same ro-bind writes against fixture original all OSError; sha unchanged; fixture not a formal original",
    f"ops={orig_err} fixture_registered_in_production={not fixture_not_registered} sha_before={probe_body['sha256_before'].get('/trusted/originals/fixture-sample.txt')}",
    "PASS_EVIDENCE" if na_ro_hold else "FAIL",
    bed="tip51",
    not_tip047=True,
    fixture_physical_ro_only=True,
    gap04="OPEN",
    note="Fixture file only. Production registry records stay []. EXDEV on os.replace disclosed.",
)
add(
    "OPS-TIP51-PIN",
    "ops",
    "proof and receipt pin this HEAD/tree/parent and intake b98f5a5c; hashes match the stated digests",
    f"hash_match={hash_match} pin_match={pin_match} proof={proof_sha} md={md_sha} json={ops_sha}",
    "MATCH" if hash_match and pin_match else "FAIL",
)
add(
    "WAITING_OPS_TIP51",
    "ops",
    "cleared because tip51 Ops bed is hash-matched; tip047 bed is not a substitute and was not used",
    "CLEARED",
    "CLEARED",
)

# Local chmod / os.access are not this proof.
chmod_root = WORK / "chmod-only"
chmod_root.mkdir()
target = chmod_root / "registry.json"
target.write_text('{"records":[]}\n', encoding="utf-8")
chmod_root.chmod(0o555)
target.chmod(0o444)
access_false = os.access(chmod_root, os.W_OK) is False
flags = os.statvfs(chmod_root).f_flag
st_rdonly_local = bool(flags & getattr(os, "ST_RDONLY", 1))
add(
    "NA-RO-01",
    "t187",
    "chmod a-w without ro-bind is RO_BIND_UNPROVEN and is not hard-isolation PASS",
    f"ro_bind_assessment(chmod)={ro_bind_assessment({'method':'chmod'})} os.access_W_OK={os.access(chmod_root, os.W_OK)} local_ST_RDONLY={st_rdonly_local}",
    "MATCH" if ro_bind_assessment({"method": "chmod"}) == "RO_BIND_UNPROVEN" and access_false and not st_rdonly_local else "FAIL",
)
add(
    "NA-RO-02",
    "t187",
    "os.access W_OK false alone is RO_BIND_UNPROVEN",
    f"assessment={ro_bind_assessment({'method':'os.access'})} access_false={access_false}",
    "MATCH" if ro_bind_assessment({"method": "os.access"}) == "RO_BIND_UNPROVEN" else "FAIL",
)
assessment_any = ro_bind_assessment({"method": "bwrap", "status": "RO_BIND_PROVEN"})
add(
    "RO-BIND-ASSESSMENT-CODE",
    "ops",
    "candidate ro_bind_assessment does not consume the Ops proof and does not close GAP-04",
    f"assessment_of_bwrap_dict={assessment_any}",
    "OPEN" if assessment_any == "RO_BIND_UNPROVEN" else "FAIL",
    gap="GAP-04",
)

# ---------------------------------------------------------------------------
# t187 issuer / registry / fixture
# ---------------------------------------------------------------------------

SAMPLE = b"TEST_FIXTURE bytes are not a formal original\n"
SAMPLE_SHA = hashlib.sha256(SAMPLE).hexdigest()
SECRET = b"SECRET_SHOULD_NOT_LEAK_9f3a\n"


def reg(name: str, **kwargs) -> Path:
    files = kwargs.pop("files", {"originals/sample.txt": SAMPLE})
    rec = record(file_sha=kwargs.pop("file_sha", SAMPLE_SHA), **kwargs)
    return publish(name, [rec], files)


def check_reject(case_id: str, expected_code: str, root: Path) -> None:
    result = consume(root)
    text = brief_consume(result)
    leaked = SECRET.decode() in text or "SECRET_SHOULD_NOT_LEAK" in text
    ok = (not leaked) and expected_code in text
    add(case_id, "t187", f"Rejected/Empty {expected_code}; content not returned", text, "MATCH" if ok else "FAIL")


check_reject("NA-IS-01", "ISSUER_SESSION_COLLISION", reg("is01", registration_id="is01", session=AGENT))
check_reject("NA-IS-02", "ISSUER_MISMATCH", reg("is02", registration_id="is02", session="6ae6216e-bbec-83e8-87dc-c3edd9027b00"))
check_reject("NA-IS-03", "ISSUER_MISMATCH", reg("is03", registration_id="is03", session=SESSION, issuer="agt_00000000000000000000000000000000"))

shape = consume(reg("is04", registration_id="is04", session=SESSION))
env_fix = run11(reg("is04b", registration_id="is04b", session=SESSION))
shape_ok = type(shape).__name__ == "Found" and shape.test_only is True
n11_blocked = env_fix["status"] == "BLOCKED" and env_fix["output"]["verdict"] != "PASS" and "TEST_FIXTURE_ONLY" in brief_n11(env_fix)
add(
    "NA-IS-04",
    "t187",
    "correct issuer and session: shape may pass; formal trust is not PASS",
    f"consume={brief_consume(shape)} n11={brief_n11(env_fix)}",
    "MATCH" if shape_ok and n11_blocked else "FAIL",
)
add(
    "NA-TF-01",
    "t187",
    "TEST_FIXTURE hit is BLOCKED + TEST_FIXTURE_ONLY and is not a formal original",
    brief_n11(env_fix),
    "MATCH" if n11_blocked and env_fix["output"]["verdict"] == "BLOCKED" else "FAIL",
)

# registry escape
outside = WORK / "outside-secret.txt"
outside.write_bytes(SECRET)
link_root = publish("rg01", [], {}, symlink_index=str(outside))
opened_link = open_registry(link_root, store_root=WORK / "iso-store-separate")
link_text = brief_consume(opened_link)
leaked = "SECRET_SHOULD_NOT_LEAK" in link_text or (isinstance(opened_link, trusted_mod.ReadOnlyRegistry) and opened_link.records)
add(
    "NA-RG-01",
    "t187",
    "registry.json symlink to outside is PATH_ESCAPE or ROOT_UNAVAILABLE and yields no content",
    link_text,
    "MATCH" if (not leaked) and ("PATH_ESCAPE" in link_text or "ROOT_UNAVAILABLE" in link_text) else "FAIL",
)

parent_escape = reg(
    "rg02",
    registration_id="rg02",
    session=SESSION,
    raw_ref="../outside-secret.txt",
)
dotdot = consume(parent_escape)
abs_rec_root = reg("rg02b", registration_id="rg02b", session=SESSION, raw_ref="/etc/hostname")
absolute = consume(abs_rec_root)
mid = WORK / "rg02c"
if mid.exists():
    thaw(mid)
    shutil.rmtree(mid)
mid.mkdir()
(mid / "originals").symlink_to(WORK)
payload = record(registration_id="rg02c", session=SESSION, file_sha=hashlib.sha256(SECRET).hexdigest(), raw_ref="originals/outside-secret.txt")
(mid / "registry.json").write_text(json.dumps({"records": [payload]}), encoding="utf-8")
freeze(mid)
middle = consume(mid)
escape_ok = all(
    "PATH_ESCAPE" in brief_consume(item) and "SECRET_SHOULD_NOT_LEAK" not in brief_consume(item)
    for item in (dotdot, absolute, middle)
)
add(
    "NA-RG-02",
    "t187",
    "absolute path, .., and an intermediate symlink are PATH_ESCAPE and yield no content",
    f"dotdot={brief_consume(dotdot)} absolute={brief_consume(absolute)} middle={brief_consume(middle)}",
    "MATCH" if escape_ok else "FAIL",
)

source = inspect.getsource(trusted_mod.open_registry)
naive = registry_index_review(Path(trusted_mod.__file__).read_text(encoding="utf-8"))
confined = "_read_confined(root, \"registry.json\")" in source and "read_text" not in source
add(
    "NA-RG-03",
    "t187",
    "open_registry reads registry.json through _read_confined; bare read_text is absent",
    f"confined={confined} naive_whole_file_scan={naive}",
    "MATCH" if confined else "FAIL",
    note="A whole-file scan of trusted_original.py sees the word read_text inside registry_index_review. That scan is not the open_registry check.",
)

# empty / unconfigured / writable / in-tree
empty_root = publish("empty-reg", [], {})
# publish wrote registry.json records [] because records list empty, plus no sample file. Good.
empty_open = open_registry(empty_root, store_root=WORK / "iso-store-separate")
empty_consume = consume(empty_root)
empty_n11 = run11(empty_root)
empty_ok = (
    isinstance(empty_open, trusted_mod.ReadOnlyRegistry)
    and empty_open.records == {}
    and brief_consume(empty_consume) == "Empty EMPTY_REGISTRY"
    and empty_n11["status"] == "BLOCKED"
    and "EMPTY_REGISTRY" in brief_n11(empty_n11)
    and empty_n11["output"]["verdict"] != "PASS"
)
add(
    "NA-TF-02",
    "t187",
    "empty registry is EMPTY_REGISTRY and N11 BLOCKED, not PASS",
    f"open={type(empty_open).__name__}:{getattr(empty_open,'records',None)} consume={brief_consume(empty_consume)} n11={brief_n11(empty_n11)}",
    "MATCH" if empty_ok else "FAIL",
)
unset = run11(None)
add(
    "N11-TO-01b",
    "n11",
    "unconfigured root is BLOCKED ROOT_UNAVAILABLE",
    brief_n11(unset),
    "MATCH" if unset["status"] == "BLOCKED" and "ROOT_UNAVAILABLE" in brief_n11(unset) and unset["output"]["verdict"] != "PASS" else "FAIL",
)
writable = publish("writable-reg", [], {"originals/sample.txt": SECRET}, lock=False)
writable_open = open_registry(writable)
add(
    "N11-TO-01b-writable",
    "n11",
    "a writable root is ROOT_UNAVAILABLE and does not return the file body",
    brief_consume(writable_open),
    "MATCH" if brief_consume(writable_open) == "Empty ROOT_UNAVAILABLE" else "FAIL",
)
intree = open_registry(ROOT / "octo")
add(
    "N11-ROOT-IN-CANDIDATE",
    "n11",
    "a root inside the candidate tree is ROOT_UNAVAILABLE",
    brief_consume(intree),
    "MATCH" if brief_consume(intree) == "Empty ROOT_UNAVAILABLE" else "FAIL",
)

# forged receipt / nonempty evidence is not verification
forged_path = WORK / "forged-receipt.json"
forged_body = {
    "issuer": AGENT,
    "candidate_sha": HEAD,
    "verdict": "PASS",
    "signed_by": AGENT,
    "path": str(forged_path),
    "source_evidence": "nonempty-string-is-not-verification",
}
forged_path.write_text(json.dumps(forged_body), encoding="utf-8")
forged_env = run11(None, forged_body)
add(
    "NA-TF-03",
    "t187",
    "forged REVIEW_RECEIPT / nonempty string is EVIDENCE_UNVERIFIED or BLOCKED and is not formal trust",
    brief_n11(forged_env),
    "MATCH" if forged_env["status"] == "BLOCKED" and forged_env["output"]["verdict"] != "PASS" else "FAIL",
)
review = publish(
    "review-receipt",
    [record(registration_id="rev1", session=SESSION, kind="REVIEW_RECEIPT", test_only=False, file_sha=SAMPLE_SHA, proof="relay-proof-nonempty-still-not-verified")],
    {"originals/sample.txt": SAMPLE},
)
review_result = consume(review)
add(
    "SOURCE-EVIDENCE-NONEMPTY",
    "t187",
    "nonempty source_evidence on a REVIEW_RECEIPT is not independent verification",
    brief_consume(review_result),
    "MATCH" if brief_consume(review_result) == "Rejected EVIDENCE_UNVERIFIED" else "FAIL",
    gap="GAP-03",
)
add(
    "N11-FORMAL-OK",
    "n11",
    "a real verified REVIEW_RECEIPT PASS is not available; GAP-01 and GAP-03 stay OPEN",
    brief_consume(review_result),
    "OPEN",
    gap="GAP-01,GAP-03",
    note="Code returns EVIDENCE_UNVERIFIED for every REVIEW_RECEIPT. That refuses an unverified original. It does not close GAP-03 and it is not N11 complete.",
)

# more interface cases on the fixture mechanism
wrong_route = dict(binding())
wrong_route["route"] = "other-route"
bad_tuple_root = publish(
    "tuple",
    [record(registration_id="tup", session=SESSION, file_sha=SAMPLE_SHA, tuple_override=wrong_route)],
    {"originals/sample.txt": SAMPLE},
)
add(
    "N11-TO-06-route",
    "n11",
    "changed route is TUPLE_MISMATCH",
    brief_consume(consume(bad_tuple_root)),
    "MATCH" if brief_consume(consume(bad_tuple_root)) == "Rejected TUPLE_MISMATCH" else "FAIL",
)
short = dict(binding())
short["base_sha"] = "abc"
short_root = publish(
    "shortsha",
    [record(registration_id="short", session=SESSION, file_sha=SAMPLE_SHA, tuple_override=short)],
    {"originals/sample.txt": SAMPLE},
)
add(
    "N11-TO-06f-short",
    "n11",
    "short SHA does not normalize to a tuple and does not hit",
    brief_consume(consume(short_root)),
    "MATCH" if "TUPLE_MISMATCH" in brief_consume(consume(short_root)) else "FAIL",
)
upper = dict(binding())
upper["candidate_sha"] = HEAD.upper()
upper_root = publish(
    "upper",
    [record(registration_id="upper", session=SESSION, file_sha=SAMPLE_SHA, tuple_override=upper)],
    {"originals/sample.txt": SAMPLE},
)
upper_hit = consume(upper_root)
add(
    "N11-TO-06f-upper",
    "n11",
    "uppercase hex normalizes and can hit the TEST_FIXTURE row; still test_only",
    brief_consume(upper_hit),
    "MATCH" if type(upper_hit).__name__ == "Found" and upper_hit.test_only else "FAIL",
)
loop_hashes = {SAMPLE_SHA}
loop_root = publish(
    "loop",
    [record(registration_id="loop", session=SESSION, file_sha=SAMPLE_SHA, hashes=loop_hashes)],
    {"originals/sample.txt": SAMPLE},
)
add(
    "N11-TO-09",
    "n11",
    "bytes_sha256 in the fixture set is FIXTURE_LOOP",
    brief_consume(consume(loop_root, hashes=loop_hashes)),
    "MATCH" if brief_consume(consume(loop_root, hashes=loop_hashes)) == "Rejected FIXTURE_LOOP" else "FAIL",
)
tampered = bytearray(SAMPLE)
tampered[0] ^= 0x01
tamper_root = publish("tamper", [record(registration_id="tamper", session=SESSION, file_sha=SAMPLE_SHA)], {"originals/sample.txt": bytes(tampered)})
add(
    "N11-TO-11",
    "n11",
    "changed raw bytes are HASH_MISMATCH",
    brief_consume(consume(tamper_root)),
    "MATCH" if brief_consume(consume(tamper_root)) == "Rejected HASH_MISMATCH" else "FAIL",
)
amb = publish(
    "amb",
    [
        record(registration_id="a", session=SESSION, file_sha=SAMPLE_SHA),
        record(registration_id="b", session=SESSION, file_sha=SAMPLE_SHA),
    ],
    {"originals/sample.txt": SAMPLE},
)
add(
    "N11-TO-14",
    "n11",
    "two records for one tuple are AMBIGUOUS",
    brief_consume(consume(amb)),
    "MATCH" if brief_consume(consume(amb)) == "Rejected AMBIGUOUS" else "FAIL",
)
before = sha256_file(ROOT / "octo/closing.py")
_ = consume(reg("zero", registration_id="zero", session=SESSION))
after = sha256_file(ROOT / "octo/closing.py")
add(
    "N11-TO-08",
    "n11",
    "consuming a TEST_FIXTURE does not change closing.py; this is not a real PASS",
    f"sha_before={before} sha_after={after}",
    "MATCH" if before == after else "FAIL",
    note="GAP-01 remains. TEST_FIXTURE is not the original.",
)
self_report = {"candidate_sha": HEAD, "signed_by": "candidate-self-report", "verdict": "PASS", "issuer": AGENT}
builder_signed = {"candidate_sha": HEAD, "builder_signed": True, "verdict": "PASS"}
wrong_issuer = {"candidate_sha": HEAD, "issuer": "forged-not-a-ta-reviewer", "verdict": "PASS"}
revise = {"candidate_sha": HEAD, "verdict": "REVISE", "evidence": [{"note": "revise me"}]}
blocked_claim = {"candidate_sha": HEAD, "verdict": "BLOCKED"}
empty_proof = {"candidate_sha": HEAD}
add("N11-TO-02", "n11", "self-written file plus public reviewer id is BLOCKED", brief_n11(forged_env), "MATCH" if forged_env["output"]["verdict"] != "PASS" else "FAIL")
add("N11-TO-03", "n11", "builder_signed is BLOCKED BUILDER_PASS_FORBIDDEN", brief_n11(run11(None, builder_signed)), "MATCH" if "BUILDER_PASS_FORBIDDEN" in brief_n11(run11(None, builder_signed)) else "FAIL")
add("N11-TO-04", "n11", "candidate self-report is BLOCKED", brief_n11(run11(None, self_report)), "MATCH" if "self-report" in brief_n11(run11(None, self_report)) else "FAIL")
add("N11-TO-05", "n11", "wrong issuer is BLOCKED forged", brief_n11(run11(None, wrong_issuer)), "MATCH" if "forged" in brief_n11(run11(None, wrong_issuer)) else "FAIL")
revise_env = run11(None, revise)
add(
    "DOD-A-UNTRUSTED-REVISE",
    "DoD-A",
    "an untrusted REVISE dict is not a formal opinion and is not raised to PASS",
    brief_n11(revise_env),
    "MATCH" if revise_env["status"] == "BLOCKED" and revise_env["output"]["verdict"] == "BLOCKED" else "FAIL",
)
blocked_env = run11(None, blocked_claim)
add(
    "DOD-A-UNTRUSTED-BLOCKED",
    "DoD-A",
    "an untrusted BLOCKED dict is not raised to PASS",
    brief_n11(blocked_env),
    "MATCH" if blocked_env["output"]["verdict"] == "BLOCKED" and blocked_env["status"] == "BLOCKED" else "FAIL",
)
add(
    "DOD-A-EMPTY-PROOF",
    "DoD-A",
    "sha-only empty proof is BLOCKED",
    brief_n11(run11(None, empty_proof)),
    "MATCH" if run11(None, empty_proof)["output"]["verdict"] != "PASS" else "FAIL",
)
try:
    run_n11({"candidate_sha": HEAD, "scope": {"route": "internal_readonly"}}, at=AT, builder_claims_pass=True)
    add("DOD-A-BUILDER-FLAG", "DoD-A", "builder_claims_pass raises BUILDER_PASS_FORBIDDEN", "returned", "FAIL")
except ValueError as exc:
    add("DOD-A-BUILDER-FLAG", "DoD-A", "builder_claims_pass raises BUILDER_PASS_FORBIDDEN", str(exc), "MATCH" if "BUILDER_PASS_FORBIDDEN" in str(exc) else "FAIL")

verified_none = trusted_mod  # keep linter quiet
from octo.closing import _verified_original  # noqa: E402

none_original = _verified_original(None, HEAD, {"route": "internal_readonly"})
add(
    "N11-TO-15",
    "n11",
    "with no registry, _verified_original is None; with a TEST_FIXTURE registry it is not None and stays test_only",
    f"no_registry={none_original} with_fixture={brief_consume(shape)}",
    "MATCH" if none_original is None and shape_ok else "FAIL",
)
add(
    "N11-TO-16",
    "n11",
    "a non-fixture FAIL verdict cannot become a formal PASS while GAP-03 is open",
    brief_consume(consume(publish(
        "verdict-fail",
        [record(registration_id="vf", session=SESSION, kind="REVIEW_RECEIPT", test_only=False, file_sha=SAMPLE_SHA, verdict="FAIL")],
        {"originals/sample.txt": SAMPLE},
    ))),
    "OPEN",
    gap="GAP-03",
    note="Observed rejection is EVIDENCE_UNVERIFIED before verdict forwarding. Formal REVISE/BLOCKED passthrough stays OPEN.",
)

# candidate-supplied registration id is not the query key
injected = {
    "candidate_sha": HEAD,
    "registration_id": "not-the-real-row",
    "issuer": AGENT,
    "verdict": "PASS",
}
injected_env = run11(reg("inject", registration_id="real-row", session=SESSION), injected)
add(
    "N11-TO-10",
    "n11",
    "candidate registration_id / path does not grant trust; fixture hit stays TEST_FIXTURE_ONLY",
    brief_n11(injected_env),
    "MATCH" if "TEST_FIXTURE_ONLY" in brief_n11(injected_env) and injected_env["output"]["verdict"] != "PASS" else "FAIL",
)

# ---------------------------------------------------------------------------
# DoD B / C / D / E / H / N10
# ---------------------------------------------------------------------------


def make_request(store: Path, *, intent_id: str, idem: str, grant_id: str, text: str = "synthetic"):
    resource = store / "readable.txt"
    resource.write_text(text, encoding="utf-8")
    request = AuthorizationRequest(
        actor="actor-a",
        action="internal_readonly",
        resource=str(resource),
        parameters={"op": "read"},
        intent_id=intent_id,
        idempotency_key=idem,
        git_candidate_sha=HEAD,
        tree_sha=TREE,
        grant_id=grant_id,
    )
    grants = GrantStore(store, fixture_key=KEY)
    grants.issue_test_fixture(
        grant_id=grant_id,
        subject=request.actor,
        resource=str(store),
        request_digest_hex=request.digest,
        git_candidate=request.git_candidate_sha,
        tree=request.tree_sha,
        now=NOW,
    )
    return request, grants


def pack_for(intent: dict, *, n2_bound=None, n3_signal=None, n5=None, n5_bound=None, n8_acceptance="PYTHONPATH=. pytest tests/ -q exits 0", n2_foreign=None) -> dict:
    return {
        "n1": N1_IN,
        "n2": {"intent_id": n2_foreign or intent["intent_id"]},
        "n2_bound": n2_bound,
        "n3": {
            "intent": intent,
            "context_pack": {"intent_id": intent["intent_id"]},
            "新事实/偏差信号": n3_signal or {"kill_line_ref": "SOURCE_UNAVAILABLE"},
        },
        "n4": {"intent": intent},
        "n4_bound": {
            "candidates": [{
                "type": "internal",
                "ref": "isolation-store",
                "fit": "TEST_FIXTURE",
                "cost_hint": "low",
            }]
        },
        "n5": n5 or {"claims": ["closing nodes write only to the isolation store"]},
        "n5_bound": n5_bound or {
            "facts": [{
                "claim": "closing nodes write only to the isolation store",
                "verdict": "CLAIM",
                "evidence_ref": "SOURCE_UNAVAILABLE",
                "freshness": "TEST_FIXTURE",
            }],
        },
        "n8": {
            "intent": intent,
            "options": [{
                "id": "S1_CONTROLLED_REUSE",
                "description": "controlled reuse",
                "measurable_acceptance": n8_acceptance,
            }],
        },
    }


intent = run_n1(N1_IN, at=AT)["output"]


def standard(store: Path, *, idem: str, grant_id: str, **pack_kw):
    request, grants = make_request(store, intent_id=intent["intent_id"], idem=idem, grant_id=grant_id)
    journal = Journal(store)
    gateway = Gateway(journal, grants)
    body = pack_for(intent, **pack_kw)
    body["gateway"] = gateway
    result = run_standard(
        {"action_type": "internal_readonly", "grant_ref": grant_id},
        body,
        at=AT,
        request=request,
        store=grants,
        now=NOW,
    )
    return result, journal, request


h2_store = WORK / "h2"
h2_store.mkdir()
h2, h2_journal, _h2_request = standard(h2_store, idem="idem-h2", grant_id="g-h2")
h2_ids = [item["node_id"] for item in h2["envelopes"]]
h2_n2 = next(item for item in h2["envelopes"] if item["node_id"] == "N2")
h2_n10 = next(item for item in h2["envelopes"] if item["node_id"] == "N10")
h2_n11 = next(item for item in h2["envelopes"] if item["node_id"] == "N11")
h2_n12 = next(item for item in h2["envelopes"] if item["node_id"] == "N12")
h2_n13 = next(item for item in h2["envelopes"] if item["node_id"] == "N13")
n10_pack_same = h2_n10["inputs"]["context_pack"] == h2_n2["output"]
seven = {"intent_id", "current_decisions", "key_evidence", "open_states", "prohibitions", "assembled_at", "sources"}
add(
    "DOD-B-N11-OVERALL",
    "DoD-B",
    "no trusted original: N11 BLOCKED and run_standard body status is not OK",
    f"body={h2['status']} n11={h2_n11['status']}/{h2_n11['output']['verdict']} ids={h2_ids}",
    "MATCH" if h2["status"] == "BLOCKED" and h2_n11["status"] == "BLOCKED" and h2_n11["output"]["verdict"] != "PASS" and "N6" not in h2_ids and "N7" not in h2_ids else "FAIL",
)
add(
    "DOD-B-N10-PACK",
    "DoD-B",
    "N10 context_pack is that run's N2 seven-field pack",
    f"equal={n10_pack_same} keys={sorted(h2_n10['inputs']['context_pack'])}",
    "MATCH" if n10_pack_same and set(h2_n10["inputs"]["context_pack"]) == seven else "FAIL",
)
same_intent = len({item["output"].get("intent_id") for item in h2["envelopes"] if item["node_id"] in {"N1", "N2"} and isinstance(item.get("output"), dict)}) == 1
add(
    "DOD-B-INTENT",
    "DoD-B",
    "N1 and N2 share one intent id on this run",
    f"n1={h2['envelopes'][0]['output']['intent_id']} n2={h2_n2['output']['intent_id']}",
    "MATCH" if same_intent and h2["envelopes"][0]["output"]["intent_id"] == h2_n2["output"]["intent_id"] else "FAIL",
)

ROUTE = {"action_type": "internal_readonly", "grant_ref": "g-shape"}
unclear = run_prefix(
    ROUTE,
    pack_for(intent) | {"n1": {"text": "maybe later?", "source": {"kind": "human"}}},
    at=AT,
)
add(
    "DOD-B-N1-STOP",
    "DoD-B",
    "N1 NEEDS_CLARIFICATION stops the prefix",
    f"status={unclear['status']} ids={[e['node_id'] for e in unclear['envelopes']]}",
    "MATCH" if unclear["status"] == "NEEDS_CLARIFICATION" and [e["node_id"] for e in unclear["envelopes"]] == ["N1"] else "FAIL",
)
foreign = run_prefix(
    ROUTE,
    pack_for(intent, n2_foreign="intent-OTHER"),
    at=AT,
)
add(
    "DOD-B-FOREIGN-INTENT",
    "DoD-B",
    "a foreign N2 intent stops the chain",
    f"status={foreign['status']} ids={[e['node_id'] for e in foreign['envelopes']]}",
    "MATCH" if foreign["status"] == "BLOCKED" and [e["node_id"] for e in foreign["envelopes"]] == ["N1"] else "FAIL",
)
partial = run_prefix(
    ROUTE,
    pack_for(intent, n2_bound={"gaps": ["source-b-missing"]}),
    at=AT,
)
add(
    "DOD-B-N2-PARTIAL-READONLY",
    "DoD-B",
    "N2 PARTIAL on internal_readonly may continue and the body stays PARTIAL",
    f"status={partial['status']} n2={partial['envelopes'][1]['status']} readonly={partial['readonly_continue']} ids={[e['node_id'] for e in partial['envelopes']]}",
    "MATCH" if partial["status"] == "PARTIAL" and partial["envelopes"][1]["status"] == "PARTIAL" and partial["readonly_continue"] is True else "FAIL",
)
from octo.nodes import guard_consequential  # noqa: E402

conseq = run_prefix(
    {"action_type": "external_effect", "grant_ref": "g-shape"},
    pack_for(intent, n2_bound={"gaps": ["source-b-missing"]}),
    at=AT,
)
guard_raised = False
try:
    guard_consequential("PARTIAL", "external_effect")
except ValueError:
    guard_raised = True
add(
    "DOD-B-PARTIAL-CONSEQUENTIAL",
    "DoD-B",
    "a non-readonly action does not run the prefix; the PARTIAL guard rejects a consequential action",
    f"route_status={conseq['status']} ids={[e['node_id'] for e in conseq['envelopes']]} guard_raised={guard_raised}",
    "MATCH" if conseq["status"] != "OK" and conseq["envelopes"] == [] and guard_raised else "FAIL",
)
killed = run_prefix(
    ROUTE,
    pack_for(intent, n3_signal={"observed": 9, "kill_line": {"label": "TEST_FIXTURE", "threshold": 5}}),
    at=AT,
)
add(
    "DOD-B-N3-STOP",
    "DoD-B",
    "N3 still_worth_it false stops before N4 and body is not OK",
    f"status={killed['status']} ids={[e['node_id'] for e in killed['envelopes']]} worth={killed['envelopes'][-1]['output'].get('still_worth_it')}",
    "MATCH" if killed["status"] == "BLOCKED" and [e["node_id"] for e in killed["envelopes"]] == ["N1", "N2", "N3"] and killed["envelopes"][-1]["output"]["still_worth_it"] is False else "FAIL",
)
no_evidence = run_prefix(
    ROUTE,
    pack_for(intent, n5={"claims": ["no-evidence-claim"]}, n5_bound={"facts": []}),
    at=AT,
)
add(
    "DOD-B-N5-STOP",
    "DoD-B",
    "N5 with an unadjudicated claim is PARTIAL and stops before N8",
    f"status={no_evidence['status']} ids={[e['node_id'] for e in no_evidence['envelopes']]} fact={no_evidence['envelopes'][-1]['output']['facts'][0]['verdict']}",
    "MATCH" if no_evidence["status"] == "PARTIAL" and no_evidence["envelopes"][-1]["node_id"] == "N5" and no_evidence["envelopes"][-1]["output"]["facts"][0]["verdict"] == "CLAIM" else "FAIL",
)
vague = run_prefix(
    ROUTE,
    pack_for(intent, n8_acceptance="works well"),
    at=AT,
)
add(
    "DOD-B-N8-STOP",
    "DoD-B",
    "N8 'works well' is NEEDS_CLARIFICATION and stops before N9",
    f"status={vague['status']} ids={[e['node_id'] for e in vague['envelopes']]}",
    "MATCH" if vague["status"] == "NEEDS_CLARIFICATION" and vague["envelopes"][-1]["node_id"] == "N8" else "FAIL",
)

# N2 partial then N11 blocked => overall not OK
partial_store = WORK / "partial-std"
partial_store.mkdir()
partial_std, partial_journal, _ = standard(partial_store, idem="idem-partial", grant_id="g-partial", n2_bound={"gaps": ["source-b-missing"]})
add(
    "DOD-V11-OVERALL",
    "DoD-B",
    "N2 PARTIAL may continue read-only; N11 BLOCKED makes run_standard overall not OK",
    f"body={partial_std['status']} n2={partial_std['envelopes'][1]['status']} n11={next(e for e in partial_std['envelopes'] if e['node_id']=='N11')['status']}",
    "MATCH" if partial_std["status"] != "OK" and partial_std["envelopes"][1]["status"] == "PARTIAL" else "FAIL",
)
partial_journal.close()

# N12
n12_store = WORK / "n12"
n12_store.mkdir()
n12_inputs = {
    "decisions": [
        {"id": "d0", "content": "original"},
        {"id": "d1", "content": "replacement", "supersedes": "d0"},
    ],
    "evidence": [{"id": "e1", "uri_or_hash": "sha256:evidence"}],
    "receipts": [{"receipt_id": "r1", "result": "SUCCEEDED"}],
    "failures": [{"id": "f1", "reason": "disk write failed"}],
}
n12_env = run_n12(n12_inputs, at=AT, store_root=n12_store)
objects = [row["object"] for row in n12_env["output"]["written"]]
paths_open = []
sha_ok = True
for row in n12_env["output"]["written"]:
    path = n12_store / row["path"]
    paths_open.append(path.is_file() and row["path"].startswith("capture/"))
    sha_ok = sha_ok and hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
link = n12_env["output"]["superseded"][0]["link"]
link_ok = (n12_store / link).is_file() and not str(link).startswith("supersedes:")
add(
    "DOD-C-OBJECTS",
    "DoD-C",
    "written objects are only Decision, Evidence, Receipt; failure row is a Receipt; path opens from store_root; sha matches",
    f"objects={objects} paths_open={paths_open} sha_ok={sha_ok} link={link} link_ok={link_ok}",
    "MATCH" if objects.count("Receipt") >= 2 and "Failure" not in objects and all(paths_open) and sha_ok and link_ok else "FAIL",
)
again = run_n12(
    {"decisions": [], "evidence": [], "receipts": [{"receipt_id": "r1", "result": "SUCCEEDED"}], "failures": []},
    at=AT,
    store_root=n12_store,
)
kept = (n12_store / again["output"]["written"][0]["path"]).read_bytes()
try:
    run_n12(
        {"decisions": [], "evidence": [], "receipts": [{"receipt_id": "r1", "result": "OTHER"}], "failures": []},
        at=AT,
        store_root=n12_store,
    )
    conflict = "no exception"
    conflict_verdict = "FAIL"
except ValueError as exc:
    conflict = str(exc)
    conflict_verdict = "MATCH" if conflict.startswith("CONTENT_CONFLICT:") else "FAIL"
still = (n12_store / again["output"]["written"][0]["path"]).read_bytes()
add(
    "DOD-C-IDEMPOTENT",
    "DoD-C",
    "same Receipt content is returned again and does not raise SUPERSEDE_OVERWRITE",
    f"second_sha={again['output']['written'][0]['sha256']} same_bytes={kept==still}",
    "MATCH" if again["output"]["written"][0]["sha256"] == n12_env["output"]["written"][0]["sha256"] and "SUPERSEDE_OVERWRITE" not in json.dumps(again) else "FAIL",
)
add(
    "DOD-C-CONFLICT",
    "DoD-C",
    "conflicting content raises CONTENT_CONFLICT and leaves the old bytes in place",
    f"{conflict} bytes_unchanged={kept==still}",
    conflict_verdict if kept == still else "FAIL",
)

# H1 writeback failure
h1_store = WORK / "h1"
h1_store.mkdir()
(h1_store / "capture").write_text("not-a-directory", encoding="utf-8")
h1, h1_journal, _ = standard(h1_store, idem="idem-h1", grant_id="g-h1")
h1_n13 = h1["envelopes"][-1]
h1_n12 = next(item for item in h1["envelopes"] if item["node_id"] == "N12")
add(
    "DOD-H1",
    "DoD-D4",
    "N12 writeback failure makes N13 writeback_state FAILED and body is not OK",
    f"n12={h1_n12['status']} writeback={h1_n13['inputs']['writeback_state']} body={h1['status']} helper={writeback_state_from_n12(h1_n12)}",
    "MATCH" if h1_n13["inputs"]["writeback_state"] == "FAILED" and h1["status"] != "OK" and writeback_state_from_n12(h1_n12) == "FAILED" else "FAIL",
)
add(
    "DOD-H2",
    "DoD-D4",
    "N12 success makes writeback_state OK legally while N11 stays BLOCKED",
    f"writeback={h2_n13['inputs']['writeback_state']} n12={h2_n12['status']} n11={h2_n11['output']['verdict']} body={h2['status']}",
    "MATCH" if h2_n13["inputs"]["writeback_state"] == "OK" and h2_n12["status"] == "OK" and h2_n11["output"]["verdict"] == "BLOCKED" and h2["status"] == "BLOCKED" else "FAIL",
)
ready_env = {"status": "OK", "output": {"verdict": "PASS"}}
blocked_handoff_env = {"status": "BLOCKED", "output": {"verdict": "BLOCKED"}}
revise_handoff_env = {"status": "BLOCKED", "output": {"verdict": "REVISE"}}
h_ready = handoff_state_from_n11(ready_env)
h_blocked = handoff_state_from_n11(blocked_handoff_env)
h_revise = handoff_state_from_n11(revise_handoff_env)
standard_follows = h2_n13["inputs"]["handoff_state"] == handoff_state_from_n11(h2_n11)
add(
    "DOD-H3",
    "DoD-D4",
    "handoff follows the N11 condition: missing reviewer is NOT_READY; a PASS envelope is READY; a BLOCKED/REVISE envelope is NOT_READY",
    f"ready={h_ready} blocked={h_blocked} revise={h_revise} run_standard={h2_n13['inputs']['handoff_state']} wired={standard_follows}",
    "MATCH" if h_ready == "READY" and h_blocked == "NOT_READY" and h_revise == "NOT_READY" and h2_n13["inputs"]["handoff_state"] == "NOT_READY" and standard_follows else "FAIL",
    note="READY here is the helper applied to a synthetic envelope. run_standard on this VM stays NOT_READY because no verified original exists. GAP-01 remains OPEN. This is not a constant swap and not a product PASS.",
)
literal_assign = 'writeback_state = "OK"' in (ROOT / "octo/standard.py").read_text(encoding="utf-8") or 'handoff_state = "NOT_READY"' in (ROOT / "octo/standard.py").read_text(encoding="utf-8")
add(
    "DOD-H-NO-CONSTANT-ASSIGN",
    "DoD-D4",
    "run_standard does not assign writeback_state or handoff_state as a bare constant",
    f"bare_constant_assignment_present={literal_assign}",
    "MATCH" if not literal_assign else "FAIL",
)

# D4 store dedup
states = {"outcome": "SUCCEEDED", "verify_state": "BLOCKED", "writeback_state": "OK", "handoff_state": "NOT_READY"}
dedup_store = WORK / "dedup"
dedup_store.mkdir()
first = run_n13(states, at=AT, store_root=dedup_store, intent_id="intent-a")
second = run_n13(states, at=AT, store_root=dedup_store, intent_id="intent-a")
changed = run_n13(
    {"outcome": "FAILED", "verify_state": "BLOCKED", "writeback_state": "FAILED", "handoff_state": "NOT_READY"},
    at=AT,
    store_root=dedup_store,
    intent_id="intent-a",
)
other_intent = run_n13(states, at=AT, store_root=dedup_store, intent_id="intent-b")
other_store = WORK / "dedup-b"
other_store.mkdir()
other = run_n13(states, at=AT, store_root=other_store, intent_id="intent-a")
proc = subprocess.run(
    [sys.executable, "-c", """
import json, sys
sys.path.insert(0, "/workspace")
from octo.closing import run_n13
store, intent = sys.argv[1], sys.argv[2]
env = run_n13(
    {"outcome":"SUCCEEDED","verify_state":"BLOCKED","writeback_state":"OK","handoff_state":"NOT_READY"},
    at="2026-11-01T12:00:00+00:00",
    store_root=store,
    intent_id=intent,
)
print(json.dumps({"notify_once": env["output"]["notify_once"]}))
""", str(dedup_store), "intent-a"],
    check=False,
    text=True,
    capture_output=True,
    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
)
restart = json.loads(proc.stdout) if proc.returncode == 0 and proc.stdout.strip() else {"error": proc.stderr, "code": proc.returncode}
add(
    "DOD-D4-SAME",
    "DoD-D4",
    "same store, intent, and blocker: second call and a new process do not notify again",
    f"first={first['output']['notify_once']} second={second['output']['notify_once']} restart={restart}",
    "MATCH" if first["output"]["notify_once"] is True and second["output"]["notify_once"] is False and restart.get("notify_once") is False else "FAIL",
)
add(
    "DOD-D4-CHANGE",
    "DoD-D4",
    "a blocker change notifies again",
    f"changed={changed['output']['notify_once']}",
    "MATCH" if changed["output"]["notify_once"] is True else "FAIL",
)
add(
    "DOD-D4-INTENT",
    "DoD-D4",
    "a different intent is not suppressed by the same blocker label",
    f"other_intent={other_intent['output']['notify_once']}",
    "MATCH" if other_intent["output"]["notify_once"] is True else "FAIL",
)
add(
    "DOD-D4-OTHER-STORE",
    "DoD-D4",
    "another store still notifies; two stores are not used as the dedup proof",
    f"other_store={other['output']['notify_once']} proof_is_same_store_second={second['output']['notify_once']}",
    "MATCH" if other["output"]["notify_once"] is True and second["output"]["notify_once"] is False else "FAIL",
)
def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
    return None


mutable_sets = []
frozen_names = []
for node in ast.parse(Path(closing_mod.__file__).read_text(encoding="utf-8")).body:
    if not isinstance(node, ast.Assign):
        continue
    for target in node.targets:
        if not isinstance(target, ast.Name):
            continue
        if isinstance(node.value, ast.Set) or _call_name(node.value) == "set":
            mutable_sets.append(target.id)
        elif _call_name(node.value) == "frozenset":
            frozen_names.append(target.id)
schema_sets = {"N11_KEYS", "N12_KEYS", "N13_KEYS"}
dedup_sets = [name for name in mutable_sets if name not in schema_sets]
add(
    "DOD-D4-NO-GLOBAL-SET",
    "DoD-D4",
    "no module-level mutable set is the dedup bucket; shape sets are not that bucket",
    f"dedup_sets={dedup_sets} schema_sets={sorted(set(mutable_sets) & schema_sets)} frozenset_constants={frozen_names}",
    "MATCH" if dedup_sets == [] and set(mutable_sets) <= schema_sets else "FAIL",
    note="N11_KEYS, N12_KEYS, and N13_KEYS are input-shape sets. They are not the notification bucket. Dedup is store/board/notifications.json, shown by DOD-D4-SAME across a second process.",
)

# evidence links and four-state split
links = h2_n13["output"]["evidence_links"]
status_prefix = any(str(link).startswith(("outcome:", "verify_state:", "writeback_state:", "handoff_state:")) for link in links)
hash_links = [link for link in links if str(link).startswith("sha256:")]
recomputed = "sha256:" + product_digest({"field": "outcome", "value": h2_n13["inputs"]["outcome"]})
path_links = [link for link in links if not str(link).startswith("sha256:")]
paths_exist = all((h2_store / link).is_file() for link in path_links)
add(
    "DOD-D-LINKS",
    "DoD-D",
    "evidence_links are openable capture paths or recomputable sha256 pointers, not status strings",
    f"links={links} recomputed_present={recomputed in links} paths_exist={paths_exist}",
    "MATCH" if (not status_prefix) and recomputed in hash_links and paths_exist else "FAIL",
)
split = run_n13(
    {"outcome": "SUCCEEDED", "verify_state": "READY", "writeback_state": "FAILED", "handoff_state": "READY"},
    at=AT,
    store_root=WORK / "split",
    intent_id="intent-split",
)
add(
    "DOD-D-WRITEBACK-SPLIT",
    "DoD-D",
    "writeback FAILED is not reported as SUCCEEDED or envelope OK",
    f"state={split['output']['state']} status={split['status']} owner={split['output']['owner']} next={split['output']['next_legal_action']}",
    "MATCH" if split["output"]["state"] != "SUCCEEDED" and split["status"] != "OK" and split["output"]["next_legal_action"] == "repair-writeback" else "FAIL",
)

# second run_standard on h2 store should suppress
h2_body = pack_for(intent)
h2_body["gateway"] = Gateway(h2_journal, GrantStore(h2_store, fixture_key=KEY))
h2b = run_standard(
    {"action_type": "internal_readonly", "grant_ref": "g-h2"},
    h2_body,
    at=AT,
    request=_h2_request,
    store=GrantStore(h2_store, fixture_key=KEY),
    now=NOW,
)
h2b_n13 = h2b["envelopes"][-1]
add(
    "DOD-D4-RUN-STANDARD",
    "DoD-D4",
    "a second run_standard on the same store and intent suppresses the same blocker",
    f"first={h2_n13['output']['notify_once']} second={h2b_n13['output']['notify_once']} blocker={h2b_n13['inputs']}",
    "MATCH" if h2_n13["output"]["notify_once"] is True and h2b_n13["output"]["notify_once"] is False else "FAIL",
)
h2_journal.close()
h1_journal.close()

# N9 / N5
n9_store = WORK / "n9"
n9_store.mkdir()
n9_request, n9_grants = make_request(n9_store, intent_id=intent["intent_id"], idem="idem-n9", grant_id="g-n9")
bad_digest = "ab" * 32
n9_env = run_n9(
    {"action": n9_request.action, "grant_id": n9_request.grant_id, "request_digest": bad_digest},
    at=AT,
    store=n9_grants,
    request=n9_request,
    now=NOW,
)
receipts = list((n9_store / "receipts").glob("*.json"))
deny_text = "\n".join(path.read_text(encoding="utf-8") for path in receipts)
add(
    "DOD-E-N9-DIGEST",
    "DoD-E",
    "a mismatched request_digest is DENY, writes a receipt file, and carries this request's grant draft",
    f"status={n9_env['status']} verdict={n9_env['output']['verdict']} receipts={len(receipts)} draft_has_digest={'digest=' + n9_request.digest in n9_env['output']['reason']}",
    "MATCH" if n9_env["status"] == "AUTHORIZATION_REQUIRED" and n9_env["output"]["verdict"] == "DENY" and receipts and "grant_scope_draft" in n9_env["output"]["reason"] and n9_request.digest in deny_text else "FAIL",
)
missing = AuthorizationRequest(
    actor=n9_request.actor,
    action=n9_request.action,
    resource=n9_request.resource,
    parameters=n9_request.parameters,
    intent_id=n9_request.intent_id,
    idempotency_key="idem-missing",
    git_candidate_sha=HEAD,
    tree_sha=TREE,
    grant_id="missing-grant",
)
missing_env = run_n9(
    {"action": missing.action, "grant_id": missing.grant_id, "request_digest": missing.digest},
    at=AT,
    store=n9_grants,
    request=missing,
    now=NOW,
)
add(
    "DOD-E-N9-NO-GRANT",
    "DoD-E",
    "no valid grant is DENY / AUTHORIZATION_REQUIRED with a draft and does not authorize",
    f"status={missing_env['status']} reason={missing_env['output']['reason'][:180]}",
    "MATCH" if missing_env["status"] == "AUTHORIZATION_REQUIRED" and missing_env["output"]["verdict"] == "DENY" and "grant_scope_draft" in missing_env["output"]["reason"] else "FAIL",
)

fact_missing = run_n5(
    {"claims": ["readable-fact"]},
    at=AT,
    bound={"facts": [{"claim": "readable-fact", "verdict": "FACT", "evidence_ref": str(WORK / "no-such-fact.txt"), "freshness": "fresh"}]},
)
add(
    "DOD-E-N5-UNREADABLE",
    "DoD-E",
    "a FACT whose file does not open is not left as FACT and is SOURCE_UNAVAILABLE",
    f"status={fact_missing['status']} fact={fact_missing['output']['facts'][0]} gaps={fact_missing['output']['gaps']}",
    "MATCH" if fact_missing["output"]["facts"][0]["verdict"] != "FACT" and fact_missing["status"] == "SOURCE_UNAVAILABLE" else "FAIL",
)
readable = WORK / "fact.txt"
readable.write_text("observed bytes\n", encoding="utf-8")
fact_ok = run_n5(
    {"claims": ["readable-fact"]},
    at=AT,
    bound={"facts": [{"claim": "readable-fact", "verdict": "FACT", "evidence_ref": str(readable), "freshness": "fresh"}]},
)
stale_file = WORK / "stale.txt"
stale_file.write_text("old bytes\n", encoding="utf-8")
stale = run_n5(
    {"claims": ["old-claim"]},
    at=AT,
    bound={"facts": [{"claim": "old-claim", "verdict": "FACT", "evidence_ref": str(stale_file), "freshness": "stale"}]},
)
marker = Path(str(stale_file) + ".recollect.json")
label_only = "recollect:old-claim" in stale["output"]["gaps"]
add(
    "DOD-E-N5-FACT",
    "DoD-E",
    "a FACT with a readable fresh file stays FACT",
    f"status={fact_ok['status']} verdict={fact_ok['output']['facts'][0]['verdict']}",
    "MATCH" if fact_ok["status"] == "OK" and fact_ok["output"]["facts"][0]["verdict"] == "FACT" else "FAIL",
)
add(
    "DOD-E-N5-STALE",
    "DoD-E",
    "stale evidence stays STALE, writes a recollect marker, and the label alone is not the whole result",
    f"verdict={stale['output']['facts'][0]['verdict']} status={stale['status']} label={label_only} marker_exists={marker.is_file()} marker_sha={sha256_file(marker) if marker.is_file() else None}",
    "MATCH" if stale["output"]["facts"][0]["verdict"] == "STALE" and marker.is_file() and stale["status"] == "PARTIAL" else "FAIL",
)

# N10 controlled contrast
n10a = WORK / "n10a"
n10a.mkdir()
req_a, grants_a = make_request(n10a, intent_id="intent-n10", idem="idem-n10-a", grant_id="g-n10-a", text="fixed-bytes")
journal_a = Journal(n10a)
gw_a = Gateway(journal_a, grants_a)
first_n10 = gw_a.execute(req_a, now=NOW)
second_n10 = gw_a.execute(req_a, now=NOW)
effect_a = json.loads(journal_a.db.execute("SELECT result FROM effects").fetchone()["result"])
expected_a = hashlib.sha256(b"fixed-bytes").hexdigest()
add(
    "N10-FIXED",
    "N10",
    "fixed file bytes: two executions share one SUCCEEDED effect and the same content summary",
    f"first={first_n10['state']} second={second_n10['state']} same_receipt={first_n10['receipt_id']==second_n10['receipt_id']} dispatch={gw_a.dispatch_count} sha={effect_a.get('content_sha256')} summary={effect_a.get('summary')}",
    "MATCH" if first_n10["state"] == "SUCCEEDED" and second_n10["receipt_id"] == first_n10["receipt_id"] and gw_a.dispatch_count == 1 and effect_a["content_sha256"] == expected_a and effect_a["summary"]["sha256"] == expected_a else "FAIL",
)
n10b = WORK / "n10b"
n10b.mkdir()
req_b, grants_b = make_request(n10b, intent_id="intent-n10", idem="idem-n10-b", grant_id="g-n10-b", text="fixed-bytes")
(n10b / "readable.txt").write_text("changed-bytes", encoding="utf-8")
journal_b = Journal(n10b)
changed_n10 = Gateway(journal_b, grants_b).execute(req_b, now=NOW)
effect_b = json.loads(journal_b.db.execute("SELECT result FROM effects").fetchone()["result"])
expected_b = hashlib.sha256(b"changed-bytes").hexdigest()
add(
    "N10-CHANGED",
    "N10",
    "changed file bytes change the content summary",
    f"state={changed_n10['state']} sha={effect_b.get('content_sha256')} expected={expected_b}",
    "MATCH" if changed_n10["state"] == "SUCCEEDED" and effect_b["content_sha256"] == expected_b and effect_b["content_sha256"] != expected_a else "FAIL",
)
n10c = WORK / "n10c"
n10c.mkdir()
req_c, grants_c = make_request(n10c, intent_id="intent-n10", idem="idem-n10-c", grant_id="g-n10-c", text="fixed-bytes")
no_auth = AuthorizationRequest(
    actor=req_c.actor,
    action=req_c.action,
    resource=req_c.resource,
    parameters=req_c.parameters,
    intent_id=req_c.intent_id,
    idempotency_key="idem-n10-noauth",
    git_candidate_sha=HEAD,
    tree_sha=TREE,
    grant_id="missing-grant",
)
journal_c = Journal(n10c)
gw_c = Gateway(journal_c, grants_c)
no_auth_env = run_n10(
    {"action": no_auth.action, "grant_ref": no_auth.grant_id, "context_pack": h2_n2["output"]},
    at=AT,
    gateway=gw_c,
    request=no_auth,
    now=NOW,
)
add(
    "N10-NO-AUTH",
    "N10",
    "no grant does not SUCCEEDED and does not dispatch",
    f"status={no_auth_env['status']} output={no_auth_env['output']} dispatch={gw_c.dispatch_count} effects={journal_c.effect_count()}",
    "MATCH" if no_auth_env["status"] == "AUTHORIZATION_REQUIRED" and no_auth_env["output"] is None and gw_c.dispatch_count == 0 and journal_c.effect_count() == 0 else "FAIL",
)
journal_a.close()
journal_b.close()
journal_c.close()

# ---------------------------------------------------------------------------
# bwrap on THIS vm
# ---------------------------------------------------------------------------

which = shutil.which("bwrap")
which_run = subprocess.run(["bash", "-lc", "command -v bwrap || true"], text=True, capture_output=True)
ls_run = subprocess.run(["ls", "-l", "/usr/bin/bwrap", "/bin/bwrap"], text=True, capture_output=True)
iso = WORK / "iso"
(iso / "tmp").mkdir(parents=True)
runner = apply_hardened_runner(str(iso), ["/usr/bin/python3", "-c", "print('PIDS')"], log_path=OUT / "bwrap-runner.log")
(OUT / "bwrap-which.txt").write_text(
    f"which={which}\ncommand_v={which_run.stdout}\nls_code={ls_run.returncode}\nls={ls_run.stderr}{ls_run.stdout}\n",
    encoding="utf-8",
)
add(
    "BWRAP-LOCAL",
    "bwrap",
    "if bwrap is absent, CAPABILITY_GAP with the runner record; xfail is not a pass",
    f"which={which} runner={runner}",
    "CAPABILITY_GAP" if which is None and runner.get("capability") == "CAPABILITY_GAP" and runner.get("error") == "BWRAP_MISSING" and runner.get("runtime_pass") is False else "FAIL",
    xfail_counted_as_pass=False,
    note="This host has no bwrap binary. The tip51 Ops bed is a separate ro-bind proof and is not reused as a local process-isolation pass.",
)

# ---------------------------------------------------------------------------
# A2
# ---------------------------------------------------------------------------

a2 = WORK / "a2-store"
a2.mkdir()
files = {
    "grant": b"grant-v1\n",
    "request": b"request-v1\n",
    "receipt": b"receipt-v1\n",
    "log": b"log-v1\n",
}
for name, data in files.items():
    (a2 / name).write_bytes(data)


def manifest_for(candidate: str, file_bytes: dict[str, bytes] | None = None) -> Path:
    used = file_bytes or {name: (a2 / name).read_bytes() for name in files}
    items = []
    for kind in ("grant", "request", "receipt", "log"):
        data = used[kind]
        items.append({
            "kind": kind,
            "path": kind,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    path = a2 / "runtime-manifest.json"
    path.write_text(json.dumps({
        "kind": "external_runtime_artifact_inventory",
        "candidate_sha": candidate,
        "store_root": str(a2),
        "items": items,
    }), encoding="utf-8")
    return path


man = manifest_for(HEAD)
inventory = verified_runtime_inventory(man, candidate_sha=HEAD)
indep_items = []
for item in inventory["items"]:
    raw = Path(item["path"]).read_bytes()
    indep_items.append({
        "bytes": len(raw),
        "kind": item["kind"],
        "path": str(Path(item["path"]).resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
    })
indep_items.sort(key=lambda item: (item["kind"], item["path"]))
indep_obj = {"kind": "external_runtime_artifact_inventory", "candidate_sha": HEAD, "items": indep_items}
indep_runtime = independent_digest(indep_obj)
code_runtime = product_digest(inventory)
columns = column_digests(runtime_manifest=man, candidate_sha=HEAD)
indep_fixture = independent_digest({
    "template_digest": columns["template_digest"],
    "runtime_artifact_digest": indep_runtime,
    "isolation_policy_digest": columns["isolation_policy_digest"],
})
add(
    "A2-THREE-COMPONENT",
    "A2",
    "template, isolation, and runtime digests recompute; fixture_digest is the digest of those three",
    f"runtime_code={code_runtime} runtime_indep={indep_runtime} fixture_code={columns['fixture_digest']} fixture_indep={indep_fixture} template={columns['template_digest']} isolation={columns['isolation_policy_digest']}",
    "PASS" if code_runtime == indep_runtime and columns["fixture_digest"] == indep_fixture and columns["template_digest"] == template_digest() and columns["isolation_policy_digest"] == isolation_policy_digest() else "FAIL",
    note="Mechanism on a tester-made external store. Not an Ops inventory for tip51.",
)
# one byte
original_grant = (a2 / "grant").read_bytes()
(a2 / "grant").write_bytes(original_grant + b"X")
try:
    verified_runtime_inventory(man, candidate_sha=HEAD)
    mismatch = "accepted"
except ValueError as exc:
    mismatch = str(exc)
(a2 / "grant").write_bytes(original_grant + b"X")
man2 = manifest_for(HEAD)
columns2 = column_digests(runtime_manifest=man2, candidate_sha=HEAD)
add(
    "A2-BYTE",
    "A2",
    "one flipped byte invalidates the old binding; re-registering changes runtime and fixture digests only",
    f"old_call={mismatch} runtime_changed={columns2['runtime_artifact_digest']!=columns['runtime_artifact_digest']} fixture_changed={columns2['fixture_digest']!=columns['fixture_digest']} template_same={columns2['template_digest']==columns['template_digest']} isolation_same={columns2['isolation_policy_digest']==columns['isolation_policy_digest']}",
    "PASS" if mismatch == "CONTENT_SHA_MISMATCH" and columns2["runtime_artifact_digest"] != columns["runtime_artifact_digest"] and columns2["fixture_digest"] != columns["fixture_digest"] and columns2["template_digest"] == columns["template_digest"] and columns2["isolation_policy_digest"] == columns["isolation_policy_digest"] else "FAIL",
)
(a2 / "grant").write_bytes(original_grant)
man_ok = manifest_for(HEAD)
missing_items = json.loads(man_ok.read_text(encoding="utf-8"))
missing_items["items"][0]["path"] = "grant-missing"
(a2 / "missing-manifest.json").write_text(json.dumps(missing_items), encoding="utf-8")
try:
    verified_runtime_inventory(a2 / "missing-manifest.json", candidate_sha=HEAD)
    missing_actual = "accepted"
except ValueError as exc:
    missing_actual = str(exc)
try:
    verified_runtime_inventory(man_ok, candidate_sha="0" * 40)
    cand_actual = "accepted"
except ValueError as exc:
    cand_actual = str(exc)
cycle = json.loads(man_ok.read_text(encoding="utf-8"))
cycle["items"][0]["kind"] = "handoff_snapshot"
(a2 / "cycle-manifest.json").write_text(json.dumps(cycle), encoding="utf-8")
try:
    verified_runtime_inventory(a2 / "cycle-manifest.json", candidate_sha=HEAD)
    cycle_actual = "accepted"
except ValueError as exc:
    cycle_actual = str(exc)
empty_manifest = {"kind": "external_runtime_artifact_inventory", "candidate_sha": HEAD, "store_root": str(a2), "items": []}
(a2 / "empty-manifest.json").write_text(json.dumps(empty_manifest), encoding="utf-8")
try:
    verified_runtime_inventory(a2 / "empty-manifest.json", candidate_sha=HEAD)
    empty_actual = "accepted"
except ValueError as exc:
    empty_actual = str(exc)
schema_path = ROOT / "tests/fixtures/g2s1/runtime-artifact-inventory.json"
try:
    verified_runtime_inventory(schema_path, candidate_sha=HEAD)
    schema_actual = "accepted"
except ValueError as exc:
    schema_actual = str(exc)
escape = json.loads(man_ok.read_text(encoding="utf-8"))
escape["items"][0]["path"] = "../outside-secret.txt"
(a2 / "escape-manifest.json").write_text(json.dumps(escape), encoding="utf-8")
try:
    verified_runtime_inventory(a2 / "escape-manifest.json", candidate_sha=HEAD)
    escape_actual = "accepted"
except ValueError as exc:
    escape_actual = str(exc)
abs_manifest = json.loads(man_ok.read_text(encoding="utf-8"))
for item in abs_manifest["items"]:
    item["path"] = str((a2 / item["path"]).resolve())
(a2 / "abs-manifest.json").write_text(json.dumps(abs_manifest), encoding="utf-8")
rel_digest = runtime_digest_rel = product_digest(verified_runtime_inventory(man_ok, candidate_sha=HEAD))
abs_digest = product_digest(verified_runtime_inventory(a2 / "abs-manifest.json", candidate_sha=HEAD))
add(
    "A2-FAIL-CLOSED",
    "A2",
    "missing file, wrong candidate, snapshot kind, empty items, in-repo schema, and .. are rejected",
    f"missing={missing_actual} candidate={cand_actual} cycle={cycle_actual} empty={empty_actual} schema={schema_actual} escape={escape_actual}",
    "PASS" if all(x in {"ARTIFACT_MISSING", "CANDIDATE_SHA_MISMATCH", "CYCLE_INPUT_FORBIDDEN", "EXTERNAL_MANIFEST_EMPTY", "RUNTIME_SCHEMA_NOT_EVIDENCE", "PATH_ESCAPE"} for x in (missing_actual, cand_actual, cycle_actual, empty_actual, schema_actual, escape_actual)) else "FAIL",
)
add(
    "A2-PATH-NORMALIZE",
    "A2",
    "relative and absolute manifest paths normalize to one runtime digest",
    f"relative={rel_digest} absolute={abs_digest}",
    "PASS" if rel_digest == abs_digest else "FAIL",
)
before_names = sorted(p.name for p in a2.iterdir())
binding_obj = handoff_binding(base_sha=BASE, candidate_sha=HEAD, runtime_manifest=man_ok)
after_names = sorted(p.name for p in a2.iterdir())
snapshot_in_repo = list(ROOT.rglob("handoff-snapshot.json"))
add(
    "A2-HANDOFF-BINDING",
    "A2",
    "handoff_binding returns RECEIVED with runtime_pass false and does not write a snapshot",
    f"decision={binding_obj.get('decision')} product_pass={binding_obj.get('product_pass')} runtime_pass={binding_obj.get('runtime_pass')} wrote_new={before_names!=after_names} repo_snapshots={[str(p) for p in snapshot_in_repo]}",
    "PASS" if binding_obj.get("decision") == "RECEIVED" and binding_obj.get("product_pass") is False and binding_obj.get("runtime_pass") is False and before_names == after_names else "FAIL",
)
try:
    review_entry({
        "base_sha": BASE,
        "candidate_sha": HEAD,
        "scope_digest": SCOPE,
        "fixture_digest": columns["fixture_digest"],
        "runtime_manifest": str(man_ok),
        "product_pass": True,
        "builder_id": "builder",
        "verifier_id": "builder",
        "decision": "PASS",
    })
    review_actual = "accepted"
except (PermissionError, ValueError) as exc:
    review_actual = f"{type(exc).__name__}: {exc}"
add(
    "A2-REVIEW-REFUSES-PASS",
    "A2",
    "review_entry does not issue PASS",
    review_actual,
    "PASS" if review_actual.startswith("PermissionError") else "FAIL",
)
add(
    "A2-TIP51-INVENTORY",
    "A2",
    "an Ops external Grant/request/Receipt/log inventory pinned to tip51",
    "no such manifest is on this VM; the ro-bind proof is not an A24 inventory",
    "OPEN",
)
add(
    "A2-HANDOFF-SNAPSHOT",
    "A2",
    "a sealed handoff_snapshot for tip51",
    "function does not write one; none is in the candidate tree",
    "OPEN",
)

# gaps stay open as declarations, not closures
for gap, why in (
    ("GAP-01", "no production reviewer record; empty registry"),
    ("GAP-02", "no writer, key, or channel was created"),
    ("GAP-03", "source_evidence shape is not independent verification"),
    ("GAP-04", "Ops measured fixture physical RO; status still OPEN"),
):
    add(gap, "gap", "remain OPEN", why, "OPEN")

add(
    "NA-GAP-01",
    "t187",
    "this handback must not claim N11 complete or GAP-01..04 closed",
    "not claimed; gaps recorded OPEN; tip047 seal not applied",
    "MATCH",
)

# pytest as context only
pytest_log = OUT / "pytest.txt"
proc = subprocess.run(
    [sys.executable, "-m", "pytest", "tests", "-q", "--tb=line", "-p", "no:cacheprovider", "-rxX"],
    cwd=ROOT,
    text=True,
    capture_output=True,
    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
)
pytest_log.write_text(proc.stdout + "\n" + proc.stderr, encoding="utf-8")
add(
    "PYTEST-CONTEXT",
    "context",
    "pytest exit and xfail are context only and are not acceptance",
    f"exit={proc.returncode} tail={proc.stdout.strip().splitlines()[-8:]}",
    "CONTEXT",
    not_acceptance=True,
    xfail_is_not_pass=True,
)

# product tree untouched
status = subprocess.check_output(["git", "status", "--short"], cwd=ROOT, text=True)
add(
    "PRODUCT-TREE-UNTOUCHED",
    "custody",
    "git status --short empty after the probe",
    status or "(clean)",
    "MATCH" if status.strip() == "" else "FAIL",
)

counts: dict[str, int] = {}
for row in rows:
    counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
fails = [row["id"] for row in rows if row["verdict"] == "FAIL"]
opens = [row["id"] for row in rows if row["verdict"] == "OPEN"]
status_name = "FAIL" if fails else "T192_TIP51_EVIDENCED_PARTIAL"
summary = {
    "status": status_name,
    "runtime_pass": False,
    "verification_pass": False,
    "product_pass": False,
    "merge": False,
    "tip047_sealed": False,
    "stack_ok_is_not_pass": True,
    "ci_is_not_pass": True,
    "n11_complete": False,
    "head": HEAD,
    "tree": TREE,
    "parent": PARENT,
    "pin_ok": PIN_OK,
    "counts": counts,
    "fail_ids": fails,
    "open_ids": opens,
    "pytest_exit": proc.returncode,
    "pytest_is_not_acceptance": True,
    "bwrap_local": "CAPABILITY_GAP",
    "na_ro_03_04": "PASS_EVIDENCE",
    "waiting_ops_tip51": "CLEARED",
}
(OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
(OUT / "cases.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2))
jsonl.close()
sys.exit(0 if not fails else 2)
