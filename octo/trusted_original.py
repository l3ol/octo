"""Read-only consumer for N11 trusted originals.

Spec SPEC-N11-TRUSTED-ORIGINAL-INTERFACE-v1
sha256 ``c9341bf7b3c149655de865953d03f46c19377e4a796e606590ae590adfc9bebf``.

The registry root (``OCTO_TRUSTED_ORIGINAL_ROOT``) sits outside the candidate
work tree and outside any writable isolation store. This module only reads it.
A candidate-supplied path, issuer, hash, or registration id is not a query key.

Relay, documented only. This module does not write it and does not sign:
original reviewer session collects the bytes, the registrar stores the SHA,
the record is copied to the box, and Ops publishes that directory read-only.
Writeback of a reviewer conclusion happens only when that original role
issues it. There is no new signing authority, no key, and no resident channel.

ENGINEERING_GAP (still open):
- GAP-01 the original reviewer session has not placed a production record.
- GAP-02 no existing control-plane writer or CopyToBox entry is wired here.
- GAP-03 agent id and session id are checked as two read-only constants.
  A separate proof channel is not defined and is not invented here.
- GAP-04 Ops still confirms the deployed root is read-only to the candidate.

Empty registry stays BLOCKED. A TEST_FIXTURE hit stays BLOCKED with
``TEST_FIXTURE_ONLY``. A later record in that root is consumed without
editing the trust predicate. ``runtime_pass`` stays false.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from octo.g3_review import product_scope_digest
from octo.objects import digest

TA_REVIEWER_ID = "agt_6ae61c44e54081918e81a0adea556ef8"
ORIGINAL_AGENT_ID = TA_REVIEWER_ID
ORIGINAL_REVIEWER_SESSION_ID = "6ae6216e-bbec-83e8-87dc-c3edd9027bcc"
ORIGINAL_SESSION_ID = ORIGINAL_REVIEWER_SESSION_ID
REGISTRY_ENV = "OCTO_TRUSTED_ORIGINAL_ROOT"
FIXTURE_DIGEST_ENV = "OCTO_FIXTURE_DIGEST"
CANDIDATE_ROOT = Path(__file__).resolve().parents[1]
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class BindingTuple:
    route: str
    scope_digest: str
    base_sha: str
    candidate_sha: str
    fixture_digest: str

    def as_dict(self) -> dict[str, str]:
        return {
            "route": self.route,
            "scope_digest": self.scope_digest,
            "base_sha": self.base_sha,
            "candidate_sha": self.candidate_sha,
            "fixture_digest": self.fixture_digest,
        }


@dataclass(frozen=True)
class Found:
    record: dict[str, Any]
    test_only: bool


@dataclass(frozen=True)
class Empty:
    reason: str


@dataclass(frozen=True)
class Rejected:
    reason_code: str


ConsumeResult = Found | Empty | Rejected


@dataclass(frozen=True)
class ReadOnlyRegistry:
    root: Path
    records: dict[str, dict[str, Any]]
    duplicate_ids: bool = False


def fixture_set_digest(fixture_hashes: set[str] | frozenset[str]) -> str:
    """Canonical digest of the fixture hash set. Review originals must stay out of it."""
    return digest(sorted(fixture_hashes))


def _hex_field(value: Any, length: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if len(text) != length or any(char not in _HEX for char in text):
        return None
    return text


def normalize_binding(raw: Mapping[str, Any] | BindingTuple | None) -> BindingTuple | None:
    """Five fields, exact after normalization. A short SHA or a missing field is not a tuple."""
    if isinstance(raw, BindingTuple):
        raw = raw.as_dict()
    if not isinstance(raw, Mapping):
        return None
    route = raw.get("route")
    if not isinstance(route, str) or not route.strip():
        return None
    scope_digest = _hex_field(raw.get("scope_digest"), 64)
    base_sha = _hex_field(raw.get("base_sha"), 40)
    candidate_sha = _hex_field(raw.get("candidate_sha"), 40)
    fixture_digest = _hex_field(raw.get("fixture_digest"), 64)
    if None in (scope_digest, base_sha, candidate_sha, fixture_digest):
        return None
    return BindingTuple(route.strip(), scope_digest, base_sha, candidate_sha, fixture_digest)


def runner_base_sha() -> str | None:
    """Base commit from git. Not a value read off a candidate receipt."""
    import subprocess
    try:
        sha = subprocess.check_output(
            ["git", "merge-base", "HEAD", "origin/main"],
            cwd=CANDIDATE_ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip().lower()
    except (OSError, subprocess.CalledProcessError):
        return None
    return sha if _hex_field(sha, 40) else None


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def root_block(root: Path | None, *, store_root: Path | None = None) -> str | None:
    """Unconfigured, missing, inside the candidate or a writable store, or writable."""
    if root is None or root.is_symlink():
        return "ROOT_UNAVAILABLE"
    if not root.exists() or not root.is_dir():
        return "ROOT_UNAVAILABLE"
    resolved = root.resolve()
    candidate = CANDIDATE_ROOT.resolve()
    if _inside(resolved, candidate):
        return "ROOT_UNAVAILABLE"
    if store_root is not None:
        store = Path(store_root).resolve()
        if _inside(resolved, store) or _inside(store, resolved):
            return "ROOT_UNAVAILABLE"
    if os.access(resolved, os.W_OK):
        return "ROOT_UNAVAILABLE"
    return None


def _read_confined(root: Path, ref: Any) -> bytes | str:
    if not isinstance(ref, str) or not ref or ref.startswith(("/", "\\")):
        return "PATH_ESCAPE"
    parts = Path(ref).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return "PATH_ESCAPE"
    current = root.resolve()
    for part in parts:
        current = current / part
        if current.is_symlink():
            return "PATH_ESCAPE"
    if current.is_symlink() or not current.is_file():
        return "PATH_ESCAPE"
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(current, flags)
    except OSError:
        return "PATH_ESCAPE"
    try:
        chunks = []
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(fd)
    return b"".join(chunks)


def open_registry(root: Path | None, *, store_root: Path | None = None) -> ReadOnlyRegistry | Empty:
    blocked = root_block(root, store_root=store_root)
    if blocked:
        return Empty(blocked)
    assert root is not None
    index = root / "registry.json"
    if not index.exists() and not index.is_symlink():
        return ReadOnlyRegistry(root=root.resolve(), records={})
    payload = _read_confined(root, "registry.json")
    if isinstance(payload, str):
        return Empty("PATH_ESCAPE")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return Empty("ROOT_UNAVAILABLE")
    rows = document.get("records") if isinstance(document, dict) else None
    if not isinstance(rows, list):
        return Empty("ROOT_UNAVAILABLE")
    records: dict[str, dict[str, Any]] = {}
    duplicate = False
    for row in rows:
        if not isinstance(row, dict):
            return Empty("ROOT_UNAVAILABLE")
        registration_id = row.get("registration_id")
        if not isinstance(registration_id, str) or not registration_id:
            return Empty("ROOT_UNAVAILABLE")
        if registration_id in records:
            duplicate = True
        records[registration_id] = row
    return ReadOnlyRegistry(root=root.resolve(), records=records, duplicate_ids=duplicate)


def registry_index_review(source: str) -> str | None:
    """Static check. A bare ``read_text`` on the index is not confined IO."""
    if "read_text" in source:
        return "REGISTRY_INDEX_UNCONFINED"
    return None


_RO_BIND_METHODS = frozenset({"bwrap-ro-bind", "mount-ro", "ro-bind"})
_RO_BIND_ERRNOS = frozenset({"EROFS", "EACCES", "EPERM"})
_RO_BIND_OPS = frozenset({"open", "replace", "unlink", "rename"})


def ro_bind_assessment(proof: Mapping[str, Any] | None) -> str:
    """Assess a read-only mount proof. This does not issue trust or PASS.

    chmod and ``os.access`` stay ``RO_BIND_UNPROVEN``. A complete mount proof
    is ``RO_BIND_PROVEN`` as an assessment only. GAP-04 stays open until Ops
    records that proof on the real root. GAP-03 stays open: a proven mount
    does not verify a reviewer original.
    """
    if not isinstance(proof, dict):
        return "RO_BIND_UNPROVEN"
    method = proof.get("method")
    if method in {None, "chmod", "os.access"} or method not in _RO_BIND_METHODS:
        return "RO_BIND_UNPROVEN"
    operations = proof.get("operations")
    if not isinstance(operations, list):
        return "RO_BIND_UNPROVEN"
    seen: set[str] = set()
    for operation in operations:
        if not isinstance(operation, dict) or operation.get("exception") != "OSError":
            return "RO_BIND_UNPROVEN"
        errno_name = operation.get("errno") or operation.get("errno_name")
        if errno_name not in _RO_BIND_ERRNOS:
            return "RO_BIND_UNPROVEN"
        name = operation.get("op")
        if name not in _RO_BIND_OPS:
            return "RO_BIND_UNPROVEN"
        seen.add(name)
    if seen != _RO_BIND_OPS:
        return "RO_BIND_UNPROVEN"
    return "RO_BIND_PROVEN"


def _evidence_ok(record: Mapping[str, Any]) -> str | None:
    """Check the agent and the session against two different constants.

    A non-empty ``relay_proof`` is shape only. It is not independent source
    verification. GAP-03 stays open.
    """
    evidence = record.get("source_evidence")
    issuer = record.get("issuer_id")
    if not isinstance(evidence, dict):
        return "EVIDENCE_UNVERIFIED"
    transfer = evidence.get("transfer_receipt_id")
    session = evidence.get("issuer_session_id")
    agent = evidence.get("issuer_agent_id")
    proof = evidence.get("relay_proof")
    if not all(isinstance(item, str) and item.strip() for item in (transfer, proof)):
        return "EVIDENCE_UNVERIFIED"
    if not isinstance(issuer, str) or not isinstance(agent, str) or not isinstance(session, str):
        return "EVIDENCE_UNVERIFIED"
    if issuer != ORIGINAL_AGENT_ID or agent != ORIGINAL_AGENT_ID:
        return "ISSUER_MISMATCH"
    if session == issuer or session == TA_REVIEWER_ID or session.startswith("agt_"):
        return "ISSUER_SESSION_COLLISION"
    if session != ORIGINAL_SESSION_ID:
        return "ISSUER_MISMATCH"
    return None


def _kind_ok(record: Mapping[str, Any]) -> bool:
    kind = record.get("content_kind")
    test_only = record.get("test_only")
    if kind == "TEST_FIXTURE":
        return test_only is True
    if kind == "REVIEW_RECEIPT":
        return test_only is False
    return False


def consume_trusted_original(
    binding_tuple: BindingTuple | Mapping[str, Any] | None,
    registry_view: ReadOnlyRegistry | None,
    fixture_hashes: set[str] | frozenset[str] | None = None,
) -> ConsumeResult:
    """Look up one original by the runner tuple. Candidate keys are not consulted."""
    if not isinstance(registry_view, ReadOnlyRegistry):
        return Empty("ROOT_UNAVAILABLE")
    if registry_view.duplicate_ids:
        return Rejected("AMBIGUOUS")
    if not registry_view.records:
        return Empty("EMPTY_REGISTRY")
    query = normalize_binding(binding_tuple)
    if query is None or query.scope_digest != product_scope_digest():
        return Rejected("TUPLE_MISMATCH")
    matches = []
    for record in registry_view.records.values():
        recorded = normalize_binding(record.get("binding_tuple") if isinstance(record, dict) else None)
        if recorded == query:
            matches.append(record)
    if not matches:
        return Rejected("TUPLE_MISMATCH")
    if len(matches) > 1:
        return Rejected("AMBIGUOUS")
    record = matches[0]
    if not _kind_ok(record):
        return Rejected("EVIDENCE_UNVERIFIED")
    evidence_gap = _evidence_ok(record)
    if evidence_gap:
        return Rejected(evidence_gap)
    if record.get("content_kind") == "REVIEW_RECEIPT":
        return Rejected("EVIDENCE_UNVERIFIED")
    payload = _read_confined(registry_view.root, record.get("raw_bytes_ref"))
    if isinstance(payload, str):
        return Rejected(payload)
    actual = hashlib.sha256(payload).hexdigest()
    expected = _hex_field(record.get("bytes_sha256"), 64)
    if expected is None or actual != expected:
        return Rejected("HASH_MISMATCH")
    hashes = set(fixture_hashes or ())
    proof = record.get("excluded_fixture_hashes_proof")
    if not isinstance(proof, dict) or proof.get("checked") is not True:
        return Rejected("EVIDENCE_UNVERIFIED")
    if proof.get("fixture_set_digest") != fixture_set_digest(hashes):
        return Rejected("EVIDENCE_UNVERIFIED")
    if actual in hashes or actual == query.fixture_digest:
        return Rejected("FIXTURE_LOOP")
    return Found(record=dict(record), test_only=record.get("test_only") is True)
