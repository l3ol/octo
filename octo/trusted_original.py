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
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
from typing import Any, Mapping

from octo.g3_review import product_scope_digest
from octo.objects import digest
from octo.scope_metadata import FORMAL_REVIEWER_ID, HISTORICAL_AGENT_ID

# Historical ids. They are not the acceptance identity. The current issuer
# comes from current_appointment(). This module does not sign for the
# historical agent and does not claim that its signatures moved.
TA_REVIEWER_ID = FORMAL_REVIEWER_ID
ORIGINAL_AGENT_ID = FORMAL_REVIEWER_ID
ORIGINAL_REVIEWER_SESSION_ID = "6ae6216e-bbec-83e8-87dc-c3edd9027bcc"
REGISTRY_ENV = "OCTO_TRUSTED_ORIGINAL_ROOT"
ALLOWLIST_ENV = "OCTO_TRUST_ALLOWLIST"
CONTROL_PLANE_ENV = "OCTO_CONTROL_PLANE"
# Ops installs this root. This module only reads it and does not create it.
OPS_CONTROL_PLANE_ROOT = Path(
    "/home/box/octo-handoff/control-plane/ops-protected-g3-de6649-fenced-t497u-20261104"
)
OPS_CONTROL_PLANE_SHA256 = {
    "allowlist": "2f24e5d5a0a9e77646fd486f376b42a5a3427ecaf59c1e8be31933b9d7b1971e",
    "controlplane_pin": "dd810f620d0414bad3733d836decd953c8647c5af79bf8c8ae31db2317d7cd49",
    "registry": "77b95cdb49c74077b005256afe79ef3d0d88ee5f2ff1727fffa9cbbc79e700a5",
    "evidence_tar": "7c57ec20f0240a7ae0b866d9378bc5f38f5bf3f2ccf664d5e6cc0ed71f162688",
}
_CONSUME_LOCK = threading.Lock()
FIXTURE_DIGEST_ENV = "OCTO_FIXTURE_DIGEST"
# Historical label only. Not an acceptance fallback and not a const swap.
DEFAULT_EXPECTED_ISSUER = FORMAL_REVIEWER_ID
ALLOWLIST_RUN_LOG: list[dict[str, str]] = []
_CONSUMED_RECEIPTS: dict[str, set[str]] = {}
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
    mechanism_accept: bool = False


@dataclass(frozen=True)
class Empty:
    reason: str


@dataclass(frozen=True)
class Rejected:
    reason_code: str
    detail: str = ""


ConsumeResult = Found | Empty | Rejected


@dataclass(frozen=True)
class ReadOnlyRegistry:
    root: Path
    records: dict[str, dict[str, Any]]
    duplicate_ids: bool = False
    production: bool = True


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


def _is_sha256_hex(value: Any) -> bool:
    """Exactly 64 lowercase hex characters. No strip and no case fold."""
    return isinstance(value, str) and len(value) == 64 and all(char in _HEX for char in value)


def _agreed_nonempty_string(document: Mapping[str, Any], *keys: str) -> str | None:
    """Shared non-empty string for synonym keys. A present key must agree.

    A missing key is the unused synonym. No usable key, an empty value, or
    two different values yields None.
    """
    found: list[str] = []
    for key in keys:
        if key not in document:
            continue
        value = document.get(key)
        if not isinstance(value, str) or not value:
            return None
        found.append(value)
    if not found or any(item != found[0] for item in found):
        return None
    return found[0]


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


def read_stored_bytes(registry_view: ReadOnlyRegistry, ref: Any) -> bytes | None:
    """Read exact stored bytes. A rewritten projection is not this payload."""
    payload = _read_confined(registry_view.root, ref)
    if isinstance(payload, str):
        return None
    return payload


def read_stored_json(registry_view: ReadOnlyRegistry, ref: Any) -> dict | None:
    """Read one JSON object already stored in the registry. No new channel."""
    payload = _read_confined(registry_view.root, ref)
    if isinstance(payload, str):
        return None
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _consume_journal_dir(root: Path) -> Path:
    """Durable consume records beside the read-only root, never inside it.

    The Ops control-plane root stays read-only. This journal is not created
    under that root.
    """
    resolved = root.resolve()
    stamp = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()
    return resolved.parent / ".octo-receipt-consume" / stamp


def _consume_journal_path(root: Path, receipt_id: str) -> Path:
    name = hashlib.sha256(receipt_id.encode("utf-8")).hexdigest()
    return _consume_journal_dir(root) / name


def _journal_outside_root(root: Path, directory: Path) -> bool:
    resolved = root.resolve()
    place = directory.resolve()
    return place != resolved and resolved not in place.parents


def _consume_payload(receipt_id: str) -> bytes:
    return receipt_id.encode("utf-8") + b"\n"


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        view = view[written:]


def receipt_is_consumed(root: Path, receipt_id: str) -> bool:
    """True only for a final marker whose bytes are ``receipt_id`` plus newline.

    A temp name, an empty file, or a short write is not a consume.
    """
    if not isinstance(receipt_id, str) or not receipt_id:
        return False
    path = _consume_journal_path(root, receipt_id)
    if path.is_symlink() or not path.is_file():
        return False
    try:
        data = path.read_bytes()
    except OSError:
        return False
    return data == _consume_payload(receipt_id)


def _durable_claim(root: Path, receipt_id: str) -> bool:
    """Claim once: temp file, full write, fsync, link, directory fsync.

    ``os.link`` does not replace an existing final marker. The only unlink
    is this call's own temp name. There is no discard of a final marker.
    """
    directory = _consume_journal_dir(root)
    if not _journal_outside_root(root, directory.parent.parent):
        return False
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    if not _journal_outside_root(root, directory):
        return False
    final = _consume_journal_path(root, receipt_id)
    tmp = directory / f".tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC
    fd: int | None = None
    try:
        fd = os.open(tmp, flags, 0o644)
        payload = _consume_payload(receipt_id)
        _write_all(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = None
        try:
            os.link(tmp, final)
        except FileExistsError:
            return False
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                return False
            return False
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return True
    except OSError:
        return False
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def commit_receipt_consume(registry_view: ReadOnlyRegistry, record: Mapping[str, Any]) -> bool:
    """Atomically claim one receipt on disk. False means it is already committed.

    The in-memory set is only a cache. A new process reads the journal.
    A failed verification must not call this. There is no discard.
    """
    receipt_id = record.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        return False
    key = str(registry_view.root)
    with _CONSUME_LOCK:
        seen = _CONSUMED_RECEIPTS.setdefault(key, set())
        if receipt_id in seen or receipt_is_consumed(registry_view.root, receipt_id):
            return False
        if not _durable_claim(registry_view.root, receipt_id):
            return False
        seen.add(receipt_id)
        return True


def load_trusted_raw(registry_view: ReadOnlyRegistry, record: Mapping[str, Any]) -> bytes | None:
    """Re-read the confined original. Metadata is not a substitute for these bytes."""
    payload = _read_confined(registry_view.root, record.get("raw_bytes_ref"))
    if isinstance(payload, str):
        return None
    expected = record.get("bytes_sha256")
    if not isinstance(expected, str) or hashlib.sha256(payload).hexdigest() != expected:
        return None
    return payload


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
    production = document.get("registry_class") != "TEST_FIXTURE"
    return ReadOnlyRegistry(
        root=root.resolve(),
        records=records,
        duplicate_ids=duplicate,
        production=production,
    )


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


def _read_external_bytes(path: Path) -> bytes | None:
    if path.is_symlink() or not path.is_file():
        return None
    if _inside(path.resolve(), CANDIDATE_ROOT.resolve()):
        return None
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        chunks = []
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_control_plane(path: Path | None = None) -> dict[str, str] | None:
    """Read-only registrar pins. A sha256 of the thread id is not an appointment original.

    The required content anchor is ``expected_service_response_sha256``
    (synonyms ``service_response_sha256`` and ``raw_service_response_sha256``).
    ``collector_receipt_sha256`` binds a separate receipt file when that file
    exists; a missing file is not by itself a failure. ``expected_original_sha256``,
    ``original_sha256``, and ``message_text_sha256`` are optional and are
    checked when present. ``collection_source`` and ``collected_at`` are
    required non-empty strings and are the collection authority. Writer may
    mint ``registration_id`` or ``registrar_operation_id`` for local tracking
    only. ``collector_receipt_id`` is not a pin and must not be invented.
    """
    if path is None:
        env = os.environ.get(CONTROL_PLANE_ENV)
        path = Path(env) if env else None
    if path is None:
        return None
    raw = _read_external_bytes(path)
    if raw is None:
        return None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    if document.get("kind") != "REGISTRAR_RELAY" or document.get("not_issuer") is not True:
        return None
    if document.get("current_reviewer_conclusion") is not True:
        return None
    # A synthetic registration cannot take the production pin path.
    # TEST_ONLY / TEST_FIXTURE stay blocked even when the mark is present.
    if document.get("synthetic") is True or document.get("fixture_class") in {"TEST_ONLY", "TEST_FIXTURE"}:
        return None
    thread_id = document.get("thread_id")
    appointment = document.get("appointment_original_digest")
    if not isinstance(thread_id, str) or not _is_sha256_hex(appointment):
        return None
    if appointment == hashlib.sha256(thread_id.encode("utf-8")).hexdigest():
        return None
    required = (
        "turn_id",
        "message_id",
        "base_sha",
        "candidate_sha",
        "scope_digest",
        "fixture_digest",
        "allowlist_sha256",
        "collection_source",
        "collected_at",
    )
    pins: dict[str, str] = {"thread_id": thread_id, "appointment_original_digest": appointment}
    for key in required:
        value = document.get(key)
        if not isinstance(value, str) or not value:
            return None
        pins[key] = value
    service_sha = _agreed_nonempty_string(
        document,
        "expected_service_response_sha256",
        "raw_service_response_sha256",
        "service_response_sha256",
    )
    if service_sha is None:
        return None
    pins["expected_service_response_sha256"] = service_sha
    pins["raw_service_response_sha256"] = service_sha
    pins["service_response_sha256"] = service_sha
    if "collector_receipt_sha256" in document:
        receipt_sha = _agreed_nonempty_string(document, "collector_receipt_sha256")
        if receipt_sha is None:
            return None
        pins["collector_receipt_sha256"] = receipt_sha
    original_keys = ("expected_original_sha256", "original_sha256", "message_text_sha256")
    if any(key in document for key in original_keys):
        original_sha = _agreed_nonempty_string(document, *original_keys)
        if original_sha is None:
            return None
        pins["expected_original_sha256"] = original_sha
        pins["original_sha256"] = original_sha
        pins["message_text_sha256"] = original_sha
    return pins


def ops_control_plane_status(root: Path | None = None) -> str:
    """Read-only check of the Ops pin directory. ABSENT, MATCH, or MISMATCH.

    This does not create, write, or replace the directory or any file in it.
    """
    target = OPS_CONTROL_PLANE_ROOT if root is None else root
    if target.is_symlink() or not target.exists() or not target.is_dir():
        return "ABSENT"
    found: set[str] = set()
    for path in target.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        found.add(digest)
    if set(OPS_CONTROL_PLANE_SHA256.values()) <= found:
        return "MATCH"
    return "MISMATCH"


def load_allowlists(path: Path | None = None) -> tuple[dict[str, list[str]], str] | None:
    """Load the external issuer and source lists. Missing config does not fall back."""
    if path is None:
        env = os.environ.get(ALLOWLIST_ENV)
        path = Path(env) if env else None
    if path is None:
        return None
    raw = _read_external_bytes(path)
    if raw is None:
        return None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    issuers = document.get("issuer_allowlist") if isinstance(document, dict) else None
    sources = document.get("source_allowlist") if isinstance(document, dict) else None
    if not isinstance(issuers, list) or not isinstance(sources, list):
        return None
    if not all(isinstance(item, str) and item for item in issuers + sources):
        return None
    sha = hashlib.sha256(raw).hexdigest()
    ALLOWLIST_RUN_LOG.append({"path": str(path), "sha256": sha})
    return {"issuer_allowlist": issuers, "source_allowlist": sources}, sha


_APPOINTMENT_ORIGINAL_NAME = "appointment-original.bin"


def _nonempty_str(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _str_list(value: Any) -> list[str] | None:
    if not isinstance(value, list) or not value:
        return None
    if not all(isinstance(item, str) and item for item in value):
        return None
    return list(value)


def current_appointment() -> dict[str, Any] | None:
    """Read the Ops-protected appointment pin. Callers cannot select the path.

    Missing pin, fields, or appointment bytes fail closed. The returned
    ``appointment_raw_sha256`` is sha256 of those protected bytes.
    """
    env = os.environ.get(CONTROL_PLANE_ENV)
    if not env:
        return None
    path = Path(env)
    raw = _read_external_bytes(path)
    if raw is None:
        return None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    if document.get("kind") != "REGISTRAR_RELAY" or document.get("not_issuer") is not True:
        return None
    if document.get("current_reviewer_conclusion") is not True:
        return None
    if document.get("synthetic") is True or document.get("fixture_class") in {"TEST_ONLY", "TEST_FIXTURE"}:
        return None
    issuer_id = _nonempty_str(document.get("issuer_id"))
    session_id = _nonempty_str(document.get("issuer_session_id"))
    thread_id = _nonempty_str(document.get("thread_id"))
    turn_id = _nonempty_str(document.get("turn_id"))
    message_id = _nonempty_str(document.get("message_id"))
    issuers = _str_list(document.get("issuer_allowlist"))
    sources = _str_list(document.get("source_allowlist"))
    if None in (issuer_id, session_id, thread_id, turn_id, message_id, issuers, sources):
        return None
    assert issuer_id is not None and session_id is not None and thread_id is not None
    assert turn_id is not None and message_id is not None and issuers is not None and sources is not None
    if issuer_id not in issuers or session_id not in sources:
        return None
    original = _read_external_bytes(path.parent / _APPOINTMENT_ORIGINAL_NAME)
    if original is None:
        return None
    recomputed = hashlib.sha256(original).hexdigest()
    if recomputed == hashlib.sha256(thread_id.encode("utf-8")).hexdigest():
        return None
    claimed_raw = document.get("appointment_raw_sha256")
    claimed_digest = document.get("appointment_original_digest")
    if claimed_raw is None and claimed_digest is None:
        return None
    if claimed_raw is not None and claimed_raw != recomputed:
        return None
    if claimed_digest is not None and claimed_digest != recomputed:
        return None
    return {
        "issuer_id": issuer_id,
        "issuer_session_id": session_id,
        "thread_id": thread_id,
        "appointment_raw_sha256": recomputed,
        "turn_id": turn_id,
        "message_id": message_id,
        "issuer_allowlist": issuers,
        "source_allowlist": sources,
    }


def migration_claimed(record: Mapping[str, Any]) -> bool:
    """A claim that an old signature moved, or that this code signed for that agent."""
    blobs: list[Mapping[str, Any]] = [record]
    evidence = record.get("source_evidence")
    if isinstance(evidence, Mapping):
        blobs.append(evidence)
    for blob in blobs:
        if blob.get("signature_migration_claimed") is True:
            return True
        if blob.get("signed_on_behalf_of") or blob.get("migrated_from_agent"):
            return True
    return False


def _review_allowlist(record: Mapping[str, Any], allowlists: Mapping[str, list[str]]) -> str | None:
    """Issuer and source are different lists. An agent id in the session field collides.

    The external allowlist stays a separate rule-config check. It does not
    turn the historical agent id into the current formal reviewer.
    """
    evidence = record.get("source_evidence")
    issuer = record.get("issuer_id")
    if not isinstance(evidence, dict) or not isinstance(issuer, str):
        return "EVIDENCE_UNVERIFIED"
    session = evidence.get("issuer_session_id")
    agent = evidence.get("issuer_agent_id")
    if not isinstance(session, str):
        return "EVIDENCE_UNVERIFIED"
    if session == issuer or session == HISTORICAL_AGENT_ID or session.startswith("agt_"):
        return "ISSUER_SESSION_COLLISION"
    if issuer == HISTORICAL_AGENT_ID or agent == HISTORICAL_AGENT_ID:
        return "ISSUER_MISMATCH"
    if issuer in {"TB", "BUILDER", "DEVSPACE_VERIFIER"} or agent in {"TB", "BUILDER", "DEVSPACE_VERIFIER"}:
        return "ISSUER_MISMATCH"
    appointment = current_appointment()
    if appointment is None:
        return "EVIDENCE_UNVERIFIED"
    if issuer != appointment["issuer_id"] or issuer not in appointment["issuer_allowlist"]:
        return "ISSUER_MISMATCH"
    if isinstance(agent, str) and (agent != appointment["issuer_id"] or agent not in appointment["issuer_allowlist"]):
        return "ISSUER_MISMATCH"
    if session != appointment["issuer_session_id"] or session not in appointment["source_allowlist"]:
        return "ISSUER_MISMATCH"
    thread_id = evidence.get("thread_id")
    if isinstance(thread_id, str) and thread_id != appointment["thread_id"]:
        return "THREAD_MISMATCH"
    issuers = set(allowlists.get("issuer_allowlist") or [])
    sources = set(allowlists.get("source_allowlist") or [])
    if issuer not in issuers:
        return "ISSUER_MISMATCH"
    if isinstance(agent, str) and agent not in issuers:
        return "ISSUER_MISMATCH"
    if session not in sources:
        return "ISSUER_MISMATCH"
    return None


def _gap03_readonly(root: Path, record: Mapping[str, Any], actual_sha: str) -> bool | None:
    """Read-only check of an existing one-shot custody artifact.

    None means the channel is not connected. A custody file is not an issuer
    and cannot carry a verdict. GAP-03 stays open when this returns None.
    """
    ref = record.get("custody_ref")
    if not isinstance(ref, str) or not ref:
        return None
    payload = _read_confined(root, ref)
    if isinstance(payload, str):
        return False
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(document, dict):
        return False
    if document.get("issuer") or document.get("verdict") or document.get("signed_by"):
        return False
    return document.get("raw_sha256") == actual_sha and document.get("not_issuer") is True


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
    if issuer in {"TB", "BUILDER", "DEVSPACE_VERIFIER"} or agent in {"TB", "BUILDER", "DEVSPACE_VERIFIER"}:
        return "ISSUER_MISMATCH"
    appointment = current_appointment()
    if appointment is None:
        return "EVIDENCE_UNVERIFIED"
    if issuer != appointment["issuer_id"] or agent != appointment["issuer_id"]:
        return "ISSUER_MISMATCH"
    if issuer not in appointment["issuer_allowlist"] or agent not in appointment["issuer_allowlist"]:
        return "ISSUER_MISMATCH"
    if session == issuer or session == HISTORICAL_AGENT_ID or session.startswith("agt_"):
        return "ISSUER_SESSION_COLLISION"
    if session != appointment["issuer_session_id"] or session not in appointment["source_allowlist"]:
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
    *,
    allowlist_path: Path | None = None,
) -> ConsumeResult:
    """Look up one original by the runner tuple. Candidate keys are not consulted."""
    if not isinstance(registry_view, ReadOnlyRegistry):
        return Empty("ROOT_UNAVAILABLE")
    if registry_view.duplicate_ids:
        return Rejected("AMBIGUOUS")
    if not registry_view.records:
        return Empty("BLOCKED_WAITING_REAL_DATA")
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
    if registry_view.production and record.get("content_kind") == "TEST_FIXTURE":
        return Rejected("EVIDENCE_UNVERIFIED")
    if not _kind_ok(record):
        return Rejected("EVIDENCE_UNVERIFIED")
    if migration_claimed(record):
        return Rejected("SIGNATURE_MIGRATION_CLAIM")
    if record.get("content_kind") != "REVIEW_RECEIPT":
        evidence_gap = _evidence_ok(record)
        if evidence_gap:
            return Rejected(evidence_gap)
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
    if record.get("content_kind") != "REVIEW_RECEIPT":
        return Found(record=dict(record), test_only=True)
    return _review_decision(registry_view, record, query, actual, binding_tuple, allowlist_path)


def _review_decision(
    registry_view: ReadOnlyRegistry,
    record: Mapping[str, Any],
    query: BindingTuple,
    actual: str,
    binding_tuple: BindingTuple | Mapping[str, Any] | None,
    allowlist_path: Path | None,
) -> ConsumeResult:
    """Allowlisted review receipt. Unconnected GAP-03 stays unverified. Not PASS."""
    loaded = load_allowlists(allowlist_path)
    if loaded is None:
        return Rejected("SOURCE_UNAVAILABLE")
    allowlists, _sha = loaded
    gap = _review_allowlist(record, allowlists)
    if gap:
        return Rejected(gap)
    raw_binding = binding_tuple if isinstance(binding_tuple, Mapping) and not isinstance(binding_tuple, BindingTuple) else {}
    recorded = record.get("binding_tuple") if isinstance(record.get("binding_tuple"), Mapping) else {}
    # task/rule_version are an optional extension. A missing value must not
    # reject a compliant five-field tuple. Compare only when both sides carry one.
    for key in ("task", "rule_version"):
        recorded_value = recorded.get(key)
        runner_value = raw_binding.get(key)
        if not isinstance(recorded_value, str) or not recorded_value:
            continue
        if not isinstance(runner_value, str) or not runner_value:
            continue
        if recorded_value != runner_value:
            return Rejected("TUPLE_MISMATCH")
    receipt_id = record.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        return Rejected("EVIDENCE_UNVERIFIED")
    seen = _CONSUMED_RECEIPTS.setdefault(str(registry_view.root), set())
    if receipt_id in seen or receipt_is_consumed(registry_view.root, receipt_id):
        return Rejected("EVIDENCE_UNVERIFIED")
    verified = _gap03_readonly(registry_view.root, record, actual)
    if verified is not True:
        return Rejected("EVIDENCE_UNVERIFIED", "GAP-03")
    return Found(record=dict(record), test_only=False, mechanism_accept=True)
