"""N9 grant checks adapted from Mac ``octo/grant.py``.

Path confinement and the six boundary validators are kept. The founder CLI,
key minting, and a brain-directory default are not. In-repo material is the
static template only. Issued TEST_FIXTURE grants are written to an external
isolation store supplied by the caller.

``git_candidate_sha`` on a grant is 40 hex. It is not the legacy 64-hex
file-manifest digest.

Builder selftest support only. A TEST_FIXTURE grant is not a production Grant.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import uuid

from octo.candidate import git_candidate_sha, tree_sha
from octo.governor import POLICY, Denied
from octo.objects import canonical, digest, identifier, sha256, timestamp, utcnow

S1_GRANT_ACTIONS = frozenset({"internal_readonly"})
SIX_VALIDATORS = (
    "subject",
    "action",
    "resource",
    "amount",
    "time",
    "request_digest",
)
_BANNED_PARTS = {".git", ".gx", ".founder-key", "brain"}
_TTL = timedelta(hours=POLICY["default_ttl_hours"])


class GrantDenied(Denied):
    """One validator refusal. ``code`` is the stable reason on the DENY receipt."""

    def __init__(self, code: str, validator: str):
        super().__init__(code)
        self.code = code
        self.validator = validator


def inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def safe_path(path: Path, root: Path) -> Path:
    """Reject symlinks, traversal, and protected path parts."""
    root = root.resolve()
    absolute = Path(os.path.abspath(path))
    if not inside(absolute, root):
        raise Denied("RESOURCE_OUT_OF_SCOPE")
    relative = absolute.relative_to(root)
    if any(part in _BANNED_PARTS for part in relative.parts):
        raise Denied("PROTECTED_RESOURCE")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise Denied("SYMLINK_RESOURCE")
    if not inside(absolute.resolve(), root):
        raise Denied("RESOURCE_OUT_OF_SCOPE")
    return absolute


def write_once(path: Path, value: dict) -> None:
    """Exclusive creation. An existing record is never overwritten."""
    data = canonical(value) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def request_digest(fields: dict) -> str:
    """Digest of the intended action. The grant id is not part of it."""
    body = {
        "actor": fields["actor"],
        "action": fields["action"],
        "resource": fields["resource"],
        "parameters": json.loads(canonical(fields["parameters"])),
        "intent_id": fields["intent_id"],
        "idempotency_key": fields["idempotency_key"],
        "git_candidate_sha": fields["git_candidate_sha"],
        "tree_sha": fields["tree_sha"],
    }
    return digest(body)


@dataclass(frozen=True)
class AuthorizationRequest:
    actor: str
    action: str
    resource: str
    parameters: dict
    intent_id: str
    idempotency_key: str
    git_candidate_sha: str
    tree_sha: str
    grant_id: str | None = None

    def __post_init__(self) -> None:
        identifier(self.actor)
        identifier(self.intent_id)
        identifier(self.idempotency_key)
        git_candidate_sha(self.git_candidate_sha)
        tree_sha(self.tree_sha)
        if not isinstance(self.parameters, dict):
            raise ValueError("parameters must be an object")
        object.__setattr__(self, "parameters", json.loads(canonical(self.parameters)))

    @property
    def digest(self) -> str:
        return request_digest({
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "parameters": self.parameters,
            "intent_id": self.intent_id,
            "idempotency_key": self.idempotency_key,
            "git_candidate_sha": self.git_candidate_sha,
            "tree_sha": self.tree_sha,
        })


class GrantStore:
    """Isolation-store grants. There is no default brain path and no key file."""

    def __init__(self, root: Path, *, fixture_key: bytes):
        if not isinstance(fixture_key, bytes) or len(fixture_key) < 32:
            raise Denied("APPROVAL_KEY_UNAVAILABLE")
        self.root = Path(root).resolve()
        if any(part in _BANNED_PARTS for part in self.root.parts):
            raise Denied("PROTECTED_RESOURCE")
        self.fixture_key = fixture_key
        self.directory = self.root / "grants"
        self.receipts = self.root / "receipts"

    def issue_test_fixture(
        self,
        *,
        grant_id: str,
        subject: str,
        resource: str,
        request_digest_hex: str,
        git_candidate: str,
        tree: str,
        now: datetime,
        ttl_hours: float = 1,
        actions: list[str] | None = None,
        amount_limit: int = 0,
        extension_reason: str = "",
        revoked: bool = False,
        issued_via: str = "TEST_FIXTURE",
        test_only: bool = True,
    ) -> dict:
        """Write one TEST_FIXTURE grant outside the candidate tree."""
        identifier(grant_id)
        sha256(request_digest_hex)
        payload = {
            "grant_id": grant_id,
            "subject": subject,
            "actions": list(actions or ["internal_readonly"]),
            "action_type": "internal_readonly",
            "resources": [str(safe_path(Path(resource), self.root))],
            "request_digest": request_digest_hex,
            "git_candidate_sha": git_candidate_sha(git_candidate),
            "tree_sha": tree_sha(tree),
            "issued_via": issued_via,
            "test_only": test_only,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=ttl_hours)).isoformat(),
            "extension_reason": extension_reason,
            "amount_limit": amount_limit,
            "revoked": revoked,
        }
        self.directory.mkdir(parents=True, exist_ok=True)
        path = safe_path(self.directory / f"{grant_id}.json", self.root)
        write_once(path, {"grant": payload, "mac": self._mac(payload)})
        return payload

    def load(self, grant_id: str | None) -> dict:
        if not grant_id:
            raise GrantDenied("GRANT_REQUIRED", "grant_ref")
        identifier(grant_id)
        try:
            path = safe_path(self.directory / f"{grant_id}.json", self.root)
            value = json.loads(path.read_text(encoding="utf-8"))
            payload, signature = value["grant"], value["mac"]
            expected = self._mac(payload)
            if (not isinstance(signature, str) or not signature.isascii()
                    or not hmac.compare_digest(expected, signature)):
                raise GrantDenied("GRANT_SIGNATURE_INVALID", "signature")
            if payload.get("grant_id") != grant_id:
                raise GrantDenied("GRANT_INVALID", "signature")
            git_candidate_sha(payload["git_candidate_sha"])
            tree_sha(payload["tree_sha"])
            return payload
        except GrantDenied:
            raise
        except Denied as exc:
            raise GrantDenied(str(exc), "resource") from exc
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise GrantDenied("GRANT_FILE_INVALID_OR_MISSING", "signature") from exc

    def validate(self, grant_id: str | None, request: AuthorizationRequest, *, now: datetime | None = None) -> dict:
        grant = self.load(grant_id)
        self._check_issuance(grant)
        now = now or utcnow()
        self._check_subject(grant, request)
        self._check_action(grant, request)
        self._check_resource(grant, request)
        self._check_amount(grant)
        self._check_time(grant, now)
        self._check_digest(grant, request)
        return grant

    def write_receipt(self, *, decision: str, validator: str | None, reason: str, grant_id: str | None) -> dict:
        if decision not in {"DENY", "ALLOW"}:
            raise ValueError("receipt decision must be DENY or ALLOW")
        self.receipts.mkdir(parents=True, exist_ok=True)
        receipt_id = "R-" + uuid.uuid4().hex
        receipt = {
            "record_type": "Receipt",
            "receipt_id": receipt_id,
            "decision": decision,
            "validator": validator,
            "reason": reason,
            "grant_id": grant_id,
            "grant_ref": grant_id,
            "test_only": True,
            "issued_via": "TEST_FIXTURE",
            "action_type": "internal_readonly",
        }
        path = safe_path(self.receipts / f"{receipt_id}.json", self.root)
        write_once(path, receipt)
        return receipt

    def _mac(self, payload: dict) -> str:
        return hmac.new(self.fixture_key, canonical(payload), hashlib.sha256).hexdigest()

    @staticmethod
    def _check_issuance(grant: dict) -> None:
        if grant.get("issued_via") != "TEST_FIXTURE" or grant.get("test_only") is not True:
            raise GrantDenied("GRANT_ISSUER_INVALID", "issuer")
        if type(grant.get("revoked")) is not bool or grant.get("revoked"):
            raise GrantDenied("GRANT_REVOKED", "revoked")

    @staticmethod
    def _check_subject(grant: dict, request: AuthorizationRequest) -> None:
        if grant.get("subject") != request.actor:
            raise GrantDenied("GRANT_SUBJECT_MISMATCH", "subject")

    @staticmethod
    def _check_action(grant: dict, request: AuthorizationRequest) -> None:
        actions = grant.get("actions")
        if (not isinstance(actions, list) or not actions
                or not set(actions) <= S1_GRANT_ACTIONS
                or request.action not in actions):
            raise GrantDenied("GRANT_ACTION_OUT_OF_SCOPE", "action")

    def _check_resource(self, grant: dict, request: AuthorizationRequest) -> None:
        resources = grant.get("resources")
        if not isinstance(resources, list) or not resources:
            raise GrantDenied("GRANT_RESOURCES_INVALID", "resource")
        try:
            target = safe_path(Path(request.resource), self.root)
            scopes = [safe_path(Path(item), self.root) for item in resources]
        except Denied as exc:
            raise GrantDenied(str(exc), "resource") from exc
        if not any(inside(target, scope) for scope in scopes):
            raise GrantDenied("RESOURCE_OUT_OF_SCOPE", "resource")

    @staticmethod
    def _check_amount(grant: dict) -> None:
        if type(grant.get("amount_limit")) is not int or grant.get("amount_limit") != 0:
            raise GrantDenied("PAYMENT_FORBIDDEN", "amount")

    @staticmethod
    def _check_time(grant: dict, now: datetime) -> None:
        start, end = timestamp(grant["issued_at"]), timestamp(grant["expires_at"])
        if not start <= now < end:
            raise GrantDenied("GRANT_EXPIRED_OR_NOT_YET_VALID", "time")
        if end <= start or ((end - start) > _TTL and not str(grant.get("extension_reason", "")).strip()):
            raise GrantDenied("GRANT_TTL_INVALID", "time")

    @staticmethod
    def _check_digest(grant: dict, request: AuthorizationRequest) -> None:
        if grant.get("request_digest") != request.digest:
            raise GrantDenied("GRANT_REQUEST_DIGEST_MISMATCH", "request_digest")
        if grant.get("git_candidate_sha") != request.git_candidate_sha:
            raise GrantDenied("CANDIDATE_SHA_MISMATCH", "request_digest")
        if grant.get("tree_sha") != request.tree_sha:
            raise GrantDenied("TREE_SHA_MISMATCH", "request_digest")
