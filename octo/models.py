"""Five core objects. Fields frozen per PRD §5. Synthetic data only.

PRD field names stay here. Identifier, SHA-256, and offset-timestamp checks are
the adapted primitives in ``octo.objects`` — Mac object field names are not a
second schema. ``compute_candidate_sha`` still hashes the sorted path map; node
``inputs_hash`` is ``octo.objects.inputs_hash`` and does not include ``at``.
"""
from dataclasses import dataclass, field
from typing import List, Optional

from octo.objects import digest, identifier, sha256 as require_sha256, timestamp

@dataclass
class Intent:
    intent_id: str
    text: str
    created_at: str
    source: str

@dataclass
class Decision:
    decision_id: str
    intent_id: str
    content: str
    decider: str
    decided_at: str
    supersedes_id: Optional[str] = None

@dataclass
class Evidence:
    evidence_id: str
    decision_id: str
    type: str
    uri_or_hash: Optional[str]
    collected_at: str

@dataclass
class Grant:
    grant_id: str
    request_digest: str
    actions: List[str]
    amount_limit: float = 0.0
    resources: List[str] = field(default_factory=list)
    subject: str = ""
    issued_at: str = ""
    expires_at: str = ""
    issued_via: str = "github_pr"
    revoked: bool = False

@dataclass
class Outcome:
    outcome_id: str
    decision_id: str
    receipt_id: str
    state: str  # SUCCEEDED / DENIED / BLOCKED / UNKNOWN_COMMIT / RECONCILED_*

@dataclass
class Receipt:
    receipt_id: str
    grant_id: Optional[str]
    request_digest: str
    candidate_sha: str
    action: str
    object_id: str
    idempotency_key: str
    started_at: str
    finished_at: str
    state: str
    verifier: str = "NOT_RUN"

@dataclass
class Journal:
    journal_id: str
    receipt_id: str
    event: str
    at: str

def compute_candidate_sha(file_map: dict) -> str:
    """Frozen SHA algorithm: path → SHA-256 map, canonical JSON, then SHA-256.

    Canonical bytes come from ``octo.objects.digest`` (UTF-8, sorted keys,
    separators ``(',', ':')``, no trailing newline). This digest is not a node
    ``inputs_hash``.
    """
    sorted_items = sorted(file_map.items())
    return digest(sorted_items)


_ID_FIELDS = (
    "intent_id",
    "decision_id",
    "evidence_id",
    "grant_id",
    "outcome_id",
    "receipt_id",
    "journal_id",
    "object_id",
    "supersedes_id",
)
_SHA_FIELDS = ("request_digest", "candidate_sha")
_TIME_FIELDS = (
    "created_at",
    "decided_at",
    "collected_at",
    "issued_at",
    "expires_at",
    "started_at",
    "finished_at",
    "at",
)


def validate_prd_record(record: object) -> object:
    """Check present PRD ids, sha256 fields, and offset timestamps.

    ``None`` and ``""`` are skipped so partial defaults still construct.
    Field names are unchanged.
    """
    for name in _ID_FIELDS:
        value = getattr(record, name, None)
        if isinstance(value, str) and value:
            identifier(value)
    for name in _SHA_FIELDS:
        value = getattr(record, name, None)
        if isinstance(value, str) and value:
            require_sha256(value)
    for name in _TIME_FIELDS:
        value = getattr(record, name, None)
        if isinstance(value, str) and value:
            timestamp(value)
    return record

def reject_self_sign(builder_id: str, verifier_id: str, claimed_state: str) -> bool:
    """Builder cannot self-sign PASS. Returns True if rejected."""
    if builder_id == verifier_id and claimed_state == "PASS":
        return True  # rejected
    return False
