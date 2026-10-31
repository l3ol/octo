"""Five core objects. Fields frozen per PRD §5. Synthetic data only."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
import hashlib
import json

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
    """Frozen SHA algorithm: path → SHA-256 map, canonical JSON, then SHA-256."""
    sorted_items = sorted(file_map.items())
    canonical = json.dumps(sorted_items, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

def reject_self_sign(builder_id: str, verifier_id: str, claimed_state: str) -> bool:
    """Builder cannot self-sign PASS. Returns True if rejected."""
    if builder_id == verifier_id and claimed_state == "PASS":
        return True  # rejected
    return False
