"""Append-only receipts and an idempotency ledger in an isolation store.

The Mac journal's reconcile rule is kept: an unknown commit is resolved from
the effect row before any further dispatch. Git attestations, a brain tree,
and a product-repo database file are not used.

Builder selftest support only.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import uuid

from octo.governor import Denied
from octo.grant import safe_path, write_once
from octo.objects import canonical, utcnow

_BANNED = {".git", ".gx", ".founder-key", "brain"}


class Blocked(RuntimeError):
    """Unknown persistence or reconciliation state. Do not blind-retry."""


class Journal:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        if any(part in _BANNED for part in self.root.parts):
            raise Denied("PROTECTED_RESOURCE")
        self.records = self.root / "journal"
        self.records.mkdir(parents=True, exist_ok=True)
        self.db_path = safe_path(self.root / "ledger.sqlite", self.root)
        self.db = sqlite3.connect(self.db_path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY,
                id TEXT UNIQUE NOT NULL,
                key TEXT NOT NULL,
                state TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS effects (
                key TEXT PRIMARY KEY,
                request_digest TEXT NOT NULL,
                object_id TEXT NOT NULL,
                result TEXT NOT NULL
            );
        """)
        self.reconcile_count = 0

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def writer(self):
        lock_path = safe_path(self.records / ".writer.lock", self.root)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "rb") as lock:
            try:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Blocked("ANOTHER_LOCAL_WRITER") from exc
            try:
                yield
            finally:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_UN)

    def record(self, request, state: str, result: str, *, reason: str = "", evidence_refs=()) -> dict:
        record_id = "R-" + uuid.uuid4().hex
        started = self.db.execute(
            "SELECT payload FROM events WHERE key=? ORDER BY seq LIMIT 1",
            (request.idempotency_key,),
        ).fetchone()
        payload = {
            "record_type": "Receipt",
            "receipt_id": record_id,
            "intent_id": request.intent_id,
            "action": request.action,
            "actor": request.actor,
            "grant_id": request.grant_id,
            "idempotency_key": request.idempotency_key,
            "request_digest": request.digest,
            "git_candidate_sha": request.git_candidate_sha,
            "tree_sha": request.tree_sha,
            "started_at": json.loads(started["payload"])["started_at"] if started else utcnow().isoformat(),
            "finished_at": utcnow().isoformat(),
            "state": state,
            "result": result,
            "evidence_refs": list(evidence_refs),
            "verifier": "NOT_RUN",
            "notes": reason,
        }
        path = safe_path(self.records / f"{record_id}.json", self.root)
        try:
            write_once(path, payload)
        except FileExistsError as exc:
            raise Blocked("ORIGINAL_RECORD_CHANGED") from exc
        with self.db:
            self.db.execute(
                "INSERT INTO events(id, key, state, payload) VALUES(?,?,?,?)",
                (record_id, request.idempotency_key, state, canonical(payload).decode()),
            )
        return payload

    def events(self, key: str) -> list[dict]:
        return [
            json.loads(row["payload"])
            for row in self.db.execute(
                "SELECT payload FROM events WHERE key=? ORDER BY seq",
                (key,),
            )
        ]

    def latest(self, key: str):
        row = self.db.execute(
            "SELECT payload FROM events WHERE key=? AND state!='DENIED' ORDER BY seq DESC LIMIT 1",
            (key,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["payload"])

    def effect_count(self) -> int:
        return int(self.db.execute("SELECT COUNT(*) AS n FROM effects").fetchone()["n"])

    def apply(self, request) -> dict:
        """Record the read effect once. This does not execute a command."""
        from octo.objects import digest
        effect = {
            "object_id": "read-" + digest({"resource": request.resource})[:16],
            "op": "read",
        }
        with self.db:
            self.db.execute(
                "INSERT INTO effects(key, request_digest, object_id, result) VALUES(?,?,?,?)",
                (request.idempotency_key, request.digest, effect["object_id"], canonical(effect).decode()),
            )
        return effect

    def reconcile(self, request) -> tuple[str, dict | None]:
        """Resolve a prior dispatch from the effect ledger. Absence is authoritative."""
        self.reconcile_count += 1
        row = self.db.execute(
            "SELECT request_digest, result FROM effects WHERE key=?",
            (request.idempotency_key,),
        ).fetchone()
        if row is None:
            return "NOT_APPLIED", None
        if row["request_digest"] != request.digest:
            raise Blocked("IDEMPOTENCY_DIGEST_CONFLICT")
        return "APPLIED", json.loads(row["result"])
