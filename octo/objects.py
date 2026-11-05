"""Serialization and validation primitives adapted from Mac ``octo/objects.py``.

Source candidate sha256 ``09afd2f1813964851b25ac934d9176940bed957d391ce55ea184899d8e5b66a9``
(commit ``4caf7ea4``). Manifest decision: adapt, not adopt.

Mac Intent / Decision / Evidence / Grant / Outcome field names are not the
PRD §5 shapes. Those records stay in ``octo.models``. This module keeps the
canonical JSON, digest, identifier, SHA-256, and timestamp helpers only.

A2-2 node ``inputs_hash`` is ``sha256(canonical(inputs))``. The envelope field
``at`` is not part of ``inputs`` and does not enter the hash.
"""

from datetime import datetime, timezone
import hashlib
import json
import re


def canonical(value: object) -> bytes:
    """UTF-8 canonical JSON: sorted keys, no extra space, no trailing newline.

    ``allow_nan=False`` rejects NaN and Infinity. ``ensure_ascii=False`` leaves
    non-ASCII characters as raw UTF-8. The hashed bytes have no trailing newline.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(value: object) -> str:
    """Lowercase SHA-256 hex of :func:`canonical` bytes."""
    return hashlib.sha256(canonical(value)).hexdigest()


def inputs_hash(inputs: object) -> str:
    """A2-2 hash of a node's actual input object. Do not pass the envelope."""
    return digest(inputs)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp. A timezone offset is required."""
    if not isinstance(value, str):
        raise ValueError("timestamp required")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.astimezone(timezone.utc)


def identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}", value):
        raise ValueError("invalid identifier")
    return value


def sha256(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("SHA-256 required")
    return value
