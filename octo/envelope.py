"""Common node envelope (T-01 §1).

Required fields: ``node_id``, ``at``, ``inputs``, ``inputs_hash``, ``status``,
``output``. ``inputs_hash`` is recomputed from ``inputs`` alone; ``at`` is not
hashed. ``NOT_RUN_THIS_STAGE`` is valid only for N6 and N7 and requires
``output`` null. Invented states such as ``DEGRADED_SKIP_*`` are rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from octo.objects import inputs_hash, timestamp

SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "node-envelope.schema.json"

NODE_IDS = (
    "N1",
    "N2",
    "N3",
    "N4",
    "N5",
    "N6",
    "N7",
    "N8",
    "N9",
    "N10",
    "N11",
    "N12",
    "N13",
)
STATUSES = (
    "OK",
    "PARTIAL",
    "NEEDS_CLARIFICATION",
    "BLOCKED",
    "AUTHORIZATION_REQUIRED",
    "SOURCE_UNAVAILABLE",
    "NOT_RUN_THIS_STAGE",
)
NOT_RUN_NODES = frozenset({"N6", "N7"})


class EnvelopeValidationError(ValueError):
    """Envelope failed schema, timestamp, or inputs_hash checks."""


@dataclass(frozen=True)
class NodeEnvelope:
    node_id: str
    at: str
    inputs: dict
    inputs_hash: str
    status: str
    output: dict | None

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "at": self.at,
            "inputs": self.inputs,
            "inputs_hash": self.inputs_hash,
            "status": self.status,
            "output": self.output,
        }


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = load_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def build_envelope(
    *,
    node_id: str,
    at: str,
    inputs: dict,
    status: str,
    output: dict | None,
) -> dict:
    """Assemble an envelope dict, filling ``inputs_hash`` from ``inputs`` only."""
    return {
        "node_id": node_id,
        "at": at,
        "inputs": inputs,
        "inputs_hash": inputs_hash(inputs),
        "status": status,
        "output": output,
    }


def validate_envelope(value: Any) -> NodeEnvelope:
    """Validate ``value`` against the node-envelope schema and A2-2 hash."""
    if not isinstance(value, dict):
        raise EnvelopeValidationError("envelope must be an object")
    errors = sorted(_validator().iter_errors(value), key=lambda err: list(err.absolute_path))
    if errors:
        raise EnvelopeValidationError("; ".join(err.message for err in errors))
    try:
        timestamp(value["at"])
    except (TypeError, ValueError) as exc:
        raise EnvelopeValidationError(f"at must be ISO-8601 with an offset: {exc}") from exc
    try:
        recomputed = inputs_hash(value["inputs"])
    except (TypeError, ValueError) as exc:
        raise EnvelopeValidationError(f"inputs are not canonical JSON: {exc}") from exc
    if recomputed != value["inputs_hash"]:
        raise EnvelopeValidationError(
            f"inputs_hash mismatch: {value['inputs_hash']} != {recomputed}"
        )
    if value["status"] == "NOT_RUN_THIS_STAGE":
        if value["node_id"] not in NOT_RUN_NODES:
            raise EnvelopeValidationError("NOT_RUN_THIS_STAGE is only valid for N6 and N7")
        if value["output"] is not None:
            raise EnvelopeValidationError("NOT_RUN_THIS_STAGE requires output null")
    output = value["output"]
    return NodeEnvelope(
        node_id=value["node_id"],
        at=value["at"],
        inputs=json.loads(json.dumps(value["inputs"])),
        inputs_hash=value["inputs_hash"],
        status=value["status"],
        output=None if output is None else json.loads(json.dumps(output)),
    )
