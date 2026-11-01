"""N11, N12, and N13 closing nodes.

N11 records the journal state against the Git candidate and tree SHAs.
N12 keeps verifier NOT_RUN and does not accept a builder runtime PASS.
N13 writes only inside the isolation store.

Builder selftest support only.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from octo.candidate import git_candidate_sha, tree_sha
from octo.grant import safe_path, write_once
from octo.models import reject_self_sign
from octo.nodes import emit_envelope
from octo.objects import sha256

N11_KEYS = {
    "receipt_id",
    "state",
    "grant_ref",
    "request_digest",
    "git_candidate_sha",
    "tree_sha",
}
N12_KEYS = {"receipt_id", "builder_id", "verifier_id", "claimed_state"}
N13_KEYS = {"name", "record"}


def run_n11(inputs: Mapping[str, Any], *, at: str) -> dict:
    if set(inputs) != N11_KEYS:
        raise ValueError("N11 inputs do not match the closing receipt shape")
    git_candidate_sha(inputs["git_candidate_sha"])
    tree_sha(inputs["tree_sha"])
    sha256(inputs["request_digest"])
    if inputs["state"] == "PASS":
        return emit_envelope(
            node_id="N11",
            at=at,
            inputs=dict(inputs),
            status="BLOCKED",
            output=None,
        )
    output = {
        "receipt_id": inputs["receipt_id"],
        "state": inputs["state"],
        "grant_ref": inputs["grant_ref"],
        "request_digest": inputs["request_digest"],
        "git_candidate_sha": inputs["git_candidate_sha"],
        "tree_sha": inputs["tree_sha"],
        "verifier": "NOT_RUN",
    }
    return emit_envelope(node_id="N11", at=at, inputs=dict(inputs), status="OK", output=output)


def run_n12(inputs: Mapping[str, Any], *, at: str) -> dict:
    """Separate from N11. A claimed PASS is BLOCKED and is not stored as success."""
    if set(inputs) != N12_KEYS:
        raise ValueError("N12 inputs do not match the check shape")
    claimed = inputs["claimed_state"]
    rejected = reject_self_sign(inputs["builder_id"], inputs["verifier_id"], claimed)
    if claimed == "PASS" or rejected:
        return emit_envelope(
            node_id="N12",
            at=at,
            inputs=dict(inputs),
            status="BLOCKED",
            output=None,
        )
    output = {
        "receipt_id": inputs["receipt_id"],
        "state": "NOT_RUN",
        "verifier": "NOT_RUN",
        "builder_runtime_pass": False,
    }
    return emit_envelope(node_id="N12", at=at, inputs=dict(inputs), status="OK", output=output)


def run_n13(inputs: Mapping[str, Any], *, at: str, store_root: Path) -> dict:
    """Write one record under ``store_root`` and nowhere else."""
    if set(inputs) != N13_KEYS:
        raise ValueError("N13 inputs do not match the writeback shape")
    name = inputs["name"]
    record = inputs["record"]
    if not isinstance(name, str) or not isinstance(record, dict):
        raise ValueError("N13 name and record are required")
    relative = Path(name)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("N13 writeback name must stay inside the isolation store")
    directory = store_root / "writeback"
    directory.mkdir(parents=True, exist_ok=True)
    path = safe_path(directory / relative, store_root)
    write_once(path, record)
    output = {
        "state": "WRITTEN",
        "relative_path": str(path.relative_to(store_root)),
        "content_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    return emit_envelope(node_id="N13", at=at, inputs=dict(inputs), status="OK", output=output)
