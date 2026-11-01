"""G3 review entry. Shape check only. This module does not issue product PASS.

The quadruple is ``base_sha + candidate_sha + scope_digest + fixture_digest``.
``fixture_digest`` follows execution-plan §1 over ``tests/fixtures/g2s1/``:

each fixture file is one line ``relative_posix_path=<sha256 of file bytes>``,
lines sorted by that path, joined with ``\\n`` and no trailing newline.
The digest is sha256 of those UTF-8 bytes.

``scope_digest`` is sha256 of the canonical JSON object for ``scope``.
A caller may pass ``scope_digest`` directly instead of ``scope``.

Builder selftest support only. A stored PASS is marked INVALID when its
candidate_sha or fixture_digest no longer matches the quadruple. This code
does not sign that PASS.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from octo.candidate import file_digest, git_candidate_sha
from octo.models import reject_self_sign
from octo.objects import digest

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "g2s1"


def require_candidate_sha(value: str) -> str:
    """40-hex Git commit. Shared by N11 and the G3 quadruple."""
    return git_candidate_sha(value)


def fixture_digest(directory: Path | None = None) -> str:
    """Plan §1 digest of every file under the G2-S1 fixture directory."""
    root = FIXTURE_DIR if directory is None else Path(directory)
    if not root.is_dir():
        raise ValueError("fixture directory is missing")
    entries = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        file_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append((relative, file_sha))
    entries.sort(key=lambda item: item[0])
    material = "\n".join(f"{name}={file_sha}" for name, file_sha in entries).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def scope_digest_of(scope: Mapping[str, Any]) -> str:
    """sha256 of canonical JSON for a scope manifest object."""
    if not isinstance(scope, Mapping):
        raise ValueError("scope must be an object")
    return digest(dict(scope))


def review_entry(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Accept the quadruple and echo it. Never emit decision PASS."""
    if not isinstance(payload, Mapping):
        raise ValueError("review entry payload must be an object")
    claimed = payload.get("claimed_state", payload.get("decision"))
    if reject_self_sign(
        str(payload.get("builder_id", "")),
        str(payload.get("verifier_id", "")),
        str(claimed or ""),
    ):
        raise PermissionError("builder self-sign blocked")
    if claimed == "PASS" or payload.get("product_pass") is True:
        raise PermissionError("review entry does not issue PASS")
    base_sha = require_candidate_sha(payload.get("base_sha"))  # type: ignore[arg-type]
    candidate_sha = require_candidate_sha(payload.get("candidate_sha"))  # type: ignore[arg-type]
    if "scope" in payload and "scope_digest" in payload:
        computed = scope_digest_of(payload["scope"])
        supplied = file_digest(payload["scope_digest"])
        if computed != supplied:
            raise ValueError("scope_digest does not match scope")
        scope_digest = supplied
        scope = dict(payload["scope"])
    elif "scope" in payload:
        scope = dict(payload["scope"])
        scope_digest = scope_digest_of(scope)
    elif "scope_digest" in payload:
        scope = None
        scope_digest = file_digest(payload["scope_digest"])
    else:
        raise ValueError("scope or scope_digest is required")
    fixture = file_digest(payload.get("fixture_digest"))  # type: ignore[arg-type]
    receipt = {
        "kind": "g3_review_receipt",
        "base_sha": base_sha,
        "candidate_sha": candidate_sha,
        "scope_digest": scope_digest,
        "fixture_digest": fixture,
        "decision": "RECEIVED",
        "product_pass": False,
    }
    if scope is not None:
        receipt["scope"] = scope
    if receipt["decision"] == "PASS" or receipt["product_pass"] is True:
        raise PermissionError("review entry does not issue PASS")
    return receipt


def invalidate_stored_pass(stored: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    """Mark a stored PASS INVALID when candidate_sha or fixture_digest moved.

    This does not create a new PASS. A matching quadruple stays UNCHANGED.
    """
    if not isinstance(stored, Mapping) or not isinstance(current, Mapping):
        raise ValueError("stored PASS and current quadruple must be objects")
    current_candidate = require_candidate_sha(current.get("candidate_sha"))  # type: ignore[arg-type]
    current_fixture = file_digest(current.get("fixture_digest"))  # type: ignore[arg-type]
    reasons = []
    if stored.get("candidate_sha") != current_candidate:
        reasons.append("candidate_sha")
    if stored.get("fixture_digest") != current_fixture:
        reasons.append("fixture_digest")
    status = "INVALID" if reasons else "UNCHANGED"
    return {
        "kind": "pass_invalidation",
        "status": status,
        "reasons": reasons,
        "base_sha": current.get("base_sha"),
        "candidate_sha": current_candidate,
        "scope_digest": current.get("scope_digest"),
        "fixture_digest": current_fixture,
        "stored_candidate_sha": stored.get("candidate_sha"),
        "stored_fixture_digest": stored.get("fixture_digest"),
        "product_pass": False,
    }
