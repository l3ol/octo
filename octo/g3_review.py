"""G3 review entry. Shape check only. This module does not issue product PASS.

Quadruple: ``base_sha + candidate_sha + scope_digest + fixture_digest``.

``scope_digest`` is ``octo.objects.digest`` of ``octo/scope/SCOPE-MANIFEST.json``.
That file is the product scope. A caller-supplied test object is rejected.
The manifest does not contain the candidate commit SHA.

A2-4 fixture composition, also via ``octo.objects.digest``:

- ``template_digest`` hashes the static template inventory object
  ``{kind, files:[{path, sha256}]}`` for files under
  ``tests/fixtures/g2s1/templates/``. ``sha256`` is the raw file bytes.
- ``runtime_artifact_digest`` hashes the committed schema
  ``tests/fixtures/g2s1/runtime-artifact-inventory.json``.
  That schema is not a generated Grant, request, Receipt, or log.
- ``isolation_policy_digest`` hashes
  ``tests/fixtures/g2s1/isolation-policy.json``.
- ``fixture_digest`` hashes
  ``{template_digest, runtime_artifact_digest, isolation_policy_digest}``.

Generated runtime artifacts stay outside the repo and are not folded back
into this definition. Review receipts and handoff bindings are not part of
the hashed template set.

Recompute:

``PYTHONPATH=. python3 -c "import json; from octo.g3_review import product_scope_digest, column_digests; print(json.dumps({'scope_digest': product_scope_digest(), **column_digests()}, sort_keys=True))"``

Any difference in base_sha, candidate_sha, scope_digest, or fixture_digest
marks a stored PASS INVALID. This code does not sign that PASS.

Builder selftest support only. runtime_pass stays false.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from octo.candidate import file_digest, git_candidate_sha
from octo.models import reject_self_sign
from octo.objects import digest

ROOT = Path(__file__).resolve().parents[1]
SCOPE_PATH = ROOT / "octo" / "scope" / "SCOPE-MANIFEST.json"
TEMPLATE_DIR = ROOT / "tests" / "fixtures" / "g2s1" / "templates"
RUNTIME_INVENTORY_PATH = ROOT / "tests" / "fixtures" / "g2s1" / "runtime-artifact-inventory.json"
ISOLATION_POLICY_PATH = ROOT / "tests" / "fixtures" / "g2s1" / "isolation-policy.json"
SCOPE_SOURCE = "octo/scope/SCOPE-MANIFEST.json"


def require_candidate_sha(value: str) -> str:
    """40-hex Git commit. Shared by N11 and the G3 quadruple."""
    return git_candidate_sha(value)


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be a JSON object")
    return value


def product_scope() -> dict:
    """The product SCOPE-MANIFEST object. Not a CLI test scope."""
    return load_json(SCOPE_PATH)


def product_scope_digest() -> str:
    """sha256(canonical JSON of the product SCOPE-MANIFEST)."""
    return digest(product_scope())


def template_inventory() -> dict:
    """In-repo static template list. Paths are repo-relative."""
    if not TEMPLATE_DIR.is_dir():
        raise ValueError("static template directory is missing")
    files = []
    for path in sorted(item for item in TEMPLATE_DIR.rglob("*") if item.is_file()):
        relative = path.relative_to(ROOT).as_posix()
        files.append({
            "path": relative,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    if not files:
        raise ValueError("static template inventory is empty")
    return {"kind": "static_fixture_template_inventory", "files": files}


def template_digest() -> str:
    return digest(template_inventory())


def runtime_artifact_digest() -> str:
    """Digest of the out-of-repo artifact schema, not of generated artifacts."""
    return digest(load_json(RUNTIME_INVENTORY_PATH))


def isolation_policy_digest() -> str:
    return digest(load_json(ISOLATION_POLICY_PATH))


def column_digests() -> dict[str, str]:
    template = template_digest()
    runtime = runtime_artifact_digest()
    isolation = isolation_policy_digest()
    composed = digest({
        "template_digest": template,
        "runtime_artifact_digest": runtime,
        "isolation_policy_digest": isolation,
    })
    return {
        "template_digest": template,
        "runtime_artifact_digest": runtime,
        "isolation_policy_digest": isolation,
        "fixture_digest": composed,
    }


def fixture_digest() -> str:
    """A2-4 three-column fixture digest. Not a path=sha256 file listing."""
    return column_digests()["fixture_digest"]


def handoff_binding(*, base_sha: str, candidate_sha: str) -> dict[str, Any]:
    """Quadruple for a later handoff. Does not write a snapshot or sign PASS."""
    columns = column_digests()
    return {
        "base_sha": require_candidate_sha(base_sha),
        "candidate_sha": require_candidate_sha(candidate_sha),
        "scope_digest": product_scope_digest(),
        "fixture_digest": columns["fixture_digest"],
        "template_digest": columns["template_digest"],
        "runtime_artifact_digest": columns["runtime_artifact_digest"],
        "isolation_policy_digest": columns["isolation_policy_digest"],
        "scope_source": SCOPE_SOURCE,
        "decision": "RECEIVED",
        "product_pass": False,
        "runtime_pass": False,
    }


def review_entry(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Echo the product quadruple. Never emit decision PASS."""
    if not isinstance(payload, Mapping):
        raise ValueError("review entry payload must be an object")
    claimed = payload.get("claimed_state", payload.get("decision"))
    if reject_self_sign(
        str(payload.get("builder_id", "")),
        str(payload.get("verifier_id", "")),
        str(claimed or ""),
    ):
        raise PermissionError("builder self-sign blocked")
    if claimed == "PASS" or payload.get("product_pass") is True or payload.get("runtime_pass") is True:
        raise PermissionError("review entry does not issue PASS")
    base_sha = require_candidate_sha(payload.get("base_sha"))  # type: ignore[arg-type]
    candidate_sha = require_candidate_sha(payload.get("candidate_sha"))  # type: ignore[arg-type]
    expected_scope = product_scope_digest()
    if "scope" in payload:
        supplied_scope = payload["scope"]
        if not isinstance(supplied_scope, Mapping) or digest(dict(supplied_scope)) != expected_scope:
            raise ValueError("scope is not the product SCOPE-MANIFEST")
    if "scope_digest" not in payload:
        raise ValueError("scope_digest is required")
    scope_digest = file_digest(payload["scope_digest"])
    if scope_digest != expected_scope:
        raise ValueError("scope_digest is not the product SCOPE-MANIFEST digest")
    expected_fixture = fixture_digest()
    supplied_fixture = file_digest(payload.get("fixture_digest"))  # type: ignore[arg-type]
    if supplied_fixture != expected_fixture:
        raise ValueError("fixture_digest does not match the in-repo three-column digest")
    receipt = {
        "kind": "g3_review_receipt",
        "base_sha": base_sha,
        "candidate_sha": candidate_sha,
        "scope_digest": scope_digest,
        "fixture_digest": supplied_fixture,
        "scope_source": SCOPE_SOURCE,
        "decision": "RECEIVED",
        "product_pass": False,
        "runtime_pass": False,
    }
    if receipt["decision"] == "PASS" or receipt["product_pass"] or receipt["runtime_pass"]:
        raise PermissionError("review entry does not issue PASS")
    return receipt


def invalidate_stored_pass(stored: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    """Mark a stored PASS INVALID when any quadruple field differs.

    This does not create a new PASS. A matching quadruple stays UNCHANGED.
    """
    if not isinstance(stored, Mapping) or not isinstance(current, Mapping):
        raise ValueError("stored PASS and current quadruple must be objects")
    checked = {
        "base_sha": require_candidate_sha(current.get("base_sha")),  # type: ignore[arg-type]
        "candidate_sha": require_candidate_sha(current.get("candidate_sha")),  # type: ignore[arg-type]
        "scope_digest": file_digest(current.get("scope_digest")),  # type: ignore[arg-type]
        "fixture_digest": file_digest(current.get("fixture_digest")),  # type: ignore[arg-type]
    }
    reasons = [name for name in ("base_sha", "candidate_sha", "scope_digest", "fixture_digest") if stored.get(name) != checked[name]]
    return {
        "kind": "pass_invalidation",
        "status": "INVALID" if reasons else "UNCHANGED",
        "reasons": reasons,
        "base_sha": checked["base_sha"],
        "candidate_sha": checked["candidate_sha"],
        "scope_digest": checked["scope_digest"],
        "fixture_digest": checked["fixture_digest"],
        "product_pass": False,
        "runtime_pass": False,
    }
