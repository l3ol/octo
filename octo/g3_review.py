"""G3 review entry. Shape check only. This module does not issue product PASS.

Quadruple: ``base_sha + candidate_sha + scope_digest + fixture_digest``.

``scope_digest`` is ``octo.objects.digest`` of ``octo/scope/SCOPE-MANIFEST.json``.
That file is the product scope. A caller-supplied test object is rejected.
The manifest does not contain the candidate commit SHA.

A2-4 fixture composition, also via ``octo.objects.digest``:

- ``template_digest`` hashes the static template inventory object
  ``{kind, files:[{path, sha256}]}`` for files under
  ``tests/fixtures/g2s1/templates/``. ``sha256`` is the raw file bytes.
- ``isolation_policy_digest`` hashes
  ``tests/fixtures/g2s1/isolation-policy.json``.
- ``runtime_artifact_digest`` hashes a verified external inventory:
  ``{kind, candidate_sha, items:[{bytes, kind, path, sha256}]}``.
  The in-repo schema ``runtime-artifact-inventory.json`` is not that input.
  Each item must be a real grant, request, receipt, or log file outside the
  candidate tree, confined to ``store_root``, with matching byte length and
  content sha256. The manifest must bind ``candidate_sha``.
- ``fixture_digest`` hashes
  ``{template_digest, runtime_artifact_digest, isolation_policy_digest}``.
  It is refused when the external manifest is missing or does not verify.

The runtime manifest itself, a G3 review receipt, a handoff snapshot, and a
fixture-digest record are not members of the hashed item list. A one-byte
change in an external file breaks the old binding. Re-registering the
inventory changes both the runtime column and ``fixture_digest``.

In-repo recompute of the two static columns:

``PYTHONPATH=. python3 -c "from octo.g3_review import template_digest, isolation_policy_digest; print(template_digest()); print(isolation_policy_digest())"``

The runtime and fixture columns have no acceptance value until an external
manifest is supplied. Passing the schema path is rejected.

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
from octo.grant import Denied, safe_path
from octo.models import reject_self_sign
from octo.objects import digest

ROOT = Path(__file__).resolve().parents[1]
SCOPE_PATH = ROOT / "octo" / "scope" / "SCOPE-MANIFEST.json"
TEMPLATE_DIR = ROOT / "tests" / "fixtures" / "g2s1" / "templates"
RUNTIME_SCHEMA_PATH = ROOT / "tests" / "fixtures" / "g2s1" / "runtime-artifact-inventory.json"
ISOLATION_POLICY_PATH = ROOT / "tests" / "fixtures" / "g2s1" / "isolation-policy.json"
SCOPE_SOURCE = "octo/scope/SCOPE-MANIFEST.json"
REQUIRED_ARTIFACT_KINDS = frozenset({"grant", "request", "receipt", "log"})
EXCLUDED_ARTIFACT_KINDS = frozenset({
    "runtime_manifest",
    "review_receipt",
    "handoff_snapshot",
    "fixture_digest",
    "snapshot",
})
EXCLUDED_ARTIFACT_NAMES = frozenset({
    "runtime-manifest.json",
    "g3-review-receipt.json",
    "review-receipt.json",
    "handoff-snapshot.json",
    "fixture-digest.json",
})


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


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def verified_runtime_inventory(manifest_path: Path | str, *, candidate_sha: str) -> dict:
    """Check an external Grant/request/Receipt/log inventory and return its canonical body.

    The returned object is the hashed runtime input. It does not contain the
    manifest path, a review receipt, a handoff snapshot, or a fixture digest.
    """
    candidate_sha = require_candidate_sha(candidate_sha)
    manifest = Path(manifest_path)
    if not manifest.is_file():
        raise ValueError("external runtime manifest is missing")
    resolved_manifest = manifest.resolve()
    if _inside(resolved_manifest, ROOT) or resolved_manifest == RUNTIME_SCHEMA_PATH.resolve():
        raise ValueError("in-repo schema is not an external runtime manifest")
    document = load_json(resolved_manifest)
    if document.get("kind") == "runtime_artifact_inventory_schema" or document.get("acceptance_input") is False:
        raise ValueError("schema inventory is not an acceptance runtime manifest")
    if "candidate_sha" not in document or require_candidate_sha(document["candidate_sha"]) != candidate_sha:
        raise ValueError("runtime manifest candidate binding mismatch")
    store_root = document.get("store_root")
    if not isinstance(store_root, str) or not Path(store_root).is_dir():
        raise ValueError("runtime store_root is missing")
    store_root_path = Path(store_root).resolve()
    if _inside(store_root_path, ROOT):
        raise ValueError("runtime store_root is inside the candidate tree")
    raw_items = document.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("runtime manifest has no artifact items")
    items = []
    seen: set[Path] = set()
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise ValueError("runtime artifact item must be an object")
        kind = raw.get("kind")
        if kind in EXCLUDED_ARTIFACT_KINDS:
            raise ValueError(
                "runtime inventory must not include the manifest, snapshot, review receipt, or fixture_digest"
            )
        if kind not in REQUIRED_ARTIFACT_KINDS:
            raise ValueError("runtime artifact kind must be grant, request, receipt, or log")
        if not isinstance(raw.get("path"), str) or "sha256" not in raw or "bytes" not in raw:
            raise ValueError("runtime artifact item requires path, bytes, and sha256")
        try:
            confined = safe_path(Path(raw["path"]), store_root_path)
        except Denied as exc:
            raise ValueError(f"runtime artifact path escape: {exc}") from exc
        if not confined.is_file():
            raise ValueError("runtime artifact file is missing")
        if confined.resolve() == resolved_manifest:
            raise ValueError("runtime manifest must not be a member of the runtime inventory")
        if confined.name in EXCLUDED_ARTIFACT_NAMES:
            raise ValueError(
                "runtime inventory must not include the manifest, snapshot, review receipt, or fixture_digest"
            )
        if confined.resolve() in seen:
            raise ValueError("runtime artifact path repeated")
        seen.add(confined.resolve())
        content = confined.read_bytes()
        file_sha = hashlib.sha256(content).hexdigest()
        if file_sha != file_digest(raw["sha256"]):
            raise ValueError("runtime artifact sha256 mismatch")
        if type(raw["bytes"]) is not int or raw["bytes"] != len(content):
            raise ValueError("runtime artifact byte length mismatch")
        if "candidate_sha" in raw and require_candidate_sha(raw["candidate_sha"]) != candidate_sha:
            raise ValueError("runtime artifact candidate binding mismatch")
        items.append({
            "bytes": len(content),
            "kind": kind,
            "path": confined.resolve().as_posix(),
            "sha256": file_sha,
        })
    if not REQUIRED_ARTIFACT_KINDS <= {item["kind"] for item in items}:
        raise ValueError("runtime manifest must list grant, request, receipt, and log")
    items.sort(key=lambda item: (item["kind"], item["path"]))
    return {
        "kind": "external_runtime_artifact_inventory",
        "candidate_sha": candidate_sha,
        "items": items,
    }


def runtime_artifact_digest(manifest_path: Path | str, *, candidate_sha: str) -> str:
    """Digest of a verified external inventory. The in-repo schema is rejected."""
    return digest(verified_runtime_inventory(manifest_path, candidate_sha=candidate_sha))


def isolation_policy_digest() -> str:
    return digest(load_json(ISOLATION_POLICY_PATH))


def column_digests(*, runtime_manifest: Path | str, candidate_sha: str) -> dict[str, str]:
    template = template_digest()
    runtime = runtime_artifact_digest(runtime_manifest, candidate_sha=candidate_sha)
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


def fixture_digest(*, runtime_manifest: Path | str, candidate_sha: str) -> str:
    """A2-4 three-column fixture digest. Refused without a verified external inventory."""
    return column_digests(runtime_manifest=runtime_manifest, candidate_sha=candidate_sha)["fixture_digest"]


def handoff_binding(*, base_sha: str, candidate_sha: str, runtime_manifest: Path | str) -> dict[str, Any]:
    """Quadruple for a later handoff. Does not write a snapshot or sign PASS."""
    columns = column_digests(runtime_manifest=runtime_manifest, candidate_sha=candidate_sha)
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
    runtime_manifest = payload.get("runtime_manifest")
    if not isinstance(runtime_manifest, str) or not runtime_manifest:
        raise ValueError("external runtime manifest is required")
    expected_fixture = fixture_digest(runtime_manifest=runtime_manifest, candidate_sha=candidate_sha)
    supplied_fixture = file_digest(payload.get("fixture_digest"))  # type: ignore[arg-type]
    if supplied_fixture != expected_fixture:
        raise ValueError("fixture_digest does not match the external three-column digest")
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
