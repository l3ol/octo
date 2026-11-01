"""Plan B config inventory. No config seal exists for tip24.

`config_digest` is sha256 of the canonical manifest bytes. It is not the
sha256 of `GATES-PARAMETERS-CANONICAL.txt`. That file stays a read-only
citation (`parameters_canonical_sha256` = cff01a57…, 4332 bytes).

Component digests hash existing blobs. They do not introduce parameter values.
"""

from __future__ import annotations

import re
from pathlib import Path

from gates.gitcmd import run_git
from gates.rules import CANONICAL_BYTES, CANONICAL_SHA256
from gates.types import canonical_json, sha256_hex

CONFIG_MANIFEST_KEYS = (
    "parameters_canonical_sha256",
    "policy_config_digest",
    "protection_settings_digest",
    "rule_version",
)

# Existing policy modules plus the rule-set binding. The canonical parameter
# file is cited separately and is not an input to policy_config_digest.
POLICY_PATHS = (
    "gates/policy/audit.py",
    "gates/policy/content.py",
    "gates/policy/decide.py",
    "gates/policy/forbidden.py",
    "gates/policy/size.py",
    "gates/rules.py",
    "gates/tamper/downgrade.py",
)

# Existing protection matchers. Not a new protection setting.
PROTECTION_PATHS = (
    "gates/pathmatch.py",
    "gates/tamper/path_filter.py",
)

_RULE_VERSION_RE = re.compile(r'^RULE_VERSION\s*=\s*"([^"]+)"\s*$', re.MULTILINE)


class InventoryError(Exception):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _show(repo: str | Path, spec: str) -> bytes:
    proc = run_git(repo, "show", spec, check=False)
    if proc.returncode != 0:
        raise InventoryError("CONFIG_DIGEST_INCOMPLETE")
    return proc.stdout


def _component_digest(repo: str | Path, commit: str, paths: tuple[str, ...]) -> str:
    entries = {path: sha256_hex(_show(repo, f"{commit}:{path}")) for path in paths}
    return sha256_hex(canonical_json(entries))


def _rule_version(repo: str | Path, commit: str) -> str:
    text = _show(repo, f"{commit}:gates/rules.py").decode("utf-8")
    found = _RULE_VERSION_RE.findall(text)
    if len(found) != 1 or found[0] == "":
        raise InventoryError("CONFIG_DIGEST_INCOMPLETE")
    return found[0]


def _canonical_sha(repo: str | Path, commit: str) -> str:
    data = _show(repo, f"{commit}:gates/policy/GATES-PARAMETERS-CANONICAL.txt")
    digest = sha256_hex(data)
    if len(data) != CANONICAL_BYTES or digest != CANONICAL_SHA256:
        raise InventoryError("CONFIG_DIGEST_INCOMPLETE")
    return digest


def config_manifest_bytes(manifest: dict) -> bytes:
    """Sorted keys, UTF-8, no extra whitespace, trailing LF."""
    if not isinstance(manifest, dict):
        raise InventoryError("CONFIG_DIGEST_INCOMPLETE")
    if any(key not in manifest for key in CONFIG_MANIFEST_KEYS):
        raise InventoryError("CONFIG_DIGEST_INCOMPLETE")
    body = {key: manifest[key] for key in CONFIG_MANIFEST_KEYS}
    for value in body.values():
        if not isinstance(value, str) or value == "":
            raise InventoryError("CONFIG_DIGEST_INCOMPLETE")
    if body["parameters_canonical_sha256"] != CANONICAL_SHA256:
        raise InventoryError("CONFIG_DIGEST_INCOMPLETE")
    if body["policy_config_digest"] == CANONICAL_SHA256 and body["protection_settings_digest"] == CANONICAL_SHA256:
        raise InventoryError("CONFIG_DIGEST_INCOMPLETE")
    return canonical_json(body) + b"\n"


def digest_config_manifest(manifest: dict) -> str:
    raw = config_manifest_bytes(manifest)
    digest = sha256_hex(raw)
    if digest == CANONICAL_SHA256 or digest == manifest.get("parameters_canonical_sha256"):
        raise InventoryError("CONFIG_DIGEST_INCOMPLETE")
    return digest


def judge_config_digest(digest: object, manifest: dict) -> dict:
    """FAIL CONFIG_DIGEST_INCOMPLETE when the digest is only the canonical file."""
    if not isinstance(digest, str) or digest == CANONICAL_SHA256:
        return {"status": "FAIL", "reason_code": "CONFIG_DIGEST_INCOMPLETE"}
    try:
        expected = digest_config_manifest(manifest)
    except InventoryError as exc:
        return {"status": "FAIL", "reason_code": exc.reason_code}
    if digest != expected:
        return {"status": "FAIL", "reason_code": "CONFIG_DIGEST_INCOMPLETE" if digest == CANONICAL_SHA256 else "digest_mismatch"}
    return {"status": "OK", "config_digest": expected}


def evaluate_pinned_config(repo: str | Path, commit: str) -> dict:
    """Recompute the plan-B manifest from a commit's blobs."""
    manifest = {
        "parameters_canonical_sha256": _canonical_sha(repo, commit),
        "policy_config_digest": _component_digest(repo, commit, POLICY_PATHS),
        "protection_settings_digest": _component_digest(repo, commit, PROTECTION_PATHS),
        "rule_version": _rule_version(repo, commit),
    }
    raw = config_manifest_bytes(manifest)
    digest = digest_config_manifest(manifest)
    return {
        "status": "OK",
        "config_manifest": manifest,
        "config_manifest_canonical": raw.decode("utf-8"),
        "config_digest": digest,
    }
