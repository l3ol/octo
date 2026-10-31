"""Backup and retention. Synthetic data only. Restore only on copy."""
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Dict

def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def create_backup_manifest(src_dir: Path, dest_manifest: Path) -> Dict[str, str]:
    """Create backup pack + per-file SHA-256 manifest."""
    manifest = {}
    for p in src_dir.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(src_dir))
            manifest[rel] = file_sha256(p)
    dest_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest

def restore_to_copy(src_dir: Path, copy_dir: Path, manifest: Dict[str, str]) -> bool:
    """Restore only to a copy. Verify 100% SHA match. Never overwrite live."""
    if copy_dir.exists():
        shutil.rmtree(copy_dir)
    shutil.copytree(src_dir, copy_dir)
    for rel, expected in manifest.items():
        actual = file_sha256(copy_dir / rel)
        if actual != expected:
            return False
    return True

def reject_delete_without_grant(has_founder_grant: bool, is_delete: bool) -> bool:
    """Delete only by Founder Grant. Returns True if rejected."""
    if is_delete and not has_founder_grant:
        return True  # rejected
    return False
