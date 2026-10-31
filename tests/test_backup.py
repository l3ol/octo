"""Tests for backup, restore on copy, delete rejection. Synthetic only."""
import pytest
from pathlib import Path
import tempfile
from octo.backup import create_backup_manifest, restore_to_copy, reject_delete_without_grant, file_sha256

def test_backup_manifest_and_restore_copy():
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        src.mkdir()
        (src / "a.txt").write_text("synthetic")
        (src / "b.txt").write_text("data only")
        manifest_path = Path(tmp) / "manifest.json"
        manifest = create_backup_manifest(src, manifest_path)
        assert len(manifest) == 2
        copy = Path(tmp) / "copy"
        assert restore_to_copy(src, copy, manifest) is True
        assert file_sha256(copy / "a.txt") == manifest["a.txt"]

def test_delete_rejected_without_grant():
    assert reject_delete_without_grant(has_founder_grant=False, is_delete=True) is True
    assert reject_delete_without_grant(has_founder_grant=True, is_delete=True) is False
