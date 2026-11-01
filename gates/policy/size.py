"""P-3 tree measurement. Counts every tracked blob, not the diff."""

from __future__ import annotations

import hashlib

from gates.rules import SIZE_LIMIT_BYTES


def git_blob_oid(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def git_tree_sha(entries: list[tuple[str, str]]) -> str:
    payload = b""
    for path, oid in sorted(entries):
        payload += b"100644 " + path.encode("utf-8") + b"\0" + bytes.fromhex(oid)
    header = f"tree {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


def measure_tree(blobs: list[tuple[str, bytes]]) -> dict:
    seen: set[str] = set()
    rows = []
    total = 0
    for path, content in blobs:
        if path in seen:
            raise ValueError(f"duplicate tracked path {path}")
        seen.add(path)
        size = len(content)
        total += size
        rows.append({"path": path, "oid": git_blob_oid(content), "byte_size": size})
    rows.sort(key=lambda row: row["path"])
    entries = [(row["path"], row["oid"]) for row in rows]
    if total > SIZE_LIMIT_BYTES:
        comparison = "gt"
    elif total == SIZE_LIMIT_BYTES:
        comparison = "eq"
    else:
        comparison = "lt"
    return {
        "blobs": rows,
        "total_bytes": total,
        "threshold": SIZE_LIMIT_BYTES,
        "comparison": comparison,
        "rejected": total > SIZE_LIMIT_BYTES,
        "tree_sha": git_tree_sha(entries),
    }
