"""Git candidate identity is separate from the M0 file-manifest digest.

G2, G3, N9, and N11 call ``git_candidate_sha`` and record ``tree_sha``.
Both are exactly 40 lowercase hex characters. ``file_digest`` is the legacy
64-hex digest. ``models.compute_candidate_sha`` and ``validate_prd_record``
stay in that legacy object domain and must not be used to accept a Git commit.
"""

from __future__ import annotations

import re

from octo.objects import sha256

_GIT = re.compile(r"[0-9a-f]{40}")


def git_candidate_sha(value: str) -> str:
    """Accept a Git commit SHA. Reject the 64-hex file-manifest digest."""
    if not isinstance(value, str) or _GIT.fullmatch(value) is None:
        raise ValueError("git_candidate_sha must be exactly 40 lowercase hex")
    return value


def tree_sha(value: str) -> str:
    """Accept a Git tree SHA. It is recorded beside ``git_candidate_sha``."""
    if not isinstance(value, str) or _GIT.fullmatch(value) is None:
        raise ValueError("tree_sha must be exactly 40 lowercase hex")
    return value


def file_digest(value: str) -> str:
    """Legacy M0 file-manifest digest: exactly 64 lowercase hex."""
    return sha256(value)
