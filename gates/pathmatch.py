"""Git-wildmatch subset and repo-relative path normalization.

Separator is `/`. `**/` matches zero or more directories. Matching is
case-sensitive. A pattern with no `/` matches at any directory level.
"""

from __future__ import annotations

import re

_CACHE: dict[str, re.Pattern[str]] = {}


def normalize_repo_path(path: str) -> tuple[str | None, str | None]:
    """Strip one leading `./`. Reject absolute, empty, `.`/`..`, and backslash."""
    if not isinstance(path, str) or path == "":
        return None, "empty"
    if "\\" in path:
        return None, "backslash"
    if path.startswith("/") or _is_drive_absolute(path):
        return None, "absolute"
    if path.startswith("./"):
        path = path[2:]
    if path.startswith("/"):
        return None, "absolute"
    if path == "":
        return None, "empty"
    segments = path.split("/")
    if any(segment == "" for segment in segments):
        return None, "empty_segment"
    if any(segment in {".", ".."} for segment in segments):
        return None, "traversal"
    return path, None


def _is_drive_absolute(path: str) -> bool:
    return len(path) >= 3 and path[0].isalpha() and path[1] == ":" and path[2] == "/"


def _translate(pattern: str) -> str:
    index = 0
    parts: list[str] = []
    while index < len(pattern):
        if pattern.startswith("**/", index):
            parts.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            parts.append(".*")
            index += 2
        elif pattern[index] == "*":
            parts.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            parts.append("[^/]")
            index += 1
        else:
            parts.append(re.escape(pattern[index]))
            index += 1
    return "".join(parts)


def _compile(pattern: str) -> re.Pattern[str]:
    cached = _CACHE.get(pattern)
    if cached is not None:
        return cached
    body = _translate(pattern)
    if "/" in pattern:
        expression = f"^{body}$"
    else:
        expression = f"(?:^|/){body}$"
    compiled = re.compile(expression)
    _CACHE[pattern] = compiled
    return compiled


def wildmatch(pattern: str, path: str) -> bool:
    return _compile(pattern).search(path) is not None


def first_wildmatch(path: str, patterns: tuple[str, ...] | list[str]) -> str | None:
    for pattern in patterns:
        if wildmatch(pattern, path):
            return pattern
    return None


def is_gates_protected(path: str) -> bool:
    """Root `gates/**` only. Case-sensitive."""
    return path == "gates" or path.startswith("gates/")


def is_merge_bypass_path(path: str) -> bool:
    if path == "gates/atomic_merge" or path.startswith("gates/atomic_merge/"):
        return True
    if path == ".git/hooks" or path.startswith(".git/hooks/"):
        return True
    if path == "hooks/compare-and-merge" or path.startswith("hooks/compare-and-merge"):
        return True
    return False
