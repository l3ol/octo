"""P-4 forbidden-path evaluation, including the manifest basename exception."""

from __future__ import annotations

from gates.pathmatch import first_wildmatch, normalize_repo_path
from gates.types import failed, passed


def exception_applies(normalized_path: str) -> bool:
    base = normalized_path.rsplit("/", 1)[-1]
    if "manifest" not in base:
        return False
    return base.endswith(".json") or base.endswith(".sha256")


def evaluate_paths(paths: list[str], patterns: tuple[str, ...] | list[str], rule_digest: str) -> dict:
    rows = []
    rejected = False
    ordered: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        if raw not in seen:
            seen.add(raw)
            ordered.append(raw)
    for raw in ordered:
        norm, err = normalize_repo_path(raw)
        if err:
            rows.append(
                {
                    "normalized_path": None,
                    "raw_path": raw,
                    "matched_pattern": None,
                    "exception_applied": False,
                    "rule_digest": rule_digest,
                    "normalization_error": err,
                }
            )
            rejected = True
            continue
        matched = first_wildmatch(norm, patterns)
        excepted = bool(matched) and exception_applies(norm)
        rows.append(
            {
                "normalized_path": norm,
                "raw_path": raw,
                "matched_pattern": matched,
                "exception_applied": excepted,
                "rule_digest": rule_digest,
                "normalization_error": None,
            }
        )
        if matched and not excepted:
            rejected = True
    if rejected:
        check = failed("forbidden_path", "POLICY_FORBIDDEN_PATH")
    else:
        check = passed("forbidden_path")
    check["paths"] = rows
    return check
