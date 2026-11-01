"""Canonical parameter bytes stay verbatim, including the three U+FFFD on line 55."""

from __future__ import annotations

import hashlib
from pathlib import Path

from gates.rules import (
    CANONICAL_BYTES,
    CANONICAL_PATH,
    CANONICAL_SHA256,
    FORBIDDEN_PATTERNS,
    SIZE_LIMIT_BYTES,
    canonical_parameter_bytes,
    load_forbidden_patterns,
)

EXPECTED_PATTERNS = (
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/secrets/**",
    "**/*credential*",
    "**/*secret*",
    "**/id_rsa*",
    "**/*.pem",
    "**/brain/**",
    "**/Brain/**",
    "**/backup-raw/**",
    "**/full-backup/**",
    "**/*.key",
    "**/wallet/**",
    "**/.ssh/**",
    "**/private/**",
    "**/mega/**",
    "**/*backup*.tar*",
    "**/*backup*.zip",
    "**/agent-data/**",
)


def test_canonical_file_bytes_and_semantic_gap():
    data = canonical_parameter_bytes()
    assert len(data) == CANONICAL_BYTES == 4332
    assert hashlib.sha256(data).hexdigest() == CANONICAL_SHA256
    assert Path(CANONICAL_PATH).read_bytes() == data
    line = data.splitlines()[54]
    assert line.count("\ufffd".encode()) == 3


def test_forbidden_patterns_are_the_21_canonical_lines():
    parsed = load_forbidden_patterns()
    assert parsed == EXPECTED_PATTERNS
    assert FORBIDDEN_PATTERNS == EXPECTED_PATTERNS
    assert SIZE_LIMIT_BYTES == 10 * 1024 * 1024
