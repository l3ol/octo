"""Machine-readable task registry shipped with the pinned gates."""

from __future__ import annotations

import json
from pathlib import Path

REGISTRY_PATH = Path(__file__).with_name("registry.json")


def load_registry(path: Path | None = None) -> dict:
    raw = (path or REGISTRY_PATH).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("tasks"), dict):
        raise RuntimeError("task registry is not machine-readable")
    return data
