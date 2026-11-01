"""Every acceptance-map path must import to a real function."""

from __future__ import annotations

import importlib
import re
from pathlib import Path


def test_acceptance_map_paths_are_real_functions():
    text = Path("gates/acceptance_item_map.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| ([A-Z]-\d+) \|", text, flags=re.MULTILINE)
    assert len(rows) == 42
    assert "PLACEHOLDER" not in text
    paths = re.findall(r"`(gates/[^`]+)::([^`]+)`", text)
    assert len(paths) == 42
    for file_path, func_name in paths:
        module_name = file_path[:-3].replace("/", ".")
        module = importlib.import_module(module_name)
        assert callable(getattr(module, func_name)), f"{module_name}.{func_name}"
