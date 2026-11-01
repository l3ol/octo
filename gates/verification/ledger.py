"""Single-consumption ledger shared with compare-and-merge."""

from __future__ import annotations

import threading
from typing import Callable


class ConsumptionLedger:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consumed: dict[str, dict] = {}
        self.merges: list[dict] = []

    def is_consumed(self, receipt_id: str) -> bool:
        with self._lock:
            return receipt_id in self._consumed

    def mark_consumed(self, receipt_id: str, record: dict | None = None) -> None:
        with self._lock:
            self._consumed[receipt_id] = record or {"consumed": True, "source": "preexisting"}

    def finalize(
        self,
        *,
        head_ok: bool,
        receipt_id: str,
        record: dict,
        publish: Callable[[], bool],
    ) -> str:
        """Atomic final slot. Publish and consume commit together, or neither does."""
        with self._lock:
            if not head_ok:
                return "head_mismatch"
            if receipt_id in self._consumed:
                return "conflict"
            if not publish():
                return "board_invisible"
            self._consumed[receipt_id] = record
            self.merges.append(record)
            return "merged"
