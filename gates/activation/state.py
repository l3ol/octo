"""Path B state. Defaults closed. Production cannot be enabled."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ActivationState:
    environment: str = "isolated"
    path_b_enabled: bool = False
    emergency_stop: bool = False
    self_closed: bool = False
    kill_line_tripped: bool = False
    kill_line_category: str | None = None
    founder_ids: frozenset = field(default_factory=lambda: frozenset({"founder"}))
    builder_ids: frozenset = field(default_factory=lambda: frozenset({"squad-builder"}))
    acceptance_ids: frozenset = field(default_factory=lambda: frozenset({"independent-reviewer"}))
    shared_write_principals: frozenset = field(default_factory=frozenset)
    gate_version: str = "6.0.0"
    founder_receipt_secret: bytes = b"founder-activation-test-secret"

    def trip_kill(self, category: str) -> None:
        self.kill_line_tripped = True
        self.kill_line_category = category
        self.path_b_enabled = False

    def self_close(self) -> None:
        self.self_closed = True
        self.path_b_enabled = False
