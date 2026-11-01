"""Pytest stub that refuses outbound socket connects.

This is an application-level monkeypatch only. It is not a process,
container, or sand-egress deny. Ops preflight for network isolation stays
NOT_READY. Nothing here installs a firewall, expands privileges, or writes
a capability report that claims deny-egress.

On-disk isolation in this candidate is Unix file permissions on the
caller-supplied store (for example mode 0o600 records). This stub is a
separate test double and does not upgrade that limit.
"""

from __future__ import annotations

import socket


class NetworkDenied(OSError):
    """The test stub refused an outbound connect."""


def install(monkeypatch) -> None:
    """Replace ``socket.socket.connect`` and ``socket.create_connection``."""

    def blocked_connect(self, address, *args, **kwargs):
        raise NetworkDenied("outbound connect blocked by test stub")

    def blocked_create_connection(address, *args, **kwargs):
        raise NetworkDenied("outbound connect blocked by test stub")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    monkeypatch.setattr(socket, "create_connection", blocked_create_connection)
