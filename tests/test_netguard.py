"""Builder selftest only. The socket stub is not a deny-egress capability."""
import socket

import pytest

from octo.netguard import NetworkDenied, install


def test_outbound_connect_is_blocked_by_test_stub(monkeypatch):
    install(monkeypatch)
    with pytest.raises(NetworkDenied, match="test stub"):
        socket.create_connection(("203.0.113.1", 9), timeout=0.05)
    with pytest.raises(NetworkDenied, match="test stub"):
        socket.socket().connect(("203.0.113.1", 9))
