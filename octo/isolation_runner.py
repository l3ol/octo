"""Static bwrap runner contract. This module does not launch a sandbox.

The argv and subprocess arguments mirror tests/fixtures/g2s1/isolation-policy.json.
runtime_pass stays false. The pytest socket stub is not this recipe.
"""

from __future__ import annotations

import subprocess

TMPDIR = "/iso/tmp"


def runner_subprocess_kwargs() -> dict:
    """close_fds, stdin DEVNULL, and no inherited pass_fds."""
    return {
        "close_fds": True,
        "pass_fds": (),
        "stdin": subprocess.DEVNULL,
    }


def bwrap_argv(iso_host_path: str, command: list[str]) -> list[str]:
    """Final hardened recipe. The only ordinary writable bind is /iso."""
    if not iso_host_path or not command:
        raise ValueError("iso host path and command are required")
    return [
        "bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--unshare-pid",
        "--as-pid-1",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--symlink", "usr/bin", "/bin",
        "--ro-bind", "/etc", "/etc",
        "--proc", "/proc",
        "--dev", "/dev",
        "--remount-ro", "/dev",
        "--bind", iso_host_path, "/iso",
        "--setenv", "TMPDIR", TMPDIR,
        "--remount-ro", "/",
        "--chdir", "/iso",
        "--",
        *command,
    ]
