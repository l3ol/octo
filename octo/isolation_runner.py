"""Hardened bwrap runner. ``apply_hardened_runner`` executes the contract.

The argv and subprocess arguments mirror tests/fixtures/g2s1/isolation-policy.json.
runtime_pass stays false. The pytest socket stub is not this recipe.
"""

from __future__ import annotations

import json
from pathlib import Path
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


def apply_hardened_runner(iso_host_path: str, command: list[str], *, log_path: Path) -> dict:
    """Run one command inside the hardened recipe and append a log line.

    The log is runner evidence. It does not set runtime_pass.
    """
    argv = bwrap_argv(iso_host_path, command)
    kwargs = runner_subprocess_kwargs()
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            **kwargs,
        )
    except FileNotFoundError:
        record = {
            "runtime_pass": False,
            "capability": "CAPABILITY_GAP",
            "returncode": None,
            "argv": argv,
            "close_fds": True,
            "pass_fds": [],
            "stdin": "devnull",
            "error": "BWRAP_MISSING",
        }
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record
    text = completed.stdout.decode("utf-8", errors="replace")
    record = {
        "runtime_pass": False,
        "returncode": completed.returncode,
        "argv": argv,
        "close_fds": True,
        "pass_fds": [],
        "stdin": "devnull",
        "stdout": text,
    }
    if completed.returncode != 0 and "PIDS" not in text:
        record["capability"] = "CAPABILITY_GAP"
        record["error"] = "PROCESS_ISOLATION_UNAVAILABLE"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record
