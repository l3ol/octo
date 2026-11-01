"""Builder selftest only. The runner contract is not a runtime PASS."""
import json
import subprocess
from pathlib import Path

from octo.isolation_runner import TMPDIR, bwrap_argv, runner_subprocess_kwargs

ROOT = Path(__file__).resolve().parents[1]


def test_runner_contract_matches_isolation_policy():
    policy = json.loads((ROOT / "tests/fixtures/g2s1/isolation-policy.json").read_text(encoding="utf-8"))
    kwargs = runner_subprocess_kwargs()
    assert kwargs["close_fds"] is policy["runner_close_fds"] is True
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["pass_fds"] == tuple(policy["runner_pass_fds"]) == ()
    argv = bwrap_argv("/var/isolation/iso", ["python3", "-c", "print(1)"])
    assert argv[:6] == [
        "bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--unshare-pid",
        "--as-pid-1",
    ]
    dev_at = argv.index("--dev")
    assert argv[dev_at:dev_at + 4] == ["--dev", "/dev", "--remount-ro", "/dev"]
    assert "/iso" in argv
    assert TMPDIR == policy["tmpdir"] == "/iso/tmp"
    assert argv[argv.index("--setenv") + 2] == "/iso/tmp"
    assert policy["writable_binds"] == ["/iso"]
    assert policy["runtime_pass"] is False
    assert policy["full_sandbox"] is False
