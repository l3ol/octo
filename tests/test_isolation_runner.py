"""Builder selftest only. The runner contract is not a runtime PASS."""
import json
import subprocess
from pathlib import Path

from octo.isolation_runner import TMPDIR, apply_hardened_runner, bwrap_argv, runner_subprocess_kwargs

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


def test_hardened_runner_applies_proc_and_dev_contract(tmp_path):
    iso = tmp_path / "iso"
    (iso / "tmp").mkdir(parents=True)
    log_path = tmp_path / "runner.log"
    probe = (
        "import os\n"
        "from pathlib import Path\n"
        "pids = sorted((p.name for p in Path('/proc').iterdir() if p.name.isdigit()), key=int)\n"
        "print('PIDS', ','.join(pids))\n"
        "try:\n"
        "    open('/dev/OOB_WRITE', 'w').write('x')\n"
        "    print('DEV_WRITE OK')\n"
        "except OSError as exc:\n"
        "    print('DEV_WRITE', exc.errno)\n"
        "Path('/iso/tmp').mkdir(parents=True, exist_ok=True)\n"
        "Path('/iso/tmp/probe.txt').write_text('ok', encoding='utf-8')\n"
        "print('ISO_WRITE OK')\n"
    )
    result = apply_hardened_runner(str(iso), ["/usr/bin/python3", "-c", probe], log_path=log_path)
    assert result["runtime_pass"] is False
    assert result["returncode"] == 0, result["stdout"]
    assert "PIDS 1" in result["stdout"]
    assert "DEV_WRITE 30" in result["stdout"]
    assert "ISO_WRITE OK" in result["stdout"]
    assert (iso / "tmp" / "probe.txt").read_text(encoding="utf-8") == "ok"
    logged = log_path.read_text(encoding="utf-8")
    assert "bwrap" in logged
    assert "\"runtime_pass\": false" in logged
