"""Run the whole gate harness inside one unprivileged user and mount namespace.

Host-global ST_RDONLY is not a frozen gate (NO_HOST_GLOBAL_ST_RDONLY_GATE).
The pin checkout and load path are bind-mounted read-only in this namespace.
chmod and mode bits are not treated as ST_RDONLY. This is not a PASS and not a G4 seal.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

NS_ENV = "GATES_RDONLY_NS"
HOST_ST_ENV = "GATES_HOST_ST_RDONLY"
HOST_MNT_ENV = "GATES_HOST_MNT_NS"
HOST_UID_ENV = "GATES_HOST_UID"
_SEALED = False
_CAP_SYS_ADMIN = 1 << 21
_PR_SET_SECUREBITS = 28
# NOROOT | NOROOT_LOCKED | NO_SETUID_FIXUP | NO_SETUID_FIXUP_LOCKED
_NOROOT_LOCKED = 1 | 2 | 4 | 8
_CAP_VERSION_3 = 0x20080522
_SYSCALLS = {
    "x86_64": (125, 126),
    "aarch64": (90, 91),
}


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _syscalls() -> tuple[int, int]:
    machine = platform.machine()
    if machine not in _SYSCALLS:
        raise OSError(f"no capget/capset numbers for {machine}")
    return _SYSCALLS[machine]


def harness_ns_label(env: dict[str, str] | None = None) -> str:
    """STACK_OK harness_ns. Twin sets GATES_RDONLY_NS; OPS-ENTER sets OPS_NS_ST_RDONLY_EXPECTED."""
    source = os.environ if env is None else env
    if source.get(NS_ENV) == "1" or source.get("OPS_NS_ST_RDONLY_EXPECTED") == "1":
        return "1"
    return "0"


def namespace_active() -> bool:
    return harness_ns_label() == "1"


def classify_harness_label(*, harness_ns: str, independent_ns_proven: bool, runtime_pass: bool) -> str:
    """Label versus namespace evidence. Never a PASS and never a containment gap."""
    if runtime_pass:
        return "PREMATURE_PASS"
    if harness_ns == "0" and independent_ns_proven:
        return "LABEL_MISREPORT"
    return "LABEL_ALIGNED"


def classify_ci_uid_map(text: str) -> str:
    """GitHub runner uid_map denial is an environment boundary, not this label bug."""
    if "uid_map" in text and "Operation not permitted" in text:
        return "ENV_BOUNDARY"
    return "OTHER"


def _mnt_ns() -> str:
    return os.readlink("/proc/self/ns/mnt")


def _is_rdonly(path: Path) -> bool:
    return bool(os.statvfs(path).f_flag & os.ST_RDONLY)


def _status_caps() -> dict[str, str]:
    found: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if line.startswith(("CapEff:", "CapPrm:", "Uid:")):
            key, value = line.split(":", 1)
            found[key] = value.strip()
    return found


def _has_sys_admin(cap_hex: str) -> bool:
    return bool(int(cap_hex, 16) & _CAP_SYS_ADMIN)


def harness_argv() -> list[str]:
    """Argv of this process, shaped so enter_exec_ctx.sh execs the real harness."""
    name = Path(sys.argv[0]).name if sys.argv else ""
    if "selftest" in name:
        return [sys.executable, "-m", "gates.selftest", *sys.argv[1:]]
    if "pytest" in name or name == "__main__.py":
        return [sys.executable, "-m", "pytest", *sys.argv[1:]]
    return [sys.executable, *sys.argv]


def ensure_harness_namespace() -> None:
    """Replace this process with enter_exec_ctx.sh <this harness>.

    The Ops bed script is used when it is installed. A probe is never the argv.
    Failure to enter exits and is not reported as ST_RDONLY.
    """
    if namespace_active():
        host_mnt = os.environ.get(HOST_MNT_ENV)
        if host_mnt and _mnt_ns() == host_mnt:
            raise SystemExit("harness namespace flag is set but the mount namespace is the host")
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        sys.dont_write_bytecode = True
        if os.environ.get("GATES_RDONLY_ANNOUNCED") != "1":
            os.environ["GATES_RDONLY_ANNOUNCED"] = "1"
            print(
                "GATES_HARNESS_NS"
                f" uid={os.getuid()}"
                f" mnt={_mnt_ns()}"
                f" host_uid={os.environ.get(HOST_UID_ENV)}"
                f" host_mnt={os.environ.get(HOST_MNT_ENV)}"
                f" host_ST_RDONLY={os.environ.get(HOST_ST_ENV)}"
                f" ns_root_ST_RDONLY={int(_is_rdonly(Path('/')))}",
                file=sys.stderr,
                flush=True,
            )
        return
    script = Path(__file__).resolve().parent / "enter_exec_ctx.sh"
    command = [str(script), *harness_argv()]
    try:
        os.execv(script, command)
    except OSError as exc:
        raise SystemExit(f"harness did not enter the mount namespace: {exc}") from exc


def _run_mount(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, capture_output=True)


def protect_readonly(path: Path) -> dict:
    """Bind-mount path onto itself and remount it read-only. Requires the harness namespace."""
    if not namespace_active():
        raise RuntimeError("ST_RDONLY refused: pytest is not inside the harness mount namespace")
    if _mnt_ns() == os.environ.get(HOST_MNT_ENV):
        raise RuntimeError("ST_RDONLY refused: mount namespace is the host")
    if _SEALED:
        raise RuntimeError("ST_RDONLY mount refused after capabilities were sealed")
    target = Path(path).resolve()
    if not target.exists():
        raise RuntimeError(f"ST_RDONLY refused: missing path {target}")
    bind = _run_mount(["mount", "--bind", str(target), str(target)])
    if bind.returncode != 0:
        raise RuntimeError(bind.stderr.decode()[-400:])
    remount = _run_mount(["mount", "-o", "remount,bind,ro", str(target)])
    if remount.returncode != 0:
        raise RuntimeError(remount.stderr.decode()[-400:])
    if not _is_rdonly(target):
        raise RuntimeError("remount did not set ST_RDONLY")
    write_errno = _write_errno(target)
    if write_errno is None:
        raise RuntimeError("write succeeded on a path claimed ST_RDONLY")
    delete_errno = _delete_errno(target)
    if target.is_dir() and delete_errno is None:
        raise RuntimeError("unlink succeeded on a path claimed ST_RDONLY")
    return {
        "path": str(target),
        "st_rdonly": True,
        "write_errno": write_errno,
        "delete_errno": delete_errno,
        "mnt_ns": _mnt_ns(),
        "uid": os.getuid(),
    }


def _write_errno(target: Path) -> int | None:
    probe = target / ".gates-rdonly-write-probe" if target.is_dir() else target
    try:
        if target.is_dir():
            probe.write_text("nope", encoding="utf-8")
        else:
            with probe.open("ab") as handle:
                handle.write(b"nope")
    except OSError as exc:
        return exc.errno
    return None


def _delete_errno(target: Path) -> int | None:
    if not target.is_dir():
        return None
    victim = next((item for item in target.rglob("*") if item.is_file()), None)
    if victim is None:
        return None
    try:
        victim.unlink()
    except OSError as exc:
        return exc.errno
    return None


def _drop_sys_admin() -> dict[str, str]:
    global _SEALED
    libc = _libc()
    if libc.prctl(_PR_SET_SECUREBITS, _NOROOT_LOCKED, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl")
    capget, capset = _syscalls()
    header = _CapHeader(_CAP_VERSION_3, 0)
    data = (_CapData * 2)()
    if libc.syscall(capget, ctypes.byref(header), data) != 0:
        raise OSError(ctypes.get_errno(), "capget")
    for item in data:
        item.inheritable = 0
    data[0].effective &= ~_CAP_SYS_ADMIN
    data[0].permitted &= ~_CAP_SYS_ADMIN
    if libc.syscall(capset, ctypes.byref(header), data) != 0:
        raise OSError(ctypes.get_errno(), "capset")
    _SEALED = True
    return _status_caps()


def seal_against_remount(path: Path) -> dict:
    """Drop CAP_SYS_ADMIN and prove this process and a child cannot remount read-write."""
    target = Path(path).resolve()
    if not _is_rdonly(target):
        raise RuntimeError("seal requested before ST_RDONLY")
    parent_caps = _drop_sys_admin()
    parent_remount = _run_mount(["mount", "-o", "remount,bind,rw", str(target)])
    child = subprocess.run(
        [sys.executable, "-m", "gates.readonly_ns", "prove", str(target)],
        capture_output=True,
        text=True,
    )
    if child.returncode != 0:
        raise RuntimeError(child.stderr[-500:] or "child prove failed")
    payload = json.loads(child.stdout)
    if parent_remount.returncode == 0 or payload["remount_rc"] == 0:
        raise RuntimeError("remount read-write was not blocked")
    if not payload["st_rdonly_after"] or not _is_rdonly(target):
        raise RuntimeError("path lost ST_RDONLY")
    if payload["mnt_ns"] != _mnt_ns():
        raise RuntimeError("child left the harness mount namespace")
    if _has_sys_admin(parent_caps["CapEff"]) or payload["has_sys_admin"]:
        raise RuntimeError("CAP_SYS_ADMIN still effective")
    return {
        "parent_mnt_ns": _mnt_ns(),
        "parent_uid": os.getuid(),
        "parent_caps": parent_caps,
        "parent_remount_rc": parent_remount.returncode,
        "parent_has_sys_admin": _has_sys_admin(parent_caps["CapEff"]),
        "child_mnt_ns": payload["mnt_ns"],
        "child_uid": payload["uid"],
        "child_caps": payload["caps"],
        "child_remount_rc": payload["remount_rc"],
        "child_has_sys_admin": payload["has_sys_admin"],
        "st_rdonly_after": True,
        "host_mnt_ns": os.environ.get(HOST_MNT_ENV),
        "host_ST_RDONLY": os.environ.get(HOST_ST_ENV),
    }


def _prove(path: str) -> int:
    target = Path(path)
    remount = _run_mount(["mount", "-o", "remount,bind,rw", str(target)])
    write_errno = _write_errno(target)
    caps = _status_caps()
    report = {
        "uid": os.getuid(),
        "mnt_ns": _mnt_ns(),
        "caps": caps,
        "has_sys_admin": _has_sys_admin(caps.get("CapEff", "0")),
        "remount_rc": remount.returncode,
        "st_rdonly_after": _is_rdonly(target),
        "write_errno": write_errno,
    }
    print(json.dumps(report, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["prove"] and len(args) == 2:
        return _prove(args[1])
    ensure_harness_namespace()
    return 0


if __name__ == "__main__":
    sys.exit(main())
