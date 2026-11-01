#!/usr/bin/env bash
# Real harness entry. Arguments are the gates selftest or pytest command.
# A standalone probe is not this argv and is not evidence.
# When the Ops bed script is present it is the authority and is exec'd unchanged.
set -euo pipefail
OPS_ENTER=/home/box/ops-isolation/gates/source-qa-isolation-bed-2026-11-01/exec-ctx-unshare-ro/OPS-ENTER-UNSHARE-RO.sh
if [ $# -lt 1 ]; then
  echo "usage: $0 <harness> [args...]" >&2
  exit 64
fi
if [ -f "$OPS_ENTER" ]; then
  export GATES_HOST_ST_RDONLY="$(python3 -c 'import os; print(int(bool(os.statvfs("/").f_flag & os.ST_RDONLY)))')"
  export GATES_HOST_MNT_NS="$(readlink /proc/self/ns/mnt)"
  export GATES_HOST_UID="$(id -u)"
  export GATES_ENTER_VIA=ops-enter
  export GATES_RDONLY_NS=1
  exec bash "$OPS_ENTER" "$@"
fi
if [ "${GATES_RDONLY_NS:-}" != 1 ]; then
  export GATES_HOST_ST_RDONLY="$(python3 -c 'import os; print(int(bool(os.statvfs("/").f_flag & os.ST_RDONLY)))')"
  export GATES_HOST_MNT_NS="$(readlink /proc/self/ns/mnt)"
  export GATES_HOST_UID="$(id -u)"
  exec unshare --user --map-root-user --mount --propagation private \
    env GATES_RDONLY_NS=1 PYTHONDONTWRITEBYTECODE=1 bash "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null || true
if [ -n "${GATES_PIN_LOADPATH:-}" ] && [ -e "$GATES_PIN_LOADPATH" ]; then
  mount --bind "$GATES_PIN_LOADPATH" "$GATES_PIN_LOADPATH" || { echo "FAIL: bind" >&2; exit 70; }
  mount -o remount,bind,ro "$GATES_PIN_LOADPATH" || { echo "FAIL: remount,ro" >&2; exit 71; }
  python3 -c 'import os,sys; raise SystemExit(0 if os.statvfs(sys.argv[1]).f_flag & os.ST_RDONLY else 1)' "$GATES_PIN_LOADPATH" \
    || { echo "FAIL: ST_RDONLY not set" >&2; exit 72; }
  export OPS_NS_ST_RDONLY_EXPECTED=1
fi
export GATES_ENTER_VIA=twin
exec "$@"
