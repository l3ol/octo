"""Builder selftest runner. STACK_OK_BUILDER_EVIDENCE only — not independent acceptance."""

from __future__ import annotations

import os
import sys


class _Count:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def pytest_runtest_logreport(self, report):
        if report.when != "call":
            return
        if report.passed:
            self.passed += 1
        elif report.failed:
            self.failed += 1


def main(argv: list[str] | None = None) -> int:
    from gates.readonly_ns import ensure_harness_namespace, harness_ns_label

    ensure_harness_namespace()
    marker = os.environ.get("GATES_CI_MARKER")
    if marker:
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("pytest_entered=1\n")
    import pytest

    counter = _Count()
    args = ["-q", "--tb=line", "tests/gates", "tests/test_models.py", "tests/test_backup.py"]
    if argv:
        args.extend(argv)
    code = pytest.main(args, plugins=[counter])
    print(
        "STACK_OK_BUILDER_EVIDENCE "
        f"command='PYTHONPATH=. python -m gates.selftest' "
        f"exit={code} passed={counter.passed} failed={counter.failed} "
        "independent_acceptance=false runtime_pass=false "
        f"harness_ns={harness_ns_label()}"
    )
    return int(code)


if __name__ == "__main__":
    sys.exit(main())
