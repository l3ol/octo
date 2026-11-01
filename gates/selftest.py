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
    from gates.readonly_ns import NS_ENV, ensure_harness_namespace

    ensure_harness_namespace()
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
        f"harness_ns={os.environ.get(NS_ENV, '0')}"
    )
    return int(code)


if __name__ == "__main__":
    sys.exit(main())
