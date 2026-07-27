"""Independent unittest discovery used by the mandatory scanner self-test."""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path


def run_self_test() -> int:
    test_root = Path(__file__).resolve().parents[1] / "tests"
    suite = unittest.defaultTestLoader.discover(
        str(test_root), pattern="test_secret_contract_scanner.py"
    )
    count = suite.countTestCases()
    captured = io.StringIO()
    result = unittest.TextTestRunner(stream=captured, verbosity=2).run(suite)
    if not result.wasSuccessful():
        print(
            f"C03 secret contract scanner self-test: FAIL ({count - len(result.failures) - len(result.errors)}/{count})",
            file=sys.stderr,
        )
        print(captured.getvalue(), file=sys.stderr, end="")
        return 1
    print(f"C03 secret contract scanner self-test: PASS ({count} checks)")
    return 0
