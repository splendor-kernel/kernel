"""Independent unittest discovery used by the mandatory scanner self-test."""

from __future__ import annotations

import hashlib
import io
import sys
import unittest
from pathlib import Path


EXPECTED_TEST_COUNT = 141
EXPECTED_TEST_MANIFEST_SHA256 = (
    "26aad19b08a2f5d32c8ef8c8f51f923bb2ac9661ce399040a60e72d630852cf6"
)


def _test_ids(suite: unittest.TestSuite) -> list[str]:
    identities: list[str] = []
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            identities.extend(_test_ids(test))
        else:
            identities.append(test.id())
    return identities


def run_self_test() -> int:
    test_root = Path(__file__).resolve().parents[1] / "tests"
    suite = unittest.defaultTestLoader.discover(
        str(test_root), pattern="test_secret_contract_scanner.py"
    )
    identities = sorted(_test_ids(suite))
    count = len(identities)
    manifest = hashlib.sha256("\n".join(identities).encode("utf-8")).hexdigest()
    if (
        count != EXPECTED_TEST_COUNT
        or len(set(identities)) != count
        or manifest != EXPECTED_TEST_MANIFEST_SHA256
    ):
        print(
            "C03 secret contract scanner self-test: FAIL (manifest mismatch)",
            file=sys.stderr,
        )
        return 1
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
