"""Independent unittest discovery used by the mandatory scanner self-test."""

from __future__ import annotations

import hashlib
import io
import sys
import unittest
from pathlib import Path


EXPECTED_TEST_COUNT = 159
EXPECTED_TEST_MANIFEST_SHA256 = (
    "2e52983060e78f03f47cff6f9418445bb4030429e3cc37aef4803f21213925bf"
)
EXPECTED_TEST_MODULE_SHA256 = {
    "test_secret_contract_scanner.py": (
        "b9f28f220d1229c44858beb829f4781b5" "e4cacbb03e2850e54e874fcb186433b"
    ),
    "test_secret_contract_scanner_correction3.py": "98080757cee9c9722da86223573d36432260145e972a86974c33646fd9d7d19b",
}


def _test_ids(suite: unittest.TestSuite) -> list[str]:
    identities: list[str] = []
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            identities.extend(_test_ids(test))
        else:
            identities.append(test.id())
    return identities


def _test_module_inventory_valid(test_root: Path) -> bool:
    test_modules = sorted(
        entry.name
        for entry in test_root.iterdir()
        if entry.name.startswith("test_") and entry.suffix == ".py"
    )
    return test_modules == sorted(EXPECTED_TEST_MODULE_SHA256) and not any(
        (test_root / name).is_symlink()
        or not (test_root / name).is_file()
        or hashlib.sha256((test_root / name).read_bytes()).hexdigest()
        != EXPECTED_TEST_MODULE_SHA256[name]
        for name in test_modules
    )


def run_self_test(test_root: Path | None = None) -> int:
    test_root = test_root or Path(__file__).resolve().parents[1] / "tests"
    if not _test_module_inventory_valid(test_root):
        print(
            "C03 secret contract scanner self-test: FAIL (module inventory mismatch)",
            file=sys.stderr,
        )
        return 1
    suite = unittest.defaultTestLoader.discover(str(test_root), pattern="test_*.py")
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
