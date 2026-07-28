"""Independent unittest discovery used by the mandatory scanner self-test."""

from __future__ import annotations

import hashlib
import io
import sys
import unittest
from pathlib import Path


EXPECTED_TEST_COUNT = 176
EXPECTED_TEST_MANIFEST_SHA256 = (
    "c479f9f96bb7dd4b233ef6da92b937cb759a16ba47147f44f1e57b03832a61b3"
)
EXPECTED_TEST_MODULE_SHA256 = {
    "test_secret_contract_scanner.py": (
        "22eddebbc667bf6f1fff8283feb092eeb" "17929daa4b855f2cc23cd3ea5b7ac13"
    ),
    "test_secret_contract_scanner_correction3.py": "fd190bd2601a58c4522d2d299c40d7af6def9fbf5386ab9b9cfd2c47296a7afb",
    "test_secret_contract_scanner_correction4.py": "d5e0f8c0062862be5a7426922806bc728a8ade58b1de1ab6e421332e1c4542dc",
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
    discovered = sorted(test_root.rglob("test_*.py"))
    if any(path.parent != test_root for path in discovered):
        return False
    test_modules = [entry.name for entry in discovered]
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
