#!/usr/bin/env python3
"""Isolated bootstrap for the offline C03 repository scanner.

Invoke this file with Python's ``-I`` flag.  The scanner package is loaded from
its exact sibling directory without adding candidate repository directories to
``sys.path``.  A tracked or untracked ``scripts/security/hashlib.py`` (or another
standard-library lookalike) therefore cannot run before the scanner.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Callable


_PACKAGE_NAME = "_splendor_secret_contract_scanner"


def _load_main() -> Callable[[], int]:
    package_root = Path(__file__).resolve().with_name("secret_contract_scanner")
    package_init = package_root / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        _PACKAGE_NAME,
        package_init,
        submodule_search_locations=[str(package_root)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("scanner bootstrap unavailable")
    package = importlib.util.module_from_spec(spec)
    sys.modules[_PACKAGE_NAME] = package
    spec.loader.exec_module(package)
    return importlib.import_module(f"{_PACKAGE_NAME}.cli").main


if __name__ == "__main__":
    raise SystemExit(_load_main()())
