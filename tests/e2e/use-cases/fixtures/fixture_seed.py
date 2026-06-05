#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def canonical_digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed-file", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    seed = json.loads(Path(args.seed_file).read_text(encoding="utf-8"))
    seed["deterministic_digest"] = canonical_digest(seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(seed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "out": str(out), "digest": seed["deterministic_digest"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
