#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT_DIR="${SPLENDOR_E2E_REPORT_DIR:-${ROOT_DIR}/target/splendor-e2e/use-case-acceptance}"
mkdir -p "${REPORT_DIR}"

python3 "${ROOT_DIR}/tests/e2e/use-cases/anti_drift/scan.py" \
  --root "${ROOT_DIR}" \
  --out "${REPORT_DIR}/anti-drift-results.json" \
  "$@"
