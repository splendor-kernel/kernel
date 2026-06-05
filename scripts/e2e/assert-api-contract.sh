#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT_DIR="${SPLENDOR_E2E_REPORT_DIR:-${ROOT_DIR}/target/splendor-e2e/use-case-acceptance}"
mkdir -p "${REPORT_DIR}"

python3 "${ROOT_DIR}/tests/e2e/use-cases/contract/openapi_contract_test.py" \
  --openapi "${ROOT_DIR}/openapi/splendor-runtime-daemon.yaml" \
  --out "${REPORT_DIR}/contract-status.json"
