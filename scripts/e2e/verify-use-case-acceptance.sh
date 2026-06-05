#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT_DIR="${SPLENDOR_E2E_REPORT_DIR:-${ROOT_DIR}/target/splendor-e2e/use-case-acceptance}"
SCENARIO=""
MODE="scenario"
INSIDE_COMPOSE=0
REUSE_BUILD=0

usage() {
  cat <<'USAGE'
Usage: bash scripts/e2e/verify-use-case-acceptance.sh [--all|--scenario UC-E2E-S0|--contract-only|--anti-drift-only] [--reuse-build] [--inside-compose]

S0 is a static/container-harness gate. Later scenarios intentionally report blocked/not-yet-covered until implemented.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) MODE="all"; shift ;;
    --scenario) MODE="scenario"; SCENARIO="${2:-}"; shift 2 ;;
    --contract-only) MODE="contract"; shift ;;
    --anti-drift-only) MODE="anti_drift"; shift ;;
    --reuse-build) REUSE_BUILD=1; shift ;;
    --inside-compose) INSIDE_COMPOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "${MODE}" == "scenario" && -z "${SCENARIO}" ]]; then
  SCENARIO="UC-E2E-S0"
fi
if [[ "${MODE}" == "scenario" && "${SCENARIO}" != "UC-E2E-S0" ]]; then
  echo "${SCENARIO} is not implemented by S0; use --all to report future scenarios as blocked." >&2
  exit 2
fi

mkdir -p "${REPORT_DIR}/artifacts/UC-E2E-S0"
COMMAND_LOG="${REPORT_DIR}/artifacts/UC-E2E-S0/commands.log"
{
  echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "command=bash scripts/e2e/verify-use-case-acceptance.sh $*"
  echo "mode=${MODE} scenario=${SCENARIO:-all} inside_compose=${INSIDE_COMPOSE} reuse_build=${REUSE_BUILD}"
} >> "${COMMAND_LOG}"

COMPOSE_FILE="${ROOT_DIR}/tests/e2e/use-cases/docker-compose.acceptance.yml"
if [[ ( "${MODE}" == "all" || "${MODE}" == "scenario" ) && "${INSIDE_COMPOSE}" == "0" ]]; then
  if [[ "${SPLENDOR_E2E_NO_COMPOSE:-0}" == "1" ]]; then
    echo "SPLENDOR_E2E_NO_COMPOSE cannot be used for full UC-E2E-S0 scenario success; use --contract-only or --anti-drift-only for static gates." >&2
    exit 2
  fi
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -f "${COMPOSE_FILE}" config >/dev/null
    export SPLENDOR_E2E_SOURCE_REV="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || printf unknown-source-revision)"
    COMPOSE_ARGS=( -f "${COMPOSE_FILE}" up --abort-on-container-exit --exit-code-from e2e-runner )
    if [[ "${REUSE_BUILD}" == "0" ]]; then
      COMPOSE_ARGS+=( --build )
    fi
    docker compose "${COMPOSE_ARGS[@]}"
    exit $?
  fi
  echo "Docker compose is required for UC-E2E-S0 scenario success; use --contract-only or --anti-drift-only for static gates." >&2
  exit 2
fi

run_contract() {
  bash "${ROOT_DIR}/scripts/e2e/assert-api-contract.sh"
}

run_anti_drift() {
  bash "${ROOT_DIR}/scripts/e2e/assert-no-product-drift.sh" --self-test
}

case "${MODE}" in
  contract)
    run_contract
    ;;
  anti_drift)
    run_anti_drift
    ;;
  scenario|all)
    run_anti_drift
    run_contract
    python3 "${ROOT_DIR}/tests/e2e/use-cases/fixtures/fixture_seed.py" \
      --seed-file "${ROOT_DIR}/tests/e2e/use-cases/fixtures/seed.json" \
      --out "${REPORT_DIR}/artifacts/UC-E2E-S0/fixture-seed.json"
    python3 "${ROOT_DIR}/tests/e2e/use-cases/contract/public_boundary_probe.py" \
      --base-url "${SPLENDOR_DAEMON_URL:-http://127.0.0.1:8077}" \
      --out "${REPORT_DIR}/artifacts/UC-E2E-S0/public-boundary.json"
    python3 "${ROOT_DIR}/tests/e2e/use-cases/reporting/aggregate_report.py" \
      --root "${ROOT_DIR}" \
      --report-dir "${REPORT_DIR}" \
      --scenario "UC-E2E-S0" \
      --mode "${MODE}" \
      --compose-file "${COMPOSE_FILE}"
    ;;
esac

echo "Splendor use-case acceptance ${MODE} completed. Report: ${REPORT_DIR}/report.json"
