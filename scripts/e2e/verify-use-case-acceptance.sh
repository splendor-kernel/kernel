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
Usage: bash scripts/e2e/verify-use-case-acceptance.sh [--all|--scenario UC-E2E-S0|--scenario UC-E2E-S1|--scenario UC-E2E-S2|--scenario UC-E2E-S3|--scenario UC-E2E-S4|--scenario UC-E2E-S5|--scenario UC-E2E-S6|--scenario UC-E2E-S7|--scenario UC-E2E-S8|--scenario UC-E2E-S9|--scenario UC-E2E-S10|--contract-only|--anti-drift-only] [--reuse-build] [--inside-compose]

S0 is a static/container-harness gate. S1 is the local governed loop gate. S2 is the management API/client contract gate. S3 is the local multi-agent delegation gate. S4 is the fleet dispatch acceptance gate. S5 is the governance acceptance gate. S6 is the physical/edge safety acceptance gate. S7 is the data-local isolation/artifact gate. S8 is the replay/audit/schema compatibility gate. S9 is the failure injection/fail-closed gate. S10 is the final cross-component journey and runs after its dependencies.
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
if [[ "${MODE}" == "scenario" && "${SCENARIO}" != "UC-E2E-S0" && "${SCENARIO}" != "UC-E2E-S1" && "${SCENARIO}" != "UC-E2E-S2" && "${SCENARIO}" != "UC-E2E-S3" && "${SCENARIO}" != "UC-E2E-S4" && "${SCENARIO}" != "UC-E2E-S5" && "${SCENARIO}" != "UC-E2E-S6" && "${SCENARIO}" != "UC-E2E-S7" && "${SCENARIO}" != "UC-E2E-S8" && "${SCENARIO}" != "UC-E2E-S9" && "${SCENARIO}" != "UC-E2E-S10" ]]; then
  echo "${SCENARIO} is not implemented; use --all to report future scenarios as blocked." >&2
  exit 2
fi

COMMAND_SCENARIO="${SCENARIO:-UC-E2E-S0}"
if [[ "${MODE}" == "all" ]]; then
  COMMAND_SCENARIO="UC-E2E-S0"
fi
mkdir -p "${REPORT_DIR}/artifacts/${COMMAND_SCENARIO}"
COMMAND_LOG="${REPORT_DIR}/artifacts/${COMMAND_SCENARIO}/commands.log"
{
  echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "command=bash scripts/e2e/verify-use-case-acceptance.sh $*"
  echo "mode=${MODE} scenario=${SCENARIO:-all} inside_compose=${INSIDE_COMPOSE} reuse_build=${REUSE_BUILD}"
} >> "${COMMAND_LOG}"
if [[ "${COMMAND_SCENARIO}" != "UC-E2E-S0" ]]; then
  mkdir -p "${REPORT_DIR}/artifacts/UC-E2E-S0"
  {
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "command=bash scripts/e2e/verify-use-case-acceptance.sh $*"
    echo "mode=${MODE} scenario=${SCENARIO:-all} inside_compose=${INSIDE_COMPOSE} reuse_build=${REUSE_BUILD}"
    echo "delegated_command_log=${COMMAND_LOG}"
  } >> "${REPORT_DIR}/artifacts/UC-E2E-S0/commands.log"
fi

COMPOSE_FILE="${ROOT_DIR}/tests/e2e/use-cases/docker-compose.acceptance.yml"
if [[ ( "${MODE}" == "all" || "${MODE}" == "scenario" ) && "${INSIDE_COMPOSE}" == "0" ]]; then
  if [[ "${SPLENDOR_E2E_NO_COMPOSE:-0}" == "1" ]]; then
    echo "SPLENDOR_E2E_NO_COMPOSE cannot be used for full UC-E2E-S0 scenario success; use --contract-only or --anti-drift-only for static gates." >&2
    exit 2
  fi
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose -f "${COMPOSE_FILE}" config >/dev/null
    export SPLENDOR_E2E_SOURCE_REV="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || printf unknown-source-revision)"
    export SPLENDOR_E2E_SCENARIO="${SCENARIO:-UC-E2E-S0}"
    export SPLENDOR_E2E_MODE_ARG="${MODE}"
    SETUP_ARGS=( -f "${COMPOSE_FILE}" --profile setup run --rm )
    if [[ "${REUSE_BUILD}" == "0" ]]; then
      SETUP_ARGS+=( --build )
    fi
    SETUP_ARGS+=( resident-auth-fixture )
    docker compose "${SETUP_ARGS[@]}"
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
    if [[ ( "${MODE}" == "scenario" && ( "${SCENARIO}" == "UC-E2E-S1" || "${SCENARIO}" == "UC-E2E-S8" || "${SCENARIO}" == "UC-E2E-S9" || "${SCENARIO}" == "UC-E2E-S10" ) ) || "${MODE}" == "all" ]]; then
      python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s1_local_loop/run.py" \
        --root "${ROOT_DIR}" \
        --report-dir "${REPORT_DIR}"
    fi
    if [[ ( "${MODE}" == "scenario" && ( "${SCENARIO}" == "UC-E2E-S2" || "${SCENARIO}" == "UC-E2E-S8" || "${SCENARIO}" == "UC-E2E-S10" ) ) || "${MODE}" == "all" ]]; then
      python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s2_management_api/run.py" \
        --root "${ROOT_DIR}" \
        --report-dir "${REPORT_DIR}" \
        --base-url "${SPLENDOR_DAEMON_URL:-http://127.0.0.1:8077}"
    fi
    if [[ ( "${MODE}" == "scenario" && ( "${SCENARIO}" == "UC-E2E-S3" || "${SCENARIO}" == "UC-E2E-S8" || "${SCENARIO}" == "UC-E2E-S10" ) ) || "${MODE}" == "all" ]]; then
      python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s3_multi_agent_delegation/run.py" \
        --root "${ROOT_DIR}" \
        --report-dir "${REPORT_DIR}"
    fi
    if [[ ( "${MODE}" == "scenario" && ( "${SCENARIO}" == "UC-E2E-S4" || "${SCENARIO}" == "UC-E2E-S8" || "${SCENARIO}" == "UC-E2E-S9" || "${SCENARIO}" == "UC-E2E-S10" ) ) || "${MODE}" == "all" ]]; then
      python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s4_fleet_dispatch/run.py" \
        --root "${ROOT_DIR}" \
        --report-dir "${REPORT_DIR}" \
        --manager-url "${SPLENDOR_MANAGER_URL:-http://central-manager:8081}" \
        --vpc-url "${SPLENDOR_VPC_NODE_URL:-http://resident-vpc-node:8092}" \
        --cloud-url "${SPLENDOR_CLOUD_NODE_URL:-http://resident-cloud-node:8091}"
    fi
    if [[ ( "${MODE}" == "scenario" && ( "${SCENARIO}" == "UC-E2E-S5" || "${SCENARIO}" == "UC-E2E-S8" || "${SCENARIO}" == "UC-E2E-S9" || "${SCENARIO}" == "UC-E2E-S10" ) ) || "${MODE}" == "all" ]]; then
      python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s5_governance/run.py" \
        --root "${ROOT_DIR}" \
        --report-dir "${REPORT_DIR}" \
        --base-url "${SPLENDOR_DAEMON_URL:-http://splendor-daemon-local:8080}" \
        --manager-url "${SPLENDOR_MANAGER_URL:-http://central-manager:8081}"
    fi
    if [[ ( "${MODE}" == "scenario" && ( "${SCENARIO}" == "UC-E2E-S6" || "${SCENARIO}" == "UC-E2E-S8" || "${SCENARIO}" == "UC-E2E-S10" ) ) || "${MODE}" == "all" ]]; then
      python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s6_physical_edge/run.py" \
        --root "${ROOT_DIR}" \
        --report-dir "${REPORT_DIR}" \
        --edge-url "${SPLENDOR_EDGE_NODE_URL:-http://resident-edge-node:8093}"
    fi
    if [[ ( "${MODE}" == "scenario" && ( "${SCENARIO}" == "UC-E2E-S7" || "${SCENARIO}" == "UC-E2E-S8" || "${SCENARIO}" == "UC-E2E-S10" ) ) || "${MODE}" == "all" ]]; then
      python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s7_data_isolation_artifacts/run.py" \
        --root "${ROOT_DIR}" \
        --report-dir "${REPORT_DIR}" \
        --manager-url "${SPLENDOR_MANAGER_URL:-http://central-manager:8081}" \
        --vpc-url "${SPLENDOR_VPC_NODE_URL:-http://resident-vpc-node:8092}"
    fi
    if [[ ( "${MODE}" == "scenario" && ( "${SCENARIO}" == "UC-E2E-S8" || "${SCENARIO}" == "UC-E2E-S10" ) ) || "${MODE}" == "all" ]]; then
      python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s8_replay_audit_compat/run.py" \
        --root "${ROOT_DIR}" \
        --report-dir "${REPORT_DIR}" \
        --base-url "${SPLENDOR_DAEMON_URL:-http://splendor-daemon-local:8080}" \
        --vpc-url "${SPLENDOR_VPC_NODE_URL:-http://resident-vpc-node:8092}" \
        --edge-url "${SPLENDOR_EDGE_NODE_URL:-http://resident-edge-node:8093}"
    fi
    if [[ ( "${MODE}" == "scenario" && ( "${SCENARIO}" == "UC-E2E-S9" || "${SCENARIO}" == "UC-E2E-S10" ) ) || "${MODE}" == "all" ]]; then
      python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s9_failure_injection/run.py" \
        --root "${ROOT_DIR}" \
        --report-dir "${REPORT_DIR}" \
        --base-url "${SPLENDOR_DAEMON_URL:-http://splendor-daemon-local:8080}" \
        --manager-url "${SPLENDOR_MANAGER_URL:-http://central-manager:8081}" \
        --vpc-url "${SPLENDOR_VPC_NODE_URL:-http://resident-vpc-node:8092}" \
        --cloud-url "${SPLENDOR_CLOUD_NODE_URL:-http://resident-cloud-node:8091}"
    fi
    if [[ ( "${MODE}" == "scenario" && "${SCENARIO}" == "UC-E2E-S10" ) || "${MODE}" == "all" ]]; then
      python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s10_final_journey/run.py" \
        --root "${ROOT_DIR}" \
        --report-dir "${REPORT_DIR}" \
        --manager-url "${SPLENDOR_MANAGER_URL:-http://central-manager:8081}" \
        --vpc-url "${SPLENDOR_VPC_NODE_URL:-http://resident-vpc-node:8092}" \
        --cloud-url "${SPLENDOR_CLOUD_NODE_URL:-http://resident-cloud-node:8091}" \
        --edge-url "${SPLENDOR_EDGE_NODE_URL:-http://resident-edge-node:8093}" \
        --device-sim-url "${SPLENDOR_DEVICE_SIM_URL:-http://device-sim:8086}"
    fi
    python3 "${ROOT_DIR}/tests/e2e/use-cases/reporting/aggregate_report.py" \
      --root "${ROOT_DIR}" \
      --report-dir "${REPORT_DIR}" \
      --scenario "${SCENARIO:-UC-E2E-S0}" \
      --mode "${MODE}" \
      --compose-file "${COMPOSE_FILE}"
    ;;
esac

echo "Splendor use-case acceptance ${MODE} completed. Report: ${REPORT_DIR}/report.json"
