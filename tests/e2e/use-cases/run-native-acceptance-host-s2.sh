#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
REPORT_DIR="${1:-${ROOT_DIR}/target/splendor-e2e/corr-001-native}"
RUNTIME_DIR="${ROOT_DIR}/target/splendor-e2e/corr-001-runtime"
PROVIDER_AUTH_DIR="${RUNTIME_DIR}/provider-auth"
RUNNER_PROVIDER_AUTH_DIR="${RUNTIME_DIR}/provider-runner-auth"
LOCAL_PROVIDER_AUTH_DIR="${RUNTIME_DIR}/provider-local-auth"
PROVIDER_LOG="${RUNTIME_DIR}/action-provider.log"
HOST_LOG="${RUNTIME_DIR}/acceptance-host.log"
PRODUCTION_LOG="${RUNTIME_DIR}/production-daemon.log"

case "${RUNTIME_DIR}" in
  "${ROOT_DIR}"/target/splendor-e2e/*) ;;
  *) echo "refusing to clean unexpected native runtime path" >&2; exit 1 ;;
esac
rm -rf -- "${RUNTIME_DIR}"
mkdir -p "${RUNTIME_DIR}" "${REPORT_DIR}"

cleanup() {
  if [[ -n "${HOST_PID:-}" ]]; then
    kill "${HOST_PID}" 2>/dev/null || true
    wait "${HOST_PID}" 2>/dev/null || true
  fi
  if [[ -n "${PROVIDER_PID:-}" ]]; then
    kill "${PROVIDER_PID}" 2>/dev/null || true
    wait "${PROVIDER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

wait_for_url() {
  local url="$1"
  local process_id="$2"
  for _ in {1..100}; do
    if python3 - "${url}" <<'PY'
import sys
import urllib.request

url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=1) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception:  # noqa: BLE001 - bounded readiness probe
    raise SystemExit(1)
PY
    then
      return 0
    fi
    if ! kill -0 "${process_id}" 2>/dev/null; then
      echo "service process exited before becoming ready at ${url}" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "service did not become ready at ${url}" >&2
  return 1
}

cargo build \
  -p splendor-acceptance-action-host \
  -p splendor-daemon \
  -p splendorctl
cargo build -p splendor-daemon --example resident_auth_key_tool

PATH="${ROOT_DIR}/target/debug/examples:${PATH}" \
  python3 "${ROOT_DIR}/tests/e2e/use-cases/fixtures/acceptance_provider_auth.py" \
    --provider-out "${PROVIDER_AUTH_DIR}" \
    --runner-out "${RUNNER_PROVIDER_AUTH_DIR}" \
    --local-out "${LOCAL_PROVIDER_AUTH_DIR}" \
    --roles local

if [[ -e "${RUNTIME_DIR}/action-provider.key" ]]; then
  echo "stale legacy provider key survived native runtime cleanup" >&2
  exit 1
fi

export SPLENDOR_ACCEPTANCE_EVIDENCE_CREDENTIAL_FILE="${RUNNER_PROVIDER_AUTH_DIR}/action-provider-evidence-credential.json"
export SPLENDOR_ACCEPTANCE_RECEIPT_PUBLIC_KEY_FILE="${RUNNER_PROVIDER_AUTH_DIR}/receipt-public-key.raw"
export SPLENDOR_ACCEPTANCE_SIGNATURE_VERIFIER="${ROOT_DIR}/target/debug/examples/resident_auth_key_tool"

SPLENDOR_ACCEPTANCE_ONLY=1 \
SPLENDOR_ACCEPTANCE_REQUEST_KEYRING_FILE="${PROVIDER_AUTH_DIR}/action-provider-request-keyring.json" \
SPLENDOR_ACCEPTANCE_EVIDENCE_KEYRING_FILE="${PROVIDER_AUTH_DIR}/action-provider-evidence-keyring.json" \
SPLENDOR_ACCEPTANCE_RECEIPT_SIGNING_KEY_FILE="${PROVIDER_AUTH_DIR}/receipt-signing-key.pk8" \
SPLENDOR_ACCEPTANCE_SIGNER="${ROOT_DIR}/target/debug/examples/resident_auth_key_tool" \
  python3 "${ROOT_DIR}/tests/e2e/use-cases/fixtures/action_provider.py" \
  >"${PROVIDER_LOG}" 2>&1 &
PROVIDER_PID=$!
wait_for_url "http://127.0.0.1:8086/health" "${PROVIDER_PID}"

SPLENDOR_ACCEPTANCE_ONLY=1 \
SPLENDOR_ACCEPTANCE_PROVIDER_ENDPOINT="http://127.0.0.1:8086/actions" \
SPLENDOR_DAEMON_MODE=local_dev \
SPLENDOR_DAEMON_BIND_ADDR=127.0.0.1:8077 \
  "${ROOT_DIR}/target/debug/splendor-daemon" \
  >"${PRODUCTION_LOG}" 2>&1 &
HOST_PID=$!
wait_for_url "http://127.0.0.1:8077/health" "${HOST_PID}"
python3 "${ROOT_DIR}/tests/e2e/use-cases/contract/production_adapterless_probe.py" \
  --root "${ROOT_DIR}" \
  --report-dir "${REPORT_DIR}" \
  --base-url "http://127.0.0.1:8077" \
  --action-provider-url "http://127.0.0.1:8086"
kill "${HOST_PID}"
wait "${HOST_PID}" 2>/dev/null || true
HOST_PID=""

SPLENDOR_ACCEPTANCE_ONLY=1 \
SPLENDOR_ACCEPTANCE_PROVIDER_ENDPOINT="http://127.0.0.1:8086/actions" \
SPLENDOR_ACCEPTANCE_REQUEST_CREDENTIAL_FILE="${LOCAL_PROVIDER_AUTH_DIR}/action-provider-request-credential.json" \
SPLENDOR_ACCEPTANCE_RECEIPT_PUBLIC_KEY_FILE="${LOCAL_PROVIDER_AUTH_DIR}/receipt-public-key.raw" \
SPLENDOR_INSTANCE_ID="00000000-0000-4000-8000-000000000300" \
SPLENDOR_DAEMON_MODE=local_dev \
SPLENDOR_DAEMON_BIND_ADDR=127.0.0.1:8077 \
  "${ROOT_DIR}/target/debug/splendor-acceptance-action-host" \
  >"${HOST_LOG}" 2>&1 &
HOST_PID=$!
wait_for_url "http://127.0.0.1:8077/health" "${HOST_PID}"

python3 "${ROOT_DIR}/tests/e2e/use-cases/scenarios/uc_e2e_s2_management_api/run.py" \
  --root "${ROOT_DIR}" \
  --report-dir "${REPORT_DIR}" \
  --base-url "http://127.0.0.1:8077" \
  --action-provider-url "http://127.0.0.1:8086"

python3 - "${REPORT_DIR}" <<'PY'
import json
import sys
from pathlib import Path

report_dir = Path(sys.argv[1])
production = json.loads(
    (report_dir / "production-adapterless" / "report.json").read_text(encoding="utf-8")
)
scenario = json.loads(
    (report_dir / "artifacts" / "UC-E2E-S2" / "scenario-report.json").read_text(
        encoding="utf-8"
    )
)
production["native_execution_classification"] = "functional_only"
production["docker_role_isolation"] = "not_exercised"
scenario["native_execution_classification"] = "functional_only"
scenario["docker_role_isolation"] = "not_exercised"
(report_dir / "production-adapterless" / "report.json").write_text(
    json.dumps(production, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
(report_dir / "artifacts" / "UC-E2E-S2" / "scenario-report.json").write_text(
    json.dumps(scenario, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
if production.get("status") != "passed":
    raise SystemExit("production adapterless probe did not pass")
if scenario.get("status") != "passed" or scenario.get("blocking_failures"):
    raise SystemExit("native acceptance-host S2 retained report did not pass")
PY
