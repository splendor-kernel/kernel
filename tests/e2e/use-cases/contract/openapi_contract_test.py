#!/usr/bin/env python3
"""S0 OpenAPI acceptance contract check.

This checker intentionally distinguishes between currently available local daemon
operations and future/fleet/governance/device contract groups. Missing future
groups are reported as blocked/not-yet-covered, not as passing coverage.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


CORE_LOCAL_REQUIRED = {
    "createRun",
    "inspectRun",
    "startRun",
    "pauseRun",
    "resumeRun",
    "stopRun",
    "appendPercept",
    "submitAction",
    "getStateHead",
    "getRunTraces",
    "replayRun",
    "getHealth",
    "getCapabilities",
}

LOCAL_CONTRACT_NOT_YET_COVERED = {
    "getVersion",
    "cancelRun",
    "exportStateSnapshot",
    "importStateSnapshot",
    "exportTraces",
}

FUTURE_GROUPS = {
    "fleet": {
        "registerNode",
        "registerInstance",
        "heartbeatNode",
        "advertiseCapabilities",
        "listNodes",
        "evaluatePlacement",
        "submitWorkOrder",
        "revokeWorkOrder",
        "dispatchWorkOrder",
        "getFleetTelemetry",
        "syncTraceBuffer",
    },
    "messages": {
        "sendMessage",
        "getMessage",
        "listInbox",
        "listOutbox",
        "ackMessage",
        "nackMessage",
        "getMessageCausalGraph",
        "validateMessageSchema",
        "listMessageSchemas",
    },
    "governance": {
        "publishPolicyBundle",
        "revokePolicyBundle",
        "getPolicyStatus",
        "requestApproval",
        "grantApproval",
        "denyApproval",
        "revokeApproval",
        "createCircuitBreaker",
        "clearCircuitBreaker",
        "activateKillSwitch",
        "exportGovernanceAudit",
    },
    "physical_edge": {
        "registerDeviceProfile",
        "getDeviceStatus",
        "getPolicyCacheStatus",
        "submitPhysicalAction",
        "requestOperatorIntervention",
        "grantOperatorIntervention",
        "denyOperatorIntervention",
        "syncDeviceTraceBuffer",
    },
}


def parse_operation_ids(text: str) -> set[str]:
    return set(re.findall(r"^\s*operationId:\s*([A-Za-z0-9_]+)\s*$", text, re.MULTILINE))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openapi", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    openapi_path = Path(args.openapi)
    out_path = Path(args.out)
    text = openapi_path.read_text(encoding="utf-8")
    operation_ids = parse_operation_ids(text)

    failures: list[str] = []
    if "openapi: 3.1.0" not in text:
        failures.append("OpenAPI document is not declared as 3.1.0")

    missing_core = sorted(CORE_LOCAL_REQUIRED - operation_ids)
    if missing_core:
        failures.append(f"Missing current local daemon operation IDs: {', '.join(missing_core)}")

    blocked = []
    local_blocked = sorted(LOCAL_CONTRACT_NOT_YET_COVERED - operation_ids)
    if local_blocked:
        blocked.append(
            {
                "group": "local_daemon_future_contract",
                "status": "blocked_not_yet_covered",
                "missing_operation_ids": local_blocked,
            }
        )

    for group, expected in FUTURE_GROUPS.items():
        missing = sorted(expected - operation_ids)
        present = sorted(expected & operation_ids)
        blocked.append(
            {
                "group": group,
                "status": "covered" if not missing else "blocked_not_yet_covered",
                "present_operation_ids": present,
                "missing_operation_ids": missing,
            }
        )

    replay_schema_mentions_suppression = (
        "side_effects_allowed" in text and "inspect_only" in text and "ReplayRequest" in text
    )
    if not replay_schema_mentions_suppression:
        blocked.append(
            {
                "group": "replay_contract_suppression_fields",
                "status": "blocked_not_yet_covered",
                "missing_fields": ["ReplayRequest.side_effects_allowed"],
                "note": "S0 report schema carries replay suppression fields; daemon OpenAPI must expose them before replay scenarios can pass.",
            }
        )

    physical_forbidden_markers = [
        "set_motor_pwm",
        "disable_firmware_safety",
        "bypass_collision_avoidance",
        "ignore_emergency_stop",
    ]
    physical_schema_status = {
        "forbidden_low_level_actions_marked_in_contract": [
            marker for marker in physical_forbidden_markers if marker in text
        ],
        "status": "blocked_not_yet_executable",
    }

    status = "passed" if not failures else "failed"
    result = {
        "schema_version": "splendor.e2e.contract-status.v1",
        "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "openapi_path": str(openapi_path),
        "openapi_declared_version": "3.1.0" if "openapi: 3.1.0" in text else "unknown",
        "status": status,
        "core_local_required": sorted(CORE_LOCAL_REQUIRED),
        "present_operation_ids": sorted(operation_ids),
        "missing_core_operation_ids": missing_core,
        "blocked_not_yet_covered": blocked,
        "physical_contract_status": physical_schema_status,
        "failures": failures,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
