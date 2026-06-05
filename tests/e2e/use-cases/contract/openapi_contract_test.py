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
    "cancelRun",
    "appendPercept",
    "submitAction",
    "getStateHead",
    "getRunTraces",
    "exportTraces",
    "replayRun",
    "getHealth",
    "getVersion",
    "getCapabilities",
}

LOCAL_CONTRACT_NOT_YET_COVERED = {
    "exportStateSnapshot",
    "importStateSnapshot",
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


def operation_blocks(text: str) -> dict[str, str]:
    matches = list(re.finditer(r"^\s*operationId:\s*([A-Za-z0-9_]+)\s*$", text, re.MULTILINE))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        # Include nearby method/path/request/response lines before operationId.
        prefix_start = max(text.rfind("\n  /", 0, start), text.rfind("\n    get:", 0, start), text.rfind("\n    post:", 0, start))
        if prefix_start == -1:
            prefix_start = start
        blocks[match.group(1)] = text[prefix_start:end]
    return blocks


def schema_block(text: str, schema_name: str) -> str:
    marker = f"    {schema_name}:\n"
    start = text.find(marker)
    if start == -1:
        return ""
    next_schema = re.search(r"^    [A-Za-z0-9_]+:\n", text[start + len(marker) :], re.MULTILINE)
    end = start + len(marker) + next_schema.start() if next_schema else len(text)
    return text[start:end]


def require_schema_fields(text: str, schema_name: str, fields: set[str]) -> list[str]:
    block = schema_block(text, schema_name)
    if not block:
        return [f"missing schema {schema_name}"]
    missing = [field for field in sorted(fields) if not re.search(rf"^\s+{re.escape(field)}:\s*", block, re.MULTILINE)]
    return [f"{schema_name}.{field}" for field in missing]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openapi", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    openapi_path = Path(args.openapi)
    out_path = Path(args.out)
    text = openapi_path.read_text(encoding="utf-8")
    operation_ids = parse_operation_ids(text)
    blocks = operation_blocks(text)

    failures: list[str] = []
    if "openapi: 3.1.0" not in text:
        failures.append("OpenAPI document is not declared as 3.1.0")

    missing_core = sorted(CORE_LOCAL_REQUIRED - operation_ids)
    if missing_core:
        failures.append(f"Missing current local daemon operation IDs: {', '.join(missing_core)}")

    mutating_core = {
        "createRun",
        "startRun",
        "pauseRun",
        "resumeRun",
        "stopRun",
        "cancelRun",
        "appendPercept",
        "submitAction",
        "replayRun",
        "exportTraces",
    }
    for op_id in sorted(mutating_core & operation_ids):
        block = blocks.get(op_id, "")
        if "requestBody:" not in block:
            failures.append(f"{op_id} is mutating and must declare requestBody")
        if "'403':" not in block and "403:" not in block:
            failures.append(f"{op_id} must declare fail-closed 403 response")

    for op_id in sorted({"getHealth", "getCapabilities"} & operation_ids):
        block = blocks.get(op_id, "")
        if "'401':" not in block and "401:" not in block:
            failures.append(f"{op_id} must declare missing-caller/local-dev auth response semantics")

    schema_failures: list[str] = []
    schema_failures.extend(
        require_schema_fields(
            text,
            "CallerCredential",
            {"credential_id", "principal", "scopes", "binding", "audience", "expires_at", "revocation"},
        )
    )
    schema_failures.extend(
        require_schema_fields(
            text,
            "WorkOrderEnvelope",
            {
                "work_order_id",
                "tenant_id",
                "agent_id",
                "allowed_actions",
                "allowed_adapters",
                "allowed_permissions",
                "data_refs",
                "quotas",
                "placement",
                "expires_at",
                "revocation",
                "signature",
            },
        )
    )
    schema_failures.extend(require_schema_fields(text, "ReplayRequest", {"credential", "mode", "side_effects_allowed"}))
    schema_failures.extend(
        require_schema_fields(text, "TraceExportRequest", {"credential", "redaction_policy", "start", "end"})
    )
    schema_failures.extend(
        require_schema_fields(text, "VersionResponse", {"daemon_api_version", "compatibility_line", "openapi_version", "local_only", "schema_versions"})
    )
    if schema_failures:
        failures.append("Missing required local contract schema fields: " + ", ".join(schema_failures))

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
        "structural_checks": {
            "mutating_operations_checked": sorted(mutating_core & operation_ids),
            "health_capabilities_auth_semantics_checked": sorted({"getHealth", "getCapabilities"} & operation_ids),
            "schema_fields_checked": ["CallerCredential", "WorkOrderEnvelope", "ReplayRequest"],
        },
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
