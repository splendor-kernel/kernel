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
    "revokeApprovalReceipt",
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
        "heartbeatInstance",
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

S4_MANAGER_RESPONSE_REFS = {
    "getFleetTelemetry": "FleetTelemetrySnapshot",
    "evaluatePlacement": "PlacementDecision",
    "dispatchWorkOrder": "DispatchReport",
    "sendMessage": "MessageStatusReport",
    "getMessage": "MessageStatusReport",
    "syncTraceBuffer": "TraceSyncReport",
    "exportStateSnapshot": "ExportStateSnapshotResponse",
    "importStateSnapshot": "ImportStateSnapshotResponse",
}

MESSAGE_RESPONSE_REFS = {
    "sendMessage": "MessageStatusReport",
    "getMessage": "MessageStatusReport",
    "ackMessage": "MessageStatusReport",
    "nackMessage": "MessageStatusReport",
    "listInbox": "MessageListResponse",
    "listOutbox": "MessageListResponse",
    "getMessageCausalGraph": "MessageCausalGraphResponse",
    "validateMessageSchema": "MessageSchemaValidationReport",
    "listMessageSchemas": "MessageSchemaListResponse",
}

MESSAGE_REQUEST_REFS = {
    "sendMessage": "SendMessageRequest",
    "getMessage": "MessageReadRequest",
    "ackMessage": "MessageDeliveryUpdateRequest",
    "nackMessage": "MessageDeliveryUpdateRequest",
    "listInbox": "MessageReadRequest",
    "listOutbox": "MessageReadRequest",
    "getMessageCausalGraph": "MessageReadRequest",
    "validateMessageSchema": "MessageSchemaValidationRequest",
    "listMessageSchemas": "ManagerReadRequest",
}

S6_PHYSICAL_RESPONSE_REFS = {
    "registerDeviceProfile": "RegisterDeviceProfileResponse",
    "getDeviceStatus": "DeviceRuntimeProfile",
    "getPolicyCacheStatus": "DevicePolicyCacheStatus",
    "submitPhysicalAction": "ActionOutcome",
    "requestOperatorIntervention": "OperatorInterventionRecord",
    "grantOperatorIntervention": "OperatorInterventionRecord",
    "denyOperatorIntervention": "OperatorInterventionRecord",
    "syncDeviceTraceBuffer": "DeviceTraceBufferSyncResponse",
}

S6_PHYSICAL_REQUEST_REFS = {
    "registerDeviceProfile": "RegisterDeviceProfileRequest",
    "submitPhysicalAction": "SubmitPhysicalActionRequest",
    "requestOperatorIntervention": "OperatorInterventionRequest",
    "grantOperatorIntervention": "OperatorDecisionRequest",
    "denyOperatorIntervention": "OperatorDecisionRequest",
    "syncDeviceTraceBuffer": "DeviceTraceBufferSyncRequest",
}

RESIDENT_DAEMON_OPERATIONS = CORE_LOCAL_REQUIRED | LOCAL_CONTRACT_NOT_YET_COVERED | FUTURE_GROUPS["physical_edge"]


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


def schema_property_fields(text: str, schema_name: str) -> set[str]:
    return set(
        re.findall(
            r"^        ([a-z][A-Za-z0-9_]*):\s*",
            schema_block(text, schema_name),
            re.MULTILINE,
        )
    )


def require_exact_schema_fields(text: str, schema_name: str, fields: set[str]) -> list[str]:
    actual = schema_property_fields(text, schema_name)
    failures = [
        f"{schema_name}.{field}"
        for field in sorted(fields - actual)
    ]
    failures.extend(
        f"{schema_name}.{field}_unexpected"
        for field in sorted(actual - fields)
    )
    return failures


def require_non_null_authority_fields(text: str, schema_name: str) -> list[str]:
    block = schema_block(text, schema_name)
    if not block:
        return [f"missing schema {schema_name}"]
    failures: list[str] = []
    for field in ("credential", "audit_attribution"):
        field_match = re.search(rf"^\s+{field}:\s*(.*)$", block, re.MULTILINE)
        if not field_match:
            failures.append(f"{schema_name}.{field}")
            continue
        inline = field_match.group(1)
        next_field = re.search(r"^\s{8}[A-Za-z0-9_]+:\s*", block[field_match.end() :], re.MULTILINE)
        field_block = inline + "\n" + (block[field_match.end() : field_match.end() + next_field.start()] if next_field else block[field_match.end() :])
        if "type: 'null'" in field_block or "type: [" in field_block and "'null'" in field_block:
            failures.append(f"{schema_name}.{field}_allows_null")
        expected_ref = "CallerCredential" if field == "credential" else "AuditAttribution"
        if f"#/components/schemas/{expected_ref}" not in field_block:
            failures.append(f"{schema_name}.{field}_missing_ref")
    return failures


def require_schema_required_fields(text: str, schema_name: str, fields: set[str]) -> list[str]:
    block = schema_block(text, schema_name)
    if not block:
        return [f"missing schema {schema_name}"]
    matches = re.findall(r"required:\s*\[([^\]]+)\]", block)
    required_fields = set()
    for match in matches:
        required_fields.update(item.strip().strip("'\"") for item in match.split(","))
    missing = sorted(field for field in fields if field not in required_fields)
    return [f"{schema_name}.{field}_not_required" for field in missing]


def require_exact_schema_required_fields(text: str, schema_name: str, fields: set[str]) -> list[str]:
    block = schema_block(text, schema_name)
    if not block:
        return [f"missing schema {schema_name}"]
    match = re.search(r"^      required:\s*\[([^\]]*)\]\s*$", block, re.MULTILINE)
    if not match:
        return [f"{schema_name}.required_fields_missing"]
    actual = {
        item.strip().strip("'\"")
        for item in match.group(1).split(",")
        if item.strip()
    }
    failures = [
        f"{schema_name}.{field}_not_required"
        for field in sorted(fields - actual)
    ]
    failures.extend(
        f"{schema_name}.{field}_unexpected_required"
        for field in sorted(actual - fields)
    )
    return failures


def require_closed_schema(text: str, schema_name: str) -> list[str]:
    block = schema_block(text, schema_name)
    if not block:
        return [f"missing schema {schema_name}"]
    if not re.search(r"^\s+additionalProperties:\s*false\s*$", block, re.MULTILINE):
        return [f"{schema_name}.additionalProperties_not_false"]
    return []


def require_non_null_fields(text: str, schema_name: str, fields: set[str]) -> list[str]:
    block = schema_block(text, schema_name)
    if not block:
        return [f"missing schema {schema_name}"]
    failures: list[str] = []
    for field in sorted(fields):
        field_match = re.search(rf"^\s+{re.escape(field)}:\s*(.*)$", block, re.MULTILINE)
        if not field_match:
            failures.append(f"{schema_name}.{field}")
            continue
        inline = field_match.group(1)
        next_field = re.search(r"^\s{12}[A-Za-z0-9_]+:\s*", block[field_match.end() :], re.MULTILINE)
        field_block = inline + "\n" + (block[field_match.end() : field_match.end() + next_field.start()] if next_field else block[field_match.end() :])
        if "'null'" in field_block or '"null"' in field_block or "type: [" in field_block:
            failures.append(f"{schema_name}.{field}_allows_null")
    return failures


def require_operation_response_ref(blocks: dict[str, str], op_id: str, schema_name: str) -> list[str]:
    block = blocks.get(op_id, "")
    if not block:
        return [f"missing operation {op_id}"]
    if "'200':" not in block and "200:" not in block:
        return [f"{op_id}.missing_200_response"]
    if f"#/components/schemas/{schema_name}" not in block:
        return [f"{op_id}.200_missing_{schema_name}_ref"]
    if re.search(r"'200':\s*\{\s*description:\s*[^}]+\}\s*$", block, re.MULTILINE):
        return [f"{op_id}.200_description_only"]
    return []


def require_operation_request_ref(blocks: dict[str, str], op_id: str, schema_name: str) -> list[str]:
    block = blocks.get(op_id, "")
    if not block:
        return [f"missing operation {op_id}"]
    if "requestBody:" not in block:
        return [f"{op_id}.missing_request_body"]
    if f"#/components/schemas/{schema_name}" not in block:
        return [f"{op_id}.request_missing_{schema_name}_ref"]
    return []


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
        "revokeApprovalReceipt",
        "replayRun",
        "exportTraces",
        "exportStateSnapshot",
        "importStateSnapshot",
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

    for op_id in sorted(RESIDENT_DAEMON_OPERATIONS & operation_ids):
        block = blocks.get(op_id, "")
        if "ResidentCallerBearer" not in block:
            failures.append(f"{op_id} must declare the resident caller bearer security scheme")
        if "'401':" not in block and "401:" not in block:
            failures.append(f"{op_id} must declare resident authentication failure semantics")
    for op_id in sorted(FUTURE_GROUPS["fleet"] & operation_ids):
        if "ResidentCallerBearer" in blocks.get(op_id, ""):
            failures.append(f"{op_id} must not claim resident bearer authentication for manager inbound traffic")
    for op_id in sorted(
        {"requestApproval", "grantApproval", "denyApproval", "revokeApproval"}
        & operation_ids
    ):
        block = blocks.get(op_id, "")
        if "ManagerApprovalCallerBearer" not in block:
            failures.append(
                f"{op_id} must declare bounded manager approval caller authentication"
            )
        if "'401':" not in block and "401:" not in block:
            failures.append(
                f"{op_id} must declare manager caller authentication failure semantics"
            )
    for op_id in sorted(
        (FUTURE_GROUPS["governance"] - {"requestApproval", "grantApproval", "denyApproval", "revokeApproval"})
        & operation_ids
    ):
        if "ManagerApprovalCallerBearer" in blocks.get(op_id, ""):
            failures.append(
                f"{op_id} must not broaden the bounded approval bearer profile"
            )
    for marker in [
        "type: http",
        "scheme: bearer",
        "splendor-caller+jwt (Ed25519)",
        "WWW-Authenticate",
        "non-authoritative compatibility mirror",
    ]:
        if marker not in text:
            failures.append(f"resident authentication contract missing marker: {marker}")

    import_block = blocks.get("importStateSnapshot", "")
    for marker in [
        "'503':",
        "state_handoff_proof_unavailable",
        "needs_intervention",
        "signed_source_handoff_manifest",
        "No state-store, state-head, or run-trace mutation occurs",
    ]:
        if marker not in import_block:
            failures.append(f"resident state import fail-closed contract missing marker: {marker}")

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
    schema_failures.extend(
        require_schema_fields(text, "SubmitWorkOrderRequest", {"approval_policies"})
    )
    submit_work_order_block = schema_block(text, "SubmitWorkOrderRequest")
    for marker in (
        "default: []",
        "maxItems: 64",
        "#/components/schemas/ApprovalPolicy",
        "non-authorizing governance configuration",
    ):
        if marker not in submit_work_order_block:
            schema_failures.append(f"SubmitWorkOrderRequest.approval_policies_missing_{marker}")
    approval_policy_fields = {
        "schema_version",
        "policy_id",
        "tenant_id",
        "agent_id",
        "action_name",
        "adapter",
        "required_permission",
        "side_effect_class",
        "risk_level",
        "reason",
        "expires_at",
    }
    schema_failures.extend(
        require_exact_schema_fields(text, "ApprovalPolicy", approval_policy_fields)
    )
    schema_failures.extend(
        require_exact_schema_required_fields(text, "ApprovalPolicy", approval_policy_fields)
    )
    schema_failures.extend(require_closed_schema(text, "ApprovalPolicy"))
    approval_policy_block = schema_block(text, "ApprovalPolicy")
    for marker in (
        "enum: [splendor.approval_policy.v1]",
        "maxLength: 128",
        "maxLength: 1024",
        "#/components/schemas/SideEffectClass",
    ):
        if marker not in approval_policy_block:
            schema_failures.append(f"ApprovalPolicy.missing_{marker}")
    side_effect_class_block = schema_block(text, "SideEffectClass")
    for marker in (
        "enum: [ReadOnly, Filesystem, Network, External]",
        "additionalProperties: false",
        "required: [Custom]",
    ):
        if marker not in side_effect_class_block:
            schema_failures.append(f"SideEffectClass.missing_{marker}")
    approval_challenge_fields = {
        "schema_version",
        "approval_id",
        "tenant_id",
        "agent_id",
        "run_id",
        "action_id",
        "action_name",
        "adapter",
        "policy_id",
        "risk_level",
        "subject",
        "authority_decision_id",
        "obligation_id",
        "receipt_audience",
        "canonical_request_digest",
        "gateway_action_request_digest",
        "physical_action_resource_coordinate",
        "authority_decision_digest",
        "requested_at",
        "expires_at",
    }
    schema_failures.extend(require_schema_fields(text, "ApprovalChallenge", approval_challenge_fields))
    schema_failures.extend(
        require_schema_required_fields(
            text,
            "ApprovalChallenge",
            approval_challenge_fields
            - {"risk_level", "physical_action_resource_coordinate"},
        )
    )
    approval_challenge_block = schema_block(text, "ApprovalChallenge")
    if "enum: [splendor.approval_challenge.v1]" not in approval_challenge_block:
        schema_failures.append("ApprovalChallenge.schema_version_literal_mismatch")
    schema_failures.extend(
        require_exact_schema_fields(
            text,
            "PhysicalActionResourceCoordinate",
            {"resource_kind", "node_id"},
        )
    )
    schema_failures.extend(
        require_exact_schema_required_fields(
            text,
            "PhysicalActionResourceCoordinate",
            {"resource_kind", "node_id"},
        )
    )
    schema_failures.extend(
        require_exact_schema_fields(
            text,
            "ResidentApprovalReceiptRevocationRequest",
            {"schema_version", "authority_obligation_receipt", "reason"},
        )
    )
    schema_failures.extend(
        require_exact_schema_required_fields(
            text,
            "ResidentApprovalReceiptRevocationRequest",
            {"schema_version", "authority_obligation_receipt", "reason"},
        )
    )
    schema_failures.extend(
        require_exact_schema_fields(
            text,
            "ResidentApprovalReceiptRevocationAck",
            {
                "schema_version",
                "receipt_id",
                "approval_id",
                "target_instance_id",
                "run_id",
                "receipt_audience",
                "status",
                "effect_certainty",
                "acknowledged_at",
            },
        )
    )
    schema_failures.extend(
        require_exact_schema_required_fields(
            text,
            "ResidentApprovalReceiptRevocationAck",
            {
                "schema_version",
                "receipt_id",
                "approval_id",
                "target_instance_id",
                "run_id",
                "receipt_audience",
                "status",
                "effect_certainty",
                "acknowledged_at",
            },
        )
    )
    schema_failures.extend(
        require_operation_request_ref(
            blocks,
            "revokeApprovalReceipt",
            "ResidentApprovalReceiptRevocationRequest",
        )
    )
    schema_failures.extend(
        require_operation_response_ref(
            blocks,
            "revokeApprovalReceipt",
            "ResidentApprovalReceiptRevocationAck",
        )
    )
    revoke_receipt_block = blocks.get("revokeApprovalReceipt", "")
    for marker in (
        "ResidentCallerBearer",
        "splendor.approval_receipts.revoke",
        "approval_receipt_revocation_too_late",
        "'409':",
    ):
        if marker not in revoke_receipt_block:
            schema_failures.append(f"revokeApprovalReceipt.missing_{marker}")
    if "splendor.approvals.manage" in revoke_receipt_block:
        schema_failures.append("revokeApprovalReceipt.broad_approval_scope")
    schema_failures.extend(require_closed_schema(text, "PhysicalActionResourceCoordinate"))
    schema_failures.extend(require_closed_schema(text, "ResidentApprovalReceiptRevocationRequest"))
    schema_failures.extend(require_closed_schema(text, "ResidentApprovalReceiptRevocationAck"))
    governance_approval_record_fields = {
        "approval_id",
        "tenant_id",
        "agent_id",
        "run_id",
        "action_id",
        "action_name",
        "adapter",
        "policy_id",
        "risk_level",
        "audience",
        "status",
        "reason",
        "issued_by",
        "requested_by",
        "decided_by",
        "expires_at",
        "trace_event_id",
        "evidence",
        "challenge",
        "authority_obligation_receipt",
        "resident_receipt_revocation_ack",
    }
    schema_failures.extend(
        require_exact_schema_fields(
            text,
            "GovernanceApprovalRecord",
            governance_approval_record_fields,
        )
    )
    governance_record_block = schema_block(text, "GovernanceApprovalRecord")
    revocation_ack_match = re.search(
        r"^        resident_receipt_revocation_ack:\s*$([\s\S]*?)(?=^        [a-z][A-Za-z0-9_]*:|\Z)",
        governance_record_block,
        re.MULTILINE,
    )
    if not revocation_ack_match:
        schema_failures.append("GovernanceApprovalRecord.resident_receipt_revocation_ack")
    else:
        revocation_ack_block = revocation_ack_match.group(1)
        if "type: 'null'" not in revocation_ack_block:
            schema_failures.append("GovernanceApprovalRecord.resident_receipt_revocation_ack_not_nullable")
        if "#/components/schemas/ResidentApprovalReceiptRevocationAck" not in revocation_ack_block:
            schema_failures.append("GovernanceApprovalRecord.resident_receipt_revocation_ack_missing_ref")
    if re.search(
        r"^      required: \[[^\]]*resident_receipt_revocation_ack[^\]]*\]",
        governance_record_block,
        re.MULTILINE,
    ):
        schema_failures.append("GovernanceApprovalRecord.resident_receipt_revocation_ack_not_optional")
    schema_failures.extend(require_schema_fields(text, "ReplayRequest", {"credential", "audit_attribution", "mode", "side_effects_allowed"}))
    schema_failures.extend(
        require_schema_fields(text, "TraceExportRequest", {"credential", "audit_attribution", "redaction_policy", "start", "end"})
    )
    schema_failures.extend(
        require_schema_fields(
            text,
            "ExportStateSnapshotRequest",
            {
                "run_id",
                "credential",
                "audit_attribution",
                "work_order_id",
                "source_instance_id",
                "receiver_instance_id",
                "previous_state_node_id",
            },
        )
    )
    schema_failures.extend(
        require_schema_fields(
            text,
            "ImportStateSnapshotRequest",
            {"handoff", "work_order", "credential", "audit_attribution"},
        )
    )
    schema_failures.extend(
        require_schema_required_fields(
            text,
            "ImportStateSnapshotRequest",
            {"handoff", "work_order", "credential", "audit_attribution"},
        )
    )
    schema_failures.extend(
        require_schema_fields(
            text,
            "StateHandoff",
            {
                "schema_version",
                "handoff_id",
                "mode",
                "authority",
                "source_instance_id",
                "receiver_instance_id",
                "previous_state_node_id",
                "snapshot",
                "source_trace_id",
                "created_at",
            },
        )
    )
    schema_failures.extend(require_non_null_authority_fields(text, "ReplayRequest"))
    schema_failures.extend(require_non_null_authority_fields(text, "TraceExportRequest"))
    schema_failures.extend(require_non_null_authority_fields(text, "ExportStateSnapshotRequest"))
    schema_failures.extend(require_non_null_authority_fields(text, "ImportStateSnapshotRequest"))
    schema_failures.extend(
        require_schema_fields(text, "VersionResponse", {"daemon_api_version", "compatibility_line", "openapi_version", "local_only", "schema_versions"})
    )
    schema_failures.extend(
        require_schema_fields(
            text,
            "FleetTelemetrySnapshot",
            {
                "schema_version",
                "fleet_id",
                "observed_at",
                "authority",
                "nodes",
                "instances",
                "runs",
                "queues",
                "quota_signals",
                "denial_signals",
                "trace_sync",
                "failures",
            },
        )
    )
    schema_failures.extend(require_schema_fields(text, "NodeTelemetry", {"node_id", "online_state", "instance_ids"}))
    schema_failures.extend(
        require_schema_fields(
            text,
            "InstanceTelemetry",
            {"node_id", "instance_id", "runtime_version", "runtime_mode", "runtime_image", "build_target", "current_run_counts"},
        )
    )
    schema_failures.extend(require_schema_fields(text, "RunTelemetry", {"run_id", "node_id", "instance_id", "status"}))
    schema_failures.extend(require_schema_fields(text, "QuotaSignal", {"allowed", "usage", "reasons", "artifacts"}))
    schema_failures.extend(require_schema_fields(text, "DenialSignal", {"verifier", "action_name", "reasons", "artifacts"}))
    schema_failures.extend(require_schema_fields(text, "TraceSyncTelemetry", {"last_synced_sequence", "source_high_watermark", "lag_events", "last_failure"}))
    schema_failures.extend(require_schema_fields(text, "RegisterDeviceProfileRequest", {"credential", "audit_attribution", "profile"}))
    schema_failures.extend(require_schema_fields(text, "DeviceRuntimeProfile", {"node_id", "tenant_id", "device_kind", "capabilities", "allowed_physical_actions", "forbidden_action_classes", "safety_constraints", "runtime_mode", "safety_status", "policy_cache", "trace_buffer", "registered_at"}))
    schema_failures.extend(require_schema_fields(text, "DevicePolicyCacheStatus", {"policy_id", "loaded", "ttl_seconds", "expires_at", "expired"}))
    schema_failures.extend(require_schema_fields(text, "SubmitPhysicalActionRequest", {"safety_context", "operator_intervention_evidence"}))
    submit_action_request_fields = {
        "action_id",
        "run_id",
        "tenant_id",
        "agent_id",
        "credential",
        "audit_attribution",
        "causal_trace_id",
        "action",
        "adapter",
        "quota_usage",
        "satisfied_preconditions",
        "requested_at",
        "approval_evidence",
        "authority_obligation_receipts",
    }
    schema_failures.extend(
        require_exact_schema_fields(
            text,
            "SubmitActionRequest",
            submit_action_request_fields,
        )
    )
    schema_failures.extend(require_closed_schema(text, "SubmitActionRequest"))
    if "physical_action_resource_coordinate" in schema_property_fields(text, "SubmitActionRequest"):
        schema_failures.append("SubmitActionRequest.physical_action_resource_coordinate_is_caller_field")
    schema_failures.extend(require_closed_schema(text, "SubmitPhysicalActionRequest"))
    schema_failures.extend(require_closed_schema(text, "ApprovalEvidence"))
    schema_failures.extend(require_schema_fields(text, "SafetyContext", {"allowed_zone_refs", "zone_ref", "altitude_m", "max_altitude_m", "battery_percent", "privacy_clear", "human_proximity_clear", "emergency_stop_clear", "offline", "policy_cache_expired", "high_risk", "cloud_helper_direct_authority", "cloud_helper_proposal_id"}))
    schema_failures.extend(require_schema_fields(text, "OperatorInterventionRequest", {"credential", "audit_attribution", "intervention_id", "tenant_id", "agent_id", "run_id", "node_id", "action_name", "reason", "expires_at"}))
    schema_failures.extend(require_schema_fields(text, "OperatorDecisionRequest", {"credential", "audit_attribution", "reason", "expires_at"}))
    schema_failures.extend(require_schema_fields(text, "OperatorInterventionEvidence", {"intervention_id", "tenant_id", "run_id", "action_name", "decision", "expires_at"}))
    schema_failures.extend(require_schema_fields(text, "OperatorInterventionRecord", {"intervention_id", "tenant_id", "agent_id", "run_id", "node_id", "action_name", "status", "reason", "expires_at", "trace_event_id", "evidence"}))
    schema_failures.extend(require_schema_fields(text, "DeviceTraceBufferSyncRequest", {"credential", "audit_attribution", "run_id", "records"}))
    schema_failures.extend(require_schema_fields(text, "DeviceTraceBufferSyncResponse", {"accepted", "accepted_records", "trace_event_id", "reason_code"}))
    schema_failures.extend(require_non_null_authority_fields(text, "RegisterDeviceProfileRequest"))
    schema_failures.extend(require_non_null_authority_fields(text, "OperatorInterventionRequest"))
    schema_failures.extend(require_non_null_authority_fields(text, "OperatorDecisionRequest"))
    schema_failures.extend(require_non_null_authority_fields(text, "DeviceTraceBufferSyncRequest"))
    device_trace_sync = blocks.get("syncDeviceTraceBuffer", "")
    if "splendor.device.trace_sync" not in device_trace_sync:
        schema_failures.append("syncDeviceTraceBuffer.missing_dedicated_mutating_scope")
    if "device_trace_sync" not in schema_block(text, "EndpointScope"):
        schema_failures.append("EndpointScope.missing_device_trace_sync")
    if "approval_receipts_revoke" not in schema_block(text, "EndpointScope"):
        schema_failures.append("EndpointScope.missing_approval_receipts_revoke")
    if schema_failures:
        failures.append("Missing required local contract schema fields: " + ", ".join(schema_failures))

    s4_response_failures: list[str] = []
    for op_id, schema_name in S4_MANAGER_RESPONSE_REFS.items():
        if op_id in operation_ids:
            s4_response_failures.extend(require_operation_response_ref(blocks, op_id, schema_name))
    telemetry_block = schema_block(text, "FleetTelemetrySnapshot")
    if telemetry_block and "observational_only" not in telemetry_block:
        s4_response_failures.append("FleetTelemetrySnapshot.authority_missing_observational_only_marker")
    if s4_response_failures:
        failures.append("Missing required S4 manager response contracts: " + ", ".join(s4_response_failures))

    message_contract_failures: list[str] = []
    for op_id, schema_name in MESSAGE_RESPONSE_REFS.items():
        message_contract_failures.extend(require_operation_response_ref(blocks, op_id, schema_name))
    for op_id, schema_name in MESSAGE_REQUEST_REFS.items():
        block = blocks.get(op_id, "")
        if not block:
            message_contract_failures.append(f"missing operation {op_id}")
            continue
        if "requestBody:" not in block:
            message_contract_failures.append(f"{op_id}.missing_request_body_or_caller_scope")
        if f"#/components/schemas/{schema_name}" not in block:
            message_contract_failures.append(f"{op_id}.request_missing_{schema_name}_ref")
        if "'403':" not in block and "403:" not in block:
            message_contract_failures.append(f"{op_id}.missing_403_response")
    schema_failures_for_messages: list[str] = []
    schema_failures_for_messages.extend(
        require_schema_fields(
            text,
            "MessageStatusReport",
            {
                "message_id",
                "work_order_id",
                "tenant_id",
                "run_id",
                "source_agent_id",
                "target_agent_id",
                "schema",
                "causal_parent",
                "delivery_status",
                "trace_event_id",
                "payload_preserved",
            },
        )
    )
    for schema_name in ["MessageReadRequest", "MessageDeliveryUpdateRequest", "MessageSchemaValidationRequest"]:
        block = schema_block(text, schema_name)
        if "#/components/schemas/ManagerSecurityFields" not in block:
            schema_failures_for_messages.append(f"{schema_name}.missing_ManagerSecurityFields_ref")
    schema_failures_for_messages.extend(require_schema_fields(text, "MessageReadRequest", {"tenant_id", "run_id", "agent_id"}))
    schema_failures_for_messages.extend(require_schema_required_fields(text, "MessageReadRequest", {"tenant_id", "run_id", "agent_id"}))
    schema_failures_for_messages.extend(require_non_null_fields(text, "MessageReadRequest", {"tenant_id", "run_id", "agent_id"}))
    schema_failures_for_messages.extend(require_schema_fields(text, "MessageDeliveryUpdateRequest", {"reason"}))
    schema_failures_for_messages.extend(require_schema_fields(text, "MessageDeliveryUpdateRequest", {"tenant_id", "run_id", "agent_id"}))
    schema_failures_for_messages.extend(require_schema_required_fields(text, "MessageDeliveryUpdateRequest", {"tenant_id", "run_id", "agent_id"}))
    schema_failures_for_messages.extend(require_non_null_fields(text, "MessageDeliveryUpdateRequest", {"tenant_id", "run_id", "agent_id"}))
    schema_failures_for_messages.extend(require_schema_fields(text, "MessageListResponse", {"tenant_id", "run_id"}))
    schema_failures_for_messages.extend(require_non_null_fields(text, "MessageListResponse", {"tenant_id", "run_id"}))
    schema_failures_for_messages.extend(require_schema_fields(text, "MessageCausalGraphResponse", {"tenant_id", "run_id", "agent_id"}))
    schema_failures_for_messages.extend(require_non_null_fields(text, "MessageCausalGraphResponse", {"tenant_id", "run_id", "agent_id"}))
    schema_failures_for_messages.extend(require_schema_fields(text, "MessageSchemaValidationRequest", {"message_envelope", "schema", "payload"}))
    schema_failures_for_messages.extend(require_schema_fields(text, "MessageSchemaValidationReport", {"valid", "supported", "schema", "delivery_authority_granted", "trace_event_id"}))
    schema_failures_for_messages.extend(require_schema_fields(text, "MessageSchemaListResponse", {"schemas", "delivery_authority_granted", "trace_event_id"}))
    if schema_failures_for_messages:
        message_contract_failures.append("message schema field failures: " + ", ".join(schema_failures_for_messages))
    required_message_markers = [
        "message_payload_mutation_forbidden",
        "cross_tenant_message_read_denied",
        "splendor.message.task_request.v1",
        "splendor.message.task_response.v1",
        "splendor.message.proposal_request.v1",
        "delivery_authority_granted",
        "missing_message_tenant_scope",
        "missing_message_run_scope",
        "missing_message_agent_scope",
        "message_ack_agent_not_recipient",
    ]
    for marker in required_message_markers:
        if marker not in text:
            message_contract_failures.append(f"message_contract_missing_marker:{marker}")
    if message_contract_failures:
        failures.append("Missing required message communication contracts: " + ", ".join(message_contract_failures))

    s6_contract_failures: list[str] = []
    for op_id, schema_name in S6_PHYSICAL_RESPONSE_REFS.items():
        s6_contract_failures.extend(require_operation_response_ref(blocks, op_id, schema_name))
    for op_id, schema_name in S6_PHYSICAL_REQUEST_REFS.items():
        block = blocks.get(op_id, "")
        if not block:
            s6_contract_failures.append(f"missing operation {op_id}")
            continue
        if "requestBody:" not in block:
            s6_contract_failures.append(f"{op_id}.missing_request_body")
        if f"#/components/schemas/{schema_name}" not in block:
            s6_contract_failures.append(f"{op_id}.request_missing_{schema_name}_ref")
        if "'403':" not in block and "403:" not in block:
            s6_contract_failures.append(f"{op_id}.missing_403_response")
    for op_id in ["getDeviceStatus", "getPolicyCacheStatus"]:
        block = blocks.get(op_id, "")
        if "CallerCredentialHeader" not in block:
            s6_contract_failures.append(f"{op_id}.missing_caller_credential_header")
        if "'403':" not in block and "403:" not in block:
            s6_contract_failures.append(f"{op_id}.missing_403_response")
    physical_required_markers = [
        "inspect_zone",
        "read_sensor_summary",
        "return_to_base",
        "upload_trace_summary",
        "set_motor_pwm",
        "raw_actuator_write",
        "disable_firmware_safety",
        "bypass_collision_avoidance",
        "ignore_emergency_stop",
        "hard_real_time_stabilization",
        "cloud_helper_direct_authority",
        "cloud_helper_proposal_id",
        "trace_sync_hash_chain_mismatch",
    ]
    for marker in physical_required_markers:
        if marker not in text:
            s6_contract_failures.append(f"physical_contract_missing_marker:{marker}")
    if s6_contract_failures:
        failures.append("Missing required S6 physical/edge contracts: " + ", ".join(s6_contract_failures))

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
        "raw_actuator_write",
        "disable_firmware_safety",
        "bypass_collision_avoidance",
        "ignore_emergency_stop",
        "hard_real_time_stabilization",
    ]
    physical_missing_ops = sorted(FUTURE_GROUPS["physical_edge"] - operation_ids)
    physical_schema_status = {
        "forbidden_low_level_actions_marked_in_contract": [
            marker for marker in physical_forbidden_markers if marker in text
        ],
        "operation_ids_checked": sorted(FUTURE_GROUPS["physical_edge"] & operation_ids),
        "response_refs_checked": sorted(S6_PHYSICAL_RESPONSE_REFS),
        "request_refs_checked": sorted(S6_PHYSICAL_REQUEST_REFS),
        "failures": s6_contract_failures,
        "status": "executable" if not physical_missing_ops and not s6_contract_failures else "blocked_not_yet_executable",
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
            "resident_bearer_operations_checked": sorted(RESIDENT_DAEMON_OPERATIONS & operation_ids),
            "schema_fields_checked": ["CallerCredential", "WorkOrderEnvelope", "ReplayRequest"],
            "s4_response_refs_checked": sorted(op for op in S4_MANAGER_RESPONSE_REFS if op in operation_ids),
            "s6_physical_response_refs_checked": sorted(op for op in S6_PHYSICAL_RESPONSE_REFS if op in operation_ids),
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
