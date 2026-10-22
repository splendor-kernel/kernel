#!/usr/bin/env python3
"""Checked-in authority expectations for retained private-v3 outputs."""

from __future__ import annotations

import copy
from typing import Any

from acceptance_provider_protocol import PROVIDER_ID, SIGNING_KEY_ID


TENANT_A = "11111111-1111-4111-8111-111111111111"
PROVIDER_AUDIENCE = "splendor.acceptance.action-provider.v3"
PHYSICAL_NODE = "00000000-0000-4000-8000-000000000604"
PHYSICAL_COORDINATE = {"resource_kind": "physical_node", "node_id": PHYSICAL_NODE}

ROLE_BINDINGS = {
    "local": {
        "request_key_id": "acceptance-request-local-v3",
        "client_principal_id": "acceptance-host-local",
        "source_instance_id": "00000000-0000-4000-8000-000000000300",
    },
    "cloud": {
        "request_key_id": "acceptance-request-cloud-v3",
        "client_principal_id": "acceptance-host-cloud",
        "source_instance_id": "00000000-0000-4000-8000-000000000304",
    },
    "vpc": {
        "request_key_id": "acceptance-request-vpc-v3",
        "client_principal_id": "acceptance-host-vpc",
        "source_instance_id": "00000000-0000-4000-8000-000000000302",
    },
    "edge": {
        "request_key_id": "acceptance-request-edge-v3",
        "client_principal_id": "acceptance-host-edge",
        "source_instance_id": "00000000-0000-4000-8000-000000000306",
    },
}

OUTPUT_EXPECTATION_FIELDS = {
    "scenario_id",
    "expectation_id",
    "operation_id",
    "request_principal_role",
    "request_key_id",
    "client_principal_id",
    "source_instance_id",
    "tenant_id",
    "agent_id",
    "run_id",
    "action_id",
    "resource",
    "audience",
    "provider_id",
    "signing_key_id",
}


def make_output_expectation(
    scenario_id: str,
    expectation_id: str,
    operation_id: str,
    role: str,
    agent_id: str,
    run_id: str,
    action_id: str,
    resource: Any = None,
) -> dict[str, Any]:
    binding = ROLE_BINDINGS[role]
    return {
        "scenario_id": scenario_id,
        "expectation_id": expectation_id,
        "operation_id": operation_id,
        "request_principal_role": role,
        **binding,
        "tenant_id": TENANT_A,
        "agent_id": agent_id,
        "run_id": run_id,
        "action_id": action_id,
        "resource": copy.deepcopy(resource),
        "audience": PROVIDER_AUDIENCE,
        "provider_id": PROVIDER_ID,
        "signing_key_id": SIGNING_KEY_ID,
    }


S5_AGENT = "22222222-2222-4222-8222-222222222222"
S5_RESOURCE = f"artifact://{TENANT_A}/governance/uc-e2e-s5.md"
S6_AGENT = S5_AGENT
S6_RUN = "44444444-4444-4444-8444-444444444446"
S6_APPROVAL_RUN = "44444444-4444-4444-8444-444444444846"
S7_ORCHESTRATOR = "22222222-2222-4222-8222-222222222227"
S7_SPECIALIST = "33333333-3333-4333-8333-333333333337"
S10_ORCHESTRATOR = "22222222-2222-4222-8222-222222222210"
S10_SPECIALIST = "33333333-3333-4333-8333-333333333310"
S10_EDGE_AGENT = "22222222-2222-4222-8222-222222222610"


SCENARIO_OUTPUT_EXPECTATIONS: dict[str, dict[str, dict[str, Any]]] = {
    "UC-E2E-S5": {
        "internal_artifact": make_output_expectation(
            "UC-E2E-S5",
            "internal_artifact",
            "artifact-store/artifact.create_internal",
            "local",
            S5_AGENT,
            "44444444-4444-4444-8444-444444445446",
            "55555555-5555-4555-8555-555555445446",
            S5_RESOURCE,
        ),
        "approved_publish": make_output_expectation(
            "UC-E2E-S5",
            "approved_publish",
            "artifact-store/artifact.publish_external",
            "local",
            S5_AGENT,
            "44444444-4444-4444-8444-444444444445",
            "55555555-5555-4555-8555-555555444445",
            S5_RESOURCE,
        ),
    },
    "UC-E2E-S6": {
        "approved_capture": make_output_expectation(
            "UC-E2E-S6", "approved_capture", "device-sim/capture_image", "edge",
            S6_AGENT, S6_APPROVAL_RUN,
            "55555555-5555-4555-8555-555555555646", PHYSICAL_COORDINATE,
        ),
        "read_battery": make_output_expectation(
            "UC-E2E-S6", "read_battery", "device-sim/read_battery", "edge",
            S6_AGENT, S6_RUN, "55555555-5555-4555-8555-555555556601", PHYSICAL_COORDINATE,
        ),
        "inspect_zone": make_output_expectation(
            "UC-E2E-S6", "inspect_zone", "device-sim/inspect_zone", "edge",
            S6_AGENT, S6_RUN, "55555555-5555-4555-8555-555555556602", PHYSICAL_COORDINATE,
        ),
        "move_to_waypoint": make_output_expectation(
            "UC-E2E-S6", "move_to_waypoint", "device-sim/move_to_waypoint", "edge",
            S6_AGENT, S6_RUN, "55555555-5555-4555-8555-555555556603", PHYSICAL_COORDINATE,
        ),
        "capture_image": make_output_expectation(
            "UC-E2E-S6", "capture_image", "device-sim/capture_image", "edge",
            S6_AGENT, S6_RUN, "55555555-5555-4555-8555-555555556604", PHYSICAL_COORDINATE,
        ),
        "read_sensor_summary": make_output_expectation(
            "UC-E2E-S6", "read_sensor_summary", "device-sim/read_sensor_summary", "edge",
            S6_AGENT, S6_RUN, "55555555-5555-4555-8555-555555556605", PHYSICAL_COORDINATE,
        ),
        "return_to_base": make_output_expectation(
            "UC-E2E-S6", "return_to_base", "device-sim/return_to_base", "edge",
            S6_AGENT, S6_RUN, "55555555-5555-4555-8555-555555556606", PHYSICAL_COORDINATE,
        ),
        "upload_trace_summary": make_output_expectation(
            "UC-E2E-S6", "upload_trace_summary", "device-sim/upload_trace_summary", "edge",
            S6_AGENT, S6_RUN, "55555555-5555-4555-8555-555555556607", PHYSICAL_COORDINATE,
        ),
        "operator_capture": make_output_expectation(
            "UC-E2E-S6", "operator_capture", "device-sim/capture_image", "edge",
            S6_AGENT, S6_RUN, "55555555-5555-4555-8555-555555556608", PHYSICAL_COORDINATE,
        ),
    },
    "UC-E2E-S7": {
        "specialist_data_read": make_output_expectation(
            "UC-E2E-S7", "specialist_data_read", "fixture-data-store/data.read_fixture", "vpc",
            S7_SPECIALIST, "44444444-4444-4444-8444-555555555557",
            "55555555-5555-4555-8555-555555557701", "dataset:tenant-a.finance.board_pack.v1",
        ),
        "internal_artifact": make_output_expectation(
            "UC-E2E-S7", "internal_artifact", "artifact-store/artifact.create_internal", "vpc",
            S7_ORCHESTRATOR, "44444444-4444-4444-8444-444444444447",
            "55555555-5555-4555-8555-555555557702",
            f"artifact://{TENANT_A}/board/specialist-analysis.md",
        ),
        "approved_publish": make_output_expectation(
            "UC-E2E-S7", "approved_publish", "artifact-store/artifact.publish_external", "vpc",
            S7_ORCHESTRATOR, "44444444-4444-4444-8444-666666666667",
            "55555555-5555-4555-8555-555555555717",
            f"artifact://{TENANT_A}/board/report.md",
        ),
    },
    "UC-E2E-S10": {
        "orchestrator_data_read": make_output_expectation(
            "UC-E2E-S10", "orchestrator_data_read", "fixture-data-store/data.read_fixture", "vpc",
            S10_ORCHESTRATOR, "44444444-4444-4444-8444-444444448816",
            "55555555-5555-4555-8555-555555558801", "dataset:tenant-a.field-intel.fixture.v1",
        ),
        "specialist_data_read": make_output_expectation(
            "UC-E2E-S10", "specialist_data_read", "fixture-data-store/data.read_fixture", "vpc",
            S10_SPECIALIST, "44444444-4444-4444-8444-444444448811",
            "55555555-5555-4555-8555-555555558802", "dataset:tenant-a.field-intel.fixture.v1",
        ),
        "internal_artifact": make_output_expectation(
            "UC-E2E-S10", "internal_artifact", "artifact-store/artifact.create_internal", "vpc",
            S10_ORCHESTRATOR, "44444444-4444-4444-8444-444444448810",
            "55555555-5555-4555-8555-555555558803",
            f"artifact://{TENANT_A}/field-intelligence/s10-internal.md",
        ),
        "approved_publish": make_output_expectation(
            "UC-E2E-S10", "approved_publish", "artifact-store/artifact.publish_external", "vpc",
            S10_ORCHESTRATOR, "44444444-4444-4444-8444-444444448817",
            "55555555-5555-4555-8555-555555558821",
            f"artifact://{TENANT_A}/field-intelligence/s10-public.md",
        ),
        "inspect_zone": make_output_expectation(
            "UC-E2E-S10", "inspect_zone", "device-sim/inspect_zone", "edge",
            S10_EDGE_AGENT, "44444444-4444-4444-8444-444444448813",
            "55555555-5555-4555-8555-555555558804", PHYSICAL_COORDINATE,
        ),
        "move_to_waypoint": make_output_expectation(
            "UC-E2E-S10", "move_to_waypoint", "device-sim/move_to_waypoint", "edge",
            S10_EDGE_AGENT, "44444444-4444-4444-8444-444444448813",
            "55555555-5555-4555-8555-555555558805", PHYSICAL_COORDINATE,
        ),
        "read_sensor_summary": make_output_expectation(
            "UC-E2E-S10", "read_sensor_summary", "device-sim/read_sensor_summary", "edge",
            S10_EDGE_AGENT, "44444444-4444-4444-8444-444444448813",
            "55555555-5555-4555-8555-555555558806", PHYSICAL_COORDINATE,
        ),
        "upload_trace_summary": make_output_expectation(
            "UC-E2E-S10", "upload_trace_summary", "device-sim/upload_trace_summary", "edge",
            S10_EDGE_AGENT, "44444444-4444-4444-8444-444444448813",
            "55555555-5555-4555-8555-555555558807", PHYSICAL_COORDINATE,
        ),
        "operator_capture": make_output_expectation(
            "UC-E2E-S10", "operator_capture", "device-sim/capture_image", "edge",
            S10_EDGE_AGENT, "44444444-4444-4444-8444-444444448813",
            "55555555-5555-4555-8555-555555558808", PHYSICAL_COORDINATE,
        ),
    },
}


def expectation_for(scenario_id: str, expectation_id: str) -> dict[str, Any]:
    return copy.deepcopy(SCENARIO_OUTPUT_EXPECTATIONS[scenario_id][expectation_id])


def expectations_for(scenario_id: str) -> dict[str, dict[str, Any]]:
    return copy.deepcopy(SCENARIO_OUTPUT_EXPECTATIONS[scenario_id])
