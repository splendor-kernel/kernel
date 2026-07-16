"""Canonical immutable fleet profiles shared by acceptance scenarios.

Scenarios S4-S10 intentionally reuse the same resident node and instance IDs.
The manager therefore requires every repeated registration to carry the exact
same ordered capabilities and supported features.
"""

VPC_NODE_CAPABILITIES = (
    "sql.read_fixture",
    "data.read_fixture",
    "artifact.create_internal",
    "artifact.publish_external",
    "message.remote.proposal",
    "runtime.resident",
)

CLOUD_NODE_CAPABILITIES = (
    "message.remote.proposal",
    "runtime.resident",
    "artifact.create_internal",
    "artifact.publish_external",
    "governance.kill_switch",
)

EDGE_NODE_CAPABILITIES = (
    "message.remote.proposal",
    "runtime.resident",
    "physical.edge",
    "physical.action.read_battery",
    "physical.action.read_sensor_summary",
    "physical.action.inspect_zone",
    "physical.action.move_to_waypoint",
    "physical.action.capture_image",
    "physical.action.return_to_base",
    "physical.action.upload_trace_summary",
)

VPC_INSTANCE_FEATURES = (
    "runtime.resident",
    "gateway.verified",
    "trace.buffer.local",
    "state.handoff",
    "message.remote",
    "message.remote.proposal",
    "sql.read_fixture",
    "artifact.create_internal",
    "artifact.publish_external",
)

CLOUD_INSTANCE_FEATURES = (
    *VPC_INSTANCE_FEATURES,
    "governance.kill_switch",
)

EDGE_INSTANCE_FEATURES = (
    "runtime.resident",
    "gateway.verified",
    "trace.buffer.local",
    "message.remote",
    "physical.edge",
    "physical.action.read_battery",
    "physical.action.read_sensor_summary",
    "physical.action.inspect_zone",
    "physical.action.move_to_waypoint",
    "physical.action.capture_image",
    "physical.action.return_to_base",
    "physical.action.upload_trace_summary",
)
