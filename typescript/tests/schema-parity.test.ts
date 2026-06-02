import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  ACTION_STATUS_VALUES,
  CANONICAL_SCHEMA_FIELDS,
  ENDPOINT_SCOPE_LABELS,
  ENDPOINT_SCOPE_VALUES,
  EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION,
  GOVERNED_ARTIFACT_REF_SCHEMA_VERSION,
  TRACE_EVENT_KIND_VARIANTS
} from "@splendor/types";
import type {
  ApprovalDenial,
  ApprovalGrant,
  ApprovalRequest,
  ExternalApprovalMapping,
  ExternalGovernanceAdapterContract,
  GovernedArtifactRef
} from "@splendor/types";

const repoRoot = process.cwd();

function readRepoFile(path: string): string {
  return readFileSync(join(repoRoot, path), "utf8");
}

function extractStructFields(source: string, name: string): string[] {
  const match = new RegExp(`(?:pub\\s+)?struct\\s+${name}\\s*\\{([\\s\\S]*?)\\n\\}`, "m").exec(source);
  assert.ok(match, `struct ${name} must exist`);
  return Array.from(match[1].matchAll(/^\s*(?:pub\s+)?([a-z][A-Za-z0-9_]*)\s*:/gm), (field) => field[1]);
}

function extractEnumVariants(source: string, name: string): string[] {
  const enumStart = source.indexOf(`enum ${name}`);
  assert.notEqual(enumStart, -1, `enum ${name} must exist`);
  const open = source.indexOf("{", enumStart);
  assert.notEqual(open, -1, `enum ${name} must have a body`);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    const character = source[index];
    if (character === "{") depth += 1;
    if (character === "}") depth -= 1;
    if (depth === 0) {
      const body = source.slice(open + 1, index);
      return Array.from(body.matchAll(/^    ([A-Z][A-Za-z0-9]+)(?:\s*[,\{])/gm), (variant) => variant[1]);
    }
  }
  throw new Error(`enum ${name} closing brace not found`);
}

function extractOpenApiStringEnum(source: string, schema: string): string[] {
  const schemaMatch = new RegExp(`\\n    ${schema}:\\n`).exec(source);
  assert.ok(schemaMatch, `OpenAPI schema ${schema} must exist`);
  const start = schemaMatch.index;
  const remainder = source.slice(start + 1);
  const nextSchema = /\n    [A-Za-z][A-Za-z0-9]+:\n/.exec(remainder.slice(1));
  const block = nextSchema ? remainder.slice(0, nextSchema.index + 1) : remainder;
  const enumIndex = block.indexOf("\n      enum:");
  assert.notEqual(enumIndex, -1, `OpenAPI schema ${schema} must define an enum`);
  return Array.from(block.slice(enumIndex).matchAll(/^        - ([a-z_]+)$/gm), (entry) => entry[1]);
}

function extractOpenApiSchemaBlock(source: string, schema: string): string {
  const schemaMatch = new RegExp(`\n    ${schema}:\n`).exec(source);
  assert.ok(schemaMatch, `OpenAPI schema ${schema} must exist`);
  const start = schemaMatch.index;
  const remainder = source.slice(start + 1);
  const nextSchema = /\n    [A-Za-z][A-Za-z0-9]+:\n/.exec(remainder.slice(1));
  return nextSchema ? remainder.slice(0, nextSchema.index + 1) : remainder;
}

test("TypeScript primitive field contracts match canonical Rust structs", () => {
  const message = readRepoFile("crates/splendor-types/src/message.rs");
  const primitives = readRepoFile("crates/splendor-types/src/primitives.rs");
  const governance = readRepoFile("crates/splendor-types/src/governance.rs");
  const externalGovernance = readRepoFile("crates/splendor-types/src/external_governance.rs");
  const trace = readRepoFile("crates/splendor-types/src/trace.rs");
  const gateway = readRepoFile("crates/splendor-gateway/src/lib.rs");
  const daemon = readRepoFile("crates/splendor-daemon/src/lib.rs");

  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.message, extractStructFields(message, "Message"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.percept, extractStructFields(primitives, "Percept"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.trace_event, extractStructFields(trace, "TraceEvent"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.action_request, extractStructFields(gateway, "ActionRequest"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.action_outcome, extractStructFields(gateway, "ActionOutcome"));
  assert.deepEqual(
    CANONICAL_SCHEMA_FIELDS.external_governance_reference,
    extractStructFields(externalGovernance, "ExternalGovernanceReference")
  );
  assert.deepEqual(
    CANONICAL_SCHEMA_FIELDS.external_governance_endpoints,
    extractStructFields(externalGovernance, "ExternalGovernanceEndpoints")
  );
  assert.deepEqual(
    CANONICAL_SCHEMA_FIELDS.external_governance_adapter_contract,
    extractStructFields(externalGovernance, "ExternalGovernanceAdapterContract")
  );
  assert.deepEqual(
    CANONICAL_SCHEMA_FIELDS.external_governance_work_order_bridge,
    extractStructFields(externalGovernance, "ExternalGovernanceWorkOrderBridge")
  );
  assert.deepEqual(
    CANONICAL_SCHEMA_FIELDS.external_approval_decision,
    extractStructFields(externalGovernance, "ExternalApprovalDecision")
  );
  assert.deepEqual(
    CANONICAL_SCHEMA_FIELDS.external_governance_adapter_failure,
    extractStructFields(externalGovernance, "ExternalGovernanceAdapterFailure")
  );
  assert.deepEqual(
    CANONICAL_SCHEMA_FIELDS.external_trace_range,
    extractStructFields(externalGovernance, "ExternalTraceRange")
  );
  assert.deepEqual(
    CANONICAL_SCHEMA_FIELDS.governed_artifact_ref,
    extractStructFields(externalGovernance, "GovernedArtifactRef")
  );
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.circuit_breaker, extractStructFields(governance, "CircuitBreaker"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.state_head, extractStructFields(daemon, "StateHeadResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.create_run_request, extractStructFields(daemon, "CreateRunRequest"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.lifecycle_request, extractStructFields(daemon, "LifecycleRequest"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.run_inspect_response, extractStructFields(daemon, "RunInspectResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.tick_response, extractStructFields(daemon, "TickResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.append_percept_request, extractStructFields(daemon, "AppendPerceptRequest"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.policy_sync_request, extractStructFields(daemon, "PolicySyncRequest"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.policy_cache_status_response, extractStructFields(daemon, "PolicyCacheStatusResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.policy_sync_response, extractStructFields(daemon, "PolicySyncResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.trace_page_response, extractStructFields(daemon, "TracePageResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.replay_response, extractStructFields(daemon, "ReplayResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.submit_action_request, extractStructFields(daemon, "SubmitActionRequest"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.health_response, extractStructFields(daemon, "HealthResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.capabilities_response, extractStructFields(daemon, "CapabilitiesResponse"));
});

test("TypeScript governance approval statuses mirror Rust object validators", () => {
  const requestStatus: ApprovalRequest["status"] = "requested";
  const expiredRequestStatus: ApprovalRequest["status"] = "expired";
  const grantStatus: ApprovalGrant["status"] = "granted";
  const revokedGrantStatus: ApprovalGrant["status"] = "revoked";
  const denialStatus: ApprovalDenial["status"] = "denied";

  assert.deepEqual(
    [requestStatus, expiredRequestStatus, grantStatus, revokedGrantStatus, denialStatus],
    ["requested", "expired", "granted", "revoked", "denied"]
  );

  // @ts-expect-error Rust ApprovalRequest::validate rejects denied request states.
  const invalidRequestStatus: ApprovalRequest["status"] = "denied";
  // @ts-expect-error Rust ApprovalGrant::validate rejects requested grant states.
  const invalidGrantStatus: ApprovalGrant["status"] = "requested";
  // @ts-expect-error Rust ApprovalDenial::validate rejects granted denial states.
  const invalidDenialStatus: ApprovalDenial["status"] = "granted";

  assert.deepEqual(
    [invalidRequestStatus, invalidGrantStatus, invalidDenialStatus],
    ["denied", "requested", "granted"]
  );
});

test("TypeScript external governance adapter contracts are provider-neutral and fail closed", () => {
  const contract: ExternalGovernanceAdapterContract = {
    schema_version: EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION,
    provider: "customer_console",
    endpoints: {
      work_orders: "/governed/work-orders/{work_order_id}",
      action_gateway: "/governed/action-gateway",
      approvals: "/governed/approval-decisions",
      traces: "/governed/runtime-traces",
      state_commits: "/governed/state-commits",
      artifact_refs: "/governed/artifact-refs"
    }
  };
  const artifact: GovernedArtifactRef = {
    schema_version: GOVERNED_ARTIFACT_REF_SCHEMA_VERSION,
    artifact_id: "artifact_weekly_dashboard",
    version: "v2",
    source_refs: ["dataset:finance.revenue_monthly_v4"],
    run_id: "run_456",
    state_node_id: "blake3:abc123",
    trace_range: {
      start_trace_event_id: "trace_start",
      end_trace_event_id: "trace_end"
    },
    approval_state: "granted",
    approval_id: "approval_123",
    external_ref: {
      provider: "customer_console",
      reference_id: "artifact-ext-123",
      endpoint: "/governed/artifact-refs"
    },
    export_targets: ["customer_console:artifact-registry"]
  };
  const failure: ExternalApprovalMapping = {
    mapping: "adapter_failure",
    failure: {
      schema_version: EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION,
      external_ref: {
        provider: "customer_console",
        reference_id: "approval-ext-123"
      },
      scope: {
        scope_type: "action",
        tenant_id: "tenant_1",
        agent_id: "agent_1",
        run_id: "run_456",
        action_id: "action_1"
      },
      occurred_at: "2026-06-01T00:00:00Z",
      reason: "external approval endpoint unavailable",
      issuer: { issuer_id: "customer_console", source: "external_adapter" },
      trace: { trace_event_id: "trace_failure", run_id: "run_456" }
    }
  };

  assert.equal(contract.schema_version, EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION);
  assert.equal(artifact.schema_version, GOVERNED_ARTIFACT_REF_SCHEMA_VERSION);
  assert.equal(artifact.source_refs.length, 1);
  assert.equal(failure.mapping, "adapter_failure");
  assert.ok(!("approval" in failure), "adapter failure must not carry approval by default");
});

test("OpenAPI documents S5 daemon request and response schemas", () => {
  const openapi = readRepoFile("openapi/splendor-runtime-daemon.yaml");
  for (const schema of [
    "CreateRunRequest",
    "CreateRunResponse",
    "LifecycleRequest",
    "WorkOrderEnvelope",
    "WorkOrderSignature",
    "WorkOrderQuotaPolicy",
    "WorkOrderPlacement",
    "RunInspectResponse",
    "TickResponse",
    "AppendPerceptRequest",
    "AppendPerceptResponse",
    "PolicySyncRequest",
    "PolicyCacheStatusResponse",
    "PolicySyncResponse",
    "StateHeadResponse",
    "TracePageResponse",
    "ReplayRequest",
    "ReplayResponse",
    "SubmitActionRequest",
    "HealthResponse",
    "CapabilitiesResponse",
    "ApiError"
  ]) {
    assert.match(openapi, new RegExp(`\\n    ${schema}:\\n`), `OpenAPI must define ${schema}`);
  }
  for (const operation of [
    "createRun",
    "startRun",
    "pauseRun",
    "resumeRun",
    "stopRun",
    "appendPercept",
    "syncPolicy",
    "replayRun",
    "submitAction"
  ]) {
    assert.match(openapi, new RegExp(`operationId: ${operation}[\\s\\S]*?requestBody:`), `${operation} must document a request body`);
  }
});

test("OpenAPI work-order envelope and run status contracts stay canonical", () => {
  const openapi = readRepoFile("openapi/splendor-runtime-daemon.yaml");

  assert.deepEqual(extractOpenApiStringEnum(openapi, "RunStatus"), [
    "pending",
    "running",
    "paused",
    "waiting_for_approval",
    "interrupted",
    "resuming",
    "completed",
    "failed",
    "cancelled",
    "denied",
    "expired"
  ]);

  const createRun = extractOpenApiSchemaBlock(openapi, "CreateRunRequest");
  assert.match(createRun, /work_order:[\s\S]*\$ref: '#\/components\/schemas\/WorkOrderEnvelope'/);
  assert.doesNotMatch(createRun, /WorkOrderAuthorization/);

  const lifecycle = extractOpenApiSchemaBlock(openapi, "LifecycleRequest");
  assert.match(lifecycle, /work_order:[\s\S]*\$ref: '#\/components\/schemas\/WorkOrderEnvelope'/);

  const workOrder = extractOpenApiSchemaBlock(openapi, "WorkOrderEnvelope");
  for (const field of [
    "schema_version",
    "work_order_id",
    "tenant_id",
    "agent_id",
    "run_id",
    "objective",
    "allowed_actions",
    "allowed_adapters",
    "allowed_permissions",
    "data_refs",
    "quotas",
    "placement",
    "issued_at",
    "expires_at",
    "revocation",
    "signature"
  ]) {
    assert.match(workOrder, new RegExp(`- ${field}`), `WorkOrderEnvelope must require ${field}`);
  }
});

test("TypeScript enum contracts match canonical Rust gateway and trace variants", () => {
  const trace = readRepoFile("crates/splendor-types/src/trace.rs");
  const gateway = readRepoFile("crates/splendor-gateway/src/lib.rs");

  assert.deepEqual([...TRACE_EVENT_KIND_VARIANTS], extractEnumVariants(trace, "TraceEventKind"));
  assert.deepEqual([...ACTION_STATUS_VALUES], extractEnumVariants(gateway, "ActionStatus"));
  assert.deepEqual([...ENDPOINT_SCOPE_VALUES], extractEnumVariants(readRepoFile("crates/splendor-types/src/daemon_security.rs"), "EndpointScope"));
});

test("OpenAPI endpoint scopes stay aligned with TypeScript client scope labels", () => {
  const openapi = readRepoFile("openapi/splendor-runtime-daemon.yaml");
  const openapiScopes = extractOpenApiStringEnum(openapi, "EndpointScope");
  assert.deepEqual(openapiScopes, Object.keys(ENDPOINT_SCOPE_LABELS));
});
