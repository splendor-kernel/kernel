import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  ACTION_STATUS_VALUES,
  AUTHORITY_OPERATION_NAMESPACE_VALUES,
  AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION,
  AUTHORITY_RESOURCE_KIND_VALUES,
  AUTHORITY_VERB_VALUES,
  CANONICAL_SCHEMA_FIELDS,
  ENDPOINT_SCOPE_LABELS,
  ENDPOINT_SCOPE_VALUES,
  EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION,
  GOVERNED_ARTIFACT_REF_SCHEMA_VERSION,
  STABLE_0_1_ENUM_VALUES,
  STABLE_0_1_PRIMITIVES,
  STABLE_0_1_REQUIRED_FIELDS,
  STABLE_0_1_RESERVED_EXTENSION_KEYS,
  TRACE_EVENT_KIND_VARIANTS
} from "@splendor/types";
import type {
  ApprovalDenial,
  ApprovalGrant,
  ApprovalRequest,
  AuthorityObligationReceipt,
  AuthorityObligationReceiptValidation,
  DaemonActionCandidate,
  ExternalApprovalMapping,
  ExternalGovernanceAdapterContract,
  GovernedArtifactRef,
  RegisteredAction
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

function pascalToSnake(value: string): string {
  return value.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

type StablePrimitiveManifest = {
  schema_version: string;
  extension_policy: { authority: string; reserved_keys: string[] };
  enum_values: Record<string, string[]>;
  deprecated_aliases: Array<{ alias: string; replacement: string }>;
  primitives: Array<{
    name: string;
    identity_fields: string[];
    required_fields: string[];
    optional_fields: string[];
    extensions: string;
    example: Record<string, unknown>;
  }>;
};

function rejectAuthorityFields(
  primitive: { required_fields: string[]; optional_fields: string[]; extensions: string },
  candidate: Record<string, unknown>,
  reserved: readonly string[]
): void {
  const declared = new Set([...primitive.required_fields, ...primitive.optional_fields]);
  for (const key of Object.keys(candidate)) {
    assert.ok(!reserved.includes(key) || declared.has(key), `unknown top-level authority field ${key} must be rejected`);
  }
  if ("extensions" in candidate) {
    assert.equal(primitive.extensions, "non_authorizing", "extensions must be explicitly allowed");
    const extensions = candidate.extensions;
    assert.ok(extensions !== null && typeof extensions === "object" && !Array.isArray(extensions), "extensions must be an object");
    for (const key of Object.keys(extensions as Record<string, unknown>)) {
      assert.ok(!reserved.includes(key), `extension key ${key} must not carry authority`);
    }
  }
}

function validateStableExample(
  primitive: StablePrimitiveManifest["primitives"][number],
  reserved: readonly string[],
  enumValues: Record<string, readonly string[]>
): void {
  for (const field of primitive.required_fields) {
    assert.ok(Object.hasOwn(primitive.example, field), `${primitive.name} example must include ${field}`);
    assert.notEqual(primitive.example[field], undefined, `${primitive.name}.${field} must not be undefined`);
  }
  rejectAuthorityFields(primitive, primitive.example, reserved);
  const invalidExtension = { ...primitive.example, extensions: { allowed_permissions: ["admin"] } };
  if (primitive.extensions === "non_authorizing") {
    assert.throws(() => rejectAuthorityFields(primitive, invalidExtension, reserved), /extension key allowed_permissions/);
  }
  const invalidTopLevel = { ...primitive.example, credential: "secret" };
  assert.throws(() => rejectAuthorityFields(primitive, invalidTopLevel, reserved), /unknown top-level authority field credential/);

  if (primitive.name === "Run") assert.ok(enumValues.run_status.includes(String(primitive.example.status)));
  if (primitive.name === "Action") assert.ok(enumValues.side_effect_class.includes(String(primitive.example.side_effect_class)));
  if (primitive.name === "Approval") assert.ok(enumValues.approval_decision.includes(String(primitive.example.decision)));
  if (primitive.name === "Constraint") {
    assert.ok(enumValues.constraint_kind.includes(String(primitive.example.kind)));
    assert.ok(enumValues.constraint_scope.includes(String(primitive.example.scope)));
  }
}

test("0.1-S1 stable primitive docs and example manifest are aligned", () => {
  const primitivesDoc = readRepoFile("docs/spec/0.1/primitives.md");
  const versioningDoc = readRepoFile("docs/spec/0.1/schema-versioning.md");
  const milestoneDoc = readRepoFile("docs/milestones/0.1-dev/S1-stable-schema-freeze.md");
  const manifest = JSON.parse(readRepoFile("docs/spec/0.1/stable-primitive-examples.json")) as StablePrimitiveManifest;

  assert.equal(manifest.schema_version, "splendor.stable_primitives_manifest.v1");
  assert.equal(manifest.extension_policy.authority, "non_authorizing");
  assert.deepEqual(
    manifest.primitives.map((primitive) => primitive.name),
    [...STABLE_0_1_PRIMITIVES]
  );
  assert.deepEqual(manifest.extension_policy.reserved_keys, [...STABLE_0_1_RESERVED_EXTENSION_KEYS]);
  assert.deepEqual(manifest.enum_values, STABLE_0_1_ENUM_VALUES);

  for (const primitive of STABLE_0_1_PRIMITIVES) {
    assert.match(primitivesDoc, new RegExp(`## Primitive: ${primitive}\\n`), `${primitive} section must exist`);
    const entry = manifest.primitives.find((candidate) => candidate.name === primitive);
    assert.ok(entry, `${primitive} manifest entry must exist`);
    assert.deepEqual(entry.required_fields, STABLE_0_1_REQUIRED_FIELDS[primitive], `${primitive} required fields must match TS surface`);
    if (primitive === "Message") {
      assert.deepEqual(entry.optional_fields, [], "Message has no optional fields once causal_parent is canonical");
      assert.ok(entry.required_fields.includes("causal_parent"), "Message must require causal_parent for replay causality");
    } else {
      assert.ok(entry.optional_fields.length > 0, `${primitive} must list optional fields`);
    }
    assert.ok(["none", "non_authorizing"].includes(entry.extensions), `${primitive} extension policy must be explicit`);
    validateStableExample(entry, STABLE_0_1_RESERVED_EXTENSION_KEYS, STABLE_0_1_ENUM_VALUES);
  }

  for (const reserved of STABLE_0_1_RESERVED_EXTENSION_KEYS) {
    assert.match(primitivesDoc, new RegExp(`\\b${reserved}\\b`), `primitive docs must mention ${reserved}`);
  }

  assert.ok(
    manifest.deprecated_aliases.some((alias) => alias.alias === "trace_id" && alias.replacement === "trace_event_id"),
    "trace_id alias must have migration guidance"
  );
  assert.match(primitivesDoc, /Replay must not execute side effects by default/);
  assert.match(primitivesDoc, /Side-effectful work must remain mediated by `ActionRequest`/);
  assert.match(versioningDoc, /## Breaking Changes/);
  assert.match(versioningDoc, /## Non-Breaking Changes/);
  assert.match(versioningDoc, /## Deprecation Policy/);
  assert.match(versioningDoc, /This is not the full 0\.1-S2 conformance\s+suite/);
  assert.match(milestoneDoc, /0\.1-S1/);
  assert.match(milestoneDoc, /No runtime behavior changes/);
});

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
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.trace_export_request, extractStructFields(daemon, "TraceExportRequest"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.trace_export_response, extractStructFields(daemon, "TraceExportResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.replay_response, extractStructFields(daemon, "ReplayResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.submit_action_request, extractStructFields(daemon, "SubmitActionRequest"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.health_response, extractStructFields(daemon, "HealthResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.version_response, extractStructFields(daemon, "VersionResponse"));
  assert.deepEqual(CANONICAL_SCHEMA_FIELDS.capabilities_response, extractStructFields(daemon, "CapabilitiesResponse"));
});

test("C02 obligation receipt and trusted action profile contracts stay exact", () => {
  const authority = readRepoFile("crates/splendor-types/src/authority.rs");
  const openapi = readRepoFile("openapi/splendor-runtime-daemon.yaml");
  const receiptFields = [
    "schema_version",
    "receipt_id",
    "issuer",
    "audience",
    "obligation_id",
    "kind",
    "subject",
    "authority_decision_id",
    "canonical_request_digest",
    "evidence_digest",
    "evidence_ref",
    "issued_at",
    "expires_at",
    "revocation",
    "revocation_ref",
    "approval_id",
    "approval_trace_event_id",
    "validation"
  ];
  const validationFields = ["validation_kind", "algorithm", "key_id", "digest", "signature"];
  const rustReceiptVersion =
    /pub const AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION:\s*&str\s*=\s*\n?\s*"([^"]+)"/.exec(
      authority
    )?.[1];
  assert.equal(AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION, rustReceiptVersion);

  assert.deepEqual(extractStructFields(authority, "AuthorityObligationReceipt"), receiptFields);
  assert.deepEqual(
    extractStructFields(authority, "AuthorityObligationReceiptValidation"),
    validationFields
  );
  for (const [schema, fields] of [
    ["AuthorityObligationReceipt", receiptFields],
    ["AuthorityObligationReceiptValidation", validationFields]
  ] as const) {
    const block = extractOpenApiSchemaBlock(openapi, schema);
    assert.match(block, /additionalProperties: false/);
    for (const field of fields) assert.match(block, new RegExp(`^        ${field}:`, "m"));
  }
  assert.match(extractOpenApiSchemaBlock(openapi, "DaemonActionCandidate"), /maxItems: 64/);
  assert.match(extractOpenApiSchemaBlock(openapi, "SubmitActionRequest"), /maxItems: 64/);
  const registeredActionSchema = extractOpenApiSchemaBlock(openapi, "RegisteredAction");
  assert.match(registeredActionSchema, /additionalProperties: false/);
  assert.match(registeredActionSchema, /uniqueItems: true/);
  assert.match(registeredActionSchema, /maxItems: 64/);
  const receiptSchema = extractOpenApiSchemaBlock(openapi, "AuthorityObligationReceipt");
  assert.match(
    receiptSchema,
    /enum: \[splendor\.authority\.obligation_receipt\.v1\]/
  );
  for (const nullable of ["evidence_ref", "approval_id", "approval_trace_event_id"]) {
    assert.match(
      receiptSchema,
      new RegExp(`^        ${nullable}:\\n          type: \\[string, 'null'\\]`, "m")
    );
  }

  const rustNamespaces = extractEnumVariants(authority, "AuthorityOperationNamespace").map(pascalToSnake);
  const rustResourceKinds = extractEnumVariants(authority, "AuthorityResourceKind").map(pascalToSnake);
  const rustVerbs = extractEnumVariants(authority, "AuthorityVerb").map(pascalToSnake);
  assert.deepEqual([...AUTHORITY_OPERATION_NAMESPACE_VALUES], rustNamespaces);
  assert.deepEqual([...AUTHORITY_RESOURCE_KIND_VALUES], rustResourceKinds);
  assert.deepEqual([...AUTHORITY_VERB_VALUES], rustVerbs);
  assert.deepEqual(extractOpenApiStringEnum(openapi, "AuthorityOperationNamespace"), rustNamespaces);
  assert.deepEqual(extractOpenApiStringEnum(openapi, "AuthorityResourceKind"), rustResourceKinds);
  assert.deepEqual(extractOpenApiStringEnum(openapi, "AuthorityVerb"), rustVerbs);

  const validation: AuthorityObligationReceiptValidation = {
    validation_kind: "local_signature",
    algorithm: "local-obligation-receipt-v1",
    key_id: "key-1",
    digest: "blake3:digest",
    signature: "blake3:signature"
  };
  const receipt: AuthorityObligationReceipt = {
    schema_version: AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION,
    receipt_id: "00000000-0000-4000-8000-000000000001" as AuthorityObligationReceipt["receipt_id"],
    issuer: "00000000-0000-4000-8000-000000000002" as AuthorityObligationReceipt["issuer"],
    audience: "daemon:local",
    obligation_id: "00000000-0000-4000-8000-000000000003" as AuthorityObligationReceipt["obligation_id"],
    kind: "human_review",
    subject: "00000000-0000-4000-8000-000000000004" as AuthorityObligationReceipt["subject"],
    authority_decision_id: "00000000-0000-4000-8000-000000000005" as AuthorityObligationReceipt["authority_decision_id"],
    canonical_request_digest: "blake3:request",
    evidence_digest: "blake3:evidence",
    evidence_ref: null,
    issued_at: "2026-07-12T00:00:00Z",
    expires_at: "2026-07-12T00:05:00Z",
    revocation: "active",
    revocation_ref: "revocation:receipt-1",
    approval_id: null,
    approval_trace_event_id: null,
    validation
  };
  const profile: RegisteredAction = {
    name: "fixture.write",
    adapter: "fixture.local",
    required_permissions: ["fixture.write"]
  };
  const candidateIdentity: Pick<DaemonActionCandidate, "action_id"> = {
    action_id: "00000000-0000-4000-8000-000000000006" as DaemonActionCandidate["action_id"]
  };
  assert.equal(receipt.kind, "human_review");
  assert.deepEqual(profile.required_permissions, ["fixture.write"]);
  assert.equal(candidateIdentity.action_id, "00000000-0000-4000-8000-000000000006");

  const invalidValidation: AuthorityObligationReceiptValidation = {
    ...validation,
    // @ts-expect-error validation contract rejects unknown credential fields
    credential: "secret"
  };
  assert.equal(invalidValidation.validation_kind, "local_signature");
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
    "TraceExportRequest",
    "ReplayRequest",
    "ReplayResponse",
    "SubmitActionRequest",
    "HealthResponse",
    "CapabilitiesResponse",
    "ServiceCapabilityProfile",
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
  for (const schema of ["TraceExportRequest", "ReplayRequest"]) {
    const block = extractOpenApiSchemaBlock(openapi, schema);
    assert.doesNotMatch(block, /credential:[\s\S]*?type:\s*'null'/, `${schema}.credential must be non-null`);
    assert.doesNotMatch(block, /audit_attribution:[\s\S]*?type:\s*'null'/, `${schema}.audit_attribution must be non-null`);
    assert.match(block, /credential:\n\s+\$ref: '#\/components\/schemas\/CallerCredential'/, `${schema}.credential must reference CallerCredential directly`);
    assert.match(block, /audit_attribution:\n\s+\$ref: '#\/components\/schemas\/AuditAttribution'/, `${schema}.audit_attribution must reference AuditAttribution directly`);
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
  assert.match(createRun, /- request_id/);
  assert.match(createRun, /- idempotency_key/);
  assert.match(createRun, /request_id:[\s\S]*minLength: 1/);
  assert.match(createRun, /idempotency_key:[\s\S]*minLength: 1/);
  assert.match(createRun, /work_order:[\s\S]*\$ref: '#\/components\/schemas\/WorkOrderEnvelope'/);
  assert.doesNotMatch(createRun, /WorkOrderAuthorization/);

  const createRunResponse = extractOpenApiSchemaBlock(openapi, "CreateRunResponse");
  for (const field of ["request_id", "idempotency_key", "idempotency_receipt_id", "duplicate", "run_id", "status"]) {
    assert.match(createRunResponse, new RegExp(`required: \\[.*${field}`), `CreateRunResponse must require ${field}`);
  }

  const capabilities = extractOpenApiSchemaBlock(openapi, "CapabilitiesResponse");
  assert.match(capabilities, /service_profiles:[\s\S]*\$ref: '#\/components\/schemas\/ServiceCapabilityProfile'/);

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
  const primitives = readRepoFile("crates/splendor-types/src/primitives.rs");
  const message = readRepoFile("crates/splendor-types/src/message.rs");
  const approval = readRepoFile("crates/splendor-types/src/approval.rs");

  assert.deepEqual([...TRACE_EVENT_KIND_VARIANTS], extractEnumVariants(trace, "TraceEventKind"));
  assert.deepEqual([...ACTION_STATUS_VALUES], extractEnumVariants(gateway, "ActionStatus"));
  assert.deepEqual([...STABLE_0_1_ENUM_VALUES.action_status], extractEnumVariants(gateway, "ActionStatus"));
  assert.deepEqual([...STABLE_0_1_ENUM_VALUES.approval_decision], extractEnumVariants(approval, "ApprovalDecision"));
  assert.deepEqual([...STABLE_0_1_ENUM_VALUES.constraint_kind], extractEnumVariants(primitives, "ConstraintKind"));
  assert.deepEqual([...STABLE_0_1_ENUM_VALUES.constraint_scope], extractEnumVariants(primitives, "ConstraintScope"));
  assert.deepEqual([...STABLE_0_1_ENUM_VALUES.side_effect_class], extractEnumVariants(primitives, "SideEffectClass").filter((variant) => variant !== "Custom"));
  assert.deepEqual(
    [...STABLE_0_1_ENUM_VALUES.message_delivery_status],
    extractEnumVariants(message, "MessageDeliveryStatus").map(pascalToSnake)
  );
  assert.deepEqual([...ENDPOINT_SCOPE_VALUES], extractEnumVariants(readRepoFile("crates/splendor-types/src/daemon_security.rs"), "EndpointScope"));
});

test("OpenAPI endpoint scopes stay aligned with TypeScript client scope labels", () => {
  const openapi = readRepoFile("openapi/splendor-runtime-daemon.yaml");
  const openapiScopes = extractOpenApiStringEnum(openapi, "EndpointScope");
  assert.deepEqual(openapiScopes, Object.keys(ENDPOINT_SCOPE_LABELS));
});
