//! # Splendor Kernel Runtime
//!
//! The kernel crate exposes the runtime surface used by higher-level systems to
//! emit trace events, manage explicit state graphs, and drive deterministic
//! kernel loops. It re-exports the stable primitives from `splendor-types` so
//! consumers can build against a unified contract.
//!
//! ## Capabilities
//! - Emit ordered trace events via pluggable sinks.
//! - Commit explicit state graph nodes and snapshots.
//! - Provide a stable API surface for kernel-adjacent components.
//!
//! ## Example
//! ```rust,no_run
//! use splendor_kernel::{KernelRuntime, KernelRuntimeConfig, TraceEventKind};
//!
//! let runtime = KernelRuntime::new(KernelRuntimeConfig::default());
//! let event = runtime
//!     .record_event(TraceEventKind::LoopTickCompleted {
//!         tick_id: 1,
//!         integrity: None,
//!     })
//!     .expect("record");
//! assert_eq!(event.sequence, 0);
//! ```

mod escalation;
mod fleet_telemetry;
mod local_delegation;
mod loop_engine;
mod message_router;
mod node_registry;
mod policy_cache;
mod remote_message_transport;
mod runtime;
mod scheduler;
mod state;
mod tenancy;
mod trace;
mod trace_durability;

pub use escalation::{
    apply_escalation_to_outcome, escalations_require_intervention, observations_for_outcome,
    EscalationEvaluator, EscalationOutcomeInput, ESCALATION_ENGINE_SOURCE,
};
pub use fleet_telemetry::{FleetTelemetryCollector, TelemetryThresholds};
pub use local_delegation::{
    replay_local_delegations, LocalAgentRegistration, LocalChildRun, LocalDelegationAuthority,
    LocalDelegationError, LocalDelegationManager, LocalDelegationRejection, LocalDelegationReplay,
    LocalDelegationRequest, LocalRunRecord, LocalRunStatus, LocalTaskResponse,
    REASON_CHILD_CAPABILITY_GRANT_ID_COLLISION, REASON_MISSING_PARENT_RUN_GRANT_BINDING,
    REASON_PARENT_RUN_GRANT_MISMATCH,
};
pub use loop_engine::{
    ActionCandidate, AllowAllConstraintEngine, ConstraintEngine, ConstraintEvaluation, LoopEngine,
    LoopError, NoopOutcomeEvaluator, OutcomeEvaluator, OutcomeSignal, Perceptor, Policy,
    PolicyDecision, ResumeInfo, RunTraceContext, TickOutcome,
};
pub use message_router::{
    AgentMailboxSnapshot, LocalMessageRouter, MessageRouter, MessageRouterConfig,
    MessageRouterError, MessageTraceRecorder,
};
pub use node_registry::{
    HeartbeatFreshness, InMemoryManagementAuditSink, InMemoryNodeRegistry, InstanceRecord,
    ManagementAuditError, ManagementAuditSink, NodeRecord, NodeRegistry, NodeRegistryConfig,
    NodeRegistryError, RegistryHealthStatus,
};
pub use policy_cache::{
    PolicyCache, PolicyCacheConfig, PolicyCacheInstallError, PolicyCacheInstallPlan,
    PolicyCacheInstallResult, PolicyCacheInstallStatus, PolicyCacheOwner,
    PolicyCacheRevocationMetadata, PolicyCacheRevocationPlan, PolicyCacheRevocationResult,
    PolicyCacheRevocationStatus, PolicyCacheSnapshot, PolicyCacheValidationMetadata,
    PolicyDistributionGateway, PolicyDistributionStatus, PolicyOfflineStatus,
    PolicyRuntimeAuthority, PolicyRuntimeDecision, PolicySyncFailure,
};
pub use remote_message_transport::{
    send_remote_message, InMemoryRemoteMessageTransport, InMemoryRemoteTransportFault,
    RemoteMessageReceiver, RemoteMessageTransport, RemoteMessageTransportError,
};
pub use runtime::{KernelRuntime, KernelRuntimeConfig};
pub use scheduler::{Scheduler, SchedulerConfig, SchedulerError, SchedulerStep};
pub use splendor_types::{
    cloud_helper_failure_validation, validate_cloud_helper_work_order,
    validate_route_plan_for_local_execution, Action, ActionId, AgentId, AuthorityBudgetScope,
    CapabilityDocument, CapabilityGrantId, CapabilityValidationError, CloudHelperAuthority,
    CloudHelperValidationError, Constraint, ConstraintKind, ConstraintScope, ContentHash,
    CostEstimate, DelegatedAuthority, DelegationRoleProfile, DenialSignal, EscalationContext,
    EscalationDecision, EscalationObservation, EscalationPolicy, EscalationPolicyError,
    EscalationRule, EscalationScope, EscalationTrigger, FailureCategory, FailureSignal, Feedback,
    FleetId, FleetTelemetrySnapshot, HashAlgorithm, HealthStatus, IdentityValidationError,
    InstanceHealth, InstanceHeartbeat, InstanceId, InstanceRegistration, InstanceTelemetry,
    LocalDelegationAuthorityEvidence, LocalDelegationTraceContext, LocalRoutePlanValidation,
    ManagementAuditEvent, ManagementAuditEventKind, Message, MessageDeliveryStatus,
    MessageEnvelope, MessageId, MessageSchemaVersion, MessageTraceContext, MessageTraceLinks,
    MessageValidationError, NodeHealth, NodeHeartbeat, NodeId, NodeKind, NodeOnlineState,
    NodeRegistration, NodeRegistryValidationError, NodeTelemetry, Percept, PerceptProvenance,
    PolicyBundle, PolicyBundleEnvelope, PolicyBundleId, PolicyBundleKeyring,
    PolicyBundleTraceContext, PolicyBundleValidationContext, PolicyBundleValidationError,
    PolicyDegradedMode, PrincipalId, QueueTelemetry, QuotaSignal, QuotaUsage, RegistryScope,
    RemoteMessageEnvelope, RemoteMessageEnvelopeVersion, RemoteMessageRetryPolicy,
    RemoteMessageTraceContext, RemoteMessageValidationError, Reward, RoutePlanProposal,
    RouteWaypointProposal, RunId, RunStatus, RunStatusCount, RunStatusCounts, RunTelemetry,
    RuntimeIdentityContext, RuntimeMode, SideEffectClass, SnapshotId, StateHandoff,
    StateHandoffAuthority, StateHandoffSnapshot, StateHandoffTraceContext, StateNodeId,
    StateReference, StateReferenceMode, TaskFailure, TaskRequest, TaskResponse, TaskResponseStatus,
    TelemetryAuthority, TelemetryRuntimeMode, TenantId, TickId, TraceEvent, TraceEventId,
    TraceEventKind, TraceId, TraceIdentityContext, TraceSyncFailure, TraceSyncTelemetry,
    VerificationResult, CLOUD_HELPER_ADAPTER_ID, CLOUD_HELPER_UNAVAILABLE_REASON,
    ESCALATION_POLICY_SCHEMA_VERSION, FLEET_TELEMETRY_SCHEMA_VERSION, MISSION_PLAN_PROPOSE_ACTION,
    POLICY_BUNDLE_SCHEMA_VERSION, POLICY_BUNDLE_SIGNATURE_ALGORITHM, ROUTE_PLAN_PROPOSAL_SCHEMA,
    ROUTE_PLAN_PROPOSE_ACTION, TASK_REQUEST_SCHEMA, TASK_RESPONSE_SCHEMA,
};
pub use state::{
    SnapshotPolicy, StateCommit, StateGraph, StateGraphError, StateHandoffExportRequest,
    StateHandoffScope,
};
pub use tenancy::{
    AdapterQuota, AgentContext, AgentIsolationPolicy, AgentRuntimeConfig, QuotaLedger, QuotaPolicy,
    TenantContext, TenantPolicy, TenantRegistry, AGENT_ISOLATION_LEDGER_SOURCE,
    QUOTA_LEDGER_SOURCE,
};
pub use trace::{AsyncTraceSink, StdoutTraceSink, TraceError, TraceSink, TraceStoreSink};
pub use trace_durability::{
    TraceDurabilityGateway, TraceDurabilityMonitor, TraceDurabilityPolicy, TraceDurabilityState,
    TraceDurabilityStatus,
};

#[cfg(test)]
#[path = "../tests/unit/cloud_helper_tests.rs"]
mod cloud_helper_tests;

#[cfg(test)]
#[path = "../tests/unit/physical_simulation_harness_tests.rs"]
mod physical_simulation_harness_tests;
