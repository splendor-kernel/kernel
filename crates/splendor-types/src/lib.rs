//! # Splendor Kernel Types
//!
//! Canonical data structures that form Splendor's kernel contract: stable
//! identifiers, trace event taxonomy, verification outcomes, and
//! content-addressed hashes. These types are deterministic, serializable, and
//! safe to persist across runs so higher-level components can replay and audit
//! agent behavior.
//!
//! ## Design goals
//! - **Deterministic** identifiers for reproducibility.
//! - **Serializable** payloads for trace and state storage.
//! - **Auditable** structures for governance and debugging.
//!
//! ## Example
//! ```rust,no_run
//! use splendor_types::{Action, CostEstimate, SideEffectClass};
//!
//! let action = Action {
//!     name: "http_get".to_string(),
//!     params: serde_json::json!({"url": "https://example.com"}),
//!     side_effect_class: SideEffectClass::Network,
//!     cost_estimate: Some(CostEstimate {
//!         units: "ms".to_string(),
//!         amount: 25.0,
//!     }),
//!     required_permissions: vec!["http:read".to_string()],
//!     preconditions: vec!["allowed_domain".to_string()],
//!     postconditions: vec!["status:200".to_string()],
//! };
//! assert_eq!(action.name, "http_get");
//! ```

mod approval;
mod authority;
mod capabilities;
mod cloud_helper;
mod daemon_security;
mod determinism;
mod device_profile;
mod driver;
mod escalation;
mod external_governance;
mod failure_taxonomy;
mod fleet_telemetry;
mod foundation_grammar;
mod governance;
mod hash;
mod identity;
mod ids;
mod message;
mod node_registry;
mod performance_budgets;
mod placement;
mod policy_distribution;
mod primitives;
mod schema_extensions;
mod secret_lease;
mod secret_ref;
mod secret_use_requirement;
mod secrets;
mod security_invariants;
mod state_handoff;
mod trace;
mod work_order;

pub use approval::{
    ApprovalActionScope, ApprovalChallenge, ApprovalDecision, ApprovalEvidence, ApprovalPolicy,
    ApprovalTraceContext, ResidentApprovalReceiptRevocationAck,
    ResidentApprovalReceiptRevocationRequest, ResidentApprovalReceiptRevocationStatus,
    APPROVAL_CHALLENGE_SCHEMA_VERSION, APPROVAL_EVIDENCE_SCHEMA_VERSION,
    APPROVAL_POLICY_SCHEMA_VERSION, RESIDENT_APPROVAL_RECEIPT_REVOCATION_ACK_SCHEMA_VERSION,
    RESIDENT_APPROVAL_RECEIPT_REVOCATION_SCHEMA_VERSION,
};
pub use authority::{
    AuthorityBudgetScope, AuthorityDecision, AuthorityDecisionStatus, AuthorityObligation,
    AuthorityObligationKind, AuthorityObligationReceipt, AuthorityObligationReceiptValidation,
    AuthorityObligationReceiptValidationKind, AuthorityOperation, AuthorityOperationNamespace,
    AuthorityResourceKind, AuthorityTimeScope, AuthorityVerb, CapabilityGrant,
    CapabilityGrantValidation, CapabilityGrantValidationKind, CapabilityRequest, CapabilityScope,
    DataPurpose, DelegationChain, DelegationCleanupObligations, DelegationGrant,
    DelegationLedgerEvidence, DelegationLedgerTraceSummary, DelegationReservationStatus,
    DelegationResultContract, DelegationRoleProfile, DriverOperationRef, LocalityScope,
    NetworkScope, PhysicalActionResourceCoordinate, PhysicalActionResourceKind, RevocationRecord,
    AUTHORITY_DECISION_SCHEMA_VERSION, AUTHORITY_OBLIGATION_RECEIPT_SCHEMA_VERSION,
    AUTHORITY_OBLIGATION_SCHEMA_VERSION, AUTHORITY_OPERATION_SCHEMA_VERSION,
    CAPABILITY_GRANT_SCHEMA_VERSION, CAPABILITY_REQUEST_SCHEMA_VERSION,
    CAPABILITY_SCOPE_SCHEMA_VERSION, DELEGATION_CHAIN_SCHEMA_VERSION,
    DELEGATION_GRANT_SCHEMA_VERSION, DELEGATION_RESULT_CONTRACT_SCHEMA_VERSION,
    REVOCATION_RECORD_SCHEMA_VERSION,
};
pub use capabilities::{
    is_valid_capability_name, CapabilityDocument, CapabilityValidationError,
    CAPABILITY_DOCUMENT_SCHEMA,
};
pub use cloud_helper::{
    cloud_helper_failure_validation, validate_cloud_helper_work_order,
    validate_route_plan_for_local_execution, CloudHelperAuthority, CloudHelperValidationError,
    LocalRoutePlanValidation, RoutePlanProposal, RouteWaypointProposal, CLOUD_HELPER_ADAPTER_ID,
    CLOUD_HELPER_UNAVAILABLE_REASON, MISSION_PLAN_PROPOSE_ACTION, ROUTE_PLAN_PROPOSAL_SCHEMA,
    ROUTE_PLAN_PROPOSE_ACTION,
};
pub use daemon_security::{
    validate_client_connection_policy, validate_daemon_request, validate_insecure_dev_mode,
    AppPrincipal, AuditAttribution, CallerCredential, ClientConnectionPolicy, ClientPrincipal,
    CredentialAudience, CredentialBinding, DaemonEndpoint, DaemonSecurityDecision,
    DaemonSecurityError, DaemonSecurityRequest, EndpointScope, GatewayVerificationState,
    InsecureDevMode, LocalTransportBinding, RevocationStatus, WorkOrderAuthorization,
    WorkOrderSignature,
};
pub use determinism::{DeterminismError, DeterministicIdFactory, FixedClock, StepClock};
pub use device_profile::{
    is_allowed_physical_action, physical_action_capability, validate_physical_capability_document,
    DeviceCapability, DeviceCapabilityCategory, DeviceLocalPolicyIndicators, DeviceNodeKind,
    DeviceProfile, DeviceProfileValidationError, DeviceSafetyConstraint, ALLOWED_PHYSICAL_ACTIONS,
    DEVICE_KIND_CAPABILITY_PREFIX, DEVICE_PROFILE_SCHEMA, FORBIDDEN_PHYSICAL_ACTION_PATTERNS,
    PHYSICAL_ACTION_CAPABILITY_PREFIX,
};
pub use driver::{
    validate_driver_operation_ref_v1, DriverCredentialDestinationDigest,
    DriverCredentialDestinationDigestError, DriverCredentialSinkContractError,
    DriverCredentialSinkContractErrorCode, DriverOperationCredentialSinkV1,
    DriverOperationCredentialSinksV1, DriverOperationRefV1ValidationError,
    DriverTrustedSendProfileV1, SecretCredentialSlotId, SecretCredentialSlotIdError,
    DRIVER_OPERATION_CREDENTIAL_SINKS_SCHEMA_V1, DRIVER_OPERATION_SCHEMA_V1,
};
pub use escalation::{
    EscalationContext, EscalationDecision, EscalationObservation, EscalationPolicy,
    EscalationPolicyError, EscalationRule, EscalationScope, EscalationTrigger,
    ESCALATION_POLICY_SCHEMA_VERSION,
};
pub use external_governance::{
    ExternalApprovalDecision, ExternalApprovalDecisionKind, ExternalApprovalMapping,
    ExternalGovernanceAdapterContract, ExternalGovernanceAdapterError,
    ExternalGovernanceAdapterFailure, ExternalGovernanceEndpoints, ExternalGovernanceReference,
    ExternalGovernanceWorkOrderBridge, ExternalTraceRange, GovernedArtifactRef,
    EXTERNAL_GOVERNANCE_ADAPTER_SCHEMA_VERSION, GOVERNED_ARTIFACT_REF_SCHEMA_VERSION,
};
pub use failure_taxonomy::{
    EffectCertainty, ErrorCategory, ErrorTaxonomy, ProviderDetail, ReasonCode, ReasonCodeError,
    RetryClass, UNKNOWN_ADAPTER_FAILURE_REASON, UNKNOWN_PROVIDER_FAILURE_REASON,
};
pub use fleet_telemetry::{
    DenialSignal, FailureCategory, FailureSignal, FleetTelemetrySnapshot, InstanceTelemetry,
    NodeOnlineState, NodeTelemetry, QueueTelemetry, QuotaSignal, RunStatus, RunStatusCount,
    RunStatusCounts, RunTelemetry, RuntimeMode as TelemetryRuntimeMode, TelemetryAuthority,
    TraceSyncFailure, TraceSyncTelemetry, FLEET_TELEMETRY_SCHEMA_VERSION,
};
pub use foundation_grammar::{
    CanonicalCountV1, CanonicalLabelV1, CanonicalOrdinalV1, CanonicalPositiveRevisionV1,
    CanonicalSchemaIdV1, CanonicalSequenceV1, CanonicalTimestampV1, FoundationGrammarCodeV1,
    FoundationGrammarError, RegistryDeclarationDigest,
};
pub use governance::{
    ApprovalDenial, ApprovalGrant, ApprovalRequest, ApprovalStatus, CircuitBreaker,
    CircuitBreakerMatch, CircuitBreakerScope, CircuitBreakerState, CircuitBreakerStatus,
    CircuitBreakerTraceContext, CircuitBreakerValidationError, Escalation, EscalationStatus,
    GovernanceCircuitBreaker, GovernanceExtensions, GovernanceIssuer, GovernanceObjectKind,
    GovernanceObjectRef, GovernanceRevocation, GovernanceScope, GovernanceState,
    GovernanceTraceLink, GovernanceTransition, GovernanceTransitionError,
    GovernanceTransitionRejection, GovernanceValidationError, Intervention, InterventionStatus,
    KillSwitch, KillSwitchStatus, CIRCUIT_BREAKER_SCHEMA_VERSION, GOVERNANCE_STATE_SCHEMA_VERSION,
};
pub use hash::{ContentHash, HashAlgorithm};
pub use identity::{
    IdentityBindingLookupKind, IdentityLifecycleEvent, IdentityLifecycleEventKind,
    IdentityLookupKey, IdentityLookupSummary, IdentityQuery, IdentityQueryResult,
    IdentityQuerySummary, IdentityRevision, Principal, PrincipalBinding, PrincipalDisplay,
    PrincipalKind, PrincipalProofRef, PrincipalSnapshot, PrincipalStatus,
};
pub use ids::{
    ActionId, AgentId, ApprovalId, ArtifactId, AuthorityDecisionId, AuthorityObligationId,
    AuthorityObligationReceiptId, AuthorityRevocationId, CapabilityGrantId, CircuitBreakerId,
    DeviceId, EscalationId, FleetId, IdentityEventId, IdentityValidationError, InstanceId,
    InterventionId, KillSwitchId, MessageId, NodeId, PrincipalId, PrincipalProofRefId, RunId,
    RuntimeIdentityContext, SecretAccessEventId, SecretActionIdempotencyKey,
    SecretActionSubmissionId, SecretApprovalContinuationId, SecretAudienceId,
    SecretBootstrapSourceBindingId, SecretCleanupCommandId, SecretConsumedEffectTombstoneId,
    SecretContainmentCommandId, SecretContainmentReserveId, SecretDeliveryControlAttestationId,
    SecretDeliveryHandleId, SecretDeliveryReceiptId, SecretDetectorRegistrationId,
    SecretExposureLineageId, SecretIdParseError, SecretLeaseId, SecretLeaseRequestId,
    SecretNodeControlInvocationId, SecretNodeControlReceiptId,
    SecretOuterAdmissionCapacityBindingId, SecretPermanentAuxiliaryIdentityMarkerId,
    SecretProviderAuditId, SecretProviderControlInvocationId, SecretProviderId,
    SecretProviderRouteId, SecretPublicationAuthorizationId, SecretPublicationPreparationId,
    SecretPublicationPrepareReceiptId, SecretReconciliationClaimId, SecretRefId,
    SecretRefMutationCommandId, SecretRenewalCommandId, SecretRetiredAuthorityDomainDenyHeadId,
    SecretRetirementManifestId, SecretRevocationCommandId, SecretRotationCommandId,
    SecretTickCandidateObservationId, SecretTickCandidateObservationLinkReceiptId,
    SecretUseAttemptId, SecretUseClaimId, SnapshotId, StateNodeId, StatePartitionId, TenantId,
    TickId, TraceEventId, TraceId, TraceIdentityContext, WorkOrderId, WorkOrderIdError, WorkloadId,
};
pub use message::{
    DelegatedAuthority, LocalDelegationAuthorityEvidence, Message, MessageDeliveryStatus,
    MessageEnvelope, MessageSchemaVersion, MessageTraceContext, MessageTraceLinks,
    MessageValidationError, RemoteMessageEnvelope, RemoteMessageEnvelopeVersion,
    RemoteMessageRetryPolicy, RemoteMessageTraceContext, RemoteMessageValidationError, TaskFailure,
    TaskRequest, TaskResponse, TaskResponseStatus,
    LOCAL_DELEGATION_AUTHORITY_EVIDENCE_SCHEMA_VERSION, TASK_REQUEST_SCHEMA,
    TASK_REQUEST_SCHEMA_V1, TASK_RESPONSE_SCHEMA,
};
pub use node_registry::{
    HealthStatus, InstanceHealth, InstanceHeartbeat, InstanceRegistration, ManagementAuditEvent,
    ManagementAuditEventKind, NodeHealth, NodeHeartbeat, NodeKind, NodeRegistration,
    NodeRegistryValidationError, RegistryScope, RuntimeMode,
};
pub use performance_budgets::{
    validate_performance_budget_catalog, BenchmarkEnvironment, GoldBudgetEvidenceStatus,
    GoldSloResourceBudget, LatencyBudget, MeasurementBoundary, PerformanceBudgetCatalog,
    PerformanceBudgetValidationError, PerformanceReportStatus, PerformanceReportSummary,
    RegressionThreshold, ResourceBudget, ResourceBudgetKind, RetentionBackpressureAction,
    RetentionBackpressureKind, ScaleTarget, ThroughputBudget, PERFORMANCE_BUDGET_EVIDENCE_SCOPE,
    PERFORMANCE_BUDGET_SCHEMA_VERSION, REQUIRED_LATENCY_BUDGET_METRICS,
    REQUIRED_PERFORMANCE_GOLD_IDS, REQUIRED_PERFORMANCE_NON_CLAIMS,
    REQUIRED_THROUGHPUT_BUDGET_METRICS,
};
pub use placement::{
    select_placement, DataLocality, PlacementCandidate, PlacementCandidateEvaluation,
    PlacementDecision, PlacementDecisionStatus, PlacementExecutionMode, PlacementExplain,
    PlacementRejectionReason, PlacementRequest, PlacementTarget, PlacementTraceAudit,
    PLACEMENT_DECISION_SCHEMA,
};
pub use policy_distribution::{
    validate_policy_bundle, validate_policy_bundle_candidate, OfflineHighRiskBehavior,
    PolicyBundle, PolicyBundleEnvelope, PolicyBundleId, PolicyBundleIdError, PolicyBundleKeyring,
    PolicyBundleTraceContext, PolicyBundleValidationContext, PolicyBundleValidationError,
    PolicyDegradedMode, ValidatedPolicyBundle, ValidatedPolicyBundleCandidate,
    POLICY_BUNDLE_SCHEMA_VERSION, POLICY_BUNDLE_SIGNATURE_ALGORITHM,
};
pub use primitives::{
    Action, Constraint, ConstraintKind, ConstraintScope, CostEstimate, Feedback, Percept,
    PerceptProvenance, QuotaUsage, Reward, SideEffectClass, VerificationResult,
};
pub use schema_extensions::{
    is_reserved_extension_key, normalize_extension_key, validate_extension_map,
    validate_extension_map_with_reserved_keys, validate_extension_value,
    validate_extension_value_with_reserved_keys, ExtensionValidationError,
    ExtensionValidationReason, RESERVED_EXTENSION_KEYS, RESERVED_EXTENSION_KEY_FRAGMENTS,
};
pub use secret_lease::{
    SecretAccessDenialCode, SecretAccessEvidence, SecretAccessEvidenceKind,
    SecretAccessEvidenceOutcome, SecretLeaseContractError, SecretLeaseRequest, SecretLeaseSnapshot,
    SecretLeaseStatus, SecretLeaseUseBinding, SECRET_ACCESS_EVIDENCE_SCHEMA_V1,
    SECRET_LEASE_REQUEST_SCHEMA_V1, SECRET_LEASE_SNAPSHOT_SCHEMA_V1,
    SECRET_LEASE_USE_BINDING_SCHEMA_V1,
};
pub use secret_ref::{
    compare_secret_credential_authorization_v2, HistoricalSecretCredentialAuthorizationV1,
    HistoricalSecretRefV1, HistoricalSecretRefV1Error, HistoricalSecretRefV1LiveDenial,
    SecretCredentialAuthorizationV2, SecretCredentialAuthorizationV2Error,
    SecretCredentialAuthorizationV2ErrorCode, SecretCredentialDeclarationComparisonV2,
    SecretCredentialDeclarationMismatchCodeV2, SecretRefV2, SecretRefV2Error, SecretRefV2ErrorCode,
    SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V2, SECRET_REF_SCHEMA_V2,
};
pub use secret_use_requirement::{
    SecretUseRequirement, SecretUseRequirementError, SECRET_USE_REQUIREMENT_SCHEMA_V1,
};
pub use secrets::{
    SecretClassification, SecretDeliveryControlKind, SecretDeliveryExposureProfile,
    SecretDeliveryMethod, SecretLeasePolicy, SecretLeasePolicyError, SecretOfflineBehavior,
    SecretProviderVersionRef, SecretProviderVersionRefError, SecretPurpose, SecretUseIntent,
};
pub use security_invariants::{
    validate_security_invariant_catalog, ContainmentAction, CryptoAgility, ExecutableGoldEvidence,
    FailClosedDecision, KeyRotationPolicy, SecurityCaseStatus, SecurityEnforcementMapping,
    SecurityInvariantCatalog, SecurityInvariantRecord, SecurityInvariantValidationError,
    SecurityMaturityGate, SecurityPlane, SecurityReviewChecklistItem, SecurityThreatId,
    SecurityThreatIdError, TrustBoundary, ALL_SECURITY_PLANES, REQUIRED_SECURITY_GOLD_IDS,
    SECURITY_INVARIANT_PARTIAL_EVIDENCE_SCOPE, SECURITY_INVARIANT_REQUIRED_NON_CLAIMS,
    SECURITY_INVARIANT_SCHEMA_VERSION,
};
pub use state_handoff::{
    StateHandoff, StateHandoffAuthority, StateHandoffSnapshot, StateHandoffTraceContext,
    StateReference, StateReferenceMode,
};
pub use trace::{
    GovernanceTraceEventKindError, LocalDelegationTraceContext, OfflineTraceIntervalTraceContext,
    TraceEvent, TraceEventKind, TraceIntegrity, TraceSyncBoundaryTraceContext,
};
pub use work_order::{
    validate_work_order, ValidatedWorkOrder, WorkOrder, WorkOrderEnvelope, WorkOrderKeyring,
    WorkOrderPlacement, WorkOrderQuotaPolicy, WorkOrderValidationContext, WorkOrderValidationError,
    WORK_ORDER_SCHEMA_VERSION, WORK_ORDER_SIGNATURE_ALGORITHM,
};

#[cfg(test)]
#[path = "../tests/unit/lib_tests.rs"]
mod tests;
