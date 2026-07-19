//! # Kernel Identifiers
//!
//! Stable identifiers for Splendor kernel entities. These identifiers are
//! intentionally distinct types so principal, fleet, node, instance, tenant,
//! agent, run, tick, action, state, trace, and message identities cannot be
//! interchanged by accident. UUID-backed IDs provide predictable formatting and
//! deterministic derivation where required (for example, trace events use a
//! stable UUID derived from the run ID and sequence number). State node IDs
//! remain content-addressed.
//!
//! ## Example
//! ```rust,no_run
//! use splendor_types::{RunId, TraceEventId};
//!
//! let run_id = RunId::new();
//! let trace_event_id = TraceEventId::from_run_sequence(&run_id, 42);
//! assert_eq!(trace_event_id.to_string().len(), 36);
//! ```

use crate::ContentHash;
use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new identifier using a random UUID.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Parses the canonical UUID string representation for this ID type.
            pub fn parse(value: &str) -> Result<Self, uuid::Error> {
                Uuid::parse_str(value).map(Self)
            }

            /// Returns the underlying UUID.
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Returns true when this identifier is the nil UUID and therefore invalid.
            pub fn is_nil(&self) -> bool {
                self.0.is_nil()
            }
        }

        impl Default for $name {
            /// Creates a new identifier using a random UUID.
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            /// Formats the identifier as a UUID string.
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<Uuid> for $name {
            /// Wraps an existing UUID as this identity type.
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            /// Parses the canonical UUID string representation for this ID type.
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

uuid_id! {
    /// Unique identifier for a registry principal identity.
    PrincipalId
}

uuid_id! {
    /// Unique identifier for an immutable principal lifecycle event.
    IdentityEventId
}

uuid_id! {
    /// Unique identifier for a proof reference bound to a principal.
    PrincipalProofRefId
}

uuid_id! {
    /// Unique identifier for an immutable capability grant.
    CapabilityGrantId
}

uuid_id! {
    /// Unique identifier for an authority decision record.
    AuthorityDecisionId
}

uuid_id! {
    /// Unique identifier for an authority revocation record.
    AuthorityRevocationId
}

uuid_id! {
    /// Unique identifier for an explicit authority obligation.
    AuthorityObligationId
}

uuid_id! {
    /// Unique identifier for an authority obligation receipt.
    AuthorityObligationReceiptId
}

uuid_id! {
    /// Unique identifier for a v2 workload boundary.
    WorkloadId
}

uuid_id! {
    /// Unique identifier for a physical or edge device boundary.
    DeviceId
}

uuid_id! {
    /// Unique identifier for an artifact reference.
    ArtifactId
}

uuid_id! {
    /// Unique identifier for a named state partition.
    StatePartitionId
}

uuid_id! {
    /// Unique identifier for a governed fleet boundary.
    FleetId
}

uuid_id! {
    /// Unique identifier for a physical, virtual, or logical node.
    NodeId
}

uuid_id! {
    /// Unique identifier for one running Splendor runtime process/instance.
    InstanceId
}

uuid_id! {
    /// Unique identifier for a tenant boundary.
    TenantId
}

uuid_id! {
    /// Unique identifier for an agent within a tenant.
    AgentId
}

uuid_id! {
    /// Unique identifier for a single runtime execution.
    RunId
}

uuid_id! {
    /// Unique identifier assigned to a submitted action.
    ActionId
}

uuid_id! {
    /// Unique identifier for a scoped approval object.
    ApprovalId
}

uuid_id! {
    /// Unique identifier for an agent-to-agent message.
    MessageId
}

uuid_id! {
    /// Unique identifier for an escalation governance lifecycle object.
    EscalationId
}

uuid_id! {
    /// Unique identifier for an operator/runtime intervention lifecycle object.
    InterventionId
}

uuid_id! {
    /// Unique identifier for a scoped circuit-breaker governance object.
    CircuitBreakerId
}

uuid_id! {
    /// Unique identifier for a scoped kill-switch governance object.
    KillSwitchId
}

/// Validation failure for a C03 secret identity.
///
/// Errors intentionally omit the rejected input so candidate values cannot be
/// copied into logs or API responses through formatting.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretIdParseError {
    /// The input was not canonical lowercase hyphenated UUID text.
    #[error("secret ID must use canonical lowercase hyphenated UUID text")]
    InvalidFormat,
    /// Nil is not a valid C03 secret identity.
    #[error("secret ID must not be nil")]
    Nil,
}

fn parse_strict_secret_uuid(value: &str) -> Result<Uuid, SecretIdParseError> {
    if value.len() != 36 || !value.is_ascii() {
        return Err(SecretIdParseError::InvalidFormat);
    }
    let uuid = Uuid::parse_str(value).map_err(|_| SecretIdParseError::InvalidFormat)?;
    let mut canonical = Uuid::encode_buffer();
    if uuid.hyphenated().encode_lower(&mut canonical) != value {
        return Err(SecretIdParseError::InvalidFormat);
    }
    if uuid.is_nil() {
        return Err(SecretIdParseError::Nil);
    }
    Ok(uuid)
}

struct StrictSecretUuidVisitor;

impl<'de> Visitor<'de> for StrictSecretUuidVisitor {
    type Value = Uuid;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("canonical lowercase hyphenated non-nil UUID text")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        parse_strict_secret_uuid(value).map_err(E::custom)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_char<E>(self, _value: char) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_byte_buf<E>(self, _value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_seq<A>(self, _sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        Err(A::Error::custom(SecretIdParseError::InvalidFormat))
    }

    fn visit_map<A>(self, _map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        Err(A::Error::custom(SecretIdParseError::InvalidFormat))
    }
}

macro_rules! strict_secret_uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Parses a non-nil canonical lowercase hyphenated UUID.
            pub fn parse(value: &str) -> Result<Self, SecretIdParseError> {
                parse_strict_secret_uuid(value).map(Self)
            }

            /// Returns the underlying non-nil UUID.
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = SecretIdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl TryFrom<Uuid> for $name {
            type Error = SecretIdParseError;

            fn try_from(value: Uuid) -> Result<Self, Self::Error> {
                if value.is_nil() {
                    Err(SecretIdParseError::Nil)
                } else {
                    Ok(Self(value))
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer
                    .deserialize_any(StrictSecretUuidVisitor)
                    .map(Self)
            }
        }
    };
}

strict_secret_uuid_id! {
    /// Unique identifier for one logical secret reference history.
    ///
    /// Secret identity types are nominal and cannot be interchanged:
    ///
    /// ```compile_fail
    /// use splendor_types::{SecretLeaseId, SecretRefId};
    ///
    /// fn accept_secret_ref(_id: SecretRefId) {}
    ///
    /// let lease_id: SecretLeaseId =
    ///     "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001".parse().unwrap();
    /// accept_secret_ref(lease_id);
    /// ```
    SecretRefId
}

strict_secret_uuid_id! {
    /// Unique identifier for one idempotent secret lease request.
    SecretLeaseRequestId
}

strict_secret_uuid_id! {
    /// Unique identifier for one secret lease lifecycle.
    SecretLeaseId
}

strict_secret_uuid_id! {
    /// Unique identifier for one node-local secret delivery-handle lifecycle.
    SecretDeliveryHandleId
}

strict_secret_uuid_id! {
    /// Unique identifier for one immutable secret-effect delivery receipt.
    SecretDeliveryReceiptId
}

strict_secret_uuid_id! {
    /// Unique identifier for one terminal delivery-control attestation.
    SecretDeliveryControlAttestationId
}

strict_secret_uuid_id! {
    /// Unique identifier for one durable outer secret-action submission.
    SecretActionSubmissionId
}

strict_secret_uuid_id! {
    /// Canonical UUID idempotency key for one direct secret-action submission.
    SecretActionIdempotencyKey
}

strict_secret_uuid_id! {
    /// Unique identifier for one exact secret approval continuation.
    SecretApprovalContinuationId
}

strict_secret_uuid_id! {
    /// Unique identifier for one outer-admission capacity binding.
    SecretOuterAdmissionCapacityBindingId
}

strict_secret_uuid_id! {
    /// Unique identifier for one configured secret provider.
    SecretProviderId
}

strict_secret_uuid_id! {
    /// Unique identifier for one immutable configured secret provider route.
    SecretProviderRouteId
}

strict_secret_uuid_id! {
    /// Unique identifier for one sanitized secret provider audit receipt.
    SecretProviderAuditId
}

strict_secret_uuid_id! {
    /// Unique identifier for one provider control invocation.
    SecretProviderControlInvocationId
}

strict_secret_uuid_id! {
    /// Unique identifier for one private bootstrap source binding.
    SecretBootstrapSourceBindingId
}

strict_secret_uuid_id! {
    /// Unique identifier for one immutable secret access event.
    SecretAccessEventId
}

strict_secret_uuid_id! {
    /// Unique identifier for one preclaim tick-candidate observation.
    SecretTickCandidateObservationId
}

strict_secret_uuid_id! {
    /// Unique identifier for one tick-candidate observation link receipt.
    SecretTickCandidateObservationLinkReceiptId
}

strict_secret_uuid_id! {
    /// Unique identifier for one resident-node secret control invocation.
    SecretNodeControlInvocationId
}

strict_secret_uuid_id! {
    /// Unique identifier for one immutable node-control terminal receipt.
    SecretNodeControlReceiptId
}

strict_secret_uuid_id! {
    /// Unique identifier for one trusted secret target audience.
    SecretAudienceId
}

strict_secret_uuid_id! {
    /// Unique identifier for one restricted detector registration.
    SecretDetectorRegistrationId
}

strict_secret_uuid_id! {
    /// Unique identifier for one secret exposure aggregate or lineage.
    SecretExposureLineageId
}

strict_secret_uuid_id! {
    /// Unique identifier for one reserved secret use attempt.
    SecretUseAttemptId
}

strict_secret_uuid_id! {
    /// Idempotency identifier for one secret-reference mutation command.
    SecretRefMutationCommandId
}

strict_secret_uuid_id! {
    /// Idempotency identifier for one secret renewal command.
    SecretRenewalCommandId
}

strict_secret_uuid_id! {
    /// Idempotency identifier for one secret rotation command.
    SecretRotationCommandId
}

strict_secret_uuid_id! {
    /// Idempotency identifier for one scoped secret revocation command.
    SecretRevocationCommandId
}

strict_secret_uuid_id! {
    /// Idempotency identifier for one secret cleanup command.
    SecretCleanupCommandId
}

strict_secret_uuid_id! {
    /// Idempotency identifier for one secret containment command.
    SecretContainmentCommandId
}

strict_secret_uuid_id! {
    /// Unique identifier for one atomic secret exposure or use claim.
    SecretUseClaimId
}

strict_secret_uuid_id! {
    /// Unique identifier for one pre-exposure containment reservation.
    SecretContainmentReserveId
}

strict_secret_uuid_id! {
    /// Unique identifier for one immutable publication preparation.
    SecretPublicationPreparationId
}

strict_secret_uuid_id! {
    /// Unique identifier for one final result or state publication authorization.
    SecretPublicationAuthorizationId
}

strict_secret_uuid_id! {
    /// Unique identifier for one publication prepare receipt.
    SecretPublicationPrepareReceiptId
}

strict_secret_uuid_id! {
    /// Unique identifier for one provider or node reconciliation claim.
    SecretReconciliationClaimId
}

strict_secret_uuid_id! {
    /// Unique identifier for one permanent consumed-effect tombstone.
    SecretConsumedEffectTombstoneId
}

strict_secret_uuid_id! {
    /// Unique identifier for one permanent containment auxiliary marker.
    SecretPermanentAuxiliaryIdentityMarkerId
}

strict_secret_uuid_id! {
    /// Unique identifier for one retired authority-domain deny head.
    SecretRetiredAuthorityDomainDenyHeadId
}

strict_secret_uuid_id! {
    /// Unique identifier for one authority-domain retirement manifest.
    SecretRetirementManifestId
}

/// Stable identifier for a signed work order.
///
/// Work-order IDs are issued by external managers and may use prefixed strings
/// such as `wo_123`; they are deliberately distinct from run, action, trace,
/// state, and message IDs.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkOrderId(String);

impl WorkOrderId {
    /// Creates a work-order identifier after rejecting empty values.
    pub fn try_new(value: impl Into<String>) -> Result<Self, WorkOrderIdError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(WorkOrderIdError::Empty);
        }
        Ok(Self(value))
    }

    /// Returns the raw work-order ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkOrderId {
    /// Formats the work-order identifier as its manager-issued string.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<WorkOrderId> for String {
    /// Converts the work-order identifier into its raw string.
    fn from(value: WorkOrderId) -> Self {
        value.0
    }
}

/// Work-order identifier validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkOrderIdError {
    /// Empty IDs are not valid authority objects.
    Empty,
}

/// Deterministic identifier for a trace event within a run.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TraceEventId(Uuid);

impl TraceEventId {
    /// Creates a new trace event identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Parses the canonical UUID string representation for a trace event ID.
    pub fn parse(value: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(value).map(Self)
    }

    /// Derives a deterministic trace event identifier from a run/sequence pair.
    pub fn from_run_sequence(run_id: &RunId, sequence: u64) -> Self {
        let name = format!("{run_id}:{sequence}");
        Self(Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes()))
    }

    /// Returns the underlying UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Returns true when this identifier is the nil UUID and therefore invalid.
    pub fn is_nil(&self) -> bool {
        self.0.is_nil()
    }
}

impl Default for TraceEventId {
    /// Creates a new trace event identifier using a random UUID.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TraceEventId {
    /// Formats the trace event identifier as a UUID string.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<Uuid> for TraceEventId {
    /// Wraps an existing UUID as a trace event identifier.
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl FromStr for TraceEventId {
    type Err = uuid::Error;

    /// Parses the canonical UUID string representation for a trace event ID.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Backwards-compatible alias for the 0.02 trace-event identifier name.
pub type TraceId = TraceEventId;

/// Tick identifier scoped within a run.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TickId(u64);

impl TickId {
    /// Creates a tick identifier from a monotonic tick counter.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the tick counter value.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for TickId {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for TickId {
    /// Formats the tick identifier as its decimal counter value.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Deterministic identifier for a state graph node.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StateNodeId(ContentHash);

impl StateNodeId {
    /// Wraps a content hash as a state node identifier.
    pub fn from_hash(hash: ContentHash) -> Self {
        Self(hash)
    }

    /// Returns the underlying content hash.
    pub fn hash(&self) -> &ContentHash {
        &self.0
    }
}

impl fmt::Display for StateNodeId {
    /// Formats the state node identifier as an algorithm-prefixed hash string.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for StateNodeId {
    /// Serializes state node identity as the canonical `algorithm:value` string.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for StateNodeId {
    /// Deserializes state node identity from the canonical `algorithm:value` string.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let hash = ContentHash::parse(&value)
            .ok_or_else(|| DeError::custom("state_node_id must be algorithm:value"))?;
        Ok(Self::from_hash(hash))
    }
}

/// Optional runtime placement identity fields inherited by emitted traces.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeIdentityContext {
    /// Fleet that owns the runtime instance, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_id: Option<FleetId>,
    /// Node hosting the runtime instance, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<NodeId>,
    /// Concrete Splendor runtime instance, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,
    /// Tenant currently bound to the runtime path, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<TenantId>,
    /// Agent currently bound to the runtime path, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
}

impl RuntimeIdentityContext {
    /// Validates all populated UUID-backed identity fields.
    pub fn validate(&self) -> Result<(), IdentityValidationError> {
        validate_optional_uuid("fleet_id", self.fleet_id.as_ref())?;
        validate_optional_uuid("node_id", self.node_id.as_ref())?;
        validate_optional_uuid("instance_id", self.instance_id.as_ref())?;
        validate_optional_uuid("tenant_id", self.tenant_id.as_ref())?;
        validate_optional_uuid("agent_id", self.agent_id.as_ref())?;
        Ok(())
    }
}

/// Identity fields embedded in every trace event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceIdentityContext {
    /// Fleet that owns the runtime instance, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_id: Option<FleetId>,
    /// Node hosting the runtime instance, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<NodeId>,
    /// Concrete Splendor runtime instance, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<InstanceId>,
    /// Tenant that scopes the event, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<TenantId>,
    /// Agent that scopes the event, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    /// Run that owns the event stream.
    pub run_id: RunId,
    /// Tick that scopes the event, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_id: Option<TickId>,
    /// Action associated with the event, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<ActionId>,
    /// Approval associated with the event, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    /// State node associated with the event, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_node_id: Option<StateNodeId>,
    /// Message associated with the event, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
}

impl TraceIdentityContext {
    /// Creates a trace identity context for a run.
    pub fn new(run_id: RunId) -> Self {
        Self {
            fleet_id: None,
            node_id: None,
            instance_id: None,
            tenant_id: None,
            agent_id: None,
            run_id,
            tick_id: None,
            action_id: None,
            approval_id: None,
            state_node_id: None,
            message_id: None,
        }
    }

    /// Creates trace identity from runtime placement context and run identity.
    pub fn from_runtime(run_id: RunId, runtime: &RuntimeIdentityContext) -> Self {
        let mut identity = Self::new(run_id);
        identity.fleet_id = runtime.fleet_id.clone();
        identity.node_id = runtime.node_id.clone();
        identity.instance_id = runtime.instance_id.clone();
        identity.tenant_id = runtime.tenant_id.clone();
        identity.agent_id = runtime.agent_id.clone();
        identity
    }

    /// Returns a copy with tenant and agent identity set.
    pub fn with_tenant_agent(mut self, tenant_id: TenantId, agent_id: AgentId) -> Self {
        self.tenant_id = Some(tenant_id);
        self.agent_id = Some(agent_id);
        self
    }

    /// Returns a copy with tick identity set.
    pub fn with_tick_id(mut self, tick_id: TickId) -> Self {
        self.tick_id = Some(tick_id);
        self
    }

    /// Returns a copy with action identity set.
    pub fn with_action_id(mut self, action_id: ActionId) -> Self {
        self.action_id = Some(action_id);
        self
    }

    /// Returns a copy with approval identity set.
    pub fn with_approval_id(mut self, approval_id: ApprovalId) -> Self {
        self.approval_id = Some(approval_id);
        self
    }

    /// Returns a copy with state node identity set.
    pub fn with_state_node_id(mut self, state_node_id: StateNodeId) -> Self {
        self.state_node_id = Some(state_node_id);
        self
    }

    /// Returns a copy with message identity set.
    pub fn with_message_id(mut self, message_id: MessageId) -> Self {
        self.message_id = Some(message_id);
        self
    }

    /// Validates populated identity fields and the required run identity.
    pub fn validate(&self) -> Result<(), IdentityValidationError> {
        validate_uuid("run_id", &self.run_id)?;
        validate_optional_uuid("fleet_id", self.fleet_id.as_ref())?;
        validate_optional_uuid("node_id", self.node_id.as_ref())?;
        validate_optional_uuid("instance_id", self.instance_id.as_ref())?;
        validate_optional_uuid("tenant_id", self.tenant_id.as_ref())?;
        validate_optional_uuid("agent_id", self.agent_id.as_ref())?;
        validate_optional_uuid("action_id", self.action_id.as_ref())?;
        validate_optional_uuid("approval_id", self.approval_id.as_ref())?;
        validate_optional_uuid("message_id", self.message_id.as_ref())?;
        if let Some(state_node_id) = &self.state_node_id {
            if state_node_id.hash().value.trim().is_empty() {
                return Err(IdentityValidationError::Missing {
                    field: "state_node_id",
                });
            }
        }
        Ok(())
    }

    /// Ensures the trace identity belongs to the expected runtime run.
    pub fn ensure_run(&self, expected: &RunId) -> Result<(), IdentityValidationError> {
        if &self.run_id != expected {
            return Err(IdentityValidationError::Mismatch {
                field: "run_id",
                expected: expected.to_string(),
                actual: self.run_id.to_string(),
            });
        }
        Ok(())
    }
}

/// Stable identifier for a snapshot of state bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SnapshotId(ContentHash);

impl SnapshotId {
    /// Wraps a precomputed content hash as a snapshot identifier.
    pub fn from_hash(hash: ContentHash) -> Self {
        Self(hash)
    }

    /// Creates a snapshot identifier by hashing the state bytes.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(ContentHash::blake3(bytes))
    }

    /// Returns the underlying content hash.
    pub fn hash(&self) -> &ContentHash {
        &self.0
    }
}

impl fmt::Display for SnapshotId {
    /// Formats the snapshot identifier as an algorithm-prefixed hash string.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Validation failures for runtime identity contexts.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentityValidationError {
    /// A required identity field was omitted or set to a nil/empty value.
    #[error("{field} is required")]
    Missing { field: &'static str },
    /// A runtime path attempted to combine identities from incompatible scopes.
    #[error("{field} mismatch: expected {expected}, found {actual}")]
    Mismatch {
        /// Field that failed validation.
        field: &'static str,
        /// Expected identity value.
        expected: String,
        /// Actual identity value.
        actual: String,
    },
}

trait UuidIdentity {
    fn is_nil(&self) -> bool;
}

macro_rules! impl_uuid_identity {
    ($($name:ident),+ $(,)?) => {
        $(
            impl UuidIdentity for $name {
                fn is_nil(&self) -> bool {
                    self.is_nil()
                }
            }
        )+
    };
}

impl_uuid_identity!(
    PrincipalId,
    IdentityEventId,
    PrincipalProofRefId,
    CapabilityGrantId,
    AuthorityDecisionId,
    AuthorityRevocationId,
    AuthorityObligationId,
    AuthorityObligationReceiptId,
    WorkloadId,
    DeviceId,
    ArtifactId,
    StatePartitionId,
    FleetId,
    NodeId,
    InstanceId,
    TenantId,
    AgentId,
    ApprovalId,
    RunId,
    ActionId,
    CircuitBreakerId,
    EscalationId,
    InterventionId,
    KillSwitchId,
    MessageId,
    TraceEventId,
);

fn validate_uuid<T: UuidIdentity>(
    field: &'static str,
    value: &T,
) -> Result<(), IdentityValidationError> {
    if value.is_nil() {
        Err(IdentityValidationError::Missing { field })
    } else {
        Ok(())
    }
}

fn validate_optional_uuid<T: UuidIdentity>(
    field: &'static str,
    value: Option<&T>,
) -> Result<(), IdentityValidationError> {
    match value {
        Some(value) => validate_uuid(field, value),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "../tests/unit/ids_tests.rs"]
mod tests;
