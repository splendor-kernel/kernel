//! Deterministic fixture utilities for tests and conformance inputs.
//!
//! This module is a bounded FND-008 seam: it gives tests reproducible typed IDs
//! and fixture clocks without changing production ID randomness or runtime clock
//! behavior. The values created here do not carry authority, permissions,
//! approvals, policy, data-use grants, or replay side-effect semantics.

use crate::ids::{
    ActionId, AgentId, ApprovalId, CircuitBreakerId, EscalationId, FleetId, InstanceId,
    InterventionId, KillSwitchId, MessageId, NodeId, RunId, TenantId, TraceEventId, WorkOrderId,
};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const DEFAULT_FIXTURE_DOMAIN: &str = "splendor.fixture";
const DETERMINISTIC_ID_NAME_FORMAT: &str = "splendor.deterministic-id.v1";

macro_rules! typed_id {
    ($method:ident, $ty:ty, $id_type:literal) => {
        /// Derives a deterministic typed ID for a fixture label.
        pub fn $method(&self, label: &str) -> Result<$ty, DeterminismError> {
            self.uuid_for($id_type, label).map(<$ty>::from)
        }
    };
}

/// Validation failure for deterministic fixture utilities.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DeterminismError {
    /// A required deterministic fixture input was empty or whitespace-only.
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    /// Deterministic UUID namespaces must be real UUID namespaces, not nil.
    #[error("deterministic namespace must not be nil")]
    NilNamespace,
    /// Deterministic ID derivation unexpectedly produced a nil UUID.
    #[error("deterministic derivation produced nil {id_type}")]
    NilId { id_type: &'static str },
    /// Fixture clocks must not step backwards by default.
    #[error("fixture clock step must not be negative")]
    NegativeClockStep,
    /// Advancing the fixture clock would exceed the supported timestamp range.
    #[error("fixture clock advancement overflowed")]
    ClockOverflow,
}

/// Deterministic typed-ID factory for fixtures and tests.
///
/// The factory derives UUID-backed Splendor IDs with UUIDv5 from a caller-owned
/// namespace, a non-authorizing fixture domain, the target ID type, and a label.
/// Production constructors such as `RunId::new()` remain random and unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicIdFactory {
    namespace: Uuid,
    domain: String,
}

impl DeterministicIdFactory {
    /// Creates a factory with the default non-authorizing fixture domain.
    pub fn new(namespace: Uuid) -> Result<Self, DeterminismError> {
        Self::with_domain(namespace, DEFAULT_FIXTURE_DOMAIN)
    }

    /// Creates a factory with a deterministic namespace derived from a seed.
    pub fn from_seed(seed: &str) -> Result<Self, DeterminismError> {
        let seed = non_empty("seed", seed)?;
        Self::new(Uuid::new_v5(&Uuid::NAMESPACE_URL, seed.as_bytes()))
    }

    /// Creates a factory with an explicit non-authorizing fixture domain.
    pub fn with_domain(namespace: Uuid, domain: &str) -> Result<Self, DeterminismError> {
        if namespace.is_nil() {
            return Err(DeterminismError::NilNamespace);
        }
        let domain = non_empty("domain", domain)?.to_string();
        Ok(Self { namespace, domain })
    }

    /// Returns the UUID namespace used by this factory.
    pub fn namespace(&self) -> Uuid {
        self.namespace
    }

    /// Returns the non-authorizing fixture domain used by this factory.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Derives a deterministic UUID for a fixture label and ID type.
    ///
    /// The UUIDv5 name is encoded as length-prefixed UTF-8 components:
    /// format marker, fixture domain, ID type, and label. This keeps derivation
    /// deterministic without relying on delimiter-joined strings where component
    /// boundaries could become ambiguous.
    pub fn uuid_for(&self, id_type: &'static str, label: &str) -> Result<Uuid, DeterminismError> {
        let id_type = non_empty("id_type", id_type)?;
        let label = non_empty("label", label)?;
        let name =
            canonical_uuid_name(&[DETERMINISTIC_ID_NAME_FORMAT, &self.domain, id_type, label]);
        let uuid = Uuid::new_v5(&self.namespace, &name);
        if uuid.is_nil() {
            Err(DeterminismError::NilId { id_type })
        } else {
            Ok(uuid)
        }
    }

    typed_id!(fleet_id, FleetId, "fleet_id");
    typed_id!(node_id, NodeId, "node_id");
    typed_id!(instance_id, InstanceId, "instance_id");
    typed_id!(tenant_id, TenantId, "tenant_id");
    typed_id!(agent_id, AgentId, "agent_id");
    typed_id!(run_id, RunId, "run_id");
    typed_id!(action_id, ActionId, "action_id");
    typed_id!(approval_id, ApprovalId, "approval_id");
    typed_id!(message_id, MessageId, "message_id");
    typed_id!(escalation_id, EscalationId, "escalation_id");
    typed_id!(intervention_id, InterventionId, "intervention_id");
    typed_id!(circuit_breaker_id, CircuitBreakerId, "circuit_breaker_id");
    typed_id!(kill_switch_id, KillSwitchId, "kill_switch_id");
    typed_id!(trace_event_id, TraceEventId, "trace_event_id");

    /// Creates a deterministic work-order ID for fixtures.
    pub fn work_order_id(&self, label: &str) -> Result<WorkOrderId, DeterminismError> {
        let uuid = self.uuid_for("work_order_id", label)?;
        WorkOrderId::try_new(format!("wo_{uuid}"))
            .map_err(|_| DeterminismError::Empty { field: "label" })
    }
}

/// A fixture clock that always returns the same timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedClock {
    timestamp: OffsetDateTime,
}

impl FixedClock {
    /// Creates a fixed fixture clock.
    pub fn new(timestamp: OffsetDateTime) -> Self {
        Self { timestamp }
    }

    /// Returns the fixed timestamp.
    pub fn now(&self) -> OffsetDateTime {
        self.timestamp
    }
}

/// A deterministic fixture clock that advances by a fixed non-negative step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepClock {
    current: OffsetDateTime,
    step: Duration,
}

impl StepClock {
    /// Creates a stepped fixture clock from a start timestamp and step.
    pub fn new(start: OffsetDateTime, step: Duration) -> Result<Self, DeterminismError> {
        if step.is_negative() {
            return Err(DeterminismError::NegativeClockStep);
        }
        Ok(Self {
            current: start,
            step,
        })
    }

    /// Returns the next timestamp and advances by the configured step.
    pub fn now(&mut self) -> Result<OffsetDateTime, DeterminismError> {
        let current = self.current;
        let next = current
            .checked_add(self.step)
            .ok_or(DeterminismError::ClockOverflow)?;
        self.current = next;
        Ok(current)
    }

    /// Returns the timestamp that will be emitted by the next call to `now`.
    pub fn peek(&self) -> OffsetDateTime {
        self.current
    }

    /// Returns the configured fixture-clock step.
    pub fn step(&self) -> Duration {
        self.step
    }
}

fn non_empty<'a>(field: &'static str, value: &'a str) -> Result<&'a str, DeterminismError> {
    let value = value.trim();
    if value.is_empty() {
        Err(DeterminismError::Empty { field })
    } else {
        Ok(value)
    }
}

fn canonical_uuid_name(components: &[&str]) -> Vec<u8> {
    let mut name = Vec::new();
    for component in components {
        let bytes = component.as_bytes();
        name.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        name.extend_from_slice(bytes);
    }
    name
}

#[cfg(test)]
#[path = "../tests/unit/determinism_tests.rs"]
mod tests;
