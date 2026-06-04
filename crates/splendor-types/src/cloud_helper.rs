//! Advisory cloud/on-prem helper contracts for physical devices.
//!
//! Cloud helpers receive scoped planning authority through the normal signed
//! work-order and message contracts. They may return proposal artifacts/messages,
//! but they never receive robotics adapter authority or direct physical action
//! execution authority by default.

use crate::{
    is_allowed_physical_action, Action, PlacementExecutionMode, SideEffectClass,
    VerificationResult, WorkOrder, FORBIDDEN_PHYSICAL_ACTION_PATTERNS,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

/// Typed message schema for helper route-plan proposals.
pub const ROUTE_PLAN_PROPOSAL_SCHEMA: &str = "splendor.message.route_plan_proposal.v1";

/// Advisory helper adapter identifier used in examples and tests.
pub const CLOUD_HELPER_ADAPTER_ID: &str = "cloud_helper";

/// Advisory action used by helpers to produce a route proposal.
pub const ROUTE_PLAN_PROPOSE_ACTION: &str = "route_plan.propose";

/// Advisory action used by helpers to produce a mission proposal.
pub const MISSION_PLAN_PROPOSE_ACTION: &str = "mission_plan.propose";

/// Stable reason emitted when helper transport fails before local validation.
pub const CLOUD_HELPER_UNAVAILABLE_REASON: &str = "cloud_helper_unavailable";

/// Trace/replay-ready summary of helper work-order authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CloudHelperAuthority {
    /// Helper objective copied from the signed work order.
    pub objective: String,
    /// Scoped data references available to the helper.
    pub data_refs: Vec<String>,
    /// Advisory actions allowed to the helper.
    pub allowed_actions: Vec<String>,
    /// Non-robotics adapters allowed to the helper.
    pub allowed_adapters: Vec<String>,
}

/// One bounded route waypoint proposed by a helper.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RouteWaypointProposal {
    /// Trace-safe waypoint reference, not a low-level actuator command.
    pub waypoint_ref: String,
    /// Zone/geofence reference that the local device must validate.
    pub zone_ref: String,
}

/// Advisory route plan returned as a typed message or artifact payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RoutePlanProposal {
    /// Proposal identifier unique within the helper run/artifact.
    pub proposal_id: String,
    /// Planning objective the helper evaluated.
    pub objective: String,
    /// Optional artifact reference for a persisted proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    /// Scoped data references used by the helper.
    #[serde(default)]
    pub data_refs: Vec<String>,
    /// Ordered bounded waypoints. These are not executable commands.
    pub waypoints: Vec<RouteWaypointProposal>,
    /// Proposal creation time.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl RoutePlanProposal {
    /// Decodes and validates a route-plan proposal payload.
    pub fn from_payload(payload: &serde_json::Value) -> Result<Self, CloudHelperValidationError> {
        let proposal = serde_json::from_value::<Self>(payload.clone()).map_err(|error| {
            CloudHelperValidationError::MalformedProposal {
                reason: error.to_string(),
            }
        })?;
        proposal.validate()?;
        Ok(proposal)
    }

    /// Validates that the proposal is advisory and scoped.
    pub fn validate(&self) -> Result<(), CloudHelperValidationError> {
        require_non_blank("proposal_id", &self.proposal_id)?;
        require_non_blank("objective", &self.objective)?;
        require_no_blank_items("data_refs", &self.data_refs)?;
        if let Some(artifact_ref) = &self.artifact_ref {
            require_non_blank("artifact_ref", artifact_ref)?;
        }
        if self.waypoints.is_empty() {
            return Err(CloudHelperValidationError::MalformedProposal {
                reason: "route_plan_requires_waypoints".to_string(),
            });
        }
        for waypoint in &self.waypoints {
            require_non_blank("waypoint_ref", &waypoint.waypoint_ref)?;
            require_non_blank("zone_ref", &waypoint.zone_ref)?;
            reject_direct_physical_command(&waypoint.waypoint_ref)?;
        }
        Ok(())
    }
}

/// Local validation result before any proposal becomes gateway-submitted actions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LocalRoutePlanValidation {
    /// Aggregate local validation result for trace/replay.
    pub result: VerificationResult,
    /// Bounded local action candidates. Empty on rejection/failure.
    pub bounded_actions: Vec<Action>,
}

/// Fail-closed helper contract validation errors.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CloudHelperValidationError {
    /// Helper work order is not explicitly advisory/cloud-helper mode.
    #[error("cloud helper work order must use cloud_helper placement execution mode")]
    MissingCloudHelperMode,
    /// Helper attempted to receive robotics adapter authority.
    #[error("cloud helper must not receive robotics adapter authority")]
    RoboticsAdapterAuthorityDenied,
    /// Helper attempted to receive direct physical action authority.
    #[error("cloud helper must not receive direct physical action authority: {action}")]
    PhysicalActionAuthorityDenied { action: String },
    /// Helper does not have scoped data refs.
    #[error("cloud helper work order requires scoped data refs")]
    MissingScopedDataRefs,
    /// Proposal payload is malformed or contains unsafe fields.
    #[error("route plan proposal is malformed: {reason}")]
    MalformedProposal { reason: String },
}

impl CloudHelperValidationError {
    /// Stable sanitized reason code for trace/audit/replay.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::MissingCloudHelperMode => "missing_cloud_helper_mode",
            Self::RoboticsAdapterAuthorityDenied => "robotics_adapter_authority_denied",
            Self::PhysicalActionAuthorityDenied { .. } => "physical_action_authority_denied",
            Self::MissingScopedDataRefs => "missing_scoped_data_refs",
            Self::MalformedProposal { .. } => "malformed_route_plan_proposal",
        }
    }
}

/// Validates that a normal signed work-order payload is advisory helper scoped.
pub fn validate_cloud_helper_work_order(
    work_order: &WorkOrder,
) -> Result<CloudHelperAuthority, CloudHelperValidationError> {
    if work_order.placement.execution_mode != PlacementExecutionMode::CloudHelper {
        return Err(CloudHelperValidationError::MissingCloudHelperMode);
    }
    if work_order.data_refs.is_empty() {
        return Err(CloudHelperValidationError::MissingScopedDataRefs);
    }
    require_no_blank_items("data_refs", &work_order.data_refs)?;

    for adapter in &work_order.allowed_adapters {
        if adapter == "robotics" {
            return Err(CloudHelperValidationError::RoboticsAdapterAuthorityDenied);
        }
    }
    for action in &work_order.allowed_actions {
        if is_allowed_physical_action(action) || matches_forbidden_physical_pattern(action) {
            return Err(CloudHelperValidationError::PhysicalActionAuthorityDenied {
                action: action.clone(),
            });
        }
    }

    Ok(CloudHelperAuthority {
        objective: work_order.objective.clone(),
        data_refs: work_order.data_refs.clone(),
        allowed_actions: work_order.allowed_actions.clone(),
        allowed_adapters: work_order.allowed_adapters.clone(),
    })
}

/// Converts a validated route proposal into bounded local action candidates.
///
/// The returned actions still must be submitted through the local action gateway
/// and safety verifier before any robotics adapter can execute.
pub fn validate_route_plan_for_local_execution(
    proposal: &RoutePlanProposal,
    allowed_zone_refs: &[String],
) -> LocalRoutePlanValidation {
    if let Err(error) = proposal.validate() {
        return denied_validation(
            error.reason_code(),
            serde_json::json!({"error": error.to_string()}),
        );
    }
    if allowed_zone_refs.is_empty() || allowed_zone_refs.iter().any(|zone| zone.trim().is_empty()) {
        return denied_validation(
            "local_allowed_zones_unavailable",
            serde_json::json!({"allowed_zone_refs": allowed_zone_refs}),
        );
    }

    let rejected_zones = proposal
        .waypoints
        .iter()
        .filter(|waypoint| {
            !allowed_zone_refs
                .iter()
                .any(|zone| zone == &waypoint.zone_ref)
        })
        .map(|waypoint| waypoint.zone_ref.clone())
        .collect::<Vec<_>>();
    if !rejected_zones.is_empty() {
        return denied_validation(
            "route_plan_zone_not_allowed",
            serde_json::json!({"rejected_zone_refs": rejected_zones}),
        );
    }

    let bounded_actions = proposal
        .waypoints
        .iter()
        .map(|waypoint| Action {
            name: "move_to_waypoint".to_string(),
            params: serde_json::json!({
                "proposal_id": proposal.proposal_id,
                "waypoint_ref": waypoint.waypoint_ref,
                "zone_ref": waypoint.zone_ref,
                "physical_action": true,
            }),
            side_effect_class: SideEffectClass::Custom("physical.high_level".to_string()),
            cost_estimate: None,
            required_permissions: vec!["physical.move_to_waypoint".to_string()],
            preconditions: vec!["cloud_helper.local_plan_validated".to_string()],
            postconditions: vec!["robotics.move_to_waypoint.acknowledged".to_string()],
        })
        .collect();

    LocalRoutePlanValidation {
        result: VerificationResult {
            allowed: true,
            reasons: Vec::new(),
            artifacts: serde_json::json!({
                "source": "cloud_helper_local_validation",
                "proposal_id": proposal.proposal_id,
                "waypoint_count": proposal.waypoints.len(),
            }),
        },
        bounded_actions,
    }
}

/// Fail-closed validation result used when a helper call times out or fails.
pub fn cloud_helper_failure_validation(reason: impl Into<String>) -> LocalRoutePlanValidation {
    denied_validation(
        CLOUD_HELPER_UNAVAILABLE_REASON,
        serde_json::json!({"reason": reason.into()}),
    )
}

fn denied_validation(reason: &str, artifacts: serde_json::Value) -> LocalRoutePlanValidation {
    LocalRoutePlanValidation {
        result: VerificationResult {
            allowed: false,
            reasons: vec![reason.to_string()],
            artifacts,
        },
        bounded_actions: Vec::new(),
    }
}

fn require_non_blank(field: &str, value: &str) -> Result<(), CloudHelperValidationError> {
    if value.trim().is_empty() {
        return Err(CloudHelperValidationError::MalformedProposal {
            reason: format!("{field}_required"),
        });
    }
    Ok(())
}

fn require_no_blank_items(
    field: &str,
    values: &[String],
) -> Result<(), CloudHelperValidationError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(CloudHelperValidationError::MalformedProposal {
            reason: format!("blank_{field}"),
        });
    }
    Ok(())
}

fn reject_direct_physical_command(value: &str) -> Result<(), CloudHelperValidationError> {
    if matches_forbidden_physical_pattern(value) || is_allowed_physical_action(value) {
        return Err(CloudHelperValidationError::MalformedProposal {
            reason: "proposal_contains_direct_physical_command".to_string(),
        });
    }
    Ok(())
}

fn matches_forbidden_physical_pattern(value: &str) -> bool {
    let normalized = value
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    FORBIDDEN_PHYSICAL_ACTION_PATTERNS
        .iter()
        .any(|pattern| normalized.contains(pattern))
}

#[cfg(test)]
#[path = "../tests/unit/cloud_helper_tests.rs"]
mod tests;
