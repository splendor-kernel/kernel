//! Middleware-agnostic high-level robotics adapter contract.
//!
//! This adapter issues bounded mission commands to local device middleware. It
//! does not talk to motors, firmware internals, ROS/native drivers, or live
//! hardware. Production implementations must still be registered behind
//! `VerifiedActionGateway` with a local `SafetyVerifier`.

use serde::{Deserialize, Serialize};
use splendor_gateway::{ActionAdapter, ActionRequest, AdapterError, AdapterResult};
use splendor_types::{
    is_allowed_physical_action, ALLOWED_PHYSICAL_ACTIONS, FORBIDDEN_PHYSICAL_ACTION_PATTERNS,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

/// Stable adapter identifier used for gateway registration.
pub const ROBOTICS_ADAPTER_ID: &str = "robotics";

/// Typed status embedded in adapter output payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoboticsActionStatus {
    Succeeded,
    OperatorOverrideRequested,
}

/// Trace-safe adapter output for high-level physical actions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RoboticsActionOutput {
    pub adapter: String,
    pub action: String,
    pub status: RoboticsActionStatus,
    pub evidence: serde_json::Value,
    pub postconditions: serde_json::Value,
}

/// Middleware-agnostic robotics adapter interface.
pub trait RoboticsAdapter: ActionAdapter {
    fn supported_actions(&self) -> &'static [&'static str] {
        ALLOWED_PHYSICAL_ACTIONS
    }
}

/// Configurable reference simulated robot/drone adapter.
#[derive(Clone, Debug)]
pub struct SimulatedRoboticsAdapter {
    calls: Arc<AtomicUsize>,
    fail_actions: Vec<String>,
}

impl Default for SimulatedRoboticsAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SimulatedRoboticsAdapter {
    pub fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            fail_actions: Vec::new(),
        }
    }

    pub fn with_fail_actions(
        mut self,
        actions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.fail_actions = actions.into_iter().map(Into::into).collect();
        self
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn validate_action(action: &str) -> Result<(), AdapterError> {
        let normalized = normalize(action);
        if FORBIDDEN_PHYSICAL_ACTION_PATTERNS
            .iter()
            .any(|pattern| normalized.contains(pattern))
        {
            return Err(AdapterError::Failed(
                "forbidden low-level physical action".to_string(),
            ));
        }
        if !is_allowed_physical_action(action) {
            return Err(AdapterError::Failed(format!(
                "unknown physical action: {action}"
            )));
        }
        Ok(())
    }
}

impl RoboticsAdapter for SimulatedRoboticsAdapter {}

impl ActionAdapter for SimulatedRoboticsAdapter {
    fn execute(&self, request: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        Self::validate_action(&request.action.name)?;
        self.calls.fetch_add(1, Ordering::SeqCst);

        if self
            .fail_actions
            .iter()
            .any(|action| action == &request.action.name)
        {
            return Err(AdapterError::Failed(format!(
                "simulated robotics middleware failure for {}",
                request.action.name
            )));
        }

        let status = if request.action.name == "request_operator_override" {
            RoboticsActionStatus::OperatorOverrideRequested
        } else {
            RoboticsActionStatus::Succeeded
        };
        let postcondition = format!("robotics.{}.acknowledged", request.action.name);
        let output = RoboticsActionOutput {
            adapter: ROBOTICS_ADAPTER_ID.to_string(),
            action: request.action.name.clone(),
            status,
            evidence: serde_json::json!({
                "middleware": "simulated_device_middleware",
                "command_ref": format!("sim://{}/{}", request.run_id, request.action_id),
                "trace_safe": true,
            }),
            postconditions: serde_json::json!({
                "safety_status": "safe",
                "acknowledged_by": "simulated_realtime_controller",
                "postcondition": postcondition,
            }),
        };

        Ok(AdapterResult {
            output: serde_json::to_value(output)
                .map_err(|error| AdapterError::Failed(error.to_string()))?,
            satisfied_postconditions: vec![postcondition],
        })
    }
}

fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "../tests/unit/robotics_adapter_tests.rs"]
mod tests;
