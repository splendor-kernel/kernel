//! Device profile schema for physical and edge runtime targets.
//!
//! This 0.05-S1 contract is descriptive and validation-only. It does not execute
//! device actions, integrate with ROS/native drivers, or replace hard real-time
//! controllers.

use crate::capabilities::{
    is_valid_capability_name, CapabilityDocument, CapabilityValidationError,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Canonical schema identifier for 0.05-S1 device profiles.
pub const DEVICE_PROFILE_SCHEMA: &str = "splendor.device_profile.v1";
/// Capability-document prefix for high-level physical action advertisements.
pub const PHYSICAL_ACTION_CAPABILITY_PREFIX: &str = "physical.action.";
/// Capability-document prefix for physical/edge device kind advertisements.
pub const DEVICE_KIND_CAPABILITY_PREFIX: &str = "device.kind.";

/// High-level physical actions Splendor may advertise and later gate through the
/// Action Gateway plus device-local safety verifiers.
pub const ALLOWED_PHYSICAL_ACTIONS: &[&str] = &[
    "read_battery",
    "read_sensor_summary",
    "read_map",
    "move_to_waypoint",
    "return_to_base",
    "dock",
    "inspect_zone",
    "capture_image",
    "pause_mission",
    "resume_mission",
    "request_operator_override",
    "notify_operator",
    "upload_trace_summary",
];

/// Forbidden direct Splendor action tokens or token fragments for physical
/// devices. These are low-level, firmware-bypass, or safety-bypass authorities.
pub const FORBIDDEN_PHYSICAL_ACTION_PATTERNS: &[&str] = &[
    "raw_actuator",
    "actuator_write",
    "motor_pwm",
    "set_motor_pwm",
    "firmware_safety_bypass",
    "disable_firmware_safety",
    "flight_controller_internals",
    "modify_flight_controller",
    "bypass_collision_avoidance",
    "collision_avoidance_bypass",
    "ignore_emergency_stop",
    "emergency_stop_bypass",
];

/// Device classes supported by the 0.05-S1 profile contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceNodeKind {
    Robot,
    Drone,
    Humanoid,
    EdgeAppliance,
    DesktopSidecar,
    IndustrialDevice,
}

impl DeviceNodeKind {
    /// Stable device-kind token used in capability-document compatibility output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Robot => "robot",
            Self::Drone => "drone",
            Self::Humanoid => "humanoid",
            Self::EdgeAppliance => "edge_appliance",
            Self::DesktopSidecar => "desktop_sidecar",
            Self::IndustrialDevice => "industrial_device",
        }
    }
}

/// Device capability categories required by 0.05-S1.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceCapabilityCategory {
    Sensor,
    BoundedAction,
    LocalCompute,
    Network,
    Power,
    SafetyStatus,
}

/// Structured capability advertised by a device profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceCapability {
    pub category: DeviceCapabilityCategory,
    pub name: String,
}

impl DeviceCapability {
    /// Creates a bounded high-level physical action capability.
    pub fn bounded_action(action: impl Into<String>) -> Self {
        Self {
            category: DeviceCapabilityCategory::BoundedAction,
            name: action.into(),
        }
    }
}

/// Safety or operating envelope constraint advertised by a device profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceSafetyConstraint {
    pub name: String,
    #[serde(default)]
    pub value: serde_json::Value,
}

/// Offline/local-policy indicators. This is metadata for later policy-cache and
/// safety-verifier sprints, not a policy implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceLocalPolicyIndicators {
    pub supports_local_policy_cache: bool,
    pub supports_offline_operation: bool,
    pub supports_local_operator_intervention: bool,
    pub max_offline_policy_ttl_seconds: Option<u64>,
}

/// Canonical 0.05 device profile. It is intentionally not a node_id,
/// instance_id, or run_id; registry identity remains separate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceProfile {
    pub schema: String,
    pub kind: DeviceNodeKind,
    pub capabilities: Vec<DeviceCapability>,
    pub safety_constraints: Vec<DeviceSafetyConstraint>,
    pub local_policy: DeviceLocalPolicyIndicators,
}

impl DeviceProfile {
    /// Builds and validates a device profile.
    pub fn new(
        kind: DeviceNodeKind,
        capabilities: Vec<DeviceCapability>,
        safety_constraints: Vec<DeviceSafetyConstraint>,
        local_policy: DeviceLocalPolicyIndicators,
    ) -> Result<Self, DeviceProfileValidationError> {
        let profile = Self {
            schema: DEVICE_PROFILE_SCHEMA.to_string(),
            kind,
            capabilities,
            safety_constraints,
            local_policy,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Validates the schema, categories, high-level action vocabulary, safety
    /// constraints, and local-policy indicators.
    pub fn validate(&self) -> Result<(), DeviceProfileValidationError> {
        if self.schema.trim().is_empty() {
            return Err(DeviceProfileValidationError::MissingSchema);
        }
        if self.schema != DEVICE_PROFILE_SCHEMA {
            return Err(DeviceProfileValidationError::UnsupportedSchema {
                schema: self.schema.clone(),
            });
        }
        if self.capabilities.is_empty() {
            return Err(DeviceProfileValidationError::EmptyCapabilities);
        }
        let mut seen = HashSet::new();
        for capability in &self.capabilities {
            validate_device_capability(capability)?;
            let key = (capability.category, capability.name.as_str());
            if !seen.insert(key) {
                return Err(DeviceProfileValidationError::DuplicateCapability {
                    name: capability.name.clone(),
                });
            }
        }
        if self.safety_constraints.is_empty() {
            return Err(DeviceProfileValidationError::MissingSafetyConstraints);
        }
        for constraint in &self.safety_constraints {
            if !is_valid_capability_name(constraint.name.as_str()) {
                return Err(DeviceProfileValidationError::InvalidSafetyConstraint {
                    name: constraint.name.clone(),
                });
            }
        }
        if self.local_policy.supports_offline_operation
            && !self.local_policy.supports_local_policy_cache
        {
            return Err(DeviceProfileValidationError::OfflineRequiresLocalPolicyCache);
        }
        if self.local_policy.supports_offline_operation
            && self.local_policy.max_offline_policy_ttl_seconds.is_none()
        {
            return Err(DeviceProfileValidationError::MissingOfflinePolicyTtl);
        }
        Ok(())
    }

    /// Converts the profile into the existing 0.03 capability document instead
    /// of forking the registry capability model.
    pub fn to_capability_document(
        &self,
    ) -> Result<CapabilityDocument, DeviceProfileValidationError> {
        self.validate()?;
        let mut capabilities = vec![format!(
            "{DEVICE_KIND_CAPABILITY_PREFIX}{}",
            self.kind.as_str()
        )];
        capabilities.extend(
            self.capabilities
                .iter()
                .map(|capability| match capability.category {
                    DeviceCapabilityCategory::BoundedAction => {
                        physical_action_capability(&capability.name)
                    }
                    category => format!("device.{}.{}", category_token(category), capability.name),
                }),
        );
        capabilities.sort();
        capabilities.dedup();
        Ok(CapabilityDocument::new(
            capabilities,
            serde_json::json!({
                "device_profile_schema": self.schema,
                "device_kind": self.kind.as_str(),
                "safety_constraints": self.safety_constraints,
                "local_policy": self.local_policy,
            }),
        )?)
    }
}

/// Validates a 0.03 capability document that advertises physical actions.
pub fn validate_physical_capability_document(
    document: &CapabilityDocument,
) -> Result<(), DeviceProfileValidationError> {
    document.validate()?;
    for capability in &document.capabilities {
        reject_forbidden_physical_action(capability)?;
        if let Some(action) = capability.strip_prefix(PHYSICAL_ACTION_CAPABILITY_PREFIX) {
            validate_physical_action(action)?;
        }
    }
    Ok(())
}

/// Returns true when `action` is in the high-level bounded vocabulary.
pub fn is_allowed_physical_action(action: &str) -> bool {
    ALLOWED_PHYSICAL_ACTIONS.contains(&action)
}

/// Returns the compatibility capability token for a bounded physical action.
pub fn physical_action_capability(action: &str) -> String {
    format!("{PHYSICAL_ACTION_CAPABILITY_PREFIX}{action}")
}

/// Structured device-profile validation failures.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum DeviceProfileValidationError {
    #[error("device profile schema is required")]
    MissingSchema,
    #[error("unsupported device profile schema: {schema}")]
    UnsupportedSchema { schema: String },
    #[error("device profile must contain at least one capability")]
    EmptyCapabilities,
    #[error("invalid device capability name: {name}")]
    InvalidCapabilityName { name: String },
    #[error("duplicate device capability: {name}")]
    DuplicateCapability { name: String },
    #[error("unknown or ambiguous physical action: {action}")]
    UnknownPhysicalAction { action: String },
    #[error("forbidden direct physical action advertisement: {action}")]
    ForbiddenPhysicalAction { action: String },
    #[error("device profile requires safety constraints")]
    MissingSafetyConstraints,
    #[error("invalid safety constraint name: {name}")]
    InvalidSafetyConstraint { name: String },
    #[error("offline operation requires local policy cache support")]
    OfflineRequiresLocalPolicyCache,
    #[error("offline operation requires a max offline policy ttl")]
    MissingOfflinePolicyTtl,
    #[error("invalid capability document: {0}")]
    InvalidCapabilityDocument(#[from] CapabilityValidationError),
}

fn validate_device_capability(
    capability: &DeviceCapability,
) -> Result<(), DeviceProfileValidationError> {
    if !is_valid_capability_name(capability.name.as_str()) {
        return Err(DeviceProfileValidationError::InvalidCapabilityName {
            name: capability.name.clone(),
        });
    }
    reject_forbidden_physical_action(&capability.name)?;
    if capability.category == DeviceCapabilityCategory::BoundedAction {
        validate_physical_action(&capability.name)?;
    }
    Ok(())
}

fn validate_physical_action(action: &str) -> Result<(), DeviceProfileValidationError> {
    reject_forbidden_physical_action(action)?;
    if !is_allowed_physical_action(action) {
        return Err(DeviceProfileValidationError::UnknownPhysicalAction {
            action: action.to_string(),
        });
    }
    Ok(())
}

fn reject_forbidden_physical_action(action: &str) -> Result<(), DeviceProfileValidationError> {
    let normalized = action
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
    if FORBIDDEN_PHYSICAL_ACTION_PATTERNS
        .iter()
        .any(|pattern| normalized.contains(pattern))
    {
        return Err(DeviceProfileValidationError::ForbiddenPhysicalAction {
            action: action.to_string(),
        });
    }
    Ok(())
}

fn category_token(category: DeviceCapabilityCategory) -> &'static str {
    match category {
        DeviceCapabilityCategory::Sensor => "sensor",
        DeviceCapabilityCategory::BoundedAction => "action",
        DeviceCapabilityCategory::LocalCompute => "local_compute",
        DeviceCapabilityCategory::Network => "network",
        DeviceCapabilityCategory::Power => "power",
        DeviceCapabilityCategory::SafetyStatus => "safety_status",
    }
}

#[cfg(test)]
#[path = "../tests/unit/device_profile_tests.rs"]
mod tests;
