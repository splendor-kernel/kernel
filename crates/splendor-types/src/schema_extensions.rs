//! Reusable guards for non-authorizing extension metadata.
//!
//! Extension maps are forward-compatible metadata only. They are deliberately
//! not a place to add identity, authority, capability, work-order, approval,
//! credential, data-use, driver/adapter, verifier, quota, gateway, or gate
//! semantics. This module keeps that rule behavior-free and reusable by schema
//! modules that already accept extension-style metadata.

use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

/// Canonical normalized keys that are reserved for authoritative schemas.
///
/// Input keys are normalized with [`normalize_extension_key`] before matching,
/// so camelCase, kebab-case, snake_case, spaces, dots, and other separators map
/// to the same reserved spelling.
pub const RESERVED_EXTENSION_KEYS: &[&str] = &[
    "action_gateway",
    "action_id",
    "adapter",
    "adapter_id",
    "adapter_selection",
    "agent_id",
    "allowed_actions",
    "allowed_adapters",
    "allowed_permissions",
    "artifact_id",
    "approval",
    "approval_id",
    "approval_token",
    "attempt_id",
    "auth_header",
    "authority",
    "authorization",
    "capabilities",
    "capability",
    "capability_grant",
    "change_id",
    "checkpoint_id",
    "credential",
    "credentials",
    "data_ref",
    "data_refs",
    "data_use",
    "data_use_grant",
    "dataset_id",
    "deployment_id",
    "device_id",
    "driver",
    "driver_id",
    "driver_manifest",
    "eval_id",
    "event_id",
    "evidence_id",
    "feedback_id",
    "fleet_id",
    "gate",
    "gate_decision",
    "gate_id",
    "gateway",
    "identity",
    "identity_ref",
    "identity_refs",
    "incident_id",
    "instance_id",
    "invocation_id",
    "lease_id",
    "message_id",
    "model_id",
    "node_id",
    "permission",
    "permissions",
    "policy",
    "policy_bundle",
    "principal_id",
    "quota",
    "quotas",
    "reward_id",
    "run_id",
    "runtime_context_id",
    "scope",
    "scope_type",
    "secret",
    "secret_ref",
    "signature",
    "state_node_id",
    "tenant_id",
    "tick_id",
    "token",
    "trace_event_id",
    "trace_id",
    "verification",
    "verification_result",
    "verifier",
    "verifier_result",
    "verifier_results",
    "worker_id",
    "workload_id",
    "work_order",
    "work_order_id",
];

/// Canonical normalized fragments that are always authority- or credential-like.
///
/// Fragment matching is intentionally narrow enough to avoid rejecting common
/// safe keys such as `reference_id`, while still rejecting aliases such as
/// `accessToken`, `api-key`, `driver_url`, and `quota_override`.
pub const RESERVED_EXTENSION_KEY_FRAGMENTS: &[&str] = &[
    "access_token",
    "adapter",
    "apikey",
    "api_key",
    "approval",
    "authheader",
    "auth_header",
    "authority",
    "authorization",
    "bearer",
    "capability",
    "credential",
    "cookie",
    "datause",
    "data_use",
    "driver",
    "gateway",
    "jwt",
    "oauth",
    "password",
    "permission",
    "policy",
    "privatekey",
    "private_key",
    "quota",
    "secret",
    "session",
    "signature",
    "token",
    "verifier",
    "workorder",
    "work_order",
];

/// Structured validation failure for extension metadata.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("extension metadata rejected at {path} for key {key:?}: {reason}")]
pub struct ExtensionValidationError {
    /// Path to the rejected key, including array indexes where applicable.
    pub path: String,
    /// Original rejected key.
    pub key: String,
    /// Canonical normalized key used for reserved-authority matching.
    pub normalized_key: String,
    /// Stable rejection reason.
    pub reason: ExtensionValidationReason,
}

/// Stable reasons why an extension key was rejected.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExtensionValidationReason {
    /// The key was empty or all whitespace.
    #[error("blank_extension_key")]
    BlankKey,
    /// The key contained leading or trailing whitespace.
    #[error("trimmed_extension_key")]
    TrimmedKey,
    /// The key normalized to a reserved authorizing/credential namespace.
    #[error("reserved_authority_key")]
    ReservedAuthorityKey,
}

/// Normalizes extension keys for reserved-authority matching.
///
/// The normal form is lower snake case. ASCII case transitions, hyphens,
/// underscores, dots, spaces, and other separators normalize consistently.
pub fn normalize_extension_key(key: &str) -> String {
    let characters: Vec<char> = key.trim().chars().collect();
    let mut normalized = String::with_capacity(characters.len());
    let mut previous_was_separator = true;

    for (index, character) in characters.iter().copied().enumerate() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase() {
                let previous = index.checked_sub(1).and_then(|idx| characters.get(idx));
                let next = characters.get(index + 1);
                let lower_or_digit_before = previous
                    .map(|previous| previous.is_ascii_lowercase() || previous.is_ascii_digit())
                    .unwrap_or(false);
                let acronym_boundary = previous
                    .map(|previous| previous.is_ascii_uppercase())
                    .unwrap_or(false)
                    && next.map(|next| next.is_ascii_lowercase()).unwrap_or(false);

                if !normalized.is_empty()
                    && !previous_was_separator
                    && (lower_or_digit_before || acronym_boundary)
                {
                    normalized.push('_');
                }
                normalized.push(character.to_ascii_lowercase());
            } else {
                normalized.push(character.to_ascii_lowercase());
            }
            previous_was_separator = false;
        } else if !normalized.is_empty() && !previous_was_separator {
            normalized.push('_');
            previous_was_separator = true;
        }
    }

    normalized.trim_matches('_').to_string()
}

/// Returns true when `key` is reserved for authoritative schema fields.
pub fn is_reserved_extension_key(key: &str) -> bool {
    let normalized = normalize_extension_key(key);
    is_reserved_normalized_extension_key(&normalized, &[])
}

/// Validates a top-level extension map with the canonical reserved key policy.
pub fn validate_extension_map(
    values: &BTreeMap<String, Value>,
    root_path: impl Into<String>,
) -> Result<(), ExtensionValidationError> {
    validate_extension_map_with_reserved_keys(values, root_path, &[])
}

/// Validates a top-level extension map with additional context-specific keys.
pub fn validate_extension_map_with_reserved_keys(
    values: &BTreeMap<String, Value>,
    root_path: impl Into<String>,
    additional_reserved_keys: &[&str],
) -> Result<(), ExtensionValidationError> {
    let root_path = root_path.into();
    for (key, value) in values {
        let key_path = child_path(&root_path, key);
        validate_extension_key(key, &key_path, additional_reserved_keys)?;
        validate_value(value, &key_path, additional_reserved_keys)?;
    }
    Ok(())
}

/// Validates a metadata value recursively with the canonical reserved key policy.
pub fn validate_extension_value(
    value: &Value,
    root_path: impl Into<String>,
) -> Result<(), ExtensionValidationError> {
    validate_extension_value_with_reserved_keys(value, root_path, &[])
}

/// Validates a metadata value recursively with additional context-specific keys.
pub fn validate_extension_value_with_reserved_keys(
    value: &Value,
    root_path: impl Into<String>,
    additional_reserved_keys: &[&str],
) -> Result<(), ExtensionValidationError> {
    let root_path = root_path.into();
    validate_value(value, &root_path, additional_reserved_keys)
}

fn validate_value(
    value: &Value,
    path: &str,
    additional_reserved_keys: &[&str],
) -> Result<(), ExtensionValidationError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let key_path = child_path(path, key);
                validate_extension_key(key, &key_path, additional_reserved_keys)?;
                validate_value(child, &key_path, additional_reserved_keys)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_value(child, &format!("{path}[{index}]"), additional_reserved_keys)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_extension_key(
    key: &str,
    path: &str,
    additional_reserved_keys: &[&str],
) -> Result<(), ExtensionValidationError> {
    let normalized_key = normalize_extension_key(key);
    if key.trim().is_empty() {
        return Err(extension_error(
            path,
            key,
            normalized_key,
            ExtensionValidationReason::BlankKey,
        ));
    }
    if key.trim() != key {
        return Err(extension_error(
            path,
            key,
            normalized_key,
            ExtensionValidationReason::TrimmedKey,
        ));
    }
    if is_reserved_normalized_extension_key(&normalized_key, additional_reserved_keys) {
        return Err(extension_error(
            path,
            key,
            normalized_key,
            ExtensionValidationReason::ReservedAuthorityKey,
        ));
    }
    Ok(())
}

fn extension_error(
    path: &str,
    key: &str,
    normalized_key: String,
    reason: ExtensionValidationReason,
) -> ExtensionValidationError {
    ExtensionValidationError {
        path: path.to_string(),
        key: key.to_string(),
        normalized_key,
        reason,
    }
}

fn is_reserved_normalized_extension_key(
    normalized_key: &str,
    additional_reserved_keys: &[&str],
) -> bool {
    RESERVED_EXTENSION_KEYS.contains(&normalized_key)
        || RESERVED_EXTENSION_KEY_FRAGMENTS
            .iter()
            .any(|fragment| normalized_key.contains(fragment))
        || additional_reserved_keys
            .iter()
            .any(|reserved| normalize_extension_key(reserved) == normalized_key)
}

fn child_path(parent: &str, key: &str) -> String {
    if parent.is_empty() {
        key.to_string()
    } else {
        format!("{parent}.{key}")
    }
}

#[cfg(test)]
#[path = "../tests/unit/schema_extensions_tests.rs"]
mod tests;
