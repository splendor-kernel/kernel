use crate::protocol::{
    canonical_json, parse_json, printable_token, sha256_bytes, sha256_value, JsonLimits,
    OPERATION_DIGEST_DOMAIN, PROFILE_DIGEST_DOMAIN,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MANIFEST_BYTES: &[u8] =
    include_bytes!("../../fixtures/acceptance-operation-profiles.v3.json");
const MANIFEST_DIGEST: &str =
    include_str!("../../fixtures/acceptance-operation-profiles.v3.sha256");

const PRINCIPALS: &[&str] = &["cloud", "edge", "local", "vpc"];
const PARAMETER_PROFILES: &[&str] = &[
    "artifact_create",
    "artifact_publish",
    "data_read",
    "empty",
    "idempotent_read",
    "management_marker",
    "physical",
    "unsafe_failure",
];
const OUTPUT_PROFILES: &[&str] = &[
    "artifact_create",
    "artifact_publish",
    "data_read",
    "fixture_read",
    "marker",
    "none",
    "physical_battery",
    "physical_image",
    "physical_inspect",
    "physical_return",
    "physical_sensor",
    "physical_trace_upload",
    "physical_waypoint",
    "sql_read",
];
const SEMANTIC_RETRY_FIELDS: &[&str] = &[
    "action_id",
    "request_id",
    "issued_at_unix_ms",
    "deadline_unix_ms",
    "action.params.retry_attempt",
];
const EXTERNAL_IDEMPOTENCY_IDENTITY_FIELD: &str = "action.params.idempotency_key";
const SEMANTIC_RETRY_MARKER_PATH: &str = "action.params.retry_attempt";
type OperationContract = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
);
const OPERATION_CONTRACTS: &[OperationContract] = &[
    (
        "none",
        "failure_recorded",
        "controlled_failure",
        "empty",
        "none",
        None,
    ),
    (
        "none",
        "failure_recorded",
        "controlled_failure",
        "unsafe_failure",
        "none",
        None,
    ),
    ("none", "message_routed", "forbidden", "empty", "none", None),
    (
        "marker",
        "marker_recorded",
        "execute",
        "empty",
        "none",
        Some("executed"),
    ),
    (
        "marker",
        "marker_recorded",
        "execute",
        "management_marker",
        "none",
        Some("executed"),
    ),
    (
        "fixture_read",
        "fixture_read",
        "execute",
        "idempotent_read",
        "none",
        Some("read"),
    ),
    (
        "artifact_create",
        "artifact_created",
        "execute",
        "artifact_create",
        "none",
        Some("executed"),
    ),
    (
        "artifact_publish",
        "artifact_published",
        "execute",
        "artifact_publish",
        "none",
        Some("executed"),
    ),
    (
        "data_read",
        "data_read",
        "execute",
        "data_read",
        "none",
        Some("read"),
    ),
    (
        "sql_read",
        "fixture_read",
        "execute",
        "empty",
        "none",
        Some("read"),
    ),
    (
        "physical_battery",
        "sensor_read",
        "execute",
        "physical",
        "physical_node",
        Some("read"),
    ),
    (
        "physical_sensor",
        "sensor_read",
        "execute",
        "physical",
        "physical_node",
        Some("read"),
    ),
    (
        "physical_inspect",
        "device_state_updated",
        "execute",
        "physical",
        "physical_node",
        Some("executed"),
    ),
    (
        "physical_waypoint",
        "device_state_updated",
        "execute",
        "physical",
        "physical_node",
        Some("executed"),
    ),
    (
        "physical_image",
        "device_state_updated",
        "execute",
        "physical",
        "physical_node",
        Some("executed"),
    ),
    (
        "physical_return",
        "device_state_updated",
        "execute",
        "physical",
        "physical_node",
        Some("executed"),
    ),
    (
        "physical_trace_upload",
        "device_state_updated",
        "execute",
        "physical",
        "physical_node",
        Some("executed"),
    ),
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    pub max_active_requests: usize,
    pub max_array_items: usize,
    pub max_depth: usize,
    pub max_evidence_bytes: usize,
    pub max_evidence_nonces: usize,
    pub max_fields: usize,
    pub max_future_skew_ms: i64,
    pub max_ledger_entries: usize,
    pub max_output_bytes: usize,
    pub max_principal_active_requests: usize,
    pub max_principal_ledger_entries: usize,
    pub max_receipt_ttl_ms: i64,
    pub max_request_bytes: usize,
    pub max_request_ttl_ms: i64,
    pub max_response_bytes: usize,
    pub max_string_bytes: usize,
}

impl Limits {
    pub(crate) fn json(&self, max_bytes: usize) -> JsonLimits {
        JsonLimits {
            max_bytes,
            max_depth: self.max_depth,
            max_fields: self.max_fields,
            max_array_items: self.max_array_items,
            max_string_bytes: self.max_string_bytes,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationBounds {
    pub max_array_items: usize,
    pub max_integer_abs: i64,
    pub max_output_bytes: usize,
    pub max_string_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdempotencyProfile {
    pub external_idempotency_identity_field: Option<String>,
    pub mode: String,
    pub required_retry_marker: Option<RetryMarker>,
    pub retry_varying_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetryMarker {
    pub initial: i64,
    pub path: String,
    pub reconciled: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedStatus {
    pub initial: Option<String>,
    pub reconciled: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationProfile {
    pub action_name: String,
    pub adapter_id: String,
    pub allowed_request_principals: Vec<String>,
    pub bounds: OperationBounds,
    pub coordinate_rule: String,
    pub effect_class: Value,
    pub expected_status: ExpectedStatus,
    pub idempotency: IdempotencyProfile,
    pub operation_id: String,
    pub output_profile: String,
    pub parameter_profile: String,
    pub postcondition: String,
    pub provider_mode: String,
    pub required_permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDocument {
    audience: String,
    limits: Limits,
    operations: Vec<OperationProfile>,
    profile_revision: String,
    protocol_version: String,
    provider_id: String,
    provider_revision: String,
    schema_version: String,
}

#[derive(Clone, Debug)]
pub(crate) struct OperationManifest {
    pub audience: String,
    pub digest: String,
    pub limits: Limits,
    pub provider_revision: String,
    operations: BTreeMap<(String, String), OperationProfile>,
}

impl OperationManifest {
    pub(crate) fn load_embedded() -> Result<Self, String> {
        Self::load(MANIFEST_BYTES, MANIFEST_DIGEST.trim())
    }

    fn load(bytes: &[u8], expected_digest: &str) -> Result<Self, String> {
        let value = parse_json(
            bytes,
            JsonLimits {
                max_bytes: 131_072,
                max_depth: 16,
                max_fields: 1024,
                max_array_items: 64,
                max_string_bytes: 2048,
            },
            false,
        )?;
        let document: ManifestDocument =
            serde_json::from_value(value).map_err(|_| "manifest_contract_invalid".to_string())?;
        if document.schema_version != "splendor.acceptance.operation_profiles.v3"
            || document.protocol_version != "private-v3"
            || document.provider_id != "acceptance-action-provider"
            || document.profile_revision != "acceptance-operation-profile.v3"
            || document.audience != "splendor.acceptance.action-provider.v3"
            || !printable_token(&document.provider_revision, 256)
        {
            return Err("manifest_identity_invalid".to_string());
        }
        validate_limits(&document.limits)?;
        if document.operations.len() != 18 {
            return Err("manifest_operation_count_invalid".to_string());
        }
        let digest = sha256_bytes(PROFILE_DIGEST_DOMAIN, bytes);
        if expected_digest.len() != 71
            || !expected_digest.starts_with("sha256:")
            || digest != expected_digest
        {
            return Err("manifest_digest_drift".to_string());
        }

        let mut operations = BTreeMap::new();
        let mut operation_ids = Vec::new();
        for operation in document.operations {
            validate_operation(&operation, &document.limits)?;
            operation_ids.push(operation.operation_id.clone());
            if operations
                .insert(
                    (operation.adapter_id.clone(), operation.action_name.clone()),
                    operation,
                )
                .is_some()
            {
                return Err("manifest_operation_identity_invalid".to_string());
            }
        }
        let unique = operation_ids.iter().collect::<BTreeSet<_>>();
        let mut sorted = operation_ids.clone();
        sorted.sort();
        if unique.len() != 18 || sorted != operation_ids {
            return Err("manifest_operations_not_sorted".to_string());
        }
        Ok(Self {
            audience: document.audience,
            digest,
            limits: document.limits,
            provider_revision: document.provider_revision,
            operations,
        })
    }

    pub(crate) fn operation(
        &self,
        adapter_id: &str,
        action_name: &str,
    ) -> Option<&OperationProfile> {
        self.operations
            .get(&(adapter_id.to_string(), action_name.to_string()))
    }

    pub(crate) fn operation_digest(&self, operation: &OperationProfile) -> Result<String, String> {
        let value = serde_json::to_value(operation)
            .map_err(|_| "manifest_operation_serialize_failed".to_string())?;
        sha256_value(OPERATION_DIGEST_DOMAIN, &value)
    }

    pub(crate) fn allowed_for_role(&self, role: &str) -> Vec<String> {
        self.operations
            .values()
            .filter(|operation| {
                operation
                    .allowed_request_principals
                    .iter()
                    .any(|candidate| candidate == role)
            })
            .map(|operation| operation.operation_id.clone())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn operation_count(&self) -> usize {
        self.operations.len()
    }
}

fn validate_limits(limits: &Limits) -> Result<(), String> {
    if limits.max_active_requests != 16
        || limits.max_array_items != 64
        || limits.max_depth != 16
        || limits.max_evidence_bytes != 262_144
        || limits.max_evidence_nonces != 128
        || limits.max_fields != 256
        || limits.max_future_skew_ms != 2_000
        || limits.max_ledger_entries != 256
        || limits.max_output_bytes != 32_768
        || limits.max_principal_active_requests != 4
        || limits.max_principal_ledger_entries != 64
        || limits.max_receipt_ttl_ms != 60_000
        || limits.max_request_bytes != 65_536
        || limits.max_request_ttl_ms != 10_000
        || limits.max_response_bytes != 262_144
        || limits.max_string_bytes != 2_048
    {
        return Err("manifest_required_limit_drift".to_string());
    }
    Ok(())
}

fn validate_operation(operation: &OperationProfile, limits: &Limits) -> Result<(), String> {
    if operation.operation_id != format!("{}/{}", operation.adapter_id, operation.action_name)
        || !printable_token(&operation.operation_id, 512)
        || !printable_token(&operation.postcondition, 256)
    {
        return Err("manifest_operation_identity_invalid".to_string());
    }
    if operation.effect_class != Value::String("External".to_string())
        && operation.effect_class != Value::String("ReadOnly".to_string())
        && operation.effect_class != serde_json::json!({"Custom": "physical.high_level"})
    {
        return Err("manifest_effect_class_unsupported".to_string());
    }
    if !sorted_unique(&operation.required_permissions, None)
        || !sorted_unique(&operation.allowed_request_principals, Some(PRINCIPALS))
        || !PARAMETER_PROFILES.contains(&operation.parameter_profile.as_str())
        || !OUTPUT_PROFILES.contains(&operation.output_profile.as_str())
        || !matches!(operation.coordinate_rule.as_str(), "none" | "physical_node")
        || !matches!(
            operation.provider_mode.as_str(),
            "execute" | "controlled_failure" | "forbidden"
        )
        || operation.provider_mode == "forbidden"
            && !operation.allowed_request_principals.is_empty()
    {
        return Err("manifest_operation_contract_unsupported".to_string());
    }
    let valid_initial = matches!(
        operation.expected_status.initial.as_deref(),
        None | Some("executed") | Some("read")
    );
    if !valid_initial
        || operation.provider_mode == "execute" && operation.expected_status.initial.is_none()
        || operation.provider_mode != "execute" && operation.expected_status.initial.is_some()
    {
        return Err("manifest_status_unsupported".to_string());
    }
    let contract = (
        operation.output_profile.as_str(),
        operation.postcondition.as_str(),
        operation.provider_mode.as_str(),
        operation.parameter_profile.as_str(),
        operation.coordinate_rule.as_str(),
        operation.expected_status.initial.as_deref(),
    );
    if !OPERATION_CONTRACTS.contains(&contract) {
        return Err("manifest_operation_contract_incoherent".to_string());
    }
    match operation.idempotency.mode.as_str() {
        "invocation"
            if operation.idempotency.retry_varying_fields.is_empty()
                && operation
                    .idempotency
                    .external_idempotency_identity_field
                    .is_none()
                && operation.idempotency.required_retry_marker.is_none()
                && operation.expected_status.reconciled.is_none() => {}
        "semantic_retry"
            if operation.idempotency.retry_varying_fields
                == SEMANTIC_RETRY_FIELDS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect::<Vec<_>>()
                && operation
                    .idempotency
                    .external_idempotency_identity_field
                    .as_deref()
                    == Some(EXTERNAL_IDEMPOTENCY_IDENTITY_FIELD)
                && operation
                    .idempotency
                    .required_retry_marker
                    .as_ref()
                    .is_some_and(|marker| {
                        marker.path == SEMANTIC_RETRY_MARKER_PATH
                            && marker.initial == 1
                            && marker.reconciled == 2
                    })
                && operation.expected_status.reconciled.as_deref() == Some("reconciled") => {}
        _ => return Err("manifest_idempotency_unsupported".to_string()),
    }
    if operation.bounds.max_array_items == 0
        || operation.bounds.max_integer_abs == 0
        || operation.bounds.max_output_bytes == 0
        || operation.bounds.max_string_bytes == 0
        || operation.bounds.max_array_items > limits.max_array_items
        || operation.bounds.max_output_bytes > limits.max_output_bytes
        || operation.bounds.max_string_bytes > limits.max_string_bytes
    {
        return Err("manifest_operation_bound_invalid".to_string());
    }
    canonical_json(
        &serde_json::to_value(operation)
            .map_err(|_| "manifest_operation_serialize_failed".to_string())?,
        limits.json(65_536),
    )?;
    Ok(())
}

fn sorted_unique(values: &[String], allowed: Option<&[&str]>) -> bool {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted == values
        && allowed
            .is_none_or(|allowed| values.iter().all(|value| allowed.contains(&value.as_str())))
}

impl serde::Serialize for OperationProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("OperationProfile", 15)?;
        state.serialize_field("action_name", &self.action_name)?;
        state.serialize_field("adapter_id", &self.adapter_id)?;
        state.serialize_field(
            "allowed_request_principals",
            &self.allowed_request_principals,
        )?;
        state.serialize_field("bounds", &SerializableBounds(&self.bounds))?;
        state.serialize_field("coordinate_rule", &self.coordinate_rule)?;
        state.serialize_field("effect_class", &self.effect_class)?;
        state.serialize_field(
            "expected_status",
            &SerializableStatus(&self.expected_status),
        )?;
        state.serialize_field("idempotency", &SerializableIdempotency(&self.idempotency))?;
        state.serialize_field("operation_id", &self.operation_id)?;
        state.serialize_field("output_profile", &self.output_profile)?;
        state.serialize_field("parameter_profile", &self.parameter_profile)?;
        state.serialize_field("postcondition", &self.postcondition)?;
        state.serialize_field("provider_mode", &self.provider_mode)?;
        state.serialize_field("required_permissions", &self.required_permissions)?;
        state.end()
    }
}

struct SerializableBounds<'a>(&'a OperationBounds);
impl serde::Serialize for SerializableBounds<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("OperationBounds", 4)?;
        state.serialize_field("max_array_items", &self.0.max_array_items)?;
        state.serialize_field("max_integer_abs", &self.0.max_integer_abs)?;
        state.serialize_field("max_output_bytes", &self.0.max_output_bytes)?;
        state.serialize_field("max_string_bytes", &self.0.max_string_bytes)?;
        state.end()
    }
}

struct SerializableStatus<'a>(&'a ExpectedStatus);
impl serde::Serialize for SerializableStatus<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("ExpectedStatus", 2)?;
        state.serialize_field("initial", &self.0.initial)?;
        state.serialize_field("reconciled", &self.0.reconciled)?;
        state.end()
    }
}

struct SerializableIdempotency<'a>(&'a IdempotencyProfile);
impl serde::Serialize for SerializableIdempotency<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct(
            "IdempotencyProfile",
            2 + usize::from(self.0.external_idempotency_identity_field.is_some())
                + usize::from(self.0.required_retry_marker.is_some()),
        )?;
        if let Some(field) = &self.0.external_idempotency_identity_field {
            state.serialize_field("external_idempotency_identity_field", field)?;
        }
        state.serialize_field("mode", &self.0.mode)?;
        if let Some(marker) = &self.0.required_retry_marker {
            state.serialize_field("required_retry_marker", &SerializableRetryMarker(marker))?;
        }
        state.serialize_field("retry_varying_fields", &self.0.retry_varying_fields)?;
        state.end()
    }
}

struct SerializableRetryMarker<'a>(&'a RetryMarker);
impl serde::Serialize for SerializableRetryMarker<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;
        let mut state = serializer.serialize_struct("RetryMarker", 3)?;
        state.serialize_field("initial", &self.0.initial)?;
        state.serialize_field("path", &self.0.path)?;
        state.serialize_field("reconciled", &self.0.reconciled)?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_manifest_is_exact_and_complete() {
        let manifest = OperationManifest::load_embedded().expect("manifest");
        let golden: Value = serde_json::from_str(include_str!(
            "../../fixtures/acceptance-provider-private-v3-golden.json"
        ))
        .expect("golden vectors");
        assert_eq!(manifest.operation_count(), 18);
        assert_eq!(
            manifest.digest,
            "sha256:7c0bbbc1fbe5d60c844a5c672d2f53bcf96782f72631c70abf30f4c2fd9909a0"
        );
        assert_eq!(manifest.allowed_for_role("local").len(), 8);
        assert_eq!(manifest.allowed_for_role("cloud").len(), 2);
        assert_eq!(manifest.allowed_for_role("vpc").len(), 4);
        assert_eq!(manifest.allowed_for_role("edge").len(), 7);
        let expected = golden["operation_digests"]
            .as_object()
            .expect("operation digests");
        for operation in manifest.operations.values() {
            assert_eq!(
                manifest
                    .operation_digest(operation)
                    .expect("operation digest"),
                expected[&operation.operation_id]
                    .as_str()
                    .expect("expected operation digest"),
                "{}",
                operation.operation_id,
            );
        }
    }

    #[test]
    fn malformed_duplicate_and_drifted_manifests_fail_closed() {
        let duplicate = br#"{"schema_version":"x","schema_version":"x"}"#;
        assert!(OperationManifest::load(duplicate, "sha256:invalid").is_err());
        assert!(OperationManifest::load(MANIFEST_BYTES, "sha256:invalid").is_err());
        let mut changed = MANIFEST_BYTES.to_vec();
        changed.push(b' ');
        assert!(OperationManifest::load(&changed, MANIFEST_DIGEST.trim()).is_err());
    }

    #[test]
    fn unknown_predicates_and_cross_family_contracts_fail_with_recomputed_digest() {
        let source: Value = serde_json::from_slice(MANIFEST_BYTES).expect("manifest JSON");
        for (index, field, replacement) in [
            (5, "postcondition", "totally_unimplemented_predicate"),
            (5, "output_profile", "marker"),
            (8, "postcondition", "sensor_read"),
        ] {
            let mut changed = source.clone();
            changed["operations"][index][field] = Value::String(replacement.to_string());
            let bytes = serde_json::to_vec(&changed).expect("changed manifest");
            let digest = sha256_bytes(PROFILE_DIGEST_DOMAIN, &bytes);
            assert!(OperationManifest::load(&bytes, &digest).is_err());
        }
    }
}
