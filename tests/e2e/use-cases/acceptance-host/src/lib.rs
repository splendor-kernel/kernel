//! Acceptance-only private-v3 provider adapter and outer composition support.
//!
//! This unpublished package is outside every production crate and image. The
//! checked-in manifest is the sole owner of acceptance operation policy.

mod manifest;
mod protocol;

use manifest::{OperationManifest, OperationProfile};
use protocol::{
    canonical_json, decode_b64, object_fields, parse_json, printable_token, read_secure_file,
    request_mac, sha256_bytes, sha256_value, validate_value, JsonLimits, EFFECT_DOMAIN,
    IDEMPOTENCY_DOMAIN, OUTPUT_DOMAIN, RECEIPT_ID_DOMAIN, RECEIPT_SIGNATURE_DOMAIN,
    REQUEST_BODY_DIGEST_DOMAIN, SEMANTIC_DOMAIN, STATE_DOMAIN,
};
use ring::signature;
use serde::Deserialize;
use serde_json::{Map, Value};
use splendor_daemon::ConfiguredActionAdapters;
use splendor_gateway::{ActionAdapter, ActionRequest, AdapterError, AdapterResult};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

const REQUEST_SCHEMA: &str = "splendor.acceptance.action_provider.request.v3";
const RECEIPT_PAYLOAD_SCHEMA: &str = "splendor.acceptance.action_provider.receipt_payload.v3";
const RECEIPT_ENVELOPE_SCHEMA: &str = "splendor.acceptance.signed_envelope.v3";
const HEALTH_SCHEMA: &str = "splendor.acceptance.action_provider.health.v3";
const REQUEST_CREDENTIAL_SCHEMA: &str = "splendor.acceptance.request_credential.v3";
const PROTOCOL_VERSION: &str = "private-v3";
const PROVIDER_ID: &str = "acceptance-action-provider";
const SIGNING_KEY_ID: &str = "acceptance-action-provider-ed25519-v3";
const TENANT_A: &str = "11111111-1111-4111-8111-111111111111";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestCredentialFile {
    schema_version: String,
    key_id: String,
    status: String,
    request_principal_role: String,
    client_principal_id: String,
    source_instance_id: String,
    tenant_id: String,
    audience: String,
    not_before_unix_ms: i64,
    expires_at_unix_ms: i64,
    max_request_ttl_ms: i64,
    allowed_operation_ids: Vec<String>,
    allowed_resource_scopes: Vec<ResourceScopeFile>,
    secret_b64: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct ResourceScopeFile {
    operation_id: String,
    resource_kind: String,
    resource_id: String,
}

#[derive(Clone)]
struct RequestCredential {
    key_id: String,
    role: String,
    client_principal_id: String,
    source_instance_id: String,
    tenant_id: String,
    audience: String,
    not_before_unix_ms: i64,
    expires_at_unix_ms: i64,
    max_request_ttl_ms: i64,
    allowed_operation_ids: Vec<String>,
    allowed_resource_scopes: BTreeSet<(String, String, String)>,
    secret: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthResponse {
    schema_version: String,
    protocol_version: String,
    status: String,
    provider_epoch: String,
    profile_set_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptEnvelope {
    schema_version: String,
    algorithm: String,
    signing_key_id: String,
    payload_encoding: String,
    payload_b64: String,
    signature_b64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PostconditionProof {
    operation_id: String,
    predicate: String,
    effect_id: String,
    state_digest: String,
    output_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptPayload {
    schema_version: String,
    protocol_version: String,
    provider_id: String,
    provider_revision: String,
    provider_epoch: String,
    provider_receipt_id: String,
    request_body_digest: String,
    request_key_id: String,
    client_principal_id: String,
    source_instance_id: String,
    audience: String,
    request_id: String,
    tenant_id: String,
    agent_id: String,
    run_id: String,
    tick_id: Value,
    action_id: String,
    adapter_id: String,
    action_name: String,
    physical_action_resource_coordinate: Value,
    operation_id: String,
    profile_set_digest: String,
    operation_profile_digest: String,
    idempotency_key: String,
    semantic_digest: String,
    request_issued_at_unix_ms: i64,
    request_deadline_unix_ms: i64,
    status: String,
    effect_certainty: String,
    effect_id: String,
    state_digest: String,
    output_profile: String,
    output_b64: String,
    output_digest: String,
    satisfied_postconditions: Vec<String>,
    postcondition_proof: PostconditionProof,
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReceiptBinding {
    receipt_id: String,
    payload_digest: String,
}

#[derive(Default)]
struct HostLedger {
    invocations: BTreeMap<String, Option<ReceiptBinding>>,
}

struct ProviderClient {
    endpoint: Url,
    agent: ureq::Agent,
    manifest: Arc<OperationManifest>,
    credential: RequestCredential,
    provider_epoch: String,
    receipt_public_key: [u8; 32],
    ledger: Mutex<HostLedger>,
}

struct AcceptanceActionAdapter {
    adapter_id: String,
    client: Arc<ProviderClient>,
}

/// Builds the fixed acceptance adapter set from one role-scoped credential.
pub fn configured_adapters(
    endpoint: &str,
    credential_path: &Path,
    public_key_path: &Path,
    expected_source_instance_id: &str,
) -> Result<ConfiguredActionAdapters, String> {
    let manifest = Arc::new(OperationManifest::load_embedded()?);
    let credential = load_request_credential(
        credential_path,
        expected_source_instance_id,
        manifest.as_ref(),
    )?;
    let receipt_public_key = load_public_key(public_key_path)?;
    let endpoint = validate_endpoint(endpoint)?;
    let agent = build_agent(Duration::from_secs(3));
    let provider_epoch = load_provider_epoch(&agent, &endpoint, manifest.as_ref())?;
    let client = Arc::new(ProviderClient {
        endpoint,
        agent,
        manifest,
        credential,
        provider_epoch,
        receipt_public_key,
        ledger: Mutex::new(HostLedger::default()),
    });
    let mut adapters = ConfiguredActionAdapters::new();
    for adapter_id in [
        "acceptance-fixture",
        "artifact-store",
        "daemon.local",
        "device-sim",
        "fixture-data-store",
        "fixture-sql",
        "remote-message",
    ] {
        adapters.insert(
            adapter_id,
            Arc::new(AcceptanceActionAdapter {
                adapter_id: adapter_id.to_string(),
                client: Arc::clone(&client),
            }),
        )?;
    }
    Ok(adapters)
}

fn build_agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(timeout)
        .timeout_connect(Duration::from_millis(750))
        .timeout_read(Duration::from_secs(2))
        .timeout_write(Duration::from_secs(2))
        .user_agent("splendor-acceptance-action-host/private-v3")
        .build()
}

fn validate_endpoint(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "acceptance_provider_endpoint_invalid".to_string())?;
    let host = url
        .host_str()
        .ok_or_else(|| "acceptance_provider_endpoint_invalid".to_string())?;
    let allowed_host = host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("acceptance-action-provider")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "http"
        || !allowed_host
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/actions"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("acceptance_provider_endpoint_not_closed".to_string());
    }
    Ok(url)
}

fn load_request_credential(
    path: &Path,
    expected_source_instance_id: &str,
    manifest: &OperationManifest,
) -> Result<RequestCredential, String> {
    let raw = read_secure_file(path, 65_536, true)?;
    let value = parse_json(
        &raw,
        JsonLimits {
            max_bytes: 65_536,
            max_depth: 12,
            max_fields: 128,
            max_array_items: 64,
            max_string_bytes: 2048,
        },
        false,
    )?;
    let file: RequestCredentialFile = serde_json::from_value(value)
        .map_err(|_| "request_credential_contract_invalid".to_string())?;
    let role_binding = match file.request_principal_role.as_str() {
        "local" => (
            "acceptance-request-local-v3",
            "acceptance-host-local",
            "00000000-0000-4000-8000-000000000300",
        ),
        "cloud" => (
            "acceptance-request-cloud-v3",
            "acceptance-host-cloud",
            "00000000-0000-4000-8000-000000000304",
        ),
        "vpc" => (
            "acceptance-request-vpc-v3",
            "acceptance-host-vpc",
            "00000000-0000-4000-8000-000000000302",
        ),
        "edge" => (
            "acceptance-request-edge-v3",
            "acceptance-host-edge",
            "00000000-0000-4000-8000-000000000306",
        ),
        _ => return Err("request_credential_role_invalid".to_string()),
    };
    let expected_operations = manifest.allowed_for_role(&file.request_principal_role);
    let allowed_resource_scopes = validate_credential_resource_scopes(
        &file.allowed_resource_scopes,
        &expected_operations,
        manifest,
        &file.tenant_id,
    )?;
    let now = now_ms()?;
    if file.schema_version != REQUEST_CREDENTIAL_SCHEMA
        || file.status != "active"
        || file.key_id != role_binding.0
        || file.client_principal_id != role_binding.1
        || file.source_instance_id != role_binding.2
        || file.source_instance_id != expected_source_instance_id
        || !canonical_uuid(&file.source_instance_id)
        || file.tenant_id != TENANT_A
        || file.audience != manifest.audience
        || file.max_request_ttl_ms != manifest.limits.max_request_ttl_ms
        || file.allowed_operation_ids != expected_operations
        || now < file.not_before_unix_ms
        || now >= file.expires_at_unix_ms
        || file.expires_at_unix_ms <= file.not_before_unix_ms
        || !printable_token(&file.key_id, 128)
        || !printable_token(&file.client_principal_id, 128)
    {
        return Err("request_credential_scope_invalid".to_string());
    }
    let secret = decode_b64(&file.secret_b64, Some(32))?;
    Ok(RequestCredential {
        key_id: file.key_id,
        role: file.request_principal_role,
        client_principal_id: file.client_principal_id,
        source_instance_id: file.source_instance_id,
        tenant_id: file.tenant_id,
        audience: file.audience,
        not_before_unix_ms: file.not_before_unix_ms,
        expires_at_unix_ms: file.expires_at_unix_ms,
        max_request_ttl_ms: file.max_request_ttl_ms,
        allowed_operation_ids: file.allowed_operation_ids,
        allowed_resource_scopes,
        secret,
    })
}

fn validate_credential_resource_scopes(
    scopes: &[ResourceScopeFile],
    allowed_operations: &[String],
    manifest: &OperationManifest,
    tenant_id: &str,
) -> Result<BTreeSet<(String, String, String)>, String> {
    let mut sorted = scopes.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted != scopes {
        return Err("request_credential_resource_scopes_invalid".to_string());
    }
    let mut required_operations = BTreeSet::new();
    for operation_id in allowed_operations {
        let (adapter, action) = operation_id
            .split_once('/')
            .ok_or_else(|| "request_credential_resource_scope_invalid".to_string())?;
        let operation = manifest
            .operation(adapter, action)
            .ok_or_else(|| "request_credential_resource_scope_invalid".to_string())?;
        if operation.coordinate_rule == "physical_node"
            || matches!(
                operation.parameter_profile.as_str(),
                "artifact_create" | "artifact_publish" | "data_read"
            )
        {
            required_operations.insert(operation_id.as_str());
        }
    }
    let mut result = BTreeSet::new();
    for scope in scopes {
        if !allowed_operations.contains(&scope.operation_id) {
            return Err("request_credential_resource_scope_invalid".to_string());
        }
        let (adapter, action) = scope
            .operation_id
            .split_once('/')
            .ok_or_else(|| "request_credential_resource_scope_invalid".to_string())?;
        let operation = manifest
            .operation(adapter, action)
            .ok_or_else(|| "request_credential_resource_scope_invalid".to_string())?;
        let valid = match scope.resource_kind.as_str() {
            "physical_node" => {
                operation.coordinate_rule == "physical_node" && canonical_uuid(&scope.resource_id)
            }
            "artifact_ref" => {
                matches!(
                    operation.parameter_profile.as_str(),
                    "artifact_create" | "artifact_publish"
                ) && scope
                    .resource_id
                    .starts_with(&format!("artifact://{tenant_id}/"))
                    && scope.resource_id.len() <= 512
                    && !scope.resource_id.contains("..")
            }
            "data_ref" => {
                operation.parameter_profile == "data_read"
                    && scope.resource_id.starts_with("dataset:tenant-a.")
                    && scope.resource_id.len() <= 512
                    && !scope.resource_id.contains("..")
            }
            _ => false,
        };
        if !valid
            || !result.insert((
                scope.operation_id.clone(),
                scope.resource_kind.clone(),
                scope.resource_id.clone(),
            ))
        {
            return Err("request_credential_resource_scope_invalid".to_string());
        }
    }
    let scoped_operations = result
        .iter()
        .map(|(operation, _, _)| operation.as_str())
        .collect::<BTreeSet<_>>();
    if scoped_operations != required_operations {
        return Err("request_credential_resource_scopes_invalid".to_string());
    }
    Ok(result)
}

fn load_public_key(path: &Path) -> Result<[u8; 32], String> {
    let raw = read_secure_file(path, 32, false)?;
    raw.try_into()
        .map_err(|_| "receipt_public_key_length_invalid".to_string())
}

fn load_provider_epoch(
    agent: &ureq::Agent,
    endpoint: &Url,
    manifest: &OperationManifest,
) -> Result<String, String> {
    let mut health_url = endpoint.clone();
    health_url.set_path("/health");
    let response = agent
        .get(health_url.as_str())
        .set("Accept", "application/json")
        .set("Accept-Encoding", "identity")
        .call()
        .map_err(|_| "acceptance_provider_health_unavailable".to_string())?;
    let bytes = read_http_body(response, 4096)
        .map_err(|_| "acceptance_provider_health_invalid".to_string())?;
    let value = parse_json(
        &bytes,
        JsonLimits {
            max_bytes: 4096,
            max_depth: 4,
            max_fields: 8,
            max_array_items: 1,
            max_string_bytes: 256,
        },
        true,
    )?;
    let health: HealthResponse = serde_json::from_value(value)
        .map_err(|_| "acceptance_provider_health_contract_invalid".to_string())?;
    if health.schema_version != HEALTH_SCHEMA
        || health.protocol_version != PROTOCOL_VERSION
        || health.status != "ready"
        || health.profile_set_digest != manifest.digest
        || !canonical_uuid(&health.provider_epoch)
    {
        return Err("acceptance_provider_health_identity_invalid".to_string());
    }
    Ok(health.provider_epoch)
}

impl AcceptanceActionAdapter {
    fn validate_action<'a>(
        &'a self,
        request: &ActionRequest,
    ) -> Result<&'a OperationProfile, AdapterError> {
        let operation = self
            .client
            .manifest
            .operation(&self.adapter_id, &request.action.name)
            .ok_or_else(|| adapter_failure("acceptance_operation_profile_unknown"))?;
        let action = serde_json::to_value(&request.action)
            .map_err(|_| adapter_failure("acceptance_action_not_serializable"))?;
        validate_value(
            &action,
            self.client
                .manifest
                .limits
                .json(self.client.manifest.limits.max_request_bytes),
        )
        .map_err(|_| adapter_failure("acceptance_action_grammar_invalid"))?;
        if request.tenant_id.to_string() != self.client.credential.tenant_id
            || request.adapter.as_deref() != Some(self.adapter_id.as_str())
            || !operation
                .allowed_request_principals
                .contains(&self.client.credential.role)
            || !self
                .client
                .credential
                .allowed_operation_ids
                .contains(&operation.operation_id)
            || operation.provider_mode == "forbidden"
            || action.get("side_effect_class") != Some(&operation.effect_class)
            || !request.action.preconditions.is_empty()
            || !request.satisfied_preconditions.is_empty()
            || request.action.cost_estimate.is_some()
            || request.action.postconditions != [operation.postcondition.as_str()]
            || request.action.required_permissions != operation.required_permissions
        {
            return Err(adapter_failure("acceptance_operation_profile_mismatch"));
        }
        validate_parameters(operation, request)?;
        validate_coordinate(operation, request)?;
        validate_resource_scope(operation, request, &self.client.credential)?;
        Ok(operation)
    }

    fn build_request(
        &self,
        request: &ActionRequest,
        operation: &OperationProfile,
    ) -> Result<Value, AdapterError> {
        let now = now_ms().map_err(|_| adapter_failure("acceptance_clock_invalid"))?;
        if now < self.client.credential.not_before_unix_ms
            || now >= self.client.credential.expires_at_unix_ms
        {
            return Err(adapter_failure("acceptance_request_credential_expired"));
        }
        let deadline = now
            .checked_add(self.client.credential.max_request_ttl_ms)
            .ok_or_else(|| adapter_failure("acceptance_request_deadline_invalid"))?
            .min(self.client.credential.expires_at_unix_ms);
        if deadline <= now {
            return Err(adapter_failure("acceptance_request_deadline_invalid"));
        }
        let action = serde_json::to_value(&request.action)
            .map_err(|_| adapter_failure("acceptance_action_not_serializable"))?;
        let coordinate = serde_json::to_value(&request.physical_action_resource_coordinate)
            .map_err(|_| adapter_failure("acceptance_resource_coordinate_invalid"))?;
        let tick_id = serde_json::to_value(request.tick_id)
            .map_err(|_| adapter_failure("acceptance_tick_id_invalid"))?;
        let mut value = serde_json::json!({
            "schema_version": REQUEST_SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "provider_id": PROVIDER_ID,
            "provider_revision": self.client.manifest.provider_revision,
            "provider_epoch": self.client.provider_epoch,
            "audience": self.client.credential.audience,
            "request_key_id": self.client.credential.key_id,
            "client_principal_id": self.client.credential.client_principal_id,
            "source_instance_id": self.client.credential.source_instance_id,
            "request_id": splendor_gateway::ActionId::new().to_string(),
            "tenant_id": request.tenant_id.to_string(),
            "agent_id": request.agent_id.to_string(),
            "run_id": request.run_id.to_string(),
            "tick_id": tick_id,
            "action_id": request.action_id.to_string(),
            "adapter_id": self.adapter_id,
            "action_name": request.action.name,
            "action_requested_at_unix_nanos": request.requested_at.unix_timestamp_nanos().to_string(),
            "action": action,
            "physical_action_resource_coordinate": coordinate,
            "operation_id": operation.operation_id,
            "profile_set_digest": self.client.manifest.digest,
            "operation_profile_digest": self.client.manifest.operation_digest(operation)
                .map_err(|_| adapter_failure("acceptance_operation_digest_failed"))?,
            "issued_at_unix_ms": now,
            "deadline_unix_ms": deadline,
        });
        let semantic = semantic_material(&value, operation)?;
        let idempotency = idempotency_material(&value, operation)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| adapter_failure("acceptance_request_not_object"))?;
        object.insert(
            "semantic_digest".to_string(),
            Value::String(
                sha256_value(SEMANTIC_DOMAIN, &semantic)
                    .map_err(|_| adapter_failure("acceptance_semantic_digest_failed"))?,
            ),
        );
        object.insert(
            "idempotency_key".to_string(),
            Value::String(
                sha256_value(IDEMPOTENCY_DOMAIN, &idempotency)
                    .map_err(|_| adapter_failure("acceptance_idempotency_digest_failed"))?,
            ),
        );
        let body_digest = sha256_value(REQUEST_BODY_DIGEST_DOMAIN, &value)
            .map_err(|_| adapter_failure("acceptance_request_digest_failed"))?;
        value
            .as_object_mut()
            .expect("request object remains an object")
            .insert(
                "request_body_digest".to_string(),
                Value::String(body_digest),
            );
        Ok(value)
    }

    fn reserve(&self, request_digest: &str) -> Result<(), AdapterError> {
        let mut ledger = self
            .client
            .ledger
            .lock()
            .map_err(|_| adapter_failure("acceptance_host_ledger_unavailable"))?;
        if !ledger.invocations.contains_key(request_digest) {
            if ledger.invocations.len() >= self.client.manifest.limits.max_ledger_entries {
                return Err(adapter_failure("acceptance_host_ledger_capacity_exhausted"));
            }
            ledger.invocations.insert(request_digest.to_string(), None);
        }
        Ok(())
    }

    fn bind_receipt(
        &self,
        request_digest: &str,
        receipt_id: &str,
        payload: &[u8],
    ) -> Result<(), AdapterError> {
        let binding = ReceiptBinding {
            receipt_id: receipt_id.to_string(),
            payload_digest: sha256_bytes(b"splendor.acceptance.host_receipt.v3\0", payload),
        };
        let mut ledger = self
            .client
            .ledger
            .lock()
            .map_err(|_| adapter_failure("acceptance_host_ledger_unavailable"))?;
        let current = ledger
            .invocations
            .get(request_digest)
            .ok_or_else(|| adapter_failure("acceptance_host_ledger_reservation_missing"))?;
        if current
            .as_ref()
            .is_some_and(|existing| existing != &binding)
        {
            return Err(adapter_failure("acceptance_provider_receipt_equivocated"));
        }
        if ledger.invocations.iter().any(|(digest, existing)| {
            digest != request_digest
                && existing.as_ref().is_some_and(|existing| {
                    existing.receipt_id == binding.receipt_id && existing != &binding
                })
        }) {
            return Err(adapter_failure("acceptance_provider_receipt_reused"));
        }
        let entry = ledger
            .invocations
            .get_mut(request_digest)
            .expect("reservation checked above");
        *entry = Some(binding);
        Ok(())
    }

    fn verify_receipt(
        &self,
        request: &ActionRequest,
        operation: &OperationProfile,
        invocation: &Value,
        response: &[u8],
    ) -> Result<AdapterResult, AdapterError> {
        let limits = &self.client.manifest.limits;
        let envelope_value = parse_json(
            response,
            JsonLimits {
                max_bytes: limits.max_response_bytes,
                max_depth: limits.max_depth,
                max_fields: limits.max_fields,
                max_array_items: limits.max_array_items,
                max_string_bytes: limits.max_response_bytes,
            },
            true,
        )
        .map_err(|_| post_send_failure("acceptance_provider_envelope_malformed"))?;
        let envelope: ReceiptEnvelope = serde_json::from_value(envelope_value.clone())
            .map_err(|_| post_send_failure("acceptance_provider_envelope_fields_invalid"))?;
        if envelope.schema_version != RECEIPT_ENVELOPE_SCHEMA
            || envelope.algorithm != "Ed25519"
            || envelope.signing_key_id != SIGNING_KEY_ID
            || envelope.payload_encoding != "base64url"
        {
            return Err(post_send_failure(
                "acceptance_provider_envelope_identity_invalid",
            ));
        }
        let payload_raw = decode_b64(&envelope.payload_b64, None)
            .map_err(|_| post_send_failure("acceptance_provider_payload_encoding_invalid"))?;
        let signature_bytes = decode_b64(&envelope.signature_b64, Some(64))
            .map_err(|_| post_send_failure("acceptance_provider_signature_encoding_invalid"))?;
        if payload_raw.is_empty() || payload_raw.len() > limits.max_response_bytes {
            return Err(post_send_failure("acceptance_provider_payload_oversized"));
        }
        let mut frame = Vec::with_capacity(RECEIPT_SIGNATURE_DOMAIN.len() + payload_raw.len());
        frame.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN);
        frame.extend_from_slice(&payload_raw);
        signature::UnparsedPublicKey::new(&signature::ED25519, self.client.receipt_public_key)
            .verify(&frame, &signature_bytes)
            .map_err(|_| post_send_failure("acceptance_provider_signature_invalid"))?;

        let payload_value = parse_json(
            &payload_raw,
            JsonLimits {
                max_bytes: limits.max_response_bytes,
                max_depth: limits.max_depth,
                max_fields: limits.max_fields,
                max_array_items: limits.max_array_items,
                max_string_bytes: limits.max_response_bytes,
            },
            true,
        )
        .map_err(|_| post_send_failure("acceptance_provider_payload_malformed"))?;
        let payload: ReceiptPayload = serde_json::from_value(payload_value)
            .map_err(|_| post_send_failure("acceptance_provider_payload_fields_invalid"))?;
        self.verify_receipt_payload(request, operation, invocation, &payload, &payload_raw)?;
        let output_raw = decode_b64(&payload.output_b64, None)
            .map_err(|_| post_send_failure("acceptance_provider_output_encoding_invalid"))?;
        let output = verify_output(request, operation, &payload, &output_raw, limits)?;
        self.bind_receipt(
            &payload.request_body_digest,
            &payload.provider_receipt_id,
            &payload_raw,
        )?;
        let mut output = output
            .as_object()
            .cloned()
            .ok_or_else(|| post_send_failure("acceptance_provider_output_invalid"))?;
        output.insert("provider_receipt".to_string(), envelope_value);
        Ok(AdapterResult {
            output: Value::Object(output),
            satisfied_postconditions: vec![operation.postcondition.clone()],
        })
    }

    fn verify_receipt_payload(
        &self,
        request: &ActionRequest,
        operation: &OperationProfile,
        invocation: &Value,
        payload: &ReceiptPayload,
        payload_raw: &[u8],
    ) -> Result<(), AdapterError> {
        let field = |name: &str| invocation.get(name);
        let retry_marker = operation.idempotency.required_retry_marker.as_ref();
        let expected_status = if operation.idempotency.mode == "semantic_retry"
            && request
                .action
                .params
                .get("retry_attempt")
                .and_then(Value::as_i64)
                == retry_marker.map(|marker| marker.reconciled)
        {
            operation.expected_status.reconciled.as_deref()
        } else {
            operation.expected_status.initial.as_deref()
        };
        let expected_operation_digest = self
            .client
            .manifest
            .operation_digest(operation)
            .map_err(|_| post_send_failure("acceptance_operation_digest_failed"))?;
        let invocation_string = |name: &str| field(name).and_then(Value::as_str);
        if payload.schema_version != RECEIPT_PAYLOAD_SCHEMA
            || payload.protocol_version != PROTOCOL_VERSION
            || payload.provider_id != PROVIDER_ID
            || payload.provider_revision != self.client.manifest.provider_revision
            || payload.provider_epoch != self.client.provider_epoch
            || payload.request_body_digest != invocation_string("request_body_digest").unwrap_or("")
            || payload.request_key_id != self.client.credential.key_id
            || payload.client_principal_id != self.client.credential.client_principal_id
            || payload.source_instance_id != self.client.credential.source_instance_id
            || payload.audience != self.client.credential.audience
            || payload.request_id != invocation_string("request_id").unwrap_or("")
            || payload.tenant_id != request.tenant_id.to_string()
            || payload.agent_id != request.agent_id.to_string()
            || payload.run_id != request.run_id.to_string()
            || Some(&payload.tick_id) != field("tick_id")
            || payload.action_id != request.action_id.to_string()
            || payload.adapter_id != self.adapter_id
            || payload.action_name != request.action.name
            || Some(&payload.physical_action_resource_coordinate)
                != field("physical_action_resource_coordinate")
            || payload.operation_id != operation.operation_id
            || payload.profile_set_digest != self.client.manifest.digest
            || payload.operation_profile_digest != expected_operation_digest
            || payload.idempotency_key != invocation_string("idempotency_key").unwrap_or("")
            || payload.semantic_digest != invocation_string("semantic_digest").unwrap_or("")
            || Some(payload.request_issued_at_unix_ms)
                != field("issued_at_unix_ms").and_then(Value::as_i64)
            || Some(payload.request_deadline_unix_ms)
                != field("deadline_unix_ms").and_then(Value::as_i64)
            || Some(payload.status.as_str()) != expected_status
            || payload.effect_certainty != "known"
            || payload.output_profile != operation.output_profile
            || payload.satisfied_postconditions != [operation.postcondition.as_str()]
        {
            return Err(post_send_failure(
                "acceptance_provider_receipt_binding_mismatch",
            ));
        }
        let now = now_ms().map_err(|_| post_send_failure("acceptance_clock_invalid"))?;
        if payload.issued_at_unix_ms > now + self.client.manifest.limits.max_future_skew_ms
            || payload.expires_at_unix_ms <= now
            || payload.expires_at_unix_ms <= payload.issued_at_unix_ms
            || payload.expires_at_unix_ms - payload.issued_at_unix_ms
                > self.client.manifest.limits.max_receipt_ttl_ms
        {
            return Err(post_send_failure("acceptance_provider_receipt_stale"));
        }
        let expected_effect = sha256_value(
            EFFECT_DOMAIN,
            &serde_json::json!({"idempotency_key": payload.idempotency_key}),
        )
        .map_err(|_| post_send_failure("acceptance_effect_digest_failed"))?;
        let expected_receipt_id = sha256_value(
            RECEIPT_ID_DOMAIN,
            &serde_json::json!({
                "provider_epoch": payload.provider_epoch,
                "idempotency_key": payload.idempotency_key,
                "request_body_digest": payload.request_body_digest,
                "status": payload.status,
            }),
        )
        .map_err(|_| post_send_failure("acceptance_receipt_digest_failed"))?;
        if payload.effect_id != expected_effect
            || payload.provider_receipt_id != expected_receipt_id
        {
            return Err(post_send_failure(
                "acceptance_provider_receipt_identity_mismatch",
            ));
        }
        if payload_raw.len() > self.client.manifest.limits.max_response_bytes {
            return Err(post_send_failure("acceptance_provider_payload_oversized"));
        }
        Ok(())
    }
}

impl ActionAdapter for AcceptanceActionAdapter {
    fn execute(&self, request: &ActionRequest) -> Result<AdapterResult, AdapterError> {
        let operation = self.validate_action(request)?;
        let invocation = self.build_request(request, operation)?;
        let request_digest = invocation
            .get("request_body_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| adapter_failure("acceptance_request_digest_missing"))?;
        self.reserve(request_digest)?;
        let body = canonical_json(
            &invocation,
            self.client
                .manifest
                .limits
                .json(self.client.manifest.limits.max_request_bytes),
        )
        .map_err(|_| adapter_failure("acceptance_request_canonicalization_failed"))?;
        let signature = request_mac(
            &self.client.credential.secret,
            &self.client.credential.key_id,
            &body,
        )
        .map_err(|_| adapter_failure("acceptance_request_signature_failed"))?;
        let response = self
            .client
            .agent
            .post(self.client.endpoint.as_str())
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .set("Accept-Encoding", "identity")
            .set(
                "X-Splendor-Acceptance-Key-Id",
                &self.client.credential.key_id,
            )
            .set("X-Splendor-Acceptance-Signature", &signature)
            .send_bytes(&body)
            .map_err(classify_transport)?;
        let response = read_http_body(response, self.client.manifest.limits.max_response_bytes)?;
        self.verify_receipt(request, operation, &invocation, &response)
    }
}

fn semantic_material(request: &Value, operation: &OperationProfile) -> Result<Value, AdapterError> {
    let mut material = request
        .as_object()
        .cloned()
        .ok_or_else(|| adapter_failure("acceptance_request_not_object"))?;
    for field in ["idempotency_key", "semantic_digest", "request_body_digest"] {
        material.remove(field);
    }
    if operation.idempotency.mode == "semantic_retry" {
        for path in &operation.idempotency.retry_varying_fields {
            remove_material_path(&mut material, path)?;
        }
    }
    Ok(Value::Object(material))
}

fn idempotency_material(
    request: &Value,
    operation: &OperationProfile,
) -> Result<Value, AdapterError> {
    if operation.idempotency.mode != "semantic_retry" {
        return semantic_material(request, operation);
    }
    let external = request
        .pointer("/action/params/idempotency_key")
        .cloned()
        .ok_or_else(|| adapter_failure("acceptance_external_idempotency_key_missing"))?;
    Ok(serde_json::json!({
        "request_key_id": request.get("request_key_id").ok_or_else(|| adapter_failure("acceptance_request_material_missing"))?,
        "operation_id": request.get("operation_id").ok_or_else(|| adapter_failure("acceptance_request_material_missing"))?,
        "external_idempotency_key": external,
        "provider_epoch": request.get("provider_epoch").ok_or_else(|| adapter_failure("acceptance_request_material_missing"))?,
    }))
}

fn remove_material_path(material: &mut Map<String, Value>, path: &str) -> Result<(), AdapterError> {
    let mut parts = path.split('.').peekable();
    let mut current = material;
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return current
                .remove(part)
                .map(|_| ())
                .ok_or_else(|| adapter_failure("acceptance_semantic_retry_path_missing"));
        }
        current = current
            .get_mut(part)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| adapter_failure("acceptance_semantic_retry_path_missing"))?;
    }
    Err(adapter_failure("acceptance_semantic_retry_path_missing"))
}

fn validate_parameters(
    operation: &OperationProfile,
    request: &ActionRequest,
) -> Result<(), AdapterError> {
    let params = request
        .action
        .params
        .as_object()
        .ok_or_else(|| adapter_failure("acceptance_operation_params_not_object"))?;
    if contains_reserved(&request.action.params) {
        return Err(adapter_failure("acceptance_operation_reserved_field"));
    }
    let keys = params.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let valid_token = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .is_some_and(|value| printable_token(value, 256))
    };
    let valid = match operation.parameter_profile.as_str() {
        "empty" => keys.is_empty(),
        "management_marker" => {
            params
                == &Map::from_iter([
                    ("source".to_string(), Value::String("uc-e2e-s2".to_string())),
                    ("ok".to_string(), Value::Bool(true)),
                ])
        }
        "idempotent_read" => {
            let retry_marker = operation.idempotency.required_retry_marker.as_ref();
            keys.is_subset(&BTreeSet::from([
                "idempotency_key",
                "retry_attempt",
                "retryable",
                "max_attempts",
            ])) && valid_token(params.get("idempotency_key"))
                && params
                    .get("retry_attempt")
                    .is_none_or(|value| {
                        retry_marker.is_some_and(|marker| {
                            matches!(value.as_i64(), Some(attempt) if attempt == marker.initial || attempt == marker.reconciled)
                        })
                    })
                && params
                    .get("retryable")
                    .is_none_or(|value| value.as_bool() == Some(true))
                && params
                    .get("max_attempts")
                    .is_none_or(|value| value.as_i64() == Some(2))
        }
        "unsafe_failure" => {
            keys == BTreeSet::from(["idempotency_key", "retry_attempt", "retryable"])
                && params.get("idempotency_key").is_some_and(Value::is_null)
                && params.get("retry_attempt").and_then(Value::as_i64) == Some(1)
                && params.get("retryable").and_then(Value::as_bool) == Some(false)
        }
        "artifact_create" | "artifact_publish" => {
            let field = if operation.parameter_profile == "artifact_create" {
                "artifact_path"
            } else {
                "publish_ref"
            };
            keys == BTreeSet::from([field])
                && params
                    .get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| {
                        value.starts_with(&format!("artifact://{}/", request.tenant_id))
                            && value.len() <= 512
                            && !value.contains("..")
                    })
        }
        "data_read" => {
            keys == BTreeSet::from(["data_ref"])
                && request.tenant_id.to_string() == TENANT_A
                && params
                    .get("data_ref")
                    .and_then(Value::as_str)
                    .is_some_and(|value| {
                        value.starts_with("dataset:tenant-a.")
                            && value.len() <= 512
                            && !value.contains("..")
                    })
        }
        "physical" => {
            keys.is_subset(&BTreeSet::from([
                "physical_action",
                "cloud_helper_proposal_id",
                "cloud_helper_message_id",
            ])) && params.get("physical_action").and_then(Value::as_bool) == Some(true)
                && ["cloud_helper_proposal_id", "cloud_helper_message_id"]
                    .iter()
                    .all(|field| {
                        params
                            .get(*field)
                            .is_none_or(|value| valid_token(Some(value)))
                    })
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(adapter_failure("acceptance_operation_params_invalid"))
    }
}

fn validate_coordinate(
    operation: &OperationProfile,
    request: &ActionRequest,
) -> Result<(), AdapterError> {
    let value = serde_json::to_value(&request.physical_action_resource_coordinate)
        .map_err(|_| adapter_failure("acceptance_resource_coordinate_invalid"))?;
    match operation.coordinate_rule.as_str() {
        "none" if value.is_null() => Ok(()),
        "physical_node"
            if object_fields(&value) == Some(BTreeSet::from(["node_id", "resource_kind"]))
                && value.get("resource_kind").and_then(Value::as_str) == Some("physical_node")
                && value
                    .get("node_id")
                    .and_then(Value::as_str)
                    .is_some_and(canonical_uuid) =>
        {
            Ok(())
        }
        _ => Err(adapter_failure("acceptance_resource_coordinate_mismatch")),
    }
}

fn validate_resource_scope(
    operation: &OperationProfile,
    request: &ActionRequest,
    credential: &RequestCredential,
) -> Result<(), AdapterError> {
    let scope = if operation.coordinate_rule == "physical_node" {
        let coordinate = serde_json::to_value(&request.physical_action_resource_coordinate)
            .map_err(|_| adapter_failure("acceptance_resource_coordinate_invalid"))?;
        Some((
            operation.operation_id.clone(),
            "physical_node".to_string(),
            coordinate
                .get("node_id")
                .and_then(Value::as_str)
                .ok_or_else(|| adapter_failure("acceptance_resource_coordinate_invalid"))?
                .to_string(),
        ))
    } else {
        let (kind, field) = match operation.parameter_profile.as_str() {
            "artifact_create" => ("artifact_ref", "artifact_path"),
            "artifact_publish" => ("artifact_ref", "publish_ref"),
            "data_read" => ("data_ref", "data_ref"),
            _ => return Ok(()),
        };
        Some((
            operation.operation_id.clone(),
            kind.to_string(),
            request
                .action
                .params
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| adapter_failure("acceptance_resource_scope_invalid"))?
                .to_string(),
        ))
    };
    if scope.is_some_and(|scope| credential.allowed_resource_scopes.contains(&scope)) {
        Ok(())
    } else {
        Err(adapter_failure("acceptance_request_resource_scope_denied"))
    }
}

fn contains_reserved(value: &Value) -> bool {
    const RESERVED: &[&str] = &[
        "endpoint",
        "url",
        "authorization",
        "credential",
        "secret",
        "adapter_id",
        "tenant_id",
        "agent_id",
        "run_id",
        "tick_id",
        "action_id",
        "node_id",
        "resource_coordinate",
        "provider_receipt",
        "signature_b64",
        "request_key_id",
        "provider_epoch",
    ];
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, child)| RESERVED.contains(&key.as_str()) || contains_reserved(child)),
        Value::Array(values) => values.iter().any(contains_reserved),
        _ => false,
    }
}

fn verify_output(
    request: &ActionRequest,
    operation: &OperationProfile,
    payload: &ReceiptPayload,
    output_raw: &[u8],
    limits: &manifest::Limits,
) -> Result<Value, AdapterError> {
    if output_raw.is_empty() || output_raw.len() > operation.bounds.max_output_bytes {
        return Err(post_send_failure("acceptance_provider_output_oversized"));
    }
    let output = parse_json(
        output_raw,
        JsonLimits {
            max_bytes: operation.bounds.max_output_bytes,
            max_depth: limits.max_depth,
            max_fields: limits.max_fields,
            max_array_items: operation.bounds.max_array_items,
            max_string_bytes: operation.bounds.max_string_bytes,
        },
        true,
    )
    .map_err(|_| post_send_failure("acceptance_provider_output_malformed"))?;
    let expected_output_digest = sha256_bytes(OUTPUT_DOMAIN, output_raw);
    let expected_fields = BTreeSet::from([
        "action_id",
        "effect_id",
        "operation_id",
        "proof_type",
        "result",
        "state_digest",
        "tenant_id",
    ]);
    if object_fields(&output) != Some(expected_fields)
        || output.get("operation_id").and_then(Value::as_str) != Some(&operation.operation_id)
        || output.get("proof_type").and_then(Value::as_str) != Some(&operation.output_profile)
        || output.get("tenant_id").and_then(Value::as_str)
            != Some(request.tenant_id.to_string().as_str())
        || output.get("action_id").and_then(Value::as_str)
            != Some(request.action_id.to_string().as_str())
        || output.get("effect_id").and_then(Value::as_str) != Some(&payload.effect_id)
        || output.get("state_digest").and_then(Value::as_str) != Some(&payload.state_digest)
        || payload.output_digest != expected_output_digest
    {
        return Err(post_send_failure(
            "acceptance_provider_output_binding_mismatch",
        ));
    }
    let result = output
        .get("result")
        .ok_or_else(|| post_send_failure("acceptance_provider_result_missing"))?;
    validate_integer_bounds(result, operation.bounds.max_integer_abs)?;
    let expected_state = sha256_value(STATE_DOMAIN, result)
        .map_err(|_| post_send_failure("acceptance_state_digest_failed"))?;
    if payload.state_digest != expected_state
        || !validate_result_family(request, operation, payload, result)
    {
        return Err(post_send_failure(
            "acceptance_provider_output_family_mismatch",
        ));
    }
    let proof = &payload.postcondition_proof;
    if proof.operation_id != operation.operation_id
        || proof.predicate != operation.postcondition
        || proof.effect_id != payload.effect_id
        || proof.state_digest != payload.state_digest
        || proof.output_digest != payload.output_digest
    {
        return Err(post_send_failure(
            "acceptance_provider_postcondition_proof_mismatch",
        ));
    }
    Ok(output)
}

fn validate_result_family(
    request: &ActionRequest,
    operation: &OperationProfile,
    payload: &ReceiptPayload,
    result: &Value,
) -> bool {
    let exact = |fields: &[&str]| {
        object_fields(result) == Some(fields.iter().copied().collect::<BTreeSet<_>>())
    };
    let coordinate = serde_json::to_value(&request.physical_action_resource_coordinate).ok();
    let coordinate_matches = || result.get("coordinate") == coordinate.as_ref();
    match operation.output_profile.as_str() {
        "marker" => {
            exact(&[
                "tenant_id",
                "run_id",
                "action_id",
                "action_name",
                "effect_id",
            ]) && result.get("tenant_id").and_then(Value::as_str)
                == Some(request.tenant_id.to_string().as_str())
                && result.get("run_id").and_then(Value::as_str)
                    == Some(request.run_id.to_string().as_str())
                && result.get("action_id").and_then(Value::as_str)
                    == Some(request.action_id.to_string().as_str())
                && result.get("action_name").and_then(Value::as_str)
                    == Some(request.action.name.as_str())
                && result.get("effect_id").and_then(Value::as_str) == Some(&payload.effect_id)
        }
        "fixture_read" => {
            exact(&["fixture", "record_count"])
                && result.get("fixture").and_then(Value::as_str) == Some("s9-idempotent-read")
                && result.get("record_count").and_then(Value::as_i64) == Some(1)
        }
        "sql_read" => {
            exact(&["row_count", "rows"])
                && result.get("row_count").and_then(Value::as_i64) == Some(1)
                && result.get("rows") == Some(&serde_json::json!([{"fixture": 1}]))
        }
        "data_read" => {
            exact(&[
                "data_ref",
                "tenant_id",
                "raw_payload_included",
                "record_count",
            ]) && result.get("data_ref") == request.action.params.get("data_ref")
                && result.get("tenant_id").and_then(Value::as_str)
                    == Some(request.tenant_id.to_string().as_str())
                && result.get("raw_payload_included").and_then(Value::as_bool) == Some(false)
                && result.get("record_count").and_then(Value::as_i64) == Some(3)
        }
        "artifact_create" | "artifact_publish" => {
            let field = if operation.output_profile == "artifact_create" {
                "artifact_path"
            } else {
                "publish_ref"
            };
            let published = operation.output_profile == "artifact_publish";
            exact(&[
                "artifact_ref",
                "tenant_id",
                "created",
                "published",
                "external_store",
            ]) && result.get("artifact_ref") == request.action.params.get(field)
                && result.get("tenant_id").and_then(Value::as_str)
                    == Some(request.tenant_id.to_string().as_str())
                && result.get("created").and_then(Value::as_bool) == Some(true)
                && result.get("published").and_then(Value::as_bool) == Some(published)
                && if published {
                    result.get("external_store").and_then(Value::as_str)
                        == Some("acceptance-action-provider-v3")
                } else {
                    result.get("external_store").is_some_and(Value::is_null)
                }
        }
        "physical_battery" => {
            exact(&["coordinate", "battery_milli_percent"])
                && coordinate_matches()
                && result.get("battery_milli_percent").and_then(Value::as_i64) == Some(820)
        }
        "physical_sensor" => {
            exact(&["coordinate", "battery_milli_percent", "sensor_status"])
                && coordinate_matches()
                && result.get("battery_milli_percent").and_then(Value::as_i64) == Some(820)
                && result.get("sensor_status").and_then(Value::as_str) == Some("nominal")
        }
        "physical_inspect" => {
            exact(&["coordinate", "inspected_zone"])
                && coordinate_matches()
                && result.get("inspected_zone").and_then(Value::as_str) == Some("zone:warehouse-a3")
        }
        "physical_waypoint" => {
            exact(&["coordinate", "waypoint"])
                && coordinate_matches()
                && result.get("waypoint").and_then(Value::as_str) == Some("waypoint:warehouse-a3")
        }
        "physical_image" => {
            exact(&["coordinate", "images_captured"])
                && coordinate_matches()
                && result
                    .get("images_captured")
                    .and_then(Value::as_i64)
                    .is_some_and(|value| value > 0)
        }
        "physical_return" => {
            exact(&["coordinate", "at_base"])
                && coordinate_matches()
                && result.get("at_base").and_then(Value::as_bool) == Some(true)
        }
        "physical_trace_upload" => {
            exact(&["coordinate", "trace_summaries_uploaded"])
                && coordinate_matches()
                && result
                    .get("trace_summaries_uploaded")
                    .and_then(Value::as_i64)
                    .is_some_and(|value| value > 0)
        }
        _ => false,
    }
}

fn validate_integer_bounds(value: &Value, maximum: i64) -> Result<(), AdapterError> {
    match value {
        Value::Number(number) => {
            let value = number
                .as_i64()
                .ok_or_else(|| post_send_failure("acceptance_provider_integer_invalid"))?;
            if value.checked_abs().is_none_or(|value| value > maximum) {
                return Err(post_send_failure(
                    "acceptance_provider_integer_bound_exceeded",
                ));
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_integer_bounds(value, maximum)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_integer_bounds(value, maximum)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn read_http_body(response: ureq::Response, maximum: usize) -> Result<Vec<u8>, AdapterError> {
    let lengths = response.all("Content-Length");
    if response.status() != 200
        || response.header("Content-Type") != Some("application/json")
        || lengths.len() != 1
        || !response.all("Transfer-Encoding").is_empty()
    {
        return Err(post_send_failure(
            "acceptance_provider_http_framing_invalid",
        ));
    }
    let length = lengths[0]
        .parse::<usize>()
        .map_err(|_| post_send_failure("acceptance_provider_content_length_invalid"))?;
    if length == 0 || length > maximum {
        return Err(post_send_failure("acceptance_provider_response_oversized"));
    }
    let mut bytes = Vec::with_capacity(length);
    response
        .into_reader()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| post_send_failure("acceptance_provider_response_read_failed"))?;
    if bytes.len() != length || bytes.len() > maximum {
        return Err(post_send_failure(
            "acceptance_provider_response_size_mismatch",
        ));
    }
    Ok(bytes)
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| !parsed.is_nil() && parsed.to_string() == value)
}

fn now_ms() -> Result<i64, String> {
    i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| "clock_out_of_range".to_string())
}

fn classify_transport(error: ureq::Error) -> AdapterError {
    match error {
        ureq::Error::Transport(transport)
            if matches!(
                transport.kind(),
                ureq::ErrorKind::Dns | ureq::ErrorKind::ConnectionFailed
            ) =>
        {
            adapter_failure("acceptance_provider_connect_failed")
        }
        ureq::Error::Transport(_) => post_send_failure("acceptance_provider_transport_uncertain"),
        ureq::Error::Status(_, _) => post_send_failure("acceptance_provider_status_failure"),
    }
}

fn post_send_failure(reason: &'static str) -> AdapterError {
    adapter_failure(reason)
}

fn adapter_failure(reason: &'static str) -> AdapterError {
    AdapterError::Failed(reason.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use splendor_gateway::ActionId;
    use splendor_types::{
        Action, AgentId, NodeId, PhysicalActionResourceCoordinate, QuotaUsage, RunId,
        SideEffectClass, TenantId,
    };

    const TENANT_B: &str = "11111111-1111-4111-8111-222222222227";

    #[test]
    fn endpoint_is_closed_and_v2_is_absent() {
        assert!(validate_endpoint("http://127.0.0.1:8086/actions").is_ok());
        for endpoint in [
            "https://127.0.0.1:8086/actions",
            "http://example.com/actions",
            "http://user@127.0.0.1:8086/actions",
            "http://127.0.0.1:8086/actions?target=other",
            "http://127.0.0.1:8086/other",
        ] {
            assert!(validate_endpoint(endpoint).is_err(), "{endpoint}");
        }
        assert_ne!(
            REQUEST_SCHEMA,
            "splendor.acceptance_action_provider.request.v2"
        );
    }

    #[test]
    fn canonical_parser_rejects_ambiguous_grammar() {
        let limits = JsonLimits {
            max_bytes: 128,
            max_depth: 4,
            max_fields: 8,
            max_array_items: 4,
            max_string_bytes: 32,
        };
        for invalid in [
            br#"{"a":1,"a":1}"#.as_slice(),
            br#"{"a":1.0}"#.as_slice(),
            br#"{"a":1e0}"#.as_slice(),
            br#"{"a":9223372036854775808}"#.as_slice(),
            br#"{ "a":1}"#.as_slice(),
            b"{\"a\":\"\n\"}".as_slice(),
        ] {
            assert!(parse_json(invalid, limits, true).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn shared_parser_boundary_and_limit_vectors_fail_closed() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ClosedObject {
            #[serde(rename = "a")]
            _a: i64,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TypedInteger {
            #[serde(rename = "value")]
            _value: i64,
        }

        let vector: Value = serde_json::from_str(include_str!(
            "../../fixtures/acceptance-provider-private-v3-golden.json"
        ))
        .expect("golden vectors");
        let base_limits = JsonLimits {
            max_bytes: 6_000,
            max_depth: 16,
            max_fields: 256,
            max_array_items: 64,
            max_string_bytes: 2_048,
        };
        for case in vector["invalid_json"]
            .as_array()
            .expect("invalid JSON vectors")
        {
            let raw = decode_b64(case["raw_b64"].as_str().expect("raw vector"), None)
                .expect("decoded raw vector");
            assert!(parse_json(&raw, base_limits, true).is_err(), "{case}");
        }
        for case in vector["canonical_integer_boundaries"]
            .as_array()
            .expect("integer vectors")
        {
            let raw = decode_b64(case["raw_b64"].as_str().expect("raw vector"), None)
                .expect("decoded raw vector");
            let parsed = parse_json(&raw, base_limits, true).expect("integer boundary");
            assert_eq!(parsed["a"], case["value"]);
        }
        let generated = [
            (
                "huge_integer",
                {
                    let mut raw = b"{\"a\":".to_vec();
                    raw.extend(std::iter::repeat_n(b'9', 5_000));
                    raw.push(b'}');
                    raw
                },
                base_limits,
            ),
            (
                "depth",
                b"{\"a\":{\"b\":{\"c\":{\"d\":1}}}}".to_vec(),
                JsonLimits {
                    max_depth: 4,
                    ..base_limits
                },
            ),
            (
                "fields",
                b"{\"a\":1,\"b\":2,\"c\":3}".to_vec(),
                JsonLimits {
                    max_fields: 2,
                    ..base_limits
                },
            ),
            (
                "array",
                b"{\"a\":[1,2,3]}".to_vec(),
                JsonLimits {
                    max_array_items: 2,
                    ..base_limits
                },
            ),
            (
                "string",
                b"{\"a\":\"abc\"}".to_vec(),
                JsonLimits {
                    max_string_bytes: 2,
                    ..base_limits
                },
            ),
            (
                "body",
                b"{\"a\":123}".to_vec(),
                JsonLimits {
                    max_bytes: 8,
                    ..base_limits
                },
            ),
        ];
        for (name, raw, limits) in generated {
            assert!(vector["invalid_generated_json"]
                .as_array()
                .expect("generated vectors")
                .iter()
                .any(|case| case["case"].as_str() == Some(name)));
            assert!(parse_json(&raw, limits, true).is_err(), "{name}");
        }
        for case in vector["closed_object_vectors"]
            .as_array()
            .expect("closed object vectors")
        {
            let raw = decode_b64(case["raw_b64"].as_str().expect("raw vector"), None)
                .expect("decoded raw vector");
            let parsed = parse_json(&raw, base_limits, true).expect("closed object syntax");
            let allowed = case["allowed_fields"]
                .as_array()
                .expect("allowed fields")
                .iter()
                .map(|field| field.as_str().expect("field"))
                .collect::<BTreeSet<_>>();
            assert_ne!(object_fields(&parsed), Some(allowed));
            assert!(serde_json::from_value::<ClosedObject>(parsed).is_err());
        }
        for case in vector["typed_integer_vectors"]
            .as_array()
            .expect("typed integer vectors")
        {
            let raw = decode_b64(case["raw_b64"].as_str().expect("raw vector"), None)
                .expect("decoded raw vector");
            let parsed = parse_json(&raw, base_limits, true).expect("typed vector syntax");
            assert!(parsed[case["field"].as_str().expect("field")]
                .as_i64()
                .is_none());
            assert!(serde_json::from_value::<TypedInteger>(parsed).is_err());
        }
        for value in vector["invalid_base64url"]
            .as_array()
            .expect("base64 vectors")
        {
            assert!(decode_b64(value.as_str().expect("base64 value"), None).is_err());
        }
    }

    #[test]
    fn shared_canonical_hmac_and_ed25519_golden_vectors_match() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../fixtures/acceptance-provider-private-v3-golden.json"
        ))
        .expect("golden vector");
        let value = vector.get("canonical_value").expect("canonical value");
        let limits = JsonLimits {
            max_bytes: 4096,
            max_depth: 16,
            max_fields: 128,
            max_array_items: 64,
            max_string_bytes: 2048,
        };
        let canonical = canonical_json(value, limits).expect("canonical bytes");
        assert_eq!(
            std::str::from_utf8(&canonical).expect("ascii"),
            vector["canonical_bytes"].as_str().expect("canonical text")
        );
        assert_eq!(
            sha256_value(
                vector["canonical_digest_domain"]
                    .as_str()
                    .expect("digest domain"),
                value,
            )
            .expect("digest"),
            vector["canonical_digest"]
                .as_str()
                .expect("expected digest")
        );
        let request_key = decode_b64(
            vector["request_hmac_test_input_b64"]
                .as_str()
                .expect("request key"),
            Some(32),
        )
        .expect("decoded request key");
        assert_eq!(
            request_mac(
                &request_key,
                vector["request_key_id"].as_str().expect("request key id"),
                &canonical,
            )
            .expect("request MAC"),
            vector["request_signature_b64"]
                .as_str()
                .expect("request signature")
        );

        let payload = decode_b64(
            vector["receipt_payload_b64"]
                .as_str()
                .expect("receipt payload"),
            None,
        )
        .expect("decoded payload");
        let public_key = decode_b64(
            vector["receipt_public_key_b64"]
                .as_str()
                .expect("receipt public key"),
            Some(32),
        )
        .expect("decoded public key");
        let signature = decode_b64(
            vector["receipt_signature_b64"]
                .as_str()
                .expect("receipt signature"),
            Some(64),
        )
        .expect("decoded signature");
        let mut frame = RECEIPT_SIGNATURE_DOMAIN.to_vec();
        frame.extend_from_slice(&payload);
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(&frame, &signature)
            .expect("golden Ed25519 signature");
    }

    fn marker_request() -> ActionRequest {
        ActionRequest {
            action_id: ActionId::new(),
            tenant_id: TenantId::parse(TENANT_A).expect("tenant"),
            agent_id: AgentId::new(),
            run_id: RunId::new(),
            tick_id: None,
            action: Action {
                name: "daemon_management_action".to_string(),
                params: serde_json::json!({"source": "uc-e2e-s2", "ok": true}),
                side_effect_class: SideEffectClass::External,
                cost_estimate: None,
                required_permissions: vec![],
                preconditions: vec![],
                postconditions: vec!["marker_recorded".to_string()],
            },
            adapter: Some("daemon.local".to_string()),
            quota_usage: QuotaUsage::single_action(),
            satisfied_preconditions: vec![],
            requested_at: OffsetDateTime::now_utc(),
            physical_action_resource_coordinate: None,
            approval_evidence: None,
            authority_obligation_evidence: None,
            authority_obligation_receipts: vec![],
        }
    }

    fn marker_context() -> (
        AcceptanceActionAdapter,
        Ed25519KeyPair,
        ActionRequest,
        Value,
    ) {
        let manifest = Arc::new(OperationManifest::load_embedded().expect("manifest"));
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("key bytes");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key pair");
        let public_key: [u8; 32] = key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("public key");
        let now = now_ms().expect("clock");
        let credential = RequestCredential {
            key_id: "acceptance-request-local-v3".to_string(),
            role: "local".to_string(),
            client_principal_id: "acceptance-host-local".to_string(),
            source_instance_id: "00000000-0000-4000-8000-000000000300".to_string(),
            tenant_id: TENANT_A.to_string(),
            audience: manifest.audience.clone(),
            not_before_unix_ms: now - 60_000,
            expires_at_unix_ms: now + 60_000,
            max_request_ttl_ms: manifest.limits.max_request_ttl_ms,
            allowed_operation_ids: manifest.allowed_for_role("local"),
            allowed_resource_scopes: BTreeSet::new(),
            secret: vec![7; 32],
        };
        let adapter = AcceptanceActionAdapter {
            adapter_id: "daemon.local".to_string(),
            client: Arc::new(ProviderClient {
                endpoint: validate_endpoint("http://127.0.0.1:1/actions").expect("endpoint"),
                agent: build_agent(Duration::from_millis(25)),
                manifest,
                credential,
                provider_epoch: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1".to_string(),
                receipt_public_key: public_key,
                ledger: Mutex::new(HostLedger::default()),
            }),
        };
        let request = marker_request();
        let operation = adapter
            .client
            .manifest
            .operation("daemon.local", "daemon_management_action")
            .expect("operation");
        let invocation = adapter
            .build_request(&request, operation)
            .expect("invocation");
        adapter
            .reserve(
                invocation["request_body_digest"]
                    .as_str()
                    .expect("request digest"),
            )
            .expect("reservation");
        (adapter, key_pair, request, invocation)
    }

    fn marker_payload(
        adapter: &AcceptanceActionAdapter,
        request: &ActionRequest,
        invocation: &Value,
    ) -> Value {
        let operation = adapter
            .client
            .manifest
            .operation("daemon.local", "daemon_management_action")
            .expect("operation");
        let idempotency_key = invocation["idempotency_key"]
            .as_str()
            .expect("idempotency key");
        let effect_id = sha256_value(
            EFFECT_DOMAIN,
            &serde_json::json!({"idempotency_key": idempotency_key}),
        )
        .expect("effect digest");
        let result = serde_json::json!({
            "tenant_id": request.tenant_id.to_string(),
            "run_id": request.run_id.to_string(),
            "action_id": request.action_id.to_string(),
            "action_name": request.action.name,
            "effect_id": effect_id,
        });
        let state_digest = sha256_value(STATE_DOMAIN, &result).expect("state digest");
        let output = serde_json::json!({
            "operation_id": operation.operation_id,
            "proof_type": operation.output_profile,
            "tenant_id": request.tenant_id.to_string(),
            "action_id": request.action_id.to_string(),
            "effect_id": effect_id,
            "state_digest": state_digest,
            "result": result,
        });
        let output_raw = canonical_json(
            &output,
            JsonLimits {
                max_bytes: operation.bounds.max_output_bytes,
                max_depth: adapter.client.manifest.limits.max_depth,
                max_fields: adapter.client.manifest.limits.max_fields,
                max_array_items: operation.bounds.max_array_items,
                max_string_bytes: operation.bounds.max_string_bytes,
            },
        )
        .expect("output bytes");
        let output_digest = sha256_bytes(OUTPUT_DOMAIN, &output_raw);
        let now = now_ms().expect("clock");
        let status = operation
            .expected_status
            .initial
            .as_deref()
            .expect("status");
        let receipt_id = sha256_value(
            RECEIPT_ID_DOMAIN,
            &serde_json::json!({
                "provider_epoch": adapter.client.provider_epoch,
                "idempotency_key": idempotency_key,
                "request_body_digest": invocation["request_body_digest"],
                "status": status,
            }),
        )
        .expect("receipt digest");
        serde_json::json!({
            "schema_version": RECEIPT_PAYLOAD_SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "provider_id": PROVIDER_ID,
            "provider_revision": adapter.client.manifest.provider_revision,
            "provider_epoch": adapter.client.provider_epoch,
            "provider_receipt_id": receipt_id,
            "request_body_digest": invocation["request_body_digest"],
            "request_key_id": adapter.client.credential.key_id,
            "client_principal_id": adapter.client.credential.client_principal_id,
            "source_instance_id": adapter.client.credential.source_instance_id,
            "audience": adapter.client.credential.audience,
            "request_id": invocation["request_id"],
            "tenant_id": request.tenant_id.to_string(),
            "agent_id": request.agent_id.to_string(),
            "run_id": request.run_id.to_string(),
            "tick_id": invocation["tick_id"],
            "action_id": request.action_id.to_string(),
            "adapter_id": "daemon.local",
            "action_name": request.action.name,
            "physical_action_resource_coordinate": null,
            "operation_id": operation.operation_id,
            "profile_set_digest": adapter.client.manifest.digest,
            "operation_profile_digest": invocation["operation_profile_digest"],
            "idempotency_key": idempotency_key,
            "semantic_digest": invocation["semantic_digest"],
            "request_issued_at_unix_ms": invocation["issued_at_unix_ms"],
            "request_deadline_unix_ms": invocation["deadline_unix_ms"],
            "status": status,
            "effect_certainty": "known",
            "effect_id": effect_id,
            "state_digest": state_digest,
            "output_profile": operation.output_profile,
            "output_b64": URL_SAFE_NO_PAD.encode(&output_raw),
            "output_digest": output_digest,
            "satisfied_postconditions": [operation.postcondition],
            "postcondition_proof": {
                "operation_id": operation.operation_id,
                "predicate": operation.postcondition,
                "effect_id": effect_id,
                "state_digest": state_digest,
                "output_digest": output_digest,
            },
            "issued_at_unix_ms": now,
            "expires_at_unix_ms": now + adapter.client.manifest.limits.max_receipt_ttl_ms,
        })
    }

    fn sign_payload(
        adapter: &AcceptanceActionAdapter,
        key_pair: &Ed25519KeyPair,
        payload: &Value,
    ) -> Vec<u8> {
        let limits = &adapter.client.manifest.limits;
        let payload_raw = canonical_json(
            payload,
            JsonLimits {
                max_bytes: limits.max_response_bytes,
                max_depth: limits.max_depth,
                max_fields: limits.max_fields,
                max_array_items: limits.max_array_items,
                max_string_bytes: limits.max_response_bytes,
            },
        )
        .expect("payload bytes");
        let mut frame = RECEIPT_SIGNATURE_DOMAIN.to_vec();
        frame.extend_from_slice(&payload_raw);
        let envelope = serde_json::json!({
            "schema_version": RECEIPT_ENVELOPE_SCHEMA,
            "algorithm": "Ed25519",
            "signing_key_id": SIGNING_KEY_ID,
            "payload_encoding": "base64url",
            "payload_b64": URL_SAFE_NO_PAD.encode(payload_raw),
            "signature_b64": URL_SAFE_NO_PAD.encode(key_pair.sign(&frame).as_ref()),
        });
        canonical_json(
            &envelope,
            JsonLimits {
                max_bytes: limits.max_response_bytes,
                max_depth: limits.max_depth,
                max_fields: limits.max_fields,
                max_array_items: limits.max_array_items,
                max_string_bytes: limits.max_response_bytes,
            },
        )
        .expect("envelope bytes")
    }

    #[test]
    fn receipt_signature_binding_output_and_postcondition_tampering_fail_closed() {
        let (adapter, key_pair, request, invocation) = marker_context();
        let operation = adapter
            .client
            .manifest
            .operation("daemon.local", "daemon_management_action")
            .expect("operation");
        let payload = marker_payload(&adapter, &request, &invocation);
        let valid = sign_payload(&adapter, &key_pair, &payload);
        adapter
            .verify_receipt(&request, operation, &invocation, &valid)
            .expect("valid receipt");

        let mut bad_signature: Value = serde_json::from_slice(&valid).expect("envelope");
        bad_signature["signature_b64"] = Value::String(URL_SAFE_NO_PAD.encode([0; 64]));
        let bad_signature = canonical_json(
            &bad_signature,
            JsonLimits {
                max_bytes: 262_144,
                max_depth: 16,
                max_fields: 256,
                max_array_items: 64,
                max_string_bytes: 262_144,
            },
        )
        .expect("bad signature envelope");
        assert!(adapter
            .verify_receipt(&request, operation, &invocation, &bad_signature)
            .expect_err("signature tamper")
            .to_string()
            .contains("signature_invalid"));

        for (reason, mutate) in [
            (
                "coordinate",
                (|value: &mut Value| {
                    value["tenant_id"] = Value::String(TENANT_B.to_string());
                }) as fn(&mut Value),
            ),
            ("status", |value: &mut Value| {
                value["status"] = Value::String("read".to_string());
            }),
            ("postcondition", |value: &mut Value| {
                value["satisfied_postconditions"] = serde_json::json!(["wrong"]);
            }),
            ("output_digest", |value: &mut Value| {
                value["output_digest"] = Value::String(format!("sha256:{}", "0".repeat(64)));
            }),
        ] {
            let mut changed = payload.clone();
            mutate(&mut changed);
            let signed = sign_payload(&adapter, &key_pair, &changed);
            assert!(adapter
                .verify_receipt(&request, operation, &invocation, &signed)
                .expect_err(reason)
                .to_string()
                .contains("acceptance_provider"));
        }
    }

    #[test]
    fn receipt_payload_and_envelope_attack_matrix_fails_closed() {
        fn alter(value: &mut Value) {
            match value {
                Value::Null => {
                    *value = serde_json::json!({"tampered": true});
                }
                Value::Bool(current) => *current = !*current,
                Value::Number(number) => {
                    *value = serde_json::json!(number.as_i64().expect("signed integer") + 1);
                }
                Value::String(text) => text.push_str("-tampered"),
                Value::Array(items) => items.push(Value::String("tampered".to_string())),
                Value::Object(object) => {
                    object.insert("tampered".to_string(), Value::Bool(true));
                }
            }
        }

        let payload_fields = [
            "schema_version",
            "protocol_version",
            "provider_id",
            "provider_revision",
            "provider_epoch",
            "provider_receipt_id",
            "request_body_digest",
            "request_key_id",
            "client_principal_id",
            "source_instance_id",
            "audience",
            "request_id",
            "tenant_id",
            "agent_id",
            "run_id",
            "tick_id",
            "action_id",
            "adapter_id",
            "action_name",
            "physical_action_resource_coordinate",
            "operation_id",
            "profile_set_digest",
            "operation_profile_digest",
            "idempotency_key",
            "semantic_digest",
            "request_issued_at_unix_ms",
            "request_deadline_unix_ms",
            "status",
            "effect_certainty",
            "effect_id",
            "state_digest",
            "output_profile",
            "output_b64",
            "output_digest",
            "satisfied_postconditions",
            "postcondition_proof",
            "issued_at_unix_ms",
            "expires_at_unix_ms",
        ];
        for field in payload_fields {
            let (adapter, key_pair, request, invocation) = marker_context();
            let operation = adapter
                .client
                .manifest
                .operation("daemon.local", "daemon_management_action")
                .expect("operation");
            let mut payload = marker_payload(&adapter, &request, &invocation);
            if field == "issued_at_unix_ms" || field == "expires_at_unix_ms" {
                payload[field] = serde_json::json!(0);
            } else {
                alter(&mut payload[field]);
            }
            let signed = sign_payload(&adapter, &key_pair, &payload);
            assert!(
                adapter
                    .verify_receipt(&request, operation, &invocation, &signed)
                    .is_err(),
                "tampered receipt field was accepted: {field}"
            );
        }

        for field in [
            "operation_id",
            "predicate",
            "effect_id",
            "state_digest",
            "output_digest",
        ] {
            let (adapter, key_pair, request, invocation) = marker_context();
            let operation = adapter
                .client
                .manifest
                .operation("daemon.local", "daemon_management_action")
                .expect("operation");
            let mut payload = marker_payload(&adapter, &request, &invocation);
            alter(&mut payload["postcondition_proof"][field]);
            let signed = sign_payload(&adapter, &key_pair, &payload);
            assert!(
                adapter
                    .verify_receipt(&request, operation, &invocation, &signed)
                    .is_err(),
                "tampered postcondition field was accepted: {field}"
            );
        }

        for field in [
            "schema_version",
            "algorithm",
            "signing_key_id",
            "payload_encoding",
        ] {
            let (adapter, key_pair, request, invocation) = marker_context();
            let operation = adapter
                .client
                .manifest
                .operation("daemon.local", "daemon_management_action")
                .expect("operation");
            let payload = marker_payload(&adapter, &request, &invocation);
            let valid = sign_payload(&adapter, &key_pair, &payload);
            let mut envelope: Value = serde_json::from_slice(&valid).expect("envelope");
            alter(&mut envelope[field]);
            let changed = canonical_json(
                &envelope,
                JsonLimits {
                    max_bytes: 262_144,
                    max_depth: 16,
                    max_fields: 256,
                    max_array_items: 64,
                    max_string_bytes: 262_144,
                },
            )
            .expect("changed envelope");
            assert!(
                adapter
                    .verify_receipt(&request, operation, &invocation, &changed)
                    .is_err(),
                "tampered envelope field was accepted: {field}"
            );
        }

        for (field, value) in [
            ("payload_b64", "AA="),
            ("payload_b64", "AA*"),
            ("signature_b64", "AA="),
            ("signature_b64", "AA*"),
            ("signature_b64", "AA"),
        ] {
            let (adapter, key_pair, request, invocation) = marker_context();
            let operation = adapter
                .client
                .manifest
                .operation("daemon.local", "daemon_management_action")
                .expect("operation");
            let payload = marker_payload(&adapter, &request, &invocation);
            let valid = sign_payload(&adapter, &key_pair, &payload);
            let mut envelope: Value = serde_json::from_slice(&valid).expect("envelope");
            envelope[field] = Value::String(value.to_string());
            let changed = serde_json::to_vec(&envelope).expect("changed envelope");
            assert!(
                adapter
                    .verify_receipt(&request, operation, &invocation, &changed)
                    .is_err(),
                "noncanonical base64 was accepted: {field}={value}"
            );
        }

        let (adapter, key_pair, request, invocation) = marker_context();
        let operation = adapter
            .client
            .manifest
            .operation("daemon.local", "daemon_management_action")
            .expect("operation");
        let payload = marker_payload(&adapter, &request, &invocation);
        let payload_raw = canonical_json(
            &payload,
            JsonLimits {
                max_bytes: 262_144,
                max_depth: 16,
                max_fields: 256,
                max_array_items: 64,
                max_string_bytes: 262_144,
            },
        )
        .expect("payload");
        let mut wrong_domain_frame = b"splendor.acceptance.evidence_signature.v3\0".to_vec();
        wrong_domain_frame.extend_from_slice(&payload_raw);
        let wrong_domain = serde_json::json!({
            "schema_version": RECEIPT_ENVELOPE_SCHEMA,
            "algorithm": "Ed25519",
            "signing_key_id": SIGNING_KEY_ID,
            "payload_encoding": "base64url",
            "payload_b64": URL_SAFE_NO_PAD.encode(&payload_raw),
            "signature_b64": URL_SAFE_NO_PAD.encode(key_pair.sign(&wrong_domain_frame).as_ref()),
        });
        let wrong_domain = serde_json::to_vec(&wrong_domain).expect("wrong-domain envelope");
        assert!(adapter
            .verify_receipt(&request, operation, &invocation, &wrong_domain)
            .is_err());

        let mut noncanonical_payload = vec![b' '];
        noncanonical_payload.extend_from_slice(&payload_raw);
        let mut receipt_frame = RECEIPT_SIGNATURE_DOMAIN.to_vec();
        receipt_frame.extend_from_slice(&noncanonical_payload);
        let noncanonical = serde_json::json!({
            "schema_version": RECEIPT_ENVELOPE_SCHEMA,
            "algorithm": "Ed25519",
            "signing_key_id": SIGNING_KEY_ID,
            "payload_encoding": "base64url",
            "payload_b64": URL_SAFE_NO_PAD.encode(&noncanonical_payload),
            "signature_b64": URL_SAFE_NO_PAD.encode(key_pair.sign(&receipt_frame).as_ref()),
        });
        let noncanonical = serde_json::to_vec(&noncanonical).expect("noncanonical envelope");
        assert!(adapter
            .verify_receipt(&request, operation, &invocation, &noncanonical)
            .is_err());
    }

    #[test]
    fn signed_wrong_family_output_and_same_request_equivocation_are_rejected() {
        let (adapter, key_pair, request, invocation) = marker_context();
        let operation = adapter
            .client
            .manifest
            .operation("daemon.local", "daemon_management_action")
            .expect("operation");
        let payload = marker_payload(&adapter, &request, &invocation);

        let mut wrong_family = payload.clone();
        let result = serde_json::json!({"fixture": "s9-idempotent-read", "record_count": 1});
        let state_digest = sha256_value(STATE_DOMAIN, &result).expect("state digest");
        let output = serde_json::json!({
            "operation_id": operation.operation_id,
            "proof_type": operation.output_profile,
            "tenant_id": request.tenant_id.to_string(),
            "action_id": request.action_id.to_string(),
            "effect_id": wrong_family["effect_id"],
            "state_digest": state_digest,
            "result": result,
        });
        let output_raw = canonical_json(
            &output,
            JsonLimits {
                max_bytes: operation.bounds.max_output_bytes,
                max_depth: 16,
                max_fields: 256,
                max_array_items: operation.bounds.max_array_items,
                max_string_bytes: operation.bounds.max_string_bytes,
            },
        )
        .expect("wrong-family output");
        let output_digest = sha256_bytes(OUTPUT_DOMAIN, &output_raw);
        wrong_family["state_digest"] = Value::String(state_digest.clone());
        wrong_family["output_b64"] = Value::String(URL_SAFE_NO_PAD.encode(output_raw));
        wrong_family["output_digest"] = Value::String(output_digest.clone());
        wrong_family["postcondition_proof"]["state_digest"] = Value::String(state_digest);
        wrong_family["postcondition_proof"]["output_digest"] = Value::String(output_digest);
        let signed = sign_payload(&adapter, &key_pair, &wrong_family);
        assert!(adapter
            .verify_receipt(&request, operation, &invocation, &signed)
            .expect_err("signed wrong family")
            .to_string()
            .contains("output_family_mismatch"));

        let valid = sign_payload(&adapter, &key_pair, &payload);
        adapter
            .verify_receipt(&request, operation, &invocation, &valid)
            .expect("first receipt");
        let mut equivocated = payload.clone();
        equivocated["issued_at_unix_ms"] =
            serde_json::json!(payload["issued_at_unix_ms"].as_i64().expect("issued") + 1);
        equivocated["expires_at_unix_ms"] =
            serde_json::json!(payload["expires_at_unix_ms"].as_i64().expect("expires") + 1);
        let equivocated = sign_payload(&adapter, &key_pair, &equivocated);
        assert!(adapter
            .verify_receipt(&request, operation, &invocation, &equivocated)
            .expect_err("equivocation")
            .to_string()
            .contains("receipt_equivocated"));
    }

    fn request_for_operation(operation: &OperationProfile) -> ActionRequest {
        let params = match operation.parameter_profile.as_str() {
            "empty" => serde_json::json!({}),
            "management_marker" => serde_json::json!({"source": "uc-e2e-s2", "ok": true}),
            "idempotent_read" => serde_json::json!({
                "idempotency_key": "read-once",
                "retry_attempt": 1,
                "retryable": true,
                "max_attempts": 2,
            }),
            "artifact_create" => serde_json::json!({
                "artifact_path": format!("artifact://{TENANT_A}/internal.md"),
            }),
            "artifact_publish" => serde_json::json!({
                "publish_ref": format!("artifact://{TENANT_A}/published.md"),
            }),
            "data_read" => serde_json::json!({"data_ref": "dataset:tenant-a.finance.v1"}),
            "physical" => serde_json::json!({"physical_action": true}),
            other => panic!("unexpected executable parameter profile: {other}"),
        };
        let coordinate = (operation.coordinate_rule == "physical_node").then(|| {
            PhysicalActionResourceCoordinate::physical_node(
                NodeId::parse("00000000-0000-4000-8000-000000000604").expect("node"),
            )
        });
        ActionRequest {
            action_id: ActionId::new(),
            tenant_id: TenantId::parse(TENANT_A).expect("tenant"),
            agent_id: AgentId::new(),
            run_id: RunId::new(),
            tick_id: None,
            action: Action {
                name: operation.action_name.clone(),
                params,
                side_effect_class: serde_json::from_value(operation.effect_class.clone())
                    .expect("effect class"),
                cost_estimate: None,
                required_permissions: operation.required_permissions.clone(),
                preconditions: vec![],
                postconditions: vec![operation.postcondition.clone()],
            },
            adapter: Some(operation.adapter_id.clone()),
            quota_usage: QuotaUsage::single_action(),
            satisfied_preconditions: vec![],
            requested_at: OffsetDateTime::now_utc(),
            physical_action_resource_coordinate: coordinate,
            approval_evidence: None,
            authority_obligation_evidence: None,
            authority_obligation_receipts: vec![],
        }
    }

    #[test]
    fn every_manifest_success_output_family_has_an_exact_rust_predicate() {
        let (adapter, _, marker, invocation) = marker_context();
        let marker_payload = marker_payload(&adapter, &marker, &invocation);
        let payload: ReceiptPayload =
            serde_json::from_value(marker_payload).expect("receipt payload");
        let manifest = OperationManifest::load_embedded().expect("manifest");
        let mut observed = BTreeSet::new();
        for operation_id in [
            "acceptance-fixture/s9.approval_required",
            "acceptance-fixture/s9.idempotent_read",
            "acceptance-fixture/s9.quota_once",
            "artifact-store/artifact.create_internal",
            "artifact-store/artifact.publish_external",
            "daemon.local/daemon_management_action",
            "device-sim/capture_image",
            "device-sim/inspect_zone",
            "device-sim/move_to_waypoint",
            "device-sim/read_battery",
            "device-sim/read_sensor_summary",
            "device-sim/return_to_base",
            "device-sim/upload_trace_summary",
            "fixture-data-store/data.read_fixture",
            "fixture-sql/sql.read_fixture",
        ] {
            let (adapter_id, action_name) = operation_id.split_once('/').expect("operation id");
            let operation = manifest
                .operation(adapter_id, action_name)
                .expect("operation");
            let request = request_for_operation(operation);
            let coordinate = serde_json::to_value(&request.physical_action_resource_coordinate)
                .expect("coordinate");
            let result = match operation.output_profile.as_str() {
                "marker" => serde_json::json!({
                    "tenant_id": request.tenant_id.to_string(),
                    "run_id": request.run_id.to_string(),
                    "action_id": request.action_id.to_string(),
                    "action_name": request.action.name,
                    "effect_id": payload.effect_id,
                }),
                "fixture_read" => {
                    serde_json::json!({"fixture": "s9-idempotent-read", "record_count": 1})
                }
                "sql_read" => serde_json::json!({"row_count": 1, "rows": [{"fixture": 1}]}),
                "data_read" => serde_json::json!({
                    "data_ref": request.action.params["data_ref"],
                    "tenant_id": request.tenant_id.to_string(),
                    "raw_payload_included": false,
                    "record_count": 3,
                }),
                "artifact_create" => serde_json::json!({
                    "artifact_ref": request.action.params["artifact_path"],
                    "tenant_id": request.tenant_id.to_string(),
                    "created": true,
                    "published": false,
                    "external_store": null,
                }),
                "artifact_publish" => serde_json::json!({
                    "artifact_ref": request.action.params["publish_ref"],
                    "tenant_id": request.tenant_id.to_string(),
                    "created": true,
                    "published": true,
                    "external_store": "acceptance-action-provider-v3",
                }),
                "physical_battery" => serde_json::json!({
                    "coordinate": coordinate,
                    "battery_milli_percent": 820,
                }),
                "physical_sensor" => serde_json::json!({
                    "coordinate": coordinate,
                    "battery_milli_percent": 820,
                    "sensor_status": "nominal",
                }),
                "physical_inspect" => serde_json::json!({
                    "coordinate": coordinate,
                    "inspected_zone": "zone:warehouse-a3",
                }),
                "physical_waypoint" => serde_json::json!({
                    "coordinate": coordinate,
                    "waypoint": "waypoint:warehouse-a3",
                }),
                "physical_image" => serde_json::json!({
                    "coordinate": coordinate,
                    "images_captured": 1,
                }),
                "physical_return" => serde_json::json!({
                    "coordinate": coordinate,
                    "at_base": true,
                }),
                "physical_trace_upload" => serde_json::json!({
                    "coordinate": coordinate,
                    "trace_summaries_uploaded": 1,
                }),
                other => panic!("missing result predicate: {other}"),
            };
            assert!(
                validate_result_family(&request, operation, &payload, &result),
                "{operation_id}"
            );
            observed.insert(operation.output_profile.as_str());
        }
        assert_eq!(
            observed,
            BTreeSet::from([
                "artifact_create",
                "artifact_publish",
                "data_read",
                "fixture_read",
                "marker",
                "physical_battery",
                "physical_image",
                "physical_inspect",
                "physical_return",
                "physical_sensor",
                "physical_trace_upload",
                "physical_waypoint",
                "sql_read",
            ])
        );
    }

    #[test]
    fn host_ledger_rejects_new_work_at_capacity_but_keeps_existing_identity() {
        let (adapter, _, _, invocation) = marker_context();
        let existing = invocation["request_body_digest"]
            .as_str()
            .expect("request digest");
        {
            let mut ledger = adapter.client.ledger.lock().expect("ledger");
            for index in 0..255 {
                ledger.invocations.insert(format!("capacity-{index}"), None);
            }
            assert_eq!(ledger.invocations.len(), 256);
        }
        adapter
            .reserve(existing)
            .expect("existing identity remains available");
        assert!(adapter
            .reserve("sha256:new-work")
            .expect_err("new work at capacity")
            .to_string()
            .contains("ledger_capacity_exhausted"));
    }
}
