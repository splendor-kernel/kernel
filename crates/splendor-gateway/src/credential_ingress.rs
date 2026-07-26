//! Bounded pre-persistence denial for raw credential-bearing actions.
//!
//! This guard is deliberately denial-only. It does not recognize a generic
//! JSON secret reference as authority and cannot resolve, deliver, or authorize
//! credential material.

use crate::{ActionOutcome, ActionRequest, ActionStatus, AdapterResult};
use splendor_types::{
    Action, ApprovalEvidence, AuthorityObligationReceipt, Percept, RevocationStatus,
    SideEffectClass, VerificationResult,
};
use std::{fmt, net::Ipv6Addr, str};
use time::OffsetDateTime;

/// Stable, non-reflecting reason returned for every raw credential denial.
pub const RAW_CREDENTIAL_INPUT_DENIED: &str = "raw_credential_input_denied";
/// Stable, non-reflecting reason used when an entered adapter returns unsafe output.
pub const RAW_CREDENTIAL_OUTPUT_SUPPRESSED: &str = "raw_credential_output_suppressed";

/// Maximum nesting depth accepted in `Action.params` (root depth is zero).
pub const CREDENTIAL_INGRESS_MAX_DEPTH: usize = 16;
/// Maximum number of action envelope, value, and string nodes inspected.
pub const CREDENTIAL_INGRESS_MAX_NODES: usize = 2_048;
/// Maximum UTF-8 byte length accepted for one inspected string or object key.
pub const CREDENTIAL_INGRESS_MAX_STRING_BYTES: usize = 16 * 1024;
/// Maximum cumulative UTF-8 bytes inspected across strings and object keys.
pub const CREDENTIAL_INGRESS_MAX_TOTAL_BYTES: usize = 64 * 1024;

const CREDENTIAL_INGRESS_MAX_URL_NESTING: usize = 4;
const CREDENTIAL_INGRESS_MAX_AUTHORIZATION_TOKEN_BYTES: usize = 4 * 1024;
const CREDENTIAL_INGRESS_MAX_REFERENCE_PAYLOAD_BYTES: usize = 2_048;

/// Opaque denial from the raw credential ingress guard.
///
/// The type intentionally has no serialization contract and carries no source,
/// path, candidate bytes, digest, or parser detail.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RawCredentialInputDenied;

impl fmt::Debug for RawCredentialInputDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(RAW_CREDENTIAL_INPUT_DENIED)
    }
}

impl fmt::Display for RawCredentialInputDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(RAW_CREDENTIAL_INPUT_DENIED)
    }
}

impl std::error::Error for RawCredentialInputDenied {}

/// Screens an action before any untrusted action payload is persisted.
pub fn guard_action(action: &Action) -> Result<(), RawCredentialInputDenied> {
    guard_action_routing_and_receipts(action, None, &[], &[])
}

/// Screens an action plus untrusted adapter/precondition routing metadata.
pub fn guard_action_routing(
    action: &Action,
    adapter: Option<&str>,
    satisfied_preconditions: &[String],
) -> Result<(), RawCredentialInputDenied> {
    guard_action_routing_and_receipts(action, adapter, satisfied_preconditions, &[])
}

/// Screens action routing plus raw authority-receipt metadata without treating
/// a receipt as authority or duplicating Authority validation semantics.
pub fn guard_action_routing_and_receipts(
    action: &Action,
    adapter: Option<&str>,
    satisfied_preconditions: &[String],
    authority_obligation_receipts: &[AuthorityObligationReceipt],
) -> Result<(), RawCredentialInputDenied> {
    let mut scanner = CredentialIngressScanner::default();
    scan_action_routing_and_receipts(
        &mut scanner,
        action,
        adapter,
        satisfied_preconditions,
        authority_obligation_receipts,
    )
}

fn scan_action_routing_and_receipts(
    scanner: &mut CredentialIngressScanner,
    action: &Action,
    adapter: Option<&str>,
    satisfied_preconditions: &[String],
    authority_obligation_receipts: &[AuthorityObligationReceipt],
) -> Result<(), RawCredentialInputDenied> {
    scanner.scan_action(action)?;
    if let Some(adapter) = adapter {
        scanner.scan_string(adapter)?;
    }
    for precondition in satisfied_preconditions {
        scanner.scan_string(precondition)?;
    }
    scanner.scan_authority_obligation_receipts(authority_obligation_receipts)?;
    Ok(())
}

/// Screens an owner-selected set of untrusted, credential-capable strings.
///
/// Callers select fields from their own closed envelope; all detection grammar
/// and resource limits remain owned here by the Gateway. This check is
/// denial-only and never validates or grants authority.
pub fn guard_credential_capable_strings<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), RawCredentialInputDenied> {
    let mut scanner = CredentialIngressScanner::default();
    for value in values {
        scanner.scan_string(value)?;
    }
    Ok(())
}

/// Recursively screens every string and object key in one caller-owned JSON
/// envelope using the same bounds and grammar as action ingress.
///
/// The caller remains the schema and mutation owner. This function only returns
/// clear or the fixed denial and cannot validate or authorize the envelope.
pub fn guard_credential_capable_value(
    value: &serde_json::Value,
) -> Result<(), RawCredentialInputDenied> {
    CredentialIngressScanner::default().scan_value(value, 0)
}

/// Screens one percept before it can be retained, traced, or supplied to policy.
///
/// The complete percept shares one scanner budget. The caller still owns
/// percept admission and schema semantics; this function is denial-only.
pub fn guard_persisted_percept(percept: &Percept) -> Result<(), RawCredentialInputDenied> {
    let mut scanner = CredentialIngressScanner::default();
    scanner.scan_string(&percept.schema)?;
    scanner.scan_string(&percept.provenance.source)?;
    if let Some(detail) = percept.provenance.detail.as_deref() {
        scanner.scan_string(detail)?;
    }
    scanner.scan_persisted_json(&percept.payload)
}

/// Screens policy-selected state bytes before state/outcome persistence.
///
/// Declared JSON and text are parsed or decoded strictly. Opaque binary remains
/// compatible, but this guard makes no absence claim for encrypted, compressed,
/// or otherwise non-textual bytes.
pub fn guard_persisted_state(
    bytes: &[u8],
    content_type: Option<&str>,
    label: Option<&str>,
) -> Result<(), RawCredentialInputDenied> {
    let mut scanner = CredentialIngressScanner::default();
    if let Some(content_type) = content_type {
        scanner.scan_string(content_type)?;
    }
    if let Some(label) = label {
        scanner.scan_string(label)?;
    }
    scanner.scan_persisted_bytes(bytes, content_type)
}

/// Screens adapter-owned output and postcondition strings with one shared budget.
pub(crate) fn guard_adapter_result(result: &AdapterResult) -> Result<(), RawCredentialInputDenied> {
    let mut scanner = CredentialIngressScanner::default();
    scanner.scan_persisted_json(&result.output)?;
    for postcondition in &result.satisfied_postconditions {
        scanner.scan_string(postcondition)?;
    }
    Ok(())
}

/// Screens all credential-capable strings in an untrusted action request.
///
/// Typed caller authentication and authority decisions are intentionally not
/// scanned as workload input. Raw approval-evidence and receipt strings are
/// content-screened before their owning validators run; screening does not make
/// them valid or authorizing.
pub fn guard_action_request(request: &ActionRequest) -> Result<(), RawCredentialInputDenied> {
    let mut scanner = CredentialIngressScanner::default();
    scan_action_routing_and_receipts(
        &mut scanner,
        &request.action,
        request.adapter.as_deref(),
        &request.satisfied_preconditions,
        &request.authority_obligation_receipts,
    )?;
    if let Some(evidence) = request.approval_evidence.as_ref() {
        scanner.scan_approval_evidence(evidence)?;
    }
    Ok(())
}

/// Returns the constant action projection used for all credential denials.
///
/// Action identity remains on the enclosing trace identity/outcome. No
/// requester-controlled action field is retained by this projection.
pub fn raw_credential_denied_action() -> Action {
    Action {
        name: "credential_input_suppressed".to_string(),
        params: serde_json::json!({"suppressed": RAW_CREDENTIAL_INPUT_DENIED}),
        side_effect_class: SideEffectClass::External,
        cost_estimate: None,
        required_permissions: Vec::new(),
        preconditions: Vec::new(),
        postconditions: Vec::new(),
    }
}

/// Returns the fixed denied outcome for a raw credential-bearing request.
pub fn raw_credential_denied_outcome(action_id: crate::ActionId) -> ActionOutcome {
    ActionOutcome {
        action_id,
        status: ActionStatus::Denied,
        verification: VerificationResult::deny(RAW_CREDENTIAL_INPUT_DENIED),
        post_verification: None,
        output: None,
        error: Some(RAW_CREDENTIAL_INPUT_DENIED.to_string()),
        approval_challenge: None,
        completed_at: OffsetDateTime::now_utc(),
    }
}

/// Returns the fixed failed outcome used after an adapter returned unsafe output.
///
/// `Failed` and the retained pre-verification result preserve that the adapter
/// was entered and an effect may already have occurred. The raw result is never
/// retained by this projection.
pub(crate) fn raw_credential_output_suppressed_outcome(
    action_id: crate::ActionId,
    verification: VerificationResult,
) -> ActionOutcome {
    ActionOutcome {
        action_id,
        status: ActionStatus::Failed,
        verification,
        post_verification: Some(VerificationResult::deny(RAW_CREDENTIAL_OUTPUT_SUPPRESSED)),
        output: None,
        error: Some(RAW_CREDENTIAL_OUTPUT_SUPPRESSED.to_string()),
        approval_challenge: None,
        completed_at: OffsetDateTime::now_utc(),
    }
}

#[derive(Default)]
struct CredentialIngressScanner {
    nodes: usize,
    total_bytes: usize,
}

impl CredentialIngressScanner {
    fn scan_action(&mut self, action: &Action) -> Result<(), RawCredentialInputDenied> {
        self.charge_node()?;
        self.scan_string(&action.name)?;
        self.scan_top_level_numeric_bytes(&action.params)?;
        self.scan_value(&action.params, 0)?;

        if let SideEffectClass::Custom(value) = &action.side_effect_class {
            self.scan_string(value)?;
        }
        if let Some(cost) = &action.cost_estimate {
            self.charge_node()?;
            self.scan_string(&cost.units)?;
        }
        for value in &action.required_permissions {
            self.scan_string(value)?;
        }
        for value in &action.preconditions {
            self.scan_string(value)?;
        }
        for value in &action.postconditions {
            self.scan_string(value)?;
        }
        Ok(())
    }

    fn scan_top_level_numeric_bytes(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<(), RawCredentialInputDenied> {
        let Some(bytes) = params.as_object().and_then(|params| params.get("bytes")) else {
            return Ok(());
        };
        let bytes = bytes.as_array().ok_or(RawCredentialInputDenied)?;
        if bytes.len() > CREDENTIAL_INGRESS_MAX_NODES {
            return Err(RawCredentialInputDenied);
        }
        let mut reconstructed = Vec::with_capacity(bytes.len());
        for value in bytes {
            let value = value.as_u64().ok_or(RawCredentialInputDenied)?;
            let byte = u8::try_from(value).map_err(|_| RawCredentialInputDenied)?;
            reconstructed.push(byte);
        }
        let textual = unambiguous_utf8_body(&reconstructed).ok_or(RawCredentialInputDenied)?;
        self.scan_string(textual)
    }

    fn scan_authority_obligation_receipts(
        &mut self,
        receipts: &[AuthorityObligationReceipt],
    ) -> Result<(), RawCredentialInputDenied> {
        for receipt in receipts {
            self.charge_node()?;
            self.scan_string(&receipt.schema_version)?;
            self.scan_string(&receipt.audience)?;
            self.scan_string(&receipt.canonical_request_digest)?;
            self.scan_string(&receipt.evidence_digest)?;
            if let Some(evidence_ref) = receipt.evidence_ref.as_deref() {
                self.scan_string(evidence_ref)?;
            }
            if let RevocationStatus::Revoked { reason } = &receipt.revocation {
                self.scan_string(reason)?;
            }
            self.scan_string(&receipt.revocation_ref)?;
            self.scan_string(&receipt.validation.algorithm)?;
            self.scan_string(&receipt.validation.key_id)?;
            self.scan_string(&receipt.validation.digest)?;
            self.scan_string(&receipt.validation.signature)?;
        }
        Ok(())
    }

    fn scan_approval_evidence(
        &mut self,
        evidence: &ApprovalEvidence,
    ) -> Result<(), RawCredentialInputDenied> {
        self.charge_node()?;
        self.scan_string(&evidence.schema_version)?;
        for value in [
            evidence.action_name.as_deref(),
            evidence.adapter.as_deref(),
            evidence.reason.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            self.scan_string(value)?;
        }
        Ok(())
    }

    fn scan_value(
        &mut self,
        value: &serde_json::Value,
        depth: usize,
    ) -> Result<(), RawCredentialInputDenied> {
        if depth > CREDENTIAL_INGRESS_MAX_DEPTH {
            return Err(RawCredentialInputDenied);
        }
        self.charge_node()?;
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    self.scan_value(value, depth.saturating_add(1))?;
                }
            }
            serde_json::Value::Object(values) => {
                for (key, value) in values {
                    self.scan_key(key)?;
                    self.scan_value(value, depth.saturating_add(1))?;
                }
                if structured_credential_object(values)? {
                    return Err(RawCredentialInputDenied);
                }
            }
            serde_json::Value::String(value) => self.scan_string_without_node(value)?,
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            }
        }
        Ok(())
    }

    fn scan_persisted_json(
        &mut self,
        value: &serde_json::Value,
    ) -> Result<(), RawCredentialInputDenied> {
        self.scan_value(value, 0)?;
        self.scan_persisted_byte_envelopes(value, true)
    }

    fn scan_persisted_byte_envelopes(
        &mut self,
        value: &serde_json::Value,
        root: bool,
    ) -> Result<(), RawCredentialInputDenied> {
        match value {
            serde_json::Value::Array(values) => {
                if root {
                    self.scan_numeric_byte_array(values, None)?;
                }
                for value in values {
                    self.scan_persisted_byte_envelopes(value, false)?;
                }
            }
            serde_json::Value::Object(values) => {
                for (key, value) in values {
                    if persisted_byte_coordinate(key) {
                        match value {
                            serde_json::Value::Array(bytes) => {
                                let content_type = persisted_content_type(values)?;
                                self.scan_numeric_byte_array(bytes, content_type)?;
                            }
                            serde_json::Value::String(text) => {
                                let content_type = persisted_content_type(values)?;
                                self.scan_persisted_bytes(text.as_bytes(), content_type)?;
                            }
                            _ => {}
                        }
                    }
                    self.scan_persisted_byte_envelopes(value, false)?;
                }
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
        Ok(())
    }

    fn scan_numeric_byte_array(
        &mut self,
        values: &[serde_json::Value],
        content_type: Option<&str>,
    ) -> Result<(), RawCredentialInputDenied> {
        let mut reconstructed = Vec::with_capacity(values.len());
        for value in values {
            let Some(value) = value.as_u64() else {
                return Ok(());
            };
            let Ok(byte) = u8::try_from(value) else {
                return Ok(());
            };
            reconstructed.push(byte);
        }
        self.scan_persisted_bytes(&reconstructed, content_type)
    }

    fn scan_persisted_bytes(
        &mut self,
        bytes: &[u8],
        content_type: Option<&str>,
    ) -> Result<(), RawCredentialInputDenied> {
        match persisted_content_kind(content_type)? {
            PersistedContentKind::Json => {
                if bytes.len() > CREDENTIAL_INGRESS_MAX_TOTAL_BYTES {
                    return Err(RawCredentialInputDenied);
                }
                let text = unambiguous_utf8_body(bytes).ok_or(RawCredentialInputDenied)?;
                let value = serde_json::from_str(text).map_err(|_| RawCredentialInputDenied)?;
                self.scan_persisted_json(&value)
            }
            PersistedContentKind::Text => {
                let text = unambiguous_utf8_body(bytes).ok_or(RawCredentialInputDenied)?;
                self.scan_string(text)
            }
            PersistedContentKind::OpaqueOrUnspecified => {
                let Some(text) = unambiguous_utf8_body(bytes) else {
                    return if ambiguous_textual_bytes(bytes) {
                        Err(RawCredentialInputDenied)
                    } else {
                        Ok(())
                    };
                };
                self.scan_string(text)?;
                let trimmed = text.trim();
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    let value =
                        serde_json::from_str(trimmed).map_err(|_| RawCredentialInputDenied)?;
                    self.scan_persisted_json(&value)?;
                }
                Ok(())
            }
        }
    }

    fn scan_key(&mut self, key: &str) -> Result<(), RawCredentialInputDenied> {
        self.charge_string_bytes(key)?;
        ensure_unambiguous_text(key)?;
        if normalized_credential_key(key)? || credential_content(key)? {
            return Err(RawCredentialInputDenied);
        }
        Ok(())
    }

    fn scan_string(&mut self, value: &str) -> Result<(), RawCredentialInputDenied> {
        self.charge_node()?;
        self.scan_string_without_node(value)
    }

    fn scan_string_without_node(&mut self, value: &str) -> Result<(), RawCredentialInputDenied> {
        self.charge_string_bytes(value)?;
        ensure_unambiguous_text(value)?;
        if credential_content(value)? {
            return Err(RawCredentialInputDenied);
        }
        Ok(())
    }

    fn charge_node(&mut self) -> Result<(), RawCredentialInputDenied> {
        self.nodes = self.nodes.checked_add(1).ok_or(RawCredentialInputDenied)?;
        if self.nodes > CREDENTIAL_INGRESS_MAX_NODES {
            return Err(RawCredentialInputDenied);
        }
        Ok(())
    }

    fn charge_string_bytes(&mut self, value: &str) -> Result<(), RawCredentialInputDenied> {
        if value.len() > CREDENTIAL_INGRESS_MAX_STRING_BYTES {
            return Err(RawCredentialInputDenied);
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(value.len())
            .ok_or(RawCredentialInputDenied)?;
        if self.total_bytes > CREDENTIAL_INGRESS_MAX_TOTAL_BYTES {
            return Err(RawCredentialInputDenied);
        }
        Ok(())
    }
}

fn structured_credential_coordinate_key(key: &str) -> bool {
    matches!(
        compact_ascii(key).as_str(),
        "name"
            | "key"
            | "header"
            | "headername"
            | "env"
            | "envname"
            | "environment"
            | "environmentname"
            | "variablename"
    )
}

fn structured_credential_material_key(key: &str) -> bool {
    matches!(
        compact_ascii(key).as_str(),
        "value"
            | "values"
            | "data"
            | "contents"
            | "body"
            | "valuefrom"
            | "secretvalue"
            | "material"
    )
}

fn structured_credential_object(
    values: &serde_json::Map<String, serde_json::Value>,
) -> Result<bool, RawCredentialInputDenied> {
    if !values
        .keys()
        .any(|key| structured_credential_material_key(key))
    {
        return Ok(false);
    }
    for (key, value) in values {
        if structured_credential_coordinate_key(key)
            && value
                .as_str()
                .map(structured_credential_alias)
                .transpose()?
                .unwrap_or_default()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn structured_credential_alias(value: &str) -> Result<bool, RawCredentialInputDenied> {
    let decoded;
    let value = if contains_percent_escape(value) {
        decoded = percent_decode(value)?;
        if contains_percent_escape(&decoded) {
            return Err(RawCredentialInputDenied);
        }
        decoded.as_str()
    } else {
        value
    };
    if !value.is_ascii() {
        return Ok(false);
    }
    let normalized = compact_ascii(value);
    Ok(normalized != "token" && normalized_credential_key_name(&normalized))
}

fn normalized_credential_coordinate(value: &str) -> Result<String, RawCredentialInputDenied> {
    let decoded;
    let value = if value.as_bytes().contains(&b'%') {
        decoded = percent_decode(value)?;
        decoded.as_str()
    } else {
        value
    };
    if !value.is_ascii() || value.as_bytes().contains(&b'%') {
        return Err(RawCredentialInputDenied);
    }
    Ok(compact_ascii(value))
}

fn normalized_credential_key(key: &str) -> Result<bool, RawCredentialInputDenied> {
    let normalized = normalized_credential_coordinate(key)?;
    Ok(normalized_credential_key_name(&normalized))
}

fn normalized_credential_key_name(normalized: &str) -> bool {
    matches!(
        normalized,
        "authorization"
            | "proxyauthorization"
            | "auth"
            | "authentication"
            | "authkey"
            | "authorizationkey"
            | "xapikey"
            | "xauthtoken"
            | "privatetoken"
            | "apitoken"
            | "authz"
            | "password"
            | "passwd"
            | "pwd"
            | "passphrase"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "authtoken"
            | "bearertoken"
            | "personalaccesstoken"
            | "apikey"
            | "clientsecret"
            | "clientpassword"
            | "privatekey"
            | "cookie"
            | "setcookie"
            | "secret"
            | "secretref"
            | "secretrefid"
            | "secretkeyref"
            | "credential"
            | "credentials"
            | "connectionstring"
            | "dsn"
            | "databaseurl"
            | "dbpassword"
            | "redisurl"
            | "awsaccesskeyid"
            | "awssecretaccesskey"
            | "awssessiontoken"
            | "xamzcredential"
            | "xamzsecuritytoken"
            | "xamzsignature"
            | "secretaccesskey"
            | "azureclientsecret"
            | "azureopenaiapikey"
            | "googleapplicationcredentials"
            | "googleapikey"
            | "geminiapikey"
            | "githubtoken"
            | "gitlabtoken"
            | "openaiapikey"
            | "anthropicapikey"
            | "slackbottoken"
            | "slackapptoken"
            | "cijobtoken"
            | "dockerauthconfig"
            | "pgpassword"
            | "vaulttoken"
            | "consulhttptoken"
            | "postgrespassword"
            | "postgresqlpassword"
            | "pgpassfile"
            | "mysqlpwd"
            | "mysqlpassword"
            | "mysqlrootpassword"
            | "mariadbpassword"
            | "mariadbrootpassword"
            | "mongopassword"
            | "mongoinitdbrootpassword"
            | "redispassword"
            | "rabbitmqdefaultpass"
            | "mssqlsapassword"
            | "oraclepassword"
            | "elasticpassword"
            | "opensearchinitialadminpassword"
            | "mongodburi"
            | "rabbitmqurl"
            | "hftoken"
            | "huggingfacehubtoken"
            | "cargoregistrytoken"
            | "stripesecretkey"
            | "sendgridapikey"
            | "sshprivatekey"
            | "npmtoken"
            | "pypitoken"
    )
}

fn credential_content(value: &str) -> Result<bool, RawCredentialInputDenied> {
    credential_content_bounded(value, 0)
}

fn credential_content_bounded(
    value: &str,
    url_nesting: usize,
) -> Result<bool, RawCredentialInputDenied> {
    if url_nesting > CREDENTIAL_INGRESS_MAX_URL_NESTING {
        return Err(RawCredentialInputDenied);
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    if credential_percent_encoded_tokens(trimmed, url_nesting)? {
        return Ok(true);
    }
    if credential_form(trimmed, url_nesting)? {
        return Ok(true);
    }
    credential_content_plain(trimmed, url_nesting)
}

fn credential_content_decoded(
    value: &str,
    url_nesting: usize,
) -> Result<bool, RawCredentialInputDenied> {
    if url_nesting > CREDENTIAL_INGRESS_MAX_URL_NESTING {
        return Err(RawCredentialInputDenied);
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    ensure_unambiguous_text(trimmed)?;
    if contains_percent_escape(trimmed) {
        return Err(RawCredentialInputDenied);
    }
    if credential_form_decoded(trimmed, url_nesting)? {
        return Ok(true);
    }
    credential_content_plain(trimmed, url_nesting)
}

fn credential_content_plain(
    value: &str,
    url_nesting: usize,
) -> Result<bool, RawCredentialInputDenied> {
    let lowercase = value.to_ascii_lowercase();
    if authorization_form(value)
        || private_key_block(&lowercase)
        || provider_key_prefix(value)
        || secret_reference_form(&lowercase)
        || credential_assignment(value)?
        || credential_url(value, url_nesting)?
        || credential_dsn_without_scheme(value)
    {
        return Ok(true);
    }
    Ok(false)
}

fn credential_percent_encoded_tokens(
    value: &str,
    url_nesting: usize,
) -> Result<bool, RawCredentialInputDenied> {
    if !contains_percent_escape(value) {
        return Ok(false);
    }
    let mut cursor = 0;
    let mut search = 0;
    while let Some(relative_separator) = value[search..].find("://") {
        let separator = search + relative_separator;
        let mut start = separator;
        while start > 0 && url_scheme_byte(value.as_bytes()[start - 1]) {
            start -= 1;
        }
        if !valid_url_scheme(&value[start..separator]) {
            return Err(RawCredentialInputDenied);
        }
        if start >= cursor && credential_percent_encoded_span(&value[cursor..start], url_nesting)? {
            return Ok(true);
        }
        let end = absolute_url_candidate_end(value, separator + 3);
        cursor = end;
        search = end.max(separator + 3);
        if search >= value.len() {
            break;
        }
    }
    credential_percent_encoded_span(&value[cursor..], url_nesting)
}

fn credential_percent_encoded_span(
    value: &str,
    url_nesting: usize,
) -> Result<bool, RawCredentialInputDenied> {
    for token in value.split(char::is_whitespace) {
        if !contains_percent_escape(token) {
            continue;
        }
        let decoded = percent_decode(token)?;
        if contains_percent_escape(&decoded) {
            return Err(RawCredentialInputDenied);
        }
        ensure_unambiguous_text(&decoded)?;
        if credential_content_decoded(&decoded, url_nesting.saturating_add(1))? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn credential_form(value: &str, url_nesting: usize) -> Result<bool, RawCredentialInputDenied> {
    if !value.contains('=') {
        return Ok(false);
    }
    let mut structured_alias = false;
    let mut structured_material = false;
    for field in value.split(['&', ';']) {
        let Some((raw_key, raw_value)) = field.split_once('=') else {
            continue;
        };
        if raw_key.trim().is_empty() {
            continue;
        }
        let url_prefixed_key = url_coordinate_candidate(raw_key.trim());
        let key = percent_decode_form(raw_key.trim())?;
        ensure_unambiguous_text(&key)?;
        if contains_percent_escape(&key) {
            return Err(RawCredentialInputDenied);
        }
        if !url_prefixed_key && normalized_credential_key(&key)? {
            return Ok(true);
        }

        let decoded_value = percent_decode_form(raw_value.trim())?;
        ensure_unambiguous_text(&decoded_value)?;
        if contains_percent_escape(&decoded_value) {
            return Err(RawCredentialInputDenied);
        }
        update_structured_form_coordinates(
            &key,
            &decoded_value,
            &mut structured_alias,
            &mut structured_material,
        )?;
        if credential_content_decoded(&decoded_value, url_nesting.saturating_add(1))? {
            return Ok(true);
        }
    }
    Ok(structured_alias && structured_material)
}

fn credential_form_decoded(
    value: &str,
    url_nesting: usize,
) -> Result<bool, RawCredentialInputDenied> {
    if !value.contains('=') {
        return Ok(false);
    }
    let mut structured_alias = false;
    let mut structured_material = false;
    for field in value.split(['&', ';']) {
        let Some((key, decoded_value)) = field.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let decoded_value = decoded_value.trim();
        ensure_unambiguous_text(key)?;
        ensure_unambiguous_text(decoded_value)?;
        if !url_coordinate_candidate(key) && normalized_credential_key(key)? {
            return Ok(true);
        }
        update_structured_form_coordinates(
            key,
            decoded_value,
            &mut structured_alias,
            &mut structured_material,
        )?;
        if credential_content_decoded(decoded_value, url_nesting.saturating_add(1))? {
            return Ok(true);
        }
    }
    Ok(structured_alias && structured_material)
}

fn update_structured_form_coordinates(
    key: &str,
    value: &str,
    structured_alias: &mut bool,
    structured_material: &mut bool,
) -> Result<(), RawCredentialInputDenied> {
    *structured_material |= structured_credential_material_key(key);
    if structured_credential_coordinate_key(key) && structured_credential_alias(value)? {
        *structured_alias = true;
    }
    Ok(())
}

fn authorization_form(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    ["bearer", "basic"].iter().any(|scheme| {
        lowercase.match_indices(scheme).any(|(index, _)| {
            if index > 0 {
                let Some(before) = lowercase[..index].chars().next_back() else {
                    return false;
                };
                if !authorization_scheme_boundary(before) {
                    return false;
                }
            }
            let after_scheme = &value[index + scheme.len()..];
            if !after_scheme.chars().next().is_some_and(char::is_whitespace) {
                return false;
            }
            let line = after_scheme
                .split(['\r', '\n'])
                .next()
                .unwrap_or_default()
                .trim_start();
            contains_plausible_authorization_token(line, scheme)
        })
    })
}

fn contains_plausible_authorization_token(line: &str, scheme: &str) -> bool {
    for (index, character) in line.char_indices() {
        if index > CREDENTIAL_INGRESS_MAX_AUTHORIZATION_TOKEN_BYTES {
            return false;
        }
        if index > 0
            && authorization_candidate_boundary(&line[index..], character)
            && plausible_authorization_token(&line[..index], scheme)
        {
            return true;
        }
        if !character.is_ascii()
            || !authorization_token_byte(character as u8, scheme)
            || index == CREDENTIAL_INGRESS_MAX_AUTHORIZATION_TOKEN_BYTES
        {
            return false;
        }
    }
    plausible_authorization_token(line, scheme)
}

fn authorization_candidate_boundary(remainder: &str, character: char) -> bool {
    if !character.is_whitespace() {
        return authorization_token_boundary(character);
    }
    let trailing = remainder.trim_start();
    trailing.is_empty()
        || trailing
            .chars()
            .next()
            .is_some_and(|next| !next.is_whitespace() && authorization_token_boundary(next))
}

fn plausible_authorization_token(token: &str, scheme: &str) -> bool {
    if scheme == "basic" {
        plausible_basic_token(token)
    } else {
        plausible_bearer_token(token)
    }
}

fn authorization_scheme_boundary(character: char) -> bool {
    credential_token_boundary(character)
}

fn authorization_token_byte(byte: u8, scheme: &str) -> bool {
    byte.is_ascii_alphanumeric()
        || if scheme == "basic" {
            matches!(byte, b'+' | b'/' | b'=')
        } else {
            matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        }
}

fn authorization_token_boundary(character: char) -> bool {
    credential_token_boundary(character)
}

fn credential_token_boundary(character: char) -> bool {
    !character.is_alphanumeric()
}

fn plausible_basic_token(token: &str) -> bool {
    const MINIMUM_BASIC_TOKEN_BYTES: usize = 4;

    if !(MINIMUM_BASIC_TOKEN_BYTES..=CREDENTIAL_INGRESS_MAX_AUTHORIZATION_TOKEN_BYTES)
        .contains(&token.len())
        || !token.len().is_multiple_of(4)
    {
        return false;
    }
    basic_base64_decodes_with_colon(token.as_bytes())
}

fn plausible_bearer_token(token: &str) -> bool {
    const MINIMUM_BEARER_TOKEN_BYTES: usize = 1;

    if !(MINIMUM_BEARER_TOKEN_BYTES..=CREDENTIAL_INGRESS_MAX_AUTHORIZATION_TOKEN_BYTES)
        .contains(&token.len())
    {
        return false;
    }
    let padding = token.bytes().rev().take_while(|byte| *byte == b'=').count();
    padding <= 2
        && padding < token.len()
        && token[..token.len() - padding].bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

fn basic_base64_decodes_with_colon(token: &[u8]) -> bool {
    let mut contains_colon = false;
    let chunk_count = token.len() / 4;
    for (index, chunk) in token.chunks_exact(4).enumerate() {
        let last = index + 1 == chunk_count;
        let Some(first) = base64_value(chunk[0]) else {
            return false;
        };
        let Some(second) = base64_value(chunk[1]) else {
            return false;
        };
        contains_colon |= (first << 2 | second >> 4) == b':';

        if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' || second & 0x0f != 0 {
                return false;
            }
            continue;
        }
        let Some(third) = base64_value(chunk[2]) else {
            return false;
        };
        contains_colon |= ((second & 0x0f) << 4 | third >> 2) == b':';

        if chunk[3] == b'=' {
            if !last || third & 0x03 != 0 {
                return false;
            }
            continue;
        }
        let Some(fourth) = base64_value(chunk[3]) else {
            return false;
        };
        contains_colon |= ((third & 0x03) << 6 | fourth) == b':';
    }
    contains_colon
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn private_key_block(lowercase: &str) -> bool {
    [
        concat!("-----begin private", " key-----"),
        concat!("-----begin rsa private", " key-----"),
        concat!("-----begin ec private", " key-----"),
        concat!("-----begin openssh private", " key-----"),
    ]
    .iter()
    .any(|marker| lowercase.contains(marker))
        || (lowercase.contains("-----begin ") && lowercase.contains(" private key-----"))
}

#[derive(Clone, Copy)]
enum ProviderTokenAlphabet {
    Alphanumeric,
    AlphanumericDashUnderscore,
    AlphanumericDashUnderscoreDot,
    UpperAlphanumeric,
}

#[derive(Clone, Copy)]
struct ProviderTokenProfile {
    prefix: &'static str,
    minimum_suffix: usize,
    maximum_suffix: usize,
    case_sensitive: bool,
    alphabet: ProviderTokenAlphabet,
}

const fn provider_token_profile(
    prefix: &'static str,
    minimum_suffix: usize,
    maximum_suffix: usize,
    case_sensitive: bool,
    alphabet: ProviderTokenAlphabet,
) -> ProviderTokenProfile {
    ProviderTokenProfile {
        prefix,
        minimum_suffix,
        maximum_suffix,
        case_sensitive,
        alphabet,
    }
}

fn provider_key_prefix(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    [
        provider_token_profile("gho_", 36, 128, false, ProviderTokenAlphabet::Alphanumeric),
        provider_token_profile("ghp_", 36, 128, false, ProviderTokenAlphabet::Alphanumeric),
        provider_token_profile(
            "github_pat_",
            40,
            256,
            false,
            ProviderTokenAlphabet::AlphanumericDashUnderscore,
        ),
        provider_token_profile(
            "xoxb-",
            24,
            128,
            false,
            ProviderTokenAlphabet::AlphanumericDashUnderscore,
        ),
        provider_token_profile(
            "xoxp-",
            24,
            128,
            false,
            ProviderTokenAlphabet::AlphanumericDashUnderscore,
        ),
        provider_token_profile(
            "glpat-",
            20,
            128,
            false,
            ProviderTokenAlphabet::AlphanumericDashUnderscore,
        ),
        provider_token_profile("npm_", 36, 36, false, ProviderTokenAlphabet::Alphanumeric),
        provider_token_profile(
            "pypi-",
            32,
            256,
            false,
            ProviderTokenAlphabet::AlphanumericDashUnderscore,
        ),
        provider_token_profile("hf_", 34, 34, false, ProviderTokenAlphabet::Alphanumeric),
        provider_token_profile(
            "dop_v1_",
            64,
            64,
            false,
            ProviderTokenAlphabet::Alphanumeric,
        ),
        provider_token_profile(
            "sg.",
            32,
            256,
            false,
            ProviderTokenAlphabet::AlphanumericDashUnderscoreDot,
        ),
        provider_token_profile("sk-", 48, 48, true, ProviderTokenAlphabet::Alphanumeric),
        provider_token_profile(
            "sk-proj-",
            48,
            256,
            true,
            ProviderTokenAlphabet::AlphanumericDashUnderscore,
        ),
        provider_token_profile(
            "sk-ant-",
            48,
            256,
            true,
            ProviderTokenAlphabet::AlphanumericDashUnderscore,
        ),
        provider_token_profile(
            "sk_live_",
            24,
            128,
            true,
            ProviderTokenAlphabet::Alphanumeric,
        ),
        provider_token_profile(
            "sk_test_",
            24,
            128,
            true,
            ProviderTokenAlphabet::Alphanumeric,
        ),
        provider_token_profile(
            "AIza",
            35,
            35,
            true,
            ProviderTokenAlphabet::AlphanumericDashUnderscore,
        ),
        provider_token_profile(
            "AKIA",
            16,
            16,
            true,
            ProviderTokenAlphabet::UpperAlphanumeric,
        ),
        provider_token_profile(
            "ASIA",
            16,
            16,
            true,
            ProviderTokenAlphabet::UpperAlphanumeric,
        ),
    ]
    .into_iter()
    .any(|profile| {
        let candidate = if profile.case_sensitive {
            value
        } else {
            &lowercase
        };
        contains_prefixed_token(candidate, profile)
    })
}

fn contains_prefixed_token(value: &str, profile: ProviderTokenProfile) -> bool {
    value.match_indices(profile.prefix).any(|(index, _)| {
        if index > 0 {
            let Some(before) = value[..index].chars().next_back() else {
                return false;
            };
            if !provider_token_start_boundary(before) {
                return false;
            }
        }
        let suffix = &value[index + profile.prefix.len()..];
        contains_provider_token_suffix(suffix, profile)
    })
}

fn contains_provider_token_suffix(suffix: &str, profile: ProviderTokenProfile) -> bool {
    for (index, character) in suffix.char_indices() {
        if index > profile.maximum_suffix {
            return false;
        }
        if (profile.minimum_suffix..=profile.maximum_suffix).contains(&index)
            && provider_token_end_boundary(character)
        {
            return true;
        }
        if !character.is_ascii()
            || !provider_suffix_byte(character as u8, profile.alphabet)
            || index == profile.maximum_suffix
        {
            return false;
        }
    }
    (profile.minimum_suffix..=profile.maximum_suffix).contains(&suffix.len())
}

fn provider_suffix_byte(byte: u8, alphabet: ProviderTokenAlphabet) -> bool {
    match alphabet {
        ProviderTokenAlphabet::Alphanumeric => byte.is_ascii_alphanumeric(),
        ProviderTokenAlphabet::AlphanumericDashUnderscore => {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
        }
        ProviderTokenAlphabet::AlphanumericDashUnderscoreDot => {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
        }
        ProviderTokenAlphabet::UpperAlphanumeric => {
            byte.is_ascii_uppercase() || byte.is_ascii_digit()
        }
    }
}

fn provider_token_start_boundary(character: char) -> bool {
    credential_token_boundary(character)
}

fn provider_token_end_boundary(character: char) -> bool {
    credential_token_boundary(character)
}

fn secret_reference_form(lowercase: &str) -> bool {
    [
        "secret:",
        "secret://",
        "secret_ref:",
        "secret-ref:",
        "secretref:",
        "vault:",
        "vault://",
        "arn:aws:secretsmanager:",
    ]
    .iter()
    .any(|prefix| {
        lowercase.match_indices(prefix).any(|(index, _)| {
            if index > 0 {
                let Some(before) = lowercase[..index].chars().next_back() else {
                    return false;
                };
                if !reference_start_boundary(before) {
                    return false;
                }
            }
            if prefix.ends_with(':')
                && url_authority_numeric_port_separator(
                    lowercase,
                    index + prefix.len().saturating_sub(1),
                )
            {
                return false;
            }
            let remainder = &lowercase[index + prefix.len()..];
            contains_secret_reference_payload(remainder)
        })
    })
}

fn contains_secret_reference_payload(remainder: &str) -> bool {
    for (index, character) in remainder.char_indices() {
        if index > CREDENTIAL_INGRESS_MAX_REFERENCE_PAYLOAD_BYTES {
            return false;
        }
        if (1..=CREDENTIAL_INGRESS_MAX_REFERENCE_PAYLOAD_BYTES).contains(&index)
            && reference_end_boundary(character)
        {
            return true;
        }
        if !reference_payload_character(character)
            || index == CREDENTIAL_INGRESS_MAX_REFERENCE_PAYLOAD_BYTES
        {
            return false;
        }
    }
    (1..=CREDENTIAL_INGRESS_MAX_REFERENCE_PAYLOAD_BYTES).contains(&remainder.len())
}

fn reference_payload_character(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(character, '_' | '-' | '.' | '/' | ':' | '@' | '~')
}

fn reference_start_boundary(character: char) -> bool {
    credential_token_boundary(character)
}

fn reference_end_boundary(character: char) -> bool {
    credential_token_boundary(character)
}

fn credential_assignment(value: &str) -> Result<bool, RawCredentialInputDenied> {
    let bytes = value.as_bytes();
    for (separator, byte) in bytes.iter().copied().enumerate() {
        if !matches!(byte, b'=' | b':') {
            continue;
        }
        if byte == b':'
            && (value[separator + 1..].starts_with("//")
                || url_authority_numeric_port_separator(value, separator))
        {
            continue;
        }

        let left = value[..separator].trim_end_matches(|character: char| {
            character.is_whitespace() || matches!(character, '"' | '\'')
        });
        let start = left
            .char_indices()
            .rev()
            .find_map(|(index, character)| {
                (!assignment_key_character(character)).then_some(index + character.len_utf8())
            })
            .unwrap_or(0);
        let segment = &left[start..];
        for candidate in assignment_key_suffixes(segment) {
            if normalized_credential_key(candidate)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn url_authority_numeric_port_separator(value: &str, separator: usize) -> bool {
    let Some(scheme_separator) = value[..separator].rfind("://") else {
        return false;
    };
    let authority_start = scheme_separator + 3;
    if authority_start >= separator {
        return false;
    }
    let mut scheme_start = scheme_separator;
    while scheme_start > 0 && url_scheme_byte(value.as_bytes()[scheme_start - 1]) {
        scheme_start -= 1;
    }
    if !valid_url_scheme(&value[scheme_start..scheme_separator]) {
        return false;
    }
    let after_port_separator = &value[separator + 1..];
    let port_length = after_port_separator
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    if port_length == 0 {
        return false;
    }
    let remainder = &after_port_separator[port_length..];
    if !(remainder.is_empty()
        || remainder.chars().next().is_some_and(|character| {
            matches!(character, '/' | '?' | '#') || url_candidate_terminator(character)
        }))
    {
        return false;
    }
    let raw_authority = &value[authority_start..separator + 1 + port_length];
    parse_url_authority(raw_authority).is_ok_and(|authority| authority.has_numeric_port)
}

fn assignment_key_suffixes(segment: &str) -> Vec<&str> {
    let segment = segment.trim_matches(|character: char| {
        character.is_ascii_whitespace() || matches!(character, '"' | '\'')
    });
    let mut candidates = Vec::new();
    if plausible_assignment_key(segment) {
        candidates.push(segment);
    }
    for (index, character) in segment.char_indices() {
        if !character.is_whitespace() && !matches!(character, '"' | '\'' | '_' | '-' | '.' | '/') {
            continue;
        }
        let candidate = segment[index + character.len_utf8()..].trim_matches(|character: char| {
            character.is_ascii_whitespace() || matches!(character, '"' | '\'')
        });
        if plausible_assignment_key(candidate) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn assignment_key_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '-' | '.' | '/')
}

fn plausible_assignment_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'_' | b'-' | b'.' | b'/')
        })
}

fn credential_url(value: &str, url_nesting: usize) -> Result<bool, RawCredentialInputDenied> {
    if url_nesting > CREDENTIAL_INGRESS_MAX_URL_NESTING {
        return Err(RawCredentialInputDenied);
    }

    let mut cursor = 0;
    let mut found_absolute = false;
    while let Some(relative_separator) = value[cursor..].find("://") {
        let separator = cursor + relative_separator;
        let mut start = separator;
        while start > 0 && url_scheme_byte(value.as_bytes()[start - 1]) {
            start -= 1;
        }
        let scheme = &value[start..separator];
        if !valid_url_scheme(scheme) {
            return Err(RawCredentialInputDenied);
        }
        let end = absolute_url_candidate_end(value, separator + 3);
        if credential_url_candidate(&value[start..end], url_nesting)? {
            return Ok(true);
        }
        found_absolute = true;
        cursor = end.max(separator + 3);
        if cursor >= value.len() {
            break;
        }
    }

    if !found_absolute && (value.starts_with("//") || value.starts_with('/') && value.contains('?'))
    {
        return credential_url_candidate(value, url_nesting);
    }
    Ok(false)
}

fn credential_url_candidate(
    value: &str,
    url_nesting: usize,
) -> Result<bool, RawCredentialInputDenied> {
    let scheme_separator = value.find("://");
    let relative_authority = value.starts_with("//");
    let query_only = value.starts_with('/') && value.contains('?') && !relative_authority;
    if scheme_separator.is_none() && !relative_authority && !query_only {
        return Ok(false);
    }
    if let Some(separator) = scheme_separator {
        if !valid_url_scheme(&value[..separator]) {
            return Err(RawCredentialInputDenied);
        }
    }
    if value.as_bytes().contains(&b'%') {
        let decoded = percent_decode(value)?;
        ensure_unambiguous_text(&decoded)?;
    }

    let authority_start = scheme_separator.map_or(2, |index| index + 3);
    let mut path_start = 0;
    if !query_only {
        let remainder = &value[authority_start..];
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        if authority.is_empty() {
            return Err(RawCredentialInputDenied);
        }
        let decoded_authority = percent_decode(authority)?;
        ensure_unambiguous_text(&decoded_authority)?;
        if authority.contains('@') || decoded_authority.contains('@') {
            return Ok(true);
        }
        let parsed_authority = parse_url_authority(authority)?;
        if credential_content_decoded(
            &parsed_authority.screening_host,
            url_nesting.saturating_add(1),
        )? {
            return Ok(true);
        }
        path_start = authority_start + authority_end;
    }

    let fragment_start = value.find('#');
    let query_start = value
        .find('?')
        .filter(|query| fragment_start.is_none_or(|fragment| query < &fragment));
    let path_end = query_start.or(fragment_start).unwrap_or(value.len());
    if path_start < path_end
        && credential_url_component(
            &value[path_start..path_end],
            false,
            url_nesting.saturating_add(1),
        )?
    {
        return Ok(true);
    }

    if let Some(query_start) = query_start {
        let query_end = fragment_start.unwrap_or(value.len());
        let query = &value[query_start + 1..query_end];
        if credential_form(query, url_nesting.saturating_add(1))? {
            return Ok(true);
        }
        for field in query.split(['&', ';']) {
            if field.is_empty() {
                continue;
            }
            let (raw_key, raw_value) = field.split_once('=').unwrap_or((field, ""));
            let key = percent_decode_form(raw_key)?;
            ensure_unambiguous_text(&key)?;
            if contains_percent_escape(&key)
                || normalized_credential_key(&key)?
                || credential_content_decoded(&key, url_nesting.saturating_add(1))?
            {
                return if contains_percent_escape(&key) {
                    Err(RawCredentialInputDenied)
                } else {
                    Ok(true)
                };
            }
            if credential_url_component(raw_value, true, url_nesting.saturating_add(1))? {
                return Ok(true);
            }
        }
    }

    if let Some(fragment_start) = fragment_start {
        if credential_url_component(
            &value[fragment_start + 1..],
            false,
            url_nesting.saturating_add(1),
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn credential_url_component(
    value: &str,
    plus_as_space: bool,
    url_nesting: usize,
) -> Result<bool, RawCredentialInputDenied> {
    if url_nesting > CREDENTIAL_INGRESS_MAX_URL_NESTING {
        return Err(RawCredentialInputDenied);
    }
    let decoded = if plus_as_space {
        percent_decode_form(value)?
    } else {
        percent_decode(value)?
    };
    if contains_percent_escape(&decoded) {
        return Err(RawCredentialInputDenied);
    }
    ensure_unambiguous_text(&decoded)?;
    credential_content_decoded(&decoded, url_nesting)
}

struct ParsedUrlAuthority {
    screening_host: String,
    has_numeric_port: bool,
}

fn parse_url_authority(authority: &str) -> Result<ParsedUrlAuthority, RawCredentialInputDenied> {
    let literal_start = if authority.starts_with('[') {
        Some(1)
    } else if percent_encoded_byte_at(authority, 0, b'[') {
        Some(3)
    } else {
        None
    };
    if let Some(literal_start) = literal_start {
        let (literal_end, closing_end) =
            closing_bracket_range(authority, literal_start).ok_or(RawCredentialInputDenied)?;
        let screening_host =
            decode_ip_literal_for_screening(&authority[literal_start..literal_end])?;
        let remainder = &authority[closing_end..];
        let has_numeric_port = if remainder.is_empty() {
            false
        } else if remainder.strip_prefix(':').is_some_and(valid_numeric_port) {
            true
        } else {
            return Err(RawCredentialInputDenied);
        };
        return Ok(ParsedUrlAuthority {
            screening_host,
            has_numeric_port,
        });
    }

    if authority.contains(['[', ']']) {
        return Err(RawCredentialInputDenied);
    }
    let (raw_host, has_numeric_port) = match authority.rsplit_once(':') {
        None => (authority, false),
        Some((host, port))
            if !host.contains(':') && !host.is_empty() && valid_numeric_port(port) =>
        {
            (host, true)
        }
        Some(_) => return Err(RawCredentialInputDenied),
    };
    let decoded_host = percent_decode(raw_host)?;
    ensure_unambiguous_text(&decoded_host)?;
    if contains_percent_escape(&decoded_host) || !valid_reg_name_host(&decoded_host) {
        return Err(RawCredentialInputDenied);
    }
    Ok(ParsedUrlAuthority {
        screening_host: decoded_host,
        has_numeric_port,
    })
}

fn decode_ip_literal_for_screening(address: &str) -> Result<String, RawCredentialInputDenied> {
    let decoded = percent_decode(address)?;
    ensure_unambiguous_text(&decoded)?;
    if decoded
        .strip_prefix('v')
        .or_else(|| decoded.strip_prefix('V'))
        .is_some()
    {
        return valid_ip_literal(&decoded)
            .then_some(decoded)
            .ok_or(RawCredentialInputDenied);
    }

    let zone_delimiter =
        (0..address.len()).find(|index| percent_encoded_byte_at(address, *index, b'%'));
    let (raw_address, raw_zone) = zone_delimiter.map_or((address, None), |delimiter| {
        (&address[..delimiter], Some(&address[delimiter + 3..]))
    });
    if raw_address.contains('%')
        || raw_zone.is_some_and(|zone| !valid_encoded_zone(zone))
        || !valid_ip_literal(&decoded)
    {
        return Err(RawCredentialInputDenied);
    }
    if let Some((address, zone)) = decoded.split_once('%') {
        Ok(format!("{address}/{zone}"))
    } else {
        Ok(decoded)
    }
}

fn valid_encoded_zone(zone: &str) -> bool {
    let Ok(decoded_zone) = percent_decode(zone) else {
        return false;
    };
    !decoded_zone.is_empty()
        && !decoded_zone.contains('%')
        && decoded_zone.chars().all(|character| {
            character.is_alphanumeric() || matches!(character, '-' | '.' | '_' | '~')
        })
}

fn valid_numeric_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

fn valid_reg_name_host(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && !host.split('.').any(str::is_empty)
        && host.chars().all(|character| {
            character.is_alphanumeric() || matches!(character, '-' | '.' | '_' | '~')
        })
}

fn valid_ip_literal(address: &str) -> bool {
    if let Some(ipv_future) = address
        .strip_prefix('v')
        .or_else(|| address.strip_prefix('V'))
    {
        return valid_ipv_future(ipv_future);
    }
    let (address, zone) = address
        .split_once('%')
        .map_or((address, None), |(address, zone)| (address, Some(zone)));
    address.parse::<Ipv6Addr>().is_ok()
        && zone.is_none_or(|zone| {
            !zone.is_empty()
                && !zone.contains('%')
                && zone.chars().all(|character| {
                    character.is_alphanumeric() || matches!(character, '-' | '.' | '_' | '~')
                })
        })
}

fn valid_ipv_future(value: &str) -> bool {
    let Some((version, address)) = value.split_once('.') else {
        return false;
    };
    !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !address.is_empty()
        && address.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    '-' | '.'
                        | '_'
                        | '~'
                        | '!'
                        | '$'
                        | '&'
                        | '\''
                        | '('
                        | ')'
                        | '*'
                        | '+'
                        | ','
                        | ';'
                        | '='
                        | ':'
                )
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistedContentKind {
    Json,
    Text,
    OpaqueOrUnspecified,
}

fn persisted_content_kind(
    content_type: Option<&str>,
) -> Result<PersistedContentKind, RawCredentialInputDenied> {
    let Some(content_type) = content_type else {
        return Ok(PersistedContentKind::OpaqueOrUnspecified);
    };
    let essence = content_type
        .split(';')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(RawCredentialInputDenied)?;
    let (kind, subtype) = essence.split_once('/').ok_or(RawCredentialInputDenied)?;
    if !valid_media_type_token(kind) || !valid_media_type_token(subtype) {
        return Err(RawCredentialInputDenied);
    }
    let kind = kind.to_ascii_lowercase();
    let subtype = subtype.to_ascii_lowercase();
    if subtype == "json" || subtype.ends_with("+json") {
        Ok(PersistedContentKind::Json)
    } else if kind == "text" {
        Ok(PersistedContentKind::Text)
    } else {
        Ok(PersistedContentKind::OpaqueOrUnspecified)
    }
}

fn valid_media_type_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                )
        })
}

fn persisted_content_type(
    values: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<&str>, RawCredentialInputDenied> {
    let value = values
        .get("content_type")
        .or_else(|| values.get("contentType"));
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(RawCredentialInputDenied),
    }
}

fn persisted_byte_coordinate(key: &str) -> bool {
    matches!(compact_ascii(key).as_str(), "body" | "bytes" | "contents")
}

fn ambiguous_textual_bytes(bytes: &[u8]) -> bool {
    const BYTE_ORDER_MARKS: &[&[u8]] = &[
        &[0xef, 0xbb, 0xbf],
        &[0xff, 0xfe],
        &[0xfe, 0xff],
        &[0xff, 0xfe, 0x00, 0x00],
        &[0x00, 0x00, 0xfe, 0xff],
    ];
    if BYTE_ORDER_MARKS
        .iter()
        .any(|marker| bytes.starts_with(marker))
    {
        return true;
    }
    str::from_utf8(bytes).is_ok_and(|text| {
        text.chars().any(|character| {
            character == '\u{feff}'
                || character.is_control() && !matches!(character, '\t' | '\n' | '\r')
        }) && text.chars().any(|character| !character.is_control())
    })
}

fn unambiguous_utf8_body(bytes: &[u8]) -> Option<&str> {
    let text = str::from_utf8(bytes).ok()?;
    unambiguous_text(text).then_some(text)
}

fn ensure_unambiguous_text(value: &str) -> Result<(), RawCredentialInputDenied> {
    unambiguous_text(value)
        .then_some(())
        .ok_or(RawCredentialInputDenied)
}

fn unambiguous_text(value: &str) -> bool {
    !value.chars().any(|character| {
        character == '\u{feff}'
            || character.is_control() && !matches!(character, '\t' | '\n' | '\r')
    })
}

fn url_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

fn url_candidate_terminator(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '"' | '\'' | '`' | '<' | '>' | ')' | '}' | ',' | '|' | '!' | '\\'
        )
}

fn absolute_url_candidate_end(value: &str, authority_start: usize) -> usize {
    let candidate = &value[authority_start..];
    let bracket_search_start = if candidate.starts_with('[') {
        Some(1)
    } else if percent_encoded_byte_at(candidate, 0, b'[') {
        Some(3)
    } else {
        None
    };
    let bracket_close_end = bracket_search_start
        .and_then(|search_start| closing_bracket_range(candidate, search_start))
        .map(|(_, end)| end);
    if bracket_search_start.is_some() && bracket_close_end.is_none() {
        return value.len();
    }
    candidate
        .char_indices()
        .find_map(|(index, character)| {
            if bracket_close_end.is_some_and(|close_end| index < close_end) {
                None
            } else {
                url_candidate_terminator(character).then_some(authority_start + index)
            }
        })
        .unwrap_or(value.len())
}

fn closing_bracket_range(value: &str, mut index: usize) -> Option<(usize, usize)> {
    while index < value.len() {
        if value.as_bytes()[index] == b']' {
            return Some((index, index + 1));
        }
        if percent_encoded_byte_at(value, index, b']') {
            return Some((index, index + 3));
        }
        index += 1;
    }
    None
}

fn percent_encoded_byte_at(value: &str, index: usize, expected: u8) -> bool {
    let bytes = value.as_bytes();
    index + 2 < bytes.len()
        && bytes[index] == b'%'
        && hex_value(bytes[index + 1])
            .zip(hex_value(bytes[index + 2]))
            .is_some_and(|(high, low)| (high << 4 | low) == expected)
}

fn url_coordinate_candidate(value: &str) -> bool {
    value.contains("://")
        || value.starts_with("//")
        || value.starts_with('/') && value.contains('?')
}

fn credential_dsn_without_scheme(value: &str) -> bool {
    if value.chars().any(char::is_whitespace) || value.contains("://") {
        return false;
    }
    let Some(at) = value.rfind('@') else {
        return false;
    };
    let userinfo = &value[..at];
    let host = &value[at + 1..];
    !host.is_empty() && userinfo.split_once(':').is_some()
}

fn valid_url_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn contains_percent_escape(value: &str) -> bool {
    value.as_bytes().windows(3).any(|window| {
        window[0] == b'%' && hex_value(window[1]).is_some() && hex_value(window[2]).is_some()
    })
}

fn percent_decode(value: &str) -> Result<String, RawCredentialInputDenied> {
    percent_decode_component(value, false)
}

fn percent_decode_form(value: &str) -> Result<String, RawCredentialInputDenied> {
    percent_decode_component(value, true)
}

fn percent_decode_component(
    value: &str,
    plus_as_space: bool,
) -> Result<String, RawCredentialInputDenied> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if plus_as_space && bytes[index] == b'+' {
            decoded.push(b' ');
            index += 1;
            continue;
        }
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(RawCredentialInputDenied);
        }
        let high = hex_value(bytes[index + 1]).ok_or(RawCredentialInputDenied)?;
        let low = hex_value(bytes[index + 2]).ok_or(RawCredentialInputDenied)?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| RawCredentialInputDenied)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn compact_ascii(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use splendor_types::{
        AgentId, ApprovalDecision, ApprovalId, AuthorityDecisionId, AuthorityObligationId,
        AuthorityObligationKind, AuthorityObligationReceiptId,
        AuthorityObligationReceiptValidation, AuthorityObligationReceiptValidationKind,
        CostEstimate, PerceptProvenance, PrincipalId, QuotaUsage, RunId, TenantId,
    };

    fn action(params: serde_json::Value) -> Action {
        action_named("inspect", params)
    }

    fn action_named(name: &str, params: serde_json::Value) -> Action {
        Action {
            name: name.to_string(),
            params,
            side_effect_class: SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        }
    }

    fn ordinary_receipt() -> AuthorityObligationReceipt {
        let now = OffsetDateTime::now_utc();
        AuthorityObligationReceipt {
            schema_version: "splendor.authority_obligation_receipt.v1".to_string(),
            receipt_id: AuthorityObligationReceiptId::new(),
            issuer: PrincipalId::new(),
            audience: "splendor.daemon.run:fixture".to_string(),
            obligation_id: AuthorityObligationId::new(),
            kind: AuthorityObligationKind::ApprovalRequired,
            subject: PrincipalId::new(),
            authority_decision_id: AuthorityDecisionId::new(),
            canonical_request_digest: "blake3:canonical-request".to_string(),
            evidence_digest: "blake3:evidence".to_string(),
            evidence_ref: Some("evidence:approval/fixture".to_string()),
            issued_at: now,
            expires_at: now + time::Duration::minutes(5),
            revocation: RevocationStatus::Active,
            revocation_ref: "revocation:fixture".to_string(),
            approval_id: None,
            approval_trace_event_id: None,
            validation: AuthorityObligationReceiptValidation {
                validation_kind: AuthorityObligationReceiptValidationKind::LocalSignature,
                algorithm: "local-signature-v1".to_string(),
                key_id: "local-receipt-key-v1".to_string(),
                digest: "blake3:receipt".to_string(),
                signature: "synthetic-signature".to_string(),
            },
        }
    }

    fn synthetic_private_key_canary() -> String {
        format!(
            "-----BEGIN {}-----\nSYNTHETIC\n-----END {}-----",
            "PRIVATE KEY", "PRIVATE KEY"
        )
    }

    fn synthetic_provider_token(prefix: &str, suffix_bytes: usize) -> String {
        format!("{prefix}{}", "A".repeat(suffix_bytes))
    }

    fn request(action: Action) -> ActionRequest {
        ActionRequest {
            action_id: crate::ActionId::new(),
            tenant_id: TenantId::new(),
            agent_id: AgentId::new(),
            run_id: RunId::new(),
            tick_id: None,
            action,
            adapter: None,
            quota_usage: QuotaUsage::single_action(),
            satisfied_preconditions: Vec::new(),
            requested_at: OffsetDateTime::now_utc(),
            physical_action_resource_coordinate: None,
            approval_evidence: None,
            authority_obligation_evidence: None,
            authority_obligation_receipts: Vec::new(),
        }
    }

    fn ordinary_approval_evidence(request: &ActionRequest) -> ApprovalEvidence {
        let mut evidence = ApprovalEvidence::new(
            ApprovalId::new(),
            request.tenant_id.clone(),
            request.agent_id.clone(),
            request.run_id.clone(),
            ApprovalDecision::Denied,
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        );
        evidence.action_id = Some(request.action_id.clone());
        evidence.action_name = Some(request.action.name.clone());
        evidence.adapter = request.adapter.clone();
        evidence.reason = Some("operator denied exact action".to_string());
        evidence
    }

    #[test]
    fn key_matrix_denies_case_separator_nested_and_environment_aliases() {
        for key in [
            "Authorization",
            "proxy-authorization",
            "Pass.Word",
            "PASSWD",
            "token",
            "api_key",
            "ApiKey",
            "authKey",
            "apiToken",
            "X-API-Key",
            "X-Auth-Token",
            "Private-Token",
            "authz",
            "client secret",
            "private/key",
            "cookie",
            "set-cookie",
            "secret",
            "credential",
            "connectionString",
            "D_S_N",
            "DATABASE_URL",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "X-Amz-Signature",
            "AZURE_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "PGPASSWORD",
            "VAULT_TOKEN",
            "CONSUL_HTTP_TOKEN",
            "POSTGRES_PASSWORD",
            "POSTGRESQL_PASSWORD",
            "MYSQL_PWD",
            "MYSQL_PASSWORD",
            "MYSQL_ROOT_PASSWORD",
            "MARIADB_PASSWORD",
            "MARIADB_ROOT_PASSWORD",
            "MONGO_PASSWORD",
            "MONGO_INITDB_ROOT_PASSWORD",
            "REDIS_PASSWORD",
            "RABBITMQ_DEFAULT_PASS",
            "MSSQL_SA_PASSWORD",
            "ORACLE_PASSWORD",
            "ELASTIC_PASSWORD",
            "OPENSEARCH_INITIAL_ADMIN_PASSWORD",
            "DOCKER_AUTH_CONFIG",
            "HF_TOKEN",
            "secret_ref_id",
            "secretKeyRef",
        ] {
            let params = serde_json::json!({"outer": [{key: "synthetic-value"}]});
            assert_eq!(guard_action(&action(params)), Err(RawCredentialInputDenied));
        }
    }

    #[test]
    fn credential_content_in_object_keys_is_denied() {
        for key in [
            "Bearer synthetic-value".to_string(),
            "vault:team/service".to_string(),
            synthetic_provider_token("ghp_", 36),
            "authKey = synthetic".to_string(),
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({&key: "ordinary-value"}))),
                Err(RawCredentialInputDenied),
                "credential-bearing object key must deny independently: {key}"
            );
        }
    }

    #[test]
    fn quoted_assignments_and_embedded_refs_are_denied_independently() {
        for value in [
            r#""authKey" = "synthetic""#,
            r#"prefix "X-API-Key" : "synthetic""#,
            "export POSTGRES_PASSWORD = synthetic",
            "read vault:team/service for deployment",
            "reference=(secret_ref:team/service)",
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": value}))),
                Err(RawCredentialInputDenied),
                "assignment/ref must deny independently: {value}"
            );
        }
    }

    #[test]
    fn content_matrix_denies_auth_private_provider_ref_url_and_dsn_forms() {
        let mut values = vec![
            "Bearer synthetic-value".to_string(),
            "Bearer%20synthetic-value".to_string(),
            "Basic dTpw".to_string(),
            synthetic_private_key_canary(),
            "secret_ref:synthetic-reference".to_string(),
            "https://user:synthetic@example.invalid/path".to_string(),
            "https%3A%2F%2Fuser%3Asynthetic%40example.invalid%2Fpath".to_string(),
            "https://example.invalid/path?api%5Fkey=synthetic".to_string(),
            "Driver=sqlite;Server=local;Pwd=synthetic".to_string(),
            "AWS_SESSION_TOKEN=synthetic".to_string(),
            "PASSWORD = synthetic".to_string(),
            "SAFE=x API_KEY = synthetic".to_string(),
            r#"{"token":"synthetic"}"#.to_string(),
            "user:synthetic@example.invalid".to_string(),
        ];
        for (prefix, suffix_bytes) in [
            ("gho_", 36),
            ("ghp_", 36),
            ("github_pat_", 40),
            ("xoxb-", 24),
            ("xoxp-", 24),
            ("glpat-", 20),
            ("npm_", 36),
            ("pypi-", 32),
            ("hf_", 34),
            ("dop_v1_", 64),
            ("SG.", 32),
            ("sk-", 48),
            ("sk-proj-", 48),
            ("sk-ant-", 48),
            ("sk_live_", 24),
            ("sk_test_", 24),
            ("AIza", 35),
            ("AKIA", 16),
            ("ASIA", 16),
        ] {
            values.push(synthetic_provider_token(prefix, suffix_bytes));
        }
        for value in values {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": value}))),
                Err(RawCredentialInputDenied)
            );
        }
    }

    #[test]
    fn authorization_and_provider_grammar_preserves_ordinary_prose_and_resources() {
        for value in [
            "Basic monthly reporting",
            "Basic planning",
            "Bearer monthly reporting",
            "hf_transformer",
            "models/hf_transformer",
            "models/Basic planning",
            "models/sk-learn",
            "models/sk-learn-sentiment-classifier-v2",
            "prefixghp_syntheticcredential",
            "Bearer ========",
            "Basic reporting",
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": value}))),
                Ok(()),
                "ordinary content must remain accepted: {value}"
            );
        }

        for value in [
            "Basic dTpw",
            "Basic YTpi",
            "models/Basic dTpw",
            "Bearer x",
            "Bearer synthetic-value",
            "prefix Authorization: Bearer synthetic-value",
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": value}))),
                Err(RawCredentialInputDenied),
                "complete credential form must deny: {value}"
            );
        }

        for value in [
            synthetic_provider_token("hf_", 34),
            synthetic_provider_token("ghp_", 36),
            format!(
                "https://example.invalid/models/{}/metadata",
                synthetic_provider_token("ghp_", 36)
            ),
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": value}))),
                Err(RawCredentialInputDenied),
                "realistic complete provider token must deny"
            );
        }
    }

    #[test]
    fn bounded_url_path_query_and_nested_values_deny_without_rejecting_url_prose() {
        let provider_path = format!(
            "https://example.invalid/models/{}/metadata",
            synthetic_provider_token("ghp_", 36)
        );
        let nested_url =
            "https://example.invalid/redirect?target=https%3A%2F%2Fuser%3Apass%40nested.invalid";
        for value in [
            provider_path.as_str(),
            "https://example.invalid/%76ault%3Ateam%2Fservice",
            "vault://team/service?version=1",
            nested_url,
            "Bearer%20x see https://example.invalid/docs",
            "vault%3A%2F%2Fteam%2Fservice see https://example.invalid/docs",
            "https://example.invalid/form?value=Bearer+short",
            "https://example.invalid/form?name=VAULT_TOKEN&value=synthetic",
            "https://example.invalid/sign?X-Amz-Signature=synthetic",
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": value}))),
                Err(RawCredentialInputDenied),
                "URL/ref credential vector must deny: {value}"
            );
        }

        for value in [
            "see https://example.invalid/docs",
            "read https://example.invalid/models/hf_transformer for details",
            "https://example.invalid/docs?topic=Basic+planning",
            "https://example.invalid/#section?topic=Basic+planning",
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": value}))),
                Ok(()),
                "ordinary embedded URL/prose must remain accepted: {value}"
            );
        }

        let mut over_nested = "https://leaf.invalid/docs".to_string();
        for level in 0..=CREDENTIAL_INGRESS_MAX_URL_NESTING {
            over_nested = format!("https://level-{level}.invalid/?next={over_nested}");
        }
        assert_eq!(
            guard_action(&action(serde_json::json!({"input": over_nested}))),
            Err(RawCredentialInputDenied),
            "URL nesting beyond the explicit cap must fail closed"
        );
    }

    #[test]
    fn standalone_forms_structured_coordinates_and_ambiguous_text_fail_closed() {
        for params in [
            serde_json::json!({"body": "value=Basic+dTpw"}),
            serde_json::json!({"body": "safe=1&X-Auth-Token=synthetic"}),
            serde_json::json!({"json": {"name": "VAULT_TOKEN", "value": "synthetic"}}),
            serde_json::json!({"body": "\u{feff}Basic dTpw"}),
            serde_json::json!({"contents": "B\0e\0a\0r\0e\0r\0 \0x\0"}),
            serde_json::json!({"body": "name=VAULT_TOKEN&value=synthetic"}),
            serde_json::json!({"body": "header=X-Auth-Token&value=synthetic"}),
            serde_json::json!({"body": "Bearer%20x,https://example.invalid/docs"}),
            serde_json::json!({"body": "vault%3Ateam%2Fservice,https://example.invalid/docs"}),
            serde_json::json!({"body": "vault%3A%2F%2Fteam%2Fservice,https://example.invalid/docs"}),
            serde_json::json!({"body": "value=%EF%BB%BFBasic%20dTpw"}),
            serde_json::json!({"body": "value=B%00e%00a%00r%00e%00r%00%20x"}),
            serde_json::json!({"body": "safe/Bearer x"}),
            serde_json::json!({"body": "safe|Bearer x"}),
            serde_json::json!({"body": "safe|token=synthetic"}),
            serde_json::json!({"json": {"key": "password", "value": "hunter2"}}),
            serde_json::json!({"json": {"header": "Authorization", "value": "opaque"}}),
            serde_json::json!({"body": "key=password&value=hunter2"}),
            serde_json::json!({"body": "env=API_KEY&value=opaque"}),
            serde_json::json!({"url": "https://example.invalid/Bearer%20x"}),
            serde_json::json!({"url": "https://example.invalid/?%42earer%20x"}),
            serde_json::json!({"url": "https://example.invalid/?%76ault%3Aprod%2Fdb"}),
            serde_json::json!({"body": "Basic dTpw/next"}),
            serde_json::json!({"body": "Basic dTpw+next"}),
            serde_json::json!({"body": "Basic dTpw=next"}),
            serde_json::json!({"body": "Basic ICA+OnA=/next"}),
            serde_json::json!({"body": "Basic ICA/OnA=+next"}),
            serde_json::json!({"url": "https://example.invalid/Basic%20dTpw/next"}),
            serde_json::json!({"url": "https://example.invalid/#Basic%20dTpw/next"}),
            serde_json::json!({"url": "https://example.invalid/?q=Basic+dTpw%2Fnext"}),
            serde_json::json!({"body": "https://example.invalid password:1234"}),
            serde_json::json!({"body": "https://example.invalid vault:8200/path"}),
            serde_json::json!({"body": "https://example.invalid,token:8443"}),
            serde_json::json!({"body": "https://example.invalid|password:1234"}),
            serde_json::json!({"body": "https://example.invalid—auth:8443"}),
            serde_json::json!({"url": "https://example.invalid%20password:1234/path"}),
            serde_json::json!({"url": "https://example.invalid%2Ctoken:8443/path"}),
            serde_json::json!({"url": "https://example.invalid%20vault:8200/path"}),
            serde_json::json!({"body": "https://example.invalid'token:8443"}),
            serde_json::json!({"url": "https://example.invalid%27token:8443/path"}),
            serde_json::json!({"body": "https://example.invalid)token:8443"}),
            serde_json::json!({"url": "https://example.invalid%29token:8443/path"}),
            serde_json::json!({"body": "https://example.invalid]token:8443"}),
            serde_json::json!({"url": "https://example.invalid%5Dtoken:8443/path"}),
        ] {
            assert_eq!(
                guard_action(&action(params)),
                Err(RawCredentialInputDenied),
                "structured or ambiguous credential representation must deny"
            );
        }

        for (index, params) in [
            serde_json::json!({"body": "topic=Basic+planning&mode=monthly"}),
            serde_json::json!({"json": {"name": "model_name", "value": "hf_transformer"}}),
            serde_json::json!({"descriptor": {"name": "token", "type": "string"}}),
            serde_json::json!({"json": {"name": "token", "value": "linguistic unit"}}),
            serde_json::json!({"json": {"name": "café", "value": "ordinary"}}),
            serde_json::json!({"descriptor": {"key": "password", "description": "field label only"}}),
            serde_json::json!({"example": {"header": "Authorization", "description": "header name only"}}),
            serde_json::json!({"body": "name=token&value=linguistic+unit"}),
            serde_json::json!({"body": "name=CPU%25&value=ordinary"}),
            serde_json::json!({"body": "safe=1&label=50%25"}),
            serde_json::json!({"contents": "ordinary UTF-8 café\n"}),
            serde_json::json!({"url": "https://auth:8443/path"}),
            serde_json::json!({"url": "https://token:8443/path"}),
            serde_json::json!({"url": "https://password:8443/path"}),
            serde_json::json!({"url": "https://vault:8200/v1/sys/health"}),
            serde_json::json!({"url": "https://[::1]:8443/path"}),
            serde_json::json!({"url": "https://[v1.fe80]:8443/path"}),
            serde_json::json!({"url": "https://[fe80::1%25eth0]:8443/path"}),
            serde_json::json!({"url": "https://[fe80::1%2512]:8443/path"}),
            serde_json::json!({"url": "https://[fe80::1%25ab0]:8443/path"}),
            serde_json::json!({"url": "https://[fe80::1%25%31%32]:8443/path"}),
            serde_json::json!({"url": "https://example.invalid:65535/path"}),
            serde_json::json!({"url": "https://example.invalid.:8443/path"}),
            serde_json::json!({"url": "https://[v1.a!b]:443/"}),
            serde_json::json!({"url": "https://[v1.a'b]:443/"}),
            serde_json::json!({"url": "https://[v1.a)b]:443/"}),
            serde_json::json!({"url": "https://[v1.a,b]:443/"}),
            serde_json::json!({"url": "https://[v1.a%21b]:443/"}),
            serde_json::json!({"url": "https://[v1.a%27b]:443/"}),
            serde_json::json!({"url": "https://[v1.a%29b]:443/"}),
            serde_json::json!({"url": "https://[v1.a%2Cb]:443/"}),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                guard_action(&action(params)),
                Ok(()),
                "ordinary form, coordinate, and text control {index} must remain accepted"
            );
        }

        let provider = synthetic_provider_token("ghp_", 36);
        for value in [
            format!("safe|{provider}"),
            format!("https://example.invalid/?%67hp%5F{}", "A".repeat(36)),
            format!("https://sink-%41KIA{}.attacker.invalid/", "1".repeat(16)),
            format!("https://sink-%67hp%5F{}.attacker.invalid/", "A".repeat(36)),
            format!("github_pat_{}-tail", "A".repeat(256)),
            format!("xoxb-{}-tail", "A".repeat(128)),
            format!("SG.{}.tail", "A".repeat(256)),
            format!("AIza{}-tail", "A".repeat(35)),
            format!(
                "vault:{}/next",
                "A".repeat(CREDENTIAL_INGRESS_MAX_REFERENCE_PAYLOAD_BYTES)
            ),
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": value}))),
                Err(RawCredentialInputDenied)
            );
        }
    }

    #[test]
    fn executable_numeric_byte_coordinates_are_reconstructed_and_fail_closed() {
        let credential_bodies = vec![
            "Bearer synthetic-value".to_string(),
            "Basic dTpw".to_string(),
            synthetic_private_key_canary(),
            synthetic_provider_token("ghp_", 36),
            "PASSWORD=synthetic".to_string(),
            "https://user:synthetic@example.invalid/path".to_string(),
            "user:synthetic@example.invalid".to_string(),
            "vault:team/service".to_string(),
            "value=Bearer+short".to_string(),
        ];
        for action_name in ["http_post", "write_file"] {
            for credential in &credential_bodies {
                let bytes = credential.as_bytes().to_vec();
                assert_eq!(
                    guard_action(&action_named(
                        action_name,
                        serde_json::json!({"bytes": bytes})
                    )),
                    Err(RawCredentialInputDenied),
                    "{action_name} numeric body must deny: {credential}"
                );
            }

            assert_eq!(
                guard_action(&action_named(
                    action_name,
                    serde_json::json!({"bytes": b"ordinary bounded body".to_vec()})
                )),
                Ok(())
            );
            for invalid in [
                serde_json::json!("not-an-array"),
                serde_json::json!([256]),
                serde_json::json!([-1]),
                serde_json::json!([1.5]),
                serde_json::json!({"nested": true}),
            ] {
                assert_eq!(
                    guard_action(&action_named(
                        action_name,
                        serde_json::json!({"bytes": invalid})
                    )),
                    Err(RawCredentialInputDenied),
                    "ambiguous executable bytes must fail closed"
                );
            }
            assert_eq!(
                guard_action(&action_named(
                    action_name,
                    serde_json::json!({
                        "bytes": vec![0_u8; CREDENTIAL_INGRESS_MAX_NODES + 1]
                    })
                )),
                Err(RawCredentialInputDenied),
                "oversized executable bytes must fail closed"
            );

            for ambiguous in [
                vec![0xff, b'a'],
                vec![0xef, 0xbb, 0xbf, b'o', b'k'],
                vec![b'B', 0, b'e', 0, b'a', 0, b'r', 0, b'e', 0, b'r', 0],
                vec![0, b'B', 0, b'e', 0, b'a', 0, b'r', 0, b'e', 0, b'r'],
                vec![b'o', b'k', 0, b'x'],
            ] {
                assert_eq!(
                    guard_action(&action_named(
                        action_name,
                        serde_json::json!({"bytes": ambiguous})
                    )),
                    Err(RawCredentialInputDenied),
                    "ambiguous executable encoding must fail closed"
                );
            }
        }

        assert_eq!(
            guard_action(&action(serde_json::json!({"vector": [256]}))),
            Ok(()),
            "unrelated numeric arrays retain their non-byte semantics"
        );
        assert_eq!(
            guard_action(&action(serde_json::json!({"vector": [255, 0]}))),
            Ok(()),
            "unrelated numeric arrays retain their non-byte semantics"
        );
        assert_eq!(
            guard_action(&action(
                serde_json::json!({"vector": b"Basic dTpw".to_vec()})
            )),
            Ok(()),
            "unrelated textual numeric arrays retain their non-byte semantics"
        );

        let mut alternate = request(action_named(
            "custom_upload",
            serde_json::json!({"bytes": b"Basic dTpw".to_vec()}),
        ));
        alternate.adapter = Some("http".to_string());
        assert_eq!(
            guard_action_request(&alternate),
            Err(RawCredentialInputDenied),
            "adapter routing cannot evade executable byte screening"
        );
    }

    #[test]
    fn generic_envelope_guard_recursively_screens_strings_and_keys() {
        for value in [
            serde_json::json!({"nested": [{"secretKeyRef": "fixture"}]}),
            serde_json::json!({"nested": [{"name": "VAULT_TOKEN", "value": "fixture"}]}),
            serde_json::json!({"nested": ["\u{feff}Basic dTpw"]}),
        ] {
            assert_eq!(
                guard_credential_capable_value(&value),
                Err(RawCredentialInputDenied)
            );
        }
        assert_eq!(
            guard_credential_capable_value(&serde_json::json!({
                "nested": [{"zone_ref": "zone_a"}],
                "status": "ready"
            })),
            Ok(())
        );
    }

    #[test]
    fn persisted_percept_guard_shares_one_budget_across_all_credential_capable_fields() {
        let ordinary = Percept {
            schema: "splendor.percept.fixture.v1".to_string(),
            payload: serde_json::json!({"value": 7, "description": "ordinary reading"}),
            provenance: PerceptProvenance {
                source: "fixture-sensor".to_string(),
                detail: Some("local sample".to_string()),
            },
            timestamp: OffsetDateTime::now_utc(),
        };
        assert_eq!(guard_persisted_percept(&ordinary), Ok(()));

        for field in ["schema", "payload", "source", "detail"] {
            let mut guarded = ordinary.clone();
            match field {
                "schema" => guarded.schema = "Bearer x".to_string(),
                "payload" => guarded.payload = serde_json::json!({"api_key": "synthetic"}),
                "source" => guarded.provenance.source = "Basic dTpw".to_string(),
                "detail" => guarded.provenance.detail = Some("vault:team/service".to_string()),
                _ => unreachable!("closed percept field matrix"),
            }
            assert_eq!(
                guard_persisted_percept(&guarded),
                Err(RawCredentialInputDenied),
                "percept field must fail closed: {field}"
            );
        }
    }

    #[test]
    fn persisted_state_guard_denies_text_json_and_ambiguity_but_preserves_opaque_binary() {
        for (bytes, content_type) in [
            (b"Bearer x".as_slice(), Some("text/plain")),
            (
                br#"{"api_key":"synthetic"}"#.as_slice(),
                Some("application/json"),
            ),
            (b"{not-json}".as_slice(), Some("application/json")),
        ] {
            assert_eq!(
                guard_persisted_state(bytes, content_type, None),
                Err(RawCredentialInputDenied)
            );
        }

        let utf16 = "Bearer x"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            guard_persisted_state(&utf16, Some("application/octet-stream"), None),
            Err(RawCredentialInputDenied)
        );
        assert_eq!(
            guard_persisted_state(
                "x".repeat(CREDENTIAL_INGRESS_MAX_STRING_BYTES + 1)
                    .as_bytes(),
                Some("text/plain"),
                None
            ),
            Err(RawCredentialInputDenied)
        );

        assert_eq!(
            guard_persisted_state(&[0, 1, 0xff], Some("application/octet-stream"), None),
            Ok(())
        );
        assert_eq!(guard_persisted_state(&[1], None, None), Ok(()));
        assert_eq!(
            guard_persisted_state(
                br#"{"status":"ready","values":[1,2,3]}"#,
                Some("application/json; charset=utf-8"),
                Some("ordinary snapshot")
            ),
            Ok(())
        );
        assert_eq!(
            guard_persisted_state(
                b"ordinary state",
                Some("text/plain"),
                Some("password=C03_STATE_LABEL_CANARY")
            ),
            Err(RawCredentialInputDenied),
            "policy-selected state metadata must share the pre-persistence guard"
        );
    }

    #[test]
    fn raw_receipt_strings_are_screened_without_validating_authority() {
        let mut safe = request(action(serde_json::json!({"safe": true})));
        safe.authority_obligation_receipts = vec![ordinary_receipt()];
        assert_eq!(guard_action_request(&safe), Ok(()));

        for field in [
            "schema_version",
            "audience",
            "canonical_request_digest",
            "evidence_digest",
            "evidence_ref",
            "revocation_reason",
            "revocation_ref",
            "algorithm",
            "key_id",
            "validation_digest",
            "signature",
        ] {
            let mut receipt = ordinary_receipt();
            let canary = "Bearer synthetic-value".to_string();
            match field {
                "schema_version" => receipt.schema_version = canary,
                "audience" => receipt.audience = canary,
                "canonical_request_digest" => receipt.canonical_request_digest = canary,
                "evidence_digest" => receipt.evidence_digest = canary,
                "evidence_ref" => receipt.evidence_ref = Some(canary),
                "revocation_reason" => {
                    receipt.revocation = RevocationStatus::Revoked { reason: canary }
                }
                "revocation_ref" => receipt.revocation_ref = canary,
                "algorithm" => receipt.validation.algorithm = canary,
                "key_id" => receipt.validation.key_id = canary,
                "validation_digest" => receipt.validation.digest = canary,
                "signature" => receipt.validation.signature = canary,
                _ => unreachable!("closed receipt field matrix"),
            }
            let mut guarded = request(action(serde_json::json!({"safe": true})));
            guarded.authority_obligation_receipts = vec![receipt];
            assert_eq!(
                guard_action_request(&guarded),
                Err(RawCredentialInputDenied),
                "receipt field must deny independently: {field}"
            );
        }
    }

    #[test]
    fn raw_approval_evidence_strings_are_screened_without_granting_authority() {
        let mut safe = request(action(serde_json::json!({"safe": true})));
        safe.adapter = Some("fixture".to_string());
        safe.approval_evidence = Some(ordinary_approval_evidence(&safe));
        assert_eq!(guard_action_request(&safe), Ok(()));

        for field in ["schema_version", "action_name", "adapter", "reason"] {
            let mut guarded = safe.clone();
            let evidence = guarded
                .approval_evidence
                .as_mut()
                .expect("approval evidence");
            let canary = "Bearer synthetic-value".to_string();
            match field {
                "schema_version" => evidence.schema_version = canary,
                "action_name" => evidence.action_name = Some(canary),
                "adapter" => evidence.adapter = Some(canary),
                "reason" => evidence.reason = Some(canary),
                _ => unreachable!("closed approval evidence field matrix"),
            }
            assert_eq!(
                guard_action_request(&guarded),
                Err(RawCredentialInputDenied),
                "approval evidence field must deny independently: {field}"
            );
        }
    }

    #[test]
    fn approval_evidence_shares_the_action_request_cumulative_byte_budget() {
        let mut guarded = request(action(serde_json::json!({"safe": true})));
        let evidence = ordinary_approval_evidence(&guarded);
        let evidence_bytes = evidence.schema_version.len()
            + evidence.action_name.as_deref().map_or(0, str::len)
            + evidence.adapter.as_deref().map_or(0, str::len)
            + evidence.reason.as_deref().map_or(0, str::len);
        let mut remaining = CREDENTIAL_INGRESS_MAX_TOTAL_BYTES
            .checked_sub(evidence_bytes + guarded.action.name.len())
            .expect("evidence fixture fits request budget");
        let mut values = Vec::new();
        while remaining > 0 {
            let len = remaining.min(CREDENTIAL_INGRESS_MAX_STRING_BYTES);
            values.push(serde_json::Value::String("x".repeat(len)));
            remaining -= len;
        }
        guarded.action.params = serde_json::Value::Array(values);
        guarded.approval_evidence = Some(evidence);
        assert_eq!(guard_action_request(&guarded), Ok(()));

        guarded
            .approval_evidence
            .as_mut()
            .expect("approval evidence")
            .reason
            .as_mut()
            .expect("approval reason")
            .push('x');
        assert_eq!(
            guard_action_request(&guarded),
            Err(RawCredentialInputDenied)
        );
    }

    #[test]
    fn malformed_credential_coordinates_fail_closed_without_reflection() {
        let canary = "CREDENTIAL_GUARD_ERROR_CANARY";
        let guarded = action(serde_json::json!({
            "input": format!("https://example.invalid/?api%ZZkey={canary}")
        }));
        let error = guard_action(&guarded).expect_err("malformed URL must deny");
        assert_eq!(error.to_string(), RAW_CREDENTIAL_INPUT_DENIED);
        assert_eq!(format!("{error:?}"), RAW_CREDENTIAL_INPUT_DENIED);
        assert!(!error.to_string().contains(canary));
        assert!(!format!("{error:?}").contains(canary));

        for ambiguous in [
            "https://example.invalid/?field=%",
            "https://example.invalid/?field=%FF",
            "https://example.invalid/path%ZZ",
            "https://example.invalid/?field=Bearer%2520synthetic",
            "https://user%40example.invalid/",
            "https://first@second@example.invalid/",
            "https:///missing-authority",
            "1https://example.invalid/",
            "https://[vault]:8200/path",
            "https://[password]:1234/path",
            "https://[gggg]:8443/path",
            "https://[v1.]:8443/path",
            "https://[é]:8443/path",
            "https://:8443/path",
            "https://2001:db8::1/path",
            "https://example.invalid:99999/path",
            "https://example.invalid$password:1234/path",
            "https://example.invalid&vault:8200/path",
            "https://[v1.a!b:443/",
            "https://password%3A1234/path",
            "https://vault%3A8200/path",
            "https://%70assword%3A1234/path",
            "https://[::1]%3A8443/path",
            "https://%5B::1%5D%3A8443/path",
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": ambiguous}))),
                Err(RawCredentialInputDenied)
            );
        }
    }

    #[test]
    fn valid_authority_hosts_and_ports_are_not_assignments_or_references() {
        let authority =
            parse_url_authority("example.invalid:65535").expect("valid authority and port");
        assert_eq!(authority.screening_host, "example.invalid");
        assert!(authority.has_numeric_port);
        assert_eq!(credential_url_component("/path", false, 1), Ok(false));
        for value in [
            "https://auth:8443/path",
            "https://vault:8200/v1/sys/health",
            "https://example.invalid:65535/path",
            "https://example.invalid.:8443/path",
            "https://[::1]:8443/path",
            "https://[v1.fe80]:8443/path",
            "https://[fe80::1%25eth0]:8443/path",
            "https://[fe80::1%2512]:8443/path",
            "https://[fe80::1%25ab0]:8443/path",
            "https://[fe80::1%25%31%32]:8443/path",
        ] {
            assert_eq!(
                credential_assignment(value),
                Ok(false),
                "authority port must not become an assignment: {value}"
            );
            assert!(
                !secret_reference_form(&value.to_ascii_lowercase()),
                "authority host must not become a secret reference: {value}"
            );
            assert_eq!(
                credential_url(value, 0),
                Ok(false),
                "valid credential-free authority must remain clear: {value}"
            );
        }

        for opening in ["[", "%5B"] {
            for closing in ["]", "%5D"] {
                for delimiter in "!$&'()*+,;=:".chars() {
                    for rendered_delimiter in
                        [delimiter.to_string(), format!("%{:02X}", delimiter as u8)]
                    {
                        let value =
                            format!("https://{opening}v1.a{rendered_delimiter}b{closing}:443/");
                        assert_eq!(
                            guard_action(&action(serde_json::json!({"url": value}))),
                            Ok(()),
                            "raw/encoded IPvFuture forms must be equivalent"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn lexical_delimiter_matrix_is_complement_based_and_unicode_safe() {
        let provider = synthetic_provider_token("ghp_", 36);
        for delimiter in ('!'..='~').filter(|character| character.is_ascii_punctuation()) {
            for value in [
                format!("safe{delimiter}Bearer x{delimiter}"),
                format!("safe{delimiter}Basic dTpw{delimiter}next"),
                format!("safe{delimiter}token=synthetic"),
                format!("safe{delimiter}{provider}{delimiter}"),
            ] {
                assert_eq!(
                    guard_action(&action(serde_json::json!({"input": value}))),
                    Err(RawCredentialInputDenied),
                    "ASCII punctuation {delimiter:?} must delimit credential syntax"
                );
            }

            let encoded_delimiter = format!("%{:02X}", delimiter as u8);
            let encoded_query = format!(
                "https://example.invalid/?safe{encoded_delimiter}%42earer%20x{encoded_delimiter}"
            );
            assert_eq!(
                guard_action(&action(serde_json::json!({"url": encoded_query}))),
                Err(RawCredentialInputDenied),
                "encoded ASCII punctuation {delimiter:?} must delimit credential syntax"
            );
        }

        for (delimiter, encoded_delimiter) in [
            ('—', "%E2%80%94"),
            ('。', "%E3%80%82"),
            ('\u{0301}', "%CC%81"),
        ] {
            for value in [
                format!("safe{delimiter}Bearer x{delimiter}"),
                format!("safe{delimiter}Basic dTpw{delimiter}next"),
                format!("safe{delimiter}token=synthetic"),
                format!("safe{delimiter}{provider}{delimiter}"),
            ] {
                assert_eq!(
                    guard_action(&action(serde_json::json!({"input": value}))),
                    Err(RawCredentialInputDenied),
                    "Unicode punctuation {delimiter:?} must delimit credential syntax"
                );
            }
            let encoded_query = format!(
                "https://example.invalid/?safe{encoded_delimiter}%42earer%20x{encoded_delimiter}"
            );
            assert_eq!(
                guard_action(&action(serde_json::json!({"url": encoded_query}))),
                Err(RawCredentialInputDenied),
                "encoded Unicode punctuation {delimiter:?} must delimit credential syntax"
            );
        }

        for value in [
            "safeéBearer x".to_string(),
            "safeétoken prose".to_string(),
            format!("safe漢{provider}"),
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": value}))),
                Ok(()),
                "Unicode alphanumeric adjacency must not create a delimiter"
            );
        }
    }

    #[test]
    fn non_ascii_confusable_and_malformed_normalized_keys_fail_closed() {
        for key in [
            "pаssword",
            "ＡＰＩ＿ＫＥＹ",
            "auth\u{200d}orization",
            "api%ZZkey",
            "api%FFkey",
            "api%255Fkey",
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({key: "synthetic-value"}))),
                Err(RawCredentialInputDenied),
                "ambiguous key must fail closed"
            );
        }
    }

    #[test]
    fn depth_budget_accepts_cap_and_denies_cap_plus_one() {
        let mut at_cap = serde_json::Value::Null;
        for _ in 0..CREDENTIAL_INGRESS_MAX_DEPTH {
            at_cap = serde_json::json!([at_cap]);
        }
        assert_eq!(guard_action(&action(at_cap.clone())), Ok(()));
        assert_eq!(
            guard_action(&action(serde_json::json!([at_cap]))),
            Err(RawCredentialInputDenied)
        );
    }

    #[test]
    fn node_budget_accepts_cap_and_denies_cap_plus_one() {
        // Action envelope + action name + params array root consume three nodes.
        let at_cap = vec![serde_json::Value::Null; CREDENTIAL_INGRESS_MAX_NODES - 3];
        assert_eq!(
            guard_action(&action(serde_json::Value::Array(at_cap))),
            Ok(())
        );

        let over_cap = vec![serde_json::Value::Null; CREDENTIAL_INGRESS_MAX_NODES - 2];
        assert_eq!(
            guard_action(&action(serde_json::Value::Array(over_cap))),
            Err(RawCredentialInputDenied)
        );
    }

    #[test]
    fn individual_string_budget_accepts_cap_and_denies_cap_plus_one() {
        assert_eq!(
            guard_action(&action(serde_json::json!({
                "input": "x".repeat(CREDENTIAL_INGRESS_MAX_STRING_BYTES)
            }))),
            Ok(())
        );
        assert_eq!(
            guard_action(&action(serde_json::json!({
                "input": "x".repeat(CREDENTIAL_INGRESS_MAX_STRING_BYTES + 1)
            }))),
            Err(RawCredentialInputDenied)
        );
    }

    #[test]
    fn cumulative_byte_budget_accepts_cap_and_denies_cap_plus_one() {
        // The action name consumes seven bytes. Array strings consume the rest.
        let baseline = "inspect".len();
        let build = |bytes: usize| {
            let mut remaining = bytes - baseline;
            let mut values = Vec::new();
            while remaining > 0 {
                let len = remaining.min(CREDENTIAL_INGRESS_MAX_STRING_BYTES);
                values.push(serde_json::Value::String("x".repeat(len)));
                remaining -= len;
            }
            action(serde_json::Value::Array(values))
        };
        assert_eq!(
            guard_action(&build(CREDENTIAL_INGRESS_MAX_TOTAL_BYTES)),
            Ok(())
        );
        assert_eq!(
            guard_action(&build(CREDENTIAL_INGRESS_MAX_TOTAL_BYTES + 1)),
            Err(RawCredentialInputDenied)
        );
    }

    #[test]
    fn ordinary_structured_actions_remain_accepted() {
        let mut ordinary = action(serde_json::json!({
            "url": "https://example.invalid/caf%C3%A9?q=hello%20world&label=50%25",
            "encoded_url": "https%3A%2F%2Fexample.invalid%2Freports%3Flimit%3D10",
            "headers": {"accept": "application/json"},
            "display%2Dname": "ordinary",
            "path": "reports/output.json",
            "model": {"tokenizer": "gpt2", "token_count": 42},
            "status": "status = ready",
            "email": "user@example.invalid"
        }));
        ordinary.side_effect_class = SideEffectClass::Network;
        ordinary.cost_estimate = Some(CostEstimate {
            units: "milliseconds".to_string(),
            amount: 10.0,
        });
        ordinary.required_permissions = vec!["http.read".to_string()];
        assert_eq!(guard_action(&ordinary), Ok(()));
    }

    #[test]
    fn request_guard_checks_routing_but_not_typed_identity_fields() {
        let mut request = request(action(serde_json::json!({"safe": true})));
        request.adapter = Some("Bearer synthetic".to_string());
        assert_eq!(
            guard_action_request(&request),
            Err(RawCredentialInputDenied)
        );

        request.adapter = Some("fixture".to_string());
        request.satisfied_preconditions = vec!["api_key=synthetic".to_string()];
        assert_eq!(
            guard_action_request(&request),
            Err(RawCredentialInputDenied)
        );

        request.satisfied_preconditions = vec!["safe".to_string()];
        request.quota_usage = QuotaUsage::single_action();
        assert_eq!(guard_action_request(&request), Ok(()));
    }

    #[test]
    fn denial_projection_and_outcome_are_constant_and_safe() {
        let projection = raw_credential_denied_action();
        assert_eq!(guard_action(&projection), Ok(()));
        let encoded = serde_json::to_string(&projection).expect("projection serializes");
        assert_eq!(encoded.matches(RAW_CREDENTIAL_INPUT_DENIED).count(), 1);

        let outcome = raw_credential_denied_outcome(crate::ActionId::new());
        assert_eq!(outcome.status, ActionStatus::Denied);
        assert_eq!(
            outcome.verification.reasons,
            vec![RAW_CREDENTIAL_INPUT_DENIED.to_string()]
        );
        assert_eq!(outcome.error.as_deref(), Some(RAW_CREDENTIAL_INPUT_DENIED));
    }
}
