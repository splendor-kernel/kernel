//! Bounded pre-persistence denial for raw credential-bearing actions.
//!
//! This guard is deliberately denial-only. It does not recognize a generic
//! JSON secret reference as authority and cannot resolve, deliver, or authorize
//! credential material.

use crate::{ActionOutcome, ActionRequest, ActionStatus};
use splendor_types::{
    Action, AuthorityObligationReceipt, RevocationStatus, SideEffectClass, VerificationResult,
};
use std::{fmt, str};
use time::OffsetDateTime;

/// Stable, non-reflecting reason returned for every raw credential denial.
pub const RAW_CREDENTIAL_INPUT_DENIED: &str = "raw_credential_input_denied";

/// Maximum nesting depth accepted in `Action.params` (root depth is zero).
pub const CREDENTIAL_INGRESS_MAX_DEPTH: usize = 16;
/// Maximum number of action envelope, value, and string nodes inspected.
pub const CREDENTIAL_INGRESS_MAX_NODES: usize = 2_048;
/// Maximum UTF-8 byte length accepted for one inspected string or object key.
pub const CREDENTIAL_INGRESS_MAX_STRING_BYTES: usize = 16 * 1024;
/// Maximum cumulative UTF-8 bytes inspected across strings and object keys.
pub const CREDENTIAL_INGRESS_MAX_TOTAL_BYTES: usize = 64 * 1024;

const CREDENTIAL_INGRESS_MAX_URL_NESTING: usize = 4;

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

/// Screens the untrusted action/routing portion of an action request.
///
/// Typed caller authentication and authority decisions are intentionally not
/// scanned as workload input. Raw receipt strings are content-screened before
/// their owning Authority validator runs; screening does not make them valid or
/// authorizing.
pub fn guard_action_request(request: &ActionRequest) -> Result<(), RawCredentialInputDenied> {
    guard_action_routing_and_receipts(
        &request.action,
        request.adapter.as_deref(),
        &request.satisfied_preconditions,
        &request.authority_obligation_receipts,
    )
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
            }
            serde_json::Value::String(value) => self.scan_string_without_node(value)?,
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            }
        }
        Ok(())
    }

    fn scan_key(&mut self, key: &str) -> Result<(), RawCredentialInputDenied> {
        self.charge_string_bytes(key)?;
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

fn normalized_credential_key(key: &str) -> Result<bool, RawCredentialInputDenied> {
    let decoded;
    let key = if key.as_bytes().contains(&b'%') {
        decoded = percent_decode(key)?;
        decoded.as_str()
    } else {
        key
    };
    if !key.is_ascii() || key.as_bytes().contains(&b'%') {
        return Err(RawCredentialInputDenied);
    }
    let normalized = compact_ascii(key);
    Ok(matches!(
        normalized.as_str(),
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
    ))
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
    if contains_percent_escape(trimmed) && !url_coordinate_candidate(trimmed) {
        let decoded = percent_decode(trimmed)?;
        if contains_percent_escape(&decoded) {
            return Err(RawCredentialInputDenied);
        }
        if credential_content_bounded(&decoded, url_nesting.saturating_add(1))? {
            return Ok(true);
        }
    }
    let lowercase = trimmed.to_ascii_lowercase();

    if authorization_form(trimmed)
        || private_key_block(&lowercase)
        || provider_key_prefix(trimmed)
        || secret_reference_form(&lowercase)
        || credential_assignment(trimmed)?
        || credential_url(trimmed, url_nesting)?
        || credential_dsn_without_scheme(trimmed)
    {
        return Ok(true);
    }
    Ok(false)
}

fn authorization_form(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    ["bearer", "basic"].iter().any(|scheme| {
        lowercase.match_indices(scheme).any(|(index, _)| {
            if index > 0 {
                let before = lowercase.as_bytes()[index - 1];
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
            let token_length = line
                .bytes()
                .take_while(|byte| authorization_token_byte(*byte, scheme))
                .count();
            if token_length == 0 {
                return false;
            }
            let token = &line[..token_length];
            let trailing = line[token_length..].trim();
            trailing.bytes().all(is_authorization_closing_delimiter)
                && if *scheme == "basic" {
                    plausible_basic_token(token)
                } else {
                    plausible_bearer_token(token)
                }
        })
    })
}

fn authorization_scheme_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'"' | b'\'' | b'=' | b':' | b',' | b';' | b'(' | b'[' | b'{'
        )
}

fn authorization_token_byte(byte: u8, scheme: &str) -> bool {
    byte.is_ascii_alphanumeric()
        || if scheme == "basic" {
            matches!(byte, b'+' | b'/' | b'=')
        } else {
            matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        }
}

fn is_authorization_closing_delimiter(byte: u8) -> bool {
    matches!(byte, b'"' | b'\'' | b'}' | b']' | b')' | b',' | b';')
}

fn plausible_basic_token(token: &str) -> bool {
    const MINIMUM_BASIC_TOKEN_BYTES: usize = 4;
    const MAXIMUM_AUTHORIZATION_TOKEN_BYTES: usize = 4 * 1024;

    if !(MINIMUM_BASIC_TOKEN_BYTES..=MAXIMUM_AUTHORIZATION_TOKEN_BYTES).contains(&token.len())
        || !token.len().is_multiple_of(4)
    {
        return false;
    }
    basic_base64_decodes_with_colon(token.as_bytes())
}

fn plausible_bearer_token(token: &str) -> bool {
    const MINIMUM_BEARER_TOKEN_BYTES: usize = 1;
    const MAXIMUM_AUTHORIZATION_TOKEN_BYTES: usize = 4 * 1024;

    if !(MINIMUM_BEARER_TOKEN_BYTES..=MAXIMUM_AUTHORIZATION_TOKEN_BYTES).contains(&token.len()) {
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
        provider_token_profile(
            "sk-",
            20,
            256,
            false,
            ProviderTokenAlphabet::AlphanumericDashUnderscore,
        ),
        provider_token_profile(
            "sk_",
            20,
            256,
            false,
            ProviderTokenAlphabet::AlphanumericDashUnderscore,
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
        if index > 0 && !provider_token_start_boundary(value.as_bytes()[index - 1]) {
            return false;
        }
        let suffix = &value[index + profile.prefix.len()..];
        let token_suffix_len = suffix
            .bytes()
            .take_while(|byte| provider_suffix_byte(*byte, profile.alphabet))
            .count();
        if !(profile.minimum_suffix..=profile.maximum_suffix).contains(&token_suffix_len) {
            return false;
        }
        let token_end = index + profile.prefix.len() + token_suffix_len;
        token_end == value.len() || provider_token_end_boundary(value.as_bytes()[token_end])
    })
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

fn provider_token_start_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'"' | b'\''
                | b'='
                | b':'
                | b','
                | b';'
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'/'
        )
}

fn provider_token_end_boundary(byte: u8) -> bool {
    provider_token_start_boundary(byte) || matches!(byte, b'/' | b'?' | b'#' | b'&')
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
                let before = lowercase.as_bytes()[index - 1];
                if before.is_ascii_alphanumeric() || matches!(before, b'_' | b'-') {
                    return false;
                }
            }
            let remainder = &lowercase[index + prefix.len()..];
            let payload_length = remainder
                .bytes()
                .take_while(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(*byte, b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'~')
                })
                .count();
            payload_length > 0
                && payload_length <= 2_048
                && (payload_length == remainder.len()
                    || reference_boundary(remainder.as_bytes()[payload_length]))
        })
    })
}

fn reference_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'"' | b'\'' | b',' | b';' | b')' | b']' | b'}' | b'&' | b'#' | b'?'
        )
}

fn credential_assignment(value: &str) -> Result<bool, RawCredentialInputDenied> {
    let bytes = value.as_bytes();
    for (separator, byte) in bytes.iter().copied().enumerate() {
        if !matches!(byte, b'=' | b':') {
            continue;
        }

        let mut start = separator;
        while start > 0
            && !matches!(
                bytes[start - 1],
                b'=' | b':' | b',' | b';' | b'{' | b'[' | b'(' | b'\r' | b'\n'
            )
        {
            start -= 1;
        }
        let segment = value[start..separator].trim();
        for candidate in assignment_key_suffixes(segment) {
            if normalized_credential_key(candidate)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
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
        if !character.is_ascii_whitespace() && !matches!(character, '"' | '\'') {
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
        let end = value[separator + 3..]
            .char_indices()
            .find_map(|(index, character)| {
                url_candidate_terminator(character).then_some(separator + 3 + index)
            })
            .unwrap_or(value.len());
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
        if contains_percent_escape(&decoded) {
            return Err(RawCredentialInputDenied);
        }
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
        if authority.contains('@') || decoded_authority.contains('@') {
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
        for field in query.split(['&', ';']) {
            if field.is_empty() {
                continue;
            }
            let (raw_key, raw_value) = field.split_once('=').unwrap_or((field, ""));
            let key = percent_decode_form(raw_key)?;
            if contains_percent_escape(&key) || normalized_credential_key(&key)? {
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
    credential_content_bounded(&decoded, url_nesting)
}

fn unambiguous_utf8_body(bytes: &[u8]) -> Option<&str> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return None;
    }
    let text = str::from_utf8(bytes).ok()?;
    if text.chars().any(|character| {
        character == '\u{feff}'
            || character.is_control() && !matches!(character, '\t' | '\n' | '\r')
    }) {
        return None;
    }
    Some(text)
}

fn url_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

fn url_candidate_terminator(character: char) -> bool {
    character.is_ascii_whitespace()
        || matches!(character, '"' | '\'' | '<' | '>' | ')' | ']' | '}' | ',')
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
        AgentId, AuthorityDecisionId, AuthorityObligationId, AuthorityObligationKind,
        AuthorityObligationReceiptId, AuthorityObligationReceiptValidation,
        AuthorityObligationReceiptValidationKind, CostEstimate, PrincipalId, QuotaUsage, RunId,
        TenantId,
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
            ("sk-", 20),
            ("sk_", 20),
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
            "models/Basic dTpw",
            "models/sk-learn",
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
            "https://example.invalid/form?value=Bearer+short",
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
        assert_eq!(
            guard_credential_capable_value(&serde_json::json!({
                "nested": [{"secretKeyRef": "fixture"}]
            })),
            Err(RawCredentialInputDenied)
        );
        assert_eq!(
            guard_credential_capable_value(&serde_json::json!({
                "nested": [{"zone_ref": "zone_a"}],
                "status": "ready"
            })),
            Ok(())
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
        ] {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": ambiguous}))),
                Err(RawCredentialInputDenied)
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
