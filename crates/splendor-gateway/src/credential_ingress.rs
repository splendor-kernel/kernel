//! Bounded pre-persistence denial for raw credential-bearing actions.
//!
//! This guard is deliberately denial-only. It does not recognize a generic
//! JSON secret reference as authority and cannot resolve, deliver, or authorize
//! credential material.

use crate::{ActionOutcome, ActionRequest, ActionStatus};
use splendor_types::{Action, SideEffectClass, VerificationResult};
use std::fmt;
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
    guard_action_routing(action, None, &[])
}

/// Screens an action plus untrusted adapter/precondition routing metadata.
pub fn guard_action_routing(
    action: &Action,
    adapter: Option<&str>,
    satisfied_preconditions: &[String],
) -> Result<(), RawCredentialInputDenied> {
    let mut scanner = CredentialIngressScanner::default();
    scanner.scan_action(action)?;
    if let Some(adapter) = adapter {
        scanner.scan_string(adapter)?;
    }
    for precondition in satisfied_preconditions {
        scanner.scan_string(precondition)?;
    }
    Ok(())
}

/// Screens the untrusted action/routing portion of an action request.
///
/// Typed caller authentication and authority evidence are intentionally not
/// scanned as workload input. They remain governed by their owning validators.
pub fn guard_action_request(request: &ActionRequest) -> Result<(), RawCredentialInputDenied> {
    guard_action_routing(
        &request.action,
        request.adapter.as_deref(),
        &request.satisfied_preconditions,
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
        if normalized_credential_key(key)? {
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
            | "pgpassfile"
            | "mysqlpwd"
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
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    if contains_percent_escape(trimmed) && !url_coordinate_candidate(trimmed) {
        let decoded = percent_decode(trimmed)?;
        if contains_percent_escape(&decoded) {
            return Err(RawCredentialInputDenied);
        }
        let lowercase = decoded.to_ascii_lowercase();
        if authorization_form(&lowercase)
            || private_key_block(&lowercase)
            || provider_key_prefix(&decoded)
            || secret_reference_form(&lowercase)
            || credential_assignment(&decoded)?
            || credential_url(&decoded)?
            || credential_dsn_without_scheme(&decoded)
        {
            return Ok(true);
        }
    }
    let lowercase = trimmed.to_ascii_lowercase();

    if authorization_form(&lowercase)
        || private_key_block(&lowercase)
        || provider_key_prefix(trimmed)
        || secret_reference_form(&lowercase)
        || credential_assignment(trimmed)?
        || credential_url(trimmed)?
        || credential_dsn_without_scheme(trimmed)
    {
        return Ok(true);
    }
    Ok(false)
}

fn authorization_form(lowercase: &str) -> bool {
    let value = lowercase.trim_start();
    ["bearer", "basic"].iter().any(|scheme| {
        value == *scheme
            || value
                .strip_prefix(scheme)
                .is_some_and(|rest| rest.chars().next().is_some_and(char::is_whitespace))
            || value.contains(&format!("authorization: {scheme}"))
            || value.contains(&format!("authorization={scheme}"))
            || value.contains(&format!("proxy-authorization: {scheme}"))
    })
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

fn provider_key_prefix(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    let prefixed = [
        ("gho_", 8_usize),
        ("ghp_", 8),
        ("github_pat_", 8),
        ("xoxb-", 8),
        ("xoxp-", 8),
        ("glpat-", 8),
        ("npm_", 8),
        ("pypi-", 8),
        ("hf_", 8),
        ("dop_v1_", 8),
        ("sg.", 8),
        ("sk-", 8),
        ("sk_", 8),
        ("aiza", 16),
    ]
    .iter()
    .any(|(prefix, minimum_suffix)| contains_prefixed_token(&lowercase, prefix, *minimum_suffix));
    prefixed
        || ["AKIA", "ASIA"]
            .iter()
            .any(|prefix| contains_prefixed_token(value, prefix, 12))
}

fn contains_prefixed_token(value: &str, prefix: &str, minimum_suffix: usize) -> bool {
    value.match_indices(prefix).any(|(index, _)| {
        let boundary_before = index == 0
            || !value.as_bytes()[index - 1].is_ascii_alphanumeric()
                && value.as_bytes()[index - 1] != b'_';
        if !boundary_before {
            return false;
        }
        let suffix = &value[index + prefix.len()..];
        let token_suffix_len = suffix
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
            .count();
        token_suffix_len >= minimum_suffix
    })
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
        lowercase
            .strip_prefix(prefix)
            .is_some_and(|remainder| !remainder.trim().is_empty())
    })
}

fn credential_assignment(value: &str) -> Result<bool, RawCredentialInputDenied> {
    let bytes = value.as_bytes();
    for (separator, byte) in bytes.iter().copied().enumerate() {
        if !matches!(byte, b'=' | b':') {
            continue;
        }

        let mut end = separator;
        while end > 0
            && (bytes[end - 1].is_ascii_whitespace() || matches!(bytes[end - 1], b'"' | b'\''))
        {
            end -= 1;
        }
        let mut start = end;
        while start > 0
            && (bytes[start - 1].is_ascii_alphanumeric()
                || matches!(bytes[start - 1], b'_' | b'-' | b'.'))
        {
            start -= 1;
        }
        let key = &value[start..end];
        if !key.is_empty() && normalized_credential_key(key)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn credential_url(value: &str) -> Result<bool, RawCredentialInputDenied> {
    let scheme_separator = value.find("://");
    let relative_authority = value.starts_with("//");
    let query_only = value.starts_with('/') && value.contains('?');
    if scheme_separator.is_none() && !relative_authority && !query_only {
        return Ok(false);
    }
    if let Some(separator) = scheme_separator {
        let scheme = &value[..separator];
        if !valid_url_scheme(scheme) {
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
    }

    let Some(query_start) = value.find('?') else {
        return Ok(false);
    };
    let query = value[query_start + 1..]
        .split('#')
        .next()
        .unwrap_or_default();
    for field in query.split(['&', ';']) {
        if field.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = field.split_once('=').unwrap_or((field, ""));
        let key = percent_decode(raw_key)?;
        if normalized_credential_key(&key)? {
            return Ok(true);
        }
        let decoded_value = percent_decode(raw_value)?;
        let lower_value = decoded_value.to_ascii_lowercase();
        if authorization_form(&lower_value)
            || private_key_block(&lower_value)
            || provider_key_prefix(&decoded_value)
            || secret_reference_form(&lower_value)
            || credential_assignment(&decoded_value)?
        {
            return Ok(true);
        }
    }
    Ok(false)
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
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
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
    use splendor_types::{AgentId, CostEstimate, QuotaUsage, RunId, TenantId};

    fn action(params: serde_json::Value) -> Action {
        Action {
            name: "inspect".to_string(),
            params,
            side_effect_class: SideEffectClass::ReadOnly,
            cost_estimate: None,
            required_permissions: Vec::new(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
        }
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
            "AZURE_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "PGPASSWORD",
            "MYSQL_PWD",
            "DOCKER_AUTH_CONFIG",
            "HF_TOKEN",
            "secret_ref_id",
        ] {
            let params = serde_json::json!({"outer": [{key: "synthetic-value"}]});
            assert_eq!(guard_action(&action(params)), Err(RawCredentialInputDenied));
        }
    }

    #[test]
    fn content_matrix_denies_auth_private_provider_ref_url_and_dsn_forms() {
        let mut values = vec![
            "Bearer synthetic-value".to_string(),
            "Bearer%20synthetic-value".to_string(),
            "Basic c3ludGhldGlj".to_string(),
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----".to_string(),
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
        for (prefix, suffix) in [
            ("gho_", "syntheticcredential"),
            ("ghp_", "syntheticcredential"),
            ("github_pat_", "syntheticcredential"),
            ("xoxb-", "syntheticcredential"),
            ("xoxp-", "syntheticcredential"),
            ("glpat-", "synthetic"),
            ("npm_", "synthetic"),
            ("pypi-", "synthetic"),
            ("hf_", "synthetic"),
            ("dop_v1_", "synthetic"),
            ("SG.", "synthetic"),
            ("sk_", "syntheticcredential"),
            ("AKIA", "SYNTHETICVALUE"),
        ] {
            values.push(format!("{prefix}{suffix}"));
        }
        for value in values {
            assert_eq!(
                guard_action(&action(serde_json::json!({"input": value}))),
                Err(RawCredentialInputDenied)
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
