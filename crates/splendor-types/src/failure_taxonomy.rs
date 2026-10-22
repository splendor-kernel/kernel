//! Stable error and denial taxonomy primitives.
//!
//! These types are intentionally behavior-light: they make failures
//! machine-actionable without turning provider text into authority. Provider
//! detail is diagnostic only, bounded, and sanitized before serialization.

use crate::ids::TraceEventId;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use thiserror::Error;

/// Stable category labels required by the FND-004 error/denial taxonomy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// Caller supplied invalid input.
    InvalidInput,
    /// Payload, schema, version, or compatibility mismatch.
    IncompatibleSchema,
    /// Caller or work-order identity could not be authenticated.
    Unauthenticated,
    /// Authenticated caller/work order lacks authority for this operation.
    Unauthorized,
    /// Credential, work order, policy, approval, or authority was revoked.
    Revoked,
    /// Credential, work order, policy, approval, or authority expired.
    Expired,
    /// Quota or resource budget was exceeded.
    QuotaExceeded,
    /// Required service, verifier, worker, gateway, or dependency is unavailable.
    Unavailable,
    /// Operation conflicts with another lifecycle/state transition.
    Conflict,
    /// Request used a stale state head, lease, checkpoint, or version.
    StaleHead,
    /// Safety, physical, governance, or high-risk policy denied the operation.
    Unsafe,
    /// The system cannot classify the failure safely.
    Uncertain,
    /// Protected data, secret, eval, artifact, or privacy scope was denied.
    ProtectedDataDenial,
    /// Signature, hash, lineage, receipt, or tamper-evidence check failed.
    IntegrityFailure,
    /// Operation timed out.
    Timeout,
    /// Operation was cancelled before normal completion.
    Cancellation,
    /// Work was preempted by scheduler, lease, or policy control.
    Preemption,
    /// Worker process/node failed.
    WorkerFailure,
    /// Driver/adapter/provider failed.
    DriverFailure,
    /// Postcondition verification failed after execution.
    PostconditionFailure,
    /// Kernel/runtime invariant was violated.
    InternalInvariantViolation,
}

impl ErrorCategory {
    /// Returns the stable serialized label for this category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::IncompatibleSchema => "incompatible_schema",
            Self::Unauthenticated => "unauthenticated",
            Self::Unauthorized => "unauthorized",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::QuotaExceeded => "quota_exceeded",
            Self::Unavailable => "unavailable",
            Self::Conflict => "conflict",
            Self::StaleHead => "stale_head",
            Self::Unsafe => "unsafe",
            Self::Uncertain => "uncertain",
            Self::ProtectedDataDenial => "protected_data_denial",
            Self::IntegrityFailure => "integrity_failure",
            Self::Timeout => "timeout",
            Self::Cancellation => "cancellation",
            Self::Preemption => "preemption",
            Self::WorkerFailure => "worker_failure",
            Self::DriverFailure => "driver_failure",
            Self::PostconditionFailure => "postcondition_failure",
            Self::InternalInvariantViolation => "internal_invariant_violation",
        }
    }
}

/// Stable retry disposition for a failed or denied operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    /// Do not retry this request automatically.
    NotRetryable,
    /// Retry is permitted only with the same idempotency key/attempt identity.
    RetryWithSameIdempotencyKey,
    /// The operation requires fresh/scoped authorization before retry.
    RetryWithNewAuthorization,
}

impl RetryClass {
    /// Returns the stable serialized label for this retry class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRetryable => "not_retryable",
            Self::RetryWithSameIdempotencyKey => "retry_with_same_idempotency_key",
            Self::RetryWithNewAuthorization => "retry_with_new_authorization",
        }
    }
}

/// Certainty about whether a side effect happened.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectCertainty {
    /// No side effect was attempted or possible for this failure.
    None,
    /// The effect state is known by receipt, verifier, or trusted outcome.
    Known,
    /// The effect state is unknown and must not be treated as safely retryable.
    Uncertain,
}

impl EffectCertainty {
    /// Returns the stable serialized label for this effect certainty.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Known => "known",
            Self::Uncertain => "uncertain",
        }
    }
}

/// Stable machine-readable reason code.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReasonCode(String);

impl ReasonCode {
    /// Creates a validated stable reason code.
    pub fn try_new(value: impl Into<String>) -> Result<Self, ReasonCodeError> {
        let value = value.into();
        validate_reason_code(&value)?;
        Ok(Self(value))
    }

    /// Creates a reason code from a compile-time constant used by kernel code.
    ///
    /// Constants in this repository are validated in tests. Invalid constants
    /// fall back to normal debug assertions during development instead of
    /// panicking in runtime paths.
    pub fn from_static(value: &'static str) -> Self {
        debug_assert!(validate_reason_code(value).is_ok());
        Self(value.to_string())
    }

    /// Returns the stable reason code string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for ReasonCode {
    type Error = ReasonCodeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<ReasonCode> for String {
    fn from(value: ReasonCode) -> Self {
        value.0
    }
}

/// Reason-code validation failures.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReasonCodeError {
    /// Reason code was empty after trimming.
    #[error("reason code is empty")]
    Empty,
    /// Reason code exceeded the stable bound.
    #[error("reason code exceeds {max} bytes")]
    TooLong { max: usize },
    /// Reason code contained a character outside the stable code alphabet.
    #[error("reason code contains invalid character {character:?}")]
    InvalidCharacter { character: char },
}

/// Diagnostic-only provider or adapter detail.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProviderDetail {
    /// Sanitized provider/adapter label. This field never grants authority.
    #[serde(deserialize_with = "deserialize_provider_label")]
    provider: String,
    /// Sanitized provider-specific code, when available.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_provider_code"
    )]
    provider_code: Option<String>,
    /// Bounded sanitized summary. Raw provider dumps, credentials, and tokens do
    /// not belong here.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_summary"
    )]
    safe_summary: Option<String>,
}

impl ProviderDetail {
    /// Creates diagnostic provider detail with a sanitized provider label.
    pub fn new(provider: impl AsRef<str>) -> Self {
        Self {
            provider: sanitize_label(provider.as_ref(), "unknown_provider"),
            provider_code: None,
            safe_summary: None,
        }
    }

    /// Adds a sanitized provider code.
    pub fn with_provider_code(mut self, provider_code: impl AsRef<str>) -> Self {
        let provider_code = sanitize_label(provider_code.as_ref(), "unknown_code");
        self.provider_code = Some(provider_code);
        self
    }

    /// Adds a bounded, sanitized diagnostic summary.
    pub fn with_safe_summary(mut self, summary: impl AsRef<str>) -> Self {
        if let Some(summary) = sanitize_summary(summary.as_ref()) {
            self.safe_summary = Some(summary);
        }
        self
    }

    /// Returns the sanitized provider/adapter label.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the sanitized provider code, when present.
    pub fn provider_code(&self) -> Option<&str> {
        self.provider_code.as_deref()
    }

    /// Returns the bounded sanitized summary, when present.
    pub fn safe_summary(&self) -> Option<&str> {
        self.safe_summary.as_deref()
    }
}

/// Canonical error/denial taxonomy payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ErrorTaxonomy {
    /// Stable category label.
    pub category: ErrorCategory,
    /// Stable machine-readable reason code.
    pub reason_code: ReasonCode,
    /// Retry disposition.
    pub retry_class: RetryClass,
    /// Certainty about whether a side effect happened.
    pub effect_certainty: EffectCertainty,
    /// Optional causal trace event reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_event_id: Option<TraceEventId>,
    /// Optional diagnostic-only provider detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_detail: Option<ProviderDetail>,
}

impl ErrorTaxonomy {
    /// Builds a taxonomy payload from already-classified values.
    pub fn new(
        category: ErrorCategory,
        reason_code: ReasonCode,
        retry_class: RetryClass,
        effect_certainty: EffectCertainty,
    ) -> Self {
        Self {
            category,
            reason_code,
            retry_class,
            effect_certainty,
            causal_event_id: None,
            provider_detail: None,
        }
    }

    /// Builds a taxonomy payload and validates the reason code.
    pub fn try_new(
        category: ErrorCategory,
        reason_code: impl Into<String>,
        retry_class: RetryClass,
        effect_certainty: EffectCertainty,
    ) -> Result<Self, ReasonCodeError> {
        Ok(Self::new(
            category,
            ReasonCode::try_new(reason_code)?,
            retry_class,
            effect_certainty,
        ))
    }

    /// Attaches a causal trace event reference.
    pub fn with_causal_event(mut self, causal_event_id: TraceEventId) -> Self {
        self.causal_event_id = Some(causal_event_id);
        self
    }

    /// Attaches diagnostic-only provider detail.
    pub fn with_provider_detail(mut self, provider_detail: ProviderDetail) -> Self {
        self.provider_detail = Some(provider_detail);
        self
    }

    /// Classifies an untyped provider failure as non-retryable with uncertain
    /// effect until a narrower adapter/provider mapping is added.
    pub fn unknown_provider_failure(provider: impl AsRef<str>, safe_summary: Option<&str>) -> Self {
        let detail = provider_detail(provider, None, safe_summary);
        Self::new(
            ErrorCategory::DriverFailure,
            ReasonCode::from_static(UNKNOWN_PROVIDER_FAILURE_REASON),
            RetryClass::NotRetryable,
            EffectCertainty::Uncertain,
        )
        .with_provider_detail(detail)
    }

    /// Classifies an untyped adapter failure as non-retryable with uncertain
    /// effect until a narrower adapter mapping is added.
    pub fn unknown_adapter_failure(adapter: impl AsRef<str>, safe_summary: Option<&str>) -> Self {
        let detail = provider_detail(adapter, None, safe_summary);
        Self::new(
            ErrorCategory::DriverFailure,
            ReasonCode::from_static(UNKNOWN_ADAPTER_FAILURE_REASON),
            RetryClass::NotRetryable,
            EffectCertainty::Uncertain,
        )
        .with_provider_detail(detail)
    }

    /// Classifies a known provider/adapter unavailable path where no side effect
    /// was attempted and retry may use the same idempotency key.
    pub fn unavailable_before_execution(reason_code: &'static str) -> Self {
        Self::new(
            ErrorCategory::Unavailable,
            ReasonCode::from_static(reason_code),
            RetryClass::RetryWithSameIdempotencyKey,
            EffectCertainty::None,
        )
    }
}

/// Reason used for unclassified provider failures.
pub const UNKNOWN_PROVIDER_FAILURE_REASON: &str = "unknown_provider_failure";
/// Reason used for unclassified adapter failures.
pub const UNKNOWN_ADAPTER_FAILURE_REASON: &str = "unknown_adapter_failure";

const MAX_REASON_CODE_BYTES: usize = 128;
const MAX_LABEL_CHARS: usize = 64;
const MAX_SUMMARY_CHARS: usize = 256;
const SENSITIVE_SUMMARY_MARKERS: &[&str] = &[
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "client_secret",
    "credential",
    "password",
    "passwd",
    "private_key",
    "secret",
    "token",
];

fn provider_detail(
    provider: impl AsRef<str>,
    provider_code: Option<&str>,
    safe_summary: Option<&str>,
) -> ProviderDetail {
    let mut detail = ProviderDetail::new(provider);
    if let Some(provider_code) = provider_code {
        detail = detail.with_provider_code(provider_code);
    }
    if let Some(summary) = safe_summary {
        detail = detail.with_safe_summary(summary);
    }
    detail
}

fn validate_reason_code(value: &str) -> Result<(), ReasonCodeError> {
    if value.trim().is_empty() {
        return Err(ReasonCodeError::Empty);
    }
    if value.len() > MAX_REASON_CODE_BYTES {
        return Err(ReasonCodeError::TooLong {
            max: MAX_REASON_CODE_BYTES,
        });
    }
    for character in value.chars() {
        if !(character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_') {
            return Err(ReasonCodeError::InvalidCharacter { character });
        }
    }
    Ok(())
}

fn sanitize_label(value: &str, fallback: &str) -> String {
    let mut sanitized = String::new();
    for character in value.trim().chars() {
        let normalized = if character.is_ascii_alphanumeric() {
            Some(character.to_ascii_lowercase())
        } else if matches!(character, '-' | '_' | '.' | ':' | '/') || character.is_whitespace() {
            Some('_')
        } else {
            None
        };
        if let Some(character) = normalized {
            if sanitized.len() < MAX_LABEL_CHARS {
                sanitized.push(character);
            }
        }
    }
    let sanitized = sanitized.trim_matches('_').to_string();
    if sanitized.is_empty() {
        fallback.to_string()
    } else {
        sanitized
    }
}

fn sanitize_summary(value: &str) -> Option<String> {
    let collapsed = collapse_whitespace(value);
    if collapsed.is_empty() {
        return None;
    }
    let lower = collapsed.to_ascii_lowercase();
    if SENSITIVE_SUMMARY_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return Some("[redacted]".to_string());
    }
    Some(collapsed.chars().take(MAX_SUMMARY_CHARS).collect())
}

fn deserialize_provider_label<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(sanitize_label(&value, "unknown_provider"))
}

fn deserialize_optional_provider_code<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.map(|value| sanitize_label(&value, "unknown_code")))
}

fn deserialize_optional_summary<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.and_then(|value| sanitize_summary(&value)))
}

fn collapse_whitespace(value: &str) -> String {
    let mut collapsed = String::new();
    let mut previous_was_space = false;
    for character in value.chars() {
        if character.is_control() || character.is_whitespace() {
            if !previous_was_space && !collapsed.is_empty() {
                collapsed.push(' ');
            }
            previous_was_space = true;
        } else {
            collapsed.push(character);
            previous_was_space = false;
        }
    }
    collapsed.trim().to_string()
}

#[cfg(test)]
#[path = "../tests/unit/failure_taxonomy_tests.rs"]
mod tests;
