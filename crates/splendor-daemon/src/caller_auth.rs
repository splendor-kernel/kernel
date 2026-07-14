//! Closed resident caller-token profile.
//!
//! This module authenticates an app caller. It does not authorize a run or an
//! action: signed work orders, live run authority, verifiers, and the gateway
//! remain mandatory after this boundary succeeds.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use splendor_types::{
    AppPrincipal, CallerCredential, ClientPrincipal, CredentialAudience, CredentialBinding,
    EndpointScope, InstanceId, RevocationStatus, TenantId,
};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

pub const CALLER_TOKEN_TYPE: &str = "splendor-caller+jwt";
pub const CALLER_TOKEN_ALGORITHM: &str = "Ed25519";
pub const CALLER_TOKEN_SCHEMA_VERSION: u16 = 1;
pub const CALLER_TRUST_SCHEMA_VERSION: &str = "splendor.caller_trust.v1";
pub const MAX_CALLER_TOKEN_BYTES: usize = 8 * 1024;
const MAX_TRUST_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_SCOPES: usize = 16;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MAX_TRUST_SNAPSHOT_LIFETIME_SECONDS: i64 = 24 * 60 * 60;
const MAX_REVOKED_JTIS: usize = 100_000;
const MAX_TRUST_KEYS: usize = 64;
const MAX_CONSUMED_MUTATING_JTIS: usize = 100_000;
const MAX_TRUST_REVISION: u64 = i64::MAX as u64;
const JTI_CORRELATION_DOMAIN: &[u8] = b"splendor.resident.caller-jti-correlation.v1\0";

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerTokenTrustSnapshot {
    pub schema_version: String,
    pub revision: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub issuer: String,
    pub app_principal_id: String,
    pub max_token_ttl_seconds: u64,
    pub allowed_scopes: Vec<String>,
    pub keys: Vec<CallerVerificationKey>,
    #[serde(default)]
    pub revoked_jtis: Vec<String>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerVerificationKey {
    pub kid: String,
    pub algorithm: String,
    pub public_key: String,
    pub status: CallerVerificationKeyStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerVerificationKeyStatus {
    Active,
    Revoked,
}

impl std::fmt::Debug for CallerTokenTrustSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallerTokenTrustSnapshot")
            .field("schema_version", &self.schema_version)
            .field("revision", &self.revision)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("issuer", &self.issuer)
            .field("app_principal_id", &self.app_principal_id)
            .field("max_token_ttl_seconds", &self.max_token_ttl_seconds)
            .field("allowed_scopes", &self.allowed_scopes)
            .field("keys", &self.keys)
            .field("revoked_jti_count", &self.revoked_jtis.len())
            .finish()
    }
}

impl std::fmt::Debug for CallerVerificationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallerVerificationKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("public_key", &"[REDACTED]")
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct CallerTokenVerifier {
    inner: Arc<CallerTokenVerifierInner>,
}

struct CallerTokenVerifierInner {
    trust: CallerTokenTrustSnapshot,
    expected_instance_id: InstanceId,
    clock_leeway_seconds: i64,
    maximum_observed_unix_time: AtomicI64,
    consumed_mutating_jtis: Mutex<HashMap<String, i64>>,
}

impl std::fmt::Debug for CallerTokenVerifierInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let consumed_jti_count = self
            .consumed_mutating_jtis
            .lock()
            .map(|consumed| consumed.len())
            .ok();
        formatter
            .debug_struct("CallerTokenVerifierInner")
            .field("trust", &self.trust)
            .field("expected_instance_id", &self.expected_instance_id)
            .field("clock_leeway_seconds", &self.clock_leeway_seconds)
            .field(
                "maximum_observed_unix_time",
                &self.maximum_observed_unix_time.load(Ordering::SeqCst),
            )
            .field("consumed_mutating_jti_count", &consumed_jti_count)
            .finish()
    }
}

#[derive(Clone)]
pub struct CallerTokenSigner {
    inner: Arc<CallerTokenSignerInner>,
}

struct CallerTokenSignerInner {
    issuer: String,
    app_principal_id: String,
    client_principal_id: String,
    kid: String,
    key_pair: Ed25519KeyPair,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SignedCallerToken {
    pub encoded: String,
    pub credential: CallerCredential,
}

impl std::fmt::Debug for SignedCallerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedCallerToken")
            .field("encoded", &"[REDACTED]")
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum CallerAuthError {
    #[error("caller token is missing")]
    MissingToken,
    #[error("caller token is malformed")]
    MalformedToken,
    #[error("caller token uses an unsupported profile")]
    UnsupportedProfile,
    #[error("caller token signing key is unknown or revoked")]
    UntrustedKey,
    #[error("caller token signature is invalid")]
    InvalidSignature,
    #[error("caller token issuer is invalid")]
    WrongIssuer,
    #[error("caller token audience is invalid")]
    WrongAudience,
    #[error("caller token subject is invalid")]
    WrongSubject,
    #[error("caller token lifetime is invalid")]
    InvalidLifetime,
    #[error("caller token scope is invalid")]
    InvalidScope,
    #[error("caller token tenant binding is invalid")]
    InvalidTenant,
    #[error("caller token has been revoked")]
    RevokedToken,
    #[error("caller token was already used for a mutating request")]
    ReplayedToken,
    #[error("caller trust snapshot is unavailable, invalid, or stale")]
    InvalidTrustSnapshot,
    #[error("caller authentication clock moved backwards")]
    ClockRollback,
    #[error("caller token signer configuration is invalid")]
    InvalidSigner,
    #[error("caller key material could not be loaded")]
    KeyLoad,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CallerTokenHeader {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CallerTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    splendor_ver: u16,
    app_principal_id: String,
    tenant_id: String,
    scope: Vec<String>,
}

impl CallerTokenTrustSnapshot {
    pub fn single_key(
        issuer: impl Into<String>,
        app_principal_id: impl Into<String>,
        kid: impl Into<String>,
        public_key: &[u8],
        allowed_scopes: Vec<EndpointScope>,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            schema_version: CALLER_TRUST_SCHEMA_VERSION.to_string(),
            revision: 1,
            issued_at: now,
            expires_at: now + Duration::hours(1),
            issuer: issuer.into(),
            app_principal_id: app_principal_id.into(),
            max_token_ttl_seconds: 300,
            allowed_scopes: allowed_scopes
                .into_iter()
                .map(|scope| scope.as_str().to_string())
                .collect(),
            keys: vec![CallerVerificationKey {
                kid: kid.into(),
                algorithm: CALLER_TOKEN_ALGORITHM.to_string(),
                public_key: URL_SAFE_NO_PAD.encode(public_key),
                status: CallerVerificationKeyStatus::Active,
            }],
            revoked_jtis: Vec::new(),
        }
    }
}

impl CallerTokenVerifier {
    pub fn new(
        trust: CallerTokenTrustSnapshot,
        expected_instance_id: InstanceId,
    ) -> Result<Self, CallerAuthError> {
        if expected_instance_id.is_nil() {
            return Err(CallerAuthError::InvalidTrustSnapshot);
        }
        validate_trust_snapshot_shape(&trust)?;
        Ok(Self {
            inner: Arc::new(CallerTokenVerifierInner {
                trust,
                expected_instance_id,
                clock_leeway_seconds: 30,
                maximum_observed_unix_time: AtomicI64::new(i64::MIN),
                consumed_mutating_jtis: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn from_file(
        path: impl AsRef<Path>,
        expected_instance_id: InstanceId,
    ) -> Result<Self, CallerAuthError> {
        let bytes = read_bounded(path.as_ref(), MAX_TRUST_FILE_BYTES, false)?;
        let trust =
            serde_json::from_slice(&bytes).map_err(|_| CallerAuthError::InvalidTrustSnapshot)?;
        Self::new(trust, expected_instance_id)
    }

    pub fn verify(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<CallerCredential, CallerAuthError> {
        self.verify_claims(token, now)
            .map(|verified| verified.credential)
    }

    /// Verifies a caller token and atomically consumes its JTI for one mutating
    /// request. Read-only requests should continue to use [`Self::verify`].
    ///
    /// Consumption occurs before the daemon handler is entered, so concurrent
    /// copies of a captured bearer cannot both reach run or gateway mutation.
    pub fn verify_and_consume_mutation(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<CallerCredential, CallerAuthError> {
        let verified = self.verify_claims(token, now)?;
        let mut consumed = self
            .inner
            .consumed_mutating_jtis
            .lock()
            .map_err(|_| CallerAuthError::InvalidTrustSnapshot)?;
        let now_unix = now.unix_timestamp();
        consumed.retain(|_, retained_until| *retained_until >= now_unix);
        if consumed.contains_key(&verified.raw_jti) {
            return Err(CallerAuthError::ReplayedToken);
        }
        if consumed.len() >= MAX_CONSUMED_MUTATING_JTIS {
            return Err(CallerAuthError::InvalidTrustSnapshot);
        }
        let retained_until = verified
            .expires_at_unix
            .checked_add(self.inner.clock_leeway_seconds)
            .ok_or(CallerAuthError::InvalidLifetime)?;
        consumed.insert(verified.raw_jti, retained_until);
        Ok(verified.credential)
    }

    fn verify_claims(
        &self,
        token: &str,
        now: OffsetDateTime,
    ) -> Result<VerifiedCallerClaims, CallerAuthError> {
        if token.is_empty() || token.len() > MAX_CALLER_TOKEN_BYTES {
            return Err(CallerAuthError::MalformedToken);
        }
        self.observe_time(now)?;
        validate_trust_snapshot_at(&self.inner.trust, now, self.inner.clock_leeway_seconds)?;

        let mut segments = token.split('.');
        let encoded_header = segments.next().ok_or(CallerAuthError::MalformedToken)?;
        let encoded_claims = segments.next().ok_or(CallerAuthError::MalformedToken)?;
        let encoded_signature = segments.next().ok_or(CallerAuthError::MalformedToken)?;
        if segments.next().is_some()
            || encoded_header.is_empty()
            || encoded_claims.is_empty()
            || encoded_signature.is_empty()
        {
            return Err(CallerAuthError::MalformedToken);
        }

        let header_bytes = decode_segment(encoded_header)?;
        let claims_bytes = decode_segment(encoded_claims)?;
        let signature_bytes = decode_segment(encoded_signature)?;
        if signature_bytes.len() != ED25519_SIGNATURE_BYTES {
            return Err(CallerAuthError::MalformedToken);
        }
        let header: CallerTokenHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| CallerAuthError::MalformedToken)?;
        let claims: CallerTokenClaims =
            serde_json::from_slice(&claims_bytes).map_err(|_| CallerAuthError::MalformedToken)?;
        if header.typ != CALLER_TOKEN_TYPE
            || header.alg != CALLER_TOKEN_ALGORITHM
            || header.kid.trim().is_empty()
            || header.kid.len() > 128
        {
            return Err(CallerAuthError::UnsupportedProfile);
        }

        let key = self
            .inner
            .trust
            .keys
            .iter()
            .find(|key| key.kid == header.kid && key.algorithm == header.alg)
            .filter(|key| key.status == CallerVerificationKeyStatus::Active)
            .ok_or(CallerAuthError::UntrustedKey)?;
        let public_key = URL_SAFE_NO_PAD
            .decode(key.public_key.as_bytes())
            .map_err(|_| CallerAuthError::InvalidTrustSnapshot)?;
        if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(CallerAuthError::InvalidTrustSnapshot);
        }
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(signing_input.as_bytes(), &signature_bytes)
            .map_err(|_| CallerAuthError::InvalidSignature)?;

        self.project_claims(claims, now)
    }

    fn observe_time(&self, now: OffsetDateTime) -> Result<(), CallerAuthError> {
        let now = now.unix_timestamp();
        let previous = self.inner.maximum_observed_unix_time.load(Ordering::SeqCst);
        let rollback_floor = now
            .checked_add(self.inner.clock_leeway_seconds)
            .ok_or(CallerAuthError::ClockRollback)?;
        if previous != i64::MIN && rollback_floor < previous {
            return Err(CallerAuthError::ClockRollback);
        }
        self.inner
            .maximum_observed_unix_time
            .fetch_max(now, Ordering::SeqCst);
        Ok(())
    }

    fn project_claims(
        &self,
        claims: CallerTokenClaims,
        now: OffsetDateTime,
    ) -> Result<VerifiedCallerClaims, CallerAuthError> {
        if claims.splendor_ver != CALLER_TOKEN_SCHEMA_VERSION {
            return Err(CallerAuthError::UnsupportedProfile);
        }
        if claims.iss != self.inner.trust.issuer {
            return Err(CallerAuthError::WrongIssuer);
        }
        let expected_audience =
            format!("urn:splendor:instance:{}", self.inner.expected_instance_id);
        if claims.aud != expected_audience {
            return Err(CallerAuthError::WrongAudience);
        }
        if claims.app_principal_id != self.inner.trust.app_principal_id
            || claims.sub.trim().is_empty()
            || claims.sub.len() > 256
        {
            return Err(CallerAuthError::WrongSubject);
        }
        let now_unix = now.unix_timestamp();
        let leeway = self.inner.clock_leeway_seconds;
        let maximum_ttl = i64::try_from(self.inner.trust.max_token_ttl_seconds)
            .map_err(|_| CallerAuthError::InvalidTrustSnapshot)?;
        let token_ttl = claims
            .exp
            .checked_sub(claims.iat)
            .ok_or(CallerAuthError::InvalidLifetime)?;
        let earliest_nbf = claims
            .iat
            .checked_sub(leeway)
            .ok_or(CallerAuthError::InvalidLifetime)?;
        let latest_current = now_unix
            .checked_add(leeway)
            .ok_or(CallerAuthError::InvalidLifetime)?;
        let expiry_floor = now_unix
            .checked_sub(leeway)
            .ok_or(CallerAuthError::InvalidLifetime)?;
        if claims.iat > latest_current
            || claims.nbf > latest_current
            || claims.exp <= expiry_floor
            || claims.exp <= claims.nbf
            || claims.nbf < earliest_nbf
            || token_ttl > maximum_ttl
        {
            return Err(CallerAuthError::InvalidLifetime);
        }
        let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp)
            .map_err(|_| CallerAuthError::InvalidLifetime)?;
        let jti =
            uuid::Uuid::parse_str(&claims.jti).map_err(|_| CallerAuthError::MalformedToken)?;
        if jti.is_nil() {
            return Err(CallerAuthError::MalformedToken);
        }
        let canonical_jti = jti.to_string();
        if self
            .inner
            .trust
            .revoked_jtis
            .iter()
            .any(|revoked| revoked == &canonical_jti)
        {
            return Err(CallerAuthError::RevokedToken);
        }
        if claims.scope.is_empty() || claims.scope.len() > MAX_TOKEN_SCOPES {
            return Err(CallerAuthError::InvalidScope);
        }
        let allowed = self
            .inner
            .trust
            .allowed_scopes
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let mut seen = HashSet::new();
        let mut scopes = Vec::with_capacity(claims.scope.len());
        for raw in claims.scope {
            if !seen.insert(raw.clone()) || !allowed.contains(raw.as_str()) {
                return Err(CallerAuthError::InvalidScope);
            }
            scopes.push(parse_endpoint_scope(&raw).ok_or(CallerAuthError::InvalidScope)?);
        }
        let tenant_id =
            TenantId::parse(&claims.tenant_id).map_err(|_| CallerAuthError::InvalidTenant)?;
        if tenant_id.is_nil() {
            return Err(CallerAuthError::InvalidTenant);
        }
        let credential = CallerCredential {
            credential_id: caller_jti_correlation(&canonical_jti),
            principal: ClientPrincipal {
                app: AppPrincipal {
                    app_principal_id: claims.app_principal_id,
                    label: None,
                },
                client_principal_id: claims.sub,
                label: None,
            },
            scopes,
            binding: CredentialBinding::Tenant { tenant_id },
            audience: CredentialAudience::Instance {
                instance_id: self.inner.expected_instance_id.clone(),
            },
            expires_at,
            revocation: RevocationStatus::Active,
        };
        Ok(VerifiedCallerClaims {
            credential,
            raw_jti: canonical_jti,
            expires_at_unix: claims.exp,
        })
    }
}

impl CallerTokenSigner {
    pub fn from_pkcs8(
        issuer: impl Into<String>,
        app_principal_id: impl Into<String>,
        client_principal_id: impl Into<String>,
        kid: impl Into<String>,
        pkcs8: &[u8],
    ) -> Result<Self, CallerAuthError> {
        let issuer = issuer.into();
        let app_principal_id = app_principal_id.into();
        let client_principal_id = client_principal_id.into();
        let kid = kid.into();
        if [
            issuer.as_str(),
            app_principal_id.as_str(),
            client_principal_id.as_str(),
            kid.as_str(),
        ]
        .iter()
        .any(|value| value.trim().is_empty())
            || kid.len() > 128
        {
            return Err(CallerAuthError::InvalidSigner);
        }
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| CallerAuthError::KeyLoad)?;
        Ok(Self {
            inner: Arc::new(CallerTokenSignerInner {
                issuer,
                app_principal_id,
                client_principal_id,
                kid,
                key_pair,
            }),
        })
    }

    pub fn from_pkcs8_file(
        issuer: impl Into<String>,
        app_principal_id: impl Into<String>,
        client_principal_id: impl Into<String>,
        kid: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<Self, CallerAuthError> {
        let bytes = read_bounded(path.as_ref(), 64 * 1024, true)?;
        Self::from_pkcs8(issuer, app_principal_id, client_principal_id, kid, &bytes)
    }

    pub fn generate_for_test(
        issuer: impl Into<String>,
        app_principal_id: impl Into<String>,
        client_principal_id: impl Into<String>,
        kid: impl Into<String>,
    ) -> Result<Self, CallerAuthError> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| CallerAuthError::KeyLoad)?;
        Self::from_pkcs8(
            issuer,
            app_principal_id,
            client_principal_id,
            kid,
            pkcs8.as_ref(),
        )
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.key_pair.public_key().as_ref().to_vec()
    }

    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    pub fn app_principal_id(&self) -> &str {
        &self.inner.app_principal_id
    }

    pub fn kid(&self) -> &str {
        &self.inner.kid
    }

    pub fn sign(
        &self,
        tenant_id: &TenantId,
        instance_id: &InstanceId,
        scopes: Vec<EndpointScope>,
        now: OffsetDateTime,
        ttl: Duration,
    ) -> Result<SignedCallerToken, CallerAuthError> {
        if ttl <= Duration::ZERO
            || ttl > Duration::minutes(5)
            || scopes.is_empty()
            || tenant_id.is_nil()
            || instance_id.is_nil()
        {
            return Err(CallerAuthError::InvalidLifetime);
        }
        let mut seen = HashSet::new();
        let scope = scopes
            .iter()
            .map(|scope| scope.as_str().to_string())
            .map(|scope| {
                if seen.insert(scope.clone()) {
                    Ok(scope)
                } else {
                    Err(CallerAuthError::InvalidScope)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        if scope.len() > MAX_TOKEN_SCOPES {
            return Err(CallerAuthError::InvalidScope);
        }
        let issued_at_unix = now.unix_timestamp();
        let expires_at_unix = issued_at_unix
            .checked_add(ttl.whole_seconds())
            .ok_or(CallerAuthError::InvalidLifetime)?;
        if expires_at_unix <= issued_at_unix {
            return Err(CallerAuthError::InvalidLifetime);
        }
        let expires_at = OffsetDateTime::from_unix_timestamp(expires_at_unix)
            .map_err(|_| CallerAuthError::InvalidLifetime)?;
        let jti = uuid::Uuid::new_v4().to_string();
        let header = CallerTokenHeader {
            alg: CALLER_TOKEN_ALGORITHM.to_string(),
            kid: self.inner.kid.clone(),
            typ: CALLER_TOKEN_TYPE.to_string(),
        };
        let claims = CallerTokenClaims {
            iss: self.inner.issuer.clone(),
            sub: self.inner.client_principal_id.clone(),
            aud: format!("urn:splendor:instance:{instance_id}"),
            iat: issued_at_unix,
            nbf: issued_at_unix,
            exp: expires_at_unix,
            jti: jti.clone(),
            splendor_ver: CALLER_TOKEN_SCHEMA_VERSION,
            app_principal_id: self.inner.app_principal_id.clone(),
            tenant_id: tenant_id.to_string(),
            scope,
        };
        let encoded_header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).map_err(|_| CallerAuthError::InvalidSigner)?);
        let encoded_claims = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).map_err(|_| CallerAuthError::InvalidSigner)?);
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = self.inner.key_pair.sign(signing_input.as_bytes());
        let encoded = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        );
        let credential = CallerCredential {
            credential_id: caller_jti_correlation(&jti),
            principal: ClientPrincipal {
                app: AppPrincipal {
                    app_principal_id: self.inner.app_principal_id.clone(),
                    label: None,
                },
                client_principal_id: self.inner.client_principal_id.clone(),
                label: None,
            },
            scopes,
            binding: CredentialBinding::Tenant {
                tenant_id: tenant_id.clone(),
            },
            audience: CredentialAudience::Instance {
                instance_id: instance_id.clone(),
            },
            expires_at,
            revocation: RevocationStatus::Active,
        };
        Ok(SignedCallerToken {
            encoded,
            credential,
        })
    }
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, CallerAuthError> {
    if segment.contains('=') {
        return Err(CallerAuthError::MalformedToken);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|_| CallerAuthError::MalformedToken)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != segment {
        return Err(CallerAuthError::MalformedToken);
    }
    Ok(decoded)
}

fn validate_trust_snapshot_shape(trust: &CallerTokenTrustSnapshot) -> Result<(), CallerAuthError> {
    if trust.schema_version != CALLER_TRUST_SCHEMA_VERSION
        || trust.revision == 0
        || trust.revision > MAX_TRUST_REVISION
        || trust.issuer.trim().is_empty()
        || trust.app_principal_id.trim().is_empty()
        || trust.max_token_ttl_seconds == 0
        || trust.max_token_ttl_seconds > 300
        || trust.keys.is_empty()
        || trust.keys.len() > MAX_TRUST_KEYS
        || trust.allowed_scopes.is_empty()
        || trust.revoked_jtis.len() > MAX_REVOKED_JTIS
        || trust.issuer.len() > 512
        || trust.app_principal_id.len() > 256
    {
        return Err(CallerAuthError::InvalidTrustSnapshot);
    }
    let lifetime = trust.expires_at - trust.issued_at;
    if trust.expires_at <= trust.issued_at
        || lifetime > Duration::seconds(MAX_TRUST_SNAPSHOT_LIFETIME_SECONDS)
    {
        return Err(CallerAuthError::InvalidTrustSnapshot);
    }
    let mut kids = HashSet::new();
    for key in &trust.keys {
        let public_key = URL_SAFE_NO_PAD
            .decode(key.public_key.as_bytes())
            .map_err(|_| CallerAuthError::InvalidTrustSnapshot)?;
        if key.kid.trim().is_empty()
            || key.kid.len() > 128
            || !kids.insert(key.kid.as_str())
            || key.algorithm != CALLER_TOKEN_ALGORITHM
            || public_key.len() != ED25519_PUBLIC_KEY_BYTES
        {
            return Err(CallerAuthError::InvalidTrustSnapshot);
        }
    }
    let mut scopes = HashSet::new();
    if trust.allowed_scopes.len() > MAX_TOKEN_SCOPES
        || trust
            .allowed_scopes
            .iter()
            .any(|scope| parse_endpoint_scope(scope).is_none() || !scopes.insert(scope.as_str()))
    {
        return Err(CallerAuthError::InvalidTrustSnapshot);
    }
    let mut revoked = HashSet::new();
    for jti in &trust.revoked_jtis {
        let parsed =
            uuid::Uuid::parse_str(jti).map_err(|_| CallerAuthError::InvalidTrustSnapshot)?;
        if parsed.is_nil() || parsed.to_string() != *jti || !revoked.insert(jti.as_str()) {
            return Err(CallerAuthError::InvalidTrustSnapshot);
        }
    }
    Ok(())
}

fn validate_trust_snapshot_at(
    trust: &CallerTokenTrustSnapshot,
    now: OffsetDateTime,
    leeway_seconds: i64,
) -> Result<(), CallerAuthError> {
    let leeway = Duration::seconds(leeway_seconds);
    let latest_current = now
        .checked_add(leeway)
        .ok_or(CallerAuthError::InvalidTrustSnapshot)?;
    let lifetime = trust.expires_at - trust.issued_at;
    if trust.issued_at > latest_current
        || trust.expires_at <= now
        || trust.expires_at <= trust.issued_at
        || lifetime > Duration::seconds(MAX_TRUST_SNAPSHOT_LIFETIME_SECONDS)
    {
        return Err(CallerAuthError::InvalidTrustSnapshot);
    }
    Ok(())
}

fn parse_endpoint_scope(value: &str) -> Option<EndpointScope> {
    [
        EndpointScope::RunsCreate,
        EndpointScope::RunsStart,
        EndpointScope::RunsRead,
        EndpointScope::RunsPause,
        EndpointScope::RunsResume,
        EndpointScope::RunsStop,
        EndpointScope::PerceptsAppend,
        EndpointScope::ActionsSubmit,
        EndpointScope::TracesRead,
        EndpointScope::StateRead,
        EndpointScope::ReplayCreate,
        EndpointScope::MessagesSend,
        EndpointScope::MessagesRead,
        EndpointScope::WorkOrdersSubmit,
        EndpointScope::WorkOrdersRevoke,
        EndpointScope::FleetRead,
        EndpointScope::FleetDispatch,
        EndpointScope::StateHandoff,
        EndpointScope::HealthRead,
        EndpointScope::CapabilitiesRead,
        EndpointScope::PoliciesSync,
        EndpointScope::NodesRegister,
        EndpointScope::InstancesRegister,
        EndpointScope::NodesHeartbeat,
        EndpointScope::InstancesHeartbeat,
        EndpointScope::PoliciesPublish,
        EndpointScope::PoliciesRevoke,
        EndpointScope::ApprovalsManage,
        EndpointScope::GovernanceControl,
        EndpointScope::DeviceRegister,
        EndpointScope::DeviceRead,
        EndpointScope::OperatorIntervene,
    ]
    .into_iter()
    .find(|scope| scope.as_str() == value)
}

fn read_bounded(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>, CallerAuthError> {
    let mut file = open_regular_file(path)?;
    if private {
        require_private_file_permissions(&file)?;
    }
    let metadata = file.metadata().map_err(|_| CallerAuthError::KeyLoad)?;
    if metadata.len() > maximum as u64 {
        return Err(CallerAuthError::KeyLoad);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| CallerAuthError::KeyLoad)?;
    if bytes.len() > maximum {
        return Err(CallerAuthError::KeyLoad);
    }
    Ok(bytes)
}

fn open_regular_file(path: &Path) -> Result<File, CallerAuthError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|_| CallerAuthError::KeyLoad)?;
    if !file
        .metadata()
        .map_err(|_| CallerAuthError::KeyLoad)?
        .file_type()
        .is_file()
    {
        return Err(CallerAuthError::KeyLoad);
    }
    Ok(file)
}

#[cfg(unix)]
fn require_private_file_permissions(file: &File) -> Result<(), CallerAuthError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = file.metadata().map_err(|_| CallerAuthError::KeyLoad)?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(CallerAuthError::KeyLoad);
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_file_permissions(_file: &File) -> Result<(), CallerAuthError> {
    Ok(())
}

struct VerifiedCallerClaims {
    credential: CallerCredential,
    raw_jti: String,
    expires_at_unix: i64,
}

/// Returns the bounded, domain-separated digest used to correlate one caller
/// credential in audit records without persisting its raw JTI.
pub fn caller_jti_correlation(jti: &str) -> String {
    let mut input = Vec::with_capacity(JTI_CORRELATION_DOMAIN.len() + jti.len());
    input.extend_from_slice(JTI_CORRELATION_DOMAIN);
    input.extend_from_slice(jti.as_bytes());
    format!("sha256:{}", hex_bytes(digest(&SHA256, &input).as_ref()))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        rendered.push(HEX[(byte >> 4) as usize] as char);
        rendered.push(HEX[(byte & 0x0f) as usize] as char);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resign_token(
        signer: &CallerTokenSigner,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> String {
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("header"));
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims"));
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature = signer.inner.key_pair.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        )
    }

    fn decoded_token(token: &str) -> (serde_json::Value, serde_json::Value) {
        let segments = token.split('.').collect::<Vec<_>>();
        let header = serde_json::from_slice(&decode_segment(segments[0]).expect("header bytes"))
            .expect("header JSON");
        let claims = serde_json::from_slice(&decode_segment(segments[1]).expect("claims bytes"))
            .expect("claims JSON");
        (header, claims)
    }

    fn raw_jti(token: &str) -> String {
        decoded_token(token).1["jti"]
            .as_str()
            .expect("raw token JTI")
            .to_string()
    }

    fn fixture() -> (
        CallerTokenSigner,
        CallerTokenVerifier,
        TenantId,
        InstanceId,
        OffsetDateTime,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_783_958_400).expect("time");
        let tenant_id = TenantId::new();
        let instance_id = InstanceId::new();
        let signer = CallerTokenSigner::generate_for_test(
            "urn:splendor:manager:central-manager",
            "central-manager",
            "resident-dispatch-client",
            "manager-resident-test",
        )
        .expect("signer");
        let trust = CallerTokenTrustSnapshot::single_key(
            signer.issuer(),
            signer.app_principal_id(),
            signer.kid(),
            &signer.public_key_bytes(),
            vec![EndpointScope::RunsCreate, EndpointScope::RunsStart],
            now,
        );
        let verifier = CallerTokenVerifier::new(trust, instance_id.clone()).expect("verifier");
        (signer, verifier, tenant_id, instance_id, now)
    }

    #[test]
    fn signed_token_projects_only_verified_caller_facts() {
        let (signer, verifier, tenant_id, instance_id, now) = fixture();
        let signed = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(60),
            )
            .expect("signed");
        let verified = verifier.verify(&signed.encoded, now).expect("verified");
        assert_eq!(verified, signed.credential);
        assert_eq!(verified.principal.app.label, None);
        assert_eq!(verified.principal.label, None);
    }

    #[test]
    fn signer_mints_fresh_jti_for_each_request() {
        let (signer, _verifier, tenant_id, instance_id, now) = fixture();
        let first = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(60),
            )
            .expect("first token");
        let second = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsStart],
                now,
                Duration::seconds(60),
            )
            .expect("second token");
        assert_ne!(
            first.credential.credential_id,
            second.credential.credential_id
        );
        assert_ne!(first.encoded, second.encoded);
    }

    #[test]
    fn mutating_jti_consumption_is_atomic_while_read_verification_is_reusable() {
        let (signer, verifier, tenant_id, instance_id, now) = fixture();
        let signed = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(60),
            )
            .expect("signed");
        verifier.verify(&signed.encoded, now).expect("first read");
        verifier.verify(&signed.encoded, now).expect("second read");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let verifier = verifier.clone();
            let encoded = signed.encoded.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                verifier.verify_and_consume_mutation(&encoded, now)
            }));
        }
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(CallerAuthError::ReplayedToken)))
                .count(),
            1
        );
    }

    #[test]
    fn consumed_mutating_jti_is_retained_through_expiry_leeway_boundary() {
        let (signer, verifier, tenant_id, instance_id, now) = fixture();
        let consumed = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(60),
            )
            .expect("consumed token");
        let consumed_jti = raw_jti(&consumed.encoded);
        verifier
            .verify_and_consume_mutation(&consumed.encoded, now)
            .expect("first mutation consumes JTI");

        let at_boundary = now + Duration::seconds(90);
        let boundary_token = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                at_boundary,
                Duration::seconds(60),
            )
            .expect("boundary token");
        verifier
            .verify_and_consume_mutation(&boundary_token.encoded, at_boundary)
            .expect("fresh mutation at retention boundary");
        assert!(verifier
            .inner
            .consumed_mutating_jtis
            .lock()
            .expect("consumed JTI ledger")
            .contains_key(&consumed_jti));

        let after_boundary = at_boundary + Duration::seconds(1);
        let later_token = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                after_boundary,
                Duration::seconds(60),
            )
            .expect("later token");
        verifier
            .verify_and_consume_mutation(&later_token.encoded, after_boundary)
            .expect("fresh mutation after retention boundary");
        assert!(!verifier
            .inner
            .consumed_mutating_jtis
            .lock()
            .expect("consumed JTI ledger")
            .contains_key(&consumed_jti));
    }

    #[test]
    fn tampering_wrong_audience_expiry_revocation_and_eddsa_fail_closed() {
        let (signer, verifier, tenant_id, instance_id, now) = fixture();
        let signed = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(60),
            )
            .expect("signed");
        let mut tampered = signed.encoded.into_bytes();
        let index = tampered.len() - 2;
        tampered[index] = if tampered[index] == b'a' { b'b' } else { b'a' };
        assert!(matches!(
            verifier.verify(std::str::from_utf8(&tampered).expect("utf8"), now),
            Err(CallerAuthError::InvalidSignature | CallerAuthError::MalformedToken)
        ));

        let wrong_instance = InstanceId::new();
        let wrong_audience = signer
            .sign(
                &tenant_id,
                &wrong_instance,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(60),
            )
            .expect("signed");
        assert!(matches!(
            verifier.verify(&wrong_audience.encoded, now),
            Err(CallerAuthError::WrongAudience)
        ));

        let expired = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(1),
            )
            .expect("signed");
        assert!(matches!(
            verifier.verify(&expired.encoded, now + Duration::minutes(1)),
            Err(CallerAuthError::InvalidLifetime)
        ));

        let mut revoked_trust = CallerTokenTrustSnapshot::single_key(
            signer.issuer(),
            signer.app_principal_id(),
            signer.kid(),
            &signer.public_key_bytes(),
            vec![EndpointScope::RunsCreate],
            now,
        );
        revoked_trust.revoked_jtis = vec![raw_jti(&expired.encoded)];
        let revoked = CallerTokenVerifier::new(revoked_trust, instance_id).expect("verifier");
        assert!(matches!(
            revoked.verify(&expired.encoded, now),
            Err(CallerAuthError::RevokedToken)
        ));

        let segments = expired.encoded.split('.').collect::<Vec<_>>();
        let mut header: serde_json::Value =
            serde_json::from_slice(&decode_segment(segments[0]).expect("header")).expect("json");
        header["alg"] = serde_json::json!("EdDSA");
        let eddsa = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("json")),
            segments[1],
            segments[2]
        );
        assert!(matches!(
            verifier.verify(&eddsa, now + Duration::minutes(1)),
            Err(CallerAuthError::UnsupportedProfile)
        ));
    }

    #[test]
    fn hostile_key_issuer_tenant_scope_and_lifetime_claims_fail_closed() {
        let (signer, verifier, tenant_id, instance_id, now) = fixture();
        let signed = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(60),
            )
            .expect("signed");
        let (header, claims) = decoded_token(&signed.encoded);

        let mut unknown_key = header.clone();
        unknown_key["kid"] = serde_json::json!("unknown-key");
        assert!(matches!(
            verifier.verify(&resign_token(&signer, &unknown_key, &claims), now),
            Err(CallerAuthError::UntrustedKey)
        ));

        let mut wrong_issuer = claims.clone();
        wrong_issuer["iss"] = serde_json::json!("urn:splendor:manager:other");
        assert!(matches!(
            verifier.verify(&resign_token(&signer, &header, &wrong_issuer), now),
            Err(CallerAuthError::WrongIssuer)
        ));

        let mut invalid_tenant = claims.clone();
        invalid_tenant["tenant_id"] = serde_json::json!("not-a-tenant");
        assert!(matches!(
            verifier.verify(&resign_token(&signer, &header, &invalid_tenant), now),
            Err(CallerAuthError::InvalidTenant)
        ));

        let mut invalid_scope = claims.clone();
        invalid_scope["scope"] = serde_json::json!(["splendor.root"]);
        assert!(matches!(
            verifier.verify(&resign_token(&signer, &header, &invalid_scope), now),
            Err(CallerAuthError::InvalidScope)
        ));

        let mut future = claims.clone();
        future["iat"] = serde_json::json!(now.unix_timestamp() + 120);
        future["nbf"] = serde_json::json!(now.unix_timestamp() + 120);
        future["exp"] = serde_json::json!(now.unix_timestamp() + 180);
        assert!(matches!(
            verifier.verify(&resign_token(&signer, &header, &future), now),
            Err(CallerAuthError::InvalidLifetime)
        ));

        let mut excessive = claims;
        excessive["exp"] = serde_json::json!(now.unix_timestamp() + 301);
        assert!(matches!(
            verifier.verify(&resign_token(&signer, &header, &excessive), now),
            Err(CallerAuthError::InvalidLifetime)
        ));
    }

    #[test]
    fn closed_json_profile_rotation_and_debug_redaction_are_enforced() {
        let (signer, _verifier, tenant_id, instance_id, now) = fixture();
        let rotated = CallerTokenSigner::generate_for_test(
            signer.issuer(),
            signer.app_principal_id(),
            "resident-dispatch-client",
            "manager-resident-rotated",
        )
        .expect("rotated signer");
        let mut trust = CallerTokenTrustSnapshot::single_key(
            signer.issuer(),
            signer.app_principal_id(),
            signer.kid(),
            &signer.public_key_bytes(),
            vec![EndpointScope::RunsCreate],
            now,
        );
        trust.keys.push(CallerVerificationKey {
            kid: rotated.kid().to_string(),
            algorithm: CALLER_TOKEN_ALGORITHM.to_string(),
            public_key: URL_SAFE_NO_PAD.encode(rotated.public_key_bytes()),
            status: CallerVerificationKeyStatus::Active,
        });
        let public_key_encoding = trust.keys[0].public_key.clone();
        let verifier = CallerTokenVerifier::new(trust.clone(), instance_id.clone())
            .expect("rotating verifier");
        for active_signer in [&signer, &rotated] {
            let token = active_signer
                .sign(
                    &tenant_id,
                    &instance_id,
                    vec![EndpointScope::RunsCreate],
                    now,
                    Duration::seconds(60),
                )
                .expect("token");
            verifier.verify(&token.encoded, now).expect("active key");
        }

        trust.keys[0].status = CallerVerificationKeyStatus::Revoked;
        let after_rotation =
            CallerTokenVerifier::new(trust, instance_id.clone()).expect("post-rotation verifier");
        let old = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(60),
            )
            .expect("old token");
        assert!(matches!(
            after_rotation.verify(&old.encoded, now),
            Err(CallerAuthError::UntrustedKey)
        ));

        let (mut header, claims) = decoded_token(&old.encoded);
        header["jku"] = serde_json::json!("https://attacker.invalid/key");
        assert!(matches!(
            verifier.verify(&resign_token(&signer, &header, &claims), now),
            Err(CallerAuthError::MalformedToken)
        ));

        let trust_debug = format!("{verifier:?}");
        assert!(!trust_debug.contains(&public_key_encoding));
        assert!(trust_debug.contains("[REDACTED]"));

        let consumed = rotated
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(60),
            )
            .expect("consumed token");
        let consumed_jti = raw_jti(&consumed.encoded);
        verifier
            .verify_and_consume_mutation(&consumed.encoded, now)
            .expect("consume token");
        let verifier_debug = format!("{verifier:?}");
        assert!(!verifier_debug.contains(&consumed_jti));
        assert!(verifier_debug.contains("consumed_mutating_jti_count: Some(1)"));
    }

    #[test]
    fn malformed_oversized_stale_key_revocation_and_clock_rollback_fail_closed() {
        let (signer, verifier, tenant_id, instance_id, now) = fixture();
        for malformed in ["", "one", "one.two", "one.two.three.four", "@@.@@.@@"] {
            assert!(matches!(
                verifier.verify(malformed, now),
                Err(CallerAuthError::MalformedToken)
            ));
        }
        let oversized = "a".repeat(MAX_CALLER_TOKEN_BYTES + 1);
        assert!(matches!(
            verifier.verify(&oversized, now),
            Err(CallerAuthError::MalformedToken)
        ));

        let signed = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::minutes(5),
            )
            .expect("signed");

        let mut stale_trust = CallerTokenTrustSnapshot::single_key(
            signer.issuer(),
            signer.app_principal_id(),
            signer.kid(),
            &signer.public_key_bytes(),
            vec![EndpointScope::RunsCreate],
            now - Duration::hours(2),
        );
        stale_trust.expires_at = now - Duration::seconds(1);
        let stale = CallerTokenVerifier::new(stale_trust, instance_id.clone()).expect("verifier");
        assert!(matches!(
            stale.verify(&signed.encoded, now),
            Err(CallerAuthError::InvalidTrustSnapshot)
        ));

        let mut revoked_key_trust = CallerTokenTrustSnapshot::single_key(
            signer.issuer(),
            signer.app_principal_id(),
            signer.kid(),
            &signer.public_key_bytes(),
            vec![EndpointScope::RunsCreate],
            now,
        );
        revoked_key_trust.keys[0].status = CallerVerificationKeyStatus::Revoked;
        let revoked_key =
            CallerTokenVerifier::new(revoked_key_trust, instance_id.clone()).expect("verifier");
        assert!(matches!(
            revoked_key.verify(&signed.encoded, now),
            Err(CallerAuthError::UntrustedKey)
        ));

        verifier
            .verify(&signed.encoded, now + Duration::minutes(2))
            .expect("later observation remains within token lifetime");
        assert!(matches!(
            verifier.verify(&signed.encoded, now),
            Err(CallerAuthError::ClockRollback)
        ));
    }

    #[test]
    fn trust_bounds_and_regular_file_reads_fail_closed() {
        let (signer, _verifier, _tenant_id, instance_id, now) = fixture();
        let mut trust = CallerTokenTrustSnapshot::single_key(
            signer.issuer(),
            signer.app_principal_id(),
            signer.kid(),
            &signer.public_key_bytes(),
            vec![EndpointScope::RunsCreate],
            now,
        );
        trust.revision = MAX_TRUST_REVISION + 1;
        assert!(matches!(
            CallerTokenVerifier::new(trust.clone(), instance_id.clone()),
            Err(CallerAuthError::InvalidTrustSnapshot)
        ));
        trust.revision = 1;
        trust.expires_at = trust.issued_at + Duration::hours(25);
        assert!(matches!(
            CallerTokenVerifier::new(trust.clone(), instance_id.clone()),
            Err(CallerAuthError::InvalidTrustSnapshot)
        ));

        trust.expires_at = trust.issued_at + Duration::hours(1);
        let root = std::env::temp_dir().join(format!(
            "splendor-caller-trust-file-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).expect("fixture directory");
        let trust_path = root.join("trust.json");
        std::fs::write(&trust_path, serde_json::to_vec(&trust).expect("trust JSON"))
            .expect("trust file");
        assert!(CallerTokenVerifier::from_file(&root, instance_id.clone()).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&trust_path, root.join("trust-link.json"))
                .expect("trust symlink");
            assert!(matches!(
                CallerTokenVerifier::from_file(root.join("trust-link.json"), instance_id),
                Err(CallerAuthError::KeyLoad)
            ));
        }
        std::fs::remove_dir_all(root).expect("remove fixture directory");
    }

    #[test]
    fn signed_token_debug_and_auth_errors_redact_bearer_material() {
        let (signer, verifier, tenant_id, instance_id, now) = fixture();
        let signed = signer
            .sign(
                &tenant_id,
                &instance_id,
                vec![EndpointScope::RunsCreate],
                now,
                Duration::seconds(60),
            )
            .expect("signed");
        let rendered = format!("{signed:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&signed.encoded));
        assert!(!rendered.contains(&signed.credential.credential_id));
        assert!(!rendered.contains(&tenant_id.to_string()));
        let mut trust = CallerTokenTrustSnapshot::single_key(
            signer.issuer(),
            signer.app_principal_id(),
            signer.kid(),
            &signer.public_key_bytes(),
            vec![EndpointScope::RunsCreate],
            now,
        );
        trust.revoked_jtis = vec![raw_jti(&signed.encoded)];
        let trust_rendered = format!("{trust:?}");
        assert!(!trust_rendered.contains(&signed.credential.credential_id));
        assert!(trust_rendered.contains("revoked_jti_count: 1"));
        let signature = signed
            .encoded
            .rsplit('.')
            .next()
            .expect("signature segment");
        assert!(!rendered.contains(signature));

        let mut tampered = signed.encoded.clone().into_bytes();
        let final_byte = tampered.last_mut().expect("token byte");
        *final_byte = if *final_byte == b'a' { b'b' } else { b'a' };
        let error = verifier
            .verify(std::str::from_utf8(&tampered).expect("utf8"), now)
            .expect_err("tampering denied");
        let error_text = format!("{error:?}: {error}");
        assert!(!error_text.contains(&signed.encoded));
        assert!(!error_text.contains(signature));
    }
}
