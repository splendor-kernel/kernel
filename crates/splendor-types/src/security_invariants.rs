//! Behavior-free security threat and invariant mapping primitives.
//!
//! FND-011 requires concrete threat/invariant records before later fleet,
//! evaluation, change-control, and physical paths can claim conformance. These
//! types only model and validate the mapping evidence. They do not authorize
//! requests, execute verifiers, read secrets, attest nodes, or contain incidents.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use thiserror::Error;

/// Schema version for the FND-011 security invariant fixture.
pub const SECURITY_INVARIANT_SCHEMA_VERSION: &str = "splendor.security_invariants.v1";

/// Evidence scope used by the bounded FND-011 foundation fixture.
pub const SECURITY_INVARIANT_PARTIAL_EVIDENCE_SCOPE: &str =
    "partial_fnd_011_security_invariants_v0";

/// Required non-claims for the bounded FND-011 foundation fixture.
pub const SECURITY_INVARIANT_REQUIRED_NON_CLAIMS: &[&str] = &[
    "no_fnd_011_completion",
    "no_g80_g89_pass",
    "no_gold_harness_pass",
];

/// Required gold security cases covered by FND-011.
pub const REQUIRED_SECURITY_GOLD_IDS: &[&str] = &[
    "G80", "G81", "G82", "G83", "G84", "G85", "G86", "G87", "G88", "G89",
];

/// The eight v2 security planes from the architecture rule pack.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityPlane {
    /// Principal, authority, approval, secret-lease, and scoped authorization decisions.
    IdentityAuthority,
    /// Immutable artifacts, lineage, data-use references, and supply-chain metadata.
    ArtifactLineage,
    /// Ordered events, state, evidence, and replay/simulation inputs.
    EventStateEvidence,
    /// Workloads, placement, leases, fencing, resources, and node execution.
    ExecutionFabric,
    /// Typed driver/adapter invocation boundary and operation ABI.
    DriverBoundary,
    /// Agent instances, route crossings, percept/action channels, and delegation.
    AgentRuntimeRouting,
    /// Data, feedback, evaluation, reward, training, and candidate controls.
    DataFeedbackEvalLearningControl,
    /// Change, gates, deployment, rollback, quarantine, and incidents.
    ChangeGovernance,
}

impl SecurityPlane {
    /// Stable serialized label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityAuthority => "identity_authority",
            Self::ArtifactLineage => "artifact_lineage",
            Self::EventStateEvidence => "event_state_evidence",
            Self::ExecutionFabric => "execution_fabric",
            Self::DriverBoundary => "driver_boundary",
            Self::AgentRuntimeRouting => "agent_runtime_routing",
            Self::DataFeedbackEvalLearningControl => "data_feedback_eval_learning_control",
            Self::ChangeGovernance => "change_governance",
        }
    }
}

/// All security planes that an FND-011 mapping must cover.
pub const ALL_SECURITY_PLANES: &[SecurityPlane] = &[
    SecurityPlane::IdentityAuthority,
    SecurityPlane::ArtifactLineage,
    SecurityPlane::EventStateEvidence,
    SecurityPlane::ExecutionFabric,
    SecurityPlane::DriverBoundary,
    SecurityPlane::AgentRuntimeRouting,
    SecurityPlane::DataFeedbackEvalLearningControl,
    SecurityPlane::ChangeGovernance,
];

/// Stable threat identifier. This is an evidence key, not an authorization token.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecurityThreatId(String);

impl SecurityThreatId {
    /// Creates a validated threat identifier.
    pub fn try_new(value: impl Into<String>) -> Result<Self, SecurityThreatIdError> {
        let value = value.into();
        validate_threat_id(&value)?;
        Ok(Self(value))
    }

    /// Returns the stable identifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecurityThreatId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for SecurityThreatId {
    type Error = SecurityThreatIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl From<SecurityThreatId> for String {
    fn from(value: SecurityThreatId) -> Self {
        value.0
    }
}

/// Threat identifier validation failures.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SecurityThreatIdError {
    /// Threat ID was empty after trimming.
    #[error("security threat id is empty")]
    Empty,
    /// Threat ID exceeded the stable length bound.
    #[error("security threat id exceeds {max} bytes")]
    TooLong { max: usize },
    /// Threat ID contained a character outside the stable evidence key alphabet.
    #[error("security threat id contains invalid character {character:?}")]
    InvalidCharacter { character: char },
}

/// Fail-closed disposition for a mapped threat.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedDecision {
    /// Reject the request before authority, state, or side effects advance.
    Deny,
    /// Place the object or worker in quarantine.
    Quarantine,
    /// Pause the run/workload/change until fresh authority or intervention exists.
    Pause,
    /// Degrade to a pinned safe policy or safe mode.
    Degrade,
    /// Fence a lease, worker, node, or writer authority.
    Fence,
    /// Roll back to a last-known-safe version.
    Rollback,
    /// Revoke the affected credential, lease, policy, or capability.
    Revoke,
    /// Require human/operator/governance intervention.
    RequestIntervention,
    /// Stop a physical/device path into a safe state.
    SafeStop,
}

/// Containment action recorded for a threat mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentAction {
    /// Deny the request before the protected effect.
    DenyRequest,
    /// Quarantine an artifact, dataset, checkpoint, or bundle.
    QuarantineArtifact,
    /// Quarantine a worker, node, or runtime instance.
    QuarantineWorker,
    /// Fence a lease or writer authority.
    FenceLease,
    /// Revoke a credential, capability, policy, or work order.
    RevokeCredential,
    /// Pause a run, workload, evaluation, or change.
    PauseRun,
    /// Degrade to a pinned safe mode.
    DegradeToSafeMode,
    /// Roll back a deployment or active version.
    RollbackDeployment,
    /// Block egress or another gateway-mediated effect.
    BlockNetworkEgress,
    /// Request intervention by an operator or governance principal.
    RequireHumanIntervention,
    /// Stop a physical/device path in a bounded safe state.
    SafeStopDevice,
    /// Record an incident/classification fact for follow-up workflows.
    RecordIncident,
}

/// Current executable status for the mapped conformant case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityCaseStatus {
    /// Mapping exists and is validated, but the gold case remains not exercised.
    MappedNotExercised,
    /// An executable case exists for this exact mapping.
    Exercised,
    /// The case was intentionally skipped; invalid for mandatory conformant gates.
    Skipped,
}

/// Boundary crossed by the threat.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrustBoundary {
    /// Human-readable boundary name.
    pub name: String,
    /// True if the boundary is only a prompt/instruction. FND-011 rejects this.
    pub prompt_only: bool,
    /// Concrete components or checks that enforce this boundary.
    pub enforced_by: Vec<String>,
}

/// Enforcement mapping for one threat/invariant record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityEnforcementMapping {
    /// Owning component or service responsible for the decision.
    pub enforcing_component: String,
    /// Event kinds that must exist to prove the decision/containment path.
    pub required_events: Vec<String>,
    /// Evidence or payload-reference links required by the mapping.
    pub evidence_links: Vec<String>,
    /// Containment actions allowed for this threat.
    pub containment_actions: Vec<ContainmentAction>,
}

/// Conformant maturity gate for one threat.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityMaturityGate {
    /// Whether a component cannot graduate to conformant while this case is skipped.
    pub conformant_required: bool,
    /// Current executable case status.
    pub case_status: SecurityCaseStatus,
    /// Non-claim text that keeps mapping evidence distinct from gold pass evidence.
    pub non_claim: String,
    /// Required when `case_status` is `exercised`. This is executable evidence
    /// metadata only; it is not authority and does not by itself mark a gold
    /// case passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_gold_evidence: Option<ExecutableGoldEvidence>,
}

/// Executable gold evidence metadata for an exercised case.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutableGoldEvidence {
    /// Stable harness ID that executed the case.
    pub harness_id: String,
    /// Report or artifact reference containing the retained run output.
    pub report_ref: String,
    /// Execution timestamp or externally retained run reference.
    pub executed_at: String,
    /// Evidence assertions covered by the harness report.
    pub evidence_assertions: Vec<String>,
}

/// One threat/invariant mapping record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityInvariantRecord {
    /// Stable threat evidence key.
    pub threat_id: SecurityThreatId,
    /// Gold case ID, e.g. `G80`.
    pub gold_id: String,
    /// Threat name.
    pub name: String,
    /// Primary owning plane.
    pub primary_plane: SecurityPlane,
    /// Other planes affected by this threat.
    #[serde(default)]
    pub related_planes: Vec<SecurityPlane>,
    /// Protected assets.
    pub assets: Vec<String>,
    /// Boundary crossed by the threat.
    pub trust_boundary: TrustBoundary,
    /// Principal or principal class under attack.
    pub principal: String,
    /// Attacker capability covered by this record.
    pub attacker_capability: String,
    /// Fail-closed decision.
    pub fail_closed_decision: FailClosedDecision,
    /// Enforcement, event, evidence, and containment mapping.
    pub enforcement: SecurityEnforcementMapping,
    /// Incident classification fed by this threat ID.
    pub incident_classification: String,
    /// Change-risk classification fed by this threat ID.
    pub change_risk_classification: String,
    /// Maturity gate status and non-claim.
    pub maturity_gate: SecurityMaturityGate,
}

/// Key-rotation posture for a security invariant catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeyRotationPolicy {
    /// Whether key rotation is required by the threat model.
    pub rotation_required: bool,
    /// Whether a revocation path is required.
    pub revocation_path_required: bool,
    /// Trace-safe compromise response summary.
    pub compromise_response: String,
}

/// Cryptographic agility posture for FND-011.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CryptoAgility {
    /// Explicitly allowed signature algorithm labels for future signed controls.
    ///
    /// This bounded fixture contract intentionally uses a narrow allow-list rather
    /// than a deny-list so weak or underspecified labels cannot become accidental
    /// conformance evidence. Additional labels require a follow-up RFC or fixture
    /// contract update.
    pub allowed_signature_algorithms: Vec<String>,
    /// Key rotation and revocation posture.
    pub key_rotation: KeyRotationPolicy,
    /// Extension point names for future node attestation evidence.
    pub node_attestation_extension_points: Vec<String>,
    /// Non-cryptographic assumptions that crypto cannot prove.
    pub non_cryptographic_safety_assumptions: Vec<String>,
}

/// Required security review checklist item for authorizing schemas or driver operations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityReviewChecklistItem {
    /// Stable checklist item ID.
    pub id: String,
    /// Review question or requirement.
    pub question: String,
    /// Required evidence before accepting the change.
    pub required_evidence: String,
}

/// Machine-readable FND-011 threat/invariant catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityInvariantCatalog {
    /// Catalog schema version.
    pub schema_version: String,
    /// Evidence scope for truthful partial completion reporting.
    pub evidence_scope: String,
    /// Non-claims that must accompany partial mapping evidence.
    #[serde(default)]
    pub non_claims: Vec<String>,
    /// Cryptographic agility and non-crypto safety assumptions.
    pub crypto_agility: CryptoAgility,
    /// Security review checklist required for new authorizing schemas/drivers.
    pub security_review_checklist: Vec<SecurityReviewChecklistItem>,
    /// Threat/invariant mappings.
    pub invariants: Vec<SecurityInvariantRecord>,
}

/// Security invariant validation failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SecurityInvariantValidationError {
    /// The catalog schema version was not recognized.
    #[error("security invariant schema_version must be {expected}, found {found:?}")]
    UnsupportedSchemaVersion {
        /// Required schema version.
        expected: &'static str,
        /// Found schema version.
        found: String,
    },
    /// The catalog evidence scope is not the bounded partial FND-011 scope.
    #[error("security invariant evidence_scope must be {expected}, found {found:?}")]
    UnsupportedEvidenceScope {
        /// Required evidence scope.
        expected: &'static str,
        /// Found evidence scope.
        found: String,
    },
    /// Required non-claim labels are missing.
    #[error("security invariant non_claims missing: {missing:?}")]
    MissingNonClaims {
        /// Missing non-claim labels.
        missing: Vec<&'static str>,
    },
    /// Required G80-G89 mappings are missing.
    #[error("missing security invariant mappings: {gold_ids:?}")]
    MissingGoldMappings {
        /// Missing gold IDs.
        gold_ids: Vec<&'static str>,
    },
    /// A gold case appears more than once.
    #[error("duplicate security invariant mapping for {gold_id}")]
    DuplicateGoldMapping {
        /// Duplicate gold ID.
        gold_id: String,
    },
    /// The mapping does not cover every security plane.
    #[error("security invariant catalog missing security planes: {planes:?}")]
    MissingSecurityPlanes {
        /// Missing plane labels.
        planes: Vec<&'static str>,
    },
    /// A required scalar/list field was empty.
    #[error("security invariant {gold_id} has empty field {field}")]
    EmptyField {
        /// Gold case ID.
        gold_id: String,
        /// Field name.
        field: &'static str,
    },
    /// A trust boundary relied only on prompt/instruction text.
    #[error("security invariant {gold_id} uses a prompt-only trust boundary")]
    PromptOnlyBoundary {
        /// Gold case ID.
        gold_id: String,
    },
    /// A case claimed to be exercised without explicit executable evidence metadata.
    #[error("security invariant {gold_id} is exercised without executable gold evidence")]
    MissingExecutableGoldEvidence {
        /// Gold case ID.
        gold_id: String,
    },
    /// A mandatory conformant case was skipped.
    #[error("mandatory conformant security case {gold_id} is skipped")]
    SkippedMandatoryCase {
        /// Gold case ID.
        gold_id: String,
    },
    /// Required enforcement/event/evidence/containment mapping is absent.
    #[error("security invariant {gold_id} missing enforcement field {field}")]
    MissingEnforcementMapping {
        /// Gold case ID.
        gold_id: String,
        /// Missing field.
        field: &'static str,
    },
    /// Required crypto agility field is absent.
    #[error("security invariant catalog missing crypto agility field {field}")]
    MissingCryptoAgility {
        /// Missing field.
        field: &'static str,
    },
    /// An unsafe or unsupported algorithm label was present in crypto agility metadata.
    #[error("security invariant catalog uses unsafe crypto algorithm label {algorithm:?}")]
    UnsafeCryptoAlgorithm {
        /// Rejected algorithm label.
        algorithm: String,
    },
    /// The security review checklist is missing or incomplete.
    #[error("security invariant catalog security review checklist is incomplete")]
    MissingSecurityReviewChecklist,
}

/// Validates that a catalog provides the bounded FND-011 security mapping evidence.
pub fn validate_security_invariant_catalog(
    catalog: &SecurityInvariantCatalog,
) -> Result<(), SecurityInvariantValidationError> {
    if catalog.schema_version != SECURITY_INVARIANT_SCHEMA_VERSION {
        return Err(SecurityInvariantValidationError::UnsupportedSchemaVersion {
            expected: SECURITY_INVARIANT_SCHEMA_VERSION,
            found: catalog.schema_version.clone(),
        });
    }

    if catalog.evidence_scope != SECURITY_INVARIANT_PARTIAL_EVIDENCE_SCOPE {
        return Err(SecurityInvariantValidationError::UnsupportedEvidenceScope {
            expected: SECURITY_INVARIANT_PARTIAL_EVIDENCE_SCOPE,
            found: catalog.evidence_scope.clone(),
        });
    }

    let non_claims: BTreeSet<&str> = catalog.non_claims.iter().map(String::as_str).collect();
    let missing_non_claims: Vec<&'static str> = SECURITY_INVARIANT_REQUIRED_NON_CLAIMS
        .iter()
        .copied()
        .filter(|required| !non_claims.contains(required))
        .collect();
    if !missing_non_claims.is_empty() {
        return Err(SecurityInvariantValidationError::MissingNonClaims {
            missing: missing_non_claims,
        });
    }

    validate_crypto_agility(&catalog.crypto_agility)?;
    validate_security_review_checklist(&catalog.security_review_checklist)?;

    let mut seen_gold_ids = BTreeSet::new();
    let mut covered_planes = BTreeSet::new();
    for invariant in &catalog.invariants {
        if !seen_gold_ids.insert(invariant.gold_id.clone()) {
            return Err(SecurityInvariantValidationError::DuplicateGoldMapping {
                gold_id: invariant.gold_id.clone(),
            });
        }
        validate_security_invariant_record(invariant)?;
        covered_planes.insert(invariant.primary_plane);
        covered_planes.extend(invariant.related_planes.iter().copied());
    }

    let missing_gold_ids: Vec<&'static str> = REQUIRED_SECURITY_GOLD_IDS
        .iter()
        .copied()
        .filter(|required| !seen_gold_ids.contains(*required))
        .collect();
    if !missing_gold_ids.is_empty() {
        return Err(SecurityInvariantValidationError::MissingGoldMappings {
            gold_ids: missing_gold_ids,
        });
    }

    let missing_planes: Vec<&'static str> = ALL_SECURITY_PLANES
        .iter()
        .copied()
        .filter(|plane| !covered_planes.contains(plane))
        .map(SecurityPlane::as_str)
        .collect();
    if !missing_planes.is_empty() {
        return Err(SecurityInvariantValidationError::MissingSecurityPlanes {
            planes: missing_planes,
        });
    }

    Ok(())
}

fn validate_security_invariant_record(
    invariant: &SecurityInvariantRecord,
) -> Result<(), SecurityInvariantValidationError> {
    ensure_non_empty_string(&invariant.gold_id, &invariant.gold_id, "gold_id")?;
    ensure_non_empty_string(&invariant.name, &invariant.gold_id, "name")?;
    ensure_non_empty_strings(&invariant.assets, &invariant.gold_id, "assets")?;
    ensure_non_empty_string(&invariant.principal, &invariant.gold_id, "principal")?;
    ensure_non_empty_string(
        &invariant.attacker_capability,
        &invariant.gold_id,
        "attacker_capability",
    )?;
    ensure_non_empty_string(
        &invariant.incident_classification,
        &invariant.gold_id,
        "incident_classification",
    )?;
    ensure_non_empty_string(
        &invariant.change_risk_classification,
        &invariant.gold_id,
        "change_risk_classification",
    )?;

    if invariant.trust_boundary.prompt_only {
        return Err(SecurityInvariantValidationError::PromptOnlyBoundary {
            gold_id: invariant.gold_id.clone(),
        });
    }
    ensure_non_empty_string(
        &invariant.trust_boundary.name,
        &invariant.gold_id,
        "trust_boundary.name",
    )?;
    ensure_non_empty_strings(
        &invariant.trust_boundary.enforced_by,
        &invariant.gold_id,
        "trust_boundary.enforced_by",
    )?;
    reject_prompt_only_control_text(
        &invariant.gold_id,
        "trust_boundary.name",
        std::slice::from_ref(&invariant.trust_boundary.name),
    )?;
    reject_prompt_only_control_text(
        &invariant.gold_id,
        "trust_boundary.enforced_by",
        &invariant.trust_boundary.enforced_by,
    )?;

    if invariant.maturity_gate.conformant_required
        && invariant.maturity_gate.case_status == SecurityCaseStatus::Skipped
    {
        return Err(SecurityInvariantValidationError::SkippedMandatoryCase {
            gold_id: invariant.gold_id.clone(),
        });
    }
    ensure_non_empty_string(
        &invariant.maturity_gate.non_claim,
        &invariant.gold_id,
        "maturity_gate.non_claim",
    )?;
    validate_executable_gold_evidence(&invariant.gold_id, &invariant.maturity_gate)?;

    validate_enforcement(&invariant.gold_id, &invariant.enforcement)
}

fn validate_enforcement(
    gold_id: &str,
    enforcement: &SecurityEnforcementMapping,
) -> Result<(), SecurityInvariantValidationError> {
    if enforcement.enforcing_component.trim().is_empty() {
        return Err(
            SecurityInvariantValidationError::MissingEnforcementMapping {
                gold_id: gold_id.to_string(),
                field: "enforcing_component",
            },
        );
    }
    reject_prompt_only_control_text(
        gold_id,
        "enforcement.enforcing_component",
        std::slice::from_ref(&enforcement.enforcing_component),
    )?;
    if enforcement.required_events.is_empty()
        || enforcement
            .required_events
            .iter()
            .any(|event| event.trim().is_empty())
    {
        return Err(
            SecurityInvariantValidationError::MissingEnforcementMapping {
                gold_id: gold_id.to_string(),
                field: "required_events",
            },
        );
    }
    if enforcement.evidence_links.is_empty()
        || enforcement
            .evidence_links
            .iter()
            .any(|evidence| evidence.trim().is_empty())
    {
        return Err(
            SecurityInvariantValidationError::MissingEnforcementMapping {
                gold_id: gold_id.to_string(),
                field: "evidence_links",
            },
        );
    }
    if enforcement.containment_actions.is_empty() {
        return Err(
            SecurityInvariantValidationError::MissingEnforcementMapping {
                gold_id: gold_id.to_string(),
                field: "containment_actions",
            },
        );
    }
    Ok(())
}

fn validate_crypto_agility(crypto: &CryptoAgility) -> Result<(), SecurityInvariantValidationError> {
    if crypto.allowed_signature_algorithms.is_empty()
        || crypto
            .allowed_signature_algorithms
            .iter()
            .any(|algorithm| algorithm.trim().is_empty())
    {
        return Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "allowed_signature_algorithms",
        });
    }
    for algorithm in &crypto.allowed_signature_algorithms {
        if is_unsafe_crypto_algorithm_label(algorithm) {
            return Err(SecurityInvariantValidationError::UnsafeCryptoAlgorithm {
                algorithm: algorithm.clone(),
            });
        }
    }
    if !crypto.key_rotation.rotation_required {
        return Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "key_rotation.rotation_required",
        });
    }
    if !crypto.key_rotation.revocation_path_required {
        return Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "key_rotation.revocation_path_required",
        });
    }
    if crypto.key_rotation.compromise_response.trim().is_empty() {
        return Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "key_rotation.compromise_response",
        });
    }
    if crypto.node_attestation_extension_points.is_empty()
        || crypto
            .node_attestation_extension_points
            .iter()
            .any(|point| point.trim().is_empty())
    {
        return Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "node_attestation_extension_points",
        });
    }
    if crypto.non_cryptographic_safety_assumptions.is_empty()
        || crypto
            .non_cryptographic_safety_assumptions
            .iter()
            .any(|assumption| assumption.trim().is_empty())
    {
        return Err(SecurityInvariantValidationError::MissingCryptoAgility {
            field: "non_cryptographic_safety_assumptions",
        });
    }
    Ok(())
}

fn validate_executable_gold_evidence(
    gold_id: &str,
    maturity_gate: &SecurityMaturityGate,
) -> Result<(), SecurityInvariantValidationError> {
    if maturity_gate.case_status != SecurityCaseStatus::Exercised {
        return Ok(());
    }

    let Some(evidence) = &maturity_gate.executable_gold_evidence else {
        return Err(
            SecurityInvariantValidationError::MissingExecutableGoldEvidence {
                gold_id: gold_id.to_string(),
            },
        );
    };

    ensure_non_empty_string(
        &evidence.harness_id,
        gold_id,
        "executable_gold_evidence.harness_id",
    )?;
    ensure_non_empty_string(
        &evidence.report_ref,
        gold_id,
        "executable_gold_evidence.report_ref",
    )?;
    ensure_non_empty_string(
        &evidence.executed_at,
        gold_id,
        "executable_gold_evidence.executed_at",
    )?;
    ensure_non_empty_strings(
        &evidence.evidence_assertions,
        gold_id,
        "executable_gold_evidence.evidence_assertions",
    )?;
    Ok(())
}

fn reject_prompt_only_control_text(
    gold_id: &str,
    _field: &'static str,
    values: &[String],
) -> Result<(), SecurityInvariantValidationError> {
    if values
        .iter()
        .any(|value| is_prompt_only_control_text(value))
    {
        return Err(SecurityInvariantValidationError::PromptOnlyBoundary {
            gold_id: gold_id.to_string(),
        });
    }
    Ok(())
}

fn validate_security_review_checklist(
    checklist: &[SecurityReviewChecklistItem],
) -> Result<(), SecurityInvariantValidationError> {
    if checklist.is_empty()
        || checklist.iter().any(|item| {
            item.id.trim().is_empty()
                || item.question.trim().is_empty()
                || item.required_evidence.trim().is_empty()
        })
    {
        return Err(SecurityInvariantValidationError::MissingSecurityReviewChecklist);
    }
    Ok(())
}

fn ensure_non_empty_string(
    value: &str,
    gold_id: &str,
    field: &'static str,
) -> Result<(), SecurityInvariantValidationError> {
    if value.trim().is_empty() {
        return Err(SecurityInvariantValidationError::EmptyField {
            gold_id: gold_id.to_string(),
            field,
        });
    }
    Ok(())
}

fn ensure_non_empty_strings(
    values: &[String],
    gold_id: &str,
    field: &'static str,
) -> Result<(), SecurityInvariantValidationError> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(SecurityInvariantValidationError::EmptyField {
            gold_id: gold_id.to_string(),
            field,
        });
    }
    Ok(())
}

const PROMPT_ONLY_CONTROL_PHRASES: &[&str] = &[
    "prompt instruction",
    "system prompt",
    "llm instruction",
    "model instruction",
    "assistant instruction",
    "developer instruction",
    "instruction prompt",
];

const ALLOWED_SIGNATURE_ALGORITHM_LABELS: &[&str] = &["ed25519", "ecdsa_p256_sha256"];

fn is_prompt_only_control_text(value: &str) -> bool {
    let normalized = normalize_free_text(value);
    PROMPT_ONLY_CONTROL_PHRASES
        .iter()
        .any(|phrase| normalized.contains(phrase))
}

fn is_unsafe_crypto_algorithm_label(value: &str) -> bool {
    let normalized = normalize_label(value);
    if normalized.is_empty() {
        return true;
    }
    !ALLOWED_SIGNATURE_ALGORITHM_LABELS.contains(&normalized.as_str())
}

fn normalize_free_text(value: &str) -> String {
    let mut normalized = String::new();
    let mut previous_was_space = true;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
            previous_was_space = false;
        } else if !previous_was_space {
            normalized.push(' ');
            previous_was_space = true;
        }
    }
    normalized.trim().to_string()
}

fn normalize_label(value: &str) -> String {
    let mut normalized = String::new();
    let mut previous_was_separator = true;
    for character in value.trim().chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
            previous_was_separator = false;
        } else if !previous_was_separator {
            normalized.push('_');
            previous_was_separator = true;
        }
    }
    normalized.trim_matches('_').to_string()
}

const MAX_SECURITY_THREAT_ID_BYTES: usize = 96;

fn validate_threat_id(value: &str) -> Result<(), SecurityThreatIdError> {
    if value.trim().is_empty() {
        return Err(SecurityThreatIdError::Empty);
    }
    if value.len() > MAX_SECURITY_THREAT_ID_BYTES {
        return Err(SecurityThreatIdError::TooLong {
            max: MAX_SECURITY_THREAT_ID_BYTES,
        });
    }
    for character in value.chars() {
        if !(character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '.' | '_' | '-'))
        {
            return Err(SecurityThreatIdError::InvalidCharacter { character });
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/security_invariants_tests.rs"]
mod tests;
