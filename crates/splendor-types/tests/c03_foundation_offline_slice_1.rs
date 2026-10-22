#![forbid(unsafe_code)]

use serde::de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use splendor_types::{
    validate_extension_map, validate_extension_map_with_reserved_keys, validate_extension_value,
    validate_extension_value_with_reserved_keys, CallerCredential, CanonicalCountV1,
    CanonicalLabelV1, CanonicalOrdinalV1, CanonicalPositiveRevisionV1, CanonicalSchemaIdV1,
    CanonicalSequenceV1, CanonicalTimestampV1, CredentialAudience,
    DriverOperationCredentialSinksV1, ExtensionValidationError, ExtensionValidationReason,
    FoundationGrammarCodeV1, FoundationGrammarError, RegistryDeclarationDigest, TenantId,
    TraceEvent, WorkOrder,
};
use std::collections::{BTreeMap, HashSet};
use std::error::Error as _;
use std::fmt;
use std::io::{self, Write};
use std::str::FromStr;

const README_BYTES: &[u8] = include_bytes!("../../../conformance/0.2/c03-foundation/v1/README.md");
const MANIFEST_BYTES: &[u8] =
    include_bytes!("../../../conformance/0.2/c03-foundation/v1/manifest.json");
const POSITIVE_CASE_BYTES: &[u8] =
    include_bytes!("../../../conformance/0.2/c03-foundation/v1/positive/cases.json");
const NEGATIVE_CASE_BYTES: &[u8] =
    include_bytes!("../../../conformance/0.2/c03-foundation/v1/negative/cases.json");
const DECLARATION_BYTES: &[u8] =
    include_bytes!("fixtures/driver/operation-credential-sinks-v1.json");

const FORMAT_MANIFEST: &str = "splendor.internal.conformance.rfc0021.offline-slice-1-manifest.v1";
const FORMAT_CASES: &str = "splendor.internal.conformance.rfc0021.offline-slice-1-cases.v1";
const PROFILE: &str = "rfc0021_c03_foundation_offline_slice_1";
const RFC_0018_HASH: &str = "427028b9fff0fe7d2337095bdb9093fd0966ea0cb4e1e68c8b1ae89a3cf5ae69";
const RFC_0020_HASH: &str = "a1e94f7df3e2778bf9e1e3724a54398e1141831ef54045ad8d969a93f5c9b561";
const RFC_0021_HASH: &str = "5ae1424de99729cf25030897d5c487a0de4e13b9aab4cb4acb951e590e3fca0b";
const RESOURCE_ID: &str = "rfc0013_driver_operation_credential_sinks_v1";
const POSITIVE_PATH: &str = "conformance/0.2/c03-foundation/v1/positive/cases.json";
const NEGATIVE_PATH: &str = "conformance/0.2/c03-foundation/v1/negative/cases.json";
const WRONG_DOMAIN: &[u8] = b"splendor.driver.operation_credential_sinks.v2";
const REVISION_MARKER: &[u8] = b"\"driver_declaration_revision\":1";
const GOLDEN_DIGEST: &str =
    "blake3:f18d117f253c367f79de0ca2c546088580cc47e53f49ce177ed10022d39ecdb6";
const MUTATED_DIGEST: &str =
    "blake3:389beec569d117cd75596113ea8283bf0595d6beb5c9a15fa9bb6401648f5444";
const WRONG_DOMAIN_DIGEST: &str =
    "blake3:ce3e3334c4d36ffdf3dfff0dd71132a38116e8fa0c6c1843c10e395fa065c59a";
const RELATION_NOW_UNIX: i64 = 1_893_542_400;
const EXPECTED_TENANT_ID: &str = "00000000-0000-4000-8000-000000000001";
const EXPECTED_APP_PRINCIPAL_ID: &str = "app_expected";
const EXPECTED_DAEMON_ID: &str = "daemon_expected";

const README_MAX_BYTES: usize = 65_536;
const MANIFEST_MAX_BYTES: usize = 65_536;
const CASE_FILE_MAX_BYTES: usize = 262_144;
const BUILTIN_RESOURCE_MAX_BYTES: usize = 65_536;
const CASES_PER_FILE_MIN: usize = 1;
const CASES_PER_FILE_MAX: usize = 256;
const CASES_TOTAL_MAX: usize = 512;
const CASE_ID_MAX_BYTES: usize = 64;
const INLINE_TEXT_MAX_BYTES: usize = 8_192;
const INLINE_JSON_MAX_BYTES: usize = 32_768;
const OUTPUT_MAX_BYTES: usize = 65_536;
const JSON_MAX_DEPTH: usize = 16;
const JSON_OBJECT_MEMBERS_MAX: usize = 256;
const JSON_ARRAY_ELEMENTS_MAX: usize = 256;
const ADDITIONAL_RESERVED_KEYS_MAX: usize = 16;
const METADATA_STRING_MAX_BYTES: usize = 256;

const REQUIRED_LIVE_CASE_IDS: [&str; 4] = [
    "live_relation.stale_work_order",
    "live_relation.wrong_owner_caller_credential",
    "live_relation.wrong_tenant_work_order",
    "live_relation.wrong_audience_caller_credential",
];

const NON_CLAIMS: [&str; 12] = [
    "no_fnd_006_completion",
    "no_issue_225_closure",
    "no_c03_completion",
    "no_g00_or_g72_pass",
    "no_live_disposition",
    "no_compatibility_classification",
    "no_schema_registration",
    "no_public_schema_enum_or_runtime_serde",
    "no_generated_surface_or_sdk",
    "no_owner_integration",
    "no_daemon_store_runtime_or_migration_change",
    "no_gold_task_conformance_release_or_production_claim",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureCategory {
    RawBound,
    Utf8,
    JsonEnvelope,
    FixtureContract,
    IdentityOrder,
    Dispatch,
    Observation,
    ProductionRejected,
    ProductionAccepted,
    SerializationBound,
    ValueMismatch,
}

impl FailureCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RawBound => "raw_bound",
            Self::Utf8 => "utf8",
            Self::JsonEnvelope => "json_envelope",
            Self::FixtureContract => "fixture_contract",
            Self::IdentityOrder => "identity_order",
            Self::Dispatch => "dispatch",
            Self::Observation => "observation",
            Self::ProductionRejected => "production_rejected",
            Self::ProductionAccepted => "production_accepted",
            Self::SerializationBound => "serialization_bound",
            Self::ValueMismatch => "value_mismatch",
        }
    }
}

struct Diagnostic {
    case_id: String,
    subject: Subject,
    operation: Operation,
    category: FailureCategory,
    matches: Vec<bool>,
    byte_lengths: Vec<usize>,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "case={} subject={} operation={} category={} matches={:?} byte_lengths={:?}",
            self.case_id,
            self.subject.as_str(),
            self.operation.as_str(),
            self.category.as_str(),
            self.matches,
            self.byte_lengths
        )
    }
}

impl fmt::Debug for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

enum HarnessError {
    Sanitized(FailureCategory),
    Mismatch(Diagnostic),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sanitized(category) => formatter.write_str(category.as_str()),
            Self::Mismatch(diagnostic) => diagnostic.fmt(formatter),
        }
    }
}

impl fmt::Debug for HarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

type HarnessResult<T> = Result<T, HarnessError>;

fn sanitized(category: FailureCategory) -> HarnessError {
    HarnessError::Sanitized(category)
}

fn replace_once_sanitized(input: &str, from: &str, to: &str) -> HarnessResult<String> {
    let changed = input.replacen(from, to, 1);
    if changed == input {
        Err(sanitized(FailureCategory::FixtureContract))
    } else {
        Ok(changed)
    }
}

fn mismatch(
    case: &Case,
    category: FailureCategory,
    matches: &[bool],
    byte_lengths: &[usize],
) -> HarnessError {
    HarnessError::Mismatch(Diagnostic {
        case_id: case.case_id.clone(),
        subject: case.subject,
        operation: case.operation,
        category,
        matches: matches.to_vec(),
        byte_lengths: byte_lengths.to_vec(),
    })
}

fn require_case(
    condition: bool,
    case: &Case,
    category: FailureCategory,
    matches: &[bool],
    byte_lengths: &[usize],
) -> HarnessResult<()> {
    if condition {
        Ok(())
    } else {
        Err(mismatch(case, category, matches, byte_lengths))
    }
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_id: String,
    profile: String,
    fixture_contract_revision: u64,
    accepted_proposal_sha256: AcceptedHashes,
    active_execution_line: String,
    program: String,
    component: String,
    task_id: String,
    issue_number: u64,
    owner_package: String,
    dependencies: Vec<String>,
    primary_functional_requirements: Vec<String>,
    preserved_requirements: Vec<String>,
    foundation_readiness_status: String,
    task_status: String,
    slice_status: String,
    case_id_pattern: String,
    limits: Limits,
    case_files: Vec<CaseFileEntry>,
    builtin_resource_id: String,
    production_surfaces: Vec<ProductionSurface>,
    live_disposition_status: String,
    compatibility_classification_status: String,
    required_live_relation_case_ids: Vec<String>,
    gold_statuses: Vec<GoldStatus>,
    non_claims: Vec<String>,
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct AcceptedHashes {
    rfc_0018: String,
    rfc_0020: String,
    rfc_0021: String,
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Limits {
    readme_max_bytes: usize,
    manifest_max_bytes: usize,
    case_file_max_bytes: usize,
    builtin_resource_max_bytes: usize,
    cases_per_file_min: usize,
    cases_per_file_max: usize,
    cases_total_max: usize,
    case_id_max_ascii_bytes: usize,
    inline_text_max_bytes: usize,
    inline_json_max_bytes: usize,
    serialized_output_max_bytes: usize,
    json_max_depth: usize,
    json_object_members_max: usize,
    json_array_elements_max: usize,
    additional_reserved_keys_max: usize,
    metadata_string_max_bytes: usize,
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct CaseFileEntry {
    file_id: String,
    polarity: Polarity,
    path: String,
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProductionSurface {
    subject: String,
    rust_surface: String,
    entry_points: Vec<String>,
}

#[derive(Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct GoldStatus {
    gold_id: String,
    source_status: String,
    evidence_status: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseFile {
    format_id: String,
    profile: String,
    polarity: Polarity,
    case_count: usize,
    cases: Vec<Case>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    case_id: String,
    subject: Subject,
    operation: Operation,
    input: Input,
    expected: Expected,
    live_disposition_status: String,
    schema_registration_status: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Polarity {
    Positive,
    Negative,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Subject {
    CanonicalSchemaIdV1,
    CanonicalLabelV1,
    FoundationGrammarCodeV1,
    CanonicalTimestampV1,
    CanonicalCountV1,
    CanonicalOrdinalV1,
    CanonicalSequenceV1,
    CanonicalPositiveRevisionV1,
    FoundationGrammarError,
    RegistryDeclarationDigest,
    TraceEvent,
    SchemaExtensionMap,
    SchemaExtensionValue,
    WorkOrder,
    CallerCredential,
}

impl Subject {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalSchemaIdV1 => "canonical_schema_id_v1",
            Self::CanonicalLabelV1 => "canonical_label_v1",
            Self::FoundationGrammarCodeV1 => "foundation_grammar_code_v1",
            Self::CanonicalTimestampV1 => "canonical_timestamp_v1",
            Self::CanonicalCountV1 => "canonical_count_v1",
            Self::CanonicalOrdinalV1 => "canonical_ordinal_v1",
            Self::CanonicalSequenceV1 => "canonical_sequence_v1",
            Self::CanonicalPositiveRevisionV1 => "canonical_positive_revision_v1",
            Self::FoundationGrammarError => "foundation_grammar_error",
            Self::RegistryDeclarationDigest => "registry_declaration_digest",
            Self::TraceEvent => "trace_event",
            Self::SchemaExtensionMap => "schema_extension_map",
            Self::SchemaExtensionValue => "schema_extension_value",
            Self::WorkOrder => "work_order",
            Self::CallerCredential => "caller_credential",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Parse,
    Construct,
    FromStr,
    Serialize,
    ParseReject,
    ConstructReject,
    FromStrReject,
    InspectError,
    DeclarationDigest,
    WrongDomainCompare,
    TraceDeserializeSerialize,
    TraceReject,
    ValidateExtensionMap,
    ValidateExtensionMapWithReservedKeys,
    ValidateExtensionValue,
    ValidateExtensionValueWithReservedKeys,
    ParseLiveRelation,
}

impl Operation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Construct => "construct",
            Self::FromStr => "from_str",
            Self::Serialize => "serialize",
            Self::ParseReject => "parse_reject",
            Self::ConstructReject => "construct_reject",
            Self::FromStrReject => "from_str_reject",
            Self::InspectError => "inspect_error",
            Self::DeclarationDigest => "declaration_digest",
            Self::WrongDomainCompare => "wrong_domain_compare",
            Self::TraceDeserializeSerialize => "trace_deserialize_serialize",
            Self::TraceReject => "trace_reject",
            Self::ValidateExtensionMap => "validate_extension_map",
            Self::ValidateExtensionMapWithReservedKeys => {
                "validate_extension_map_with_reserved_keys"
            }
            Self::ValidateExtensionValue => "validate_extension_value",
            Self::ValidateExtensionValueWithReservedKeys => {
                "validate_extension_value_with_reserved_keys"
            }
            Self::ParseLiveRelation => "parse_live_relation",
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Input {
    Text(TextBody),
    U64(U64Body),
    ErrorCode(ErrorCodeBody),
    Declaration(DeclarationBody),
    TraceJson(JsonBody),
    ExtensionJson(ExtensionBody),
    WorkOrderJson(JsonBody),
    CallerCredentialJson(JsonBody),
}

impl Input {
    const fn kind(&self) -> InputKind {
        match self {
            Self::Text(_) => InputKind::Text,
            Self::U64(_) => InputKind::U64,
            Self::ErrorCode(_) => InputKind::ErrorCode,
            Self::Declaration(_) => InputKind::Declaration,
            Self::TraceJson(_) => InputKind::TraceJson,
            Self::ExtensionJson(_) => InputKind::ExtensionJson,
            Self::WorkOrderJson(_) => InputKind::WorkOrderJson,
            Self::CallerCredentialJson(_) => InputKind::CallerCredentialJson,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum InputKind {
    Text,
    U64,
    ErrorCode,
    Declaration,
    TraceJson,
    ExtensionJson,
    WorkOrderJson,
    CallerCredentialJson,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TextBody {
    value: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct U64Body {
    value: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorCodeBody {
    value: ErrorCode,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclarationBody {
    resource_id: ResourceId,
    mutation: DeclarationMutation,
    digest_domain: DigestDomain,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonBody {
    json: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtensionBody {
    json: String,
    root_path: String,
    additional_reserved_keys: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ResourceId {
    Rfc0013DriverOperationCredentialSinksV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DeclarationMutation {
    None,
    #[serde(rename = "driver_declaration_revision_1_to_2")]
    DriverDeclarationRevision1To2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DigestDomain {
    Production,
    WrongDomainV2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ErrorCode {
    #[serde(rename = "invalid_contract_shape")]
    Shape,
    #[serde(rename = "invalid_contract_version")]
    Version,
    #[serde(rename = "invalid_contract_identity")]
    Identity,
    #[serde(rename = "invalid_contract_timestamp")]
    Timestamp,
    #[serde(rename = "invalid_contract_integer")]
    Integer,
    #[serde(rename = "invalid_contract_digest")]
    Digest,
    #[serde(rename = "invalid_contract_signature")]
    Signature,
    #[serde(rename = "invalid_contract_bound")]
    Bound,
    #[serde(rename = "invalid_contract_binding")]
    Binding,
}

impl ErrorCode {
    const fn grammar_error(self) -> FoundationGrammarError {
        match self {
            Self::Shape => FoundationGrammarError::InvalidContractShape,
            Self::Version => FoundationGrammarError::InvalidContractVersion,
            Self::Identity => FoundationGrammarError::InvalidContractIdentity,
            Self::Timestamp => FoundationGrammarError::InvalidContractTimestamp,
            Self::Integer => FoundationGrammarError::InvalidContractInteger,
            Self::Digest => FoundationGrammarError::InvalidContractDigest,
            Self::Signature => FoundationGrammarError::InvalidContractSignature,
            Self::Bound => FoundationGrammarError::InvalidContractBound,
            Self::Binding => FoundationGrammarError::InvalidContractBinding,
        }
    }

    const fn as_str(self) -> &'static str {
        self.grammar_error().as_str()
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    execution_result: ExecutionResult,
    #[serde(default, deserialize_with = "non_null_option")]
    stable_error_code: Option<ErrorCode>,
    #[serde(default, deserialize_with = "non_null_option")]
    serialized_utf8: Option<String>,
    #[serde(default, deserialize_with = "non_null_option")]
    expected_digest_wire: Option<String>,
    #[serde(default, deserialize_with = "non_null_option")]
    digest_equality: Option<bool>,
    #[serde(default, deserialize_with = "non_null_option")]
    extension_error: Option<ExpectedExtensionError>,
}

fn non_null_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ExecutionResult {
    Accepted,
    Rejected,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedExtensionError {
    reason: ExtensionReason,
    path: String,
    key: String,
    normalized_key: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ExtensionReason {
    #[serde(rename = "blank_extension_key")]
    Blank,
    #[serde(rename = "trimmed_extension_key")]
    Trimmed,
    #[serde(rename = "reserved_authority_key")]
    ReservedAuthority,
}

impl ExtensionReason {
    const fn production(self) -> ExtensionValidationReason {
        match self {
            Self::Blank => ExtensionValidationReason::BlankKey,
            Self::Trimmed => ExtensionValidationReason::TrimmedKey,
            Self::ReservedAuthority => ExtensionValidationReason::ReservedAuthorityKey,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DuplicatePolicy {
    Permit,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StringLimitPolicy {
    Fixture,
    Inline,
}

impl StringLimitPolicy {
    fn value_limit(self, field: Option<&str>) -> usize {
        match (self, field) {
            (Self::Fixture, Some("json")) => INLINE_JSON_MAX_BYTES,
            (Self::Fixture, Some("serialized_utf8")) => OUTPUT_MAX_BYTES,
            (Self::Fixture, Some("value")) => INLINE_TEXT_MAX_BYTES,
            _ => METADATA_STRING_MAX_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsonKind {
    Object,
    Array,
    Scalar,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PreflightStats {
    root_kind: Option<JsonKind>,
    maximum_depth: usize,
    maximum_object_members: usize,
    maximum_array_elements: usize,
}

struct ScanSeed<'a> {
    stats: &'a mut PreflightStats,
    depth: usize,
    duplicates: DuplicatePolicy,
    strings: StringLimitPolicy,
    value_limit: usize,
}

impl<'de> DeserializeSeed<'de> for ScanSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > JSON_MAX_DEPTH {
            return Err(D::Error::custom("bounded_json"));
        }
        self.stats.maximum_depth = self.stats.maximum_depth.max(self.depth);
        deserializer.deserialize_any(ScanVisitor(self))
    }
}

struct ScanVisitor<'a>(ScanSeed<'a>);

impl<'de> Visitor<'de> for ScanVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.0.depth == 1 {
            self.0.stats.root_kind = Some(JsonKind::Object);
        }
        let mut members = 0_usize;
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            members += 1;
            if members > JSON_OBJECT_MEMBERS_MAX || name.len() > METADATA_STRING_MAX_BYTES {
                return Err(A::Error::custom("bounded_json"));
            }
            if self.0.duplicates == DuplicatePolicy::Reject && !names.insert(name.clone()) {
                return Err(A::Error::custom("bounded_json"));
            }
            let value_limit = self.0.strings.value_limit(Some(&name));
            map.next_value_seed(ScanSeed {
                stats: self.0.stats,
                depth: self.0.depth + 1,
                duplicates: self.0.duplicates,
                strings: self.0.strings,
                value_limit,
            })?;
        }
        self.0.stats.maximum_object_members = self.0.stats.maximum_object_members.max(members);
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.0.depth == 1 {
            self.0.stats.root_kind = Some(JsonKind::Array);
        }
        let mut elements = 0_usize;
        while sequence
            .next_element_seed(ScanSeed {
                stats: self.0.stats,
                depth: self.0.depth + 1,
                duplicates: self.0.duplicates,
                strings: self.0.strings,
                value_limit: self.0.value_limit,
            })?
            .is_some()
        {
            elements += 1;
            if elements > JSON_ARRAY_ELEMENTS_MAX {
                return Err(A::Error::custom("bounded_json"));
            }
        }
        self.0.stats.maximum_array_elements = self.0.stats.maximum_array_elements.max(elements);
        Ok(())
    }

    fn visit_str<E>(mut self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.scalar_root();
        if value.len() <= self.0.value_limit {
            Ok(())
        } else {
            Err(E::custom("bounded_json"))
        }
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_bool<E>(mut self, _value: bool) -> Result<Self::Value, E> {
        self.scalar_root();
        Ok(())
    }

    fn visit_i64<E>(mut self, _value: i64) -> Result<Self::Value, E> {
        self.scalar_root();
        Ok(())
    }

    fn visit_u64<E>(mut self, _value: u64) -> Result<Self::Value, E> {
        self.scalar_root();
        Ok(())
    }

    fn visit_f64<E>(mut self, _value: f64) -> Result<Self::Value, E> {
        self.scalar_root();
        Ok(())
    }

    fn visit_unit<E>(mut self) -> Result<Self::Value, E> {
        self.scalar_root();
        Ok(())
    }

    fn visit_none<E>(mut self) -> Result<Self::Value, E> {
        self.scalar_root();
        Ok(())
    }
}

impl ScanVisitor<'_> {
    fn scalar_root(&mut self) {
        if self.0.depth == 1 {
            self.0.stats.root_kind = Some(JsonKind::Scalar);
        }
    }
}

fn preflight_json(
    input: &str,
    duplicates: DuplicatePolicy,
    strings: StringLimitPolicy,
) -> HarnessResult<PreflightStats> {
    let mut stats = PreflightStats::default();
    let mut deserializer = serde_json::Deserializer::from_str(input);
    ScanSeed {
        stats: &mut stats,
        depth: 1,
        duplicates,
        strings,
        value_limit: strings.value_limit(None),
    }
    .deserialize(&mut deserializer)
    .map_err(|_| sanitized(FailureCategory::JsonEnvelope))?;
    deserializer
        .end()
        .map_err(|_| sanitized(FailureCategory::JsonEnvelope))?;
    Ok(stats)
}

fn bounded_utf8(input: &[u8], maximum: usize) -> HarnessResult<&str> {
    if input.len() > maximum {
        return Err(sanitized(FailureCategory::RawBound));
    }
    std::str::from_utf8(input).map_err(|_| sanitized(FailureCategory::Utf8))
}

fn parse_closed<T: DeserializeOwned>(input: &[u8], maximum: usize) -> HarnessResult<T> {
    let text = bounded_utf8(input, maximum)?;
    preflight_json(text, DuplicatePolicy::Permit, StringLimitPolicy::Fixture)?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let parsed = T::deserialize(&mut deserializer)
        .map_err(|_| sanitized(FailureCategory::FixtureContract))?;
    deserializer
        .end()
        .map_err(|_| sanitized(FailureCategory::FixtureContract))?;
    Ok(parsed)
}

fn load_readme(input: &[u8]) -> HarnessResult<()> {
    let text = bounded_utf8(input, README_MAX_BYTES)?;
    if text.is_empty() || !text.contains(PROFILE) {
        return Err(sanitized(FailureCategory::FixtureContract));
    }
    Ok(())
}

fn expected_limits() -> Limits {
    Limits {
        readme_max_bytes: README_MAX_BYTES,
        manifest_max_bytes: MANIFEST_MAX_BYTES,
        case_file_max_bytes: CASE_FILE_MAX_BYTES,
        builtin_resource_max_bytes: BUILTIN_RESOURCE_MAX_BYTES,
        cases_per_file_min: CASES_PER_FILE_MIN,
        cases_per_file_max: CASES_PER_FILE_MAX,
        cases_total_max: CASES_TOTAL_MAX,
        case_id_max_ascii_bytes: CASE_ID_MAX_BYTES,
        inline_text_max_bytes: INLINE_TEXT_MAX_BYTES,
        inline_json_max_bytes: INLINE_JSON_MAX_BYTES,
        serialized_output_max_bytes: OUTPUT_MAX_BYTES,
        json_max_depth: JSON_MAX_DEPTH,
        json_object_members_max: JSON_OBJECT_MEMBERS_MAX,
        json_array_elements_max: JSON_ARRAY_ELEMENTS_MAX,
        additional_reserved_keys_max: ADDITIONAL_RESERVED_KEYS_MAX,
        metadata_string_max_bytes: METADATA_STRING_MAX_BYTES,
    }
}

fn expected_surfaces() -> Vec<ProductionSurface> {
    fn surface(subject: &str, rust_surface: &str, entry_points: &[&str]) -> ProductionSurface {
        ProductionSurface {
            subject: subject.to_string(),
            rust_surface: rust_surface.to_string(),
            entry_points: entry_points
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        }
    }
    vec![
        surface(
            "canonical_schema_id_v1",
            "splendor_types::CanonicalSchemaIdV1",
            &[
                "splendor_types::CanonicalSchemaIdV1::parse",
                "splendor_types::CanonicalSchemaIdV1::try_new",
                "<splendor_types::CanonicalSchemaIdV1 as std::str::FromStr>::from_str",
                "splendor_types::CanonicalSchemaIdV1::as_str",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "canonical_label_v1",
            "splendor_types::CanonicalLabelV1",
            &[
                "splendor_types::CanonicalLabelV1::parse",
                "splendor_types::CanonicalLabelV1::try_new",
                "<splendor_types::CanonicalLabelV1 as std::str::FromStr>::from_str",
                "splendor_types::CanonicalLabelV1::as_str",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "foundation_grammar_code_v1",
            "splendor_types::FoundationGrammarCodeV1",
            &[
                "splendor_types::FoundationGrammarCodeV1::parse",
                "splendor_types::FoundationGrammarCodeV1::try_new",
                "<splendor_types::FoundationGrammarCodeV1 as std::str::FromStr>::from_str",
                "splendor_types::FoundationGrammarCodeV1::as_str",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "canonical_timestamp_v1",
            "splendor_types::CanonicalTimestampV1",
            &[
                "splendor_types::CanonicalTimestampV1::parse",
                "splendor_types::CanonicalTimestampV1::try_new",
                "<splendor_types::CanonicalTimestampV1 as std::str::FromStr>::from_str",
                "splendor_types::CanonicalTimestampV1::as_str",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "canonical_count_v1",
            "splendor_types::CanonicalCountV1",
            &[
                "splendor_types::CanonicalCountV1::parse",
                "splendor_types::CanonicalCountV1::try_new",
                "<splendor_types::CanonicalCountV1 as std::str::FromStr>::from_str",
                "splendor_types::CanonicalCountV1::get",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "canonical_ordinal_v1",
            "splendor_types::CanonicalOrdinalV1",
            &[
                "splendor_types::CanonicalOrdinalV1::parse",
                "splendor_types::CanonicalOrdinalV1::try_new",
                "<splendor_types::CanonicalOrdinalV1 as std::str::FromStr>::from_str",
                "splendor_types::CanonicalOrdinalV1::get",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "canonical_sequence_v1",
            "splendor_types::CanonicalSequenceV1",
            &[
                "splendor_types::CanonicalSequenceV1::parse",
                "splendor_types::CanonicalSequenceV1::try_new",
                "<splendor_types::CanonicalSequenceV1 as std::str::FromStr>::from_str",
                "splendor_types::CanonicalSequenceV1::get",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "canonical_positive_revision_v1",
            "splendor_types::CanonicalPositiveRevisionV1",
            &[
                "splendor_types::CanonicalPositiveRevisionV1::parse",
                "splendor_types::CanonicalPositiveRevisionV1::try_new",
                "<splendor_types::CanonicalPositiveRevisionV1 as std::str::FromStr>::from_str",
                "splendor_types::CanonicalPositiveRevisionV1::get",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "foundation_grammar_error",
            "splendor_types::FoundationGrammarError",
            &[
                "splendor_types::FoundationGrammarError::as_str",
                "std::fmt::Display::fmt",
                "std::fmt::Debug::fmt",
                "std::error::Error::source",
            ],
        ),
        surface(
            "registry_declaration_digest",
            "splendor_types::RegistryDeclarationDigest",
            &[
                "splendor_types::DriverOperationCredentialSinksV1::from_json_slice",
                "splendor_types::DriverOperationCredentialSinksV1::driver_declaration_revision",
                "<splendor_types::RegistryDeclarationDigest as std::convert::TryFrom<&splendor_types::DriverOperationCredentialSinksV1>>::try_from",
                "splendor_types::RegistryDeclarationDigest::parse",
                "<splendor_types::RegistryDeclarationDigest as std::str::FromStr>::from_str",
                "std::fmt::Debug::fmt",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "trace_event",
            "splendor_types::TraceEvent",
            &[
                "serde_json::from_str::<splendor_types::TraceEvent>",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "schema_extension_map",
            "std::collections::BTreeMap<String, serde_json::Value>",
            &[
                "splendor_types::validate_extension_map",
                "splendor_types::validate_extension_map_with_reserved_keys",
            ],
        ),
        surface(
            "schema_extension_value",
            "serde_json::Value",
            &[
                "splendor_types::validate_extension_value",
                "splendor_types::validate_extension_value_with_reserved_keys",
            ],
        ),
        surface(
            "work_order",
            "splendor_types::WorkOrder",
            &[
                "serde_json::from_str::<splendor_types::WorkOrder>",
                "splendor_types::WorkOrder::signing_payload_bytes",
                "serde_json::to_writer",
            ],
        ),
        surface(
            "caller_credential",
            "splendor_types::CallerCredential",
            &[
                "serde_json::from_str::<splendor_types::CallerCredential>",
                "serde_json::to_writer",
            ],
        ),
    ]
}

fn validate_manifest(manifest: &Manifest) -> HarnessResult<()> {
    let exact = manifest.format_id == FORMAT_MANIFEST
        && manifest.profile == PROFILE
        && manifest.fixture_contract_revision == 1
        && manifest.accepted_proposal_sha256.rfc_0018 == RFC_0018_HASH
        && manifest.accepted_proposal_sha256.rfc_0020 == RFC_0020_HASH
        && manifest.accepted_proposal_sha256.rfc_0021 == RFC_0021_HASH
        && manifest.active_execution_line == "0.2/v2"
        && manifest.program == "V2-FND-0 Foundations"
        && manifest.component == "C03"
        && manifest.task_id == "FND-006"
        && manifest.issue_number == 225
        && manifest.owner_package == "crates/splendor-types"
        && strings_equal(&manifest.dependencies, &["FND-001", "FND-002"])
        && strings_equal(
            &manifest.primary_functional_requirements,
            &["FR-0.2-01", "FR-0.2-08"],
        )
        && strings_equal(
            &manifest.preserved_requirements,
            &["FR-0.2-02", "stable_0.1"],
        )
        && manifest.foundation_readiness_status == "foundation_ready"
        && manifest.task_status == "partial_slice_1_not_completed"
        && manifest.slice_status == "offline_characterization_only"
        && manifest.case_id_pattern == "^[a-z0-9][a-z0-9._-]*$"
        && manifest.limits == expected_limits()
        && manifest.builtin_resource_id == RESOURCE_ID
        && manifest.production_surfaces == expected_surfaces()
        && manifest.live_disposition_status == "not_exercised"
        && manifest.compatibility_classification_status == "not_exercised"
        && strings_equal(
            &manifest.required_live_relation_case_ids,
            &REQUIRED_LIVE_CASE_IDS,
        )
        && strings_equal(&manifest.non_claims, &NON_CLAIMS);
    if !exact {
        return Err(sanitized(FailureCategory::FixtureContract));
    }

    let files_ok = manifest.case_files.len() == 2
        && manifest.case_files[0].file_id == "positive_cases"
        && manifest.case_files[0].polarity == Polarity::Positive
        && manifest.case_files[0].path == POSITIVE_PATH
        && manifest.case_files[1].file_id == "negative_cases"
        && manifest.case_files[1].polarity == Polarity::Negative
        && manifest.case_files[1].path == NEGATIVE_PATH;
    let gold_ok = manifest.gold_statuses.len() == 2
        && manifest.gold_statuses[0].gold_id == "G00"
        && manifest.gold_statuses[0].source_status == "specified_not_implemented"
        && manifest.gold_statuses[0].evidence_status == "not_exercised"
        && manifest.gold_statuses[1].gold_id == "G72"
        && manifest.gold_statuses[1].source_status == "specified_not_implemented"
        && manifest.gold_statuses[1].evidence_status == "not_exercised";
    if files_ok && gold_ok {
        Ok(())
    } else {
        Err(sanitized(FailureCategory::FixtureContract))
    }
}

fn strings_equal(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
}

fn valid_case_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= CASE_ID_MAX_BYTES
        && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn valid_root_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= METADATA_STRING_MAX_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

fn validate_case_file(file: &CaseFile, source_polarity: Polarity) -> HarnessResult<()> {
    if file.format_id != FORMAT_CASES
        || file.profile != PROFILE
        || file.polarity != source_polarity
        || file.case_count != file.cases.len()
        || !(CASES_PER_FILE_MIN..=CASES_PER_FILE_MAX).contains(&file.cases.len())
    {
        return Err(sanitized(FailureCategory::FixtureContract));
    }
    let mut previous: Option<&str> = None;
    for case in &file.cases {
        if !valid_case_id(&case.case_id)
            || previous.is_some_and(|value| value >= case.case_id.as_str())
        {
            return Err(sanitized(FailureCategory::IdentityOrder));
        }
        previous = Some(&case.case_id);
        validate_case(case, source_polarity)?;
    }
    Ok(())
}

fn validate_case(case: &Case, polarity: Polarity) -> HarnessResult<()> {
    if case.live_disposition_status != "not_exercised"
        || case.schema_registration_status != "not_exercised"
    {
        return Err(sanitized(FailureCategory::FixtureContract));
    }
    match &case.input {
        Input::Text(body) if body.value.len() <= INLINE_TEXT_MAX_BYTES => {}
        Input::U64(_) | Input::ErrorCode(_) => {}
        Input::Declaration(body) => {
            validate_declaration_combination(case.operation, body)?;
            let fixed_wire = match (body.mutation, body.digest_domain) {
                (DeclarationMutation::None, DigestDomain::Production) => GOLDEN_DIGEST,
                (DeclarationMutation::DriverDeclarationRevision1To2, DigestDomain::Production) => {
                    MUTATED_DIGEST
                }
                (DeclarationMutation::None, DigestDomain::WrongDomainV2) => WRONG_DOMAIN_DIGEST,
                _ => return Err(sanitized(FailureCategory::Dispatch)),
            };
            if case.expected.expected_digest_wire.as_deref() != Some(fixed_wire) {
                return Err(sanitized(FailureCategory::Observation));
            }
        }
        Input::TraceJson(body) => {
            validate_inline_json(&body.json, DuplicatePolicy::Permit)?;
        }
        Input::ExtensionJson(body) => {
            let stats = validate_inline_json(&body.json, DuplicatePolicy::Reject)?;
            if !valid_root_path(&body.root_path)
                || body.additional_reserved_keys.len() > ADDITIONAL_RESERVED_KEYS_MAX
                || body
                    .additional_reserved_keys
                    .iter()
                    .any(|key| key.len() > METADATA_STRING_MAX_BYTES)
            {
                return Err(sanitized(FailureCategory::FixtureContract));
            }
            if case.subject == Subject::SchemaExtensionMap
                && stats.root_kind != Some(JsonKind::Object)
            {
                return Err(sanitized(FailureCategory::Dispatch));
            }
        }
        Input::WorkOrderJson(body) | Input::CallerCredentialJson(body) => {
            validate_inline_json(&body.json, DuplicatePolicy::Permit)?;
        }
        Input::Text(_) => return Err(sanitized(FailureCategory::RawBound)),
    }
    validate_dispatch(case)?;
    validate_expected(case)?;
    validate_polarity(case, polarity)
}

fn validate_inline_json(input: &str, duplicates: DuplicatePolicy) -> HarnessResult<PreflightStats> {
    if input.len() > INLINE_JSON_MAX_BYTES {
        return Err(sanitized(FailureCategory::RawBound));
    }
    preflight_json(input, duplicates, StringLimitPolicy::Inline)
}

fn validate_declaration_combination(
    operation: Operation,
    body: &DeclarationBody,
) -> HarnessResult<()> {
    let _resource_is_fixed =
        body.resource_id == ResourceId::Rfc0013DriverOperationCredentialSinksV1;
    let legal = matches!(
        (operation, body.mutation, body.digest_domain),
        (
            Operation::DeclarationDigest,
            DeclarationMutation::None,
            DigestDomain::Production
        ) | (
            Operation::DeclarationDigest,
            DeclarationMutation::DriverDeclarationRevision1To2,
            DigestDomain::Production
        ) | (
            Operation::WrongDomainCompare,
            DeclarationMutation::None,
            DigestDomain::WrongDomainV2
        )
    );
    if legal {
        Ok(())
    } else {
        Err(sanitized(FailureCategory::Dispatch))
    }
}

fn legal_dispatch(subject: Subject, operation: Operation, input: InputKind, case_id: &str) -> bool {
    use InputKind as I;
    use Operation as O;
    use Subject as S;
    let string_scalar = matches!(
        subject,
        S::CanonicalSchemaIdV1
            | S::CanonicalLabelV1
            | S::FoundationGrammarCodeV1
            | S::CanonicalTimestampV1
    );
    let integer_scalar = matches!(
        subject,
        S::CanonicalCountV1
            | S::CanonicalOrdinalV1
            | S::CanonicalSequenceV1
            | S::CanonicalPositiveRevisionV1
    );
    (string_scalar
        && input == I::Text
        && matches!(
            operation,
            O::Parse
                | O::Construct
                | O::FromStr
                | O::Serialize
                | O::ParseReject
                | O::ConstructReject
                | O::FromStrReject
        ))
        || (integer_scalar
            && input == I::Text
            && matches!(
                operation,
                O::Parse | O::FromStr | O::ParseReject | O::FromStrReject
            ))
        || (integer_scalar
            && input == I::U64
            && matches!(operation, O::Construct | O::Serialize | O::ConstructReject))
        || (subject == S::FoundationGrammarError
            && operation == O::InspectError
            && input == I::ErrorCode)
        || (subject == S::RegistryDeclarationDigest
            && input == I::Text
            && matches!(
                operation,
                O::Parse | O::FromStr | O::Serialize | O::ParseReject | O::FromStrReject
            ))
        || (subject == S::RegistryDeclarationDigest
            && input == I::Declaration
            && matches!(operation, O::DeclarationDigest | O::WrongDomainCompare))
        || (subject == S::TraceEvent
            && input == I::TraceJson
            && matches!(operation, O::TraceDeserializeSerialize | O::TraceReject))
        || (subject == S::SchemaExtensionMap
            && input == I::ExtensionJson
            && matches!(
                operation,
                O::ValidateExtensionMap | O::ValidateExtensionMapWithReservedKeys
            ))
        || (subject == S::SchemaExtensionValue
            && input == I::ExtensionJson
            && matches!(
                operation,
                O::ValidateExtensionValue | O::ValidateExtensionValueWithReservedKeys
            ))
        || (subject == S::WorkOrder
            && operation == O::ParseLiveRelation
            && input == I::WorkOrderJson
            && matches!(
                case_id,
                "live_relation.stale_work_order" | "live_relation.wrong_tenant_work_order"
            ))
        || (subject == S::CallerCredential
            && operation == O::ParseLiveRelation
            && input == I::CallerCredentialJson
            && matches!(
                case_id,
                "live_relation.wrong_owner_caller_credential"
                    | "live_relation.wrong_audience_caller_credential"
            ))
}

fn validate_dispatch(case: &Case) -> HarnessResult<()> {
    if !legal_dispatch(
        case.subject,
        case.operation,
        case.input.kind(),
        &case.case_id,
    ) {
        return Err(sanitized(FailureCategory::Dispatch));
    }
    if let Input::ExtensionJson(body) = &case.input {
        let with_reserved = matches!(
            case.operation,
            Operation::ValidateExtensionMapWithReservedKeys
                | Operation::ValidateExtensionValueWithReservedKeys
        );
        if with_reserved == body.additional_reserved_keys.is_empty() {
            return Err(sanitized(FailureCategory::Dispatch));
        }
    }
    Ok(())
}

fn validate_expected(case: &Case) -> HarnessResult<()> {
    let expected = &case.expected;
    let stable = expected.stable_error_code.is_some();
    let serialized = expected.serialized_utf8.is_some();
    let digest = expected.expected_digest_wire.is_some();
    let equality = expected.digest_equality.is_some();
    let extension = expected.extension_error.is_some();
    if expected
        .serialized_utf8
        .as_ref()
        .is_some_and(|value| value.len() > OUTPUT_MAX_BYTES)
        || expected
            .expected_digest_wire
            .as_ref()
            .is_some_and(|value| value.len() > 71)
        || expected.extension_error.as_ref().is_some_and(|error| {
            [
                error.path.len(),
                error.key.len(),
                error.normalized_key.len(),
            ]
            .into_iter()
            .any(|length| length > METADATA_STRING_MAX_BYTES)
        })
    {
        return Err(sanitized(FailureCategory::RawBound));
    }

    use Operation as O;
    use Subject as S;
    let string_or_integer_scalar = matches!(
        case.subject,
        S::CanonicalSchemaIdV1
            | S::CanonicalLabelV1
            | S::FoundationGrammarCodeV1
            | S::CanonicalTimestampV1
            | S::CanonicalCountV1
            | S::CanonicalOrdinalV1
            | S::CanonicalSequenceV1
            | S::CanonicalPositiveRevisionV1
    );
    let shape = if string_or_integer_scalar
        && matches!(
            case.operation,
            O::Parse | O::Construct | O::FromStr | O::Serialize
        ) {
        expected.execution_result == ExecutionResult::Accepted
            && !stable
            && serialized
            && !digest
            && !equality
            && !extension
    } else if string_or_integer_scalar
        && matches!(
            case.operation,
            O::ParseReject | O::ConstructReject | O::FromStrReject
        )
    {
        expected.execution_result == ExecutionResult::Rejected
            && stable
            && !serialized
            && !digest
            && !equality
            && !extension
    } else if case.subject == S::FoundationGrammarError && case.operation == O::InspectError {
        expected.execution_result == ExecutionResult::Accepted
            && stable
            && !serialized
            && !digest
            && !equality
            && !extension
    } else if case.subject == S::RegistryDeclarationDigest
        && matches!(case.operation, O::Parse | O::FromStr | O::Serialize)
    {
        expected.execution_result == ExecutionResult::Accepted
            && !stable
            && serialized
            && !digest
            && !equality
            && !extension
    } else if case.subject == S::RegistryDeclarationDigest
        && matches!(case.operation, O::ParseReject | O::FromStrReject)
    {
        expected.execution_result == ExecutionResult::Rejected
            && stable
            && !serialized
            && !digest
            && !equality
            && !extension
    } else if matches!(case.operation, O::DeclarationDigest | O::WrongDomainCompare) {
        expected.execution_result == ExecutionResult::Accepted
            && !stable
            && serialized
            && digest
            && equality
            && !extension
            && expected.digest_equality == Some(case.operation == O::DeclarationDigest)
    } else if case.operation == O::TraceDeserializeSerialize {
        expected.execution_result == ExecutionResult::Accepted
            && !stable
            && serialized
            && !digest
            && !equality
            && !extension
    } else if case.operation == O::TraceReject {
        expected.execution_result == ExecutionResult::Rejected
            && !stable
            && !serialized
            && !digest
            && !equality
            && !extension
    } else if matches!(
        case.operation,
        O::ValidateExtensionMap
            | O::ValidateExtensionMapWithReservedKeys
            | O::ValidateExtensionValue
            | O::ValidateExtensionValueWithReservedKeys
    ) {
        !stable
            && !serialized
            && !digest
            && !equality
            && (expected.execution_result == ExecutionResult::Rejected) == extension
    } else if case.operation == O::ParseLiveRelation {
        expected.execution_result == ExecutionResult::Accepted
            && !stable
            && serialized
            && !digest
            && !equality
            && !extension
    } else {
        false
    };
    if shape {
        Ok(())
    } else {
        Err(sanitized(FailureCategory::Observation))
    }
}

fn validate_polarity(case: &Case, polarity: Polarity) -> HarnessResult<()> {
    let accepted_negative = case.operation == Operation::WrongDomainCompare
        || case.operation == Operation::ParseLiveRelation;
    let legal = match polarity {
        Polarity::Positive => case.expected.execution_result == ExecutionResult::Accepted,
        Polarity::Negative => {
            (case.expected.execution_result == ExecutionResult::Accepted) == accepted_negative
        }
    };
    if legal {
        Ok(())
    } else {
        Err(sanitized(FailureCategory::FixtureContract))
    }
}

fn validate_cross_file(positive: &CaseFile, negative: &CaseFile) -> HarnessResult<()> {
    let total = positive.cases.len() + negative.cases.len();
    if total > CASES_TOTAL_MAX {
        return Err(sanitized(FailureCategory::RawBound));
    }
    let mut identities = HashSet::with_capacity(total);
    if positive
        .cases
        .iter()
        .chain(&negative.cases)
        .any(|case| !identities.insert(case.case_id.as_str()))
    {
        return Err(sanitized(FailureCategory::IdentityOrder));
    }
    for required in REQUIRED_LIVE_CASE_IDS {
        if negative
            .cases
            .iter()
            .filter(|case| case.case_id == required)
            .count()
            != 1
            || positive.cases.iter().any(|case| case.case_id == required)
        {
            return Err(sanitized(FailureCategory::FixtureContract));
        }
    }
    Ok(())
}

fn load_all() -> HarnessResult<(Manifest, CaseFile, CaseFile)> {
    load_readme(README_BYTES)?;
    if DECLARATION_BYTES.len() > BUILTIN_RESOURCE_MAX_BYTES {
        return Err(sanitized(FailureCategory::RawBound));
    }
    let manifest: Manifest = parse_closed(MANIFEST_BYTES, MANIFEST_MAX_BYTES)?;
    validate_manifest(&manifest)?;
    let positive: CaseFile = parse_closed(POSITIVE_CASE_BYTES, CASE_FILE_MAX_BYTES)?;
    let negative: CaseFile = parse_closed(NEGATIVE_CASE_BYTES, CASE_FILE_MAX_BYTES)?;
    validate_case_file(&positive, Polarity::Positive)?;
    validate_case_file(&negative, Polarity::Negative)?;
    validate_cross_file(&positive, &negative)?;
    Ok((manifest, positive, negative))
}

struct CappedWriter {
    bytes: Box<[u8; OUTPUT_MAX_BYTES]>,
    length: usize,
    attempted_length: usize,
}

impl CappedWriter {
    fn new() -> Self {
        Self {
            bytes: Box::new([0; OUTPUT_MAX_BYTES]),
            length: 0,
            attempted_length: 0,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes[..self.length].to_vec()
    }
}

impl Write for CappedWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.attempted_length = self.length.saturating_add(input.len());
        if input.len() > OUTPUT_MAX_BYTES.saturating_sub(self.length) {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "bounded_output"));
        }
        let end = self.length + input.len();
        self.bytes[self.length..end].copy_from_slice(input);
        self.length = end;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capped_json<T: Serialize>(value: &T) -> HarnessResult<Vec<u8>> {
    let mut writer = CappedWriter::new();
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| sanitized(FailureCategory::SerializationBound))?;
    Ok(writer.finish())
}

fn expected_serialized(case: &Case) -> HarnessResult<&str> {
    case.expected
        .serialized_utf8
        .as_deref()
        .ok_or_else(|| sanitized(FailureCategory::Observation))
}

fn compare_output(case: &Case, actual: &[u8]) -> HarnessResult<()> {
    let expected = expected_serialized(case)?.as_bytes();
    require_case(
        actual == expected,
        case,
        FailureCategory::ValueMismatch,
        &[actual == expected],
        &[actual.len(), expected.len()],
    )
}

trait StringScalar: Eq + Serialize + Sized {
    fn public_parse(value: &str) -> Result<Self, FoundationGrammarError>;
    fn public_try_new(value: String) -> Result<Self, FoundationGrammarError>;
    fn public_from_str(value: &str) -> Result<Self, FoundationGrammarError>;
    fn public_as_str(&self) -> &str;
}

macro_rules! string_scalar {
    ($type:ty) => {
        impl StringScalar for $type {
            fn public_parse(value: &str) -> Result<Self, FoundationGrammarError> {
                <$type>::parse(value)
            }

            fn public_try_new(value: String) -> Result<Self, FoundationGrammarError> {
                <$type>::try_new(value)
            }

            fn public_from_str(value: &str) -> Result<Self, FoundationGrammarError> {
                <$type as FromStr>::from_str(value)
            }

            fn public_as_str(&self) -> &str {
                self.as_str()
            }
        }
    };
}

string_scalar!(CanonicalSchemaIdV1);
string_scalar!(CanonicalLabelV1);
string_scalar!(FoundationGrammarCodeV1);
string_scalar!(CanonicalTimestampV1);

fn execute_string_scalar<T: StringScalar>(case: &Case, text: &str) -> HarnessResult<()> {
    let primary = match case.operation {
        Operation::Parse | Operation::ParseReject | Operation::Serialize => T::public_parse(text),
        Operation::Construct | Operation::ConstructReject => T::public_try_new(text.to_string()),
        Operation::FromStr | Operation::FromStrReject => T::public_from_str(text),
        _ => return Err(sanitized(FailureCategory::Dispatch)),
    };
    match case.expected.execution_result {
        ExecutionResult::Accepted => {
            let primary = primary
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let primary_bytes = capped_json(&primary)?;
            let parsed = T::public_parse(text)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let constructed = T::public_try_new(text.to_string())
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let from_str = T::public_from_str(text)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let parsed_bytes = capped_json(&parsed)?;
            let constructed_bytes = capped_json(&constructed)?;
            let from_str_bytes = capped_json(&from_str)?;
            let matches = [
                primary.public_as_str() == text,
                parsed == constructed,
                parsed == from_str,
                primary == parsed,
                parsed_bytes == constructed_bytes,
                parsed_bytes == from_str_bytes,
                primary_bytes == parsed_bytes,
            ];
            require_case(
                matches.into_iter().all(|value| value),
                case,
                FailureCategory::ValueMismatch,
                &matches,
                &[
                    primary_bytes.len(),
                    parsed_bytes.len(),
                    constructed_bytes.len(),
                    from_str_bytes.len(),
                ],
            )?;
            compare_output(case, &primary_bytes)
        }
        ExecutionResult::Rejected => {
            let primary_error = primary
                .err()
                .ok_or_else(|| mismatch(case, FailureCategory::ProductionAccepted, &[], &[]))?;
            let parsed = T::public_parse(text);
            let constructed = T::public_try_new(text.to_string());
            let from_str = T::public_from_str(text);
            compare_grammar_errors(
                case,
                primary_error,
                &[parsed.err(), constructed.err(), from_str.err()],
            )
        }
    }
}

trait IntegerScalar: Copy + Eq + Serialize + Sized {
    fn public_parse(value: &str) -> Result<Self, FoundationGrammarError>;
    fn public_try_new(value: u64) -> Result<Self, FoundationGrammarError>;
    fn public_from_str(value: &str) -> Result<Self, FoundationGrammarError>;
    fn public_get(self) -> u64;
}

macro_rules! integer_scalar {
    ($type:ty) => {
        impl IntegerScalar for $type {
            fn public_parse(value: &str) -> Result<Self, FoundationGrammarError> {
                <$type>::parse(value)
            }

            fn public_try_new(value: u64) -> Result<Self, FoundationGrammarError> {
                <$type>::try_new(value)
            }

            fn public_from_str(value: &str) -> Result<Self, FoundationGrammarError> {
                <$type as FromStr>::from_str(value)
            }

            fn public_get(self) -> u64 {
                self.get()
            }
        }
    };
}

integer_scalar!(CanonicalCountV1);
integer_scalar!(CanonicalOrdinalV1);
integer_scalar!(CanonicalSequenceV1);
integer_scalar!(CanonicalPositiveRevisionV1);

fn execute_integer_text<T: IntegerScalar>(case: &Case, text: &str) -> HarnessResult<()> {
    let primary = match case.operation {
        Operation::Parse | Operation::ParseReject => T::public_parse(text),
        Operation::FromStr | Operation::FromStrReject => T::public_from_str(text),
        _ => return Err(sanitized(FailureCategory::Dispatch)),
    };
    match case.expected.execution_result {
        ExecutionResult::Accepted => {
            let primary = primary
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let parsed = T::public_parse(text)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let from_str = T::public_from_str(text)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let constructed = T::public_try_new(parsed.public_get())
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let primary_bytes = capped_json(&primary)?;
            let parsed_bytes = capped_json(&parsed)?;
            let from_str_bytes = capped_json(&from_str)?;
            let constructed_bytes = capped_json(&constructed)?;
            let matches = [
                primary == parsed,
                parsed == from_str,
                parsed == constructed,
                parsed.public_get() == constructed.public_get(),
                primary_bytes == parsed_bytes,
                parsed_bytes == from_str_bytes,
                parsed_bytes == constructed_bytes,
            ];
            require_case(
                matches.into_iter().all(|value| value),
                case,
                FailureCategory::ValueMismatch,
                &matches,
                &[
                    primary_bytes.len(),
                    parsed_bytes.len(),
                    from_str_bytes.len(),
                    constructed_bytes.len(),
                ],
            )?;
            compare_output(case, &primary_bytes)
        }
        ExecutionResult::Rejected => {
            let primary_error = primary
                .err()
                .ok_or_else(|| mismatch(case, FailureCategory::ProductionAccepted, &[], &[]))?;
            compare_grammar_errors(
                case,
                primary_error,
                &[T::public_parse(text).err(), T::public_from_str(text).err()],
            )
        }
    }
}

fn execute_integer_u64<T: IntegerScalar>(case: &Case, value: u64) -> HarnessResult<()> {
    let primary = T::public_try_new(value);
    match case.expected.execution_result {
        ExecutionResult::Accepted => {
            let primary = primary
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let token = value.to_string();
            let parsed = T::public_parse(&token)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let from_str = T::public_from_str(&token)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let primary_bytes = capped_json(&primary)?;
            let parsed_bytes = capped_json(&parsed)?;
            let from_str_bytes = capped_json(&from_str)?;
            let matches = [
                primary.public_get() == value,
                primary == parsed,
                primary == from_str,
                primary_bytes == parsed_bytes,
                primary_bytes == from_str_bytes,
            ];
            require_case(
                matches.into_iter().all(|value| value),
                case,
                FailureCategory::ValueMismatch,
                &matches,
                &[
                    primary_bytes.len(),
                    parsed_bytes.len(),
                    from_str_bytes.len(),
                ],
            )?;
            compare_output(case, &primary_bytes)
        }
        ExecutionResult::Rejected => {
            let primary_error = primary
                .err()
                .ok_or_else(|| mismatch(case, FailureCategory::ProductionAccepted, &[], &[]))?;
            let token = value.to_string();
            compare_grammar_errors(
                case,
                primary_error,
                &[
                    T::public_parse(&token).err(),
                    T::public_from_str(&token).err(),
                ],
            )
        }
    }
}

fn compare_grammar_errors(
    case: &Case,
    primary: FoundationGrammarError,
    agreements: &[Option<FoundationGrammarError>],
) -> HarnessResult<()> {
    let expected = case
        .expected
        .stable_error_code
        .ok_or_else(|| sanitized(FailureCategory::Observation))?
        .grammar_error();
    let mut matches = Vec::with_capacity(agreements.len() + 1);
    matches.push(primary == expected);
    matches.extend(
        agreements
            .iter()
            .map(|error| error.is_some_and(|value| value == expected)),
    );
    require_case(
        matches.iter().copied().all(|value| value),
        case,
        FailureCategory::ValueMismatch,
        &matches,
        &[],
    )
}

fn execute_error(case: &Case, code: ErrorCode) -> HarnessResult<()> {
    let error = code.grammar_error();
    let expected = case
        .expected
        .stable_error_code
        .ok_or_else(|| sanitized(FailureCategory::Observation))?;
    let display = error.to_string();
    let debug = format!("{error:?}");
    let matches = [
        code == expected,
        error.as_str() == code.as_str(),
        display == code.as_str(),
        debug == code.as_str(),
        error.source().is_none(),
    ];
    require_case(
        matches.into_iter().all(|value| value),
        case,
        FailureCategory::ValueMismatch,
        &matches,
        &[display.len(), debug.len()],
    )
}

fn execute_digest_text(case: &Case, text: &str) -> HarnessResult<()> {
    let primary = match case.operation {
        Operation::Parse | Operation::ParseReject | Operation::Serialize => {
            RegistryDeclarationDigest::parse(text)
        }
        Operation::FromStr | Operation::FromStrReject => {
            <RegistryDeclarationDigest as FromStr>::from_str(text)
        }
        _ => return Err(sanitized(FailureCategory::Dispatch)),
    };
    match case.expected.execution_result {
        ExecutionResult::Accepted => {
            let primary = primary
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let parsed = RegistryDeclarationDigest::parse(text)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let from_str = <RegistryDeclarationDigest as FromStr>::from_str(text)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let primary_bytes = capped_json(&primary)?;
            let parsed_bytes = capped_json(&parsed)?;
            let from_str_bytes = capped_json(&from_str)?;
            let redacted = format!("{primary:?}");
            let matches = [
                primary == parsed,
                parsed == from_str,
                primary_bytes == parsed_bytes,
                parsed_bytes == from_str_bytes,
                redacted == "RegistryDeclarationDigest(<redacted>)",
            ];
            require_case(
                matches.into_iter().all(|value| value),
                case,
                FailureCategory::ValueMismatch,
                &matches,
                &[
                    primary_bytes.len(),
                    parsed_bytes.len(),
                    from_str_bytes.len(),
                ],
            )?;
            compare_output(case, &primary_bytes)
        }
        ExecutionResult::Rejected => {
            let primary_error = primary
                .err()
                .ok_or_else(|| mismatch(case, FailureCategory::ProductionAccepted, &[], &[]))?;
            compare_grammar_errors(
                case,
                primary_error,
                &[
                    RegistryDeclarationDigest::parse(text).err(),
                    <RegistryDeclarationDigest as FromStr>::from_str(text).err(),
                ],
            )
        }
    }
}

fn declaration_bytes(mutation: DeclarationMutation) -> HarnessResult<(Vec<u8>, u64)> {
    if DECLARATION_BYTES.len() > BUILTIN_RESOURCE_MAX_BYTES {
        return Err(sanitized(FailureCategory::RawBound));
    }
    match mutation {
        DeclarationMutation::None => Ok((DECLARATION_BYTES.to_vec(), 1)),
        DeclarationMutation::DriverDeclarationRevision1To2 => {
            let mut offsets = DECLARATION_BYTES
                .windows(REVISION_MARKER.len())
                .enumerate()
                .filter_map(|(index, bytes)| (bytes == REVISION_MARKER).then_some(index));
            let first = offsets
                .next()
                .ok_or_else(|| sanitized(FailureCategory::FixtureContract))?;
            if offsets.next().is_some() {
                return Err(sanitized(FailureCategory::FixtureContract));
            }
            let mut bytes = DECLARATION_BYTES.to_vec();
            bytes[first + REVISION_MARKER.len() - 1] = b'2';
            let differences = bytes
                .iter()
                .zip(DECLARATION_BYTES)
                .filter(|(left, right)| left != right)
                .count();
            if differences != 1 {
                return Err(sanitized(FailureCategory::FixtureContract));
            }
            Ok((bytes, 2))
        }
    }
}

fn execute_declaration(case: &Case, body: &DeclarationBody) -> HarnessResult<()> {
    let (bytes, expected_revision) = declaration_bytes(body.mutation)?;
    let declaration = DriverOperationCredentialSinksV1::from_json_slice(&bytes)
        .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
    let declaration_output = capped_json(&declaration)?;
    let revision_matches = declaration.driver_declaration_revision() == expected_revision;
    let declaration_matches = declaration_output == bytes;
    require_case(
        revision_matches && declaration_matches,
        case,
        FailureCategory::ValueMismatch,
        &[revision_matches, declaration_matches],
        &[declaration_output.len(), bytes.len()],
    )?;

    let production = RegistryDeclarationDigest::try_from(&declaration)
        .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
    let expected_wire = case
        .expected
        .expected_digest_wire
        .as_deref()
        .ok_or_else(|| sanitized(FailureCategory::Observation))?;
    let expected_digest = RegistryDeclarationDigest::parse(expected_wire)
        .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;

    let selected = match body.digest_domain {
        DigestDomain::Production => production,
        DigestDomain::WrongDomainV2 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(WRONG_DOMAIN);
            hasher.update(&[0]);
            hasher.update(&bytes);
            let wire = format!("blake3:{}", hasher.finalize().to_hex());
            let wire_matches = wire == expected_wire;
            require_case(
                wire_matches,
                case,
                FailureCategory::ValueMismatch,
                &[wire_matches],
                &[wire.len(), expected_wire.len()],
            )?;
            RegistryDeclarationDigest::parse(&wire)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?
        }
    };
    let equality = selected == production;
    let expected_equality = case
        .expected
        .digest_equality
        .ok_or_else(|| sanitized(FailureCategory::Observation))?;
    let selected_output = capped_json(&selected)?;
    let expected_output = capped_json(&expected_digest)?;
    let selected_debug = format!("{selected:?}");
    let production_debug = format!("{production:?}");
    let matches = [
        selected == expected_digest,
        equality == expected_equality,
        selected_output == expected_output,
        selected_debug == "RegistryDeclarationDigest(<redacted>)",
        production_debug == "RegistryDeclarationDigest(<redacted>)",
        body.digest_domain != DigestDomain::WrongDomainV2 || selected != production,
    ];
    require_case(
        matches.into_iter().all(|value| value),
        case,
        FailureCategory::ValueMismatch,
        &matches,
        &[selected_output.len(), expected_output.len()],
    )?;
    compare_output(case, &selected_output)
}

fn execute_trace(case: &Case, json: &str) -> HarnessResult<()> {
    validate_inline_json(json, DuplicatePolicy::Permit)?;
    let parsed = serde_json::from_str::<TraceEvent>(json);
    match case.expected.execution_result {
        ExecutionResult::Rejected => {
            if parsed.is_err() {
                Ok(())
            } else {
                Err(mismatch(
                    case,
                    FailureCategory::ProductionAccepted,
                    &[],
                    &[],
                ))
            }
        }
        ExecutionResult::Accepted => {
            let event = parsed
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let output = capped_json(&event)?;
            compare_output(case, &output)?;
            let object: BTreeMap<String, serde_json::Value> = serde_json::from_slice(&output)
                .map_err(|_| sanitized(FailureCategory::JsonEnvelope))?;
            let canonical = object.contains_key("trace_event_id");
            let alias_absent = !object.contains_key("trace_id");
            require_case(
                canonical && alias_absent,
                case,
                FailureCategory::ValueMismatch,
                &[canonical, alias_absent],
                &[output.len()],
            )
        }
    }
}

fn compare_extension_error(case: &Case, actual: &ExtensionValidationError) -> HarnessResult<()> {
    let expected = case
        .expected
        .extension_error
        .as_ref()
        .ok_or_else(|| sanitized(FailureCategory::Observation))?;
    let matches = [
        actual.reason == expected.reason.production(),
        actual.path == expected.path,
        actual.key == expected.key,
        actual.normalized_key == expected.normalized_key,
    ];
    require_case(
        matches.into_iter().all(|value| value),
        case,
        FailureCategory::ValueMismatch,
        &matches,
        &[
            actual.path.len(),
            actual.key.len(),
            actual.normalized_key.len(),
            expected.path.len(),
            expected.key.len(),
            expected.normalized_key.len(),
        ],
    )
}

fn execute_extension(case: &Case, body: &ExtensionBody) -> HarnessResult<()> {
    validate_inline_json(&body.json, DuplicatePolicy::Reject)?;
    let reserved: Vec<&str> = body
        .additional_reserved_keys
        .iter()
        .map(String::as_str)
        .collect();
    let result = match case.operation {
        Operation::ValidateExtensionMap => {
            let value = serde_json::from_str::<BTreeMap<String, serde_json::Value>>(&body.json)
                .map_err(|_| sanitized(FailureCategory::JsonEnvelope))?;
            validate_extension_map(&value, body.root_path.clone())
        }
        Operation::ValidateExtensionMapWithReservedKeys => {
            let value = serde_json::from_str::<BTreeMap<String, serde_json::Value>>(&body.json)
                .map_err(|_| sanitized(FailureCategory::JsonEnvelope))?;
            validate_extension_map_with_reserved_keys(&value, body.root_path.clone(), &reserved)
        }
        Operation::ValidateExtensionValue => {
            let value = serde_json::from_str::<serde_json::Value>(&body.json)
                .map_err(|_| sanitized(FailureCategory::JsonEnvelope))?;
            validate_extension_value(&value, body.root_path.clone())
        }
        Operation::ValidateExtensionValueWithReservedKeys => {
            let value = serde_json::from_str::<serde_json::Value>(&body.json)
                .map_err(|_| sanitized(FailureCategory::JsonEnvelope))?;
            validate_extension_value_with_reserved_keys(&value, body.root_path.clone(), &reserved)
        }
        _ => return Err(sanitized(FailureCategory::Dispatch)),
    };
    match case.expected.execution_result {
        ExecutionResult::Accepted => {
            if result.is_ok() {
                Ok(())
            } else {
                Err(mismatch(
                    case,
                    FailureCategory::ProductionRejected,
                    &[],
                    &[],
                ))
            }
        }
        ExecutionResult::Rejected => {
            let error = result
                .err()
                .ok_or_else(|| mismatch(case, FailureCategory::ProductionAccepted, &[], &[]))?;
            compare_extension_error(case, &error)
        }
    }
}

fn execute_live_relation(case: &Case) -> HarnessResult<()> {
    match (&case.input, case.case_id.as_str()) {
        (Input::WorkOrderJson(body), "live_relation.stale_work_order") => {
            validate_inline_json(&body.json, DuplicatePolicy::Permit)?;
            let order = serde_json::from_str::<WorkOrder>(&body.json)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            order
                .signing_payload_bytes()
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let relation_now = time::OffsetDateTime::from_unix_timestamp(RELATION_NOW_UNIX)
                .map_err(|_| sanitized(FailureCategory::FixtureContract))?;
            let relation = order.expires_at <= relation_now;
            let output = capped_json(&order)?;
            require_case(
                relation,
                case,
                FailureCategory::ValueMismatch,
                &[relation],
                &[output.len()],
            )?;
            compare_output(case, &output)
        }
        (Input::WorkOrderJson(body), "live_relation.wrong_tenant_work_order") => {
            validate_inline_json(&body.json, DuplicatePolicy::Permit)?;
            let order = serde_json::from_str::<WorkOrder>(&body.json)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            order
                .signing_payload_bytes()
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let expected = TenantId::parse(EXPECTED_TENANT_ID)
                .map_err(|_| sanitized(FailureCategory::FixtureContract))?;
            let relation = order.tenant_id != expected;
            let output = capped_json(&order)?;
            require_case(
                relation,
                case,
                FailureCategory::ValueMismatch,
                &[relation],
                &[output.len()],
            )?;
            compare_output(case, &output)
        }
        (Input::CallerCredentialJson(body), "live_relation.wrong_owner_caller_credential") => {
            validate_inline_json(&body.json, DuplicatePolicy::Permit)?;
            let credential = serde_json::from_str::<CallerCredential>(&body.json)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let relation = credential.principal.app.app_principal_id != EXPECTED_APP_PRINCIPAL_ID;
            let output = capped_json(&credential)?;
            require_case(
                relation,
                case,
                FailureCategory::ValueMismatch,
                &[relation],
                &[output.len()],
            )?;
            compare_output(case, &output)
        }
        (Input::CallerCredentialJson(body), "live_relation.wrong_audience_caller_credential") => {
            validate_inline_json(&body.json, DuplicatePolicy::Permit)?;
            let credential = serde_json::from_str::<CallerCredential>(&body.json)
                .map_err(|_| mismatch(case, FailureCategory::ProductionRejected, &[], &[]))?;
            let relation = matches!(
                &credential.audience,
                CredentialAudience::Daemon { daemon_id } if daemon_id != EXPECTED_DAEMON_ID
            );
            let output = capped_json(&credential)?;
            require_case(
                relation,
                case,
                FailureCategory::ValueMismatch,
                &[relation],
                &[output.len()],
            )?;
            compare_output(case, &output)
        }
        _ => Err(sanitized(FailureCategory::Dispatch)),
    }
}

fn execute_case(case: &Case, source_polarity: Polarity) -> HarnessResult<()> {
    validate_case(case, source_polarity)?;
    match (case.subject, &case.input) {
        (Subject::CanonicalSchemaIdV1, Input::Text(body)) => {
            execute_string_scalar::<CanonicalSchemaIdV1>(case, &body.value)
        }
        (Subject::CanonicalLabelV1, Input::Text(body)) => {
            execute_string_scalar::<CanonicalLabelV1>(case, &body.value)
        }
        (Subject::FoundationGrammarCodeV1, Input::Text(body)) => {
            execute_string_scalar::<FoundationGrammarCodeV1>(case, &body.value)
        }
        (Subject::CanonicalTimestampV1, Input::Text(body)) => {
            execute_string_scalar::<CanonicalTimestampV1>(case, &body.value)
        }
        (Subject::CanonicalCountV1, Input::Text(body)) => {
            execute_integer_text::<CanonicalCountV1>(case, &body.value)
        }
        (Subject::CanonicalOrdinalV1, Input::Text(body)) => {
            execute_integer_text::<CanonicalOrdinalV1>(case, &body.value)
        }
        (Subject::CanonicalSequenceV1, Input::Text(body)) => {
            execute_integer_text::<CanonicalSequenceV1>(case, &body.value)
        }
        (Subject::CanonicalPositiveRevisionV1, Input::Text(body)) => {
            execute_integer_text::<CanonicalPositiveRevisionV1>(case, &body.value)
        }
        (Subject::CanonicalCountV1, Input::U64(body)) => {
            execute_integer_u64::<CanonicalCountV1>(case, body.value)
        }
        (Subject::CanonicalOrdinalV1, Input::U64(body)) => {
            execute_integer_u64::<CanonicalOrdinalV1>(case, body.value)
        }
        (Subject::CanonicalSequenceV1, Input::U64(body)) => {
            execute_integer_u64::<CanonicalSequenceV1>(case, body.value)
        }
        (Subject::CanonicalPositiveRevisionV1, Input::U64(body)) => {
            execute_integer_u64::<CanonicalPositiveRevisionV1>(case, body.value)
        }
        (Subject::FoundationGrammarError, Input::ErrorCode(body)) => {
            execute_error(case, body.value)
        }
        (Subject::RegistryDeclarationDigest, Input::Text(body)) => {
            execute_digest_text(case, &body.value)
        }
        (Subject::RegistryDeclarationDigest, Input::Declaration(body)) => {
            execute_declaration(case, body)
        }
        (Subject::TraceEvent, Input::TraceJson(body)) => execute_trace(case, &body.json),
        (
            Subject::SchemaExtensionMap | Subject::SchemaExtensionValue,
            Input::ExtensionJson(body),
        ) => execute_extension(case, body),
        (Subject::WorkOrder | Subject::CallerCredential, _) => execute_live_relation(case),
        _ => Err(sanitized(FailureCategory::Dispatch)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputPolicy {
    ExplicitlyPinned,
    ObservedProduction,
    NotApplicable,
}

fn output_policy(case: &Case) -> OutputPolicy {
    if case.expected.serialized_utf8.is_none() {
        OutputPolicy::NotApplicable
    } else {
        match case.subject {
            Subject::CanonicalSchemaIdV1
            | Subject::CanonicalLabelV1
            | Subject::FoundationGrammarCodeV1
            | Subject::CanonicalTimestampV1
            | Subject::CanonicalCountV1
            | Subject::CanonicalOrdinalV1
            | Subject::CanonicalSequenceV1
            | Subject::CanonicalPositiveRevisionV1
            | Subject::RegistryDeclarationDigest => OutputPolicy::ExplicitlyPinned,
            Subject::TraceEvent | Subject::WorkOrder | Subject::CallerCredential => {
                OutputPolicy::ObservedProduction
            }
            Subject::FoundationGrammarError
            | Subject::SchemaExtensionMap
            | Subject::SchemaExtensionValue => OutputPolicy::NotApplicable,
        }
    }
}

fn case_by_id<'a>(files: &'a [&CaseFile], case_id: &str) -> &'a Case {
    files
        .iter()
        .flat_map(|file| &file.cases)
        .find(|case| case.case_id == case_id)
        .expect("source-fixed case identity")
}

fn one_case_file_json(
    polarity: &str,
    subject: &str,
    operation: &str,
    input: &str,
    expected: &str,
    case_extra: &str,
) -> String {
    format!(
        "{{\"format_id\":\"{FORMAT_CASES}\",\"profile\":\"{PROFILE}\",\"polarity\":\"{polarity}\",\"case_count\":1,\"cases\":[{{\"case_id\":\"z.case\",\"subject\":\"{subject}\",\"operation\":\"{operation}\",\"input\":{input},\"expected\":{expected},\"live_disposition_status\":\"not_exercised\",\"schema_registration_status\":\"not_exercised\"{case_extra}}}]}}"
    )
}

fn generated_array(elements: usize) -> String {
    let mut json = String::with_capacity(elements.saturating_mul(2).saturating_add(2));
    json.push('[');
    for index in 0..elements {
        if index != 0 {
            json.push(',');
        }
        json.push('0');
    }
    json.push(']');
    json
}

fn generated_duplicate_object(members: usize) -> String {
    let mut json = String::with_capacity(members.saturating_mul(6).saturating_add(2));
    json.push('{');
    for index in 0..members {
        if index != 0 {
            json.push(',');
        }
        json.push_str("\"a\":0");
    }
    json.push('}');
    json
}

fn generated_nested_array(wrappers: usize) -> String {
    format!("{}0{}", "[".repeat(wrappers), "]".repeat(wrappers))
}

#[test]
fn exact_manifest_and_fixture_roots_load() {
    load_readme(README_BYTES).expect("README contract");
    let manifest: Manifest =
        parse_closed(MANIFEST_BYTES, MANIFEST_MAX_BYTES).expect("manifest typed load");
    validate_manifest(&manifest).expect("manifest exact values");
    let positive: CaseFile =
        parse_closed(POSITIVE_CASE_BYTES, CASE_FILE_MAX_BYTES).expect("positive typed load");
    validate_case_file(&positive, Polarity::Positive).expect("positive fixture contract");
    let negative: CaseFile =
        parse_closed(NEGATIVE_CASE_BYTES, CASE_FILE_MAX_BYTES).expect("negative typed load");
    validate_case_file(&negative, Polarity::Negative).expect("negative fixture contract");
    validate_cross_file(&positive, &negative).expect("cross-file fixture contract");
    assert_eq!(manifest.production_surfaces.len(), 15);
    assert_eq!(positive.cases.len(), 55);
    assert_eq!(negative.cases.len(), 68);
    assert_eq!(positive.case_count + negative.case_count, 123);
    assert!(README_BYTES.len() <= README_MAX_BYTES);
    assert!(MANIFEST_BYTES.len() <= MANIFEST_MAX_BYTES);
    assert!(POSITIVE_CASE_BYTES.len() <= CASE_FILE_MAX_BYTES);
    assert!(NEGATIVE_CASE_BYTES.len() <= CASE_FILE_MAX_BYTES);
    assert!(DECLARATION_BYTES.len() <= BUILTIN_RESOURCE_MAX_BYTES);
}

#[test]
fn all_positive_production_cases_match() {
    let (_, positive, _) = load_all().expect("fixture load");
    for case in &positive.cases {
        execute_case(case, Polarity::Positive).expect("positive production observation matched");
    }
}

#[test]
fn all_negative_production_cases_match() {
    let (_, _, negative) = load_all().expect("fixture load");
    for case in &negative.cases {
        execute_case(case, Polarity::Negative).expect("negative production observation matched");
    }
}

#[test]
fn high_value_inventory_is_present_and_exercised() {
    let (_, positive, negative) = load_all().expect("fixture load");
    let files = [&positive, &negative];

    let schema_max = case_by_id(&files, "p002.schema.construct.maximum");
    let label_max = case_by_id(&files, "p006.label.construct.maximum");
    let code_max = case_by_id(&files, "p010.code.construct.maximum");
    let schema_over = case_by_id(&files, "n002.schema.construct-reject.over-bound");
    let label_over = case_by_id(&files, "n007.label.construct-reject.over-bound");
    let code_over = case_by_id(&files, "n011.code.construct-reject.over-bound");
    let lengths = [
        schema_max,
        label_max,
        code_max,
        schema_over,
        label_over,
        code_over,
    ]
    .map(|case| match &case.input {
        Input::Text(body) => body.value.len(),
        _ => 0,
    });
    assert_eq!(lengths, [128, 128, 128, 129, 129, 129]);

    let scalar_subjects = [
        Subject::CanonicalSchemaIdV1,
        Subject::CanonicalLabelV1,
        Subject::FoundationGrammarCodeV1,
        Subject::CanonicalTimestampV1,
        Subject::CanonicalCountV1,
        Subject::CanonicalOrdinalV1,
        Subject::CanonicalSequenceV1,
        Subject::CanonicalPositiveRevisionV1,
    ];
    for subject in scalar_subjects {
        let operations: HashSet<Operation> = positive
            .cases
            .iter()
            .filter(|case| case.subject == subject)
            .map(|case| case.operation)
            .collect();
        assert!(operations.contains(&Operation::Parse));
        assert!(operations.contains(&Operation::Construct));
        assert!(operations.contains(&Operation::FromStr));
        assert!(operations.contains(&Operation::Serialize));

        let rejected: HashSet<Operation> = negative
            .cases
            .iter()
            .filter(|case| case.subject == subject)
            .map(|case| case.operation)
            .collect();
        assert!(rejected.contains(&Operation::ParseReject));
        assert!(rejected.contains(&Operation::ConstructReject));
        assert!(rejected.contains(&Operation::FromStrReject));
    }

    let errors: HashSet<ErrorCode> = positive
        .cases
        .iter()
        .filter_map(|case| match &case.input {
            Input::ErrorCode(body) => Some(body.value),
            _ => None,
        })
        .collect();
    assert_eq!(errors.len(), 9);
    assert_eq!(
        positive
            .cases
            .iter()
            .filter(|case| case.subject == Subject::TraceEvent)
            .count(),
        5
    );
    assert_eq!(
        negative
            .cases
            .iter()
            .filter(|case| case.subject == Subject::TraceEvent)
            .count(),
        7
    );
}

#[test]
fn pinned_and_observed_policy_is_source_controlled() {
    let (_, positive, negative) = load_all().expect("fixture load");
    let policies: Vec<OutputPolicy> = positive
        .cases
        .iter()
        .chain(&negative.cases)
        .map(output_policy)
        .collect();
    assert_eq!(
        policies
            .iter()
            .filter(|policy| **policy == OutputPolicy::ExplicitlyPinned)
            .count(),
        38
    );
    assert_eq!(
        policies
            .iter()
            .filter(|policy| **policy == OutputPolicy::ObservedProduction)
            .count(),
        9
    );
    for bytes in [MANIFEST_BYTES, POSITIVE_CASE_BYTES, NEGATIVE_CASE_BYTES] {
        let text = std::str::from_utf8(bytes).expect("embedded UTF-8");
        assert!(!text.contains("explicitly_pinned"));
        assert!(!text.contains("observed_production"));
    }
}

#[test]
fn trace_alias_duplicate_unknown_and_emission_inventory_matches() {
    let (_, positive, negative) = load_all().expect("fixture load");
    for (file, polarity) in [
        (&positive, Polarity::Positive),
        (&negative, Polarity::Negative),
    ] {
        for case in file
            .cases
            .iter()
            .filter(|case| case.subject == Subject::TraceEvent)
        {
            execute_case(case, polarity).expect("Trace current truth matched");
        }
    }
}

#[test]
fn declaration_golden_mutation_and_wrong_domain_match() {
    let (_, positive, negative) = load_all().expect("fixture load");
    for (case_id, polarity) in [
        ("p045.digest.declaration.golden", Polarity::Positive),
        (
            "p046.digest.declaration.revision-mutation",
            Polarity::Positive,
        ),
        ("n047.digest.wrong-domain", Polarity::Negative),
    ] {
        execute_case(case_by_id(&[&positive, &negative], case_id), polarity)
            .expect("declaration digest observation matched");
    }
}

#[test]
fn all_four_extension_validators_match_structured_observations() {
    let (_, positive, negative) = load_all().expect("fixture load");
    let mut accepted = HashSet::new();
    let mut rejected = HashSet::new();
    for (file, polarity) in [
        (&positive, Polarity::Positive),
        (&negative, Polarity::Negative),
    ] {
        for case in file.cases.iter().filter(|case| {
            matches!(
                case.subject,
                Subject::SchemaExtensionMap | Subject::SchemaExtensionValue
            )
        }) {
            execute_case(case, polarity).expect("extension observation matched");
            match case.expected.execution_result {
                ExecutionResult::Accepted => {
                    accepted.insert(case.operation);
                }
                ExecutionResult::Rejected => {
                    rejected.insert(case.operation);
                }
            }
        }
    }
    let expected = HashSet::from([
        Operation::ValidateExtensionMap,
        Operation::ValidateExtensionMapWithReservedKeys,
        Operation::ValidateExtensionValue,
        Operation::ValidateExtensionValueWithReservedKeys,
    ]);
    assert_eq!(accepted, expected);
    assert_eq!(rejected, expected);
}

#[test]
fn exact_four_source_fixed_live_relations_match_without_owner_validation() {
    let (_, positive, negative) = load_all().expect("fixture load");
    assert!(positive
        .cases
        .iter()
        .all(|case| case.operation != Operation::ParseLiveRelation));
    let relations: Vec<&Case> = negative
        .cases
        .iter()
        .filter(|case| case.operation == Operation::ParseLiveRelation)
        .collect();
    assert_eq!(relations.len(), 4);
    for case in relations {
        assert_eq!(case.live_disposition_status, "not_exercised");
        assert_eq!(case.schema_registration_status, "not_exercised");
        execute_case(case, Polarity::Negative).expect("source-fixed parse-only relation matched");
    }
}

#[test]
fn raw_utf8_inline_and_count_bounds_reject_before_dispatch() {
    assert!(load_readme(&vec![b'a'; README_MAX_BYTES]).is_err());
    assert!(load_readme(&vec![b'a'; README_MAX_BYTES + 1]).is_err());
    assert!(load_readme(&[0xff]).is_err());
    assert!(
        parse_closed::<Manifest>(&vec![b' '; MANIFEST_MAX_BYTES + 1], MANIFEST_MAX_BYTES).is_err()
    );
    assert!(
        parse_closed::<CaseFile>(&vec![b' '; CASE_FILE_MAX_BYTES + 1], CASE_FILE_MAX_BYTES)
            .is_err()
    );
    assert!(bounded_utf8(
        &vec![b'a'; BUILTIN_RESOURCE_MAX_BYTES + 1],
        BUILTIN_RESOURCE_MAX_BYTES
    )
    .is_err());

    let (_, positive, negative) = load_all().expect("fixture load");
    let mut text_over = positive.cases[0].clone();
    text_over.case_id = "z.text-over".to_string();
    text_over.input = Input::Text(TextBody {
        value: "a".repeat(INLINE_TEXT_MAX_BYTES + 1),
    });
    assert!(validate_case(&text_over, Polarity::Positive).is_err());

    let mut json_over = negative
        .cases
        .iter()
        .find(|case| case.subject == Subject::TraceEvent)
        .expect("Trace case")
        .clone();
    json_over.case_id = "z.json-over".to_string();
    json_over.input = Input::TraceJson(JsonBody {
        json: format!("\"{}\"", "a".repeat(INLINE_JSON_MAX_BYTES)),
    });
    assert!(validate_case(&json_over, Polarity::Negative).is_err());

    let mut output_over = positive.cases[0].clone();
    output_over.case_id = "z.output-over".to_string();
    output_over.expected.serialized_utf8 = Some("a".repeat(OUTPUT_MAX_BYTES + 1));
    assert!(validate_case(&output_over, Polarity::Positive).is_err());

    let mut keys_over = positive
        .cases
        .iter()
        .find(|case| case.operation == Operation::ValidateExtensionMapWithReservedKeys)
        .expect("extension case")
        .clone();
    keys_over.case_id = "z.keys-over".to_string();
    if let Input::ExtensionJson(body) = &mut keys_over.input {
        body.additional_reserved_keys = (0..=ADDITIONAL_RESERVED_KEYS_MAX)
            .map(|index| format!("key_{index}"))
            .collect();
    }
    assert!(validate_case(&keys_over, Polarity::Positive).is_err());

    let mut metadata_over = positive
        .cases
        .iter()
        .find(|case| case.subject == Subject::SchemaExtensionMap)
        .expect("extension case")
        .clone();
    metadata_over.case_id = "z.metadata-over".to_string();
    if let Input::ExtensionJson(body) = &mut metadata_over.input {
        body.root_path = "a".repeat(METADATA_STRING_MAX_BYTES + 1);
    }
    assert!(validate_case(&metadata_over, Polarity::Positive).is_err());

    let mut too_many = CaseFile {
        format_id: FORMAT_CASES.to_string(),
        profile: PROFILE.to_string(),
        polarity: Polarity::Positive,
        case_count: CASES_PER_FILE_MAX + 1,
        cases: Vec::new(),
    };
    for index in 0..=CASES_PER_FILE_MAX {
        let mut case = positive.cases[0].clone();
        case.case_id = format!("z.generated.{index:03}");
        too_many.cases.push(case);
    }
    assert!(validate_case_file(&too_many, Polarity::Positive).is_err());
    let mut negative_max = negative.clone();
    negative_max.cases = (0..CASES_PER_FILE_MAX)
        .map(|index| {
            let mut case = negative.cases[4].clone();
            case.case_id = format!("y.generated.{index:03}");
            case
        })
        .collect();
    negative_max.case_count = negative_max.cases.len();
    assert!(validate_cross_file(&too_many, &negative_max).is_err());
}

#[test]
fn streaming_preflight_enforces_depth_members_arrays_and_strings() {
    let exact_depth = generated_nested_array(JSON_MAX_DEPTH - 1);
    let too_deep = generated_nested_array(JSON_MAX_DEPTH);
    let stats = preflight_json(
        &exact_depth,
        DuplicatePolicy::Permit,
        StringLimitPolicy::Inline,
    )
    .expect("exact depth");
    assert_eq!(stats.maximum_depth, JSON_MAX_DEPTH);
    assert!(preflight_json(
        &too_deep,
        DuplicatePolicy::Permit,
        StringLimitPolicy::Inline
    )
    .is_err());

    let exact_members = generated_duplicate_object(JSON_OBJECT_MEMBERS_MAX);
    let stats = preflight_json(
        &exact_members,
        DuplicatePolicy::Permit,
        StringLimitPolicy::Inline,
    )
    .expect("exact members including duplicates");
    assert_eq!(stats.maximum_object_members, JSON_OBJECT_MEMBERS_MAX);
    assert!(preflight_json(
        &generated_duplicate_object(JSON_OBJECT_MEMBERS_MAX + 1),
        DuplicatePolicy::Permit,
        StringLimitPolicy::Inline
    )
    .is_err());

    let exact_array = generated_array(JSON_ARRAY_ELEMENTS_MAX);
    let stats = preflight_json(
        &exact_array,
        DuplicatePolicy::Permit,
        StringLimitPolicy::Inline,
    )
    .expect("exact array");
    assert_eq!(stats.maximum_array_elements, JSON_ARRAY_ELEMENTS_MAX);
    assert!(preflight_json(
        &generated_array(JSON_ARRAY_ELEMENTS_MAX + 1),
        DuplicatePolicy::Permit,
        StringLimitPolicy::Inline
    )
    .is_err());

    let exact_string = format!("\"{}\"", "\\u0061".repeat(METADATA_STRING_MAX_BYTES));
    let long_string = format!("\"{}\"", "\\u0061".repeat(METADATA_STRING_MAX_BYTES + 1));
    preflight_json(
        &exact_string,
        DuplicatePolicy::Permit,
        StringLimitPolicy::Inline,
    )
    .expect("exact decoded string");
    assert!(preflight_json(
        &long_string,
        DuplicatePolicy::Permit,
        StringLimitPolicy::Inline
    )
    .is_err());
}

#[test]
fn capped_writer_accepts_65536_and_aborts_attempted_65537() {
    let exact = "a".repeat(OUTPUT_MAX_BYTES - 2);
    let output = capped_json(&exact).expect("exact capped JSON string");
    assert_eq!(output.len(), OUTPUT_MAX_BYTES);
    let over = "a".repeat(OUTPUT_MAX_BYTES - 1);
    assert!(capped_json(&over).is_err());

    let mut writer = CappedWriter::new();
    writer
        .write_all(&vec![b'x'; OUTPUT_MAX_BYTES])
        .expect("exact writer ceiling");
    assert_eq!(writer.length, OUTPUT_MAX_BYTES);
    assert_eq!(writer.bytes.len(), OUTPUT_MAX_BYTES);
    assert!(writer.write_all(b"x").is_err());
    assert_eq!(writer.attempted_length, OUTPUT_MAX_BYTES + 1);
    assert_eq!(writer.length, OUTPUT_MAX_BYTES);
}

#[test]
fn fixture_trace_extension_and_relation_duplicates_have_distinct_paths() {
    let duplicate_manifest =
        format!("{{\"format_id\":\"{FORMAT_MANIFEST}\",\"format_id\":\"{FORMAT_MANIFEST}\"}}");
    assert!(parse_closed::<Manifest>(duplicate_manifest.as_bytes(), MANIFEST_MAX_BYTES).is_err());

    let trace_duplicate = "{\"trace_event_id\":\"11111111-1111-4111-8111-111111111111\",\"trace_event_id\":\"11111111-1111-4111-8111-111111111111\"}";
    preflight_json(
        trace_duplicate,
        DuplicatePolicy::Permit,
        StringLimitPolicy::Inline,
    )
    .expect("Trace duplicates reach production");
    assert!(serde_json::from_str::<TraceEvent>(trace_duplicate).is_err());

    let extension_duplicate = "{\"display\":1,\"display\":2}";
    assert!(preflight_json(
        extension_duplicate,
        DuplicatePolicy::Reject,
        StringLimitPolicy::Inline
    )
    .is_err());

    let (_, _, negative) = load_all().expect("fixture load");
    let files = [&negative];
    let relation = case_by_id(&files, "live_relation.wrong_owner_caller_credential");
    let Input::CallerCredentialJson(body) = &relation.input else {
        panic!("source-fixed relation input kind");
    };
    let duplicate_relation = replace_once_sanitized(
        &body.json,
        "\"credential_id\":",
        "\"credential_id\":\"duplicate\",\"credential_id\":",
    )
    .expect("source-fixed duplicate relation marker");
    let unchanged = duplicate_relation.clone();
    preflight_json(
        &duplicate_relation,
        DuplicatePolicy::Permit,
        StringLimitPolicy::Inline,
    )
    .expect("relation duplicate reaches production");
    assert!(duplicate_relation == unchanged);
    assert!(serde_json::from_str::<CallerCredential>(&duplicate_relation).is_err());
}

#[test]
fn typed_loader_rejects_duplicates_unknowns_missing_null_types_and_trailing() {
    let duplicate_case = format!(
        "{{\"format_id\":\"{FORMAT_CASES}\",\"profile\":\"{PROFILE}\",\"polarity\":\"positive\",\"case_count\":1,\"cases\":[{{\"case_id\":\"a\",\"case_id\":\"b\",\"subject\":\"canonical_label_v1\",\"operation\":\"parse\",\"input\":{{\"kind\":\"text\",\"body\":{{\"value\":\"a\"}}}},\"expected\":{{\"execution_result\":\"accepted\",\"serialized_utf8\":\"\\\"a\\\"\"}},\"live_disposition_status\":\"not_exercised\",\"schema_registration_status\":\"not_exercised\"}}]}}"
    );
    assert!(parse_closed::<CaseFile>(duplicate_case.as_bytes(), CASE_FILE_MAX_BYTES).is_err());

    let duplicate_expected = one_case_file_json(
        "positive",
        "canonical_label_v1",
        "parse",
        "{\"kind\":\"text\",\"body\":{\"value\":\"a\"}}",
        "{\"execution_result\":\"accepted\",\"execution_result\":\"accepted\",\"serialized_utf8\":\"\\\"a\\\"\"}",
        "",
    );
    assert!(parse_closed::<CaseFile>(duplicate_expected.as_bytes(), CASE_FILE_MAX_BYTES).is_err());
    let duplicate_body = one_case_file_json(
        "positive",
        "canonical_label_v1",
        "parse",
        "{\"kind\":\"text\",\"body\":{\"value\":\"a\",\"value\":\"b\"}}",
        "{\"execution_result\":\"accepted\",\"serialized_utf8\":\"\\\"a\\\"\"}",
        "",
    );
    assert!(parse_closed::<CaseFile>(duplicate_body.as_bytes(), CASE_FILE_MAX_BYTES).is_err());

    let manifest_text = std::str::from_utf8(MANIFEST_BYTES).expect("manifest UTF-8");
    let unknown_manifest = manifest_text.replacen('{', "{\"unknown\":1,", 1);
    assert!(parse_closed::<Manifest>(unknown_manifest.as_bytes(), MANIFEST_MAX_BYTES).is_err());

    for raw in [
        one_case_file_json(
            "positive",
            "canonical_label_v1",
            "parse",
            "{\"kind\":\"text\",\"body\":{\"value\":\"a\",\"unknown\":1}}",
            "{\"execution_result\":\"accepted\",\"serialized_utf8\":\"\\\"a\\\"\"}",
            "",
        ),
        one_case_file_json(
            "positive",
            "canonical_label_v1",
            "parse",
            "{\"kind\":\"text\",\"body\":{\"value\":\"a\"},\"unknown\":1}",
            "{\"execution_result\":\"accepted\",\"serialized_utf8\":\"\\\"a\\\"\"}",
            "",
        ),
    ] {
        assert!(parse_closed::<CaseFile>(raw.as_bytes(), CASE_FILE_MAX_BYTES).is_err());
    }

    let present_null = one_case_file_json(
        "negative",
        "canonical_label_v1",
        "parse_reject",
        "{\"kind\":\"text\",\"body\":{\"value\":\"A\"}}",
        "{\"execution_result\":\"rejected\",\"stable_error_code\":null}",
        "",
    );
    assert!(parse_closed::<CaseFile>(present_null.as_bytes(), CASE_FILE_MAX_BYTES).is_err());

    for raw in [
        "{}".to_string(),
        "null".to_string(),
        "[]".to_string(),
        format!("{{\"format_id\":\"{FORMAT_CASES}\",\"profile\":\"{PROFILE}\",\"polarity\":\"positive\",\"case_count\":1,\"cases\":{{}}}}"),
        format!("{{\"format_id\":\"{FORMAT_CASES}\",\"profile\":\"{PROFILE}\",\"polarity\":\"positive\",\"case_count\":0,\"cases\":[]}} trailing"),
    ] {
        assert!(parse_closed::<CaseFile>(raw.as_bytes(), CASE_FILE_MAX_BYTES).is_err());
    }

    let empty_cases = format!(
        "{{\"format_id\":\"{FORMAT_CASES}\",\"profile\":\"{PROFILE}\",\"polarity\":\"positive\",\"case_count\":0,\"cases\":[]}}"
    );
    let empty_cases: CaseFile =
        parse_closed(empty_cases.as_bytes(), CASE_FILE_MAX_BYTES).expect("closed empty case file");
    assert!(validate_case_file(&empty_cases, Polarity::Positive).is_err());

    for raw in [
        one_case_file_json(
            "positive",
            "canonical_label_v1",
            "parse",
            "{\"kind\":\"text\",\"body\":{\"value\":[]}}",
            "{\"execution_result\":\"accepted\",\"serialized_utf8\":\"\\\"a\\\"\"}",
            "",
        ),
        one_case_file_json(
            "positive",
            "canonical_label_v1",
            "parse",
            "{\"kind\":\"text\",\"body\":{\"value\":\"a\"}}",
            "{\"execution_result\":true,\"serialized_utf8\":\"\\\"a\\\"\"}",
            "",
        ),
    ] {
        assert!(parse_closed::<CaseFile>(raw.as_bytes(), CASE_FILE_MAX_BYTES).is_err());
    }
}

#[test]
fn loader_rejects_every_unknown_closed_value_family() {
    let scalar_expected =
        "{\"execution_result\":\"rejected\",\"stable_error_code\":\"invalid_contract_shape\"}";
    let text_input = "{\"kind\":\"text\",\"body\":{\"value\":\"A\"}}";
    let cases = [
        one_case_file_json(
            "negative",
            "unknown_subject",
            "parse_reject",
            text_input,
            scalar_expected,
            "",
        ),
        one_case_file_json(
            "negative",
            "canonical_label_v1",
            "unknown_operation",
            text_input,
            scalar_expected,
            "",
        ),
        one_case_file_json(
            "negative",
            "canonical_label_v1",
            "parse_reject",
            "{\"kind\":\"unknown_input\",\"body\":{\"value\":\"A\"}}",
            scalar_expected,
            "",
        ),
        one_case_file_json(
            "negative",
            "canonical_label_v1",
            "parse_reject",
            text_input,
            "{\"execution_result\":\"rejected\",\"stable_error_code\":\"unknown_error\"}",
            "",
        ),
        one_case_file_json(
            "negative",
            "schema_extension_map",
            "validate_extension_map",
            "{\"kind\":\"extension_json\",\"body\":{\"json\":\"{\\\"gateway\\\":1}\",\"root_path\":\"extensions\",\"additional_reserved_keys\":[]}}",
            "{\"execution_result\":\"rejected\",\"extension_error\":{\"reason\":\"unknown_reason\",\"path\":\"extensions.gateway\",\"key\":\"gateway\",\"normalized_key\":\"gateway\"}}",
            "",
        ),
    ];
    for raw in cases {
        assert!(parse_closed::<CaseFile>(raw.as_bytes(), CASE_FILE_MAX_BYTES).is_err());
    }
    let bad_polarity = format!(
        "{{\"format_id\":\"{FORMAT_CASES}\",\"profile\":\"{PROFILE}\",\"polarity\":\"side\",\"case_count\":1,\"cases\":[]}}"
    );
    assert!(parse_closed::<CaseFile>(bad_polarity.as_bytes(), CASE_FILE_MAX_BYTES).is_err());

    for input in [
        "{\"kind\":\"declaration\",\"body\":{\"resource_id\":\"unknown_resource\",\"mutation\":\"none\",\"digest_domain\":\"production\"}}",
        "{\"kind\":\"declaration\",\"body\":{\"resource_id\":\"rfc0013_driver_operation_credential_sinks_v1\",\"mutation\":\"unknown_mutation\",\"digest_domain\":\"production\"}}",
        "{\"kind\":\"declaration\",\"body\":{\"resource_id\":\"rfc0013_driver_operation_credential_sinks_v1\",\"mutation\":\"none\",\"digest_domain\":\"unknown_domain\"}}",
    ] {
        let raw = one_case_file_json(
            "positive",
            "registry_declaration_digest",
            "declaration_digest",
            input,
            "{\"execution_result\":\"accepted\",\"serialized_utf8\":\"x\",\"expected_digest_wire\":\"x\",\"digest_equality\":true}",
            "",
        );
        assert!(parse_closed::<CaseFile>(raw.as_bytes(), CASE_FILE_MAX_BYTES).is_err());
    }
}

#[test]
fn manifest_constants_paths_statuses_and_nonclaims_are_immutable() {
    let (manifest, _, _) = load_all().expect("fixture load");
    let mut mutations: Vec<Manifest> = Vec::new();

    let mut changed = manifest.clone();
    changed.accepted_proposal_sha256.rfc_0021 = "0".repeat(64);
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.case_files[0].file_id = "other".to_string();
    mutations.push(changed);
    for path in [
        "other.json",
        "scheme:remote",
        "/absolute",
        "../parent",
        "${EXPANSION}",
    ] {
        let mut changed = manifest.clone();
        changed.case_files[0].path = path.to_string();
        mutations.push(changed);
    }
    let mut changed = manifest.clone();
    changed.builtin_resource_id = "nested/resource".to_string();
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.required_live_relation_case_ids.swap(0, 1);
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.required_live_relation_case_ids.pop();
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.required_live_relation_case_ids[0] = "live_relation.renamed_work_order".to_string();
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.gold_statuses[0].evidence_status = "exercised".to_string();
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.non_claims.swap(0, 1);
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.production_surfaces.swap(0, 1);
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.limits.json_max_depth += 1;
    mutations.push(changed);
    let mut changed = manifest.clone();
    changed.live_disposition_status = "current".to_string();
    mutations.push(changed);

    for changed in mutations {
        assert!(validate_manifest(&changed).is_err());
    }
}

#[test]
fn case_identity_order_polarity_and_required_relations_are_enforced() {
    let (_, positive, negative) = load_all().expect("fixture load");
    let mut count = positive.clone();
    count.case_count += 1;
    assert!(validate_case_file(&count, Polarity::Positive).is_err());
    assert!(validate_case_file(&positive, Polarity::Negative).is_err());

    let mut unsorted = positive.clone();
    unsorted.cases.swap(0, 1);
    assert!(validate_case_file(&unsorted, Polarity::Positive).is_err());
    let mut duplicate = positive.clone();
    duplicate.cases[1].case_id = duplicate.cases[0].case_id.clone();
    assert!(validate_case_file(&duplicate, Polarity::Positive).is_err());
    let mut cross = negative.clone();
    cross.cases[4].case_id = positive.cases[0].case_id.clone();
    assert!(validate_cross_file(&positive, &cross).is_err());

    let required_index = negative
        .cases
        .iter()
        .position(|case| case.case_id == "live_relation.stale_work_order")
        .expect("required relation");
    let mut missing = negative.clone();
    missing.cases.remove(required_index);
    missing.case_count -= 1;
    assert!(validate_cross_file(&positive, &missing).is_err());

    let mut duplicate_required = negative.clone();
    duplicate_required.cases.insert(
        required_index,
        duplicate_required.cases[required_index].clone(),
    );
    duplicate_required.case_count += 1;
    assert!(validate_case_file(&duplicate_required, Polarity::Negative).is_err());
    assert!(validate_cross_file(&positive, &duplicate_required).is_err());

    let mut reordered_required = negative.clone();
    reordered_required
        .cases
        .swap(required_index, required_index + 1);
    assert!(validate_case_file(&reordered_required, Polarity::Negative).is_err());

    let mut renamed = negative.clone();
    renamed.cases[required_index].case_id = "live_relation.renamed_work_order".to_string();
    assert!(validate_case_file(&renamed, Polarity::Negative).is_err());
    assert!(validate_cross_file(&positive, &renamed).is_err());

    let mut wrong_subject = negative.clone();
    wrong_subject.cases[required_index].subject = Subject::CallerCredential;
    assert!(validate_case_file(&wrong_subject, Polarity::Negative).is_err());
    let mut wrong_operation = negative.clone();
    wrong_operation.cases[required_index].operation = Operation::Parse;
    assert!(validate_case_file(&wrong_operation, Polarity::Negative).is_err());
    let mut wrong_input = negative.clone();
    wrong_input.cases[required_index].input = Input::CallerCredentialJson(JsonBody {
        json: "{}".to_string(),
    });
    assert!(validate_case_file(&wrong_input, Polarity::Negative).is_err());
    let mut wrong_status = negative.clone();
    wrong_status.cases[required_index].live_disposition_status = "current".to_string();
    assert!(validate_case_file(&wrong_status, Polarity::Negative).is_err());
    let mut wrong_registration_status = negative.clone();
    wrong_registration_status.cases[required_index].schema_registration_status =
        "registered".to_string();
    assert!(validate_case_file(&wrong_registration_status, Polarity::Negative).is_err());

    let relation_field = one_case_file_json(
        "negative",
        "work_order",
        "parse_live_relation",
        "{\"kind\":\"work_order_json\",\"body\":{\"json\":\"{}\"}}",
        "{\"execution_result\":\"accepted\",\"serialized_utf8\":\"{}\"}",
        ",\"relation\":\"fixture_selected\"",
    );
    assert!(parse_closed::<CaseFile>(relation_field.as_bytes(), CASE_FILE_MAX_BYTES).is_err());
}

#[test]
fn source_fixed_live_relations_reject_false_relation_variants() {
    let (_, _, negative) = load_all().expect("fixture load");
    let files = [&negative];
    let variants = [
        (
            "live_relation.stale_work_order",
            "\"expires_at\":\"2029-12-31T00:00:00Z\"",
            "\"expires_at\":\"2031-12-31T00:00:00Z\"",
        ),
        (
            "live_relation.wrong_owner_caller_credential",
            "\"app_principal_id\":\"app_other\"",
            "\"app_principal_id\":\"app_expected\"",
        ),
        (
            "live_relation.wrong_tenant_work_order",
            "\"tenant_id\":\"00000000-0000-4000-8000-000000000099\"",
            "\"tenant_id\":\"00000000-0000-4000-8000-000000000001\"",
        ),
        (
            "live_relation.wrong_audience_caller_credential",
            "\"daemon_id\":\"daemon_other\"",
            "\"daemon_id\":\"daemon_expected\"",
        ),
    ];
    for (case_id, from, to) in variants {
        let mut case = case_by_id(&files, case_id).clone();
        let json = match &mut case.input {
            Input::WorkOrderJson(body) | Input::CallerCredentialJson(body) => &mut body.json,
            _ => panic!("source-fixed relation input kind"),
        };
        let changed = replace_once_sanitized(json, from, to)
            .expect("source-fixed false-relation mutation marker");
        *json = changed;
        assert!(execute_live_relation(&case).is_err());
    }
}

#[test]
fn operation_result_and_observation_matrix_rejects_fixture_claims() {
    let (_, positive, negative) = load_all().expect("fixture load");
    let mut unexpected = positive.cases[0].clone();
    unexpected.expected.stable_error_code = Some(ErrorCode::Shape);
    assert!(validate_case(&unexpected, Polarity::Positive).is_err());
    let mut missing = positive.cases[0].clone();
    missing.expected.serialized_utf8 = None;
    assert!(validate_case(&missing, Polarity::Positive).is_err());
    let mut positive_rejected = positive.cases[0].clone();
    positive_rejected.expected.execution_result = ExecutionResult::Rejected;
    assert!(validate_case(&positive_rejected, Polarity::Positive).is_err());
    let mut negative_accepted = negative.cases[4].clone();
    negative_accepted.expected.execution_result = ExecutionResult::Accepted;
    assert!(validate_case(&negative_accepted, Polarity::Negative).is_err());

    let wrong_domain = negative
        .cases
        .iter()
        .find(|case| case.operation == Operation::WrongDomainCompare)
        .expect("wrong domain");
    let mut wrong_wire = wrong_domain.clone();
    wrong_wire.expected.expected_digest_wire = Some(GOLDEN_DIGEST.to_string());
    assert!(validate_case(&wrong_wire, Polarity::Negative).is_err());
    let mut wrong_equality = wrong_domain.clone();
    wrong_equality.expected.digest_equality = Some(true);
    assert!(validate_case(&wrong_equality, Polarity::Negative).is_err());

    for claim in [
        "passed",
        "conformant",
        "compatible",
        "supported",
        "registered",
        "current",
        "authorized",
        "completed",
        "gold_passed",
        "accept_current",
    ] {
        let raw = one_case_file_json(
            "positive",
            "canonical_label_v1",
            "parse",
            "{\"kind\":\"text\",\"body\":{\"value\":\"a\"}}",
            "{\"execution_result\":\"accepted\",\"serialized_utf8\":\"\\\"a\\\"\"}",
            &format!(",\"claim\":\"{claim}\""),
        );
        assert!(parse_closed::<CaseFile>(raw.as_bytes(), CASE_FILE_MAX_BYTES).is_err());
    }
}

#[test]
fn legal_dispatch_matrix_and_declaration_combinations_are_exhaustive() {
    let subjects = [
        Subject::CanonicalSchemaIdV1,
        Subject::CanonicalLabelV1,
        Subject::FoundationGrammarCodeV1,
        Subject::CanonicalTimestampV1,
        Subject::CanonicalCountV1,
        Subject::CanonicalOrdinalV1,
        Subject::CanonicalSequenceV1,
        Subject::CanonicalPositiveRevisionV1,
        Subject::FoundationGrammarError,
        Subject::RegistryDeclarationDigest,
        Subject::TraceEvent,
        Subject::SchemaExtensionMap,
        Subject::SchemaExtensionValue,
        Subject::WorkOrder,
        Subject::CallerCredential,
    ];
    let operations = [
        Operation::Parse,
        Operation::Construct,
        Operation::FromStr,
        Operation::Serialize,
        Operation::ParseReject,
        Operation::ConstructReject,
        Operation::FromStrReject,
        Operation::InspectError,
        Operation::DeclarationDigest,
        Operation::WrongDomainCompare,
        Operation::TraceDeserializeSerialize,
        Operation::TraceReject,
        Operation::ValidateExtensionMap,
        Operation::ValidateExtensionMapWithReservedKeys,
        Operation::ValidateExtensionValue,
        Operation::ValidateExtensionValueWithReservedKeys,
        Operation::ParseLiveRelation,
    ];
    let inputs = [
        InputKind::Text,
        InputKind::U64,
        InputKind::ErrorCode,
        InputKind::Declaration,
        InputKind::TraceJson,
        InputKind::ExtensionJson,
        InputKind::WorkOrderJson,
        InputKind::CallerCredentialJson,
    ];
    let mut non_live_matrix = HashSet::new();
    for subject in [
        Subject::CanonicalSchemaIdV1,
        Subject::CanonicalLabelV1,
        Subject::FoundationGrammarCodeV1,
        Subject::CanonicalTimestampV1,
    ] {
        for operation in [
            Operation::Parse,
            Operation::Construct,
            Operation::FromStr,
            Operation::Serialize,
            Operation::ParseReject,
            Operation::ConstructReject,
            Operation::FromStrReject,
        ] {
            non_live_matrix.insert((subject, operation, InputKind::Text));
        }
    }
    for subject in [
        Subject::CanonicalCountV1,
        Subject::CanonicalOrdinalV1,
        Subject::CanonicalSequenceV1,
        Subject::CanonicalPositiveRevisionV1,
    ] {
        for operation in [
            Operation::Parse,
            Operation::FromStr,
            Operation::ParseReject,
            Operation::FromStrReject,
        ] {
            non_live_matrix.insert((subject, operation, InputKind::Text));
        }
        for operation in [
            Operation::Construct,
            Operation::Serialize,
            Operation::ConstructReject,
        ] {
            non_live_matrix.insert((subject, operation, InputKind::U64));
        }
    }
    non_live_matrix.insert((
        Subject::FoundationGrammarError,
        Operation::InspectError,
        InputKind::ErrorCode,
    ));
    for operation in [
        Operation::Parse,
        Operation::FromStr,
        Operation::Serialize,
        Operation::ParseReject,
        Operation::FromStrReject,
    ] {
        non_live_matrix.insert((
            Subject::RegistryDeclarationDigest,
            operation,
            InputKind::Text,
        ));
    }
    for operation in [Operation::DeclarationDigest, Operation::WrongDomainCompare] {
        non_live_matrix.insert((
            Subject::RegistryDeclarationDigest,
            operation,
            InputKind::Declaration,
        ));
    }
    for operation in [Operation::TraceDeserializeSerialize, Operation::TraceReject] {
        non_live_matrix.insert((Subject::TraceEvent, operation, InputKind::TraceJson));
    }
    for operation in [
        Operation::ValidateExtensionMap,
        Operation::ValidateExtensionMapWithReservedKeys,
    ] {
        non_live_matrix.insert((
            Subject::SchemaExtensionMap,
            operation,
            InputKind::ExtensionJson,
        ));
    }
    for operation in [
        Operation::ValidateExtensionValue,
        Operation::ValidateExtensionValueWithReservedKeys,
    ] {
        non_live_matrix.insert((
            Subject::SchemaExtensionValue,
            operation,
            InputKind::ExtensionJson,
        ));
    }
    assert!(non_live_matrix.len() == 70);

    let live_matrix = [
        (
            "live_relation.stale_work_order",
            Subject::WorkOrder,
            Operation::ParseLiveRelation,
            InputKind::WorkOrderJson,
        ),
        (
            "live_relation.wrong_owner_caller_credential",
            Subject::CallerCredential,
            Operation::ParseLiveRelation,
            InputKind::CallerCredentialJson,
        ),
        (
            "live_relation.wrong_tenant_work_order",
            Subject::WorkOrder,
            Operation::ParseLiveRelation,
            InputKind::WorkOrderJson,
        ),
        (
            "live_relation.wrong_audience_caller_credential",
            Subject::CallerCredential,
            Operation::ParseLiveRelation,
            InputKind::CallerCredentialJson,
        ),
    ];
    for case_id in [
        "not_live_relation",
        "live_relation.stale_work_order",
        "live_relation.wrong_owner_caller_credential",
        "live_relation.wrong_tenant_work_order",
        "live_relation.wrong_audience_caller_credential",
    ] {
        for subject in subjects {
            assert!(!subject.as_str().is_empty());
            for operation in operations {
                assert!(!operation.as_str().is_empty());
                for input in inputs {
                    let expected = non_live_matrix.contains(&(subject, operation, input))
                        || live_matrix.iter().any(
                            |(live_id, live_subject, live_operation, live_input)| {
                                case_id == *live_id
                                    && subject == *live_subject
                                    && operation == *live_operation
                                    && input == *live_input
                            },
                        );
                    assert!(legal_dispatch(subject, operation, input, case_id) == expected);
                }
            }
        }
    }

    let mutations = [
        DeclarationMutation::None,
        DeclarationMutation::DriverDeclarationRevision1To2,
    ];
    let domains = [DigestDomain::Production, DigestDomain::WrongDomainV2];
    for operation in operations {
        for mutation in mutations {
            for domain in domains {
                let body = DeclarationBody {
                    resource_id: ResourceId::Rfc0013DriverOperationCredentialSinksV1,
                    mutation,
                    digest_domain: domain,
                };
                let expected = matches!(
                    (operation, mutation, domain),
                    (
                        Operation::DeclarationDigest,
                        DeclarationMutation::None,
                        DigestDomain::Production
                    ) | (
                        Operation::DeclarationDigest,
                        DeclarationMutation::DriverDeclarationRevision1To2,
                        DigestDomain::Production
                    ) | (
                        Operation::WrongDomainCompare,
                        DeclarationMutation::None,
                        DigestDomain::WrongDomainV2
                    )
                );
                assert_eq!(
                    validate_declaration_combination(operation, &body).is_ok(),
                    expected
                );
            }
        }
    }
}

#[test]
fn diagnostics_omit_rejected_values_serde_text_extension_fields_and_digest_wires() {
    const SENTINELS: [&str; 6] = [
        "PRIVATE_REJECTED_INPUT_CANARY",
        "PRIVATE_SERDE_TEXT_CANARY",
        "PRIVATE_EXTENSION_PATH_CANARY",
        "PRIVATE_EXTENSION_KEY_CANARY",
        "PRIVATE_NORMALIZED_KEY_CANARY",
        "blake3:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    for category in [
        FailureCategory::RawBound,
        FailureCategory::Utf8,
        FailureCategory::JsonEnvelope,
        FailureCategory::FixtureContract,
        FailureCategory::IdentityOrder,
        FailureCategory::Dispatch,
        FailureCategory::Observation,
        FailureCategory::ProductionRejected,
        FailureCategory::ProductionAccepted,
        FailureCategory::SerializationBound,
        FailureCategory::ValueMismatch,
    ] {
        let rendered = sanitized(category).to_string();
        assert!(SENTINELS
            .iter()
            .all(|sentinel| !rendered.contains(sentinel)));
    }

    let (_, _, negative) = load_all().expect("fixture load");
    let case = negative
        .cases
        .iter()
        .find(|case| case.expected.extension_error.is_some())
        .expect("extension denial");
    let actual = ExtensionValidationError {
        path: SENTINELS[2].to_string(),
        key: SENTINELS[3].to_string(),
        normalized_key: SENTINELS[4].to_string(),
        reason: ExtensionValidationReason::ReservedAuthorityKey,
    };
    let rendered = compare_extension_error(case, &actual)
        .expect_err("sentinel comparison differs")
        .to_string();
    assert!(SENTINELS
        .iter()
        .all(|sentinel| !rendered.contains(sentinel)));

    let rejected = one_case_file_json(
        "negative",
        "canonical_label_v1",
        "parse_reject",
        &format!(
            "{{\"kind\":\"text\",\"body\":{{\"value\":\"{}\"}}}}",
            SENTINELS[0]
        ),
        "{\"execution_result\":\"rejected\",\"stable_error_code\":null}",
        "",
    );
    let rendered = parse_closed::<CaseFile>(rejected.as_bytes(), CASE_FILE_MAX_BYTES)
        .err()
        .expect("present null rejects")
        .to_string();
    assert!(SENTINELS
        .iter()
        .all(|sentinel| !rendered.contains(sentinel)));

    let malformed = format!("{{\"{}\":", SENTINELS[1]);
    let rendered = parse_closed::<CaseFile>(malformed.as_bytes(), CASE_FILE_MAX_BYTES)
        .err()
        .expect("malformed fixture rejects")
        .to_string();
    assert!(SENTINELS
        .iter()
        .all(|sentinel| !rendered.contains(sentinel)));

    let rendered = replace_once_sanitized(SENTINELS[0], "missing-marker", "replacement")
        .expect_err("missing relation marker rejects")
        .to_string();
    assert!(SENTINELS
        .iter()
        .all(|sentinel| !rendered.contains(sentinel)));

    let over_bound_output = SENTINELS[1].repeat(OUTPUT_MAX_BYTES);
    let rendered = capped_json(&over_bound_output)
        .expect_err("over-bound serialization rejects")
        .to_string();
    assert!(SENTINELS
        .iter()
        .all(|sentinel| !rendered.contains(sentinel)));

    let digest_error = RegistryDeclarationDigest::parse(SENTINELS[5])
        .expect_err("uppercase digest sentinel rejects");
    let grammar_rendered = format!("{digest_error} {digest_error:?}");
    assert!(!grammar_rendered.contains(SENTINELS[5]));
}
