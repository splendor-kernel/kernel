# RFC 0021 - C03 Foundation Offline Characterization Contract

## Status and Binding

**Status:** Proposed implementation-blocking contract

**Date:** 2026-07-21

**Accepted proposal SHA-256:** Not assigned while this RFC is proposed. The
acceptance process must record the accepted proposal hash here before the
implementation authorized by this RFC starts.

**Active execution line:** `Splendor0.2-dev` / `0.2/v2`

**Program:** `V2-FND-0 Foundations`

**Catalog task:** `FND-006` / issue `#225`, partial offline Slice 1 only

**Required dependencies:** `FND-001` and `FND-002`

**Primary functional requirements:** `FR-0.2-01` and `FR-0.2-08`

**Constrained and preserved requirements:** `FR-0.2-02` and the stable 0.1
compatibility line

**Owner package:** `crates/splendor-types`

**Gold targets:** `G00` and `G72`

**Gold status:** both remain `specified_not_implemented` / `not_exercised`;
this RFC changes no status

**Normative inputs:** [AGENTS.md](../../AGENTS.md), the
[active roadmap](../rules/sprints_frs_milestones.md), the
[FND-006 catalog record](../rules/v2/catalog/complete_implementation_task_catalog.md),
the [machine-readable FND-006 record](../rules/v2/catalog/architecture/implementation_tasks.yaml),
the [foundation-readiness checkpoint](../rules/v2/foundation-readiness.md),
[RFC 0013](0013-driver-operation-credential-sink-contract.md),
[RFC 0018](0018-c03-foundation-grammar-profile.md),
[RFC 0020](0020-c03-foundation-compatibility-migration-profile.md), and the
stable [0.1 primitive contract](../spec/0.1/primitives.md)

This RFC is documentation-only and proposal-only. It changes no Rust type,
Cargo manifest, lockfile, public schema, generated surface, daemon, Store,
runtime, SDK, CI, migration, compatibility classification, live disposition,
schema registration, task status, issue status, Gold status, conformance status,
or release claim. It does not implement or complete `FND-006`, `G00`, `G72`,
C03, or any dependent task.

RFC 0018 is an accepted planning contract and its bounded Slice 1A values are
implemented. RFC 0020 is an accepted planning contract, but its Open Owner
Annexes make this exact characterization contract implementation-blocking. This
RFC fills only that planning gap. Until this RFC is accepted, the implementation
below must not start.

## Decision

After this RFC is accepted through separate architecture/compatibility and
security/privacy review, one fresh implementation branch may add a bounded,
offline, private Rust characterization harness for already implemented stable
0.1 and RFC 0018 Slice 1A production APIs.

The harness records only:

- production parser, checked-constructor, and `FromStr` acceptance or rejection;
- exact stable error codes where the production API exposes one;
- exact serialization explicitly pinned by an accepted governing contract;
- exact observed production serialization where no governing contract pins the
  complete output;
- declaration-digest equality or inequality for fixed synthetic vectors;
- extension-validator reason, path, key, and normalized key compared internally
  where the public API exposes them; and
- parse-only structural and fixed-relation observations for the exact four
  RFC 0020 stale/wrong-relation inputs defined below.

The comparison outcome is named `matched`. It is never named `passed`,
`conformant`, `compatible`, `registered`, `authorized`, `current`, a Gold result,
or a task-completion result. No retained report is created in this slice. Cargo
test output and captured command evidence are the only execution evidence.

The harness does not execute a compatibility class or live disposition. It does
include the four machine-readable, structurally valid stale/wrong-relation
inputs required by accepted RFC 0020. Those cases parse public `WorkOrder` or
`CallerCredential` values and check one source-code-fixed relation only; they do
not execute owner, authorization, signature, tenant, audience, expiry,
revocation, currentness, policy, or operation validation. Every case keeps live
disposition and schema registration exactly `not_exercised`.

## In-Scope Public API Inventory

The following is the bounded production inventory characterized by this slice.
It does not claim to cover every public API. Planning reservations and private
fixture labels are excluded.

| Subject | Current production truth |
| --- | --- |
| `CanonicalSchemaIdV1` | [`foundation_grammar.rs`](../../crates/splendor-types/src/foundation_grammar.rs) exposes `parse`, `try_new`, `FromStr`, `as_str`, and `Serialize`. Accepted cases assert `as_str()` equals the exact input. Lexical success does not register a schema. |
| `CanonicalLabelV1` | The same source exposes `parse`, `try_new`, `FromStr`, `as_str`, and `Serialize` for the accepted ASCII label profile. Accepted cases assert the exact `as_str()` value. |
| `FoundationGrammarCodeV1` | The same source exposes a nominally distinct code with `parse`, `try_new`, `FromStr`, `as_str`, and `Serialize`. Accepted cases assert the exact `as_str()` value. |
| `CanonicalTimestampV1` | The same source exposes `parse`, `try_new`, `FromStr`, `as_str`, and `Serialize` for exact UTC microsecond text. Accepted cases assert the exact `as_str()` value. |
| `CanonicalCountV1` | The same source exposes original-token `parse`, checked `try_new`, `FromStr`, `get`, and `Serialize`. Accepted cases assert `get()` equals the parsed or constructed integer. |
| `CanonicalOrdinalV1` | The same source exposes original-token `parse`, checked `try_new`, `FromStr`, `get`, and `Serialize`. Accepted cases assert `get()` equals the parsed or constructed integer. |
| `CanonicalSequenceV1` | The same source exposes original-token `parse`, checked `try_new`, `FromStr`, `get`, and `Serialize`. Accepted cases assert `get()` equals the parsed or constructed integer. |
| `CanonicalPositiveRevisionV1` | The same source exposes original-token `parse`, positive checked `try_new`, `FromStr`, `get`, and `Serialize`. Accepted cases assert `get()` equals the parsed or constructed integer. |
| `FoundationGrammarError` | The same source exposes exactly nine variants, stable `as_str`, code-only `Display` and `Debug`, and no source chain. Some variants are intentionally inspectable even when current Slice 1A constructors do not emit them. |
| `RegistryDeclarationDigest` | The same source exposes strict digest `parse`, `FromStr`, redacted `Debug`, `Serialize`, and `TryFrom<&DriverOperationCredentialSinksV1>`. Construction hashes the production declaration serialization under the accepted RFC 0018 domain. Every accepted digest asserts exact `Debug` output `RegistryDeclarationDigest(<redacted>)`; diagnostics never expose its wire. |
| RFC 0013 declaration | [`driver.rs`](../../crates/splendor-types/src/driver.rs) exposes `DriverOperationCredentialSinksV1::from_json_slice`, checked `try_new`, `driver_declaration_revision`, other accessors, and `Serialize`. Declaration cases assert the `driver_declaration_revision()` accessor. The existing fixed synthetic declaration fixture is [`operation-credential-sinks-v1.json`](../../crates/splendor-types/tests/fixtures/driver/operation-credential-sinks-v1.json). |
| `TraceEvent` | [`trace.rs`](../../crates/splendor-types/src/trace.rs) derives production `Deserialize` and `Serialize`. `trace_id` is an input alias for canonical `trace_event_id`, and output emits only `trace_event_id`. `TraceEvent` and `TraceIdentityContext` do not currently use `deny_unknown_fields`; unknown fields are therefore characterized as accepted and dropped where serde permits. This slice does not harden that behavior. |
| Extension map | [`schema_extensions.rs`](../../crates/splendor-types/src/schema_extensions.rs) exposes `validate_extension_map` and `validate_extension_map_with_reserved_keys`. These functions validate only schemas that already admit extension metadata. |
| Extension value | The same source exposes `validate_extension_value` and `validate_extension_value_with_reserved_keys`, with stable `ExtensionValidationReason` and structured error fields. Harness bounds are not production extension guarantees. |
| `WorkOrder` | [`work_order.rs`](../../crates/splendor-types/src/work_order.rs) exposes public serde and `signing_payload_bytes()`. The two required work-order relation cases deserialize `WorkOrder`, use `signing_payload_bytes()` only as a public structural-shape check, inspect one source-fixed relation, and serialize through the capped harness sink. They never construct or validate `WorkOrderEnvelope`, sign, or call `validate_work_order`. |
| `CallerCredential` | [`daemon_security.rs`](../../crates/splendor-types/src/daemon_security.rs) exposes public serde for caller credential metadata. The required owner and audience cases deserialize `CallerCredential`, inspect only the source-fixed app-owner or daemon-audience relation, and serialize through the capped harness sink. They never call `validate_daemon_request`. |

Current unit tests are wired privately from the production modules through
`#[cfg(test)]` path modules under `crates/splendor-types/tests/unit/`. The new
file authorized here is instead a normal Cargo integration-test target and must
use only exports from the public `splendor_types` crate API. Cargo discovers
that target automatically; no `Cargo.toml` change is needed or allowed.

## Exact Implementation Files

Acceptance authorizes exactly these five new files and no others:

```text
conformance/0.2/c03-foundation/v1/README.md
conformance/0.2/c03-foundation/v1/manifest.json
conformance/0.2/c03-foundation/v1/positive/cases.json
conformance/0.2/c03-foundation/v1/negative/cases.json
crates/splendor-types/tests/c03_foundation_offline_slice_1.rs
```

The implementation must not add a Python validator. It must not change
production Rust, a Cargo manifest, `Cargo.lock`, daemon, Store, runtime, SDK,
CI, a public schema, a generated file, a migration, or an existing fixture.

The integration test must use `include_bytes!` with source-code-fixed literals
for all four new conformance files and for the existing RFC 0013 declaration
resource. Manifest paths are assertion data only; they never drive file access.
The existing resource is mapped in Rust source to its reviewed fixture path.
There is no dynamic file lookup and no fixture-controlled path.

All five new files and the existing RFC 0013 resource must be regular repository
files, not symlinks. Review must verify their Git modes before compile-time
embedding; the harness must not follow a fixture-selected symlink or resolve a
runtime path.

`README.md` documents the profile, commands, private status, and non-claims. The
test includes it, verifies non-empty UTF-8, and verifies the exact profile token,
but does not treat it as machine-readable fixture input.

## Private Fixture Contract

The manifest and case formats are private conformance input only. They are not:

- public JSON Schema;
- production serde records;
- public Rust types or enums;
- generated Python, TypeScript, OpenAPI, daemon, or SDK contracts;
- registered schema IDs;
- compatibility decisions or live dispositions; or
- stable external fixture APIs.

Every fixture struct in
`crates/splendor-types/tests/c03_foundation_offline_slice_1.rs` is private and
annotated `#[serde(deny_unknown_fields)]`. Every nested object uses another
closed private struct. Tagged-union bodies are also closed private structs. A
plain `serde_json::Value` is not used for manifest or case metadata.

Optional observation members mean omitted or present with the exact declared
type. `null` is never equivalent to omission. The private deserializer must use
a non-null optional helper or an equivalent duplicate-aware visitor so a present
`null` rejects. Known duplicate fields reject through typed deserialization;
unknown fields reject through `deny_unknown_fields`.

Internal format IDs, profile names, operation names, subject names, status
labels, and `matched` are test-local spellings fixed by this RFC. Their presence
does not register a public schema, enum, compatibility class, disposition,
error, or generated contract.

## Exact Manifest

The manifest root is a non-empty closed object. It contains exactly the fields
below. Field order is not semantic, but arrays use the stated order.

| Field | Type | Exact value or rule |
| --- | --- | --- |
| `format_id` | string | `splendor.internal.conformance.rfc0021.offline-slice-1-manifest.v1` |
| `profile` | string | `rfc0021_c03_foundation_offline_slice_1` |
| `fixture_contract_revision` | integer | `1` |
| `accepted_proposal_sha256` | closed object | Exact object defined below. |
| `active_execution_line` | string | `0.2/v2` |
| `program` | string | `V2-FND-0 Foundations` |
| `component` | string | `C03` |
| `task_id` | string | `FND-006` |
| `issue_number` | integer | `225` |
| `owner_package` | string | `crates/splendor-types` |
| `dependencies` | string array | Exactly `FND-001`, `FND-002`, in that order. |
| `primary_functional_requirements` | string array | Exactly `FR-0.2-01`, `FR-0.2-08`, in that order. |
| `preserved_requirements` | string array | Exactly `FR-0.2-02`, `stable_0.1`, in that order. |
| `foundation_readiness_status` | string | `foundation_ready`, preserving the current checkpoint without implying task completion. |
| `task_status` | string | `partial_slice_1_not_completed` |
| `slice_status` | string | `offline_characterization_only` |
| `case_id_pattern` | string | `^[a-z0-9][a-z0-9._-]*$` |
| `limits` | closed object | Exact numeric object in Bounds. |
| `case_files` | closed object array | Exact two entries below, in positive then negative order. |
| `builtin_resource_id` | string | `rfc0013_driver_operation_credential_sinks_v1` |
| `production_surfaces` | closed object array | Exact inventory below, in table order. |
| `live_disposition_status` | string | `not_exercised` |
| `compatibility_classification_status` | string | `not_exercised` |
| `required_live_relation_case_ids` | string array | Exact four parse-only RFC 0020 case IDs below, in stated order. |
| `gold_statuses` | closed object array | Exact two entries below, in `G00`, `G72` order. |
| `non_claims` | string array | Exact ordered list below. |

### Accepted proposal hashes

`accepted_proposal_sha256` has exactly three string fields:

| Field | Exact value |
| --- | --- |
| `rfc_0018` | `427028b9fff0fe7d2337095bdb9093fd0966ea0cb4e1e68c8b1ae89a3cf5ae69` |
| `rfc_0020` | `a1e94f7df3e2778bf9e1e3724a54398e1141831ef54045ad8d969a93f5c9b561` |
| `rfc_0021` | The exact 64-character lowercase hexadecimal accepted proposal SHA-256 recorded in this RFC's Status and Binding section after acceptance. The field and accepted value are mandatory in implementation fixtures; no placeholder is legal. |

The loader hard-codes all three accepted values. It does not read arbitrary RFC
paths or compute acceptance status from fixture metadata.

### Case files

`case_files` is exactly:

```json
[
  {
    "file_id": "positive_cases",
    "polarity": "positive",
    "path": "conformance/0.2/c03-foundation/v1/positive/cases.json"
  },
  {
    "file_id": "negative_cases",
    "polarity": "negative",
    "path": "conformance/0.2/c03-foundation/v1/negative/cases.json"
  }
]
```

Each entry is a closed object. Those are the only accepted file IDs and paths.
They are compared for exact equality and are never opened. No other resource or
path member exists.

### Required live-relation case IDs

`required_live_relation_case_ids` is exactly:

```json
[
  "live_relation.stale_work_order",
  "live_relation.wrong_owner_caller_credential",
  "live_relation.wrong_tenant_work_order",
  "live_relation.wrong_audience_caller_credential"
]
```

The loader hard-codes this exact array and order. Each ID must occur exactly once
in `negative/cases.json` with the source-fixed subject, operation, input kind,
relation, and expected presence rules below. These are parse-only required RFC
0020 inputs, not owner-integrated outcomes. They do not claim that the
corresponding production behavior is compatible, authorized, current, live,
accepted by an owner, or passed.

### Gold statuses and non-claims

`gold_statuses` is exactly:

```json
[
  {
    "gold_id": "G00",
    "source_status": "specified_not_implemented",
    "evidence_status": "not_exercised"
  },
  {
    "gold_id": "G72",
    "source_status": "specified_not_implemented",
    "evidence_status": "not_exercised"
  }
]
```

`non_claims` is exactly this ordered list:

```json
[
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
  "no_gold_task_conformance_release_or_production_claim"
]
```

### Production surface inventory

Every `production_surfaces` element is a closed object with exactly `subject`,
`rust_surface`, and `entry_points`. `entry_points` is an ordered non-empty string
array. The manifest array must equal these rows exactly.

| `subject` | `rust_surface` | Exact `entry_points`, in order |
| --- | --- | --- |
| `canonical_schema_id_v1` | `splendor_types::CanonicalSchemaIdV1` | `splendor_types::CanonicalSchemaIdV1::parse`; `splendor_types::CanonicalSchemaIdV1::try_new`; `<splendor_types::CanonicalSchemaIdV1 as std::str::FromStr>::from_str`; `splendor_types::CanonicalSchemaIdV1::as_str`; `serde_json::to_writer` |
| `canonical_label_v1` | `splendor_types::CanonicalLabelV1` | `splendor_types::CanonicalLabelV1::parse`; `splendor_types::CanonicalLabelV1::try_new`; `<splendor_types::CanonicalLabelV1 as std::str::FromStr>::from_str`; `splendor_types::CanonicalLabelV1::as_str`; `serde_json::to_writer` |
| `foundation_grammar_code_v1` | `splendor_types::FoundationGrammarCodeV1` | `splendor_types::FoundationGrammarCodeV1::parse`; `splendor_types::FoundationGrammarCodeV1::try_new`; `<splendor_types::FoundationGrammarCodeV1 as std::str::FromStr>::from_str`; `splendor_types::FoundationGrammarCodeV1::as_str`; `serde_json::to_writer` |
| `canonical_timestamp_v1` | `splendor_types::CanonicalTimestampV1` | `splendor_types::CanonicalTimestampV1::parse`; `splendor_types::CanonicalTimestampV1::try_new`; `<splendor_types::CanonicalTimestampV1 as std::str::FromStr>::from_str`; `splendor_types::CanonicalTimestampV1::as_str`; `serde_json::to_writer` |
| `canonical_count_v1` | `splendor_types::CanonicalCountV1` | `splendor_types::CanonicalCountV1::parse`; `splendor_types::CanonicalCountV1::try_new`; `<splendor_types::CanonicalCountV1 as std::str::FromStr>::from_str`; `splendor_types::CanonicalCountV1::get`; `serde_json::to_writer` |
| `canonical_ordinal_v1` | `splendor_types::CanonicalOrdinalV1` | `splendor_types::CanonicalOrdinalV1::parse`; `splendor_types::CanonicalOrdinalV1::try_new`; `<splendor_types::CanonicalOrdinalV1 as std::str::FromStr>::from_str`; `splendor_types::CanonicalOrdinalV1::get`; `serde_json::to_writer` |
| `canonical_sequence_v1` | `splendor_types::CanonicalSequenceV1` | `splendor_types::CanonicalSequenceV1::parse`; `splendor_types::CanonicalSequenceV1::try_new`; `<splendor_types::CanonicalSequenceV1 as std::str::FromStr>::from_str`; `splendor_types::CanonicalSequenceV1::get`; `serde_json::to_writer` |
| `canonical_positive_revision_v1` | `splendor_types::CanonicalPositiveRevisionV1` | `splendor_types::CanonicalPositiveRevisionV1::parse`; `splendor_types::CanonicalPositiveRevisionV1::try_new`; `<splendor_types::CanonicalPositiveRevisionV1 as std::str::FromStr>::from_str`; `splendor_types::CanonicalPositiveRevisionV1::get`; `serde_json::to_writer` |
| `foundation_grammar_error` | `splendor_types::FoundationGrammarError` | `splendor_types::FoundationGrammarError::as_str`; `std::fmt::Display::fmt`; `std::fmt::Debug::fmt`; `std::error::Error::source` |
| `registry_declaration_digest` | `splendor_types::RegistryDeclarationDigest` | `splendor_types::DriverOperationCredentialSinksV1::from_json_slice`; `splendor_types::DriverOperationCredentialSinksV1::driver_declaration_revision`; `<splendor_types::RegistryDeclarationDigest as std::convert::TryFrom<&splendor_types::DriverOperationCredentialSinksV1>>::try_from`; `splendor_types::RegistryDeclarationDigest::parse`; `<splendor_types::RegistryDeclarationDigest as std::str::FromStr>::from_str`; `std::fmt::Debug::fmt`; `serde_json::to_writer` |
| `trace_event` | `splendor_types::TraceEvent` | `serde_json::from_str::<splendor_types::TraceEvent>`; `serde_json::to_writer` |
| `schema_extension_map` | `std::collections::BTreeMap<String, serde_json::Value>` | `splendor_types::validate_extension_map`; `splendor_types::validate_extension_map_with_reserved_keys` |
| `schema_extension_value` | `serde_json::Value` | `splendor_types::validate_extension_value`; `splendor_types::validate_extension_value_with_reserved_keys` |
| `work_order` | `splendor_types::WorkOrder` | `serde_json::from_str::<splendor_types::WorkOrder>`; `splendor_types::WorkOrder::signing_payload_bytes`; `serde_json::to_writer` |
| `caller_credential` | `splendor_types::CallerCredential` | `serde_json::from_str::<splendor_types::CallerCredential>`; `serde_json::to_writer` |

The manifest cannot add, remove, rename, or reorder a surface or entry point.
Changing this inventory requires a later reviewed amendment.

## Exact Case Files

Each case file root is a closed private object with exactly these fields:

| Field | Type | Exact rule |
| --- | --- | --- |
| `format_id` | string | `splendor.internal.conformance.rfc0021.offline-slice-1-cases.v1` |
| `profile` | string | `rfc0021_c03_foundation_offline_slice_1` |
| `polarity` | enum string | `positive` or `negative`; must equal the fixed manifest entry and source file. |
| `case_count` | integer | `1..=256` and exactly equal to `cases.len()`. |
| `cases` | case array | `1..=256`, strictly ascending by `case_id`, with no duplicate in this file or the other file. |

The source file fixes polarity. Every case in `positive/cases.json` must have
`execution_result: "accepted"`. A case in `negative/cases.json` must be either
rejected, the exact accepted `wrong_domain_compare` case with
`digest_equality: false`, or one of the exact four accepted
`parse_live_relation` cases with both status fields `not_exercised` and its
source-hard-coded relation true. No other accepted negative case is legal. No
case file contains an actual result, report, completion marker, compatibility
class, live disposition value, output policy, or Gold assertion.

## Exact Case Record

Every case is a closed object with exactly these fields:

| Field | Type | Exact rule |
| --- | --- | --- |
| `case_id` | string | `1..=64` ASCII bytes matching `^[a-z0-9][a-z0-9._-]*$`. Unique across both files. |
| `subject` | closed enum | One exact subject below. |
| `operation` | closed enum | One exact operation below and a legal subject/input combination. |
| `input` | tagged union | One exact closed input variant below. |
| `expected` | closed object | One exact expected observation below. |
| `live_disposition_status` | string | Exactly `not_exercised`. |
| `schema_registration_status` | string | Exactly `not_exercised`. |

The `subject` enum is exactly:

```text
canonical_schema_id_v1
canonical_label_v1
foundation_grammar_code_v1
canonical_timestamp_v1
canonical_count_v1
canonical_ordinal_v1
canonical_sequence_v1
canonical_positive_revision_v1
foundation_grammar_error
registry_declaration_digest
trace_event
schema_extension_map
schema_extension_value
work_order
caller_credential
```

The `operation` enum is exactly:

```text
parse
construct
from_str
serialize
parse_reject
construct_reject
from_str_reject
inspect_error
declaration_digest
wrong_domain_compare
trace_deserialize_serialize
trace_reject
validate_extension_map
validate_extension_map_with_reserved_keys
validate_extension_value
validate_extension_value_with_reserved_keys
parse_live_relation
```

Neither enum is public. A case has no field for compatibility class,
disposition, canonicality policy, support, registration, currentness,
authorization, conformance, pass status, or Gold status.

## Exact Input Tagged Union

`input` is an adjacently tagged closed object with exactly `kind` and `body`.
The outer object and every body struct use `deny_unknown_fields`. The variants
are:

| `kind` | Exact closed `body` | Rule |
| --- | --- | --- |
| `text` | `{ "value": string }` | Exact unnormalized UTF-8 input, at most 8,192 bytes. Used for lexical parsing, `FromStr`, serializer setup, and lexical rejection. |
| `u64` | `{ "value": integer }` | A JSON integer representable as Rust `u64`. Used only for checked integer construction and integer `serialize` setup through `try_new`. Alternate JSON token spellings are carried by `text`, never coerced through this variant. |
| `error_code` | `{ "value": error-code-enum }` | One of the exact nine `FoundationGrammarError::as_str` spellings. Rust maps it to the corresponding hard-coded variant. |
| `declaration` | `{ "resource_id": declaration-resource-enum, "mutation": declaration-mutation-enum, "digest_domain": declaration-domain-enum }` | Uses only the built-in declaration resource and closed transformations below. No path or arbitrary bytes are accepted. |
| `trace_json` | `{ "json": string }` | Exact inline production JSON, at most 32,768 bytes. It remains a string until passed unchanged to the production `TraceEvent` serde path. |
| `extension_json` | `{ "json": string, "root_path": string, "additional_reserved_keys": string array }` | Exact inline production JSON, at most 32,768 bytes; root path `1..=256` ASCII bytes matching `^[a-z][a-z0-9._-]*$`; at most 16 additional keys, each at most 256 UTF-8 bytes. |
| `work_order_json` | `{ "json": string }` | Exact inline public `WorkOrder` JSON, at most 32,768 bytes. Used only by the two exact work-order `parse_live_relation` cases and passed unchanged to production serde after streaming preflight. |
| `caller_credential_json` | `{ "json": string }` | Exact inline public `CallerCredential` JSON, at most 32,768 bytes. Used only by the exact wrong-owner and wrong-audience `parse_live_relation` cases and passed unchanged to production serde after streaming preflight. |

The `error_code` enum is exactly:

```text
invalid_contract_shape
invalid_contract_version
invalid_contract_identity
invalid_contract_timestamp
invalid_contract_integer
invalid_contract_digest
invalid_contract_signature
invalid_contract_bound
invalid_contract_binding
```

The declaration enums are exactly:

```text
resource_id:
  rfc0013_driver_operation_credential_sinks_v1

mutation:
  none
  driver_declaration_revision_1_to_2

digest_domain:
  production
  wrong_domain_v2
```

Only these declaration combinations are legal:

| Operation | Mutation | Digest domain |
| --- | --- | --- |
| `declaration_digest` | `none` | `production` |
| `declaration_digest` | `driver_declaration_revision_1_to_2` | `production` |
| `wrong_domain_compare` | `none` | `wrong_domain_v2` |

The one-byte mutation locates the exact byte sequence
`"driver_declaration_revision":1` in the built-in resource, requires exactly
one occurrence, changes only the final `1` to `2`, and verifies a one-byte diff
before calling the production declaration parser. The wrong domain is exactly
`splendor.driver.operation_credential_sinks.v2`, followed by `0x00` and the
unchanged production-serialized declaration bytes. It is an adversarial test
vector, not a registered domain.

### Source-fixed live-relation cases

The operation `parse_live_relation` is legal only for the exact four case IDs in
`required_live_relation_case_ids`. Rust source, not fixture context, maps each ID
to its subject, input kind, and one relation. The fixed synthetic constants are:

```text
relation_now = 2030-01-02T00:00:00Z
expected_tenant_id = 00000000-0000-4000-8000-000000000001
expected_app_principal_id = app_expected
expected_daemon_id = daemon_expected
```

The exact source-fixed mapping is:

| Case ID | Subject and production parse | Required source-fixed relation |
| --- | --- | --- |
| `live_relation.stale_work_order` | `work_order` / `serde_json::from_str::<WorkOrder>` | Parsed `expires_at <= relation_now`. |
| `live_relation.wrong_owner_caller_credential` | `caller_credential` / `serde_json::from_str::<CallerCredential>` | Parsed `principal.app.app_principal_id != expected_app_principal_id`. `AppPrincipal` is the documented application identity that owns the client credential; this comparison remains parse-only and does not perform authentication or owner lookup. |
| `live_relation.wrong_tenant_work_order` | `work_order` / `serde_json::from_str::<WorkOrder>` | Parsed `tenant_id != expected_tenant_id`. |
| `live_relation.wrong_audience_caller_credential` | `caller_credential` / `serde_json::from_str::<CallerCredential>` | Parsed audience is `CredentialAudience::Daemon` and its `daemon_id != expected_daemon_id`. |

All four records must otherwise remain structurally valid, synthetic, and free
of real identifiers, secrets, tokens, and signatures. For each work-order case,
Rust calls `signing_payload_bytes()` only as the public shape check, discards its
bytes without signing, and then performs capped observed production
serialization. It must not construct or use `WorkOrderEnvelope`, generate a
signature, call `validate_work_order`, or validate authorization. The caller-
credential case performs capped observed production serialization and must not
call `validate_daemon_request`. No fixture field can select, rename, or alter a
relation or expected constant.

These parse-only checks execute successfully when parse, structural shape where
applicable, relation, and capped serialization all match. They do not execute or
infer owner validation, a compatibility class, or a live disposition. Every
one has `live_disposition_status: "not_exercised"` and
`schema_registration_status: "not_exercised"`.

## Exact Expected Observation

`expected` is a closed object with exactly one required result and five optional
observations:

| Field | Type | Presence rule |
| --- | --- | --- |
| `execution_result` | enum string | Required; exactly `accepted` or `rejected`. |
| `stable_error_code` | error-code-enum | Optional, never null. Present only where the matrix requires a public stable `FoundationGrammarError` code. |
| `serialized_utf8` | string | Optional, never null. Exact UTF-8 emitted by capped `serde_json::to_writer` production serialization. A digest scalar is therefore represented here as a JSON-quoted string, not as a bare wire. At most 65,536 bytes. |
| `expected_digest_wire` | string | Optional, never null. Its string content is the bare, not JSON-serialized/quoted, lowercase `blake3:` wire; at most 71 bytes and accepted by the strict production digest parser. Required only for `declaration_digest` and `wrong_domain_compare`. |
| `digest_equality` | boolean | Optional, never null. Required only for `declaration_digest` and `wrong_domain_compare`, with the exact value fixed by the matrix. |
| `extension_error` | closed object | Optional, never null. Required for rejected extension validation; forbidden otherwise. |

The exact operation/result/presence matrix is:

| Subject and operation | `execution_result` | `stable_error_code` | `serialized_utf8` | `expected_digest_wire` | `digest_equality` | `extension_error` |
| --- | --- | --- | --- | --- | --- | --- |
| Foundation scalar `parse`, `construct`, `from_str`, or `serialize` | `accepted` | absent | required | absent | absent | absent |
| Foundation scalar `parse_reject`, `construct_reject`, or `from_str_reject` | `rejected` | required | absent | absent | absent | absent |
| `foundation_grammar_error` / `inspect_error` | `accepted` | required | absent | absent | absent | absent |
| Registry digest wire `parse`, `from_str`, or `serialize` | `accepted` | absent | required | absent | absent | absent |
| Registry digest wire `parse_reject` or `from_str_reject` | `rejected` | required | absent | absent | absent | absent |
| `declaration_digest` | `accepted` | absent | required | required | exactly `true` | absent |
| `wrong_domain_compare` | `accepted` | absent | required | required | exactly `false` | absent |
| `trace_deserialize_serialize` | `accepted` | absent | required | absent | absent | absent |
| `trace_reject` | `rejected` | absent | absent | absent | absent | absent |
| Any extension validator, accepted result | `accepted` | absent | absent | absent | absent | absent |
| Any extension validator, rejected result | `rejected` | absent | absent | absent | absent | required |
| Exact four `parse_live_relation` cases | `accepted` | absent | required | absent | absent | absent |

No other combination is valid. Foundation rejections compare a stable error code
only where the invoked public API exposes `FoundationGrammarError`. Serde
rejections have no expected error text or code. For `declaration_digest` and
`wrong_domain_compare`, `serialized_utf8` is the capped JSON serialization of the
digest value; declaration-byte equality is a separate source-fixed execution
assertion.

`extension_error`, when present, has exactly:

| Field | Type | Rule |
| --- | --- | --- |
| `reason` | enum string | `blank_extension_key`, `trimmed_extension_key`, or `reserved_authority_key`. |
| `path` | string | Exact production path, at most 256 UTF-8 bytes. |
| `key` | string | Exact production key, at most 256 UTF-8 bytes. |
| `normalized_key` | string | Exact production normalized key, at most 256 UTF-8 bytes. |

For `declaration_digest`, the harness computes the digest with production
`TryFrom<&DriverOperationCredentialSinksV1>`, serializes it through the capped
sink, independently parses the fixture's fixed `expected_digest_wire` through
the production digest parser, and requires equality to be true. For
`wrong_domain_compare`, the harness computes the exact source-fixed wrong-domain
vector, requires its bare wire to equal the independently fixed
`expected_digest_wire`, parses that wire through the production digest parser,
serializes it through the capped sink, and requires inequality with the
production `TryFrom` digest. A merely different arbitrary digest cannot satisfy
the wrong-domain case.

The harness compares only these stable observations. It discards unstable serde
error text. Rejected input may exist temporarily in bounded memory while parsing
but is not persisted or emitted. It must never format or print
`ExtensionValidationError`, its path, key, normalized key, any serde error text,
or rejected input. Structured extension fields are compared internally.
Mismatch diagnostics contain only bounded case ID, subject, operation, a stable
reason category, and per-field match booleans or byte lengths; they never contain
field values. Dedicated diagnostic canary tests use sentinel-sensitive values
and require every failure rendering path to omit them.

## Bounds

The manifest `limits` object is closed and exactly:

```json
{
  "readme_max_bytes": 65536,
  "manifest_max_bytes": 65536,
  "case_file_max_bytes": 262144,
  "builtin_resource_max_bytes": 65536,
  "cases_per_file_min": 1,
  "cases_per_file_max": 256,
  "cases_total_max": 512,
  "case_id_max_ascii_bytes": 64,
  "inline_text_max_bytes": 8192,
  "inline_json_max_bytes": 32768,
  "serialized_output_max_bytes": 65536,
  "json_max_depth": 16,
  "json_object_members_max": 256,
  "json_array_elements_max": 256,
  "additional_reserved_keys_max": 16,
  "metadata_string_max_bytes": 256
}
```

The Rust loader hard-codes these limits and then verifies that the manifest
contains the same values. A fixture cannot increase its own limits.

Raw README, manifest, and case-file bytes are bounded before UTF-8, token, or
JSON parsing. The README bound is enforced before its UTF-8 and exact-profile-
token checks. The built-in RFC 0013 resource is bounded before the production
declaration parser. Fixture JSON and every inline JSON kind have maximum nesting
depth 16, counting the root as depth one; each object has at most 256 member
occurrences and each array has at most 256 elements. Duplicate members count
toward the limit on every occurrence. No preflight may parse through
`serde_json::Value` or another representation that collapses duplicate keys.

All metadata strings are at most 256 UTF-8 bytes except these exact fields:

- `input.body.value` for `text`, at most 8,192 bytes;
- `input.body.json` for `trace_json`, `extension_json`, `work_order_json`, and
  `caller_credential_json`, at most 32,768 bytes;
  and
- `expected.serialized_utf8`, at most 65,536 bytes.

Every harness output serialization uses `serde_json::to_writer` with a private
capped `std::io::Write` sink whose backing allocation cannot exceed 65,536
bytes. The sink aborts on the byte that would make the output 65,537 bytes and
does not log or expose partial output. Thus the actual allocation and write are
bounded, not merely checked after materialization. Production internals invoked
by public `TryFrom` or shape-check APIs may use their own production
serialization; the harness must not replace those internals. The two case files
contain no more than 512 cases in total. Over-bound test vectors are constructed
as hard-coded Rust test data, including deterministic repeated-byte vectors;
they are never loaded from an external reference.

These are fixture-safety ceilings. They do not change or advertise production
grammar, Trace, declaration, or extension limits.

## Loader and Security Laws

The private loader must enforce all of the following before dispatch:

1. Bound raw bytes before parse and require valid UTF-8; apply the README bound
   before its UTF-8 and token checks.
2. Run a private fixture-envelope/metadata streaming preflight for depth,
   per-object member occurrences, per-array elements, and decoded string
   lengths. This preflight is not a production grammar implementation and does
   not materialize through `Value`.
3. Deserialize each manifest and case file through closed typed visitors,
   deserialize exactly one JSON value, and call the deserializer end check so
   non-whitespace trailing tokens reject.
4. Reject duplicate typed fixture fields at every level, unknown fields, missing
   fields, present null optionals, wrong types, and unknown enum values.
5. Require the exact manifest constants, accepted hashes, task/program/owner
   values, status values, limits, file list, resource ID, surface inventory,
   Gold statuses, `required_live_relation_case_ids`, and non-claims.
6. Require each file's polarity to equal its fixed source file, `case_count` to
   equal array length, and every count bound to hold. Enforce the exact positive
   and negative outcome laws before production dispatch.
7. Require each case array to be strictly ascending by `case_id`; reject an ID
   duplicate within one file or across both files. Require each source-fixed
   live-relation case ID exactly once in the negative file.
8. Reject illegal subject/operation/input combinations before any production
   call. A fixture cannot select the production entry point or relation through
   a label alone; source dispatch is authoritative.
9. Enforce the exact expected-field presence matrix and reject null in place of
   omission.
10. Reject any fixture-controlled URL, absolute path, path separator, parent
    component, environment expansion, dynamic import, symlink target, arbitrary
    resource, or unrecognized file/resource ID. The fixed repo-relative manifest
    case paths are exact allowlisted assertion strings and are never resolved.
11. Reject fixture-envelope metadata fields or values outside the opaque inline
    production JSON strings that claim registered, supported, current,
    compatible, authorized, passed, conformant, completed, Gold-passed, or a live
    disposition. The exact non-claiming status fields above are the only status
    metadata.
12. Keep inline production JSON as a bounded string until its dedicated
    streaming preflight completes and it is handed unchanged to the named
    production parser. Fixture fields cannot merge into, default, normalize, or
    escape into that JSON.
13. For inline Trace JSON, count every token/member occurrence but permit
    duplicate object keys in preflight so duplicate-field cases reach production
    `TraceEvent` serde unchanged.
14. For inline extension JSON, reject duplicate object keys in streaming
    preflight before conversion to `BTreeMap` or `Value`; this prevents
    last-key-wins behavior and duplicate undercounting.
15. For inline WorkOrder and CallerCredential JSON, count every occurrence in a
    bounded streaming preflight and pass the exact string unchanged to production
    serde. Known duplicate-field semantics remain those of production serde; the
    four required relation fixtures themselves contain no duplicate keys.

The integration-test crate begins with `#![forbid(unsafe_code)]`. It performs no
network access, process spawn, environment read, dynamic file I/O, dynamic
import, or symlink following. Compile-time `include_bytes!` inputs are the
complete data set. Source-fixed dispatch has no handles or imports for a daemon,
Store, runtime, Gateway, adapter, owner service, migration, protocol, SDK,
network, process, environment, or dynamic filesystem service. Non-effects are
harness-level scope guarantees by construction, exact diff review, diagnostic
canary tests, and retained review evidence; they are not fixture-selected or
per-case observed fields, and no counter is claimed to observe arbitrary
external effects.

## Legal Dispatch Matrix

The loader accepts only these subject, operation, and input combinations:

| Subject | Operations | Input |
| --- | --- | --- |
| `canonical_schema_id_v1`, `canonical_label_v1`, `foundation_grammar_code_v1`, `canonical_timestamp_v1` | `parse`, `construct`, `from_str`, `serialize`, `parse_reject`, `construct_reject`, `from_str_reject` | `text` |
| `canonical_count_v1`, `canonical_ordinal_v1`, `canonical_sequence_v1`, `canonical_positive_revision_v1` | `parse`, `from_str`, `parse_reject`, `from_str_reject` | `text` |
| The four integer subjects | `construct`, `serialize`, `construct_reject` | `u64` |
| `foundation_grammar_error` | `inspect_error` | `error_code` |
| `registry_declaration_digest` | `parse`, `from_str`, `serialize`, `parse_reject`, `from_str_reject` | `text` |
| `registry_declaration_digest` | `declaration_digest`, `wrong_domain_compare` | `declaration` with the exact combination table above |
| `trace_event` | `trace_deserialize_serialize`, `trace_reject` | `trace_json` |
| `schema_extension_map` | `validate_extension_map`, `validate_extension_map_with_reserved_keys` | `extension_json`; inline root must be an object |
| `schema_extension_value` | `validate_extension_value`, `validate_extension_value_with_reserved_keys` | `extension_json` |
| `work_order` | `parse_live_relation` | `work_order_json`; only the exact stale and wrong-tenant source-fixed case IDs |
| `caller_credential` | `parse_live_relation` | `caller_credential_json`; only the exact wrong-owner and wrong-audience source-fixed case IDs |

The operations without `_with_reserved_keys` require an empty
`additional_reserved_keys` array. The two operations with that suffix require a
non-empty array. Any other pairing rejects as fixture-invalid and never calls a
production API.

Operation labels are authoritative. The executor first invokes the named primary
public route: `parse`/`parse_reject` call `parse`,
`construct`/`construct_reject` call `try_new`, and
`from_str`/`from_str_reject` call `FromStr`. `serialize` uses exactly `parse` as
setup for string-backed scalar and digest text, and exactly `try_new` as setup
for integer `u64`, before capped `serde_json::to_writer`.

Every other operation first invokes the exact production route named by its
legal-dispatch and execution-law row: error inspection uses the mapped public
variant surfaces, declaration operations begin with the production declaration
parser, Trace operations begin with production Trace serde, extension operations
begin with the selected public validator after preflight/conversion, and
`parse_live_relation` begins with the source-fixed public serde parser. No
secondary assertion can substitute for that primary call.

After an accepted primary call, the executor invokes every equivalent public
route that exists and requires value/accessor/serialization agreement:

- foundation string-backed values run `parse`, `try_new(String)`, and `FromStr`;
- integer text values run `parse`, `FromStr`, and `try_new(parsed.get())`;
- integer `u64` values run `try_new`, then `parse` and `FromStr` over the exact
  decimal token;
- registry digest text runs `parse` and `FromStr`; and
- all resulting values compare equal, expose the expected `as_str()` or `get()`,
  and serialize identically through separate capped sinks.

After a rejected primary call, the executor may cross-check equivalent public
routes. Rejected string-backed scalar inputs must include `try_new` as well as
`parse` and `FromStr` agreement where those routes exist. Digest rejection
cross-checks `parse` and `FromStr`. Integer `u64` construction rejection calls
`try_new` as its primary route. Every compared stable code must agree. Operation
coverage is proven by actual calls, never by fixture labels alone.

## Authoritative Production Execution

Rust production execution is authoritative. Fixture declarations never
substitute for a production call.

| Subject | Exact execution law |
| --- | --- |
| Foundation strings and timestamp | Call the public type's `parse`, `try_new`, `FromStr`, `as_str`, and capped `serde_json::to_writer` exactly as required by the primary-operation and agreement rules. Do not copy regex, date, width, or normalization logic into the harness. |
| Foundation integers | Preserve lexical tokens as strings for `parse`/`FromStr`; use `u64` only for `try_new`; compare public values, assert `get`, and run capped `serde_json::to_writer`. Do not parse through float or generic fixture JSON numbers. |
| Foundation errors | Map the closed input enum to all nine actual variants, including variants not emitted by current constructors. Assert `as_str`, `Display`, `Debug`, and absent source; no candidate data is persisted or emitted. |
| Registry digest wire | Call `RegistryDeclarationDigest::parse` and `FromStr`; serialize accepted values through the capped sink and require exact `Debug` output `RegistryDeclarationDigest(<redacted>)` without placing the digest wire in diagnostics. Rejection compares only `FoundationGrammarError`, not candidate text. |
| Declaration digest | Select the source-code-fixed built-in bytes, apply only the exact closed mutation, call `DriverOperationCredentialSinksV1::from_json_slice`, assert `driver_declaration_revision()`, serialize through the capped sink, require serialization to equal the selected declaration bytes, then execute the exact independent expected-wire, `TryFrom`, serialization, Debug-redaction, and equality laws above. |
| Wrong-domain digest | Parse the production declaration, assert its revision accessor, serialize it through the capped sink, compute the exact hard-coded adversarial v2-domain BLAKE3 vector, prove that wire equals the independently fixed expected wire, parse the wire through `RegistryDeclarationDigest::parse`, compute the production declaration digest through `TryFrom`, assert Debug redaction, and require equality to be false. Lexical parsing does not register the wrong domain. |
| `TraceEvent` | Run the duplicate-permitting streaming preflight, then pass the exact bounded inline string to `serde_json::from_str::<TraceEvent>`. On success call capped `serde_json::to_writer`. On rejection assert rejection only and discard serde text. Do not implement the alias or event grammar in the harness. |
| Extension map | Reject duplicate keys in streaming preflight before parsing the exact bounded inline string into `BTreeMap<String, serde_json::Value>`, then call the selected public map validator. Compare public structured error fields internally without formatting their values. |
| Extension value | Reject duplicate keys in streaming preflight before parsing the exact bounded inline string into `serde_json::Value`, then call the selected public value validator. Compare public structured error fields internally without formatting their values. |
| `WorkOrder` live relation | Run bounded streaming preflight, pass the unchanged string to `serde_json::from_str::<WorkOrder>`, call `signing_payload_bytes()` only for structural shape, check the one source-fixed relation, and run capped observed production serialization. Do not sign, authorize, construct an envelope, or call `validate_work_order`. |
| `CallerCredential` live relation | Run bounded streaming preflight, pass the unchanged string to `serde_json::from_str::<CallerCredential>`, check only the source-fixed app-owner or wrong-daemon relation selected by the exact case ID, and run capped observed production serialization. Do not authenticate the credential, perform owner lookup, or call `validate_daemon_request`. |

The fixture preflight protects the private loader. It is not used to predict or
replace production acceptance. In particular, extension depth/member limits are
harness safety limits, not claims about the public validators.

## Pinned and Observed Output Policy

Fixture metadata cannot choose `explicitly_pinned` or `observed_production` and
contains neither string. The integration test hard-codes the policy from subject
and observation:

- accepted RFC 0018 Slice 1A scalar and `RegistryDeclarationDigest` output is
  `explicitly_pinned` by its governing contract;
- the exact RFC 0013 declaration bytes are checked only as the accepted input to
  the RFC 0018 declaration-digest construction, not elevated into a new fixture
  classification;
- the exact stable alias field spelling `trace_event_id`, and absence of emitted
  `trace_id`, is explicitly pinned where the stable governing contract says so;
- the complete `TraceEvent` serializer output is `observed_production`, even in
  alias cases; and
- the complete `WorkOrder` and `CallerCredential` serializer outputs are
  `observed_production`; parse-only relation fixtures cannot elevate them to
  canonical compatibility, owner, authorization, or live-disposition output;
  and
- any later stable 0.1 serializer added by an amendment is
  `observed_production` unless its governing contract explicitly pins the exact
  complete bytes.

For `TraceEvent`, the test therefore performs two assertions: exact full output
against the observed fixture string, and a separate hard-coded object-key check
that output contains `trace_event_id` and does not contain `trace_id`. Fixture
data cannot elevate the full output to a canonical ABI.

## Required High-Value Case Inventory

The two case files must cover this bounded inventory without copying every
existing unit-test permutation.

### Foundation schema, label, and code

- `CanonicalSchemaIdV1`: valid minimum, valid maximum, representative valid
  registered-looking value, and lexically valid but unregistered value; invalid
  key/start, missing or invalid version, and over-bound cases. The
  lexical-but-unregistered case is accepted by the parser while
  `schema_registration_status` remains `not_exercised`.
- `CanonicalLabelV1` and `FoundationGrammarCodeV1`: representative accepted
  values, maximum value, selected invalid ASCII/Unicode/start cases, and
  over-bound cases. Include a same-spelling case that proves the two nominal
  values are exercised separately without claiming interchangeability.

### Timestamp and integers

- `CanonicalTimestampV1`: minimum, leap-day, and maximum timestamps; selected
  invalid calendar, leap-second, UTC-offset, lowercase-`z`, missing precision,
  short precision, long precision, and whitespace cases.
- Count, ordinal, and sequence: minimum `0`, maximum
  `9007199254740991`, one nominal middle value, alternate token spellings, and
  maximum-plus-one.
- Positive revision: minimum `1`, maximum `9007199254740991`, alternate token
  spellings, maximum-plus-one, and revision zero.
- At least one accepted case for every scalar subject uses each applicable primary
  label `parse`, `construct`, `from_str`, and `serialize`. Integer `serialize`
  uses `u64` and `try_new`; text-backed `serialize` uses `text` and `parse`.
- Every scalar subject has a rejected case for each applicable authoritative
  primary operation `parse_reject`, `construct_reject`, and
  `from_str_reject`. String-backed constructor rejection exercises `try_new`;
  integer construction rejection uses `u64` and `try_new`. Agreement checks run
  only after the named primary route has actually been called.

### Error and declaration digest

- `inspect_error` covers all nine `FoundationGrammarError` surfaces, including
  variants no current Slice 1A constructor emits.
- Digest wire covers the accepted golden wire with `parse`, `from_str`, and
  `serialize` primary coverage plus selected prefix, width, uppercase,
  algorithm, and whitespace rejection with both `parse_reject` and
  `from_str_reject` primary coverage.
- Declaration digest covers the unchanged RFC 0013 fixture golden, the exact
  one-byte revision mutation with its independently fixed changed digest, and
  the wrong-domain lexical parse whose independently fixed wrong-domain wire is
  proven and whose equality with the production digest is `false`.

### Stable Trace alias behavior

Use fixed synthetic UUIDs, timestamps, sequence values, identity, and a small
stable event kind. Cover all of:

- canonical `trace_event_id` only;
- alias `trace_id` only, with canonical-only emission;
- canonical plus alias with the same value, in both member orders;
- canonical plus alias with different values, in both member orders;
- duplicate canonical field;
- a nested `identity.trace_id` wrong-boundary alias while canonical top-level ID
  is present;
- a wrong top-level spelling replacing both accepted spellings;
- unknown top-level and unknown nested identity fields;
- missing `identity`; and
- canonical emission after every accepted input.

Current truth must be characterized, not improved in this slice. Because the
current structs lack `deny_unknown_fields`, unknown top-level and nested identity
fields are expected to deserialize where serde permits and disappear on
serialization. Canonical-plus-alias and duplicate-canonical forms are expected
to reject as duplicate field input, regardless of equal values or order. A
wrong spelling that leaves the required ID absent rejects. The harness asserts
rejection only; serde error text is not persisted or emitted.

### Extension guards

- one safe nested map and one safe nested value;
- normalized reserved-key variants;
- blank keys;
- leading/trailing-trimmed keys;
- nested reserved keys through objects and arrays; and
- one context-specific additional reserved-key denial for each `_with_reserved`
  validator.

The public validator must produce the exact expected reason, path, key, and
normalized key for denials. Accepted extension metadata remains non-authorizing
and does not imply that any closed schema admits extensions.

### Required RFC 0020 live-relation inputs

`negative/cases.json` contains all four exact source-fixed
`parse_live_relation` cases in the manifest array. Each production parser accepts
its structurally valid public record, the hard-coded relation evaluates true,
and capped observed serialization matches. Both status fields remain exactly
`not_exercised`. These are required parse-only inputs, not fabricated owner
output: no owner, signature, authorization, work-order validation, daemon-request
validation, compatibility class, or live disposition executes, and no case may
claim `accept_current`.

## Fixture Loader Negative Tests

The integration test must test its own loader and dispatcher with hard-coded
malformed JSON and hard-coded generated over-bound vectors. These negatives do
not come from either case file and are not external references.

At minimum, assert rejection of:

- duplicate manifest-root and case-record fields;
- duplicate nested fixture fields, including `expected` and tagged-union body
  fields;
- unknown root, nested, tagged-union, subject, operation, input-kind, error-code,
  reason, polarity, resource, mutation, and domain values;
- missing fields, nulls, wrong scalar/container types, empty required arrays, and
  trailing JSON content;
- README, manifest, case-file, built-in-resource, inline text, inline JSON,
  output, metadata string, depth, member, array, additional-key, per-file case,
  and total case over-bounds;
- capped serializer behavior at exactly 65,536 bytes and rejection on attempted
  byte 65,537, with no partial output in diagnostics;
- a 257-member inline object and member counting that includes every duplicate
  occurrence;
- extension inline duplicate-key rejection before `BTreeMap`/`Value`
  conversion, while duplicate-key Trace and relation JSON are passed unchanged
  after their distinct streaming preflights;
- the fixture-versus-inline duplicate distinction: duplicate typed fixture
  metadata rejects in the loader, duplicate Trace keys reach production serde,
  and duplicate extension keys reject in inline preflight;
- case-count mismatch, wrong file polarity, unsorted IDs, duplicate IDs in one
  file, and duplicate IDs across files;
- altered case-file IDs or paths, URL-like strings, absolute paths, parent
  components, path separators in resource IDs, environment-expansion strings,
  and arbitrary resource IDs;
- every illegal subject/operation/input combination and every illegal
  declaration mutation/domain combination;
- unexpected optional observations, missing required observations, present-null
  observations, wrong `expected_digest_wire`, and wrong `digest_equality`;
- missing, duplicate, reordered, renamed, wrong-subject, wrong-input,
  wrong-operation, wrong-relation, or non-`not_exercised` variants of any required
  live-relation ID;
- a positive case that is rejected, or a negative case that is accepted without
  being the exact false-equality wrong-domain exception or one of the exact four
  true-relation exceptions; and
- injected metadata claiming `passed`, `conformant`, `compatible`, `supported`,
  `registered`, `current`, `authorized`, completion, a compatibility class, or a
  live disposition.

A loader-negative succeeds only by rejecting before production dispatch. Its
diagnostic must not print the malformed input.

## Security and Privacy

All fixture data is fixed, synthetic, and non-secret. The existing RFC 0013
resource contains only synthetic driver names, operation names, slot IDs,
classification labels, intent labels, destination schemas, and exposure
profiles. It contains no credential material.

The new fixture files must contain no:

- secret, bearer token, credential secret/material, private key, signature,
  approval token, authentication header, cookie, reusable secret-derived digest,
  protected payload, personal data, or private chain-of-thought;
- real tenant, principal, agent, node, instance, driver, customer, or provider
  identifier;
- URL, host, absolute path, environment variable, command, or dynamic import;
  or
- data that requires network, process, environment, dynamic filesystem, daemon,
  Store, Gateway, adapter, owner, or SDK access.

Hashing is not redaction. The declaration fixture is safe because its complete
synthetic source is reviewable, not because it is hashed. A public
`CallerCredential` fixture is metadata-only and carries no bearer token or
secret. WorkOrder fixtures contain no detached signature. Rejected input may
exist temporarily in bounded parser memory but is not persisted or emitted in a
report, panic payload, diagnostic, snapshot, log, metric, or generated artifact.

The integration test is offline and side-effect-free. It may allocate bounded
memory and CPU for parsing, serialization, and BLAKE3 comparison only. Resource
ceilings are enforced before expensive dispatch. There are no unbounded loops,
recursive descent beyond depth 16, retries, sleeps, clocks, random values, or
external cleanup requirements.

## Tests and Evidence

The implementation test must have distinct assertions for:

- exact manifest and root contract loading;
- all positive production cases;
- all negative production cases;
- cross-file identity, ordering, and total-count laws;
- scalar route agreement;
- scalar `as_str`/integer `get`, RFC 0013 revision-accessor, and exact digest
  redacted-Debug assertions;
- pinned versus observed hard-coded policy;
- stable alias key emission and current unknown-field behavior;
- declaration golden, one-byte mutation, independently fixed expected digest
  wires, and non-vacuous wrong-domain inequality;
- all four extension validators;
- all four source-fixed live-relation cases with parse success, true relation,
  capped observed serialization, and both statuses `not_exercised`;
- positive/negative polarity and exact accepted-negative exceptions;
- README over-bound rejection, capped serialization at 65,536/65,537, 257
  duplicate-member counting, extension duplicate-key rejection, and the
  fixture-versus-inline duplicate distinction;
- diagnostic canaries proving rejected input, serde text, extension error and
  path/key values, normalized keys, and digest wires are not emitted;
- source/diff review evidence for `#![forbid(unsafe_code)]`, source-fixed
  dispatch, compile-time-only resources, and absence of prohibited service
  handles/imports; and
- every loader-negative category above.

The test creates no report file. A successful case comparison is internally
`matched`; a mismatch fails the Cargo test with bounded non-sensitive context.
The normal Cargo test runner may display `ok` for the Rust test function, but
fixture and harness vocabulary must not translate that into compatibility,
conformance, Gold, registration, or task status.

After implementation, run and retain command evidence for:

```sh
cargo test -p splendor-types --test c03_foundation_offline_slice_1
cargo test -p splendor-types
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
python3 conformance/0.1/run-conformance.py --format json
python3 scripts/architecture/check-dependency-policy.py
python3 scripts/architecture/check-dependency-policy.py --self-test
cargo llvm-cov -p splendor-types --test c03_foundation_offline_slice_1 --ignore-filename-regex 'crates/splendor-types/src/' --fail-under-lines 95
git diff --check
git diff --name-only
git diff --name-only origin/dev...HEAD
git ls-files -s -- conformance/0.2/c03-foundation/v1 crates/splendor-types/tests/c03_foundation_offline_slice_1.rs crates/splendor-types/tests/fixtures/driver/operation-credential-sinks-v1.json
gitleaks detect --no-banner --redact --source .
cargo audit
```

The `llvm-cov` threshold applies to the private integration-test loader,
dispatcher, and assertion harness, not to unrelated production modules excluded
by the command. Coverage is at least 95 percent line coverage. The production
APIs are still exercised by the focused and package tests; exclusion from this
specific percentage calculation does not replace those execution requirements.

If a named external scanner is unavailable in the implementation environment,
the implementation cannot claim that scan passed. The retained evidence must
state it was unavailable and the separate security review must require an
equivalent repository-approved secret/security scan before merge. No CI edit is
authorized by this RFC.

Review must also verify that the implementation diff contains exactly the five
authorized files, all links in `README.md` are relative and resolve, all Markdown
fences are balanced, every listed Git mode is regular-file mode `100644`, and
claim searches find no accidental implementation,
task-completion, issue-closure, Gold-pass, compatibility, registration, live
disposition, generated-publication, runtime, or migration statement.

## No-Go Gates

Implementation must not start, or must stop, if any of these is true:

- this RFC is not accepted or its exact accepted proposal hash is absent;
- architecture/compatibility or security/privacy review is missing;
- the branch is not fresh from its reviewed base or contains unrelated files;
- any file outside the exact five-file set would change;
- a Python validator, retained report, generator, public schema, public enum,
  production serde type, generated output, SDK, daemon, Store, runtime, migration,
  Cargo, lockfile, CI, or existing fixture change is proposed;
- a fixture path or resource drives file I/O, or any URL, absolute path, parent
  traversal, environment expansion, dynamic import, symlink following, network,
  process, or arbitrary resource becomes reachable;
- fixture structs are public, open, map-backed, permit unknown fields, collapse
  null into omission, accept duplicate typed fields, or parse trailing content;
- a raw, decoded, nested, member, array, string, case-count, additional-key,
  README, built-in-resource, or actual-output allocation/write bound is absent
  or fixture-adjustable;
- harness output serialization materializes unbounded output before checking its
  length, does not use the capped `Write` sink, accepts byte 65,537, or logs
  partial output;
- case IDs are unsorted, duplicated, over-bound, or fail the exact ASCII grammar;
- a subject, operation, input, error, extension reason, declaration mutation, or
  domain falls outside the closed sets;
- inline JSON can escape into fixture metadata or is normalized before its
  production call; Trace preflight rejects duplicates before production serde;
  extension preflight permits duplicates before `BTreeMap`/`Value` conversion;
  relation preflight changes the original string; or any member limit fails to
  count duplicate occurrences;
- the harness reimplements foundation grammar, Trace alias behavior, extension
  reservation logic, or declaration parsing/serialization instead of calling the
  public production API;
- an operation label does not invoke its exact named primary public route first,
  coverage is inferred from a fixture label, equivalent routes disagree where
  they exist, or successful values are not run through capped production
  serialization;
- a rejected string-backed scalar omits applicable `try_new` agreement, or an
  integer `u64` construction rejection does not call `try_new`;
- a Trace rejection asserts unstable serde text, or rejected input is persisted,
  emitted, or printed;
- a diagnostic formats or prints `ExtensionValidationError`, an extension path,
  key, normalized key, serde text, rejected input, digest wire, or any compared
  value instead of bounded categories, match booleans, or lengths;
- current permissive Trace unknown-field behavior is silently hardened in this
  slice;
- extension harness bounds are represented as production validator guarantees;
- `RegistryDeclarationDigest` skips the production declaration parser,
  declaration serializer, revision accessor, `TryFrom`, exact redacted Debug
  assertion, independent expected-wire parse, or non-vacuous wrong-domain vector
  equality, or a wrong-domain lexical digest is treated as registered;
- fixture metadata selects pinned versus observed output, or complete
  `TraceEvent`, `WorkOrder`, or `CallerCredential` output is elevated to a
  canonical ABI;
- a parser success is described as `accept_current`, compatible, supported,
  registered, current, trusted, authorized, durable, or live;
- a case or manifest contains an executed compatibility class or live
  disposition value;
- any exact required live-relation input is absent, rejected, in the positive
  file, assigned a fixture-selected relation, fails its source-fixed relation,
  uses a real identifier/secret/token/signature, or changes either status from
  `not_exercised`;
- a live-relation case signs a WorkOrder, constructs or uses
  `WorkOrderEnvelope`, calls `validate_work_order` or
  `validate_daemon_request`, executes owner/live authorization or compatibility,
  fabricates owner output, or claims `accept_current`;
- a positive case rejects, or a negative case accepts except for the exact
  false-equality wrong-domain case and exact four true-relation cases;
- fixtures declare per-case effect/non-effect evidence, the harness claims
  counters can observe arbitrary external effects, `unsafe` is permitted,
  dispatch or file access is fixture-selected, prohibited service
  handles/imports are present, or resources are not compile-time-only;
- a successful comparison is called passed, conformant, Gold, certified, or task
  completion instead of `matched`;
- `G00` or `G72` changes from `specified_not_implemented` / `not_exercised`;
- `FND-006`, issue #225, C03, a sprint, conformance line, release, durability, or
  production readiness is claimed complete; or
- any focused, package, workspace, 0.1 conformance, dependency-policy, coverage,
  formatting, lint, diff, secret, or security evidence required above fails or
  is misreported.

## Acceptance Effect

Acceptance of this RFC freezes only the private offline Slice 1 characterization
contract in this document. It authorizes one separately reviewed implementation
on a fresh branch containing exactly the five files listed in Exact
Implementation Files.

That implementation may execute only already public production Rust APIs using
compile-time embedded synthetic fixtures. Its result is limited to `matched`
expected observations for parser/constructor acceptance or rejection, stable
error codes where available, exact explicitly pinned output, exact observed
production output, digest comparison, internally compared extension-validator
details, and the exact four successful parse-only source-fixed relations. Its
absence of external effects is a harness-level construction and review guarantee,
not a fixture-declared per-case observation.

Acceptance does not authorize a Python validator, report, generator, public
schema or enum, generated surface, owner integration, live disposition,
compatibility classification, negotiation, capability advertisement, protocol,
migration, daemon, Store, runtime, SDK, Gateway, adapter, CI, or production
change. It authorizes no fabricated owner output, signing, authorization
validation, `accept_current`, executed compatibility class, or executed live
disposition. The required stale/wrong-owner/wrong-tenant/wrong-audience public
records are machine-readable parser inputs only, with both statuses remaining
`not_exercised`.

Acceptance and later implementation do not complete `FND-006`, issue #225,
C03, `FR-0.2-01`, `FR-0.2-08`, any sprint, any conformance line, any release, or
any Gold case. `G00` and `G72` remain `specified_not_implemented` /
`not_exercised`. Only later owner-integrated, generated-parity, migration, and
Gold work with separate accepted contracts and retained executable evidence may
change those truths.
