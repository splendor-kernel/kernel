# RFC 0014 - Revision-Bound Secret Credential Authorization

## Status and Binding

**Status:** Proposed

**Proposed:** 2026-07-19

**Compatibility line:** Additive experimental 0.2/v2 C03 successor contract;
historical RFC 0012 v1 bytes remain readable but non-live

**Component:** C03 `splendor.secret-broker`

**Owner:** Authority Service in `crates/splendor-authority::secrets`; behavior-free
wire grammar in `splendor-types`

**Sprint:** `V2-IA-3 - Secret Broker`

**Catalog tasks:** prerequisite contract for `SECR-001` through `SECR-006`,
issues [#245](https://github.com/splendor-kernel/kernel/issues/245) through
[#250](https://github.com/splendor-kernel/kernel/issues/250)

**Functional requirements:** `FR-0.2-02`, `FR-0.2-08`

**Primitive strengthened:** secret reference and credential authorization

**Normative dependencies:** [RFC 0012](0012-secret-broker-contract.md) and
[RFC 0013](0013-driver-operation-credential-sink-contract.md)

This RFC is a proposed, docs-only correction to the C03 planning contract. It
does not implement a schema, construct a `SecretRef`, authorize credential use,
change runtime behavior, add a provider or broker, alter the Gateway, close an
issue, or make any gold or conformance case pass. Acceptance would authorize
only the subsequent behavior-free C03 grammar and fixtures described here.

## Decision

RFC 0012's `splendor.secret.credential_authorization.v1` omits the positive
driver declaration revision that RFC 0013 requires for safe use of a driver
credential-sink declaration. C03 will not change those accepted v1 bytes in
place. It will use two additive successor schemas:

- `splendor.secret.credential_authorization.v2`, represented in Rust as
  `SecretCredentialAuthorizationV2`; and
- `splendor.secret.ref.v2`, represented in Rust as `SecretRefV2`.

Every v2 credential authorization carries one explicit positive
`driver_declaration_revision`. The complete credential-authorization coordinate
is:

```text
(
  canonical DriverOperationRef bytes,
  driver_declaration_revision,
  SecretCredentialSlotId bytes,
  destination_schema,
  SecretDeliveryExposureProfile,
  canonical DriverTrustedSendProfileV1 bytes,
  sorted approved DriverCredentialDestinationDigest values
)
```

Every component is authorizing input and participates in equality,
canonicalization, persistence, migration, and cache keys. A match on fewer
components is never sufficient. A declaration revision change requires a fresh
`SecretRefV2` revision and a fresh current Authority decision even when every
other declaration byte is identical.

For uniqueness inside one ref, the authorization binding key is the same tuple
without its final approved-digest set. Exactly one authorization entry owns the
complete digest set for one binding key. This prevents splitting one binding
across entries to evade set bounds while preserving every digest as part of the
complete authorizing coordinate.

Revision-less v1 history may be retained and decoded for audit, migration
analysis, and inspect-only replay. It is never current live authority. It may
produce a new v2 ref revision only through the explicit proof-bound migration
path below. No implementation may infer `latest`, `active`, newest numeric,
same-number, or only matching declaration; consult a hidden side table; add a
shadow Driver Registry field; translate at the broker; or fall back to v1.

## Amendment Scope

This RFC normatively supersedes only these RFC 0012 details:

1. The live element type of `SecretRef.allowed_credential_bindings` becomes
   `SecretCredentialAuthorizationV2`, not the revision-less v1 value.
2. The live secret-ref schema becomes `splendor.secret.ref.v2`.
3. `driver_declaration_revision` is part of every complete credential
   authorization, authorization-sensitive key, and same-revision comparison.
4. Historical v1 records receive the read/deny and proof-bound migration rules
   below.

All other RFC 0012 rules remain unchanged. In particular, this RFC does not
weaken current authority, work-order, tenant, principal, data-use, purpose,
intent, audience, expiry, revocation, quota, approval, lease, Gateway, verifier,
trace, state, evidence, or replay requirements.

This RFC imports the exact RFC 0013 names `destination_schema`,
`delivery_exposure_profile`, and `trusted_send_profile`. The phrase
"destination schema/version" in RFC 0012 means the one version-bearing
`destination_schema` string and does not create a second version field. The
approved digest field is named exactly `approved_destination_digests`.

## Ownership and Non-Authority Boundary

| Owner | Owns here | Must not own here |
| --- | --- | --- |
| `splendor-types` | Behavior-free v2 value types, strict bounded parsing, deterministic serialization, code-only errors, canonical fixtures | Authority decisions, declaration lookup, persistence, migration execution, provider or Gateway behavior |
| Authority Service / C03 | Ref mutation, current-head CAS, current authority, proof-bound historical migration, authorization intersection | Driver operation or slot identity, declaration lifecycle, projection logic, Gateway execution |
| Driver Registry | Existing RFC 0013 declaration bytes, revision lifecycle, exact operation/revision lookup, immutable declaration evidence | C03 refs, approved destination sets, C03 authority, v1 migration decisions |
| Gateway | Future consumption of an already-current exact authorization through every required verifier | Ref mutation, migration, revision inference, alternate credential path |
| Store | Persistence of already-validated versioned records and explicit migration evidence links | Schema upgrade decisions, inferred revisions, current-head selection |
| Daemon, SDK, CLI, adapters, providers, nodes | No new surface in this RFC | Constructing authority, selecting a declaration revision, resolving v1 into live authority |

`SecretCredentialAuthorizationV2` and `SecretRefV2` remain behavior-free data.
Possessing, parsing, serializing, or persisting one does not authorize a lease,
provider access, delivery, driver entry, or side effect.

## Public Contract Surface

Acceptance may authorize a later behavior-free C03 slice to expose only:

| Symbol | Contract |
| --- | --- |
| `SECRET_CREDENTIAL_AUTHORIZATION_SCHEMA_V2` | Exact value `splendor.secret.credential_authorization.v2`. |
| `SECRET_REF_SCHEMA_V2` | Exact value `splendor.secret.ref.v2`. |
| `SecretCredentialAuthorizationV2` | Closed revision-bearing credential authorization. |
| `SecretRefV2` | Closed ref revision containing only v2 authorizations. |
| `SecretCredentialAuthorizationV2Error` | One fixed non-reflecting authorization-grammar error code. |
| `SecretCredentialAuthorizationV2ErrorCode` | Closed authorization-grammar code enum below. |
| `SecretRefV2Error` | One fixed non-reflecting ref-grammar error code. |
| `SecretRefV2ErrorCode` | Closed ref-grammar code enum below. |

Both validated records implement `Serialize` and do not implement
`Deserialize`. Untrusted, imported, persisted, or rehydrated bytes reach a
validated record only through its bounded `from_json_slice` parser. Private wire
inputs are not exported and cannot be retained as alternate record types.
Checked constructors enforce the same semantic rules without creating a second
wire grammar.

No `Default`, unchecked constructor, arbitrary `serde_json::Value`, map,
metadata, `extensions`, alias, optional revision, string operation, digest-only
authorization, or generic deserialization route is part of the contract.

## `SecretCredentialAuthorizationV2`

### Exact schema

The top-level value is a closed JSON object with exactly eight required,
non-null fields.

| Field | JSON type | Exact rule |
| --- | --- | --- |
| `schema_version` | string | Exactly `splendor.secret.credential_authorization.v2`. |
| `driver_operation` | object | Exact existing three-field RFC 0013 `DriverOperationRef`; it must pass `validate_driver_operation_ref_v1`. |
| `driver_declaration_revision` | integer | Decimal JSON integer token matching `^[1-9][0-9]*$` and numerically in `1..=9007199254740991`. |
| `credential_slot_id` | string | One canonical non-nil RFC 0013 `SecretCredentialSlotId`. |
| `destination_schema` | string | `1..=128` ASCII bytes matching `^[a-z][a-z0-9._-]*\.v[1-9][0-9]*$`; it must equal the exact slot declaration value. |
| `delivery_exposure_profile` | string | One exact C03 `SecretDeliveryExposureProfile`; it must equal the exact slot declaration value. |
| `trusted_send_profile` | object | One exact RFC 0013 `DriverTrustedSendProfileV1`; it must equal the exact slot declaration profile. |
| `approved_destination_digests` | array of strings | Semantic set of `1..=16` unique `DriverCredentialDestinationDigest` values. |

Unknown, missing, duplicate, null, alias, default, extension, wildcard, and
extra fields reject. The revision token forbids zero, a sign, leading zero,
fraction, exponent, string coercion, and numeric coincidence with another
counter. It is not a secret-ref revision, lease revision, lifecycle generation,
or inferred declaration head.

The imported trusted-send profile remains exact:

- `trusted_injection` has exactly `kind`,
  `max_credential_bearing_sends` in `1..=8`, and a semantic set of `1..=8`
  `applicable_delivery_controls` containing `trusted_injection_boundary`;
- `not_applicable` is exactly `{"kind":"not_applicable"}` and is valid only
  with `delivery_exposure_profile = "material_exposed"`; and
- controls use the C03-owned `SecretDeliveryControlKind` values already
  imported by RFC 0013. No copied, translated, or expanded control vocabulary is
  created.

The digest wire form remains exactly `blake3:` followed by 64 lowercase
hexadecimal characters. A digest is only one component of the coordinate; it is
not a credential, locator, permission, signature, or complete key.

### Exact same-revision example

```json
{
  "schema_version": "splendor.secret.credential_authorization.v2",
  "driver_operation": {
    "driver": "example_driver",
    "operation": "example_operation",
    "schema_version": "splendor.driver.operation.v1"
  },
  "driver_declaration_revision": 7,
  "credential_slot_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001",
  "destination_schema": "example.driver.https_destination.v1",
  "delivery_exposure_profile": "trusted_injection",
  "trusted_send_profile": {
    "kind": "trusted_injection",
    "max_credential_bearing_sends": 1,
    "applicable_delivery_controls": [
      "destination_network_egress",
      "trusted_injection_boundary"
    ]
  },
  "approved_destination_digests": [
    "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  ]
}
```

The object is grammar-valid without registry I/O. It is contextually valid only
when pure comparison against the exact supplied declaration at revision 7 finds
the named operation, slot, destination schema, exposure profile, and trusted-send
profile. Neither success is a live allow. Live use remains blocked until every
later C03 current-authority and runtime gate also succeeds.

## `SecretRefV2`

`SecretRefV2` is the only live ref shape authorized by this successor. It is a
closed JSON object with the RFC 0012 fields below. The only semantic changes are
the v2 schema constant, the v2 binding element, and the explicit refresh rule.

| Field | JSON type | Exact rule |
| --- | --- | --- |
| `schema_version` | string | Exactly `splendor.secret.ref.v2`. |
| `secret_ref_id` | string | Exact canonical non-nil `SecretRefId`. |
| `secret_ref_revision` | integer | Decimal JSON integer token in `1..=9007199254740991`; immutable and owner-issued. |
| `tenant_id` | string | Exact canonical non-nil `TenantId`. |
| `secret_provider_id` | string | Exact canonical non-nil `SecretProviderId`; not an endpoint. |
| `provider_namespace` | string | `1..=128` ASCII bytes matching `^[a-z][a-z0-9._-]*$`; not a locator. |
| `logical_name` | string | `1..=128` ASCII bytes matching `^[a-z][a-z0-9._-]*$`; non-sensitive and not provider-resolvable by itself. |
| `provider_version_ref` | string | Exact validated `SecretProviderVersionRef`, `1..=128` printable non-space ASCII bytes with locator delimiters forbidden. |
| `classification` | string | One exact `SecretClassification`. |
| `allowed_credential_bindings` | array | Semantic set of `1..=16` `SecretCredentialAuthorizationV2` values with unique authorization binding keys. |
| `allowed_delivery_methods` | array of strings | Semantic set of `1..=5` unique `SecretDeliveryMethod` values; `environment_variable` alone is invalid. |
| `lease_policy` | object | Exact closed `SecretLeasePolicy` from RFC 0012. |
| `offline_behavior` | string | One exact `SecretOfflineBehavior`. |
| `created_at` | string | Exact RFC 0012 timestamp `YYYY-MM-DDTHH:MM:SS.ffffffZ`. |
| `disabled_at` | string or absent | When present, the exact timestamp form above and not earlier than `created_at`; null is forbidden. |

Two entries duplicate when their authorization binding keys are equal, whether
their digest sets are equal, overlap, or are disjoint. A single binding cannot be
split into multiple entries to evade the 16-digest bound. The entries reject as
`duplicate_credential_authorization_coordinate` rather than being merged. One
slot may have multiple entries only when at least one binding-key component
differs, and every such entry still requires a corresponding exact declaration
match and current authority.

### Declaration revision refresh rule

For one `SecretRefId`, replacing any authorization's
`driver_declaration_revision = N` with any `M != N` requires all of:

1. a new immutable `SecretRefV2` record with a fresh owner-issued
   `secret_ref_revision` under the existing RFC 0012 expected-current-revision
   CAS;
2. exact lookup and validation of the admitted declaration at `M` without
   alias, latest, fallback, or numeric inference;
3. exact comparison of the operation, slot, schema, exposure profile, and
   trusted-send profile against that declaration;
4. fresh current Authority evaluation of the complete new ref specification and
   every applicable tenant, principal, work-order, purpose, policy, data-use,
   revocation, expiry, and scope fact; and
5. invalidation or fencing of any authorization-sensitive cache entry keyed by
   the prior ref or declaration revision before the new revision can be selected.

A changed declaration revision is a semantic change even if its declaration
bytes happen to be identical. Reusing the current ref revision, mutating an
authorization in place, copying an old Authority decision, or accepting an old
lease as proof is forbidden. This RFC does not define lease fencing behavior;
that remains a later runtime slice, but no old-revision lease may gain new use
from the new declaration.

## Canonicalization and Bytes

Validation and duplicate rejection run before sorting. Canonicalization never
repairs invalid input.

| Value | Canonical order |
| --- | --- |
| `approved_destination_digests` | Ascending 32 digest bytes after strict lowercase wire parsing. |
| `applicable_delivery_controls` | Ascending exact ASCII enum spelling, as in RFC 0013. |
| `allowed_credential_bindings` | Lexicographic order of each authorization's complete canonical JCS bytes. |
| `allowed_delivery_methods` | Ascending exact ASCII enum spelling. |
| Object members | RFC 8785 JSON Canonicalization Scheme order. |

After set normalization, ordinary compact serialization of either validated
Rust value is its RFC 8785 JCS byte sequence. Implementations must declare and
serialize fields in that exact order; there is no alternate canonical API whose
bytes can diverge. No BOM, whitespace, trailing newline, float, or Unicode
normalization is permitted.

The authorization example above has these exact canonical bytes:

```json
{"approved_destination_digests":["blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],"credential_slot_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001","delivery_exposure_profile":"trusted_injection","destination_schema":"example.driver.https_destination.v1","driver_declaration_revision":7,"driver_operation":{"driver":"example_driver","operation":"example_operation","schema_version":"splendor.driver.operation.v1"},"schema_version":"splendor.secret.credential_authorization.v2","trusted_send_profile":{"applicable_delivery_controls":["destination_network_egress","trusted_injection_boundary"],"kind":"trusted_injection","max_credential_bearing_sends":1}}
```

The fenced code block has a Markdown newline for readability. The fixture file
must contain exactly the JSON bytes inside the block and no trailing newline.

This exact minimal `SecretRefV2` example is the same-revision migration target:

```json
{
  "schema_version": "splendor.secret.ref.v2",
  "secret_ref_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5001",
  "secret_ref_revision": 2,
  "tenant_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5002",
  "secret_provider_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5003",
  "provider_namespace": "example",
  "logical_name": "billing_api",
  "provider_version_ref": "release-007",
  "classification": "authentication_credential",
  "allowed_credential_bindings": [
    {
      "schema_version": "splendor.secret.credential_authorization.v2",
      "driver_operation": {
        "driver": "example_driver",
        "operation": "example_operation",
        "schema_version": "splendor.driver.operation.v1"
      },
      "driver_declaration_revision": 7,
      "credential_slot_id": "018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001",
      "destination_schema": "example.driver.https_destination.v1",
      "delivery_exposure_profile": "trusted_injection",
      "trusted_send_profile": {
        "kind": "trusted_injection",
        "max_credential_bearing_sends": 1,
        "applicable_delivery_controls": [
          "destination_network_egress",
          "trusted_injection_boundary"
        ]
      },
      "approved_destination_digests": [
        "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      ]
    }
  ],
  "allowed_delivery_methods": ["inherited_fd"],
  "lease_policy": {
    "max_lease_duration_seconds": 300,
    "max_continuous_lifetime_seconds": 3600,
    "max_uses": 1,
    "renewable": false,
    "clock_skew_tolerance_seconds": 0
  },
  "offline_behavior": "deny",
  "created_at": "2026-07-19T00:00:00.000000Z"
}
```

Its exact canonical bytes are:

```json
{"allowed_credential_bindings":[{"approved_destination_digests":["blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],"credential_slot_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001","delivery_exposure_profile":"trusted_injection","destination_schema":"example.driver.https_destination.v1","driver_declaration_revision":7,"driver_operation":{"driver":"example_driver","operation":"example_operation","schema_version":"splendor.driver.operation.v1"},"schema_version":"splendor.secret.credential_authorization.v2","trusted_send_profile":{"applicable_delivery_controls":["destination_network_egress","trusted_injection_boundary"],"kind":"trusted_injection","max_credential_bearing_sends":1}}],"allowed_delivery_methods":["inherited_fd"],"classification":"authentication_credential","created_at":"2026-07-19T00:00:00.000000Z","lease_policy":{"clock_skew_tolerance_seconds":0,"max_continuous_lifetime_seconds":3600,"max_lease_duration_seconds":300,"max_uses":1,"renewable":false},"logical_name":"billing_api","offline_behavior":"deny","provider_namespace":"example","provider_version_ref":"release-007","schema_version":"splendor.secret.ref.v2","secret_provider_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5003","secret_ref_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5001","secret_ref_revision":2,"tenant_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5002"}
```

Future Rust, persisted, OpenAPI, JSON Schema, Python, and TypeScript surfaces
must reproduce these bytes before any such surface is exposed. This RFC adds no
generated surface itself.

## Untrusted Ingress Budgets

Every untrusted byte ingress applies these limits before generic decoding or
record construction. Counts include duplicate and unknown content before
semantic rejection. A decoder token is one object/array open, one object/array
close, one member name, or one scalar value.

| Resource | Authorization v2 maximum | Secret ref v2 maximum |
| --- | ---: | ---: |
| Raw encoded JSON body | 8,192 bytes | 65,536 bytes |
| Container nesting depth, root at 1 | 8 | 12 |
| Decoder tokens | 128 | 2,048 |
| Object members across document | 32 | 384 |
| Array elements across document | 32 | 512 |
| Decoded UTF-8 bytes in one name or string token | 256 | 256 |

The owner parser signatures are semantically:

```rust
impl SecretCredentialAuthorizationV2 {
    pub fn from_json_slice(input: &[u8])
        -> Result<Self, SecretCredentialAuthorizationV2Error>;
}

impl SecretRefV2 {
    pub fn from_json_slice(input: &[u8])
        -> Result<Self, SecretRefV2Error>;
}
```

The parser rejects an over-bound body before decoding and runs one bounded,
duplicate-aware preflight scanner before strict private-wire construction.
Streaming readers stop and reject on the first byte above the cap. The final
types expose no generic `Deserialize` bypass. The future implementation must
generate independent legal-maximum fixtures and prove both fit within every
cap; if they do not, implementation stops and this RFC is amended rather than
silently raising a limit.

Malformed UTF-8, escapes, duplicate members, integer overflow, depth, token,
member, element, or string excess returns only the relevant fixed shape code.
Rejected bytes and candidates are dropped and never persisted, traced, logged,
measured as labels, attached to audit, or retained in an error/source chain.

## Validation Precedence

### Authorization grammar

| Order | Check | Fixed code |
| ---: | --- | --- |
| 1 | Enforce ingress budgets; require valid UTF-8/JSON, no duplicate member at any depth, and a top-level object | `invalid_contract_shape` |
| 2 | Reject top-level members outside the exact eight-name vocabulary | `invalid_contract_shape` |
| 3 | Require the exact authorization schema string | `invalid_schema_version` |
| 4 | Require the exact nested operation object and RFC 0013 owner validation | `invalid_driver_operation` |
| 5 | Require the positive safe-integer declaration revision token | `invalid_driver_declaration_revision` |
| 6 | Require the exact canonical non-nil nominal slot | `invalid_credential_slot` |
| 7 | Require the bounded version-bearing destination schema | `invalid_destination_schema` |
| 8 | Require an exact exposure enum and closed trusted-send profile with a matching pair | `invalid_exposure_profile_binding` or `invalid_trusted_send_profile` |
| 9 | Require digest-array kind and cardinality | `empty_approved_destination_digests` or `too_many_approved_destination_digests` |
| 10 | Validate digest values in input order | `invalid_destination_digest` |
| 11 | Reject duplicate digest values before sorting | `duplicate_destination_digest` |
| 12 | Normalize semantic sets | Cannot fail |

Missing, null, or wrong-kind recognized fields fail at their named stage. A
trusted-injection profile with missing/invalid send limit, controls, or required
boundary returns `invalid_trusted_send_profile`; a not-applicable payload or
profile/exposure mismatch returns `invalid_exposure_profile_binding`.

### Secret ref grammar

| Order | Check | Fixed code |
| ---: | --- | --- |
| 1 | Enforce ref ingress budgets; require valid UTF-8/JSON, no duplicate member, and a top-level object | `invalid_contract_shape` |
| 2 | Reject members outside the exact fifteen-name vocabulary | `invalid_contract_shape` |
| 3 | Require exact ref v2 schema | `invalid_schema_version` |
| 4 | Validate canonical non-nil ref ID | `invalid_secret_ref_id` |
| 5 | Validate positive safe-integer ref revision | `invalid_secret_ref_revision` |
| 6 | Validate tenant and provider nominal IDs in that order | `invalid_tenant_id` or `invalid_secret_provider_id` |
| 7 | Validate namespace, logical name, and provider version in that order | Field-specific fixed code |
| 8 | Validate classification | `invalid_classification` |
| 9 | Validate authorization-array kind and `1..=16` cardinality | `empty_credential_authorizations` or `too_many_credential_authorizations` |
| 10 | Validate each authorization in input order using the complete authorization precedence | The nested authorization code |
| 11 | Reject duplicate authorization coordinates before sorting | `duplicate_credential_authorization_coordinate` |
| 12 | Validate delivery-method set, uniqueness, and environment-only denial | `invalid_delivery_methods` |
| 13 | Validate exact closed lease policy | `invalid_lease_policy` |
| 14 | Validate offline behavior | `invalid_offline_behavior` |
| 15 | Validate created time, then optional disabled time and ordering | `invalid_created_at` or `invalid_disabled_at` |
| 16 | Normalize semantic sets | Cannot fail |

## Fixed Non-Reflecting Errors

`SecretCredentialAuthorizationV2ErrorCode` is closed to:

```text
invalid_contract_shape
invalid_schema_version
invalid_driver_operation
invalid_driver_declaration_revision
invalid_credential_slot
invalid_destination_schema
invalid_exposure_profile_binding
invalid_trusted_send_profile
empty_approved_destination_digests
too_many_approved_destination_digests
invalid_destination_digest
duplicate_destination_digest
```

`SecretRefV2ErrorCode` is closed to the authorization codes above plus:

```text
invalid_secret_ref_id
invalid_secret_ref_revision
invalid_tenant_id
invalid_secret_provider_id
invalid_provider_namespace
invalid_logical_name
invalid_provider_version_ref
invalid_classification
empty_credential_authorizations
too_many_credential_authorizations
duplicate_credential_authorization_coordinate
invalid_delivery_methods
invalid_lease_policy
invalid_offline_behavior
invalid_created_at
invalid_disabled_at
```

Each error contains exactly one code. `Display` and `Debug` render only its exact
snake-case code. Errors retain no input, field name, index, line, column,
expected or rejected value, operation, slot, destination, digest, declaration,
provider, parser source, or source chain.

Future live comparison and migration decisions use these separate closed denial
codes without candidate reflection:

```text
driver_declaration_revision_unproven
driver_declaration_revision_mismatch
driver_declaration_revision_not_active
secret_ref_revision_refresh_required
current_authority_required
historical_revisionless_authorization_live_denied
```

Grammar success never implies a live allow. At live comparison, the first
applicable order is exact proof, exact revision equality, active lifecycle,
fresh ref revision, then current authority. Missing or unavailable owner state
denies with the corresponding earliest code.

## Historical V1 Read and Migration

### Historical profile

The accepted revision-less shapes are frozen for historical decoding:

- `splendor.secret.credential_authorization.v1` has the same fields and rules as
  v2 except it has no `driver_declaration_revision`; and
- `splendor.secret.ref.v1` has the same fields and rules as ref v2 except its
  bindings are v1 authorizations and its schema string remains v1.

Historical byte readers use the corresponding v2 ingress budget and strict
duplicate-aware parsing. They do not route v1 through a permissive generic JSON
decoder or accept a field that v1 did not define.

The migration fixture source corresponding to the v2 example has
`secret_ref_revision = 1`, removes only `driver_declaration_revision`, and uses
the two v1 schema strings. Its exact canonical bytes are:

```json
{"allowed_credential_bindings":[{"approved_destination_digests":["blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],"credential_slot_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001","delivery_exposure_profile":"trusted_injection","destination_schema":"example.driver.https_destination.v1","driver_operation":{"driver":"example_driver","operation":"example_operation","schema_version":"splendor.driver.operation.v1"},"schema_version":"splendor.secret.credential_authorization.v1","trusted_send_profile":{"applicable_delivery_controls":["destination_network_egress","trusted_injection_boundary"],"kind":"trusted_injection","max_credential_bearing_sends":1}}],"allowed_delivery_methods":["inherited_fd"],"classification":"authentication_credential","created_at":"2026-07-19T00:00:00.000000Z","lease_policy":{"clock_skew_tolerance_seconds":0,"max_continuous_lifetime_seconds":3600,"max_lease_duration_seconds":300,"max_uses":1,"renewable":false},"logical_name":"billing_api","offline_behavior":"deny","provider_namespace":"example","provider_version_ref":"release-007","schema_version":"splendor.secret.ref.v1","secret_provider_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5003","secret_ref_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5001","secret_ref_revision":1,"tenant_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5002"}
```

Historical readers may validate, canonicalize, export under access control, and
inspect these bytes. They mark each record
`historical_revisionless_authorization_live_denied`. They do not return a live
`SecretCredentialAuthorizationV2` or `SecretRefV2`, move a ref head, issue a
lease, contact a registry/provider/node, invoke the Gateway, or create fresh
authority.

### Explicit proof-bound migration path

Authority Service is the sole migration decision owner. A migration is an
authenticated, separately authorized ref-update command, not parser fallback.
For every v1 authorization, its input must contain explicit immutable evidence
of all of:

1. the exact source v1 ref bytes and their RFC 8785 JCS BLAKE3 content digest;
2. an Authority-owned historical issuance or import evidence record that binds
   that exact source digest to one exact positive driver declaration revision;
3. a Driver Registry-owned immutable admitted-declaration evidence record for
   the exact canonical `(driver_operation, driver_declaration_revision)` and
   declaration bytes;
4. proof that the slot, destination schema, exposure profile, and trusted-send
   profile in the source equal that admitted declaration entry;
5. the expected current `SecretRefId` and `secret_ref_revision` for CAS; and
6. fresh current ref-mutation authority for the complete v2 target bytes.

The source digest in item 1 has exact wire form `blake3:` plus 64 lowercase
hexadecimal characters and this exact construction:

```text
canonical_source = RFC8785_JCS(validated_source_SecretRef_v1)
digest_input = UTF8("splendor.secret.ref.v1") || 0x00 || canonical_source
source_ref_digest = "blake3:" || lowercase_hex(BLAKE3-256(digest_input))
```

There is no alternate algorithm, prefix, field projection, whitespace form, or
digest over unvalidated input. The future migration fixture must independently
pin the 32 digest bytes and exact 71-byte wire value.

Both evidence records are explicit owner records with distinct identities and
integrity/authenticity validation. A caller assertion, unsigned manifest,
matching number, current registry head, operation lookup, declaration byte
similarity, timestamp, filename, row order, import order, provider metadata, or
hidden database relation proves none of these facts. If the historical issuance
evidence never bound a declaration revision, the exact revision is unproven and
migration to live authority is impossible.

The exact Authority issuance/import-evidence and Driver Registry admission-
evidence schemas are prerequisites owned by their respective components. No
migration implementation may land until separately accepted contracts pin those
schemas, identities, signatures or integrity chains, revocation behavior,
canonical bytes, and retention. This RFC does not permit ad hoc maps, database
joins, unsigned rows, or implementation-defined evidence in their place.

On success, Authority appends one new immutable `SecretRefV2` revision under the
same `SecretRefId`, carries the explicitly proven revision into every v2
authorization, performs fresh current authority evaluation, and CAS-moves the
head. It does not rewrite, annotate, delete, or reinterpret v1 bytes. Migration
evidence links remain audit/replay facts but are not reusable authority.

If any proof, owner, integrity check, exact comparison, current authority, or CAS
is absent, stale, revoked, unavailable, or ambiguous, migration denies with no
new ref, head movement, lease, provider/node/Gateway call, or side effect.

### Rollback

Before release or external/persisted use, an unimplemented experimental v2
module may be removed. Once any v2 bytes or consumers exist, v2 remains readable
and can only be deprecated through another accepted compatible migration.
Rollback never makes v1 live, strips the revision, rewrites v2 as v1, selects an
older declaration, restores an old ref head, deletes authority history, or
re-enables an old authorization-sensitive cache entry.

## Required Canonical and Migration Fixtures

The implementation fixture family is mandatory in Rust first and in every
future generated or persisted surface before that surface is exposed.

| Fixture | Input and assertion |
| --- | --- |
| `authorization-v2-same-revision-positive` | Exact canonical authorization bytes above plus an RFC 0013 declaration at revision 7 with the exact matching entry. Grammar and same-revision comparison succeed; no runtime allow is claimed. |
| `secret-ref-v2-same-revision-positive` | Exact canonical ref bytes above and matching declaration revision 7. Behavior-free grammar, canonical bytes, and same-revision comparison succeed; live current-authority behavior remains deferred. |
| `authorization-v2-cross-revision-denied` | Keep every authorization byte except compare it to otherwise byte-identical declaration revision 8. Deny `driver_declaration_revision_mismatch`; declaration 7 is not substituted and 8 is not inferred. |
| `authorization-v2-stale-revision-denied` | Exact revision 7 exists but is stale or revoked. Deny `driver_declaration_revision_not_active`; revision 8 is not selected. |
| `secret-ref-v2-refresh-required` | Attempt to replace binding revision 7 with 8 under ref revision 2. Deny `secret_ref_revision_refresh_required`; a fresh ref revision and authority are required. |
| `secret-ref-v1-historical-read-deny` | Exact v1 bytes parse only into the historical view. Audit/replay read succeeds and live comparison returns `historical_revisionless_authorization_live_denied`. |
| `secret-ref-v1-migration-proven` | Exact source digest, historical issuance proof bound to revision 7, admitted declaration evidence, expected ref head, and fresh authority produce exactly the canonical ref v2 target above at revision 2. Source v1 bytes remain unchanged. |
| `secret-ref-v1-migration-unproven` | Remove or alter the source-to-revision evidence. Deny `driver_declaration_revision_unproven` with zero target bytes/head mutation. |
| `secret-ref-v1-migration-cross-revision` | Source proof binds revision 7 while declaration evidence or proposed target names 8. Deny `driver_declaration_revision_mismatch`; numeric ordering and active revision do not repair it. |

Negative grammar fixtures cover every missing, null, wrong-kind, duplicate,
unknown, alias, wildcard, zero, maximum-plus-one, noncanonical ID, bad operation,
bad schema, profile mismatch, digest form, empty/17-element set, body/depth/token/
member/element/string cap, and error-precedence conflict. Set permutations must
produce identical canonical bytes; changing any coordinate must change bytes and
equality.

Persistence tests must prove the schema string and revision survive insert,
read, export, import, restart, and inspect-only replay. No store may project the
revision to a side column that is omitted from canonical record bytes or accept a
row whose side index disagrees with those bytes.

## Security Properties

- The declaration revision prevents a credential authorization from following a
  mutable or inferred driver declaration head.
- Exact operation, slot, schema, digest set, exposure, and trusted-send matching
  prevents cross-operation, cross-slot, cross-destination, and cross-profile
  credential reuse.
- Fresh ref revision plus fresh authority prevents an old C03 decision from
  silently authorizing a changed driver contract.
- Historical read/deny preserves audit and replay without turning old bytes into
  current authority.
- Bounded strict parsing and non-reflecting errors prevent hostile contract
  amplification and destination/digest enumeration.
- Driver Registry remains the declaration owner; C03 cannot launder authority
  through a copied field, broker translation, or hidden relation.
- A validated record contains no secret material, provider locator, endpoint,
  token, password, API key, raw provider request/error, permit, lease, or
  delivery handle.

This RFC does not make a `SecretRefV2` sufficient authority. Live use still
requires the complete RFC 0012 intersection and every required fail-closed
Gateway verifier. Unavailable declaration lifecycle or current Authority state
denies rather than selecting a cached or older value.

## Trace, State, Replay, and Runtime Impact

This proposed contract has no runtime impact.

| Surface | Impact authorized by acceptance |
| --- | --- |
| Trace/evidence | None for behavior-free construction. Future migration must record explicit source, proof, decision, and new-ref links under a later implementation contract. No secret material or unrestricted digest is emitted. |
| State/store | None in this RFC. Future behavior-free persisted fixtures retain exact schema/revision bytes; only Authority may later move a ref head. |
| Replay | Historical v1 and v2 values may be inspected. Replay cannot create authority, migrate, move a head, select a declaration, issue a lease, or execute a side effect. |
| Gateway/driver/provider/node | None. No lookup, projection, verification, lease, material, delivery, or invocation path is added. |
| Daemon/API/SDK/generated | None. Any future surface must reproduce the canonical fixture family before exposure. |
| Gold/conformance | No status changes. `G07`, `G08`, and all C03 task evidence remain not exercised/incomplete. |

## Compatibility

This is an additive experimental v2 successor, not an in-place additive field.
Adding an authorizing field to v1 while retaining its schema string would change
canonical bytes and authority semantics and is forbidden.

The following remain byte-for-byte and semantically unchanged:

- RFC 0013 `DriverOperationRef`, `SecretCredentialSlotId`,
  `DriverOperationCredentialSinksV1`, sink entries, trusted-send profiles,
  declaration canonical bytes, destination schema, and digest type;
- RFC 0012 behavior-free `SecretUseRequirement` schema and meaning;
- stable 0.1 `Action`, `ActionRequest`, `ActionOutcome`, Gateway, trace, state,
  replay, work-order, daemon, Python, TypeScript, and OpenAPI contracts; and
- all current C03 V1a identity, enum, provider-version, and lease-policy bytes.

`SecretUseRequirement` remains a non-authorizing request. It contains no driver
declaration revision, destination schema, destination digest, exposure profile,
trusted-send profile, ref revision, lease, provider, or authority decision. C03
binds it server-side to the exact v2 ref authorization only in a later accepted
runtime slice. A caller cannot repair or override a revision through the
requirement, action params, metadata, prompt, message, work order, SDK, or
adapter.

There is no dual live-reader negotiation: a privileged C03 boundary accepts
only exact v2 for new or migrated live refs. V1 remains historical read/deny.
Unknown future schema versions fail closed.

Any later serialized command, event, state, evidence, API, or generated schema
that embeds the v2 ref or authorization must receive its own compatible schema
version before exposure. RFC 0012's unimplemented v1 containing-record names do
not gain v2 authorizing semantics while retaining v1 bytes. This RFC does not
define or authorize those containing-record successors.

## Implementation and Review Order

If accepted, implementation may proceed only in this order:

1. Preserve the current RFC 0012 and RFC 0013 implementation baselines and pin
   this RFC's canonical fixture text independently.
2. Add only the behavior-free v2 constants, validated closed types, bounded
   parsers, checked constructors, getters, serializers, and code-only errors in
   `splendor-types`. Reuse RFC 0013 owner types and validation; do not copy or
   wrap `DriverOperationRef`, `SecretCredentialSlotId`, digest, or trusted-send
   profile.
3. Add grammar, canonical, same-revision, cross-revision, maximum, compile/API,
   and historical read/deny fixtures. The final types have `Serialize` and no
   `Deserialize`; no store or runtime behavior lands in this slice.
4. Run independent architecture/compatibility and security review. Prove stable
   conformance, dependency policy, and existing C03/Driver Registry bytes remain
   unchanged. Do not claim issue closure, runtime activation, or gold.
5. A separately reviewed C03 persistence/migration slice may add explicit
   historical views and the proof-bound Authority migration command only after
   the Driver Registry and Authority evidence-owner contracts required above
   exist. No mock or hidden side table satisfies that gate.
6. Complete credential authorization, ref-head mutation, caches, leases,
   projection use, Gateway integration, providers, nodes, SDKs, and gold remain
   blocked on their own accepted owner contracts and production-path evidence.

Acceptance of this RFC does not authorize steps 5 or 6 by itself.

## Non-Goals

This RFC does not define or implement:

- Rust/runtime/generated code in this proposal branch;
- a broker, ref store, ref head, Authority evaluator, migration executor, lease,
  cache, provider, node delivery, scanner, leak detector, or secret material;
- Driver Registry registration, admission, lifecycle, projection validation or
  execution, or a shadow declaration/revision field;
- a Gateway verifier, action normalization, adapter/driver invocation, daemon
  endpoint, CLI, Python, TypeScript, OpenAPI, or JSON Schema surface;
- projection isolation, resource accounting, destination discovery, digest-only
  lookup, latest selection, compatibility fallback, or runtime revision fencing;
- modification of RFC 0013 declaration bytes or standalone
  `DriverOperationRef` behavior;
- modification of `SecretUseRequirement` or permission for it to carry
  authority;
- trace/state/store migration behavior beyond the explicit future requirements;
- task/issue completion, release activation, RFC self-acceptance, or gold pass.

## Acceptance Gate

This RFC must remain Proposed until independent reviewers confirm all of:

- architecture/compatibility review confirms C03/Authority ownership, unchanged
  Driver Registry and stable 0.1 bytes, versioned v2 rather than v1 mutation, no
  wrapper/translation/side table, and behavior-free implementation scope;
- security review confirms the complete revision-bearing coordinate, fresh-ref
  and fresh-authority rule, strict live v2-only behavior, historical read/deny,
  proof-bound migration, fail-closed unavailable state, bounded ingress, and
  non-reflecting errors;
- contract review confirms every field, type, bound, order, canonical byte,
  validation stage, error, fixture, migration, rollback, compatibility rule,
  implementation gate, and non-goal is internally consistent; and
- reviewers confirm acceptance authorizes only a later behavior-free C03
  grammar slice and no runtime behavior, issue closure, release claim, or gold
  evidence.

If accepted, the acceptance record must add an accepted date and proposal
SHA-256 without altering the reviewed normative body. This proposal must not
self-accept.
