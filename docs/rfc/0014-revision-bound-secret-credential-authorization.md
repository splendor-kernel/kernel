# RFC 0014 - Revision-Bound Secret Credential Authorization

## Status and Binding

**Status:** Accepted planning contract

**Accepted:** 2026-07-19

**Accepted proposal SHA-256:**
`0d93b37f6417519db393b49c032e1e5ec8b8509e485e0af5446d010a349153a3`

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
only the subsequent behavior-free C03 v2 grammar, closed historical view, pure
comparison API, and fixtures described here.

## Decision

RFC 0012's `splendor.secret.credential_authorization.v1` omits the positive
driver declaration revision that RFC 0013 requires for safe use of a driver
credential-sink declaration. C03 will not change those accepted v1 bytes in
place. It will use two additive successor schemas:

- `splendor.secret.credential_authorization.v2`, represented in Rust as
  `SecretCredentialAuthorizationV2`; and
- `splendor.secret.ref.v2`, represented in Rust as `SecretRefV2`.

Every v2 credential authorization carries one explicit positive
`driver_declaration_revision`. For each approved destination digest, the exact
RFC 0013 `credential_destination_binding_subkey` is:

```text
(
  canonical DriverOperationRef bytes,
  driver_declaration_revision,
  SecretCredentialSlotId bytes,
  destination_schema,
  one approved DriverCredentialDestinationDigest,
  SecretDeliveryExposureProfile,
  canonical DriverTrustedSendProfileV1 bytes
)
```

This seven-element value is only a destination-binding subkey. It is never a
complete authorization, cache, idempotency, permit, lease, or final-use key. One
authorization entry denotes the bounded semantic set of subkeys obtained by
substituting each value in its sorted `approved_destination_digests`. The
complete authorization-entry coordinate is the canonical entry bytes, including
that complete sorted digest set. Every component is authorizing input and
participates in equality, canonicalization, persistence, and migration. Live
cache, idempotency, permit, and use coordinates add all dimensions in the
Complete Live Coordinates and Final-Use Fencing section below. A match on fewer
components is never sufficient. A declaration revision change requires a fresh
`SecretRefV2` revision and a fresh current Authority decision even when every
other declaration byte is identical.

For uniqueness inside one ref, the authorization binding key is the canonical
entry coordinate without `approved_destination_digests`. Exactly one
authorization entry owns the complete digest set for one binding key. This
prevents splitting one binding across entries to evade set bounds while
preserving every digest as part of the complete authorizing coordinate.

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
| `HistoricalSecretCredentialAuthorizationV1` | Closed, non-live historical authorization view. |
| `HistoricalSecretRefV1` | Closed, non-live historical ref view and bounded parser. |
| `HistoricalSecretRefV1Error` | One fixed non-reflecting historical-parser error. |
| `HistoricalSecretRefV1LiveDenial` | One fieldless non-live denial result. |
| `compare_secret_credential_authorization_v2` | Exact pure function `pub fn compare_secret_credential_authorization_v2(authorization: &SecretCredentialAuthorizationV2, ref_classification: &SecretClassification, requirement_intent: &SecretUseIntent, declaration: &DriverOperationCredentialSinksV1) -> SecretCredentialDeclarationComparisonV2`; it performs no lookup, authority decision, persistence, or I/O. |
| `SecretCredentialDeclarationComparisonV2` | Behavior-free comparison result; never authority or proof. |
| `SecretCredentialDeclarationMismatchCodeV2` | Closed, code-only declaration/context mismatch taxonomy. |

Both validated v2 records implement `Serialize` and do not implement
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

The object is grammar-valid without registry I/O. Given the exact containing-ref
classification and requirement intent, it is contextually valid only when pure
comparison against the exact supplied declaration at revision 7 finds the named
operation, slot, destination schema, exposure profile, trusted-send profile,
classification, and intent. Neither success is a live allow. Live use remains
blocked until purpose/current authority and every later C03 runtime gate also
succeeds.

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
3. exact comparison of the operation, slot, destination schema, exposure
   profile, and trusted-send profile against that declaration;
4. fresh current Authority evaluation of the complete new ref specification and
   every applicable tenant, principal, work-order, purpose, policy, data-use,
   revocation, expiry, and scope fact; and
5. invalidation or fencing of every authorization-sensitive cache entry whose
   complete coordinate contains the prior ref or declaration revision before the
   new revision can be selected.

A changed declaration revision is a semantic change even if its declaration
bytes happen to be identical. Reusing the current ref revision, mutating an
authorization in place, copying an old Authority decision, or accepting an old
lease as proof is forbidden. This RFC specifies the blocking final-use fencing
requirements below but does not authorize their implementation. No old-revision
lease may gain new use from the new declaration.

## Behavior-Free Declaration Comparison

The first behavior-free slice exposes this exact pure function:

```rust
pub fn compare_secret_credential_authorization_v2(
    authorization: &SecretCredentialAuthorizationV2,
    ref_classification: &SecretClassification,
    requirement_intent: &SecretUseIntent,
    declaration: &DriverOperationCredentialSinksV1,
) -> SecretCredentialDeclarationComparisonV2;
```

It performs no lookup, current/lifecycle selection, persistence, migration,
authority evaluation, purpose evaluation, lease issuance, cache access, or I/O.
All arguments are already validated behavior-free values. The caller must obtain
`ref_classification` from the exact containing `SecretRefV2` and
`requirement_intent` from the exact `SecretUseRequirement`; supplying arbitrary
values cannot authorize anything.

The result is closed and non-serializable:

```rust
pub enum SecretCredentialDeclarationComparisonV2 {
    Matched,
    Denied(SecretCredentialDeclarationMismatchCodeV2),
}
```

`Matched` is neither a wrapper nor a capability, proof, receipt, decision,
permit, lease, cache value, or evidence record. The mismatch enum is closed to
these exact code-only values:

```text
driver_operation_mismatch
driver_declaration_revision_mismatch
credential_slot_not_declared
destination_schema_mismatch
delivery_exposure_profile_mismatch
trusted_send_profile_mismatch
secret_classification_not_allowed
secret_use_intent_not_allowed
```

The comparison returns the first mismatch in this exact order:

1. compare exact canonical `driver_operation`;
2. compare exact positive `driver_declaration_revision`;
3. select exactly one declaration entry by `credential_slot_id`, with no
   positional, latest, alias, or fallback selection;
4. compare exact `destination_schema`;
5. compare exact `delivery_exposure_profile`;
6. compare exact canonical `trusted_send_profile`;
7. require the exact ref classification to be a member of that entry's
   `allowed_classifications`; and
8. require the exact requirement intent to be a member of that entry's
   `allowed_intents`.

Stages 1-6 are declaration binding. Stage 7 is ref contextual-classification
membership. Stage 8 is requirement-intent membership. The declaration owns no
purpose list: a live consumer must separately validate the exact requirement
purpose under current tenant, principal, work-order, capability, data-use,
policy, and revocation authority. A digest is not compared to the declaration,
because Driver Registry does not own C03's approved digest set; its exact
recomputed destination subkey is compared later under the complete live
coordinate.

The result and its code implement `Display` and `Debug` as only `matched` or the
exact snake-case code. They retain no candidate, field, index, declaration,
slot, ref, digest, provider coordinate, parser error, or source chain. The code
may be used by local canonical fixtures and dedicated restricted evidence. It
must not be copied to a generic outward error, log, metric label, trace,
discovery response, or unauthorized inspection response.

## Complete Live Coordinates and Final-Use Fencing

The destination-binding subkey is only one member of the complete live
authorization coordinate. A future live decision, authorization-sensitive
cache entry, idempotency semantic projection, lease, permit, delivery context,
and final-use record must bind all of these exact dimensions:

1. exact `tenant_id`;
2. authenticated `principal_id`, caller-credential identity/revocation
   generation, and caller credential's daemon or service audience;
3. exact current `work_order_id` plus its immutable digest/revision, capability
   binding, expiry, and revocation generation;
4. exact workload, run, attempt, action/invocation, node, instance, sandbox, and
   process coordinates required by the RFC 0012 execution binding;
5. exact `SecretRefId`, positive `secret_ref_revision`, current ref-head
   generation, and disabled/refresh generation;
6. exact `SecretClassification`, `SecretUseIntent`, and `SecretPurpose`;
7. exact current Authority decision identity/revision and the current policy,
   data-use, capability, work-order, and Authority revocation generations on
   which it depends;
8. exact Driver Registry tenant and installation scope, immutable admission
   identity and admission digest, canonical declaration digest, positive
   declaration revision, and observed lifecycle generation;
9. one exact `credential_destination_binding_subkey`; a decision over the whole
   authorization entry also binds the complete sorted approved-digest set and
   canonical authorization-entry bytes;
10. exact execution audience, including its workload/attempt and
    node/instance/sandbox/process binding; and
11. exact `SecretLeaseId`, lease revision/generation, ref/authority/Registry
    generations pinned by the lease, and the applicable `SecretUseAttemptId` or
    `SecretUseClaimId` for idempotent use.

Every stricter caller, work-order, placement, fencing, data-use, approval,
quota, target, delivery-control, or exposure-lineage coordinate required by RFC
0012 remains an additional member; this list narrows none of them. A cache at an
earlier stage may contain only dimensions then available, but it is an
intermediate non-authorizing fact and cannot be promoted to a later allow until
every later dimension is added and revalidated. Prefix keys, digest-only keys,
ref-ID-only keys, declaration-revision-only keys, cross-tenant partitions, and
any key omitting an applicable dimension above are forbidden.

Every future live path must pin the complete coordinate through normalization,
projection, lease, final permit, provider access, delivery, and use. Immediately
before provider access and immediately before each credential-bearing send or
other use, it must recheck all of:

- exact ref ID/revision is still the current enabled head;
- exact current Authority, policy, capability, work-order, data-use, approval,
  quota, and revocation generations still permit the same purpose and audience;
- exact Registry tenant/installation/admission identity and declaration
  revision/lifecycle generation are still active;
- exact workload/attempt, placement/fencing, node/instance/sandbox/process, and
  execution audience remain current; and
- exact lease ID/revision/generation remains active, unexpired, unrevoked,
  within use/send bounds, and bound to the same destination subkey.

An `active -> stale|revoked` Registry transition, current-ref-head change,
authority/policy/data-use/work-order revocation, audience/fence change, or lease
revocation that commits before a provider access or send/use wins the race. It
invalidates the cached allow, fences every outstanding lease/permit/use for the
old generation, and prevents new bytes from leaving. No successful earlier
comparison, cache hit, lease, or pre-send check can override the final recheck.
The later Registry/C03/Gateway owner contracts must define and prove these CAS
race winners before any runtime implementation lands.

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
| 8 | Require `delivery_exposure_profile` to be an exact known enum value | `invalid_exposure_profile_binding` |
| 9 | Validate the trusted-send object structurally by its own `kind`: exact member vocabulary, required fields, send limit, controls, uniqueness, and required boundary | `invalid_trusted_send_profile` |
| 10 | Validate only the exposure/profile-kind pair compatibility: `trusted_injection` with `trusted_injection`, or `material_exposed` with fieldless `not_applicable` | `invalid_exposure_profile_binding` |
| 11 | Require digest-array kind and cardinality | `empty_approved_destination_digests` or `too_many_approved_destination_digests` |
| 12 | Validate digest values in input order | `invalid_destination_digest` |
| 13 | Reject duplicate digest values before sorting | `duplicate_destination_digest` |
| 14 | Normalize semantic sets | Cannot fail |

Missing, null, or wrong-kind recognized fields fail at their named stage. An
unknown or wrong-kind exposure fails at stage 8 even if the profile is also bad.
A profile with unknown/wrong-kind `kind`, extra members, missing or invalid send
limit, controls, required boundary, or a payload on `not_applicable` fails at
stage 9 even if its exposure pairing would also fail. Only two independently
valid values with an incompatible pair reach stage 10. This exposure-enum,
profile-structure, then pair-compatibility precedence is deterministic.

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

Future live and migration owners may retain these separate internal denial codes
only in dedicated restricted evidence:

```text
driver_declaration_revision_unproven
driver_declaration_revision_mismatch
driver_declaration_revision_not_active
secret_ref_revision_refresh_required
current_authority_required
historical_revisionless_authorization_live_denied
migration_proof_entry_mismatch
migration_mapping_not_bijective
migration_shape_change_forbidden
migration_command_conflict
```

Grammar success never implies a live allow. At live comparison, the first
applicable order is behavior-free declaration binding, ref classification,
requirement intent, purpose/current authority, exact destination-subkey equality,
exact full-coordinate equality, active/current final-use rechecks, and only then
permit use. Missing or unavailable owner state denies at its stage. These codes
are not an outward result taxonomy.

## Visibility, Outward Denial, and Restricted Evidence

Authentication, endpoint-scope authorization, exact tenant binding, and current
ref-visibility authorization occur before any ref, historical evidence, Driver
Registry, migration ledger, command-idempotency, cache, declaration, or provider
lookup that can reveal object state. The dedicated command scope is exactly
`splendor.secrets.refs.migrate_revision_binding`; the dedicated historical-read
scope is exactly `splendor.secrets.refs.history.read`. Neither scope is implied
by tenant membership, generic secret use, trace/state read, ref administration,
operator role text, wildcard text, possession of an ID/digest, or the other
scope. Both also require current exact tenant/ref/principal/work-order,
capability, data-use, policy, revocation, and audit authority for the requested
operation.

After closed-schema validation, all hidden, absent, wrong-tenant,
wrong-principal, wrong-scope, unproven, entry/coordinate mismatch,
cross-revision, non-bijective, forbidden-shape-change, stale, revoked,
wrong-current-head, and exact-ID/changed-semantic conflict cases use RFC 0012's
one outward profile:

```text
HTTP status: 404
content-type: application/json
code: secret_not_available
body before padding:
{"code":"secret_not_available","message":"secret is not available","details":{}}
body length after right-padding with ASCII spaces: 256 bytes
non-HTTP code: secret_not_available, with no additional field
```

From completed caller authentication and closed-schema parse to response-header
readiness, the local profile pads each case into the same 20-40 ms class using a
monotonic clock. Under RFC 0012's at-most-50-concurrent, at-most-70%-host-CPU
conformance profile, 10,000 warm-cache observations per case must have median
differences no greater than 2 ms and two-sample Kolmogorov-Smirnov `D <= 0.05`.
Outside that load profile, an implementation may return only one uniform
service-unavailable response before object lookup, never a faster
object-specific result. No code path may vary body shape, headers, retry advice,
padding, lookup count exposed to the caller, or timing class by internal reason.

Exact reasons, proof/admission identities, source or target bytes/digests,
declaration revision/digest/lifecycle, destination digest, provider/ref
coordinate, current head, and conflict fact may appear only in owner-authenticated
restricted evidence after current dedicated-scope and ref-visibility checks.
Every successful historical export or restricted denial inspection requires an
audit append that identifies inspector principal, tenant, ref, scope, current
authority/policy/revocation revisions, released view, and result; audit failure
withholds the view. Historical export returns only the already-authorized exact
historical record, never provider material, and does not grant migration or live
use.

Validated or successful refs, historical views, migration commands/results,
comparison results, declaration/provider coordinates, destination digests, and
proof records must omit or redact those values from `Debug`, `Display`, generic
errors and source chains, logs, metrics and labels, generic traces/evidence,
discovery/list responses, crash/debug bundles, and unauthorized responses.
Candidate bytes and identifiers rejected before visibility are dropped rather
than persisted in those surfaces. Dedicated restricted evidence is not a generic
trace or observability escape hatch.

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

The behavior-free historical surface is exact:

```rust
impl HistoricalSecretRefV1 {
    pub fn from_json_slice(input: &[u8])
        -> Result<Self, HistoricalSecretRefV1Error>;

    pub fn credential_authorizations(
        &self,
    ) -> &[HistoricalSecretCredentialAuthorizationV1];

    pub fn live_denial(&self) -> HistoricalSecretRefV1LiveDenial;
}
```

The two historical view types implement deterministic `Serialize`, getters, and
equality over their complete validated canonical values. They do not implement
`Deserialize`, a live-type conversion, a v2 constructor, migration, lookup,
authority, or current-head selection. `HistoricalSecretRefV1Error` contains only
the closed code `invalid_historical_secret_ref`; `Display` and `Debug` emit only
that code and retain no input or source chain. `HistoricalSecretRefV1LiveDenial`
has exactly one fieldless variant,
`HistoricalRevisionlessAuthorizationLiveDenied`, displayed and debugged only as
`historical_revisionless_authorization_live_denied`. It is non-serializable and
cannot be converted to a v2 comparison result. The parser applies the ref-v2
budget, validates every exact frozen v1 field and nested authorization rule,
rejects duplicates before sorting, and canonicalizes with the same v1 semantic-
set ordering that produced the accepted bytes.

After validation, historical authorization entries are ordered by their exact
canonical JCS bytes. Each entry has one zero-based `source_entry_ordinal` in that
order and this non-substitutable source identity:

```text
source_entry_identity = (
  exact SecretRefId,
  exact positive source secret_ref_revision,
  source_entry_ordinal
)
```

Its exact canonical entry bytes are
`RFC8785_JCS(HistoricalSecretCredentialAuthorizationV1)`. Its digest uses:

```text
entry_digest_input =
  UTF8("splendor.secret.credential_authorization.v1") || 0x00 ||
  canonical_source_entry
source_entry_digest =
  "blake3:" || lowercase_hex(BLAKE3-256(entry_digest_input))
```

The identity, ordinal, canonical entry bytes, entry digest, source-ref identity,
source ref revision, and source-ref digest are all required migration-proof
bindings. None can substitute for another. Reordering raw input cannot change
the canonical ordinal; duplicate canonical entries reject rather than share an
identity.

The migration fixture source corresponding to the v2 example has
`secret_ref_revision = 1`, removes only `driver_declaration_revision`, and uses
the two v1 schema strings. Its exact canonical bytes are:

```json
{"allowed_credential_bindings":[{"approved_destination_digests":["blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],"credential_slot_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f4001","delivery_exposure_profile":"trusted_injection","destination_schema":"example.driver.https_destination.v1","driver_operation":{"driver":"example_driver","operation":"example_operation","schema_version":"splendor.driver.operation.v1"},"schema_version":"splendor.secret.credential_authorization.v1","trusted_send_profile":{"applicable_delivery_controls":["destination_network_egress","trusted_injection_boundary"],"kind":"trusted_injection","max_credential_bearing_sends":1}}],"allowed_delivery_methods":["inherited_fd"],"classification":"authentication_credential","created_at":"2026-07-19T00:00:00.000000Z","lease_policy":{"clock_skew_tolerance_seconds":0,"max_continuous_lifetime_seconds":3600,"max_lease_duration_seconds":300,"max_uses":1,"renewable":false},"logical_name":"billing_api","offline_behavior":"deny","provider_namespace":"example","provider_version_ref":"release-007","schema_version":"splendor.secret.ref.v1","secret_provider_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5003","secret_ref_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5001","secret_ref_revision":1,"tenant_id":"018f0a1b-2c3d-4e5f-8a9b-0c1d2e3f5002"}
```

Historical readers may validate, canonicalize, export only under the dedicated
visibility/audit rules above, and inspect these bytes. They mark each record
`historical_revisionless_authorization_live_denied`. They do not return a live
`SecretCredentialAuthorizationV2` or `SecretRefV2`, move a ref head, issue a
lease, contact a registry/provider/node, invoke the Gateway, or create fresh
authority.

### Explicit proof-bound migration path

Authority Service is the sole migration decision owner. A migration is an
authenticated, separately authorized ref-update command, not parser fallback.
It requires the exact `splendor.secrets.refs.migrate_revision_binding` scope,
the dedicated visibility checks above, and the imported RFC 0012
`SecretRefMutationCommandId`. That nominal ID cannot be replaced by a request
ID, ref ID, evidence ID, digest, trace ID, work-order ID, or target revision.

The source-ref digest has exact wire form `blake3:` plus 64 lowercase
hexadecimal characters and this exact construction:

```text
canonical_source = RFC8785_JCS(HistoricalSecretRefV1)
digest_input = UTF8("splendor.secret.ref.v1") || 0x00 || canonical_source
source_ref_digest = "blake3:" || lowercase_hex(BLAKE3-256(digest_input))
```

There is no alternate algorithm, prefix, field projection, whitespace form, or
digest over unvalidated input. The future migration fixture must independently
pin the 32 digest bytes and exact 71-byte wire value.

Target ref and target-entry digests use the same construction with exact domains
`splendor.secret.ref.v2` and
`splendor.secret.credential_authorization.v2`, respectively, followed by one
zero byte and the complete validated target ref or entry JCS bytes. No digest is
computed over a field projection, unordered input, side column, or proposed
bytes that failed closed validation.

#### Exact per-entry proof bundle

The command contains one ordered proof bundle per canonical historical source
entry. Proof bundles are ordered by `source_entry_ordinal`; duplicates, gaps,
reordering, or a count different from the source authorization count reject.
Each bundle binds all of these facts directly, not by an implementation-defined
join:

```text
source_entry_identity
source_entry_ordinal
source_entry
source_entry_digest
authority_historical_evidence_id
authority_historical_evidence_digest
registry_admission_evidence_id
registry_admission_evidence_digest
registry_installation_id
registry_installation_scope_digest
registry_admission_id
registry_admission_digest
registry_declaration_digest
registry_lifecycle_generation
proven_driver_declaration_revision
target_entry_ordinal
target_entry
target_entry_digest
```

Those are the exact eighteen non-null members of one future command proof-bundle
object. `source_entry` and `target_entry` are the complete closed historical-v1
and v2 authorization objects, not strings or projections. Evidence IDs are
owner-nominal IDs and evidence digests bind the complete separately contracted
owner records described below. The explicit Registry fields must equal the
Registry-owned facts in the Registry record and the same Registry coordinates
bound by the Authority historical record. This exact three-way equality makes
installation/admission/declaration/lifecycle substitution fail before target
construction without making Registry own a C03 source entry. Unknown, missing,
null, duplicate, alias, side, or extension members reject before evidence
lookup.

| Binding | Exact required facts |
| --- | --- |
| Source ref | Exact `SecretRefId`, positive source `secret_ref_revision`, complete canonical source-ref JCS bytes, and `source_ref_digest`. |
| Source entry | Exact `source_entry_identity`, zero-based canonical ordinal, complete canonical entry JCS bytes, `source_entry_digest`, canonical operation, slot, destination schema, exposure profile, trusted-send profile, and complete sorted approved-digest set. |
| Authority historical evidence | Immutable Authority evidence identity, schema/version, canonical digest, integrity/signature-chain identity, exact tenant, source-ref identity/revision/digest, source-entry identity/ordinal/digest/coordinate and complete sorted approved-digest set, issuance-or-import decision identity, the one exact positive declaration revision proven for that entry, and the exact Registry evidence identity/digest plus tenant scope, installation/scope, admission/digest, operation, declaration revision/digest, slot, and lifecycle generation to which that Authority decision was bound. |
| Driver Registry admission evidence | Immutable Registry evidence identity, schema/version, canonical digest, integrity/signature-chain identity, exact tenant scope, installation identity and scope, immutable admission identity and admission digest, canonical operation, positive declaration revision, complete canonical declaration digest, exact slot-entry bytes/fingerprint, lifecycle state `active`, and the exact monotonic lifecycle generation observed for migration. It contains no C03 ref, source-entry identity/digest, approved destination set, or C03 decision. |
| Target entry | Target canonical ordinal, complete canonical v2 entry JCS bytes and digest, and the exact proven declaration revision inserted into that target entry. Target ref revision, creation time, complete bytes, and ref digest are later Authority allocation results and are not proof-bundle facts. |

The Authority and Registry evidence identities are distinct. Authority
historical evidence alone binds the C03 source-ref and source-entry identity,
digest, coordinate, and complete approved-digest set to the exact Registry
evidence identity, digest, and Registry-owned coordinates listed above. Registry
evidence binds only its tenant/installation/admission/operation/declaration/slot/
lifecycle facts. Migration proves the join by requiring the Registry evidence
identity, digest, and every Registry coordinate in the proof bundle and Authority
record to equal the Registry record byte-for-byte. Evidence for one entry, ref,
tenant, installation, admission, operation, slot, declaration digest/revision,
or lifecycle generation cannot prove another even when numbers or bytes happen
to match. Registry never attests a C03 ref, source-entry identity or digest,
approved destination set, ref classification, provider coordinate, lease policy,
or target ref byte.

A caller assertion, unsigned manifest, matching number, current registry head,
operation lookup, declaration byte similarity, timestamp, filename, database
row/order/join, import order, provider metadata, or hidden relation proves none
of these facts. If Authority evidence did not historically bind the exact C03
entry to the exact Registry evidence record and coordinates, or Registry
evidence did not bind every Registry-owned fact, that entry's revision is
unproven and migration to live authority is impossible.

#### Bijective shape-preserving transform

The command must prove one bijection from canonical source entries to canonical
target entries. Every source identity/ordinal appears exactly once, every target
ordinal appears exactly once, and every Authority or Registry evidence identity
or digest appears in only its one mapped proof bundle. Omitted, duplicated,
swapped, reused, many-to-one, one-to-many, or extra entries deny. Target sorting
may give an entry a different ordinal after the revision field is inserted, so
the explicit source-to-target mapping and both canonical entry digests are
mandatory; ordinal coincidence is not proof.

For each mapped entry, the target is the deterministic source entry with only:

1. `schema_version` changed from
   `splendor.secret.credential_authorization.v1` to
   `splendor.secret.credential_authorization.v2`; and
2. the exact separately proven positive `driver_declaration_revision` inserted.

The normalized migration target specification follows RFC 0012's command-only
`SecretRefSpec` ownership rule. It contains exactly these eleven semantic
members: `secret_ref_id`, `tenant_id`, `secret_provider_id`,
`provider_namespace`, `logical_name`, `provider_version_ref`, `classification`,
`allowed_credential_bindings`, `allowed_delivery_methods`, `lease_policy`, and
`offline_behavior`. The binding array contains the mapped v2 entries above in
canonical order. The specification contains no target schema field,
`secret_ref_revision`, `created_at`, `disabled_at`, target ref digest, generated
identity, or owner time.

After the first durable command claim and an allow decision, Authority constructs
the one target from that retained specification and source record by only:

1. setting `schema_version` to `splendor.secret.ref.v2`;
2. allocating one fresh positive Authority-owned `secret_ref_revision`;
3. allocating one Authority-owned target-revision `created_at` not earlier than
   the source revision's `created_at`;
4. copying the source's optional Authority-owned `disabled_at` unchanged when it
   is present; and
5. inserting the specification's mapped v2 entries.

Every semantic proposal value is byte-for-byte preserved after canonical
parsing: ref ID, tenant, provider ID/namespace/version, logical name,
classification, allowed delivery methods, lease policy, offline behavior, every
operation/slot/destination-schema/exposure/profile value, and every approved
digest. The target revision, creation time, complete target bytes, and target ref
digest are owner results retained after allocation, not caller-selected or
pre-claim command facts. Command/result/event identities and first-observation
times are other owner facts outside `SecretRefV2`; they do not permit another
target-field change. A target specification that changes any other semantic
value is not migration. It must deny here and, if desired, be submitted later as
a separately authorized ordinary v2 update with a fresh nominal command ID,
expected head, current authority, and ref revision after migration completes.

The exact Authority issuance/import-evidence and Driver Registry admission-
evidence schemas are prerequisites owned by their respective components. No
migration implementation may land until separately accepted contracts pin those
schemas, identities, signatures or integrity chains, revocation behavior,
canonical bytes, lifecycle-current query/evidence, and retention. This RFC does
not permit ad hoc maps, database joins, unsigned rows, or implementation-defined
evidence in their place.

#### Authority migration command and semantic idempotency

The future closed command schema is exactly
`splendor.secret.ref_revision_migration_command.v1`. It is a closed object with
these exact fifteen required, non-null members:

| Field | Exact command content |
| --- | --- |
| `schema_version` | Exact command schema above. |
| `secret_ref_mutation_command_id` | Exact imported RFC 0012 nominal command ID. |
| `actor_binding` | Exact RFC 0012 `SecretCommandActorBinding`, containing only authenticated `tenant_id`, authenticated `actor_principal_id`, the complete current `SecretAuthorityBinding`, and `causal_ref`; its tenant and principal equal the authority binding. |
| `observed_at` | Exact RFC 0012 Authority-owned first-observation timestamp. It is allocated and retained by Authority during the first atomic claim and is never accepted from caller bytes. |
| `required_scope` | Literal `splendor.secrets.refs.migrate_revision_binding`. |
| `service_audience` | Exact authenticated Authority-service audience. |
| `work_order_id` | Exact current work order authorizing this migration. |
| `work_order_digest` | Canonical digest of that immutable signed work order. |
| `migration_purpose` | Literal `bind_historical_driver_declaration_revisions`. |
| `source_ref` | Complete validated `HistoricalSecretRefV1`, including source ID/revision/tenant and exact canonical entries. |
| `source_ref_digest` | Exact source digest defined above. |
| `proof_bundles` | Non-empty ordered array with exactly one closed eighteen-member proof bundle per canonical source entry. |
| `expected_head` | Closed object defined below. |
| `migration_target_spec` | Complete closed eleven-member command-only specification defined above. It excludes target schema, revision, creation/disable time, complete target bytes, and target ref digest. |
| `expected_current_generations` | Closed object defined below. |

The explicit `work_order_id` and `work_order_digest` are semantic fields and
remain in equality even though work order is not part of the stable nominal-
command lookup scope below. `work_order_id` must equal the binding's required
work-order ID. `work_order_digest` is independently validated against that same
current immutable signed work order because RFC 0012's
`SecretAuthorityBinding` does not carry a work-order digest. The command-level
`causal_ref` is inside `actor_binding`; no duplicate top-level causal or
authority field is permitted.

`expected_head` contains exactly `secret_ref_id`, positive
`secret_ref_revision`, `secret_ref_digest`, and positive
`secret_ref_head_generation`. `expected_current_generations` contains exactly
these owner-validated current counters, positive wherever the owner grammar
requires:

```text
secret_ref_head_generation
secret_ref_refresh_generation
authority_revision
policy_revision
revocation_snapshot_generation
capability_grant_revision
work_order_revision
work_order_revocation_generation
data_use_decision_revision
data_use_revocation_generation
```

The nested generation values must equal their corresponding complete Authority,
work-order, capability, data-use, and ref evidence. Each proof bundle's separate
`registry_lifecycle_generation` must equal its exact Registry evidence and is
rechecked independently. Unknown,
missing, null, duplicate, alias, default, metadata, `extensions`, caller time,
generated result/event ID, or alternate authority field rejects. Audit
attribution is derived from authenticated context and retained in the decision,
event, and result; it is not caller-supplied command content.

At first decision and again at head CAS, the expected current ref-head
ID/revision/digest must equal the exact source ref identity/revision/digest. A
historical ref that is no longer the current head cannot overwrite or branch from
a newer head through this migration path.

The closed normalized semantic projection has exactly two members:
`schema_version`, equal to
`splendor.secret.ref_revision_migration_semantic_projection.v1`, and
`command_semantics`, containing all fourteen semantic command members other than
Authority-owned `observed_at`, including the complete actor binding, work-order
ID/digest, source, proof bundles, expected values, and migration target
specification. It contains no target ref revision, target creation time, complete
target bytes, target ref digest, completion time, audit record, generated
result/event ID, or physical outbox/store metadata. RFC 8785 JCS determines exact
member order. This follows RFC 0012's semantic-idempotency exclusion of
Authority-owned observation/result facts. Its digest is:

```text
migration_semantic_digest_input =
  UTF8("splendor.secret.ref_revision_migration_semantic_projection.v1") ||
  0x00 || RFC8785_JCS(complete_semantic_projection)
migration_semantic_digest =
  "blake3:" || lowercase_hex(BLAKE3-256(migration_semantic_digest_input))
```

Authority maintains one stable nominal-command non-reuse index keyed exactly by
authenticated `tenant_id`, authenticated `actor_principal_id`, command kind
`ref_revision_migration`, and `SecretRefMutationCommandId`. Work-order identity,
work-order digest, service audience, ref identity, expected values, and every
other request/body field are deliberately absent from this lookup key. The key
is derived from authenticated context plus the nominal ID, never from an
untrusted actor binding. Therefore a retry under another otherwise-valid work
order reaches the retained nominal command and cannot become a fresh miss.

Authority completes authentication, dedicated-scope, tenant/ref-visibility,
current work-order/capability/data-use, revocation, service-audience, and audit
checks before any stable-index lookup or claim, then derives the stable key. In
one atomic compare-insert, the first accepted observation claims the non-reuse
index and retains the complete normalized semantic projection/digest, the
Authority-owned `observed_at`, and the resulting fifteen-field command in
`accepted` state. No target revision, target creation time, target bytes, target
digest, target row, or ref orphan exists at this point. Authority reruns those
current checks before releasing prior state or a retained result.

The retained row later adds, but never replaces, the canonical decision/state,
the one owner-allocated target revision, creation time, exact bytes, and digest,
and the terminal or in-progress result. The ordered proof bundles and expected
heads/generations remain the exact command facts retained at claim. Nominal
command IDs are never reusable within the stable key's owner retention horizon.
When full records reach their accepted retention limit, Authority keeps a
permanent non-reuse tombstone over that same stable key, semantic digest, whether
target allocation occurred, any allocated target revision/digest, and terminal
result digest. Deletion can never turn an exact or changed command into a fresh
miss.

An exact duplicate under the same stable key and with the same complete semantic
digest never reruns migration. After current visibility authorization, it returns
only the retained historical result or resumes the one retained in-progress
command. The same stable key with any changed semantic byte, including a changed
work-order ID/digest or authority binding, proof order/identity/digest, source or
target-spec byte, or expected head/generation, is
`migration_command_conflict`. The conflict is decided from the retained index
before any new command row, target allocation, target append/orphan, head move,
or other effect. Hidden, absent, unauthorized,
exact-duplicate-with-now-hidden-result, and conflict cases share the outward
profile above. A new target or refreshed expected value requires a fresh nominal
command ID; evidence links never authorize reuse under changed semantic bytes.

#### Command state, durable ordering, and recovery

The Authority-owned command state machine is closed to:

```text
accepted -> authorized -> target_allocated -> append_prepared -> target_appended -> head_committed -> completed
accepted -> denied
authorized -> denied
target_allocated -> denied
append_prepared -> denied
target_appended -> denied_stale_state
```

`denied`, `denied_stale_state`, and `completed` are terminal. State and result
transitions use owner-controlled CAS. The required ordering is:

1. derive and atomically claim the stable nominal-command index, retaining the
   normalized proposal/digest, Authority-owned `observed_at`, and complete
   command in `accepted` state;
2. validate both owner evidence chains and their exact cross-record equality,
   the bijection, shape-preserving migration target specification, expected
   head, and current generations without provider, node, Gateway, or driver
   effects;
3. retain the canonical allow decision and advance to `authorized`, or retain a
   terminal denial without allocating any target fact;
4. after authorization, atomically reserve exactly one fresh positive target
   ref revision, allocate exactly one owner creation time, construct the complete
   target from the retained specification/source, compute its canonical bytes
   and digest, and retain all four facts while advancing to `target_allocated`;
5. retain a unique prepared event or transactional outbox record before any
   target append;
6. append exactly the retained immutable target bytes once under unique
   `(SecretRefId, target secret_ref_revision)` and target digest; the same key
   with changed bytes is an invariant conflict, never an overwrite;
7. after a durable prepared/append acknowledgement, CAS the head only from the
   exact expected head/digest/generation to that already-appended target while
   atomically rechecking the retained current Authority/ref generations and the
   separately contracted current Registry lifecycle evidence;
8. retain one terminal decision/event/result binding the command, semantic
   digest, source, proof set, target, append result, head-CAS result, and final
   state; and
9. release a response only after the canonical event is durably appended or a
   unique outbox append has durable acknowledgement.

Target allocation in step 4 is one owner transaction/CAS. A crash cannot expose
an allocated revision without the same row also retaining its creation time,
complete bytes, and digest. Every duplicate and recovery path reuses those exact
facts; none invokes the allocator or owner clock again.

If Event/Evidence storage is separate, Authority writes the unique outbox in the
same transaction as each decision/state change. No response, live head, or
second command may treat an unacknowledged event as terminal. A stale head or
generation after target append leaves that exact target immutable and non-live,
records `denied_stale_state`, and never allocates another revision for the same
command.

Exactly one Authority-owned migration reconciler may claim an in-progress row by
CAS. Recovery behavior is closed:

| Crash or loss point | Sole permitted recovery |
| --- | --- |
| Before first stable-index claim | No command state, target fact, or ref effect exists; an authenticated retry may make the first atomic claim. |
| After claim, before authorization decision | Resume validation only from the retained command/proposal and owner `observed_at`; denial allocates no target. |
| After authorization, before or during target allocation | Complete only the row's one CAS allocation transition. Read uncertain transaction state first; if `target_allocated`, reuse all retained facts, and if still `authorized`, atomically allocate and retain one revision/time/byte/digest tuple. Never invoke the allocator or clock after `target_allocated`. |
| After target allocation, before prepared append | Reuse only the retained target revision/time/bytes/digest and write the one prepared event/outbox. |
| After preparation, before target append | Append only the retained target bytes under the already-fixed target revision/digest. |
| After target append, before head CAS | Verify that exact append, then attempt only the original expected-head/current-generation CAS; stale state terminates as `denied_stale_state`. |
| After head CAS, before terminal event/result | Append/finalize only the retained terminal bytes proving the already-committed head; do not repeat the CAS or append. |
| After terminal commit, before response | An authorized exact duplicate returns the retained historical result; no mutation runs. |

The reconciler cannot mint or select another command/ref/evidence/event/result
identity, allocate a second ref revision/time/target, alter source/target/proof
bytes, change the decision, consult `latest`, invoke policy anew, or call
Registry, provider, node, Gateway, driver, adapter, lease, or delivery effects.
It may finish the sole `authorized -> target_allocated` owner CAS only as the
table specifies. Required current Registry evidence must already be a retained
owner-authenticated current-lifecycle input whose later contract permits the
step-7 atomic recheck;
otherwise migration remains blocked. Reconciliation exhaustion or unavailable
trusted state fails closed and requires intervention; it never retries under new
bytes.

Inspect-only replay may reconstruct this state machine and explain restricted
decisions. It cannot claim a command, validate as current authority, invoke the
reconciler, append a target/event, move a head, contact any owner/provider, or
make a historical result live.

On success, Authority appends one new immutable `SecretRefV2` revision under the
same `SecretRefId`, carries each separately proven revision into only its mapped
v2 entry, and CAS-moves the head once. It does not rewrite, annotate, delete, or
reinterpret v1 bytes. Migration evidence links remain audit/replay facts but are
not reusable authority. If any proof, owner, integrity check, comparison,
visibility, current authority/generation, event acknowledgement, or CAS is
absent, stale, revoked, unavailable, or ambiguous, migration fails closed with
no live head movement, lease, provider/node/Gateway call, or side effect.

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
| `authorization-v2-same-revision-positive` | Exact canonical authorization bytes above, ref classification `authentication_credential`, intent `authenticate`, and an RFC 0013 declaration at revision 7 with the exact matching entry. Grammar and the exact behavior-free comparison return `Matched`; no runtime allow is claimed. |
| `secret-ref-v2-same-revision-positive` | Exact canonical ref bytes above, intent `authenticate`, and matching declaration revision 7. Behavior-free grammar, canonical bytes, and comparison return `Matched`; live purpose/current-authority behavior remains deferred. |
| `authorization-v2-coordinate-mismatch-denied` | Independently change operation, declaration revision, slot, destination schema, exposure, or trusted-send profile on one side. The exact first applicable mismatch code returns; no positional slot or alternate revision is selected. |
| `authorization-v2-wrong-classification-denied` | Stages 1-6 match, but exact containing ref classification is absent from the slot's `allowed_classifications`. Return `secret_classification_not_allowed`. |
| `authorization-v2-wrong-intent-denied` | Stages 1-7 match, but exact requirement intent is absent from the slot's `allowed_intents`. Return `secret_use_intent_not_allowed`; purpose is not inferred. |
| `authorization-v2-cross-revision-denied` | Keep every authorization byte except compare it to otherwise byte-identical declaration revision 8. Deny `driver_declaration_revision_mismatch`; declaration 7 is not substituted and 8 is not inferred. |
| `authorization-v2-stale-revision-denied` | In the later lifecycle suite, exact revision 7 exists but is stale or revoked. Deny internally as `driver_declaration_revision_not_active`; revision 8 is not selected. |
| `secret-ref-v2-refresh-required` | In the later Authority mutation suite, attempt to replace binding revision 7 with 8 under ref revision 2. Deny internally as `secret_ref_revision_refresh_required`; a fresh ref revision and authority are required. |
| `secret-ref-v1-historical-read-deny` | Exact v1 bytes parse only into the historical view. Audit/replay read succeeds and live comparison returns `historical_revisionless_authorization_live_denied`. |
| `secret-ref-v1-migration-proven` | Exact source bytes/digest, per-entry identities/ordinals/bytes/digests, Authority evidence that binds each C03 entry to the exact Registry evidence ID/digest/coordinates, Registry-only tenant/installation/admission/operation/declaration/slot/lifecycle evidence, bijection, expected head/current generations, normalized semantic digest, and fresh authority cause Authority to allocate and retain exactly the canonical ref v2 target above at revision 2. Source v1 bytes remain unchanged. |
| `secret-ref-v1-migration-unproven` | Remove or alter any source-ref, source-entry, Authority-to-Registry evidence binding, Registry-owned fact, target-entry, scope, admission, declaration, or lifecycle coordinate. Registry evidence that purports to attest a C03 source entry is invalid rather than sufficient. Deny internally as unproven/mismatch with zero live head mutation. |
| `secret-ref-v1-migration-cross-revision` | Source proof binds revision 7 while declaration evidence or proposed target names 8. Deny `driver_declaration_revision_mismatch`; numeric ordering and active revision do not repair it. |
| `secret-ref-v1-migration-bijection-denied` | Multi-entry vectors swap or reuse proofs, duplicate/omit source or target entries, reuse an evidence identity, or create one-to-many/many-to-one mappings. Deny `migration_mapping_not_bijective`; no target becomes live. |
| `secret-ref-v1-migration-shape-change-denied` | Independently mutate every source/spec/entry semantic field other than the schema-version transform and each separately proven declaration revision. Target revision, creation time, complete bytes, and ref digest cannot be supplied in the proposal. Deny `migration_shape_change_forbidden`; an ordinary v2 update is not treated as migration. |
| `secret-ref-v1-migration-command-duplicate` | Drop responses at every state. An exact normalized semantic digest returns or completes only the retained original result and owner-allocated revision/time/bytes/digest. The same stable-key command ID with any changed semantic byte returns internal `migration_command_conflict`; no second row, allocation, revision, event, or effect is created. |
| `secret-ref-v1-migration-command-work-order-conflict` | First claim one command ID under valid work order A. Retry the same ID and authenticated tenant/principal under distinct valid work order B, changing `work_order_id`, `work_order_digest`, and the matching actor authority binding. The stable nominal-command index finds A and returns internal `migration_command_conflict` before any B row, target allocation, append/orphan, event, or head effect. |
| `secret-ref-v1-migration-crash-recovery` | Crash before/after stable claim, decision, atomic target allocation, preparation/outbox, target append, head CAS, terminal append, and response. Only the recovery-table transition occurs; every post-allocation path reuses one revision/time/bytes/digest tuple, stale head leaves one non-live immutable target, and replay/reconciler performs no external call. |
| `secret-ref-visibility-oracle-denied` | Hidden, absent, wrong tenant/principal/scope, unproven, mismatch, stale, revoked, wrong head, and conflict inputs produce byte-identical padded outward responses and satisfy the fixed timing profile. Exact facts appear only in authorized/audited restricted evidence. |
| `secret-ref-live-coordinate-mutation-denied` | In the later runtime suite, mutate each complete-live-coordinate dimension independently. Every mutation misses/denies, and prefix/digest/ref/revision-only cache keys are rejected. |
| `secret-ref-final-use-race-denied` | In the later runtime suite, commit ref/authority/policy/data-use/work-order/Registry/audience/lease stale or revoked state between normalization, lease, permit, provider access, and each send/use. The transition wins and fences outstanding use. |

Negative grammar fixtures cover every missing, null, wrong-kind, duplicate,
unknown, alias, wildcard, zero, maximum-plus-one, noncanonical ID, bad operation,
bad schema, invalid exposure, invalid trusted-send structure, incompatible valid
pair, digest form, empty/17-element set, body/depth/token/member/element/string
cap, and error-precedence conflict. Combined exposure/profile failures prove
stage 8 before 9 before 10. Set permutations must produce identical canonical
bytes; changing any coordinate must change bytes and equality.

Persistence tests must prove the schema string and revision survive insert,
read, export, import, restart, and inspect-only replay. No store may project the
revision to a side column that is omitted from canonical record bytes or accept a
row whose side index disagrees with those bytes.

The first behavior-free slice implements only grammar/canonical/comparison and
closed historical-parser fixtures that require no live owner state. Migration
command, owner evidence, persistence, visibility/timing, live-coordinate, cache,
lease, race, and final-use fixtures remain blocking specifications for their
later separately accepted owner slices; listing them here is not execution or
gold evidence.

## Security Properties

- The declaration revision prevents a credential authorization from following a
  mutable or inferred driver declaration head.
- Exact operation, slot, schema, digest set, exposure, and trusted-send matching
  prevents cross-operation, cross-slot, cross-destination, and cross-profile
  credential reuse.
- Fresh ref revision plus fresh authority prevents an old C03 decision from
  silently authorizing a changed driver contract.
- Declaration binding, contextual ref classification, requirement intent, and
  purpose/current authority are distinct stages, so a match at one cannot skip
  another.
- Per-entry source identities/digests and a bijective shape-preserving transform
  prevent proof swapping, proof reuse, and ordinary semantic edits disguised as
  migration.
- One stable nominal-command index, semantic proposal, retained owner allocation,
  CAS ordering, and no-second-revision recovery prevent work-order changes,
  response loss, or replay from creating another row, orphan, or live ref.
- Complete live coordinates and final-use generation checks prevent cache reuse
  across tenant/ref/purpose/audience/lease boundaries and make stale/revoked
  transitions win races.
- Historical read/deny preserves audit and replay without turning old bytes into
  current authority.
- Bounded strict parsing and non-reflecting errors prevent hostile contract
  amplification and destination/digest enumeration.
- Pre-lookup visibility and one padded outward profile prevent ref,
  declaration, lifecycle, proof, and conflict oracles.
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
| Trace/evidence | None for behavior-free construction. A later migration implementation must retain the command, semantic digest, per-entry owner proofs, decision, prepared/append/head/terminal links, and restricted audit attribution under the exact state/recovery contract above. Generic projections omit sensitive coordinates and digests. |
| State/store | None in this RFC. Future behavior-free persisted fixtures retain exact schema/revision bytes. A later Authority owner may append the one post-claim owner-allocated and retained target and CAS the head once; Store enforces uniqueness/CAS but never decides migration or recovery. |
| Replay | Historical v1 and v2 values and retained migration states may be inspected. Replay cannot claim/reconcile a command, create authority, migrate, append, move a head, select a declaration, issue a lease, or execute a side effect. |
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
2. Add the closed `HistoricalSecretCredentialAuthorizationV1` and
   `HistoricalSecretRefV1` views, bounded parser, canonical source-entry
   identity/ordinal/digest helpers, and denial-only errors in `splendor-types`.
   They must exist before any historical or migration fixture is written and
   expose no live conversion.
3. Add only the behavior-free v2 constants, validated closed types, bounded
   parsers, checked constructors, getters, serializers, code-only errors, and
   exact pure declaration/context comparison API in `splendor-types`. Reuse RFC
   0013 owner types and validation; do not copy or wrap `DriverOperationRef`,
   `SecretCredentialSlotId`, digest, declaration, or trusted-send profile.
4. Add grammar, canonical, comparison-coordinate, wrong-classification,
   wrong-intent, maximum, compile/API, and historical read/deny fixtures. The
   record types have `Serialize` and no `Deserialize`; comparison results are
   non-serializable. No store, lookup, evidence, migration, cache, lease, or
   runtime behavior lands in this slice.
5. Run independent architecture/compatibility and security review. Prove stable
   conformance, dependency policy, and existing C03/Driver Registry bytes remain
   unchanged. Do not claim issue closure, runtime activation, or gold.
6. Only after separately accepted Authority issuance/import-evidence, Driver
   Registry admission/lifecycle-evidence, and cross-owner current-generation
   recheck contracts exist may a separately reviewed Authority persistence/
   migration slice implement the exact command, stable nominal-ID non-reuse
   index, semantic idempotency ledger, post-claim owner target allocation,
   per-entry bijection and cross-owner evidence equality, event/outbox/CAS state
   machine, visibility profile, and one reconciler above. No mock, test helper,
   broad evidence row, database join, or hidden side table satisfies that gate.
7. Complete credential authorization, ref-head mutation, full-coordinate caches,
   idempotency, leases, final-use generation fencing,
   projection use, Gateway integration, providers, nodes, SDKs, and gold remain
   blocked on their own accepted owner contracts and production-path evidence.

Acceptance of this RFC authorizes only steps 2-4. It does not authorize steps 6
or 7 by itself.

## Non-Goals

This RFC does not implement any item below and does not authorize its later
implementation except through the separate owner gates stated above:

- Rust/runtime/generated code in this proposal branch;
- a broker, ref store, ref head, Authority evaluator, migration executor, lease,
  cache, provider, node delivery, scanner, leak detector, or secret material;
- Driver Registry registration, admission, lifecycle, projection validation or
  execution, or a shadow declaration/revision field;
- a Gateway verifier, action normalization, adapter/driver invocation, daemon
  endpoint, CLI, Python, TypeScript, OpenAPI, or JSON Schema surface;
- projection isolation, resource accounting, destination discovery, digest-only
  lookup, latest selection, compatibility fallback, or implementation of the
  specified runtime revision/final-use fencing;
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
  and fresh-authority rule, declaration/classification/intent stage separation,
  strict live v2-only behavior, historical read/deny, per-entry bijective
  shape-preserving migration, Authority-only C03-to-Registry evidence binding,
  stable command-ID non-reuse across work-order changes, post-claim owner target
  allocation and no-second-revision recovery, complete live coordinates/final-
  use fencing, pre-lookup visibility, fail-closed unavailable state, bounded
  ingress, and non-reflecting errors;
- contract review confirms every field, type, bound, order, canonical byte,
  validation stage, error, fixture, migration, rollback, compatibility rule,
  implementation gate, and non-goal is internally consistent; and
- reviewers confirm acceptance authorizes only a later behavior-free C03 v2
  grammar, closed historical view/parser, pure comparison API, and fixtures, with
  no runtime behavior, issue closure, release claim, or gold evidence.

If accepted, the acceptance record must add an accepted date and proposal
SHA-256 without altering the reviewed normative body. This proposal must not
self-accept.
