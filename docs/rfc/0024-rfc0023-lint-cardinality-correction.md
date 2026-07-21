# RFC 0024 - RFC 0023 Lint Cardinality Correction

## Status and Binding

**Status:** Accepted lint-cardinality correction

**Date:** 2026-07-21

**Accepted:** 2026-07-21

**Accepted proposal SHA-256:**
`aae38a7b333daa66ed2ee027fdf738db67401db68d86a8fcfee321612e3e385e`

**Active execution line:** `Splendor0.2-dev` / `0.2/v2`

**Program:** `V2-FND-0 Foundations`

**Catalog task:** `FND-006` / issue `#225`, partial offline Slice 1 only

**Primary contract:** [RFC 0023](0023-rfc0021-lint-evidence-addendum.md),
accepted proposal SHA-256
`5518211430bc007024d6b9d301fbd13f2bddf42ff56f4426ee81e37a69abfca3`

**Owner package:** `crates/splendor-types`

**Gold targets:** `G00` and `G72`; both remain
`specified_not_implemented` / `not_exercised`

This proposal corrects one empirical diagnostic-cardinality value in RFC 0023.
It changes no evidence schema, extractor law, comparison rule, implementation,
production Rust, Cargo input, feature, lint policy, suppression, toolchain, CI,
public contract, compatibility, migration, runtime, conformance, Gold, task,
issue, or release status.

Until accepted through separate architecture/compatibility and
security/privacy review, this correction grants no RFC 0023 disposition and the
RFC 0021 implementation remains blocked.

## Empirical Finding

RFC 0023 requires the paired baseline and candidate diagnostic identity
multisets to have total cardinality 21. Fresh, isolated execution of its exact
JSON diagnostic command shows instead:

```text
baseline total identities: 42
candidate total identities: 42
baseline unique identities: 21
candidate unique identities: 21
each unique identity multiplicity: 2
```

Cargo's `--all-targets` selection checks the unchanged PyO3 binding library in
both library and library-test compilation contexts. Each of the 21 unique source
locations is therefore emitted exactly twice. Preserving multiplicity is the
intended non-gameable behavior; deduplicating the multiset to force total 21
would violate RFC 0023.

Both runs exited 101, all 42 identities were the `deprecated` lint at one of the
same 21 unchanged `python/bindings/src/lib.rs` source locations, and no identity
was attributable to an RFC 0021 candidate file. No raw rendered diagnostic or
source snippet was retained.

## Decision

If accepted, this RFC replaces only RFC 0023 Decision condition 11 with:

> The warning multiset has total cardinality 42 and unique cardinality 21. Every
> unique identity occurs exactly twice. All identities are PyO3 `deprecated`
> diagnostics at the unchanged 21 source locations in
> `python/bindings/src/lib.rs`, with no warning attributable to any candidate
> path.

The RFC 0023 lexicographically sorted, length-prefixed encoded baseline and
candidate diagnostic identity multisets must still be byte-for-byte equal,
including multiplicity. Retained execution evidence records their equal
SHA-256 together with extractor source/version and candidate, toolchain, Cargo,
Clippy, host, flags, and configuration identities. Tool, extractor, encoding,
or configuration drift requires a new review; it must not be normalized to
force a match.

Every other RFC 0023 condition remains unchanged, including fresh isolated
targets, immutable candidate binding, exact failed status, deterministic
allowlisted extraction, no raw diagnostics, both narrower green commands,
remediation, expiry, and all no-go gates.

## Security and Compatibility Boundaries

This correction does not:

- convert 42 occurrences into 21 by deduplication;
- ignore occurrence multiplicity;
- change or suppress a diagnostic;
- classify a PyO3 warning as resolved or harmless;
- waive the exact command failure or remediation exit criterion;
- change stable 0.1 behavior, compatibility, or migration semantics; or
- complete `FND-006`, issue `#225`, C03, `FR-0.2-01`, `FR-0.2-08`, `G00`, or
  `G72`.

## Required Review and Evidence

Acceptance requires separate architecture/compatibility and security/privacy
review with P0/P1/P2 counts. Review must confirm the observed 42-total,
21-unique, multiplicity-two shape from the fixed extractor and verify that this
RFC changes no other RFC 0023 rule. Implementation-use review must also verify
the retained equal multiset digest and complete RFC 0023 provenance; no digest
is accepted from this proposal text alone.

Required proposal-acceptance validation, run against a committed proposal:

```sh
git diff --check 1198e413e77d8c6956ea149f5ec7d30ba55eff79...HEAD
git diff --name-status 1198e413e77d8c6956ea149f5ec7d30ba55eff79...HEAD
test -z "$(git status --porcelain=v1 --untracked-files=all)"
python3 scripts/architecture/check-dependency-policy.py
python3 scripts/architecture/check-dependency-policy.py --self-test
```

The proposal diff must contain only this RFC file with status `A`. Retained
evidence records proposal commit, tree, and file SHA-256. The relative RFC link
must resolve, Markdown fences must balance, and no implementation or completion
claim may appear.

## No-Go Gates

Acceptance or use stops if the paired evidence does not show exactly 42 total,
21 unique, multiplicity two for each identity, exact baseline/candidate equality,
only the unchanged PyO3 locations, and no candidate warning. Any deduplication,
raw diagnostic retention, identity drift, candidate warning, suppression, or
change to another RFC 0023 gate remains blocking.

## Acceptance Effect

Acceptance corrects only RFC 0023's lint identity cardinality. Every other RFC
0021, RFC 0022, and RFC 0023 law, command, evidence requirement, non-claim,
no-go gate, and acceptance limitation remains binding. Acceptance does not
itself accept the RFC 0021 implementation or change any implementation,
compatibility, Gold, conformance, task, issue, or release status.
