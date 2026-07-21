# RFC 0023 - RFC 0021 Lint Evidence Addendum

## Status and Binding

**Status:** Accepted lint-evidence addendum

**Date:** 2026-07-21

**Accepted:** 2026-07-21

**Accepted proposal SHA-256:**
`5518211430bc007024d6b9d301fbd13f2bddf42ff56f4426ee81e37a69abfca3`

**Active execution line:** `Splendor0.2-dev` / `0.2/v2`

**Program:** `V2-FND-0 Foundations`

**Catalog task:** `FND-006` / issue `#225`, partial offline Slice 1 only

**Primary contracts:** [RFC 0021](0021-c03-foundation-offline-characterization-contract.md),
accepted proposal SHA-256
`5ae1424de99729cf25030897d5c487a0de4e13b9aab4cb4acb951e590e3fca0b`,
and [RFC 0022](0022-rfc0021-validation-evidence-addendum.md), accepted
proposal SHA-256
`835cb255d21f302b35e4b40748106f501224a3fbb9bfcf1d0c36a3dffb7dc805`

**Owner package:** `crates/splendor-types`

**Gold targets:** `G00` and `G72`; both remain
`specified_not_implemented` / `not_exercised`

This proposal changes only lint-evidence disposition for the exact private RFC
0021 implementation. It changes no implementation, production Rust, Cargo
manifest, lockfile, dependency, feature, public schema, generated surface,
daemon, Store, runtime, SDK, CI, migration, compatibility classification, live
disposition, task status, issue status, Gold status, conformance status, or
release claim.

Until this addendum is accepted through separate architecture/compatibility and
security/privacy review, the RFC 0021 implementation remains blocked by its
exact workspace-all-features lint gate.

## Problem Statement

RFC 0021 requires:

```sh
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

On reviewed implementation base commit
`2e07157ff3182f8425edf070ffd655b6490afb9e`, that command fails on 21 existing
PyO3 deprecation diagnostics in `python/bindings/src/lib.rs`. The exact private
RFC 0021 candidate changes only five new conformance/test files, changes no
feature or dependency input, and does not touch Python bindings.

Two narrower commands are green on the candidate:

```sh
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p splendor-types --all-targets --all-features -- -D warnings
```

Together they prove that every workspace target under its normal feature set and
every owning-package target under all features remains warning-free. They do not
make the failing workspace-all-features command pass and do not remediate the
baseline PyO3 deprecations.

## Decision

If accepted, this RFC carves only the non-zero exit from RFC 0021's exact
workspace-all-features clippy command out of RFC 0021 lines 1147-1149 for one
immutable candidate commit satisfying every condition below:

1. the candidate satisfies RFC 0022's immutable base, commit, tree, diff,
   per-file hash, clean-worktree, and exact-five-`A`-file conditions;
2. no Cargo manifest, lockfile, feature configuration, Rust toolchain file,
   lint configuration, scanner configuration, CI file, existing Rust source, or
   generated file changes;
3. the exact failing command is executed after candidate immutability and is
   reported as failed; retained evidence records its exit code and a sanitized
   summary but never raw rendered diagnostics;
4. baseline and candidate runs execute in separate clean worktrees using
   separate, initially empty `CARGO_TARGET_DIR`s and the same literal command,
   toolchain, Cargo, Clippy, host target, target-selection flags,
   feature-selection flags, and configuration;
5. retained evidence records candidate commit/tree, UTC start and end, exit
   code, literal command, `rustc -Vv`, Cargo version, Clippy version, host
   target, and SHA-256 identities for all Cargo/Clippy/toolchain configuration
   inputs. `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CLIPPY_CONF_DIR`,
   `CARGO_BUILD_RUSTFLAGS`, and any equivalent lint-affecting override must be
   absent; only the distinct empty target-directory value may differ;
6. retained `cargo metadata --no-deps --format-version 1` target inventories are
   equal after removing from the candidate only the auto-discovered
   `c03_foundation_offline_slice_1` integration-test target required by RFC 0021;
7. paired diagnostic-only runs use the same invocation with
   `--message-format=json` added before `-- -D warnings`. The original literal
   command remains the authoritative exit-status evidence;
8. a fixed, reviewable extractor consumes each JSON stream directly without
   persisting raw messages. It accepts only compiler-message diagnostics with a
   lint code and exactly one primary span rooted in the repository, fails closed
   on every other warning shape, and emits only: lint code, reported level,
   repository-relative primary path, primary start/end line and column, and the
   exact top-level diagnostic message after line-ending normalization only;
9. the extractor excludes and never retains `rendered`, child diagnostics,
   source text, span text, suggested replacements, absolute paths, environment
   values, or fixture values. Retained evidence records the extractor source
   SHA-256 and version; arbitrary post-hoc redaction is forbidden;
10. the lexicographically sorted, length-prefixed diagnostic identity
    **multisets** are byte-for-byte equal, including occurrence multiplicity.
    Retained evidence records total and unique counts and SHA-256 of the encoded
    multiset, not the identities or raw diagnostics;
11. the warning multiset has total cardinality 21 and consists only of PyO3
    deprecations in the unchanged
    `python/bindings/src/lib.rs`, with no warning attributable to any candidate
    path;
12. both narrower commands above run in a fresh empty candidate target directory
    and pass against the same immutable candidate;
13. independent implementation review reports zero P0/P1 findings attributable
    to lint quality in the five-file candidate; and
14. a separate PyO3 lint/dependency remediation work item is linked before
   implementation merge and identifies an owner, the reviewed base SHA, warning
   inventory, triage state, target date or release, and the technical exit
   criterion that the exact workspace-all-targets/all-features command passes
   with `-D warnings` and no `allow`, `expect`, `--cap-lints`, or equivalent
   suppression. Missing the target triggers explicit escalation and new
   security/architecture review; it cannot be silently retargeted or closed.

The disposition is named `baseline_present_not_attributable_to_slice`. It is
not a lint pass, suppression, allow, warning waiver for production, or
permission to add a warning. The retained evidence must state that the exact
command failed and that the two narrower commands passed.

Any changed warning identity or multiplicity, new warning, warning in a
candidate file, missing or unextractable diagnostic, non-fresh target directory,
tool/configuration drift, lint suppression, changed feature input beyond the one
required test target, failed narrower command, missing or overdue remediation
metadata, or P0/P1 implementation finding remains blocking.

This disposition expires with the recorded RFC 0021 candidate commit. It cannot
be copied to another commit, branch, slice, RFC, or general project lint policy.
Every other RFC 0021 and RFC 0022 validation failure remains a blocking no-go.

## Security and Compatibility Boundaries

This addendum does not:

- add `allow`, `expect`, or warning-suppression attributes;
- change lint levels, features, toolchains, dependencies, or PyO3 code;
- classify the 21 baseline warnings as harmless or resolved;
- weaken direct all-feature linting of the owning `splendor-types` package;
- change stable 0.1 behavior, public compatibility, or migration semantics;
- create conformance or Gold evidence; or
- complete `FND-006`, issue `#225`, C03, `FR-0.2-01`, `FR-0.2-08`, `G00`, or
  `G72`.

The warning evidence must not retain source snippets, absolute paths,
environment values, rendered diagnostics, fixture values, or any secret. If a
diagnostic cannot be represented by the exact allowlisted schema without
retaining sensitive text, extraction and review stop; arbitrary value stripping
must not convert it into accepted evidence.

## Required Review and Evidence

Acceptance requires separate architecture/compatibility and security/privacy
review with explicit P0/P1/P2 counts. Review must verify that the exception is
candidate-bound, mechanically compares exact warning sets, preserves the failed
status, and cannot hide warning drift.

Required proposal-acceptance validation, run against a committed proposal:

```sh
git diff --check c71d0a5357952fcf6941e971701f6582db0de263...HEAD
git diff --name-status c71d0a5357952fcf6941e971701f6582db0de263...HEAD
test -z "$(git status --porcelain=v1 --untracked-files=all)"
python3 scripts/architecture/check-dependency-policy.py
python3 scripts/architecture/check-dependency-policy.py --self-test
```

The proposal diff must contain only this RFC file with status `A`. Retained
evidence records its commit and tree SHAs and the proposal file SHA-256. Any
content change requires re-review. Both relative RFC links must resolve,
Markdown fences must be balanced, and claim search must find no accidental
implementation, compatibility, Gold, task-completion, issue-closure, release,
or production-readiness statement.

## No-Go Gates

Acceptance or use of this addendum must stop if:

- it is used outside the exact RFC 0021 five-file private offline Slice 1;
- candidate or tool identity differs from RFC 0022's immutable evidence;
- any exact warning identity or occurrence multiplicity differs between
  reviewed base and candidate, or diagnostic extraction is incomplete or
  non-reproducible;
- a candidate file, changed feature, changed dependency, lint suppression, or
  configuration change contributes to the exact-command failure;
- a run reuses a target directory, omits execution provenance, retains raw
  diagnostics, or uses non-allowlisted normalization;
- either narrower lint command fails;
- the exact workspace-all-features failure is hidden or described as passed;
- PyO3 remediation lacks owner, baseline, inventory, triage, or target metadata;
  the target is silently extended; or the issue closes before the exact command
  passes without suppression; or
- any implementation, compatibility, registration, live-disposition, Gold,
  conformance, task, issue, release, durability, or production-readiness claim
  changes.

## Acceptance Effect

Acceptance carves only the exact workspace-all-features clippy non-zero exit out
of RFC 0021 lines 1147-1149 under the complete candidate-bound disposition
above. Every other RFC 0021 and RFC 0022 field, law, test, command, non-claim,
no-go gate, and acceptance limitation remains binding.

The RFC 0021 implementation may proceed to merge only after all RFC 0022 gates,
the exact failed lint evidence, equal warning identities, both passing narrower
commands, independent reviews, and linked remediation work satisfy this
addendum. Acceptance does not itself accept the implementation or change any
implementation, compatibility, Gold, conformance, task, issue, or release
status.
