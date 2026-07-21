# RFC 0022 - RFC 0021 Validation Evidence Addendum

## Status and Binding

**Status:** Accepted validation-evidence addendum

**Date:** 2026-07-21

**Accepted:** 2026-07-21

**Accepted proposal SHA-256:**
`835cb255d21f302b35e4b40748106f501224a3fbb9bfcf1d0c36a3dffb7dc805`

**Active execution line:** `Splendor0.2-dev` / `0.2/v2`

**Program:** `V2-FND-0 Foundations`

**Catalog task:** `FND-006` / issue `#225`, partial offline Slice 1 only

**Primary contract:** [RFC 0021](0021-c03-foundation-offline-characterization-contract.md),
accepted proposal SHA-256
`5ae1424de99729cf25030897d5c487a0de4e13b9aab4cb4acb951e590e3fca0b`

**Owner package:** `crates/splendor-types`

**Gold targets:** `G00` and `G72`; both remain
`specified_not_implemented` / `not_exercised`

This proposal changes only the validation-evidence rules for the exact private
RFC 0021 implementation. It changes no implementation file, production Rust,
Cargo manifest, lockfile, dependency, public schema, generated surface, daemon,
Store, runtime, SDK, CI, migration, compatibility classification, live
disposition, task status, issue status, Gold status, conformance status, or
release claim.

Until this addendum is accepted through separate architecture/compatibility and
security/privacy review, it grants no exception to RFC 0021. The exact private
implementation remains blocked by RFC 0021's no-go gates.

## Problem Statement

Execution of RFC 0021's required validation commands exposed two properties of
the reviewed baseline and local tooling that the accepted contract did not
model.

First, with `cargo-llvm-cov 0.8.2`, the exact RFC 0021 coverage command excludes
production source explicitly while cargo-llvm-cov's default filename filter
also excludes integration-test files. The command exits successfully while
reporting `TOTAL 0` lines. A zero-line denominator is not evidence and must not
be described as satisfying the 95 percent threshold.

Second, the exact required repository-wide secret-history and dependency scans
fail on reviewed base commit
`2e07157ff3182f8425edf070ffd655b6490afb9e`. The name `origin/dev` is
descriptive only; later movement of that ref does not change this reviewed
baseline:

- `gitleaks detect --no-banner --redact --source .` reports 97 findings across
  461 existing commits; and
- `cargo audit` reports seven existing advisories in the unchanged lockfile:
  `RUSTSEC-2025-0020`, `RUSTSEC-2026-0177`, `RUSTSEC-2026-0104`,
  `RUSTSEC-2026-0098`, `RUSTSEC-2026-0099`, `RUSTSEC-2026-0049`, and
  `RUSTSEC-2026-0009`.

The RFC 0021 implementation changes exactly five private fixture/test files and
changes no dependency input. Direct current-tree scans of each changed file
report no leaks. `pyo3` and `rustls-webpki` are not in the
`splendor-types` package dependency tree. `time 0.3.45` is an existing direct
dependency, but this slice adds no deployed parser or externally supplied input:
the private integration test invokes the existing production API only with
bounded, compile-time embedded synthetic fixtures.

Baseline attribution does not make historical findings or advisories harmless.
It does establish that changing the exact five-file harness cannot remediate
them without violating RFC 0021's scope and immutability rules.

## Decision

If accepted, this RFC amends only RFC 0021 lines 1031-1061 and the corresponding
validation portion of its no-go gate. It makes two narrow corrections.

### 1. Non-vacuous private-harness coverage

The authoritative RFC 0021 private-harness coverage command becomes:

```sh
cargo llvm-cov -p splendor-types \
  --test c03_foundation_offline_slice_1 \
  --no-default-ignore-filename-regex \
  --ignore-filename-regex 'crates/splendor-types/src/' \
  --fail-under-lines 95
```

Retained evidence must show all of the following:

1. the focused 21-test target executed successfully;
2. the report contains the exact file
   `crates/splendor-types/tests/c03_foundation_offline_slice_1.rs`;
3. the report has a non-zero line denominator; and
4. line coverage for that file and the total is at least 95 percent.

The coverage run must use the exact command above with no additional filename
filter, `LLVM_COV_FLAGS`, `RUSTFLAGS`, cargo configuration, source annotation,
or environment setting that suppresses lines in the private harness. Review
must confirm that the harness contains no coverage-disable annotation. Any
change to the candidate bytes invalidates the coverage evidence and requires a
fresh run.

The original RFC 0021 command must also be retained with its observed `TOTAL 0`
result and identified as **vacuous tooling evidence**, not as a pass. A later
cargo-llvm-cov version may change default filters; the four semantic checks
above remain authoritative over tool-version-specific defaults.

This correction does not widen coverage to unrelated production files and does
not weaken the 95 percent threshold.

### 2. Narrow baseline-failure disposition

The exact repository-wide commands remain mandatory and their exit status must
be reported truthfully:

```sh
gitleaks detect --no-banner --redact --source .
cargo audit
```

For this RFC 0021 implementation only and for one immutable candidate commit,
an existing baseline failure is
classified `baseline_present_not_attributable_to_slice` rather than an
implementation failure when every condition below is proven:

1. the candidate has reviewed base commit
   `2e07157ff3182f8425edf070ffd655b6490afb9e` as its merge base;
2. final evidence is collected from an immutable candidate commit with a clean
   index and worktree, and
   `git diff --name-status 2e07157ff3182f8425edf070ffd655b6490afb9e...HEAD`
   contains exactly the five RFC 0021 paths, each with status `A`;
3. retained evidence records the candidate commit SHA, candidate tree SHA,
   SHA-256 of the binary diff from the reviewed base, and SHA-256 of each exact
   changed file; any candidate-content change invalidates every scan and review;
4. no `Cargo.toml`, `Cargo.lock`, dependency configuration, scanner
   configuration, ignore file, generated artifact, or CI file changed;
5. baseline and candidate scans run in the same environment with identical tool
   versions and configuration; retained evidence records UTC time, gitleaks
   version and configuration source or hash, cargo-audit version, and the
   successfully refreshed RustSec advisory-database commit;
6. a direct current-tree `gitleaks dir --no-banner --redact <file>` scan of each
   of the five committed candidate files reports no leaks after file hashes are
   recorded;
7. paired baseline and candidate gitleaks scans produce exactly equal canonical
   redacted finding-identity sets; the sorted identity is only rule ID, source
   commit, repository-relative path, and start/end line range, and retained
   evidence records its count and SHA-256 without any matched value;
8. the cargo-audit crate/version/advisory-ID set is recorded and is identical to
   the reviewed baseline set under the same refreshed advisory-database commit;
9. package-tree evidence identifies which advisories are absent from or present
   in `splendor-types`, and security review assesses any present advisory against
   the private, compile-time-only, bounded test input model;
10. independent security/privacy review reports zero P0/P1 findings attributable
    to the five-file implementation and explicitly accepts its diagnostic,
    bounds, dispatch, path, and side-effect controls; and
11. separate remediation work items for the historical secret findings and
    dependency advisories are linked before implementation merge. Each work item
    identifies an owner, the reviewed baseline SHA, a sanitized inventory or
    advisory IDs, triage state, and target date or release. Any confirmed active
    credential is revoked or rotated before merge.

This disposition is not a scan pass, suppression, allowlist, finding closure,
risk acceptance for production, or permission to ignore a new finding. The
retained result must state both the exact command failure and the narrower
changed-file result.

Any changed-file leak, changed dependency input, new advisory, any difference
from the reviewed baseline finding set, missing redaction, unreviewed
reachability, missing remediation metadata, or P0/P1 security finding remains a
blocking failure.

For avoidance of doubt, only the non-zero exits from the two exact
repository-wide commands above are carved out from RFC 0021 lines 1147-1149,
and only when every condition in this disposition is satisfied. Their recorded
status remains failed. Every other required validation-command failure remains
a blocking no-go. This disposition expires with the recorded candidate commit
and cannot be copied to another commit, branch, slice, or RFC.

## Security and Compatibility Boundaries

This addendum does not:

- authorize scanner configuration or ignore-list changes;
- suppress, redact by hashing, delete, rewrite, or declare false-positive any
  historical finding;
- waive credential revocation or rotation if triage identifies a real secret;
- waive dependency remediation, reachability analysis, or release security
  requirements;
- authorize a dependency update inside the RFC 0021 implementation branch;
- change stable 0.1 behavior, public compatibility, or migration semantics;
- classify any fixture as supported, compatible, registered, authorized,
  current, conformant, or live;
- create retained conformance or Gold evidence; or
- complete `FND-006`, issue `#225`, C03, `FR-0.2-01`, `FR-0.2-08`, `G00`, or
  `G72`.

The direct-file scans are safe because the five files are synthetic and public
within the repository. Secret values from repository-history findings must not
be copied into review comments, RFC text, state files, or reports.

## Required Review and Evidence

Acceptance requires separate architecture/compatibility and security/privacy
review with explicit P0/P1/P2 counts. Review must verify:

- this RFC changes validation evidence only;
- the coverage correction measures the intended integration-test file and has
  a non-zero denominator;
- the baseline disposition is closed to this exact five-file private slice;
- no scanner, dependency, runtime, public contract, compatibility, or task
  status is changed;
- existing findings remain visible and separately tracked; and
- no wording describes a failed repository-wide scan as passed.

Required proposal validation:

```sh
git diff --check 2e07157ff3182f8425edf070ffd655b6490afb9e...HEAD
git diff --name-status 2e07157ff3182f8425edf070ffd655b6490afb9e...HEAD
test -z "$(git status --porcelain=v1 --untracked-files=all)"
python3 scripts/architecture/check-dependency-policy.py
python3 scripts/architecture/check-dependency-policy.py --self-test
```

These commands are final proposal-acceptance gates and therefore run against a
committed proposal candidate. The proposal diff must contain only this RFC file
with status `A`. Retained evidence records its commit and tree SHAs. Any content
change requires re-review. Markdown links must be relative and resolve, fences
must be balanced, and claim search must find no accidental implementation,
compatibility, Gold, task-completion, issue-closure, release, or
production-readiness statement.

## No-Go Gates

Acceptance or use of this addendum must stop if:

- it is used for any implementation other than the exact RFC 0021 five-file
  private offline Slice 1;
- the candidate base, diff, dependency inputs, scanner configuration, or
  baseline advisory/finding set differs from reviewed evidence;
- the corrected coverage report omits the test file, has zero measured lines,
  falls below 95 percent line coverage, or uses any additional denominator
  suppression;
- a repository-wide scan failure is hidden, reported as passed, or stripped of
  its count or advisory identities;
- a direct changed-file scan finds a candidate secret;
- a new or changed advisory is dismissed as baseline;
- security review cannot establish that the five-file slice adds no exposure to
  an existing advisory;
- historical secret and dependency remediation work lacks the required owner,
  baseline, sanitized inventory, triage state, or target metadata, or a
  confirmed active credential remains unrevoked/unrotated before merge;
- a scanner ignore, dependency update, production change, or CI change is added
  to the RFC 0021 implementation branch; or
- any completion, compatibility, registration, live-disposition, Gold, release,
  durability, or production-readiness claim changes.

## Acceptance Effect

Acceptance supersedes only RFC 0021's vacuous cargo-llvm-cov invocation and
carves the two exact, still-failing repository-wide commands out of RFC 0021
lines 1147-1149 under the complete narrow baseline-failure disposition above.
Every other RFC 0021 field, file boundary, loader law, execution law, security
law, non-claim, test requirement, no-go gate, and acceptance limitation remains
binding.

The implementation may proceed to merge only after the corrected coverage gate,
direct changed-file secret scans, independent reviews, retained baseline
evidence, and linked remediation work all satisfy this addendum. Acceptance does
not itself accept the implementation and does not change any implementation,
task, issue, compatibility, Gold, conformance, or release status.
