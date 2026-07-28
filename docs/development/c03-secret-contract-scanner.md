# C03 Secret Contract and Fixture Scanner

## Status and purpose

`scripts/security/check-secret-contracts.py` is the offline, fail-closed
repository guard owned by `SECR-006`. It rejects raw/value-bearing secret fields
in governed contracts and examples and scans repository candidate content for
known credential, private-key, authorization, credential-URL, encoded-key, and
high-entropy token forms.

This is partial `SECR-006` and QA-089 evidence. It does not complete C03, make a
Gold case pass, resolve material, scan runtime outputs, or replace the Gateway's
live pre-persistence credential guard.

## Developer command

Run the same two commands used by CI:

```bash
make security-secret-contracts
```

Or run them directly:

```bash
/usr/bin/python3 -I scripts/security/check-secret-contracts.py --self-test
/usr/bin/python3 -I scripts/security/check-secret-contracts.py
```

The absolute interpreter and isolated-mode flag are part of the security
contract: repository files such as `scripts/security/hashlib.py` cannot shadow
the standard library during scanner startup. The self-test includes a subprocess
regression for both commands and uses only temporary synthetic fragments. Normal mode enumerates
tracked plus non-ignored files with local `git ls-files`; every regular file is
read relative to one no-follow, descriptor-pinned repository root under the
cumulative budget and every unambiguous UTF-8 file is
content-scanned regardless of suffix. The scanner performs no network access. CI
and the Docker image workflow run these commands in a dedicated prerequisite
job; build, test, image, and publication jobs do not start unless both pass.
Every job fetches, detaches, and verifies the same immutable `GITHUB_SHA`; there
is no mutable-ref or `FETCH_HEAD` fallback.
Recognized JSON, YAML, INI/TOML-style configuration, and Markdown files are
additionally decoded so escaped, folded, keyed, ancestor-scoped, and scalar
content is scanned recursively. Registered governed Python, JavaScript, and
TypeScript roots, sniffed archive members, and explicitly selected source files
receive bounded declaration checks. Normal mode rejects unregistered OpenAPI,
external SDK/client/package, conformance, and Gold authorizing surfaces instead
of treating a new root as ordinary text.

To check one new repository-relative fixture before placing it under a governed
root:

```bash
/usr/bin/python3 -I scripts/security/check-secret-contracts.py --path path/to/fixture.json
```

Missing paths, symlinks, traversal, malformed or duplicate JSON/YAML keys,
unsupported governed formats, invalid UTF-8, resource exhaustion, stale policy
entries, and unavailable repository enumeration all fail the command.
Ancestor and final-file identities are checked before and after reads. FIFOs and
other non-regular objects are opened nonblocking and rejected.

## Governed roots and formats

The exact registry is
`scripts/security/secret-contract-policy.json` with schema
`splendor.secret_field_scan.v1`. It currently governs:

- canonical C03 and Driver credential-sink JSON fixtures;
- C03 foundation conformance JSON and structured Markdown fences;
- stable adapter-manifest JSON;
- the runtime daemon OpenAPI YAML;
- repository examples and their JSON/YAML fences;
- current Python SDK and TypeScript type/client source with bounded declaration
  checks in addition to content scanning.

JSON is parsed with duplicate-key and non-finite-number rejection. YAML uses the
scanner's closed bounded subset: mappings, normal and indentless sequences,
single-line and folded multiline quoted/plain scalars, flow maps/lists, and
literal/folded blocks (including sequence block scalars). Anchors, aliases, tags,
merge keys, multiple documents, tabs in indentation, and ambiguous indentation
are rejected. Standard YAML quoted scalar escapes are decoded under the same
Unicode and work budgets. Recognized JSON/YAML fences in Markdown must close and
parse; governed Python/JavaScript/TypeScript fences use the bounded source
grammar, and bounded MyST options such as captions are normalized before parsing.
JSONC/JSON5/JSON-lines-like fences and residual container/fence syntax beyond the
configured structural depth fail closed instead of being skipped. Structural
forbidden-field enforcement remains limited to registered governed roots,
explicit paths, and sniffed archive manifests; decoded content signatures and
low-entropy assignment checks cover every unambiguous repository text file.

Repository content scanning covers bounded UTF-8 source, fixtures, generated
text, docs, manifests, and ZIP/TAR/GZIP containers recognized by magic rather
than filename. Standalone gzip text and gzip-wrapped TAR are supported; every
other nested archive is rejected. ZIP members use stored, Deflate, or BZIP2
streams with exact end-of-stream, size, CRC, and metadata validation; other ZIP
compression methods fail closed. Archive traversal, links, encryption,
prefixes/polyglots, trailing data, ZIP comments, credential-capable
member/metadata names, concatenated GZIP streams, malformed members, excessive
expansion, or cumulative file/member/unpacked/work budget overflow fail closed.
Supported V7 and USTAR TAR headers are detected by a bounded linear scan at every
possible offset, including inside an otherwise opaque nested member.
Global member capacity is checked before archive-library enumeration. Every
archive member that decodes as unambiguous UTF-8 is content-scanned regardless
of filename suffix. UTF-8 BOM/NUL/control/format ambiguity fails closed; opaque
non-UTF-8 members remain outside the absence claim.
JSON/YAML-looking members are structurally sniffed before scanning; Markdown
members are parsed when their member name identifies Markdown.

## Safe records and exceptions

Safe C03 recognition is exact, not substring based. Each canonical
`SecretUseRequirement`, `SecretCredentialAuthorization`, `SecretRef`, and Driver
credential-sink fixture is bound to an exact path, schema version, and SHA-256
digest owned by its canonical Rust implementation. Independent scanner tests pin
the complete owner/symbolic path-schema-digest inventory plus nonempty
conformance case counts and identities. This avoids maintaining a second,
drifting Python copy of owner semantics. Any mutation—including legal field names
with invalid bounds or relationships—invalidates the fixture.
Copying a schema string into another path or wrapping a generic value does not
make the object safe.

The only structural exceptions are exact path + document schema + field path
entries. Current entries cover:

- exact daemon Python/TypeScript caller-auth transport declarations and object
  projections;
- exact digest-bound TypeScript owner declarations/references for current
  non-material caller-credential metadata;
- two exact process-local synthetic HMAC-key declarations in the containerized
  acceptance provider (declarations only; no committed value);
- the deprecated daemon caller-credential header name and closed OpenAPI
  `CallerCredential` references;
- exact caller-auth projections in two Markdown examples;
- one exact local-only symbolic `verification_secret` placeholder.

Every exception has an owner, reason, expiry, validator, and scanner version.
Array/object wildcards are rejected. An entry that no longer matches is stale and
fails CI.

Intentional synthetic canaries and public protocol vectors use the separate
content allowlist. Each entry pins an exact path, SHA-256 file digest, exact rule
code/count map, owner, reason, expiry, and scanner version. A file change, new or
removed match, expiry, or unused entry fails; content exceptions never suppress
structural findings.

## Rule families

| Prefix | Meaning |
| --- | --- |
| `SCN` | policy, path, parser, availability, format, budget, or stale-entry failure |
| `SCF` | forbidden structural field, fake wrapper, invalid safe record, or invalid exception |
| `SCC` | private key, provider token, authorization value, entropy candidate, credential URL, or encoded key |
| `SCA` | malformed, unsafe, encrypted, or over-budget archive |

Diagnostics contain only a safe repository location, optional line, and a fixed
rule message. Credential-capable path/archive-member segments are
replaced by the single fixed `<redacted>` marker, including normalized plural,
percent-encoded, and opaque mixed-token segments;
candidate material and matched substrings are never printed.
Percent-encoded diagnostic segments are decoded to a bounded fixed point before
classification and collapse to the same fixed marker.
Malformed Unicode, non-finite values, archives, and filesystem objects map to
fixed rule codes.

## Negative smoke check

This creates a non-authenticating synthetic fragment, proves nonzero exit, and
removes it:

```bash
tmp="$(mktemp .c03-secret-negative.XXXXXX.json)"
trap 'rm -f "$tmp"' EXIT
/usr/bin/python3 - "$tmp" <<'PY'
import json
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(
    json.dumps({"authorization": "Bearer " + "A1b2_" * 8}),
    encoding="utf-8",
)
PY
if /usr/bin/python3 -I scripts/security/check-secret-contracts.py --path "$tmp"; then
  echo "unsafe fixture unexpectedly passed" >&2
  exit 1
fi
```

## Limits and nonclaims

The policy caps cumulative files/work bytes/parser operations/structure
nodes/archive members and unpacked bytes, plus per-document
depth/members/strings/fences. YAML, source token/AST walks, normalization, and
provenance construction are deterministically operation- or work-charged before
unbounded allocation. Raising a cap beyond the scanner's hard ceiling is invalid.
Both CI workflows impose a five-minute scanner-job timeout as an outer resource
bound.

The mandatory self-test discovers and digest-pins every
`scripts/security/tests/test_*.py` module, currently exactly 159 unique test
identities. Zero discovery, an added/removed/renamed test module or case,
governed-root inventory drift, or owner/symbolic fixture digest drift fails
closed.

The repository has no configured root Python typing policy or scanner-specific
type-check CI job. Correction validation therefore runs the explicit default-tool
checks `ruff format --check`, `ruff check`, `mypy`, and `pyright` over the entry
point, package, and independent tests; none is required at scanner runtime.

The content scan is deterministic defense in depth, not proof that arbitrary
binary, encrypted, compressed-inside-an-unknown-container, steganographic,
custom-encoded, or split runtime material is absent. Python uses the standard AST
and JavaScript/TypeScript uses a closed bounded authoring grammar rather than a
complete language parser; unsupported credential-capable record, computed,
mapped, rebinding, or nesting forms fail closed.
Gitleaks or another approved general secret scanner remains complementary;
neither replaces the structural C03 contract checks.
