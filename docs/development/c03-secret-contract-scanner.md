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
python3 scripts/security/check-secret-contracts.py --self-test
python3 scripts/security/check-secret-contracts.py
```

The self-test uses only temporary synthetic fragments. Normal mode enumerates
tracked plus non-ignored candidate files with local `git ls-files`; it performs
no network access.

To check one new repository-relative fixture before placing it under a governed
root:

```bash
python3 scripts/security/check-secret-contracts.py --path path/to/fixture.json
```

Missing paths, symlinks, traversal, malformed or duplicate JSON/YAML keys,
unsupported governed formats, invalid UTF-8, resource exhaustion, stale policy
entries, and unavailable repository enumeration all fail the command.

## Governed roots and formats

The exact registry is
`scripts/security/secret-contract-policy.json` with schema
`splendor.secret_field_scan.v1`. It currently governs:

- canonical C03 and Driver credential-sink JSON fixtures;
- C03 foundation conformance JSON and structured Markdown fences;
- stable adapter-manifest JSON;
- the runtime daemon OpenAPI YAML;
- repository examples and their JSON/YAML fences;
- current Python SDK and TypeScript type/client source in content-only mode.

JSON is parsed with duplicate-key rejection. OpenAPI and example YAML use the
scanner's closed bounded YAML subset: mappings, sequences, quoted/plain scalars,
flow maps/lists, and literal/folded blocks. Anchors, aliases, tags, merge keys,
multiple documents, tabs in indentation, and ambiguous indentation are rejected.
Recognized JSON/YAML fences in governed Markdown must close and parse.

Repository content scanning covers bounded UTF-8 source, fixtures, generated
text, docs, manifests, and supported ZIP/TAR/TAR.GZ archives. Archive traversal,
links, encryption, malformed members, excessive expansion, or resource overflow
fails closed. Nested archives are rejected instead of being silently skipped.
Structured JSON/YAML/Markdown members are also structurally checked.

## Safe records and exceptions

Safe C03 recognition is structural, not substring based. Each canonical
`SecretUseRequirement`, `SecretCredentialAuthorization`, `SecretRef`, and Driver
credential-sink fixture is bound to an exact path, schema version, and closed
validator. Copying a schema string into another path, adding an unknown field, or
wrapping a generic value does not make the object safe.

The only structural exceptions are exact path + document schema + field path
entries. Current entries cover:

- closed daemon `CallerCredential` references and correlation IDs;
- exact caller-auth projections in two Markdown examples;
- three descriptive adapter `credential_scope` fields; and
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

Diagnostics contain only repository path, optional line, and a fixed rule
message. Candidate material and matched substrings are never printed.

## Negative smoke check

This creates a non-authenticating synthetic fragment, proves nonzero exit, and
removes it:

```bash
tmp="$(mktemp .c03-secret-negative.XXXXXX.json)"
trap 'rm -f "$tmp"' EXIT
python3 - "$tmp" <<'PY'
import json
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(
    json.dumps({"authorization": "Bearer " + "A1b2_" * 8}),
    encoding="utf-8",
)
PY
if python3 scripts/security/check-secret-contracts.py --path "$tmp"; then
  echo "unsafe fixture unexpectedly passed" >&2
  exit 1
fi
```

## Limits and nonclaims

The policy caps files, bytes, structure depth/nodes/members, strings, fences, and
archive expansion. Raising a cap beyond the scanner's hard ceiling is invalid.

The content scan is deterministic defense in depth, not proof that arbitrary
binary, encrypted, compressed-inside-an-unknown-container, steganographic,
custom-encoded, or split runtime material is absent. TypeScript source is
content-scanned rather than parsed as a complete TypeScript grammar. Gitleaks or
another approved general secret scanner remains complementary; neither replaces
the structural C03 contract checks.
