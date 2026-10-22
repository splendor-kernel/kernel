# Splendor 0.1 Conformance Suite

This directory contains the reference 0.1 compatibility suite for stable
primitive contracts. It is fixture-driven, secret-free, and does not contact
external services, production adapters, SaaS systems, networks, filesystems
outside this repository, or physical hardware.

Run from the repository root:

```bash
python conformance/0.1/run-conformance.py
```

The runner validates the fixture library in `fixtures/conformance-cases.json` and
the adapter maturity manifests in `docs/spec/0.1/fixtures/adapter-manifests/`.
It reports every failure with the exact primitive and requirement ID.

Current partial v2 foundation evidence includes a bounded FND-011/G86 driver
schema-confusion denial fixture under `fixtures/`. It proves a schema/version
mismatch is denied before adapter/driver execution and includes negative guards
for false execution reports, unknown execution/receipt fields, side-effect events,
missing side-effect counters, duplicate trace IDs, out-of-order events, and
mismatched verifier evidence. It is not a G86 gold pass, full G80-G89 pass,
driver registry, certification system, or live adapter execution claim.
