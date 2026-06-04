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
