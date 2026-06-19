> **Status:** Imported vNext planning reference. This file is not part of the stable 0.1 implementation contract and is not evidence that the repository implements the described behavior. Existing `AGENTS.md`, `docs/rules/*`, `docs/spec/0.1/*`, and release limitation documents remain authoritative until an RFC is accepted and implemented. If the source text below says `normative`, that status applies only to the imported vNext source pack, not to current repository rules.

# Clean Architecture Rules Validation

- Architecture document: `16_clean_architecture_rules.md`
- Lines: 974
- Normative rule IDs: 62; all unique
- Machine-readable package rules: 14
- Package-pattern rules: 1
- Migration exceptions: 2
- Path-owner rules: 22
- JSON policy: valid
- Impact-manifest JSON Schema: valid JSON and expected schema marker
- Python enforcement tools: syntax compiled successfully
- Synthetic current workspace: migration mode passed with 6 explicitly reported debt warnings
- Synthetic current workspace: target mode correctly failed on grandfathered edges
- Recursive-impact smoke test: gateway change propagated to compile and semantic consumers and correctly remained blocked on runtime lineage/deployment queries

The synthetic workspace validates checker behavior against the currently observed Cargo dependency shape. It is not a substitute for running both tools in a full repository checkout.
