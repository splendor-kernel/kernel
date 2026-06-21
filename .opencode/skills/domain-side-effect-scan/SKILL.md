---
name: domain-side-effect-scan
description: "Domain Side-Effect Scan: Use when you need to keep domain logic deterministic by finding side effects and global dependencies where they matter."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "01-architecture"
  source: "skills/01-architecture/domain-side-effect-scan.md"
---

# Domain Side-Effect Scan

## Purpose

Keep domain logic deterministic by finding side effects and global dependencies where they matter.

## Params

```yaml
  DOMAIN_ROOTS: "<value>"
  SIDE_EFFECT_PATTERNS: "<value>"
  REPORT_PATH: "<value>"
```

## Use When

- Architecture discovery
- Reviewing domain changes
- Audit/governance/runtime workflows

## Inputs

- Domain files
- Tests
- Application ports
- Architecture docs

## Procedure

- Search domain code for wall clock, randomness, hashing/signing, env access, filesystem, network, database, process globals, and mutable singletons.
- Determine whether the code is a pure helper, deterministic policy, mutation flow, or low-risk convenience.
- Flag only side effects that harm determinism, auditability, replayability, portability, or testability.
- Prefer passing values into pure domain functions over creating domain-level service abstractions.
- Move side-effect acquisition to application or infrastructure when needed.
- Add tests that demonstrate deterministic behavior with explicit inputs.
- Record acceptable direct calls when they are low-risk and documented by convention.
- Do not use this skill to force perfect purity everywhere.

## Outputs

- Side-effect report
- Determinism migration candidates
- False-positive notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not over-abstract pure value helpers
- Do not ignore audit-critical time/id/hash paths
- Do not hide globals behind static singletons

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Findings are tied to concrete risk
- Domain stays simpler, not more abstract
- Tests prove deterministic behavior when migrated
