---
name: contract-change-qa
description: "Contract Change QA: Use when you need to validate schema/API/SDK contract changes and generated evidence."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "05-qa-release"
  source: "skills/05-qa-release/contract-change-qa.md"
---

# Contract Change QA

## Purpose

Validate schema/API/SDK contract changes and generated evidence.

## Params

```yaml
  CONTRACT_FILES: "<value>"
  GENERATION_COMMANDS: "<value>"
  API_TESTS: "<value>"
  SDK_TESTS: "<value>"
```

## Use When

- Contract/schema updates
- API response changes
- SDK changes
- Release evidence drift

## Inputs

- Schemas
- Generated files
- API routes
- SDK usage
- Tests

## Procedure

- Run contract generation/check commands according to repo convention.
- Compare generated artifacts against source schema changes.
- Record schema hash/version when the repo uses one.
- Run API tests for valid and invalid payloads.
- Run SDK/client typecheck or usage tests when affected.
- Check docs/release evidence for stale hashes, paths, or examples.
- Flag breaking changes that lack compatibility/deprecation notes.
- Update PR with exact generated evidence.

## Outputs

- Contract validation log
- Updated generated artifacts/docs
- Risk notes

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not hand-wave generated drift
- Do not silently break clients
- Do not update hash manually without generation evidence

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Source and generated contract agree
- Clients are considered
- Release evidence is truthful
