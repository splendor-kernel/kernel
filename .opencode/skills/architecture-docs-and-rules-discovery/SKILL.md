---
name: architecture-docs-and-rules-discovery
description: "Architecture Docs and Rules Discovery: Use when you need to identify the repository’s actual architecture rules before judging violations."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "01-architecture"
  source: "skills/01-architecture/architecture-docs-and-rules-discovery.md"
---

# Architecture Docs and Rules Discovery

## Purpose

Identify the repository’s actual architecture rules before judging violations.

## Params

```yaml
  ARCH_DOC_PATHS: "<value>"
  CHECK_SCRIPT_PATHS: "<value>"
  LAYER_ROOTS: "<value>"
  REPORT_PATH: "<value>"
```

## Use When

- Starting clean architecture discovery
- When project conventions are unclear
- Before creating architecture issues

## Inputs

- Architecture docs
- Custom lint/check scripts
- Package structure
- Existing imports

## Procedure

- Read architecture docs, ADRs, package READMEs, and custom architecture check scripts.
- Extract allowed dependency directions, known exceptions, transitional seams, and planned migrations.
- Compare docs to actual package layout and import patterns.
- Record explicit rules separately from inferred rules.
- Identify areas where docs are stale or ambiguous.
- Use existing checker scripts as evidence, but do not assume they cover every violation.
- Create/update issues for docs that materially contradict code or CI.
- Feed the resulting rule map to import, service, and PR review skills.

## Outputs

- Architecture rule map
- Known exceptions list
- Docs drift findings

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not invent architecture rules from preference
- Do not ignore transitional exceptions
- Do not treat folder names as proof of ownership

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Rules are grounded in repo evidence
- False positives are reduced
- Ambiguities are tracked
