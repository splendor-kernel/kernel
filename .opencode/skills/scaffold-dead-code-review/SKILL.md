---
name: scaffold-dead-code-review
description: "Scaffold and Dead Code Review: Use when you need to remove or classify placeholder, duplicate, and dead code without deleting purposeful services by mistake."
compatibility: opencode
metadata:
  pack: agent-production-skill-pack
  version: "2.0"
  category: "06-maintenance-scaling"
  source: "skills/06-maintenance-scaling/scaffold-dead-code-review.md"
---

# Scaffold and Dead Code Review

## Purpose

Remove or classify placeholder, duplicate, and dead code without deleting purposeful services by mistake.

## Params

```yaml
  SOURCE_ROOTS: "<value>"
  ALLOW_DELETE_LOW_RISK: "<value>"
  INVENTORY_PATH: "<value>"
  ISSUE_LABELS: "<value>"
```

## Use When

- Clean arch cleanup
- Service audit
- Package surface cleanup
- Before deletion PRs

## Inputs

- Source files
- Exports
- Imports
- Docs
- Tests
- Config
- Migrations

## Procedure

- Identify scaffold-only files: comments plus empty exports, placeholder classes, unused TODO stubs, fake ports.
- Check imports, exports, docs, tests, config, migrations, generated references, and service inventory.
- Classify as planned scaffold, misleading scaffold, duplicate-replaced, test helper, generated placeholder, or dead-remove-candidate.
- Delete only low-risk misleading scaffolds when no references and no documented purpose exist.
- For risky candidates, create issues with evidence and suggested deprecation/removal path.
- Update package exports and docs when removing files.
- Run lint/typecheck/architecture checks after deletion.
- Record remaining scaffold debt in handoff.

## Outputs

- Cleanup PR or issues
- Updated inventory
- Validation evidence

## Quality Bar

- Every claim is backed by code, command output, issue/PR evidence, or explicit project documentation.
- The result reduces surprise for the next maintainer or agent.
- Uncertainty is labeled instead of hidden.
- The work respects current project conventions before introducing new patterns.

## Guardrails

- Do not delete because a single grep missed dynamic use
- Do not remove planned scaffolds without issue context
- Do not leave broken exports

## Anti-Patterns

- Creating fake completeness through docs, mocks, or placeholders.
- Making broad changes that are hard to review.
- Skipping production wiring because tests pass.
- Closing or marking work done without validation evidence.

## Done When

- Misleading placeholders are reduced
- Purposeful code is protected
- Remaining debt is tracked
