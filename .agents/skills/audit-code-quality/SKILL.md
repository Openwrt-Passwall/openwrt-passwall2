---
name: audit-code-quality
description: >-
  Audits repository modules for circular dependencies, dead exports, type-safety bypasses,
  and architectural boundary violations. Use before completing Tier 1 or Tier 2 changes.
---

# Code Quality & Boundary Audit Skill

## Operational Procedure
1. Execute the deterministic boundary scanner:
   `python3 .agents/skills/audit-code-quality/scripts/scan_boundaries.py`
2. If authorization, API routes, or external input handlers were modified, review:
   [.agents/skills/audit-code-quality/references/security_checklist.md](./references/security_checklist.md)
3. Confirm that no unauthorized mock boundaries or test assertion bypasses exist.

## Done When
- [ ] `scan_boundaries.py` exits with code `0`.
- [ ] No circular imports or unauthorized cross-package imports are detected.
