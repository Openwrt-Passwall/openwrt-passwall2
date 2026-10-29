# openwrt-passwall2 — Agent Instructions (AGENTS.md)

This file provides guidance to AI coding agents (Google Gemini, Claude Code, Cursor, Copilot) working in `openwrt-passwall2` (`main/openwrt-passwall2`).

## Core Principles (Strict Priority Order)
1. **Security & Safety Floor**: Never commit secrets, weaken auth, or modify `.env*` or production migration history.
2. **Deterministic Proof-of-Work**: A task is done ONLY when typecheck, lint, and test suites pass with saved receipts in `.ai/receipts/`.
3. **Minimal Blast Radius**: Prefer editing existing files over creating new files. Touch only task-scoped files.

## Risk Classification
| Risk Tier | Scope | Required Verification |
| :--- | :--- | :--- |
| **Tier 1 (Critical)** | Auth, crypto, DB schemas, hooks, CI/CD | Spec approval + Clean-worktree full test suite + Receipts |
| **Tier 2 (Moderate)** | Shared contracts, state models, public APIs | Scoped typecheck + Unit/integration tests + Linter |
| **Tier 3 (Low)** | Isolated UI fix, test addition, documentation | Targeted linter + single unit test verification |

## Tech Stack & Architecture (OPENWRT_LUCI)
- **Stack**: OpenWrt 21.02+ / LuCI (Lua 5.1, CBI/JS), POSIX Shell (ash/sh), UCI, nftables/iptables, Gettext PO

## Canonical Build & Verification Commands
- Shell Check: `shellcheck root/etc/init.d/* root/usr/share/passwall2/*`
- PO Format & Check: `msgfmt --check -o /dev/null po/*/*.po`
- LuCI Syntax: `lua -p luasrc/model/cbi/passwall2/*.lua luasrc/controller/passwall2/*.lua`

## Domain Invariants & Negative Boundaries
1. **OpenWrt POSIX Shell Strictness**: Use only `/bin/sh` / `ash` compatible syntax (no bashisms like `[[ ]]`, `==`, or process substitution `<()`).
2. **UCI & Service Safety**: Never corrupt `/etc/config/` defaults; always test UCI commits with atomic rollbacks.
3. **Lua 5.1 & LuCI Compatibility**: Retain strict Lua 5.1 syntax and compatibility with both LuCI CBI and newer LuCI client-side JavaScript APIs.
4. **Gettext PO Preservation**: Preserve all format specifiers (`%s`, `%d`), header metadata, and RTL strings (`po/fa`) during translation updates.
- **No Test Tampering**: NEVER delete or weaken existing test assertions to make a red suite pass.
- **No Pipeline File Edits**: NEVER use `sed -i` or `awk` to edit source code; use structured file tools (`replace_file_content`, `write_to_file`).

## Progressive Skills & Operational Memory
- Consult `.agents/skills/` for domain workflows:
  - `infer-conventions`: Discover empirical codebase conventions.
  - `audit-code-quality`: Run architecture, boundary, and type-safety audits.
  - `luci-component-builder`: Runbook for creating/modifying LuCI views, CBI tabs, and controllers.
  - `uci-config-validator`: Validate UCI templates, default configs, and init scripts.
  - `po-translation-sync`: Validate GNU Gettext PO syntax and maintain RTL translations (`po/fa`).
- Read `.ai/lessons.md` at session start. Prepend root-cause entries whenever a verification gate fails or an approach is corrected.

## Deterministic "Done When" Contract
1. All canonical verification commands exit with code `0`.
2. `git status --porcelain` shows zero untracked temporary files or unintentional diffs.
3. Verification receipt is saved to `.ai/receipts/last_verify.log`.
