# Operational Memory & Continuous Learning Ledger (.ai/lessons.md)

> **Protocol**: Read this file at session start. Prepend new entries (newest first) whenever a verification gate fails,
> an obscure platform quirk is diagnosed, or an operator corrects an instruction.
> When `[Hits]` reaches 3+, graduate the rule into `AGENTS.md` and create a deterministic test in `.agents/hooks/`.

## Active Episodic Lessons

### [openwrt-passwall2] Busybox Ash Compatibility
- **Hits**: 1 | **Status**: Active
- **Domain**: openwrt_luci
- **Prevention Rule**: Shell scripts running on OpenWrt use Busybox `ash`. Never write Bashisms such as `[[ ]]`, `==`, `&>`, or bash arrays. Always use standard POSIX `[ ]` and `=` for string comparison.

### [openwrt-passwall2] GNU Gettext PO Formatting & RTL Protection
- **Hits**: 1 | **Status**: Active
- **Domain**: openwrt_luci
- **Prevention Rule**: When modifying translation files in `po/`, strictly preserve format specifiers (`%s`, `%d`) matching the English `msgid`. Maintain Persian (`po/fa`) RTL integrity. Note that OpenWrt LuCI compiles POs into LMO binaries via `po2lmo`; raw PO files may omit standard GNU gettext headers.

### [openwrt-passwall2] Architectural Baseline
- **Hits**: 1 | **Status**: Active
- **Domain**: openwrt_luci
- **Prevention Rule**: Always run canonical verification commands (`shellcheck`, `msgfmt`, Lua syntax checks) and record receipts in `.ai/receipts/` before claiming completion.

## Operator & Prompt Antipatterns (Human Mistakes to Guard Against)
- Prepend common operator pitfalls here to guard against unverified prompt assumptions.

## Graduated Rules Archive (Enforced in Hooks / CI)
- [Graduated -> `.agents/hooks/pre_shell_guard.py`]: Shell string pipeline mutations (`sed -i`, `perl -pi`) are blocked deterministically.
