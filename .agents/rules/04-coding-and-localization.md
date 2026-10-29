# Rule 04: Coding Standards, Shell Strictness & Localization

This rule defines the coding discipline, POSIX shell standards, and GNU Gettext localization requirements for PassWall 2.

---

## 1. OpenWrt POSIX Shell Strictness
Scripts in OpenWrt run in Busybox `ash` or standard `/bin/sh`, NOT full GNU `bash`.
- **Bashisms are STRICTLY FORBIDDEN**:
  - Do NOT use `[[ ... ]]`; use standard `[ ... ]` or `test`.
  - Do NOT use `==` in test commands; use `=` (e.g. `[ "$val" = "yes" ]`).
  - Do NOT use `&>` for redirection; use `>file 2>&1`.
  - Do NOT use process substitution (`<(command)` or `>(command)`).
  - Do NOT use bash arrays (`declare -a arr`, `${arr[@]}`). Use whitespace-delimited strings or newline loops.
  - Do NOT use `function name()`; use `name() { ... }`.
  - Do NOT use `source`; use `. /path/to/script`.
- **Defensive Shell Conventions**:
  - Quote all variable expansions: `"${variable}"` to prevent globbing and word splitting.
  - Test for executable presence with `command -v <binary> >/dev/null 2>&1`.
  - Avoid `set -e` in complex OpenWrt scripts where benign non-zero returns (like `grep -q` or `ip rule del`) would prematurely kill the script; check exit codes explicitly.

## 2. GNU Gettext Localization (`po/`)
PassWall 2 supports multiple languages under `luci-app-passwall2/po/`:
- `fa`: Persian (Farsi) — First-Class RTL Support
- `zh-cn`, `zh_Hans`: Simplified Chinese
- `zh-tw`, `zh_Hant`: Traditional Chinese
- `ru`: Russian

### Invariants for PO Editing
1. **Placeholder & Specifier Preservation**:
   - Never remove, rename, or alter format specifiers such as `%s`, `%d`, `%1$s`, `{0}`, `\n`, or HTML tags in `msgstr`.
   - The number and type of specifiers in `msgstr` MUST match `msgid` exactly.
2. **RTL Considerations (`po/fa`)**:
   - Ensure translated strings preserve correct directionality and terminology.
   - Technical terms (e.g., *TPROXY*, *Xray*, *Sing-Box*, *VLESS*, *gRPC*, *WebSocket*, *DNS*, *MTU*, *TCP*, *UDP*) should remain clear and recognizable.
3. **Syntax Validation**:
   - Always validate PO files with `msgfmt --check -o /dev/null <path_to_po_file>` before completing translation changes.
   - PO headers (`Content-Type: text/plain; charset=UTF-8`, `Content-Transfer-Encoding: 8bit`) must be valid UTF-8.
