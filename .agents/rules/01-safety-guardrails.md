# Rule 01: Safety Guardrails & Operational Boundaries

This rule establishes non-negotiable safety guardrails for any AI agent executing commands, generating code, or inspecting configurations in this workspace.

---

## 1. Strictly Forbidden Shell Commands
Under NO circumstances should the agent run the following destructive commands unless explicitly ordered by the user with unambiguous instructions:
- `firstboot -y` or `sysupgrade` (destroys router configuration and installs firmware)
- `rm -rf /` or recursive deletion targeting system roots (`/etc`, `/usr`, `/lib`, `/overlay`)
- `git reset --hard` or `git clean -fd` (risks destroying uncommitted local changes)
- `git push --force` or pushing directly to remote branches without review
- `sed -i` or `awk` pipelines directly mutating source code (risks UTF-8 corruption)
- Untested `uci commit network` or `uci commit firewall` that can brick router network access

## 2. Blast Radius Minimization
- Confine edits strictly to the specific files requested by the user.
- Do NOT perform unsolicited cosmetic reorganizations or arbitrary white-space changes on unaffected files.
- Always check `git status` prior to initiating any file write operations.

## 3. Secret & Credential Sanitization
- Never print, log, or commit server credentials, passwords, WireGuard private keys, REALITY private keys, or SSH credentials.
- When generating support diagnostics, inspect output to ensure sensitive token/key patterns are redacted.

## 4. Pre-Flight Verification Over Speculation
- Before marking any task as complete:
  - Verify shell script syntax with `shellcheck` when modifying scripts in `root/etc/init.d/` or `root/usr/share/passwall2/`.
  - Validate PO localization syntax with `msgfmt --check -o /dev/null <file.po>`.
  - Verify Lua syntax where feasible to catch missing `end`, syntax regressions, or unescaped strings.

## 5. UCI Configuration Integrity
- The default configuration file `/usr/share/passwall2/0_default_config` provides the template for `/etc/config/passwall2`.
- When adding or changing UCI options:
  - Maintain backward compatibility so existing configurations are not broken.
  - Define sensible defaults in both the LuCI CBI/JS layer and the backend daemon scripts.
  - Never introduce unescaped quotes or invalid section syntax into UCI files.
