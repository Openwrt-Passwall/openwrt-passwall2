# Contributing to OpenWrt-PassWall2

Thank you for your interest in contributing to **OpenWrt-PassWall2**!

PassWall2 is an embedded router gateway application running with elevated system privileges on OpenWrt routers. Because it manages low-level routing tables, packet filtering (`nftables`/`iptables`), DNS resolution, and proxy daemons on resource-constrained hardware, all contributions must uphold high standards for stability, performance, and clean repository hygiene.

This guide outlines our development workflow, technical rules, and submission standards to make your pull requests smooth and easy to merge.

---

## 1. Core Principles & Philosophy

- **Embedded Router Footprint:** Routers have limited flash storage, RAM, and CPU cycles. We favor minimal, lightweight, and self-contained implementations.
- **Zero Third-Party API Dependencies:** Features must work offline and reliably on local network gateways. Avoid introducing external web APIs or cloud parsing services unless explicitly agreed upon with maintainers.
- **Discuss Major Changes First:** If you plan to add a new proxy core, overhaul the UI, or refactor routing engines, please open an [Issue or Discussion](https://github.com/Openwrt-Passwall/openwrt-passwall2/issues) first to align with maintainers before writing code.

---

## 2. Git & Branch Hygiene

To keep git history clean, maintainable, and bisectable:

### Never Submit from Your Fork's `main` Branch
Always create a dedicated feature branch for your work:
```bash
# Correct:
git checkout -b fix/socks-backup-naming

# Incorrect:
# Submitting directly from your fork's main branch creates messy merge commits.
```

### Keep Commits Clean & Linear
- Avoid merge commits (`Merge branch 'main' into main`). Rebase your branch against the latest upstream `main` instead:
  ```bash
  git fetch upstream
  git rebase upstream/main
  ```
- Write clear, descriptive commit messages following project conventions:
  - `luci: <brief description>` (for LuCI UI and controller changes)
  - `fix: <brief description>` (for bug fixes in routing or scripts)
  - `docs: <brief description>` (for documentation or translation updates)

---

## 3. AI & LLM Assistance Policy (Anti-Vibe-Coding Guard)

AI tools (Cursor, Claude Code, GitHub Copilot, Gemini) are welcomed and encouraged, but **untested "vibe coding" is strictly prohibited**.

If you use AI assistants, you are responsible for the code they generate:
1. **Mandatory Human Line-by-Line Review:** Review your git diff before opening a pull request. Do not submit code you do not understand.
2. **Zero Tolerance for Debug Scraps:** Never commit temporary debugging scripts, test logs, or scratch files.
3. **Verify OpenWrt Compatibility:** AI models frequently hallucinate non-POSIX bash syntax or assume desktop Linux environments. You must verify that generated code conforms to Busybox and LuCI standards.

---

## 4. Technical Invariants for OpenWrt

All code merged into PassWall2 must satisfy the following technical boundaries:

### A. POSIX Shell Strictness (Busybox `ash`)
Shell scripts in `root/etc/init.d/` and `root/usr/share/passwall2/` execute via Busybox `ash` (`/bin/sh`), NOT Bash.
- **No Bashisms:**
  - :x: Do not use `[[ ... ]]` -> :white_check_mark: Use standard `[ ... ]`
  - :x: Do not use `==` for string comparison -> :white_check_mark: Use `=`
  - :x: Do not use `&>` for redirection -> :white_check_mark: Use `> file 2>&1`
  - :x: Do not use Bash arrays `arr=(a b c)` -> :white_check_mark: Use space-separated strings or POSIX positional parameters
- **Linting:** Run `shellcheck -s sh` on modified scripts before submitting.

### B. Lua 5.1 & LuCI Conventions
- PassWall2 targets OpenWrt LuCI environments running **Lua 5.1**. Avoid features from newer Lua versions (e.g., bitwise operators from Lua 5.3).
- Respect UCI conventions: Use named section identifiers (e.g. `socks_` prefixes) where required by recent codebase updates, rather than legacy anonymous sections.
- Never write unvalidated user inputs directly into `/etc/config/passwall2`.

### C. Localization (Gettext PO) Integrity
- When editing translation catalogs in `po/`:
  - Strictly preserve `%s` and `%d` format specifiers matching the English `msgid`.
  - Maintain right-to-left (RTL) punctuation and structure in Persian (`po/fa`).
  - Do not alter translation file headers arbitrarily.

---

## 5. Local Testing & Verification Workflow

You do not need to flash a physical router to test your changes:

### Testing on a Test Router or VM via SCP
1. Copy modified shell scripts or LuCI models directly to your test OpenWrt router:
   ```bash
   # Copy a modified shell script:
   scp luci-app-passwall2/root/usr/share/passwall2/app.sh root@192.168.1.1:/usr/share/passwall2/

   # Copy a modified LuCI CBI model:
   scp luci-app-passwall2/luasrc/model/cbi/passwall2/client/global.lua root@192.168.1.1:/usr/lib/lua/luci/model/cbi/passwall2/client/
   ```
2. Restart the service and inspect live logs:
   ```bash
   /etc/init.d/passwall2 restart
   logread -e passwall -f
   ```

### Running Static Checks Locally
Before submitting, run basic syntax checks on modified files:
```bash
# Check shell scripts:
shellcheck luci-app-passwall2/root/usr/share/passwall2/*.sh

# Check Lua syntax (if Lua 5.1/luac is installed):
luac -p luci-app-passwall2/luasrc/model/cbi/passwall2/*.lua
```

---

## 6. Submitting Your Pull Request

1. Push your clean feature branch to your fork.
2. Open a Pull Request against the `main` branch of `Openwrt-Passwall/openwrt-passwall2`.
3. Fill out the automated [Pull Request Template](.github/pull_request_template.md):
   - Provide a clear summary of what was changed and why.
   - Mention what hardware/OpenWrt version you tested on (if applicable).
   - Attach screenshots for LuCI web interface changes.
4. Respond constructively to maintainer feedback.

Thank you for helping keep OpenWrt-PassWall2 fast, reliable, and secure!
