---
name: uci-config-validator
description: >-
  Procedure for verifying OpenWrt UCI configuration integrity, validating default templates,
  and testing init script syntax for PassWall 2.
---

# UCI Configuration Validator Skill

This skill guides agents in validating UCI configuration templates and ensuring daemon init scripts follow OpenWrt standards.

## Operational Workflow

### 1. Default Configuration File Integrity
The reference template is stored at:
`root/usr/share/passwall2/0_default_config`

Verify that:
1. Every section declaration begins with `config <section_type> ['<section_name>']`.
2. All `option <name> '<value>'` entries have balanced quotes.
3. All `list <name> '<value>'` entries are valid.
4. Boolean options use `'0'` or `'1'`.

### 2. Init Script Verification (`root/etc/init.d/passwall2`)
1. Ensure the shebang is `#!/bin/sh /etc/rc.common`.
2. Confirm standard OpenWrt init priorities exist:
   ```sh
   START=95
   STOP=10
   ```
3. Run ShellCheck on the init script and helper scripts:
   ```sh
   shellcheck root/etc/init.d/passwall2
   shellcheck -s sh root/usr/share/passwall2/*.sh
   ```
4. Verify that the init script handles clean termination:
   - Stopping proxy core daemons.
   - Restoring DNS configuration.
   - Flushing custom iptables/nftables firewall chains and sets.

### 3. Done When
- [ ] ShellCheck reports zero errors/warnings (or only acceptable ash idioms).
- [ ] `0_default_config` has valid UCI syntax.
- [ ] Service stop actions cleanly dismantle all created network state.
