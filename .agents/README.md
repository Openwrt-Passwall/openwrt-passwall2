# Antigravity & Gemini Agent Architecture: OpenWrt PassWall 2

This directory (`.agents/`) contains the complete configuration, rules, specialized custom subagents, runbook skills, and lifecycle hooks for **Google Antigravity** and **Gemini 3.8** operating within the **PassWall 2** (`openwrt-passwall2`) repository.

---

## Directory Structure

```
.agents/
├── README.md                          # This architectural handbook
├── hooks.json                         # PreToolUse, PostToolUse, and Stop lifecycle hooks
├── hooks/                             # Executable lifecycle interceptors
│   ├── pre_shell_guard.py             # PreToolUse safety gate intercepting destructive commands
│   ├── post_edit_format.py            # PostToolUse formatter and syntax validator
│   └── stop_verify_gate.py            # Stop verification gate ensuring clean diffs and validity
├── rules/                             # Modular, hierarchical rules loaded by Antigravity
│   ├── 01-safety-guardrails.md        # Router safety, forbidden commands, UCI safety, secrets
│   ├── 02-openwrt-luci-architecture.md# LuCI CBI/JS MVC architecture, Lua 5.1, rpcd, ubus, Makefile
│   ├── 03-routing-and-nftables.md     # TPROXY, REDIRECT, nftables (fw4) / iptables (fw3), cores
│   └── 04-coding-and-localization.md  # POSIX ash shell compliance, PO gettext, RTL Persian (fa)
├── agents/                            # Specialized custom subagents (YAML frontmatter)
│   ├── passwall-architect.md          # Principal OpenWrt & Proxy Architecture Specialist
│   ├── luci-ui-engineer.md            # LuCI Web UI, JavaScript & Template Specialist
│   └── network-routing-specialist.md  # Linux Networking, Netfilter/nftables & Proxy Core Specialist
├── skills/                            # On-demand progressive procedural runbooks (SKILL.md)
│   ├── infer-conventions/             # Discovers codebase patterns and conventions
│   ├── audit-code-quality/            # Boundary, credential, and syntax scanner
│   ├── luci-component-builder/        # LuCI CBI models, controllers, and JS view generator
│   ├── uci-config-validator/          # UCI schema and init script syntax validator
│   └── po-translation-sync/           # Gettext PO syntax validator and RTL synchronization
├── templates/
│   └── agent_template.md              # Boilerplate for creating new specialized agents
└── mcp_config.json                    # Model Context Protocol server registrations
```

---

## How Customizations Work in Antigravity

1. **Automatic Discovery**:
   - As any agent operates in this workspace, Antigravity automatically traverses the `.agents/` folder and root `GEMINI.md` / `AGENTS.md`.
   - Rules in `.agents/rules/` are seamlessly merged into the active context tree without duplicate token overhead.

2. **Custom Agent Invocation**:
   - In the Antigravity UI or CLI, type `/agents` to view and switch between specialized agents.
   - Any primary agent can delegate focused tasks to subagents (`passwall-architect`, `luci-ui-engineer`, `network-routing-specialist`) via the `invoke_subagent` tool.

3. **Progressive Disclosure Skills**:
   - Skills in `.agents/skills/` are dynamically activated when a task matches their YAML description.
   - This keeps the main context window lean while giving the agent step-by-step procedures when needed.
   - Both Cursor (`.cursor/skills`) and Claude Code (`.claude/skills`) share these skills via symlinks.

4. **Lifecycle Safety Hooks**:
   - `hooks.json` registers `hooks/pre_shell_guard.py` to inspect `run_command` calls before execution, blocking destructive shell actions or string pipeline source modifications (`sed -i`).
   - `hooks/stop_verify_gate.py` prevents completing tasks if git conflict markers or syntax errors exist.
