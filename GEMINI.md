# Google Gemini & Antigravity Context (GEMINI.md)

@./AGENTS.md
@./.ai/lessons.md

## Gemini Operational Directives

### 1. Scope Containment & Precision
- **Anti-Scope-Expansion Guard**: Execute ONLY the explicit requirements requested in the prompt.
- Do not opportunistically refactor adjacent files, upgrade unrelated dependencies, or add unrequested abstractions.
- Keep responses concise and technical; avoid re-summarizing entire files before executing approved edits.

### 2. Multimodal & Visual Quality Protocol
- When modifying UI, Qt widgets, stylesheets, or Canvas/WebGL components, drive the flow using the `playwright` MCP server.
- Capture a screenshot and inspect via `@{.ai/receipts/latest_ui.png}` to verify layout alignment, contrast, and RTL responsiveness before claiming completion.

### 3. Context & Tool Synchronization
- Use `/memory show` to inspect loaded hierarchical context and `/memory refresh` to reload modified rules.
- Verify active tools and progressive skills via `/mcp list` and `/skills list`.
- Never use shell string pipelines (`sed`, `awk`) inside `run_command` to edit source files.
