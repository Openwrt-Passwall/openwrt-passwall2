#!/usr/bin/env python3
# File: .agents/hooks/pre_shell_guard.py
"""PreToolUse hook: Tokenizes shell commands to block destructive actions and string-pipeline file mutations."""
import json
import re
import shlex
import sys

BLOCKED_PATTERNS = [
    (r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b\s+(/|\.|~|\*)", "Destructive recursive root/workspace deletion is forbidden."),
    (r"\bgit\s+(reset\s+--hard|push\s+.*--force|clean\s+-[a-zA-Z]*f)", "Destructive git history/worktree rewrite is forbidden."),
    (r"\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b", "Unprotected destructive SQL execution is forbidden."),
    (r"\bsed\s+-i\b|\bperl\s+-pi\b", "Mutating files via shell string pipelines causes UTF-8 corruption. Use structured Edit/Write tools."),
    (r"\b(pip\s+install|npm\s+install|yarn\s+add)\b", "Non-standard package manager blocked. Use 'uv add' for Python and 'pnpm add' for Web."),
]

def deny(reason: str) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"[SECURITY GATE BLOCKED]: {reason}"
        }
    }
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stderr.write(f"[SECURITY GATE BLOCKED]: {reason}\n")
    sys.exit(2)

def main() -> None:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)
        event = json.loads(raw)
    except Exception:
        sys.exit(0)

    tool_input = event.get("tool_input", {})
    cmd = tool_input.get("command") or tool_input.get("cmd") or tool_input.get("CommandLine") or ""
    if not isinstance(cmd, str) or not cmd.strip():
        sys.exit(0)

    for pattern, reason in BLOCKED_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            deny(reason)

    try:
        tokens = shlex.split(cmd)
        if any(t in ("sudo", "su", "chmod", "chown") and "777" in cmd for t in tokens):
            deny("Privilege escalation or world-writable permission mutation is forbidden.")
    except ValueError:
        deny("Malformed shell quoting detected in command string.")

    sys.exit(0)

if __name__ == "__main__":
    main()
