#!/usr/bin/env python3
# File: .agents/hooks/post_edit_format.py
"""PostToolUse hook: Zero-friction auto-formatting and linting immediately after file modification."""
import json
import os
import subprocess
import sys
from pathlib import Path

def run_quiet(cmd: list[str]) -> tuple[int, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return res.returncode, (res.stdout + "\n" + res.stderr).strip()
    except Exception:
        return 0, ""

def main() -> None:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)
        event = json.loads(raw)
    except Exception:
        sys.exit(0)

    tool_input = event.get("tool_input", {})
    raw_path = (
        tool_input.get("file_path")
        or tool_input.get("TargetFile")
        or tool_input.get("path")
        or ""
    )
    if not raw_path or not os.path.isfile(raw_path):
        sys.exit(0)

    path = Path(raw_path)
    ext = path.suffix.lower()
    diagnostics: list[str] = []

    # Python formatting via ruff / black if installed
    if ext in {".py", ".pyi"}:
        if shutil.which("ruff"):
            run_quiet(["ruff", "format", str(path)])
            code, out = run_quiet(["ruff", "check", "--fix", str(path)])
            if code != 0 and out:
                diagnostics.append(f"Ruff lint findings in {path}:\n{out}")
        elif shutil.which("black"):
            run_quiet(["black", "-q", str(path)])

    # JS/TS/Web formatting via prettier if available
    elif ext in {".ts", ".tsx", ".js", ".jsx", ".json", ".css", ".md", ".html"}:
        if shutil.which("prettier"):
            run_quiet(["prettier", "--write", str(path)])

    if diagnostics:
        payload = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "\n".join(diagnostics)
            }
        }
        sys.stdout.write(json.dumps(payload) + "\n")

    sys.exit(0)

if __name__ == "__main__":
    import shutil
    main()
