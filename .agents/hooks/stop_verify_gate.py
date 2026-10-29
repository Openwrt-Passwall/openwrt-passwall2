#!/usr/bin/env python3
# File: .agents/hooks/stop_verify_gate.py
"""Stop hook: Blocks agent task completion (Exit 2) unless deterministic syntax/diff gates pass."""
import os
import subprocess
import sys
from pathlib import Path

RECEIPT_FILE = Path(".ai/receipts/last_verify.log")

def main() -> None:
    RECEIPT_FILE.parent.mkdir(parents=True, exist_ok=True)
    log_lines: list[str] = []

    # 1. Git diff check (whitespace / conflict markers)
    res = subprocess.run(["git", "diff", "--check"], capture_output=True, text=True, check=False)
    log_lines.append(f"=== git diff --check -> Exit {res.returncode} ===")
    if res.stdout:
        log_lines.append(res.stdout.strip())
    if res.stderr:
        log_lines.append(res.stderr.strip())

    if res.returncode != 0:
        RECEIPT_FILE.write_text("\n".join(log_lines), encoding="utf-8")
        sys.stderr.write(
            f"[STOP GATE REJECTED COMPLETION]: Git conflict markers or whitespace errors detected.\n"
            f"Output:\n{res.stdout}\n{res.stderr}\n"
        )
        sys.exit(2)

    # 2. Python check if applicable
    if Path("pyproject.toml").exists() or Path("requirements.txt").exists():
        import shutil
        if shutil.which("ruff"):
            r_res = subprocess.run(["ruff", "check", "."], capture_output=True, text=True, check=False)
            log_lines.append(f"=== ruff check . -> Exit {r_res.returncode} ===")
            if r_res.stdout:
                log_lines.append(r_res.stdout.strip())
            if r_res.returncode != 0:
                RECEIPT_FILE.write_text("\n".join(log_lines), encoding="utf-8")
                sys.stderr.write(f"[STOP GATE REJECTED COMPLETION]: Ruff lint errors detected.\n{r_res.stdout}\n")
                sys.exit(2)

    RECEIPT_FILE.write_text("\n".join(log_lines), encoding="utf-8")
    sys.exit(0)

if __name__ == "__main__":
    main()
