#!/usr/bin/env python3
"""Fail when public package files appear to contain private data or live credentials."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", "__pycache__", ".ruff_cache", ".pytest_cache"}
TEXT_SUFFIXES = {".md", ".py", ".sh", ".json", ".toml", ".txt", ".yml", ".yaml", ".svg", ""}

PATTERNS = {
    "absolute Linux home path": re.compile(r"/home/[A-Za-z0-9._-]+/"),
    "private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "common API token": re.compile(r"\b(?:sk-|xox[baprs]-)[A-Za-z0-9_-]{20,}\b"),
    "bearer token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}", re.IGNORECASE),
    "live Secret Drop link": re.compile(r"https://[^\s/]+\.ts\.net(?::\d+)?/(?:#token=|r/)[A-Za-z0-9_-]{32,128}"),
}


def iter_files():
    for path in ROOT.rglob("*"):
        if path.resolve() == Path(__file__).resolve():
            continue
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            yield path


def main() -> int:
    denylist = [item.strip() for item in os.environ.get("SECRET_DROP_PRIVATE_DENYLIST", "").split(",") if item.strip()]
    findings: list[str] = []
    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        relative = path.relative_to(ROOT)
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{relative}: {name}")
        lowered = text.casefold()
        for private_term in denylist:
            if private_term.casefold() in lowered:
                findings.append(f"{relative}: private denylist term")
    if findings:
        print("Privacy check failed:")
        for finding in sorted(set(findings)):
            print(f"- {finding}")
        return 1
    print("Privacy check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
