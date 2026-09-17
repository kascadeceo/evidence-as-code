#!/usr/bin/env python3
"""Reject sensitive identifiers before public-repository pushes."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path
from typing import Iterable


ACCOUNT_ID = re.compile(r"(?<![0-9A-Fa-f])\d{12}(?![0-9A-Fa-f])")
OCID = re.compile(r"ocid1\.[a-z0-9]+\.oc\d\.", re.IGNORECASE)
ARN = re.compile(r"arn:aws[a-z-]*:", re.IGNORECASE)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
ENGINE = re.compile("prow" + "ler", re.IGNORECASE)
FORBIDDEN_TOOLS = (
    re.compile("lima" + "charlie", re.IGNORECASE),
    re.compile("scout" + "suite", re.IGNORECASE),
)
DOCUMENTATION_ACCOUNT = "123456789012"
LEGACY_ENGINE_PATHS = {
    "caiq_autofill.py",
    "examples/run_scan.sh",
    "docs/evidence-as-code.md",
}
ATTRIBUTION_PATHS = {"README.md", "mappings/README.md"}


def scan_text(
    path: str, text: str, denylist: Iterable[str] = ()
) -> list[tuple[int, str]]:
    """Return ``(line number, rule)`` pairs without exposing matched values."""
    problems: list[tuple[int, str]] = []
    normalized_path = path.replace("\\", "/")

    for line_number, line in enumerate(text.splitlines(), 1):
        for match in ACCOUNT_ID.finditer(line):
            if match.group(0) != DOCUMENTATION_ACCOUNT:
                problems.append((line_number, "account_id"))

        if OCID.search(line):
            problems.append((line_number, "ocid"))

        if ARN.search(line) and DOCUMENTATION_ACCOUNT not in line:
            problems.append((line_number, "aws_arn"))

        for match in EMAIL.finditer(line):
            if not match.group(0).lower().endswith("@example.com"):
                problems.append((line_number, "email"))

        if ENGINE.search(line):
            attribution = (
                normalized_path in ATTRIBUTION_PATHS
                and line.startswith("Scan engine attribution:")
            )
            legacy_path = normalized_path in LEGACY_ENGINE_PATHS
            if not attribution and not legacy_path:
                problems.append((line_number, "scan_engine_name"))

        for pattern in FORBIDDEN_TOOLS:
            if pattern.search(line):
                problems.append((line_number, "forbidden_tool_name"))

        folded = line.casefold()
        for word in denylist:
            candidate = word.strip()
            if candidate and candidate.casefold() in folded:
                problems.append((line_number, "private_denylist"))

    return problems


def tracked_files() -> list[Path]:
    """Return files known to Git, including staged additions."""
    result = subprocess.run(
        ["git", "ls-files", "-z"], check=True, capture_output=True
    )
    return [Path(raw.decode("utf-8")) for raw in result.stdout.split(b"\0") if raw]


def read_denylist(path: Path | None) -> list[str]:
    if path is None or not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--denylist", type=Path)
    args = parser.parse_args()
    denylist = read_denylist(args.denylist)
    found = False

    for path in tracked_files():
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            continue
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, rule in scan_text(str(path), text, denylist):
            print(f"{path}:{line_number}: {rule}")
            found = True

    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
