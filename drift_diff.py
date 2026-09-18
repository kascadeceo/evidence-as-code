#!/usr/bin/env python3
"""Diff two small OCSF-shaped scans and print newly failing checks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


Finding = dict[str, str]
Key = tuple[str, str]


def _files(source: Path) -> list[Path]:
    if source.is_dir():
        files = sorted(source.glob("*.ocsf.json"))
        if not files:
            raise ValueError(f"no OCSF JSON files in {source}")
        return files
    if not source.is_file():
        raise ValueError(f"input is not readable: {source}")
    return [source]


def load_findings(source: str | Path) -> dict[Key, Finding]:
    """Load a file or directory, collapsing duplicates so any FAIL wins."""
    findings: dict[Key, Finding] = {}
    for path in _files(Path(source)):
        records = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(records, list):
            raise ValueError(f"expected a JSON list: {path}")
        for index, record in enumerate(records):
            location = f"{path}: record {index}"
            if not isinstance(record, dict):
                raise ValueError(f"{location} must be an object")
            metadata = record.get("metadata")
            if not isinstance(metadata, dict):
                raise ValueError(f"{location} metadata must be an object")
            resources = record.get("resources")
            if not isinstance(resources, list) or not resources:
                raise ValueError(f"{location} resources must be a non-empty list")
            if not isinstance(resources[0], dict):
                raise ValueError(f"{location} first resource must be an object")
            finding_info = record.get("finding_info", {})
            if not isinstance(finding_info, dict):
                raise ValueError(f"{location} finding_info must be an object")
            item = {
                "event_code": str(metadata.get("event_code", "")),
                "resource_uid": str(resources[0].get("uid", "")),
                "status_code": str(record.get("status_code", "")),
                "severity": str(record.get("severity", "unknown")),
                "title": str(finding_info.get("title", "")),
            }
            key = (item["event_code"], item["resource_uid"])
            if not all(key):
                continue
            if key not in findings or item["status_code"] == "FAIL":
                findings[key] = item
    return findings


def diff_findings(
    yesterday: dict[Key, Finding], today: dict[Key, Finding]
) -> tuple[list[Finding], list[Finding]]:
    new_failures = [
        item
        for key, item in today.items()
        if item["status_code"] == "FAIL"
        and yesterday.get(key, {}).get("status_code") != "FAIL"
    ]
    resolved = [
        item
        for key, item in today.items()
        if item["status_code"] != "FAIL"
        and yesterday.get(key, {}).get("status_code") == "FAIL"
    ]
    order = lambda item: (item["event_code"], item["resource_uid"])
    return sorted(new_failures, key=order), sorted(resolved, key=order)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("yesterday", type=Path)
    parser.add_argument("today", type=Path)
    args = parser.parse_args()
    try:
        before = load_findings(args.yesterday)
        after = load_findings(args.today)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        print(f"UNREADABLE INPUT: {error}")
        return 2

    new_failures, resolved = diff_findings(before, after)
    if args.as_json:
        print(json.dumps({"new_failures": new_failures, "resolved": resolved}))
    else:
        for item in new_failures:
            print(
                "NEW FAILURE  "
                f"{item['severity']}  {item['event_code']}  {item['resource_uid']}"
            )
    return 1 if new_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
