#!/usr/bin/env python3
"""Verify a small evidence bundle with a hash-chained provenance ledger."""

from __future__ import annotations

import argparse
from decimal import Decimal
import hashlib
import json
import math
from pathlib import Path
from typing import Any


GENESIS = "0" * 64


class BundleError(ValueError):
    """The directory does not contain a ledger that can be verified."""


def _javascript_float(value: float) -> str:
    """Format a finite float like JavaScript ``Number.toString`` for JSON."""
    if not math.isfinite(value):
        raise ValueError("canonical JSON does not support non-finite numbers")
    if value == 0:
        return "0"

    negative = value < 0
    decimal_value = Decimal(repr(abs(value)))
    digits = list(decimal_value.as_tuple().digits)
    exponent = decimal_value.as_tuple().exponent
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1

    raw = "".join(str(digit) for digit in digits)
    count = len(raw)
    decimal_position = count + exponent

    if count <= decimal_position <= 21:
        rendered = raw + ("0" * (decimal_position - count))
    elif 0 < decimal_position <= 21:
        rendered = raw[:decimal_position] + "." + raw[decimal_position:]
    elif -6 < decimal_position <= 0:
        rendered = "0." + ("0" * -decimal_position) + raw
    else:
        mantissa = raw[0] + (("." + raw[1:]) if count > 1 else "")
        scientific_exponent = decimal_position - 1
        sign = "+" if scientific_exponent >= 0 else "-"
        rendered = f"{mantissa}e{sign}{abs(scientific_exponent)}"

    return ("-" if negative else "") + rendered


def canonical(value: Any) -> str:
    """Return deterministic JSON compatible with JavaScript serialization."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _javascript_float(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        return "{" + ",".join(
            canonical(key) + ":" + canonical(value[key]) for key in sorted(value)
        ) + "}"
    raise TypeError(f"unsupported canonical JSON type: {type(value).__name__}")


def sha256_hex(data: str | bytes) -> str:
    """Return the lowercase SHA-256 hex digest of text or bytes."""
    payload = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(payload).hexdigest()


def _load_ledger(bundle: Path) -> dict[str, Any]:
    ledger_path = bundle / "provenance.json"
    if not ledger_path.is_file():
        raise BundleError("provenance.json is missing")
    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError("provenance.json is not valid JSON") from error
    if not isinstance(ledger, dict) or not isinstance(ledger.get("entries"), list):
        raise BundleError("provenance.json lacks an entries list")
    if not ledger["entries"]:
        raise BundleError("provenance.json contains no entries")
    return ledger


def verify_bundle(bundle: str | Path) -> tuple[str, list[tuple[int, str]]]:
    """Verify ledger records, their chain, and the latest entry's artifacts."""
    directory = Path(bundle)
    entries = _load_ledger(directory)["entries"]
    problems: list[tuple[int, str]] = []
    expected_previous = GENESIS

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems.append((index, "record_tampered"))
            expected_previous = None
            continue
        sequence = entry.get("sequence", index)
        report_sequence = sequence if isinstance(sequence, int) else index
        if sequence != index:
            problems.append((report_sequence, "sequence_gap"))

        unsigned = dict(entry)
        stored_digest = unsigned.pop("record_digest", None)
        try:
            recomputed = sha256_hex(canonical(unsigned))
        except (TypeError, ValueError):
            recomputed = None
        if recomputed != stored_digest:
            problems.append((report_sequence, "record_tampered"))
        if entry.get("prev_digest") != expected_previous:
            problems.append((report_sequence, "chain_broken"))
        expected_previous = stored_digest

    latest = entries[-1]
    latest_sequence = latest.get("sequence", len(entries) - 1)
    for artifact in latest.get("artifacts", []):
        name = artifact.get("name", "") if isinstance(artifact, dict) else ""
        relative = Path(name)
        safe = bool(name) and not relative.is_absolute() and ".." not in relative.parts
        path = directory / relative if safe else None
        if path is None or not path.is_file():
            problems.append((latest_sequence, "artifact_missing"))
        elif sha256_hex(path.read_bytes()) != artifact.get("digest"):
            problems.append((latest_sequence, "artifact_altered"))

    return ("not_verified" if problems else "verified", problems)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    try:
        ledger = _load_ledger(args.bundle)
        verdict, problems = verify_bundle(args.bundle)
    except BundleError as error:
        print(f"NOTHING TO VERIFY: {error}")
        return 2

    if problems:
        print("NOT VERIFIED")
        for sequence, kind in problems:
            print(f"[entry #{sequence}] {kind}")
        return 1

    latest = ledger["entries"][-1]
    print(
        "VERIFIED "
        f"entry={latest['sequence']} generated_at={latest['generated_at']} "
        f"record_digest={latest['record_digest']}"
    )
    for artifact in latest.get("artifacts", []):
        print(f"artifact={artifact['name']} digest={artifact['digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
