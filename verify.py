#!/usr/bin/env python3
"""Verify a small evidence bundle with a hash-chained provenance ledger."""

from __future__ import annotations

from decimal import Decimal
import hashlib
import json
import math
from typing import Any


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
