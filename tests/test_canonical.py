"""Canonical JSON compatibility tests for the public verifier."""

import hashlib
import json
from pathlib import Path
import unittest

import verify


VECTORS = Path(__file__).parent / "fixtures" / "bundle-v1" / "canonical-vectors.json"


class CanonicalJsonTests(unittest.TestCase):
    def test_contract_vectors(self) -> None:
        vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
        for vector in vectors:
            with self.subTest(source=vector["json"]):
                value = json.loads(vector["json"])
                canonical = verify.canonical(value)
                self.assertEqual(vector["canonical"], canonical)
                self.assertEqual(
                    vector["sha256"],
                    hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                )

    def test_bool_precedes_integer(self) -> None:
        self.assertEqual("true", verify.canonical(True))

    def test_small_number_uses_javascript_notation(self) -> None:
        self.assertEqual("1e-7", verify.canonical(1e-7))


if __name__ == "__main__":
    unittest.main()
