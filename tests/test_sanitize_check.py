"""Tests for the public-repository sanitization gate."""

import unittest

from tools.sanitize_check import scan_text


class SanitizeCheckTests(unittest.TestCase):
    def assert_flagged(self, path: str, text: str, denylist=()) -> None:
        self.assertTrue(scan_text(path, text, denylist), (path, text))

    def assert_clean(self, path: str, text: str, denylist=()) -> None:
        self.assertEqual([], scan_text(path, text, denylist))

    def test_flags_sensitive_identifiers(self) -> None:
        engine = "prow" + "ler"
        cases = [
            ("notes.txt", "account " + ("4" * 12), ()),
            ("notes.txt", "ocid" + "1.bucket.oc1..letters", ()),
            ("notes.txt", "arn" + ":aws:s3:::private-bucket", ()),
            ("notes.txt", "someone" + "@corp.example", ()),
            ("notes.txt", "private-host", ("private-host",)),
            ("notes.txt", engine, ()),
        ]
        for path, text, denylist in cases:
            with self.subTest(text=text):
                self.assert_flagged(path, text, denylist)

    def test_allows_documentation_values_and_digests(self) -> None:
        engine = "prow" + "ler"
        cases = [
            "f3843501552908fe" + ("a" * 48),
            "0" * 64,
            "123456789012",
            "maintainer@example.com",
        ]
        for text in cases:
            with self.subTest(text=text):
                self.assert_clean("notes.txt", text)
        self.assert_clean(
            "README.md", f"Scan engine attribution: {engine} (Apache-2.0)"
        )

    def test_engine_attribution_is_narrow(self) -> None:
        engine = "prow" + "ler"
        self.assert_flagged("README.md", f"Uses {engine}")
        self.assert_flagged(
            "notes.txt", f"Scan engine attribution: {engine} (Apache-2.0)"
        )

    def test_new_file_naming_engine_fails(self) -> None:
        engine = "prow" + "ler"
        self.assert_flagged("new_public_file.py", f"scanner = {engine!r}")

    def test_legacy_paths_only_exempt_engine_rule(self) -> None:
        engine = "prow" + "ler"
        legacy_paths = (
            "caiq_autofill.py",
            "examples/run_scan.sh",
            "docs/evidence-as-code.md",
        )
        for path in legacy_paths:
            with self.subTest(path=path):
                self.assert_clean(path, engine)
                problems = scan_text(path, engine + " " + ("4" * 12))
                self.assertEqual(["account_id"], [rule for _, rule in problems])


if __name__ == "__main__":
    unittest.main()
