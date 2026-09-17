"""Tests for the small scan-to-scan drift teaching tool."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import drift_diff


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "drift"


class DriftDiffTests(unittest.TestCase):
    def run_cli(self, *args: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "drift_diff.py"), *(str(arg) for arg in args)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_new_failures_resolved_and_unchanged(self) -> None:
        yesterday = drift_diff.load_findings(FIXTURES / "yesterday.json")
        today = drift_diff.load_findings(FIXTURES / "today.json")
        new_failures, resolved = drift_diff.diff_findings(yesterday, today)
        self.assertEqual(
            ["new_identity_check", "storage_public_access"],
            sorted(item["event_code"] for item in new_failures),
        )
        self.assertEqual(
            ["duplicate_example", "logging_enabled"],
            sorted(item["event_code"] for item in resolved),
        )
        self.assertNotIn(
            "encryption_enabled", [item["event_code"] for item in new_failures + resolved]
        )

    def test_any_duplicate_failure_wins(self) -> None:
        yesterday = drift_diff.load_findings(FIXTURES / "yesterday.json")
        duplicate = yesterday[("duplicate_example", "resource-example-01")]
        self.assertEqual("FAIL", duplicate["status_code"])
        self.assertEqual("high", duplicate["severity"])

    def test_cli_text_and_json_contract(self) -> None:
        text = self.run_cli(FIXTURES / "yesterday.json", FIXTURES / "today.json")
        self.assertEqual(1, text.returncode)
        self.assertIn("NEW FAILURE  high  storage_public_access  bucket-example-01", text.stdout)

        result = self.run_cli(
            "--json", FIXTURES / "yesterday.json", FIXTURES / "today.json"
        )
        self.assertEqual(1, result.returncode)
        payload = json.loads(result.stdout)
        self.assertEqual(2, len(payload["new_failures"]))
        self.assertEqual(2, len(payload["resolved"]))

    def test_no_new_failure_exits_zero(self) -> None:
        result = self.run_cli(FIXTURES / "today.json", FIXTURES / "today.json")
        self.assertEqual(0, result.returncode)

    def test_unreadable_input_exits_two(self) -> None:
        result = self.run_cli(FIXTURES / "missing.json", FIXTURES / "today.json")
        self.assertEqual(2, result.returncode)

    def test_directory_reads_every_ocsf_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            source = json.loads((FIXTURES / "today.json").read_text(encoding="utf-8"))
            midpoint = len(source) // 2
            (target / "a.ocsf.json").write_text(json.dumps(source[:midpoint]))
            (target / "b.ocsf.json").write_text(json.dumps(source[midpoint:]))
            findings = drift_diff.load_findings(target)
            self.assertEqual(5, len(findings))


if __name__ == "__main__":
    unittest.main()
