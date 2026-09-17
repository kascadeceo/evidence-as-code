"""Contract and command-line tests for evidence bundle verification."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import verify


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "bundle-v1"
EXPECTED = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))


class VerifyBundleTests(unittest.TestCase):
    def run_cli(self, bundle: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "verify.py"), str(bundle)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_fixture_verdicts_and_problem_order(self) -> None:
        for name, expected in EXPECTED.items():
            with self.subTest(case=name):
                verdict, problems = verify.verify_bundle(FIXTURES / name)
                self.assertEqual(expected["verdict"], verdict)
                self.assertEqual(
                    [(item["sequence"], item["kind"]) for item in expected["problems"]],
                    problems,
                )

    def test_fixture_cli_contract(self) -> None:
        for name, expected in EXPECTED.items():
            with self.subTest(case=name):
                result = self.run_cli(FIXTURES / name)
                self.assertEqual(expected["exit_code"], result.returncode, result.stderr)
                prefix = "VERIFIED" if expected["exit_code"] == 0 else "NOT VERIFIED"
                self.assertTrue(result.stdout.startswith(prefix), result.stdout)
        altered = self.run_cli(FIXTURES / "tampered-artifact")
        self.assertIn("[entry #1] artifact_altered", altered.stdout)

    def test_missing_or_malformed_ledger_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            missing = self.run_cli(bundle)
            self.assertEqual(2, missing.returncode)
            (bundle / "provenance.json").write_text("{}", encoding="utf-8")
            malformed = self.run_cli(bundle)
            self.assertEqual(2, malformed.returncode)
            self.assertEqual(1, len(malformed.stdout.strip().splitlines()))

    def test_one_byte_edit_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            shutil.copytree(FIXTURES / "verified", bundle)
            with (bundle / "ssp.md").open("ab") as artifact:
                artifact.write(b"\n")
            verdict, problems = verify.verify_bundle(bundle)
            self.assertEqual("not_verified", verdict)
            self.assertEqual([(1, "artifact_altered")], problems)


if __name__ == "__main__":
    unittest.main()
