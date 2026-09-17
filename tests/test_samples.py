"""Public examples remain runnable and internally consistent."""

from pathlib import Path
import json
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SampleBundleTests(unittest.TestCase):
    def test_example_bundle_verifies(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "verify.py"), str(ROOT / "examples/evidence-bundle")],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("VERIFIED"), result.stdout)

    def test_mapping_samples_are_small_and_well_formed(self) -> None:
        check_id = re.compile(r"^[a-z0-9_]+$")
        for name in ("hipaa-sample.json", "soc2-sample.json"):
            with self.subTest(name=name):
                sample = json.loads((ROOT / "mappings" / name).read_text(encoding="utf-8"))
                self.assertLessEqual(len(sample["requirements"]), 5)
                self.assertEqual("Apache-2.0", sample["license"])
                self.assertIn("allow-list", sample["note"])
                for requirement in sample["requirements"]:
                    self.assertTrue(requirement["check_ids"])
                    self.assertTrue(all(check_id.fullmatch(item) for item in requirement["check_ids"]))


if __name__ == "__main__":
    unittest.main()
