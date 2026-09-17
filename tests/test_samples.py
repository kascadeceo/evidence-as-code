"""Public examples remain runnable and internally consistent."""

from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
