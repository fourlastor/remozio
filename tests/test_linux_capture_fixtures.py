"""Keep the checked-in schema 4 corpus reproducible from its synthetic source."""

from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LinuxCaptureFixtureTests(unittest.TestCase):
    def test_generated_corpus_is_current(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/generate-linux-capture-fixtures.py"), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
