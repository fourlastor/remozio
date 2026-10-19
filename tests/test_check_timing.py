"""Timing must preserve gates, exit status and structured child output."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("timed_macos_build_checks", ROOT / "scripts/macos_build_checks.py")
CHECKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKS)


class CheckStageTimingTests(unittest.TestCase):
    def run_checks(self, system="Linux", github=False, fail_argument=""):
        with tempfile.TemporaryDirectory(prefix="timed checks ") as temporary:
            directory = Path(temporary)
            (directory / "repo/scripts").mkdir(parents=True)
            binary = directory / "bin"
            binary.mkdir()
            shutil.copy2(ROOT / "scripts/check.sh", directory / "repo/scripts/check.sh")
            stub = '''#!/bin/sh
printf '%s %s\\n' "${0##*/}" "$*" >> "$CHECK_TIMING_LOG"
printf '%s\\n' 'child stdout'
printf '%s\\n' 'child stderr' >&2
if [ -n "${FAIL_ARGUMENT:-}" ] && [ "${1:-}" = "$FAIL_ARGUMENT" ]; then exit 23; fi
'''
            for name in ("python3", "swift", "git"):
                path = binary / name
                path.write_text(stub)
                path.chmod(0o755)
            uname = binary / "uname"
            uname.write_text('#!/bin/sh\nprintf "%s\\n" "$CHECK_SYSTEM"\n')
            uname.chmod(0o755)
            log = directory / "calls"
            env = os.environ | {"PATH": str(binary) + os.pathsep + os.environ["PATH"],
                                "CHECK_SYSTEM": system, "CHECK_TIMING_LOG": str(log),
                                "GITHUB_ACTIONS": "true" if github else "false", "FAIL_ARGUMENT": fail_argument}
            result = subprocess.run(["/bin/sh", str(directory / "repo/scripts/check.sh")], cwd=directory,
                                    env=env, capture_output=True, text=True, timeout=10)
            return result, log.read_text().splitlines()

    def test_local_timing_keeps_child_streams_and_command_arguments(self):
        result, calls = self.run_checks()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["python3 -m unittest discover -s tests -p test_*.py",
                                 "python3 -m unittest discover -s .agents/skills/babysit-pr/scripts -p test_*.py",
                                 "git diff --check"])
        self.assertEqual(result.stdout, "child stdout\n" * 3)
        self.assertEqual(result.stderr.count("child stderr\n"), 3)
        self.assertEqual(result.stderr.count("Stage timing:"), 3)
        self.assertNotIn("::group::", result.stderr)
        self.assertRegex(result.stderr, r"Stage timing: Working-tree whitespace: [0-9]+s \(exit 0\)")

    def test_failed_native_stage_closes_group_preserves_exit_and_stops_later_checks(self):
        result, calls = self.run_checks("Darwin", github=True, fail_argument="scripts/check-macos-app.py")
        self.assertEqual(result.returncode, 23)
        self.assertEqual(calls[-1], "python3 scripts/check-macos-app.py")
        self.assertFalse(any("run-native-bootstrap-file-experiment.py" in call for call in calls))
        self.assertFalse(any(call.startswith("git ") for call in calls))
        self.assertEqual(result.stderr.count("::group::"), len(calls))
        self.assertEqual(result.stderr.count("::endgroup::"), len(calls))
        self.assertRegex(result.stderr, r"Stage timing: check-macos-app: [0-9]+s \(exit 23\)")
        self.assertEqual(result.stdout, "child stdout\n" * len(calls))


class CapturedBuildTimingTests(unittest.TestCase):
    def test_build_timing_preserves_captured_output_without_printing_arguments(self):
        arguments = ("swift", "build", "--private-argument")
        completed = subprocess.CompletedProcess(arguments, 0, '{"structured":true}\n', "private compiler output")
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(CHECKS.subprocess, "run", return_value=completed) as run, \
             patch.object(CHECKS.time, "monotonic", side_effect=[10.0, 12.5]), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertIs(CHECKS.run(*arguments), completed)
        run.assert_called_once_with(arguments, text=True, capture_output=True)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "Command timing: swift build: 2.500s (exit 0)\n")
        self.assertNotIn("private", stderr.getvalue())
        self.assertEqual(completed.stdout, '{"structured":true}\n')
        self.assertEqual(completed.stderr, "private compiler output")

    def test_failed_build_still_reports_duration_and_keeps_error_behavior(self):
        completed = subprocess.CompletedProcess(("xcodebuild", "build"), 9, "", "original diagnostic")
        stderr = io.StringIO()
        with patch.object(CHECKS.subprocess, "run", return_value=completed), \
             patch.object(CHECKS.time, "monotonic", side_effect=[4.0, 7.0]), \
             contextlib.redirect_stderr(stderr), self.assertRaisesRegex(RuntimeError, "xcodebuild exited 9: original diagnostic"):
            CHECKS.run("xcodebuild", "build")
        self.assertEqual(stderr.getvalue(), "Command timing: xcodebuild build: 3.000s (exit 9)\n")

    def test_path_query_is_distinct_from_a_build_and_inspections_stay_quiet(self):
        completed = subprocess.CompletedProcess((), 0, "/synthetic/products", "")
        stderr = io.StringIO()
        with patch.object(CHECKS.subprocess, "run", return_value=completed), \
             patch.object(CHECKS.time, "monotonic", side_effect=[1.0, 1.25, 2.0]), contextlib.redirect_stderr(stderr):
            self.assertIs(CHECKS.run("swift", "build", "--show-bin-path"), completed)
            self.assertIs(CHECKS.run("codesign", "--verify", "/synthetic/product"), completed)
        self.assertEqual(stderr.getvalue(), "Command timing: swift path query: 0.250s (exit 0)\n")


if __name__ == "__main__":
    unittest.main()
