"""Profiling one XCTest must preserve its result and own every sampled process."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("core_test_profile", ROOT / "scripts/profile-core-test.py")
PROFILE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROFILE
SPEC.loader.exec_module(PROFILE)

TEST = (
    "RemozioCoreTests.GatewayRuntimeActivationOperationTests/"
    "testCompleteOperationPublishesOnlyTheOptionalGatewayAndReleasesTheWriterBeforeRegistration"
)
PASSED_LINE = (
    f"Test Case 'GatewayRuntimeActivationOperationTests.{TEST.split('/')[1]}' passed (5.0 seconds).\n"
).encode()
PASS_LOG = b"Complete native test diagnostics\n" * 2048 + PASSED_LINE + b"Executed 1 test, with 0 failures in 5.0 seconds\n"
INHERITED_ENVIRONMENT = {"PATH": "/synthetic/bin", "SWIFT_TESTING_ENABLED": "1"}


class CoreTestProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="core test profile ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.bundle = self.root / "RemozioCorePackageTests.xctest"
        self.bundle.mkdir()
        self.bundle_alias = self.root / "selected bundle.xctest"
        self.bundle_alias.symlink_to(self.bundle, target_is_directory=True)
        self.sequence = 0

    def profile(self, *, target_exit=0, sample_exit=0, target_finish=6, sample_finish=3,
                stack=True, sample_launch_error=False, test_log=PASS_LOG, timeout=60):
        self.sequence += 1
        output = self.root / f"result-{self.sequence}"
        clock = SimpleNamespace(now=100.0, sleeps=0)
        children = {}
        killed = set()
        reaped = set()
        commands = []
        events = []
        target_pid, sample_pid = 32110, 32111

        def spawn(command, **options):
            commands.append(command)
            if len(commands) == 1:
                pid = target_pid
                options["stdout"].write(test_log)
            else:
                self.assertEqual(len(commands), 2, "Only one target and one sampler may launch")
                if sample_launch_error:
                    raise OSError("synthetic sampler launch failure")
                pid = sample_pid
                options["stdout"].write(b"Complete sampler diagnostics\n")
                if stack:
                    Path(command[-1]).write_text("Synthetic stack trace\n")
            events.append(("spawn", pid))
            child = SimpleNamespace(pid=pid, returncode=None)
            children[pid] = child
            return child

        def wait4(pid, options):
            events.append(("wait4", pid))
            self.assertEqual(options, os.WNOHANG)
            self.assertIn(pid, children)
            self.assertNotIn(pid, reaped, "A reaped PID must not be polled again")
            finish = target_finish if pid == target_pid else sample_finish
            if pid not in killed and clock.now < 100.0 + finish:
                return 0, 0, None
            reaped.add(pid)
            events.append(("reap", pid))
            exit_code = target_exit if pid == target_pid else sample_exit
            status = signal.SIGKILL if pid in killed else exit_code << 8
            usage = SimpleNamespace(ru_utime=1.25 if pid == target_pid else .25, ru_stime=.125)
            return pid, status, usage

        def killpg(pid, sent_signal):
            self.assertIn(pid, children)
            self.assertNotIn(pid, reaped, "Never signal a reaped process group")
            self.assertEqual(sent_signal, signal.SIGKILL)
            killed.add(pid)

        def sleep(_seconds):
            clock.sleeps += 1
            self.assertLess(clock.sleeps, 1000, "Mocked polling failed to terminate")
            clock.now += 1.0

        with patch.dict(PROFILE.os.environ, INHERITED_ENVIRONMENT, clear=True), \
             patch.object(PROFILE, "resolve_xctest", return_value=Path("/resolved/toolchain/usr/bin/xctest")) as resolve, \
             patch.object(PROFILE.subprocess, "Popen", side_effect=spawn) as popen, \
             patch.object(PROFILE.subprocess, "run", side_effect=AssertionError("Unexpected real command")), \
             patch.object(PROFILE.os, "wait4", side_effect=wait4) as wait, \
             patch.object(PROFILE.os, "killpg", side_effect=killpg) as kill, \
             patch.object(PROFILE.time, "monotonic", side_effect=lambda: clock.now), \
             patch.object(PROFILE.time, "sleep", side_effect=sleep):
            status = PROFILE.run_profile(self.bundle_alias, output, timeout)
        return SimpleNamespace(status=status, output=output, report=json.loads((output / "report.json").read_text()),
                               popen=popen, wait=wait, kill=kill, resolve=resolve,
                               target_pid=target_pid, sample_pid=sample_pid, events=events)

    def test_samples_exact_owned_xctest_with_fixed_filter_and_complete_logs(self):
        result = self.profile()
        self.assertEqual(result.status, 0)
        result.resolve.assert_called_once_with()
        target, sampler = result.popen.call_args_list
        self.assertEqual(target.args, (["/resolved/toolchain/usr/bin/xctest", "-XCTest", TEST, str(self.bundle)],))
        self.assertEqual(sampler.args, (["/usr/bin/sample", str(result.target_pid), "10", "-file",
                                        str(result.output / "stacks.txt")],))
        for invocation, log in ((target, "test.log"), (sampler, "sample.log")):
            self.assertTrue(invocation.kwargs["start_new_session"])
            self.assertEqual(invocation.kwargs["stderr"], subprocess.STDOUT)
            self.assertEqual(invocation.kwargs["stdout"].name, str(result.output / log))
            self.assertTrue(invocation.kwargs["stdout"].closed)
        self.assertEqual(target.kwargs["env"], INHERITED_ENVIRONMENT)
        self.assertEqual((result.output / "test.log").read_bytes(), PASS_LOG)
        self.assertEqual((result.output / "sample.log").read_bytes(), b"Complete sampler diagnostics\n")
        self.assertTrue(result.report["test"]["exactOneTestPassed"])
        self.assertEqual(result.report["test"]["pid"], result.target_pid)
        self.assertEqual(result.report["sample"]["pid"], result.sample_pid)
        self.assertEqual(result.report["test"]["userCPUSeconds"], 1.25)
        self.assertEqual(result.report["sample"]["userCPUSeconds"], .25)
        result.kill.assert_not_called()

    def test_target_pid_is_not_reaped_while_sampler_still_references_it(self):
        result = self.profile(target_finish=3, sample_finish=8)
        self.assertEqual(result.status, 0)
        launched = result.events.index(("spawn", result.sample_pid))
        retired = result.events.index(("reap", result.sample_pid))
        self.assertNotIn(("wait4", result.target_pid), result.events[launched:retired])
        self.assertGreater(result.events.index(("reap", result.target_pid)), retired)
        result.kill.assert_not_called()

    def test_nonzero_test_exit_is_preserved_when_sampling_succeeds(self):
        result = self.profile(target_exit=7)
        self.assertEqual(result.report["sample"]["returncode"], 0)
        self.assertTrue(result.report["sample"]["stackFilePresent"])
        self.assertEqual(result.report["test"]["returncode"], 7)
        self.assertEqual(result.report["exitStatus"], 7)
        self.assertEqual(result.status, 7)

    def test_failed_missing_or_unlaunchable_sampler_cannot_report_success(self):
        for scenario in ({"sample_exit": 9}, {"stack": False}, {"sample_launch_error": True}):
            with self.subTest(scenario=scenario):
                result = self.profile(**scenario)
                self.assertEqual(result.report["test"]["returncode"], 0)
                self.assertTrue(result.report["test"]["exactOneTestPassed"])
                self.assertTrue(result.report["sample"]["attempted"])
                self.assertEqual(result.status, 2)
                result.kill.assert_not_called()

    def test_test_timeout_kills_only_the_unreaped_owned_test_group(self):
        result = self.profile(target_finish=100, timeout=30)
        result.kill.assert_called_once_with(result.target_pid, signal.SIGKILL)
        self.assertEqual(result.status, 124)
        self.assertTrue(result.report["test"]["timedOut"])
        self.assertEqual(result.report["test"]["returncode"], -signal.SIGKILL)
        self.assertEqual(result.report["sample"]["returncode"], 0)
        self.assertTrue(result.report["cleanupComplete"])

    def test_sampler_timeout_does_not_terminate_or_replace_the_test_result(self):
        result = self.profile(target_finish=40, sample_finish=100, timeout=60)
        result.kill.assert_called_once_with(result.sample_pid, signal.SIGKILL)
        self.assertEqual(result.report["test"]["returncode"], 0)
        self.assertFalse(result.report["test"]["timedOut"])
        self.assertTrue(result.report["sample"]["timedOut"])
        self.assertEqual(result.report["sample"]["returncode"], -signal.SIGKILL)
        self.assertEqual(result.status, 2)
        self.assertTrue(result.report["cleanupComplete"])

    def test_already_finished_test_is_never_sampled_or_signaled(self):
        result = self.profile(target_finish=0)
        self.assertEqual(result.popen.call_count, 1)
        result.wait.assert_called_once_with(result.target_pid, os.WNOHANG)
        result.kill.assert_not_called()
        self.assertEqual(result.report["test"]["returncode"], 0)
        self.assertFalse(result.report["sample"]["attempted"])
        self.assertEqual(result.status, 2)

    def test_zero_multiple_or_skipped_tests_refuse_successful_profile(self):
        for summary in (b"Executed 0 tests, with 0 failures\n",
                        b"Executed 2 tests, with 0 failures\n",
                        b"1 test skipped\nExecuted 1 test, with 0 failures\n"):
            with self.subTest(summary=summary):
                result = self.profile(test_log=PASSED_LINE + summary)
                self.assertEqual(result.report["test"]["returncode"], 0)
                self.assertEqual(result.report["sample"]["returncode"], 0)
                self.assertFalse(result.report["test"]["exactOneTestPassed"])
                self.assertEqual(result.status, 2)

    def test_unrelated_passing_test_cannot_satisfy_the_fixed_selection(self):
        case, method = TEST.split("/", 1)
        for passed_line in (PASSED_LINE.decode(), f"Test Case '-[{case} {method}]' passed (5.0 seconds).\n"):
            with self.subTest(format=passed_line):
                self.assertTrue(PROFILE.exact_test_summary(passed_line + "Executed 1 test, with 0 failures\n"))
        log = b"Test Case 'UnrelatedTests.testSomethingElse' passed (0.01 seconds).\n" \
              b"Executed 1 test, with 0 failures in 0.01 seconds\n"
        result = self.profile(test_log=log)
        self.assertEqual(result.report["test"]["returncode"], 0)
        self.assertEqual(result.report["sample"]["returncode"], 0)
        self.assertFalse(result.report["test"]["exactOneTestPassed"])
        self.assertEqual(result.status, 2)

    def test_invalid_bundle_output_or_timeout_refuses_before_launch(self):
        wrong_bundle = self.root / "UnrelatedTests.xctest"
        wrong_bundle.mkdir()
        regular_file = self.root / "RemozioCoreOtherTests.xctest"
        regular_file.write_text("not a bundle")
        existing = self.root / "existing-output"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_text("keep")
        cases = ((wrong_bundle, self.root / "wrong-output", 60),
                 (regular_file, self.root / "file-output", 60),
                 (self.root / "absent.xctest", self.root / "missing-output", 60),
                 (self.bundle, existing, 60),
                 (self.bundle, self.root / "short-timeout", 0),
                 (self.bundle, self.root / "long-timeout", 601))
        with patch.object(PROFILE, "resolve_xctest") as resolve, \
             patch.object(PROFILE.subprocess, "Popen") as popen, \
             patch.object(PROFILE.os, "wait4") as wait, \
             patch.object(PROFILE.os, "killpg") as kill:
            for bundle, output, timeout in cases:
                with self.subTest(bundle=bundle, output=output, timeout=timeout), \
                     self.assertRaises((OSError, ValueError)):
                    PROFILE.run_profile(bundle, output, timeout)
            resolve.assert_not_called()
            popen.assert_not_called()
            wait.assert_not_called()
            kill.assert_not_called()
        self.assertEqual(sentinel.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
