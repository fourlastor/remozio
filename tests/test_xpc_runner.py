import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "xpc_runner", Path(__file__).resolve().parents[1] / "scripts/run-macos-xpc-experiment.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ExperimentTests(unittest.TestCase):
    def test_wrong_server_baseline_requires_observed_dispatch(self):
        result = subprocess.CompletedProcess([], 3, "rejected:NSCocoaErrorDomain:4102", "")
        self.assertTrue(runner.case_matches("wrong-server-requirement", result, 3, True))
        self.assertFalse(runner.case_matches("wrong-server-requirement", result, 3, False))
        self.assertFalse(runner.case_matches("guarded-wrong-server", result, 3, True))
        self.assertTrue(runner.case_matches("guarded-wrong-server", result, 3, False))

    def test_frame_cases_require_dispatch_only_for_matching_peers(self):
        accepted = subprocess.CompletedProcess([], 0, "accepted", "")
        rejected = subprocess.CompletedProcess([], 3, "rejected:NSCocoaErrorDomain:4102", "")
        for name in ("frame-bytes", "frame-empty", "frame-nil", "exchange-bytes", "exchange-empty", "exchange-nil", "setup-bytes", "setup-empty", "setup-nil"):
            self.assertTrue(runner.case_matches(name, accepted, 0, True))
            self.assertFalse(runner.case_matches(name, accepted, 0, False))
        for name in ("frame-wrong-client", "frame-wrong-server", "exchange-wrong-client", "exchange-wrong-server", "setup-wrong-client", "setup-wrong-server"):
            self.assertTrue(runner.case_matches(name, rejected, 3, False))
            self.assertFalse(runner.case_matches(name, rejected, 3, True))

    def test_setup_progress_has_no_nonce_payload(self):
        accepted = subprocess.CompletedProcess([], 0, "accepted", "")
        self.assertTrue(runner.case_matches("setup-progress", accepted, 0, False))
        self.assertFalse(runner.case_matches("setup-progress", accepted, 0, True))

    def test_crash_and_timeout_are_not_rejections(self):
        for code in (-5, 4):
            result = subprocess.CompletedProcess([], code, "rejected:error", "")
            self.assertFalse(runner.case_matches("wrong-client-identifier", result, 3, False))

    def test_cleanup_after_interrupted_bootstrap(self):
        report = {}
        with patch.object(runner, "command", side_effect=KeyboardInterrupt), patch.object(
            runner.subprocess, "run", side_effect=[
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess([], 113, "", "Could not find service x"),
            ]
        ) as process:
            with self.assertRaises(KeyboardInterrupt):
                with runner.registered_service("gui/501", "x", Path("test.plist"), report):
                    self.fail("Interrupted bootstrap must not enter the body")
        self.assertEqual(process.call_args_list[0].args[0], ["/bin/launchctl", "bootout", "gui/501/x"])
        self.assertEqual(report["temporaryService"], "gui/501/x")
        self.assertTrue(report["cleanup"]["serviceAbsent"])

    def test_cleanup_does_not_treat_permission_errors_as_absence(self):
        report = {}
        with patch.object(runner, "command"), patch.object(runner.time, "sleep"), patch.object(
            runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "Permission denied")
        ):
            with self.assertRaisesRegex(RuntimeError, "Could not confirm removal"):
                with runner.registered_service("gui/501", "x", Path("test.plist"), report):
                    pass
        self.assertFalse(report["cleanup"]["serviceAbsent"])


if __name__ == "__main__":
    unittest.main()
