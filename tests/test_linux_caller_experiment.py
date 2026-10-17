import importlib.util
import json
import os
from pathlib import Path
import platform
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-caller-experiment.py"
spec = importlib.util.spec_from_file_location("linux_caller_experiment", SCRIPT)
experiment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(experiment)


class LinuxCallerReportTests(unittest.TestCase):
    def test_only_exact_boolean_checks_and_successful_exit_pass(self):
        case = "same_pid_exec"
        valid = {"passed": True, "checks": dict.fromkeys(experiment.EXPECTED[case], True)}
        self.assertEqual(experiment.validate_result(json.dumps(valid), case, 0), valid)
        invalid = [None, {}, {**valid, "extra": True},
                   {**valid, "checks": {}}, {**valid, "passed": 1},
                   {**valid, "checks": dict.fromkeys(experiment.EXPECTED[case], 1)},
                   {**valid, "checks": dict.fromkeys(experiment.EXPECTED[case], False)}]
        for result in invalid:
            with self.subTest(result=result), self.assertRaises(ValueError):
                experiment.validate_result(json.dumps(result), case, 0)
        with self.assertRaises(ValueError):
            experiment.validate_result(json.dumps(valid), case, 1)

    def test_error_report_discards_private_strings(self):
        result = experiment.validate_result(json.dumps({"passed": False, "error_type": "/private/example",
                                                        "errno": "secret", "error": "private path"}), "kernel_ipc", 1)
        self.assertEqual(result, {"passed": False, "error_type": "ProbeFailure", "errno": None})

    def test_refused_host_or_elevation_never_spawns(self):
        with patch.object(experiment.platform, "system", return_value="Darwin"), patch.object(experiment, "invoke") as invoke:
            with self.assertRaisesRegex(RuntimeError, "Linux"):
                experiment.measure()
            invoke.assert_not_called()
        with patch.object(experiment.platform, "system", return_value="Linux"), patch.object(experiment.platform, "machine", return_value="x86_64"), patch.object(experiment.os, "geteuid", return_value=0), patch.object(experiment, "invoke") as invoke:
            with self.assertRaisesRegex(RuntimeError, "without elevation"):
                experiment.measure()
            invoke.assert_not_called()

    @unittest.skipUnless(platform.system() == "Linux", "Linux process cleanup")
    def test_timeout_kills_and_reaps_worker_and_its_descendant(self):
        code = "import os,time; os.fork(); time.sleep(30)"
        with experiment.subreaper():
            result = experiment.invoke([sys.executable, "-c", code], 0.15, "kernel_ipc")
        self.assertEqual(result, {"passed": False, "error_type": "TimeoutError", "errno": None,
                                  "cleanup_reaped_all_fixture_children": True})

    @unittest.skipUnless(platform.system() == "Linux", "Linux process cleanup")
    def test_invalid_output_is_rejected_and_reaped(self):
        with experiment.subreaper():
            result = experiment.invoke([sys.executable, "-c", "print('private invalid output')"], 3, "kernel_ipc")
        self.assertFalse(result["passed"])
        self.assertEqual(result["error_type"], "InvalidProbeReport")
        self.assertTrue(result["cleanup_reaped_all_fixture_children"])
        self.assertNotIn("private", json.dumps(result))

    @unittest.skipUnless(platform.system() == "Linux", "Linux process cleanup")
    def test_completed_group_without_owned_live_members_is_never_signaled(self):
        # Include an adopted zombie so cleanup must drain terminal statuses too.
        code = "import os; os.fork(); os._exit(0)"
        with experiment.subreaper(), patch.object(experiment.os, "killpg") as killpg:
            result = experiment.invoke([sys.executable, "-c", code], 3, "kernel_ipc")
        killpg.assert_not_called()
        self.assertTrue(result["cleanup_reaped_all_fixture_children"])

    @unittest.skipUnless(platform.system() == "Linux", "Linux process cleanup")
    def test_reaped_worker_still_retires_its_owned_live_descendant(self):
        code = "import os,time\nif os.fork() == 0:\n os.close(1); time.sleep(30)\nelse:\n os._exit(0)"
        with experiment.subreaper(), patch.object(experiment.os, "killpg", wraps=os.killpg) as killpg:
            result = experiment.invoke([sys.executable, "-c", code], 3, "kernel_ipc")
        killpg.assert_called_once()
        self.assertTrue(result["cleanup_reaped_all_fixture_children"])

    @unittest.skipUnless(platform.system() == "Linux", "Linux process cleanup")
    def test_retire_never_signals_an_already_reaped_or_exited_child(self):
        probe_spec = importlib.util.spec_from_file_location("linux_caller_probe", experiment.PROBE)
        probe = importlib.util.module_from_spec(probe_spec)
        probe_spec.loader.exec_module(probe)
        for already_reaped in (False, True):
            child = os.fork()
            if child == 0:
                os._exit(4)
            if already_reaped:
                os.waitpid(child, 0)
            else:
                # Leave the terminal child owned, but prove it has exited before retire.
                os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT)
            with self.subTest(already_reaped=already_reaped), patch.object(probe.os, "kill") as kill:
                probe.retire(child)
                kill.assert_not_called()
            with self.assertRaises(ChildProcessError):
                os.waitpid(child, os.WNOHANG)

    @unittest.skipUnless(os.environ.get("REMOZIO_LINUX_CALLER_LIVE") == "1", "explicit owned-process live probe")
    def test_live_kernel_caller_fixtures(self):
        report = experiment.measure()
        self.assertTrue(report["passed"], report["cases"])
        self.assertEqual(set(report["cases"]), set(experiment.CASES))
        self.assertTrue(all(item["cleanup_reaped_all_fixture_children"] for item in report["cases"].values()))


if __name__ == "__main__":
    unittest.main()
