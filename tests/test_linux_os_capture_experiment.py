import importlib.util
import ctypes
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("linux_os_capture", ROOT / "scripts/run-linux-os-capture-experiment.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LinuxOSCaptureReportTests(unittest.TestCase):
    def report(self):
        return {"passed": True, "checks": dict.fromkeys(MODULE.CHECKS, True), "observations": MODULE.OBSERVATIONS.copy()}

    def validate(self, value, code=0):
        return MODULE.validate_result(json.dumps(value).encode(), code)

    def test_exact_scope_is_required(self):
        self.assertTrue(self.validate(self.report())["passed"])
        for field, value in MODULE.OBSERVATIONS.items():
            with self.subTest(field=field):
                report = self.report()
                report["observations"][field] = not value if type(value) is bool else value + 1
                with self.assertRaises(ValueError):
                    self.validate(report)

    def test_unknown_missing_and_nonboolean_checks_fail(self):
        for operation in (lambda c: c.update(extra=True), lambda c: c.pop(next(iter(c))),
                          lambda c: c.update({next(iter(c)): 1}), lambda c: c.update({next(iter(c)): False})):
            report = self.report()
            operation(report["checks"])
            with self.assertRaises(ValueError):
                self.validate(report)

    def test_scope_types_and_extra_data_fail(self):
        for key, value in (("trustedCode", 0), ("schemaVersion", True), ("commandsExecuted", False), ("privatePath", "/private")):
            report = self.report()
            report["observations"][key] = value
            with self.assertRaises(ValueError):
                self.validate(report)

    def test_duplicates_excess_output_and_process_failure_fail(self):
        for raw, code in ((b'{"passed":true,"passed":true}', 0), (b"x" * 32769, 0),
                          (json.dumps(self.report()).encode(), 1), (b'{"passed":NaN}', 0)):
            with self.assertRaises(ValueError):
                MODULE.validate_result(raw, code)

    def test_manifest_covers_actual_protocol_and_component_sources(self):
        inventory = MODULE.source_inventory()
        for path in ("protocol/swift/Sources/RemozioProtocol/LinuxCommandCapture.swift",
                     "experiments/linux-os-capture/Sources/LinuxOSCaptureExperiment/Observation.swift",
                     "experiments/linux-os-capture/Sources/LinuxOSCaptureExperiment/main.swift",
                     "scripts/run-linux-caller-experiment.py"):
            self.assertIn(path, inventory)
            self.assertEqual(len(inventory[path]), 64)

    def test_build_is_bounded_and_uses_separate_paths(self):
        arguments = MODULE.swift_arguments(Path("/tmp/os-capture-test"))
        self.assertIn("--force-resolved-versions", arguments)
        for flag in ("--scratch-path", "--cache-path", "--config-path", "--security-path"):
            self.assertTrue(arguments[arguments.index(flag) + 1].startswith("/tmp/os-capture-test/"))
        self.assertEqual(arguments[arguments.index("--jobs") + 1], "4")


@unittest.skipUnless(platform.system() == "Linux", "Linux child subreaper lifecycle")
class LinuxOSCaptureCleanupTests(unittest.TestCase):
    def setUp(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.previous = self.subreaper_state()
        self.assertEqual(self.libc.prctl(36, 0, 0, 0, 0), 0)
        self.addCleanup(lambda: self.libc.prctl(36, self.previous, 0, 0, 0))

    def subreaper_state(self):
        state = ctypes.c_int()
        self.assertEqual(self.libc.prctl(37, ctypes.byref(state), 0, 0, 0), 0)
        return state.value

    def fixture_report(self):
        return json.dumps({"passed": True, "checks": dict.fromkeys(MODULE.CHECKS, True),
                           "observations": MODULE.OBSERVATIONS}).encode()

    def orphan_worker(self):
        # Only this owned Python fixture forks. The descendant proves adoption before its pipe closes.
        return f"""import os,time
if os.fork():
 os._exit(0)
deadline=time.monotonic()+2
while os.getppid()!={os.getpid()} and time.monotonic()<deadline:
 time.sleep(0.002)
if os.getppid()!={os.getpid()}:
 os.write(1,b'unadopted\\n'); os._exit(2)
os.write(1,('adopted:'+str(os.getpid())+'\\n').encode())
os.close(1)
time.sleep(10)
"""

    def test_runner_owns_adopts_and_reaps_descendant_then_restores_state(self):
        owned = MODULE._helpers.run_owned
        calls, adopted = [], []

        def worker(arguments, timeout, **kwargs):
            self.assertEqual(self.subreaper_state(), 1)
            calls.append(arguments)
            if len(calls) == 1:
                return b"Swift version 6.2.4", 0, None, True
            if len(calls) == 2:
                raw, code, error, clean = owned([sys.executable, "-c", self.orphan_worker()], 3)
                self.assertTrue(raw.startswith(b"adopted:"))
                adopted.append(int(raw.removeprefix(b"adopted:").strip()))
                self.assertEqual(code, 0); self.assertIsNone(error); self.assertTrue(clean)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(adopted[0], os.WNOHANG)
                return b"", 0, None, clean
            return self.fixture_report(), 0, None, True

        with tempfile.TemporaryDirectory() as directory, patch.object(MODULE._helpers, "run_owned", side_effect=worker):
            result = MODULE.run(Path(directory))
        self.assertTrue(result["cleanupReapedAllFixtureChildren"])
        self.assertEqual(len(calls), 3); self.assertEqual(len(adopted), 1)
        self.assertEqual(self.subreaper_state(), 0)

    def test_runner_restores_subreaper_after_each_worker_failure(self):
        for failing_phase in range(3):
            calls = []

            def worker(arguments, timeout, **kwargs):
                self.assertEqual(self.subreaper_state(), 1)
                phase = len(calls); calls.append(arguments)
                if phase == failing_phase:
                    return b"", 1, None, True
                return (b"Swift version 6.2.4" if phase == 0 else b""), 0, None, True

            with self.subTest(phase=failing_phase), tempfile.TemporaryDirectory() as directory, \
                    patch.object(MODULE._helpers, "run_owned", side_effect=worker), self.assertRaises(ValueError):
                MODULE.run(Path(directory))
            self.assertEqual(self.subreaper_state(), 0)

    def test_cancellation_reaps_adopted_child_and_restores_subreaper(self):
        owned = MODULE._helpers.run_owned
        calls, adopted = [], []

        def interrupt(process, _timeout, _limit):
            raw = process.stdout.readline()
            self.assertTrue(raw.startswith(b"adopted:"))
            adopted.append(int(raw.removeprefix(b"adopted:").strip()))
            raise KeyboardInterrupt()

        def worker(arguments, timeout, **kwargs):
            self.assertEqual(self.subreaper_state(), 1)
            calls.append(arguments)
            if len(calls) == 1:
                return b"Swift version 6.2.4", 0, None, True
            with patch.object(MODULE._helpers, "_read_output", side_effect=interrupt):
                return owned([sys.executable, "-c", self.orphan_worker()], 3)

        with tempfile.TemporaryDirectory() as directory, patch.object(MODULE._helpers, "run_owned", side_effect=worker), \
                self.assertRaises(KeyboardInterrupt):
            MODULE.run(Path(directory))
        self.assertEqual(self.subreaper_state(), 0)
        self.assertEqual(len(adopted), 1)
        with self.assertRaises(ChildProcessError):
            os.waitpid(adopted[0], os.WNOHANG)


if __name__ == "__main__":
    unittest.main()
