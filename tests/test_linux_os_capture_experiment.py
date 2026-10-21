import importlib.util
import ctypes
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
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


def lifecycle_host_supported():
    if (sys.version_info < (3, 11) or platform.system() != "Linux" or platform.machine() != "x86_64" or
            os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid()):
        return False
    try:
        Path(f"/proc/self/task/{os.getpid()}/children").read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        return False
    return True


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

    def run_cli(self, work, output, error=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", [str(MODULE.__file__), "--work-dir", str(work), "--output", str(output)]), \
                patch.object(MODULE, "run", return_value=self.report(), side_effect=error) as run, \
                redirect_stdout(stdout), redirect_stderr(stderr):
            status = MODULE.main()
        run.assert_called_once_with(work, 30, 600)
        self.assertEqual(stderr.getvalue(), "")
        for private in (str(ROOT), str(work), str(output), "Traceback"):
            self.assertNotIn(private, stdout.getvalue())
        return status, stdout.getvalue()

    def assert_cli_failure(self, status, stdout):
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(stdout), {"passed": False, "error": "experimentFailed"})

    def test_cli_publishes_success_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / "report.json"
            status, stdout = self.run_cli(root / "work", output)
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(stdout), self.report())
            self.assertEqual(output.read_text(encoding="utf-8"), stdout)

    def test_cli_missing_output_parent_returns_sanitized_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / "private-missing-parent" / "report.json"
            for error in (None, RuntimeError(f"private failure at {ROOT}")):
                with self.subTest(experiment_failed=error is not None):
                    self.assert_cli_failure(*self.run_cli(root / "work", output, error))
            self.assertFalse(output.parent.exists())

    def test_cli_unwritable_output_does_not_report_stale_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / "private-unwritable-report.json"
            # Inject denial so this portable CLI test also works under root.
            failure = PermissionError(13, "permission denied", str(output))
            with patch.object(Path, "write_text", side_effect=failure) as write:
                self.assert_cli_failure(*self.run_cli(root / "work", output))
            write.assert_called_once()
            self.assertTrue(json.loads(write.call_args.args[0])["passed"])
            self.assertFalse(output.exists())

    def test_cli_experiment_failure_still_publishes_sanitized_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / "report.json"
            status, stdout = self.run_cli(root / "work", output, RuntimeError(f"private failure at {ROOT}"))
            self.assert_cli_failure(status, stdout)
            self.assertEqual(output.read_text(encoding="utf-8"), stdout)

    def test_lifecycle_gate_matches_runner_prerequisites(self):
        supported = {"python": (3, 11), "system": "Linux", "machine": "x86_64",
                     "uid": 1000, "euid": 1000, "gid": 1000, "egid": 1000}
        cases = (
            ("supported", {}, None),
            ("old-python", {"python": (3, 10)}, None),
            ("other-system", {"system": "Darwin"}, None),
            ("other-architecture", {"machine": "aarch64"}, None),
            ("root", {"uid": 0, "euid": 0}, None),
            ("different-effective-uid", {"euid": 1001}, None),
            ("different-effective-gid", {"egid": 1001}, None),
            ("missing-children", {}, FileNotFoundError("children unavailable")),
            ("unreadable-children", {}, PermissionError("children unavailable")),
            ("non-ascii-children", {}, UnicodeDecodeError("ascii", b"\xff", 0, 1, "children unavailable")),
        )
        for name, changes, read_error in cases:
            host = supported | changes
            with self.subTest(host=name), ExitStack() as stack:
                stack.enter_context(patch.object(sys, "version_info", host["python"]))
                for field in ("system", "machine"):
                    stack.enter_context(patch.object(platform, field, return_value=host[field]))
                for field in ("uid", "euid", "gid", "egid"):
                    stack.enter_context(patch.object(os, f"get{field}", return_value=host[field]))
                stack.enter_context(patch.object(Path, "read_text", return_value="", side_effect=read_error))
                inventory = stack.enter_context(patch.object(MODULE, "source_inventory",
                    side_effect=RuntimeError("preflight reached")))
                subreaper = stack.enter_context(patch.object(MODULE._helpers, "subreaper"))
                worker = stack.enter_context(patch.object(MODULE._helpers, "run_owned"))
                self.assertEqual(lifecycle_host_supported(), name == "supported")
                if name == "supported":
                    with self.assertRaisesRegex(RuntimeError, "preflight reached"):
                        MODULE.run(Path("/tmp/os-capture-prerequisite-test"))
                    inventory.assert_called_once_with()
                else:
                    case = LinuxOSCaptureCleanupTests("test_runner_owns_adopts_and_reaps_descendant_then_restores_state")
                    with patch.object(ctypes, "CDLL") as libc, self.assertRaises(unittest.SkipTest):
                        case.setUp()
                    libc.assert_not_called()
                    with self.assertRaisesRegex((ValueError, OSError, UnicodeDecodeError),
                                                "unsupported host|children unavailable"):
                        MODULE.run(Path("/tmp/os-capture-prerequisite-test"))
                    inventory.assert_not_called()
                subreaper.assert_not_called()
                worker.assert_not_called()


class LinuxOSCaptureCleanupTests(unittest.TestCase):
    def setUp(self):
        if not lifecycle_host_supported():
            self.skipTest("requires the OS-capture runner's supported host and readable task children")
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
        for failing_phase, reason in enumerate(("swift version", "build failed", "native result")):
            calls = []

            def worker(arguments, timeout, **kwargs):
                self.assertEqual(self.subreaper_state(), 1)
                phase = len(calls); calls.append(arguments)
                if phase == failing_phase:
                    return b"", 1, None, True
                return (b"Swift version 6.2.4" if phase == 0 else b""), 0, None, True

            with self.subTest(phase=failing_phase), tempfile.TemporaryDirectory() as directory, \
                    patch.object(MODULE._helpers, "run_owned", side_effect=worker), self.assertRaisesRegex(ValueError, reason):
                MODULE.run(Path(directory))
            self.assertEqual(len(calls), failing_phase + 1)
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
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(adopted), 1)
        with self.assertRaises(ChildProcessError):
            os.waitpid(adopted[0], os.WNOHANG)


if __name__ == "__main__":
    unittest.main()
