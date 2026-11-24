from contextlib import redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-macos-live-frontend.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("live_frontend_runner", SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


@unittest.skipUnless(os.name == "posix", "The fixture requires private POSIX process groups")
class TimeoutCleanupTests(unittest.TestCase):
    def test_second_timeout_kills_and_reaps_the_owned_runner(self):
        real_popen = subprocess.Popen
        processes = []
        calls = []

        def factory(*_args, **_kwargs):
            child = real_popen([sys.executable, "-c",
                "import signal, threading; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "print('READY', flush=True); threading.Event().wait()"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            processes.append(child)
            ready, _, _ = select.select([child.stdout], [], [], 10)
            self.assertTrue(ready, "The owned child must install its handler before the timeout starts")
            self.assertEqual(child.stdout.readline(), b"READY\n")

            class BoundedTimeouts:
                def __getattr__(self, name):
                    return getattr(child, name)

                def communicate(self, timeout):
                    calls.append(timeout)
                    return child.communicate(timeout=0.1)

            return BoundedTimeouts()

        try:
            helpers = {name: Path("/unused") for name in ["supervisor", "monitor", "child", "target"]}
            with patch.object(RUNNER.subprocess, "Popen", side_effect=factory):
                with self.assertRaises(subprocess.TimeoutExpired):
                    RUNNER.invoke(Path("/unused"), helpers, "job")
            self.assertEqual(calls, [60, 20])
            self.assertEqual(len(processes), 1)
            self.assertEqual(processes[0].returncode, -signal.SIGKILL)
            self.assertTrue(processes[0].stdout.closed)
            self.assertTrue(processes[0].stderr.closed)
            with self.assertRaises(ChildProcessError):
                os.waitpid(processes[0].pid, os.WNOHANG)
        finally:
            # Keep this regression safe even when the cleanup implementation fails.
            for child in processes:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
                child.stdout.close()
                child.stderr.close()


class StaleTraceTests(unittest.TestCase):
    evidence = {
        "nativeSupervisorStatus": 13 << 8,
        "oneOriginalAdmission": True,
        "separateAuthorityAndFrontend": True,
        "actualMonitorAndTargetReaped": True,
        "durableVerifiedOutcome": True,
        "frontend": {
            "frontendCleanupCompleted": True,
            "freshStoppedQueries": 0,
            "freshRunningQueries": 1,
            "originalContinuations": 1,
        },
    }

    def invoke(self, output, *, actions, returncode=0):
        process = Mock(returncode=returncode)
        process.poll.return_value = returncode
        process.communicate.return_value = output, b"STALE_TRACE frontend started\nother fixture log\n"
        helpers = {name: Path("/unused") for name in ["supervisor", "monitor", "child", "target"]}
        stderr = io.StringIO()
        failure = None
        with patch.dict(os.environ, {"GITHUB_ACTIONS": actions}), redirect_stderr(stderr), \
                patch.object(RUNNER.subprocess, "Popen", return_value=process) as popen:
            try:
                RUNNER.invoke(Path("/unused"), helpers, "stale")
            except (ValueError, RuntimeError) as error:
                failure = error
        return popen.call_args.kwargs["env"], stderr.getvalue(), failure

    def test_ci_success_keeps_trace_quiet(self):
        env, trace, failure = self.invoke(json.dumps(self.evidence).encode(), actions="true")
        self.assertEqual(env["REMOZIO_CI_STALE_TRACE"], "1")
        self.assertEqual(trace, "")
        self.assertIsNone(failure)

    def test_ci_evidence_failure_reports_only_phase_trace(self):
        env, trace, failure = self.invoke(b"{}", actions="true")
        self.assertEqual(env["REMOZIO_CI_STALE_TRACE"], "1")
        self.assertEqual(trace, "STALE_TRACE frontend started\n")
        self.assertIsInstance(failure, RuntimeError)

    def test_ci_process_failure_includes_trace_in_existing_error(self):
        _, trace, failure = self.invoke(b"", actions="true", returncode=1)
        self.assertEqual(trace, "")
        self.assertIn("STALE_TRACE frontend started", str(failure))

    def test_local_run_keeps_trace_disabled(self):
        env, trace, failure = self.invoke(b"{}", actions="false")
        self.assertNotIn("REMOZIO_CI_STALE_TRACE", env)
        self.assertEqual(trace, "")
        self.assertIsInstance(failure, RuntimeError)


class SourceEvidenceTests(unittest.TestCase):
    shared_inputs = [
        "host/shared-core/Sources/RemozioHostCore/DecisionVerifier.swift",
        "host/shared-core/Package.swift",
        "host/shared-core/Package.resolved",
    ]

    def shared_fixture(self, root):
        for name in self.shared_inputs:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("before")
        for path in RUNNER.source_files():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("before")

    def run_shared_change(self, name, phase):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(RUNNER, "ROOT", root), patch.object(RUNNER, "PACKAGE", root / "experiments/command-frontend"), \
                    patch.object(RUNNER, "NATIVE", root / "macos/core/Sources/RemozioMach"), \
                    patch.object(RUNNER, "__file__", str(root / "scripts/run-macos-live-frontend.py")), \
                    patch.object(RUNNER, "BUILD", root), patch.object(RUNNER.os, "geteuid", return_value=1000):
                self.shared_fixture(root)
                def compile_fixture():
                    if phase == "compilation":
                        (root / name).write_text("after")
                    return Path("/unused"), {}
                def measure_fixture(*_args):
                    if phase == "measurement":
                        (root / name).write_text("after")
                    return {}
                with patch.object(RUNNER, "build", side_effect=compile_fixture), \
                        patch.object(RUNNER, "invoke", side_effect=measure_fixture) as invoke, \
                        patch.object(RUNNER, "measure_forced_cleanup", return_value={}):
                    with self.assertRaisesRegex(RuntimeError, f"source changed during {phase}"):
                        RUNNER.main()
                    if phase == "compilation":
                        invoke.assert_not_called()
                self.assertFalse((root / "evidence.json").exists())

    def test_shared_input_change_during_build_stops_before_measurement(self):
        for name in self.shared_inputs:
            with self.subTest(name=name):
                self.run_shared_change(name, "compilation")

    def test_shared_input_change_during_measurement_prevents_evidence(self):
        for name in self.shared_inputs:
            with self.subTest(name=name):
                self.run_shared_change(name, "measurement")

    def test_shared_source_addition_during_build_stops_before_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(RUNNER, "ROOT", root), patch.object(RUNNER, "PACKAGE", root / "experiments/command-frontend"), \
                    patch.object(RUNNER, "NATIVE", root / "macos/core/Sources/RemozioMach"), \
                    patch.object(RUNNER, "__file__", str(root / "scripts/run-macos-live-frontend.py")), \
                    patch.object(RUNNER, "BUILD", root), patch.object(RUNNER.os, "geteuid", return_value=1000):
                self.shared_fixture(root)
                def compile_then_add():
                    source = root / "host/shared-core/Sources/RemozioHostCore/nested/NewVerifier.swift"
                    source.parent.mkdir(parents=True)
                    source.write_text("new source")
                    return Path("/unused"), {}
                with patch.object(RUNNER, "build", side_effect=compile_then_add), \
                        patch.object(RUNNER, "invoke") as invoke:
                    with self.assertRaisesRegex(RuntimeError, "source set changed during compilation"):
                        RUNNER.main()
                    invoke.assert_not_called()
                self.assertFalse((root / "evidence.json").exists())

    def test_source_change_during_build_stops_before_measurement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "target.c"
            source.write_text("before")
            evidence = root / "evidence.json"
            evidence.write_text("stale evidence")

            def compile_then_edit():
                self.assertEqual(source.read_text(), "before")
                source.write_text("after")
                return Path("/unused"), {}

            with patch.object(RUNNER, "BUILD", root), patch.object(RUNNER, "source_files", return_value=[source]), \
                    patch.object(RUNNER, "ROOT", root), patch.object(RUNNER.os, "geteuid", return_value=1000), \
                    patch.object(RUNNER, "build", side_effect=compile_then_edit), patch.object(RUNNER, "invoke") as invoke:
                with self.assertRaisesRegex(RuntimeError, "source changed during compilation"):
                    RUNNER.main()
                invoke.assert_not_called()
            self.assertFalse(evidence.exists())


if __name__ == "__main__":
    unittest.main()
