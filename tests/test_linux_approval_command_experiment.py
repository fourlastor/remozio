import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/run-linux-approval-command-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_approval_command_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


def valid_report(mode="approve"):
    return {"passed": True, "checks": dict.fromkeys(EXPERIMENT.CHECKS, True),
            "observations": EXPERIMENT.OBSERVATIONS[mode].copy()}


@contextlib.contextmanager
def ordinary_linux():
    with contextlib.ExitStack() as stack:
        for owner, name, value in ((EXPERIMENT.platform, "system", "Linux"),
                                   (EXPERIMENT.platform, "machine", "x86_64"),
                                   (EXPERIMENT.os, "getuid", 1000), (EXPERIMENT.os, "geteuid", 1000),
                                   (EXPERIMENT.os, "getgid", 1000), (EXPERIMENT.os, "getegid", 1000)):
            stack.enter_context(patch.object(owner, name, return_value=value))
        yield


class ApprovalCommandReportTests(unittest.TestCase):
    def test_exact_fixed_reports_accept_only_successful_fixture_exits(self):
        for mode in EXPERIMENT.OBSERVATIONS:
            report = valid_report(mode)
            with self.subTest(mode=mode):
                self.assertEqual(EXPERIMENT.validate_result(json.dumps(report), mode, 0), report)
                with self.assertRaises(ValueError):
                    EXPERIMENT.validate_result(json.dumps(report), mode, 86)

    def test_malformed_extra_wrong_phase_and_numeric_booleans_never_count_as_denial(self):
        good = valid_report("bad-signature")
        key = next(iter(EXPERIMENT.CHECKS))
        variants = [None, {}, [], {**good, "passed": 1}, {**good, "passed": False},
                    {**good, "private": "/do/not/publish"}, {**good, "checks": {}},
                    {**good, "checks": {**good["checks"], key: 1}},
                    {**good, "observations": {**good["observations"], "phase": "succeeded"}},
                    {**good, "observations": {**good["observations"], "decisionResult": "malformedCapture"}},
                    {**good, "observations": {**good["observations"], "executions": False}},
                    {**good, "observations": {**good["observations"], "physicalPhone": 0}},
                    {**good, "observations": {**good["observations"], "pid": 1234}}]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                EXPERIMENT.validate_result(json.dumps(value), "bad-signature", 0)
        for value in (b"\xff", "NaN", '{"passed":true,"passed":true}', "private stdout",
                      "x" * (EXPERIMENT.MAX_OUTPUT_BYTES + 1)):
            with self.subTest(raw=value[:20]), self.assertRaises(ValueError):
                EXPERIMENT.validate_result(value, "bad-signature", 0)

    def test_marker_appending_detects_second_launch_and_rejects_symlinks_or_empty_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker = directory / "command.marker"
            self.assertTrue(EXPERIMENT.marker_matches(directory, 0))
            self.assertFalse(EXPERIMENT.marker_matches(directory, 1))
            marker.write_bytes(EXPERIMENT.MARKER)
            self.assertTrue(EXPERIMENT.marker_matches(directory, 1))
            self.assertFalse(EXPERIMENT.marker_matches(directory, 0))
            with marker.open("ab") as stream:
                stream.write(EXPERIMENT.MARKER)
            self.assertFalse(EXPERIMENT.marker_matches(directory, 1))
            marker.write_bytes(b"")
            self.assertFalse(EXPERIMENT.marker_matches(directory, 0))
            marker.unlink()
            marker.symlink_to(directory / "missing-target")
            self.assertFalse(EXPERIMENT.marker_matches(directory, 0))

    def test_crash_requires_exit86_empty_stdout_and_exact_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for output, code in ((b"", 0), (b"{}", 86), (b"private", 86), (b"", -9)):
                with self.subTest(code=code), patch.object(EXPERIMENT, "run_owned", return_value=(output, code, None, True)):
                    result = EXPERIMENT.invoke(Path("unused"), "crash-before-launch", directory, 1, 0)
                    self.assertEqual(result, EXPERIMENT.failure("UnexpectedCrashResult", True))
            with patch.object(EXPERIMENT, "run_owned", return_value=(b"", 86, None, True)):
                self.assertTrue(EXPERIMENT.invoke(Path("unused"), "crash-before-launch", directory, 1, 0)["passed"])
                self.assertEqual(EXPERIMENT.invoke(Path("unused"), "crash-after-output", directory, 1, 1),
                                 EXPERIMENT.failure("ExecutionMarkerMismatch", True))

    def test_fixture_report_cannot_override_independent_marker_or_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            raw = json.dumps(valid_report()).encode()
            with patch.object(EXPERIMENT, "run_owned", return_value=(raw, 0, None, True)):
                self.assertEqual(EXPERIMENT.invoke(Path("unused"), "approve", directory, 1),
                                 EXPERIMENT.failure("ExecutionMarkerMismatch", True))
            (directory / "command.marker").write_bytes(EXPERIMENT.MARKER)
            with patch.object(EXPERIMENT, "run_owned", return_value=(raw, 0, None, False)):
                self.assertEqual(EXPERIMENT.invoke(Path("unused"), "approve", directory, 1),
                                 EXPERIMENT.failure("CleanupFailure", False))

    def test_recovery_reopens_same_private_directory_after_crash_and_failed_seed_skips_recovery(self):
        calls = []

        def invoke(_binary, mode, directory, _timeout, expected_crash_count=None):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            calls.append((mode, directory))
            return {"passed": mode != "crash-before-launch"}

        with ordinary_linux(), patch.object(EXPERIMENT, "subreaper", contextlib.nullcontext), \
             patch.object(EXPERIMENT._helpers, "check_prerequisites"), \
             patch.object(EXPERIMENT, "swift_version", return_value="6.2.3"), \
             patch.object(EXPERIMENT, "build_fixture", return_value=Path("/not-executed")), \
             patch.object(EXPERIMENT, "invoke", side_effect=invoke), \
             patch.object(EXPERIMENT, "source_hashes", return_value={}):
            report = EXPERIMENT.measure()
        by_mode = dict(calls)
        self.assertEqual(by_mode["approve"], by_mode["reopen-completed"])
        self.assertEqual(by_mode["crash-after-output"], by_mode["recover-after-output"])
        self.assertNotIn("recover-before-launch", by_mode)
        self.assertEqual(report["cases"]["recover-before-launch"]["error_type"], "PrerequisiteFailed")
        self.assertFalse(report["passed"])
        self.assertFalse(any(directory.exists() for _, directory in calls))

    def test_refused_runtime_elevation_paths_and_deadlines_never_build_or_spawn(self):
        with ordinary_linux(), patch.object(EXPERIMENT.platform, "system", return_value="Darwin"), \
             patch.object(EXPERIMENT, "build_fixture") as build, patch.object(EXPERIMENT, "run_owned") as worker:
            with self.assertRaises(RuntimeError):
                EXPERIMENT.measure()
            build.assert_not_called(); worker.assert_not_called()
        with ordinary_linux(), patch.object(EXPERIMENT.os, "geteuid", return_value=0), \
             patch.object(EXPERIMENT, "build_fixture") as build:
            with self.assertRaises(RuntimeError):
                EXPERIMENT.measure()
            build.assert_not_called()
        for timeout in (True, 0, -1, 61, float("nan"), float("inf"), "15"):
            with ordinary_linux(), self.subTest(timeout=timeout), patch.object(EXPERIMENT, "build_fixture") as build:
                with self.assertRaises(ValueError):
                    EXPERIMENT.measure(timeout=timeout)
                build.assert_not_called()
        with ordinary_linux(), patch.object(EXPERIMENT, "build_fixture") as build:
            with self.assertRaises(ValueError):
                EXPERIMENT.measure(work_dir=Path("relative"))
            build.assert_not_called()

    def test_changed_sources_cannot_produce_success_and_cli_diagnostic_does_not_echo_paths(self):
        with ordinary_linux(), patch.object(EXPERIMENT, "subreaper", contextlib.nullcontext), \
             patch.object(EXPERIMENT._helpers, "check_prerequisites"), \
             patch.object(EXPERIMENT, "swift_version", return_value="6.2.3"), \
             patch.object(EXPERIMENT, "build_fixture", return_value=Path("/not-executed")), \
             patch.object(EXPERIMENT, "invoke", return_value={"passed": True}), \
             patch.object(EXPERIMENT, "source_hashes", side_effect=[{"source": "before"}, {"source": "after"}]), \
             self.assertRaisesRegex(RuntimeError, "source inputs changed"):
            EXPERIMENT.measure()
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(EXPERIMENT.sys, "argv", [str(SCRIPT)]), \
             patch.object(EXPERIMENT, "measure", side_effect=RuntimeError("/private/changed/source")), \
             patch.object(EXPERIMENT.sys, "stdout", stdout), patch.object(EXPERIMENT.sys, "stderr", stderr), \
             self.assertRaises(SystemExit) as raised:
            EXPERIMENT.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "Approval-command experiment unavailable; no raw diagnostic data published.\n")

    def test_missing_proc_children_support_refuses_before_build_or_fixtures(self):
        with ordinary_linux(), patch.object(EXPERIMENT._helpers, "check_prerequisites", side_effect=RuntimeError("private proc error")), \
             patch.object(EXPERIMENT, "build_fixture") as build, patch.object(EXPERIMENT, "run_owned") as worker:
            with self.assertRaises(RuntimeError):
                EXPERIMENT.measure()
            build.assert_not_called(); worker.assert_not_called()

    def test_swift_build_uses_reusable_locked_paths_and_four_jobs_without_diagnostic_echo(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "build/debug/LinuxApprovalCommandFixture"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"not executed")
            binary.chmod(0o700)
            with patch.object(EXPERIMENT.shutil, "which", return_value="/tool/swift"), \
                 patch.object(EXPERIMENT, "run_owned", return_value=(b"private build text", 0, None, True)) as worker:
                self.assertEqual(EXPERIMENT.build_fixture(directory, 9), binary)
            arguments, timeout, bound = worker.call_args.args
            self.assertEqual(timeout, 9)
            self.assertEqual(bound, EXPERIMENT.MAX_BUILD_OUTPUT_BYTES)
            self.assertEqual(arguments[-5:], ["--disable-keychain", "--disable-netrc", "--force-resolved-versions", "--jobs", "4"])
            self.assertEqual(worker.call_args.kwargs["env"]["CLANG_MODULE_CACHE_PATH"], str(directory / "module-cache"))
            self.assertEqual(worker.call_args.kwargs["env"]["SWIFTPM_MODULECACHE_OVERRIDE"], str(directory / "module-cache"))
            for flag, name in (("--cache-path", "cache"), ("--config-path", "config"),
                               ("--security-path", "security"), ("--scratch-path", "build")):
                self.assertEqual(arguments[arguments.index(flag) + 1], str(directory / name))
            with patch.object(EXPERIMENT.shutil, "which", return_value="/tool/swift"), \
                 patch.object(EXPERIMENT, "run_owned", return_value=(b"private/secret", 1, None, True)):
                with self.assertRaisesRegex(RuntimeError, "bounded fixture build failed") as raised:
                    EXPERIMENT.build_fixture(directory, 9)
            self.assertNotIn("private", str(raised.exception))

    def test_source_inventory_covers_swift_sqlite_headers_modulemaps_and_lockfiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            packages = [root / name for name in ("experiments/linux-approval-command", "protocol/swift", "host/shared-core")]
            for package in packages:
                for name in ("Package.swift", "Package.resolved", "Sources/Entry.swift", "Sources/CSQLite/module.modulemap", "Sources/CSQLite/shim.h"):
                    path = package / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"synthetic input\n")
            helpers = [root / name for name in ("scripts/runner.py", "scripts/helper.py", "scripts/cleanup.py")]
            for path in helpers:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic input\n")
            with patch.object(EXPERIMENT, "ROOT", root), patch.object(EXPERIMENT, "PACKAGE", packages[0]), \
                 patch.object(EXPERIMENT, "__file__", str(helpers[0])), patch.object(EXPERIMENT, "HELPER", helpers[1]), \
                 patch.object(EXPERIMENT, "CLEANUP_SOURCE", helpers[2]):
                hashes = EXPERIMENT.source_hashes()
            self.assertEqual(len(hashes), 18)
            self.assertEqual(set(hashes.values()), {hashlib.sha256(b"synthetic input\n").hexdigest()})
            self.assertIn("host/shared-core/Sources/CSQLite/shim.h", hashes)
            self.assertIn("experiments/linux-approval-command/Package.resolved", hashes)
            self.assertNotIn(temporary, json.dumps(hashes))

    def test_metadata_and_swift_version_are_bounded_numeric_public_values(self):
        with patch.object(EXPERIMENT.platform, "release", return_value="6.17.0-private-host"), \
             patch.object(EXPERIMENT.platform, "python_version", return_value="3.13.7/private-host"):
            metadata = EXPERIMENT.host_metadata("6.2.3")
        self.assertEqual(metadata["kernelVersion"], "6.17.0")
        self.assertEqual(metadata["pythonVersion"], "unknown")
        self.assertNotIn("private", json.dumps(metadata))
        for raw, accepted in ((b"Swift version 6.2.3 (private build metadata)", True),
                              (b"Swift version 6.1.9", False), (b"private version", False)):
            with self.subTest(raw=raw), patch.object(EXPERIMENT.shutil, "which", return_value="/tool/swift"), \
                 patch.object(EXPERIMENT, "run_owned", return_value=(raw, 0, None, True)):
                if accepted:
                    self.assertEqual(EXPERIMENT.swift_version(10), "6.2.3")
                else:
                    with self.assertRaises(RuntimeError):
                        EXPERIMENT.swift_version(10)


@unittest.skipUnless(platform.system() == "Linux", "owned Linux process groups")
class ApprovalCommandWorkerTests(unittest.TestCase):
    def owned(self, code, timeout=3):
        with EXPERIMENT.subreaper():
            return EXPERIMENT.run_owned([sys.executable, "-c", code], timeout)

    def test_timeout_and_cancellation_reap_worker_and_stdout_inheriting_descendant(self):
        _, _, error, clean = self.owned("import os,time; os.fork(); time.sleep(30)", 0.1)
        self.assertEqual(error, "TimeoutError"); self.assertTrue(clean)
        workers = []

        def interrupt(process, _timeout, _limit):
            self.assertEqual(process.stdout.readline(), b"ready\n")
            workers.append(process.pid)
            raise KeyboardInterrupt()

        with EXPERIMENT.subreaper(), patch.object(EXPERIMENT, "_read_output", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            EXPERIMENT.run_owned([sys.executable, "-c", "import os,time; os.fork(); print('ready',flush=True); time.sleep(30)"], 3)
        with self.assertRaises(ChildProcessError):
            os.waitpid(-workers[0], os.WNOHANG)

    def test_output_limit_retires_noisy_worker_and_completed_groups_are_not_signaled(self):
        _, _, error, clean = self.owned(f"import os,time; os.fork(); os.write(1,b'x'*{EXPERIMENT.MAX_OUTPUT_BYTES + 8192}); time.sleep(30)")
        self.assertEqual(error, "OutputLimitError"); self.assertTrue(clean)
        with patch.object(EXPERIMENT._helpers.os, "killpg") as kill:
            _, code, error, clean = self.owned("import os; os._exit(0)")
        self.assertEqual(code, 0); self.assertIsNone(error); self.assertTrue(clean)
        kill.assert_not_called()

    def test_invalid_output_with_live_descendant_is_failure_and_reaps_it(self):
        code = "import os,time\nif os.fork()==0:\n os.close(1); time.sleep(30)\nelse:\n print('/private/secret',flush=True); os._exit(0)"
        with tempfile.TemporaryDirectory() as temporary, EXPERIMENT.subreaper():
            # invoke accepts argv only for the fixed native CLI; exercise the same
            # bounded worker primitive here and its report validation separately.
            output, returncode, error, clean = EXPERIMENT.run_owned([sys.executable, "-c", code], 3)
        self.assertIsNone(error); self.assertTrue(clean)
        with self.assertRaises(ValueError):
            EXPERIMENT.validate_result(output, "bad-signature", returncode)


class ApprovalCommandCheckIntegrationTests(unittest.TestCase):
    def test_linux_host_check_keeps_shared_suite_then_runs_the_reusable_fixture(self):
        with tempfile.TemporaryDirectory(prefix="approval check ") as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir(); (root / "bin").mkdir()
            script = root / "scripts/check-linux-host.sh"
            shutil.copyfile(ROOT / "scripts/check-linux-host.sh", script)
            log = root / "calls.jsonl"
            for tool in ("swift", "python3"):
                stub = root / "bin" / tool
                stub.write_text(f"#!{sys.executable}\nimport json,os,sys\nwith open(os.environ['FIXTURE_LOG'],'a') as f: f.write(json.dumps([os.path.basename(sys.argv[0])]+sys.argv[1:])+'\\n')\n")
                stub.chmod(0o700)
            uname = root / "bin/uname"
            uname.write_text("#!/bin/sh\nprintf '%s\\n' Linux\n")
            uname.chmod(0o700)
            environment = {**os.environ, "PATH": str(root / "bin") + os.pathsep + os.environ.get("PATH", ""),
                           "REMOZIO_SWIFT_WORK_DIR": str(root / "reusable build"), "REMOZIO_SWIFT_JOBS": "4", "FIXTURE_LOG": str(log)}
            subprocess.run(["sh", str(script)], env=environment, check=True, capture_output=True, timeout=10)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(calls[0], ["swift", "--version"])
            self.assertEqual(calls[1][:4], ["swift", "test", "--package-path", "host/shared-core"])
            self.assertIn("--force-resolved-versions", calls[1])
            self.assertEqual(calls[1][-2:], ["--jobs", "4"])
            self.assertEqual(calls[2], ["python3", "scripts/run-linux-approval-command-experiment.py", "--work-dir", str(root / "reusable build/approval-command")])


@unittest.skipUnless(os.environ.get("REMOZIO_LINUX_APPROVAL_COMMAND_LIVE") == "1", "explicit real fixed-command fixture")
class ApprovalCommandLiveTests(unittest.TestCase):
    def test_signed_approval_fixed_execution_and_restart_controls(self):
        report = EXPERIMENT.measure()
        self.assertTrue(report["passed"], report["cases"])
        self.assertFalse(report["productionAuthority"])
        self.assertFalse(report["physicalPhone"])
        self.assertFalse(report["hardwareKeys"])


if __name__ == "__main__":
    unittest.main()
