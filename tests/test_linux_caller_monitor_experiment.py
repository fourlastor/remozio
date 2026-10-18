import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest
from unittest.mock import mock_open, patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-caller-monitor-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_caller_monitor_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


def valid_report(case="healthy"):
    return {"passed": True, "checks": dict.fromkeys(EXPERIMENT.EXPECTED[case], True),
            "observations": EXPERIMENT.OBSERVATIONS[case].copy()}


@contextlib.contextmanager
def ordinary_linux():
    with contextlib.ExitStack() as stack:
        for owner, name, value in (
                (EXPERIMENT.platform, "system", "Linux"), (EXPERIMENT.platform, "machine", "x86_64"),
                (EXPERIMENT.os, "getuid", 1000), (EXPERIMENT.os, "geteuid", 1000),
                (EXPERIMENT.os, "getgid", 1000), (EXPERIMENT.os, "getegid", 1000)):
            stack.enter_context(patch.object(owner, name, return_value=value))
        yield


class AcknowledgmentLeaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("linux_caller_monitor_probe_ack_test", EXPERIMENT.PROBE)
        cls.probe = importlib.util.module_from_spec(spec)
        # Only the pure ACK receiver is exercised. Stub library loading so this
        # import also works on Mac and never touches Linux libc or live processes.
        with patch("ctypes.CDLL"), patch("os.fork", create=True) as fork, patch("subprocess.Popen") as spawn:
            spec.loader.exec_module(cls.probe)
        fork.assert_not_called()
        spawn.assert_not_called()

    def acknowledgment(self, generation=7):
        return {"phase": "ack", "nonce": "11" * 32, "binding": "22" * 16, "generation": generation}

    def lease(self, generation=7):
        return self.probe.AcknowledgmentLease("11" * 32, "22" * 16, generation)

    def test_matching_full_binding_can_be_consumed_only_once(self):
        lease = self.lease()
        acknowledgment = self.acknowledgment()
        self.assertIs(lease.accept(acknowledgment), True)
        self.assertIs(lease.accept(acknowledgment.copy()), False)
        self.assertIs(lease.accept(acknowledgment.copy()), False)

    def test_stale_or_incorrect_generation_rejects_and_consumes_lease(self):
        for generation in (6, 8, -1, "7", None):
            with self.subTest(generation=generation):
                lease = self.lease()
                self.assertIs(lease.accept(self.acknowledgment(generation)), False)
                self.assertIs(lease.accept(self.acknowledgment()), False)

    def test_previous_generation_ack_cannot_enter_new_generation(self):
        previous = self.lease(7)
        self.assertIs(previous.accept(self.acknowledgment(7)), True)
        current = self.lease(8)
        self.assertIs(current.accept(self.acknowledgment(7)), False)
        self.assertIs(current.accept(self.acknowledgment(8)), False)

    def test_nonce_and_process_binding_mismatches_reject_and_consume_lease(self):
        for field, changed in (("nonce", "33" * 32), ("binding", "44" * 16)):
            with self.subTest(field=field):
                lease = self.lease()
                acknowledgment = self.acknowledgment()
                acknowledgment[field] = changed
                self.assertIs(lease.accept(acknowledgment), False)
                self.assertIs(lease.accept(self.acknowledgment()), False)

    def test_wrong_phase_missing_field_and_extra_field_are_not_partial_matches(self):
        wrong_phase = {**self.acknowledgment(), "phase": "prepare"}
        missing_nonce = self.acknowledgment()
        del missing_nonce["nonce"]
        extra_field = {**self.acknowledgment(), "unsolicited": True}
        for acknowledgment in (wrong_phase, missing_nonce, extra_field):
            with self.subTest(acknowledgment=acknowledgment):
                lease = self.lease()
                self.assertIs(lease.accept(acknowledgment), False)
                self.assertIs(lease.accept(self.acknowledgment()), False)


class MonitorPrerequisiteTests(unittest.TestCase):
    def test_readable_task_children_reports_boolean_only_and_reads_one_byte(self):
        # A readable empty children file is valid too. Contents are not metadata.
        for contents in (b"", b"12345 67890\n"):
            with self.subTest(contents=contents):
                reader = mock_open(read_data=contents)
                with patch.object(EXPERIMENT.Path, "open", reader):
                    result = EXPERIMENT.check_prerequisites()
                self.assertEqual(result, {"procTaskChildrenReadable": True})
                reader.assert_called_once_with("rb")
                reader().read.assert_called_once_with(1)
                self.assertNotIn("12345", json.dumps(result))

    def test_missing_or_denied_task_children_never_starts_any_fixture(self):
        for error in (FileNotFoundError("/private/missing-procfs"), PermissionError("/private/denied-profile")):
            with self.subTest(error=type(error).__name__), ordinary_linux(), \
                 patch.object(EXPERIMENT.Path, "open", side_effect=error), \
                 patch.object(EXPERIMENT, "subreaper") as reaper, \
                 patch.object(EXPERIMENT, "build_fixture") as build, \
                 patch.object(EXPERIMENT, "invoke_worker") as worker, \
                 patch.object(EXPERIMENT.subprocess, "Popen") as spawn, \
                 patch.object(EXPERIMENT.tempfile, "TemporaryDirectory") as directory:
                with self.assertRaises(EXPERIMENT.PrerequisiteUnavailable):
                    EXPERIMENT.measure()
                reaper.assert_not_called()
                build.assert_not_called()
                worker.assert_not_called()
                spawn.assert_not_called()
                directory.assert_not_called()

    def test_invalid_host_and_timeout_refuse_before_procfs_access(self):
        with patch.object(EXPERIMENT.platform, "system", return_value="Darwin"), \
             patch.object(EXPERIMENT, "check_prerequisites") as check:
            with self.assertRaises(RuntimeError):
                EXPERIMENT.measure()
            check.assert_not_called()
        with ordinary_linux(), patch.object(EXPERIMENT, "check_prerequisites") as check:
            with self.assertRaises(ValueError):
                EXPERIMENT.measure(0)
            check.assert_not_called()

    def test_successful_report_retains_prerequisite_metadata_without_file_contents(self):
        prerequisites = {"procTaskChildrenReadable": True}
        with ordinary_linux(), patch.object(EXPERIMENT, "check_prerequisites", return_value=prerequisites), \
             patch.object(EXPERIMENT, "subreaper", side_effect=contextlib.nullcontext), \
             patch.object(EXPERIMENT.tempfile, "TemporaryDirectory", side_effect=lambda **_kwargs: contextlib.nullcontext("/synthetic/private-fixture")), \
             patch.object(EXPERIMENT, "build_fixture", return_value=Path("/synthetic/private-fixture/binary")), \
             patch.object(EXPERIMENT, "invoke_worker", side_effect=lambda _args, _timeout, case: valid_report(case)), \
             patch.object(EXPERIMENT, "host_metadata", return_value={}), \
             patch.object(EXPERIMENT, "source_hashes", return_value={}):
            report = EXPERIMENT.measure()
        self.assertEqual(report["prerequisites"], prerequisites)
        self.assertNotIn("/synthetic", json.dumps(report))

    def test_cli_preflight_diagnostic_is_fixed_and_contains_no_private_data(self):
        stderr, stdout = io.StringIO(), io.StringIO()
        with patch.object(EXPERIMENT.sys, "argv", [str(SCRIPT)]), ordinary_linux(), \
             patch.object(EXPERIMENT.Path, "open", side_effect=PermissionError("/private/secret-profile")), \
             patch.object(EXPERIMENT, "build_fixture") as build, \
             patch.object(EXPERIMENT, "invoke_worker") as worker, \
             patch.object(EXPERIMENT.sys, "stderr", stderr), patch.object(EXPERIMENT.sys, "stdout", stdout), \
             self.assertRaises(SystemExit) as raised:
            EXPERIMENT.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(stderr.getvalue(), "Caller monitor experiment requires readable procfs task-children support; no fixtures started.\n")
        self.assertEqual(stdout.getvalue(), "")
        build.assert_not_called()
        worker.assert_not_called()


class MonitorReportTests(unittest.TestCase):
    def test_only_complete_case_results_with_successful_exit_pass(self):
        self.assertEqual(set(EXPERIMENT.EXPECTED), set(EXPERIMENT.CASES))
        self.assertEqual(set(EXPERIMENT.OBSERVATIONS), set(EXPERIMENT.CASES))
        for case in EXPERIMENT.CASES:
            with self.subTest(case=case):
                report = valid_report(case)
                self.assertEqual(EXPERIMENT.validate_result(json.dumps(report), case, 0), report)
                with self.assertRaises(ValueError):
                    EXPERIMENT.validate_result(json.dumps(report), case, 1)

    def test_malformed_missing_extra_false_and_numeric_boolean_reports_refused(self):
        good = valid_report()
        check = next(iter(good["checks"]))
        invalid = [None, [], {}, {**good, "extra": "/private/secret"},
                   {**good, "passed": False}, {**good, "passed": 1},
                   {**good, "checks": {}}, {**good, "checks": list(good["checks"])},
                   {**good, "checks": {**good["checks"], check: False}},
                   {**good, "checks": {**good["checks"], check: 1}},
                   {**good, "checks": {**good["checks"], "unknown": True}},
                   {**good, "observations": {}},
                   {**good, "observations": {**good["observations"], "reason": "/private/secret"}},
                   {**good, "observations": {**good["observations"], "authorization": "rejected"}},
                   {**good, "observations": {**good["observations"], "trustedCode": 0}},
                   {**good, "observations": {**good["observations"], "productionAdmission": 0}},
                   {**good, "observations": {**good["observations"], "pid": 12345}}]
        for result in invalid:
            with self.subTest(result=result), self.assertRaises(ValueError):
                EXPERIMENT.validate_result(json.dumps(result), "healthy", 0)
        for raw in ("private not JSON", '{"passed":true,"passed":true}', 'NaN',
                    "x" * (EXPERIMENT.MAX_OUTPUT_BYTES + 1), b"\xff"):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                EXPERIMENT.validate_result(raw, "healthy", 0)
        with self.assertRaises(ValueError):
            EXPERIMENT.validate_result(json.dumps(good), "unknown-case", 0)

    def test_host_and_elevation_refusal_never_starts_compiler_or_workers(self):
        variants = [("Darwin", "arm64", 1000, 1000, 1000, 1000),
                    ("Windows", "AMD64", 1000, 1000, 1000, 1000),
                    ("Linux", "aarch64", 1000, 1000, 1000, 1000),
                    ("Linux", "x86_64", 0, 0, 0, 0),
                    ("Linux", "x86_64", 1000, 0, 1000, 1000),
                    ("Linux", "x86_64", 1000, 1001, 1000, 1000),
                    ("Linux", "x86_64", 1000, 1000, 1000, 1001)]
        for system, machine, uid, euid, gid, egid in variants:
            with self.subTest(system=system, ids=(uid, euid, gid, egid)), \
                 patch.object(EXPERIMENT.platform, "system", return_value=system), \
                 patch.object(EXPERIMENT.platform, "machine", return_value=machine), \
                 patch.object(EXPERIMENT.os, "getuid", return_value=uid), \
                 patch.object(EXPERIMENT.os, "geteuid", return_value=euid), \
                 patch.object(EXPERIMENT.os, "getgid", return_value=gid), \
                 patch.object(EXPERIMENT.os, "getegid", return_value=egid), \
                 patch.object(EXPERIMENT, "build_fixture") as build, \
                 patch.object(EXPERIMENT, "invoke_worker") as worker, \
                 patch.object(EXPERIMENT.subprocess, "Popen") as spawn:
                with self.assertRaises(RuntimeError):
                    EXPERIMENT.measure()
                build.assert_not_called()
                worker.assert_not_called()
                spawn.assert_not_called()

    def test_deadline_validation_precedes_build(self):
        for timeout in (True, 0, -1, 61, float("nan"), float("inf"), "15"):
            with self.subTest(timeout=timeout), \
                 patch.object(EXPERIMENT.platform, "system", return_value="Linux"), \
                 patch.object(EXPERIMENT.platform, "machine", return_value="x86_64"), \
                 patch.object(EXPERIMENT.os, "getuid", return_value=1000), \
                 patch.object(EXPERIMENT.os, "geteuid", return_value=1000), \
                 patch.object(EXPERIMENT.os, "getgid", return_value=1000), \
                 patch.object(EXPERIMENT.os, "getegid", return_value=1000), \
                 patch.object(EXPERIMENT, "build_fixture") as build:
                with self.assertRaises(ValueError):
                    EXPERIMENT.measure(timeout)
                build.assert_not_called()

    def test_source_hashes_use_fixed_relative_names_and_content_only(self):
        with tempfile.TemporaryDirectory(prefix="private-do-not-publish-") as temporary:
            # Match the real module's resolved ROOT, including macOS /var symlinks.
            root = Path(temporary).resolve()
            paths = [root / name for name in ("scripts/runner.py", "experiments/probe.py",
                                               "experiments/fixture.c", "scripts/cleanup.py")]
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"invented source\n")
            with patch.object(EXPERIMENT, "ROOT", root), patch.object(EXPERIMENT, "__file__", str(paths[0])), \
                 patch.object(EXPERIMENT, "PROBE", paths[1]), patch.object(EXPERIMENT, "FIXTURE", paths[2]), \
                 patch.object(EXPERIMENT, "CLEANUP_SOURCE", paths[3]):
                hashes = EXPERIMENT.source_hashes()
            self.assertEqual(set(hashes), {str(path.relative_to(root)) for path in paths})
            self.assertEqual(set(hashes.values()), {hashlib.sha256(b"invented source\n").hexdigest()})
            self.assertNotIn(temporary, json.dumps(hashes))

    def test_policy_metadata_accepts_only_bounded_public_values(self):
        for scope, status, apparmor, expected in (
                (b"1\n", b"Name:\tprivate-name\nSeccomp:\t2\n", b"Y\n", (1, 2, True)),
                (b"3", b"Seccomp:\t0\n", b"N", (3, 0, False)),
                (b"4\n", b"Seccomp:\t3\n", b"secret-profile", ("unavailable",) * 3),
                (None, None, None, ("unavailable",) * 3),
                (b"secret", b"Seccomp:\t1\nSeccomp:\t2\n", b"Y/private", ("unavailable",) * 3)):
            with self.subTest(expected=expected), patch.object(EXPERIMENT, "_policy_bytes", side_effect=[scope, status, apparmor]):
                self.assertEqual(EXPERIMENT.policy_metadata(), dict(zip(
                    ("ptraceScope", "seccompMode", "apparmorEnabled"), expected)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public"
            self.assertIsNone(EXPERIMENT._policy_bytes(path))
            path.write_bytes(b"x" * 65)
            self.assertIsNone(EXPERIMENT._policy_bytes(path, 64))

    def test_host_metadata_never_echoes_custom_kernel_or_python_strings(self):
        with patch.object(EXPERIMENT.platform, "release", return_value="6.17.0-private-user-path"), \
             patch.object(EXPERIMENT.platform, "python_version", return_value="3.13.7/private-user"), \
             patch.object(EXPERIMENT, "policy_metadata", return_value={}):
            result = EXPERIMENT.host_metadata()
        self.assertEqual(result["kernelVersion"], "6.17.0")
        self.assertEqual(result["pythonVersion"], "unknown")
        self.assertNotIn("private", json.dumps(result))

    def test_native_build_uses_fixed_arguments_and_discards_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "monitor-fixture"
            binary.write_bytes(b"not executed by this test")
            binary.chmod(0o700)
            with patch.object(EXPERIMENT.shutil, "which", return_value="/usr/bin/cc"), \
                 patch.object(EXPERIMENT, "run_owned", return_value=(b"private diagnostic", 0, None, True)) as run:
                self.assertEqual(EXPERIMENT.build_fixture(directory, 7), binary)
            arguments, timeout = run.call_args.args
            self.assertEqual(arguments, ["/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-pthread",
                                         str(EXPERIMENT.FIXTURE), "-o", str(binary)])
            self.assertEqual(timeout, 7)
            with patch.object(EXPERIMENT.shutil, "which", return_value="/usr/bin/cc"), \
                 patch.object(EXPERIMENT, "run_owned", return_value=(b"/private/secret", 1, None, True)):
                with self.assertRaisesRegex(RuntimeError, "bounded fixture build failed") as raised:
                    EXPERIMENT.build_fixture(directory, 7)
                self.assertNotIn("/private", str(raised.exception))


@unittest.skipUnless(platform.system() == "Linux", "Linux owned-process cleanup")
class MonitorWorkerCleanupTests(unittest.TestCase):
    def invoke(self, code, timeout=3):
        with EXPERIMENT.subreaper():
            return EXPERIMENT.invoke_worker([sys.executable, "-c", code], timeout, "healthy")

    def test_timeout_retires_worker_and_descendant_inheriting_stdout(self):
        result = self.invoke("import os,time; os.fork(); time.sleep(30)", 0.1)
        self.assertEqual(result, EXPERIMENT.failure("TimeoutError", True))

    def test_output_limit_retires_noisy_worker_and_descendant(self):
        code = f"import os,time; os.fork(); os.write(1,b'x'*{EXPERIMENT.MAX_OUTPUT_BYTES + 8192}); time.sleep(30)"
        self.assertEqual(self.invoke(code), EXPERIMENT.failure("OutputLimitError", True))

    def test_invalid_report_after_worker_exit_reaps_live_descendant(self):
        code = "import os,time\nif os.fork()==0:\n os.close(1); time.sleep(30)\nelse:\n print('/private/secret',flush=True); os._exit(0)"
        with patch.object(EXPERIMENT.os, "killpg", wraps=os.killpg) as kill:
            result = self.invoke(code)
        self.assertEqual(result, EXPERIMENT.failure("InvalidProbeReport", True))
        kill.assert_called_once()
        self.assertNotIn("private", json.dumps(result))

    def test_completed_owned_group_is_never_signaled(self):
        with patch.object(EXPERIMENT.os, "killpg") as kill:
            result = self.invoke("import os; os.fork(); os._exit(0)")
        kill.assert_not_called()
        self.assertTrue(result["cleanup_reaped_all_fixture_children"])

    def test_cancellation_still_reaps_worker_and_descendant(self):
        code = "import os,time; os.fork(); print('ready',flush=True); time.sleep(30)"
        workers = []

        def interrupt(process, _timeout):
            self.assertEqual(process.stdout.readline(), b"ready\n")
            workers.append(process.pid)
            raise KeyboardInterrupt()

        with EXPERIMENT.subreaper(), patch.object(EXPERIMENT, "_read_output", side_effect=interrupt), \
             self.assertRaises(KeyboardInterrupt):
            EXPERIMENT.run_owned([sys.executable, "-c", code], 3)
        with self.assertRaises(ChildProcessError):
            os.waitpid(-workers[0], os.WNOHANG)


@unittest.skipUnless(os.environ.get("REMOZIO_LINUX_CALLER_MONITOR_LIVE") == "1", "explicit owned-process monitor controls")
class MonitorLiveTests(unittest.TestCase):
    def test_live_fixture_mechanics_and_all_negative_controls(self):
        report = EXPERIMENT.measure()
        self.assertTrue(report["passed"], report["cases"])
        self.assertIs(report["trustedCode"], False)
        self.assertIs(report["productionAdmission"], False)
        self.assertEqual(set(report["cases"]), set(EXPERIMENT.CASES))
        self.assertEqual(report["cases"]["healthy"]["observations"]["authorization"], "accepted")
        for case, result in report["cases"].items():
            self.assertTrue(result["cleanup_reaped_all_fixture_children"], case)
            if case != "healthy":
                self.assertEqual(result["observations"]["authorization"], "rejected", case)


if __name__ == "__main__":
    unittest.main()
