import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-storage-lease-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_storage_lease_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


def report(case="healthy"):
    value = {"case": case, "passed": True, "fixtureOnly": True,
             "protectedInstallation": False, "descriptorsClosed": True, "fixtureFilesystem": "tmpfs"}
    if case == "stored-owner-mismatch":
        value["storedOwnerComparisonExercised"] = True
    if case in {"later-device-mismatch", "later-filesystem-mismatch"}:
        value["anchorFilesystemObservedBeforeInjection"] = True
        value["laterObjectComparisonExercised"] = True
    return value


@contextlib.contextmanager
def ordinary_linux():
    with contextlib.ExitStack() as stack:
        for owner, name, value in ((EXPERIMENT.platform, "system", "Linux"),
                                   (EXPERIMENT.os, "getuid", 1000), (EXPERIMENT.os, "geteuid", 1000),
                                   (EXPERIMENT.os, "getgid", 1000), (EXPERIMENT.os, "getegid", 1000)):
            stack.enter_context(patch.object(owner, name, return_value=value))
        yield


class ReportTests(unittest.TestCase):
    def test_exact_controls_and_evidence_classes(self):
        self.assertEqual(len(EXPERIMENT.CASES), len(set(EXPERIMENT.CASES)))
        for case in EXPERIMENT.CASES:
            value = EXPERIMENT.validate_result(json.dumps(report(case)), case, 0)
            self.assertEqual(value["evidence"], "injected-error-control" if case in EXPERIMENT.SIMULATED
                             else "owned-live-filesystem-control")

    def test_stored_owner_evidence_requires_injection_observation(self):
        self.assertEqual(len(EXPERIMENT.CASES), 36)
        self.assertEqual(len(EXPERIMENT.SIMULATED), 7)
        self.assertNotIn("owner-mismatch", EXPERIMENT.SIMULATED)
        self.assertIn("stored-owner-mismatch", EXPERIMENT.SIMULATED)
        for flag in (None, False, 1):
            value = report("stored-owner-mismatch")
            if flag is None:
                del value["storedOwnerComparisonExercised"]
            else:
                value["storedOwnerComparisonExercised"] = flag
            with self.assertRaises(ValueError):
                EXPERIMENT.validate_result(json.dumps(value), "stored-owner-mismatch", 0)

    def test_later_object_evidence_requires_anchor_and_target_observations(self):
        for case in ("later-device-mismatch", "later-filesystem-mismatch"):
            self.assertIn(case, EXPERIMENT.SIMULATED)
            for key in ("anchorFilesystemObservedBeforeInjection", "laterObjectComparisonExercised"):
                for flag in (None, False, 1):
                    value = report(case)
                    if flag is None:
                        del value[key]
                    else:
                        value[key] = flag
                    with self.assertRaises(ValueError):
                        EXPERIMENT.validate_result(json.dumps(value), case, 0)

    def test_rejects_missing_extra_and_false_fields(self):
        for key in report():
            value = report(); del value[key]
            with self.assertRaises(ValueError):
                EXPERIMENT.validate_result(json.dumps(value), "healthy", 0)
        for changes in ({"extra": True}, {"passed": False}, {"protectedInstallation": True},
                        {"descriptorsClosed": False}, {"case": "close-reopen"},
                        {"fixtureFilesystem": "nfs"}, {"fixtureFilesystem": True}):
            with self.assertRaises(ValueError):
                EXPERIMENT.validate_result(json.dumps({**report(), **changes}), "healthy", 0)

    def test_numbers_cannot_replace_booleans(self):
        for key in ("passed", "fixtureOnly", "protectedInstallation", "descriptorsClosed"):
            with self.assertRaises(ValueError):
                EXPERIMENT.validate_result(json.dumps({**report(), key: int(report()[key])}), "healthy", 0)

    def test_rejects_duplicates_nonfinite_bad_exit_unknown_and_oversize(self):
        cases = [(json.dumps(report())[:-1] + ',"passed":true}', "healthy", 0),
                 ('{"passed":NaN}', "healthy", 0), (json.dumps(report()), "healthy", 1),
                 (json.dumps(report()), "healthy", False), (json.dumps(report()), "unsupported", 0),
                 (b"x" * (EXPERIMENT.MAX_OUTPUT_BYTES + 1), "healthy", 0)]
        for raw, case, status in cases:
            with self.assertRaises(ValueError):
                EXPERIMENT.validate_result(raw, case, status)


class PrerequisiteAndInventoryTests(unittest.TestCase):
    def test_python_below_floor_refuses_before_prerequisites_or_process(self):
        for version in ((3, 9, 0), (3, 10, 99)):
            with ordinary_linux(), patch.object(EXPERIMENT.sys, "version_info", version), \
                 patch.object(EXPERIMENT, "check_prerequisites") as prerequisites, \
                 patch.object(EXPERIMENT, "run_owned") as run, \
                 patch.object(EXPERIMENT.subprocess, "Popen", side_effect=AssertionError("unexpected subprocess")) as spawn:
                with self.assertRaisesRegex(RuntimeError, "Python 3.11 or later required"):
                    EXPERIMENT.measure()
                prerequisites.assert_not_called()
                run.assert_not_called()
                spawn.assert_not_called()

    def test_prerequisite_refusal_starts_no_process(self):
        with ordinary_linux(), patch.object(EXPERIMENT.Path, "open", side_effect=PermissionError), \
             patch.object(EXPERIMENT, "run_owned") as run:
            with self.assertRaisesRegex(RuntimeError, "cleanup unavailable"):
                EXPERIMENT.measure()
            run.assert_not_called()

    def test_wrong_platform_root_or_credential_transition_starts_no_process(self):
        for owner, name, value in ((EXPERIMENT.platform, "system", "Darwin"),
                                   (EXPERIMENT.os, "getuid", 0), (EXPERIMENT.os, "geteuid", 1001),
                                   (EXPERIMENT.os, "getegid", 1001)):
            with ordinary_linux(), patch.object(owner, name, return_value=value), \
                 patch.object(EXPERIMENT, "run_owned") as run:
                with self.assertRaises(RuntimeError):
                    EXPERIMENT.measure()
                run.assert_not_called()

    def test_invalid_deadlines_starts_no_process(self):
        for value in (0, -1, 61, True, float("inf"), float("nan"), "15"):
            with ordinary_linux(), patch.object(EXPERIMENT, "run_owned") as run:
                with self.assertRaises(ValueError):
                    EXPERIMENT.measure(value)
                run.assert_not_called()

    def test_inventory_binds_native_api_controls_and_cleanup(self):
        sources = EXPERIMENT.source_hashes()
        self.assertEqual(set(sources), {"scripts/run-linux-storage-lease-experiment.py",
                                       "scripts/run-linux-caller-experiment.py",
                                       "tests/test_linux_storage_lease_experiment.py",
                                       "experiments/linux-storage-lease/lease.c",
                                       "experiments/linux-storage-lease/lease.h",
                                       "experiments/linux-storage-lease/controls.c",
                                       "experiments/linux-storage-lease/README.md"})
        for name, digest in sources.items():
            self.assertEqual(digest, hashlib.sha256((EXPERIMENT.ROOT / name).read_bytes()).hexdigest())


class CoordinatorTests(unittest.TestCase):
    def run_mock_measure(self, hashes=None, failure=None):
        calls = []
        def native(arguments, timeout):
            calls.append((arguments, timeout))
            if "-o" in arguments:
                binary = Path(arguments[-1]); binary.write_bytes(b"fixture"); binary.chmod(0o700)
                return b"", 0, None, True
            case = arguments[1]
            if failure == case:
                return b"", 1, "TimeoutError", False
            return json.dumps(report(case)).encode(), 0, None, True
        with ordinary_linux(), patch.object(EXPERIMENT, "check_prerequisites", return_value={}), \
             patch.object(EXPERIMENT.shutil, "which", return_value="/fixture/cc"), \
             patch.object(EXPERIMENT._cleanup, "subreaper", side_effect=contextlib.nullcontext), \
             patch.object(EXPERIMENT, "run_owned", side_effect=native), \
             patch.object(EXPERIMENT, "source_hashes", side_effect=hashes or [{"fixture": "a"}, {"fixture": "a"}]):
            return EXPERIMENT.measure(), calls

    def test_fixed_build_complete_case_set_and_sanitized_report(self):
        value, calls = self.run_mock_measure()
        self.assertTrue(value["passed"])
        self.assertIs(value["protectedInstallation"], False)
        self.assertEqual(set(value["cases"]), set(EXPERIMENT.CASES))
        self.assertEqual(value["controlCounts"], {"ownedLive": 29, "injected": 7})
        arguments, timeout = calls[0]
        self.assertEqual(timeout, 30)
        self.assertEqual(arguments[:6], ["/fixture/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"])
        self.assertEqual(arguments[6:12], [str(EXPERIMENT.SOURCE / "lease.c"), str(EXPERIMENT.SOURCE / "controls.c"),
                                           "-Wl,--wrap=fgetxattr", "-Wl,--wrap=fstatfs", "-Wl,--wrap=fstat", "-Wl,--wrap=fstatat"])
        self.assertEqual(len(calls), len(EXPERIMENT.CASES) + 1)
        self.assertNotIn("/fixture", json.dumps(value))

    def test_documented_python_floor_is_admitted(self):
        with patch.object(EXPERIMENT.sys, "version_info", (3, 11, 0)):
            value, calls = self.run_mock_measure()
        self.assertTrue(value["passed"])
        self.assertEqual(value["host"]["pythonVersion"], "3.11.0")
        self.assertEqual(len(calls), len(EXPERIMENT.CASES) + 1)

    def test_failed_cleanup_or_worker_cannot_pass(self):
        value, _calls = self.run_mock_measure(failure="healthy")
        self.assertFalse(value["passed"])
        self.assertEqual(value["cases"]["healthy"], {"passed": False, "error": "TimeoutError", "ownedProcessesReaped": False})

    def test_source_change_rejects_report(self):
        with self.assertRaisesRegex(RuntimeError, "source changed"):
            self.run_mock_measure(hashes=[{"fixture": "a"}, {"fixture": "b"}])

    def test_build_failure_never_starts_controls(self):
        with ordinary_linux(), patch.object(EXPERIMENT, "check_prerequisites", return_value={}), \
             patch.object(EXPERIMENT.shutil, "which", return_value="/fixture/cc"), \
             patch.object(EXPERIMENT._cleanup, "subreaper", side_effect=contextlib.nullcontext), \
             patch.object(EXPERIMENT, "run_owned", return_value=(b"", 1, None, True)) as run:
            with self.assertRaisesRegex(RuntimeError, "build failed"):
                EXPERIMENT.measure()
            self.assertEqual(run.call_count, 1)


@unittest.skipUnless(platform.system() == "Linux", "Linux owned-process cleanup")
class WorkerTests(unittest.TestCase):
    def test_output_bound_and_timeout_retire_owned_workers(self):
        for code, error in (("import os; os.write(1, b'x' * 65536)", "OutputLimitError"),
                            ("import time; time.sleep(10)", "TimeoutError")):
            with EXPERIMENT._cleanup.subreaper():
                _raw, _status, actual, clean = EXPERIMENT.run_owned([sys.executable, "-c", code], 0.2)
            self.assertEqual(actual, error)
            self.assertTrue(clean)

    def test_interruption_still_retires_worker(self):
        with EXPERIMENT._cleanup.subreaper(), \
             patch.object(EXPERIMENT, "_read_output", side_effect=KeyboardInterrupt), \
             patch.object(EXPERIMENT._cleanup, "reap_group", wraps=EXPERIMENT._cleanup.reap_group) as reap:
            with self.assertRaises(KeyboardInterrupt):
                EXPERIMENT.run_owned([sys.executable, "-c", "import time; time.sleep(10)"], 1)
            reap.assert_called_once()


@unittest.skipUnless(os.environ.get("REMOZIO_LINUX_STORAGE_LEASE_LIVE") == "1", "explicit live filesystem controls")
class LiveTests(unittest.TestCase):
    def test_later_object_controls_detect_each_removed_filesystem_comparison(self):
        source = (EXPERIMENT.SOURCE / "lease.c").read_text()
        mutations = (("device != lease->private_device || ", "later-device-mismatch"),
                     (" || value.f_type != lease->filesystem", "later-filesystem-mismatch"))
        for comparison, failing_case in mutations:
            with self.subTest(comparison=comparison):
                self.assertEqual(source.count(comparison), 1)
                with EXPERIMENT._cleanup.subreaper(), tempfile.TemporaryDirectory(prefix="storage-filesystem-mutation-") as temporary:
                    directory = Path(temporary)
                    mutant = directory / "lease-without-one-filesystem-check.c"
                    mutant.write_text(source.replace(comparison, "", 1))
                    binary = directory / "mutant-controls"
                    compiler = EXPERIMENT.shutil.which("cc")
                    self.assertIsNotNone(compiler)
                    arguments = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                                 "-I", str(EXPERIMENT.SOURCE), str(mutant), str(EXPERIMENT.SOURCE / "controls.c"),
                                 "-Wl,--wrap=fgetxattr", "-Wl,--wrap=fstatfs", "-Wl,--wrap=fstat",
                                 "-Wl,--wrap=fstatat", "-o", str(binary)]
                    _raw, status, error, clean = EXPERIMENT.run_owned(arguments, 30)
                    self.assertEqual((status, error, clean), (0, None, True))
                    cases = ("healthy", "stored-owner-mismatch", "filesystem-unavailable", "unknown-filesystem",
                             "later-device-mismatch", "later-filesystem-mismatch")
                    for case in cases:
                        with tempfile.TemporaryDirectory(prefix="case-", dir=directory) as workspace:
                            raw, status, error, clean = EXPERIMENT.run_owned([str(binary), case, workspace], 15)
                            self.assertIsNone(error)
                            self.assertTrue(clean)
                            if case == failing_case:
                                self.assertEqual(status, 1)
                                self.assertEqual(raw, b"")
                            else:
                                self.assertTrue(EXPERIMENT.validate_result(raw, case, status)["passed"])

    def test_stored_owner_control_detects_removed_uid_comparison(self):
        source = (EXPERIMENT.SOURCE / "lease.c").read_text()
        comparison = "info->st_uid != lease->owner || "
        self.assertEqual(source.count(comparison), 1)
        with EXPERIMENT._cleanup.subreaper(), tempfile.TemporaryDirectory(prefix="storage-owner-mutation-") as temporary:
            directory = Path(temporary)
            mutant = directory / "lease-without-owner-check.c"
            mutant.write_text(source.replace(comparison, "", 1))
            binary = directory / "mutant-controls"
            compiler = EXPERIMENT.shutil.which("cc")
            self.assertIsNotNone(compiler)
            arguments = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                         "-I", str(EXPERIMENT.SOURCE), str(mutant), str(EXPERIMENT.SOURCE / "controls.c"),
                         "-Wl,--wrap=fgetxattr", "-Wl,--wrap=fstatfs", "-Wl,--wrap=fstat", "-Wl,--wrap=fstatat", "-o", str(binary)]
            _raw, status, error, clean = EXPERIMENT.run_owned(arguments, 30)
            self.assertEqual((status, error, clean), (0, None, True))
            for case in ("healthy", "stored-owner-mismatch"):
                with tempfile.TemporaryDirectory(prefix="case-", dir=directory) as workspace:
                    raw, status, error, clean = EXPERIMENT.run_owned([str(binary), case, workspace], 15)
                    self.assertIsNone(error)
                    self.assertTrue(clean)
                    if case == "healthy":
                        self.assertTrue(EXPERIMENT.validate_result(raw, case, status)["passed"])
                    else:
                        self.assertEqual(status, 1)
                        self.assertEqual(raw, b"")

    def test_native_controls_under_restrictive_umask_and_unusual_paths(self):
        with tempfile.TemporaryDirectory(prefix="storage fixture \n") as parent:
            previous = os.umask(0o777)
            try:
                with patch.object(tempfile, "tempdir", parent):
                    value = EXPERIMENT.measure()
            finally:
                os.umask(previous)
        self.assertTrue(value["passed"], json.dumps(value["cases"], sort_keys=True))
        self.assertEqual(len(value["cases"]), len(EXPERIMENT.CASES))
        self.assertEqual(value["controlCounts"], {"ownedLive": 29, "injected": 7})
        self.assertTrue(value["sourcesUnchanged"])
        self.assertTrue(all(case["ownedProcessesReaped"] for case in value["cases"].values()))


if __name__ == "__main__":
    unittest.main()
