import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-placement-validator-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_placement_validator_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


def report(case="healthy"):
    value = {"case": case, "passed": True, "fixtureOnly": True,
             "protectedInstallation": False, "descriptorsClosed": True, "fixtureFilesystem": "tmpfs"}
    if case in EXPERIMENT.SIMULATED:
        value["injectionObserved"] = True
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
        self.assertEqual(len(EXPERIMENT.CASES), 46)
        self.assertEqual(len(EXPERIMENT.SIMULATED), 7)
        self.assertLessEqual(EXPERIMENT.SIMULATED, set(EXPERIMENT.CASES))
        for case in EXPERIMENT.CASES:
            value = EXPERIMENT.validate_result(json.dumps(report(case)), case, 0)
            self.assertEqual(value["evidence"], "injected-error-control" if case in EXPERIMENT.SIMULATED
                             else "owned-live-filesystem-control")

    def test_injected_control_requires_its_observation(self):
        for flag in (None, False, 1):
            value = report("mount-crossing")
            if flag is None:
                del value["injectionObserved"]
            else:
                value["injectionObserved"] = flag
            with self.assertRaises(ValueError):
                EXPERIMENT.validate_result(json.dumps(value), "mount-crossing", 0)
        with self.assertRaises(ValueError):
            EXPERIMENT.validate_result(json.dumps({**report(), "injectionObserved": True}), "healthy", 0)

    def test_rejects_missing_extra_and_false_fields(self):
        for key in report():
            value = report(); del value[key]
            with self.assertRaises(ValueError):
                EXPERIMENT.validate_result(json.dumps(value), "healthy", 0)
        for changes in ({"extra": True}, {"passed": False}, {"protectedInstallation": True},
                        {"descriptorsClosed": False}, {"case": "extra-link"},
                        {"fixtureFilesystem": "nfs"}, {"fixtureFilesystem": True}):
            with self.assertRaises(ValueError):
                EXPERIMENT.validate_result(json.dumps({**report(), **changes}), "healthy", 0)

    def test_rejects_duplicates_nonfinite_bad_exit_unknown_and_oversize(self):
        cases = [(json.dumps(report())[:-1] + ',"passed":true}', "healthy", 0),
                 ('{"passed":NaN}', "healthy", 0), (json.dumps(report()), "healthy", 1),
                 (json.dumps(report()), "healthy", False), (json.dumps(report()), "unsupported", 0),
                 (b"x" * (EXPERIMENT.MAX_OUTPUT_BYTES + 1), "healthy", 0)]
        for raw, case, status in cases:
            with self.assertRaises(ValueError):
                EXPERIMENT.validate_result(raw, case, status)


class PrerequisiteAndInventoryTests(unittest.TestCase):
    def test_python_below_floor_refuses_before_any_process(self):
        with ordinary_linux(), patch.object(EXPERIMENT.sys, "version_info", (3, 10, 99)), \
             patch.object(EXPERIMENT._process, "check_prerequisites") as prerequisites, \
             patch.object(EXPERIMENT, "run_owned") as run:
            with self.assertRaisesRegex(RuntimeError, "Python 3.11 or later required"):
                EXPERIMENT.measure()
            prerequisites.assert_not_called()
            run.assert_not_called()

    def test_wrong_platform_root_or_credential_transition_starts_no_process(self):
        for owner, name, value in ((EXPERIMENT.platform, "system", "Darwin"),
                                   (EXPERIMENT.os, "getuid", 0), (EXPERIMENT.os, "geteuid", 1001),
                                   (EXPERIMENT.os, "getegid", 1001)):
            with ordinary_linux(), patch.object(EXPERIMENT.sys, "version_info", (3, 11, 0)), \
                 patch.object(owner, name, return_value=value), patch.object(EXPERIMENT, "run_owned") as run:
                with self.assertRaises(RuntimeError):
                    EXPERIMENT.measure()
                run.assert_not_called()

    def test_invalid_deadlines_start_no_process(self):
        for value in (0, -1, 61, True, float("inf"), float("nan"), "15"):
            with ordinary_linux(), patch.object(EXPERIMENT.sys, "version_info", (3, 11, 0)), \
                 patch.object(EXPERIMENT, "run_owned") as run:
                with self.assertRaises(ValueError):
                    EXPERIMENT.measure(value)
                run.assert_not_called()

    def test_inventory_binds_native_api_controls_shared_walk_and_process_owner(self):
        sources = EXPERIMENT.source_hashes()
        self.assertEqual(set(sources), {"scripts/run-linux-placement-validator-experiment.py",
                                       "scripts/run-linux-storage-lease-experiment.py",
                                       "scripts/run-linux-caller-experiment.py",
                                       "tests/test_linux_placement_validator_experiment.py",
                                       "experiments/linux-placement-validator/placement.c",
                                       "experiments/linux-placement-validator/placement.h",
                                       "experiments/linux-placement-validator/controls.c",
                                       "experiments/linux-placement-validator/README.md",
                                       "experiments/linux-storage-lease/descriptor-walk.c",
                                       "experiments/linux-storage-lease/descriptor-walk.h"})
        for name, digest in sources.items():
            self.assertEqual(digest, hashlib.sha256((EXPERIMENT.ROOT / name).read_bytes()).hexdigest())

    def test_expected_refusals_do_not_name_production_values(self):
        for name in ("placement.c", "placement.h", "controls.c"):
            source = (EXPERIMENT.SOURCE / name).read_text()
            for value in ("/var/lib", "/usr/libexec", "remozio-authority", "remozio-transport", "/run/remozio"):
                self.assertNotIn(value, source)


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
        with ordinary_linux(), patch.object(EXPERIMENT.sys, "version_info", (3, 11, 0)), \
             patch.object(EXPERIMENT._process, "check_prerequisites", return_value={}), \
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
        self.assertEqual(value["controlCounts"], {"ownedLive": 39, "injected": 7})
        arguments, timeout = calls[0]
        self.assertEqual(timeout, 30)
        self.assertEqual(arguments[:6], ["/fixture/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"])
        self.assertEqual(arguments[6:13], [*map(str, EXPERIMENT.NATIVE_SOURCES), *EXPERIMENT.WRAPPED])
        self.assertEqual(len(calls), len(EXPERIMENT.CASES) + 1)
        self.assertNotIn("/fixture", json.dumps(value))

    def test_failed_cleanup_or_worker_cannot_pass(self):
        value, _calls = self.run_mock_measure(failure="healthy")
        self.assertFalse(value["passed"])
        self.assertEqual(value["cases"]["healthy"], {"passed": False, "error": "TimeoutError", "ownedProcessesReaped": False})

    def test_source_change_rejects_report(self):
        with self.assertRaisesRegex(RuntimeError, "source changed"):
            self.run_mock_measure(hashes=[{"fixture": "a"}, {"fixture": "b"}])

    def test_build_failure_never_starts_controls(self):
        with ordinary_linux(), patch.object(EXPERIMENT.sys, "version_info", (3, 11, 0)), \
             patch.object(EXPERIMENT._process, "check_prerequisites", return_value={}), \
             patch.object(EXPERIMENT.shutil, "which", return_value="/fixture/cc"), \
             patch.object(EXPERIMENT._cleanup, "subreaper", side_effect=contextlib.nullcontext), \
             patch.object(EXPERIMENT, "run_owned", return_value=(b"", 1, None, True)) as run:
            with self.assertRaisesRegex(RuntimeError, "build failed"):
                EXPERIMENT.measure()
            self.assertEqual(run.call_count, 1)


@unittest.skipUnless(os.environ.get("REMOZIO_LINUX_PLACEMENT_VALIDATOR_LIVE") == "1", "explicit live filesystem controls")
class LiveTests(unittest.TestCase):
    MUTATIONS = (("if (info->st_uid != node->object.owner) return RPV_OWNER;\n", "owner-mismatch"),
                 ("if (info->st_gid != node->object.group) return RPV_GROUP;\n", "group-mismatch"),
                 ("if ((info->st_mode & 07777) != node->object.mode) return RPV_MODE;\n", "group-write"),
                 ("if (!directory && info->st_nlink != 1) return RPV_LINKS;\n", "extra-link"),
                 ("if (object->acl == RPV_ACL_NONE) return RPV_ACL_REFUSED;\n", "acl-refused-by-policy"),
                 ("tag != ACL_USER_OBJ && tag != ACL_MASK && (permissions & ACL_WRITE)", "masked-write-grant"),
                 ("(object->mode & 022) == 0", "unsafe-expectation"),
                 ("parent_entry(entries, i) == -2", "unlisted-parent"),
                 ("placement->nodes[i].device == info.st_dev && placement->nodes[i].inode == info.st_ino", "directory-alias"),
                 ("device == placement->device && ", "device-crossing"),
                 (" && value.stx_mnt_id == placement->mount", "mount-crossing"))
    REPLACEMENTS = {"tag != ACL_USER_OBJ && tag != ACL_MASK && (permissions & ACL_WRITE)": "0",
                    "(object->mode & 022) == 0": "1", "parent_entry(entries, i) == -2": "0",
                    "placement->nodes[i].device == info.st_dev && placement->nodes[i].inode == info.st_ino": "0"}

    def test_each_control_detects_its_removed_comparison(self):
        source = (EXPERIMENT.SOURCE / "placement.c").read_text()
        for comparison, failing_case in self.MUTATIONS:
            with self.subTest(comparison=comparison):
                self.assertEqual(source.count(comparison), 1)
                with EXPERIMENT._cleanup.subreaper(), tempfile.TemporaryDirectory(prefix="placement-mutation-") as temporary:
                    directory = Path(temporary)
                    mutant = directory / "placement.c"
                    mutant.write_text(source.replace(comparison, self.REPLACEMENTS.get(comparison, ""), 1))
                    binary = directory / "mutant-controls"
                    compiler = EXPERIMENT.shutil.which("cc")
                    self.assertIsNotNone(compiler)
                    # The mutant sits outside the tree, so the walk header's relative include resolves through -I.
                    arguments = [compiler, "-std=c11", "-Wall", "-Wextra", "-O2", "-I", str(EXPERIMENT.SOURCE),
                                 str(mutant), *map(str, EXPERIMENT.NATIVE_SOURCES[1:]), *EXPERIMENT.WRAPPED, "-o", str(binary)]
                    _raw, status, error, clean = EXPERIMENT.run_owned(arguments, 30)
                    self.assertEqual((status, error, clean), (0, None, True))
                    for case in ("healthy", failing_case):
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
        with tempfile.TemporaryDirectory(prefix="placement fixture \n") as parent:
            previous = os.umask(0o777)
            try:
                with patch.object(tempfile, "tempdir", parent):
                    value = EXPERIMENT.measure()
            finally:
                os.umask(previous)
        self.assertTrue(value["passed"], json.dumps(value["cases"], sort_keys=True))
        self.assertEqual(len(value["cases"]), len(EXPERIMENT.CASES))
        self.assertEqual(value["controlCounts"], {"ownedLive": 39, "injected": 7})
        self.assertTrue(value["sourcesUnchanged"])
        self.assertTrue(all(case["ownedProcessesReaped"] for case in value["cases"].values()))


if __name__ == "__main__":
    unittest.main()
