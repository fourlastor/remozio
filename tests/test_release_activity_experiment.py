import copy
import importlib.util
import pathlib
import unittest
from unittest.mock import patch
import json
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = load("release_activity_runner", "scripts/run-release-activity-experiment.py")
PROBE = load("release_activity_probe", "experiments/release-activity/probe.py")


class ReleaseActivityExperimentTests(unittest.TestCase):
    def evidence(self):
        return {"schemaVersion": 1, "passed": True,
                "cases": {name: True for name in RUNNER.EXPECTED_CASES},
                "childrenSpawned": 10, "childrenReaped": 10, "unreapedChildren": 0,
                "rootOperations": False, "servicesRegistered": False, "productionActivationTested": False}

    def test_rejects_failed_missing_and_non_boolean_controls(self):
        for result in (False, 1, "true", None):
            value = self.evidence()
            value["cases"]["exclusiveOwnerBlocksNewActivity"] = result
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                RUNNER.validate(value)
        value = self.evidence()
        value["cases"].pop("pathReplacementBypassesLockNegative")
        with self.assertRaises(RuntimeError):
            RUNNER.validate(value)
        self.assertEqual(RUNNER.validate(self.evidence()), self.evidence())

    def test_rejects_incomplete_cleanup_or_a_broader_scope(self):
        for field, result in (("unreapedChildren", 1), ("childrenReaped", 9), ("childrenSpawned", True),
                              ("rootOperations", True), ("productionActivationTested", True), ("servicesRegistered", 0)):
            value = copy.deepcopy(self.evidence())
            value[field] = result
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                RUNNER.validate(value)

    def test_probe_refuses_root_and_mixed_identity_before_any_controls(self):
        for uid, euid in ((0, 0), (501, 0), (0, 501), (501, 502)):
            with self.subTest(uid=uid, euid=euid), patch.object(PROBE.os, "getuid", return_value=uid), \
                    patch.object(PROBE.os, "geteuid", return_value=euid), patch.object(PROBE, "run") as controls:
                self.assertEqual(PROBE.main([]), 77)
                controls.assert_not_called()

    def test_runner_refuses_root_before_starting_a_process(self):
        with patch.object(RUNNER.platform, "system", return_value="Darwin"), \
                patch.object(RUNNER.platform, "machine", return_value="arm64"), \
                patch.object(RUNNER.os, "getuid", return_value=0), patch.object(RUNNER.subprocess, "run") as child:
            with self.assertRaises(RuntimeError):
                RUNNER.run()
            child.assert_not_called()

    def test_exec_stage_rejects_ambiguous_descriptors_before_io(self):
        for values in ([], ["3", "3", "200"], ["0", "4", "200"], ["3", "4", "99999"], ["3", "4", "x"]):
            with self.subTest(values=values), patch.object(PROBE.os, "fstat") as inspect:
                self.assertEqual(PROBE.exec_stage(values), 64)
                inspect.assert_not_called()

    def test_report_uses_the_actual_runtime_major_version(self):
        for version, expected in (("26.0", True), ("27.0.1", False)):
            with self.subTest(version=version), patch.object(RUNNER.platform, "system", return_value="Darwin"), \
                    patch.object(RUNNER.platform, "machine", return_value="arm64"), \
                    patch.object(RUNNER.platform, "mac_ver", return_value=(version, (), "")), \
                    patch.object(RUNNER.os, "getuid", return_value=501), \
                    patch.object(RUNNER.os, "geteuid", return_value=501), \
                    patch.object(RUNNER.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(self.evidence()))):
                result = RUNNER.run()
                self.assertEqual(result["hostMacOS"], version)
                self.assertIs(result["macOS26RuntimeTested"], expected)
