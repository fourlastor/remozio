import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-release-attributes-experiment.py"
SPEC = importlib.util.spec_from_file_location("release_attribute_runner", SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class ReleaseAttributeRunnerGuardTests(unittest.TestCase):
    def refused_before_build(self, system, machine, uid, effective):
        with patch.object(RUNNER.platform, "system", return_value=system), \
             patch.object(RUNNER.platform, "machine", return_value=machine), \
             patch.object(RUNNER.os, "getuid", return_value=uid), \
             patch.object(RUNNER.os, "geteuid", return_value=effective), \
             patch.object(RUNNER.subprocess, "run") as subprocess_run, \
             patch("sys.argv", ["probe", "--identity", "fixture", "--team-id", "FIXTURE"]):
            with self.assertRaises(SystemExit):
                RUNNER.main()
            subprocess_run.assert_not_called()

    def test_root_is_refused_before_build_or_signing(self):
        self.refused_before_build("Darwin", "arm64", 0, 0)

    def test_different_effective_identity_is_refused_before_build_or_signing(self):
        self.refused_before_build("Darwin", "arm64", 501, 0)

    def test_unsupported_hosts_are_refused_before_build_or_signing(self):
        for host in [("Linux", "arm64"), ("Darwin", "x86_64")]:
            with self.subTest(host=host):
                self.refused_before_build(*host, 501, 501)
