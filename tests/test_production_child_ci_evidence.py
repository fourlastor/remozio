import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("production_child_ci_evidence", ROOT / "scripts/collect-production-child-ci-evidence.py")
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)


class ProductionChildCIEvidenceTests(unittest.TestCase):
    def environment(self, **changes):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
               "RUNNER_ARCH": "ARM64", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "rock3r/remozio",
               "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
        env.update(changes)
        return env

    def context(self, **changes):
        return EVIDENCE.workflow_context(self.environment(**changes), "Darwin", "arm64", "26.6.2", 501, 501, "a" * 40)

    def preparation(self):
        return {"schemaVersion": 1, "hostMacOS": "26.6.2", "hostArchitecture": "arm64",
                "ordinaryControls": {"schemaVersion": 1, "codecControls": 6, "privilegedControlsRun": False},
                "ownerControls": {"schemaVersion": 1, "ownerControls": 28, "privilegedControlsRun": False, "realProcessesSpawned": 0},
                "descriptorControls": {"schemaVersion": 1, "descriptorControls": 3, "privilegedControlsRun": False},
                "ordinaryPrivilegedModeRefused": True, "invalidUIDRefused": True,
                "privilegedControlsRun": False, "productionExecutionTested": False, "installedRemozio": False,
                "sourceHashes": {"fixture.c": "b" * 64},
                "executables": {name: {"sha256": "c" * 64, "bytes": 1024} for name in EVIDENCE.BINARY_NAMES},
                "administratorCommandSHA256": "d" * 64}

    def collect(self, preparation=None, native=None, context=None):
        return EVIDENCE.collect(self.preparation() if preparation is None else preparation,
                                copy.deepcopy(EVIDENCE.NATIVE_SUCCESS) if native is None else native,
                                {"fixture.c": "b" * 64}, self.context() if context is None else context)

    def test_complete_record_has_only_the_allowed_public_fields(self):
        context = self.context()
        context["privateCredential"] = "must not appear"
        value = self.collect(context=context)
        self.assertTrue(value["nativeControls"]["allOwnedCleanupConfirmed"])
        self.assertFalse(value["installedServicesTested"])
        self.assertFalse(value["physicalPixelTested"])
        self.assertNotIn("privateCredential", value)
        self.assertNotIn("must not appear", json.dumps(value))
        self.assertEqual(value["sourceCommit"], "a" * 40)

    def test_every_missing_or_incomplete_native_result_fails(self):
        for key, value in EVIDENCE.NATIVE_SUCCESS.items():
            bad = copy.deepcopy(EVIDENCE.NATIVE_SUCCESS)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.collect(native=bad)
            bad[key] = not value if type(value) is bool else value + 1
            with self.subTest(changed=key), self.assertRaises(ValueError):
                self.collect(native=bad)
        for changed in [dict(EVIDENCE.NATIVE_SUCCESS, passed=5), dict(EVIDENCE.NATIVE_SUCCESS, passed=True), dict(EVIDENCE.NATIVE_SUCCESS, schemaVersion=True),
                        dict(EVIDENCE.NATIVE_SUCCESS, fixtureRemoved=1), dict(EVIDENCE.NATIVE_SUCCESS, accountName="private")]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.collect(native=changed)

    def test_wrong_sources_helpers_or_ordinary_controls_cannot_become_native_evidence(self):
        mutations = [("sourceHashes", {"fixture.c": "0" * 64}), ("sourceHashes", {"foreign.c": "b" * 64}),
                     ("ownerControls", {"schemaVersion": 1, "ownerControls": 27, "privilegedControlsRun": False, "realProcessesSpawned": 0}),
                     ("descriptorControls", {"schemaVersion": 1, "descriptorControls": 2, "privilegedControlsRun": False}),
                     ("installedRemozio", True), ("privilegedControlsRun", True), ("privateKey", "must not appear"),
                     ("administratorCommandSHA256", "not a hash")]
        for key, value in mutations:
            bad = self.preparation(); bad[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.collect(preparation=bad)
        for binary in EVIDENCE.BINARY_NAMES:
            for value in [{"sha256": "c" * 64, "bytes": True}, {"sha256": "x" * 64, "bytes": 1024},
                          {"sha256": "c" * 64, "bytes": 4 * 1024 * 1024 + 1}]:
                bad = self.preparation(); bad["executables"][binary] = value
                with self.subTest(binary=binary, value=value), self.assertRaises(ValueError):
                    self.collect(preparation=bad)
        bad = self.preparation(); bad["executables"]["foreign"] = {"sha256": "c" * 64, "bytes": 10}
        with self.assertRaises(ValueError):
            self.collect(preparation=bad)

    def test_other_events_refs_hosts_and_commits_are_refused(self):
        for key, value in [("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REF", "refs/heads/feature"),
                           ("GITHUB_REPOSITORY", "foreign/remozio"), ("RUNNER_ENVIRONMENT", "self-hosted"),
                           ("GITHUB_ACTIONS", "false"), ("RUNNER_ARCH", "X64"), ("GITHUB_SHA", "f" * 40),
                           ("GITHUB_RUN_ID", "../foreign"), ("GITHUB_RUN_ATTEMPT", "0")]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.context(**{key: value})
        for system, architecture, version, uid, euid in [("Linux", "arm64", "26.6.2", 501, 501),
                ("Darwin", "x86_64", "26.6.2", 501, 501), ("Darwin", "arm64", "27.0.1", 501, 501),
                ("Darwin", "arm64", "26.6.2", -1, 501), ("Darwin", "arm64", "26.6.2", 0, 501), ("Darwin", "arm64", "26.6.2", 501, 0)]:
            with self.subTest(system=system, arch=architecture, version=version), self.assertRaises(ValueError):
                EVIDENCE.workflow_context(self.environment(), system, architecture, version, uid, euid, "a" * 40)

    def test_duplicate_fields_and_large_inputs_are_refused(self):
        with self.assertRaises(ValueError):
            json.loads('{"passed": 5, "passed": 6}', object_pairs_hook=EVIDENCE.unique_object)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "large.json"
            path.write_bytes(b"x" * 65537)
            with self.assertRaises(ValueError):
                EVIDENCE.read_bytes(path)

    def test_local_cli_refuses_before_reading_a_candidate(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/collect-production-child-ci-evidence.py"),
                                 "verify", "--preparation", "/nonexistent/fixture.json"],
                                env={"PATH": os.defpath}, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicit hosted macOS 26 workflow", result.stderr)
        self.assertNotIn("FileNotFoundError", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
