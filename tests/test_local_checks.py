"""Exercise host selection and failure propagation without compilers or devices."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMMON_TASKS = [":protocol-kotlin:jvmTest", ":phone-core:test", ":phone-ui:jvmTest", ":dev-invitation:test"]
ANDROID_TASKS = [":android-app:testDebugUnitTest", ":android-app:assembleDebug", ":android-app:lintDebug"]


class LocalChecksTests(unittest.TestCase):
    def run_gate(self, host, failure=""):
        with tempfile.TemporaryDirectory(prefix="remozio-local-checks-") as temporary:
            directory = Path(temporary)
            repo = directory / "repo with spaces"
            (repo / "scripts").mkdir(parents=True)
            (directory / "bin").mkdir()
            shutil.copy2(ROOT / "scripts/check-local.sh", repo / "scripts/check-local.sh")
            stub = '#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$CHECK_LOG"\n[ "${0##*/}" != "$FAIL_CHECK" ] || exit 23\n'
            for name in ("scripts/check.sh", "scripts/check-linux-protocol.sh", "scripts/check-linux-host.sh",
                         "scripts/build-ios-app.sh", "gradlew"):
                path = repo / name
                path.write_text(stub)
                path.chmod(0o755)
            uname = directory / "bin/uname"
            uname.write_text('#!/bin/sh\nprintf "%s\\n" "$TEST_HOST"\n')
            uname.chmod(0o755)
            log = directory / "calls"
            env = os.environ | {"PATH": str(uname.parent) + os.pathsep + os.environ["PATH"],
                                "TEST_HOST": host, "FAIL_CHECK": failure, "CHECK_LOG": str(log)}
            result = subprocess.run(["/bin/sh", str(repo / "scripts/check-local.sh")],
                                    cwd=directory, env=env, text=True, capture_output=True, timeout=10)
            return result, [line.split() for line in log.read_text().splitlines()] if log.exists() else []

    def test_linux_runs_portable_checks_without_mac_peers_from_another_directory(self):
        result, calls = self.run_gate("Linux")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [["./scripts/check.sh"], ["./scripts/check-linux-protocol.sh"],
                                 ["./scripts/check-linux-host.sh"],
                                 ["./gradlew", *COMMON_TASKS, *ANDROID_TASKS]])

    def test_mac_builds_peers_before_running_all_interoperability_checks(self):
        result, calls = self.run_gate("Darwin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [["./scripts/check.sh"],
                                 ["./gradlew", *COMMON_TASKS, ":phone-core:approvalFlowTest",
                                  ":protocol-kotlin:iosSimulatorArm64Test", ":phone-ui:iosSimulatorArm64Test",
                                  *ANDROID_TASKS],
                                 ["./scripts/build-ios-app.sh"]])

    def test_unknown_platform_fails_before_running_checks(self):
        result, calls = self.run_gate("FreeBSD")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_repository_check_failure_stops_both_hosts(self):
        for host in ("Linux", "Darwin"):
            with self.subTest(host=host):
                result, calls = self.run_gate(host, "check.sh")
                self.assertEqual(result.returncode, 23)
                self.assertEqual(calls, [["./scripts/check.sh"]])

    def test_linux_swift_failure_prevents_gradle(self):
        phases = ["check.sh", "check-linux-protocol.sh", "check-linux-host.sh"]
        for failed_phase in phases[1:]:
            with self.subTest(phase=failed_phase):
                result, calls = self.run_gate("Linux", failed_phase)
                self.assertEqual(result.returncode, 23)
                self.assertEqual(calls, [[f"./scripts/{phase}"]
                                         for phase in phases[:phases.index(failed_phase) + 1]])

    def test_gradle_failure_fails_the_gate_on_both_hosts(self):
        for host in ("Linux", "Darwin"):
            with self.subTest(host=host):
                result, calls = self.run_gate(host, "gradlew")
                self.assertEqual(result.returncode, 23)
                self.assertEqual(calls[-1][0], "./gradlew")

    def test_mac_app_build_failure_fails_the_gate(self):
        result, calls = self.run_gate("Darwin", "build-ios-app.sh")
        self.assertEqual(result.returncode, 23)
        self.assertEqual(calls[-1], ["./scripts/build-ios-app.sh"])


if __name__ == "__main__":
    unittest.main()
