import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-native-tpm-tls-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_native_tpm_tls_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


def report(**overrides):
    value = {"status": "ok", "keyProviderTPM2": True, "signatureProviderTPM2": True,
        "clientVerificationRejected": False, "alpnRejected": False,
        "applicationBytesReceived": 0, "applicationBytesSent": 0, "signatureBytes": 71}
    value.update(overrides)
    return value


class NativeReportTests(unittest.TestCase):
    def test_strict_bounded_report(self):
        value = report()
        self.assertEqual(EXPERIMENT.native_report(json.dumps(value).encode()), value)
        bad = [b"private diagnostic path", b"x" * 2049, b"null", b"[]",
            json.dumps(report(status="/private/path")).encode(), json.dumps(report(signatureBytes=81)).encode(),
            json.dumps(report(signatureBytes=True)).encode(), json.dumps(report(keyProviderTPM2=1)).encode(),
            json.dumps(report(private="secret")).encode(), json.dumps(value).replace('"status": "ok"',
                '"status": "ok", "status": "ok"').encode()]
        for data in bad:
            with self.subTest(length=len(data)), self.assertRaises(EXPERIMENT.Refused) as raised:
                EXPERIMENT.native_report(data)
            self.assertEqual(str(raised.exception), "invalid-native-report")

    def test_no_success_without_both_tpm_provider_assertions(self):
        probe = EXPERIMENT.NativeExperiment(Path("/unused"), {}, "tpm2", "swtpm", "abrmd", Path("/probe"))
        for key in ("keyProviderTPM2", "signatureProviderTPM2"):
            result = subprocess.CompletedProcess([], 0, stdout=json.dumps(report(**{key: False})).encode())
            with patch.object(EXPERIMENT.subprocess, "run", return_value=result), \
                    self.assertRaisesRegex(EXPERIMENT.Refused, "native-provider-sign-failed"):
                probe.sign()

    def test_no_arbitrary_signing_purpose_or_transport_sign_entry(self):
        probe = EXPERIMENT.NativeExperiment(Path("/unused"), {}, "tpm2", "swtpm", "abrmd", Path("/probe"))
        for purpose in ("transport", "../../authority", "arbitrary"):
            with patch.object(EXPERIMENT.subprocess, "run") as run, \
                    self.assertRaisesRegex(EXPERIMENT.Refused, "unsupported-native-signing-purpose"):
                probe.sign(purpose)
            run.assert_not_called()

    def test_sign_exit_status_must_match_native_report(self):
        probe = EXPERIMENT.NativeExperiment(Path("/unused"), {}, "tpm2", "swtpm", "abrmd", Path("/probe"))
        result = subprocess.CompletedProcess([], 77, stdout=json.dumps(report()).encode())
        with patch.object(EXPERIMENT.subprocess, "run", return_value=result), \
                self.assertRaisesRegex(EXPERIMENT.Refused, "native-sign-exit-mismatch"):
            probe.sign(expected=False)


class NativeLifecycleTests(unittest.TestCase):
    def test_explicit_simulator_required_and_hardware_options_unavailable(self):
        for arguments in ([], ["--hardware"], ["--simulator", "--hardware", "--runtime-root", "/x", "--probe", "/x"]):
            with patch("sys.argv", [str(SCRIPT), *arguments]), patch("sys.stderr", new_callable=io.StringIO), \
                    patch.object(EXPERIMENT.subprocess, "Popen") as start, self.assertRaises(SystemExit) as raised:
                EXPERIMENT.main()
            self.assertEqual(raised.exception.code, 2)
            start.assert_not_called()

    def test_root_rejected_before_runtime_or_process_access(self):
        with patch.object(EXPERIMENT.os, "getuid", return_value=0), \
                patch.object(EXPERIMENT.subprocess, "Popen") as start, \
                self.assertRaisesRegex(EXPERIMENT.Refused, "ordinary-linux-user"):
            EXPERIMENT.run_native(None)
        start.assert_not_called()

    def test_real_timed_out_child_is_terminated_and_reaped(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            with patch.object(EXPERIMENT.BASE, "DEADLINE", .05), \
                    self.assertRaisesRegex(EXPERIMENT.Refused, "native-process-timeout"):
                EXPERIMENT.finish_native(process)
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.stdout.closed)
        finally:
            EXPERIMENT.BASE.stop(process)
            process.stdout.close()

    def test_expired_absolute_deadline_does_not_start_another_wait_budget(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            with self.assertRaisesRegex(EXPERIMENT.Refused, "native-process-timeout"):
                EXPERIMENT.finish_native(process, deadline=time.monotonic() - 1)
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.stdout.closed)
        finally:
            EXPERIMENT.BASE.stop(process)
            process.stdout.close()

    def test_injected_provision_failure_stops_simulator_and_removes_temporary_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in ("usr/bin/tpm2", "usr/bin/swtpm", "usr/sbin/tpm2-abrmd", "probe"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(mode=0o700)
            fake = Mock()
            fake.openssl.return_value = subprocess.CompletedProcess([], 0, stdout=b"OpenSSL fixture")
            fake.run.return_value = subprocess.CompletedProcess([], 0, stdout=b'version="5.7"')
            fake.provision.side_effect = EXPERIMENT.Refused("injected-provision-failure")
            with patch.object(EXPERIMENT, "NativeExperiment", return_value=fake) as constructor, \
                    patch.object(EXPERIMENT.platform, "system", return_value="Linux"),                     patch.object(EXPERIMENT.os, "getuid", return_value=1000), \
                    patch.object(EXPERIMENT.os, "geteuid", return_value=1000), \
                    self.assertRaisesRegex(EXPERIMENT.Refused, "injected-provision-failure"):
                EXPERIMENT.run_native(SimpleNamespace(runtime_root=root, probe=root / "probe"))
            fake.start.assert_called_once_with()
            fake.halt.assert_called_once_with()
            self.assertFalse(constructor.call_args.args[0].exists())


if __name__ == "__main__":
    unittest.main()
