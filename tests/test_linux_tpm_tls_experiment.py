import importlib.util
import io
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-tpm-tls-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_tpm_tls_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


def public_record(attributes=0x40472):
    # TPM2B_PUBLIC: ECC, SHA256, no policy, null symmetric/scheme/KDF, NIST P256.
    public = struct.pack(">HHIHHHHHH", 0x23, 0x0B, attributes, 0, 0x10, 0x10, 3, 0x10, 32)
    public += bytes(range(32)) + struct.pack(">H", 32) + bytes(range(32))
    return struct.pack(">H", len(public)) + public


class SigningTemplateTests(unittest.TestCase):
    def test_required_non_migratable_signing_template(self):
        result = EXPERIMENT.signing_template(public_record())
        self.assertTrue(result["fixedTPM"])
        self.assertTrue(result["fixedParent"])
        self.assertTrue(result["sensitiveDataOrigin"])
        self.assertTrue(result["sign"])
        self.assertFalse(result["decrypt"])

    def test_exportable_or_decrypting_templates_refused(self):
        # Clear each binding/origin/sign bit or introduce decrypt/restricted independently.
        for attributes in (0x40470, 0x40462, 0x40452, 0x472, 0x60472, 0x50472):
            with self.subTest(attributes=hex(attributes)):
                with self.assertRaises(EXPERIMENT.Refused):
                    EXPERIMENT.signing_template(public_record(attributes))

    def test_truncation_trailing_data_curve_and_policy_refused(self):
        good = public_record()
        records = [good[:n] for n in range(len(good))] + [good + b"\0"]
        for offset in (3, 5, 11, 13, 15, 17, 19, 21, 55):
            altered = bytearray(good)
            altered[offset] ^= 1
            records.append(altered)
        for record in records:
            with self.subTest(record=bytes(record).hex()[:44]):
                with self.assertRaises(EXPERIMENT.Refused):
                    EXPERIMENT.signing_template(record)

    def test_user_must_explicitly_select_simulator(self):
        with patch("sys.argv", [str(SCRIPT)]), patch("sys.stderr", new_callable=io.StringIO), \
             self.assertRaises(SystemExit) as raised:
            EXPERIMENT.main()
        self.assertEqual(raised.exception.code, 2)

    def test_refuses_root_before_starting_processes(self):
        with patch.object(EXPERIMENT.os, "getuid", return_value=0), \
             patch.object(EXPERIMENT.subprocess, "Popen") as start:
            with self.assertRaisesRegex(EXPERIMENT.Refused, "ordinary-linux-user"):
                EXPERIMENT.run_experiment(None)
            start.assert_not_called()


class VersionMetadataTests(unittest.TestCase):
    def test_tpm2_version_discards_personal_tool_paths_and_other_fields(self):
        for path in ("/home/example/private runtime/bin/tpm2", "/tmp/fixture/usr/bin/tpm2"):
            raw = f'tool="{path}" version="5.7-rc1" tctis="libtss2-tctildr" tcti-default=tcti-abrmd'.encode()
            self.assertEqual(EXPERIMENT.tpm2_version(raw), "5.7-rc1")
            self.assertNotIn(path, EXPERIMENT.tpm2_version(raw))

    def test_invalid_or_ambiguous_version_fails_without_echoing_input(self):
        for raw in (b'tool="/home/example/private"', b'version="/home/example/private"',
                    b'version="5.7\nprivate"', b'version="5.7" version="5.8"',
                    b'version="' + b'1' * 65 + b'"', b'x' * 8193):
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(EXPERIMENT.Refused) as failure:
                    EXPERIMENT.tpm2_version(raw)
                self.assertEqual(str(failure.exception), "invalid-tpm2-version")


class ReportTests(unittest.TestCase):
    def test_false_retention_or_cleanup_cannot_pass(self):
        for name in ("simulatorProcessRestartRetention", "temporaryStateRemoved"):
            with self.subTest(name=name), self.assertRaises(EXPERIMENT.Refused):
                EXPERIMENT.validate_checks({name: False, "signingTemplate": {"curve": "nist_p256"}})


def wrapped_record(public=None, parent=bytes.fromhex("40000001"), empty_auth=b"\x01\x01\x01", private=b"\0\x01\xaa"):
    import base64

    def tlv(tag, value):
        length = bytes([len(value)]) if len(value) < 128 else b"\x82" + len(value).to_bytes(2, "big")
        return bytes([tag]) + length + value
    body = b"".join((tlv(6, bytes.fromhex("6781050a0103")), tlv(0xA0, empty_auth),
                     tlv(2, parent), tlv(4, public if public is not None else public_record()), tlv(4, private)))
    return b"-----BEGIN TSS2 PRIVATE KEY-----\n" + base64.b64encode(tlv(0x30, body)) + b"\n-----END TSS2 PRIVATE KEY-----\n"


class WrappedRecordTests(unittest.TestCase):
    def test_record_binds_template_and_owner_hierarchy(self):
        EXPERIMENT.validate_wrapped_record(wrapped_record(), public_record())

    def test_wrong_parent_mismatched_public_auth_and_damaged_private_refused(self):
        records = [wrapped_record(parent=bytes.fromhex("0081000001")),
                   wrapped_record(public=public_record(0x60472)),
                   wrapped_record(empty_auth=b"\x01\x01\x00"), wrapped_record(private=b"\0\x03\xaa"),
                   wrapped_record(private=b"\0\0"), b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"]
        for record in records:
            with self.subTest(record=record[:40]), self.assertRaises(EXPERIMENT.Refused):
                EXPERIMENT.validate_wrapped_record(record, public_record())


class HardwareGateTests(unittest.TestCase):
    def test_unknown_owner_auth_or_direct_tpm_cannot_start_process(self):
        from types import SimpleNamespace
        for tcti, declaration in (("device:/dev/tpm0", True), ("device:/dev/tpmrm0", False), (None, True)):
            args = SimpleNamespace(tcti=tcti, acknowledge_empty_owner_auth=declaration)
            with self.subTest(tcti=tcti, declaration=declaration), \
                 patch.object(EXPERIMENT.platform, "system", return_value="Linux"), \
                 patch.object(EXPERIMENT.os, "getuid", return_value=1000), \
                 patch.object(EXPERIMENT.os, "geteuid", return_value=1000), \
                 patch.object(EXPERIMENT.subprocess, "Popen") as start, \
                 self.assertRaisesRegex(EXPERIMENT.Refused, "explicit-resource-manager"):
                EXPERIMENT.run_hardware(args)
            start.assert_not_called()

    def test_hardware_lifecycle_cannot_start_or_stop_services(self):
        probe = EXPERIMENT.HardwareProbe(Path("/unused"), {}, "tpm2")
        for method in (probe.start, probe.halt):
            with self.assertRaises(EXPERIMENT.Refused):
                method()

    def test_create_refuses_existing_directory_and_reuse_refuses_symlink(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            parent.chmod(0o700)
            existing = parent / "existing"
            existing.mkdir(mode=0o700)
            with self.assertRaisesRegex(EXPERIMENT.Refused, "already-exists"):
                EXPERIMENT.hardware_directory(existing, True)
            link = parent / "link"
            os.symlink(existing, link)
            with self.assertRaisesRegex(EXPERIMENT.Refused, "unsafe-hardware-directory"):
                EXPERIMENT.hardware_directory(link, False)
