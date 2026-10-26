import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('connector_artifact', ROOT / 'scripts/cloudflared_artifact.py')
ARTIFACT = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(ARTIFACT)


class ConnectorArtifactTests(unittest.TestCase):
    def fixture(self, *, name='cloudflared', kind=tarfile.REGTYPE, mode=0o755, extra=False, arm64=True):
        binary = struct.pack('<8I', 0xFEEDFACF, 0x0100000C if arm64 else 0x01000007, 0, 2, 0, 0, 0, 0) + b'owned-test-bytes'
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            member = tarfile.TarInfo(name); member.type = kind; member.mode = mode
            member.size = len(binary) if kind == tarfile.REGTYPE else 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE): member.linkname = '/outside-fixture'
            archive.addfile(member, io.BytesIO(binary) if member.size else None)
            if extra:
                second = tarfile.TarInfo('unexpected'); second.size = 1
                archive.addfile(second, io.BytesIO(b'x'))
        data = stream.getvalue()
        return data, {'version': '2026.10.2', 'archiveSHA256': hashlib.sha256(data).hexdigest(), 'archiveSize': len(data),
                      'binarySHA256': hashlib.sha256(binary).hexdigest(), 'binarySize': len(binary)}, binary

    def test_archive_hash_is_verified_before_any_tar_processing(self):
        data, value, _ = self.fixture()
        with patch.object(ARTIFACT.tarfile, 'open') as parse:
            with self.assertRaisesRegex(ValueError, 'does not match'): ARTIFACT.binary_from_archive(data[:-1] + b'x', value)
        parse.assert_not_called()

    def test_archive_yields_only_the_expected_arm64_executable(self):
        data, value, binary = self.fixture()
        self.assertEqual(ARTIFACT.binary_from_archive(data, value), binary)
        for options in ({'name': '../cloudflared'}, {'name': '/cloudflared'}, {'kind': tarfile.SYMTYPE},
                        {'kind': tarfile.LNKTYPE}, {'mode': 0o4755}, {'extra': True}, {'arm64': False}):
            with self.subTest(options=options):
                data, value, _ = self.fixture(**options)
                with self.assertRaises(ValueError): ARTIFACT.binary_from_archive(data, value)

    def test_wrong_executable_hash_or_size_cannot_escape_a_valid_archive(self):
        data, value, _ = self.fixture()
        for key, changed in (('binarySHA256', '0' * 64), ('binarySize', value['binarySize'] + 1)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                ARTIFACT.binary_from_archive(data, value | {key: changed})

    def test_cache_reuse_does_not_download_and_corruption_is_not_overwritten(self):
        data, value, _ = self.fixture(); calls = []
        def fetch(pin): calls.append(pin); return data
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary).resolve() / 'cache'
            self.assertEqual(ARTIFACT.cached_archive(cache, value, fetch), data)
            self.assertEqual(ARTIFACT.cached_archive(cache, value, fetch), data)
            self.assertEqual(len(calls), 1)
            target = cache / 'cloudflared-darwin-arm64.tgz'; corrupt = b'x' * len(data); target.write_bytes(corrupt)
            with self.assertRaises(ValueError): ARTIFACT.cached_archive(cache, value, fetch)
            self.assertEqual(target.read_bytes(), corrupt); self.assertEqual(len(calls), 1)

    def test_cache_refuses_symbolic_inputs_without_touching_the_target(self):
        data, value, _ = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve(); cache = base / 'cache'; cache.mkdir()
            target = base / 'outside'; target.write_bytes(data)
            (cache / 'cloudflared-darwin-arm64.tgz').symlink_to(target)
            with self.assertRaises(ValueError): ARTIFACT.cached_archive(cache, value, lambda _: self.fail('Unexpected download'))
            self.assertEqual(target.read_bytes(), data)

    def test_wrong_download_is_not_saved_as_a_build_input(self):
        data, value, _ = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary).resolve() / 'cache'
            with self.assertRaises(ValueError): ARTIFACT.cached_archive(cache, value, lambda _: data + b'x')
            self.assertEqual({p.name for p in cache.iterdir()}, {'input.lock'})

    def test_signature_check_requires_the_expected_identifier_hash_and_runtime(self):
        valid = 'Identifier=dev.remozio.cloudflared.debug\nCDHash=' + 'a' * 40 + '\nTeamIdentifier=not set\nCodeDirectory flags=0x10000(runtime)\n'
        with patch.object(ARTIFACT, 'command', side_effect=[subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, '', valid)]):
            digest, team = ARTIFACT.signed_tool_identity(Path('/owned-fixture'), 'dev.remozio.cloudflared.debug')
        self.assertEqual(digest, bytes.fromhex('a' * 40)); self.assertIsNone(team)
        for invalid in (valid.replace('.debug', '.other'), valid.replace('(runtime)', '(none)'), valid.replace('a' * 40, 'bad')):
            with self.subTest(invalid=invalid), patch.object(ARTIFACT, 'command', side_effect=[
                    subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, '', invalid)]):
                with self.assertRaises(ValueError): ARTIFACT.signed_tool_identity(Path('/owned-fixture'), 'dev.remozio.cloudflared.debug')

