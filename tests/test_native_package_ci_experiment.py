from contextlib import redirect_stdout
import hashlib
import io
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_package_ci', ROOT / 'scripts/run-native-package-ci-experiment.py')
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)
PINS = 'ABCDEFGHIJ:' + '01' * 20 + ':' + '02' * 32


class NativePackageCIExperimentTests(unittest.TestCase):
    def asset(self):
        return {'id': 456, 'name': EXPERIMENT.ASSET_NAME, 'state': 'uploaded', 'size': 1024}

    def release(self):
        return {'id': 123, 'draft': True, 'published_at': None,
                'tag_name': 'native-installer-experiment-0123456789ab', 'assets': [self.asset()]}

    def test_only_the_exact_unpublished_draft_and_asset_are_accepted(self):
        self.assertEqual(EXPERIMENT.validate_asset(self.release(), self.asset(), '123', '456'), 1024)
        cases = [('id', 124), ('id', True), ('draft', 1), ('draft', False),
                 ('published_at', '2026-10-16'), ('tag_name', 'v1.0'), ('assets', []),
                 ('assets', [self.asset(), self.asset()]), ('assets', [dict(self.asset(), size=2048)])]
        for key, value in cases:
            release = self.release(); release[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                EXPERIMENT.validate_asset(release, self.asset(), '123', '456')
        for key, value in [('id', 457), ('id', True), ('name', '../payload'), ('state', 'new'),
                           ('size', True), ('size', 0), ('size', EXPERIMENT.MAX_PACKAGE_BYTES + 1)]:
            asset = self.asset(); asset[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                EXPERIMENT.validate_asset(self.release(), asset, '123', '456')

    def test_provider_identifiers_and_trust_pins_cannot_inject_arguments(self):
        for value in ['', '0', '-1', '1/../../assets', '1\n', True, 123, '1' * 21]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                EXPERIMENT.positive_id(value)
        for digest, team in [('a' * 64 + '\n', 'ABCDEFGHIJ'), ('A' * 64, 'ABCDEFGHIJ'),
                             ('a' * 64, 'ABC;touchX'), ('a' * 64, 'ABCDEFGHIJ\n')]:
            with self.subTest(team=team), self.assertRaises(ValueError):
                EXPERIMENT.pins(digest, team)

    def test_transfer_rejects_changed_bytes_links_and_wrong_sizes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'fixture.pkg'; path.write_bytes(b'package fixture')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            EXPERIMENT.verify_package(path, digest, path.stat().st_size)
            for value, size in [('f' * 64, path.stat().st_size), (digest, 0), (digest, path.stat().st_size + 1)]:
                with self.assertRaises(ValueError):
                    EXPERIMENT.verify_package(path, value, size)
            link = path.with_name('link'); link.symlink_to(path)
            with self.assertRaises(ValueError):
                EXPERIMENT.verify_package(link, digest, path.stat().st_size)
            hardlink = path.with_name('hardlink'); os.link(path, hardlink)
            with self.assertRaises(ValueError):
                EXPERIMENT.verify_package(path, digest, path.stat().st_size)

    def test_production_script_and_helper_must_match_in_both_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for role in EXPERIMENT.BUILDER.IDENTIFIERS:
                directory = root / (role + '.pkg/Scripts'); directory.mkdir(parents=True)
                script = directory / ('preinstall' if role == 'payload' else 'postinstall')
                script.write_text(EXPERIMENT.BUILDER.package_script(role, PINS))
                (directory / 'RemozioSetup').write_bytes(b'same native helper')
            self.assertEqual(EXPERIMENT.read_profile(root, 'ABCDEFGHIJ'), PINS)
            metadata = bytes.fromhex('00051607000200004d6163204f5320582020202020202020000200000009000000320000007100000002000000a300000000000000000000000000000000000000000000000000000000000000000000000000004154545200000000000000a3000000980000000b00000000000000000000000000000001000000980000000b000015636f6d2e6170706c652e70726f76656e616e636500010200b4b8f8f5eeb94031')
            sidecar = root / 'payload.pkg/Scripts/._RemozioSetup'; sidecar.write_bytes(metadata)
            self.assertEqual(EXPERIMENT.read_profile(root, 'ABCDEFGHIJ'), PINS)
            changed = bytearray(metadata); changed[50] = 1; sidecar.write_bytes(changed)
            with self.assertRaises(RuntimeError): EXPERIMENT.read_profile(root, 'ABCDEFGHIJ')
            sidecar.unlink()

            with self.assertRaises(ValueError):
                EXPERIMENT.read_profile(root, 'KLMNOPQRST')
            script = root / 'bootstrap.pkg/Scripts/postinstall'
            original = script.read_bytes()
            script.write_bytes(original + b'echo unexpected\n')
            with self.assertRaises(ValueError): EXPERIMENT.read_profile(root, 'ABCDEFGHIJ')
            script.write_bytes(original)
            helper = root / 'bootstrap.pkg/Scripts/RemozioSetup'; helper.write_bytes(b'changed helper')
            with self.assertRaises(ValueError): EXPERIMENT.read_profile(root, 'ABCDEFGHIJ')
            helper.write_bytes(b'same native helper')
            extra = helper.with_name('extra'); extra.write_bytes(b'extra script')
            with self.assertRaises(ValueError): EXPERIMENT.read_profile(root, 'ABCDEFGHIJ')

    def test_unknown_or_generic_native_status_cannot_establish_retained_state(self):
        for value in [b'', b'bootstrap\n', b'retained', b'retained\nextra\n']:
            with patch.object(EXPERIMENT, 'command', return_value=subprocess.CompletedProcess([], 0, value, b'')), \
                    self.subTest(value=value), self.assertRaises(ValueError):
                EXPERIMENT.require_retained(PINS)
        with patch.object(EXPERIMENT, 'command', return_value=subprocess.CompletedProcess([], 0, b'retained\n', b'')):
            EXPERIMENT.require_retained(PINS)

    def test_sudo_is_noninteractive_with_an_empty_environment_and_no_shell(self):
        with patch.object(EXPERIMENT.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as run:
            EXPERIMENT.command(['/usr/sbin/installer', '-pkg', '/fixture with spaces.pkg', '-target', '/'], root=True)
            args, kwargs = run.call_args
            self.assertEqual(args[0], ['/usr/bin/sudo', '-n', '--', '/usr/bin/env', '-i',
                'PATH=/usr/bin:/bin:/usr/sbin:/sbin', 'HOME=/var/root', 'LC_ALL=C',
                '/usr/sbin/installer', '-pkg', '/fixture with spaces.pkg', '-target', '/'])
            self.assertFalse(kwargs.get('shell', False))
        with patch.object(EXPERIMENT.subprocess, 'run', return_value=subprocess.CompletedProcess([], -15, b'', b'')) as run:
            with self.assertRaises(RuntimeError): EXPERIMENT.command(['/fixture'], accepted=(0, 1))
            self.assertEqual(run.call_count, 1)

    def test_no_success_record_after_changed_retention_or_unclassified_failure(self):
        for failure in [None, 'repeat changed', 'generic refusal', 'refusal changed', 'signal', 'timeout']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); package = root / 'candidate.pkg'; package.write_bytes(b'fixed package')
                digest = hashlib.sha256(package.read_bytes()).hexdigest()
                output = root / 'evidence.json'
                args = SimpleNamespace(package=package, package_sha256=digest, trusted_team='ABCDEFGHIJ', output=output)
                snapshots = ['retained', 'changed' if failure == 'repeat changed' else 'retained',
                             'changed' if failure == 'refusal changed' else 'retained']
                def command(arguments, **kwargs):
                    if arguments[0] == '/usr/bin/mktemp':
                        return SimpleNamespace(stdout=b'/private/var/tmp/remozio-package-ci.ABCDEFGH\n')
                    if arguments[0] == '/usr/bin/shasum':
                        return SimpleNamespace(stdout=(digest + '  /private/var/tmp/remozio-package-ci.ABCDEFGH/' + EXPERIMENT.ASSET_NAME + '\n').encode())
                    if arguments[0] == '/usr/sbin/installer':
                        if failure == 'timeout': raise subprocess.TimeoutExpired(arguments, 180)
                        if failure == 'signal': raise RuntimeError('installer failed with status -15')
                        if '-dumplog' in arguments:
                            return SimpleNamespace(stdout=b'', stderr=b'generic error' if failure == 'generic refusal' else b'Package preparation refused or failed.')
                    if '--prepare-package' in arguments:
                        return SimpleNamespace(stdout=b'', stderr=b'Package preparation refused or failed.')
                    return SimpleNamespace(stdout=b'', stderr=b'')
                with redirect_stdout(io.StringIO()), patch.object(EXPERIMENT, 'context', return_value={'sourceCommit': 'a' * 40}), \
                     patch.object(EXPERIMENT, 'SHARED', root / 'absent'), patch.object(EXPERIMENT, 'ENTRY', root / 'entry'), \
                     patch.object(EXPERIMENT, 'command', side_effect=command), \
                     patch.object(EXPERIMENT, 'read_profile', return_value=PINS), \
                     patch.object(EXPERIMENT.BUILDER, 'verify_payload'), \
                     patch.object(EXPERIMENT, 'retained_snapshot', side_effect=snapshots):
                    if failure is None:
                        EXPERIMENT.run(args)
                        self.assertTrue(output.exists())
                    else:
                        with self.assertRaises((ValueError, RuntimeError, subprocess.TimeoutExpired)):
                            EXPERIMENT.run(args)
                        self.assertFalse(output.exists())

    def test_both_modes_refuse_local_use_before_files_network_or_elevation(self):
        for mode in ['fetch', 'run']:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/run-native-package-ci-experiment.py'), mode,
                '--package', '/nonexistent/fixture.pkg', '--package-sha256', 'a' * 64,
                '--trusted-team', 'ABCDEFGHIJ', '--output', '/nonexistent/evidence.json'],
                env={'PATH': os.defpath}, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('explicit hosted macOS 26 workflow', result.stderr)
            self.assertNotIn('FileNotFoundError', result.stderr)
            self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
