import gzip
import importlib.util
from pathlib import Path
import stat
import platform
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('package_builder', ROOT / 'scripts/build-macos-package.py')
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
PINS = 'ABCDEFGHIJ:' + '01' * 20 + ':' + '02' * 32


def cpio(name, *, mode=stat.S_IFREG | 0o644, uid=0, gid=0, links=1, data=b''):
    name = name.encode() + b'\0'
    fields = [(0, 6), (1, 6), (mode, 6), (uid, 6), (gid, 6), (links, 6), (0, 6),
              (0, 11), (len(name), 6), (len(data), 11)]
    return b'070707' + ''.join(format(value, '0' + str(width) + 'o') for value, width in fields).encode() + name + data


class MacPackageBuilderTests(unittest.TestCase):
    def inventory(self, data):
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / 'Payload'
            payload.write_bytes(gzip.compress(data + cpio('TRAILER!!!')))
            return BUILDER.archive_inventory(payload)

    def test_archive_ownership_is_read_from_cpio_not_extracted_files(self):
        rows = self.inventory(cpio('.', mode=stat.S_IFDIR | 0o755) + cpio('Remozio.app/helper', mode=stat.S_IFREG | 0o755, data=b'hello'))
        self.assertEqual(rows['Remozio.app/helper']['size'], 5)
        for kwargs in ({'uid': 501}, {'gid': 20}, {'mode': stat.S_IFREG | 0o666},
                       {'mode': stat.S_IFREG | 0o4755}, {'mode': stat.S_IFLNK | 0o755}, {'links': 2}):
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                self.inventory(cpio('Remozio.app/helper', **kwargs))

    def test_archive_rejects_traversal_duplicates_unknown_format_and_truncation(self):
        for data in (cpio('../outside'), cpio('/outside'), cpio('same') + cpio('same'), cpio('same') + cpio('./same'), b'070701', cpio('one')[:-1]):
            with self.subTest(data=data[:20]), self.assertRaises((RuntimeError, ValueError)):
                self.inventory(data)

    def test_only_native_provenance_metadata_is_accepted(self):
        metadata = bytes.fromhex('00051607000200004d6163204f5320582020202020202020000200000009000000320000007100000002000000a300000000000000000000000000000000000000000000000000000000000000000000000000004154545200000000000000a3000000980000000b00000000000000000000000000000001000000980000000b000015636f6d2e6170706c652e70726f76656e616e636500010200b4b8f8f5eeb94031')
        BUILDER.validate_metadata(metadata)
        for index in (0, 25, 37, 49, 50, 84, 119, 123, 129, 131):
            changed = bytearray(metadata); changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                BUILDER.validate_metadata(bytes(changed))
        with self.assertRaises(RuntimeError): BUILDER.validate_metadata(metadata[:-1])
        # Native cpio mirrors a directory's link count on its AppleDouble metadata.
        rows = self.inventory(cpio('._Remozio.app', links=3, data=metadata))
        self.assertTrue(rows['._Remozio.app']['metadata'])

    def test_payload_requires_exact_bytes_and_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); app = root / 'Remozio.app'; app.mkdir(); app.chmod(0o755)
            helper = app / 'helper'; helper.write_bytes(b'hello'); helper.chmod(0o755)
            base = cpio('.', mode=stat.S_IFDIR | 0o755) + cpio('Remozio.app', mode=stat.S_IFDIR | 0o755)
            payload = root / 'Payload'
            def write(data): payload.write_bytes(gzip.compress(data + cpio('TRAILER!!!')))
            write(base + cpio('Remozio.app/helper', mode=stat.S_IFREG | 0o755, data=b'hello'))
            self.assertEqual(BUILDER.verify_payload(payload, app), 3)
            for data in (base, base + cpio('Remozio.app/helper', mode=stat.S_IFREG | 0o755, data=b'other'),
                         base + cpio('Remozio.app/helper', data=b'hello'),
                         base + cpio('Remozio.app/helper', mode=stat.S_IFREG | 0o755, data=b'hello') + cpio('extra')):
                write(data)
                with self.assertRaises(RuntimeError): BUILDER.verify_payload(payload, app)

    def test_payload_rejects_directory_and_file_type_substitutions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); app = root / 'Remozio.app'; app.mkdir(); app.chmod(0o755)
            contents = app / 'Contents'; contents.mkdir(); contents.chmod(0o755)
            helper = contents / 'helper'; helper.write_bytes(b'hello'); helper.chmod(0o755)
            rows = [('.', stat.S_IFDIR | 0o755, b''), ('Remozio.app', stat.S_IFDIR | 0o755, b''),
                    ('Remozio.app/Contents', stat.S_IFDIR | 0o755, b''),
                    ('Remozio.app/Contents/helper', stat.S_IFREG | 0o755, b'hello')]
            for index in range(len(rows)):
                changed = list(rows); name, mode, data = changed[index]
                changed[index] = (name, (stat.S_IFDIR if stat.S_ISREG(mode) else stat.S_IFREG) | 0o755, data)
                payload = root / 'Payload'
                payload.write_bytes(gzip.compress(b''.join(cpio(name, mode=mode, data=data) for name, mode, data in changed) + cpio('TRAILER!!!')))
                with self.subTest(index=index), self.assertRaises(RuntimeError):
                    BUILDER.verify_payload(payload, app)

    def test_scripts_refuse_missing_or_external_volume_before_invoking_any_helper(self):
        for role in BUILDER.IDENTIFIERS:
            with tempfile.TemporaryDirectory() as temporary:
                script = Path(temporary) / 'script'; script.write_text(BUILDER.package_script(role, PINS))
                for arguments in ([], ['package', 'location', '/Volumes/Other']):
                    result = subprocess.run(['/bin/sh', script, *arguments], capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 64)
                    self.assertIn(b'current startup volume', result.stderr)
                result = subprocess.run(['/bin/sh', '-n', script], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0)

    def test_profiles_cannot_inject_script_text_or_select_a_different_team(self):
        self.assertEqual(BUILDER.profile(PINS, 'ABCDEFGHIJ'), PINS)
        for value in (PINS + '\n', PINS + '; touch /tmp/no', PINS.replace('01', 'GG'), ''):
            with self.assertRaises(ValueError): BUILDER.profile(value, 'ABCDEFGHIJ')
        with self.assertRaises(ValueError): BUILDER.profile(PINS, 'KLMNOPQRST')

    def test_distribution_has_always_selected_resume_component_and_optional_payload(self):
        root = ET.fromstring(BUILDER.distribution('1'))
        choices = {value.get('id'): value for value in root.findall('choice')}
        self.assertEqual(choices['payload'].get('selected'), 'needsPayload()')
        self.assertEqual(choices['bootstrap'].get('selected'), 'true')
        self.assertEqual(root.find('volume-check/allowed-os-versions/os-version').get('min'), '26.0')
        self.assertEqual(root.find('domains').get('enable_currentUserHome'), 'false')
        self.assertEqual(root.find('options').get('hostArchitectures'), 'arm64')

    def test_output_and_trust_must_be_explicit_before_any_build_or_signing(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(BUILDER, 'run') as run:
            output = Path(temporary) / 'Remozio.pkg'
            for kwargs in ({}, {'unsigned_developer': True, 'installer_identity': 'certificate'}):
                with self.assertRaises(ValueError): BUILDER.build(Path('/unused'), output, 'ABCDEFGHIJ', **kwargs)
            with self.assertRaises(ValueError): BUILDER.build(Path('/unused'), output, 'bad-team', unsigned_developer=True)
            output.write_bytes(b'existing')
            with self.assertRaises(ValueError): BUILDER.build(Path('/unused'), output, 'ABCDEFGHIJ', unsigned_developer=True)
            self.assertEqual(output.read_bytes(), b'existing')
            run.assert_not_called()

    def test_failed_package_copy_does_not_publish_partial_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); candidate = root / 'candidate'; candidate.write_bytes(b'verified package')
            output = root / 'Remozio.pkg'
            def failed_copy(source, destination):
                destination.write(b'partial'); raise OSError('fixture copy failure')
            with patch.object(BUILDER.shutil, 'copyfileobj', side_effect=failed_copy):
                with self.assertRaises(OSError): BUILDER.publish_package(candidate, output)
            self.assertFalse(output.exists())
            self.assertEqual(list(root.iterdir()), [candidate])
            BUILDER.publish_package(candidate, output)
            self.assertEqual(output.read_bytes(), candidate.read_bytes())
            with self.assertRaises(FileExistsError): BUILDER.publish_package(candidate, output)
            self.assertEqual(output.read_bytes(), b'verified package')
            self.assertEqual(set(root.iterdir()), {candidate, output})

    def test_failed_app_export_leaves_no_final_path_or_owned_temporary_copy(self):
        reader = BUILDER.signing_reader()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); app = root / 'source.app'; app.mkdir(); (app / 'helper').write_bytes(b'signed fixture')
            destination = root / 'export.app'
            def failed_copy(source, candidate, **kwargs):
                candidate.mkdir(); (candidate / 'partial').write_bytes(b'partial'); raise OSError('fixture copy failure')
            cases = [patch.object(reader.shutil, 'copytree', side_effect=failed_copy),
                     patch.object(reader, 'fingerprint', side_effect=['candidate', 'different source']),
                     patch.object(reader, 'inspect', side_effect=RuntimeError('fixture rejection'))]
            for failure in cases:
                with failure, self.assertRaises((OSError, RuntimeError)):
                    reader.export_verified_app('/unused', app, 'ABCDEFGHIJ', destination)
                self.assertFalse(destination.exists())
                self.assertEqual(list(root.iterdir()), [app])

    @unittest.skipUnless(platform.system() == 'Darwin', 'Native exclusive directory publication')
    def test_native_app_export_publishes_once_without_replacing_foreign_entries(self):
        reader = BUILDER.signing_reader()
        with tempfile.TemporaryDirectory() as temporary, patch.object(reader, 'inspect', return_value={'result': 'accepted'}):
            root = Path(temporary); app = root / 'source.app'; app.mkdir(); (app / 'helper').write_bytes(b'signed fixture')
            destination = root / 'export.app'
            reader.export_verified_app('/unused', app, 'ABCDEFGHIJ', destination)
            self.assertEqual(reader.fingerprint(destination), reader.fingerprint(app))
            for kind in ('directory', 'file', 'link'):
                foreign = root / kind
                if kind == 'directory': foreign.mkdir()
                elif kind == 'file': foreign.write_bytes(b'user data')
                else: foreign.symlink_to('/missing-fixture')
                before = foreign.lstat()
                with self.assertRaises(OSError): reader.export_verified_app('/unused', app, 'ABCDEFGHIJ', foreign)
                self.assertEqual(foreign.lstat().st_ino, before.st_ino)
            self.assertFalse(any(path.name.startswith('.remozio-export-') for path in root.iterdir()))

    def test_signing_export_requires_certificate_and_fresh_destination(self):
        reader = BUILDER.signing_reader()
        with tempfile.TemporaryDirectory() as temporary, patch.object(reader, 'run') as run:
            destination = Path(temporary) / 'Remozio.app'
            with self.assertRaises(ValueError): reader.measure(Path('/unused'), export_app=destination)
            destination.symlink_to('/missing-fixture-target')
            with self.assertRaises(ValueError):
                reader.measure(Path('/unused'), identity='A' * 40, team='ABCDEFGHIJ', export_app=destination)
            run.assert_not_called()
