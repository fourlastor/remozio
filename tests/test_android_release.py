import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('android_release', Path(__file__).parents[1] / 'scripts/prepare-android-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class AndroidReleaseTests(unittest.TestCase):
    metadata = "package: name='dev.sebastiano.remozio.android' versionCode='2' versionName='0.2.0'\nminSdkVersion:'37'\ntargetSdkVersion:'37'\n"
    fingerprint = 'a' * 64

    def test_versions_follow_updater_contract(self):
        for value in ('0.2.0', '1.0.0-beta.12', '1.0.0+build.01'):
            release.validate_version(value)
        for value in ('v0.2.0', '01.2.0', '0.2.0-01', '0.2', '2147483648.0.0', '1.0.0/escape'):
            with self.assertRaises(ValueError):
                release.validate_version(value)

    def test_rejects_wrong_package_version_sdk_and_debug(self):
        release.check_metadata(self.metadata, '0.2.0', 2)
        for text in (self.metadata.replace('dev.sebastiano.remozio.android', 'dev.sebastiano.remozio.android.debug'),
                     self.metadata.replace("versionCode='2'", "versionCode='1'"),
                     self.metadata.replace("minSdkVersion:'37'", "minSdkVersion:'36'"),
                     self.metadata.replace("versionName='0.2.0'", "versionName='0.1.0'"),
                     self.metadata.replace("package: ", "package: split='x' "),
                     self.metadata + 'application-debuggable\n'):
            with self.assertRaises(ValueError):
                release.check_metadata(text, '0.2.0', 2)

    def test_requires_exactly_one_expected_signer(self):
        line = f'Number of signers: 1\nSigner #1 certificate SHA-256 digest: {self.fingerprint}\n'
        release.check_signer(line, self.fingerprint)
        release.check_signer(line.replace('Signer #1', 'V3.0 Signer:'), self.fingerprint)
        for text in ('', line.replace('a' * 64, 'b' * 64), line + line.replace('#1', '#2')):
            with self.assertRaises(ValueError):
                release.check_signer(text, self.fingerprint)

    def tool(self, tool, *args):
        if tool.name == 'aapt2':
            return self.metadata if args[1] == 'badging' else ''
        if tool.name == 'apksigner':
            return f'Number of signers: 1\nV3.0 Signer: certificate SHA-256 digest: {self.fingerprint}\n'
        return ''

    def test_prepares_verified_copy_without_overwriting(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'input.apk'; source.write_bytes(b'fixture')
            output = root / 'release'
            with patch.object(release, 'run_tool', side_effect=self.tool) as tools:
                release.prepare(source, output, root, '0.2.0', 2, self.fingerprint)
                self.assertEqual((output / release.ASSET).read_bytes(), b'fixture')
                self.assertEqual(len(tools.call_args_list), 4)
                self.assertNotEqual(tools.call_args_list[0].args[-1], source)
                with self.assertRaises(ValueError):
                    release.prepare(source, output, root, '0.2.0', 2, self.fingerprint)
                self.assertEqual((output / release.ASSET).read_bytes(), b'fixture')

    def test_rejection_removes_staging_and_leaves_no_release(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'input.apk'; source.write_bytes(b'fixture')
            with patch.object(release, 'run_tool', side_effect=ValueError('invalid signature')):
                with self.assertRaises(ValueError):
                    release.prepare(source, root / 'release', root, '0.2.0', 2, self.fingerprint)
            self.assertEqual(list(root.iterdir()), [source])

    def test_rejects_test_only_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / 'input.apk'; source.write_bytes(b'fixture')
            def tool(tool, *args):
                if tool.name == 'aapt2' and args[1] == 'xmltree':
                    return 'A: android:testOnly(0x01010272)=(type 0x12)0xffffffff'
                return self.tool(tool, *args)
            with patch.object(release, 'run_tool', side_effect=tool):
                with self.assertRaises(ValueError):
                    release.prepare(source, root / 'release', root, '0.2.0', 2, self.fingerprint)
            self.assertFalse((root / 'release').exists())


if __name__ == '__main__':
    unittest.main()
