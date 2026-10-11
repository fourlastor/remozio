import base64
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'experiments/sparkle-boundary'
PRODUCTS = Path(subprocess.check_output(['swift', 'build', '--package-path', str(PACKAGE), '--show-bin-path'], text=True).strip())


class NativeBoundaryGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() == 0:
            raise unittest.SkipTest('Only ordinary-account fixtures are permitted')
        cls.temporary = tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-')
        cls.root = Path(cls.temporary.name).resolve()
        app = cls.root / 'Host/Fixture.app'
        executable = app / 'Contents/MacOS/SparkleBoundaryProbe'
        executable.parent.mkdir(parents=True)
        shutil.copy2(PRODUCTS / 'SparkleBoundaryProbe', executable)
        (app / 'Contents/Frameworks').mkdir()
        shutil.copytree((PRODUCTS / 'Sparkle.framework').resolve(), app / 'Contents/Frameworks/Sparkle.framework', symlinks=True)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': 'dev.remozio.experiment.sparkleboundary.' + uuid.uuid4().hex,
            'CFBundleName': 'Disposable Boundary Guard', 'CFBundleExecutable': 'SparkleBoundaryProbe',
            'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1'}))
        cls.executable = executable

    @classmethod
    def tearDownClass(cls):
        cls.root.chmod(0o700)
        cls.temporary.cleanup()

    def invoke(self, mode='signer', root=None, url='http://127.0.0.1:1/update.zip'):
        arguments = [str(self.executable), mode, str(root or self.root)]
        if mode == 'signer':
            arguments.append(url)
        result = subprocess.run(arguments, input=b'sign\n', capture_output=True, timeout=5)
        self.assertEqual(result.stderr, b'')
        frames = [json.loads(line) for line in result.stdout.splitlines()]
        return result.returncode, frames

    def assertRejectedBeforeKey(self, **kwargs):
        status, frames = self.invoke(**kwargs)
        self.assertEqual(status, 65)
        self.assertEqual(frames, [{'event': 'probe-failed'}])

    def tearDown(self):
        for name in ['update.zip', 'feed.xml', 'alias', 'payload']:
            path = self.root / name
            if path.exists() or path.is_symlink():
                path.unlink()
        self.root.chmod(0o700)

    def test_root_alias_and_shared_mode_are_refused_before_key_creation(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertRejectedBeforeKey(root=alias)
        self.root.chmod(0o770)
        self.assertRejectedBeforeKey()

    def test_unowned_namespace_and_nonfixture_bundle_cannot_start_an_updater(self):
        self.assertRejectedBeforeKey(root=self.root.parent)
        self.assertRejectedBeforeKey(mode='run')
        self.assertRejectedBeforeKey(mode='unknown')

    def test_nonloopback_urls_and_wrong_resource_are_refused_before_key_creation(self):
        for url in ['https://127.0.0.1:1/update.zip', 'http://192.0.2.1:1/update.zip',
                    'http://localhost:1/update.zip', 'http://127.0.0.1/update.zip',
                    'http://127.0.0.1:1/other.zip', 'http://user@127.0.0.1:1/update.zip',
                    'http://127.0.0.1:1/update.zip?token=disposable', 'http://127.0.0.1:1/update.zip#fragment']:
            with self.subTest(url=url):
                self.assertRejectedBeforeKey(url=url)

    def test_archive_alias_hardlink_and_size_bound_fail_without_signing_a_feed(self):
        payload = self.root / 'payload'; payload.write_bytes(b'disposable')
        archive = self.root / 'update.zip'
        archive.symlink_to(payload)
        for kind in ['alias', 'hardlink', 'oversize']:
            if kind == 'hardlink':
                archive.unlink(); os.link(payload, archive)
            elif kind == 'oversize':
                archive.unlink()
                with archive.open('wb') as stream:
                    stream.truncate(100_000_001)
            status, frames = self.invoke()
            self.assertEqual(status, 65)
            self.assertEqual([f['event'] for f in frames], ['public-key', 'probe-failed'])
            self.assertFalse((self.root / 'feed.xml').exists())
        self.assertEqual(payload.read_bytes(), b'disposable')

    def test_disposable_signing_writes_only_a_signed_feed_and_never_overwrites_it(self):
        (self.root / 'update.zip').write_bytes(b'disposable archive bytes')
        status, frames = self.invoke()
        self.assertEqual(status, 0)
        self.assertEqual([f['event'] for f in frames], ['public-key', 'feed-signed'])
        self.assertEqual(len(base64.b64decode(frames[0]['key'], validate=True)), 32)
        feed = (self.root / 'feed.xml').read_bytes()
        self.assertIn(b'<!-- sparkle-signatures:', feed)
        self.assertIn(b'sparkle:edSignature=', feed)
        status, frames = self.invoke()
        self.assertEqual(status, 65)
        self.assertEqual([f['event'] for f in frames], ['public-key', 'probe-failed'])
        self.assertEqual((self.root / 'feed.xml').read_bytes(), feed)


if __name__ == '__main__':
    unittest.main()
