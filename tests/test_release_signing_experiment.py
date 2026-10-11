import importlib.util
import json
import os
import plistlib
from types import SimpleNamespace
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_signing', ROOT / 'scripts/run-macos-release-signing-experiment.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class ReleaseSigningSafetyTests(unittest.TestCase):
    def test_identity_and_trust_must_be_explicit_and_paired(self):
        for identity, team in [(None, 'ABCDEFGHIJ'), ('a' * 40, None), ('-', 'ABCDEFGHIJ'),
                               ('Spectre', 'ABCDEFGHIJ'), ('a' * 40, 'invalid')]:
            with self.assertRaises(ValueError): RUNNER.signing_options(identity, team)
        self.assertEqual(RUNNER.signing_options('a' * 40, 'ABCDEFGHIJ'), ('A' * 40, 'ABCDEFGHIJ'))
        self.assertEqual(RUNNER.signing_options(None, None), (None, None))

    def test_aliases_and_special_files_are_rejected_before_any_subprocess(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / RUNNER.APP
            app.mkdir(parents=True)
            target = root / 'outside'
            target.write_bytes(b'original')
            link = app / 'helper'
            link.symlink_to(target)
            with patch.object(RUNNER, 'ROOT', root), patch.object(RUNNER, 'run') as run:
                with self.assertRaises(ValueError): RUNNER.measure(Path('/unused'), identity='A' * 40, team='ABCDEFGHIJ')
                run.assert_not_called()
            self.assertEqual(target.read_bytes(), b'original')
            link.unlink()
            os.mkfifo(link)
            with patch.object(RUNNER, 'ROOT', root), patch.object(RUNNER, 'run') as run:
                with self.assertRaises(ValueError): RUNNER.measure(Path('/unused'))
                run.assert_not_called()

    def test_fingerprint_detects_content_and_mode_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary); child = app / 'helper'; child.write_bytes(b'one')
            before = RUNNER.fingerprint(app); child.write_bytes(b'two')
            self.assertNotEqual(before, RUNNER.fingerprint(app))
            before = RUNNER.fingerprint(app); child.chmod(0o700)
            self.assertNotEqual(before, RUNNER.fingerprint(app))

    def test_probe_failure_is_not_an_expected_rejection(self):
        for status, output, error in [(70, 'rejected\n', ''), (1, '', ''), (1, 'rejected\n', 'private diagnostic')]:
            with patch.object(RUNNER, 'run', return_value=subprocess.CompletedProcess([], status, output, error)):
                with self.assertRaises(RuntimeError): RUNNER.inspect('/probe', '/private', 'ABCDEFGHIJ', False)
        with patch.object(RUNNER, 'run', return_value=subprocess.CompletedProcess([], 1, 'rejected\n', '')):
            self.assertEqual(RUNNER.inspect('/probe', '/private', 'ABCDEFGHIJ', False), {'result': 'rejected'})

    def test_acceptance_requires_complete_public_reader_evidence(self):
        for evidence in [{}, [], {'result': 'accepted', 'components': 7, 'hashes': 6}]:
            with patch.object(RUNNER, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(evidence), '')):
                with self.assertRaises(RuntimeError): RUNNER.inspect('/probe', '/private', 'ABCDEFGHIJ', True)

    def test_tool_errors_do_not_expose_candidate_paths_or_diagnostics(self):
        with patch.object(RUNNER.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2, '', 'private diagnostic')):
            with self.assertRaises(RuntimeError) as error: RUNNER.run(['/usr/bin/codesign', '/private/candidate'])
        self.assertEqual(str(error.exception), 'codesign failed with status 2')
        with patch.object(RUNNER.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['/private/candidate'], 30)):
            with self.assertRaises(RuntimeError) as error: RUNNER.run(['/usr/bin/codesign', '/private/candidate'])
        self.assertEqual(str(error.exception), 'codesign timed out; result unknown')

    def test_signing_failure_removes_owned_copies_and_preserves_the_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); app = root / RUNNER.APP
            helper = app / 'Contents/Helpers/child'; helper.parent.mkdir(parents=True)
            helper.write_bytes(b'original helper')
            (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
                'CFBundleShortVersionString': '0.1.0', 'CFBundleVersion': '1'}))
            before = RUNNER.fingerprint(app)
            owned = []; signed = []
            make_temporary = tempfile.TemporaryDirectory
            def directory(*arguments, **kwargs):
                result = make_temporary(*arguments, dir=root, **kwargs)
                owned.append(Path(result.name).resolve()); return result
            def command(arguments, **kwargs):
                if '--sign' in arguments:
                    signed.append(Path(arguments[-1]).resolve())
                    raise RuntimeError('disposable signing failure')
                return subprocess.CompletedProcess([], 0, '', 'Signature=adhoc\nTeamIdentifier=not set\n')
            manifest = SimpleNamespace(COMPONENTS=[(11, 'command-child',
                'Contents/Helpers/child', 'child', 'CommandChild')])
            with patch.object(RUNNER, 'ROOT', root), patch.object(RUNNER, 'run', side_effect=command), \
                 patch.object(RUNNER, 'inspect', return_value={'result': 'rejected'}), \
                 patch.object(RUNNER, 'load_manifest', return_value=manifest), \
                 patch.object(RUNNER.tempfile, 'TemporaryDirectory', side_effect=directory):
                with self.assertRaisesRegex(RuntimeError, 'disposable signing failure'):
                    RUNNER.measure(Path('/unused'), identity='A' * 40, team='ABCDEFGHIJ')
            self.assertEqual(len(signed), 1)
            self.assertTrue(signed[0].is_relative_to(owned[0]))
            self.assertTrue(all(not path.exists() for path in owned))
            self.assertEqual(RUNNER.fingerprint(app), before)

    def test_rejected_probe_mutation_does_not_claim_the_original_was_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); app = root / RUNNER.APP; app.mkdir(parents=True)
            helper = app / 'helper'; helper.write_bytes(b'original')
            def inspect(*arguments):
                helper.write_bytes(b'changed')
                return {'result': 'rejected'}
            display = subprocess.CompletedProcess([], 0, '', 'Signature=adhoc\nTeamIdentifier=not set\n')
            with patch.object(RUNNER, 'ROOT', root), patch.object(RUNNER, 'run', return_value=display), patch.object(RUNNER, 'inspect', side_effect=inspect):
                with self.assertRaisesRegex(RuntimeError, 'original built app changed'): RUNNER.measure(Path('/unused'))


if __name__ == '__main__': unittest.main()
