import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('notarized_candidate', ROOT / 'scripts/prepare-macos-notarized-candidate.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
READER = RUNNER.load_script('run-macos-release-signing-experiment')
ID = '12345678-1234-4234-9234-123456789abc'
NAME = 'Remozio-87654321-4321-4321-8321-cba987654321.zip'
SOURCE = {'commit': 'a' * 40, 'tree': 'b' * 40, 'scripts': {'fixture': 'c' * 64}}
PROFILE = 'ABCDEFGHIJ:' + 'd' * 40 + ':' + 'e' * 64


class NotarizedCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name) / 'candidate'
        self.folder.mkdir(mode=0o700)
        app = self.folder / 'Remozio.app'
        (app / 'Contents').mkdir(parents=True)
        (app / 'Contents/helper').write_bytes(b'signed fixture')
        archive = self.folder / NAME; archive.write_bytes(b'fixed archive'); archive.chmod(0o600)
        self.value = {'schemaVersion': 1, 'source': SOURCE, 'phase': 'prepared', 'archiveName': NAME,
            'archiveSHA256': RUNNER.sha256(archive), 'appFingerprint': READER.fingerprint(app),
            'trustedTeamID': 'ABCDEFGHIJ', 'releaseInspection': {'packageProfile': PROFILE},
            'installed': False, 'servicesRegistered': False, 'packageSigned': False,
            'appNotarizationVerified': False}
        self.write()
        self.source = patch.object(RUNNER, 'source_identity', return_value=SOURCE)
        self.source.start(); self.addCleanup(self.source.stop)

    def write(self):
        RUNNER.save(self.folder, self.value)

    def read(self):
        return json.loads((self.folder / 'journal.json').read_text())

    def result(self, status='Accepted', identity=ID, name=NAME):
        return subprocess.CompletedProcess([], 0, json.dumps({'id': identity, 'status': status, 'name': name}), '')

    def accepted(self):
        self.value.update(phase='accepted', submissionID=ID, lastStatus='Accepted'); self.write()

    def test_prepare_copies_a_verified_candidate_and_keeps_private_evidence(self):
        destination = self.folder.parent / 'fresh-workspace'
        app = self.folder / 'Remozio.app'; before = READER.fingerprint(app)
        def archive(arguments, **_):
            self.assertIn('ditto', str(arguments[0]))
            arguments[-1].write_bytes(b'new archive'); arguments[-1].chmod(0o600)
            return subprocess.CompletedProcess([], 0, '', '')
        with patch.object(RUNNER, 'native', side_effect=archive), \
             patch.object(RUNNER, 'verify_signed_app', return_value=(before, {'packageProfile': PROFILE})):
            value = RUNNER.prepare(destination, app, 'ABCDEFGHIJ')
        self.assertEqual(value['phase'], 'prepared')
        self.assertEqual(READER.fingerprint(destination / 'Remozio.app'), before)
        self.assertEqual(READER.fingerprint(app), before)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual((destination / 'journal.json').stat().st_mode & 0o777, 0o600)
        self.assertFalse(value['appNotarizationVerified'])
        with patch.object(RUNNER, 'native') as native:
            with self.assertRaises(FileExistsError): RUNNER.prepare(destination, app, 'ABCDEFGHIJ')
            native.assert_not_called()

    def test_prepare_failure_preserves_workspace_and_prevents_upload(self):
        destination = self.folder.parent / 'failed-workspace'
        with patch.object(RUNNER, 'verify_signed_app', side_effect=ValueError('missing timestamp')), \
             patch.object(RUNNER, 'native') as native:
            with self.assertRaises(ValueError): RUNNER.prepare(destination, self.folder / 'Remozio.app', 'ABCDEFGHIJ')
            native.assert_not_called()
        self.assertEqual(json.loads((destination / 'journal.json').read_text())['phase'], 'preparation-failed')
        self.assertTrue((destination / 'Remozio.app').exists())
        with patch.object(RUNNER, 'native') as native:
            with self.assertRaises((ValueError, KeyError)): RUNNER.submit(destination, 'profile')
            native.assert_not_called()

    def test_submit_records_uncertainty_before_network_and_never_retries_unknown_upload(self):
        def upload(*_args, **_kwargs):
            self.assertEqual(self.read()['phase'], 'submission-unknown')
            raise RuntimeError('upload outcome unknown')
        with patch.object(RUNNER, 'native', side_effect=upload) as native:
            with self.assertRaises(RuntimeError): RUNNER.submit(self.folder, 'local-profile')
            with self.assertRaises(ValueError): RUNNER.submit(self.folder, 'local-profile')
        self.assertEqual(native.call_count, 1)
        self.assertNotIn('submissionID', self.read())

    def test_submission_keeps_exact_id_but_requires_authenticated_info_before_finish(self):
        with patch.object(RUNNER, 'native', return_value=self.result('In Progress')) as native:
            value = RUNNER.submit(self.folder, 'local-profile')
        self.assertEqual(value['phase'], 'submitted')
        self.assertEqual(value['submissionID'], ID)
        self.assertIn('--no-wait', native.call_args.args[0])
        self.assertNotIn('local-profile', (self.folder / 'journal.json').read_text())
        with self.assertRaises(ValueError): RUNNER.finish(self.folder)

    def test_nowait_upload_receipt_preserves_id_without_inventing_a_processing_status(self):
        receipt = subprocess.CompletedProcess([], 0, json.dumps({
            'id': ID, 'message': 'Successfully uploaded file', 'path': '/private/candidate.zip'}), '')
        with patch.object(RUNNER, 'native', return_value=receipt):
            value = RUNNER.submit(self.folder, 'local-profile')
        self.assertEqual(value['submissionID'], ID)
        self.assertEqual(value['phase'], 'submitted')
        self.assertEqual(value['lastStatus'], 'Unknown')
        self.assertNotIn('/private/candidate.zip', (self.folder / 'journal.json').read_text())
        with self.assertRaises(ValueError): RUNNER.finish(self.folder)
        with patch.object(RUNNER, 'native', return_value=self.result()):
            self.assertEqual(RUNNER.status(self.folder, 'local-profile')['phase'], 'accepted')

    def test_authenticated_reconciliation_can_recover_a_lost_submission_response(self):
        self.value['phase'] = 'submission-unknown'; self.write()
        with patch.object(RUNNER, 'native', return_value=self.result()):
            value = RUNNER.status(self.folder, 'local-profile', ID)
        self.assertEqual(value['phase'], 'accepted')
        self.assertEqual(value['submissionID'], ID)

    def test_info_must_match_id_and_unique_archive_name(self):
        self.value.update(phase='submitted', submissionID=ID); self.write()
        for response in [self.result(name='another.zip'), self.result(identity='00000000-0000-4000-8000-000000000000'),
                         subprocess.CompletedProcess([], 0, 'not json', ''), self.result('unexpected')]:
            with patch.object(RUNNER, 'native', return_value=response):
                with self.assertRaises((ValueError, RuntimeError)): RUNNER.status(self.folder, 'local-profile')
        self.assertEqual(self.read()['phase'], 'submitted')
        with patch.object(RUNNER, 'native') as native:
            with self.assertRaises(ValueError): RUNNER.status(self.folder, 'local-profile', '00000000-0000-4000-8000-000000000000')
            native.assert_not_called()

    def test_rejected_and_pending_submissions_cannot_finish(self):
        for status, phase in [('In Progress', 'in-progress'), ('Invalid', 'rejected'), ('Rejected', 'rejected')]:
            self.value.update(phase='submitted', submissionID=ID); self.write()
            with patch.object(RUNNER, 'native', return_value=self.result(status)):
                self.assertEqual(RUNNER.status(self.folder, 'local-profile')['phase'], phase)
            with self.assertRaises(ValueError): RUNNER.finish(self.folder)

    def test_changed_archive_or_source_stops_before_network(self):
        archive = self.folder / NAME; archive.write_bytes(b'changed')
        with patch.object(RUNNER, 'native') as native:
            with self.assertRaises(ValueError): RUNNER.submit(self.folder, 'profile')
            native.assert_not_called()
        archive.write_bytes(b'fixed archive')
        with patch.object(RUNNER, 'source_identity', return_value={**SOURCE, 'commit': 'f' * 40}), \
             patch.object(RUNNER, 'native') as native:
            with self.assertRaises(ValueError): RUNNER.submit(self.folder, 'profile')
            native.assert_not_called()

    def test_exclusive_writer_and_private_workspace_are_required(self):
        with RUNNER.workspace(self.folder):
            with self.assertRaises(BlockingIOError):
                with RUNNER.workspace(self.folder): self.fail('second writer acquired')
        self.folder.chmod(0o755)
        with self.assertRaises(ValueError):
            with RUNNER.workspace(self.folder): self.fail('public workspace accepted')

    def test_alias_and_hard_link_journals_are_refused(self):
        journal = self.folder / 'journal.json'
        outside = self.folder.parent / 'outside'; journal.rename(outside); journal.symlink_to(outside)
        with self.assertRaises(ValueError): RUNNER.submit(self.folder, 'profile')
        journal.unlink(); os.link(outside, journal)
        with self.assertRaises(ValueError): RUNNER.submit(self.folder, 'profile')

    def test_timestamp_and_runtime_are_required_for_every_role(self):
        app = self.folder / 'Remozio.app'
        valid = 'CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1\nTeamIdentifier=ABCDEFGHIJ\nTimestamp=Oct 16, 2026\n'
        paths = [app] + [app / relative for role, _, relative, *_ in READER.load_manifest().COMPONENTS if role != 1]
        for bad in [valid.replace('Timestamp=Oct 16, 2026', 'Timestamp=none'), valid.replace('Timestamp=', 'Signed Time='), valid.replace('(runtime)', '(none)'),
                    valid.replace('ABCDEFGHIJ', 'BBBBBBBBBB')]:
            for target in paths:
                def native(arguments, **_):
                    text = bad if '--display' in arguments and arguments[-1] == target else valid
                    return subprocess.CompletedProcess([], 0, '', text)
                with patch.object(RUNNER, 'native', side_effect=native):
                    with self.assertRaises(ValueError): RUNNER.verify_signed_app(app, 'ABCDEFGHIJ')

    def finish_fixture(self, *, invalid_ticket=False, corrupt_round_trip=False, fail=None):
        self.accepted(); calls = []
        def native(arguments, **kwargs):
            calls.append((arguments, kwargs))
            if fail and fail in arguments: raise RuntimeError('disposable failure')
            if 'staple' in arguments:
                ticket = arguments[-1] / 'Contents/CodeResources'
                ticket.write_bytes(b'notary ticket'); ticket.chmod(0o600 if invalid_ticket else 0o644)
            if '--expand-full' in arguments:
                extracted = arguments[-1] / 'payload.pkg/Payload/Remozio.app'
                shutil.copytree(self.folder / 'Remozio-notarized.app', extracted)
                if corrupt_round_trip: (extracted / 'Contents/helper').write_bytes(b'changed')
            return subprocess.CompletedProcess([], 0, '', '')
        def build(app, output, _team, **kwargs):
            self.assertEqual(kwargs, {'unsigned_developer': True})
            output.write_bytes(b'verified package')
            return {'appFingerprint': READER.fingerprint(app), 'packageProfile': PROFILE}
        def loader(name): return READER if name.startswith('run-') else SimpleNamespace(build=build)
        with patch.object(RUNNER, 'native', side_effect=native), patch.object(RUNNER, 'load_script', side_effect=loader), \
             patch.object(RUNNER, 'verify_signed_app', side_effect=lambda app, _team: (READER.fingerprint(app), {'packageProfile': PROFILE})):
            value = RUNNER.finish(self.folder)
        return value, calls

    def test_complete_round_trip_preserves_submitted_app_and_scopes_stapler_umask(self):
        before = self.value['appFingerprint']
        value, calls = self.finish_fixture()
        self.assertEqual(value['phase'], 'complete')
        self.assertTrue(value['appNotarizationVerified'])
        self.assertTrue(value['packageRoundTripVerified'])
        self.assertFalse(value['packageSigned'])
        self.assertFalse(value['installed'])
        self.assertFalse(value['servicesRegistered'])
        self.assertEqual(READER.fingerprint(self.folder / 'Remozio.app'), before)
        self.assertEqual([kwargs['umask'] for args, kwargs in calls if 'staple' in args], [0o022])
        self.assertEqual((self.folder / 'journal.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(len([args for args, _ in calls if 'validate' in args]), 2)
        self.assertEqual(len([args for args, _ in calls if '--assess' in args]), 2)

    def test_ticket_failure_or_package_mutation_never_claims_completion(self):
        for option in ['invalid_ticket', 'corrupt_round_trip']:
            with self.subTest(option=option):
                if (self.folder / 'Remozio-notarized.app').exists(): shutil.rmtree(self.folder / 'Remozio-notarized.app')
                expanded = self.folder / 'expanded-package'
                if expanded.exists(): shutil.rmtree(expanded)
                with self.assertRaises((ValueError, RuntimeError)): self.finish_fixture(**{option: True})
                self.assertEqual(self.read()['phase'], 'finishing-unknown')
                self.assertFalse(self.read()['appNotarizationVerified'])
                with patch.object(RUNNER, 'native', return_value=self.result()):
                    self.assertEqual(RUNNER.status(self.folder, 'profile')['phase'], 'finishing-unknown')
                with self.assertRaises(ValueError): RUNNER.finish(self.folder)

    def test_finish_timeout_cannot_be_reset_by_a_status_query(self):
        with self.assertRaises(RuntimeError): self.finish_fixture(fail='staple')
        self.assertEqual(self.read()['phase'], 'finishing-unknown')
        with patch.object(RUNNER, 'native', return_value=self.result()): RUNNER.status(self.folder, 'profile')
        with self.assertRaises(ValueError): RUNNER.finish(self.folder)

    def test_native_failure_never_exposes_account_diagnostics(self):
        for effect in [subprocess.CompletedProcess([], 1, '', 'private account diagnostic'),
                       subprocess.TimeoutExpired(['/private/candidate'], 120)]:
            with patch.object(RUNNER.subprocess, 'run', side_effect=effect if isinstance(effect, Exception) else None,
                              return_value=effect):
                with self.assertRaises(RuntimeError) as error: RUNNER.native(['/usr/bin/xcrun', 'notarytool'])
            self.assertNotIn('private', str(error.exception))


if __name__ == '__main__': unittest.main()
