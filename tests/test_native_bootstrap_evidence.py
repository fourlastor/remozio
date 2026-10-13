import copy
from datetime import datetime, timedelta, timezone
import hashlib
import plistlib
from types import SimpleNamespace
from unittest.mock import patch
import importlib.util
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('bootstrap_experiment', ROOT / 'scripts/run-native-bootstrap-file-experiment.py')
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class NativeBootstrapEvidenceTests(unittest.TestCase):
    def report(self):
        rows = []
        for index, name in enumerate(('replace-existing-file', 'replace-missing-file', 'replace-existing-directory', 'replace-missing-directory')):
            mode = (0o600, 0o640, 0o700, 0o750)[index]
            rows.append({'case': name, 'operationReturnedSuccess': True, 'replacementBytesPresent': True,
                         'sourceRemains': False, 'returnedDestination': True,
                         'before': {'mode': mode} if index in (0, 2) else None,
                         'after': {'ownerUID': os.getuid(), 'mode': mode, 'directory': index >= 2}})
        rows.append({'case': 'replace-under-missing-parent', 'operationReturnedSuccess': False,
                     'sourceRemains': True, 'after': None, 'replacementBytesPresent': False})
        return {'schemaVersion': 1, 'administratorAuthorizationRequested': False, 'privilegedFileManagerTested': False,
                'productionProtectedInstallationTested': False, 'fixtureRootRemoved': True, 'results': rows}

    def test_complete_ordinary_evidence_is_accepted(self):
        PROBE.check_report(self.report())

    def test_privileged_claims_and_unverified_cleanup_are_rejected(self):
        for field in ('administratorAuthorizationRequested', 'privilegedFileManagerTested', 'productionProtectedInstallationTested'):
            report = self.report(); report[field] = True
            with self.assertRaises(RuntimeError): PROBE.check_report(report)
        report = self.report(); report['fixtureRootRemoved'] = False
        with self.assertRaises(RuntimeError): PROBE.check_report(report)

    def test_scope_modes_and_returned_bytes_must_match(self):
        original = self.report()
        for key, value in (('ownerUID', os.getuid() + 1), ('mode', 0o666), ('directory', True)):
            report = copy.deepcopy(original); report['results'][0]['after'][key] = value
            with self.assertRaises(RuntimeError): PROBE.check_report(report)
        for key in ('operationReturnedSuccess', 'replacementBytesPresent', 'returnedDestination'):
            report = self.report(); report['results'][0][key] = False
            with self.assertRaises(RuntimeError): PROBE.check_report(report)

    def test_missing_parent_is_a_refusal_with_the_source_retained(self):
        for key, value in (('operationReturnedSuccess', True), ('sourceRemains', False), ('after', {}), ('replacementBytesPresent', True)):
            report = self.report(); report['results'][-1][key] = value
            with self.assertRaises(RuntimeError): PROBE.check_report(report)

    def test_incomplete_or_reordered_cases_cannot_claim_a_complete_probe(self):
        for rows in (self.report()['results'][:-1], list(reversed(self.report()['results']))):
            report = self.report(); report['results'] = rows
            with self.assertRaises(RuntimeError): PROBE.check_report(report)


class NativeBootstrapSigningTests(unittest.TestCase):
    team = 'ABCDEFGHIJ'
    certificate = b'disposable structural test certificate'
    identity = hashlib.sha1(certificate).hexdigest()
    now = datetime(2026, 10, 14, tzinfo=timezone.utc)

    def profile(self):
        return {'TeamIdentifier': [self.team], 'ApplicationIdentifierPrefix': [self.team], 'Platform': ['OSX'],
                'ExpirationDate': self.now + timedelta(days=1),
                'DeveloperCertificates': [self.certificate],
                'Entitlements': {PROBE.ENTITLEMENT: True,
                                 'com.apple.application-identifier': self.team + '.' + PROBE.IDENTITY,
                                 'com.apple.developer.team-identifier': self.team}}

    def test_matching_fields_produce_only_the_exact_probe_entitlements(self):
        profile = self.profile()
        profile['Entitlements']['unrelated-capability'] = True
        expected = PROBE.profile_entitlements(profile, self.identity, self.team, self.now)
        self.assertEqual(expected, self.profile()['Entitlements'])

    def test_wrong_team_platform_expiration_or_certificate_is_rejected(self):
        for key, value in (('TeamIdentifier', ['DIFFERENT1']), ('Platform', ['iOS']),
                           ('Platform', 'OSX'), ('Platform', None),
                           ('ExpirationDate', self.now), ('ExpirationDate', None),
                           ('DeveloperCertificates', [b'another test certificate'])):
            with self.subTest(key=key, value=value):
                profile = self.profile(); profile[key] = value
                with self.assertRaises(RuntimeError):
                    PROBE.profile_entitlements(profile, self.identity, self.team, self.now)

    def test_missing_entitlement_numeric_truth_and_mismatched_app_are_rejected(self):
        for key, value in ((PROBE.ENTITLEMENT, False), (PROBE.ENTITLEMENT, 1),
                           ('com.apple.application-identifier', self.team + '.another.app'),
                           ('com.apple.developer.team-identifier', 'DIFFERENT1')):
            with self.subTest(key=key, value=value):
                profile = self.profile(); profile['Entitlements'][key] = value
                with self.assertRaises(RuntimeError):
                    PROBE.profile_entitlements(profile, self.identity, self.team, self.now)
        profile = self.profile(); del profile['Entitlements'][PROBE.ENTITLEMENT]
        with self.assertRaises(RuntimeError):
            PROBE.profile_entitlements(profile, self.identity, self.team, self.now)

    def test_certificate_and_team_argument_shapes_are_strict(self):
        for identity, team in (('certificate-name', self.team), (self.identity, 'short'),
                               (self.identity, 'abcdefghij'), (self.identity, 'ABCD!FGHIJ')):
            with self.assertRaises(RuntimeError):
                PROBE.profile_entitlements(self.profile(), identity, team, self.now)

    def verify(self, values, expected=None):
        def run(*args, **kwargs):
            if args[0] == 'lipo': return SimpleNamespace(stdout='arm64', stderr='')
            if args[0] == 'xcrun': return SimpleNamespace(stdout='minos 26.0\n', stderr='')
            if '--entitlements' in args:
                return SimpleNamespace(stdout=plistlib.dumps(values).decode(), stderr='')
            return SimpleNamespace(stdout='', stderr='flags=0x10000(runtime)')
        with patch('macos_build_checks.run', side_effect=run):
            PROBE.verify_executable(Path('/disposable/probe'), PROBE.IDENTITY, expected_entitlements=expected)

    def test_default_artifacts_still_reject_privileged_entitlements(self):
        self.verify({})
        self.verify({'com.apple.application-identifier': PROBE.IDENTITY})
        with self.assertRaises(RuntimeError): self.verify({PROBE.ENTITLEMENT: True})

    def test_explicit_artifact_rejects_missing_extra_or_numeric_entitlements(self):
        expected = self.profile()['Entitlements']
        self.verify(expected, expected)
        invalid = [dict(expected, extra=True), dict(expected)]
        invalid[1][PROBE.ENTITLEMENT] = 1
        missing = dict(expected); del missing[PROBE.ENTITLEMENT]; invalid.append(missing)
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(RuntimeError): self.verify(values, expected)

    def test_app_identifier_prefix_can_differ_from_the_team(self):
        profile = self.profile()
        profile['ApplicationIdentifierPrefix'] = ['KLMNOPQRST']
        app = 'KLMNOPQRST.' + PROBE.IDENTITY
        profile['Entitlements']['com.apple.application-identifier'] = app
        actual = PROBE.profile_entitlements(profile, self.identity, self.team, self.now)
        self.assertEqual(actual['com.apple.application-identifier'], app)
        self.assertEqual(actual['com.apple.developer.team-identifier'], self.team)

    def test_absent_malformed_or_mismatched_app_prefix_metadata_is_rejected(self):
        for prefixes in (None, [], self.team, ['KLMNOPQRST'], [None], ['']):
            with self.subTest(prefixes=prefixes):
                profile = self.profile(); profile['ApplicationIdentifierPrefix'] = prefixes
                with self.assertRaises(RuntimeError):
                    PROBE.profile_entitlements(profile, self.identity, self.team, self.now)
