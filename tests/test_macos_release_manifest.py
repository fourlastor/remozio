import importlib.util
from pathlib import Path
import plistlib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_manifest', ROOT / 'scripts/generate-macos-release-manifest.py')
MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST)


class ReleaseManifestBuildTests(unittest.TestCase):
    def environment(self, configuration='Debug'):
        return {'SRCROOT': str(ROOT / 'macos/app'), 'BUILT_PRODUCTS_DIR': '/unused-test-products',
                'CONFIGURATION': configuration, 'PRODUCT_BUNDLE_IDENTIFIER': 'dev.remozio.mac' + ('.debug' if configuration == 'Debug' else ''),
                'MACOSX_DEPLOYMENT_TARGET': '26.0', 'CURRENT_PROJECT_VERSION': '1', 'MARKETING_VERSION': '0.1.0'}

    def test_cbor_uses_shortest_integers_and_numeric_map_order(self):
        self.assertEqual(MANIFEST.encode({24: [24, 256], 0: None}), bytes.fromhex('a200f61818821818190100'))
        self.assertEqual(MANIFEST.encode(b'abc'), b'\x43abc')
        for value in (-1, True, 1 << 64, {'text-key': 1}):
            with self.assertRaises(ValueError):
                MANIFEST.encode(value)

    def test_helpers_are_checked_before_the_unsigned_app_input_is_created(self):
        with patch.object(MANIFEST, 'signed_identity', return_value=(bytes([7]) * 20, None)) as identity:
            info = MANIFEST.generate(self.environment())
        self.assertEqual(identity.call_count, 7)
        self.assertEqual(info['RemozioSecurityGeneration'], '1')
        self.assertIsInstance(info['RemozioReleaseManifest'], bytes)
        self.assertEqual(plistlib.loads(plistlib.dumps(info)), info)
        self.assertTrue(all(call.args[1].endswith('.debug') for call in identity.call_args_list))
        self.assertNotIn('LaunchDaemons', str(info))
        self.assertNotIn('LaunchAgents', str(info))

    def test_helper_signature_commands_have_explicit_deadlines(self):
        import subprocess
        metadata = 'Identifier=dev.remozio.command-child\nCDHash=' + 'a' * 40 + '\nTeamIdentifier=ABCDEFGHIJ\nflags=0x10000(runtime)\n'
        with patch.object(MANIFEST.subprocess, 'run', side_effect=[
            subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, '', metadata)]) as run:
            digest, team = MANIFEST.signed_identity(Path('/unused-fixture'), 'dev.remozio.command-child', '1')
        self.assertEqual(len(digest), 20); self.assertEqual(team, 'ABCDEFGHIJ')
        self.assertEqual([call.kwargs['timeout'] for call in run.call_args_list], [20, 20])

    def test_different_helper_teams_fail_before_app_signing(self):
        with patch.object(MANIFEST, 'signed_identity', side_effect=[(bytes([7]) * 20, 'ABCDEFGHIJ')] + [(bytes([7]) * 20, None)] * 6):
            with self.assertRaisesRegex(ValueError, 'Team IDs differ'):
                MANIFEST.generate(self.environment())

    def test_helper_verification_failure_is_not_replaced_by_a_stub_declaration(self):
        with patch.object(MANIFEST, 'signed_identity', side_effect=ValueError('invalid signature')):
            with self.assertRaisesRegex(ValueError, 'invalid signature'):
                MANIFEST.generate(self.environment())

    def test_unexpected_baseline_or_identity_is_rejected(self):
        for key, value in (('PRODUCT_BUNDLE_IDENTIFIER', 'other.app'), ('MACOSX_DEPLOYMENT_TARGET', '25.0')):
            environment = self.environment(); environment[key] = value
            with self.assertRaises(ValueError):
                MANIFEST.generate(environment)

    def test_pairing_formats_are_declared_only_by_the_roles_that_handle_them(self):
        by_role = {role: {item[0]: item for item in MANIFEST.declarations(role)} for role, *_ in MANIFEST.COMPONENTS}
        self.assertEqual((by_role[2]['authority.presence-config'][1], by_role[2]['authority.presence-config'][2]), ([1, 2], [1, 2]))
        for role in (1, 2, 4):
            self.assertEqual(by_role[role]['pairing.transcript'], MANIFEST.format_declaration('pairing.transcript', [1]))
        for role in (1, 4):
            self.assertEqual(by_role[role]['transport.pairing-control-config'][1], [1])
            self.assertEqual(by_role[role]['transport.pairing-control'][1], [1])
        self.assertEqual(by_role[4]['transport.pairing-config'][1], [1])
        self.assertEqual(by_role[4]['pairing.setup-frame'][1], [1])
        self.assertNotIn('pairing.setup-frame', by_role[1])
        self.assertNotIn('pairing.setup-frame', by_role[2])
        for role in (5, 6, 8, 11, 12):
            self.assertNotIn('pairing.transcript', by_role[role])
        self.assertTrue(all(item[3] == {} for values in by_role.values() for name, item in values.items() if 'pairing' in name))

    def test_sets_are_explicit_and_storage_migrations_do_not_claim_activation(self):
        roles = {component[0] for component in MANIFEST.COMPONENTS}
        self.assertEqual(roles, {1, 2, 4, 5, 6, 8, 11, 12})
        declarations = {item[0]: item for item in MANIFEST.declarations(2)}
        self.assertEqual(declarations['authority.command-config'][1], [1, 2])
        self.assertEqual(declarations['authority.command-host-config'][1], [1, 2])
        self.assertEqual(declarations['authority.installation-preparation'], {0: 'authority.installation-preparation', 1: [1, 2, 3, 4, 5, 6, 7, 8, 9], 2: [1, 2, 3, 4, 5, 6, 7, 8, 9], 3: {1: 2}})
        self.assertEqual(declarations['authority.installation-inventory'], {0: 'authority.installation-inventory', 1: [1, 2], 2: [1, 2], 3: {1: 2}})
        self.assertEqual(declarations['authority.journal'][1], [12, 13, 14, 15, 16])
        self.assertEqual(declarations['authority.journal'][3], {v: 12 for v in range(1, 12)})
        self.assertEqual(MANIFEST.declarations(12)[-1][1], [2])

    def test_account_enrollment_advertises_the_new_handshake_and_explicit_storage_upgrade(self):
        by_role = {role: {item[0]: item for item in MANIFEST.declarations(role)} for role, *_ in MANIFEST.COMPONENTS}
        for role in (1, 8):
            self.assertEqual((by_role[role]['setup.local-ipc'][1], by_role[role]['setup.local-ipc'][2]), ([1, 2, 3, 4, 5, 6], [1, 2, 3, 4, 5, 6]))
        self.assertEqual(by_role[8]['authority.installation-preparation'][1], [1, 2, 3, 4, 5, 6, 7, 8, 9])
        self.assertEqual(by_role[8]['authority.installation-preparation'][3], {})
        for role in (4, 5, 6, 11, 12):
            self.assertNotIn('authority.installation-preparation', by_role[role])
            self.assertNotIn('setup.local-ipc', by_role[role])

    def test_inventory_formats_are_declared_only_by_their_storage_readers(self):
        expected = {0: 'authority.installation-inventory', 1: [1, 2], 2: [1, 2], 3: {1: 2}}
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = {item[0]: item for item in MANIFEST.declarations(role)}
            if role in (2, 8):
                self.assertEqual(declarations['authority.installation-inventory'], expected)
            else:
                self.assertNotIn('authority.installation-inventory', declarations)
