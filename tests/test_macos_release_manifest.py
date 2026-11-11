import hashlib
import importlib.util
from pathlib import Path
import plistlib
import re
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_manifest', ROOT / 'scripts/generate-macos-release-manifest.py')
MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST)


class ReleaseManifestBuildTests(unittest.TestCase):
    def setUp(self):
        self.connector_identity = patch.object(MANIFEST, 'signed_connector_identity', return_value=(bytes([9]) * 20, None)).start()
        self.addCleanup(patch.stopall)

    def environment(self, configuration='Debug'):
        return {'SRCROOT': str(ROOT / 'macos/app'), 'BUILT_PRODUCTS_DIR': '/unused-test-products',
                'CONFIGURATION': configuration, 'PRODUCT_BUNDLE_IDENTIFIER': 'dev.sebastiano.remozio.macos' + ('.debug' if configuration == 'Debug' else ''),
                'MACOSX_DEPLOYMENT_TARGET': '26.0', 'CURRENT_PROJECT_VERSION': '1', 'MARKETING_VERSION': '0.1.0'}

    def test_capacity_keeps_legacy_format_bytes_with_owned_app_ids(self):
        expected = {'Debug': '78039e1874208a355a93e2e23e0f589df82a24c8252a26e17effe945ad7df29f', 'Release': 'af15c3ca748f571e4dc49c67c7a128f26ca64132190001aeb55dc9487bd4bd01'}
        original = MANIFEST.declarations
        added = {'authority.routing-ipc', 'phone.routing-frame', 'routing.away-challenge',
                 'routing.away-control', 'routing.status-response', 'authority.audit-ipc',
                 'phone.audit-frame', 'audit.history-status', 'audit.batch', 'runtime.audit-upgrade-record',
                 'runtime.audit-upgrade-graph', 'runtime.audit-upgrade-graph-record', 'runtime.audit-upgrade-cutover-record',
                 'runtime.audit-upgrade-startup-fence', 'command.monitor-activity', 'setup.audit-upgrade-progress',
                 'authority.update-scheduling-candidate', 'authority.update-admission-registration',
                 'authority.machine-update-activation', 'authority.machine-update-replacement',
                 'authority.machine-update-completion-intent', 'authority.machine-update-policy-intent',
                 'authority.machine-update-completion-publication', 'authority.installed-release-state',
                 'authority.stable-release-state', 'authority.retained-setup-policy-intent',
                 'authority.retained-setup-completion-intent',
                 'authority.update-scheduling-ipc', 'phone.update-scheduling-frame', 'update.scheduling-control',
                 'update.scheduling-challenge', 'update.scheduling-status-response'}
        def legacy(role):
            values = [dict(value) for value in original(role) if value[0] not in added]
            for value in values:
                if value[0] == 'authority.installation-preparation':
                    value[1] = list(range(1, 12))
                    value[2] = list(range(1, 12))
                if value[0] == 'runtime.activation-plan':
                    value[1] = [1, 2]
                    value[2] = [1, 2] if role == 8 else []
                if value[0] == 'setup.local-ipc':
                    value[1] = list(range(1, 11))
                    value[2] = list(range(1, 11))
                if value[0] == 'authority.command-host-config':
                    value[1] = [1, 2, 3]
                    value[2] = [1, 2, 3]
                if value[0] == 'authority.journal':
                    value[1] = [12, 13, 14, 15, 16]
                    value[2] = [12, 13, 14, 15, 16]
            return values
        with patch.object(MANIFEST, 'declarations', side_effect=legacy), \
                patch.object(MANIFEST, 'signed_identity', return_value=(bytes([7]) * 20, None)):
            for configuration, digest in expected.items():
                info = MANIFEST.generate(self.environment(configuration))
                self.assertEqual(hashlib.sha256(info['RemozioReleaseManifest']).hexdigest(), digest)

    def test_audit_upgrade_startup_fence_declares_all_native_participants(self):
        for role, *_ in MANIFEST.COMPONENTS:
            by_name = {value[0]: value for value in MANIFEST.declarations(role)}
            name = 'runtime.audit-upgrade-startup-fence'
            if role in (2, 4, 6, 8):
                self.assertEqual(by_name[name], {0: name, 1: [1], 2: [1] if role == 8 else [], 3: {}})
            else:
                self.assertNotIn(name, by_name)

    def test_audit_upgrade_record_has_only_its_storage_readers_and_setup_writer(self):
        names = {'runtime.audit-upgrade-record', 'runtime.audit-upgrade-graph',
                 'runtime.audit-upgrade-graph-record', 'runtime.audit-upgrade-cutover-record'}
        for role, *_ in MANIFEST.COMPONENTS:
            formats = MANIFEST.declarations(role)
            by_name = {value[0]: value for value in formats}
            self.assertEqual(len(by_name), len(formats))
            for name in names:
                if role in (2, 8):
                    self.assertEqual(by_name[name],
                                     {0: name, 1: [1], 2: [1] if role == 8 else [], 3: {}})
                else:
                    self.assertNotIn(name, by_name)
            if role in (2, 8):
                preparation = by_name['authority.installation-preparation']
                self.assertEqual(preparation[1], list(range(1, 27)))
                self.assertEqual(preparation[2], list(range(1, 25)))
                self.assertEqual(preparation[3], {1: 2} if role == 2 else {})

    def test_retained_setup_policy_is_declared_read_only(self):
        name = 'authority.retained-setup-policy-intent'
        for role, *_ in MANIFEST.COMPONENTS:
            by_name = {value[0]: value for value in MANIFEST.declarations(role)}
            if role in (2, 8):
                self.assertEqual(by_name[name], {0: name, 1: [2], 2: [], 3: {}})
                preparation = by_name['authority.installation-preparation']
                self.assertIn(25, preparation[1])
                self.assertNotIn(25, preparation[2])
                self.assertNotIn(24, preparation[3])
            else:
                self.assertNotIn(name, by_name)

    def test_retained_setup_completion_is_declared_read_only(self):
        name = 'authority.retained-setup-completion-intent'
        for role, *_ in MANIFEST.COMPONENTS:
            by_name = {value[0]: value for value in MANIFEST.declarations(role)}
            if role in (2, 8):
                self.assertEqual(by_name[name], {0: name, 1: [1], 2: [], 3: {}})
                preparation = by_name['authority.installation-preparation']
                self.assertIn(26, preparation[1])
                self.assertNotIn(26, preparation[2])
                self.assertNotIn(25, preparation[3])
            else:
                self.assertNotIn(name, by_name)

    def test_update_scheduling_candidate_is_declared_only_by_the_authority_and_setup_controller(self):
        name = 'authority.update-scheduling-candidate'
        for role, *_ in MANIFEST.COMPONENTS:
            by_name = {value[0]: value for value in MANIFEST.declarations(role)}
            if role in (2, 8):
                self.assertEqual(by_name[name], {0: name, 1: [1], 2: [1], 3: {}})
            else:
                self.assertNotIn(name, by_name)

    def test_update_scheduling_declares_exact_codec_directions(self):
        bidirectional = {'authority.update-scheduling-ipc', 'phone.update-scheduling-frame'}
        names = bidirectional | {'update.scheduling-control', 'update.scheduling-challenge',
                                 'update.scheduling-status-response'}
        for role, *_ in MANIFEST.COMPONENTS:
            formats = MANIFEST.declarations(role)
            by_name = {value[0]: value for value in formats}
            self.assertEqual(len(by_name), len(formats))
            self.assertEqual(names.intersection(by_name), names if role in (2, 4) else set())
            if role in (2, 4):
                for name in names:
                    writers = [1] if role == 2 or name in bidirectional else []
                    self.assertEqual(by_name[name], {0: name, 1: [1], 2: writers, 3: {}})
            if role in (2, 8):
                self.assertIn(17, by_name['authority.journal'][1])
                self.assertIn(17, by_name['authority.journal'][2])

    def test_update_admission_registration_is_declared_only_by_the_authority_and_setup_controller(self):
        name = 'authority.update-admission-registration'
        for role, *_ in MANIFEST.COMPONENTS:
            by_name = {value[0]: value for value in MANIFEST.declarations(role)}
            if role in (2, 8):
                self.assertEqual(by_name[name], {0: name, 1: [1], 2: [1], 3: {}})
            else:
                self.assertNotIn(name, by_name)

    def test_machine_update_activation_is_declared_only_by_the_authority_and_setup_controller(self):
        name = 'authority.machine-update-activation'
        for role, *_ in MANIFEST.COMPONENTS:
            by_name = {value[0]: value for value in MANIFEST.declarations(role)}
            if role in (2, 8):
                self.assertEqual(by_name[name], {0: name, 1: [1, 2, 3, 4], 2: [1, 2, 3, 4], 3: {}})
            else:
                self.assertNotIn(name, by_name)

    def test_machine_update_replacement_is_declared_only_by_the_authority_and_setup_controller(self):
        name = 'authority.machine-update-replacement'
        for role, *_ in MANIFEST.COMPONENTS:
            by_name = {value[0]: value for value in MANIFEST.declarations(role)}
            if role in (2, 8):
                self.assertEqual(by_name[name], {0: name, 1: [1], 2: [1], 3: {}})
            else:
                self.assertNotIn(name, by_name)

    def test_generated_manifests_retain_the_audit_record_within_the_existing_bounds(self):
        names = {'runtime.audit-upgrade-record', 'runtime.audit-upgrade-graph',
                 'runtime.audit-upgrade-graph-record', 'runtime.audit-upgrade-cutover-record'}
        for configuration in ('Debug', 'Release'):
            with self.subTest(configuration=configuration), \
                    patch.object(MANIFEST, 'signed_identity', return_value=(bytes([7]) * 20, None)), \
                    patch.object(MANIFEST, 'encode', wraps=MANIFEST.encode) as encode:
                info = MANIFEST.generate(self.environment(configuration))
            root = encode.call_args_list[0].args[0]
            self.assertEqual(root[0], 4)
            for component in root[5]:
                formats = {value[0]: value for value in component[7]}
                self.assertLessEqual(len(formats), 64)
                self.assertEqual(names.intersection(formats), names if component[0] in (2, 8) else set())
                if component[0] in (2, 8):
                    self.assertIn(12, formats['authority.installation-preparation'][1])
                    self.assertIn(13, formats['authority.installation-preparation'][1])
                    self.assertIn(14, formats['authority.installation-preparation'][1])
                    self.assertIn(15, formats['authority.installation-preparation'][1])
                    self.assertIn(16, formats['authority.installation-preparation'][1])
                    self.assertIn(17, formats['authority.installation-preparation'][1])
                    self.assertIn(18, formats['authority.installation-preparation'][1])
                    self.assertIn(19, formats['authority.installation-preparation'][1])
                    self.assertIn(20, formats['authority.installation-preparation'][1])
                    self.assertIn(21, formats['authority.installation-preparation'][1])
                    self.assertIn(22, formats['authority.installation-preparation'][1])
                    self.assertIn(23, formats['authority.installation-preparation'][1])
                    self.assertIn(24, formats['authority.installation-preparation'][1])
                    for name in ('authority.installed-release-state', 'authority.machine-update-completion-publication'):
                        self.assertEqual(formats[name], {0: name, 1: [1, 2], 2: [1, 2], 3: {}})
                    for name in ('authority.machine-update-completion-intent', 'authority.machine-update-policy-intent'):
                        self.assertEqual(formats[name], {0: name, 1: [1], 2: [1], 3: {}})
                for request in component[8]:
                    self.assertEqual(request[5], [])
            self.assertLessEqual(len(info['RemozioReleaseManifest']), 65536)

    def test_command_monitor_activity_has_only_the_authority_and_monitor_directions(self):
        for role, *_ in MANIFEST.COMPONENTS:
            formats = MANIFEST.declarations(role)
            by_name = {value[0]: value for value in formats}
            self.assertEqual(len(by_name), len(formats))
            if role in (2, 12):
                self.assertEqual(by_name['command.monitor-activity'],
                                 {0: 'command.monitor-activity', 1: [1], 2: [1] if role == 2 else [], 3: {}})
            else:
                self.assertNotIn('command.monitor-activity', by_name)

    def test_manifest_component_ids_match_each_xcode_configuration(self):
        project = (ROOT / 'macos/app/Remozio.xcodeproj/project.pbxproj').read_text()
        for configuration in ('Debug', 'Release'):
            expected = set()
            for line in project.splitlines():
                if f'name = {configuration}; buildSettings' in line:
                    match = re.search(r'PRODUCT_BUNDLE_IDENTIFIER = ([^;]+);', line)
                    if match:
                        expected.add(match.group(1))
            with patch.object(MANIFEST, 'signed_identity', return_value=(bytes([7]) * 20, None)), \
                    patch.object(MANIFEST, 'encode', wraps=MANIFEST.encode) as encode:
                MANIFEST.generate(self.environment(configuration))
            manifest = encode.call_args_list[0].args[0]
            self.assertEqual({component[1] for component in manifest[5]}, expected)
            self.assertEqual(len(expected), 8)
            self.assertTrue(all(value.startswith('dev.sebastiano.remozio.macos') for value in expected))

    def test_extended_capacity_selects_schema_and_keeps_explicit_request_features(self):
        for count, version in [(32, 2), (33, 4), (64, 4), (65, 5), (128, 5)]:
            def declarations(role):
                # Only this component controls the capacity boundary in this fixture.
                return [MANIFEST.format_declaration(f'capacity.{index}', [1])
                        for index in range(count)] if role == 2 else []
            with patch.object(MANIFEST, 'declarations', side_effect=declarations), \
                    patch.object(MANIFEST, 'signed_identity', return_value=(bytes([7]) * 20, None)), \
                    patch.object(MANIFEST, 'encode', wraps=MANIFEST.encode) as encode:
                MANIFEST.generate(self.environment())
            root = encode.call_args_list[0].args[0]
            self.assertEqual(root[0], version)
            for component in root[5]:
                self.assertEqual(len(component[7]), count if component[0] == 2 else 0)
                for request in component[8]:
                    if version >= 3:
                        self.assertEqual(request[5], [])
                    else:
                        self.assertNotIn(5, request)

    def test_capacity_refuses_oversized_components_and_global_item_budget(self):
        original = MANIFEST.declarations
        for count, error in [(129, 'too many component formats'), (128, 'item or depth limit')]:
            with patch.object(MANIFEST, 'declarations', side_effect=lambda role: [
                    MANIFEST.format_declaration(f'capacity.{index}', [1]) for index in range(count)]), \
                    patch.object(MANIFEST, 'signed_identity', return_value=(bytes([7]) * 20, None)):
                with self.assertRaisesRegex(ValueError, error):
                    MANIFEST.generate(self.environment())
        self.assertLessEqual(max(len(original(role)) for role, *_ in MANIFEST.COMPONENTS), 64)

    def test_capacity_keeps_the_global_byte_budget(self):
        original = MANIFEST.declarations
        def declarations(role):
            if role not in (2, 4, 8):
                return original(role)
            return [MANIFEST.format_declaration(f'capacity.{index}.' + 'x' * 230, [1]) for index in range(128)]
        with patch.object(MANIFEST, 'declarations', side_effect=declarations), \
                patch.object(MANIFEST, 'signed_identity', return_value=(bytes([7]) * 20, None)):
            with self.assertRaisesRegex(ValueError, 'manifest exceeds size limit'):
                MANIFEST.generate(self.environment())

    def test_connector_is_verified_and_declared_as_a_transport_tool(self):
        with patch.object(MANIFEST, 'signed_identity', return_value=(bytes([7]) * 20, None)), patch.object(MANIFEST, 'encode', wraps=MANIFEST.encode) as encode:
            MANIFEST.generate(self.environment())
        declaration = encode.call_args_list[0].args[0]
        self.assertEqual(declaration[0], 4)
        self.assertEqual(declaration[6], [{0: 4, 1: 4, 2: 'Contents/Helpers/RemozioCloudflared',
            3: 'Contents/Helpers/RemozioCloudflared', 4: 'dev.sebastiano.remozio.macos.cloudflared.debug',
            5: bytes([9]) * 20, 6: None, 7: None, 8: []}])
        self.assertEqual(len(declaration[5]), 8)
        self.connector_identity.assert_called_once_with(Path('/unused-test-products/RemozioCloudflared'), 'dev.sebastiano.remozio.macos.cloudflared.debug')

    def test_missing_or_differently_signed_connector_cannot_produce_app_metadata(self):
        with patch.object(MANIFEST, 'signed_identity', return_value=(bytes([7]) * 20, None)):
            self.connector_identity.side_effect = ValueError('missing verified connector')
            with self.assertRaisesRegex(ValueError, 'missing verified connector'): MANIFEST.generate(self.environment())
            self.connector_identity.side_effect = None
            self.connector_identity.return_value = (bytes([9]) * 20, 'ABCDEFGHIJ')
            with self.assertRaisesRegex(ValueError, 'Team IDs differ'): MANIFEST.generate(self.environment())

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
        metadata = 'Identifier=dev.sebastiano.remozio.macos.command-child\nCDHash=' + 'a' * 40 + '\nTeamIdentifier=ABCDEFGHIJ\nflags=0x10000(runtime)\n'
        with patch.object(MANIFEST.subprocess, 'run', side_effect=[
            subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, '', metadata)]) as run:
            digest, team = MANIFEST.signed_identity(Path('/unused-fixture'), 'dev.sebastiano.remozio.macos.command-child', '1')
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
        self.assertEqual(by_role[4]['transport.pairing-config'][1], [1, 2])
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
        self.assertEqual(declarations['authority.command-host-config'][1], [1, 2, 3, 4])
        self.assertEqual(declarations['authority.installation-preparation'],
                         {0: 'authority.installation-preparation', 1: list(range(1, 27)), 2: list(range(1, 25)), 3: {1: 2}})
        self.assertEqual(declarations['authority.installation-inventory'], {0: 'authority.installation-inventory', 1: [1, 2], 2: [1, 2], 3: {1: 2}})
        self.assertEqual(declarations['authority.journal'][1], [12, 13, 14, 15, 16, 17])
        self.assertEqual(declarations['authority.journal'][3], {v: 12 for v in range(1, 12)})
        self.assertEqual(MANIFEST.declarations(12)[-1][1], [2])

    def test_account_enrollment_advertises_the_new_handshake_and_explicit_storage_upgrade(self):
        by_role = {role: {item[0]: item for item in MANIFEST.declarations(role)} for role, *_ in MANIFEST.COMPONENTS}
        for role in (1, 8):
            self.assertEqual((by_role[role]['setup.local-ipc'][1], by_role[role]['setup.local-ipc'][2]), (list(range(1, 12)), list(range(1, 12))))
        self.assertEqual(by_role[8]['authority.installation-preparation'][1], list(range(1, 27)))
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

    def test_retained_gateway_records_declare_exact_readers_and_emitters(self):
        by_role = {role: {item[0]: item for item in MANIFEST.declarations(role)}
                   for role, *_ in MANIFEST.COMPONENTS}
        role_record = 'runtime.gateway-role-extension'
        commit = 'runtime.gateway-runtime-commit'
        pair = 'runtime.gateway-runtime-pair'
        activation = 'runtime.gateway-activation-plan'
        settings = 'runtime.gateway-settings-revision'
        for role, declarations in by_role.items():
            if role in (2, 4, 6, 8):
                self.assertEqual(declarations[role_record], {0: role_record, 1: [1], 2: [1] if role == 8 else [], 3: {}})
                self.assertEqual(declarations[commit], {0: commit, 1: [1, 2], 2: [1, 2] if role == 8 else [2] if role == 2 else [], 3: {}})
                self.assertEqual(declarations[settings], {0: settings, 1: [1], 2: [1] if role in (2, 8) else [], 3: {}})
            else:
                for name in (role_record, commit, settings):
                    self.assertNotIn(name, declarations)
            for name in (pair, activation):
                if role in (2, 8):
                    self.assertEqual(declarations[name], {0: name, 1: [1], 2: [1] if role == 8 else [], 3: {}})
                else:
                    self.assertNotIn(name, declarations)

    def test_gateway_settings_control_is_declared_only_for_the_root_and_setup_roles(self):
        expected = MANIFEST.format_declaration('authority.gateway-settings-control', [1])
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = {item[0]: item for item in MANIFEST.declarations(role)}
            if role in (2, 8):
                self.assertEqual(declarations['authority.gateway-settings-control'], expected)
            else:
                self.assertNotIn('authority.gateway-settings-control', declarations)

    def test_host_codec_four_is_declared_by_both_retained_settings_participants(self):
        expected = MANIFEST.format_declaration('authority.command-host-config', [1, 2, 3, 4])
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = {item[0]: item for item in MANIFEST.declarations(role)}
            if role in (2, 8):
                self.assertEqual(declarations['authority.command-host-config'], expected)
            else:
                self.assertNotIn('authority.command-host-config', declarations)

    def test_no_component_declares_the_installed_readiness_service_yet(self):
        # Host version 4 can name the readiness service only when the Authority also declares this format.
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = {item[0] for item in MANIFEST.declarations(role)}
            self.assertNotIn('authority.installed-readiness', declarations)

    def test_companion_controls_and_fence_declare_only_the_current_participants(self):
        by_role = {role: {item[0]: item for item in MANIFEST.declarations(role)}
                   for role, *_ in MANIFEST.COMPONENTS}
        fence = 'runtime.gateway-settings-fence'
        gateway = 'gateway.gateway-settings-control'
        transport = 'transport.gateway-settings-control'
        for role, declarations in by_role.items():
            if role in (2, 4, 6, 8):
                self.assertEqual(declarations[fence], {0: fence, 1: [1, 2], 2: [1] if role == 8 else [2] if role == 2 else [], 3: {}})
            else:
                self.assertNotIn(fence, declarations)
            for name, consumer in ((gateway, 6), (transport, 4)):
                if role in (consumer, 8, 2):
                    versions = [1, 2] if role == consumer else [2] if role == 2 else [1]
                    self.assertEqual(declarations[name], {0: name, 1: versions, 2: versions, 3: {}})
                else:
                    self.assertNotIn(name, declarations)

    def test_native_host_metadata_and_nested_configs_have_explicit_codec_sets(self):
        by_role = {role: {item[0]: item for item in MANIFEST.declarations(role)}
                   for role, *_ in MANIFEST.COMPONENTS}
        host = 'runtime.gateway-settings-consumer-host'
        pairing = 'transport.pairing-config'
        gateway = 'gateway.service-config'
        for role in (2, 4, 6, 8):
            self.assertEqual(by_role[role][host], {0: host, 1: [1], 2: [1] if role == 8 else [], 3: {}})
            self.assertEqual(by_role[role][pairing], {0: pairing, 1: [1, 2], 2: [1, 2] if role in (4, 8) else [], 3: {}})
            self.assertEqual(by_role[role][gateway], {0: gateway, 1: [1, 2], 2: [1, 2] if role in (6, 8) else [], 3: {}})
        for role in (1, 5, 11, 12):
            for name in (host, pairing, gateway):
                self.assertNotIn(name, by_role[role])

    def test_runtime_activation_codec_is_declared_by_its_actual_readers_and_writer(self):
        name = 'runtime.activation-plan'
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = {item[0]: item for item in MANIFEST.declarations(role)}
            if role in (2, 8):
                versions = [1, 2, 3, 4, 5]
                self.assertEqual(declarations[name], {0: name, 1: versions, 2: versions if role == 8 else [], 3: {}})
            else:
                self.assertNotIn(name, declarations)

    def test_service_activity_records_declare_directional_public_and_private_codecs(self):
        by_role = {role: {item[0]: item for item in MANIFEST.declarations(role)}
                   for role, *_ in MANIFEST.COMPONENTS}
        reference = 'runtime.material-reference'
        activity = 'runtime.service-release-activity-reference'
        material = 'runtime.preparation-material'
        for role, declarations in by_role.items():
            for name, versions in ((reference, [1, 2, 3]), (activity, [1])):
                if role in (2, 4, 6, 8):
                    self.assertEqual(declarations[name], {0: name, 1: versions, 2: versions if role == 8 else [], 3: {}})
                else:
                    self.assertNotIn(name, declarations)
            if role in (2, 8):
                self.assertEqual(declarations[material], {0: material, 1: [1, 2, 3], 2: [1, 2, 3] if role == 8 else [], 3: {}})
            else:
                self.assertNotIn(material, declarations)

    def test_relay_reference_has_a_transport_reader_and_only_setup_has_private_material(self):
        names = ('relay.run-credential-reference', 'relay.run-credential-material')
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = {item[0]: item for item in MANIFEST.declarations(role)}
            self.assertLessEqual(len(declarations), 64)
            for name in names:
                if role == 8:
                    self.assertEqual(declarations[name], {0: name, 1: [1], 2: [1], 3: {}})
                elif role == 4 and name == 'relay.run-credential-reference':
                    self.assertEqual(declarations[name], {0: name, 1: [1], 2: [], 3: {}})
                else:
                    self.assertNotIn(name, declarations)

    def test_portable_preview_and_root_import_have_separate_codec_declarations(self):
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = {item[0]: item for item in MANIFEST.declarations(role)}
            if role == 1:
                payload = declarations['setup.portable']
                self.assertEqual(payload[1], [1, 2, 3, 4])
                self.assertEqual(payload[2], [])
                self.assertEqual(payload[3], {})
            elif role == 8:
                self.assertEqual(declarations['setup.portable'], MANIFEST.format_declaration('setup.portable', [1, 2, 3, 4]))
            else:
                self.assertNotIn('setup.portable', declarations)
            if role in (1, 8):
                self.assertIn(9, declarations['setup.local-ipc'][1])
                self.assertIn(10, declarations['setup.local-ipc'][1])

    def test_audit_upgrade_capability_eleven_keeps_every_existing_setup_version(self):
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = {item[0]: item for item in MANIFEST.declarations(role)}
            if role in (1, 8):
                self.assertEqual(declarations['setup.local-ipc'], MANIFEST.format_declaration('setup.local-ipc', list(range(1, 12))))
                self.assertEqual(declarations['setup.audit-upgrade-progress'],
                                 MANIFEST.format_declaration('setup.audit-upgrade-progress', [1]))
            else:
                self.assertNotIn('setup.local-ipc', declarations)

    def test_audit_upgrade_progress_is_local_to_the_app_and_setup_owner(self):
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = {item[0]: item for item in MANIFEST.declarations(role)}
            if role not in (1, 8):
                self.assertNotIn('setup.audit-upgrade-progress', declarations)
            self.assertLessEqual(len(declarations), 64)

    def test_import_retained_records_have_only_the_setup_owner_and_keep_the_manifest_bound(self):
        records = {'setup.shared-import-journal': [2], 'setup.shared-import-relay-plan': [1],
                   'setup.shared-import-relay-provisioning': [1], 'setup.shared-import-access-application': [1],
                   'setup.shared-import-dns': [1]}
        for role, *_ in MANIFEST.COMPONENTS:
            declared = {item[0]: item for item in MANIFEST.declarations(role)}
            for name, versions in records.items():
                if role == 8:
                    self.assertEqual(declared[name], MANIFEST.format_declaration(name, versions))
                else:
                    self.assertNotIn(name, declared)
            self.assertLessEqual(len(declared), 64)
            self.assertNotIn('setup.portable-import-operation', declared)
            self.assertNotIn('setup.portable-import-result', declared)

    def test_phone_routing_and_audit_formats_have_exact_role_directions(self):
        routing = {'authority.routing-ipc', 'phone.routing-frame', 'routing.away-challenge',
                   'routing.away-control', 'routing.status-response'}
        audit = {'authority.audit-ipc', 'phone.audit-frame', 'audit.history-status', 'audit.batch'}
        authority_writes = routing - {'routing.away-control'}
        transport_writes = {'authority.routing-ipc', 'phone.routing-frame',
                            'authority.audit-ipc', 'phone.audit-frame'}
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = MANIFEST.declarations(role)
            by_name = {value[0]: value for value in declarations}
            self.assertEqual(len(by_name), len(declarations))
            for name in routing | audit:
                if role not in (2, 4):
                    self.assertNotIn(name, by_name)
                    continue
                writes = name in (authority_writes | audit if role == 2 else transport_writes)
                self.assertEqual(by_name[name], {0: name, 1: [1], 2: [1] if writes else [], 3: {}})

    def test_phone_capabilities_use_extended_manifest_capacity_without_claiming_request_features(self):
        counts = {role: len(MANIFEST.declarations(role)) for role, *_ in MANIFEST.COMPONENTS}
        self.assertGreater(counts[2], 32)
        self.assertLessEqual(max(counts.values()), 64)
        with patch.object(MANIFEST, 'signed_identity', return_value=(bytes([7]) * 20, None)), \
                patch.object(MANIFEST, 'encode', wraps=MANIFEST.encode) as encode:
            info = MANIFEST.generate(self.environment())
        root = encode.call_args_list[0].args[0]
        self.assertEqual(root[0], 4)
        for component in root[5]:
            self.assertEqual(len(component[7]), counts[component[0]])
            for request in component[8]:
                self.assertEqual(request[5], [])
        self.assertLessEqual(len(info['RemozioReleaseManifest']), 65536)
