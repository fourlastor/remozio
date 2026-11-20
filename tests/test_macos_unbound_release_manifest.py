import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('unbound_release_manifest', ROOT / 'scripts/generate-macos-release-manifest.py')
MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST)


class UnboundReleaseManifestTests(unittest.TestCase):
    def test_unbound_formats_belong_only_to_authority_and_setup(self):
        for role, *_ in MANIFEST.COMPONENTS:
            declarations = {value[0]: value for value in MANIFEST.declarations(role)}
            for name in ('authority.maintenance-unbound-release', 'authority.maintenance-unbound-gate'):
                if role in (2, 8):
                    self.assertEqual(declarations[name], {0: name, 1: [1], 2: [1], 3: {}})
                else:
                    self.assertNotIn(name, declarations)

    def test_record_three_keeps_writer_two_disabled_and_declares_only_setup_writer_three(self):
        for role in (2, 8):
            row = next(value for value in MANIFEST.declarations(role) if value[0] == 'runtime.maintenance-window-record')
            self.assertEqual(row[1], [1, 2, 3])
            self.assertEqual(row[2], [1, 3] if role == 8 else [])
            self.assertNotIn(2, row[2])

    def test_swift_unbound_names_match_the_manifest(self):
        source = (ROOT / 'macos/core/Sources/RemozioCore/AuthorityMaintenanceUnboundMessage.swift').read_text()
        for name in ('authority.maintenance-unbound-release', 'authority.maintenance-unbound-gate'):
            self.assertIn('= "' + name + '"', source)
            for role in (2, 8):
                self.assertIn(name, {entry[0] for entry in MANIFEST.declarations(role)})
