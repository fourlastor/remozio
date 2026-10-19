import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('ci_build_cache', Path(__file__).resolve().parents[1] / 'scripts/ci-build-cache.py')
CACHE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE)


class BuildCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        self.source = self.root / 'source with spaces.swift'
        self.source.write_text('print(1)\n')
        self.track(self.source)
        os.utime(self.source, ns=(1_700_000_000_123456789,) * 2)

    def track(self, path):
        subprocess.run(['git', '-C', str(self.root), 'add', '--', str(path)], check=True)

    def operation(self, operation, scope='interop'):
        with patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': ''}), contextlib.redirect_stdout(io.StringIO()):
            return CACHE.run(argparse.Namespace(operation=operation, scope=scope, github_output=None), root=self.root)

    def key(self):
        with patch.object(CACHE, 'compatibility', return_value={'toolchain': 'fixture', 'scope': 'interop'}):
            return self.operation('key')

    def output(self):
        output = self.root / 'experiments/approval-flow/.build/object.o'
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(b'cached output')
        return output

    def test_unchanged_checkout_restores_exact_nanoseconds(self):
        captured = CACHE.capture_inputs(self.root)
        os.utime(self.source, ns=(1_800_000_000_987654321,) * 2)
        result = CACHE.restore_inputs(self.root, captured)
        self.assertEqual(self.source.stat().st_mtime_ns, 1_700_000_000_123456789)
        self.assertEqual(result['restored'], 1)
        self.assertFalse(result['requires_clean_build'])

    def test_same_size_changed_bytes_are_never_backdated(self):
        captured = CACHE.capture_inputs(self.root)
        self.source.write_text('print(2)\n')
        os.utime(self.source, ns=(1_800_000_000_987654321,) * 2)
        result = CACHE.restore_inputs(self.root, captured)
        self.assertEqual(self.source.stat().st_mtime_ns, 1_800_000_000_987654321)
        self.assertEqual(result['changed'], 1)
        self.assertEqual(result['restored'], 0)
        self.assertFalse(result['requires_clean_build'])

    def test_changed_bytes_at_old_timestamp_invalidate_outputs(self):
        self.key()
        output = self.output()
        self.operation('save')
        old_time = self.source.stat().st_mtime_ns
        self.source.write_text('print(2)\n')
        os.utime(self.source, ns=(old_time,) * 2)
        result = self.operation('restore')
        self.assertTrue(result['requires_clean_build'])
        self.assertFalse(output.exists())
        self.assertEqual(self.source.read_text(), 'print(2)\n')
        self.assertEqual(self.source.stat().st_mtime_ns, old_time)

    def test_mode_change_is_not_treated_as_identical(self):
        captured = CACHE.capture_inputs(self.root)
        self.source.chmod(0o755)
        result = CACHE.restore_inputs(self.root, captured)
        self.assertEqual(result['restored'], 0)
        self.assertTrue(result['requires_clean_build'])

    def test_added_removed_and_renamed_inputs_require_discovery(self):
        for change in ('added', 'removed', 'renamed'):
            with self.subTest(change=change):
                captured = CACHE.capture_inputs(self.root)
                other = self.root / 'other.swift'
                if change == 'added':
                    other.write_text('print(3)\n')
                    self.track(other)
                elif change == 'removed':
                    other.unlink()
                else:
                    self.source.rename(other)
                    self.track(other)
                self.assertTrue(CACHE.restore_inputs(self.root, captured)['requires_clean_build'])

    def test_documentation_changes_retain_outputs_and_full_inventory(self):
        doc = self.root / 'docs/experiments/nested/report.md'
        doc.parent.mkdir(parents=True)
        for change in ('added', 'edited', 'renamed', 'removed'):
            with self.subTest(change=change):
                old_key = self.key()['key']
                output = self.output()
                self.operation('save')
                captured = CACHE.capture_inputs(self.root)
                if change == 'added':
                    doc.write_text('first report')
                    self.track(doc)
                elif change == 'edited':
                    doc.write_text('second report')
                    os.utime(doc, ns=(captured[str(doc.relative_to(self.root))]['mtime_ns'] + 1_000_000,) * 2)
                elif change == 'renamed':
                    renamed = doc.with_name('renamed.md')
                    doc.rename(renamed)
                    self.track(renamed)
                    doc = renamed
                else:
                    doc.unlink()
                # Full content keys still change, with compatible-prefix reuse.
                self.assertNotEqual(old_key, self.key()['key'])
                os.utime(self.source, ns=(1_800_000_000_987654321,) * 2)
                result = self.operation('restore')
                self.assertEqual(result['result'], 'restored')
                self.assertFalse(result['requires_clean_build'])
                self.assertEqual(result['changed'], int(change != 'removed'))
                self.assertEqual(result['missing'], int(change in ('renamed', 'removed')))
                self.assertEqual(output.read_bytes(), b'cached output')
                self.assertEqual(self.source.stat().st_mtime_ns, 1_700_000_000_123456789)
                self.assertTrue(self.operation('save')['saved_manifest'])
                manifest = json.loads((self.root / '.build/ci-cache/interop.json').read_text())
                self.assertEqual(CACHE.content_inventory(manifest['inputs']),
                                 CACHE.content_inventory(CACHE.capture_inputs(self.root)))

    def test_other_markdown_and_nonordinary_docs_still_require_discovery(self):
        cases = (
            ('README.md', 'file', 0o644),
            ('macos/core/Tests/CoreTests/Fixtures/report.md', 'file', 0o644),
            ('docs-copy/report.md', 'file', 0o644),
            ('docs/report.swift', 'file', 0o644),
            ('docs/report.json', 'file', 0o644),
            ('docs/report.md', 'symlink', None),
            ('docs/report.md', 'file', 0o755),
            ('docs/report.md', 'file', 0o4644),
        )
        for name, kind, mode in cases:
            with self.subTest(name=name, kind=kind, mode=mode):
                self.key()
                output = self.output()
                self.operation('save')
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if kind == 'symlink':
                    path.symlink_to(self.source)
                else:
                    path.write_text('input')
                    path.chmod(mode)
                self.track(path)
                result = self.operation('restore')
                self.assertTrue(result['requires_clean_build'])
                self.assertFalse(output.exists())
                path.unlink()

    def test_documentation_kind_and_mode_transitions_require_cold_build(self):
        doc = self.root / 'docs/report.md'
        doc.parent.mkdir()
        for transition in ('executable', 'symlink'):
            for reverse in (False, True):
                with self.subTest(transition=transition, reverse=reverse):
                    def create(ordinary):
                        if doc.exists() or doc.is_symlink():
                            doc.unlink()
                        if not ordinary and transition == 'symlink':
                            doc.symlink_to(self.source)
                        else:
                            doc.write_text('report')
                            doc.chmod(0o644 if ordinary else 0o755)
                    create(not reverse)
                    self.track(doc)
                    captured = CACHE.capture_inputs(self.root)
                    create(reverse)
                    old_mtime = captured['docs/report.md']['mtime_ns']
                    os.utime(doc, ns=(old_mtime + 1_000_000,) * 2, follow_symlinks=False)
                    self.assertTrue(CACHE.restore_inputs(self.root, captured)['requires_clean_build'])

    def test_documentation_does_not_hide_source_changes(self):
        doc = self.root / 'docs/report.md'
        doc.parent.mkdir()
        for source_change in ('ordinary-edit', 'timestamp-collision', 'addition'):
            with self.subTest(source_change=source_change):
                self.key()
                output = self.output()
                self.operation('save')
                captured = CACHE.capture_inputs(self.root)
                doc.write_text('report')
                self.track(doc)
                if source_change == 'addition':
                    added = self.root / 'added.swift'
                    added.write_text('print(4)')
                    self.track(added)
                else:
                    self.source.write_text('print(2)' if source_change == 'ordinary-edit' else 'print(3)')
                    old_mtime = captured['source with spaces.swift']['mtime_ns']
                    timestamp = old_mtime + 1_000_000 if source_change == 'ordinary-edit' else old_mtime
                    os.utime(self.source, ns=(timestamp,) * 2)
                result = self.operation('restore')
                self.assertEqual(result['changed'], 2)
                self.assertEqual(result['requires_clean_build'], source_change != 'ordinary-edit')
                self.assertEqual(output.exists(), source_change == 'ordinary-edit')
                if source_change != 'addition':
                    self.assertEqual(self.source.stat().st_mtime_ns, timestamp)
                doc.unlink()

    def test_documentation_timestamp_collision_still_invalidates_outputs(self):
        doc = self.root / 'docs/report.md'
        doc.parent.mkdir()
        doc.write_text('first')
        self.track(doc)
        self.key()
        output = self.output()
        self.operation('save')
        timestamp = doc.stat().st_mtime_ns
        doc.write_text('other')
        os.utime(doc, ns=(timestamp,) * 2)
        result = self.operation('restore')
        self.assertTrue(result['requires_clean_build'])
        self.assertFalse(output.exists())
        self.assertEqual(doc.read_text(), 'other')
        self.assertEqual(doc.stat().st_mtime_ns, timestamp)

    def test_documentation_mutation_during_build_prevents_cache_save(self):
        doc = self.root / 'docs/report.md'
        doc.parent.mkdir()
        doc.write_text('first')
        self.track(doc)
        self.key()
        doc.write_text('other')
        self.assertFalse(self.operation('save')['saved_manifest'])
        self.assertFalse((self.root / '.build/ci-cache/interop.json').exists())

    def test_symlink_does_not_modify_target_timestamp(self):
        target = self.root / 'outside-input.txt'
        target.write_text('private')
        timestamp = target.stat().st_mtime_ns
        link = self.root / 'link'
        link.symlink_to(target)
        self.track(link)
        captured = CACHE.capture_inputs(self.root)
        CACHE.restore_inputs(self.root, captured)
        self.assertEqual(target.stat().st_mtime_ns, timestamp)
        self.assertEqual(link.read_text(), 'private')

    def test_manifest_paths_cannot_escape_workspace(self):
        captured = CACHE.capture_inputs(self.root)
        entry = next(iter(captured.values()))
        for name in ('../outside.swift', '/tmp/outside.swift', 'x/../../outside.swift', './source.swift'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                CACHE.restore_inputs(self.root, {name: entry})

    def test_symlink_parent_cannot_redirect_restore(self):
        with tempfile.TemporaryDirectory() as outside:
            (self.root / 'redirect').symlink_to(outside, target_is_directory=True)
            entry = next(iter(CACHE.capture_inputs(self.root).values()))
            with self.assertRaises(ValueError):
                CACHE.restore_inputs(self.root, {'redirect/source.swift': entry})

    def test_invalid_manifest_discards_only_fixed_build_roots(self):
        self.key()
        output = self.output()
        unrelated = self.root / '.build/experiment-evidence.json'
        unrelated.write_text('keep')
        manifest = self.root / '.build/ci-cache/interop.json'
        manifest.parent.mkdir(parents=True, exist_ok=True)
        for contents in ('{', json.dumps({'version': 999, 'identity': 'wrong', 'inputs': {}})):
            with self.subTest(contents=contents):
                self.output()
                manifest.write_text(contents)
                result = self.operation('restore')
                self.assertEqual(result['result'], 'cold-missing-or-invalid-manifest')
                self.assertFalse(output.exists())
                self.assertEqual(unrelated.read_text(), 'keep')

    def test_input_mutation_during_build_prevents_cache_save(self):
        self.key()
        self.source.write_text('print(2)\n')
        result = self.operation('save')
        self.assertFalse(result['saved_manifest'])
        self.assertFalse((self.root / '.build/ci-cache/interop.json').exists())

    def test_configuration_changes_partition_fallback_keys(self):
        inputs = CACHE.capture_inputs(self.root)
        baseline = CACHE.digest(CACHE.settings_inventory(inputs))
        package = self.root / 'Package.resolved'
        package.write_text('{"pins": []}')
        self.track(package)
        updated = CACHE.capture_inputs(self.root)
        self.assertNotEqual(baseline, CACHE.digest(CACHE.settings_inventory(updated)))
        self.source.write_text('print(2)\n')
        self.assertEqual(CACHE.settings_inventory(updated), CACHE.settings_inventory(CACHE.capture_inputs(self.root)))


if __name__ == '__main__':
    unittest.main()
