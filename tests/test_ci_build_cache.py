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
