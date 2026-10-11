import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('boundary', str(Path(__file__).resolve().parents[1]/'scripts/run-sparkle-boundary-experiment.py'))
boundary = importlib.util.module_from_spec(spec); spec.loader.exec_module(boundary)

class RunnerGuards(unittest.TestCase):
    def test_fixture_tree_rejects_outside_alias_and_hardlink(self):
        with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
            root = Path(temporary).resolve(); tree = root/'app'; tree.mkdir(); leaf = tree/'file'; leaf.write_bytes(b'probe')
            boundary.validate_tree(root, tree)
            (tree/'alias').symlink_to(root)
            with self.assertRaises(AssertionError): boundary.validate_tree(root, tree)
            (tree/'alias').unlink(); os.link(leaf, tree/'hardlink')
            with self.assertRaises(AssertionError): boundary.validate_tree(root, tree)
    def test_sdk_framework_internal_alias_is_allowed_and_hashed(self):
        with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
            root = Path(temporary).resolve(); tree=root/'app'; tree.mkdir(); (tree/'file').write_bytes(b'probe'); (tree/'alias').symlink_to('file')
            boundary.validate_tree(root,tree); original=boundary.digest(tree)
            (tree/'file').write_bytes(b'changed'); self.assertNotEqual(original,boundary.digest(tree))
    def test_shared_root_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
            root=Path(temporary).resolve(); tree=root/'app'; tree.mkdir(); root.chmod(0o770)
            with self.assertRaises(AssertionError): boundary.validate_tree(root,tree)
    def test_preexisting_job_and_wrong_namespace_are_refused(self):
        with patch.object(boundary.FixtureJobs, 'inspect', return_value=b'existing'):
            with self.assertRaises(AssertionError): boundary.FixtureJobs(boundary.PREFIX+'a'*32)
        with self.assertRaises(AssertionError): boundary.FixtureJobs('production')
        with self.assertRaises(ValueError): boundary.FixtureJobs(boundary.PREFIX+'z'*32)
    def test_system_job_is_never_booted_out(self):
        with patch.object(boundary.FixtureJobs,'inspect',return_value=None): jobs=boundary.FixtureJobs(boundary.PREFIX+'a'*32)
        with patch.object(boundary.FixtureJobs,'inspect',side_effect=lambda target:b'job' if target.startswith('system/') else None), patch.object(boundary,'command') as command:
            with self.assertRaises(AssertionError): jobs.close()
            command.assert_not_called()
    def test_exact_job_absence_can_be_observed_without_services(self):
        identity=boundary.PREFIX+'a'*32
        with patch.object(boundary.FixtureJobs,'inspect',return_value=None) as inspect:
            jobs=boundary.FixtureJobs(identity); jobs.close()
            self.assertTrue(all(identity in call.args[0] for call in inspect.call_args_list))

if __name__=='__main__': unittest.main()
