import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import sys

spec=importlib.util.spec_from_file_location('sparkle_sdk_fixture_guards',str(Path(__file__).resolve().parents[1]/'scripts/sparkle_sdk_fixture.py'))
fixture=importlib.util.module_from_spec(spec);sys.modules[spec.name]=fixture;spec.loader.exec_module(fixture)

class SDKFixtureGuards(unittest.TestCase):
    def setUp(self):
        original_lstat = Path.lstat
        def ordinary_owner(path, *args, **kwargs):
            metadata = original_lstat(path, *args, **kwargs)
            values = list(metadata)
            values[4] = 501
            return os.stat_result(values)
        for patcher in [patch.object(fixture.os, 'getuid', return_value=501),
                        patch.object(fixture.os, 'geteuid', return_value=501),
                        patch.object(Path, 'lstat', ordinary_owner)]:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_ordinary_fixture_context_reaches_owner_checks(self):
        with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
            root = Path(temporary).resolve()
            self.assertEqual(fixture.owned_root(root), root)
            code = root / 'code'
            code.write_bytes(b'fixture')
            self.assertEqual(fixture.owned_file(root, code), code)

    def test_foreign_root_and_file_owner_are_refused_before_lipo(self):
        with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
            root = Path(temporary).resolve()
            code = root / 'code'
            code.write_bytes(b'fixture')
            original_lstat = Path.lstat
            for foreign_path in [root, code]:
                def foreign_owner(path, *args, **kwargs):
                    metadata = original_lstat(path, *args, **kwargs)
                    values = list(metadata)
                    if path == foreign_path:
                        values[4] = 502
                    return os.stat_result(values)
                boundary = SimpleNamespace(command=Mock())
                with self.subTest(path=foreign_path), patch.object(Path, 'lstat', foreign_owner), self.assertRaises(ValueError):
                    fixture.thin_file(boundary, root, code)
                boundary.command.assert_not_called()

    def test_signing_configuration_never_selects_an_implicit_identity(self):
        for identity,team in [('', 'ABCDEFGHIJ'), ('certificate name', 'ABCDEFGHIJ'), ('0'*40,'wrong-team'), ('a'*40,'ABCDEFGHIJ')]:
            with self.subTest(identity=identity,team=team),self.assertRaises(ValueError):fixture.SigningConfig(identity,team)
        self.assertEqual(fixture.SigningConfig('0'*40,'ABCDEFGHIJ').team,'ABCDEFGHIJ')
    def test_root_alias_shared_mode_and_root_execution_are_refused(self):
        with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
            root=Path(temporary).resolve();alias=root/'alias';alias.symlink_to(root)
            with self.assertRaises(ValueError):fixture.owned_root(alias)
            root.chmod(0o770)
            with self.assertRaises(ValueError):fixture.owned_root(root)
            root.chmod(0o700)
            with patch.object(fixture.os,'getuid',return_value=0),self.assertRaises(ValueError):fixture.owned_root(root)
    def test_escaped_file_alias_and_hardlink_never_reach_lipo(self):
        with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
            root=Path(temporary).resolve();payload=root/'payload';payload.write_bytes(b'fixture');alias=root/'alias';alias.symlink_to(payload)
            boundary=SimpleNamespace(command=Mock())
            with self.assertRaises(ValueError):fixture.thin_file(boundary,root,alias)
            os.link(payload,root/'hardlink')
            with self.assertRaises(ValueError):fixture.thin_file(boundary,root,payload)
            boundary.command.assert_not_called()
    def test_unexpected_architecture_and_occupied_output_preserve_original(self):
        with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
            root=Path(temporary).resolve();code=root/'code';code.write_bytes(b'original')
            boundary=SimpleNamespace(command=Mock(return_value=b'x86_64\n'))
            with self.assertRaises(ValueError):fixture.thin_file(boundary,root,code)
            boundary.command.assert_called_once()
            output=root/'code.probe-thin';output.write_bytes(b'preserved')
            boundary.command=Mock(return_value=b'x86_64 arm64\n')
            with self.assertRaises(ValueError):fixture.thin_file(boundary,root,code)
            self.assertEqual(output.read_bytes(),b'preserved');self.assertEqual(code.read_bytes(),b'original')
    def test_invalid_bundle_namespace_is_refused_before_copy_or_sign(self):
        with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
            root=Path(temporary).resolve();boundary=SimpleNamespace(bundle=Mock(),command=Mock())
            signer=fixture.SDKFixtureSigner(boundary,fixture.SigningConfig('0'*40,'ABCDEFGHIJ'))
            for directory,identity in [('ExistingApplication','dev.remozio.experiment.sparkleboundary.'+'a'*32),('Host','dev.remozio.app')]:
                with self.assertRaises(ValueError):signer.bundle(root,directory,root,identity,1,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',1)
            boundary.bundle.assert_not_called();boundary.command.assert_not_called()

class SignatureGuards(unittest.TestCase):
    def test_requirement_is_inline_and_signature_metadata_still_matches(self):
        config=fixture.SigningConfig('0'*40,'ABCDEFGHIJ')
        metadata=b'Identifier=org.example.fixture\nTeamIdentifier=ABCDEFGHIJ\nCodeDirectory v=20500 flags=0x10000(runtime)\n'
        verification=SimpleNamespace(returncode=0,stderr='')
        inspection=SimpleNamespace(returncode=0,stdout=b'',stderr=metadata)
        with patch.object(fixture.subprocess,'run',side_effect=[verification,inspection]) as run:
            fixture.signature(SimpleNamespace(),Path('/owned/fixture'),'org.example.fixture',config,{})
            arguments=run.call_args_list[0].args[0]
            expression=arguments[arguments.index('-R')+1]
            self.assertTrue(expression.startswith('='))
            self.assertIn('certificate 1[field.1.2.840.113635.100.6.2.6] exists',expression)
            self.assertIn('certificate leaf[field.1.2.840.113635.100.6.1.13] exists',expression)
    def test_wrong_team_missing_runtime_and_unrequested_entitlements_are_refused(self):
        config=fixture.SigningConfig('0'*40,'ABCDEFGHIJ')
        cases=[('WRONGTEAM0','0x10000',{}),('ABCDEFGHIJ','0x0',{}),('ABCDEFGHIJ','0x10000',{'com.apple.security.get-task-allow':True})]
        for team,flags,entitlements in cases:
            metadata=f'Identifier=org.example.fixture\nTeamIdentifier={team}\nCodeDirectory v=20500 flags={flags}(runtime)\n'.encode()
            verification=SimpleNamespace(returncode=0,stderr='')
            inspection=SimpleNamespace(returncode=0,stdout=fixture.plistlib.dumps(entitlements),stderr=metadata)
            with self.subTest(team=team,flags=flags),patch.object(fixture.subprocess,'run',side_effect=[verification,inspection]),self.assertRaises(ValueError):
                fixture.signature(SimpleNamespace(),Path('/owned/fixture'),'org.example.fixture',config,{})

if __name__=='__main__':unittest.main()
