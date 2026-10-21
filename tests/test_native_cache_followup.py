import importlib.util
import json
import os
from pathlib import Path
import signal
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock


PATH = Path(__file__).resolve().parents[1] / 'scripts/check-native-cache-followup.py'
SPEC = importlib.util.spec_from_file_location('native_cache_followup_under_test', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class NativeCacheFollowupTests(unittest.TestCase):
    def fixture(self, temporary):
        root = Path(temporary).resolve() / 'checkout with spaces\nand newline'
        root.mkdir()
        runner = root / MODULE.LINUX_INPUT
        runner.parent.mkdir()
        runner.write_bytes(b'#!/usr/bin/env python3\nprint("fixture")\n')
        runner.chmod(0o755)
        swift = root / 'protocol/swift/example.swift'
        swift.parent.mkdir(parents=True)
        swift.write_bytes(b'let original = 1\n')
        names = [MODULE.LINUX_INPUT, 'protocol/swift/example.swift']
        inputs = MODULE.snapshot(root, names)
        context_path = root / '.build/ci-cache-context/mac.json'
        context_path.parent.mkdir(parents=True)
        original_context = json.dumps({'identity': 'same-identity', 'key': 'prefix-old', 'inputs': {}}).encode()
        context_path.write_bytes(original_context)
        for configuration in ('debug', 'release'):
            log = root / f'.build/macos-app/xcodebuild-{configuration}.log'
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text('CompileC cold\n** BUILD SUCCEEDED **\n')
        cold_key = Path(temporary) / 'cold-key.log'
        cold_key.write_text(json.dumps({'operation': 'key', 'scope': 'mac', 'key': 'prefix-old'}) + '\n')
        cold_log = Path(temporary) / 'cold-full-check.log'
        cold_log.write_text('actual previous full check fixture\n')
        args = SimpleNamespace(repo=root, output=Path(temporary) / 'evidence', cold_key_log=cold_key,
                               cold_full_check_log=cold_log, cold_full_check_seconds=4012.5)
        return args, names, inputs, original_context

    def native_platform(self):
        return patch.object(MODULE, 'platform', SimpleNamespace(system=lambda: 'Darwin', machine=lambda: 'arm64'))

    def python(self):
        return patch.object(MODULE, 'sys', SimpleNamespace(version_info=(3, 11), executable='fixture-python'))

    def worker(self, args, inputs, calls, fail=None, unstable=False, restore_cold=False):
        def command(root, output, name, argv, deadline, timeout, env=None):
            calls.append((name, argv))
            if fail == name:
                raise RuntimeError('injected worker failure')
            log = output / f'{name}.log'
            if name == 'save':
                self.assertEqual(calls[0][0], 'save')
                manifest = root / '.build/ci-cache/mac.json'
                manifest.parent.mkdir(parents=True)
                manifest.write_bytes(b'{"original":"validated cold manifest"}')
                log.write_text(json.dumps({'operation': 'save', 'saved_manifest': not unstable}) + '\n')
            elif name == 'warm-key':
                self.assertTrue(all(v.path.stat().st_mtime_ns != v.mtime_ns for v in inputs.values()))
                self.assertEqual(inputs[MODULE.LINUX_INPUT].path.read_bytes(), inputs[MODULE.LINUX_INPUT].content + MODULE.COMMENT)
                (root / '.build/ci-cache-context/mac.json').write_text(json.dumps({'identity': 'same-identity', 'key': 'prefix-new'}))
                log.write_text(json.dumps({'operation': 'key', 'scope': 'mac', 'key': 'prefix-new'}) + '\n')
            elif name == 'warm-restore':
                self.assertEqual(env['REMOZIO_CACHE_HIT'], 'false')
                for key, before in inputs.items():
                    if key != MODULE.LINUX_INPUT:
                        os.utime(before.path, ns=(before.atime_ns, before.mtime_ns))
                log.write_text(json.dumps({'operation': 'restore', 'result': 'cold-input-change' if restore_cold else 'restored',
                                          'requires_clean_build': restore_cold}) + '\n')
            elif name == 'warm-python':
                log.write_text('Ran 17 tests in 0.01s\n\nOK (skipped=1)\n')
            elif name == 'warm-app':
                MODULE.verify_inputs(inputs, changed=True, restored_times=True)
                for configuration in ('debug', 'release'):
                    (root / f'.build/macos-app/xcodebuild-{configuration}.log').write_text('** BUILD SUCCEEDED **\n')
                log.write_text('actual app checker fixture: both configurations passed\n')
            elif name == 'warm-protocol':
                self.assertEqual(argv[:3], ['swift', 'test', '--package-path'])
                self.assertIn('--force-resolved-versions', argv)
                log.write_text('Executed 141 tests, with 0 failures (0 unexpected) in 0.1 (0.2) seconds\n')
            else:
                raise AssertionError(name)
            return {'seconds': .01, 'exit': 0, 'log': log.name, 'bytes': log.stat().st_size}
        return command

    def assert_restored(self, args, inputs, context):
        MODULE.verify_inputs(inputs)
        for before in inputs.values():
            self.assertEqual(before.path.stat().st_mtime_ns, before.mtime_ns)
        self.assertEqual((args.repo / '.build/ci-cache-context/mac.json').read_bytes(), context)

    def test_full_followup_preserves_cold_evidence_and_restores_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, names, inputs, context = self.fixture(temporary)
            calls = []
            with self.native_platform(), self.python(), patch.object(MODULE, 'tracked_paths', return_value=names), \
                 patch.object(MODULE, 'command', side_effect=self.worker(args, inputs, calls)), patch('builtins.print'):
                result = MODULE.run(args)
            self.assertEqual([x[0] for x in calls], ['save', 'warm-key', 'warm-restore', 'warm-python', 'warm-app', 'warm-protocol'])
            self.assertFalse(result['actualGitHubArchiveHitTested'])
            self.assertFalse(result['completeWarmGateRun'])
            self.assertEqual(result['coldFullCheckSeconds'], 4012.5)
            self.assertEqual(result['testSummaries']['protocolXCTests'], 141)
            self.assertEqual(result['xcode']['cold']['debug']['phaseLines']['CompileC'], 1)
            self.assertEqual(result['xcode']['warm']['debug']['phaseLines']['CompileC'], 0)
            self.assertEqual((args.output / 'cold-full-check.log').read_bytes(), args.cold_full_check_log.read_bytes())
            self.assert_restored(args, inputs, context)

    def test_worker_failure_after_churn_restores_every_tracked_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, names, inputs, context = self.fixture(temporary)
            with self.native_platform(), self.python(), patch.object(MODULE, 'tracked_paths', return_value=names), \
                 patch.object(MODULE, 'command', side_effect=self.worker(args, inputs, [], fail='warm-app')):
                with self.assertRaisesRegex(RuntimeError, 'worker failure'):
                    MODULE.run(args)
            self.assert_restored(args, inputs, context)
            self.assertFalse((args.output / 'report.json').exists())

    def test_unstable_cold_gate_cannot_be_rebased_into_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, names, inputs, context = self.fixture(temporary)
            calls = []
            with self.native_platform(), self.python(), patch.object(MODULE, 'tracked_paths', return_value=names), \
                 patch.object(MODULE, 'command', side_effect=self.worker(args, inputs, calls, unstable=True)):
                with self.assertRaisesRegex(RuntimeError, 'cold full check'):
                    MODULE.run(args)
            self.assertEqual([x[0] for x in calls], ['save'])
            self.assert_restored(args, inputs, context)

    def test_cancellation_after_churn_also_restores_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, names, inputs, context = self.fixture(temporary)
            worker = self.worker(args, inputs, [])
            def cancelled(root, output, name, *rest, **kwargs):
                if name == 'warm-app':
                    raise KeyboardInterrupt()
                return worker(root, output, name, *rest, **kwargs)
            with self.native_platform(), self.python(), patch.object(MODULE, 'tracked_paths', return_value=names), \
                 patch.object(MODULE, 'command', side_effect=cancelled):
                with self.assertRaises(KeyboardInterrupt):
                    MODULE.run(args)
            self.assert_restored(args, inputs, context)

    def test_cli_sigterm_retires_owned_worker_and_restores_sources_and_handler(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, names, inputs, context = self.fixture(temporary)
            worker = self.worker(args, inputs, [])
            real_command = MODULE.command
            previous_handler = object()
            installed = []
            def set_handler(signum, handler):
                installed.append((signum, handler))
                return previous_handler
            def terminated(*args, **kwargs):
                installed[0][1](signal.SIGTERM, None)
            proc = Mock(returncode=None, pid=654)
            waits = []
            def wait(**kwargs):
                waits.append(kwargs)
                if len(waits) == 1:
                    terminated()
                return -9
            proc.wait.side_effect = wait
            def controlled(root, output, name, *rest, **kwargs):
                if name == 'warm-app':
                    return real_command(root, output, name, *rest, **kwargs)
                return worker(root, output, name, *rest, **kwargs)
            with self.native_platform(), self.python(), patch.object(MODULE, 'tracked_paths', return_value=names), \
                 patch.object(MODULE.argparse.ArgumentParser, 'parse_args', return_value=args), \
                 patch.object(MODULE.signal, 'signal', side_effect=set_handler), \
                 patch.object(MODULE, 'command', side_effect=controlled), \
                 patch.object(MODULE.subprocess, 'Popen', return_value=proc), \
                 patch.object(MODULE.os, 'killpg') as kill:
                with self.assertRaises(SystemExit) as ended:
                    MODULE.main()
            self.assertEqual(ended.exception.code, 128 + signal.SIGTERM)
            kill.assert_called_once_with(654, signal.SIGKILL)
            self.assertEqual(waits[-1], {'timeout': 10})
            self.assertEqual(installed[-1], (signal.SIGTERM, previous_handler))
            self.assert_restored(args, inputs, context)

    def test_restore_cold_result_refuses_to_run_warm_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, names, inputs, context = self.fixture(temporary)
            calls = []
            with self.native_platform(), self.python(), patch.object(MODULE, 'tracked_paths', return_value=names), \
                 patch.object(MODULE, 'command', side_effect=self.worker(args, inputs, calls, restore_cold=True)):
                with self.assertRaisesRegex(RuntimeError, 'warm reuse'):
                    MODULE.run(args)
            self.assertEqual([x[0] for x in calls], ['save', 'warm-key', 'warm-restore'])
            self.assert_restored(args, inputs, context)

    def test_non_native_host_and_inside_checkout_output_never_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, _, _, _ = self.fixture(temporary)
            with patch.object(MODULE, 'platform', SimpleNamespace(system=lambda: 'Linux', machine=lambda: 'x86_64')), \
                 patch.object(MODULE, 'command') as launch:
                with self.assertRaisesRegex(RuntimeError, 'supported arm64 Mac'):
                    MODULE.run(args)
                launch.assert_not_called()
            args.output = args.repo / '.build/followup'
            with self.native_platform(), self.python(), patch.object(MODULE, 'command') as launch:
                with self.assertRaisesRegex(RuntimeError, 'outside the checkout'):
                    MODULE.run(args)
                launch.assert_not_called()

    def test_mismatched_cold_context_never_launches_save(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, _, _, _ = self.fixture(temporary)
            args.cold_key_log.write_text('{"operation":"key","scope":"mac","key":"different"}\n')
            with self.native_platform(), self.python(), patch.object(MODULE, 'command') as launch:
                with self.assertRaisesRegex(RuntimeError, 'before the full check'):
                    MODULE.run(args)
                launch.assert_not_called()

    def test_summary_rejects_zero_tests_and_xctest_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / 'warm-python.log').write_text('Ran 0 tests in 0.0s\nOK\n')
            (output / 'warm-protocol.log').write_text('Executed 141 tests, with 0 failures\n')
            with self.assertRaisesRegex(RuntimeError, 'Python test execution'):
                MODULE.test_summaries(output)
            (output / 'warm-python.log').write_text('Ran 5 tests in 0.0s\nOK\n')
            (output / 'warm-protocol.log').write_text('Executed 141 tests, with 1 failure\n')
            with self.assertRaisesRegex(RuntimeError, 'XCTest execution'):
                MODULE.test_summaries(output)

    def test_unexpected_edit_and_symlinked_parent_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'source').write_bytes(b'original')
            inputs = MODULE.snapshot(root, ['source'])
            (root / 'source').write_bytes(b'unexpected')
            with self.assertRaisesRegex(RuntimeError, 'unexpected tracked input'):
                MODULE.verify_inputs(inputs)
            MODULE.restore_inputs(inputs)
            (root / 'alias').symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'symlinked parent'):
                MODULE.safe_path(root, 'alias/source')

    def test_command_failure_never_signals_reaped_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = Mock(returncode=3, pid=123)
            proc.wait.return_value = 3
            with patch.object(MODULE.subprocess, 'Popen', return_value=proc), patch.object(MODULE.os, 'killpg') as kill:
                with self.assertRaisesRegex(RuntimeError, 'command failed'):
                    MODULE.command(root, root, 'failure', ['fixture'], MODULE.time.monotonic() + 10, 5)
                kill.assert_not_called()

    def test_command_timeout_kills_only_its_unreaped_owned_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = Mock(returncode=None, pid=321)
            proc.wait.return_value = -9
            with patch.object(MODULE.subprocess, 'Popen', return_value=proc), \
                 patch.object(MODULE.time, 'monotonic', side_effect=[0, 2]), patch.object(MODULE.os, 'killpg') as kill:
                with self.assertRaisesRegex(RuntimeError, 'deadline'):
                    MODULE.command(root, root, 'timeout', ['fixture'], 1, 1)
                kill.assert_called_once_with(321, signal.SIGKILL)
                proc.wait.assert_called_once_with(timeout=10)

    def test_pending_cancellation_after_reap_never_signals_published_leader(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = Mock(returncode=None, pid=789)
            events = []
            previous_mask = {signal.SIGUSR1}
            def reaped(**kwargs):
                events.append('reaped and returncode published')
                proc.returncode = 0
                return 0
            def mask(how, values):
                if how == signal.SIG_BLOCK:
                    self.assertEqual(values, {signal.SIGINT, signal.SIGTERM})
                    events.append('cancellation blocked')
                    return previous_mask
                self.assertEqual(values, previous_mask)
                events.append('pending cancellation delivered after publication')
                raise SystemExit(143)
            proc.wait.side_effect = reaped
            with patch.object(MODULE.subprocess, 'Popen', return_value=proc), \
                 patch.object(MODULE.signal, 'pthread_sigmask', side_effect=mask), \
                 patch.object(MODULE.os, 'killpg') as kill:
                with self.assertRaises(SystemExit):
                    MODULE.command(root, root, 'reaped', ['fixture'], MODULE.time.monotonic() + 10, 5)
                kill.assert_not_called()
            self.assertEqual(events, ['cancellation blocked', 'reaped and returncode published',
                                      'pending cancellation delivered after publication'])

    def test_pending_cancellation_after_launch_retires_published_owned_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = Mock(returncode=None, pid=987)
            proc.wait.return_value = -9
            before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
            def started(*args, **kwargs):
                # A real Python signal callback during Popen is deferred until
                # command() has received and published ownership of the child.
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                return proc
            with patch.object(MODULE.subprocess, 'Popen', side_effect=started), \
                 patch.object(MODULE.os, 'killpg') as kill:
                with self.assertRaises(SystemExit):
                    MODULE.command(root, root, 'launched', ['fixture'], MODULE.time.monotonic() + 10, 5)
                kill.assert_called_once_with(987, signal.SIGKILL)
                proc.wait.assert_called_once_with(timeout=10)
            self.assertEqual({sig: signal.getsignal(sig) for sig in before}, before)

    def test_actual_owned_python_worker_inherits_original_signal_mask(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = sorted(map(int, signal.pthread_sigmask(signal.SIG_BLOCK, set())))
            code = ('import json,signal; '
                    'print(json.dumps(sorted(map(int,signal.pthread_sigmask(signal.SIG_BLOCK,set())))))')
            MODULE.command(root, root, 'child-mask', [sys.executable, '-c', code],
                           MODULE.time.monotonic() + 10, 5)
            self.assertEqual(json.loads((root / 'child-mask.log').read_text()), expected)

    def test_output_limit_retires_owned_unreaped_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = Mock(returncode=None, pid=456)
            def started(*args, **kwargs):
                kwargs['stdout'].write(b'123456789')
                kwargs['stdout'].flush()
                return proc
            with patch.object(MODULE, 'MAX_LOG_BYTES', 8), \
                 patch.object(MODULE.subprocess, 'Popen', side_effect=started), \
                 patch.object(MODULE.os, 'killpg') as kill:
                with self.assertRaisesRegex(RuntimeError, 'output exceeded'):
                    MODULE.command(root, root, 'large', ['fixture'], MODULE.time.monotonic() + 10, 5)
                kill.assert_called_once_with(456, signal.SIGKILL)
                proc.wait.assert_called_once_with(timeout=10)


if __name__ == '__main__':
    unittest.main()
