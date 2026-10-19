import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'benchmark-core-tests.py'
spec = importlib.util.spec_from_file_location('benchmark_core_tests', SCRIPT)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def case_log():
    lines = []
    for name in sorted(bench.CASES):
        prefix = f"Test Case '-[{bench.CLASS} {name}]' "
        lines += [prefix + 'started.', prefix + 'passed (1.234 seconds).']
    return '\n'.join(lines + [' Executed 9 tests, with 0 failures (0 unexpected) in 11.106 seconds'])


def profile():
    return {'schemaVersion': 1, 'suite': bench.SUITE,
            'spans': {'fixed-label': {'calls': 2, 'thrownCalls': 1, 'cpuMeasurementFailures': 0,
                                      'wallSeconds': 0.2, 'processCPUSeconds': 0.3}}}


class BenchmarkTests(unittest.TestCase):
    def test_exact_nine_cases(self):
        self.assertEqual(set(bench.test_cases(case_log())), bench.CASES)

    def test_missing_duplicate_unknown_failed_and_skipped_cases_refuse(self):
        log = case_log()
        bad = [log.replace('Executed 9', 'Executed 8'), '\n'.join(log.splitlines()[2:]),
               log + '\n' + log, log.replace(sorted(bench.CASES)[0], 'testUnexpected'),
               log + '\n1 test skipped', log.replace('passed (1.234 seconds).', 'failed (1.234 seconds).', 1)]
        for value in bad:
            with self.subTest(value=value[-80:]), self.assertRaises(RuntimeError):
                bench.test_cases(value)

    def test_profile_counts_exact_but_timings_vary(self):
        value = profile()
        expected = bench.digest({'fixed-label': {'calls': 2, 'thrownCalls': 1, 'cpuMeasurementFailures': 0}})
        bench.profile_signature(value, expected)
        value['spans']['fixed-label']['wallSeconds'] = 10
        bench.profile_signature(value, expected)
        for field in ('calls', 'thrownCalls', 'cpuMeasurementFailures'):
            altered = profile()
            altered['spans']['fixed-label'][field] += 1
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                bench.profile_signature(altered, expected)
        for altered in ({'schemaVersion': 1, 'suite': bench.SUITE, 'spans': {}},
                        {'schemaVersion': 2, 'suite': bench.SUITE, 'spans': profile()['spans']}):
            with self.assertRaises(RuntimeError):
                bench.profile_signature(altered, expected)
        for bad in (float('nan'), float('inf'), -1):
            altered = profile()
            altered['spans']['fixed-label']['wallSeconds'] = bad
            with self.assertRaises(RuntimeError):
                bench.profile_signature(altered, expected)

    def test_compile_requires_actual_primary_file(self):
        prefix = '/Xcode/swift-frontend -frontend '
        source = '/same/path/DeterministicCBOR.swift'
        self.assertEqual(bench.compiler_evidence(prefix + '-c -primary-file ' + source), 1)
        for line in (prefix + '-emit-module -primary-file ' + source,
                     prefix + '-c -primary-file /other.swift ' + source,
                     '[4/5] Compiling RemozioProtocol DeterministicCBOR.swift'):
            with self.assertRaises(RuntimeError):
                bench.compiler_evidence(line)

    def test_reuse_requires_same_immediately_previous_proven_variant(self):
        current = {'mode': 'candidate', 'sourceSHA256': 's', 'bundleExecutableSHA256': 'b', 'cborObjectSHA256': 'o'}
        self.assertEqual(bench.compilation_status(1, current, None), 'recompiled')
        self.assertIn('reused', bench.compilation_status(0, current, current))
        with self.assertRaises(RuntimeError):
            bench.compilation_status(0, current, None)
        for key in current:
            changed = dict(current, **{key: 'changed'})
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                bench.compilation_status(0, current, changed)

    def test_source_restores_bytes_mode_and_mtime_on_success_and_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'source.swift'
            for failure in (False, True):
                path.write_bytes(b'candidate')
                path.chmod(0o640)
                os.utime(path, ns=(1000000000, 2000000000))
                original = path.stat()
                try:
                    with bench.source_variants(path, b'baseline', b'candidate') as select:
                        select(b'baseline')
                        first = path.stat().st_mtime_ns
                        select(b'candidate')
                        self.assertGreater(path.stat().st_mtime_ns, first)
                        if failure:
                            raise ValueError('synthetic test failure')
                except ValueError:
                    self.assertTrue(failure)
                self.assertEqual(path.read_bytes(), b'candidate')
                self.assertEqual(path.stat().st_mtime_ns, original.st_mtime_ns)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_concurrent_source_edit_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'source.swift'
            path.write_bytes(b'candidate')
            with self.assertRaises(RuntimeError):
                with bench.source_variants(path, b'baseline', b'candidate'):
                    path.write_bytes(b'other human work')
            self.assertEqual(path.read_bytes(), b'other human work')

    def test_inventory_detects_content_mode_and_symlink_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'a').write_bytes(b'one')
            (root / 'b').symlink_to('a')
            with patch.object(bench, 'git', return_value=b'a\0b\0'):
                initial = bench.inventory(root)
                (root / 'a').write_bytes(b'two')
                self.assertNotEqual(bench.inventory(root), initial)
                (root / 'a').write_bytes(b'one')
                (root / 'a').chmod(0o700)
                self.assertNotEqual(bench.inventory(root), initial)
                self.assertEqual(initial['b']['kind'], 'symlink')

    def test_interrupt_after_reap_never_signals_the_reaped_pid(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wait4 = os.wait4
            def interrupt_after_reap(pid, options):
                result = wait4(pid, options)
                if result[0]:
                    os.kill(os.getpid(), signal.SIGINT)
                return result
            with patch.object(bench.os, 'wait4', side_effect=interrupt_after_reap), patch.object(bench.os, 'killpg') as kill:
                with self.assertRaises(KeyboardInterrupt):
                    bench.owned([sys.executable, '-c', 'pass'], root / 'reaped.log', root, 5)
                kill.assert_not_called()
            result = json.loads((root / 'reaped.json').read_text())
            self.assertEqual(result['returncode'], 0)
            self.assertTrue(result['cleanupComplete'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux procfs validates child death')
    def test_timeout_kills_the_owned_descendant_group(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            script = ('import os,time; child=os.fork(); '
                      'print(child if child else os.getpid(), flush=True); time.sleep(30)')
            with self.assertRaises(subprocess.TimeoutExpired):
                bench.owned([sys.executable, '-c', script], root / 'group.log', root, 1.0)
            children = {int(line) for line in (root / 'group.log').read_text().splitlines()}
            self.assertEqual(len(children), 1)
            for child in children:
                info = Path(f'/proc/{child}/stat')
                deadline = time.monotonic() + 1
                while info.exists():
                    try:
                        state = info.read_text().split(') ', 1)[1][0]
                    except FileNotFoundError:
                        break
                    if state == 'Z':
                        break
                    if time.monotonic() >= deadline:
                        self.fail('owned descendant still running after group kill')
                    time.sleep(0.01)

    def test_owned_success_nonzero_timeout_and_interrupt_are_reaped(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            good = bench.owned([sys.executable, '-c', 'print("ok")'], root / 'ok.log', root, 5)
            self.assertEqual(good['returncode'], 0)
            self.assertGreater(good['wallSeconds'], 0)
            self.assertGreaterEqual(good['userCPUSeconds'], 0)
            for name, script, timeout, error in (
                ('failure', 'raise SystemExit(7)', 5, RuntimeError),
                ('timeout', 'import time; time.sleep(30)', 0.1, subprocess.TimeoutExpired),
            ):
                with self.assertRaises(error):
                    bench.owned([sys.executable, '-c', script], root / (name + '.log'), root, timeout)
                result = json.loads((root / (name + '.json')).read_text())
                self.assertTrue(result['cleanupComplete'])
                with self.assertRaises(ChildProcessError):
                    os.waitpid(result['pid'], os.WNOHANG)
            original_sleep = bench.time.sleep
            calls = 0
            def interrupt_once(duration):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise KeyboardInterrupt()
                original_sleep(duration)
            with patch.object(bench.time, 'sleep', side_effect=interrupt_once), self.assertRaises(KeyboardInterrupt):
                bench.owned([sys.executable, '-c', 'import time; time.sleep(30)'], root / 'interrupt.log', root, 5)
            result = json.loads((root / 'interrupt.json').read_text())
            self.assertTrue(result['cleanupComplete'])
            self.assertEqual(result['returncode'], -signal.SIGKILL)
            with self.assertRaises(ChildProcessError):
                os.waitpid(result['pid'], os.WNOHANG)


if __name__ == '__main__':
    unittest.main()
