"""Tests for scripts/core-test-time-guard.py with synthetic xctest log lines and a fake re-run runner."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('core_test_time_guard', ROOT / 'scripts/core-test-time-guard.py')
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
JOBS_SPEC = importlib.util.spec_from_file_location('ci_pr_jobs', ROOT / 'scripts/ci-pr-jobs.py')
JOBS = importlib.util.module_from_spec(JOBS_SPEC)
JOBS_SPEC.loader.exec_module(JOBS)

WEIGHTS = {'weights': {'FastTests': 2.0, 'SplitTests': 40.0, 'TinyTests': 0.5},
           'methods': {'SplitTests': {'testA': 20.0, 'testB': 20.0}}}
CAPS = {'FastTests/testListed': 40.0}


def line(test, seconds, state='passed'):
    test_class, method = test.split('/')
    return f"Test Case '-[RemozioCoreTests.{test_class} {method}]' {state} ({seconds:.3f} seconds).\n"


def measured(**tests):
    return GUARD.durations([''.join(line(name.replace('__', '/'), seconds) for name, seconds in tests.items())])


class FakeRerun:
    def __init__(self, seconds=None, elapsed=None, timeout_on=()):
        self.seconds, self.elapsed, self.timeout_on, self.calls = seconds or {}, elapsed or {}, set(timeout_on), []

    def __call__(self, test, timeout):
        self.calls.append((test, timeout))
        name = GUARD.short(test)
        if name in self.timeout_on:
            raise TimeoutError(test)
        seconds = self.seconds.get(name, 1.0)
        return seconds, self.elapsed.get(name, seconds or 1.0)


def evaluate(times, rerun=None, event='pull_request', mode='selected', selected='', changed=(), files=None,
             parts=1, nightly_cap=9500.0):
    files = files or {}
    return GUARD.evaluate(times, CAPS, nightly_cap, WEIGHTS, event=event, mode=mode, selected_tests=selected,
                          changed=list(changed), read_text=files.get, rerun=rerun or FakeRerun(), parts=parts)


class LogParsingTests(unittest.TestCase):
    def test_passed_and_failed_durations_are_kept_and_skips_ignored(self):
        text = (line('FastTests/testOne', 1.5) + 'noise\n' + line('FastTests/testTwo', 2.25, 'failed')
                + line('FastTests/testThree', 0.0, 'skipped'))
        self.assertEqual(GUARD.durations([text]), {'RemozioCoreTests.FastTests/testOne': 1.5,
                                                   'RemozioCoreTests.FastTests/testTwo': 2.25})


class PerTestLimitTests(unittest.TestCase):
    def test_tests_under_the_limit_pass_without_reruns(self):
        rerun = FakeRerun()
        errors, _ = evaluate(measured(FastTests__testOne=19.9, FastTests__testTwo=1), rerun)
        self.assertEqual(errors, [])
        self.assertEqual(rerun.calls, [])

    def test_an_over_limit_test_that_is_fast_in_isolation_passes(self):
        rerun = FakeRerun(seconds={'FastTests/testOne': 8.0})
        errors, _ = evaluate(measured(FastTests__testOne=25), rerun)
        self.assertEqual(errors, [])
        self.assertEqual([test for test, _ in rerun.calls], ['RemozioCoreTests.FastTests/testOne'])
        self.assertEqual(rerun.calls[0][1], GUARD.RERUN_BUDGET_SECONDS)

    def test_an_over_limit_test_confirmed_in_isolation_fails(self):
        errors, _ = evaluate(measured(FastTests__testOne=25), FakeRerun(seconds={'FastTests/testOne': 24.0}))
        self.assertEqual(len(errors), 1)
        self.assertIn('slow in isolation', errors[0])
        self.assertIn('FastTests/testOne', errors[0])

    def test_a_rerun_without_a_duration_fails(self):
        errors, _ = evaluate(measured(FastTests__testOne=25), FakeRerun(seconds={'FastTests/testOne': None}))
        self.assertEqual(len(errors), 1)
        self.assertIn('reported no duration', errors[0])

    def test_more_than_five_offenders_fail_without_rerunning(self):
        rerun = FakeRerun()
        times = measured(**{f'FastTests__testSlow{index}': 21 + index for index in range(6)})
        errors, _ = evaluate(times, rerun)
        self.assertEqual(rerun.calls, [])
        self.assertEqual(len(errors), 6)
        for error in errors:
            self.assertIn('too many slow tests', error)

    def test_five_offenders_are_each_rerun(self):
        rerun = FakeRerun()
        errors, _ = evaluate(measured(**{f'FastTests__testSlow{index}': 21 for index in range(5)}), rerun)
        self.assertEqual(errors, [])
        self.assertEqual(len(rerun.calls), 5)

    def test_the_rerun_budget_is_shared_and_its_exhaustion_fails_the_rest(self):
        names = [f'FastTests/testSlow{index}' for index in range(3)]
        rerun = FakeRerun(seconds={names[0]: 5.0, names[1]: 5.0}, elapsed={names[0]: 70.0, names[1]: 60.0})
        errors, _ = evaluate(measured(**{name.replace('/', '__'): 21 for name in names}), rerun)
        self.assertEqual([timeout for _, timeout in rerun.calls], [120.0, 50.0])
        self.assertEqual(len(errors), 1)
        self.assertIn('budget', errors[0])
        self.assertIn(names[2], errors[0])

    def test_a_rerun_that_times_out_fails_it_and_every_later_offender(self):
        rerun = FakeRerun(timeout_on={'FastTests/testSlow0'})
        errors, _ = evaluate(measured(FastTests__testSlow0=50, FastTests__testSlow1=21), rerun)
        self.assertEqual(len(rerun.calls), 1)
        self.assertEqual(len(errors), 2)
        for error in errors:
            self.assertIn('budget', error)

    def test_an_exception_within_its_cap_passes_without_a_rerun(self):
        rerun = FakeRerun()
        errors, _ = evaluate(measured(FastTests__testListed=39), rerun)
        self.assertEqual(errors, [])
        self.assertEqual(rerun.calls, [])

    def test_an_exception_over_its_cap_fails_when_confirmed(self):
        rerun = FakeRerun(seconds={'FastTests/testListed': 41.0})
        errors, _ = evaluate(measured(FastTests__testListed=45), rerun)
        self.assertEqual(len(errors), 1)
        self.assertIn('slow in isolation', errors[0])
        self.assertIn('limit 40s', errors[0])

    def test_the_limit_fails_on_main_and_nightly_too(self):
        for event in ('push', 'schedule', 'workflow_dispatch'):
            with self.subTest(event=event):
                errors, _ = evaluate(measured(FastTests__testOne=25), FakeRerun(seconds={'FastTests/testOne': 25}),
                                     event=event, mode='full')
                self.assertIn('slow in isolation', errors[0])


class ExceptionsFileTests(unittest.TestCase):
    def document(self):
        return json.loads((ROOT / GUARD.EXCEPTIONS).read_text())

    def test_the_exceptions_file_loads_and_says_it_should_shrink(self):
        document = self.document()
        caps, nightly_cap = GUARD.load_exceptions(document)
        self.assertTrue(caps)
        self.assertEqual(nightly_cap, 9500)
        self.assertIn('shrink', document['description'])
        self.assertIn('reviewer', document['description'])
        self.assertIn('shrink', GUARD.__doc__)

    def test_the_exceptions_name_existing_core_test_classes_and_methods(self):
        # An exceptions change runs no Mac job, so a stale or misspelled name must fail here instead.
        methods = {}
        for path in (ROOT / JOBS.CORE_TESTS).rglob('*.swift'):
            text = path.read_text()
            for test_class in JOBS.TEST_CLASS.findall(text):
                methods.setdefault(test_class, set()).update(name for _, name in JOBS.TEST_METHOD.findall(text))
        for name, entry in self.document()['exceptions'].items():
            with self.subTest(name=name):
                test_class, method = name.split('/')
                self.assertIn(test_class, methods)
                self.assertIn(method, methods[test_class])
                self.assertTrue(entry['reason'].strip())

    def test_invalid_entries_are_rejected(self):
        base = {'description': 'd', 'source': 's', 'nightly_total_cap_seconds': 1}
        for entry in ({'Module.Class/test': {'cap_seconds': 30, 'reason': 'r'}},
                      {'Class': {'cap_seconds': 30, 'reason': 'r'}},
                      {'Class/test': {'cap_seconds': 30, 'reason': ' '}},
                      {'Class/test': {'cap_seconds': 30}},
                      {'Class/test': {'cap_seconds': 10, 'reason': 'r'}}):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                GUARD.load_exceptions({**base, 'exceptions': entry})
        with self.assertRaises(ValueError):
            GUARD.load_exceptions({**base, 'exceptions': {}, 'extra': 1})


class WeightDriftTests(unittest.TestCase):
    def test_drift_fails_for_a_selected_class(self):
        errors, _ = evaluate(measured(FastTests__testOne=8, FastTests__testTwo=8),
                             selected='RemozioCoreTests.FastTests')
        self.assertEqual(len(errors), 1)
        self.assertIn('weight drift', errors[0])
        self.assertIn('FastTests', errors[0])

    def test_drift_within_the_ratio_and_margin_passes(self):
        # 2 s weight: 2 * 1.5 + 10 = 13 s allowed.
        errors, _ = evaluate(measured(FastTests__testOne=6, FastTests__testTwo=6.9),
                             selected='RemozioCoreTests.FastTests')
        self.assertEqual(errors, [])

    def test_drift_ignores_classes_that_were_not_selected(self):
        errors, _ = evaluate(measured(FastTests__testOne=16, TinyTests__testOne=1),
                             selected='RemozioCoreTests.TinyTests')
        self.assertEqual(errors, [])

    def test_full_mode_checks_only_classes_whose_test_files_changed(self):
        files = {'macos/core/Tests/RemozioCoreTests/FastTests.swift': 'final class FastTests: XCTestCase {\n}\n'}
        times = measured(FastTests__testOne=16, TinyTests__testOne=16)
        errors, _ = evaluate(times, mode='full', changed=list(files), files=files)
        self.assertEqual(len(errors), 1)
        self.assertIn('FastTests', errors[0])
        errors, _ = evaluate(times, mode='full', changed=['scripts/check.sh'])
        self.assertEqual(errors, [])

    def test_drift_is_accepted_when_the_weights_file_changes(self):
        errors, warnings = evaluate(measured(FastTests__testOne=16), selected='RemozioCoreTests.FastTests',
                                    changed=[GUARD.WEIGHTS])
        self.assertEqual(errors, [])
        self.assertTrue(any('FastTests' in warning for warning in warnings))

    def test_a_split_class_compares_only_the_methods_that_ran(self):
        # testA weighs 20 s: 20 * 1.5 + 10 = 40 s allowed, below the 40 s class weight's allowance of 70 s.
        selected = 'RemozioCoreTests.SplitTests/testA'
        errors, _ = evaluate(measured(SplitTests__testA=41), selected=selected)
        self.assertEqual(len(errors), 1)
        self.assertIn('weight 20.0s', errors[0])
        errors, _ = evaluate(measured(SplitTests__testA=19, SplitTests__testB=19, SplitTests__testC=19),
                             selected='RemozioCoreTests.SplitTests')
        # testC has no method weight, so the 40 s class weight applies: 57 s is within 70 s.
        self.assertEqual(errors, [])

    def test_unknown_changes_skip_drift_with_a_warning(self):
        errors, warnings = GUARD.evaluate(measured(FastTests__testOne=16), CAPS, 9500, WEIGHTS,
                                          event='pull_request', mode='selected',
                                          selected_tests='RemozioCoreTests.FastTests', changed=None,
                                          read_text=lambda path: None, rerun=FakeRerun())
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)

    def test_main_and_nightly_runs_never_fail_on_drift(self):
        for event in ('push', 'schedule', 'workflow_dispatch'):
            with self.subTest(event=event):
                errors, warnings = evaluate(measured(FastTests__testOne=16), event=event, mode='full')
                self.assertEqual(errors, [])
                self.assertTrue(any('weight drift' in warning for warning in warnings))


class NightlyTotalTests(unittest.TestCase):
    def test_the_nightly_run_warns_over_its_share_of_the_cap(self):
        times = measured(**{f'TinyTests__test{index}': 15 for index in range(10)})
        _, warnings = evaluate(times, event='schedule', mode='full', parts=2, nightly_cap=280)
        self.assertTrue(any('nightly cap' in warning for warning in warnings))
        errors, warnings = evaluate(times, event='schedule', mode='full', parts=1, nightly_cap=280)
        self.assertEqual(errors, [])
        self.assertFalse(any('nightly cap' in warning for warning in warnings))

    def test_only_the_scheduled_run_checks_the_total(self):
        times = measured(**{f'TinyTests__test{index}': 15 for index in range(10)})
        for event in ('push', 'pull_request'):
            with self.subTest(event=event):
                errors, warnings = evaluate(times, event=event, mode='full', nightly_cap=10)
                self.assertEqual(errors, [])
                self.assertFalse(any('nightly cap' in warning for warning in warnings))


class WorkflowTests(unittest.TestCase):
    def test_the_guard_runs_after_the_shards_and_before_the_logs_are_retained(self):
        text = (ROOT / '.github/workflows/checks.yml').read_text()
        shards = text.index('name: Run macos/core class shards concurrently')
        guard = text.index('name: Check macos/core test durations')
        retain = text.index('name: Retain shard logs')
        self.assertLess(shards, guard)
        self.assertLess(guard, retain)
        step = text[guard:retain]
        for needed in ('scripts/core-test-time-guard.py', 'github.event_name', 'pull_request.base.sha',
                       'mac_core_mode', 'mac_core_tests'):
            self.assertIn(needed, step)


if __name__ == '__main__':
    unittest.main()
