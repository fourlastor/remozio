import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/benchmark-core-parallel-tests.py'
spec = importlib.util.spec_from_file_location('benchmark_core_parallel_tests', SCRIPT)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class CoreParallelBenchmarkTests(unittest.TestCase):
    def test_listing_ignores_diagnostics_and_rejects_duplicates(self):
        text = 'warning: toolchain note\nRemozioCoreTests.A/testOne\n  RemozioCoreTests.B/testTwo\n'
        self.assertEqual(bench.listed_tests(text), ['RemozioCoreTests.A/testOne', 'RemozioCoreTests.B/testTwo'])
        with self.assertRaises(RuntimeError):
            bench.listed_tests('RemozioCoreTests.A/testOne\nRemozioCoreTests.A/testOne\n')
        with self.assertRaises(RuntimeError):
            bench.listed_tests('Building for debugging...\n')

    def test_serial_log_outcomes(self):
        log = ("Test Case '-[RemozioCoreTests.A testOne]' started.\n"
               "Test Case '-[RemozioCoreTests.A testOne]' passed (0.010 seconds).\n"
               "Test Case '-[RemozioCoreTests.A testTwo]' skipped (0.001 seconds).\n"
               "Test Case '-[RemozioCoreTests.B testThree]' failed (2.579 seconds).\n")
        self.assertEqual(bench.serial_results(log), [
            ('RemozioCoreTests.A/testOne', 'passed'),
            ('RemozioCoreTests.A/testTwo', 'skipped'),
            ('RemozioCoreTests.B/testThree', 'failed'),
        ])

    def test_xunit_outcomes_and_durations(self):
        xml = b'''<?xml version="1.0" encoding="UTF-8"?>
<testsuites><testsuite name="TestResults" errors="0" tests="3" failures="1" time="3.5">
<testcase classname="RemozioCoreTests.A" name="testOne" time="1.25"></testcase>
<testcase classname="RemozioCoreTests.A" name="testTwo" time="0.25"><skipped/></testcase>
<testcase classname="RemozioCoreTests.B" name="testThree" time="2"><failure message="failed"></failure></testcase>
</testsuite></testsuites>'''
        results, seconds = bench.xunit_results(xml)
        self.assertEqual(results, [('RemozioCoreTests.A/testOne', 'passed'),
                                   ('RemozioCoreTests.A/testTwo', 'skipped'),
                                   ('RemozioCoreTests.B/testThree', 'failed')])
        self.assertEqual(seconds, 3.5)

    def test_classification_reports_missing_unexpected_and_duplicate_cases(self):
        expected = ['M.A/one', 'M.A/two', 'M.B/three']
        complete = bench.classify(expected, [('M.A/one', 'passed'), ('M.A/two', 'skipped'), ('M.B/three', 'failed')])
        self.assertTrue(complete['completeSet'])
        self.assertEqual((complete['passed'], complete['failed'], complete['skipped']), (1, ['M.B/three'], ['M.A/two']))
        partial = bench.classify(expected, [('M.A/one', 'passed'), ('M.A/one', 'passed'), ('M.C/four', 'passed')])
        self.assertFalse(partial['completeSet'])
        self.assertEqual((partial['missing'], partial['unexpected'], partial['duplicated']), (2, 1, 1))

    def test_order_and_summary(self):
        self.assertEqual(bench.plan('SPPS'), ['serial', 'parallel', 'parallel', 'serial'])
        with self.assertRaises(ValueError):
            bench.plan('SX')
        trials = [{'mode': 'serial', 'seconds': 2400.0}, {'mode': 'parallel', 'seconds': 1400.0},
                  {'mode': 'parallel', 'seconds': 1600.0}, {'mode': 'serial', 'seconds': 2600.0},
                  {'mode': 'parallel', 'ran': False}]
        result = bench.summary(trials)
        self.assertEqual((result['serialMean'], result['parallelMean'], result['parallelReduction']), (2500.0, 1500.0, 0.4))
        self.assertFalse(bench.summary(trials[:1])['comparable'])


if __name__ == '__main__':
    unittest.main()
