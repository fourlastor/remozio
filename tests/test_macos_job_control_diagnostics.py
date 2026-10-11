import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/run-macos-job-control-experiment.py'
spec = importlib.util.spec_from_file_location('job_control_experiment', SCRIPT)
experiment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(experiment)


class JobControlDiagnosticsTests(unittest.TestCase):
    def test_process_failure_retains_case_trial_and_both_streams(self):
        with self.assertRaises(RuntimeError) as caught:
            experiment.run([sys.executable, '-c',
                            "import sys; print('before failure'); print('native failure', file=sys.stderr); sys.exit(7)"],
                           context='job-control case resume, trial 3')
        message = str(caught.exception)
        for expected in ['job-control case resume, trial 3', 'exit 7', 'before failure', 'native failure']:
            self.assertIn(expected, message)
        self.assertIsInstance(caught.exception.__cause__, subprocess.CalledProcessError)

    def test_timeout_retains_partial_byte_output_without_changing_timeout(self):
        error = subprocess.TimeoutExpired(['fixture'], 30, output=b'partial\xff', stderr=b'waiting for child')
        with patch.object(experiment.subprocess, 'run', side_effect=error) as run:
            with self.assertRaises(RuntimeError) as caught:
                experiment.run(['fixture'], context='job-control case cancel, trial 4')
        run.assert_called_once_with(['fixture'], check=True, capture_output=True, text=True, timeout=30)
        for expected in ['job-control case cancel, trial 4', 'timeout after 30 seconds', 'partial\ufffd', 'waiting for child']:
            self.assertIn(expected, str(caught.exception))
        self.assertIs(caught.exception.__cause__, error)

    def test_failure_output_is_bounded_and_preserves_the_latest_details(self):
        error = subprocess.CalledProcessError(1, ['fixture'], output='discarded stdout prefix' + 'o' * 8192,
                                             stderr='discarded stderr prefix' + 'e' * 8192)
        with patch.object(experiment.subprocess, 'run', side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                experiment.run(['fixture'])
        message = str(caught.exception)
        self.assertNotIn('discarded', message)
        self.assertIn('o' * 8192, message)
        self.assertIn('e' * 8192, message)


if __name__ == '__main__':
    unittest.main()
