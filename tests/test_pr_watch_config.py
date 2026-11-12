"""The PR watcher, with Remozio's config, must report a healthy selective CI run as ready and block any other run.

The babysit-pr skill is vendored unchanged (see its skill-source.json), so these Remozio-specific checks live here
and leave the skill's own tests untouched.
"""
import importlib.util
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / '.agents/skills/babysit-pr'
SPEC = importlib.util.spec_from_file_location('gh_pr_watch_for_remozio', SKILL / 'scripts/gh_pr_watch.py')
WATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WATCH)
JOBS_SPEC = importlib.util.spec_from_file_location('ci_pr_jobs_for_watch', ROOT / 'scripts/ci-pr-jobs.py')
JOBS = importlib.util.module_from_spec(JOBS_SPEC)
JOBS_SPEC.loader.exec_module(JOBS)
WORKFLOW = (ROOT / '.github/workflows/checks.yml').read_text()
PR = {'closed': False, 'merged': False, 'mergeable': 'MERGEABLE', 'merge_state_status': 'CLEAN',
      'review_decision': ''}


def remozio_config(**overrides):
    raw = json.loads((SKILL / 'config.json').read_text())
    raw.update(overrides)
    config, warnings = WATCH.build_config(raw)
    assert not warnings, warnings
    return patch.object(WATCH, 'CONFIG', config)


def check(name, bucket):
    state = {'pass': 'SUCCESS', 'fail': 'FAILURE', 'skipping': 'SKIPPED', 'pending': 'IN_PROGRESS'}[bucket]
    return {'name': name, 'bucket': bucket, 'state': state}


def small_selection(**changes):
    """The checks of a pull request that changed one core test class: one Mac core runner, other jobs skipped."""
    checks = {
        'Select jobs': 'pass', 'Python checks': 'pass', 'Mac build': 'pass', 'Mac experiments': 'pass',
        'Mac core tests (1)': 'pass', 'Mac interoperability': 'pass', 'Linux Swift protocol': 'skipping',
        'Kotlin protocol': 'skipping', 'Android build': 'skipping', 'iOS build': 'skipping',
        'Prune superseded main caches': 'skipping', 'Selected checks': 'pass',
    }
    checks.update(changes)
    return [check(name, bucket) for name, bucket in checks.items() if bucket]


def ready(checks):
    summary = WATCH.summarize_checks(checks)
    return WATCH.is_pr_ready_to_merge(PR, summary, [], checks_terminal_elapsed=3600, codex_gate=None)


class WatcherConfigTests(unittest.TestCase):
    def test_a_healthy_selective_run_is_ready(self):
        with remozio_config():
            self.assertTrue(ready(small_selection()))
            # The full suite on two runners, and a skipped Mac core tests job under either name GitHub may give it.
            self.assertTrue(ready(small_selection(**{'Mac core tests (2)': 'pass'})))
            for name in ('Mac core tests', 'Mac core tests ()', 'Mac core tests (${{ matrix.part }})'):
                with self.subTest(name=name):
                    self.assertTrue(ready(small_selection(**{'Mac core tests (1)': None, name: 'skipping'})))

    def test_a_failed_or_missing_check_that_should_have_run_blocks(self):
        with remozio_config():
            # A selected job that fails.
            self.assertFalse(ready(small_selection(**{'Mac core tests (1)': 'fail', 'Selected checks': 'fail'})))
            # A selected job that was skipped: the skip itself is tolerated by name, but Selected checks fails.
            self.assertFalse(ready(small_selection(**{'Mac build': 'skipping', 'Selected checks': 'fail'})))
            # The gate or the selection never reported.
            for name in ('Selected checks', 'Select jobs', 'Python checks'):
                with self.subTest(name=name):
                    checks = small_selection(**{name: None})
                    self.assertFalse(ready(checks))
                    self.assertEqual(WATCH.summarize_checks(checks)['required_missing'], [name])
            # The gate still running.
            self.assertFalse(ready(small_selection(**{'Selected checks': 'pending'})))
            # A skip that nobody planned for.
            self.assertFalse(ready(small_selection(**{'Release upload': 'skipping'})))

    def test_codex_reviews_are_off_and_can_be_switched_back_on(self):
        with remozio_config():
            self.assertFalse(WATCH.codex_required())
            self.assertTrue(ready(small_selection()))
        with remozio_config(codex={'enabled': True, 'required': True, 'idle_wait_minutes': 10}):
            self.assertTrue(WATCH.codex_required())
            self.assertFalse(ready(small_selection()))
            reviewed = {'reviewing': False, 'status': 'idle', 'active': True, 'head_reviewed': True,
                        'head_status': 'completed'}
            summary = WATCH.summarize_checks(small_selection())
            self.assertTrue(WATCH.is_pr_ready_to_merge(PR, summary, [], checks_terminal_elapsed=3600,
                                                       codex_gate=reviewed))

    def test_the_config_names_the_workflow_jobs(self):
        config = json.loads((SKILL / 'config.json').read_text())
        names = set(re.findall(r'^    name: (.+)$', WORKFLOW, re.MULTILINE))
        self.assertTrue(set(config['required_checks']) <= names)
        selective = {name for name in names if name not in config['required_checks']
                     and name not in ('Prune superseded main caches',)}
        skipped = set(config['expected_skipped_checks'])
        for name in selective:
            with self.subTest(name=name):
                self.assertTrue(name in skipped or name.replace(' (${{ matrix.part }})', '') in skipped)

    def test_the_gate_needs_every_selected_job(self):
        needs = re.search(r'^  selected-checks:\n(?:    .*\n)*?    needs: \[(.*)\]', WORKFLOW, re.MULTILINE)[1]
        self.assertEqual({name.strip() for name in needs.split(',')},
                         {'changes', 'python', *JOBS.WORKFLOW_JOBS})


class VerifyNeedsTests(unittest.TestCase):
    @staticmethod
    def needs(selected, results=None, changes='success'):
        outputs = {output: 'true' if output in selected else 'false' for output in JOBS.JOBS}
        value = {'changes': {'result': changes, 'outputs': outputs}, 'python': {'result': 'success'}}
        for job, output in JOBS.WORKFLOW_JOBS.items():
            value[job] = {'result': 'success' if output in selected else 'skipped'}
        for job, result in (results or {}).items():
            value[job] = {'result': result}
        return value

    def test_selected_jobs_pass_and_the_others_skip(self):
        self.assertEqual(JOBS.verify_needs(self.needs({'mac', 'mac_core'})), [])
        self.assertEqual(JOBS.verify_needs(self.needs(set(JOBS.JOBS))), [])

    def test_a_failure_a_wrong_skip_or_an_unselected_run_fails(self):
        self.assertEqual(JOBS.verify_needs(self.needs({'mac'}, {'mac': 'failure'})),
                         ['mac: failure, expected success'])
        self.assertEqual(JOBS.verify_needs(self.needs({'mac'}, {'mac': 'skipped'})),
                         ['mac: skipped, expected success'])
        self.assertEqual(JOBS.verify_needs(self.needs({'mac'}, {'mac-core': 'cancelled'})),
                         ['mac-core: cancelled, expected skipped'])
        self.assertEqual(JOBS.verify_needs(self.needs({'mac'}, {'python': 'failure'})),
                         ['python: failure, expected success'])

    def test_a_failed_or_incomplete_selection_fails(self):
        self.assertEqual(len(JOBS.verify_needs(self.needs({'mac'}, changes='failure'))), 1)
        needs = self.needs({'mac'})
        del needs['changes']['outputs']['ios']
        self.assertEqual(JOBS.verify_needs(needs), ['ios: the selection has no ios output'])


if __name__ == '__main__':
    unittest.main()
