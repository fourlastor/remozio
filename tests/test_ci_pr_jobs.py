"""Pull request selection must run every job and core test that a change can affect, and everything when unsure."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('ci_pr_jobs', ROOT / 'scripts/ci-pr-jobs.py')
JOBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(JOBS)
WORKFLOW = ROOT / '.github/workflows/checks.yml'
KOTLIN = {'linux', 'mac_interop', 'ios', 'kotlin', 'android'}
SHARED_SWIFT = {'linux', 'mac', 'mac_experiments', 'mac_core', 'mac_interop'}

TEST_FILE = '''import XCTest
@testable import RemozioCore

private struct LocalFixture {
    let value = 1
}

struct SharedFixture {
    let value = 2
}

@MainActor
final class HeavyTests: XCTestCase {
    private var state = 0

    func testOne() {
        XCTAssertEqual(1, 1)
    }

    func testTwo() {
        XCTAssertEqual(2, 2)
    }

    private func helper() {}
}

final class LightTests: XCTestCase, @unchecked Sendable {
    func testThree() {}
}

extension HeavyTests {
    func testFour() {
        XCTAssertTrue(true)
    }
}
'''


def changed(*texts):
    """0-based indexes of the TEST_FILE lines that contain each text."""
    lines = TEST_FILE.splitlines()
    return {next(index for index, line in enumerate(lines) if text in line) for text in texts}


def select(*texts, used_elsewhere=lambda name: True, users=lambda name: set()):
    return JOBS.tests_for_changes(TEST_FILE, changed(*texts), 'M', {'HeavyTests', 'LightTests'}, {'HeavyTests'},
                                  used_elsewhere, users)


class GitRepository:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.env = {**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid',
                    'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.invalid',
                    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
        self.git('init', '--quiet', '--initial-branch=main')

    def git(self, *arguments):
        return subprocess.run(['git', *arguments], cwd=self.directory, env=self.env, text=True, check=True,
                              capture_output=True).stdout.strip()

    def write(self, path, text):
        (self.directory / path).parent.mkdir(parents=True, exist_ok=True)
        (self.directory / path).write_text(text)

    def commit(self, message):
        self.git('add', '--all')
        self.git('commit', '--quiet', '-m', message)

    def merge(self, branch):
        """Merge `branch` into main after main moved on, as GitHub builds a pull request merge commit."""
        self.git('switch', '--quiet', 'main')
        self.write('README.md', self.git('rev-parse', 'HEAD'))
        self.commit('main moves on')
        self.git('merge', '--quiet', '--no-ff', '-m', 'merge', branch)
        return self.git('rev-parse', 'HEAD^1'), self.git('rev-parse', 'HEAD')


@contextlib.contextmanager
def working_directory(path):
    current = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(current)


class JobSelectionTests(unittest.TestCase):
    def test_unclaimed_and_shared_build_paths_run_every_job(self):
        for path in ('scripts/check.sh', '.github/workflows/checks.yml', '.github/other.json',
                     'gradle/libs.versions.toml', 'build.gradle.kts', 'settings.gradle.kts', 'gradle.properties',
                     'gradlew', '.gitignore', 'third-party/cloudflared/pin.json', 'protocol/vectors/a.json',
                     'protocol/session-envelope.md', 'unknown/file.txt'):
            with self.subTest(path=path):
                self.assertEqual(JOBS.jobs_for(path), JOBS.EVERY_JOB)

    def test_documentation_and_test_weights_run_only_the_python_checks(self):
        for path in ('docs/design-decisions.md', 'README.md', 'AGENTS.md', 'LICENSE', JOBS.WEIGHTS):
            with self.subTest(path=path):
                self.assertEqual(JOBS.jobs_for(path), frozenset())

    def test_each_area_runs_the_jobs_that_build_it(self):
        cases = {
            'protocol/kotlin/src/commonMain/kotlin/A.kt': KOTLIN,
            'phone/core/build.gradle.kts': KOTLIN,
            'tools/dev-invitation/src/main/kotlin/A.kt': KOTLIN,
            'android/app/src/main/A.kt': {'android'},
            'ios/Remozio/A.swift': {'ios'},
            '.maestro/flow.yaml': {'ios'},
            'protocol/swift/Sources/A.swift': SHARED_SWIFT,
            'host/shared-core/Sources/A.swift': SHARED_SWIFT,
            'macos/core/Sources/A.swift': {'mac', 'mac_experiments', 'mac_core', 'mac_interop'},
            'macos/core/Tests/RemozioCoreTests/ATests.swift': {'mac', 'mac_experiments', 'mac_core', 'mac_interop'},
            'macos/app/App/A.swift': {'mac', 'mac_experiments', 'mac_interop'},
            'macos/app/CommandMonitor/MonitorMain.c': {'mac', 'mac_experiments', 'mac_core', 'mac_interop'},
            'experiments/macos/Sources/A.swift': {'linux', 'mac_experiments', 'mac_interop'},
            'experiments/command-frontend/live-child.c': {'linux', 'mac_experiments', 'mac_core', 'mac_interop'},
            'experiments/release-signing/Sources/ReleaseSigningProbe/main.swift': {'linux', 'mac', 'mac_experiments',
                                                                                  'mac_interop'},
            'tests/test_xctest_shards.py': {'mac_experiments'},
            '.agents/skills/babysit-pr/scripts/gh_pr_watch.py': {'mac_experiments'},
        }
        for path, jobs in cases.items():
            with self.subTest(path=path):
                self.assertEqual(JOBS.jobs_for(path), jobs)

    def test_a_swift_package_manifest_or_lockfile_runs_every_swift_job(self):
        for path in ('experiments/sparkle-probe/Package.swift', 'macos/app/Package.resolved',
                     'ios/Remozio.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved'):
            with self.subTest(path=path):
                self.assertTrue(SHARED_SWIFT | {'ios'} <= JOBS.jobs_for(path))

    def test_selection_is_the_union_of_its_paths(self):
        self.assertEqual(JOBS.select(['android/app/A.kt', 'ios/Remozio/A.swift', 'docs/a.md']), {'android', 'ios'})
        self.assertEqual(JOBS.select([]), set())

    def test_the_workflow_gates_each_selected_job_on_its_output(self):
        text = WORKFLOW.read_text()
        for name in (*JOBS.JOBS, 'mac_core_mode', 'mac_core_parts', 'mac_core_tests', 'mac_release'):
            with self.subTest(name=name):
                self.assertIn(f'{name}: ${{{{ steps.select.outputs.{name} }}}}', text)
        for job in JOBS.JOBS:
            with self.subTest(job=job):
                self.assertRegex(text, rf"needs\.changes\.outputs\.{job} == 'true'")
        gated = re.findall(r"^  ([a-z-]+):\n(?:    .*\n)*?    if: \$\{\{ !cancelled\(\) && \(github\.event_name != "
                           r"'pull_request' \|\| needs\.changes\.outputs\.", text, re.MULTILINE)
        self.assertEqual(len(gated), len(JOBS.JOBS))


    def test_the_mac_build_builds_only_the_debug_app_on_a_pull_request_that_changes_no_release_input(self):
        text = WORKFLOW.read_text()
        self.assertEqual(text.count('REMOZIO_MAC_APP_CONFIGURATIONS'), 1)
        self.assertIn("REMOZIO_MAC_APP_CONFIGURATIONS: ${{ github.event_name == 'pull_request' && "
                      "needs.changes.outputs.mac_release == 'false' && 'Debug' || 'Debug,Release' }}", text)


class ReleaseSelectionTests(unittest.TestCase):
    def test_app_release_signing_package_and_shared_inputs_build_the_release_app(self):
        for path in ('macos/app/App/RemozioApp.swift', 'macos/app/Remozio.xcodeproj/project.pbxproj',
                     'macos/app/Authority/Info.plist', 'macos/app/CommandMonitor/MonitorMain.c',
                     'experiments/release-signing/Sources/ReleaseSigningProbe/main.swift',
                     'macos/core/Package.resolved', 'protocol/swift/Package.swift',
                     'scripts/generate-macos-release-manifest.py', 'scripts/check-macos-app.py',
                     '.github/workflows/checks.yml', 'third-party/cloudflared/pin.json', '.gitignore'):
            with self.subTest(path=path):
                self.assertIsNotNone(JOBS.release_reason(['docs/a.md', path]))

    def test_other_changes_build_only_the_debug_app(self):
        self.assertIsNone(JOBS.release_reason([]))
        for path in ('macos/core/Sources/RemozioCore/A.swift', 'macos/core/Tests/RemozioCoreTests/ATests.swift',
                     'protocol/swift/Sources/A.swift', 'host/shared-core/Sources/A.swift', 'macos/ui-adapters/A.swift',
                     'experiments/macos/Sources/A.swift', 'tests/test_macos_release_manifest.py', 'docs/a.md',
                     'gradle/libs.versions.toml', 'gradle.properties', 'gradlew', 'android/app/A.kt'):
            with self.subTest(path=path):
                self.assertIsNone(JOBS.release_reason([path]))


    def test_conditional_compilation_lines_are_found_in_added_and_removed_diff_lines(self):
        diff = '--- a/A.swift\n+++ b/A.swift\n@@ -1 +1 @@\n-let a = 1\n+let a = 2\n'
        self.assertIsNone(JOBS.conditional_change(diff))
        for line in ('+#if DEBUG', '-#endif', '+    #else', '- #elseif os(macOS)', '+let isDebug = DEBUG_BUILD'):
            with self.subTest(line=line):
                self.assertEqual(JOBS.conditional_change(diff + line + '\n'), line)
        self.assertIsNone(JOBS.conditional_change(diff + ' #if DEBUG\n'))  # Unchanged context is not a change.
        self.assertIsNone(JOBS.conditional_change(diff + '+if #available(macOS 26, *) {}\n'))

    def test_pull_request_merges_build_the_release_app_for_core_conditional_compilation(self):
        source = 'macos/core/Sources/RemozioCore/Seam.swift'
        base_text = 'let a = 1\n#if canImport(Darwin)\nlet b = 2\n#endif\nlet mode = "release"\n'
        cases = {
            'directive-added': (source, base_text.replace('let a = 1\n', '#if DEBUG\nlet a = 1\n#endif\n'), True),
            'directive-removed': (source, base_text.replace('#if canImport(Darwin)\n', '').replace('#endif\n', ''),
                                  True),
            'debug-line-changed': (source, base_text.replace('let b = 2', 'let b = DEBUG_LEVEL'), True),
            'protocol-directive': ('protocol/swift/Sources/P.swift', '#if DEBUG\nlet p = 1\n#endif\n', True),
            'ordinary-change': (source, base_text.replace('let a = 1', 'let a = 3'), False),
            'test-directive': ('macos/core/Tests/RemozioCoreTests/SeamTests.swift', '#if DEBUG\nlet t = 1\n#endif\n',
                               False),
        }
        # Each case starts from the same base in its own repository, because each merge moves main on.
        for branch, (path, text, release) in cases.items():
            with self.subTest(branch=branch), tempfile.TemporaryDirectory() as directory, \
                    working_directory(directory):
                repository = GitRepository(directory)
                repository.write(source, base_text)
                repository.write('protocol/swift/Sources/P.swift', 'let p = 1\n')
                repository.write('macos/core/Tests/RemozioCoreTests/SeamTests.swift', 'let t = 1\n')
                repository.commit('base')
                repository.git('switch', '--quiet', '-c', branch, 'main')
                repository.write(path, text)
                repository.commit(branch)
                base, merge = repository.merge(branch)
                paths = [name for name in JOBS.changed_paths(merge) if name != 'README.md']
                self.assertEqual(JOBS.release_reason(paths, base, merge) is not None, release)
                self.assertIsNone(JOBS.release_reason(paths))  # Without the diff, only the paths count.


class CoreTestSelectionTests(unittest.TestCase):
    def test_a_test_method_change_in_a_heavy_class_selects_that_method(self):
        self.assertEqual(select('XCTAssertEqual(2, 2)'), {'M.HeavyTests/testTwo'})
        self.assertEqual(select('func testOne', 'XCTAssertTrue(true)'),
                         {'M.HeavyTests/testOne', 'M.HeavyTests/testFour'})

    def test_a_change_outside_the_test_methods_of_a_heavy_class_selects_the_class(self):
        self.assertEqual(select('private func helper'), {'M.HeavyTests'})
        self.assertEqual(select('private var state', 'XCTAssertEqual(2, 2)'), {'M.HeavyTests'})

    def heavy_selection(self, text, *needles):
        lines = text.splitlines()
        changed_lines = {next(index for index, line in enumerate(lines) if needle in line) for needle in needles}
        return JOBS.tests_for_changes(text, changed_lines, 'M', {'HeavyTests'}, {'HeavyTests'}, lambda name: True,
                                      lambda name: set())

    def test_one_line_tests_each_own_only_their_line(self):
        text = ('final class HeavyTests: XCTestCase {\n'
                '    func testA() throws { try run("a") }\n'
                '    func testB() throws { try run("b", flag: true) }\n'
                '    func testC() throws {\n'
                '        try run("c")\n'
                '    }\n'
                '    private func run(_ mode: String, flag: Bool = false) throws {}\n'
                '}\n')
        self.assertEqual(self.heavy_selection(text, 'run("b"'), {'M.HeavyTests/testB'})
        self.assertEqual(self.heavy_selection(text, 'run("a")'), {'M.HeavyTests/testA'})
        self.assertEqual(self.heavy_selection(text, 'try run("c")'), {'M.HeavyTests/testC'})
        self.assertEqual(self.heavy_selection(text, 'private func run'), {'M.HeavyTests'})

    def test_braces_in_strings_and_comments_do_not_move_a_span(self):
        text = ('final class HeavyTests: XCTestCase {\n'
                '    func testA() {\n'
                '        XCTAssertEqual("}", "{") // }\n'
                '        let json = """\n'
                '        {"a": 1}}\n'
                '        """\n'
                '        XCTAssertFalse(json.isEmpty)\n'
                '    }\n'
                '    func testB() {}\n'
                '}\n')
        self.assertEqual(self.heavy_selection(text, 'XCTAssertFalse'), {'M.HeavyTests/testA'})
        self.assertEqual(self.heavy_selection(text, 'func testB'), {'M.HeavyTests/testB'})

    def last_test_then_helper(self, body_line):
        """A class whose last test, testB, holds `body_line`, followed by a helper (the reviewer's reproduction)."""
        return ('final class HeavyTests: XCTestCase {\n'
                '    func testA() {}\n'
                '    func testB() {\n'
                f'{body_line}\n'
                '        XCTAssertTrue(true)\n'
                '    }\n'
                '    private func helper() {\n'
                '        work()\n'
                '    }\n'
                '}\n')

    def helper_selection(self, text, needle):
        lines = text.splitlines()
        users = []
        changed_line = next(index for index, line in enumerate(lines) if needle in line)
        found = JOBS.tests_for_changes(text, {changed_line}, 'M', {'HeavyTests'}, {'HeavyTests'},
                                       lambda name: True, lambda name: users.append(name) or {'N.UserTests'})
        return found, users

    def test_braces_in_nested_interpolations_and_raw_strings_do_not_count(self):
        for body in ('        XCTAssertEqual("\\(xs.map { "{" })", "")',
                     '        XCTAssertEqual("a\\(f("\\(g("{"))"))b", "")',
                     '        let json = #"{"a": "\\"}"#, raw = ##"}"#"##',
                     '        let value = #"\\#(xs.map { "{" })"#'):
            with self.subTest(body=body):
                text = self.last_test_then_helper(body)
                lines = text.splitlines()
                spans = JOBS.test_spans(lines, JOBS.owners(lines, {'HeavyTests'}))
                self.assertEqual(spans[('HeavyTests', 'testB')], range(2, 6))
                self.assertEqual(self.helper_selection(text, 'work()'),
                                 ({'M.HeavyTests', 'N.UserTests'}, ['HeavyTests']))
                self.assertEqual(self.helper_selection(text, 'XCTAssertTrue')[0], {'M.HeavyTests/testB'})

    def test_a_line_the_scanner_cannot_read_makes_the_class_ambiguous(self):
        for body in ('        let text = "{ never closed', '        XCTAssertEqual("\\(f("""', ):
            with self.subTest(body=body):
                text = self.last_test_then_helper(body)
                lines = text.splitlines()
                self.assertEqual(JOBS.test_spans(lines, JOBS.owners(lines, {'HeavyTests'})), {})
                self.assertEqual(self.helper_selection(text, 'XCTAssertTrue'),
                                 ({'M.HeavyTests', 'N.UserTests'}, ['HeavyTests']))

    def test_a_brace_in_a_block_comment_does_not_count(self):
        for body in ('        /* { */', '        /* nested /* { */ } { */',
                     '        /* opens {\n         over lines */'):
            with self.subTest(body=body):
                text = self.last_test_then_helper(body)
                lines = text.splitlines()
                spans = JOBS.test_spans(lines, JOBS.owners(lines, {'HeavyTests'}))
                closing = next(index for index, line in enumerate(lines) if 'XCTAssertTrue' in line) + 1
                self.assertEqual(spans[('HeavyTests', 'testB')], range(2, closing + 1))
                self.assertEqual(self.helper_selection(text, 'work()')[0], {'M.HeavyTests', 'N.UserTests'})
                self.assertEqual(self.helper_selection(text, 'XCTAssertTrue')[0], {'M.HeavyTests/testB'})

    def test_a_closing_brace_away_from_the_func_indentation_makes_the_class_ambiguous(self):
        # A brace that the scanner miscounts would end a span on a line at another indentation, such as the class's
        # closing brace at column 0. Any such span makes the class ambiguous.
        text = ('final class HeavyTests: XCTestCase {\n'
                '    func testA() {\n'
                '        work()\n'
                '      }\n'
                '}\n')
        lines = text.splitlines()
        self.assertEqual(JOBS.test_spans(lines, JOBS.owners(lines, {'HeavyTests'})), {})

    def test_an_ambiguous_span_selects_the_whole_class_and_its_users(self):
        cases = {
            'code after the closing brace': ('final class HeavyTests: XCTestCase {\n'
                                             '    func testA() { work() }; func helper() {}\n'
                                             '    func testB() {\n'
                                             '        work()\n'
                                             '    }\n'
                                             '}\n'),
            'braces that never balance': ('final class HeavyTests: XCTestCase {\n'
                                          '    func testA() {\n'
                                          '        work()\n'
                                          '    func testB() {\n'
                                          '        work()\n'),
            'a test nested in a test': ('final class HeavyTests: XCTestCase {\n'
                                        '    func testA() {\n'
                                        '        func testInner() { work() }\n'
                                        '        testInner()\n'
                                        '    }\n'
                                        '    func testB() {\n'
                                        '        work()\n'
                                        '    }\n'
                                        '}\n'),
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                lines = text.splitlines()
                changed_line = max(index for index, line in enumerate(lines) if 'work()' in line)
                users = []
                found = JOBS.tests_for_changes(text, {changed_line}, 'M', {'HeavyTests'}, {'HeavyTests'},
                                               lambda name: True, lambda name: users.append(name) or {'N.UserTests'})
                self.assertEqual(found, {'M.HeavyTests', 'N.UserTests'})
                self.assertEqual(users, ['HeavyTests'])

    def test_a_change_in_another_class_selects_the_whole_class(self):
        self.assertEqual(select('func testThree'), {'M.LightTests'})
        self.assertEqual(select('final class LightTests'), {'M.LightTests'})
        self.assertEqual(select('@MainActor'), {'M.HeavyTests'})

    def test_imports_blank_lines_and_comments_select_nothing(self):
        self.assertEqual(select('import XCTest', '@testable import'), set())
        lines = TEST_FILE.splitlines()
        blank = {index for index, line in enumerate(lines) if not line.strip()}
        self.assertEqual(JOBS.tests_for_changes(TEST_FILE, blank, 'M', {'HeavyTests'}, set(), lambda name: True,
                                                lambda name: set()), set())

    def test_file_local_support_selects_the_classes_of_its_file(self):
        self.assertEqual(select('private struct LocalFixture'), {'M.HeavyTests', 'M.LightTests'})
        self.assertEqual(select('let value = 2', used_elsewhere=lambda name: False), {'M.HeavyTests', 'M.LightTests'})

    def test_shared_support_needs_the_full_suite(self):
        self.assertIsNone(select('let value = 2'))

    def test_a_change_outside_the_test_methods_of_a_class_also_selects_its_users(self):
        users = {'HeavyTests': {'N.CallerTests'}, 'LightTests': {'N.OtherTests'}}
        asked = []

        def lookup(name):
            asked.append(name)
            return users[name]

        self.assertEqual(select('private func helper', users=lookup), {'M.HeavyTests', 'N.CallerTests'})
        self.assertEqual(select('final class LightTests', users=lookup), {'M.LightTests', 'N.OtherTests'})
        asked.clear()
        # A change inside a test method cannot reach another class, so it asks for no users.
        self.assertEqual(select('XCTAssertEqual(2, 2)', 'func testThree', users=lookup),
                         {'M.HeavyTests/testTwo', 'M.LightTests'})
        self.assertEqual(asked, [])
        self.assertIsNone(select('private func helper', users=lambda name: None))

    def test_the_weights_name_existing_core_test_classes_and_methods(self):
        # A weights change runs no Mac job, so a stale or misspelled name must fail here instead.
        document = json.loads((ROOT / JOBS.WEIGHTS).read_text())
        self.assertEqual(set(document), {'source', 'weights', 'methods'})
        self.assertIsInstance(document['source'], str)
        methods = {}
        for path in (ROOT / JOBS.CORE_TESTS).rglob('*.swift'):
            text = path.read_text()
            for test_class in JOBS.TEST_CLASS.findall(text):
                methods.setdefault(test_class, set()).update(name for _, name in JOBS.TEST_METHOD.findall(text))
        for test_class, seconds in document['weights'].items():
            with self.subTest(test_class=test_class):
                self.assertIn(test_class, methods)
                self.assertIsInstance(seconds, (int, float))
                self.assertGreaterEqual(seconds, 0)
        for test_class, table in document['methods'].items():
            with self.subTest(test_class=test_class):
                self.assertIn(test_class, document['weights'])
                for method, seconds in table.items():
                    self.assertIn(method, methods[test_class])
                    self.assertIsInstance(seconds, (int, float))
                    self.assertGreaterEqual(seconds, 0)

    def test_a_weights_change_alone_selects_no_core_tests_and_no_release_build(self):
        self.assertEqual(JOBS.select([JOBS.WEIGHTS]), set())
        self.assertIsNone(JOBS.release_reason([JOBS.WEIGHTS]))

    def test_the_smoke_classes_are_weighted_core_classes_that_need_no_app(self):
        weights = json.loads((ROOT / JOBS.WEIGHTS).read_text())['weights']
        for name in JOBS.SMOKE_CLASSES:
            with self.subTest(name=name):
                module, test_class = name.split('.')
                self.assertEqual(module, 'RemozioCoreTests')
                self.assertLess(weights[test_class], 10)
                self.assertTrue((ROOT / f'macos/core/Tests/RemozioCoreTests/{test_class}.swift').is_file())
        self.assertLess(JOBS.estimate(JOBS.SMOKE_CLASSES, json.loads((ROOT / JOBS.WEIGHTS).read_text())), 60)

    def test_pull_request_merges_choose_full_selected_or_no_core_tests(self):
        with tempfile.TemporaryDirectory() as directory, working_directory(directory):
            repository = GitRepository(directory)
            core = 'macos/core/Tests/RemozioCoreTests/'
            repository.write(core + 'HeavyTests.swift', TEST_FILE)
            repository.write(core + 'Other.swift', 'func useShared() { _ = SharedFixture() }\n')
            repository.write('macos/core/Sources/A.swift', 'let a = 1\n')
            repository.write('macos/app/App/A.swift', 'let a = 1\n')
            repository.write('android/A.kt', 'class A\n')
            repository.commit('base')
            cases = {
                'test-method': ((core + 'HeavyTests.swift', TEST_FILE.replace('(2, 2)', '(2, 3)')),
                                ('selected', ['RemozioCoreTests.HeavyTests'])),
                'new-test-file': ((core + 'NewTests.swift', 'import XCTest\nfinal class NewTests: XCTestCase {\n'
                                   '    func testNew() {}\n}\n'), ('selected', ['RemozioCoreTests.NewTests'])),
                'core-source': (('macos/core/Sources/A.swift', 'let a = 2\n'),
                                ('selected', sorted(JOBS.SMOKE_CLASSES))),
                'shared-support': ((core + 'HeavyTests.swift', TEST_FILE.replace('value = 2', 'value = 3')),
                                   ('full', [])),
                'fixture': ((core + 'Fixtures/tls/cert.pem', 'pem\n'), ('full', [])),
                'package': (('macos/core/Package.resolved', '{}\n'), ('full', [])),
                'script': (('scripts/check.sh', 'true\n'), ('full', [])),
                'gradle': (('gradle.properties', 'a=b\n'), ('selected', sorted(JOBS.SMOKE_CLASSES))),
            }
            for branch, ((path, text), expected) in cases.items():
                with self.subTest(branch=branch):
                    repository.git('switch', '--quiet', '-c', branch, 'main')
                    repository.write(path, text)
                    repository.commit(branch)
                    base, merge = repository.merge(branch)
                    paths = [name for name in JOBS.changed_paths(merge) if name != 'README.md']
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(JOBS.core_test_plan(paths, base, merge), expected)

            repository.git('switch', '--quiet', '-c', 'app-only', 'main')
            repository.write('macos/app/App/A.swift', 'let a = 2\n')
            repository.commit('app')
            repository.merge('app-only')
            output = Path(directory) / 'output'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(JOBS.main(['--merge-commit', 'HEAD', '--github-output', str(output)]), 0)
            values = dict(line.split('=', 1) for line in output.read_text().splitlines())
            self.assertEqual(values['mac'], 'true')
            self.assertEqual(values['mac_core'], 'false')
            self.assertEqual(values['android'], 'false')
            self.assertEqual(values['mac_release'], 'true')

            output.unlink()  # Otherwise the next commit would add it, and as a top-level file it runs every job.
            repository.git('switch', '--quiet', '-c', 'core-only', 'main')
            repository.write('macos/core/Sources/A.swift', 'let a = 3\n')
            repository.commit('core')
            repository.merge('core-only')
            with tempfile.TemporaryDirectory() as elsewhere, contextlib.redirect_stdout(io.StringIO()) as printed:
                output = Path(elsewhere) / 'output'
                self.assertEqual(JOBS.main(['--merge-commit', 'HEAD', '--github-output', str(output)]), 0)
                values = dict(line.split('=', 1) for line in output.read_text().splitlines())
            self.assertIn('Mac build: Debug app only', printed.getvalue())
            self.assertEqual((values['mac'], values['mac_core'], values['mac_release']), ('true', 'true', 'false'))

    def test_a_helper_change_selects_the_classes_that_call_it_from_other_files(self):
        heavy = ('import XCTest\nfinal class HeavyTests: XCTestCase {\n    static func withFixture() -> Int { 1 }\n\n'
                 '    func testOne() { XCTAssertEqual(Self.withFixture(), 1) }\n}\n')
        caller = ('import XCTest\nfinal class CallerTests: XCTestCase {\n'
                  '    func testCalls() { XCTAssertEqual(HeavyTests.withFixture(), 1) }\n}\n')
        middle = ('import XCTest\nfinal class MiddleTests: XCTestCase {\n'
                  '    static func viaHeavy() -> Int { HeavyTests.withFixture() }\n\n'
                  '    func testMiddle() { XCTAssertEqual(Self.viaHeavy(), 1) }\n}\n')
        far = ('import XCTest\nfinal class FarTests: XCTestCase {\n'
               '    func testFar() { XCTAssertEqual(MiddleTests.viaHeavy(), 1) }\n}\n')
        unrelated = 'import XCTest\nfinal class UnrelatedTests: XCTestCase {\n    func testAlone() {}\n}\n'
        commented = ('import XCTest\n// HeavyTests covers the fixture.\nfinal class NoteTests: XCTestCase {\n'
                     '    func testNote() {}\n}\n')
        core = 'macos/core/Tests/RemozioCoreTests/'
        with tempfile.TemporaryDirectory() as directory, working_directory(directory):
            repository = GitRepository(directory)
            for name, text in (('HeavyTests', heavy), ('CallerTests', caller), ('MiddleTests', middle),
                               ('FarTests', far), ('UnrelatedTests', unrelated), ('NoteTests', commented)):
                repository.write(f'{core}{name}.swift', text)
            repository.commit('base')
            cases = {
                'helper': (heavy.replace('{ 1 }', '{ 2 }'),
                           ['RemozioCoreTests.CallerTests', 'RemozioCoreTests.FarTests',
                            'RemozioCoreTests.HeavyTests', 'RemozioCoreTests.MiddleTests']),
                # Each branch starts from main, which already holds the merged helper change.
                'test-body': (heavy.replace('{ 1 }', '{ 2 }').replace('Self.withFixture(), 1', 'Self.withFixture(), 2'),
                              ['RemozioCoreTests.HeavyTests']),
            }
            for branch, (text, expected) in cases.items():
                with self.subTest(branch=branch):
                    repository.git('switch', '--quiet', '-c', branch, 'main')
                    repository.write(core + 'HeavyTests.swift', text)
                    repository.commit(branch)
                    base, merge = repository.merge(branch)
                    paths = [name for name in JOBS.changed_paths(merge) if name != 'README.md']
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(JOBS.core_test_plan(paths, base, merge), ('selected', expected))

            # Shared support outside a test class that names the class could reach any test, so the suite runs in full.
            repository.git('switch', '--quiet', 'main')
            repository.write(core + 'Support.swift', 'func shared() -> Int { HeavyTests.withFixture() }\n')
            repository.write(core + 'UnrelatedTests.swift', unrelated.replace('{}', '{ _ = shared() }'))
            repository.commit('support')
            repository.git('switch', '--quiet', '-c', 'through-support', 'main')
            repository.write(core + 'HeavyTests.swift', heavy.replace('{ 1 }', '{ 3 }'))
            repository.commit('through-support')
            base, merge = repository.merge('through-support')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(JOBS.core_test_plan([core + 'HeavyTests.swift'], base, merge), ('full', []))

    def test_a_commit_that_is_not_a_merge_runs_everything_in_full(self):
        with tempfile.TemporaryDirectory() as directory, working_directory(directory):
            repository = GitRepository(directory)
            repository.write('android/A.kt', 'class A\n')
            repository.commit('base')
            output = Path(directory) / 'output'
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(JOBS.main(['--merge-commit', 'HEAD', '--github-output', str(output)]), 0)
            self.assertIn('::warning::', printed.getvalue())
            values = dict(line.split('=', 1) for line in output.read_text().splitlines())
            self.assertEqual({job: values[job] for job in JOBS.JOBS}, {job: 'true' for job in JOBS.JOBS})
            self.assertEqual((values['mac_core_mode'], values['mac_core_parts'], values['mac_core_tests']),
                             ('full', '[1, 2]', ''))
            self.assertEqual(values['mac_release'], 'true')

    def test_all_selects_every_job_and_the_full_suite_on_two_runners(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(JOBS.main(['--all', '--github-output', str(output)]), 0)
            values = dict(line.split('=', 1) for line in output.read_text().splitlines())
            self.assertEqual(values['mac_core_mode'], 'full')
            self.assertEqual(values['mac_core_parts'], '[1, 2]')
            self.assertEqual(values['mac_release'], 'true')
            self.assertTrue(all(values[job] == 'true' for job in JOBS.JOBS))


if __name__ == '__main__':
    unittest.main()
