#!/usr/bin/env python3
"""Choose the Checks jobs that a pull request needs, and the macos/core tests that it runs, from the paths it changes.

Jobs. Each job runs when the pull request changes a path that the job builds or tests. A path that no rule below
claims runs every job: scripts/, .github/, gradle/, third-party/, protocol/ outside its Kotlin and Swift packages,
and every top-level file except Markdown files and LICENSE. The Python checks job is not listed: it runs on every
pull request.

macos/core tests. The Mac core tests job runs in one of two modes.
- full: every class except the app-dependent ones, in six shards on two runners. A pull request gets this mode when it
  changes a path that runs every job, a Package.swift or Package.resolved file, a file under macos/core/Tests that is
  not Swift (fixtures), Swift code under macos/core/Tests outside an XCTestCase class (shared test support), or a
  file that a core test reads from outside macos/core (CORE_TEST_INPUTS).
- selected: only the XCTestCase classes whose code the pull request adds or changes under macos/core/Tests. For a
  heavy class (METHOD_LEVEL_SECONDS or more in the weights file, or split there under "methods"), only the test
  methods whose bodies change, unless a change falls outside every test method of the class. A change to a private
  or fileprivate top-level declaration in a test file selects every class of that file. A change to the
  macos/core, protocol/swift or host sources adds the fixed SMOKE_CLASSES. Import, blank and comment lines select
  nothing. A change to the Gradle build alone runs only the smoke classes. A selection estimated above
  TWO_RUNNER_SECONDS runs on two runners.

Pushes to main, the nightly run and manual runs select every job and the full mode (--all), so the nightly run of the
full matrix catches an input or a test that the rules here miss. Every mode still builds every macos/core test.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
JOBS = ('linux', 'mac', 'mac_experiments', 'mac_core', 'mac_interop', 'ios', 'kotlin', 'android')
EVERY_JOB = frozenset(JOBS)
# Gradle builds :phone-core for the Linux pairing tool and interoperability tests, and :phone-ui for the iOS app.
KOTLIN = frozenset({'linux', 'mac_interop', 'ios', 'kotlin', 'android'})
# macos/core depends on host/shared-core and protocol/swift; the Linux job tests both packages.
SHARED_SWIFT = frozenset({'linux', 'mac', 'mac_experiments', 'mac_core', 'mac_interop'})
# experiments/macos and experiments/approval-flow depend on macos/core; the app depends on it too.
MACOS_CORE = frozenset({'mac', 'mac_experiments', 'mac_core', 'mac_interop'})
# The rest of macos/ is the app and macos/ui-adapters, which the experiments part of scripts/check.sh tests.
MACOS = frozenset({'mac', 'mac_experiments', 'mac_interop'})
# The Mac build signs a release experiment, the experiments part builds most of them, the interoperability job builds
# experiments/approval-flow, and the Linux job builds the Linux pairing peer and TPM provider probe.
EXPERIMENTS = frozenset({'linux', 'mac', 'mac_experiments', 'mac_interop'})
# The Mac experiments part of scripts/check.sh also runs the repository and PR watcher Python tests on macOS.
PYTHON_TESTS = frozenset({'mac_experiments'})
# macos/core tests compile these files from outside the package (CommandMonitor*Tests, MachCommandCallerReceiverTests
# and NativeStdioLayoutTests). Tests that read protocol/vectors are covered because protocol/ runs every job.
CORE_TEST_INPUTS = ('macos/app/CommandMonitor/', 'experiments/command-frontend/')

PREFIXES = (
    ('docs/', frozenset()),
    ('protocol/kotlin/', KOTLIN),
    ('phone/', KOTLIN),
    ('tools/', KOTLIN),
    ('android/', frozenset({'android'})),
    ('ios/', frozenset({'ios'})),
    ('.maestro/', frozenset({'ios'})),
    ('protocol/swift/', SHARED_SWIFT),
    ('host/', SHARED_SWIFT),
    ('macos/core/', MACOS_CORE),
    *((prefix, (MACOS if prefix.startswith('macos/') else EXPERIMENTS) | {'mac_core'}) for prefix in CORE_TEST_INPUTS),
    ('macos/', MACOS),
    ('experiments/', EXPERIMENTS),
    ('tests/', PYTHON_TESTS),
    ('.agents/', PYTHON_TESTS),
)
# A package manifest or lockfile can change what any Swift build resolves, wherever it lives.
SWIFT_PACKAGE_FILES = ('Package.swift', 'Package.resolved')

CORE_TESTS = 'macos/core/Tests/'
# The Gradle build runs every job, but no Swift build reads it, so it runs the macos/core smoke classes only.
GRADLE_BUILD = ('gradle/', 'gradlew', 'gradlew.bat', 'gradle.properties', 'build.gradle.kts', 'settings.gradle.kts')
# A selection that the weights file estimates above this many seconds runs in six shards on two runners, as the full
# suite does. One runner would take about a third of it after the build; two take about a sixth.
TWO_RUNNER_SECONDS = 600.0
CORE_SOURCES = ('macos/core/', 'protocol/swift/', 'host/')
WEIGHTS = '.github/macos-core-test-weights.json'
METHOD_LEVEL_SECONDS = 60.0
# Fast classes from different areas of macos/core: journals, the gateway database, approval delivery, pairing setup,
# command streams and the authority service. Together they took about 25 s in CI (the weights file).
SMOKE_CLASSES = (
    'RemozioCoreTests.AuthorityJournalTests',
    'RemozioCoreTests.CheckpointedJournalTests',
    'RemozioCoreTests.GatewayDatabaseTests',
    'RemozioCoreTests.ApprovalRelayCoordinatorTests',
    'RemozioCoreTests.DirectApprovalRequestDeliveryTests',
    'RemozioCoreTests.AuthorityPairingSetupTests',
    'RemozioCoreTests.CommandStreamSourceTests',
    'RemozioCoreTests.AuthorityServiceRunnerTests',
)

DECLARATION = re.compile(r'(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:final|private|fileprivate|internal|public|open)\s+)*'
                         r'(class|struct|enum|actor|extension|protocol|func|let|var|typealias)\s+(\w+)(.*)')
TEST_CLASS = re.compile(r'^(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:final|public|open)\s+)*class\s+(\w+)\s*:\s*XCTestCase\b',
                        re.MULTILINE)
TEST_METHOD = re.compile(r'(\s+)func (test\w+)\s*\(')
HUNK = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', re.MULTILINE)


def jobs_for(path):
    """The jobs that one changed repository path needs."""
    if '/' not in path:
        return frozenset() if path.endswith('.md') or path == 'LICENSE' else EVERY_JOB
    jobs = next((jobs for prefix, jobs in PREFIXES if path.startswith(prefix)), EVERY_JOB)
    if PurePosixPath(path).name in SWIFT_PACKAGE_FILES:
        jobs |= SHARED_SWIFT | {'ios'}
    return jobs


def select(paths):
    selected = set()
    for path in paths:
        selected |= jobs_for(path)
    return selected


def owners(lines, test_classes):
    """For each line, its top-level owner: ('class', name) for an XCTestCase class or its extension, ('file', name)
    for a private or fileprivate declaration, ('import', None), or ('other', name) for anything else.

    A top-level declaration starts at column 0 and owns the lines up to the next one. An attribute line such as
    @MainActor belongs to the declaration below it. Text at column 0 inside a multi-line string literal looks like
    a new declaration, which makes the rest of the file 'other': that can only select more tests, never fewer.
    """
    result, current, pending = [], ('other', None), []
    for line in lines:
        stripped = line.strip()
        top_level = stripped and not line[0].isspace() and not stripped.startswith(('}', ')', ']', '//', '/*', '*'))
        if top_level and re.fullmatch(r'@\w+(?:\([^)]*\))?', stripped):
            pending.append(len(result))
            result.append(None)
            continue
        if top_level:
            match = DECLARATION.match(stripped)
            if stripped.startswith(('import ', '@testable import ')):
                current = ('import', None)
            elif match and match[1] == 'class' and re.match(r'\s*:\s*XCTestCase\b', match[3]):
                current = ('class', match[2])
            elif match and match[1] == 'extension' and match[2] in test_classes:
                current = ('class', match[2])
            elif match and re.match(r'(?:@\w+(?:\([^)]*\))?\s+)*(?:private|fileprivate)\s', stripped):
                current = ('file', match[2])
            else:
                current = ('other', match[2] if match else None)
            for index in pending:
                result[index] = current
            pending = []
        result.append(current)
    for index in pending:
        result[index] = ('other', None)
    return result


def test_spans(lines, line_owners):
    """Map (class, test method) to its line range, from `func testX(` to the closing brace at the same indentation."""
    spans = {}
    for start, line in enumerate(lines):
        match = TEST_METHOD.match(line)
        if not match or line_owners[start][0] != 'class':
            continue
        end = next((index for index in range(start + 1, len(lines)) if lines[index].rstrip() == match[1] + '}'),
                   start)
        spans[(line_owners[start][1], match[2])] = range(start, end + 1)
    return spans


def tests_for_changes(text, changed, module, test_classes, method_level, used_elsewhere):
    """The Module.Class and Module.Class/method names that the changed lines (0-based) of one test file select.

    A change to a top-level declaration that only this file can use selects every test class of the file: a private
    or fileprivate one, or one whose name no other test file mentions (`used_elsewhere(name)` is false). Returns None
    when a change needs the full suite: other code outside the XCTestCase classes, which other test files share.
    """
    lines = text.splitlines()
    line_owners = owners(lines, test_classes)
    spans = test_spans(lines, line_owners)
    whole, methods = set(), set()
    for index in sorted(changed):
        if not 0 <= index < len(lines):
            continue
        stripped = lines[index].strip()
        kind, name = line_owners[index]
        if not stripped or stripped.startswith(('//', '/*', '*')) or kind == 'import':
            continue
        if kind == 'file' or (kind == 'other' and name and not used_elsewhere(name)):
            whole |= {owner for kind, owner in line_owners if kind == 'class'}
            continue
        if kind != 'class':
            return None
        if name in method_level:
            method = next((test for (owner, test), span in spans.items() if owner == name and index in span), None)
            if method:
                methods.add((name, method))
                continue
        whole.add(name)
    return ({f'{module}.{name}' for name in whole}
            | {f'{module}.{name}/{method}' for name, method in methods if name not in whole})


def git(*arguments):
    return subprocess.run(['git', *arguments], text=True, capture_output=True, check=True).stdout


def changed_lines(base, merge_commit, path):
    """0-based lines of `path` at the merge commit that the diff adds or changes, and the lines around a deletion."""
    lines = set()
    for match in HUNK.finditer(git('diff', '-U0', '--no-renames', base, merge_commit, '--', path)):
        start, count = int(match[1]), int(match[2] if match[2] is not None else 1)
        lines |= set(range(start - 1, start - 1 + count)) if count else {start - 1, start}
    return lines


def core_test_plan(paths, base, merge_commit):
    """('full', []) or ('selected', sorted names) for the macos/core tests of a pull request. See the module doc."""
    def full(path, reason):
        print(f'macos/core tests: full suite, because {path} {reason}')
        return 'full', []

    weights = json.loads((ROOT / WEIGHTS).read_text())
    method_level = set(weights.get('methods', {})) | {
        name for name, seconds in weights['weights'].items() if seconds >= METHOD_LEVEL_SECONDS}
    test_classes = None
    names, smoke = set(), False
    for path in paths:
        if path.startswith(GRADLE_BUILD):
            smoke = True
            continue
        if jobs_for(path) == EVERY_JOB:
            return full(path, 'is an input of every job')
        if PurePosixPath(path).name in SWIFT_PACKAGE_FILES:
            return full(path, 'is a Swift package manifest or lockfile')
        if path.startswith(CORE_TEST_INPUTS):
            return full(path, 'is compiled by macos/core tests')
        if path.startswith(CORE_TESTS):
            if not path.endswith('.swift'):
                return full(path, 'is a test fixture')
            if subprocess.run(['git', 'cat-file', '-e', f'{merge_commit}:{path}'], capture_output=True).returncode:
                continue  # A deleted test file runs nothing; the build still compiles every remaining test.
            if test_classes is None:
                test_classes = set(TEST_CLASS.findall(git('grep', '-h', '-F', 'XCTestCase', merge_commit, '--',
                                                          CORE_TESTS)))
            module = PurePosixPath(path).relative_to(CORE_TESTS).parts[0]

            def used_elsewhere(name, path=path):
                mentions = subprocess.run(['git', 'grep', '-l', '-w', '-F', name, merge_commit, '--', CORE_TESTS],
                                          text=True, capture_output=True).stdout.split()
                return any(mention != f'{merge_commit}:{path}' for mention in mentions)

            found = tests_for_changes(git('show', f'{merge_commit}:{path}'), changed_lines(base, merge_commit, path),
                                      module, test_classes, method_level, used_elsewhere)
            if found is None:
                return full(path, 'changes test code outside an XCTestCase class')
            names |= found
        elif path.startswith(CORE_SOURCES):
            smoke = True
    if smoke:
        names |= set(SMOKE_CLASSES)
    return 'selected', sorted(names)


def estimate(names, document):
    """Seconds that the selected names take by the weights file; an unknown test counts as the median class."""
    weights, methods = document['weights'], document.get('methods', {})
    known = sorted(weights.values())
    default = known[len(known) // 2] if known else 1.0
    total = 0.0
    for name in names:
        test_class, _, method = name.partition('.')[2].partition('/')
        if not method:
            table = methods.get(test_class)
            total += sum(table.values()) if table else weights.get(test_class, default)
        else:
            total += methods.get(test_class, {}).get(method, default)
    return total


def merge_parents(merge_commit):
    parents = git('rev-list', '--parents', '-n', '1', merge_commit).split()[1:]
    if len(parents) != 2:
        raise ValueError(f'{merge_commit} is not a merge commit with two parents ({len(parents)} found)')
    return parents


def changed_paths(merge_commit):
    """Paths that a pull request merge commit changes against its first parent, the base it was merged onto.

    Both sides of a rename count, so moving a file out of a job's inputs still runs that job.
    """
    base = merge_parents(merge_commit)[0]
    return [name for name in git('diff', '--name-only', '--no-renames', '-z', base, merge_commit).split('\0') if name]


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--merge-commit', help='the pull request merge commit that actions/checkout checked out')
    source.add_argument('--all', action='store_true', help='select every job and the full macos/core suite')
    parser.add_argument('--github-output', help='append the outputs as name=value lines to this file')
    args = parser.parse_args(argv)

    selected, mode, tests = set(JOBS), 'full', []
    if not args.all:
        try:
            base = merge_parents(args.merge_commit)[0]
            paths = changed_paths(args.merge_commit)
            for path in paths:
                print(f'{path}: {", ".join(sorted(jobs_for(path))) or "Python checks only"}')
            selected = select(paths)
            if 'mac_core' in selected:
                mode, tests = core_test_plan(paths, base, args.merge_commit)
                if mode == 'selected' and not tests:
                    print('macos/core tests: the changes select no test, so the Mac core tests job does not run')
                    selected.discard('mac_core')
        except (subprocess.CalledProcessError, ValueError) as error:
            detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
            print(f'::warning::Could not read the pull request changes, so every job runs in full: {detail}',
                  flush=True)
            selected, mode, tests = set(JOBS), 'full', []
    outputs = {job: 'true' if job in selected else 'false' for job in JOBS}
    two_runners = mode == 'full' or estimate(tests, json.loads((ROOT / WEIGHTS).read_text())) > TWO_RUNNER_SECONDS
    outputs['mac_core_mode'] = mode
    # Two parts run shards 0-2 and 3-5 of six, one per runner; one part runs three shards on one runner.
    outputs['mac_core_parts'] = '[1, 2]' if two_runners else '[1]'
    outputs['mac_core_tests'] = ','.join(tests)
    lines = [f'{name}={value}' for name, value in outputs.items()]
    print('\n'.join(lines))
    if args.github_output:
        with open(args.github_output, 'a') as handle:
            handle.write(''.join(f'{line}\n' for line in lines))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
