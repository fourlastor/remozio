#!/usr/bin/env python3
"""Choose the Checks jobs that a pull request needs, and the macos/core tests that it runs, from the paths it changes.

Jobs. Each job runs when the pull request changes a path that the job builds or tests. A path that no rule below
claims runs every job: scripts/, .github/, gradle/, third-party/, protocol/ outside its Kotlin and Swift packages,
and every top-level file except Markdown files and LICENSE. The Python checks job is not listed: it runs on every
pull request. The macos/core test weights file (WEIGHTS) runs no job by itself: it changes only how the shards split
the tests and which classes run at method level, never which tests exist, and the Python checks validate its names.

macos/core tests. The Mac core tests job runs in one of two modes.
- full: every class except the app-dependent ones, in six shards on two runners. A pull request gets this mode when it
  changes a path that runs every job, a Package.swift or Package.resolved file, a file under macos/core/Tests that is
  not Swift (fixtures), Swift code under macos/core/Tests outside an XCTestCase class that other files share (shared
  test support), a test class that such shared support names, or a file that a core test reads from outside
  macos/core (CORE_TEST_INPUTS).
- selected: only the XCTestCase classes whose code the pull request adds or changes under macos/core/Tests. For a
  heavy class (METHOD_LEVEL_SECONDS or more in the weights file, or split there under "methods"), only the test
  methods whose bodies change, unless a change falls outside every test method of the class. A change outside the
  test methods of a class, such as a helper, also selects its users: every test class in another file that names
  it, and in turn the users of a class that names it outside its own test methods. A change to a private or
  fileprivate top-level declaration in a test file, or to one that no other file names, selects every class of
  that file. A change to the
  macos/core, protocol/swift or host sources adds the fixed SMOKE_CLASSES. Import, blank and comment lines select
  nothing. A change to the Gradle build alone runs only the smoke classes. A selection estimated above
  TWO_RUNNER_SECONDS runs on two runners.

Pushes to main, the nightly run and manual runs select every job and the full mode (--all), so the nightly run of the
full matrix catches an input or a test that the rules here miss. Every mode still builds every macos/core test.

Release app. The Mac build job builds and inspects the Debug app on every run. A pull request also builds the
Release app (mac_release) only when it changes a Release input that the Debug build does not check: the app under
macos/app (its project, Info.plists and `#if DEBUG` code), the release-signing experiment that signs the Release app
(RELEASE_INPUTS), a Swift package manifest or lockfile, or a path that runs every job other than the Gradle build.
It also builds the Release app when the diff of a Swift source under CORE_SOURCES, outside a Tests directory, adds or
removes a compiler directive line (#if, #elseif, #else, #endif) or a line that names DEBUG: SwiftPM debug builds
define DEBUG, so only the Release app compiles the other branch.
The release manifest declarations do not depend on the configuration, so the Debug app checks them against the
compiled contracts of a macos/core change. A Release-only failure that the rules here miss fails the next push to
main or the nightly run, which always build both configurations.

Verification. The last job of the workflow, Selected checks, runs --verify-needs on the results of every other job.
It passes only when the selection succeeded, the Python checks passed, each selected job passed, and each job that
was not selected was skipped. The PR watcher requires that one check, because the names and the number of the
other checks change with the selection.
"""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
JOBS = ('linux', 'mac', 'mac_experiments', 'mac_core', 'mac_interop', 'ios', 'kotlin', 'android')
# The workflow job that each selection output gates.
WORKFLOW_JOBS = {'linux-protocol': 'linux', 'mac': 'mac', 'mac-experiments': 'mac_experiments', 'mac-core': 'mac_core',
                 'mac-interop': 'mac_interop', 'ios': 'ios', 'kotlin': 'kotlin', 'android': 'android'}
EVERY_JOB = frozenset(JOBS)
# Gradle builds :phone-core for the Linux pairing tool and interoperability tests, and :phone-ui for the iOS app.
KOTLIN = frozenset({'linux', 'mac_interop', 'ios', 'kotlin', 'android'})
# macos/core depends on host/shared-core and protocol/swift; the Linux job tests both packages.
SHARED_SWIFT = frozenset({'linux', 'mac', 'mac_experiments', 'mac_core', 'mac_interop'})
# experiments/macos and experiments/approval-flow depend on macos/core; the app depends on it too.
MACOS_CORE = frozenset({'mac', 'mac_experiments', 'mac_core', 'mac_interop'})
# The rest of macos/ is the app and macos/ui-adapters, which the experiments part of scripts/check.sh tests.
MACOS = frozenset({'mac', 'mac_experiments', 'mac_interop'})
# The experiments part builds most of them, the interoperability job builds experiments/approval-flow, and the Linux
# job builds the Linux pairing peer and TPM provider probe. The Mac build reads only experiments/release-signing.
EXPERIMENTS = frozenset({'linux', 'mac_experiments', 'mac_interop'})
RELEASE_SIGNING = 'experiments/release-signing/'
# A pull request that changes one of these, beyond the paths that run every job, builds the Release app too.
RELEASE_INPUTS = ('macos/app/', RELEASE_SIGNING)
# The Mac experiments part of scripts/check.sh also runs the repository and PR watcher Python tests on macOS.
PYTHON_TESTS = frozenset({'mac_experiments'})
# macos/core tests compile these files from outside the package (CommandMonitor*Tests, MachCommandCallerReceiverTests
# and NativeStdioLayoutTests). Tests that read protocol/vectors are covered because protocol/ runs every job.
CORE_TEST_INPUTS = ('macos/app/CommandMonitor/', 'experiments/command-frontend/')

PREFIXES = (
    ('docs/', frozenset()),
    ('.github/macos-core-test-weights.json', frozenset()),
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
    (RELEASE_SIGNING, EXPERIMENTS | {'mac'}),
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


# A line that starts or ends a conditional compilation block, or that names the DEBUG condition.
CONDITIONAL_LINE = re.compile(r'^\s*#\s*(?:if|elseif|else|endif)\b|DEBUG')


def conditional_change(diff):
    """The first added or removed line of a unified diff that is a compiler directive or names DEBUG, or None."""
    for line in diff.splitlines():
        if line.startswith(('+++ ', '--- ')) or not line.startswith(('+', '-')):
            continue
        if CONDITIONAL_LINE.search(line[1:]):
            return line
    return None


def core_swift_source(path):
    return (path.startswith(CORE_SOURCES) and path.endswith('.swift')
            and 'Tests' not in PurePosixPath(path).parts[:-1])


def release_reason(paths, base=None, merge_commit=None):
    """Why a pull request also builds the Release app, or None when the Debug app checks everything it changes.

    With `base` and `merge_commit`, a conditional compilation change in a core Swift source counts too.
    """
    if base is not None:
        sources = [path for path in paths if core_swift_source(path)]
        for path in sources:
            line = conditional_change(git('diff', '-U0', '--no-renames', base, merge_commit, '--', path))
            if line:
                return f'{path} changes conditional compilation that only the Release build compiles ({line.strip()})'
    for path in paths:
        if path.startswith(RELEASE_INPUTS):
            return f'{path} is an input of the app or of the Release signing check'
        if PurePosixPath(path).name in SWIFT_PACKAGE_FILES:
            return f'{path} is a Swift package manifest or lockfile'
        if jobs_for(path) == EVERY_JOB and not path.startswith(GRADLE_BUILD):
            return f'{path} is an input of every job'
    return None


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


def code_only(lines):
    """Each line without string literal contents and comments, and the indexes of the lines it could not read.

    It removes // comments, nested /* */ comments over any number of lines, and the contents of string literals, so
    that their braces do not count: "...", raw #"..."# with any number of #, and multi-line literals in triple
    quotes, raw or not.
    It follows interpolations, including ones that hold nested strings. A line that it cannot read, such as a
    one-line string that does not end on its line, loses the rest of its code and is reported as unsure. This is a
    small scanner, not a Swift parser: test_spans treats a method with an unsure line as ambiguous.
    """
    result, unsure, comment, block = [], set(), 0, None
    for number, line in enumerate(lines):
        code, index = [], 0
        while index < len(line):
            raw = RAW_STRING_START.match(line, index)
            if comment:
                if line.startswith('/*', index):
                    comment, index = comment + 1, index + 2
                elif line.startswith('*/', index):
                    comment, index = comment - 1, index + 2
                else:
                    index += 1
            elif block:
                found = line.find(block, index)
                if found < 0:
                    break
                block, index = None, found + len(block)
            elif line.startswith('/*', index):
                comment, index = 1, index + 2
            elif line.startswith('//', index):
                break
            elif raw or line[index] == '"':
                hashes = raw[1] if raw else ''
                opening = raw[0] if raw else '"'
                if line.startswith(hashes + '"""', index):
                    block, index = '"""' + hashes, index + len(hashes) + 3
                    continue
                index = string_end(line, index + len(opening), len(hashes))
                if index is None:
                    unsure.add(number)
                    break
            else:
                code.append(line[index])
                index += 1
        result.append(''.join(code))
    return result, unsure


RAW_STRING_START = re.compile(r'(#+)"')


def string_end(line, index, hashes=0):
    """The index after the end of a one-line string whose contents start at `index`, or None when it does not end.

    `hashes` is the number of # around a raw string. An interpolation is skipped up to its closing parenthesis, and
    the strings nested in it are skipped the same way.
    """
    close, escape = '"' + '#' * hashes, '\\' + '#' * hashes
    while index < len(line):
        if line.startswith(escape + '(', index):
            index = interpolation_end(line, index + len(escape) + 1)
            if index is None:
                return None
        elif line.startswith(escape, index):
            index += len(escape) + 1
        elif line.startswith(close, index):
            return index + len(close)
        else:
            index += 1
    return None


def interpolation_end(line, index):
    """The index after the parenthesis that closes an interpolation whose code starts at `index`, or None."""
    depth = 1
    while index < len(line):
        raw = RAW_STRING_START.match(line, index)
        if line.startswith('"""', index) or (raw and line.startswith(raw[1] + '"""', index)):
            return None
        if raw or line[index] == '"':
            index = string_end(line, index + (len(raw[0]) if raw else 1), len(raw[1]) if raw else 0)
            if index is None:
                return None
            continue
        depth += {'(': 1, ')': -1}.get(line[index], 0)
        index += 1
        if not depth:
            return index
    return None


def test_spans(lines, line_owners):
    """Map (class, test method) to its lines, from `func testX(` to the brace that closes its body.

    The body ends where the braces opened on the func line balance again, which also handles a test on one line.
    A class gets no spans at all when one of its spans is ambiguous: the braces never balance, code follows the
    closing brace on its line, the closing brace of a longer method is not alone at the func line's indentation,
    the method has a line that code_only could not read, or two spans overlap. Every change in that class then counts
    as outside its test methods, which selects the whole class and its users instead of a guessed method.
    """
    code, unsure = code_only(lines)
    spans, ambiguous = {}, set()
    for start, line in enumerate(lines):
        match = TEST_METHOD.match(line)
        if not match or line_owners[start][0] != 'class':
            continue
        test_class, end, depth, opened = line_owners[start][1], None, 0, False
        for index in range(start, len(lines)):
            for position, char in enumerate(code[index]):
                if char == '{':
                    depth, opened = depth + 1, True
                elif char == '}':
                    depth -= 1
                    if depth < 0 or (opened and depth == 0):
                        end = index if depth == 0 and not code[index][position + 1:].strip() else None
                        break
            if end is not None or depth < 0 or (opened and depth == 0):
                break
        if (end is None
                or (end != start and code[end].rstrip() != match[1] + '}')
                or unsure & set(range(start, end + 1))
                or any(test_class == owner and set(span) & set(range(start, end + 1))
                       for (owner, _), span in spans.items())):
            ambiguous.add(test_class)
        spans[(test_class, match[2])] = range(start, (end if end is not None else start) + 1)
    return {key: span for key, span in spans.items() if key[0] not in ambiguous}


def in_test_method(spans, test_class, index):
    return any(owner == test_class and index in span for (owner, _), span in spans.items())


def tests_for_changes(text, changed, module, test_classes, method_level, used_elsewhere, users):
    """The Module.Class and Module.Class/method names that the changed lines (0-based) of one test file select.

    A change inside a test method selects its class, or only that method in a heavy class. A change elsewhere in a
    test class, such as a helper or a fixture, selects the class and also `users(name)`: the test classes of other
    files that name it. A change to a top-level declaration that only this file can use selects every test class of
    the file: a private or fileprivate one, or one whose name no other test file mentions (`used_elsewhere(name)` is
    false). Returns None when a change needs the full suite: other code outside the XCTestCase classes, which other
    test files share, or a class whose users cannot be bounded (`users` returns None).
    """
    lines = text.splitlines()
    line_owners = owners(lines, test_classes)
    spans = test_spans(lines, line_owners)
    whole, methods, others = set(), set(), set()
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
        if not in_test_method(spans, name, index):
            found = users(name)
            if found is None:
                return None
            others |= found
        elif name in method_level:
            methods.add(next((name, test) for (owner, test), span in spans.items()
                             if owner == name and index in span))
            continue
        whole.add(name)
    selected = {f'{module}.{name}' for name in whole} | others
    return selected | {f'{module}.{name}/{method}' for name, method in methods if f'{module}.{name}' not in selected}


def git(*arguments):
    return subprocess.run(['git', *arguments], text=True, capture_output=True, check=True).stdout


def changed_lines(base, merge_commit, path):
    """0-based lines of `path` at the merge commit that the diff adds or changes, and the lines around a deletion."""
    lines = set()
    for match in HUNK.finditer(git('diff', '-U0', '--no-renames', base, merge_commit, '--', path)):
        start, count = int(match[1]), int(match[2] if match[2] is not None else 1)
        lines |= set(range(start - 1, start - 1 + count)) if count else {start - 1, start}
    return lines


class TestTree:
    """The macos/core test sources at one commit, read through git."""

    def __init__(self, commit):
        self.commit = commit
        self.classes = set(TEST_CLASS.findall(git('grep', '-h', '-F', 'XCTestCase', commit, '--', CORE_TESTS)))
        self.texts = {}

    def text(self, path):
        if path not in self.texts:
            self.texts[path] = git('show', f'{self.commit}:{path}')
        return self.texts[path]

    def mentions(self, name):
        """The test files that contain `name` as a whole word."""
        found = subprocess.run(['git', 'grep', '-l', '-w', '-F', name, self.commit, '--', CORE_TESTS], text=True,
                               capture_output=True).stdout.split('\n')
        return [mention.split(':', 1)[1] for mention in found if mention]

    def used_elsewhere(self, name, path):
        return any(mention != path for mention in self.mentions(name))

    def users(self, name):
        """Module.Class names of the test classes that can reach test class `name`'s non-test code.

        A class that names `name` is a user. When it names it outside its own test methods, its helpers may pass
        the change on, so the users of that class count too. A file-local declaration that names it makes every
        class of its file a user. Returns None when shared support outside a test class names it.
        """
        found, queue, seen = set(), [name], set()
        while queue:
            current = queue.pop()
            if current in seen:
                continue
            seen.add(current)
            word = re.compile(rf'\b{re.escape(current)}\b')
            for path in self.mentions(current):
                module = PurePosixPath(path).relative_to(CORE_TESTS).parts[0]
                lines = self.text(path).splitlines()
                line_owners = owners(lines, self.classes)
                spans = test_spans(lines, line_owners)
                for index, line in enumerate(lines):
                    if not word.search(line) or line.strip().startswith(('//', '/*', '*')):
                        continue
                    kind, owner = line_owners[index]
                    if kind == 'import':
                        continue
                    if kind == 'class':
                        found.add(f'{module}.{owner}')
                        if not in_test_method(spans, owner, index):
                            queue.append(owner)
                    elif kind == 'file' or (kind == 'other' and owner and not self.used_elsewhere(owner, path)):
                        local = [test_class for kind, test_class in line_owners if kind == 'class']
                        found |= {f'{module}.{test_class}' for test_class in local}
                        queue += local
                    else:
                        return None
        return found


def core_test_plan(paths, base, merge_commit):
    """('full', []) or ('selected', sorted names) for the macos/core tests of a pull request. See the module doc."""
    def full(path, reason):
        print(f'macos/core tests: full suite, because {path} {reason}')
        return 'full', []

    weights = json.loads((ROOT / WEIGHTS).read_text())
    method_level = set(weights.get('methods', {})) | {
        name for name, seconds in weights['weights'].items() if seconds >= METHOD_LEVEL_SECONDS}
    tree = None
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
            tree = tree or TestTree(merge_commit)
            module = PurePosixPath(path).relative_to(CORE_TESTS).parts[0]
            found = tests_for_changes(tree.text(path), changed_lines(base, merge_commit, path), module, tree.classes,
                                      method_level, lambda name, path=path: tree.used_elsewhere(name, path),
                                      tree.users)
            if found is None:
                return full(path, 'changes shared test code outside an XCTestCase class or its users')
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


def verify_needs(needs):
    """Problems with one run's job results, from the workflow's `needs` context. An empty list means it passed."""
    changes = needs.get('changes') or {}
    if changes.get('result') != 'success':
        return [f'changes: {changes.get("result") or "missing"}, so the selection is unknown']
    outputs = changes.get('outputs') or {}
    problems = []
    python = (needs.get('python') or {}).get('result') or 'missing'
    if python != 'success':
        problems.append(f'python: {python}, expected success')
    for job, output in WORKFLOW_JOBS.items():
        result = (needs.get(job) or {}).get('result') or 'missing'
        if outputs.get(output) not in ('true', 'false'):
            problems.append(f'{job}: the selection has no {output} output')
            continue
        expected = 'success' if outputs[output] == 'true' else 'skipped'
        if result != expected:
            problems.append(f'{job}: {result}, expected {expected}')
    return problems


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--merge-commit', help='the pull request merge commit that actions/checkout checked out')
    source.add_argument('--all', action='store_true', help='select every job and the full macos/core suite')
    source.add_argument('--verify-needs', action='store_true',
                        help='check the job results in the NEEDS environment variable (the `needs` context as JSON)')
    parser.add_argument('--github-output', help='append the outputs as name=value lines to this file')
    args = parser.parse_args(argv)
    if args.verify_needs:
        needs = json.loads(os.environ['NEEDS'])
        for job, value in sorted(needs.items()):
            print(f'{job}: {(value or {}).get("result")}')
        problems = verify_needs(needs)
        for problem in problems:
            print(f'::error::{problem}')
        return 1 if problems else 0

    selected, mode, tests, release = set(JOBS), 'full', [], True
    if not args.all:
        try:
            base = merge_parents(args.merge_commit)[0]
            paths = changed_paths(args.merge_commit)
            for path in paths:
                print(f'{path}: {", ".join(sorted(jobs_for(path))) or "Python checks only"}')
            selected = select(paths)
            reason = release_reason(paths, base, args.merge_commit)
            release = reason is not None
            if 'mac' in selected:
                print(f'Mac build: Debug and Release apps, because {reason}' if release
                      else 'Mac build: Debug app only; the changes touch no Release input')
            if 'mac_core' in selected:
                mode, tests = core_test_plan(paths, base, args.merge_commit)
                if mode == 'selected' and not tests:
                    print('macos/core tests: the changes select no test, so the Mac core tests job does not run')
                    selected.discard('mac_core')
        except (subprocess.CalledProcessError, ValueError) as error:
            detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
            print(f'::warning::Could not read the pull request changes, so every job runs in full: {detail}',
                  flush=True)
            selected, mode, tests, release = set(JOBS), 'full', [], True
    outputs = {job: 'true' if job in selected else 'false' for job in JOBS}
    two_runners = mode == 'full' or estimate(tests, json.loads((ROOT / WEIGHTS).read_text())) > TWO_RUNNER_SECONDS
    outputs['mac_core_mode'] = mode
    # Two parts run shards 0-2 and 3-5 of six, one per runner; one part runs three shards on one runner.
    outputs['mac_core_parts'] = '[1, 2]' if two_runners else '[1]'
    outputs['mac_core_tests'] = ','.join(tests)
    outputs['mac_release'] = 'true' if release else 'false'
    lines = [f'{name}={value}' for name, value in outputs.items()]
    print('\n'.join(lines))
    if args.github_output:
        with open(args.github_output, 'a') as handle:
            handle.write(''.join(f'{line}\n' for line in lines))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
