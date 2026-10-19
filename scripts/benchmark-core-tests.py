#!/usr/bin/env python3
"""Fork-only serial A-B-B-A or B-A-A-B native XCTest comparison; builds are outside timing."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import shlex
import stat
import subprocess
import sys
import time

BASELINE = 'd202c966e22688c1b8773631e8efd7a77ba13ad2'
SOURCE = 'protocol/swift/Sources/RemozioProtocol/DeterministicCBOR.swift'
OLD = b'        guard [0, 2, 3, 4, 5].contains(major) else { throw CBORError.unsupportedType }\n'
NEW = b'        switch major {\n        case 0, 2, 3, 4, 5: break\n        default: throw CBORError.unsupportedType\n        }\n'
SUITE = 'GatewayRuntimeActivationOperationTests'
CLASS = 'RemozioCoreTests.' + SUITE
CASES = {
    'testCompleteOperationPublishesOnlyTheOptionalGatewayAndReleasesTheWriterBeforeRegistration',
    'testEveryInterruptedStageResumesTheSameIntentAndArtifacts',
    'testLostRegistrationReplyLeavesPublicationAndEnrollmentForMatchingRetry',
    'testRegistrationFailureDoesNotClaimCompletionOrUndoPublishedForegroundState',
    'testFailedHostVerificationCannotRetainAnIntentOrPublishFiles',
    'testPresentOrUncertainInitializerBlocksPublicationAndCanRetryAfterAbsence',
    'testAnInitializerAppearingAfterPublicationPreventsNormalRegistration',
    'testAnInitializerAppearingAfterRegistrationDoesNotRetainCompletion',
    'testMissingPublishedFileRefusesInsteadOfRepairingOrRegistering',
}
PROFILE_SIGNATURE = '784d0e9a6863a929bc9267045bbe8aafba4572de2e746ce9b4fa1d848a97ff4c'
PROFILE_ARTIFACT = '3d5428a29c13b54712387e186c3c63dcf166315846ba7153020202f1a761229a'
BUILD = ['swift', 'build', '--package-path', 'macos/core', '--build-tests', '--triple',
         'arm64-apple-macosx26.0', '--jobs', '4', '--force-resolved-versions', '-v']


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: object) -> str:
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def dump(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(['git', '-C', str(repo), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20).stdout


def inventory(repo: Path) -> dict:
    result = {}
    for raw in git(repo, 'ls-files', '-z').split(b'\0'):
        if not raw:
            continue
        name = os.fsdecode(raw)
        path = repo / name
        info = path.lstat()
        if stat.S_ISREG(info.st_mode):
            data, kind = path.read_bytes(), 'file'
        elif stat.S_ISLNK(info.st_mode):
            data, kind = os.fsencode(os.readlink(path)), 'symlink'
        else:
            raise RuntimeError('unsupported tracked input: ' + name)
        result[name] = {'kind': kind, 'mode': stat.S_IMODE(info.st_mode), 'sha256': sha(data)}
    return result


@contextmanager
def source_variants(path: Path, baseline: bytes, candidate: bytes):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.read_bytes() != candidate:
        raise RuntimeError('candidate source is not the expected regular file')
    last_mtime = info.st_mtime_ns

    def check() -> None:
        current = path.lstat()
        if (not stat.S_ISREG(current.st_mode) or stat.S_IMODE(current.st_mode) != stat.S_IMODE(info.st_mode)
                or path.read_bytes() not in (baseline, candidate)):
            raise RuntimeError('source changed concurrently; refusing to overwrite it')

    def select(data: bytes) -> None:
        nonlocal last_mtime
        check()
        if data not in (baseline, candidate):
            raise ValueError('unknown source variant')
        path.write_bytes(data)
        last_mtime = max(time.time_ns(), last_mtime + 1_000_000)
        os.utime(path, ns=(info.st_atime_ns, last_mtime))

    try:
        yield select
    finally:
        check()
        path.write_bytes(candidate)
        os.chmod(path, stat.S_IMODE(info.st_mode))
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))


def owned(command: list[str], log: Path, repo: Path, timeout: float, env: dict | None = None) -> dict:
    """wait4 is the only reaper; never signal a session leader after reaping it."""
    started, usage, ended, process = time.monotonic(), None, None, None
    record = {'command': command, 'timeoutSeconds': timeout, 'cleanupComplete': True}

    def poll() -> bool:
        nonlocal usage, ended
        # A pending interrupt must not see None after wait4 has already reaped the PID.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
        try:
            if process.returncode is None:
                pid, status, child_usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    usage, ended = child_usage, time.monotonic()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        return process.returncode is not None

    try:
        with log.open('wb') as stream:
            process = subprocess.Popen(command, cwd=repo, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            record['pid'] = process.pid
            while not poll():
                if time.monotonic() - started >= timeout:
                    raise subprocess.TimeoutExpired(command, timeout)
                time.sleep(0.02)
        if process.returncode != 0:
            raise RuntimeError('child failed with ' + str(process.returncode) + ': ' + log.name)
    except BaseException as error:
        record['exception'] = type(error).__name__
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 10
            while not poll() and time.monotonic() < deadline:
                time.sleep(0.02)
            record['cleanupComplete'] = process.returncode is not None
        raise
    finally:
        record.update(returncode=None if process is None else process.returncode,
                      wallSeconds=None if ended is None else ended - started,
                      userCPUSeconds=None if usage is None else usage.ru_utime,
                      systemCPUSeconds=None if usage is None else usage.ru_stime)
        dump(log.with_suffix('.json'), record)
    return record


def test_cases(log: str) -> dict[str, float]:
    matches = re.findall(r"^Test Case '-\[([^ ]+) ([^]]+)\]' (started\.|passed \(([0-9.]+) seconds\)\.)$", log, re.M)
    starts, passes = [], []
    for suite, method, event, duration in matches:
        if suite != CLASS or method not in CASES:
            raise RuntimeError('unexpected XCTest case')
        (starts if event == 'started.' else passes).append(method)
    summaries = re.findall(r'Executed (\d+) tests?, with (\d+) failures', log)
    if (len(starts) != 9 or len(passes) != 9 or set(starts) != CASES or set(passes) != CASES
            or starts != passes or not summaries or any(a != '9' or b != '0' for a, b in summaries)
            or re.search(r'\bskipped\b|\bfailed\b', log, re.I)):
        raise RuntimeError('expected exactly all nine tests with zero skips/failures')
    result = {method: float(duration) for _, method, event, duration in matches if event != 'started.'}
    if any(not math.isfinite(v) or v < 0 for v in result.values()):
        raise RuntimeError('invalid test duration')
    return result


def profile_signature(value: dict, expected: str = PROFILE_SIGNATURE) -> dict:
    if value.get('schemaVersion') != 1 or value.get('suite') != SUITE or not value.get('spans'):
        raise RuntimeError('invalid profile envelope')
    signature = {}
    for label, span in value['spans'].items():
        signature[label] = {key: span[key] for key in ('calls', 'thrownCalls', 'cpuMeasurementFailures')}
        if (any(type(v) is not int or v < 0 for v in signature[label].values())
                or span['cpuMeasurementFailures'] != 0 or span['thrownCalls'] > span['calls']):
            raise RuntimeError('invalid profile accounting')
        if any(type(span.get(k)) not in (int, float) or not math.isfinite(span[k]) or span[k] < 0
               for k in ('wallSeconds', 'processCPUSeconds')):
            raise RuntimeError('invalid span timing')
    if digest(signature) != expected:
        raise RuntimeError('profile call/throw/label work changed')
    return signature


def compiler_evidence(log: str, allow_absent: bool = False) -> int:
    count = 0
    for line in log.splitlines():
        if 'swift-frontend' not in line or 'DeterministicCBOR.swift' not in line:
            continue
        try:
            words = shlex.split(line)
        except ValueError:
            continue
        if (words and Path(words[0]).name == 'swift-frontend' and '-c' in words
                and any(a == '-primary-file' and b.endswith('/DeterministicCBOR.swift')
                        for a, b in zip(words, words[1:]))):
            count += 1
    if not count and not allow_absent:
        raise RuntimeError('no actual primary-file CBOR compilation proven')
    return count


def compilation_status(count: int, current: dict, previous: dict | None) -> str:
    if count:
        return 'recompiled'
    keys = ('mode', 'sourceSHA256', 'bundleExecutableSHA256', 'cborObjectSHA256')
    if previous is None or any(current[key] != previous[key] for key in keys):
        raise RuntimeError('no compilation and no identical proven previous variant')
    return 'reused-identical-proven-previous-variant'


def terminate(signum, _frame):
    raise SystemExit(128 + signum)


def prime_baseline(baseline: bytes, candidate: bytes, select, verify, repo: Path, output: Path) -> dict:
    """BAAB begins from candidate source; prove an untimed A build before the first B."""
    verify(candidate)
    select(baseline)
    verify(baseline)
    build = owned(BUILD, output / 'prime-baseline.log', repo, 600)
    count = compiler_evidence((output / 'prime-baseline.log').read_text())
    verify(baseline)
    return {'mode': 'baseline', 'purpose': 'untimed baseline priming so first candidate requires a source change',
            'sourceSHA256': sha(baseline), 'primaryCompileCommands': count, 'build': build}


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--order', choices=('abba', 'baab'), default='abba')
    return parser


def main() -> None:
    parser = argument_parser()
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('the native comparison requires macOS')
    signal.signal(signal.SIGTERM, terminate)
    repo, output = args.repo.resolve(strict=True), args.output.resolve()
    if git(repo, 'status', '--porcelain=v1', '--untracked-files=all'):
        raise RuntimeError('requires a clean checkout; output must be new and ignored or outside checkout')
    head, initial = git(repo, 'rev-parse', 'HEAD').decode().strip(), inventory(repo)
    baseline, candidate = git(repo, 'show', BASELINE + ':' + SOURCE), (repo / SOURCE).read_bytes()
    if baseline.count(OLD) != 1 or candidate != baseline.replace(OLD, NEW):
        raise RuntimeError('candidate must be exactly the reviewed major-type switch')
    output.mkdir(parents=True, exist_ok=False)
    dump(output / 'tracked-inputs.json', initial)
    (output / 'baseline.swift').write_bytes(baseline)
    (output / 'candidate.swift').write_bytes(candidate)
    metadata = {'baselineGitSHA': BASELINE, 'candidateGitSHA': head, 'sourceSHA256': {'baseline': sha(baseline), 'candidate': sha(candidate)},
                'buildCommand': BUILD, 'orderName': args.order,
                'order': ['baseline' if letter == 'a' else 'candidate' for letter in args.order], 'cases': sorted(CASES),
                'priming': None,
                'profileSignatureSHA256': PROFILE_SIGNATURE, 'profileReferenceArtifactSHA256': PROFILE_ARTIFACT,
                'profileReferenceRun': 39246629242, 'driverSHA256': sha(Path(__file__).read_bytes()),
                'measurement': 'fresh serial XCTest process; wait4 wall/CPU, compilation and input checks excluded; nested spans overlap'}
    observations = []

    def verify(data: bytes) -> None:
        expected = dict(initial, **{SOURCE: dict(initial[SOURCE], sha256=sha(data))})
        if inventory(repo) != expected or git(repo, 'rev-parse', 'HEAD').decode().strip() != head:
            raise RuntimeError('tracked source bytes/modes or checkout changed')

    try:
        for name, command in [('swift-version', ['swift', '--version']), ('xcode-version', ['xcodebuild', '-version']),
                              ('os-version', ['sw_vers']), ('xctest-path', ['xcrun', '--find', 'xctest']),
                              ('target-info', ['swiftc', '-print-target-info', '-target', 'arm64-apple-macosx26.0'])]:
            owned(command, output / (name + '.log'), repo, 30)
        loader = Path((output / 'xctest-path.log').read_text().strip())
        if not loader.is_absolute():
            raise RuntimeError('XCTest loader path must be absolute')
        loader = loader.resolve(strict=True)
        if not loader.is_file() or not os.access(loader, os.X_OK):
            raise RuntimeError('invalid XCTest loader')
        dump(output / 'metadata.json', metadata)
        with source_variants(repo / SOURCE, baseline, candidate) as select:
            previous = candidate
            if args.order == 'baab':
                metadata['priming'] = prime_baseline(baseline, candidate, select, verify, repo, output)
                previous = baseline
                dump(output / 'metadata.json', metadata)
            for index, mode in enumerate(metadata['order']):
                trial = output / f'{index + 1}-{mode}'
                trial.mkdir()
                data = baseline if mode == 'baseline' else candidate
                verify(previous)
                select(data)
                verify(data)
                owned(BUILD, trial / 'build.log', repo, 600)
                compile_count = compiler_evidence((trial / 'build.log').read_text(), allow_absent=True)
                verify(data)
                bundle = (repo / 'macos/core/.build/debug/RemozioCorePackageTests.xctest').resolve(strict=True)
                binary = bundle / 'Contents/MacOS/RemozioCorePackageTests'
                binary_hash = sha(binary.read_bytes())
                objects = list((repo / 'macos/core/.build/arm64-apple-macosx/debug/RemozioProtocol.build').glob('DeterministicCBOR.swift.o'))
                if len(objects) != 1:
                    raise RuntimeError('missing exact CBOR object file')
                object_hash = sha(objects[0].read_bytes())
                proof = {'mode': mode, 'sourceSHA256': sha(data), 'bundleExecutableSHA256': binary_hash, 'cborObjectSHA256': object_hash}
                compile_status = compilation_status(compile_count, proof, observations[-1] if observations else None)
                env = dict(os.environ, REMOZIO_TEST_PROFILE_DIR=str(trial))
                result = owned([str(loader), '-XCTest', CLASS, str(bundle)], trial / 'test.log', repo, 720, env)
                verify(data)
                cases = test_cases((trial / 'test.log').read_text())
                profiles = list(trial.glob(SUITE + '-*.json'))
                if len(profiles) != 1 or profiles[0].name != f'{SUITE}-{result["pid"]}.json':
                    raise RuntimeError('missing or wrong-process profile')
                profile_signature(json.loads(profiles[0].read_text()))
                observations.append({'index': index, 'mode': mode, 'test': result, 'cases': cases,
                                     'sourceSHA256': sha(data), 'profileSHA256': sha(profiles[0].read_bytes()),
                                     'primaryCompileCommands': compile_count, 'compilationStatus': compile_status,
                                     'sourceMtimeNs': (repo / SOURCE).stat().st_mtime_ns, 'bundleExecutableSHA256': binary_hash,
                                     'cborObjectSHA256': object_hash})
                dump(output / 'observations.json', observations)
                previous = data
        verify(candidate)
        dump(output / 'report.json', {'status': 'complete', 'observations': observations,
                                     'limitations': 'one balanced serial pilot, host/load/thermal variation; no automatic speedup claim'})
    except BaseException as error:
        dump(output / 'failure.json', {'type': type(error).__name__, 'message': str(error)})
        raise
    finally:
        dump(output / 'manifest.json', {'files': [{'path': str(p.relative_to(output)), 'sha256': sha(p.read_bytes()), 'bytes': p.stat().st_size}
             for p in sorted(output.rglob('*')) if p.is_file() and p.name != 'manifest.json']})


if __name__ == '__main__':
    main()
