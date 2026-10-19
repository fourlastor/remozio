#!/usr/bin/env python3
"""Compare Swift build output sinks on one host; never execute built products."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import stat
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
ORDER = ('stream', 'file', 'quiet', 'quiet', 'file', 'stream')
DEPENDENCY_DIRS = {'checkouts', 'repositories', 'artifacts'}


class BenchmarkError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise BenchmarkError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def trial_modes(repetitions):
    require(type(repetitions) is int and 1 <= repetitions <= 3, 'repetitions must be between 1 and 3')
    return list(ORDER) * repetitions


def inventory_objects(build):
    result = {}
    if not build.exists():
        return result
    for path in sorted(build.rglob('*.o')):
        relative = path.relative_to(build)
        if not (DEPENDENCY_DIRS & set(relative.parts)) and not path.is_symlink() and path.is_file():
            result[relative.as_posix()] = path.stat().st_size
    return result


def object_evidence(build):
    objects = inventory_objects(build)
    return {'count': len(objects), 'bytes': sum(objects.values()), 'sizesSha256': digest(objects)}


def reset_workspace(work, snapshot, owner):
    require(owner.is_dir() and not owner.is_symlink()
            and work.parent == owner and snapshot.parent == owner
            and work.resolve() != snapshot.resolve()
            and work != snapshot and not work.is_symlink() and not snapshot.is_symlink()
            and snapshot.is_dir(), 'reset paths must be distinct owned directories')
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(snapshot, work, copy_function=shutil.copy2, symlinks=True)


def run_command(arguments, env, log, timeout):
    with log.open('wb') as stream:
        process = subprocess.Popen(arguments, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except BaseException:
            # The child has not been reaped when wait raises. Its PID still
            # identifies this owned session, including compiler descendants.
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            raise
    require(status == 0, f'preparation failed with exit {status}; see {log}')


def measure_trial(mode, command, work, log_path, timeout, env):
    require(mode in ORDER, 'unknown output mode')
    arguments = [*command, *(['--quiet'] if mode == 'quiet' else [])]
    log_stream = None if mode == 'stream' else log_path.open('wb')
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    timed_out = False
    try:
        process = subprocess.Popen(arguments, env=env, stdin=subprocess.DEVNULL,
                                   stdout=log_stream, stderr=None if log_stream is None else subprocess.STDOUT,
                                   start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            status = process.wait()
        except BaseException:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            raise
    finally:
        elapsed = time.monotonic() - started
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        if log_stream is not None:
            log_stream.close()
    return {'mode': mode, 'command': arguments, 'wallSeconds': elapsed,
            'childUserSeconds': after.ru_utime - before.ru_utime,
            'childSystemSeconds': after.ru_stime - before.ru_stime,
            'exitStatus': status, 'timedOut': timed_out,
            'objects': object_evidence(work / 'build'),
            'log': None if mode == 'stream' else str(log_path),
            'logBytes': None if mode == 'stream' else log_path.stat().st_size}


def assess_trials(trials):
    groups = {mode: [trial for trial in trials if trial['mode'] == mode] for mode in ('stream', 'file', 'quiet')}
    counts = {len(group) for group in groups.values()}
    require(len(counts) == 1 and next(iter(counts), 0) >= 2
            and sum(len(group) for group in groups.values()) == len(trials), 'unbalanced trial modes')
    expected = trials[0]['objects']
    require(expected['count'] > 0 and expected['bytes'] > 0, 'no compiled object work was observed')
    for trial in trials:
        require(trial['exitStatus'] == 0 and trial['timedOut'] is False, 'a compiler trial failed or timed out')
        require(trial['objects'] == expected, 'compiled object work differs between trials')
        require(trial['wallSeconds'] > 0, 'invalid trial timing')
    modes = {}
    for mode, group in groups.items():
        values = [trial['wallSeconds'] for trial in group]
        modes[mode] = {'samples': len(group), 'wallMedianSeconds': statistics.median(values),
                       'wallMinSeconds': min(values), 'wallMaxSeconds': max(values),
                       'childCpuMedianSeconds': statistics.median(
                           trial['childUserSeconds'] + trial['childSystemSeconds'] for trial in group)}
    return {'modes': modes, 'comparisons': {
                'fileVsStreamWallRatio': modes['file']['wallMedianSeconds'] / modes['stream']['wallMedianSeconds'],
                'quietVsFileWallRatio': modes['quiet']['wallMedianSeconds'] / modes['file']['wallMedianSeconds']},
            'limitations': ['Two samples per mode in the default run are a pilot, not statistical significance.',
                            'Stream versus file changes the output sink; quiet versus file also changes SwiftPM formatting.',
                            'Repeated builds on one host do not establish a full CI speed improvement.',
                            'Object paths and sizes establish bounded compile-work evidence, not identical compiler scheduling.',
                            'CPU measurements cover waited-for child processes; stream byte counts are unavailable.']}


def capture_inputs(package):
    result = subprocess.run(['git', '-C', str(package), 'rev-parse', '--show-toplevel'],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
    if result.returncode == 0:
        root = Path(result.stdout.strip()).resolve()
        names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).split(b'\0')
        paths = [root / os.fsdecode(name) for name in names if name]
    else:
        root = package
        paths = [path for path in package.rglob('*')
                 if not {'.git', '.build', '.swiftpm'} & set(path.relative_to(package).parts)
                 and (path.is_file() or path.is_symlink())]
    entries = {}
    for path in sorted(paths):
        info = path.lstat()
        content = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        entries[path.relative_to(root).as_posix()] = {
            'sha256': hashlib.sha256(content).hexdigest(), 'mode': stat.S_IMODE(info.st_mode),
            'mtime_ns': info.st_mtime_ns, 'size': len(content)}
    return {'root': str(root), 'files': entries}


def metadata(swift):
    def read(*arguments):
        return subprocess.check_output(arguments, text=True, stderr=subprocess.STDOUT, timeout=30).strip()
    host = {'system': platform.system(), 'architecture': platform.machine(),
            'kernel': platform.release(), 'swiftPath': swift, 'swift': read(swift, '--version'),
            'streamStdoutIsTty': sys.stdout.isatty(), 'streamStderrIsTty': sys.stderr.isatty(),
            'runnerImage': {name: os.environ.get(name) for name in ('ImageOS', 'ImageVersion')}}
    if platform.system() == 'Darwin':
        host.update(xcode=read('xcodebuild', '-version'), osBuild=read('sw_vers', '-buildVersion'),
                    sdk=read('xcrun', '--sdk', 'macosx', '--show-sdk-build-version'))
    return host


def write_report(output, report):
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')


def benchmark(args):
    package = args.package_path.resolve()
    require((package / 'Package.swift').is_file(), 'package path must contain Package.swift')
    require(1 <= args.jobs <= 16 and 0 < args.timeout <= 3600, 'invalid jobs or timeout limit')
    modes = trial_modes(args.repetitions)
    require(not sys.stdout.isatty() and not sys.stderr.isatty(), 'stream trials require non-TTY stdout and stderr')
    output = args.output.resolve()
    require(not output.exists(), 'output directory must be new; existing files are never deleted')
    output.mkdir(parents=True)
    work, snapshot = output / 'work', output / 'resolved-snapshot'
    work.mkdir()
    report = {'experiment': 'compiler-output-sinks-v1', 'passed': False, 'trials': []}
    baseline = None
    try:
        swift = shutil.which('swift')
        require(swift is not None, 'Swift is unavailable')
        report['host'] = metadata(swift)
        baseline = capture_inputs(package)
        (output / 'source-inputs.json').write_text(json.dumps(baseline, indent=2, sort_keys=True) + '\n')
        report['sourceInputsSha256'] = digest(baseline)
        report['packagePath'] = str(package)
        for directory in ('build', 'cache', 'config', 'security', 'module-cache', 'tmp'):
            (work / directory).mkdir()
        environment = {**os.environ, 'CLANG_MODULE_CACHE_PATH': str(work / 'module-cache'),
                       'SWIFTPM_MODULECACHE_OVERRIDE': str(work / 'module-cache'), 'TMPDIR': str(work / 'tmp')}
        options = ['--package-path', str(package), '--scratch-path', str(work / 'build'),
                   '--cache-path', str(work / 'cache'), '--config-path', str(work / 'config'),
                   '--security-path', str(work / 'security'), '--manifest-cache', 'none',
                   '--disable-keychain', '--disable-netrc', '--force-resolved-versions', '--skip-update',
                   '--jobs', str(args.jobs)]
        if args.triple:
            options += ['--triple', args.triple]
        command = [swift, 'build', *options]
        report['baseCommand'] = command
        report['order'] = modes
        run_command([swift, 'package', *options, 'resolve'], environment, output / 'resolve.log', args.timeout)
        # Resolution may compile manifests and populate module caches. Remove
        # only these newly owned caches before taking the common initial image.
        for directory in ('module-cache', 'tmp'):
            shutil.rmtree(work / directory)
            (work / directory).mkdir()
        require(not inventory_objects(work / 'build'), 'resolved snapshot already contains compiled target objects')
        require(capture_inputs(package) == baseline, 'dependency preparation changed source inputs')
        shutil.copytree(work, snapshot, copy_function=shutil.copy2, symlinks=True)
        # One unmeasured build conditions file-system caches, then every timed
        # trial starts from the same resolved, compiler-output-empty snapshot.
        report['conditioning'] = measure_trial('quiet', command, work, output / 'conditioning.log', args.timeout, environment)
        require(report['conditioning']['exitStatus'] == 0 and not report['conditioning']['timedOut'],
                'conditioning build failed; see conditioning.log')
        require(report['conditioning']['objects']['count'] > 0, 'conditioning build produced no object evidence')
        write_report(output, report)
        for index, mode in enumerate(modes, 1):
            reset_workspace(work, snapshot, output)
            require(not inventory_objects(work / 'build'), 'trial reset retained compiled target objects')
            require(capture_inputs(package) == baseline, 'source inputs changed before a trial')
            print(f'Compiler-output trial {index}/{len(modes)}: {mode}', flush=True)
            trial = measure_trial(mode, command, work, output / f'{index:02}-{mode}.log', args.timeout, environment)
            trial['index'] = index
            report['trials'].append(trial)
            write_report(output, report)
            require(trial['exitStatus'] == 0 and not trial['timedOut'], f'trial {index} failed; comparison refused')
        require(capture_inputs(package) == baseline, 'source inputs changed during the benchmark')
        report['summary'] = assess_trials(report['trials'])
        report['passed'] = True
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        # These paths were created by this invocation, never supplied as cleanup
        # targets. Retain logs and metadata, not large compiler/dependency trees.
        for owned in (work, snapshot):
            if owned.exists() and not owned.is_symlink():
                shutil.rmtree(owned)
        write_report(output, report)
    print(f"Compiler-output benchmark {'passed' if report['passed'] else 'failed'}; report: {output / 'report.json'}", flush=True)
    if not report['passed']:
        print(report['error'], file=sys.stderr)
    return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-path', type=Path, default=ROOT / 'experiments/release-dependencies')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--triple')
    parser.add_argument('--repetitions', type=int, default=1)
    parser.add_argument('--timeout', type=float, default=1800)
    args = parser.parse_args()
    try:
        return benchmark(args)
    except (BenchmarkError, OSError) as error:
        print(f'Compiler-output benchmark refused: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
