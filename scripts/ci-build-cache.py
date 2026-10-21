#!/usr/bin/env python3
"""Prepare compatible Mac build caches; a restored cache never replaces a check."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import subprocess
import time


VERSION = 1
ROOT = Path(__file__).resolve().parents[1]
MAC_PACKAGES = (
    'experiments/macos', 'experiments/key-custody', 'experiments/system-keychain', 'experiments/protected-bootstrap',
    'experiments/release-dependencies', 'experiments/release-copy', 'experiments/release-attributes',
    'experiments/sparkle-probe', 'experiments/sparkle-boundary', 'experiments/approval-flow',
    'experiments/command-frontend', 'experiments/authority-journal', 'experiments/installation-inventory',
    'protocol/swift', 'host/shared-core', 'macos/core',
)
CACHE_PATHS = {
    'mac': tuple(f'{package}/.build' for package in MAC_PACKAGES) + (
        '.build/release-signing', '.build/packaging/DerivedData', '.build/macos-app/DerivedData'),
    'interop': ('experiments/approval-flow/.build',),
}

# Exact audited Linux-only inputs, not a prefix/subtree exemption. Mac Python
# checks still import/test these runners, but their commands build no cached Mac
# product. Unknown new paths and unexpected file types/modes remain conservative.
# Re-audit if a Mac build starts consuming one; workflow/build-script changes
# continue to partition the compatibility identity.
LINUX_ONLY_INPUT_MODES = {
    'experiments/linux-approval-command/Package.resolved': 0o644,
    'experiments/linux-approval-command/Package.swift': 0o644,
    'experiments/linux-approval-command/Sources/FixtureSQLite/module.modulemap': 0o644,
    'experiments/linux-approval-command/Sources/FixtureSQLite/shim.h': 0o644,
    'experiments/linux-approval-command/Sources/LinuxApprovalCommandFixture/FixtureProtocol.swift': 0o644,
    'experiments/linux-approval-command/Sources/LinuxApprovalCommandFixture/FixtureStore.swift': 0o644,
    'experiments/linux-approval-command/Sources/LinuxApprovalCommandFixture/OwnedCommand.swift': 0o644,
    'experiments/linux-approval-command/Sources/LinuxApprovalCommandFixture/main.swift': 0o644,
    'experiments/linux-caller-monitor/fixture.c': 0o644,
    'experiments/linux-caller-monitor/probe.py': 0o644,
    'experiments/linux-caller/probe.py': 0o644,
    'experiments/linux-native-tpm-tls/Package.swift': 0o644,
    'experiments/linux-native-tpm-tls/README.md': 0o644,
    'experiments/linux-native-tpm-tls/Sources/CNativeTPMProbe/include/NativeTPMProbe.h': 0o644,
    'experiments/linux-native-tpm-tls/Sources/CNativeTPMProbe/native_probe.c': 0o644,
    'experiments/linux-native-tpm-tls/Sources/COpenSSL/module.modulemap': 0o644,
    'experiments/linux-native-tpm-tls/Sources/COpenSSL/shim.h': 0o644,
    'experiments/linux-native-tpm-tls/Sources/NativeTPMProbe/main.swift': 0o644,
    'experiments/linux-storage-lease/README.md': 0o644,
    'experiments/linux-storage-lease/controls.c': 0o644,
    'experiments/linux-storage-lease/lease.c': 0o644,
    'experiments/linux-storage-lease/lease.h': 0o644,
    'experiments/linux-tpm-tls/README.md': 0o644,
    'experiments/linux-tpm-tls/check_hardware_adapter.py': 0o644,
    'scripts/check-linux-host.sh': 0o755,
    'scripts/check-linux-protocol.sh': 0o755,
    'scripts/run-linux-approval-command-experiment.py': 0o644,
    'scripts/run-linux-caller-experiment.py': 0o644,
    'scripts/run-linux-caller-monitor-experiment.py': 0o755,
    'scripts/run-linux-native-tpm-tls-experiment.py': 0o644,
    'scripts/run-linux-storage-lease-experiment.py': 0o644,
    'scripts/run-linux-tpm-tls-experiment.py': 0o755,
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def tracked_paths(root):
    raw = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z'])
    return sorted(set(os.fsdecode(path) for path in raw.split(b'\0') if path))


def safe_path(root, name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or str(path) != name:
        raise ValueError('invalid cache input path')
    candidate = root / name
    if candidate.parent.resolve() != root.resolve() and root.resolve() not in candidate.parent.resolve().parents:
        raise ValueError('cache input escapes workspace')
    return candidate


def capture_inputs(root):
    """Hash tracked input bytes and mode; preserve nanoseconds, never follow symlinks."""
    result = {}
    for name in tracked_paths(root):
        path = safe_path(root, name)
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            with path.open('rb') as stream:
                content_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
            kind = 'file'
        elif stat.S_ISLNK(info.st_mode):
            content_hash = hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest()
            kind = 'symlink'
        else:
            raise ValueError('unsupported tracked cache input')
        result[name] = {'sha256': content_hash, 'mode': stat.S_IMODE(info.st_mode),
                        'kind': kind, 'mtime_ns': info.st_mtime_ns}
    return result


def content_inventory(inputs):
    return {name: {key: value for key, value in entry.items() if key != 'mtime_ns'}
            for name, entry in inputs.items()}


def linux_only_input(name, entry):
    return (name in LINUX_ONLY_INPUT_MODES and entry['kind'] == 'file'
            and entry['mode'] == LINUX_ONLY_INPUT_MODES[name])


def discovery_paths(inputs):
    # Top-level documentation Markdown is not discovered by the cached native
    # builds. Keep it in the full inventory/key and every other validation; only
    # adding/removing these ordinary files and the exact audited Linux-only
    # inputs is exempt from graph invalidation.
    # Classify old and new inventories separately so type/mode transitions stay
    # conservative. Markdown in package resources is still a build input.
    return {name for name, entry in inputs.items()
            if not linux_only_input(name, entry)
            and not (PurePosixPath(name).parts[0] == 'docs' and name.endswith('.md')
                    and entry['kind'] == 'file' and entry['mode'] & 0o7111 == 0)}


def restore_inputs(root, inputs):
    """Restore only identical regular files. Timestamp collisions require a cold build."""
    if type(inputs) is not dict:
        raise ValueError('invalid cache input inventory')
    for name, entry in inputs.items():
        safe_path(root, name)
        if (type(entry) is not dict or set(entry) != {'sha256', 'mode', 'kind', 'mtime_ns'}
                or type(entry['mtime_ns']) is not int or entry['mtime_ns'] < 0
                or type(entry['mode']) is not int or not 0 <= entry['mode'] <= 0o7777
                or entry['kind'] not in ('file', 'symlink')
                or type(entry['sha256']) is not str or len(entry['sha256']) != 64
                or any(c not in '0123456789abcdef' for c in entry['sha256'])):
            raise ValueError('invalid cached input metadata')
    current = capture_inputs(root)
    counts = {'restored': 0, 'changed': 0, 'missing': len(inputs.keys() - current.keys()),
              'requires_clean_build': False}
    # Changes to the file set can escape timestamp-based directory discovery.
    if discovery_paths(current) != discovery_paths(inputs):
        counts['requires_clean_build'] = True
    for name, now in current.items():
        old = inputs.get(name)
        if old is None or content_inventory({'x': now}) != content_inventory({'x': old}):
            counts['changed'] += 1
            if old is not None and (now['mtime_ns'] == old['mtime_ns'] or now['kind'] != old['kind']):
                counts['requires_clean_build'] = True
            continue
        if now['kind'] == 'file':
            path = safe_path(root, name)
            os.utime(path, ns=(path.stat().st_atime_ns, old['mtime_ns']), follow_symlinks=False)
            counts['restored'] += 1
    return counts


def settings_inventory(inputs):
    # Changed commands, package graphs, lockfiles, Xcode settings, or cache code
    # start a new compatibility namespace, including fallback restores.
    return content_inventory({name: entry for name, entry in inputs.items()
        if not linux_only_input(name, entry) and (name.startswith(('scripts/', '.github/workflows/'))
        or Path(name).name in ('Package.swift', 'Package.resolved')
        or '.xcodeproj/' in name or '.xcworkspace/' in name or name.endswith('.xcconfig'))})


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def compatibility(root, scope, inputs):
    if platform.system() != 'Darwin':
        raise RuntimeError('Mac cache keys must be measured on the Mac runner')
    return {'version': VERSION, 'scope': scope, 'workspace': str(root.resolve()),
            'architecture': platform.machine(), 'os_build': command('sw_vers', '-buildVersion'),
            'runner_image': {key: os.environ.get(key, '') for key in ('ImageOS', 'ImageVersion')},
            'developer_directory': command('xcode-select', '-p'),
            'xcode': command('xcodebuild', '-version'), 'swift': command('swift', '--version'),
            'clang': command('xcrun', 'clang', '--version'),
            'sdk_path': command('xcrun', '--sdk', 'macosx', '--show-sdk-path'),
            'sdk_version': command('xcrun', '--sdk', 'macosx', '--show-sdk-version'),
            'sdk_build': command('xcrun', '--sdk', 'macosx', '--show-sdk-build-version'),
            'environment': {key: os.environ.get(key, '') for key in (
                'DEVELOPER_DIR', 'SDKROOT', 'MACOSX_DEPLOYMENT_TARGET', 'SWIFT_EXEC',
                'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS', 'SWIFTFLAGS')},
            'settings': digest(settings_inventory(inputs)), 'paths': CACHE_PATHS[scope]}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + '\n')


def outputs(path, values):
    if path is None:
        return
    with path.open('a') as stream:
        for key, value in values.items():
            stream.write(f'{key}<<REMOZIO_CACHE_OUTPUT\n{value}\nREMOZIO_CACHE_OUTPUT\n')


def clear_outputs(root, scope):
    # Only fixed compiler output roots; never use paths from a cache manifest.
    for name in CACHE_PATHS[scope]:
        path = safe_path(root, name)
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)


def run(args, root=ROOT):
    started = time.monotonic()
    scope = args.scope
    context_path = root / f'.build/ci-cache-context/{scope}.json'
    manifest_path = root / f'.build/ci-cache/{scope}.json'
    if args.operation == 'key':
        inputs = capture_inputs(root)
        identity = digest(compatibility(root, scope, inputs))
        prefix = f'mac-build-v{VERSION}-{scope}-{identity}-'
        key = prefix + digest(content_inventory(inputs))
        write_json(context_path, {'identity': identity, 'inputs': inputs, 'key': key})
        outputs(args.github_output, {'key': key, 'restore-prefix': prefix,
            'paths': '\n'.join((*CACHE_PATHS[scope], str(manifest_path.relative_to(root))))})
        report = {'operation': 'key', 'scope': scope, 'key': key, 'input_count': len(inputs)}
    else:
        context = json.loads(context_path.read_text())
        if args.operation == 'restore':
            report = {'operation': 'restore', 'scope': scope, 'result': 'cold',
                      'cache_match': {'true': 'exact', 'false': 'compatible-prefix'}.get(
                          os.environ.get('REMOZIO_CACHE_HIT'), 'miss-or-unavailable')}
            try:
                manifest = json.loads(manifest_path.read_text())
                if manifest['version'] != VERSION or manifest['identity'] != context['identity']:
                    raise ValueError('incompatible cache manifest')
                counts = restore_inputs(root, manifest['inputs'])
                report.update(counts)
                report['result'] = 'cold-input-change' if counts['requires_clean_build'] else 'restored'
                if counts['requires_clean_build']:
                    clear_outputs(root, scope)
            except (OSError, ValueError, KeyError, TypeError, OverflowError):
                clear_outputs(root, scope)
                report['result'] = 'cold-missing-or-invalid-manifest'
        else:
            inputs = capture_inputs(root)
            stable = content_inventory(inputs) == content_inventory(context['inputs'])
            if stable:
                write_json(manifest_path, {'version': VERSION, 'identity': context['identity'], 'inputs': inputs})
            outputs(args.github_output, {'save': str(stable).lower()})
            report = {'operation': 'save', 'scope': scope, 'saved_manifest': stable,
                      'reason': 'stable-inputs' if stable else 'inputs-changed-during-checks'}
            report['output_bytes'] = sum(path.stat().st_size for name in CACHE_PATHS[scope]
                for path in (root / name).rglob('*') if path.is_file() and not path.is_symlink())
    report['seconds'] = round(time.monotonic() - started, 3)
    print(json.dumps(report, sort_keys=True), flush=True)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as stream:
            stream.write(f"\nBuild cache `{scope}` / `{args.operation}`: `{json.dumps(report, sort_keys=True)}`\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('key', 'restore', 'save'))
    parser.add_argument('--scope', choices=tuple(CACHE_PATHS), required=True)
    parser.add_argument('--github-output', type=Path)
    run(parser.parse_args())


if __name__ == '__main__':
    main()
