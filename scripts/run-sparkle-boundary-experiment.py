#!/usr/bin/env python3
"""Ordinary-account Sparkle replacement controls using disposable bundles only."""
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import plistlib
import queue
import shutil
import stat
import sys
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'experiments/sparkle-boundary'
if sys.flags.optimize:
    raise RuntimeError('Run the fixture with Python safety assertions enabled')
PREFIX = 'dev.remozio.experiment.sparkleboundary.'


def command(*args, timeout=20):
    result = subprocess.run(list(map(str, args)), capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{Path(str(args[0])).name} failed: {result.returncode}')
    return result.stdout


def validate_tree(root, tree):
    root = root.resolve(strict=True)
    assert root.name.startswith('remozio-sparkle-boundary-')
    assert root.stat().st_uid == os.getuid() and stat.S_IMODE(root.stat().st_mode) == 0o700
    assert tree == tree.resolve(strict=True) and tree.is_relative_to(root)
    for parent in [tree, tree.parent, root]:
        metadata = parent.stat()
        assert metadata.st_uid == os.getuid() and os.access(parent, os.W_OK)
        # Match Sparkle's ownership-change preflight without allowing a prompt.
        witness = root / ('ownership-' + uuid.uuid4().hex)
        try:
            witness.write_bytes(b'')
            os.chown(witness, metadata.st_uid, metadata.st_gid)
        finally:
            witness.unlink(missing_ok=True)
    for current, directories, files in os.walk(tree, followlinks=False):
        for name in directories + files:
            path = Path(current) / name
            metadata = path.lstat()
            assert metadata.st_uid == os.getuid()
            if path.is_symlink():
                assert path.resolve(strict=True).is_relative_to(tree)
            elif path.is_file():
                assert metadata.st_nlink == 1
            else:
                assert path.is_dir()


def digest(tree):
    result = hashlib.sha256()
    for current, directories, files in os.walk(tree, followlinks=False):
        directories.sort(); files.sort()
        for name in directories + files:
            path = Path(current) / name
            result.update(str(path.relative_to(tree)).encode() + b'\0')
            if path.is_symlink():
                result.update(b'L' + os.readlink(path).encode())
            elif path.is_file():
                result.update(b'F' + path.read_bytes())
            else:
                result.update(b'D')
    return result.hexdigest()


class Child:
    def __init__(self, arguments):
        self.process = subprocess.Popen(list(map(str, arguments)), stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.events = queue.Queue()
        self.seen = []
        self.stderr = bytearray()
        def stdout():
            try:
                for line in self.process.stdout:
                    if len(line) > 4096:
                        raise RuntimeError('oversize frame')
                    self.events.put(json.loads(line))
            except Exception as error:
                self.events.put({'event': 'reader-failed', 'type': type(error).__name__})
            finally:
                self.events.put({'event': 'eof'})
        def stderr():
            while data := self.process.stderr.read(4096):
                if len(self.stderr) < 65536:
                    self.stderr.extend(data[:65536-len(self.stderr)])
        self.readers = [threading.Thread(target=stdout, daemon=True), threading.Thread(target=stderr, daemon=True)]
        for reader in self.readers: reader.start()
    def send(self, message):
        self.process.stdin.write(message.encode()); self.process.stdin.flush()
    def expect(self, event, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = self.events.get(timeout=max(0.01, deadline-time.monotonic()))
            self.seen.append(value)
            if value['event'] == event: return value
            if value['event'] in ['eof', 'probe-failed', 'startup-failed', 'updater-error',
                                  'unexpected-user-driver', 'cycle-failed', 'reader-failed']:
                raise RuntimeError(f'Expected {event}: {value}; events={self.seen}; diagnostic={bytes(self.stderr[-2000:]).decode(errors="replace")}')
        raise TimeoutError(event)
    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=5)
        for reader in self.readers: reader.join(timeout=2)
        for stream in [self.process.stdin, self.process.stdout, self.process.stderr]: stream.close()


class FixtureJobs:
    def __init__(self, identity):
        assert identity.startswith(PREFIX) and len(identity[len(PREFIX):]) == 32
        int(identity[len(PREFIX):], 16)
        self.targets = [f'{domain}/{identity}{suffix}'
                        for domain in [f'gui/{os.getuid()}', f'user/{os.getuid()}', 'system']
                        for suffix in ['-sparkle-updater', '-sparkle-progress']]
        self.created_user_jobs = []
        for target in self.targets:
            assert self.inspect(target) is None, 'Fixture job exists before the experiment'
    @staticmethod
    def inspect(target):
        result = subprocess.run(['/bin/launchctl', 'print', target], capture_output=True, timeout=5)
        if result.returncode == 113: return None
        if result.returncode != 0:
            raise RuntimeError(f'Cannot inspect exact fixture launchd job ({result.returncode})')
        return result.stdout
    def check(self):
        for target in self.targets:
            value = self.inspect(target)
            if value is not None:
                assert not target.startswith('system/'), 'Unexpected privileged fixture job'
                if target not in self.created_user_jobs: self.created_user_jobs.append(target)
    def close(self):
        self.check()
        for target in self.created_user_jobs:
            if self.inspect(target) is not None:
                command('/bin/launchctl', 'bootout', target, timeout=10)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if all(self.inspect(target) is None for target in self.targets): return
            time.sleep(0.1)
        raise RuntimeError('Fixture jobs did not retire')


def bundle(root, directory, products, identity, version, public_key, port):
    app = root / directory / 'Fixture.app'
    executable = app / 'Contents/MacOS/SparkleBoundaryProbe'
    executable.parent.mkdir(parents=True)
    shutil.copy2(products / 'SparkleBoundaryProbe', executable)
    (app / 'Contents/Frameworks').mkdir()
    shutil.copytree((products / 'Sparkle.framework').resolve(), app / 'Contents/Frameworks/Sparkle.framework', symlinks=True)
    info = {'CFBundleIdentifier': identity, 'CFBundleName': 'Disposable Sparkle Boundary',
            'CFBundleExecutable': 'SparkleBoundaryProbe', 'CFBundlePackageType': 'APPL',
            'CFBundleVersion': str(version), 'CFBundleShortVersionString': f'0.{version}.0',
            'LSUIElement': True, 'SUFeedURL': f'http://127.0.0.1:{port}/feed.xml',
            'SUPublicEDKey': public_key, 'SUEnableAutomaticChecks': False,
            'SUAutomaticallyUpdate': True, 'SUAllowsAutomaticUpdates': True, 'SUEnableInstallerLauncherService': False,
            'SUEnableDownloaderService': False, 'SURequireSignedFeed': True,
            'SUVerifyUpdateBeforeExtraction': True, 'SUSignedFeedFailureExpirationInterval': 0,
            'NSAppTransportSecurity': {'NSAllowsLocalNetworking': True}}
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    validate_tree(root, app)
    # Re-sign only copied disposable bundles, including nested SDK code.
    command('/usr/bin/codesign', '--force', '--deep', '--sign', '-', app)
    command('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
    return app


def wait_version(app, version, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if plistlib.loads((app/'Contents/Info.plist').read_bytes())['CFBundleVersion'] == str(version): return
        except (FileNotFoundError, plistlib.InvalidFileException): pass
        time.sleep(0.1)
    raise TimeoutError('Actual bundle replacement not observed')


def control(products, mode):
    identity = PREFIX + uuid.uuid4().hex
    cache = Path.home() / 'Library/Caches' / identity
    preferences = Path.home() / 'Library/Preferences' / (identity + '.plist')
    assert not cache.exists() and not cache.is_symlink() and not preferences.exists()
    jobs = FixtureJobs(identity)
    children = []
    requests = []
    with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as temporary:
        root = Path(temporary).resolve()
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                if self.path not in ['/feed.xml', '/update.zip'] or len(requests) > 6:
                    self.send_error(404); return
                body = (root/self.path[1:]).read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'application/xml' if self.path == '/feed.xml' else 'application/octet-stream')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def log_message(self, *args): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            bootstrap = bundle(root, 'Signer', products, identity, 1, base64.b64encode(bytes(32)).decode(), server.server_port)
            signer = Child([bootstrap/'Contents/MacOS/SparkleBoundaryProbe', 'signer', root, f'http://127.0.0.1:{server.server_port}/update.zip'])
            children.append(signer)
            public_key = signer.expect('public-key')['key']
            assert len(base64.b64decode(public_key, validate=True)) == 32
            app = bundle(root, 'Host', products, identity, 1, public_key, server.server_port)
            candidate = bundle(root, 'Candidate', products, identity, 2, public_key, server.server_port)
            active = None
            if mode == 'staging':
                active = root / 'Active/Fixture.app'; active.parent.mkdir()
                shutil.copytree(app, active, symlinks=True)
            original = digest(app); active_original = digest(active) if active else None
            command('/usr/bin/ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', candidate, root/'update.zip')
            signer.send('sign\n'); signer.expect('feed-signed'); assert signer.process.wait(timeout=5) == 0
            validate_tree(root, app)
            busy = Child(['/usr/bin/python3', '-u', '-c', 'import sys; print("{\\"event\\":\\"busy\\"}", flush=True); sys.stdin.read()'])
            children.append(busy); busy.expect('busy', seconds=5)
            host = Child([app/'Contents/MacOS/SparkleBoundaryProbe', 'run', root]); children.append(host)
            assert host.expect('started')['pid'] == host.process.pid
            host.expect('verified-feed'); host.expect('prepared-on-quit', seconds=45)
            jobs.check()
            assert digest(app) == original and busy.process.poll() is None
            if mode == 'held-release':
                host.send('resume\n'); host.expect('postponed', seconds=10)
                time.sleep(1)
                assert digest(app) == original and busy.process.poll() is None
                busy.close()  # The fixture reaches idle before callback release.
                host.send('release\n')
            else:
                host.send('resume\n'); host.expect('postponed', seconds=10)
                assert digest(app) == original and busy.process.poll() is None
                host.send('exit\n'); host.expect('fixture-exiting'); assert host.process.wait(timeout=5) == 0
            wait_version(app, 2)
            command('/usr/bin/codesign', '--verify', '--deep', '--strict', app)
            assert digest(app) == digest(candidate), 'Replacement bytes differ from the signed candidate'
            if mode != 'held-release': assert busy.process.poll() is None
            if active: assert digest(active) == active_original
            assert requests == ['/feed.xml', '/update.zip'], requests
            print(json.dumps({'control': mode, 'actualReplacement': True,
                              'busyRoleAliveAtReplacement': mode != 'held-release',
                              'activeBundleUnchanged': True if active else None,
                              'installedCandidateBytesMatch': True,
                              'heldObservationSeconds': 1 if mode == 'held-release' else None,
                              'signedFeedAndArchiveRequests': requests}, sort_keys=True), flush=True)
        finally:
            # Reap only children held by this harness, then exact initially-absent user jobs.
            for child in reversed(children): child.close()
            jobs.close()
            server.shutdown(); server.server_close(); thread.join(timeout=5)
            subprocess.run(['/usr/bin/defaults', 'delete', identity], capture_output=True, timeout=5)
            if cache.exists():
                assert cache == cache.resolve() and cache.stat().st_uid == os.getuid()
                shutil.rmtree(cache)
            assert not cache.exists()
            print(json.dumps({'control': mode, 'fixtureJobsRemoved': True, 'fixtureCacheRemoved': True, 'temporaryUserJobTargets': len(jobs.created_user_jobs)}), flush=True)


def main():
    assert os.getuid() != 0 and os.getuid() == os.geteuid()
    products = Path(command('/usr/bin/swift', 'build', '--package-path', PACKAGE, '--show-bin-path').decode().strip())
    for mode in ['held-release', 'host-exit', 'staging']: control(products, mode)

if __name__ == '__main__': main()
