#!/usr/bin/env python3
"""Exercise pinned Sparkle feed verification without downloads or installation."""
import http.server
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'experiments/sparkle-probe'


def run(*arguments):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f'Probe command failed ({result.returncode}): {result.stderr}')
    return result


def main():
    binary_dir = Path(run('swift', 'build', '--package-path', PACKAGE, '--show-bin-path').stdout.strip())
    binary = binary_dir / 'SparkleProbe'
    framework = binary_dir / 'Sparkle.framework'
    with tempfile.TemporaryDirectory(prefix='remozio-sparkle-') as temporary:
        root = Path(temporary)
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                if self.path not in ('/valid.xml', '/unsigned.xml', '/tampered.xml', '/wrong-key.xml'):
                    self.send_error(404)
                    return
                body = (root / self.path[1:]).read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'application/xml')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        run(binary, 'prepare', root, f'http://127.0.0.1:{server.server_port}/never-download.zip')
        public_key = (root / 'public-key.txt').read_text()
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for case in ('valid', 'unsigned', 'tampered', 'wrong-key'):
                identity = f'dev.sebastiano.remozio.macos.experiments.sparkle.{uuid.uuid4().hex}'
                app = root / f'{case}.app'
                executable = app / 'Contents/MacOS/SparkleProbe'
                executable.parent.mkdir(parents=True)
                shutil.copy2(binary, executable)
                (executable.parent / 'Sparkle.framework').symlink_to(framework, target_is_directory=True)
                info = {'CFBundleIdentifier': identity, 'CFBundleName': 'Disposable Sparkle Probe',
                        'CFBundleExecutable': 'SparkleProbe', 'CFBundlePackageType': 'APPL',
                        'CFBundleVersion': '1', 'CFBundleShortVersionString': '0.1.0',
                        'SUFeedURL': f'http://127.0.0.1:{server.server_port}/{case}.xml',
                        'SUPublicEDKey': public_key, 'SUEnableAutomaticChecks': False,
                        'SUAutomaticallyUpdate': False, 'SUEnableInstallerLauncherService': False,
                        'SUEnableDownloaderService': False,
                        'SURequireSignedFeed': True, 'SUVerifyUpdateBeforeExtraction': True,
                        'SUSignedFeedFailureExpirationInterval': 0,
                        'NSAppTransportSecurity': {'NSAllowsLocalNetworking': True}}
                (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
                try:
                    result = run(executable, 'probe', app)
                    outcome = json.loads(result.stdout.strip().splitlines()[-1])
                    if case == 'valid':
                        assert outcome == {'found': '2', 'signatureValid': True, 'errorCode': None, 'selectionChecks': 1, 'frameworkError': False}, outcome
                    else:
                        assert outcome == {'found': None, 'signatureValid': False, 'errorCode': 1000, 'selectionChecks': 0, 'frameworkError': True}, outcome
                    print(f'{case}: {json.dumps(outcome, sort_keys=True)}')
                finally:
                    subprocess.run(['defaults', 'delete', identity], capture_output=True, timeout=10)
            assert requests == ['/valid.xml', '/unsigned.xml', '/tampered.xml', '/wrong-key.xml'], requests
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
    print('Sparkle feed experiment passed. No archive, installation, service registration, or production key was used.')


if __name__ == '__main__':
    main()
