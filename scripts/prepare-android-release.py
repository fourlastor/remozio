#!/usr/bin/env python3
"""Verify a signed standalone APK and prepare a new local release directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

MAX_APK_BYTES = 256 * 1024 * 1024
ASSET = 'remozio-android.apk'


def validate_version(version):
    match = re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', version)
    if not match or len(version) > 128 or any(int(match[i]) > 2**31 - 1 for i in (1, 2, 3)):
        raise ValueError('Invalid release version')
    if any(len(part) > 1 and part.isdigit() and part.startswith('0') for part in (match[4] or '').split('.')):
        raise ValueError('Invalid numeric prerelease identifier')


def check_metadata(text, version, code):
    packages = [line for line in text.splitlines() if line.startswith('package: ')]
    if len(packages) != 1:
        raise ValueError('Expected one package')
    fields = dict(re.findall(r"([A-Za-z][A-Za-z0-9]*)='([^']*)'", packages[0]))
    if fields.get('name') != 'dev.sebastiano.remozio.android' or fields.get('versionName') != version or fields.get('versionCode') != str(code):
        raise ValueError('APK package or version does not match the release')
    if 'split' in fields or 'application-debuggable' in text or 'testOnly' in text:
        raise ValueError('APK must be standalone and production-only')
    for name in ('minSdkVersion', 'targetSdkVersion'):
        if re.findall(rf"^{name}:'([^']*)'$", text, re.MULTILINE) != ['37']:
            raise ValueError('APK SDK contract does not match the release')


def check_signer(text, fingerprint):
    digests = re.findall(r'^(?:Signer #[0-9]+|V[0-9]+\.[0-9]+ Signer:) certificate SHA-256 digest: ([0-9a-fA-F]{64})$', text, re.MULTILINE)
    if re.findall(r'^Number of signers: ([0-9]+)$', text, re.MULTILINE) != ['1'] or not digests or set(value.lower() for value in digests) != {fingerprint.lower()}:
        raise ValueError('APK signer does not match the expected certificate')


def run_tool(tool, *args):
    result = subprocess.run([str(tool), *map(str, args)], capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise ValueError(f'{tool.name} rejected the APK')
    return result.stdout


def prepare(apk, destination, sdk, version, code, fingerprint):
    validate_version(version)
    if not 1 <= code <= 2_100_000_000 or not re.fullmatch(r'[0-9a-fA-F]{64}', fingerprint):
        raise ValueError('Invalid version code or signer fingerprint')
    if destination.exists() or destination.is_symlink():
        raise ValueError('Release destination already exists')
    tools = sdk / 'build-tools' / '37.0.0'
    # Verify the copied bytes, so a changing source cannot replace the checked artifact.
    with tempfile.TemporaryDirectory(prefix='.remozio-release-', dir=destination.parent) as temporary:
        staging = Path(temporary)
        artifact = staging / ASSET
        total = 0
        with apk.open('rb') as source, artifact.open('xb') as output:
            while chunk := source.read(64 * 1024):
                total += len(chunk)
                if total > MAX_APK_BYTES:
                    raise ValueError('APK exceeds release size limit')
                output.write(chunk)
        if not total:
            raise ValueError('APK is empty')
        check_metadata(run_tool(tools / 'aapt2', 'dump', 'badging', artifact), version, code)
        # Inspect testOnly directly: badging output does not reliably include this attribute.
        manifest = run_tool(tools / 'aapt2', 'dump', 'xmltree', artifact, '--file', 'AndroidManifest.xml')
        if re.search(r'android:(?:testOnly|debuggable)\([^\n]*=\(type 0x12\)0xffffffff', manifest):
            raise ValueError('APK contains a debug or test-only application')
        check_signer(run_tool(tools / 'apksigner', 'verify', '--min-sdk-version', '37', '--verbose', '--print-certs', artifact), fingerprint)
        run_tool(tools / 'zipalign', '-c', '-P', '16', '4', artifact)
        with artifact.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        (staging / 'SHA256SUMS').write_text(f'{digest}  {ASSET}\n')
        (staging / 'release.json').write_text(json.dumps({
            'schema': 1, 'versionName': version, 'versionCode': code,
            'packageName': 'dev.sebastiano.remozio.android', 'asset': ASSET, 'bytes': total,
            'sha256': digest, 'signerCertificateSha256': fingerprint.lower(),
        }, indent=2) + '\n')
        # mkdir refuses an existing destination, including one created during verification.
        destination.mkdir()
        try:
            for entry in staging.iterdir():
                shutil.move(str(entry), destination / entry.name)
        except BaseException:
            shutil.rmtree(destination)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, default=os.environ.get('ANDROID_HOME'))
    parser.add_argument('--version', required=True)
    parser.add_argument('--code', type=int, required=True)
    parser.add_argument('--signer-sha256', required=True)
    args = parser.parse_args()
    if args.sdk is None:
        parser.error('--sdk or ANDROID_HOME is required')
    try:
        prepare(args.apk, args.output, args.sdk, args.version, args.code, args.signer_sha256)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'Release preparation failed: {error}\n')
    print(f'Prepared {args.output / ASSET}; nothing was uploaded.')


if __name__ == '__main__':
    main()
