#!/usr/bin/env python3
"""Build and inspect the Mac app without launching it or registering services."""
from pathlib import Path
import plistlib
import os
import subprocess

from macos_build_checks import require, run, verify_executable

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / '.build' / 'macos-app'


def check(configuration):
    result = run('xcodebuild', '-project', str(ROOT / 'macos/app/Remozio.xcodeproj'),
                 '-scheme', 'Remozio', '-configuration', configuration,
                 '-destination', 'generic/platform=macOS', '-derivedDataPath', str(BUILD / 'DerivedData'),
                 'build', check=False)
    log = BUILD / f'xcodebuild-{configuration.lower()}.log'
    log.write_text(result.stdout + result.stderr)
    require(result.returncode == 0, f'Mac app build failed; see {log}')
    app = BUILD / f'DerivedData/Build/Products/{configuration}/Remozio.app'
    identity = 'dev.remozio.mac.debug' if configuration == 'Debug' else 'dev.remozio.mac'
    run('codesign', '--verify', '--deep', '--strict', str(app))
    verify_executable(app / 'Contents/MacOS/Remozio', identity)
    authority = app / 'Contents/Library/LaunchServices/RemozioAuthority'
    authority_identity = 'dev.remozio.authority.debug' if configuration == 'Debug' else 'dev.remozio.authority'
    require(authority.is_file(), 'Missing embedded authority executable')
    verify_executable(authority, authority_identity)
    run('codesign', '--verify', '--strict', '-R', '=info[RemozioSecurityGeneration] = "1"', str(authority))
    original = BUILD / f'DerivedData/Build/Products/{configuration}/RemozioAuthority'
    require(authority.read_bytes() == original.read_bytes(), 'Embedding changed the signed authority executable')
    usage = subprocess.run([str(authority)], text=True, capture_output=True, timeout=5)
    require(usage.returncode == 64 and 'Usage:' in usage.stderr, 'Authority must reject missing configuration')
    if os.geteuid() != 0:
        for flag in ('--configuration', '--presence-configuration', '--command-configuration'):
            denied = subprocess.run([str(authority), flag, '/nonexistent/remozio.cbor'],
                                    text=True, capture_output=True, timeout=5)
            require(denied.returncode == 77, 'Authority must reject non-root startup before reading configuration')
    setup = app / 'Contents/Library/LaunchServices/RemozioSetup'
    setup_identity = 'dev.remozio.setup-controller.debug' if configuration == 'Debug' else 'dev.remozio.setup-controller'
    require(setup.is_file(), 'Missing embedded setup executable')
    verify_executable(setup, setup_identity)
    run('codesign', '--verify', '--strict', '-R', '=info[RemozioSecurityGeneration] = "1"', str(setup))
    require(setup.read_bytes() == (BUILD / f'DerivedData/Build/Products/{configuration}/RemozioSetup').read_bytes(),
            'Embedding changed the signed setup executable')
    for arguments, status in (([], 64), (['--unknown', '/private/test-path'], 64),
                              *([(['--configuration', '/private/test-path'], 77)] if os.geteuid() != 0 else [])):
        read_descriptor, write_descriptor = os.pipe()
        try:
            original_input = b'unread setup input\x00\xff'
            os.write(write_descriptor, original_input); os.close(write_descriptor); write_descriptor = -1
            refused = subprocess.run([str(setup), *arguments], stdin=read_descriptor, capture_output=True, timeout=5)
            require(refused.returncode == status, 'Setup must refuse invalid syntax or non-root startup')
            require(os.read(read_descriptor, 64) == original_input and not refused.stdout, 'Refused setup consumed stdin or wrote stdout')
            require(b'/private/test-path' not in refused.stderr, 'Setup startup disclosed a private path')
        finally:
            os.close(read_descriptor)
            if write_descriptor >= 0: os.close(write_descriptor)
    transport = app / 'Contents/Library/LaunchServices/RemozioTransport'
    transport_identity = 'dev.remozio.transport.debug' if configuration == 'Debug' else 'dev.remozio.transport'
    require(transport.is_file(), 'Missing embedded approval transport')
    verify_executable(transport, transport_identity)
    run('codesign', '--verify', '--strict', '-R', '=info[RemozioSecurityGeneration] = "1"', str(transport))
    transport_original = BUILD / f'DerivedData/Build/Products/{configuration}/RemozioTransport'
    require(transport.read_bytes() == transport_original.read_bytes(), 'Embedding changed the signed transport')
    for arguments, status in (([], 64), (['--configuration', '/nonexistent/remozio-transport.cbor'], 78),
                              (['--wake-configuration', '/nonexistent/remozio-wake.cbor'], 78),
                              (['--remote-configuration', '/nonexistent/remozio-remote.cbor'], 78),
                              (['--pairing-configuration', '/nonexistent/remozio-pairing.cbor'], 78)):
        read_descriptor, write_descriptor = os.pipe()
        try:
            original_input = b'unread transport input\x00\xff'
            os.write(write_descriptor, original_input); os.close(write_descriptor); write_descriptor = -1
            refused = subprocess.run([str(transport), *arguments], stdin=read_descriptor, capture_output=True, timeout=5)
            require(refused.returncode == status, 'Transport must refuse incomplete provisioning')
            require(os.read(read_descriptor, 64) == original_input and not refused.stdout,
                    'Refused transport consumed stdin or wrote command output')
            require(b'/nonexistent' not in refused.stderr, 'Transport startup disclosed a private path')
        finally:
            os.close(read_descriptor)
            if write_descriptor >= 0: os.close(write_descriptor)
    gateway = app / 'Contents/Library/LaunchServices/RemozioGateway'
    gateway_identity = 'dev.remozio.gateway.debug' if configuration == 'Debug' else 'dev.remozio.gateway'
    require(gateway.is_file(), 'Missing embedded push gateway')
    verify_executable(gateway, gateway_identity)
    run('codesign', '--verify', '--strict', '-R', '=info[RemozioSecurityGeneration] = "1"', str(gateway))
    gateway_original = BUILD / f'DerivedData/Build/Products/{configuration}/RemozioGateway'
    require(gateway.read_bytes() == gateway_original.read_bytes(), 'Embedding changed the signed gateway')
    for arguments, status in (([], 64), (['--configuration', '/nonexistent/remozio-gateway.cbor'], 78)):
        read_descriptor, write_descriptor = os.pipe()
        try:
            original_input = b'unread gateway input\x00\xff'
            os.write(write_descriptor, original_input); os.close(write_descriptor); write_descriptor = -1
            refused = subprocess.run([str(gateway), *arguments], stdin=read_descriptor, capture_output=True, timeout=5)
            require(refused.returncode == status, 'Gateway must refuse incomplete provisioning')
            require(os.read(read_descriptor, 64) == original_input and not refused.stdout,
                    'Refused gateway consumed stdin or wrote command output')
            require(b'/nonexistent' not in refused.stderr, 'Gateway startup disclosed a private path')
        finally:
            os.close(read_descriptor)
            if write_descriptor >= 0: os.close(write_descriptor)
    child = app / 'Contents/Helpers/RemozioCommandChild'
    child_identity = 'dev.remozio.command-child.debug' if configuration == 'Debug' else 'dev.remozio.command-child'
    require(child.is_file(), 'Missing embedded command child')
    verify_executable(child, child_identity)
    run('codesign', '--verify', '--strict', '-R', '=info[RemozioSecurityGeneration] = "1"', str(child))
    child_original = BUILD / f'DerivedData/Build/Products/{configuration}/RemozioCommandChild'
    require(child.read_bytes() == child_original.read_bytes(), 'Embedding changed the signed command child')
    frontend = app / 'Contents/Helpers/remozio'
    frontend_identity = 'dev.remozio.command-frontend.debug' if configuration == 'Debug' else 'dev.remozio.command-frontend'
    require(frontend.is_file(), 'Missing embedded command frontend')
    verify_executable(frontend, frontend_identity)
    run('codesign', '--verify', '--strict', '-R', '=info[RemozioSecurityGeneration] = "1"', str(frontend))
    frontend_original = BUILD / f'DerivedData/Build/Products/{configuration}/remozio'
    require(frontend.read_bytes() == frontend_original.read_bytes(), 'Embedding changed the signed command frontend')
    for arguments, status in (([], 64), (['--help'], 0), (['run', '--pipes', '/usr/bin/true'], 64),
                              (['sudo', '--unknown', '--', '/usr/bin/true'], 64),
                              (['run', b'private-argument-\xff'], 64)):
        read_descriptor, write_descriptor = os.pipe()
        try:
            original_input = b'unread frontend input\x00\xff'
            os.write(write_descriptor, original_input); os.close(write_descriptor); write_descriptor = -1
            refused = subprocess.run([str(frontend), *arguments], stdin=read_descriptor, capture_output=True, timeout=5)
            require(refused.returncode == status and b'Usage:' in refused.stderr, 'Frontend syntax/help result changed')
            require(os.read(read_descriptor, 64) == original_input, 'Frontend syntax/help consumed command stdin')
            require(not refused.stdout and b'/usr/bin/true' not in refused.stderr,
                    'Frontend syntax/help wrote command output or logged command arguments')
            require(b'private-argument' not in refused.stderr, 'Frontend logged a raw private argument')
        finally:
            os.close(read_descriptor)
            if write_descriptor >= 0: os.close(write_descriptor)
    require(subprocess.run([str(child)], timeout=5).returncode == 64, 'Command child must reject public command arguments')
    if os.geteuid() != 0:
        for mode in ('--execute', '--execute-in-session'):
            read_descriptor, write_descriptor = os.pipe()
            try:
                os.write(write_descriptor, b'unread command input'); os.close(write_descriptor); write_descriptor = -1
                denied_child = subprocess.run([str(child), mode], stdin=read_descriptor, capture_output=True, timeout=5)
                require(denied_child.returncode == 77, 'Command child must require root before reading private data')
                require(os.read(read_descriptor, 64) == b'unread command input', 'Refused command child consumed stdin')
                require(not denied_child.stdout and not denied_child.stderr, 'Command child wrote to the command streams')
            finally:
                os.close(read_descriptor)
                if write_descriptor >= 0: os.close(write_descriptor)
    monitor = app / 'Contents/Helpers/RemozioCommandMonitor'
    monitor_identity = 'dev.remozio.command-monitor.debug' if configuration == 'Debug' else 'dev.remozio.command-monitor'
    require(monitor.is_file(), 'Missing embedded command monitor')
    verify_executable(monitor, monitor_identity)
    run('codesign', '--verify', '--strict', '-R', '=info[RemozioSecurityGeneration] = "1"', str(monitor))
    monitor_original = BUILD / f'DerivedData/Build/Products/{configuration}/RemozioCommandMonitor'
    require(monitor.read_bytes() == monitor_original.read_bytes(), 'Embedding changed the signed command monitor')
    require(subprocess.run([str(monitor)], timeout=5).returncode == 64, 'Command monitor must reject public command arguments')
    if os.geteuid() != 0:
        read_descriptor, write_descriptor = os.pipe()
        try:
            os.write(write_descriptor, b'unread command input'); os.close(write_descriptor); write_descriptor = -1
            denied_monitor = subprocess.run([str(monitor), '--monitor', str(child)], stdin=read_descriptor, capture_output=True, timeout=5)
            require(denied_monitor.returncode == 77, 'Command monitor must require root before reading private data')
            require(os.read(read_descriptor, 64) == b'unread command input', 'Refused command monitor consumed stdin')
            require(not denied_monitor.stdout and not denied_monitor.stderr, 'Command monitor wrote to the command streams')
        finally:
            os.close(read_descriptor)
            if write_descriptor >= 0: os.close(write_descriptor)
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    require(info['CFBundleIdentifier'] == identity, 'Unexpected bundle identity')
    require(info.get('RemozioSecurityGeneration') == '1', 'Missing app security generation')
    declaration = info.get('RemozioReleaseManifest')
    require(isinstance(declaration, bytes) and 0 < len(declaration) <= 65536, 'Missing bounded release declaration')
    run('codesign', '--verify', '--strict', '-R', '=info[RemozioSecurityGeneration] = "1"', str(app))
    require(info['LSMinimumSystemVersion'] == '26.0', 'Unexpected deployment target')
    require(not info.get('LSUIElement', False), 'The app must remain reachable after hiding its menu item')
    strings = app / 'Contents/Resources/en.lproj/Localizable.strings'
    resources = plistlib.loads(run('plutil', '-convert', 'xml1', '-o', '-', str(strings)).stdout.encode())
    require(resources.get('This Mac is not configured') == 'This Mac is not configured', 'Missing application strings')
    daemon_directory = app / 'Contents/Library/LaunchDaemons'
    require({p.name for p in daemon_directory.iterdir()} == {'dev.remozio.setup.plist', 'dev.remozio.authority.plist'}, 'Unexpected bundled daemon manifests')
    job = plistlib.loads((daemon_directory / 'dev.remozio.setup.plist').read_bytes())
    require(job == {'Label': 'dev.remozio.setup', 'BundleProgram': 'Contents/Library/LaunchServices/RemozioSetup',
        'ProgramArguments': ['Contents/Library/LaunchServices/RemozioSetup', '--configuration', '/Library/Application Support/Remozio/setup.cbor'],
        'UserName': 'root', 'RunAtLoad': True, 'KeepAlive': True, 'MachServices': {'dev.remozio.setup': True}},
        'Setup manifest differs from the fixed local service contract')
    authority_job = plistlib.loads((daemon_directory / 'dev.remozio.authority.plist').read_bytes())
    require(authority_job == {'Label': 'dev.remozio.authority', 'BundleProgram': 'Contents/Library/LaunchServices/RemozioAuthority', 'ProgramArguments': ['Contents/Library/LaunchServices/RemozioAuthority', '--command-configuration', '/Library/Application Support/Remozio/command-host.cbor'], 'UserName': 'root', 'RunAtLoad': True, 'KeepAlive': True, 'MachServices': {'dev.remozio.authority': True, 'dev.remozio.presence': True, 'dev.remozio.commands': True}},
        'Authority manifest differs from the fixed command service contract')
    require(not (app / 'Contents/Library/LaunchAgents').exists(), 'Unexpected service manifests in the app scaffold')
    print(f'Mac app {configuration}: arm64, macOS 26, signature, runtime, resources, and bundle checks passed.')


if __name__ == '__main__':
    BUILD.mkdir(parents=True, exist_ok=True)
    for configuration in ('Debug', 'Release'):
        check(configuration)
