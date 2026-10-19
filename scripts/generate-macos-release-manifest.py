#!/usr/bin/env python3
"""Generate the app Info.plist input from signed helper products, before app signing."""
import os
from pathlib import Path
import plistlib
import re
import subprocess

# Role numbers are stable AuthorityCodeRole values. No service registration is installed here.
COMPONENTS = (
    (1, 'mac', 'Contents/MacOS/Remozio', None, None),
    (2, 'authority', 'Contents/Library/LaunchServices/RemozioAuthority', 'RemozioAuthority', 'Authority'),
    (4, 'transport', 'Contents/Library/LaunchServices/RemozioTransport', 'RemozioTransport', 'Transport'),
    (5, 'command-frontend', 'Contents/Helpers/remozio', 'remozio', 'CommandFrontend'),
    (6, 'gateway', 'Contents/Library/LaunchServices/RemozioGateway', 'RemozioGateway', 'Gateway'),
    (8, 'setup-controller', 'Contents/Library/LaunchServices/RemozioSetup', 'RemozioSetup', 'Setup'),
    (11, 'command-child', 'Contents/Helpers/RemozioCommandChild', 'RemozioCommandChild', 'CommandChild'),
    (12, 'command-monitor', 'Contents/Helpers/RemozioCommandMonitor', 'RemozioCommandMonitor', 'CommandMonitor'),
)


def format_declaration(name, versions, migrations=None):
    return {0: name, 1: sorted(versions), 2: sorted(versions), 3: migrations or {}}


def declarations(role):
    names = {
        1: [('authority.presence-client-config', [1]), ('setup.local-ipc', [1, 2, 3, 4, 5, 6, 7]),
            ('transport.pairing-control-config', [1]), ('transport.pairing-control', [1]),
            ('authority.pairing-ipc', [1]), ('pairing.invitation', [1]), ('pairing.transcript', [1])],
        2: [('authority.service-config', [1, 2]), ('authority.request-config', [1]),
            ('authority.wake-config', [1]), ('authority.presence-config', [1, 2]),
            ('authority.pairing-setup-config', [1]), ('authority.pairing-ipc', [1]), ('pairing.transcript', [1]),
            ('authority.command-config', [1, 2]), ('authority.command-host-config', [1, 2, 3]), ('authority.command-execution-config', [1]),
            ('authority.code-policy', [1, 2, 3]), ('command.capture', [1, 2, 3]), ('approval.message', [1])],
        4: [('transport.config', [1, 2]), ('transport.wake-config', [1]), ('transport.remote-config', [1]),
            ('transport.pairing-config', [1]), ('transport.pairing-control-config', [1]), ('transport.pairing-control', [1]),
            ('pairing.invitation', [1]), ('pairing.transcript', [1]), ('pairing.setup-frame', [1]),
            ('command.capture', [1, 2, 3]), ('approval.message', [1])],
        5: [('command.frontend-config', [1]), ('command.submission', [1])],
        6: [('gateway.service-config', [1, 2]), ('gateway.wake-endpoint-config', [1]), ('gateway.wake-signer-config', [1])],
        8: [('setup.service-config', [1]), ('setup.local-ipc', [1, 2, 3, 4, 5, 6, 7]), ('authority.code-policy', [1, 2, 3]),
            ('authority.installation-inventory', [1, 2]), ('authority.installation-preparation', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
            ('authority.journal', [12, 13, 14, 15, 16])],
        11: [('command.child-frame', [1, 2])],
        12: [('command.monitor-frame', [2]), ('command.child-frame', [1, 2])],
    }
    values = [format_declaration(name, versions, {1: 2} if name == 'authority.installation-inventory' else None)
              for name, versions in names[role]]
    if role == 2:
        values.append(format_declaration('authority.installation-inventory', [1, 2], {1: 2}))
        values.append(format_declaration('authority.installation-preparation', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], {1: 2}))
        values.append(format_declaration('authority.journal', [12, 13, 14, 15, 16], {v: 12 for v in range(1, 12)}))
    # Retained record versions follow the compiled codecs. Setup is the only emitter in this release.
    records = {
        2: [('runtime.gateway-role-extension', [1], []), ('runtime.gateway-runtime-commit', [1, 2], []),
            ('runtime.gateway-runtime-pair', [1], []), ('runtime.gateway-activation-plan', [1], []),
            ('runtime.gateway-settings-revision', [1], [])],
        4: [('runtime.gateway-role-extension', [1], []), ('runtime.gateway-runtime-commit', [1, 2], []),
            ('runtime.gateway-settings-revision', [1], [])],
        6: [('runtime.gateway-role-extension', [1], []), ('runtime.gateway-runtime-commit', [1, 2], []),
            ('runtime.gateway-settings-revision', [1], [])],
        8: [('runtime.gateway-role-extension', [1], [1]), ('runtime.gateway-runtime-commit', [1, 2], [1, 2]),
            ('runtime.gateway-runtime-pair', [1], [1]), ('runtime.gateway-activation-plan', [1], [1]),
            ('runtime.gateway-settings-revision', [1], [1])],
    }
    for name, readers, writers in records.get(role, []):
        values.append({0: name, 1: readers, 2: writers, 3: {}})
    if role == 8:
        values.append(format_declaration('authority.command-host-config', [1, 2, 3]))
    if role in (2, 8):
        values.append(format_declaration('authority.gateway-settings-control', [1]))
    if role in (2, 4, 6, 8):
        values.append({0: 'runtime.gateway-settings-fence', 1: [1], 2: [1] if role == 8 else [], 3: {}})
    if role in (6, 8):
        values.append(format_declaration('gateway.gateway-settings-control', [1]))
    if role in (4, 8):
        values.append(format_declaration('transport.gateway-settings-control', [1]))
    if role in (2, 4, 6, 8):
        values.append({0: 'runtime.material-reference', 1: [1, 2], 2: [1, 2] if role == 8 else [], 3: {}})
        values.append({0: 'runtime.service-release-activity-reference', 1: [1], 2: [1] if role == 8 else [], 3: {}})
    if role in (2, 8):
        values.append({0: 'runtime.preparation-material', 1: [1, 2], 2: [1, 2] if role == 8 else [], 3: {}})
    host_formats = {
        2: [('runtime.gateway-settings-consumer-host', [1], []),
            ('transport.pairing-config', [1, 2], []), ('gateway.service-config', [1, 2], [])],
        4: [('runtime.gateway-settings-consumer-host', [1], []),
            ('transport.pairing-config', [1, 2], [1, 2]), ('gateway.service-config', [1, 2], [])],
        6: [('runtime.gateway-settings-consumer-host', [1], []),
            ('transport.pairing-config', [1, 2], [])],
        8: [('runtime.gateway-settings-consumer-host', [1], [1]),
            ('transport.pairing-config', [1, 2], [1, 2]), ('gateway.service-config', [1, 2], [1, 2])],
    }
    by_name = {value[0]: value for value in values}
    if len(by_name) != len(values):
        raise ValueError('duplicate format declaration before host overrides')
    for name, readers, writers in host_formats.get(role, []):
        by_name[name] = {0: name, 1: readers, 2: writers, 3: {}}
    return sorted(by_name.values(), key=lambda v: v[0])


def encode(value):
    """The bounded manifest subset of deterministic CBOR; Swift independently decodes it."""
    def head(major, length):
        if length < 24:
            return bytes([major << 5 | length])
        for size, tag in ((1, 24), (2, 25), (4, 26), (8, 27)):
            if length < 1 << (size * 8):
                return bytes([major << 5 | tag]) + length.to_bytes(size, 'big')
        raise ValueError('integer exceeds UInt64')
    if value is None:
        return b'\xf6'
    if type(value) is int and value >= 0:
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode('utf-8')
        return head(3, len(data)) + data
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(encode(v) for v in value)
    if isinstance(value, dict) and all(type(k) is int and k >= 0 for k in value):
        return head(5, len(value)) + b''.join(encode(k) + encode(value[k]) for k in sorted(value))
    raise ValueError('unsupported manifest value')


def signed_identity(executable, identifier, generation):
    subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R',
                    f'=identifier "{identifier}" and info[RemozioSecurityGeneration] = "{generation}"', str(executable)], check=True, timeout=20)
    result = subprocess.run(['/usr/bin/codesign', '--display', '--verbose=4', str(executable)],
                            capture_output=True, text=True, check=True, timeout=20)
    def field(name):
        match = re.search(rf'^{name}=(.*)$', result.stderr, re.MULTILINE)
        if not match:
            raise ValueError(f'missing signing field: {name}')
        return match.group(1)
    if field('Identifier') != identifier or 'runtime)' not in result.stderr:
        raise ValueError('unexpected helper signing identity or runtime')
    digest = bytes.fromhex(field('CDHash'))
    if len(digest) != 20:
        raise ValueError('unexpected code hash size')
    team = field('TeamIdentifier')
    return digest, None if team == 'not set' else team


def generate(environment):
    source = Path(environment['SRCROOT'])
    products = Path(environment['BUILT_PRODUCTS_DIR'])
    suffix = '.debug' if environment['CONFIGURATION'] == 'Debug' else ''
    identifier = environment['PRODUCT_BUNDLE_IDENTIFIER']
    if identifier != 'dev.remozio.mac' + suffix or environment['MACOSX_DEPLOYMENT_TARGET'] != '26.0':
        raise ValueError('unsupported app identity or baseline')
    release, build = environment['MARKETING_VERSION'], environment['CURRENT_PROJECT_VERSION']
    components = []
    teams = set()
    for role, name, path, product, folder in COMPONENTS:
        expected = 'dev.remozio.' + name + suffix
        if product:
            plist = plistlib.loads((source / folder / 'Info.plist').read_bytes())
            generation = plist['RemozioSecurityGeneration']
            if not re.fullmatch(r'[1-9][0-9]{0,19}', generation) or int(generation) > (1 << 64) - 1:
                raise ValueError('invalid generation')
            digest, team = signed_identity(products / product, expected, generation)
            teams.add(team)
            component_build = plist['CFBundleVersion']
        else:
            generation, digest, team, component_build = '1', None, None, build
        requests = [{0: 0, 1: 1, 2: schema, 3: [0, 2], 4: [1, 2, 4, 5]} for schema in (1, 2, 3)] if role in (2, 4) else []
        components.append({0: role, 1: expected, 2: int(generation), 3: path, 4: digest, 5: component_build,
                           6: team, 7: declarations(role), 8: requests, 9: 0})
    if len(teams) != 1:
        raise ValueError('helper Team IDs differ')
    components[0][6] = teams.pop()
    manifest = encode({0: 1, 1: release, 2: build, 3: 'arm64', 4: '26.0', 5: components})
    if len(manifest) > 65536:
        raise ValueError('manifest exceeds size limit')
    return {'CFBundleIdentifier': identifier, 'CFBundleName': 'Remozio', 'CFBundleExecutable': 'Remozio',
            'CFBundlePackageType': 'APPL', 'CFBundleVersion': build, 'CFBundleShortVersionString': release,
            'LSMinimumSystemVersion': '26.0', 'LSApplicationCategoryType': 'public.app-category.utilities',
            'RemozioSecurityGeneration': '1', 'RemozioReleaseManifest': manifest}


if __name__ == '__main__':
    output = Path(os.environ['SCRIPT_OUTPUT_FILE_0'])
    output.parent.mkdir(parents=True, exist_ok=True)
    data = plistlib.dumps(generate(os.environ), fmt=plistlib.FMT_XML, sort_keys=True)
    # Preserve the timestamp when inputs do not change, to avoid an unnecessary app re-sign.
    if not output.exists() or output.read_bytes() != data:
        output.write_bytes(data)
