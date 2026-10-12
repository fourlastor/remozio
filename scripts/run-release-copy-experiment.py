import base64
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile
import uuid

import argparse
parser=argparse.ArgumentParser(description='Prepare owned signed release fixtures without installing services.')
parser.add_argument('--identity',required=True)
parser.add_argument('--team-id',required=True)
args=parser.parse_args()
if sys.platform!='darwin' or os.getuid()==0 or os.getuid()!=os.geteuid():
    raise SystemExit('The experiment requires an ordinary macOS account.')
REPO=Path(__file__).resolve().parents[1]
for name,path in [('boundary',REPO/'scripts/run-sparkle-boundary-experiment.py'),('sdk',REPO/'scripts/sparkle_sdk_fixture.py')]:
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
boundary=sys.modules['boundary'];sdk=sys.modules['sdk']
config=sdk.SigningConfig(args.identity,args.team_id)
def built(package):
    boundary.command('/usr/bin/swift','build','--package-path',package,'--triple','arm64-apple-macosx26.0','--disable-keychain','--disable-netrc')
    return Path(boundary.command('/usr/bin/swift','build','--package-path',package,'--triple','arm64-apple-macosx26.0','--show-bin-path').decode().strip())
products=built(boundary.PACKAGE)
inspection_products=built(REPO/'experiments/release-dependencies')
copy_products=built(REPO/'experiments/release-copy')
inspector=inspection_products/'DependencyProbe';copy_probe=copy_products/'ReleaseCopyProbe'
original_sdk=boundary.digest((products/'Sparkle.framework').resolve())


def inspect(app, identity):
    value=subprocess.run([str(inspector),'inspect',str(app),config.team,identity],capture_output=True,timeout=10)
    if value.returncode:raise RuntimeError(value.stderr.decode().strip())
    return json.loads(value.stdout)


try:
    with tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as source_temporary, \
         tempfile.TemporaryDirectory(prefix='remozio-sparkle-boundary-') as copied_temporary:
        source_root=Path(source_temporary).resolve();copied_root=Path(copied_temporary).resolve()
        identity=boundary.PREFIX+uuid.uuid4().hex
        source=sdk.SDKFixtureSigner(boundary,config).bundle(source_root,'Host',products,identity,1,
                                                           base64.b64encode(bytes(32)).decode(),1)
        boundary.command(inspector,'prepare',source,config.team,identity)
        entitlements=source_root/'empty.plist';entitlements.write_bytes(plistlib.dumps({}))
        boundary.command('/usr/bin/codesign','--force','--sign',config.identity,'--options','runtime','--timestamp=none',
                         '--identifier',identity,'--entitlements',entitlements,source)
        boundary.command('/usr/bin/codesign','--verify','--deep','--strict',source)
        expected=inspect(source,identity)
        executable=source/'Contents/MacOS/SparkleBoundaryProbe'
        os.chmod(executable,0o4777)
        boundary.command('/bin/chmod','+a','everyone allow write,writeattr,writeextattr',executable)
        if inspect(source,identity)!=expected:raise RuntimeError('Source metadata changed signing evidence')
        held=os.open(executable,os.O_RDWR|os.O_CLOEXEC)
        try:
            saved_digest=boundary.digest(source)
            parent=copied_root/'Host';parent.mkdir(mode=0o700)
            copied_result=subprocess.run([str(copy_probe),str(source),str(parent),config.team,identity],capture_output=True,timeout=10)
            if copied_result.returncode:raise RuntimeError(copied_result.stderr.decode().strip())
            counts=json.loads(copied_result.stdout)
            copied=parent/'Fixture.app'
            if boundary.digest(copied)!=saved_digest:raise RuntimeError('Copied bytes or link texts changed')
            if inspect(copied,identity)!=expected:raise RuntimeError('Copied signature evidence changed')
            if os.stat(copied/'Contents/MacOS/SparkleBoundaryProbe').st_mode & 0o7022:
                raise RuntimeError('Unsafe source mode survived')
            placement_result=subprocess.run([str(copy_probe),str(source),str(parent),config.team,identity,'inspect-only'],capture_output=True,timeout=10)
            if placement_result.returncode:raise RuntimeError(placement_result.stderr.decode().strip())
            print(json.dumps({'control':'signed-sdk-swift-copy','copiedBytesAndLinksMatch':True,'inspection':expected,
                              'counts':counts,'ordinaryPlacementMetadataVerified':True,'unsafeSourceModeAndACLNotCopied':True,
                              'RootIsolationTested':False,'activation':False}),flush=True)
            rejected_parent=copied_root/'Rejected';rejected_parent.mkdir(mode=0o700)
            policy_rejected=subprocess.run([str(copy_probe),str(source),str(rejected_parent),config.team,identity,'raise-floor'],capture_output=True,timeout=10)
            if policy_rejected.returncode!=65 or 'rollback' not in policy_rejected.stderr.decode():
                raise RuntimeError('Preparation accepted an advanced retained floor')
            if (rejected_parent/'Fixture.app').exists():raise RuntimeError('Rejected copy remained after successful owned cleanup')
            print(json.dumps({'control':'floor-advanced-during-preparation','preparationRejected':True,
                              'ownedCopyRemoved':True,'actualPolicyChanged':False,'activation':False}),flush=True)
            os.pwrite(held,b'X',0);os.fsync(held)
            if inspect(copied,identity)!=expected or boundary.digest(copied)!=saved_digest:
                raise RuntimeError('An open source descriptor changed the copy')
            print(json.dumps({'control':'source-held-descriptor','sourceChangedAfterCopy':True,
                              'copyStillValid':True,'noSharedFileInode':True}),flush=True)
            copied_executable=copied/'Contents/MacOS/SparkleBoundaryProbe'
            boundary.command('/bin/chmod','+a','everyone allow write,writeattr,writeextattr',copied_executable)
            rejected=subprocess.run([str(copy_probe),str(source),str(parent),config.team,identity,'inspect-only'],capture_output=True,timeout=10)
            if rejected.returncode!=65 or 'unsafeMetadata' not in rejected.stderr.decode():
                raise RuntimeError('Placement accepted a mutation ACL')
            print(json.dumps({'control':'copied-mutation-acl','placementRejected':True}),flush=True)
            boundary.command('/bin/chmod','-N',copied_executable)
            if subprocess.run([str(copy_probe),str(source),str(parent),config.team,identity,'inspect-only'],capture_output=True,timeout=10).returncode:
                raise RuntimeError('Placement did not recover after fixture ACL cleanup')
        finally:
            os.close(held)
finally:
    if boundary.digest((products/'Sparkle.framework').resolve())!=original_sdk:
        raise RuntimeError('Original SDK changed')
print(json.dumps({'event':'owned-fixtures-removed','originalSDKPreserved':True,'installerStarted':False,
                  'RootOwnershipAndIsolationUnproven':True,'notarizationTested':False}),flush=True)
