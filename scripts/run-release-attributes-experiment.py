#!/usr/bin/env python3
"""Inspect owned fixtures only. Do not select or change a production attribute policy."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import sys
import tempfile


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def measured_test_count(pattern, *args):
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    counts = [int(value) for value in re.findall(pattern, result.stdout + result.stderr)]
    if not counts or max(counts) < 1:
        raise ValueError("The test command did not report a positive test count")
    return max(counts)


def tree_digest(root):
    digest = hashlib.sha256()
    entries = total = links = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        for name in sorted(directories + files):
            entries += 1
            if entries > 8192:
                raise ValueError("SDK tree exceeds the fixture bound")
            path = Path(directory) / name
            digest.update(str(path.relative_to(root)).encode() + b"\0")
            if path.is_symlink():
                links += 1
                digest.update(b"link\0" + hashlib.sha256(os.fsencode(os.readlink(path))).digest())
            elif path.is_dir():
                digest.update(b"directory\0")
            elif path.is_file():
                digest.update(b"file\0")
                content = hashlib.sha256()
                with path.open("rb") as file:
                    while data := file.read(65536):
                        total += len(data)
                        if total > 1 << 30:
                            raise ValueError("SDK data exceeds the fixture bound")
                        content.update(data)
                digest.update(content.digest())
            else:
                raise ValueError("Unexpected SDK node")
    return {"sha256": digest.hexdigest(), "entries": entries, "links": links}


def signed_controls(root, identity, team):
    app = root / "Signed.app"
    contents = app / "Contents"
    executable = contents / "MacOS" / "Fixture"
    executable.parent.mkdir(parents=True)
    resource = contents / "Resources" / "data"
    resource.parent.mkdir()
    resource.write_bytes(b"disposable resource")
    (contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleExecutable": "Fixture", "CFBundleIdentifier": "dev.remozio.attribute-fixture",
        "CFBundleName": "Fixture", "CFBundlePackageType": "APPL", "CFBundleVersion": "1"}))
    source = root / "main.c"
    source.write_text("int main(void) { return 0; }\n")
    run("/usr/bin/clang", "-target", "arm64-apple-macos26.0", str(source), "-o", str(executable))
    run("/usr/bin/codesign", "--force", "--sign", identity, "--options", "runtime", "--timestamp=none", str(app))
    display = subprocess.run(["/usr/bin/codesign", "--display", "--verbose=4", str(app)], check=True,
                             capture_output=True, text=True).stderr
    if f"TeamIdentifier={team}\n" not in display or "Authority=Developer ID Application:" not in display:
        raise ValueError("Fixture must have the explicitly selected Developer ID Team")
    def verify():
        return subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)],
                              capture_output=True).returncode
    if verify() != 0:
        raise ValueError("Baseline fixture verification failed")
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    library.fsetxattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
    library.fsetxattr.restype = ctypes.c_int
    library.fremovexattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    library.fremovexattr.restype = ctypes.c_int
    controls = []
    descriptor = os.open(resource, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        for name, value, expected in [("dev.remozio.fixture-only", b"x", 0),
                                      ("com.apple.ResourceFork", b"disposable fork", 1),
                                      ("com.apple.FinderInfo", bytes([1]) + bytes(31), 1)]:
            if library.fsetxattr(descriptor, name.encode(), value, len(value), 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "Could not set the fixture attribute")
            code = verify()
            if (code == 0) != (expected == 0):
                raise ValueError(f"Unexpected strict verification result for {name}")
            controls.append({"attribute": name, "strictVerificationPassed": code == 0})
            if library.fremovexattr(descriptor, name.encode(), 0) != 0 or verify() != 0:
                raise ValueError("Fixture verification did not recover")
    finally:
        os.close(descriptor)
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--team-id", required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit("Run as an ordinary account on an Apple Silicon Mac")
    repo = Path(__file__).resolve().parents[1]
    package = repo / "experiments/release-attributes"
    sdk_package = repo / "experiments/sparkle-boundary"
    guard_tests = measured_test_count(r"\bRan (\d+) tests?\b", sys.executable, "-m", "unittest", "discover",
                                     "-s", str(repo / "tests"), "-p", "test_release_attribute_runner.py")
    unit_tests = measured_test_count(r"Executed (\d+) tests, with 0 failures", "swift", "test", "--package-path",
                                    str(package), "--triple", "arm64-apple-macosx26.0")
    for item in [package, sdk_package]:
        run("swift", "build", "--package-path", str(item), "--disable-keychain", "--disable-netrc")
    probe = Path(run("swift", "build", "--package-path", str(package), "--show-bin-path")) / "AttributeProbe"
    sdk = Path(run("swift", "build", "--package-path", str(sdk_package), "--show-bin-path")) / "Sparkle.framework"
    before = tree_digest(sdk)
    with tempfile.TemporaryDirectory(prefix="remozio-release-attributes-") as temporary:
        root = Path(temporary).resolve()
        if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o777 != 0o700:
            raise ValueError("Fixture root is not private")
        fixture = root / "Host" / "Fixture.app"
        fixture.parent.mkdir(mode=0o700)
        run("/usr/bin/ditto", str(sdk), str(fixture))
        inventory = json.loads(run(str(probe), str(fixture)))
        if inventory["skippedLinks"] != 0 or inventory["inspectedLinks"] != before["links"] or inventory["entries"] != before["entries"]:
            raise ValueError("The inventory did not cover the complete SDK tree")
        controls = signed_controls(root, args.identity, args.team_id)
    if root.exists() or tree_digest(sdk) != before:
        raise ValueError("Fixture cleanup or original SDK preservation failed")
    record = {"schema": 1, "runtime": platform.mac_ver()[0], "architecture": platform.machine(),
              "unitTests": unit_tests, "runnerGuardTests": guard_tests,
              "sdkInventory": inventory, "sdkTree": before, "signedControls": controls, "sdkBytesAndLinksPreserved": True,
              "ownedFixturesRemoved": True, "fixtureExecuted": False, "rootExecuted": False,
              "inventoryReadsAttributeValues": False, "attributeValuesReported": False, "productionPolicyChanged": False,
              "limits": ["Name inventory is not a metadata seal or activation authority",
                         "Compressed resource forks and macOS 26 runtime remain unproven",
                         "No protected service, installed app, or physical device was used"]}
    paths = ["scripts/run-release-attributes-experiment.py", "experiments/release-attributes/Package.swift",
             "experiments/release-attributes/Sources/AttributeInspection/AttributeInspection.swift",
             "experiments/release-attributes/Sources/AttributeProbe/main.swift",
             "experiments/release-attributes/Tests/AttributeInspectionTests/AttributeInspectionTests.swift",
             "tests/test_release_attribute_runner.py", "scripts/check.sh"]
    record["sourceSHA256"] = {name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in paths}
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
