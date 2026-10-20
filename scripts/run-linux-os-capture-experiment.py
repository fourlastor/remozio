#!/usr/bin/env python3
"""Bounded, unprivileged self-observation controls; no production Linux admission."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "experiments/linux-os-capture"
HELPER = ROOT / "scripts/run-linux-approval-command-experiment.py"
_spec = importlib.util.spec_from_file_location("remozio_os_capture_helpers", HELPER)
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)

CHECKS = {
    "actualCredentialRolesAndTarget", "rawPathBytesAndSchemaRoundTrip",
    "boundedHashMatchesBytesAndPreservesOffset",
    "equalBytesDifferentExecutableRejected", "sameInodeContentMutationRejected",
    "pathReplacementDuringHashRejected", "kernelExecutableObjectMustMatchPath",
    "directoryReplacementRejected", "directoryContentChangeAllowed", "sharedPipeFlagMutationRejected",
    "fileKindAccessAndAppendMutation", "retainedDuplicateSurvivesOriginalReuse",
    "descriptorShapeAndAccessRejected", "unsupportedKernelObjectsAndFlagsRejected",
    "credentialParserPreservesRolesAndRefusesUnsupported", "captureMismatchBlocksHandoff",
    "pathSubstitutionAndInvalidBytesRejected",
}
OBSERVATIONS = {
    "productionAuthority": False, "productionAdmission": False, "trustedCode": False,
    "syntheticCallerBindings": True, "syntheticCodePolicyDigest": True, "selfObservationOnly": True,
    "actualCredentialTransitionTested": False, "physicalPhone": False, "hardwareKeys": False,
    "commandsExecuted": 0, "schemaVersion": 4,
}


def validate_result(raw, returncode):
    if type(raw) is not bytes or len(raw) > 32768 or returncode != 0:
        raise ValueError("native result")
    result = json.loads(raw, object_pairs_hook=_helpers._unique_object,
                        parse_constant=_helpers._unsupported_constant)
    if type(result) is not dict or set(result) != {"passed", "checks", "observations"} or result["passed"] is not True:
        raise ValueError("native fields")
    checks, observed = result["checks"], result["observations"]
    if type(checks) is not dict or set(checks) != CHECKS or any(value is not True for value in checks.values()):
        raise ValueError("native checks")
    if type(observed) is not dict or set(observed) != set(OBSERVATIONS):
        raise ValueError("native observations")
    if any(type(observed[key]) is not type(value) or observed[key] != value for key, value in OBSERVATIONS.items()):
        raise ValueError("native scope")
    return {"passed": True, "checks": dict.fromkeys(sorted(CHECKS), True), "observations": OBSERVATIONS.copy()}


def source_inventory():
    paths = {Path(__file__), HELPER, ROOT / "scripts/run-linux-caller-monitor-experiment.py",
             ROOT / "scripts/run-linux-caller-experiment.py"}
    for directory in (PACKAGE, ROOT / "protocol/swift"):
        paths.update(directory / name for name in ("Package.swift", "Package.resolved"))
        paths.update(path for path in (directory / "Sources").rglob("*") if path.is_file())
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(paths)}


def swift_arguments(work):
    return ["swift", "build", "--package-path", str(PACKAGE), "--scratch-path", str(work / "build"),
            "--cache-path", str(work / "cache"), "--config-path", str(work / "config"),
            "--security-path", str(work / "security"), "--disable-keychain", "--disable-netrc",
            "--force-resolved-versions", "--jobs", "4"]


def run(work, timeout=30, build_timeout=600):
    _helpers.finite_deadline(timeout, 60)
    _helpers.finite_deadline(build_timeout, 900)
    if (sys.version_info < (3, 11) or platform.system() != "Linux" or platform.machine() != "x86_64" or
            os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid()):
        raise ValueError("unsupported host")
    # Existing ownership-aware cleanup helper: refuse if adopted child enumeration is unavailable.
    children = Path(f"/proc/self/task/{os.getpid()}/children")
    children.read_text(encoding="ascii")
    before = source_inventory()
    environment = os.environ.copy()
    environment["CLANG_MODULE_CACHE_PATH"] = str(work / "module-cache")
    environment["SWIFTPM_MODULECACHE_OVERRIDE"] = str(work / "module-cache")
    with _helpers.subreaper():
        version_bytes, version_code, version_error, version_clean = _helpers.run_owned(
            ["swift", "--version"], 10, limit=8192, env=environment)
        version = re.search(rb"Swift version ([0-9]+)\.([0-9]+)(?:\.([0-9]+))?", version_bytes)
        if (version_code != 0 or version_error is not None or not version_clean or version is None or
                (int(version[1]), int(version[2])) < (6, 2)):
            raise ValueError("swift version")
        swift_version = ".".join(part.decode("ascii") for part in version.groups() if part is not None)
        _output, code, error, clean = _helpers.run_owned(swift_arguments(work), build_timeout,
                                                       limit=1_048_576, env=environment)
        if code != 0 or error is not None or not clean:
            raise ValueError("build failed")
        with tempfile.TemporaryDirectory(prefix="remozio-os-capture-") as directory:
            os.chmod(directory, 0o700)
            raw, code, error, clean = _helpers.run_owned([str(work / "build/debug/LinuxOSCaptureExperiment"), directory],
                                                        timeout, env=environment)
            if error is not None or not clean:
                raise ValueError("native process failed")
            result = validate_result(raw, code)
    if source_inventory() != before:
        raise ValueError("source changed")
    result["sourceSHA256"] = before
    result["cleanupReapedAllFixtureChildren"] = True
    kernel = re.match(r"[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]+)?", platform.release())
    if kernel is None:
        raise ValueError("kernel version")
    result["platform"] = {"system": "Linux", "architecture": "x86_64", "python": platform.python_version(),
                          "kernel": kernel[0], "swift": swift_version}
    result["measuredAtUTC"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".build/linux-swift/os-capture")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--build-timeout", type=float, default=600)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    try:
        if not options.work_dir.is_absolute() or (options.output is not None and not options.output.is_absolute()):
            raise ValueError("absolute path required")
        options.work_dir.mkdir(parents=True, exist_ok=True)
        result = run(options.work_dir, options.timeout, options.build_timeout)
    except (Exception, KeyboardInterrupt):
        # No raw exception, process output or path enters evidence.
        result = {"passed": False, "error": "experimentFailed"}
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if options.output is not None and options.output.is_absolute():
        options.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
