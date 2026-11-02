#!/usr/bin/env python3
"""Ordinary-user Linux placement and ownership checks; never protected installation."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "experiments/linux-placement-validator"
WALK = ROOT / "experiments/linux-storage-lease"
PROCESS_SOURCE = ROOT / "scripts/run-linux-storage-lease-experiment.py"
_spec = importlib.util.spec_from_file_location("remozio_placement_process", PROCESS_SOURCE)
_process = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_process)
_cleanup = _process._cleanup
run_owned = _process.run_owned
MAX_OUTPUT_BYTES = _process.MAX_OUTPUT_BYTES
CASES = (
    "healthy", "invalid-path", "unsafe-expectation", "duplicate-entry", "unlisted-parent", "missing-entry",
    "file-symlink", "fifo", "directory-as-file", "file-as-directory", "directory-symlink", "anchor-symlink",
    "ancestor-symlink", "extra-link", "entry-alias", "owner-mismatch", "anchor-owner-mismatch", "group-mismatch",
    "group-write", "other-write", "directory-write", "anchor-write", "special-mode", "sticky-directory",
    "refusal-repairs-nothing", "acl-refused-by-policy", "read-grant-admitted", "masked-write-grant",
    "default-write-grant", "unmasked-write-grant", "file-replacement", "directory-replacement",
    "anchor-replacement", "mode-change", "acl-change", "replaced-during-acquire", "fork-copy", "close-on-exec",
    "failed-acquire-cleanup", "acl-unavailable", "acl-denied", "acl-malformed", "mount-crossing",
    "mount-unavailable", "device-crossing", "directory-alias",
)
SIMULATED = {"acl-unavailable", "acl-denied", "acl-malformed", "mount-crossing", "mount-unavailable",
             "device-crossing", "directory-alias"}
NATIVE_SOURCES = (SOURCE / "placement.c", WALK / "descriptor-walk.c", SOURCE / "controls.c")
WRAPPED = ("-Wl,--wrap=fgetxattr", "-Wl,--wrap=fstat", "-Wl,--wrap=fstatat", "-Wl,--wrap=statx")


def validate_result(raw, case, returncode):
    if case not in CASES or type(raw) not in (str, bytes):
        raise ValueError("unsupported report")
    if len(raw if isinstance(raw, bytes) else raw.encode()) > MAX_OUTPUT_BYTES:
        raise ValueError("oversized report")
    result = json.loads(raw, object_pairs_hook=_process._unique, parse_constant=_process._constant)
    filesystem = result.get("fixtureFilesystem") if type(result) is dict else None
    if type(filesystem) is not str or filesystem not in {"tmpfs", "ext-family", "xfs", "btrfs"}:
        raise ValueError("unsupported fixture filesystem")
    expected = {"case": case, "passed": True, "fixtureOnly": True,
                "protectedInstallation": False, "descriptorsClosed": True, "fixtureFilesystem": filesystem}
    if case in SIMULATED:
        expected["injectionObserved"] = True
    if (type(result) is not dict or set(result) != set(expected) or result != expected
            or any(type(result[key]) is not bool for key in expected if key not in {"case", "fixtureFilesystem"})
            or type(returncode) is not int or returncode != 0):
        raise ValueError("invalid control report")
    return {**expected, "evidence": "injected-error-control" if case in SIMULATED else "owned-live-filesystem-control"}


def source_hashes():
    paths = [Path(__file__).resolve(), PROCESS_SOURCE, _process.CLEANUP_SOURCE,
             ROOT / "tests/test_linux_placement_validator_experiment.py"]
    paths += [SOURCE / name for name in ("placement.c", "placement.h", "controls.c", "README.md")]
    paths += [WALK / name for name in ("descriptor-walk.c", "descriptor-walk.h")]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def measure(timeout=15):
    if sys.version_info < (3, 11):
        raise RuntimeError("Python 3.11 or later required")
    if (platform.system() != "Linux" or os.getuid() == 0 or os.getuid() != os.geteuid()
            or os.getgid() != os.getegid()):
        raise RuntimeError("ordinary Linux account required")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("invalid timeout")
    prerequisites = _process.check_prerequisites()
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("compiler unavailable")
    before = source_hashes()
    with _cleanup.subreaper(), tempfile.TemporaryDirectory(prefix="remozio-placement-") as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        binary = directory / "placement-controls"
        arguments = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                     *map(str, NATIVE_SOURCES), *WRAPPED, "-o", str(binary)]
        _output, status, error, clean = run_owned(arguments, 30)
        if status != 0 or error or not clean or not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError("native build failed")
        results = {}
        for case in CASES:
            with tempfile.TemporaryDirectory(prefix="case-", dir=directory) as workspace:
                os.chmod(workspace, 0o700)
                raw, status, error, clean = run_owned([str(binary), case, workspace], timeout)
                try:
                    if error or not clean:
                        raise ValueError("worker failed")
                    result = validate_result(raw, case, status)
                    results[case] = {**result, "ownedProcessesReaped": True}
                except (ValueError, TypeError, RecursionError):
                    results[case] = {"passed": False, "error": error or "InvalidControlResult",
                                     "ownedProcessesReaped": clean}
    after = source_hashes()
    if before != after:
        raise RuntimeError("source changed during experiment")
    kernel = re.match(r"^([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,6})?)(?:[^0-9]|$)", platform.release())
    architecture = platform.machine()
    return {"experiment": "linux-placement-validator-v1", "fixtureOnly": True, "protectedInstallation": False,
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "host": {"os": "Linux", "architecture": architecture if re.fullmatch(r"[A-Za-z0-9_]{1,32}", architecture) else "unknown",
                     "kernelVersion": kernel[1] if kernel else "unknown", "runsAsRoot": False,
                     "pythonVersion": ".".join(map(str, sys.version_info[:3]))},
            "prerequisites": prerequisites, "sources": before, "sourcesUnchanged": True, "cases": results,
            "controlCounts": {"ownedLive": len(CASES) - len(SIMULATED), "injected": len(SIMULATED)},
            "passed": all(result["passed"] for result in results.values()),
            "limits": ["ordinary-user disposable anchor; component evidence, not activation or a protected installation",
                       "expectations are caller-supplied fixture values; no production name, UID or filesystem policy",
                       "no root-owned object, foreign-owned object, real mount or bind mount is observed",
                       "point-in-time observations; a hostile same-account writer or root is not excluded",
                       "owned children stay in the runner process group; external termination and escaped children excluded"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    def cancel(_signum, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, cancel)
    try:
        result = measure(arguments.timeout)
    except (OSError, RuntimeError, ValueError, KeyboardInterrupt):
        print("Linux placement validator experiment unavailable or failed", file=sys.stderr)
        return 1
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if arguments.output:
        arguments.output.write_text(encoded)
    print(encoded, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
