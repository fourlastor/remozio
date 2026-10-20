#!/usr/bin/env python3
"""Ordinary-user Linux storage lease mechanics; never protected installation."""
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
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "experiments/linux-storage-lease"
CLEANUP_SOURCE = ROOT / "scripts/run-linux-caller-experiment.py"
_spec = importlib.util.spec_from_file_location("remozio_storage_lease_cleanup", CLEANUP_SOURCE)
_cleanup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cleanup)
MAX_OUTPUT_BYTES = 16384
CASES = (
    "healthy", "close-reopen", "invalid-path", "owner-mismatch", "missing-file",
    "file-symlink", "directory-symlink", "anchor-symlink", "ancestor-symlink", "fifo",
    "directory-as-file", "hardlink-data", "hardlink-lock", "anchor-mode", "directory-mode",
    "file-mode", "special-mode", "access-acl", "default-acl", "competing-writer", "fork-copy",
    "close-on-exec", "file-replacement", "directory-replacement", "anchor-replacement",
    "lock-replacement", "mode-change", "acl-change", "failed-acquire-cleanup",
    "acl-unavailable", "acl-denied", "filesystem-unavailable", "unknown-filesystem",
)
SIMULATED = {"acl-unavailable", "acl-denied", "filesystem-unavailable", "unknown-filesystem"}


class OutputLimitError(Exception):
    pass


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _constant(_value):
    raise ValueError("nonfinite JSON")


def validate_result(raw, case, returncode):
    if case not in CASES or type(raw) not in (str, bytes):
        raise ValueError("unsupported report")
    if len(raw if isinstance(raw, bytes) else raw.encode()) > MAX_OUTPUT_BYTES:
        raise ValueError("oversized report")
    result = json.loads(raw, object_pairs_hook=_unique, parse_constant=_constant)
    filesystem = result.get("fixtureFilesystem") if type(result) is dict else None
    if type(filesystem) is not str or filesystem not in {"tmpfs", "ext-family", "xfs", "btrfs"}:
        raise ValueError("unsupported fixture filesystem")
    expected = {"case": case, "passed": True, "fixtureOnly": True,
                "protectedInstallation": False, "descriptorsClosed": True, "fixtureFilesystem": filesystem}
    if (type(result) is not dict or set(result) != set(expected) or result != expected
            or any(type(result[key]) is not bool for key in expected if key not in {"case", "fixtureFilesystem"})
            or type(returncode) is not int or returncode != 0):
        raise ValueError("invalid control report")
    return {**expected, "evidence": "injected-error-control" if case in SIMULATED else "owned-live-filesystem-control"}


def _read_output(process, timeout):
    deadline = time.monotonic() + timeout
    output = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("owned storage fixture", timeout)
            for key, _events in selector.select(remaining):
                chunk = os.read(key.fd, min(4096, MAX_OUTPUT_BYTES + 1 - len(output)))
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    output.extend(chunk)
                    if len(output) > MAX_OUTPUT_BYTES:
                        raise OutputLimitError()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("owned storage fixture", timeout)
        process.wait(timeout=remaining)
    return bytes(output)


def run_owned(arguments, timeout):
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True, umask=0o077)
    output, error, clean = b"", None, False
    try:
        try:
            output = _read_output(process, timeout)
        except subprocess.TimeoutExpired:
            error = "TimeoutError"
        except OutputLimitError:
            error = "OutputLimitError"
    finally:
        try:
            if process.poll() is None or _cleanup.group_has_owned_child(process.pid):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=3)
                clean = _cleanup.reap_group(process.pid)
            except subprocess.TimeoutExpired:
                clean = False
        finally:
            process.stdout.close()
    return output, process.returncode, error, clean


def source_hashes():
    paths = [Path(__file__).resolve(), CLEANUP_SOURCE,
             ROOT / "tests/test_linux_storage_lease_experiment.py"]
    paths += [SOURCE / name for name in ("lease.c", "lease.h", "controls.c", "README.md")]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def check_prerequisites():
    try:
        with Path(f"/proc/self/task/{os.getpid()}/children").open("rb") as stream:
            stream.read(1)
        with os.scandir("/proc/self/fd") as entries:
            next(entries, None)
    except OSError:
        raise RuntimeError("owned-process cleanup unavailable") from None
    return {"procTaskChildrenReadable": True, "procDescriptorsReadable": True}


def measure(timeout=15):
    if (platform.system() != "Linux" or os.getuid() == 0 or os.getuid() != os.geteuid()
            or os.getgid() != os.getegid()):
        raise RuntimeError("ordinary Linux account required")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("invalid timeout")
    prerequisites = check_prerequisites()
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("compiler unavailable")
    before = source_hashes()
    with _cleanup.subreaper(), tempfile.TemporaryDirectory(prefix="remozio-storage-lease-") as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        binary = directory / "lease-controls"
        arguments = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                     str(SOURCE / "lease.c"), str(SOURCE / "controls.c"),
                     "-Wl,--wrap=fgetxattr", "-Wl,--wrap=fstatfs", "-o", str(binary)]
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
    return {"experiment": "linux-storage-lease-v1", "fixtureOnly": True, "protectedInstallation": False,
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "host": {"os": "Linux", "architecture": architecture if re.fullmatch(r"[A-Za-z0-9_]{1,32}", architecture) else "unknown",
                     "kernelVersion": kernel[1] if kernel else "unknown", "runsAsRoot": False,
                     "pythonVersion": ".".join(map(str, sys.version_info[:3]))},
            "prerequisites": prerequisites, "sources": before, "sourcesUnchanged": True, "cases": results,
            "passed": all(result["passed"] for result in results.values()),
            "limits": ["ordinary-user disposable anchor; no protected installation or production service identity",
                       "advisory locks and point-in-time metadata observations, not exclusion of a malicious owner",
                       "no journal catalog, content authentication, durability, crash recovery, TPM or phone",
                       "filesystem allowlist is fixture policy; injected failures do not measure unavailable hosts",
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
        print("Linux storage lease experiment unavailable or failed", file=sys.stderr)
        return 1
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if arguments.output:
        arguments.output.write_text(encoded)
    print(encoded, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
