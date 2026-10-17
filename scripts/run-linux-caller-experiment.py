#!/usr/bin/env python3
"""Bounded, unprivileged Linux caller experiment; JSON contains no raw identities."""
import argparse
from contextlib import contextmanager
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "experiments/linux-caller/probe.py"
CASES = ("kernel_ipc", "transferred_socket", "same_pid_exec", "monitor_failure")
EXPECTED = {
    "kernel_ipc": {"connection_credentials_identify_connector", "connection_pidfd_identifies_connector",
                   "message_credentials_identify_actual_sender", "message_pidfd_identifies_actual_sender",
                   "payload_identity_claim_ignored", "kernel_pidfds_have_cloexec",
                   "kernel_pidfds_not_ready_while_peers_alive", "connection_and_message_identity_relationship",
                   "both_kernel_pidfds_ready_after_exit", "all_owned_peers_reaped"},
    "same_pid_exec": {"owned_child_exec_event_stopped", "single_thread_exec_preserved_pid",
                      "pidfd_not_ready_at_exec_stop", "executable_inode_changed_at_exec_stop",
                      "replacement_is_expected_fixture", "exit_observed_and_reaped_after_exec", "pidfd_ready_after_exit"},
    "monitor_failure": {"tracee_alive_before_monitor_failure", "owned_monitor_killed_and_reaped",
                        "exitkill_tracee_pidfd_ready", "exitkill_tracee_killed_and_reaped"},
}
EXPECTED["transferred_socket"] = EXPECTED["kernel_ipc"]


def validate_result(raw, case, returncode):
    """Require exact checks and actual JSON booleans before reporting success."""
    result = json.loads(raw)
    if type(result) is not dict or type(result.get("passed")) is not bool:
        raise ValueError("invalid result")
    if result["passed"]:
        checks = result.get("checks")
        if (set(result) != {"passed", "checks"} or type(checks) is not dict
                or set(checks) != EXPECTED[case] or any(value is not True for value in checks.values())
                or returncode != 0):
            raise ValueError("incomplete success")
        return result
    # Copy only controlled metadata; never reproduce paths, stdout or stderr.
    return {"passed": False, "error_type": result.get("error_type") if result.get("error_type") in
            {"OSError", "PermissionError", "TimeoutError", "RuntimeError", "ValueError", "AttributeError"}
            else "ProbeFailure", "errno": result.get("errno") if type(result.get("errno")) is int else None}


def reap_group(group, timeout=3):
    """Reap workers and descendants adopted by this runner's subreaper."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            pid, _ = os.waitpid(-group, os.WNOHANG)
        except ChildProcessError:
            return True
        if pid == 0:
            time.sleep(0.005)
    return False


def group_has_owned_child(group):
    """Drain exited children and establish an owned live member before signaling."""
    while True:
        try:
            pid, status = os.waitpid(-group, os.WNOHANG)
        except ChildProcessError:
            return False
        if pid == 0 or not (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
            return True


def invoke(arguments, timeout, case):
    # The runner owns the directory so timeout/SIGKILL of the worker also removes sockets.
    with tempfile.TemporaryDirectory(prefix="remozio-linux-caller-run-") as directory:
        return invoke_worker(arguments + [directory], timeout, case)


def invoke_worker(arguments, timeout, case):
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True, start_new_session=True)
    result = {"passed": False, "error_type": "RunnerFailure", "errno": None}
    try:
        try:
            output, _ = process.communicate(timeout=timeout)
            result = validate_result(output, case, process.returncode)
        except subprocess.TimeoutExpired:
            result = {"passed": False, "error_type": "TimeoutError", "errno": None}
        except (ValueError, TypeError, KeyError):
            result = {"passed": False, "error_type": "InvalidProbeReport", "errno": None}
    finally:
        # communicate may already have reaped the worker. Do not signal a recycled
        # PGID when no owned member remains. Fixture children never change groups.
        if process.poll() is None or group_has_owned_child(process.pid):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.communicate(timeout=3)
        result["cleanup_reaped_all_fixture_children"] = reap_group(process.pid)
        result["passed"] = result["passed"] and result["cleanup_reaped_all_fixture_children"]
    return result


@contextmanager
def subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0 or libc.prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError("cannot establish fixture child cleanup")
    try:
        yield
    finally:
        libc.prctl(36, previous.value, 0, 0, 0)


def measure(timeout=15):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("requires Linux x86_64")
    if os.geteuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise RuntimeError("run without elevation or credential transition")
    if not 0 < timeout <= 60:
        raise ValueError("timeout must be greater than zero and at most 60 seconds")
    with subreaper():
        results = {case: invoke([sys.executable, str(PROBE), case], timeout, case) for case in CASES}
    release = platform.freedesktop_os_release()
    return {
        "experiment": "linux-caller-v1",
        "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {"os": release.get("ID", "unknown"), "version": release.get("VERSION_ID", "unknown"),
                 "kernel": platform.release(), "architecture": platform.machine(),
                 "python": platform.python_version(), "runs_as_root": False},
        "sources": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (Path(__file__).resolve(), PROBE)},
        "cases": results,
        "passed": all(result["passed"] for result in results.values()),
        "untested": ["unrelated or hostile caller attachment and monitor admission races",
                     "non-leader thread exec and concurrent thread/clone activity",
                     "PID or user namespaces and containers",
                     "different real/effective/saved credentials, groups and privileged transitions",
                     "forced PID reuse", "code provenance, signing policy and executable content races",
                     "installed privileged service and phone end-to-end behavior"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=15, help="seconds per case (0 < timeout <= 60)")
    args = parser.parse_args()
    try:
        report = measure(args.timeout)
    except (RuntimeError, ValueError) as error:
        parser.exit(2, str(error) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
