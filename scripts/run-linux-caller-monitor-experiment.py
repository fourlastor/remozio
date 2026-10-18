#!/usr/bin/env python3
"""Bounded owned-process monitor controls, not a protected production admission path."""
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
PROBE = ROOT / "experiments/linux-caller-monitor/probe.py"
FIXTURE = ROOT / "experiments/linux-caller-monitor/fixture.c"
CLEANUP_SOURCE = ROOT / "scripts/run-linux-caller-experiment.py"
_spec = importlib.util.spec_from_file_location("remozio_owned_caller_cleanup", CLEANUP_SOURCE)
_cleanup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cleanup)
subreaper = _cleanup.subreaper
group_has_owned_child = _cleanup.group_has_owned_child
reap_group = _cleanup.reap_group

MAX_OUTPUT_BYTES = 32768
CASES = ("healthy", "same-path-exec", "fork", "vfork", "thread-clone", "sender-mismatch",
         "caller-exit", "stop-release", "bad-ack", "duplicate-ack", "monitor-failure",
         "memory-modification")
# Exact check/reason sets are agreed with the probe; no unsolicited worker fields
# or observations can enter the published report.
COMMON = {"pre_exec_stop_observed", "pidfd_retained_before_approved_exec", "monitor_options_set_before_exec",
          "first_exec_matches_fixture", "initial_request_stop_observed", "kernel_message_identity_received",
          "monitor_observed_wait_events", "executor_result_received", "all_owned_children_reaped"}
MATCHED_SENDER = {"kernel_sender_matches_admitted_process"}
REJECTED = {"simulated_rejection_observed"}
EXPECTED = {
    "healthy": COMMON | MATCHED_SENDER | {"prepare_ack_nonce_bound", "monitor_frozen_at_final_check",
                                        "caller_ptrace_stop_confirmed_at_final", "simulated_acceptance_observed"},
    "sender-mismatch": COMMON | REJECTED | {"kernel_sender_mismatch_observed", "binding_invalidated"},
    "stop-release": COMMON | MATCHED_SENDER | REJECTED |
                    {"caller_stop_released_before_final", "executor_detected_missing_stop"},
    "bad-ack": COMMON | MATCHED_SENDER | REJECTED | {"invalid_ack_rejected"},
    "duplicate-ack": COMMON | MATCHED_SENDER | REJECTED | {"invalid_ack_rejected"},
    "monitor-failure": COMMON | MATCHED_SENDER | REJECTED |
                       {"monitor_killed_after_prepare", "executor_observed_monitor_loss", "exitkill_caller_exit_observed"},
    "memory-modification": REJECTED | {"pretrace_memory_descriptor_received", "bootstrap_ptrace_stop_observed",
                                      "retained_memory_write_succeeded", "executable_mapping_bytes_changed",
                                      "executable_backing_bytes_unchanged", "executor_result_received", "all_owned_children_reaped"},
}
for _case, _event in (("same-path-exec", "same_path_second_exec_observed"), ("fork", "fork_event_observed"),
                       ("vfork", "vfork_event_observed"), ("thread-clone", "clone_event_observed"),
                       ("caller-exit", "exit_event_observed")):
    EXPECTED[_case] = COMMON | MATCHED_SENDER | REJECTED | {
        "event_between_prepare_and_final_observed", "binding_invalidated", _event}
REASONS = {"healthy": "held_stop", "same-path-exec": "exec", "fork": "task", "vfork": "task",
           "thread-clone": "task", "sender-mismatch": "sender_mismatch", "caller-exit": "exit",
           "stop-release": "stop_released", "bad-ack": "bad_ack", "duplicate-ack": "duplicate_ack",
           "monitor-failure": "monitor_loss", "memory-modification": "code_mutation"}
OBSERVATIONS = {case: {"trustedCode": False, "productionAdmission": False,
                       "authorization": "accepted" if case == "healthy" else "rejected", "reason": REASONS[case]}
                for case in CASES}


class OutputLimitError(Exception):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _unsupported_constant(_value):
    raise ValueError("unsupported JSON constant")


def validate_result(raw, case, returncode):
    if type(raw) not in (str, bytes) or len(raw if isinstance(raw, bytes) else raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("probe report exceeds bound")
    result = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_unsupported_constant)
    if (case not in EXPECTED or type(result) is not dict or set(result) != {"passed", "checks", "observations"}
            or result["passed"] is not True or returncode != 0):
        raise ValueError("invalid probe result")
    checks, observations = result["checks"], result["observations"]
    if (type(checks) is not dict or set(checks) != EXPECTED[case]
            or any(value is not True for value in checks.values())):
        raise ValueError("incomplete probe checks")
    if (type(observations) is not dict or set(observations) != set(OBSERVATIONS[case])
            or observations.get("trustedCode") is not False
            or observations.get("productionAdmission") is not False
            or observations != OBSERVATIONS[case]):
        raise ValueError("unsupported probe observations")
    return {"passed": True, "checks": dict.fromkeys(sorted(EXPECTED[case]), True),
            "observations": OBSERVATIONS[case].copy()}


def _read_output(process, timeout):
    """Bound bytes while reading, including descendants that inherit the pipe."""
    deadline = time.monotonic() + timeout
    output = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("owned fixture", timeout)
            for key, _events in selector.select(remaining):
                data = os.read(key.fd, min(4096, MAX_OUTPUT_BYTES + 1 - len(output)))
                if not data:
                    selector.unregister(key.fileobj)
                    break
                output.extend(data)
                if len(output) > MAX_OUTPUT_BYTES:
                    raise OutputLimitError()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("owned fixture", timeout)
        process.wait(timeout=remaining)
    return bytes(output)


def _retire(process):
    """Signal only an unreaped worker or a group with an owned live child."""
    clean = True
    try:
        if process.poll() is None or group_has_owned_child(process.pid):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            clean = False
        return reap_group(process.pid) and clean
    finally:
        process.stdout.close()


def run_owned(arguments, timeout):
    """Private worker lifetime; also used for the one bounded native build."""
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    output, error = b"", None
    try:
        try:
            output = _read_output(process, timeout)
        except subprocess.TimeoutExpired:
            error = "TimeoutError"
        except OutputLimitError:
            error = "OutputLimitError"
    finally:
        clean = _retire(process)
    return output, process.returncode, error, clean


def failure(error_type, clean=False):
    return {"passed": False, "error_type": error_type,
            "cleanup_reaped_all_fixture_children": clean}


def invoke_worker(arguments, timeout, case):
    try:
        output, returncode, error, clean = run_owned(arguments, timeout)
    except OSError:
        return failure("WorkerUnavailable")
    if error or not clean:
        return failure(error or "CleanupFailure", clean)
    try:
        result = validate_result(output, case, returncode)
    except (ValueError, TypeError, KeyError, RecursionError):
        return failure("InvalidProbeReport", clean)
    result["cleanup_reaped_all_fixture_children"] = clean
    return result


def build_fixture(directory, timeout):
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("fixture compiler unavailable")
    binary = directory / "monitor-fixture"
    output, returncode, error, clean = run_owned(
        [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-pthread", str(FIXTURE), "-o", str(binary)], timeout)
    if error or not clean or returncode != 0 or not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("bounded fixture build failed")
    return binary


def source_hashes():
    paths = (Path(__file__).resolve(), PROBE, FIXTURE, CLEANUP_SOURCE)
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def _policy_bytes(path, limit=16384):
    try:
        with Path(path).open("rb") as stream:
            value = stream.read(limit + 1)
        return value if len(value) <= limit else None
    except OSError:
        return None


def policy_metadata():
    scope = _policy_bytes("/proc/sys/kernel/yama/ptrace_scope", 64)
    ptrace = int(scope.strip()) if scope is not None and re.fullmatch(rb"[0-3]\n?", scope) else "unavailable"
    status = _policy_bytes("/proc/self/status")
    modes = [] if status is None else [line for line in status.splitlines() if line.startswith(b"Seccomp:")]
    match = re.fullmatch(rb"Seccomp:\s*([0-2])", modes[0]) if len(modes) == 1 else None
    seccomp = int(match[1]) if match else "unavailable"
    apparmor = _policy_bytes("/sys/module/apparmor/parameters/enabled", 64)
    enabled = {b"Y\n": True, b"Y": True, b"N\n": False, b"N": False}.get(apparmor, "unavailable")
    return {"ptraceScope": ptrace, "seccompMode": seccomp, "apparmorEnabled": enabled}


def host_metadata():
    # Custom kernel build strings can carry names/paths; publish numeric version
    # only. No hostnames, IDs, users, process values or compiler output enter JSON.
    match = re.match(r"^([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,6})?)(?:[^0-9]|$)", platform.release())
    python = platform.python_version()
    return {"os": "Linux", "architecture": "x86_64", "runsAsRoot": False,
            "kernelVersion": match[1] if match else "unknown",
            "pythonVersion": python if re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,6}", python) else "unknown",
            "policy": policy_metadata()}


def measure(timeout=15):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("requires Linux x86_64")
    if os.geteuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise RuntimeError("run without elevation or credential transition")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("timeout must be greater than zero and at most 60 seconds")
    with subreaper(), tempfile.TemporaryDirectory(prefix="remozio-caller-monitor-") as temporary:
        directory = Path(temporary)
        binary = build_fixture(directory, min(30, timeout))
        results = {}
        for case in CASES:
            # Native workers never receive any existing caller or installation path.
            with tempfile.TemporaryDirectory(prefix="case-", dir=directory) as workspace:
                results[case] = invoke_worker([sys.executable, str(PROBE), case, workspace, str(binary)], timeout, case)
    return {"experiment": "linux-caller-monitor-v1",
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "trustedCode": False, "productionAdmission": False,
            "host": host_metadata(), "sources": source_hashes(), "cases": results,
            "passed": all(result["passed"] for result in results.values()),
            "limits": ["owned synthetic fixtures only; no protected installation or production admission",
                       "stopped handoff uses a nonce-bound simulated executor, not command execution",
                       "tracing observes lifecycle events, not trusted code or immutable memory",
                       "no namespaces, privileged credentials, unrelated processes, TPM or phone integration"]}


def _cancel(_signum, _frame):
    raise KeyboardInterrupt()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=15, help="seconds per case (0 < timeout <= 60)")
    args = parser.parse_args()
    previous = signal.signal(signal.SIGTERM, _cancel)
    try:
        try:
            report = measure(args.timeout)
        except KeyboardInterrupt:
            parser.exit(130, "Caller monitor experiment cancelled.\n")
        except (RuntimeError, ValueError, OSError):
            parser.exit(2, "Caller monitor experiment unavailable; no raw diagnostic data published.\n")
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
