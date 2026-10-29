#!/usr/bin/env python3
"""Opt-in composed caller/command fixture: a monitored stopped frontend, its transferred streams,
current own-account grants, schema-4 software approval, shared SQLite consumption and one fixed
command. Fixture evidence only; never protected admission or production Linux issuance."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/linux-composed-caller-command"
WORKER = EXPERIMENT / "composed.py"
FRONTEND = EXPERIMENT / "frontend.c"
HELPER = ROOT / "scripts/run-linux-approval-command-experiment.py"
_spec = importlib.util.spec_from_file_location("remozio_composed_helpers", HELPER)
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)
MAX_OUTPUT_BYTES = 32768
# The fixed input line the command copies to the caller's stdout and the marker.
OUTPUT_LINE_BYTES = len(b"remozio-composed-output\n")
SCOPE = {"trustedCode": False, "productionAdmission": False, "productionAuthority": False,
         "actualCredentialTransitionTested": False, "syntheticPolicyProvenance": True,
         "physicalPhone": False, "hardwareKeys": False}


def refused(refusal, stage, phase="none", rows=0, records=0, **extra):
    return {"refusal": refusal, "stage": stage, "ledgerPhase": phase, "rows": rows, "records": records,
            "markerLines": 0, **extra}


# Exact per-case outcome: refusal boundary, stage, durable ledger phase, audit records and execution count.
EXPECTED = {
    "healthy-approve": {"refusal": None, "stage": "dispatched", "ledgerPhase": "succeeded", "rows": 1, "records": 3,
                        "spawned": True, "childExit": 0, "markerMatched": True, "requesterLostDuringDispatch": False,
                        "strictAdmission": True, "replayRejected": True, "markerLines": 1},
    "healthy-decline": refused(None, "declined", "declined", 1, 1),
    "carrier-missing-stream": refused("carrier", "carrier", carrierRejected=True),
    "carrier-extra-stream": refused("carrier", "carrier", carrierRejected=True),
    "fork-before-final": refused("monitor", "final", monitorReason="task"),
    "stop-release": refused("monitor", "final", monitorReason="stop_released"),
    "grant-revoked-B0": refused("grant", "consume"),
    "monitor-death-B1": refused("monitor", "consume"),
    "monitor-death-B3": refused("monitor", "dispatch-check", "cancelled", 1, 2),
    "grant-changed-B3": refused("grant", "dispatch-check", "cancelled", 1, 2),
    "command-changed-B3": refused("command", "dispatch-check", "cancelled", 1, 2),
    "cwd-replaced-B3": refused("directory", "dispatch-check", "cancelled", 1, 2),
    "stream-flags-B3": refused("stream", "dispatch-check", "cancelled", 1, 2),
    "monitor-death-B4": refused("monitor", "last-check", "unknown", 1, 3),
    # Explicit limitation and negative control: loss after the last check is recorded, never prevented.
    "dispatch-race-limitation": {"refusal": None, "stage": "dispatched", "ledgerPhase": "unknown", "rows": 1, "records": 3,
                                 "spawned": True, "childExit": 0, "markerMatched": True,
                                 "requesterLostDuringDispatch": True, "strictAdmission": False, "markerLines": 1},
}
CASES = tuple(EXPECTED)
INJECTED = {"grant-revoked-B0": "grant-revoked", "monitor-death-B1": "kill-monitor", "monitor-death-B3": "kill-monitor",
            "grant-changed-B3": "grant-changed", "command-changed-B3": "command-changed",
            "cwd-replaced-B3": "cwd-replaced", "stream-flags-B3": "stream-nonblock",
            "monitor-death-B4": "kill-monitor", "dispatch-race-limitation": "kill-monitor"}
SUPERVISOR_ONLY = {"markerLines", "carrierRejected"}


def failure(error_type, clean=False):
    return {"passed": False, "error_type": error_type, "cleanup_reaped_all_fixture_children": clean}


def validate_result(raw, case, returncode):
    """Accept only the agreed shape; publish fixed booleans and outcome fields, never raw worker data."""
    if type(raw) not in (str, bytes) or len(raw if isinstance(raw, bytes) else raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("worker report exceeds bound")
    report = json.loads(raw, object_pairs_hook=_helpers._unique_object,
                        parse_constant=_helpers._unsupported_constant)
    if case not in EXPECTED or type(report) is not dict or returncode != 0 or report.get("case") != case:
        raise ValueError("invalid worker report")
    owner, supervisor = report.get("owner"), report.get("supervisor")
    if type(owner) is not dict or type(supervisor) is not dict or owner.get("phase") != "result" or "error" in owner:
        raise ValueError("owner did not report a result")
    expected = EXPECTED[case]
    for key, value in expected.items():
        actual = supervisor.get(key) if key in SUPERVISOR_ONLY else owner.get(key)
        if actual != value or type(actual) is not type(value):
            raise ValueError("unexpected outcome")
    reached_admission = expected["stage"] not in ("carrier",)
    checks = {"outcomeMatchesExpected": True,
              "ownerExitedCleanly": supervisor.get("ownerExit") == 0,
              "markerExact": supervisor.get("markerExact") is True,
              # The command wrote to the caller's own stdout pipe, not only the marker file.
              "outputOnCallerStdout": supervisor.get("outputBytes") == OUTPUT_LINE_BYTES * expected["markerLines"],
              "checkpointMatches": owner.get("checkpointMatches") is True,
              "reservationsMatchRows": owner.get("reservations") == owner.get("rows"),
              "faultInjectedAtBarrier": supervisor.get("injected") == INJECTED.get(case),
              "allOwnedChildrenReaped": supervisor.get("allOwnedChildrenReaped") is True}
    if reached_admission:
        checks["remoteObservation"] = owner.get("remoteObservation") is True
    if not all(checks.values()):
        raise ValueError("incomplete checks")
    observations = {key: owner.get(key) if key not in SUPERVISOR_ONLY else supervisor.get(key) for key in expected}
    if reached_admission:
        observations["callerInheritableCapabilities"] = owner.get("callerInheritableCapabilities") is True
    return {"passed": True, "checks": checks, "observations": observations}


def invoke(arguments, case, timeout):
    output, returncode, error, clean = _helpers.run_owned(arguments, timeout, MAX_OUTPUT_BYTES)
    if error:
        return failure(error, clean)
    try:
        result = validate_result(output, case, returncode)
    except (ValueError, TypeError, RecursionError):
        return failure("InvalidWorkerReport", clean)
    result["cleanup_reaped_all_fixture_children"] = clean
    result["passed"] = clean
    return result


def build(work_dir, timeout):
    compiler, swift = shutil.which("cc"), shutil.which("swift")
    if compiler is None or swift is None:
        raise RuntimeError("compiler unavailable")
    for name in ("cache", "config", "security", "build", "module-cache"):
        (work_dir / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    frontend = work_dir / "composed-frontend"
    _, returncode, error, clean = _helpers.run_owned(
        [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(FRONTEND), "-o", str(frontend)], timeout)
    if error or not clean or returncode != 0 or not os.access(frontend, os.X_OK):
        raise RuntimeError("bounded frontend build failed")
    arguments = [swift, "build", "--package-path", str(EXPERIMENT), "--product", "LinuxComposedCallerCommand",
                 "--cache-path", str(work_dir / "cache"), "--config-path", str(work_dir / "config"),
                 "--security-path", str(work_dir / "security"), "--scratch-path", str(work_dir / "build"),
                 "--disable-keychain", "--disable-netrc", "--force-resolved-versions", "--jobs", "4"]
    environment = {**os.environ, "CLANG_MODULE_CACHE_PATH": str(work_dir / "module-cache"),
                   "SWIFTPM_MODULECACHE_OVERRIDE": str(work_dir / "module-cache")}
    _, returncode, error, clean = _helpers.run_owned(arguments, timeout, _helpers.MAX_BUILD_OUTPUT_BYTES, env=environment)
    owner = work_dir / "build/debug/LinuxComposedCallerCommand"
    if error or not clean or returncode != 0 or not os.access(owner, os.X_OK):
        raise RuntimeError("bounded owner build failed")
    return frontend, owner


def prepare_workspace(directory, owner, timeout):
    for name in ("store", "work", "cmd"):
        (directory / name).mkdir(mode=0o700)
    # A disposable command specimen, so mutation controls never touch an installed binary.
    command = directory / "cmd/tee"
    shutil.copyfile("/usr/bin/tee", command)
    command.chmod(0o700)
    _, returncode, error, clean = _helpers.run_owned([str(owner), "grants", str(directory)], timeout)
    if error or not clean or returncode != 0:
        raise RuntimeError("fixture grants unavailable")


def source_hashes():
    paths = [Path(__file__).resolve(), HELPER, _helpers.HELPER, _helpers.CLEANUP_SOURCE, WORKER, FRONTEND,
             ROOT / "experiments/linux-caller-monitor/probe.py"]
    for package in (EXPERIMENT, ROOT / "experiments/linux-approval-command", ROOT / "experiments/linux-os-capture",
                    ROOT / "protocol/swift", ROOT / "host/shared-core"):
        paths.extend(package / name for name in ("Package.swift", "Package.resolved"))
        paths.extend(sorted(path for path in (package / "Sources").rglob("*") if path.is_file()))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(set(paths))}


def measure(work_dir=None, timeout=30, build_timeout=600, cases=CASES):
    if platform.system() != "Linux" or platform.machine() != "x86_64" or sys.version_info < (3, 11):
        raise RuntimeError("requires Linux x86_64 and Python 3.11")
    if os.geteuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise RuntimeError("run without elevation or credential transition")
    _helpers.finite_deadline(timeout, 60)
    _helpers.finite_deadline(build_timeout, 900)
    work_dir = ROOT / ".build/linux-swift/composed-caller-command" if work_dir is None else Path(work_dir)
    if not work_dir.is_absolute():
        raise ValueError("absolute work directory required")
    prerequisites = _helpers._helpers.check_prerequisites()
    if not os.access("/usr/bin/tee", os.X_OK):
        raise RuntimeError("fixed fixture command unavailable")
    before_sources = source_hashes()
    results = {}
    with _helpers.subreaper():
        version = _helpers.swift_version(build_timeout)
        frontend, owner = build(work_dir, build_timeout)
        with tempfile.TemporaryDirectory(prefix="remozio-composed-") as temporary:
            for case in cases:
                with _helpers.private_directory(temporary) as workspace:
                    prepare_workspace(workspace, owner, timeout)
                    results[case] = invoke([sys.executable, str(WORKER), case, str(workspace), str(frontend), str(owner)],
                                           case, timeout)
    if source_hashes() != before_sources:
        raise RuntimeError("source inputs changed during experiment")
    return {"experiment": "linux-composed-caller-command-v1", **SCOPE,
            "passed": all(value["passed"] for value in results.values()) and tuple(results) == CASES,
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "prerequisites": prerequisites, "host": {**_helpers.host_metadata(version),
                                                     "policy": _helpers._helpers.policy_metadata()},
            "sources": before_sources, "cases": results,
            "limits": ["owned ordinary-user fixture topology; controlled launch is not protected code admission",
                       "monitor, caller, owner and command run as one ordinary account; no credential transition",
                       "faults are injected at named barriers; refusal is shown at those barriers, not at every instant",
                       "loss of the caller or monitor after the last check is recorded as an unknown outcome, never prevented",
                       "software decision keys, synthetic code policy digest, disposable grants and storage",
                       "no physical phone, TPM custody, installed service or reboot/suspend evidence"]}


def _cancel(_signum, _frame):
    raise KeyboardInterrupt()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, help="absolute reusable build directory")
    parser.add_argument("--timeout", type=float, default=30, help="seconds per case (0 < timeout <= 60)")
    parser.add_argument("--build-timeout", type=float, default=600, help="bounded build seconds (at most 900)")
    parser.add_argument("--case", action="append", choices=CASES, help="run only these cases (partial report)")
    args = parser.parse_args()
    previous = signal.signal(signal.SIGTERM, _cancel)
    try:
        try:
            report = measure(args.work_dir, args.timeout, args.build_timeout, tuple(args.case) if args.case else CASES)
        except KeyboardInterrupt:
            parser.exit(130, "Composed caller/command experiment cancelled.\n")
        except (RuntimeError, ValueError, OSError):
            parser.exit(2, "Composed caller/command experiment unavailable; no raw diagnostic data published.\n")
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
