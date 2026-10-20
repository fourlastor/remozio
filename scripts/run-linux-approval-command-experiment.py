#!/usr/bin/env python3
"""Disposable signed-approval to fixed-command controls; no production authority."""
import argparse
from contextlib import closing, contextmanager
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
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "experiments/linux-approval-command"
HELPER = ROOT / "scripts/run-linux-caller-monitor-experiment.py"
CLEANUP_SOURCE = ROOT / "scripts/run-linux-caller-experiment.py"
_spec = importlib.util.spec_from_file_location("remozio_approval_command_helpers", HELPER)
_helpers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_helpers)
subreaper = _helpers.subreaper
MAX_OUTPUT_BYTES = 32768
MAX_BUILD_OUTPUT_BYTES = 1048576
MARKER = b"remozio-fixture-output\n"
NORMAL_CASES = ("approve", "malformed-decision", "malformed-capture", "bad-signature", "decline", "expired",
                "expire-before-consume", "expire-at-shared-consume", "replay", "submission-id-replay", "submission-nonce-replay", "audit-failure")
CRASH_RECOVERIES = (("crash-before-launch", "recover-before-launch", 0),
                    ("crash-after-output", "recover-after-output", 1))
CHECKS = {"expectedDecisionResult", "expectedLedgerState", "expectedAuditState", "expectedExecutionCount", "expectedCheckpointState", "expectedReplayState"}
_BASE = {"fixtureOnlyOwner": True, "sharedConsumptionTables": True, "sharedReplayTables": True, "productionAuthority": False, "physicalPhone": False,
         "hardwareKeys": False, "syntheticRequesterClaims": True}


def observation(executions=0, phase="none", checkpoint="unchanged", rows=0, audit=0, output=False, exit_status=None):
    return {**_BASE, "executions": executions, "phase": phase, "checkpointAction": checkpoint,
            "consumptionRows": rows, "submissionReservations": rows, "auditRecords": audit, "outputMatched": output, "childExitStatus": exit_status}


OBSERVATIONS = {case: observation() for case in NORMAL_CASES}
for _case in ("approve", "replay", "submission-id-replay", "submission-nonce-replay"):
    OBSERVATIONS[_case] = observation(1, "succeeded", rows=1, audit=3, output=True, exit_status=0)
OBSERVATIONS["decline"] = observation(phase="declined", rows=1, audit=1)
OBSERVATIONS["reopen-completed"] = observation(1, "succeeded", rows=1, audit=3)
OBSERVATIONS["recover-before-launch"] = observation(phase="unknown", checkpoint="finalizePending", rows=1, audit=2)
OBSERVATIONS["recover-after-output"] = observation(1, "unknown", rows=1, audit=3)
DECISION_RESULTS = {"approve": "accepted", "replay": "replayRejected",
                    "submission-id-replay": "submissionIDReplayRejected", "submission-nonce-replay": "submissionNonceReplayRejected", "decline": "declined",
                    "malformed-decision": "malformedDecision", "malformed-capture": "malformedCapture",
                    "bad-signature": "invalidSignature", "expired": "expired",
                    "expire-before-consume": "expiredBeforeConsume", "expire-at-shared-consume": "expiredAtSharedConsume", "audit-failure": "auditFailure",
                    "reopen-completed": "reopened", "recover-before-launch": "recovered", "recover-after-output": "recovered"}
for _mode, _reason in DECISION_RESULTS.items():
    OBSERVATIONS[_mode]["decisionResult"] = _reason


class OutputLimitError(Exception):
    pass


def finite_deadline(value, maximum):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= maximum:
        raise ValueError("invalid deadline")
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _unsupported_constant(_value):
    raise ValueError("unsupported JSON constant")


def validate_result(raw, mode, returncode):
    if type(raw) not in (str, bytes) or len(raw if isinstance(raw, bytes) else raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("report bound")
    report = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_unsupported_constant)
    if (mode not in OBSERVATIONS or returncode != 0 or type(report) is not dict or
            set(report) != {"passed", "checks", "observations"} or report["passed"] is not True):
        raise ValueError("report fields")
    checks, observed = report["checks"], report["observations"]
    if type(checks) is not dict or set(checks) != CHECKS or any(value is not True for value in checks.values()):
        raise ValueError("report checks")
    expected = OBSERVATIONS[mode]
    if type(observed) is not dict or set(observed) != set(expected):
        raise ValueError("report observations")
    if any(type(observed[key]) is not type(value) or observed[key] != value for key, value in expected.items()):
        raise ValueError("unexpected result")
    return {"passed": True, "checks": dict.fromkeys(sorted(CHECKS), True), "observations": expected.copy()}


def _read_output(process, timeout, limit):
    deadline = time.monotonic() + timeout
    output = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("owned fixture", timeout)
            for key, _ in selector.select(remaining):
                data = os.read(key.fd, min(4096, limit + 1 - len(output)))
                if not data:
                    selector.unregister(key.fileobj)
                    break
                output.extend(data)
                if len(output) > limit:
                    raise OutputLimitError()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("owned fixture", timeout)
        process.wait(timeout=remaining)
    return bytes(output)


def run_owned(arguments, timeout, limit=MAX_OUTPUT_BYTES, env=None):
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True, env=env)
    output, error = b"", None
    try:
        try:
            output = _read_output(process, timeout, limit)
        except subprocess.TimeoutExpired:
            error = "TimeoutError"
        except OutputLimitError:
            error = "OutputLimitError"
    finally:
        clean = _helpers._retire(process)
    return output, process.returncode, error, clean


def failure(error, clean=False):
    return {"passed": False, "error_type": error, "cleanup_reaped_all_fixture_children": clean}


def marker_matches(directory, executions):
    path = directory / "command.marker"
    expected = MARKER * executions
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return executions == 0
    except OSError:
        return False
    try:
        info = os.fstat(descriptor)
        return (executions != 0 and stat.S_ISREG(info.st_mode) and info.st_size == len(expected) and
                os.read(descriptor, len(expected) + 1) == expected)
    finally:
        os.close(descriptor)


def shared_state_matches(directory, mode):
    """Independent post-worker row checks, not protected storage or caller authentication."""
    expected = OBSERVATIONS.get(mode)
    if expected is None:
        if mode == "crash-before-launch":
            expected = observation(phase="authorized", rows=1, audit=1)
        elif mode == "crash-after-output":
            expected = observation(1, "executing", rows=1, audit=2)
        else:
            return False
    path = directory / "fixture.sqlite"
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1048576:
            return False
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.1)) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA query_only=ON")
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if tables != {"consumptions_v1", "consumption_outcomes_v1", "command_submissions_v1", "audit_epochs_v1", "audit_records_v1"}:
                return False
            for table, count in (("consumptions_v1", expected["consumptionRows"]),
                                 ("command_submissions_v1", expected["submissionReservations"]),
                                 ("audit_records_v1", expected["auditRecords"]),
                                 ("audit_epochs_v1", 2 if mode.startswith("recover-") else 1),
                                 ("consumption_outcomes_v1", int(expected["phase"] in {"executing", "succeeded", "unknown"}))):
                if db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] != count:
                    return False
                if db.execute(f"SELECT count(*) FROM {table} WHERE mac IS NOT ? OR account IS NOT ?",
                              (bytes([1]) * 16, bytes([2]) * 16)).fetchone()[0] != 0:
                    return False
            if expected["consumptionRows"]:
                reservation = db.execute("SELECT submission,nonce,caller,capture FROM command_submissions_v1").fetchone()
                if any(type(value) is not bytes or len(value) != size for value, size in zip(reservation, (16, 32, 16, 32))):
                    return False
            return not list(db.execute("PRAGMA foreign_key_check"))
    except (OSError, ValueError, sqlite3.Error):
        return False


def invoke(binary, mode, directory, timeout, expected_crash_count=None):
    try:
        raw, returncode, error, clean = run_owned([str(binary), mode, str(directory)], timeout)
    except OSError:
        return failure("WorkerUnavailable")
    if error or not clean:
        return failure(error or "CleanupFailure", clean)
    if expected_crash_count is not None:
        if returncode != 86 or raw != b"":
            return failure("UnexpectedCrashResult", clean)
        if not marker_matches(directory, expected_crash_count):
            return failure("ExecutionMarkerMismatch", clean)
        if not shared_state_matches(directory, mode):
            return failure("SharedTableStateMismatch", clean)
        return {"passed": True, "checks": {"expectedCrashExit": True, "noSuccessReport": True,
                                            "expectedMarkerBeforeRecovery": True},
                "shared_tables_match_expected_state": True,
                "cleanup_reaped_all_fixture_children": clean}
    try:
        report = validate_result(raw, mode, returncode)
    except (ValueError, TypeError, KeyError, RecursionError):
        return failure("InvalidFixtureReport", clean)
    if not marker_matches(directory, OBSERVATIONS[mode]["executions"]):
        return failure("ExecutionMarkerMismatch", clean)
    if not shared_state_matches(directory, mode):
        return failure("SharedTableStateMismatch", clean)
    report["shared_tables_match_expected_state"] = True
    report["marker_matches_expected_execution_count"] = True
    report["cleanup_reaped_all_fixture_children"] = clean
    return report


def build_fixture(work_dir, timeout):
    compiler = shutil.which("swift")
    if compiler is None:
        raise RuntimeError("Swift unavailable")
    work_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ("cache", "config", "security", "build", "module-cache"):
        (work_dir / name).mkdir(mode=0o700, exist_ok=True)
    arguments = [compiler, "build", "--package-path", str(PACKAGE), "--product", "LinuxApprovalCommandFixture",
                 "--cache-path", str(work_dir / "cache"), "--config-path", str(work_dir / "config"),
                 "--security-path", str(work_dir / "security"), "--scratch-path", str(work_dir / "build"),
                 "--disable-keychain", "--disable-netrc", "--force-resolved-versions", "--jobs", "4"]
    environment = {**os.environ, "CLANG_MODULE_CACHE_PATH": str(work_dir / "module-cache"),
                   "SWIFTPM_MODULECACHE_OVERRIDE": str(work_dir / "module-cache")}
    _, returncode, error, clean = run_owned(arguments, timeout, MAX_BUILD_OUTPUT_BYTES, env=environment)
    binary = work_dir / "build/debug/LinuxApprovalCommandFixture"
    if error or not clean or returncode != 0 or not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("bounded fixture build failed")
    return binary


def swift_version(timeout):
    compiler = shutil.which("swift")
    if compiler is None:
        raise RuntimeError("Swift unavailable")
    output, returncode, error, clean = run_owned([compiler, "--version"], min(timeout, 15), 4096)
    match = re.search(rb"Swift version ([0-9]{1,3})\.([0-9]{1,3})(?:\.([0-9]{1,6}))?(?:[^0-9]|$)", output)
    if returncode != 0 or error or not clean or not match:
        raise RuntimeError("Swift version unavailable")
    components = tuple(int(value or b"0") for value in match.groups())
    if components < (6, 2, 0):
        raise RuntimeError("Swift 6.2 required")
    return ".".join(str(value) for value in components)


def source_hashes():
    paths = [Path(__file__).resolve(), HELPER, CLEANUP_SOURCE]
    for package in (PACKAGE, ROOT / "protocol/swift", ROOT / "host/shared-core"):
        paths.extend(package / name for name in ("Package.swift", "Package.resolved"))
        paths.extend(sorted(path for path in (package / "Sources").rglob("*") if path.is_file()))
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def host_metadata(version):
    match = re.match(r"^([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,6})?)(?:[^0-9]|$)", platform.release())
    python = platform.python_version()
    return {"os": "Linux", "architecture": "x86_64", "runsAsRoot": False,
            "kernelVersion": match[1] if match else "unknown", "swiftVersion": version,
            "pythonVersion": python if re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,6}", python) else "unknown"}


@contextmanager
def private_directory(parent):
    # mkdtemp sets 0700 regardless of ambient umask; fixture state stays disposable.
    with tempfile.TemporaryDirectory(prefix="case-", dir=parent) as temporary:
        directory = Path(temporary)
        if stat.S_IMODE(directory.stat().st_mode) != 0o700:
            raise RuntimeError("private fixture directory required")
        yield directory


def measure(work_dir=None, timeout=15, build_timeout=600):
    if platform.system() != "Linux" or platform.machine() != "x86_64" or sys.version_info < (3, 11):
        raise RuntimeError("requires Linux x86_64 and Python 3.11")
    if os.geteuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise RuntimeError("run without elevation or credential transition")
    finite_deadline(timeout, 60)
    finite_deadline(build_timeout, 900)
    work_dir = ROOT / ".build/linux-swift/approval-command" if work_dir is None else Path(work_dir)
    if not work_dir.is_absolute():
        raise ValueError("absolute work directory required")
    _helpers.check_prerequisites()
    if not os.access("/usr/bin/tee", os.X_OK):
        raise RuntimeError("fixed fixture command unavailable")
    before_sources = source_hashes()
    with subreaper():
        version = swift_version(build_timeout)
        binary = build_fixture(work_dir, build_timeout)
        cases = {}
        with tempfile.TemporaryDirectory(prefix="remozio-approval-command-") as temporary:
            for case in NORMAL_CASES:
                with private_directory(temporary) as workspace:
                    directory = Path(workspace)
                    cases[case] = invoke(binary, case, directory, timeout)
                    if case == "approve":
                        cases["reopen-completed"] = (invoke(binary, "reopen-completed", directory, timeout)
                                                       if cases[case]["passed"] else failure("PrerequisiteFailed", True))
            for seed, recovery, count in CRASH_RECOVERIES:
                with private_directory(temporary) as workspace:
                    directory = Path(workspace)
                    cases[seed] = invoke(binary, seed, directory, timeout, count)
                    cases[recovery] = (invoke(binary, recovery, directory, timeout)
                                       if cases[seed]["passed"] else failure("PrerequisiteFailed", True))
    if source_hashes() != before_sources:
        raise RuntimeError("source inputs changed during experiment")
    return {"experiment": "linux-approval-command-v2", "passed": all(value["passed"] for value in cases.values()),
            "sourceInputsUnchanged": True,
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **_BASE, "host": host_metadata(version), "sources": before_sources, "cases": cases,
            "limits": ["disposable ordinary-user fixture; no installed or privileged authority",
                       "fixed /usr/bin/tee command only; ephemeral synthetic signing keys and schema-4 claims",
                       "shared consumption/replay/audit tables with fixture-only connection and checkpoint owner; no protected Linux journal or independent process locking",
                       "process exit controls are not power-loss or filesystem durability certification",
                       "no physical phone, biometric approval, TPM key custody, caller monitor integration or network delivery"]}


def _cancel(_signum, _frame):
    raise KeyboardInterrupt()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, help="absolute reusable Swift build/cache directory")
    parser.add_argument("--timeout", type=float, default=15, help="seconds per fixture process (0 < timeout <= 60)")
    parser.add_argument("--build-timeout", type=float, default=600, help="bounded Swift build seconds (at most 900)")
    parser.add_argument("--output", type=Path, help="absolute path for the sanitized public report")
    args = parser.parse_args()
    previous = signal.signal(signal.SIGTERM, _cancel)
    try:
        try:
            if args.output is not None and not args.output.is_absolute():
                raise ValueError("absolute output path required")
            report = measure(args.work_dir, args.timeout, args.build_timeout)
            rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
            if args.output is not None:
                args.output.write_text(rendered, encoding="utf-8")
        except KeyboardInterrupt:
            parser.exit(130, "Approval-command experiment cancelled.\n")
        except (RuntimeError, ValueError, OSError):
            parser.exit(2, "Approval-command experiment unavailable; no raw diagnostic data published.\n")
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(rendered, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
