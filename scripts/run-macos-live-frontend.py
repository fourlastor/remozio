#!/usr/bin/env python3
"""Join the real frontend, authority journal and native target without installing services."""
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

from macos_fixture_cleanup import retire_owned_tree

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "experiments/command-frontend"
NATIVE = ROOT / "macos/core/Sources/RemozioMach"
BUILD = ROOT / ".build/live-command-frontend"
TRIALS = 3


def build():
    BUILD.mkdir(parents=True, exist_ok=True)
    arguments = ["swift", "build", "--package-path", str(PACKAGE), "--triple", "arm64-apple-macosx26.0",
                 "--disable-keychain", "--disable-netrc", "--product", "LiveCommandFixture"]
    result = subprocess.run(arguments, capture_output=True, text=True)
    log = BUILD / "swift-build.log"
    log.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"Live frontend build failed; see {log}\n{result.stdout}{result.stderr}")
    location = subprocess.run(arguments + ["--show-bin-path"], check=True, capture_output=True, text=True)
    binary = Path(location.stdout.strip()) / "LiveCommandFixture"
    sources = {
        "monitor": [PACKAGE / "live-monitor.c", NATIVE / "CommandProcess.c",
                    NATIVE / "CommandChildSpecification.c", NATIVE / "CommandMonitorProtocol.c"],
        "child": [PACKAGE / "live-child.c", NATIVE / "CommandChildSpecification.c"],
        "target": [PACKAGE / "live-target.c"],
        "supervisor": [PACKAGE / "job-supervisor.c"],
    }
    helpers = {}
    for name, paths in sources.items():
        path = BUILD / name
        compiler = subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos26.0", "-Wall", "-Wextra", "-Werror",
                                   "-DREMOZIO_OWNED_LIVE_FIXTURE=1", "-I", str(NATIVE / "include"),
                                   *(str(item) for item in paths), "-o", str(path)], capture_output=True, text=True)
        if compiler.returncode:
            raise RuntimeError(f"{name} build failed: {compiler.stdout}{compiler.stderr}")
        helpers[name] = path
        # Finish first-launch policy evaluation before starting bounded request deadlines.
        probe = subprocess.run([str(path)], capture_output=True, timeout=15)
        if probe.returncode != 64:
            raise RuntimeError(f"{name} first launch returned {probe.returncode}")
    return binary, helpers


def invoke(binary, helpers, mode, *, stop_barrier=None, timeouts=(60, 20), on_forced_cleanup=None):
    target = "/bin/bash" if mode == "nested" else str(helpers["target"])
    environment = {"PATH": "/usr/bin:/bin"}
    if stop_barrier is not None:
        environment["REMOZIO_FIXTURE_STOP_BARRIER"] = str(stop_barrier)
    process = subprocess.Popen([str(binary), "authority", mode, str(helpers["supervisor"]), str(helpers["monitor"]),
                                str(helpers["child"]), target, str(helpers["target"])], cwd="/private/tmp",
                               env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        if stop_barrier is not None:
            deadline = time.monotonic() + 10
            while not stop_barrier.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("The real frontend did not reach its owned stop barrier")
                time.sleep(0.001)
            if stop_barrier.read_bytes() != b"READY":
                raise RuntimeError("The owned stop barrier has the wrong content")
            process.send_signal(signal.SIGSTOP)
        output, errors = process.communicate(timeout=timeouts[0])
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        # The authority remains alive to supervise cancellation and reap the actual monitor and target.
        process.send_signal(signal.SIGTERM)
        output, errors = process.communicate(timeout=timeouts[1])
        raise
    finally:
        try:
            if process.poll() is None:
                if sys.platform == "darwin":
                    retired = retire_owned_tree(process)
                    if on_forced_cleanup is not None:
                        on_forced_cleanup(retired)
                else:
                    # The portable single-process regression owns this private group.
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
        finally:
            # Independent native owners observe channel loss and retire their own children.
            process.stdout.close()
            process.stderr.close()
    if process.returncode:
        raise RuntimeError(f"Live frontend {mode} returned {process.returncode}: {errors.decode(errors='replace')}")
    observations = json.loads(output)
    if observations.get("nativeSupervisorStatus") != 13 << 8 or observations.get("oneOriginalAdmission") is not True:
        raise RuntimeError(f"Incomplete native result: {observations!r}")
    for field in ["separateAuthorityAndFrontend", "actualMonitorAndTargetReaped", "durableVerifiedOutcome"]:
        if observations.get(field) is not True:
            raise RuntimeError(f"Missing live ownership evidence: {field}")
    frontend = observations["frontend"]
    if frontend.get("frontendCleanupCompleted") is not True:
        raise RuntimeError("Frontend cleanup was not verified")
    if mode == "nested":
        confirmed = (frontend["nestedPhase"] == 7 and frontend["nestedUnknownQueries"] == 1 and
                     frontend["freshRunningQueries"] == 1 and frontend["originalStopEvents"] == 0)
    else:
        confirmed = frontend["freshStoppedQueries"] >= 1 if mode == "job" else (
            frontend["freshStoppedQueries"] == 0 and frontend["freshRunningQueries"] >= 1)
    if not confirmed or frontend["originalContinuations"] != (0 if mode == "nested" else 1):
        raise RuntimeError(f"Incomplete stop/continue evidence: {frontend!r}")
    return observations


def measure_forced_cleanup(binary, helpers):
    retired = []
    with tempfile.TemporaryDirectory(prefix="remozio-owned-timeout-") as directory:
        try:
            invoke(binary, helpers, "job", stop_barrier=Path(directory) / "stopped", timeouts=(0.1, 0.1),
                   on_forced_cleanup=retired.append)
        except subprocess.TimeoutExpired:
            pass
        else:
            raise RuntimeError("The stopped authority did not force the runner's second timeout")
    if retired != [{"trackedDescendants": 4, "observedExits": 4}]:
        raise RuntimeError(f"The actual helper topology did not retire: {retired!r}")
    return {"stoppedAuthority": True, "secondTimeoutExercised": True,
            "allFourDescendantExitsObserved": True, "ownedAuthorityReaped": True}


def source_files():
    files = [Path(__file__), ROOT / "scripts/macos_fixture_cleanup.py",
             PACKAGE / "Sources/LiveCommandFixture/Main.swift", PACKAGE / "Sources/OwnedTTY/Supervisor.c",
             PACKAGE / "job-supervisor.c", PACKAGE / "live-monitor.c", PACKAGE / "live-child.c", PACKAGE / "live-target.c",
             ROOT / "macos/app/CommandMonitor/MonitorMain.c", ROOT / "macos/app/CommandChild/ChildMain.c",
             NATIVE / "CommandProcess.c", NATIVE / "CommandMonitor.c", NATIVE / "CommandMonitorProtocol.c",
             *(ROOT / "macos/core/Sources/RemozioCore" / name for name in ["CommandExecution.swift", "AuthorityJournal.swift",
               "CommandReceiveHost.swift", "CommandCallerReadiness.swift", "CommandFrontendMain.swift", "CommandFrontendRelay.swift"])]
    files += [PACKAGE / "Package.swift", ROOT / "macos/core/Package.swift", ROOT / "protocol/swift/Package.swift",
              *PACKAGE.glob("Sources/OwnedTTY/*.c"), *PACKAGE.glob("Sources/OwnedTTY/include/*.h"),
              *(path for path in NATIVE.rglob("*") if path.is_file() and path.suffix in {".c", ".h", ".m", ".mm", ".cpp"}),
              *(ROOT / "macos/core/Sources").glob("*/module.modulemap"),
              *(ROOT / "macos/core/Sources/RemozioCore").glob("*.swift"),
              *(ROOT / "protocol/swift/Sources/RemozioProtocol").glob("*.swift"),
              ROOT / "host/shared-core/Package.swift", ROOT / "host/shared-core/Package.resolved",
              *(path for path in (ROOT / "host/shared-core/Sources").rglob("*") if path.is_file())]
    return sorted(set(files))


def main():
    if os.geteuid() == 0:
        raise RuntimeError("This experiment must run unprivileged")
    evidence_path = BUILD / "evidence.json"
    evidence_path.unlink(missing_ok=True)
    files = source_files()
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    binary, helpers = build()
    if files != source_files():
        raise RuntimeError("The live frontend source set changed during compilation")
    for path in files:
        if hashlib.sha256(path.read_bytes()).hexdigest() != hashes[str(path.relative_to(ROOT))]:
            raise RuntimeError("A live frontend source changed during compilation")
    cases = {}
    for mode in ["job", "stale", "nested"]:
        observations = [invoke(binary, helpers, mode) for _ in range(TRIALS)]
        if any(value != observations[0] for value in observations[1:]):
            raise RuntimeError(f"Live frontend observations changed between {mode} trials: {observations!r}")
        cases[mode] = {"trials": TRIALS, "allTrialsMatch": True, "observations": observations[0]}
    forced_cleanup = measure_forced_cleanup(binary, helpers)
    if files != source_files():
        raise RuntimeError("The live frontend source set changed during measurement")
    for path in files:
        if hashlib.sha256(path.read_bytes()).hexdigest() != hashes[str(path.relative_to(ROOT))]:
            raise RuntimeError("A live frontend source changed during measurement")
    evidence = {"recordedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(), "runtime": platform.mac_ver()[0],
                "architecture": platform.machine(), "deploymentTarget": "arm64-apple-macosx26.0",
                "privilegedExecution": False, "biometricsTested": False, "bootstrapDiscoveryTested": False,
                "credentialOperations": "same-user fixture seams",
                "cases": cases, "sourceHashes": hashes}
    evidence["forcedCleanup"] = forced_cleanup
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Live frontend, authority and target passed. Evidence: {evidence_path}")


if __name__ == "__main__":
    main()
