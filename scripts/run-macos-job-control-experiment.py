#!/usr/bin/env python3
"""Measure job control with disposable terminals and unprivileged children."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "experiments/command-job-control"
NATIVE = ROOT / "macos/core/Sources/RemozioMach"
LAUNCHER = ROOT / "macos/core/Tests/RemozioCoreTests/Fixtures/command-process/child.c"
TRIALS = 10
EXPECTED = {
    "native_leader": {
        "foregroundSIGTSTPStoppedLeader": False,
        "foregroundSIGSTOPStoppedLeader": True,
        "nativePollRetainedOwnedStoppedChild": True,
        "foregroundContinueProducedActualExit7": True,
        "exactOutput": True,
    },
    "resume": {
        "case": "resume", "terminalSuspendByteSent": False, "defaultTSTPStopsTarget": True, "monitorRemainsRunning": True,
        "kernelExecObserved": True, "execFailureReported": False, "actualWaitOutcome": True,
        "exactOutput": True, "monitorReaped": True,
        "externalKernelExecObserved": True, "externalKernelExitObserved": True,
    },
    "typed_suspend": {
        "case": "typed_suspend", "terminalSuspendByteSent": True,
        "defaultTSTPStopsTarget": True, "monitorRemainsRunning": True,
        "kernelExecObserved": True, "execFailureReported": False, "actualWaitOutcome": True,
        "exactOutput": True, "monitorReaped": True,
        "externalKernelExecObserved": True, "externalKernelExitObserved": True,
    },
    "cancel": {
        "case": "cancel", "terminalSuspendByteSent": False, "defaultTSTPStopsTarget": True, "monitorRemainsRunning": True,
        "kernelExecObserved": True, "execFailureReported": False, "actualWaitOutcome": True,
        "exactOutput": True, "monitorReaped": True,
        "externalKernelExecObserved": True, "externalKernelExitObserved": True,
    },
    "failure": {
        "case": "failure", "terminalSuspendByteSent": False, "defaultTSTPStopsTarget": False, "monitorRemainsRunning": False,
        "kernelExecObserved": False, "execFailureReported": True, "actualWaitOutcome": True,
        "exactOutput": True, "monitorReaped": True,
        "externalKernelExecObserved": False, "externalKernelExitObserved": True,
    },
}


def run(arguments, *, context="native fixture"):
    try:
        return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=30)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        def excerpt(value):
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            return (value or "")[-8192:]
        result = f"exit {error.returncode}" if isinstance(error, subprocess.CalledProcessError) else "timeout after 30 seconds"
        raise RuntimeError(
            f"{context}: {Path(arguments[0]).name}: {result}\n"
            f"stdout (last 8192 characters):\n{excerpt(error.stdout)}\n"
            f"stderr (last 8192 characters):\n{excerpt(error.stderr)}"
        ) from error


def compile_fixture(directory, name, sources):
    binary = directory / name
    run(["xcrun", "clang", "-arch", "arm64", "-mmacosx-version-min=26.0",
         "-Wall", "-Wextra", "-Werror", "-I" + str(NATIVE / "include"),
         *(str(source) for source in sources), "-o", str(binary)])
    return binary


def launch_frame(target):
    path = os.fsencode(target)
    strings = struct.pack(">I", len(path)) + path
    body = strings + strings
    return struct.pack(">10I", 0x524D4331, len(body), os.getuid(), os.getgid(),
                       0, 1, 0, 5000, 0o077, 1) + body


def measure():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("This experiment requires an Apple Silicon Mac")
    if os.geteuid() == 0:
        raise RuntimeError("Run this disposable experiment without elevation")
    observations = {}
    sources = list(sorted(FIXTURES.glob("*.c"))) + [
        LAUNCHER, NATIVE / "CommandProcess.c", NATIVE / "CommandPTY.c",
        NATIVE / "CommandChildSpecification.c", NATIVE / "include/RemozioCommandProcess.h",
        NATIVE / "include/RemozioCommandPTY.h", NATIVE / "include/RemozioCommandChild.h",
        Path(__file__).resolve(),
    ]
    with tempfile.TemporaryDirectory(prefix="remozio-command-job-control-") as temporary:
        directory = Path(temporary).resolve()
        native_target = compile_fixture(directory, "leader-target", [FIXTURES / "leader-target.c"])
        launcher = compile_fixture(directory, "child", [LAUNCHER, NATIVE / "CommandChildSpecification.c"])
        native_probe = compile_fixture(directory, "leader-probe", [FIXTURES / "leader-probe.c",
            NATIVE / "CommandProcess.c", NATIVE / "CommandPTY.c", NATIVE / "CommandChildSpecification.c"])
        monitor = compile_fixture(directory, "monitor", [FIXTURES / "monitor.c"])
        monitor_target = compile_fixture(directory, "monitor-target", [FIXTURES / "monitor-target.c"])
        monitor_probe = compile_fixture(directory, "monitor-probe", [FIXTURES / "monitor-probe.c", NATIVE / "CommandPTY.c"])
        frame = directory / "frame.bin"
        frame.write_bytes(launch_frame(native_target))
        for case, expected in EXPECTED.items():
            command = ([str(native_probe), str(launcher), str(frame)] if case == "native_leader"
                       else [str(monitor_probe), str(monitor),
                             str(directory / "missing-target" if case == "failure" else monitor_target), case])
            for trial in range(TRIALS):
                actual = json.loads(run(command, context=f"job-control case {case}, trial {trial}").stdout)
                if actual != expected:
                    raise RuntimeError(f"Job-control observation changed: {case}, trial {trial}, {actual!r}")
            observations[case] = {"trials": TRIALS, "allTrialsMatch": True, "observations": expected}
    return {
        "experiment": "command-job-control-v1",
        "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {"os": run(["sw_vers", "-productVersion"]).stdout.strip(),
                 "build": run(["sw_vers", "-buildVersion"]).stdout.strip(),
                 "architecture": platform.machine(),
                 "sdk": run(["xcrun", "--sdk", "macosx", "--show-sdk-version"]).stdout.strip(),
                 "deploymentTarget": "26.0"},
        "sources": {str(source.relative_to(ROOT)): hashlib.sha256(source.read_bytes()).hexdigest()
                    for source in sources},
        "cases": observations,
        "limits": ["Disposable unprivileged children and terminals; no installed service or user terminal",
                   "Native leader uses the current C owner and synthetic launcher; not production elevation",
                   "Monitor prototype owns target waitpid; external kernel observation grants no target ownership",
                   "No protected monitor protocol, durable release, crash recovery or client integration",
                   "No nested foreground jobs, cross-user execution, real shell or physical terminal validation",
                   "The runtime version is recorded; deployment target does not prove macOS 26 runtime behavior",
                   "Loop deadlines bound fixtures only; they do not set product execution time limits"]
    }


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
