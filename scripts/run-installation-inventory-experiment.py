"""Probe actual machine storage with ordinary-owner fixtures and bounded child lifetimes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "experiments/installation-inventory"
SOURCES = [
    "experiments/installation-inventory/Package.swift",
    "experiments/installation-inventory/Package.resolved",
    "experiments/installation-inventory/Sources/InventoryProbe/main.swift",
    "scripts/run-installation-inventory-experiment.py",
    "macos/core/Package.swift",
    "macos/core/Package.resolved",
    "protocol/swift/Package.swift",
    "host/shared-core/Package.swift",
    "host/shared-core/Package.resolved",
]
SOURCE_TREES = ["macos/core/Sources", "protocol/swift/Sources", "host/shared-core/Sources"]

def hashes():
    paths = {REPO / name for name in SOURCES}
    for name in SOURCE_TREES:
        paths.update(path for path in (REPO / name).rglob("*") if path.is_file())
    return {str(path.relative_to(REPO)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}

def command(arguments, timeout):
    process = subprocess.Popen(arguments, cwd=REPO, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.stdout.close()
            process.stderr.close()
            process.wait(timeout=5)
        raise
    if process.returncode:
        diagnostic = (stdout + stderr).decode(errors="replace")[-4096:]
        raise RuntimeError(f"Experiment command failed ({process.returncode}): {diagnostic}")
    return stdout

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit("The experiment requires an ordinary macOS account.")
    before = hashes()
    # Test visibility is enabled only for this experiment's dependency build, never the shipped app.
    build = ["/usr/bin/swift", "build", "--package-path", str(PACKAGE),
             "--triple", "arm64-apple-macosx26.0", "--disable-keychain", "--disable-netrc",
             "-Xswiftc", "-enable-testing"]
    command(build, timeout=240)
    products = Path(command(build + ["--show-bin-path"], timeout=30).decode().strip())
    raw = command([str(products / "InventoryProbe")], timeout=20)
    if len(raw) > 4096:
        raise RuntimeError("The probe result exceeded its bound.")
    result = json.loads(raw)
    required = ["ordinaryOwner", "productionStoreImplementation", "internalLeaseSeam", "childrenJoinedRunnerGroup",
                "crossProcessWriterExclusion", "exitWithoutFinalizersRetained",
                "killAfterCommitRetained", "preparationRecordsPreserved", "fixtureRemoved"]
    excluded = ["rootIsolationProven", "powerLossProven", "nativeIOFaultProven", "servicesRegistered"]
    if result.get("evidenceFormat") != 1 or any(result.get(key) is not True for key in required) \
            or any(result.get(key) is not False for key in excluded):
        raise RuntimeError("The probe did not establish the expected bounded controls.")
    if hashes() != before:
        raise RuntimeError("The inspected sources changed during the experiment.")
    evidence = {"evidenceFormat": 1, "status": "passed", "deploymentTarget": "26.0",
                "sourceSHA256": before, "observations": result,
                "limits": ["Ordinary-owner internal lease seam; no protected Root installation",
                           "Death after successful SQLite COMMIT; no native I/O fault or power loss",
                           "The observed runtime applies; deployment target does not prove another OS",
                           "No keys, service registration, activation or actual approval"]}
    encoded = json.dumps(evidence, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n")
    print(encoded)

if __name__ == "__main__":
    main()
