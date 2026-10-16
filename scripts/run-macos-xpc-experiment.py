#!/usr/bin/env python3
"""Run a synthetic, unprivileged XPC experiment. Never installs a login item."""
import argparse
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "experiments" / "macos"
TRUSTED = "dev.remozio.experiments.xpc-probe"
OTHER = "dev.remozio.experiments.other"


def command(args, *, timeout=120):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=True)


def interrupted(signum, frame):
    raise KeyboardInterrupt


@contextmanager
def registered_service(domain, service, plist, report):
    # Record the name before bootstrap: interruption can occur after registration.
    report["temporaryService"] = f"{domain}/{service}"
    try:
        command(["/bin/launchctl", "bootstrap", domain, str(plist)])
        yield
    finally:
        result = subprocess.run(["/bin/launchctl", "bootout", f"{domain}/{service}"],
                                capture_output=True, text=True, timeout=15)
        absent = False
        for _ in range(50):
            probe = subprocess.run(["/bin/launchctl", "print", f"{domain}/{service}"],
                                   capture_output=True, text=True, timeout=15)
            absent = probe.returncode == 113 and "Could not find service" in probe.stderr
            if absent:
                break
            time.sleep(0.1)
        report["cleanup"] = {"bootoutExitCode": result.returncode, "serviceAbsent": absent}
        if not absent:
            raise RuntimeError(f"Could not confirm removal of temporary service {service}")


def case_matches(name, result, expected_code, reached):
    expected_reached = name not in ("receipt-wrong-server", "receipt-wrong-client", "wrong-client-identifier", "guarded-wrong-server", "frame-wrong-server", "frame-wrong-client", "discovery-wrong-server", "discovery-wrong-client", "exchange-wrong-server", "exchange-wrong-client", "setup-progress", "setup-wrong-server", "setup-wrong-client", "runtime-progress", "runtime-wrong-server", "runtime-wrong-client", "activation-progress", "activation-wrong-server", "activation-wrong-client")
    return (result.returncode == expected_code
            and (expected_code != 3 or result.stdout.strip().startswith("rejected:"))
            and reached == expected_reached)


def experiment(report):
    if sys.platform != "darwin" or platform.machine() != "arm64":
        raise RuntimeError("Requires an Apple Silicon Mac")
    version = command(["/usr/bin/sw_vers", "-productVersion"]).stdout.strip()
    if int(version.split(".")[0]) < 26:
        raise RuntimeError("Requires macOS 26 or later")
    report["environment"] = {
        "macOS": version,
        "architecture": platform.machine(),
        "xcode": command(["/usr/bin/xcodebuild", "-version"]).stdout.strip(),
        "swift": command(["/usr/bin/xcrun", "swift", "--version"]).stdout.strip(),
        "deploymentTarget": "arm64-apple-macosx26.0",
        "signing": "ad-hoc identifiers only; not Developer ID or Team ID validation",
    }
    domain = f"gui/{os.getuid()}"
    command(["/bin/launchctl", "print", domain])
    command(["/usr/bin/xcrun", "swift", "build", "--package-path", str(PACKAGE),
             "--triple", "arm64-apple-macosx26.0"], timeout=300)
    binary_path = command([
        "/usr/bin/xcrun", "swift", "build", "--package-path", str(PACKAGE),
        "--triple", "arm64-apple-macosx26.0", "--show-bin-path",
    ]).stdout.strip()
    source = Path(binary_path) / "remozio-xpc-probe"
    with tempfile.TemporaryDirectory(prefix="remozio-xpc-") as temporary:
        directory = Path(temporary)
        trusted, other = directory / "trusted", directory / "other"
        for destination, identity in [(trusted, TRUSTED), (other, OTHER)]:
            shutil.copy2(source, destination)
            command(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", identity, str(destination)])
            command(["/usr/bin/codesign", "--verify", "--strict", str(destination)])
        service = "dev.remozio.experiments." + uuid.uuid4().hex
        plist = directory / "agent.plist"
        log = directory / "server.log"
        plist.write_bytes(plistlib.dumps({
            "Label": service,
            "ProgramArguments": [str(trusted), "serve", service, TRUSTED],
            "MachServices": {service: True},
            "StandardOutPath": str(log),
            "StandardErrorPath": str(directory / "server-error.log"),
        }))
        with registered_service(domain, service, plist, report):
            cases = [
                ("matching-peers", "ping", trusted, TRUSTED, 0),
                ("wrong-client-identifier", "ping", other, TRUSTED, 3),
                ("wrong-server-requirement", "ping", trusted, OTHER, 3),
                ("guarded-wrong-server", "guarded-ping", trusted, OTHER, 3),
                ("guarded-matching-peers", "guarded-ping", trusted, TRUSTED, 0),
                ("matching-peers-after-rejections", "ping", trusted, TRUSTED, 0),
                ("discovery-bytes", "discovery", trusted, TRUSTED, 0),
                ("discovery-wrong-server", "discovery", trusted, OTHER, 3),
                ("discovery-wrong-client", "discovery", other, TRUSTED, 3),
                ("receipt-bytes", "receipt", trusted, TRUSTED, 0),
                ("receipt-empty", "receipt-empty", trusted, TRUSTED, 0),
                ("receipt-nil", "receipt-nil", trusted, TRUSTED, 0),
                ("receipt-wrong-server", "receipt", trusted, OTHER, 3),
                ("receipt-wrong-client", "receipt", other, TRUSTED, 3),
                ("exchange-bytes", "exchange", trusted, TRUSTED, 0),
                ("exchange-empty", "exchange-empty", trusted, TRUSTED, 0),
                ("exchange-nil", "exchange-nil", trusted, TRUSTED, 0),
                ("exchange-wrong-server", "exchange", trusted, OTHER, 3),
                ("exchange-wrong-client", "exchange", other, TRUSTED, 3),
                ("frame-bytes", "frame", trusted, TRUSTED, 0),
                ("frame-empty", "empty", trusted, TRUSTED, 0),
                ("frame-nil", "nil", trusted, TRUSTED, 0),
                ("frame-wrong-server", "frame", trusted, OTHER, 3),
                ("frame-wrong-client", "frame", other, TRUSTED, 3),
                ("activation-progress", "activation-progress", trusted, TRUSTED, 0),
                ("activation-bytes", "activation-bytes", trusted, TRUSTED, 0),
                ("activation-empty", "activation-empty", trusted, TRUSTED, 0),
                ("activation-nil", "activation-nil", trusted, TRUSTED, 0),
                ("activation-wrong-server", "activation-bytes", trusted, OTHER, 3),
                ("activation-wrong-client", "activation-bytes", other, TRUSTED, 3),
                ("runtime-progress", "runtime-progress", trusted, TRUSTED, 0),
                ("runtime-bytes", "runtime-bytes", trusted, TRUSTED, 0),
                ("runtime-empty", "runtime-empty", trusted, TRUSTED, 0),
                ("runtime-nil", "runtime-nil", trusted, TRUSTED, 0),
                ("runtime-no-consent", "runtime-no-consent", trusted, TRUSTED, 0),
                ("runtime-wrong-server", "runtime-bytes", trusted, OTHER, 3),
                ("runtime-wrong-client", "runtime-bytes", other, TRUSTED, 3),
                ("setup-progress", "setup-progress", trusted, TRUSTED, 0),
                ("setup-bytes", "setup-bytes", trusted, TRUSTED, 0),
                ("setup-empty", "setup-empty", trusted, TRUSTED, 0),
                ("setup-nil", "setup-nil", trusted, TRUSTED, 0),
                ("setup-wrong-server", "setup-bytes", trusted, OTHER, 3),
                ("setup-wrong-client", "setup-bytes", other, TRUSTED, 3),
            ]
            for name, mode, binary, expected_peer, expected_code in cases:
                nonce = uuid.uuid4().hex
                result = subprocess.run([str(binary), mode, service, expected_peer, nonce],
                                        capture_output=True, text=True, timeout=15)
                reached = log.exists() and nonce in log.read_text()
                matched = case_matches(name, result, expected_code, reached)
                report["cases"].append({"name": name, "exitCode": result.returncode,
                    "result": result.stdout.strip(), "stderr": result.stderr.strip(), "requestReachedService": reached,
                    "passed": matched})
            if not all(case["passed"] for case in report["cases"]):
                raise RuntimeError("One or more cases did not meet the expected result")



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="New report file; an existing file is never overwritten")
    args = parser.parse_args()
    # Reserve the evidence file before changing launchd state.
    with args.output.open("x", encoding="utf-8") as output:
        report = {"schemaVersion": 1, "experiment": "macos-xpc-identifiers",
                  "recordedAt": datetime.now(timezone.utc).isoformat(), "status": "running", "cases": []}
        signal.signal(signal.SIGTERM, interrupted)
        try:
            experiment(report)
            report["status"] = "passed"
        except (Exception, KeyboardInterrupt) as error:
            report["status"] = "failed"
            report["error"] = str(error) or "Interrupted"
        finally:
            json.dump(report, output, indent=2)
            output.write("\n")
        print(f"{report['status']}: {args.output}")
        return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
