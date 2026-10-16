#!/usr/bin/env python3
"""Run the ordinary-account activity-lock controls and retain bounded evidence."""
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "experiments/release-activity/probe.py"
EXPECTED_CASES = {
    "sharedOwnersBlockUntilLastClose", "exclusiveOwnerBlocksNewActivity",
    "failedAutomaticAttemptAllowsNewActivity", "duplicateCloseRetainsLock",
    "forkCloseRetainsParentLock", "forkUnlockReleasesParentLockNegative",
    "closeOnExecReleasesWhileChildLives", "reapedCrashReleasesLock",
    "pathReplacementBypassesLockNegative",
}


def validate(value):
    fields = {"schemaVersion", "passed", "cases", "childrenSpawned", "childrenReaped",
              "unreapedChildren", "rootOperations", "servicesRegistered", "productionActivationTested"}
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeError("Unexpected activity evidence fields")
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1 or value["passed"] is not True:
        raise RuntimeError("Activity controls did not pass")
    cases = value["cases"]
    if not isinstance(cases, dict) or set(cases) != EXPECTED_CASES or any(result is not True for result in cases.values()):
        raise RuntimeError("Incomplete activity controls")
    if any(type(value[field]) is not int for field in ("childrenSpawned", "childrenReaped", "unreapedChildren")):
        raise RuntimeError("Invalid owned-child counts")
    if not 1 <= value["childrenSpawned"] <= 64 or value["childrenReaped"] != value["childrenSpawned"] or value["unreapedChildren"] != 0:
        raise RuntimeError("Incomplete owned-child cleanup")
    if any(value[field] is not False for field in ("rootOperations", "servicesRegistered", "productionActivationTested")):
        raise RuntimeError("Unexpected experiment scope")
    return value


def run():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("Requires an Apple Silicon Mac")
    if os.getuid() == 0 or os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise RuntimeError("Requires an ordinary account")
    result = subprocess.run([sys.executable, "-I", str(SOURCE)], check=True, capture_output=True, text=True, timeout=60)
    value = validate(json.loads(result.stdout))
    host_macos = platform.mac_ver()[0]
    return {"schemaVersion": 1, "hostMacOS": host_macos, "hostArchitecture": platform.machine(),
            "pythonVersion": platform.python_version(), "status": "ordinary-controls-passed", "nativeControls": value,
            "sourceSHA256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "runnerSHA256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
            "productionCodeChanged": False, "productionActivationTested": False, "macOS26RuntimeTested": host_macos.split(".", 1)[0] == "26"}


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
