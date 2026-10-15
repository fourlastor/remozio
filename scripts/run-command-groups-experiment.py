#!/usr/bin/env python3
"""Compile ordinary-account inspection and verify privileged-mode refusal."""
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "experiments/command-groups/probe.c"


def run():
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError("Requires an Apple Silicon Mac")
    if os.getuid() == 0 or os.geteuid() == 0:
        raise RuntimeError("Run inspection as an ordinary account; privileged controls are a separate interactive gate")
    with tempfile.TemporaryDirectory(prefix="remozio-command-groups-") as directory:
        def build(name, flags, source=SOURCE):
            binary = pathlib.Path(directory) / name
            subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos26.0", "-std=c11", *flags,
                            "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)], check=True, timeout=120)
            return binary
        binary = build("posix-probe", [])
        unlimited = build("darwin-probe", ["-D_DARWIN_UNLIMITED_GETGROUPS"])
        wait_source = SOURCE.with_name("wait-tests.c")
        wait_binary = build("owned-wait-controls", [], wait_source)
        wait_result = subprocess.run([str(wait_binary)], check=True, capture_output=True, text=True, timeout=30)
        wait_controls = json.loads(wait_result.stdout)
        if wait_controls != {"schemaVersion": 1, "passed": True, "cases": 7,
                             "privilegedControlsRun": False, "unreapedChildren": 0}:
            raise RuntimeError("Invalid owned-child wait evidence")
        def inspect(binary, uid, interface):
            result = subprocess.run([str(binary), "--inspect", str(uid)], check=True, capture_output=True, text=True, timeout=30)
            value = json.loads(result.stdout)
            if value.get("schemaVersion") != 1 or value.get("privilegedControlsRun") is not False or value.get("getgroupsInterface") != interface:
                raise RuntimeError("Invalid inspection evidence")
            for field in ["rootDirectoryGroups", "targetDirectoryGroups", "currentProcessGroups"]:
                if not isinstance(value.get(field), int) or not 0 <= value[field] <= 1024:
                    raise RuntimeError("Invalid group-count evidence")
            return value
        root, ordinary = inspect(binary, 0, "posix"), inspect(binary, os.getuid(), "posix")
        darwin_root, darwin_ordinary = inspect(unlimited, 0, "darwin-unlimited"), inspect(unlimited, os.getuid(), "darwin-unlimited")
        denied = subprocess.run([str(binary), "--privileged-controls", str(os.getuid())], capture_output=True, timeout=30)
        invalid = subprocess.run([str(binary), "--inspect", str(2**32 - 1)], capture_output=True, timeout=30)
        if denied.returncode != 77 or denied.stdout or invalid.returncode != 64:
            raise RuntimeError("Probe privilege or input guard failed")
        return {"schemaVersion": 1, "hostMacOS": platform.mac_ver()[0], "status": "inspection-passed",
                "rootInspection": root, "ordinaryAccountInspection": ordinary,
                "darwinUnlimitedInspection": {"root": darwin_root, "ordinaryAccount": darwin_ordinary},
                "ordinaryPrivilegedModeRefused": True,
                "invalidUIDRefused": True, "privilegedControlsRun": False, "productionCredentialsChanged": False,
                "productionExecutionTested": False, "ownedWaitControls": wait_controls,
                "waitControlsSHA256": hashlib.sha256(wait_source.read_bytes()).hexdigest(),
                "sourceSHA256": hashlib.sha256(SOURCE.read_bytes()).hexdigest()}


if __name__ == "__main__":
    print(json.dumps(run(), sort_keys=True))
