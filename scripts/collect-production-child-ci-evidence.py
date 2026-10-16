#!/usr/bin/env python3
"""Validate the fixed experiment in its explicit hosted-Mac workflow. Never elevate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BINARY_NAMES = {"probe", "monitor", "child", "target"}
NATIVE_SUCCESS = {"schemaVersion": 1, "privilegedControlsRun": True, "passed": 6,
                  "parentCredentialsUnchanged": True, "allOwnedCleanupConfirmed": True,
                  "fixtureRemoved": True, "installedRemozio": False}


def exact(value, expected):
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(exact(value[key], item) for key, item in expected.items())
    return value == expected


def workflow_context(env, system, architecture, version, uid, euid, head):
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
                "RUNNER_ARCH": "ARM64", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REPOSITORY": "rock3r/remozio", "GITHUB_REF": "refs/heads/main"}
    if any(env.get(key) != value for key, value in required.items()) or system != "Darwin" or architecture != "arm64" or \
            not re.fullmatch(r"26(?:\.[0-9]+){1,2}", version) or not 0 < uid < 2**32 - 1 or not 0 < euid < 2**32 - 1:
        raise ValueError("Requires the explicit hosted macOS 26 workflow and its ordinary account")
    if not re.fullmatch(r"[0-9a-f]{40}", head) or env.get("GITHUB_SHA") != head:
        raise ValueError("Checkout does not match the workflow commit")
    run, attempt = env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", run) or not re.fullmatch(r"[1-9][0-9]{0,9}", attempt):
        raise ValueError("Invalid workflow identity")
    return {"hostMacOS": version, "hostArchitecture": architecture, "sourceCommit": head,
            "workflowRunID": run, "workflowRunAttempt": attempt,
            "runURL": "https://github.com/rock3r/remozio/actions/runs/" + run}


def verify_preparation(manifest, expected_sources, context):
    expected = {"schemaVersion": 1, "hostMacOS": context["hostMacOS"], "hostArchitecture": "arm64",
                "ordinaryControls": {"schemaVersion": 1, "codecControls": 6, "privilegedControlsRun": False},
                "ownerControls": {"schemaVersion": 1, "ownerControls": 30, "privilegedControlsRun": False, "realProcessesSpawned": 0},
                "descriptorControls": {"schemaVersion": 1, "descriptorControls": 3, "privilegedControlsRun": False},
                "ordinaryPrivilegedModeRefused": True, "invalidUIDRefused": True,
                "privilegedControlsRun": False, "productionExecutionTested": False, "installedRemozio": False}
    if type(manifest) is not dict or manifest.keys() != expected.keys() | {"sourceHashes", "executables", "administratorCommandSHA256"} or \
            any(not exact(manifest[key], value) for key, value in expected.items()):
        raise ValueError("Unexpected preparation record")
    if not expected_sources or not exact(manifest["sourceHashes"], expected_sources):
        raise ValueError("Prepared sources differ from the workflow commit")
    binaries = manifest["executables"]
    if type(binaries) is not dict or binaries.keys() != BINARY_NAMES:
        raise ValueError("Unexpected helper set")
    for evidence in binaries.values():
        if type(evidence) is not dict or evidence.keys() != {"bytes", "sha256"} or type(evidence["bytes"]) is not int or \
                not 0 < evidence["bytes"] <= 4 * 1024 * 1024 or type(evidence["sha256"]) is not str or \
                not re.fullmatch(r"[0-9a-f]{64}", evidence["sha256"]):
            raise ValueError("Invalid helper evidence")
    if type(manifest["administratorCommandSHA256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", manifest["administratorCommandSHA256"]):
        raise ValueError("Invalid frozen command hash")


def collect(manifest, native, expected_sources, context):
    verify_preparation(manifest, expected_sources, context)
    if not exact(native, NATIVE_SUCCESS):
        raise ValueError("The native controls did not establish complete success and cleanup")
    return {"schemaVersion": 1, "kind": "macos-production-child-hosted",
            **{key: context[key] for key in ["hostMacOS", "hostArchitecture", "sourceCommit", "workflowRunID", "workflowRunAttempt", "runURL"]},
            "sourceHashes": manifest["sourceHashes"], "executables": manifest["executables"],
            "administratorCommandSHA256": manifest["administratorCommandSHA256"],
            "ordinaryControls": manifest["ordinaryControls"], "ownerControls": manifest["ownerControls"],
            "descriptorControls": manifest["descriptorControls"], "nativeControls": native,
            "installedServicesTested": False, "physicalPixelTested": False}


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate evidence field")
        value[key] = item
    return value


def read_bytes(path, maximum=65536):
    with path.open("rb") as source:
        value = source.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("Evidence input exceeds its bound")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    for name in ["verify", "collect"]:
        mode = modes.add_parser(name)
        mode.add_argument("--preparation", type=Path, required=True)
        if name == "collect":
            mode.add_argument("--native-result", type=Path, required=True)
            mode.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    context = workflow_context(os.environ, platform.system(), platform.machine(), platform.mac_ver()[0], os.getuid(), os.geteuid(), head)
    spec = importlib.util.spec_from_file_location("production_child_preparer", ROOT / "scripts/run-production-child-experiment.py")
    preparer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preparer)
    live = preparer.source_hashes()
    committed = {name: hashlib.sha256(subprocess.check_output(["git", "show", head + ":" + name], cwd=ROOT)).hexdigest() for name in live}
    if live != committed:
        raise ValueError("Live experiment sources differ from the workflow commit")
    manifest = json.loads(read_bytes(args.preparation), object_pairs_hook=unique_object)
    verify_preparation(manifest, committed, context)
    directory = args.preparation.parent
    for name, evidence in manifest["executables"].items():
        path = directory / name
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.getuid() or \
                metadata.st_size != evidence["bytes"] or hashlib.sha256(read_bytes(path, 4 * 1024 * 1024)).hexdigest() != evidence["sha256"]:
            raise ValueError("A prepared helper changed")
    command = read_bytes(directory / "administrator-command.txt")
    if command != preparer.administrator_command(directory, manifest["executables"], os.getuid()).encode() or \
            hashlib.sha256(command).hexdigest() != manifest["administratorCommandSHA256"]:
        raise ValueError("The frozen command changed")
    if args.mode == "verify":
        print("Reviewed helper and command hashes verified; no privileged operation performed.")
        return
    native = json.loads(read_bytes(args.native_result), object_pairs_hook=unique_object)
    result = collect(manifest, native, committed, context)
    with args.output.open("x") as output:
        output.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("Production child CI evidence: " + json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
