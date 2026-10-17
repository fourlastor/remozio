#!/usr/bin/env python3
"""Exercise hardware runner lifecycle ONLY via a guarded private-simulator test double."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/run-linux-tpm-tls-experiment.py"
SPEC = importlib.util.spec_from_file_location("tpm_runner", SCRIPT)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def main():
    if not __debug__:
        raise RuntimeError("Simulator control requires enabled assertions")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.runtime_root.resolve()
    libs = root / "usr/lib/x86_64-linux-gnu"
    env = os.environ.copy()
    env.update(LD_LIBRARY_PATH=f"{libs}:{libs / 'swtpm'}", OPENSSL_MODULES=str(libs / "ossl-modules"),
               OPENSSL_CONF="/dev/null", TPM2TOOLS_AUTOFLUSH="yes")
    env.pop("TPM2OPENSSL_PARENT_AUTH", None)
    with tempfile.TemporaryDirectory(prefix="remozio-adapter-control-") as temporary:
        base = Path(temporary)
        simulator_dir = base / "simulator"
        simulator_dir.mkdir(mode=0o700)
        simulator = RUNNER.Experiment(simulator_dir, env, root / "usr/bin/tpm2",
                                      root / "usr/bin/swtpm", root / "usr/sbin/tpm2-abrmd")
        original_init, original_run = RUNNER.HardwareProbe.__init__, RUNNER.HardwareProbe.run
        original_access = os.access
        calls = []

        def test_access(path, mode):
            return True if str(path) == "/dev/tpmrm0" else original_access(path, mode)

        def simulator_init(self, directory, environment, tpm2):
            environment.update({name: simulator.env[name] for name in
                                ("TPM2TOOLS_TCTI", "TPM2OPENSSL_TCTI", "DBUS_SESSION_BUS_ADDRESS")})
            original_init(self, directory, environment, tpm2)

        def guarded_run(self, *command, **kwargs):
            # Every tool call must target the private simulator or deliberately absent socket.
            assert self.env["TPM2TOOLS_TCTI"] == "tabrmd:bus_type=session"
            assert self.env["TPM2OPENSSL_TCTI"] in (
                "tabrmd:bus_type=session", f"swtpm:path={self.directory / 'absent-tpm.sock'}")
            assert self.env["DBUS_SESSION_BUS_ADDRESS"] == simulator.env["DBUS_SESSION_BUS_ADDRESS"]
            assert not any("/dev/tpm" in str(value) or "device:" in str(value) for value in command)
            calls.append(command[0])
            return original_run(self, *command, **kwargs)

        probe_args = SimpleNamespace(tcti="device:/dev/tpmrm0", acknowledge_empty_owner_auth=True,
                                     hardware_directory=base / "fixture", create_fixture=True,
                                     reuse_fixture=False, operator_phase="initial", runtime_root=root)
        try:
            simulator.start()
            with patch.object(RUNNER.os, "access", side_effect=test_access), \
                 patch.object(RUNNER.HardwareProbe, "__init__", simulator_init), \
                 patch.object(RUNNER.HardwareProbe, "run", guarded_run):
                created = RUNNER.run_hardware(probe_args)
                originals = {path.name: path.read_bytes() for path in probe_args.hardware_directory.iterdir()}
                simulator.halt()
                simulator.start()
                probe_args.create_fixture, probe_args.reuse_fixture = False, True
                probe_args.operator_phase = "after-reboot"  # Operator label; only simulator was restarted.
                reopened = RUNNER.run_hardware(probe_args)
                assert originals == {path.name: path.read_bytes() for path in probe_args.hardware_directory.iterdir()}
                key = probe_args.hardware_directory / "authority.pem"
                der = base64.b64decode(b"".join(originals["authority.pem"].splitlines()[1:-1]))
                assert der.count(bytes.fromhex("020440000001")) == 1
                changed = der.replace(bytes.fromhex("020440000001"), bytes.fromhex("020481000001"))
                key.write_bytes(b"-----BEGIN TSS2 PRIVATE KEY-----\n" + base64.b64encode(changed) +
                                b"\n-----END TSS2 PRIVATE KEY-----\n")
                count = len(calls)
                try:
                    RUNNER.run_hardware(probe_args)
                    raise AssertionError("Wrong parent accepted")
                except RUNNER.Refused as error:
                    assert str(error) == "wrapped-record-public-or-parent-mismatch"
                assert len(calls) == count
                key.write_bytes(originals["authority.pem"])
                public = probe_args.hardware_directory / "authority.pub"
                changed = bytearray(public.read_bytes())
                changed[-1] ^= 1
                public.write_bytes(changed)
                count = len(calls)
                try:
                    RUNNER.run_hardware(probe_args)
                    raise AssertionError("Mismatched sidecar accepted")
                except RUNNER.Refused as error:
                    assert str(error) == "wrapped-record-public-or-parent-mismatch"
                assert len(calls) == count
            inventory = {name: not simulator.tool("getcap", name).stdout.strip()
                         for name in ("handles-persistent", "handles-nv-index")}
            assert all(inventory.values())
        finally:
            simulator.halt()
    assert not base.exists()
    print(json.dumps({"status": "passed", "evidenceClass": "hardware-adapter-against-private-simulator",
                      "hardwareTPMTested": False, "hardwareRebootTested": False,
                      "createChecks": created["checks"], "reuseAfterSimulatorRestartChecks": reopened["checks"],
                      "retainedRecordsUnchangedByReuse": True,
                      "wrongEmbeddedParentRejectedBeforeAnyProviderCommand": True,
                      "mismatchedPublicSidecarRejectedBeforeAnyProviderCommand": True,
                      "persistentAndNVHandlesEmpty": inventory, "temporaryStateRemoved": not base.exists(),
                      "runnerSHA256": hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                      "controlSHA256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}, sort_keys=True))


if __name__ == "__main__":
    main()
