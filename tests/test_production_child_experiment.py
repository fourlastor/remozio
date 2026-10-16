import importlib.util
import json
import os
import platform
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("production_child_experiment", Path(__file__).resolve().parents[1] / "scripts/run-production-child-experiment.py")
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


class ProductionChildPreparationTests(unittest.TestCase):
    def test_concurrent_source_change_cannot_publish_a_frozen_command_or_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            invocations = []

            def run(command, **kwargs):
                invocations.append(command)
                if "-o" in command:
                    Path(command[command.index("-o") + 1]).write_bytes(b"fixture")
                    return subprocess.CompletedProcess(command, 0)
                self.assertEqual(Path(command[0]).name, "owner-controls")
                return subprocess.CompletedProcess(command, 0, json.dumps({"schemaVersion": 1, "ownerControls": 30,
                    "privilegedControlsRun": False, "realProcessesSpawned": 0}), "")

            with patch.object(EXPERIMENT, "source_hashes", return_value={"input.c": "after"}), \
                 patch.object(EXPERIMENT.subprocess, "run", side_effect=run):
                with self.assertRaisesRegex(RuntimeError, "sources changed"):
                    EXPERIMENT.prepare(directory)
            self.assertEqual(len(invocations), 6)
            self.assertFalse((directory / "manifest.json").exists())
            self.assertFalse((directory / "administrator-command.txt").exists())
            self.assertFalse(any("--privileged-controls" in command for command in invocations))

    def test_compiler_reads_captured_bytes_when_workspace_input_changes_and_is_restored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workspace"
            output = Path(temporary) / "output"
            root.mkdir(); output.mkdir()
            sources = {name: [root / (name + ".c")] for name in EXPERIMENT.SOURCES}
            inputs = {name + ".c": b"reviewed" for name in EXPERIMENT.SOURCES}
            inputs.update({"owner-controls.c": b"reviewed", "CommandAccountCredentials.c": b"reviewed",
                           "CommandChildSpecification.c": b"reviewed", "include/witness.h": b"reviewed"})
            original = root / "probe.c"
            original.write_bytes(b"reviewed")
            compiled = []

            def run(command, **kwargs):
                if "-o" in command:
                    original.write_bytes(b"temporary different code")
                    paths = [Path(value) for value in command if value.endswith(".c")]
                    self.assertTrue(paths)
                    for path in paths:
                        self.assertFalse(path.is_relative_to(root))
                        self.assertEqual(path.read_bytes(), b"reviewed")
                        self.assertEqual(path.stat().st_mode & 0o777, 0o400)
                        compiled.append(path)
                    original.write_bytes(b"reviewed")
                    Path(command[command.index("-o") + 1]).write_bytes(b"fixture executable")
                    return subprocess.CompletedProcess(command, 0)
                name = Path(command[0]).name
                if name == "owner-controls":
                    value = {"schemaVersion": 1, "ownerControls": 30, "privilegedControlsRun": False, "realProcessesSpawned": 0}
                elif "--descriptor-controls" in command:
                    value = {"schemaVersion": 1, "descriptorControls": 3, "privilegedControlsRun": False}
                elif "--inspect" in command and command[-1] != str(2**32 - 1):
                    value = {"schemaVersion": 1, "codecControls": 6, "privilegedControlsRun": False}
                else:
                    return subprocess.CompletedProcess(command, 77 if "--privileged-controls" in command else 64, "", "")
                return subprocess.CompletedProcess(command, 0, json.dumps(value), "")

            with patch.object(EXPERIMENT, "ROOT", root), patch.object(EXPERIMENT, "EXPERIMENT", root), \
                 patch.object(EXPERIMENT, "NATIVE", root), patch.object(EXPERIMENT, "SOURCES", sources), \
                 patch.object(EXPERIMENT, "source_inputs", return_value=inputs), \
                 patch.object(EXPERIMENT.os, "getuid", return_value=501), \
                 patch.object(EXPERIMENT.subprocess, "run", side_effect=run):
                result = EXPERIMENT.prepare(output)
            self.assertEqual(result["sourceHashes"], EXPERIMENT.hashes(inputs))
            self.assertTrue(compiled)
            self.assertTrue(all(not path.exists() for path in compiled))
            self.assertEqual(original.read_bytes(), b"reviewed")
            self.assertFalse(result["privilegedControlsRun"])

    def test_invalid_frozen_authority_inputs_cannot_emit_a_command(self):
        binaries = {name: {"sha256": "0" * 64} for name in EXPERIMENT.SOURCES}
        for uid in [0, -1, 2**32 - 1, True, "501; touch /tmp/foreign"]:
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                EXPERIMENT.administrator_command(Path("/tmp/fixture"), binaries, uid)
        for changed in [dict(binaries, foreign={"sha256": "0" * 64}),
                        {name: value for name, value in binaries.items() if name != "child"},
                        dict(binaries, child={"sha256": "x" * 64}),
                        dict(binaries, child={"sha256": "0" * 63 + "\n"})]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                EXPERIMENT.administrator_command(Path("/tmp/fixture"), changed, 501)


@unittest.skipUnless(platform.system() == "Darwin" and platform.machine() == "arm64" and
                     os.getuid() != 0 and os.geteuid() != 0, "Requires an ordinary Apple Silicon Mac account")
class ProductionChildLegacyCompositionTests(unittest.TestCase):
    def test_actual_legacy_refusal_retires_without_target_execution(self):
        # Only the two entry guards are substituted. The credential API keeps the real UID.
        with tempfile.TemporaryDirectory(prefix="remozio-legacy-refusal-") as temporary, \
             EXPERIMENT.source_snapshot(EXPERIMENT.source_inputs()) as snapshot:
            directory = Path(temporary)
            native = snapshot / EXPERIMENT.NATIVE.relative_to(EXPERIMENT.ROOT)
            experiment = snapshot / EXPERIMENT.EXPERIMENT.relative_to(EXPERIMENT.ROOT)
            for name, original in [("monitor", "macos/app/CommandMonitor/MonitorMain.c"),
                                   ("child", "macos/app/CommandChild/ChildMain.c")]:
                (directory / (name + ".c")).write_text(
                    '#include <unistd.h>\nstatic uid_t fixture_entry_uid(void) { return 0; }\n'
                    '#define getuid fixture_entry_uid\n#define geteuid fixture_entry_uid\n'
                    '#include "' + str(snapshot / original) + '"\n')
            (directory / "probe.c").write_text(
                '#define main production_probe_entry\n#include "' + str(experiment / "probe.c") + '"\n#undef main\n' + r'''
int main(void) {
    if (!getuid() || !geteuid()) return 77;
    if (!locate()) return 70;
    strcpy(target_path, "/usr/bin/true");
    struct sigaction action = {0}; action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGCHLD, &action, NULL)) return 70;
    signal(SIGPIPE, SIG_IGN);
    struct account target;
    if (account(getuid(), &target)) return 70;
    for (unsigned trial = 0; trial < 8; ++trial) {
        bool retired = true; struct control_diagnostic diagnostic;
        int result = one(&target, legacy, &retired, &diagnostic);
        remozio_command_monitor_observation_t state = diagnostic.state;
        if (result || !retired || !state.monitor_reaped || !state.status.reaped ||
            state.monitor_ownership_lost || state.prepared || state.release_attempted || state.target_exec_observed ||
            !state.status.failed || state.status.failure_error != EINVAL || state.fault || state.protocol_failed) {
            fprintf(stderr, "Legacy refusal trial=%u stage=%d primary=%d poll=%d monitorReaped=%d "
                "targetReaped=%d lost=%d failed=%d error=%u fault=%d protocol=%d tag=%u wait=%d\n",
                trial, result, diagnostic.primary_stage, diagnostic.poll_error, state.monitor_reaped,
                state.status.reaped, state.monitor_ownership_lost, state.status.failed, state.status.failure_error,
                state.fault, state.protocol_failed, state.status.latest.tag, state.monitor_wait_status);
            return 1;
        }
    }
    puts("Eight guarded ordinary legacy refusals retired. No target was released.");
    return 0;
}
''')
            for name, sources in EXPERIMENT.SOURCES.items():
                if name == "target":
                    continue
                compiled = [str(directory / (name + ".c"))]
                compiled.extend(str(snapshot / path.relative_to(EXPERIMENT.ROOT)) for path in sources[1:])
                subprocess.run(["xcrun", "clang", "-target", "arm64-apple-macos26.0", "-std=c11", "-Wall", "-Wextra", "-Werror",
                                "-I", str(native / "include"), "-I", str(experiment), *compiled,
                                "-o", str(directory / name)], check=True, timeout=120)
            result = subprocess.run([str(directory / "probe")], capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "Eight guarded ordinary legacy refusals retired. No target was released.\n")


if __name__ == "__main__":
    unittest.main()
