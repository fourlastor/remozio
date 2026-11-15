import contextlib
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-protected-launch-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_protected_launch_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


def first(expected):
    return {key: sorted(allowed)[0] for key, allowed in expected.items()}


def attacker_report(case, alternative=0, **changes):
    values = first(EXPERIMENT.CASES[case]["attacker"][alternative])
    values.update(changes)
    return json.dumps(values).encode()


def monitor_report(case, **changes):
    values = first(EXPERIMENT.CASES[case]["monitor"])
    values.update(monitorAppArmor="unconfined", frontendAppArmor="unconfined")
    values.update(changes)
    return json.dumps(values).encode()


def evaluate(case, attacker=None, monitor=None, attacker_rc=0, monitor_rc=0, queued="no"):
    attacker = attacker_report(case) if attacker is None else attacker
    if EXPERIMENT.CASES[case]["monitor"] is None:
        return EXPERIMENT.evaluate_case(case, attacker, attacker_rc, queued=queued)
    return EXPERIMENT.evaluate_case(case, attacker, attacker_rc,
                                    monitor_report(case) if monitor is None else monitor, monitor_rc)


@contextlib.contextmanager
def linux_root():
    with contextlib.ExitStack() as stack:
        for owner, name, value in ((EXPERIMENT.platform, "system", "Linux"), (EXPERIMENT.platform, "machine", "x86_64"),
                                   (EXPERIMENT.os, "geteuid", 0), (EXPERIMENT.os, "getuid", 0)):
            stack.enter_context(patch.object(owner, name, return_value=value))
        yield


class CaseTableTests(unittest.TestCase):
    def test_every_plan_case_is_measured_and_replacement_runs_last(self):
        # P1-P3 and N11 are the p1 monitor report; N9 has an untraced and a traced member; n13
        # is the added missing-SO_PEERPIDFD control.
        self.assertEqual(set(EXPERIMENT.CASES), {"p1", "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n9-untraced",
                                                 "n9-traced", "n10", "n12", "n13", "n8"})
        self.assertEqual(list(EXPERIMENT.CASES)[-1], "n8")

    def test_missing_pidfd_control_runs_the_real_monitor_with_an_unknown_option(self):
        spec = EXPERIMENT.CASES["n13"]
        self.assertEqual((spec["argument"], spec["monitorMode"], spec["monitorBinary"]),
                         ("p1", "cap", "monitor-nopidfd"))
        self.assertEqual(spec["monitor"]["peerPidfd"], {"ENOPROTOOPT"})
        self.assertEqual(spec["monitor"]["seize"], {"not-attempted"})
        self.assertEqual(spec["monitor"]["accepted"], {"no"})
        monitor = EXPERIMENT.MONITOR.read_text()
        self.assertIn("getsockopt(conn, SOL_SOCKET, RMZPL_PEERPIDFD_OPTION,", monitor)
        self.assertEqual(EXPERIMENT.MONITOR_BUILDS, {"monitor": (),
                                                     "monitor-nopidfd": ("-DRMZPL_PEERPIDFD_OPTION=32767",)})
        self.assertTrue(all(spec["monitorBinary"] in (None, *EXPERIMENT.MONITOR_BUILDS)
                            for spec in EXPERIMENT.CASES.values()))

    def test_monitor_tables_require_every_property_except_observed_labels(self):
        for case, spec in EXPERIMENT.CASES.items():
            if spec["monitor"] is not None:
                with self.subTest(case=case):
                    self.assertEqual(set(spec["monitor"]), set(EXPERIMENT.MONITOR_KEYS) - EXPERIMENT.OBSERVED_ONLY)

    def test_fixture_sources_match_the_runner_vocabulary(self):
        monitor = EXPERIMENT.MONITOR.read_text()
        emitted = set(re.findall(r'(?:field|flag)\("([A-Za-z]+)"', monitor))
        self.assertEqual(emitted, set(EXPERIMENT.MONITOR_KEYS) | {"error"})
        attacker = EXPERIMENT.ATTACKER.read_text()
        dispatched = set(re.findall(r'!strcmp\(name, "([a-z0-9-]+)"\)', attacker))
        self.assertEqual(dispatched, {spec["argument"] for spec in EXPERIMENT.CASES.values()})

    def test_monitor_reads_only_procfs_entries_open_to_cap_sys_ptrace(self):
        # personality and auxv are root-owned mode 0400 for a task that is not dumpable.
        monitor = EXPERIMENT.MONITOR.read_text()
        opened = set(re.findall(r'read_at\(dir, "([a-z/]+)"', monitor))
        self.assertEqual(opened, {"status", "stat", "maps", "attr/apparmor/current", "attr/current"})
        self.assertIn("process_vm_readv(pid,", monitor)

    def test_controls_isolate_the_refusal_they_measure(self):
        admitted = EXPERIMENT._expect(EXPERIMENT.ADMITTED)
        for case, differing in (("n8", {"exeIsCurrentInstalledImage", "mapsAllowed", "accepted"}),
                                ("n9-untraced", {"groupsExcludeFrontendGroup", "accepted"}),
                                ("n9-traced", {"groupsExcludeFrontendGroup", "accepted"})):
            with self.subTest(case=case):
                monitor = EXPERIMENT.CASES[case]["monitor"]
                self.assertEqual({key for key in admitted if monitor[key] != admitted[key]}, differing)
        self.assertTrue(EXPERIMENT.CASES["n9-untraced"]["member"])
        self.assertFalse(EXPERIMENT.CASES["p1"]["member"])
        self.assertEqual({case for case, spec in EXPERIMENT.CASES.items() if spec["monitorMode"] == "nocap"}, {"n10"})


class EvaluateCaseTests(unittest.TestCase):
    def test_expected_outcome_passes_for_every_case(self):
        for case in EXPERIMENT.CASES:
            with self.subTest(case=case):
                result = evaluate(case)
                self.assertTrue(result["passed"], result)
                self.assertEqual(result["mismatches"], [])

    def test_user_namespace_case_accepts_refusal_or_an_unmapped_launch(self):
        self.assertTrue(evaluate("n12", attacker_report("n12", 0))["passed"])
        self.assertTrue(evaluate("n12", attacker_report("n12", 1))["passed"])
        elevated = evaluate("n12", attacker_report("n12", 1, effectiveGidElevated="yes"))
        self.assertEqual(elevated["mismatches"], ["attacker.effectiveGidElevated"])
        # Only a policy errno counts as a refusal; any other unshare failure fails the case.
        for errno_name in ("EPERM", "EACCES"):
            self.assertTrue(evaluate("n12", attacker_report("n12", 0, userNamespace=errno_name))["passed"])
        self.assertFalse(evaluate("n12", attacker_report("n12", 0, userNamespace="other"))["passed"])
        self.assertIn('field("userNamespace", errname(code))', EXPERIMENT.ATTACKER.read_text())

    def test_admitted_launch_fails_on_any_failed_property(self):
        for key in EXPERIMENT.STOP_CHECKS:
            with self.subTest(key=key):
                result = evaluate("p1", monitor=monitor_report("p1", **{key: "no"}))
                self.assertFalse(result["passed"])
                self.assertEqual(result["mismatches"], [f"monitor.{key}"])

    def test_missing_peer_pidfd_fails_closed(self):
        refused = {"peerPidfd": "ENOPROTOOPT", "seize": "not-attempted", "pidfdAssociated": "no", "stopHeld": "no",
                   **dict.fromkeys(EXPERIMENT.STOP_CHECKS, "no"), "fdDirectoryListing": "not-attempted",
                   "frontendAppArmor": "not-attempted", "accepted": "no"}
        result = evaluate("p1", attacker_report("p1", frontendExit="rejected"), monitor_report("p1", **refused))
        self.assertFalse(result["passed"])
        self.assertIn("monitor.peerPidfd", result["mismatches"])
        self.assertIn("attacker.frontendExit", result["mismatches"])

    def test_apparmor_labels_are_recorded_not_required(self):
        result = evaluate("p1", monitor=monitor_report("p1", monitorAppArmor="confined", frontendAppArmor="confined"))
        self.assertTrue(result["passed"])
        self.assertEqual(result["monitor"]["monitorAppArmor"], "confined")

    def test_reports_reject_duplicates_non_strings_and_bounds(self):
        for raw in (b'{"frontendExit":"accepted","frontendExit":"accepted"}', b'{"frontendExit":0}',
                    b'{"frontendExit":NaN}', b'["accepted"]', b"not json",
                    b'{"frontendExit":"' + b"a" * EXPERIMENT.MAX_OUTPUT_BYTES + b'"}', "text"):
            with self.subTest(raw=raw[:40]):
                result = evaluate("p1", attacker=raw)
                self.assertEqual(result, {"passed": False, "error_type": "InvalidAttackerReport"})

    def test_unknown_keys_or_values_publish_nothing(self):
        for raw in (json.dumps({"frontendExit": "accepted", "path": "ok"}).encode(),
                    json.dumps({"frontendExit": "/home/someone"}).encode()):
            with self.subTest(raw=raw):
                self.assertEqual(evaluate("p1", attacker=raw),
                                 {"passed": False, "error_type": "InvalidAttackerReport"})
        extra = json.loads(monitor_report("p1"))
        extra["uid"] = "yes"
        result = evaluate("p1", monitor=json.dumps(extra).encode())
        self.assertEqual(result["error_type"], "InvalidMonitorReport")
        self.assertNotIn("monitor", result)
        result = evaluate("p1", monitor=monitor_report("p1", seize="1234"))
        self.assertEqual(result["error_type"], "InvalidMonitorReport")

    def test_monitor_error_publishes_a_known_category_only(self):
        known = evaluate("p1", monitor=b'{"monitorCredentialsExact":"yes","error":"accept-timeout"}')
        self.assertEqual((known["error_type"], known["monitorError"]), ("MonitorError", "accept-timeout"))
        overflow = evaluate("p1", monitor=b'{"error":"overflow"}')
        self.assertEqual(overflow["monitorError"], "overflow")
        attacker = evaluate("p1", attacker=b'{"error":"overflow"}')
        self.assertEqual((attacker["passed"], attacker["mismatches"]), (False, ["attacker.keys"]))
        unknown = evaluate("p1", monitor=b'{"error":"/etc/private"}')
        self.assertEqual(unknown, {"passed": False, "error_type": "MonitorError", "attacker": {"frontendExit": "accepted"}})

    def test_cases_without_a_monitor_require_an_empty_queue(self):
        self.assertEqual(evaluate("n1", queued="yes")["mismatches"], ["connectionQueued"])
        self.assertEqual(evaluate("n1", queued=None)["error_type"], "MissingConnectionCheck")

    def test_exit_statuses_must_be_zero(self):
        self.assertEqual(evaluate("p1", attacker_rc=1)["mismatches"], ["attacker.exitStatus"])
        self.assertEqual(evaluate("p1", monitor_rc=3)["mismatches"], ["monitor.exitStatus"])

    def test_spawn_failure_is_published_as_a_key_mismatch(self):
        result = evaluate("n2", attacker=b'{"spawn":"failed"}')
        self.assertEqual((result["passed"], result["mismatches"], result["attacker"]),
                         (False, ["attacker.keys"], {"spawn": "failed"}))
        result = evaluate("n1", attacker=b'{"installed.spawn":"failed","control.spawn":"failed"}')
        self.assertEqual(result["mismatches"], ["attacker.keys"])

    def test_same_uid_attack_must_fail_on_the_installed_image_and_work_on_the_copy(self):
        result = evaluate("n1", attacker_report("n1", **{"installed.vmWrite": "ok"}))
        self.assertEqual(result["mismatches"], ["attacker.installed.vmWrite"])
        result = evaluate("n1", attacker_report("n1", **{"control.seize": "EPERM"}))
        self.assertEqual(result["mismatches"], ["attacker.control.seize"])


def elf_header(e_type=2, program_types=(1,)):
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[16:18] = e_type.to_bytes(2, "little")
    header[32:40] = (64).to_bytes(8, "little")
    header[54:56] = (56).to_bytes(2, "little")
    header[56:58] = len(program_types).to_bytes(2, "little")
    return bytes(header) + b"".join(kind.to_bytes(4, "little") + bytes(52) for kind in program_types)


class HelperTests(unittest.TestCase):
    def test_static_non_pie_requires_an_executable_without_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image"
            for data, expected in ((elf_header(), True), (elf_header(program_types=(1, 3)), False),
                                   (elf_header(e_type=3), False), (elf_header()[:80], False), (b"#!/bin/sh\n", False)):
                with self.subTest(expected=expected, size=len(data)):
                    path.write_bytes(data)
                    self.assertEqual(EXPERIMENT.static_non_pie(path), expected)

    def test_root_file_gets_its_owner_before_its_mode_and_is_never_reused(self):
        calls = []
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(EXPERIMENT.os, "fchown", side_effect=lambda _fd, uid, gid: calls.append(("chown", uid, gid))), \
             patch.object(EXPERIMENT.os, "fchmod", side_effect=lambda _fd, mode: calls.append(("chmod", mode))):
            path = Path(directory) / "image"
            EXPERIMENT.write_root_file(path, b"image", 0o2755, 4242)
            # chown clears set-ID bits, so the mode must come after the owner.
            self.assertEqual(calls, [("chown", 0, 4242), ("chmod", 0o2755)])
            link = Path(directory) / "link"
            link.symlink_to(path)
            for target in (path, link):
                with self.subTest(target=target.name), self.assertRaises(FileExistsError):
                    EXPERIMENT.write_root_file(target, b"other", 0o755)
            self.assertEqual(path.read_bytes(), b"image")

    @unittest.skipUnless(platform.system() == "Linux", "AF_UNIX SOCK_SEQPACKET with SOCK_CLOEXEC is Linux only")
    def test_socket_gate_binds_under_a_restrictive_umask_and_checks_the_result(self):
        calls = []
        record_chown = lambda _path, uid, gid: calls.append(("chown", uid, gid))
        record_chmod = lambda _path, mode: calls.append(("chmod", mode))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.sock"
            with patch.object(EXPERIMENT.os, "chown", side_effect=record_chown), \
                 patch.object(EXPERIMENT.os, "chmod", side_effect=record_chmod):
                # Without the real chown and chmod the inode stays the caller's: the check refuses.
                with self.assertRaisesRegex(RuntimeError, "socket gate"):
                    EXPERIMENT.make_listener(path, 4242)
            self.assertEqual(calls, [("chown", 0, 4242), ("chmod", 0o660)])
            self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)  # the bind ran under umask 0177
            exact = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0, st_gid=4242)
            with patch.object(EXPERIMENT.os, "chown"), patch.object(EXPERIMENT.os, "chmod"), \
                 patch.object(EXPERIMENT.os, "lstat", return_value=exact):
                EXPERIMENT.make_listener(Path(directory) / "b.sock", 4242).close()

    def test_root_owned_ancestry_refuses_user_owned_or_writable_components(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(EXPERIMENT.root_owned_ancestry(Path(directory).resolve()))
        if os.lstat("/usr").st_uid == 0:
            self.assertTrue(EXPERIMENT.root_owned_ancestry(Path("/usr")))

    def test_host_metadata_publishes_numbers_and_closed_values_only(self):
        settings = {"/proc/sys/kernel/yama/ptrace_scope": b"1\n", "/proc/sys/fs/suid_dumpable": b"2\n",
                    "/proc/sys/fs/protected_hardlinks": b"1\n", "/sys/module/apparmor/parameters/enabled": b"Y\n",
                    "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": b"1\n",
                    "/proc/sys/kernel/unprivileged_userns_clone": b"/proc/self\n",
                    "/etc/os-release": b'NAME="Private Host"\nID=ubuntu\nVERSION_ID="25.10"\n'}
        with patch.object(EXPERIMENT, "_policy_bytes", side_effect=lambda path, limit=4096: settings.get(path)), \
             patch.object(EXPERIMENT.platform, "release", return_value="6.17.0-41-generic-private-host"):
            host = EXPERIMENT.host_metadata()
        self.assertEqual(host["kernelVersion"], "6.17.0-41")
        self.assertEqual(host["osRelease"], {"id": "ubuntu", "versionId": "25.10"})
        self.assertEqual(host["settings"], {"ptraceScope": 1, "suidDumpable": 2, "protectedHardlinks": 1,
                                            "apparmorEnabled": True, "apparmorRestrictUnprivilegedUserns": 1,
                                            "unprivilegedUsernsClone": "unavailable"})
        self.assertNotIn("private", json.dumps(host).lower())

    def test_os_release_refuses_paths(self):
        with patch.object(EXPERIMENT, "_policy_bytes", return_value=b"ID=../../etc/x\nVERSION_ID=1\n"):
            self.assertEqual(EXPERIMENT._os_release(), {"id": "unknown", "versionId": "1"})

    def test_source_hashes_are_repository_relative(self):
        hashes = EXPERIMENT.source_hashes()
        self.assertEqual(set(hashes), {"scripts/run-linux-protected-launch-experiment.py",
                                       "experiments/linux-protected-launch/frontend.c",
                                       "experiments/linux-protected-launch/monitor.c",
                                       "experiments/linux-protected-launch/attacker.c",
                                       "scripts/run-linux-caller-experiment.py"})
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()))


class PreconditionTests(unittest.TestCase):
    def test_measure_refuses_without_root(self):
        with patch.object(EXPERIMENT.platform, "system", return_value="Linux"), \
             patch.object(EXPERIMENT.platform, "machine", return_value="x86_64"), \
             patch.object(EXPERIMENT.os, "geteuid", return_value=1000), \
             patch.object(EXPERIMENT, "Run") as run:
            with self.assertRaisesRegex(RuntimeError, "requires root"):
                EXPERIMENT.measure()
        run.assert_not_called()

    def test_measure_refuses_a_bad_timeout(self):
        for timeout in (4, 61, float("nan"), "15", True):
            with self.subTest(timeout=timeout), linux_root(), patch.object(EXPERIMENT, "Run") as run:
                with self.assertRaises(ValueError):
                    EXPERIMENT.measure(timeout)
                run.assert_not_called()

    def test_operator_must_be_an_ordinary_sudo_caller(self):
        with patch.dict(EXPERIMENT.os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "through sudo"):
                EXPERIMENT.operator_account()
        account = SimpleNamespace(pw_uid=0, pw_gid=0, pw_name="root")
        with patch.dict(EXPERIMENT.os.environ, {"SUDO_UID": "0", "SUDO_GID": "0"}, clear=True), \
             patch.object(EXPERIMENT.pwd, "getpwuid", return_value=account):
            with self.assertRaisesRegex(RuntimeError, "ordinary account"):
                EXPERIMENT.operator_account()
        account = SimpleNamespace(pw_uid=1000, pw_gid=1001, pw_name="operator")
        with patch.dict(EXPERIMENT.os.environ, {"SUDO_UID": "1000", "SUDO_GID": "1000"}, clear=True), \
             patch.object(EXPERIMENT.pwd, "getpwuid", return_value=account):
            with self.assertRaisesRegex(RuntimeError, "ordinary account"):
                EXPERIMENT.operator_account()

    def test_nosuid_or_untrusted_parent_is_refused_before_any_change(self):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        for ancestry, flags in ((True, EXPERIMENT.os.ST_NOSUID), (False, 0)):
            with self.subTest(ancestry=ancestry), linux_root(), \
                 patch.object(EXPERIMENT, "operator_account", return_value=operator), \
                 patch.object(EXPERIMENT, "root_owned_ancestry", return_value=ancestry), \
                 patch.object(EXPERIMENT.os, "statvfs", return_value=SimpleNamespace(f_flag=flags)), \
                 patch.object(EXPERIMENT, "Run") as run:
                with self.assertRaisesRegex(RuntimeError, "set-ID execution"):
                    EXPERIMENT.measure()
                run.assert_not_called()

    def test_cleanup_runs_after_a_failed_setup_and_warns_when_incomplete(self):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        run = Mock()
        run.setup.side_effect = RuntimeError("fixture build failed")
        run.cleanup.return_value = {"filesRemoved": True, "monitorUserRemoved": False, "frontendGroupRemoved": True}
        stderr = io.StringIO()
        with linux_root(), patch.object(EXPERIMENT, "operator_account", return_value=operator), \
             patch.object(EXPERIMENT, "root_owned_ancestry", return_value=True), \
             patch.object(EXPERIMENT.os, "statvfs", return_value=SimpleNamespace(f_flag=0)), \
             patch.object(EXPERIMENT, "Run", return_value=run), \
             patch.object(EXPERIMENT, "subreaper", contextlib.nullcontext), \
             patch.object(EXPERIMENT.sys, "stderr", stderr):
            with self.assertRaisesRegex(RuntimeError, "fixture build failed"):
                EXPERIMENT.measure()
        run.cleanup.assert_called_once_with()
        self.assertIn("not fully removed", stderr.getvalue())

    def measure_with(self, run):
        operator = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator")
        with linux_root(), patch.object(EXPERIMENT, "operator_account", return_value=operator), \
             patch.object(EXPERIMENT, "root_owned_ancestry", return_value=True), \
             patch.object(EXPERIMENT.os, "statvfs", return_value=SimpleNamespace(f_flag=0)), \
             patch.object(EXPERIMENT, "Run", return_value=run), \
             patch.object(EXPERIMENT, "subreaper", contextlib.nullcontext), \
             patch.object(EXPERIMENT, "host_metadata", return_value={}):
            return EXPERIMENT.measure()

    def test_a_failed_setup_check_starts_no_case(self):
        run = Mock()
        run.setup.return_value = {"frontendGroupHasNoMembers": False, "installedImageExact": True}
        run.cleanup.return_value = {"filesRemoved": True}
        report = self.measure_with(run)
        run.seccomp_policy_sha256.assert_not_called()
        run.run_case.assert_not_called()
        self.assertEqual((report["passed"], report["cases"], report["seccompPolicySha256"]),
                         (False, {}, "not-measured"))

    def test_every_case_must_run_and_pass(self):
        run = Mock()
        run.setup.return_value = {"frontendGroupHasNoMembers": True}
        run.cleanup.return_value = {"filesRemoved": True}
        run.seccomp_policy_sha256.return_value = "0" * 64
        run.run_case.return_value = {"passed": True}
        report = self.measure_with(run)
        self.assertEqual([call.args[0] for call in run.run_case.call_args_list], list(EXPERIMENT.CASES))
        self.assertTrue(report["passed"])

    def test_interrupted_account_creation_is_still_removed(self):
        run = EXPERIMENT.Run(SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator"), 15)
        exists = set()

        def create(arguments, _timeout, **_options):
            exists.add(arguments[-1])  # the tool changed the account database, then timed out
            raise subprocess.TimeoutExpired(arguments[0], 15)

        absent = lambda _lookup, name: name not in exists
        with patch.object(EXPERIMENT, "run_owned", side_effect=create), patch.object(EXPERIMENT, "_absent", absent):
            with self.assertRaises(subprocess.TimeoutExpired):
                run._create("group_created", ["groupadd", "--system", run.group_name], (run.group_name,))
        self.assertTrue(run.group_created)
        with patch.object(EXPERIMENT, "run_owned") as tool, patch.object(EXPERIMENT, "_absent", absent):
            run.cleanup()
        self.assertEqual([call.args[0] for call in tool.call_args_list], [["groupdel", run.group_name]])

    def test_an_existing_name_is_never_created_or_removed(self):
        run = EXPERIMENT.Run(SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator"), 15)
        with patch.object(EXPERIMENT, "_absent", return_value=False), patch.object(EXPERIMENT, "run_owned") as tool:
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                run._create("group_created", ["groupadd", run.group_name], (run.group_name,))
            run.cleanup()
        self.assertFalse(run.group_created)
        tool.assert_not_called()

    def test_cleanup_touches_only_state_this_run_created(self):
        run = EXPERIMENT.Run(SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator"), 15)
        with patch.object(EXPERIMENT.shutil, "rmtree") as remove, patch.object(EXPERIMENT, "run_owned") as tool:
            state = run.cleanup()
        remove.assert_not_called()
        tool.assert_not_called()
        self.assertEqual(set(state), {"filesRemoved", "monitorUserRemoved", "frontendGroupRemoved"})

    def test_cleanup_continues_after_a_failed_step(self):
        run = EXPERIMENT.Run(SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name="operator"), 15)
        run.base_created = run.monitor_created = run.group_created = True
        with patch.object(EXPERIMENT.shutil, "rmtree", side_effect=OSError()), \
             patch.object(EXPERIMENT, "run_owned", side_effect=RuntimeError()) as tool, \
             patch.object(EXPERIMENT, "_absent", return_value=False):
            state = run.cleanup()
        self.assertEqual([call.args[0][0] for call in tool.call_args_list], ["userdel", "groupdel", "groupdel"])
        self.assertEqual(state["monitorUserRemoved"], False)

    def test_main_reports_no_raw_data_on_failure(self):
        for error in (OSError("/private/path"), subprocess.TimeoutExpired("/private/path", 1)):
            stderr = io.StringIO()
            with self.subTest(error=type(error).__name__), \
                 patch.object(EXPERIMENT, "measure", side_effect=error), \
                 patch.object(sys, "argv", ["runner"]), patch.object(sys, "stderr", stderr):
                with self.assertRaises(SystemExit) as raised:
                    EXPERIMENT.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertNotIn("/private/path", stderr.getvalue())


@unittest.skipUnless(platform.system() == "Linux", "Linux owned-process cleanup")
class OwnedProcessTests(unittest.TestCase):
    def spawn(self, code):
        return subprocess.Popen([sys.executable, "-I", "-c", code], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True)

    def test_output_bound_and_deadline_are_enforced_and_groups_reaped(self):
        process = self.spawn(f"import sys; sys.stdout.write('x' * {EXPERIMENT.MAX_OUTPUT_BYTES + 10})")
        with self.assertRaises(EXPERIMENT.OutputLimitError):
            EXPERIMENT._read_output(process, EXPERIMENT.time.monotonic() + 10)
        self.assertTrue(EXPERIMENT._retire(process))
        process = self.spawn("import time; time.sleep(30)")
        with self.assertRaises(subprocess.TimeoutExpired):
            EXPERIMENT._read_output(process, EXPERIMENT.time.monotonic() + 0.2)
        self.assertTrue(EXPERIMENT._retire(process))
        self.assertIsNotNone(process.returncode)


FIXTURE_FLAGS = ("-std=c11", "-O2", "-Wall", "-Wextra", "-Werror")


@unittest.skipUnless(os.environ.get("REMOZIO_LINUX_PROTECTED_LAUNCH_LIVE") == "1", "explicit live fixture controls")
@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86_64 fixtures")
class LiveFixtureTests(unittest.TestCase):
    """Unprivileged mechanics only. The set-group-ID measurement is the supervised runner."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        build = Path(cls.directory.name)
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("no C compiler")
        cls.frontend, cls.attacker = build / "frontend", build / "attacker"
        monitors = tuple((build / name, EXPERIMENT.MONITOR, flags) for name, flags in EXPERIMENT.MONITOR_BUILDS.items())
        for output, source, extra in ((cls.frontend, EXPERIMENT.FRONTEND, ("-static", "-no-pie")),
                                      (cls.attacker, EXPERIMENT.ATTACKER, ()), *monitors):
            subprocess.run([compiler, *FIXTURE_FLAGS, *extra, "-o", str(output), str(source)], check=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def attack(self, case):
        output = subprocess.run([str(self.attacker), case, str(self.frontend), str(self.frontend), "/nonexistent/s",
                                 "4294967294", "10"], stdin=subprocess.DEVNULL, capture_output=True, check=True,
                                timeout=30).stdout
        return EXPERIMENT.parse_report(output)

    def test_frontend_is_static_and_dumps_a_whole_filter(self):
        self.assertTrue(EXPERIMENT.static_non_pie(self.frontend))
        output = subprocess.run([str(self.frontend), "dump-filter"], capture_output=True, check=True, timeout=10).stdout
        self.assertTrue(output and len(output) % 8 == 0)

    def test_forbidden_operations_are_killed_by_the_filter(self):
        expected = dict.fromkeys(("exec", "mprotect", "mmap-exec", "shared", "clone", "x32"), "SIGSYS")
        self.assertEqual(self.attack("n7"), expected)
        # sudo gives the command a hard core limit of 0 (rlimit_core); the self-tests must still run.
        zero_core = lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        output = subprocess.run([str(self.attacker), "n7", str(self.frontend), str(self.frontend), "/nonexistent/s",
                                 "4294967294", "10"], stdin=subprocess.DEVNULL, capture_output=True, check=True,
                                timeout=30, preexec_fn=zero_core).stdout
        self.assertEqual(EXPERIMENT.parse_report(output), expected)

    def test_hello_carries_the_personality_read_before_the_filter(self):
        libc = ctypes.CDLL(None, use_errno=True)
        for persona, expected in ((None, b"RMZPL1 00000000\n"), (0x0040000, b"RMZPL1 00040000\n")):  # ADDR_NO_RANDOMIZE
            with self.subTest(persona=persona), tempfile.TemporaryDirectory() as directory, \
                 socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
                path = Path(directory) / "s"
                listener.bind(str(path))
                listener.listen(1)
                listener.settimeout(10)
                # The copy has no set-ID bits, so the kernel keeps the personality across exec.
                set_persona = None if persona is None else (lambda: libc.personality(persona))
                frontend = subprocess.Popen([str(self.frontend), "run", str(path)], preexec_fn=set_persona)
                connection, _ = listener.accept()
                with connection:
                    hello = connection.recv(64)
                    connection.send(b"A")
                self.assertEqual(frontend.wait(timeout=10), 0)
                self.assertEqual(hello, expected)

    def test_dumped_filter_allows_exactly_the_protocol_path(self):
        """Decodes the installed program and runs it, so a wrong hand-counted jump fails here."""
        dump = subprocess.run([str(self.frontend), "dump-filter"], capture_output=True, check=True, timeout=10).stdout
        program = [struct.unpack_from("<HBBI", dump, offset) for offset in range(0, len(dump), 8)]
        allow, kill = 0x7FFF0000, 0x80000000  # SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS

        def verdict(nr, *args, arch=0xC000003E):  # struct seccomp_data; AUDIT_ARCH_X86_64
            data = struct.pack("<iIQ6Q", nr, arch, 0, *args, *([0] * (6 - len(args))))
            pc = acc = 0
            for _ in program:  # classic BPF jumps only forward
                code, jt, jf, k = program[pc]
                if code == 0x20:  # BPF_LD | BPF_W | BPF_ABS
                    acc, pc = struct.unpack_from("<I", data, k)[0], pc + 1
                elif code in (0x15, 0x35, 0x45):  # BPF_JMP | BPF_K with JEQ, JGE, JSET
                    taken = acc == k if code == 0x15 else acc >= k if code == 0x35 else bool(acc & k)
                    pc += 1 + (jt if taken else jf)
                elif code == 0x06:  # BPF_RET | BPF_K
                    return k
                else:
                    self.fail(f"unexpected instruction {code:#x}")
            self.fail("program ran off its end")

        # read write close connect sendmsg recvmsg exit exit_group rt_sigreturn rt_sigprocmask
        # restart_syscall brk munmap; with all arguments zero only these and mprotect pass.
        simple = {0, 1, 3, 42, 46, 47, 60, 231, 15, 14, 219, 12, 11}
        self.assertEqual({nr for nr in range(512) if verdict(nr) == allow}, simple | {10})
        read_write, private_anonymous, high = 0x3, 0x22, 1 << 32
        self.assertEqual(verdict(9, 0, 4096, read_write, private_anonymous), allow)
        for prot, flags in ((read_write | 0x4, private_anonymous), (read_write, 0x21), (read_write, 0x02),
                            (read_write, private_anonymous | 0x10), (read_write | high, private_anonymous),
                            (read_write, private_anonymous | high)):
            with self.subTest(mmap=(hex(prot), hex(flags))):
                self.assertEqual(verdict(9, 0, 4096, prot, flags), kill)
        self.assertEqual(verdict(10, 0, 4096, 0x1), allow)
        for prot in (0x5, 0x4, 0x1 | high):
            with self.subTest(mprotect=hex(prot)):
                self.assertEqual(verdict(10, 0, 4096, prot), kill)
        seqpacket_cloexec = 5 | 0o2000000
        self.assertEqual(verdict(41, 1, seqpacket_cloexec, 0), allow)
        for domain, kind in ((2, seqpacket_cloexec), (1, 1 | 0o2000000), (1, 5), (1 | high, seqpacket_cloexec),
                             (1, seqpacket_cloexec | high)):
            with self.subTest(socket=(hex(domain), hex(kind))):
                self.assertEqual(verdict(41, domain, kind, 0), kill)
        self.assertEqual(verdict(0x40000000), kill)  # x32 read
        self.assertEqual(verdict(0, arch=0x40000003), kill)  # AUDIT_ARCH_I386

    def test_same_uid_attacks_work_on_a_copy_without_set_id(self):
        expected = {f"{prefix}.{key}": value for prefix in ("installed", "control")
                    for key, value in EXPERIMENT.WORKING_ATTACK.items()}
        self.assertEqual(self.attack("n1"), expected)

    def test_unprivileged_launch_paths_reach_the_socket_step(self):
        for case in ("n2", "n3", "n4"):
            with self.subTest(case=case):
                result = self.attack(case)
                self.assertEqual((result["ready"], result["effectiveGidElevated"], result["frontendExit"]),
                                 ("yes", "no", "socket-failure"))


if __name__ == "__main__":
    unittest.main()
