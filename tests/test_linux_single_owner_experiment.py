import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-linux-single-owner-experiment.py"
SPEC = importlib.util.spec_from_file_location("linux_single_owner_experiment", SCRIPT)
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)
DESIGN = SCRIPT.parents[1] / "docs/linux-single-owner-design.md"
EXPERIMENT_DOC = SCRIPT.parents[1] / "docs/experiments/linux-single-owner.md"

START = b'{"ownerCapabilitiesExact":"yes","generation":"yes","authorityAccepted":"yes"}'
DISPATCH = (b'{"dispatch":"1","admitted":"yes","permit":"yes","finalCheck":"yes","result":"dispatched",'
            b'"execErrno":"none","requesterLostAfterCheck":"no","goWritten":"yes","killedAtDeadline":"no",'
            b'"reported":"yes"}')
PROBE = (b'{"capPrm":"0000000000000000","capEff":"0000000000000000","capInh":"0000000000000000",'
         b'"capAmb":"0000000000000000","capBnd":"000001ffffffffff","noNewPrivs":"0","uid":"1000 1000 1000 1000",'
         b'"gid":"1000 1000 1000 1000","umask":"0027","nofileSoft":"777","sessionLeader":"yes","dumpable":"1"}\n')


def compiler():
    return shutil.which("cc") or shutil.which("gcc")


def full_observation(case, **changes):
    observed = {key: EXPERIMENT.NA if EXPERIMENT.NA in allowed else sorted(allowed)[0]
                for key, allowed in EXPERIMENT.OBSERVED.items()}
    observed.update({key: sorted(allowed)[0] for key, allowed in EXPERIMENT.CASES[case]["expect"].items()})
    observed.update(changes)
    return observed


@contextlib.contextmanager
def linux_root():
    with contextlib.ExitStack() as stack:
        for owner, name, value in ((EXPERIMENT.platform, "system", "Linux"),
                                   (EXPERIMENT.platform, "machine", "x86_64"),
                                   (EXPERIMENT.os, "geteuid", 0), (EXPERIMENT.os, "getuid", 0)):
            stack.enter_context(patch.object(owner, name, return_value=value))
        stack.enter_context(patch.object(EXPERIMENT.shutil, "which", return_value="/usr/bin/setpriv"))
        stack.enter_context(patch.object(EXPERIMENT.PL, "operator_account", return_value=object()))
        stack.enter_context(patch.object(EXPERIMENT.PL, "root_owned_ancestry", return_value=True))
        stack.enter_context(patch.object(EXPERIMENT.PL, "host_metadata", return_value={"os": "Linux"}))
        stack.enter_context(patch.object(EXPERIMENT.PL, "subreaper", contextlib.nullcontext))
        stack.enter_context(patch.object(EXPERIMENT, "last_capability", return_value=40))
        yield


class FakeRun:
    """Records the calls measure() makes; run_case raises on demand."""

    instances = []

    def __init__(self, operator, timeout, allow_sysctl, fail_in=None):
        self.allow_sysctl = allow_sysctl
        self.fail_in = fail_in
        self.calls = []
        FakeRun.instances.append(self)

    def setup(self):
        self.calls.append("setup")
        if self.fail_in == "setup":
            raise RuntimeError("setup failed")
        return {"serviceIdentityUnprivileged": True}

    def run_case(self, case, last_cap):
        self.calls.append(case)
        if self.fail_in == "case":
            raise RuntimeError("case runner failed")
        return {"passed": True}

    def cleanup(self):
        self.calls.append("cleanup")
        return {"filesRemoved": True, "serviceUserRemoved": True, "sysctlsRestored": True}


class SourceBuildTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux" and compiler(), "needs Linux and a C compiler")
    def test_every_fixture_build_compiles_with_warnings_as_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, (source, extra) in EXPERIMENT.BUILDS.items():
                for flags in ((), EXPERIMENT.FIXTURE_FLAGS[name]):
                    output = Path(directory) / name
                    result = subprocess.run([compiler(), *EXPERIMENT.CC_FLAGS, *extra, *flags, "-o", str(output),
                                             str(source)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, f"{name} {flags}: {result.stderr}")

    def test_compiler_flags_match_the_issue(self):
        self.assertEqual(EXPERIMENT.CC_FLAGS, ("-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"))

    def test_owner_keeps_the_designed_sequence(self):
        owner = EXPERIMENT.OWNER.read_text()
        for needle in ("PTRACE_O_EXITKILL", "PTRACE_O_TRACECLONE", "PTRACE_O_TRACEFORK", "PTRACE_O_TRACEVFORK",
                       "PTRACE_O_TRACEEXEC", "PTRACE_INTERRUPT", "SO_PEERPIDFD", "PR_CAP_AMBIENT_CLEAR_ALL",
                       "signal(SIGPIPE, SIG_IGN)", "setresuid(p->uid, p->uid, plan->owner_uid)",
                       "setresuid(p->uid, p->uid, p->uid)", "WEXITED | WNOHANG | WNOWAIT", "pidfd_send_signal",
                       "\"LANG=C\"", "own_threads() != 1", "/proc/sys/kernel/random/boot_id"):
            self.assertIn(needle, owner)
        # PR_SET_PDEATHSIG is cleared by the credential change, so the design does not use it.
        self.assertNotIn("PR_SET_PDEATHSIG", owner)
        # K clears dumpable twice: before the first credential change and after each one.
        self.assertGreaterEqual(owner.count("PR_SET_DUMPABLE, 0"), 3)
        # Every barrier the runner can name exists in O, and O names no other barrier.
        named = set(re.findall(r'barrier\("([a-z0-9-]+)"', owner))
        self.assertEqual(named, EXPERIMENT.BARRIERS)

    def test_reserved_exit_codes_match_the_runner(self):
        owner = EXPERIMENT.OWNER.read_text()
        codes = {int(value) for value in re.findall(r"#define K_[A-Z_]+ (12[0-9])", owner)}
        self.assertEqual(codes, {120, 121, 122, 123})
        self.assertIsNone(re.search(r"return 12[0-3]", EXPERIMENT.PROBE.read_text()))


class CaseTableTests(unittest.TestCase):
    def test_every_case_uses_the_closed_vocabulary(self):
        for case, spec in EXPERIMENT.CASES.items():
            self.assertIn(spec["mode"], EXPERIMENT.MODES, case)
            self.assertIn(spec["owner"], {"owner", "owner-thread", "owner-nocaps"}, case)
            for barrier, action in spec["actions"]:
                self.assertIn(barrier, EXPERIMENT.BARRIERS, case)
                self.assertIn(action, EXPERIMENT.ACTIONS, case)
            for key, allowed in spec["expect"].items():
                self.assertIn(key, EXPERIMENT.OBSERVED, case)
                self.assertLessEqual(allowed, EXPERIMENT.OBSERVED[key], case)

    def test_only_the_attach_case_needs_a_sysctl(self):
        self.assertEqual({case for case, spec in EXPERIMENT.CASES.items() if spec["sysctl"]},
                         {"caller-attaches-to-k"})
        self.assertTrue(EXPERIMENT.CASES["caller-attaches-to-k"]["rootOnly"])

    def test_sigcont_replaces_the_fork_row(self):
        design = DESIGN.read_text()
        self.assertFalse("C forks or execs during S2–S4" in design)
        self.assertIn("`SIGCONT` from the caller's account to C during the stop", design)
        spec = EXPERIMENT.CASES["caller-sigcont-c-during-stop"]
        self.assertEqual({action for _barrier, action in spec["actions"]}, {"caller-cont-c"})
        self.assertEqual(spec["expect"]["result"], {"dispatched"})

    def test_every_case_is_documented(self):
        text = EXPERIMENT_DOC.read_text()
        for case in EXPERIMENT.CASES:
            self.assertTrue(f"`{case}`" in text, case)


class ReportTests(unittest.TestCase):
    def test_owner_lines_accept_exact_reports_only(self):
        start, dispatch = EXPERIMENT.owner_lines(START + b"\n" + DISPATCH + b"\n")
        self.assertEqual(start["generation"], "yes")
        self.assertEqual(dispatch["result"], "dispatched")
        self.assertNotIn("dispatch", dispatch)
        for raw in (b"", START + b"\n" + DISPATCH + b"\n" + DISPATCH,
                    START.replace(b'"yes"}', b'"maybe"}'),
                    START.replace(b"}", b',"pid":"1234"}'),
                    START.replace(b'"generation":"yes"', b'"generation":1'),
                    START.replace(b'"generation":"yes"', b'"generation":"yes","generation":"yes"'),
                    START + b"\n" + DISPATCH.replace(b'"dispatched"', b'"/home/someone"'),
                    b"x" * (EXPERIMENT.MAX_OUTPUT_BYTES + 1)):
            with self.assertRaises(ValueError, msg=raw[:80]):
                EXPERIMENT.owner_lines(raw)

    def test_probe_checks_publish_booleans_only(self):
        checks = EXPERIMENT.probe_checks(PROBE, 1000, 1000, 40)
        self.assertEqual(checks, {**EXPERIMENT.PROBE_OK, "boundingFull": "yes", "commandDumpable": "1"})
        changed = PROBE.replace(b'"capAmb":"0000000000000000"', b'"capAmb":"0000000000200000"')
        self.assertEqual(EXPERIMENT.probe_checks(changed, 1000, 1000, 40)["capsEmpty"], "no")
        self.assertEqual(EXPERIMENT.probe_checks(PROBE, 1001, 1000, 40)["uidsExact"], "no")
        self.assertEqual(EXPERIMENT.probe_checks(PROBE.replace(b'"0027"', b'"0022"'), 1000, 1000, 40)
                         ["umaskInherited"], "no")
        self.assertEqual(set(EXPERIMENT.probe_checks(b"", 1000, 1000, 40).values()), {"not-reported"})
        for raw in (PROBE + PROBE, PROBE.replace(b'"capPrm":"0000000000000000"', b'"capPrm":"zz"'),
                    PROBE.replace(b'"dumpable":"1"', b'"dumpable":"7"')):
            with self.assertRaises(ValueError):
                EXPERIMENT.probe_checks(raw, 1000, 1000, 40)

    def test_restart_log_allows_no_restart_before_the_go_byte(self):
        clean = EXPERIMENT.restart_log_clean
        self.assertEqual(clean(b"1 1 SEIZE\n2 1 INTERRUPT\n3 1 GO\n4 1 DETACH\n"), "yes")
        self.assertEqual(clean(b"1 1 SEIZE\n2 1 INTERRUPT\n3 1 GO\n"), "yes")
        self.assertEqual(clean(b"1 1 SEIZE\n2 1 INTERRUPT\n"), "yes")
        self.assertEqual(clean(b"1 1 SEIZE\n2 1 INTERRUPT\n3 1 DETACH\n"), "yes")
        for raw in (b"1 1 SEIZE\n2 1 INTERRUPT\n3 1 DETACH\n4 1 GO\n", b"1 1 SEIZE\n2 1 GO\n",
                    b"1 1 SEIZE\n2 1 INTERRUPT\n3 1 CONT\n4 1 GO\n", b"1 1 SEIZE\n2 1 INTERRUPT\n3 1 GO\n4 1 GO\n",
                    b"1 2 SEIZE\n2 2 INTERRUPT\n"):
            self.assertEqual(clean(raw), "no", raw)

    def test_evaluate_rejects_values_outside_the_vocabulary(self):
        result = EXPERIMENT.evaluate("dispatch-normal", full_observation("dispatch-normal"))
        self.assertTrue(result["passed"], result)
        self.assertEqual(EXPERIMENT.evaluate("dispatch-normal", full_observation("dispatch-normal", result="refused"))
                         ["mismatches"], ["result"])
        for changes in ({"markerLines": "2"}, {"result": "/tmp/x"}, {"extra": "yes"}):
            observed = full_observation("dispatch-normal")
            observed.update(changes)
            self.assertEqual(EXPERIMENT.evaluate("dispatch-normal", observed),
                             {"passed": False, "error_type": "InvalidObservation"})
        observed = full_observation("dispatch-normal")
        del observed["result"]
        self.assertFalse(EXPERIMENT.evaluate("dispatch-normal", observed)["passed"])

    def test_dumpable_and_bounding_set_are_observed_not_required(self):
        result = EXPERIMENT.evaluate("dispatch-normal", full_observation("dispatch-normal", commandDumpable="0",
                                                                        boundingFull="no"))
        self.assertTrue(result["passed"])


@unittest.skipUnless(platform.system() == "Linux" and hasattr(os, "pidfd_open"), "needs Linux pidfds")
class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.record = Path(self.directory.name) / "authority"
        self.authority = EXPERIMENT.Authority(self.record, (1000, 1000, [1000, 27]), "normal")
        self.pidfd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, self.pidfd)
        start = EXPERIMENT._start_time(os.getpid())
        self.hello = f"HELLO {EXPERIMENT._boot_id()} {os.getpid()} {start} {'a' * 32}".encode()

    def test_one_use_permit_bound_to_the_generation(self):
        self.assertEqual(self.authority.handle(1, self.hello, self.pidfd), b"OK")
        permit = self.authority.handle(1, b"SUBMIT " + b"b" * 32 + b" 77", self.pidfd).decode().split()
        self.assertEqual(permit[0], "PERMIT")
        self.assertEqual(permit[2:], ["1000", "1000", "normal", "2", "1000", "27"])
        token = permit[1].encode()
        # A second permit is never issued in one case, and another connection cannot report.
        self.assertEqual(self.authority.handle(1, b"SUBMIT " + b"c" * 32 + b" 77", self.pidfd), b"REFUSED")
        self.assertEqual(self.authority.handle(2, b"OUTCOME " + token + b" dispatched no", self.pidfd), b"REFUSED")
        self.assertEqual(self.authority.handle(1, b"OUTCOME " + token + b" dispatched no", self.pidfd), b"OK")
        self.assertEqual(self.authority.handle(1, b"OUTCOME " + token + b" dispatched no", self.pidfd), b"REFUSED")
        self.assertEqual(self.authority.outcome, "refused-replay")
        lines = self.record.read_text().splitlines()
        self.assertEqual([line.split()[0] for line in lines], ["beginDispatch", "outcome"])

    def test_hello_refused_when_the_pidfd_does_not_match_the_generation(self):
        wrong_pid = self.hello.replace(f" {os.getpid()} ".encode(), b" 1 ")
        self.assertEqual(self.authority.handle(1, wrong_pid, self.pidfd), b"REFUSED")
        parts = self.hello.split(b" ")
        parts[3] = str(int(parts[3]) + 1).encode()
        self.assertEqual(self.authority.handle(1, b" ".join(parts), self.pidfd), b"REFUSED")
        self.assertEqual(self.authority.handle(1, self.hello.replace(b"a" * 32, b"z" * 32), self.pidfd), b"REFUSED")
        self.assertEqual(self.authority.handle(1, self.hello, None), b"REFUSED")
        self.assertEqual(self.authority.handle(1, b"SUBMIT " + b"b" * 32 + b" 77", self.pidfd), b"REFUSED")

    def test_hello_refused_for_an_exited_process(self):
        child = subprocess.Popen(["/bin/true"])
        pidfd = os.pidfd_open(child.pid)
        try:
            child.wait()
            start_line = f"HELLO {EXPERIMENT._boot_id()} {child.pid} 1 {'a' * 32}".encode()
            self.assertEqual(self.authority.handle(1, start_line, pidfd), b"REFUSED")
        finally:
            os.close(pidfd)


class MeasureTests(unittest.TestCase):
    def setUp(self):
        FakeRun.instances = []

    def test_refuses_without_root(self):
        with patch.object(EXPERIMENT.platform, "system", return_value="Linux"), \
             patch.object(EXPERIMENT.platform, "machine", return_value="x86_64"), \
             patch.object(EXPERIMENT.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "requires root"):
                EXPERIMENT.measure()

    def test_report_keeps_admission_false_and_the_sysctl_case_off_by_default(self):
        with linux_root():
            report = EXPERIMENT.measure(run_factory=FakeRun)
        self.assertFalse(report["strictAdmission"])
        self.assertFalse(report["productionAdmission"])
        self.assertEqual(report["sysctlCase"], "not-run")
        self.assertFalse(FakeRun.instances[0].allow_sysctl)
        self.assertEqual(FakeRun.instances[0].calls, ["setup", *EXPERIMENT.CASES, "cleanup"])
        self.assertTrue(report["passed"])

    def test_cleanup_runs_when_the_case_runner_raises(self):
        factory = lambda *arguments: FakeRun(*arguments, fail_in="case")
        with linux_root(), self.assertRaisesRegex(RuntimeError, "case runner failed"):
            EXPERIMENT.measure(run_factory=factory)
        self.assertEqual(FakeRun.instances[0].calls, ["setup", next(iter(EXPERIMENT.CASES)), "cleanup"])

    def test_cleanup_runs_when_setup_raises(self):
        factory = lambda *arguments: FakeRun(*arguments, fail_in="setup")
        with linux_root(), self.assertRaisesRegex(RuntimeError, "setup failed"):
            EXPERIMENT.measure(run_factory=factory)
        self.assertEqual(FakeRun.instances[0].calls, ["setup", "cleanup"])

    def test_attach_case_is_not_run_and_no_sysctl_is_written_without_the_flag(self):
        run = EXPERIMENT.Run.__new__(EXPERIMENT.Run)
        run.allow_sysctl, run.saved_sysctls = False, {}
        with patch.object(EXPERIMENT.Run, "enable_attach_sysctls", side_effect=AssertionError("sysctl written")):
            self.assertEqual(run.run_case("caller-attaches-to-k", 40), {"passed": True, "status": "not-run"})

    def test_sysctls_are_restored_when_the_attach_case_raises(self):
        run = EXPERIMENT.Run.__new__(EXPERIMENT.Run)
        run.allow_sysctl, run.saved_sysctls, run.timeout = True, {}, 5
        run.paths, run.operator, run.groups = {}, type("A", (), {"pw_uid": 1, "pw_gid": 1})(), []
        restored = []
        with patch.object(EXPERIMENT.Run, "enable_attach_sysctls"), \
             patch.object(EXPERIMENT.Run, "restore_sysctls", side_effect=lambda: restored.append(1) or True), \
             patch.object(EXPERIMENT, "drive_case", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                run.run_case("caller-attaches-to-k", 40)
        self.assertEqual(restored, [1])

    def test_main_publishes_no_raw_error(self):
        stderr = io.StringIO()
        with patch.object(EXPERIMENT, "measure", side_effect=RuntimeError("/home/someone secret")), \
             patch("sys.argv", ["runner"]), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                EXPERIMENT.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertNotIn("someone", stderr.getvalue())


LINUX = platform.system() == "Linux"


def gone(pid):
    """True when pid no longer runs (absent, or a zombie that someone else must reap)."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return True
    return text[text.rindex(")") + 2] in "ZX"


def processes_mentioning(text):
    found = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                if text.encode() in (entry / "cmdline").read_bytes():
                    found.append(int(entry.name))
            except OSError:
                pass
    return found


@unittest.skipUnless(LINUX, "needs Linux procfs")
class ProcessHelperTests(unittest.TestCase):
    def test_reap_waits_for_a_child_that_exits_after_the_first_poll(self):
        child = subprocess.Popen(["sh", "-c", "sleep 0.3"])
        started = time.monotonic()
        self.assertTrue(EXPERIMENT._reap(child.pid, started + 5))
        self.assertGreaterEqual(time.monotonic() - started, 0.2)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)
        child.wait()  # already reaped: lets Popen record it

    def test_reap_reports_a_child_that_outlives_the_deadline(self):
        child = subprocess.Popen(["sleep", "30"])
        try:
            self.assertFalse(EXPERIMENT._reap(child.pid, time.monotonic() + 0.1))
        finally:
            child.kill()
            child.wait()

    def test_retire_all_reaps_a_k_that_exits_late(self):
        # Not a session leader, so _end_session leaves it alone and only the poll can reap it.
        k = subprocess.Popen(["sh", "-c", "sleep 0.3"])
        self.assertTrue(EXPERIMENT._retire_all(None, None, {"c": 0, "k": k.pid}, []))
        with self.assertRaises(ChildProcessError):
            os.waitpid(k.pid, os.WNOHANG)
        k.wait()

    def test_retire_all_kills_live_processes_and_the_command_session(self):
        owner = subprocess.Popen(["sleep", "30"], stdout=subprocess.PIPE, start_new_session=True)
        frontend = subprocess.Popen(["sleep", "30"], stdout=subprocess.PIPE, start_new_session=True)
        k = subprocess.Popen(["sh", "-c", "sleep 30 & exec sleep 30"], start_new_session=True)
        time.sleep(0.1)
        members = EXPERIMENT._session_members(k.pid)
        self.assertGreaterEqual(len(members), 2)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.assertTrue(EXPERIMENT._retire_all(owner, frontend, {"c": 0, "k": k.pid}, [listener]))
        self.assertIsNotNone(owner.returncode)
        self.assertIsNotNone(frontend.returncode)
        self.assertEqual(listener.fileno(), -1)
        deadline = time.monotonic() + 3
        while not all(gone(pid) for pid in members) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(all(gone(pid) for pid in members))
        k.wait()

    def test_end_session_kills_every_member(self):
        leader = subprocess.Popen(["sh", "-c", "sleep 30 & exec sleep 30"], start_new_session=True)
        time.sleep(0.1)
        members = EXPERIMENT._session_members(leader.pid)
        EXPERIMENT._end_session(leader.pid)
        leader.wait(timeout=3)
        deadline = time.monotonic() + 3
        while not all(gone(pid) for pid in members) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(all(gone(pid) for pid in members))
        EXPERIMENT._end_session(0)  # no K: nothing to do

    def test_reap_k_categories(self):
        deadline = lambda: time.monotonic() + 3
        for command, expected in ((["sh", "-c", "exit 121"], "reserved"), (["sh", "-c", "exit 3"], "other")):
            child = subprocess.Popen(command)
            self.assertEqual(EXPERIMENT._reap_k(child.pid, deadline()), expected)
            child.wait()
        child = subprocess.Popen(["sleep", "30"])
        child.kill()
        self.assertEqual(EXPERIMENT._reap_k(child.pid, deadline()), "signaled")
        child.wait()
        self.assertEqual(EXPERIMENT._reap_k(os.getppid(), deadline()), "not-observed")
        child = subprocess.Popen(["sleep", "30"])
        try:
            self.assertEqual(EXPERIMENT._reap_k(child.pid, time.monotonic() + 0.05), "running")
        finally:
            child.kill()
            child.wait()


class KillUserTests(unittest.TestCase):
    def test_matches_real_effective_or_saved_uid_from_status(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            for pid, uids in (("101", "1000 1000 4242 1000"), ("102", "4242 0 0 0"), ("103", "1000 1000 1000 1000"),
                              ("104", "1000 4242 1000 1000")):
                (proc / pid).mkdir()
                (proc / pid / "status").write_text(f"Name:\towner\nUid:\t{uids.replace(' ', chr(9))}\n")
            (proc / "105").mkdir()  # exited: no status file
            (proc / "self").mkdir()
            with patch.object(EXPERIMENT.os, "kill") as kill:
                EXPERIMENT._kill_user(4242, proc)
        self.assertEqual(sorted(call.args for call in kill.call_args_list),
                         [(101, signal.SIGKILL), (102, signal.SIGKILL), (104, signal.SIGKILL)])

    def test_cleanup_kills_the_service_user_then_removes_files_and_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            run = EXPERIMENT.Run.__new__(EXPERIMENT.Run)
            run.base = Path(directory) / "base"
            run.base.mkdir()
            run.base_created = run.service_created = True
            run.service_name, run.saved_sysctls, run.timeout = "rmzsotest", {}, 5
            removed = []
            def getpwnam(name):
                if "userdel" in removed:
                    raise KeyError(name)
                return SimpleNamespace(pw_uid=4242)
            def run_owned(arguments, _timeout):
                removed.append(arguments[0])
                return 0, b""
            with patch.object(EXPERIMENT.pwd, "getpwnam", side_effect=getpwnam), \
                 patch.object(EXPERIMENT.grp, "getgrnam", side_effect=KeyError("absent")), \
                 patch.object(EXPERIMENT.PL, "run_owned", side_effect=run_owned), \
                 patch.object(EXPERIMENT, "_kill_user") as kill_user:
                result = run.cleanup()
            kill_user.assert_called_once_with(4242)
            self.assertEqual(removed, ["userdel"])
            self.assertEqual(result, {"filesRemoved": True, "serviceUserRemoved": True, "sysctlsRestored": True})


class SetupLimitTests(unittest.TestCase):
    def test_group_bound_matches_the_owner(self):
        owner = EXPERIMENT.OWNER.read_text()
        self.assertEqual(int(re.search(r"#define MAX_GROUPS ([0-9]+)", owner)[1]), EXPERIMENT.MAX_GROUPS)

    def test_setup_refuses_too_many_groups_before_it_changes_anything(self):
        with tempfile.TemporaryDirectory() as directory:
            run = EXPERIMENT.Run.__new__(EXPERIMENT.Run)
            run.operator = SimpleNamespace(pw_name="operator", pw_gid=1000, pw_uid=1000)
            run.base = Path(directory) / "base"
            stderr = io.StringIO()
            with patch.object(EXPERIMENT.os, "getgrouplist", return_value=list(range(1000, 1065))), \
                 contextlib.redirect_stderr(stderr), self.assertRaisesRegex(RuntimeError, "too many"):
                run.setup()
            self.assertFalse(run.base.exists())
            self.assertIn("65 groups", stderr.getvalue())

    @unittest.skipUnless(LINUX, "needs Linux")
    def test_frontend_socket_is_group_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "s.sock"
            listener = EXPERIMENT.Host().listener(path)
            try:
                self.assertEqual(path.stat().st_mode & 0o777, 0o660)
            finally:
                listener.close()


class ScriptedHost(EXPERIMENT.Host):
    """An "owner" that is a small Python script: it never answers, prints garbage, or misbehaves."""

    def __init__(self, script):
        self.script = script
        self.started = []

    def start_owner(self, binary, arguments, pass_fds):
        process = subprocess.Popen([sys.executable, "-I", "-c", self.script, *arguments], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=pass_fds,
                                   start_new_session=True)
        self.started.append(process)
        return process


@unittest.skipUnless(LINUX, "needs Linux procfs")
class DriveCaseFailureTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        base = Path(directory.name)
        for name in ("cases", "markers"):
            (base / name).mkdir()
        self.paths = {"cases": base / "cases", "markers": base / "markers", "probe": base / "probe"}

    def drive(self, script, timeout=1):
        host = ScriptedHost(script)
        result = EXPERIMENT.drive_case("dispatch-normal", host, self.paths, (1000, 1000, []), timeout, 40)
        self.assertTrue(result["cleanupReapedAllFixtureProcesses"], result)
        self.assertTrue(all(process.returncode is not None for process in host.started))
        return result

    def test_an_owner_that_never_answers_times_out_and_is_killed(self):
        result = self.drive("import time; time.sleep(30)")
        self.assertEqual(result, {"passed": False, "error_type": "TimeoutError",
                                  "cleanupReapedAllFixtureProcesses": True})

    def test_an_owner_that_prints_garbage_is_an_invalid_report(self):
        result = self.drive("print('garbage /home/someone 1234')")
        self.assertEqual(result["error_type"], "InvalidReport")
        self.assertNotIn("observed", result)

    def test_an_owner_with_a_bad_barrier_is_a_case_failure(self):
        script = ("import socket, sys, time\n"
                  "control = socket.socket(fileno=int(sys.argv[3]))\n"
                  "control.send(b'BARRIER bogus 0 0 0')\n"
                  "time.sleep(30)\n")
        self.assertEqual(self.drive(script)["error_type"], "CaseFailure")


def fixture_ready():
    if platform.system() != "Linux" or platform.machine() != "x86_64" or not compiler():
        return False
    try:
        scope = int(Path("/proc/sys/kernel/yama/ptrace_scope").read_text())
    except (OSError, ValueError):
        scope = 0
    if scope > 1 or not hasattr(os, "pidfd_open"):
        return False
    first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        os.close(first.getsockopt(socket.SOL_SOCKET, 77))  # SO_PEERPIDFD, Linux 6.5 and later
    except OSError:
        return False
    finally:
        first.close()
        second.close()
    return True


class FixtureHost(EXPERIMENT.Host):
    """Unprivileged builds: O and C run as the test's own account."""

    def __init__(self, binaries):
        self.binaries = binaries

    def start_owner(self, binary, arguments, pass_fds):
        return subprocess.Popen([str(self.binaries[binary]), *arguments], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=pass_fds,
                                start_new_session=True)

    def start_frontend(self, socket_path):
        return subprocess.Popen([str(self.binaries["frontend"]), str(socket_path)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)

    def caller_signal(self, name, pid):
        os.kill(pid, getattr(signal, f"SIG{name}"))
        return True


@unittest.skipUnless(fixture_ready(), "needs Linux x86_64, a C compiler and Yama ptrace_scope at most 1")
class FixtureCaseTests(unittest.TestCase):
    """Every case that needs no root, end to end, with the unprivileged fixture builds.

    This proves the protocol, the barriers and the evaluation. It does not measure the design:
    the root run does, with the service identity and the three capabilities."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        base = Path(cls.directory.name)
        cls.binaries = {}
        for name, (source, extra) in EXPERIMENT.BUILDS.items():
            output = base / name
            subprocess.run([compiler(), *EXPERIMENT.CC_FLAGS, *extra, *EXPERIMENT.FIXTURE_FLAGS[name], "-o",
                            str(output), str(source)], check=True, capture_output=True)
            cls.binaries[name] = output
        for name in ("cases", "markers"):
            (base / name).mkdir()
        cls.paths = {"cases": base / "cases", "markers": base / "markers", "probe": cls.binaries["probe"]}

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_cases_without_root(self):
        identity = (os.getuid(), os.getgid(), os.getgroups())
        last_cap = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
        with EXPERIMENT.PL.subreaper():
            for case, spec in EXPERIMENT.CASES.items():
                if spec["rootOnly"]:
                    continue
                with self.subTest(case=case):
                    result = EXPERIMENT.drive_case(case, FixtureHost(self.binaries), self.paths, identity, 15,
                                                   last_cap)
                    self.assertTrue(result["passed"], json.dumps(result, sort_keys=True))
                    self.assertTrue(result["cleanupReapedAllFixtureProcesses"])

    def test_cancel_during_a_running_command_leaves_no_process(self):
        """A KeyboardInterrupt while the command sleeps still kills O, C, K and the command."""

        class CancellingHost(FixtureHost):
            def caller_signal(self, name, pid):
                raise KeyboardInterrupt()

        case = "cancel-during-command"
        spec = EXPERIMENT._case("sleep", [("after-s6", "caller-cont-c")])
        identity = (os.getuid(), os.getgid(), os.getgroups())
        with patch.dict(EXPERIMENT.CASES, {case: spec}), EXPERIMENT.PL.subreaper():
            with self.assertRaises(KeyboardInterrupt):
                EXPERIMENT.drive_case(case, CancellingHost(self.binaries), self.paths, identity, 15, 40)
        self.assertEqual((self.paths["markers"] / case).read_text(), "ran\n")  # the command did run
        self.assertEqual(processes_mentioning(str(self.paths["markers"] / case)), [])
        self.assertEqual(processes_mentioning(str(self.paths["cases"] / case)), [])

    def test_runner_loss_cases_ran(self):
        self.assertIn("runner-lost-before-go", EXPERIMENT.CASES)
        self.assertIn("drop-runner", EXPERIMENT.ACTIONS)


if __name__ == "__main__":
    unittest.main()
