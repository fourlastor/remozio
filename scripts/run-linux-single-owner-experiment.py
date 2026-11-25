#!/usr/bin/env python3
"""Supervised single-owner controls (issue #988, PR1): one owner process O holds the caller's
ptrace stop and starts the command through a prepared child K. A measurement with a stub
authority, not a production admission path. See docs/linux-single-owner-design.md.

Run once as root through sudo from the operator's session. The runner creates a disposable
service user, starts O as that user with CAP_SYS_PTRACE, CAP_SETUID and CAP_SETGID in its
ambient set (as AmbientCapabilities= would), drives every PR1 case through O's named pause
points, then removes all of it. It changes no sysctl unless --allow-sysctl is given; that flag
saves fs.suid_dumpable and kernel.yama.ptrace_scope, sets them for the attach case, and restores
them. The report holds booleans, errno names, categories, settings and hashes only."""
import argparse
import contextlib
import datetime
import grp
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "experiments/linux-single-owner"
OWNER, FRONTEND, PROBE = (FIXTURES / name for name in ("owner.c", "frontend.c", "probe.c"))
PROTECTED_RUNNER = ROOT / "scripts/run-linux-protected-launch-experiment.py"
# The #728 runner gives the owned-process, account, host and cancel helpers. Loading it also
# loads run-linux-caller-experiment.py (its own import). Nothing here calls either measure().
_spec = importlib.util.spec_from_file_location("remozio_protected_launch_runner", PROTECTED_RUNNER)
PL = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(PL)

BASE_PARENT = Path("/var/lib")
BASE_PREFIX = "remozio-single-owner-experiment-"
CC_FLAGS = PL.CC_FLAGS
OWNER_CAPS = "+sys_ptrace,+setuid,+setgid"
MAX_OUTPUT_BYTES = 16384
# owner.c MAX_GROUPS: the permit carries at most this many supplementary groups.
MAX_GROUPS = 64
DEADLINE_MS = 2000
SYSCTLS = {"suidDumpable": Path("/proc/sys/fs/suid_dumpable"),
           "ptraceScope": Path("/proc/sys/kernel/yama/ptrace_scope")}
# The attach case runs with the most permissive values: Yama off and set-ID dumps allowed.
ATTACH_SYSCTLS = {"suidDumpable": "1", "ptraceScope": "0"}

# Builds: (source, extra flags). The fixture flags make an unprivileged build for the tests.
BUILDS = {"owner": (OWNER, ()), "owner-thread": (OWNER, ("-DRMZSO_TEST_THREAD", "-pthread")),
          "frontend": (FRONTEND, ()), "probe": (PROBE, ())}
FIXTURE_FLAGS = {"owner": ("-DRMZSO_FIXTURE_UNPRIVILEGED",), "owner-thread": ("-DRMZSO_FIXTURE_UNPRIVILEGED",),
                 "frontend": ("-DRMZSO_FIXTURE_PTRACER",), "probe": ()}

YES_NO = frozenset({"yes", "no"})
NA = "n/a"
RESULTS = frozenset({"dispatched", "execFailed", "unknown", "notStarted", "refused", "ownerThreads"})
ERRNO = frozenset({"none", "ok", "EPERM", "EACCES", "ENOENT", "ENOEXEC", "ESRCH", "EINVAL", "other"})
# The owner's reports: the start line, then one line per dispatch, in this vocabulary.
OWNER_START_KEYS = {"ownerCapabilitiesExact": YES_NO, "generation": YES_NO, "authorityAccepted": YES_NO}
OWNER_DISPATCH_KEYS = {"dispatch": frozenset({"1"}), "admitted": YES_NO, "permit": YES_NO, "finalCheck": YES_NO,
                       "result": RESULTS, "execErrno": ERRNO, "requesterLostAfterCheck": YES_NO,
                       "goWritten": YES_NO, "killedAtDeadline": YES_NO, "reported": YES_NO}
# Every case publishes exactly these keys; NA where the case does not reach the step.
OBSERVED = {
    **{key: values | {NA} for key, values in OWNER_START_KEYS.items()},
    **{key: values | {NA} for key, values in OWNER_DISPATCH_KEYS.items() if key != "dispatch"},
    "ownerExit": frozenset({"ok", "refused", "usage", "SIGKILL", "other", "running"}),
    "frontendExit": frozenset({"closed", "SIGKILL", "other", "not-started", "running"}),
    "markerLines": frozenset({"0", "1", "more"}),
    "authorityBegin": YES_NO, "authorityOutcome": RESULTS | {"missing", "refused-replay"},
    "restartLogClean": YES_NO | {NA}, "restartLogDetach": YES_NO | {NA},
    "kExit": frozenset({"reserved", "signaled", "other", "running", "not-observed"}),
    "commandAliveAfterOwner": YES_NO | {NA},
    "callerSignal": frozenset({"sent", "failed", NA}),
    "attachBeforeGo": ERRNO | {"not-run", NA}, "attachAfterGo": ERRNO | {"not-run", NA},
    **{key: YES_NO | {"not-reported"} for key in (
        "capsEmpty", "boundingFull", "noNewPrivsClear", "uidsExact", "gidsExact", "umaskInherited",
        "nofileInherited", "sessionLeader")},
    "commandDumpable": frozenset({"0", "1", "not-reported"}),
}
# Recorded, never required.
OBSERVED_ONLY = frozenset({"commandDumpable", "boundingFull"})
PROBE_KEYS = ("capPrm", "capEff", "capInh", "capAmb", "capBnd", "noNewPrivs", "uid", "gid", "umask",
              "nofileSoft", "sessionLeader", "dumpable")
# The frontend fixture sets these before it connects; the command must inherit them.
FIXTURE_UMASK, FIXTURE_NOFILE = "0027", "777"

PROBE_OK = {"capsEmpty": "yes", "noNewPrivsClear": "yes", "uidsExact": "yes", "gidsExact": "yes",
            "umaskInherited": "yes", "nofileInherited": "yes", "sessionLeader": "yes"}
STARTED = {"ownerCapabilitiesExact": "yes", "generation": "yes", "authorityAccepted": "yes"}
ADMITTED = {**STARTED, "admitted": "yes", "permit": "yes", "finalCheck": "yes", "restartLogClean": "yes",
            "authorityBegin": "yes"}
DISPATCHED = {**ADMITTED, "result": "dispatched", "goWritten": "yes", "requesterLostAfterCheck": "no",
              "killedAtDeadline": "no", "reported": "yes", "authorityOutcome": "dispatched", "markerLines": "1",
              "ownerExit": "ok", "frontendExit": "closed"}
NOT_STARTED = {**ADMITTED, "result": "notStarted", "goWritten": "no", "reported": "yes",
               "authorityOutcome": "notStarted", "markerLines": "0", "ownerExit": "ok", "frontendExit": "closed"}
UNKNOWN = {**ADMITTED, "result": "unknown", "goWritten": "yes", "reported": "yes", "authorityOutcome": "unknown",
           "markerLines": "0", "ownerExit": "ok", "frontendExit": "closed"}
# O dies: C dies with it (PTRACE_O_EXITKILL) and the authority never gets an outcome.
OWNER_KILLED = {**STARTED, "ownerExit": "SIGKILL", "frontendExit": "SIGKILL", "authorityOutcome": "missing",
                "restartLogClean": "yes"}


def _case(mode="normal", actions=(), expect=None, owner="owner", root_only=False, sysctl=False):
    """actions: (barrier, action) pairs that R performs while O waits at that barrier."""
    return {"mode": mode, "actions": tuple(actions), "owner": owner, "rootOnly": root_only, "sysctl": sysctl,
            "expect": {key: frozenset(value if isinstance(value, tuple) else (value,))
                       for key, value in (expect or {}).items()}}


CASES = {
    "dispatch-normal": _case(expect={**DISPATCHED, **PROBE_OK}),
    "dispatch-short-command": _case("short", expect=DISPATCHED),
    "dispatch-command-alive-at-s6": _case("sleep", expect={**DISPATCHED, **PROBE_OK}),
    "exec-fails": _case("missing", expect={**DISPATCHED, "result": "execFailed", "execErrno": "ENOENT",
                                           "authorityOutcome": "execFailed", "markerLines": "0"}),
    "k-hangs-before-go": _case("khang", expect={**NOT_STARTED, "killedAtDeadline": "yes"}),
    "kill-k-before-go": _case(actions=[("k-ready", "kill-k")], expect=NOT_STARTED),
    "caller-sigstop-k-before-go": _case(actions=[("k-ready", "caller-stop-k")],
                                        expect={**NOT_STARTED, "killedAtDeadline": "yes", "callerSignal": "sent"}),
    "caller-sigterm-k-before-go": _case(actions=[("k-ready", "caller-term-k")],
                                        expect={**NOT_STARTED, "callerSignal": "sent"}),
    "caller-sigusr1-k-before-go": _case(actions=[("k-ready", "caller-usr1-k")],
                                        expect={**NOT_STARTED, "callerSignal": "sent"}),
    "kill-k-after-go": _case("kpause", [("k-paused", "kill-k")], UNKNOWN),
    "caller-sigstop-k-after-go": _case("kpause", [("k-paused", "caller-stop-k")],
                                       {**UNKNOWN, "callerSignal": "sent"}),
    "caller-sigterm-k-after-go": _case("kpause", [("k-paused", "caller-term-k")],
                                       {**UNKNOWN, "callerSignal": "sent"}),
    "caller-sigusr1-k-after-go": _case("kpause", [("k-paused", "caller-usr1-k")],
                                       {**UNKNOWN, "callerSignal": "sent"}),
    # The row that replaces "C forks or execs during S2-S4": C cannot run in the stop, so it
    # cannot fork; a SIGCONT from the caller's account must not end the stop either.
    "caller-sigcont-c-during-stop": _case(actions=[("s1", "caller-cont-c"), ("before-go", "caller-cont-c")],
                                          expect={**DISPATCHED, "callerSignal": "sent"}),
    "caller-kills-c-before-check": _case(actions=[("before-go", "caller-kill-c")],
                                         expect={**ADMITTED, "result": "refused", "goWritten": "no",
                                                 "requesterLostAfterCheck": "yes", "reported": "yes",
                                                 "authorityOutcome": "refused", "markerLines": "0",
                                                 "ownerExit": "ok", "frontendExit": "SIGKILL",
                                                 "callerSignal": "sent"}),
    "caller-kills-c-after-check": _case(actions=[("after-check", "caller-kill-c")],
                                        expect={**DISPATCHED, "requesterLostAfterCheck": "yes",
                                                "frontendExit": "SIGKILL", "callerSignal": "sent"}),
    "caller-kills-c-after-go": _case(actions=[("after-go", "caller-kill-c")],
                                     expect={**DISPATCHED, "requesterLostAfterCheck": "yes",
                                             "frontendExit": "SIGKILL", "callerSignal": "sent"}),
    "kill-owner-at-s1": _case(actions=[("s1", "kill-owner")],
                              expect={**OWNER_KILLED, "authorityBegin": "yes", "markerLines": "0"}),
    "kill-owner-after-fork": _case(actions=[("after-fork", "kill-owner")],
                                   expect={**OWNER_KILLED, "authorityBegin": "yes", "markerLines": "0",
                                           "kExit": ("reserved", "signaled")}),
    "kill-owner-before-go": _case(actions=[("before-go", "kill-owner")],
                                  expect={**OWNER_KILLED, "authorityBegin": "yes", "markerLines": "0",
                                          "kExit": "reserved"}),
    "kill-owner-after-go": _case(actions=[("after-go", "kill-owner")],
                                 expect={**OWNER_KILLED, "authorityBegin": "yes", "markerLines": ("0", "1")}),
    "kill-owner-after-s6": _case("sleep", [("after-s6", "kill-owner")],
                                 {**OWNER_KILLED, "authorityBegin": "yes", "authorityOutcome": "dispatched",
                                  "markerLines": "1", "commandAliveAfterOwner": "yes"}),
    "kill-authority-after-s1": _case(actions=[("s1", "kill-authority")],
                                     expect={**ADMITTED, "result": "dispatched", "goWritten": "yes",
                                             "reported": "no", "authorityOutcome": "missing", "markerLines": "1",
                                             "ownerExit": "ok", "frontendExit": "closed"}),
    # The runner stops answering O's barriers: before the go byte O kills K and starts nothing;
    # after it O cannot stop the command, but makes no further restart call. C dies with O.
    "runner-lost-before-go": _case(actions=[("before-go", "drop-runner")],
                                   expect={**ADMITTED, "result": "notStarted", "goWritten": "no", "reported": "yes",
                                           "authorityOutcome": "notStarted", "markerLines": "0",
                                           "restartLogDetach": "no", "ownerExit": "refused",
                                           "frontendExit": "SIGKILL"}),
    "runner-lost-after-go": _case(actions=[("after-go", "drop-runner")],
                                  expect={**DISPATCHED, "restartLogDetach": "no", "ownerExit": "refused",
                                          "frontendExit": "SIGKILL"}),
    "owner-thread-refused": _case(owner="owner-thread",
                                  expect={**ADMITTED, "result": "ownerThreads", "goWritten": "no",
                                          "authorityOutcome": "notStarted", "markerLines": "0", "ownerExit": "ok",
                                          "frontendExit": "SIGKILL"}),
    "owner-without-capabilities": _case(owner="owner-nocaps", root_only=True,
                                        expect={"ownerCapabilitiesExact": "no", "ownerExit": "refused",
                                                "frontendExit": "not-started", "authorityBegin": "no",
                                                "markerLines": "0"}),
    "caller-attaches-to-k": _case("kpause", [("k-ready", "caller-attach-k"), ("k-paused", "caller-attach-k"),
                                             ("k-paused", "kill-k")], sysctl=True, root_only=True,
                                  expect={**UNKNOWN, "attachBeforeGo": "EPERM", "attachAfterGo": "EPERM"}),
}
MODES = frozenset({"normal", "short", "sleep", "missing", "khang", "kpause"})
ACTIONS = frozenset({"kill-k", "kill-owner", "kill-authority", "drop-runner", "caller-stop-k", "caller-term-k",
                     "caller-usr1-k",
                     "caller-cont-c", "caller-kill-c", "caller-attach-k"})
BARRIERS = frozenset({"start", "s1", "after-fork", "k-ready", "before-go", "after-check", "after-go", "k-paused",
                      "after-s6", "end"})
BARRIER_MESSAGE = re.compile(rb"BARRIER ([a-z0-9-]{1,16}) ([0-9]) ([0-9]{1,10}) ([0-9]{1,10})")
CALLER_SIGNALS = {"caller-stop-k": ("STOP", "k"), "caller-term-k": ("TERM", "k"), "caller-usr1-k": ("USR1", "k"),
                  "caller-cont-c": ("CONT", "c"), "caller-kill-c": ("KILL", "c")}


# --- Reports ---------------------------------------------------------------------------------

def parse_report(raw):
    """One JSON object of string values, bounded, with no duplicate keys."""
    return PL.parse_report(raw)


def owner_lines(raw):
    """O's stdout: a start line, then at most one dispatch line. Anything else is invalid."""
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("owner output exceeds bound")
    lines = [line for line in raw.split(b"\n") if line]
    if not 1 <= len(lines) <= 2:
        raise ValueError("unexpected owner line count")
    start = parse_report(lines[0])
    if set(start) != set(OWNER_START_KEYS) or any(v not in OWNER_START_KEYS[k] for k, v in start.items()):
        raise ValueError("invalid owner start report")
    dispatch = {}
    if len(lines) == 2:
        dispatch = parse_report(lines[1])
        if set(dispatch) != set(OWNER_DISPATCH_KEYS) or any(v not in OWNER_DISPATCH_KEYS[k]
                                                            for k, v in dispatch.items()):
            raise ValueError("invalid owner dispatch report")
        del dispatch["dispatch"]
    return start, dispatch


def _hex_mask(value):
    if not re.fullmatch(r"[0-9a-f]{16}", value or ""):
        raise ValueError("bad capability mask")
    return int(value, 16)


def probe_checks(raw, uid, gid, last_cap):
    """The command's inherited state, reduced to booleans. raw is b"" when no report came."""
    if not raw:
        return {key: "not-reported" for key in (*PROBE_OK, "boundingFull", "commandDumpable")}
    lines = [line for line in raw.split(b"\n") if line]
    if len(lines) != 1:
        raise ValueError("unexpected probe line count")
    report = parse_report(lines[0])
    if set(report) != set(PROBE_KEYS):
        raise ValueError("invalid probe report")
    caps = {key: _hex_mask(report[key]) for key in ("capPrm", "capEff", "capInh", "capAmb", "capBnd")}
    yes = lambda condition: "yes" if condition else "no"
    if report["dumpable"] not in ("0", "1") or report["sessionLeader"] not in YES_NO:
        raise ValueError("invalid probe report")
    return {"capsEmpty": yes(not (caps["capPrm"] or caps["capEff"] or caps["capInh"] or caps["capAmb"])),
            "boundingFull": yes(caps["capBnd"] == (1 << (last_cap + 1)) - 1),
            "noNewPrivsClear": yes(report["noNewPrivs"] == "0"),
            "uidsExact": yes(report["uid"] == " ".join([str(uid)] * 4)),
            "gidsExact": yes(report["gid"] == " ".join([str(gid)] * 4)),
            "umaskInherited": yes(report["umask"] == FIXTURE_UMASK),
            "nofileInherited": yes(report["nofileSoft"] == FIXTURE_NOFILE),
            "sessionLeader": report["sessionLeader"], "commandDumpable": report["dumpable"]}


def restart_log_clean(raw):
    """O's restart log: between the seize and the go byte, no restart call reached C.

    Each line is "<monotonic ns> <dispatch> <request>". Before GO (or in the whole log when no GO
    was written) only SEIZE then INTERRUPT may appear. A DETACH may follow GO only."""
    events = []
    for line in raw.decode("ascii").splitlines():
        match = re.fullmatch(r"[0-9]{1,20} 1 (SEIZE|INTERRUPT|GO|DETACH)", line)
        if not match:
            return "no"
        events.append(match[1])
    if events[:2] != ["SEIZE", "INTERRUPT"]:
        return "no"
    rest = events[2:]
    if not rest:
        return "yes"
    if rest == ["DETACH"]:
        return "yes"  # a dispatch that ends without a go byte releases C only after S6
    if rest[0] != "GO" or rest[1:] not in ([], ["DETACH"]):
        return "no"
    return "yes"


def evaluate(case, observed):
    """observed: the full OBSERVED key set. Publishes closed-set values only."""
    if set(observed) != set(OBSERVED) or any(observed[key] not in OBSERVED[key] for key in OBSERVED):
        return {"passed": False, "error_type": "InvalidObservation"}
    required = {key: value for key, value in CASES[case]["expect"].items() if key not in OBSERVED_ONLY}
    mismatches = sorted(key for key, allowed in required.items() if observed[key] not in allowed)
    return {"passed": not mismatches, "observed": dict(sorted(observed.items())), "mismatches": mismatches}


# --- Stub authority --------------------------------------------------------------------------

def _pidfd_pid(pidfd):
    """The PID that a pidfd names, from its fdinfo; -1 once the process has exited."""
    text = Path(f"/proc/self/fdinfo/{pidfd}").read_text()
    match = re.search(r"^Pid:\s*(-?[0-9]+)$", text, re.MULTILINE)
    if not match:
        raise ValueError("not a pidfd")
    return int(match[1])


def _start_time(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    return int(text[text.rindex(")") + 2:].split()[19])


def _boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


class Authority:
    """A one-use permit, bound to O's generation (checked through SO_PEERPIDFD) and to the nonce.

    The record holds "beginDispatch" when a permit goes out and the outcome when O reports. It
    stands in for the Swift authority, which PR2 composes."""

    def __init__(self, record_path, identity, mode):
        self.record_path = record_path
        self.uid, self.gid, self.groups = identity
        self.mode = mode
        self.generations = {}  # connection fileno -> generation tuple
        self.permits = {}  # token -> [generation, nonce, used]
        self.begun = self.outcome = None

    def _record(self, line):
        with open(self.record_path, "a", encoding="ascii") as record:
            record.write(line + "\n")

    def handle(self, key, message, pidfd):
        words = message.decode("ascii", "replace").split(" ")
        if words[0] == "HELLO" and len(words) == 5 and key not in self.generations:
            return self.hello(key, words[1:], pidfd)
        generation = self.generations.get(key)
        if generation is None:
            return b"REFUSED"
        if words[0] == "SUBMIT" and len(words) == 3 and re.fullmatch(r"[0-9a-f]{32}", words[1]):
            if self.begun is not None or not self._live(generation, pidfd):
                return b"REFUSED"
            token = secrets.token_hex(16)
            self.permits[token] = [generation, words[1], False]
            self.begun = token
            self._record(f"beginDispatch {token}")
            groups = " ".join(str(g) for g in self.groups)
            return f"PERMIT {token} {self.uid} {self.gid} {self.mode} {len(self.groups)} {groups}".strip().encode()
        if words[0] == "OUTCOME" and len(words) == 4:
            permit = self.permits.get(words[1])
            if permit is None or permit[0] != generation or words[2] not in RESULTS or words[3] not in YES_NO:
                return b"REFUSED"
            if permit[2]:
                self.outcome = "refused-replay"
                return b"REFUSED"
            permit[2] = True
            self.outcome = words[2]
            self._record(f"outcome {words[1]} {words[2]} {words[3]}")
            return b"OK"
        return b"REFUSED"

    def hello(self, key, fields, pidfd):
        boot_id, pid, start, random_value = fields
        try:
            generation = (boot_id, int(pid), int(start), random_value)
            if not re.fullmatch(r"[0-9a-f]{32}", random_value) or not self._live(generation, pidfd):
                return b"REFUSED"
        except (ValueError, OSError):
            return b"REFUSED"
        self.generations[key] = generation
        return b"OK"

    @staticmethod
    def _live(generation, pidfd):
        """The pidfd still names the generation's PID, and that PID has the generation's start time."""
        boot_id, pid, start, _random = generation
        try:
            return (pidfd is not None and boot_id == _boot_id() and _pidfd_pid(pidfd) == pid
                    and _start_time(pid) == start and _pidfd_pid(pidfd) == pid)
        except (ValueError, OSError, IndexError):
            return False


# --- One case --------------------------------------------------------------------------------

def _exit_category(returncode, owner=False):
    if returncode is None:
        return "running"
    if returncode == -signal.SIGKILL:
        return "SIGKILL"
    if returncode == 0:
        return "ok" if owner else "closed"
    if owner and returncode == 3:
        return "refused"
    if owner and returncode == 4:
        return "usage"
    return "other"


def _errno_name(code):
    return {0: "ok", 1: "EPERM", 13: "EACCES", 3: "ESRCH", 22: "EINVAL", 2: "ENOENT"}.get(code, "other")


def _alive(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return text[text.rindex(")") + 2] not in "ZX"


def _reap_k(pid, deadline):
    """K is reparented to this runner (a subreaper) when O dies; returns its exit category."""
    while time.monotonic() < deadline:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return "not-observed"
        if waited == pid:
            if os.WIFEXITED(status):
                return "reserved" if 120 <= os.WEXITSTATUS(status) <= 123 else "other"
            return "signaled"
        time.sleep(0.01)
    return "running"


class Host:
    """What a case needs from the host. Run (root) and the tests' fixture host provide it."""

    attach_enabled = False

    def listener(self, path):
        """C's way to O: a stream socket that the caller can reach."""
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        previous = os.umask(0o177)
        try:
            listener.bind(str(path))
        finally:
            os.umask(previous)
        os.chmod(path, 0o660)
        listener.listen(4)
        return listener

    def authority_listener(self, path):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        previous = os.umask(0o177)
        try:
            listener.bind(str(path))
        finally:
            os.umask(previous)
        listener.listen(4)
        return listener

    def start_owner(self, binary, arguments, pass_fds):
        raise NotImplementedError

    def start_frontend(self, socket_path):
        raise NotImplementedError

    def caller_signal(self, name, pid):
        raise NotImplementedError

    def caller_attach(self, pid):
        raise NotImplementedError


def drive_case(case, host, paths, identity, timeout, last_cap):
    """Runs one case through O's barriers. Always kills and reaps what it started."""
    spec = CASES[case]
    directory = paths["cases"] / case
    directory.mkdir(mode=0o755)
    marker, record, log_path = paths["markers"] / case, directory / "authority", directory / "restart.log"
    listen_path, authority_path = directory / "frontend.sock", directory / "authority.sock"
    authority = Authority(record, identity, spec["mode"])
    observed = {key: NA for key in OBSERVED}
    observed.update(kExit="not-observed", callerSignal=NA, attachBeforeGo=NA, attachAfterGo=NA,
                    frontendExit="not-started")
    if spec["sysctl"] and not host.attach_enabled:
        observed.update(attachBeforeGo="not-run", attachAfterGo="not-run")
    deadline = time.monotonic() + timeout
    owner = frontend = None
    pids = {"c": 0, "k": 0}
    owner_out, frontend_out = bytearray(), bytearray()
    sockets = []
    error, clean = None, False
    try:
        try:
            listener = host.listener(listen_path)
            sockets.append(listener)
            authority_listener = host.authority_listener(authority_path)
            sockets.append(authority_listener)
            control_owner, control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            sockets += [control_owner, control]
            log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600)
            try:
                owner = host.start_owner(spec["owner"], [str(listener.fileno()), str(authority_path),
                                                        str(control_owner.fileno()), str(log_fd), "1",
                                                        str(DEADLINE_MS), str(paths["probe"]), str(marker)],
                                         (listener.fileno(), control_owner.fileno(), log_fd))
            finally:
                os.close(log_fd)
            control_owner.close()
            with selectors.DefaultSelector() as selector:
                selector.register(owner.stdout, selectors.EVENT_READ, "owner")
                selector.register(control, selectors.EVENT_READ, "control")
                selector.register(authority_listener, selectors.EVENT_READ, "authority-listen")
                open_streams = {"owner", "control"}
                while open_streams & {"owner", "control"}:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    for key, _events in selector.select(min(remaining, 0.5)):
                        tag = key.data
                        if tag == "owner" or tag == "frontend":
                            buffer = owner_out if tag == "owner" else frontend_out
                            chunk = os.read(key.fd, 4096)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                open_streams.discard(tag)
                            buffer.extend(chunk)
                            if len(buffer) > MAX_OUTPUT_BYTES:
                                raise ValueError("output bound")
                        elif tag == "authority-listen":
                            connection, _ = authority_listener.accept()
                            sockets.append(connection)
                            selector.register(connection, selectors.EVENT_READ, ("authority", connection))
                        elif isinstance(tag, tuple):
                            connection = tag[1]
                            try:
                                message = connection.recv(1024)
                            except ConnectionError:
                                message = b""
                            if not message:
                                selector.unregister(connection)
                                connection.close()
                                continue
                            try:
                                pidfd = connection.getsockopt(socket.SOL_SOCKET, 77)
                            except OSError:
                                pidfd = None
                            try:
                                connection.send(authority.handle(connection.fileno(), message, pidfd))
                            finally:
                                if pidfd is not None:
                                    os.close(pidfd)
                        elif tag == "control":
                            try:
                                message = control.recv(256)
                            except ConnectionError:
                                message = b""
                            if not message:
                                selector.unregister(control)
                                open_streams.discard("control")
                                continue
                            match = BARRIER_MESSAGE.fullmatch(message)
                            if not match or match[1].decode() not in BARRIERS:
                                raise ValueError("bad barrier")
                            name = match[1].decode()
                            if int(match[3]):
                                pids["c"] = int(match[3])
                            if int(match[4]):
                                pids["k"] = int(match[4])
                            resume = True
                            if any(barrier == name and action == "drop-runner" for barrier, action in spec["actions"]):
                                # The runner goes away without an answer: O sees end of file on its barrier.
                                selector.unregister(control)
                                control.close()
                                open_streams.discard("control")
                                continue
                            if name == "start":
                                frontend = host.start_frontend(listen_path)
                                selector.register(frontend.stdout, selectors.EVENT_READ, "frontend")
                                open_streams.add("frontend")
                            for barrier, action in spec["actions"]:
                                if barrier != name:
                                    continue
                                resume = _act(action, host, owner, pids, observed, selector, sockets) and resume
                            if resume:
                                control.send(b"C")
                owner.wait(timeout=max(0.1, deadline - time.monotonic()))
                killed_owner = any(action == "kill-owner" for _barrier, action in spec["actions"])
                if spec["mode"] == "sleep" and pids["k"]:
                    # The command reports, then sleeps: wait for its line, then record whether it
                    # outlived O, then end it.
                    while frontend is not None and b"\n" not in frontend_out and "frontend" in open_streams:
                        _drain(selector, frontend_out, open_streams, deadline)
                    if killed_owner:
                        observed["commandAliveAfterOwner"] = "yes" if _alive(pids["k"]) else "no"
                if killed_owner and pids["k"]:
                    observed["kExit"] = _reap_k(pids["k"], min(deadline, time.monotonic() + 3))
                if spec["mode"] in ("sleep", "kpause", "khang"):
                    _end_session(pids["k"])
                while "frontend" in open_streams:
                    _drain(selector, frontend_out, open_streams, deadline)
            if frontend is not None:
                frontend.wait(timeout=max(0.1, deadline - time.monotonic()))
        except (TimeoutError, subprocess.TimeoutExpired):
            error = "TimeoutError"
        except (ValueError, OSError):
            error = "CaseFailure"
    finally:
        # Also on a cancel: nothing this case started may outlive it. A second SIGINT, SIGTERM or
        # SIGHUP waits until the removal ends.
        with PL.deferred_cancel():
            clean = _retire_all(owner, frontend, pids, sockets)
    if error:
        return {"passed": False, "error_type": error, "cleanupReapedAllFixtureProcesses": clean}
    try:
        start, dispatch = owner_lines(bytes(owner_out))
        observed.update(start)
        observed.update(dispatch)
        observed.update(probe_checks(bytes(frontend_out), identity[0], identity[1], last_cap))
        log = log_path.read_bytes()
        observed["restartLogClean"] = restart_log_clean(log) if log else NA
        observed["restartLogDetach"] = ("yes" if log.endswith(b" DETACH\n") else "no") if log else NA
    except (ValueError, UnicodeDecodeError):
        return {"passed": False, "error_type": "InvalidReport", "cleanupReapedAllFixtureProcesses": clean}
    observed["ownerExit"] = _exit_category(owner.returncode, owner=True)
    observed["frontendExit"] = _exit_category(frontend.returncode) if frontend is not None else "not-started"
    try:
        lines = marker.read_bytes().count(b"\n")
    except FileNotFoundError:
        lines = 0
    observed["markerLines"] = "0" if lines == 0 else "1" if lines == 1 else "more"
    observed["authorityBegin"] = "yes" if authority.begun else "no"
    observed["authorityOutcome"] = authority.outcome or "missing"
    result = evaluate(case, observed)
    result["cleanupReapedAllFixtureProcesses"] = clean
    result["passed"] = result["passed"] and clean
    return result


def _drain(selector, buffer, open_streams, deadline):
    """Reads the frontend's stdout (the command's stdout) once, before the deadline."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    for key, _events in selector.select(min(remaining, 0.5)):
        if key.data != "frontend":
            selector.unregister(key.fileobj)  # O is gone: only the command's output matters now
            continue
        chunk = os.read(key.fd, 4096)
        if not chunk:
            selector.unregister(key.fileobj)
            open_streams.discard("frontend")
        buffer.extend(chunk)
        if len(buffer) > MAX_OUTPUT_BYTES:
            raise ValueError("output bound")


def _act(action, host, owner, pids, observed, selector, sockets):
    """Performs one fault at a barrier. Returns False when O must not be resumed."""
    if action == "kill-owner":
        owner.kill()
        return False
    if action == "kill-k":
        if pids["k"]:
            os.kill(pids["k"], signal.SIGKILL)
        return True
    if action == "drop-runner":
        return False  # handled by drive_case, which owns the control socket
    if action == "kill-authority":
        for item in list(sockets):
            if item.family == socket.AF_UNIX and item.type == socket.SOCK_SEQPACKET and item.fileno() >= 0:
                with contextlib.suppress(KeyError, ValueError):
                    data = selector.get_key(item).data
                    if isinstance(data, tuple) or data == "authority-listen":
                        selector.unregister(item)
                        item.close()
        return True
    if action in CALLER_SIGNALS:
        name, target = CALLER_SIGNALS[action]
        sent = bool(pids[target]) and host.caller_signal(name, pids[target])
        observed["callerSignal"] = "sent" if sent and observed["callerSignal"] in (NA, "sent") else "failed"
        return True
    if action == "caller-attach-k":
        key = "attachBeforeGo" if observed["attachBeforeGo"] == NA else "attachAfterGo"
        observed[key] = host.caller_attach(pids["k"]) if host.attach_enabled else "not-run"
        return True
    raise ValueError("unknown action")


def _session_members(sid):
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / "stat").read_text()
            fields = text[text.rindex(")") + 2:].split()
        except (OSError, ValueError):
            continue
        if int(fields[3]) == sid:
            members.append(int(entry.name))
    return members


def _end_session(k_pid):
    """K's command leads its own session (setsid); a still-running command is killed."""
    if not k_pid:
        return
    for pid in _session_members(k_pid):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGKILL)


def _reap(pid, deadline):
    """Reaps pid if it is (or becomes) this runner's child; True once it is gone, before the deadline.

    A process that is not this runner's child counts as gone when /proc no longer shows it alive."""
    while True:
        try:
            waited, _status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                return True
        except ChildProcessError:
            if not _alive(pid):
                return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _retire_all(owner, frontend, pids, sockets):
    """O first (no new K after it), then the command's session, then C; every process is reaped."""
    clean = True
    for process in (owner, frontend):
        if process is not None and process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        if process is owner:
            _end_session(pids["k"])
    for process in (owner, frontend):
        if process is None:
            continue
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            clean = False
        if process.stdout is not None:
            process.stdout.close()
    if pids["k"]:
        _end_session(pids["k"])
        clean = _reap(pids["k"], time.monotonic() + 3) and clean
    for item in sockets:
        item.close()
    return clean


# --- Root host -------------------------------------------------------------------------------

def _run_tool(arguments, timeout):
    return PL.run_owned(arguments, timeout)[0]


def _read_setting(path):
    value = PL._policy_bytes(path, 64)
    return value.decode().strip() if value is not None and re.fullmatch(rb"[0-9]{1,3}\n?", value) else None


class Run(Host):
    """Disposable host state for one measurement; cleanup removes all of it."""

    def __init__(self, operator, timeout, allow_sysctl=False):
        self.operator = operator
        self.timeout = timeout
        self.allow_sysctl = allow_sysctl
        self.attach_enabled = False
        self.tag = secrets.token_hex(4)
        self.base = BASE_PARENT / (BASE_PREFIX + self.tag)
        self.service_name = f"rmzso{self.tag}"
        self.base_created = self.service_created = False
        self.saved_sysctls = {}
        self.setpriv = shutil.which("setpriv", path=PL.TOOL_ENV["PATH"]) or "/usr/bin/setpriv"

    def setup(self):
        self.groups = os.getgrouplist(self.operator.pw_name, self.operator.pw_gid)
        if len(self.groups) > MAX_GROUPS:
            sys.stderr.write(f"The operator account has {len(self.groups)} groups; the owner fixture takes at most "
                             f"{MAX_GROUPS}. Run from an account with fewer groups.\n")
            raise RuntimeError("too many operator groups")
        os.mkdir(self.base, 0o755)
        self.base_created = True
        os.chmod(self.base, 0o755)
        for name, mode in (("build", 0o700), ("run", 0o755), ("cases", 0o755)):
            os.mkdir(self.base / name, mode)
            os.chmod(self.base / name, mode)
        compiler = shutil.which("cc", path=PL.TOOL_ENV["PATH"]) or "/usr/bin/cc"
        for name, (source, extra) in BUILDS.items():
            output = self.base / "build" / name
            if _run_tool([compiler, *CC_FLAGS, *extra, "-o", str(output), str(source)], min(60, 4 * self.timeout)) != 0:
                raise RuntimeError("fixture build failed")
            PL.write_root_file(self.base / "run" / name, output.read_bytes(), 0o755)
        PL.Run._create(self, "service_created", ["useradd", "--system", "--no-create-home", "--home-dir", "/",
                                                 "--shell", "/usr/sbin/nologin", "--user-group", self.service_name],
                       (self.service_name,))
        account = pwd.getpwnam(self.service_name)
        self.service_uid, self.service_gid = account.pw_uid, account.pw_gid
        if 0 in (self.service_uid, self.service_gid):
            raise RuntimeError("disposable identity is privileged")
        # The markers belong to the caller: the command writes them as the caller.
        markers = self.base / "markers"
        os.mkdir(markers, 0o700)
        os.chown(markers, self.operator.pw_uid, self.operator.pw_gid)
        self.paths = {"cases": self.base / "cases", "markers": markers, "probe": self.base / "run" / "probe"}
        operator_groups = set(self.groups)
        return {"serviceIdentityUnprivileged": True,
                "serviceOutsideOperatorGroups": self.service_gid not in operator_groups,
                "operatorUnprivileged": self.operator.pw_uid != 0 and 0 not in operator_groups}

    def identity(self):
        return self.operator.pw_uid, self.operator.pw_gid, self.groups

    def listener(self, path):
        """Only the operator's primary group reaches O's socket; C runs with it."""
        listener = Host.listener(self, path)
        os.chown(path, 0, self.operator.pw_gid)
        return listener

    def authority_listener(self, path):
        """Only O's service group reaches the authority."""
        listener = Host.authority_listener(self, path)
        os.chown(path, 0, self.service_gid)
        os.chmod(path, 0o660)
        return listener

    def start_owner(self, binary, arguments, pass_fds):
        """setpriv emulates AmbientCapabilities=: O starts with the three capabilities ambient."""
        capabilities = [] if binary == "owner-nocaps" else ["--inh-caps", OWNER_CAPS, "--ambient-caps", OWNER_CAPS]
        image = self.base / "run" / ("owner" if binary == "owner-nocaps" else binary)
        return subprocess.Popen(
            [self.setpriv, "--reuid", str(self.service_uid), "--regid", str(self.service_gid),
             "--clear-groups", *capabilities, "--", str(image), *arguments],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=pass_fds,
            env={}, cwd="/", start_new_session=True)

    def _caller(self):
        return {"user": self.operator.pw_uid, "group": self.operator.pw_gid, "extra_groups": self.groups,
                "env": {}, "cwd": "/", "start_new_session": True}

    def start_frontend(self, socket_path):
        return subprocess.Popen([str(self.base / "run" / "frontend"), str(socket_path)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **self._caller())

    def caller_signal(self, name, pid):
        return subprocess.run(["/bin/kill", f"-{name}", str(pid)], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=self.timeout,
                              **self._caller()).returncode == 0

    def caller_attach(self, pid):
        """PTRACE_ATTACH from the caller's account; prints the errno name."""
        program = ("import ctypes,os,sys\n"
                   "libc=ctypes.CDLL(None,use_errno=True)\n"
                   "r=libc.ptrace(16,int(sys.argv[1]),0,0)\n"
                   "sys.stdout.write(str(0 if r==0 else ctypes.get_errno()))\n")
        result = subprocess.run([sys.executable, "-I", "-c", program, str(pid)], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=self.timeout, **self._caller())
        output = result.stdout.decode("ascii", "replace")
        return _errno_name(int(output)) if output.isdigit() else "other"

    def enable_attach_sysctls(self):
        """Saves both values first, so cleanup restores whatever this run changed."""
        for name, path in SYSCTLS.items():
            value = _read_setting(path)
            if value is None:
                raise RuntimeError("sysctl unavailable")
            self.saved_sysctls[name] = value
        for name, value in ATTACH_SYSCTLS.items():
            SYSCTLS[name].write_text(value)
        self.attach_enabled = True

    def restore_sysctls(self):
        restored = True
        for name, value in self.saved_sysctls.items():
            try:
                SYSCTLS[name].write_text(value)
            except OSError:
                restored = False
            restored = restored and _read_setting(SYSCTLS[name]) == value
        self.attach_enabled = False
        return restored

    def run_case(self, case, last_cap):
        if CASES[case]["sysctl"]:
            if not self.allow_sysctl:
                return {"passed": True, "status": "not-run"}
            self.enable_attach_sysctls()
            try:
                return drive_case(case, self, self.paths, self.identity(), self.timeout, last_cap)
            finally:
                if not self.restore_sysctls():
                    raise RuntimeError("sysctl restore failed")
        return drive_case(case, self, self.paths, self.identity(), self.timeout, last_cap)

    def cleanup(self):
        """Ends every process of the service user, removes files, then the user; restores sysctls.
        Each step runs even when an earlier one fails; only state this run created is touched."""
        sysctls = self.restore_sysctls() if self.saved_sysctls else True
        if self.service_created:
            with contextlib.suppress(KeyError):
                uid = pwd.getpwnam(self.service_name).pw_uid
                PL._attempt(_kill_user, uid)
        if self.base_created:
            PL._attempt(shutil.rmtree, self.base)
        if self.service_created and not PL._absent(pwd.getpwnam, self.service_name):
            PL._attempt(PL.run_owned, ["userdel", self.service_name], self.timeout)
        if self.service_created and not PL._absent(grp.getgrnam, self.service_name):
            PL._attempt(PL.run_owned, ["groupdel", self.service_name], self.timeout)
        return {"filesRemoved": not self.base.exists(),
                "serviceUserRemoved": PL._absent(pwd.getpwnam, self.service_name)
                and PL._absent(grp.getgrnam, self.service_name),
                "sysctlsRestored": sysctls}


def _kill_user(uid, proc=Path("/proc")):
    """SIGKILL every process whose real, effective or saved UID is uid.

    /proc/<pid> itself belongs to Root for a process that is not dumpable (O after setpriv), so the
    owner of the directory does not name the account; the Uid: line of the status file does."""
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / "status").read_text()
        except OSError:
            continue
        match = re.search(r"^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)", text, re.MULTILINE)
        if match and uid in (int(match[1]), int(match[2]), int(match[3])):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(int(entry.name), signal.SIGKILL)


def last_capability():
    value = PL._policy_bytes("/proc/sys/kernel/cap_last_cap", 16)
    if value is None or not re.fullmatch(rb"[0-9]{1,2}\n?", value):
        raise RuntimeError("cap_last_cap unavailable")
    return int(value)


def source_hashes():
    paths = (Path(__file__).resolve(), OWNER, FRONTEND, PROBE, PROTECTED_RUNNER)
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def measure(timeout=15, allow_sysctl=False, run_factory=Run):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("requires Linux x86_64")
    if os.geteuid() != 0 or os.getuid() != 0:
        raise RuntimeError("requires root")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 5 <= timeout <= 60:
        raise ValueError("timeout must be at least 5 and at most 60 seconds")
    if not shutil.which("setpriv", path=PL.TOOL_ENV["PATH"]):
        raise RuntimeError("setpriv unavailable")
    operator = PL.operator_account()
    if not PL.root_owned_ancestry(BASE_PARENT):
        raise RuntimeError("experiment parent must be root-owned")
    host = PL.host_metadata()
    last_cap = last_capability()
    run = run_factory(operator, timeout, allow_sysctl)
    setup, cases = {}, {}
    with PL.subreaper():
        try:
            setup = run.setup()
            if all(setup.values()):
                cases = {case: run.run_case(case, last_cap) for case in CASES}
        finally:
            # A second SIGTERM, SIGHUP or Ctrl-C must not stop the removal half way.
            with PL.deferred_cancel():
                cleanup = run.cleanup()
                if not all(cleanup.values()):
                    sys.stderr.write(f"Disposable state not fully removed: inspect {BASE_PARENT}/{BASE_PREFIX}*, the "
                                     "rmzso* system accounts and the two sysctls.\n")
    passed = (bool(setup) and all(setup.values()) and all(cleanup.values()) and set(cases) == set(CASES)
              and all(item["passed"] for item in cases.values()))
    return {"experiment": "linux-single-owner-v1",
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "supervised": True, "trustedCode": False, "strictAdmission": False, "productionAdmission": False,
            "sysctlCase": "run" if allow_sysctl else "not-run",
            "host": host, "sources": source_hashes(), "setup": setup, "cases": cases, "cleanup": cleanup,
            "passed": passed,
            "limits": ["C measurement fixture with a stub authority, not the Swift authority (PR2)",
                       "AmbientCapabilities= emulated with setpriv; no systemd unit, AppArmor or cgroup options",
                       "no sudo, controlling terminal, TPM or phone approval",
                       "one host, one kernel"]}


def _cancel(_signum, _frame):
    raise KeyboardInterrupt()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--timeout", type=float, default=15, help="seconds per case (5 <= timeout <= 60)")
    parser.add_argument("--allow-sysctl", action="store_true",
                        help="run the attach case: set fs.suid_dumpable=1 and kernel.yama.ptrace_scope=0, "
                             "then restore both")
    args = parser.parse_args()
    previous = {number: signal.signal(number, _cancel) for number in (signal.SIGTERM, signal.SIGHUP)}
    try:
        try:
            report = measure(args.timeout, args.allow_sysctl)
        except KeyboardInterrupt:
            parser.exit(130, "Single-owner experiment cancelled.\n")
        except (RuntimeError, ValueError, OSError, KeyError, subprocess.SubprocessError):
            parser.exit(2, "Single-owner experiment unavailable; no raw diagnostic data published.\n")
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
