#!/usr/bin/env python3
"""Supervised protected-launch controls: a set-group-ID static fixture, a monitor that keeps
only CAP_SYS_PTRACE, and same-UID attacks. A measurement, not a production admission path.

Run once as root through sudo from the operator's session. The runner creates a disposable
group with no members and a disposable monitor user, measures every case, then removes all
of it. The report holds booleans, errno names, categories, settings and hashes only."""
import argparse
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
FIXTURES = ROOT / "experiments/linux-protected-launch"
FRONTEND, MONITOR, ATTACKER = (FIXTURES / name for name in ("frontend.c", "monitor.c", "attacker.c"))
CLEANUP_SOURCE = ROOT / "scripts/run-linux-caller-experiment.py"
# The process-group cleanup is reused from the caller runner, which is loaded (and so runs its
# top level) at import. A change to that runner's import-time behaviour reaches this one.
_spec = importlib.util.spec_from_file_location("remozio_owned_caller_cleanup", CLEANUP_SOURCE)
_cleanup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cleanup)
subreaper = _cleanup.subreaper
group_has_owned_child = _cleanup.group_has_owned_child
reap_group = _cleanup.reap_group

BASE_PARENT = Path("/var/lib")
BASE_PREFIX = "remozio-protected-launch-experiment-"
MAX_OUTPUT_BYTES = 16384
CC_FLAGS = ("-std=c11", "-O2", "-Wall", "-Wextra", "-Werror")
TOOL_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}

YES_NO = frozenset({"yes", "no"})
ERRNO = frozenset({"ok", "EPERM", "EACCES", "ESRCH", "EFAULT", "EINVAL", "ENOSYS", "ENOPROTOOPT", "EBADF", "other"})
EXITS = frozenset({"accepted", "rejected", "forbidden-returned", "usage", "policy-setup-failed", "connect-EACCES",
                   "socket-failure", "protocol-failure", "SIGSYS", "signaled", "unknown", "other", "wait-failed",
                   "spawn-failed"})
LABELS = frozenset({"unconfined", "confined", "unavailable", "not-attempted"})
ATTACKER_VALUES = YES_NO | ERRNO | EXITS | {"not-attempted", "mismatch", "short", "unreadable", "created",
                                            "failed", "missing", "overflow"}
MONITOR_ERRORS = frozenset({"usage", "privilege-drop", "accept", "accept-timeout", "overflow"})
FAILURE_KEYS = frozenset({"spawn", "installed.spawn", "control.spawn", "error"})
# The missing-pidfd control monitor asks for a socket option the kernel does not know.
MONITOR_BUILDS = {"monitor": (), "monitor-nopidfd": ("-DRMZPL_PEERPIDFD_OPTION=32767",)}

# Every monitor report carries exactly these keys, in this vocabulary.
MONITOR_KEYS = {
    "monitorCredentialsExact": YES_NO, "monitorAppArmor": LABELS, "peerPidfd": ERRNO,
    "peerCredEffectiveGidIsGroup": YES_NO, "helloReceived": YES_NO, "seize": ERRNO | {"not-attempted"},
    "pidfdAssociated": YES_NO, "stopHeld": YES_NO, "statusGidRolesExact": YES_NO,
    "groupsExcludeFrontendGroup": YES_NO, "singleThread": YES_NO, "seccompFilterMode": YES_NO,
    "singleSeccompFilter": YES_NO, "noNewPrivs": YES_NO, "tracerIsMonitor": YES_NO, "signalsReset": YES_NO,
    "personalityCleared": YES_NO, "atSecure": YES_NO, "notDumpable": YES_NO, "exeIsCurrentInstalledImage": YES_NO,
    "mapsAllowed": YES_NO, "hostNamespaces": YES_NO, "fdDirectoryListing": ERRNO | {"not-attempted"},
    "descriptorsExact": YES_NO, "frontendAppArmor": LABELS, "accepted": YES_NO, "verdictSent": YES_NO,
}
# AppArmor labels are observations: recorded, never required.
OBSERVED_ONLY = frozenset({"monitorAppArmor", "frontendAppArmor"})
STOP_CHECKS = ("statusGidRolesExact", "groupsExcludeFrontendGroup", "singleThread", "seccompFilterMode",
               "singleSeccompFilter", "noNewPrivs", "tracerIsMonitor", "signalsReset", "personalityCleared",
               "atSecure", "notDumpable", "exeIsCurrentInstalledImage", "mapsAllowed", "hostNamespaces",
               "descriptorsExact")
ADMITTED = {"monitorCredentialsExact": "yes", "peerPidfd": "ok", "peerCredEffectiveGidIsGroup": "yes",
            "helloReceived": "yes", "seize": "ok", "pidfdAssociated": "yes", "stopHeld": "yes",
            **dict.fromkeys(STOP_CHECKS, "yes"), "fdDirectoryListing": ("EACCES", "EPERM"),
            "accepted": "yes", "verdictSent": "yes"}
NOT_SEIZED = {**ADMITTED, "seize": "EPERM", "pidfdAssociated": "no", "stopHeld": "no",
              **dict.fromkeys(STOP_CHECKS, "no"), "fdDirectoryListing": "not-attempted", "accepted": "no"}
PIDFD_MISSING = {**NOT_SEIZED, "peerPidfd": "ENOPROTOOPT", "seize": "not-attempted"}
PROBES = ("ready", "procMemOpen", "procMemReadMarker", "procMemWrite", "vmRead", "vmWrite", "pidfdGetfd", "seize")
REFUSED_ATTACK = {"ready": "yes", "procMemOpen": ("EACCES", "EPERM"), "procMemReadMarker": "not-attempted",
                  "procMemWrite": "not-attempted", "vmRead": "EPERM", "vmWrite": "EPERM", "pidfdGetfd": "EPERM",
                  "seize": "EPERM"}
WORKING_ATTACK = {"ready": "yes", "procMemOpen": "ok", "procMemReadMarker": "yes", "procMemWrite": "ok",
                  "vmRead": "ok", "vmWrite": "ok", "pidfdGetfd": "ok", "seize": "ok"}
NO_ELEVATION = {"ready": "yes", "effectiveGidElevated": "no", "frontendExit": "connect-EACCES"}
MEMBER = {"ready": "yes", "effectiveGidElevated": "yes", "frontendExit": "rejected"}


def _expect(values):
    return {key: frozenset(value if isinstance(value, tuple) else (value,)) for key, value in values.items()}


def _case(argument, attacker, monitor=None, member=False, mode="cap", binary="monitor"):
    """attacker: one or more alternative exact outcomes; monitor: required values or None."""
    alternatives = attacker if isinstance(attacker, list) else [attacker]
    return {"argument": argument, "member": member, "attacker": [_expect(item) for item in alternatives],
            "monitorMode": None if monitor is None else mode, "monitorBinary": None if monitor is None else binary,
            "monitor": None if monitor is None else _expect(monitor)}


# n8 runs last: it replaces the installed image. Plan names: P1-P3 and N11 are the p1 monitor
# report; N9 has an untraced and a traced member; n13 is the missing-SO_PEERPIDFD control.
CASES = {
    "p1": _case("p1", {"frontendExit": "accepted"}, ADMITTED),
    "n1": _case("n1", {**{f"installed.{k}": v for k, v in REFUSED_ATTACK.items()},
                       **{f"control.{k}": v for k, v in WORKING_ATTACK.items()}}),
    "n2": _case("n2", {"execStop": "yes", **NO_ELEVATION}),
    "n3": _case("n3", NO_ELEVATION),
    "n4": _case("n4", NO_ELEVATION),
    "n5": _case("n5", {"frontendExit": "accepted"}, ADMITTED),
    "n6": _case("n6", {"frontendExit": "accepted"}, ADMITTED),
    "n7": _case("n7", dict.fromkeys(("exec", "mprotect", "mmap-exec", "shared", "clone", "x32"), "SIGSYS")),
    # A member keeps all four GID roles: cap_bprm_creds_from_file sets the saved and filesystem
    # GIDs to the effective GID on every exec, whatever in_group_p decides about the downgrade.
    "n9-untraced": _case("n9-untraced", MEMBER, {**ADMITTED, "groupsExcludeFrontendGroup": "no", "accepted": "no"},
                         member=True),
    "n9-traced": _case("n9-traced", {"execStop": "yes", **MEMBER},
                       {**ADMITTED, "groupsExcludeFrontendGroup": "no", "accepted": "no"}, member=True),
    "n10": _case("n10", {"frontendExit": "rejected"}, NOT_SEIZED, mode="nocap"),
    # A policy refusal (EPERM, EACCES) or no elevation; any other unshare errno fails the case.
    "n12": _case("n12", [{"userNamespace": ("EPERM", "EACCES")}, {"userNamespace": "created", **NO_ELEVATION}]),
    "n13": _case("p1", {"frontendExit": "rejected"}, PIDFD_MISSING, binary="monitor-nopidfd"),
    "n8": _case("n8", {"oPathOpen": "ok", "frontendExit": "rejected"},
                {**ADMITTED, "exeIsCurrentInstalledImage": "no", "mapsAllowed": "no", "accepted": "no"}),
}


class OutputLimitError(Exception):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _unsupported_constant(_value):
    raise ValueError("unsupported JSON constant")


def parse_report(raw):
    """One JSON object of string values, bounded, with no duplicate keys."""
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("report exceeds bound")
    value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_unsupported_constant)
    if type(value) is not dict or any(type(k) is not str or type(v) is not str for k, v in value.items()):
        raise ValueError("report is not a flat string object")
    return value


def _mismatches(observed, expected):
    return sorted(key for key, allowed in expected.items() if observed.get(key) not in allowed)


def evaluate_case(case, attacker_raw, attacker_rc, monitor_raw=None, monitor_rc=None, queued=None):
    """Validates both fixture reports against the case table; publishes closed-set values only."""
    spec = CASES[case]
    result = {"passed": False}
    try:
        attacker = parse_report(attacker_raw)
    except (ValueError, RecursionError):
        result["error_type"] = "InvalidAttackerReport"
        return result
    allowed_keys = set().union(*(set(item) for item in spec["attacker"])) | FAILURE_KEYS
    if set(attacker) - allowed_keys or any(value not in ATTACKER_VALUES for value in attacker.values()):
        result["error_type"] = "InvalidAttackerReport"
        return result
    result["attacker"] = dict(sorted(attacker.items()))
    matching = [item for item in spec["attacker"] if set(item) == set(attacker)]
    mismatches = [f"attacker.{key}" for key in _mismatches(attacker, matching[0])] if matching else ["attacker.keys"]
    if attacker_rc != 0:
        mismatches.append("attacker.exitStatus")

    if spec["monitor"] is None:
        if queued not in YES_NO:
            result["error_type"] = "MissingConnectionCheck"
            return result
        result["connectionQueued"] = queued
        if queued != "no":
            mismatches.append("connectionQueued")
    else:
        try:
            monitor = parse_report(monitor_raw)
        except (ValueError, RecursionError):
            result["error_type"] = "InvalidMonitorReport"
            return result
        if "error" in monitor:
            result["error_type"] = "MonitorError"
            if monitor["error"] in MONITOR_ERRORS:
                result["monitorError"] = monitor["error"]
            return result
        if set(monitor) != set(MONITOR_KEYS) or any(value not in MONITOR_KEYS[key] for key, value in monitor.items()):
            result["error_type"] = "InvalidMonitorReport"
            return result
        result["monitor"] = dict(sorted(monitor.items()))
        required = {key: value for key, value in spec["monitor"].items() if key not in OBSERVED_ONLY}
        mismatches += [f"monitor.{key}" for key in _mismatches(monitor, required)]
        if monitor_rc != 0:
            mismatches.append("monitor.exitStatus")
    result["mismatches"] = sorted(mismatches)
    result["passed"] = not mismatches
    return result


# --- Owned processes -------------------------------------------------------------------------

def _read_exact(process, deadline, count):
    """Reads exactly count bytes from process.stdout before the deadline."""
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while len(data) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("owned fixture", 0)
            if selector.select(remaining):
                chunk = os.read(process.stdout.fileno(), count - len(data))
                if not chunk:
                    raise ValueError("fixture closed its output early")
                data.extend(chunk)
    return bytes(data)


def _read_output(process, deadline):
    """Bounded read to EOF, then wait for the process, both before the deadline."""
    output = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("owned fixture", 0)
            for key, _events in selector.select(remaining):
                chunk = os.read(key.fd, min(4096, MAX_OUTPUT_BYTES + 1 - len(output)))
                if not chunk:
                    selector.unregister(key.fileobj)
                    break
                output.extend(chunk)
                if len(output) > MAX_OUTPUT_BYTES:
                    raise OutputLimitError()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired("owned fixture", 0)
    process.wait(timeout=remaining)
    return bytes(output)


def _retire(process):
    """Kill the case's process group if anything owned is alive, then reap it."""
    if process is None:
        return True
    clean = True
    try:
        if process.poll() is None or group_has_owned_child(process.pid):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            clean = False
        return reap_group(process.pid) and clean
    finally:
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()


def run_owned(arguments, timeout, **options):
    """A bounded root tool run (compiler, account tools); returns its exit status."""
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=TOOL_ENV, cwd="/", start_new_session=True, **options)
    try:
        output = _read_output(process, time.monotonic() + timeout)
    finally:
        clean = _retire(process)
    if not clean:
        raise RuntimeError("tool cleanup failed")
    return process.returncode, output


# --- Host and file checks --------------------------------------------------------------------

def _policy_bytes(path, limit=4096):
    try:
        with Path(path).open("rb") as stream:
            value = stream.read(limit + 1)
        return value if len(value) <= limit else None
    except OSError:
        return None


def _small_setting(path):
    value = _policy_bytes(path, 64)
    return int(value) if value is not None and re.fullmatch(rb"[0-9]{1,3}\n?", value) else "unavailable"


def _os_release():
    text = _policy_bytes("/etc/os-release", 16384) or b""
    fields = dict(re.findall(rb'^(ID|VERSION_ID)="?([A-Za-z0-9._-]{1,32})"?$', text, re.MULTILINE))
    return {"id": fields.get(b"ID", b"unknown").decode(), "versionId": fields.get(b"VERSION_ID", b"unknown").decode()}


def host_metadata():
    # Numeric kernel version only: custom build strings can carry names or paths.
    # Keep the distribution's numeric ABI revision (6.17.0-41) but no flavor or build text.
    match = re.match(r"^([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,6})?(?:-[0-9]{1,6})?)(?:[^0-9]|$)", platform.release())
    python = platform.python_version()
    apparmor = {b"Y\n": True, b"Y": True, b"N\n": False, b"N": False}.get(
        _policy_bytes("/sys/module/apparmor/parameters/enabled", 64), "unavailable")
    return {"os": "Linux", "architecture": "x86_64", "runsAsRoot": True, "osRelease": _os_release(),
            "kernelVersion": match[1] if match else "unknown",
            "pythonVersion": python if re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,6}", python) else "unknown",
            "settings": {"ptraceScope": _small_setting("/proc/sys/kernel/yama/ptrace_scope"),
                         "suidDumpable": _small_setting("/proc/sys/fs/suid_dumpable"),
                         "protectedHardlinks": _small_setting("/proc/sys/fs/protected_hardlinks"),
                         "apparmorEnabled": apparmor,
                         "apparmorRestrictUnprivilegedUserns":
                             _small_setting("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
                         "unprivilegedUsernsClone": _small_setting("/proc/sys/kernel/unprivileged_userns_clone")}}


def source_hashes():
    paths = (Path(__file__).resolve(), FRONTEND, MONITOR, ATTACKER, CLEANUP_SOURCE)
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def root_owned_ancestry(path):
    """Every component from / is a real directory owned by root and not group/other-writable."""
    current = Path("/")
    for part in (Path("/"), *path.relative_to("/").parts):
        current = current / part
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            return False
    return True


def static_non_pie(path):
    """ET_EXEC with no PT_INTERP: no loader runs before the frontend's own code."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1 or int.from_bytes(data[16:18], "little") != 2:
        return False
    phoff, phentsize, phnum = (int.from_bytes(data[32:40], "little"), int.from_bytes(data[54:56], "little"),
                               int.from_bytes(data[56:58], "little"))
    if phentsize < 4 or phoff + phentsize * phnum > len(data):
        return False
    return all(int.from_bytes(data[phoff + i * phentsize:phoff + i * phentsize + 4], "little") != 3
               for i in range(phnum))


def write_root_file(path, data, mode, gid=0):
    """Create a new root file, set the owner first (chown clears set-ID bits), then the mode."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o700)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
        os.fchown(descriptor, 0, gid)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def installed_exact(path, gid, expected_sha256):
    info = os.lstat(path)
    return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == gid and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o2755
            and hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256)


def make_listener(path, gid):
    """Root binds with a restrictive umask, then opens the socket inode to the group only."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    previous = os.umask(0o177)
    try:
        listener.bind(str(path))
    finally:
        os.umask(previous)
    os.chown(path, 0, gid)
    os.chmod(path, 0o660)
    info = os.lstat(path)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o660:
        listener.close()
        raise RuntimeError("socket gate not exact")
    listener.listen(4)
    return listener


def connection_queued(listener):
    listener.setblocking(False)
    try:
        connection, _ = listener.accept()
    except BlockingIOError:
        return "no"
    connection.close()
    return "yes"


# --- Measurement -----------------------------------------------------------------------------

class Run:
    """Disposable host state for one measurement; cleanup removes all of it."""

    def __init__(self, operator, timeout):
        self.operator = operator
        self.timeout = timeout
        self.fixture_seconds = str(max(2, int(timeout) - 3))
        self.tag = secrets.token_hex(4)
        self.base = BASE_PARENT / (BASE_PREFIX + self.tag)
        self.group_name, self.monitor_name = f"rmzpl{self.tag}", f"rmzpm{self.tag}"
        self.base_created = self.group_created = self.monitor_created = False
        self.gid = self.monitor_uid = self.monitor_gid = None

    def setup(self):
        os.mkdir(self.base, 0o755)
        self.base_created = True
        os.chmod(self.base, 0o755)
        for name, mode in (("build", 0o700), ("run", 0o755), ("s", 0o755)):
            os.mkdir(self.base / name, mode)
            os.chmod(self.base / name, mode)
        builds = {}
        for name, source, extra in (("frontend", FRONTEND, ("-static", "-no-pie")), ("attacker", ATTACKER, ()),
                                    *((name, MONITOR, flags) for name, flags in MONITOR_BUILDS.items())):
            output = self.base / "build" / name
            code, _ = run_owned([shutil.which("cc", path=TOOL_ENV["PATH"]) or "/usr/bin/cc", *CC_FLAGS, *extra,
                                 "-o", str(output), str(source)], min(60, 4 * self.timeout))
            if code != 0 or not output.is_file():
                raise RuntimeError("fixture build failed")
            builds[name] = output.read_bytes()
        self.frontend_bytes = builds["frontend"]
        self.frontend_sha256 = hashlib.sha256(self.frontend_bytes).hexdigest()

        self._create("group_created", ["groupadd", "--system", self.group_name], (self.group_name,))
        self.gid = grp.getgrnam(self.group_name).gr_gid
        self._create("monitor_created", ["useradd", "--system", "--no-create-home", "--home-dir", "/", "--shell",
                                         "/usr/sbin/nologin", "--user-group", self.monitor_name], (self.monitor_name,))
        account = pwd.getpwnam(self.monitor_name)
        self.monitor_uid, self.monitor_gid = account.pw_uid, account.pw_gid
        if 0 in (self.gid, self.monitor_uid, self.monitor_gid):
            raise RuntimeError("disposable identity is privileged")

        run = self.base / "run"
        self.installed, self.control, self.attacker = run / "remozio", run / "control", run / "attacker"
        write_root_file(self.installed, self.frontend_bytes, 0o2755, self.gid)
        write_root_file(self.control, self.frontend_bytes, 0o755)
        write_root_file(self.attacker, builds["attacker"], 0o755)
        for name in MONITOR_BUILDS:
            write_root_file(run / name, builds[name], 0o755)
        self.operator_groups = [g for g in os.getgrouplist(self.operator.pw_name, self.operator.pw_gid)]
        members = grp.getgrgid(self.gid).gr_mem
        return {"frontendGroupHasNoMembers": members == [],
                "noAccountUsesFrontendGroupAsPrimary": all(entry.pw_gid != self.gid for entry in pwd.getpwall()),
                "operatorOutsideFrontendGroup": self.gid not in self.operator_groups,
                "installedImageExact": installed_exact(self.installed, self.gid, self.frontend_sha256),
                "frontendStaticNonPie": static_non_pie(self.installed)}

    def _create(self, flag, arguments, names):
        """The names must be free first; the attempt is recorded before the tool runs, so a
        timeout or cancellation part-way still leads cleanup to whatever the tool created."""
        if not all(_absent(pwd.getpwnam, name) and _absent(grp.getgrnam, name) for name in names):
            raise RuntimeError("disposable name already exists")
        setattr(self, flag, True)
        if run_owned(arguments, self.timeout)[0] != 0:
            raise RuntimeError("disposable account creation failed")

    def operator_options(self, extra_group=False):
        groups = self.operator_groups + ([self.gid] if extra_group else [])
        return {"user": self.operator.pw_uid, "group": self.operator.pw_gid, "extra_groups": groups,
                "env": {}, "cwd": "/", "umask": 0o077, "start_new_session": True}

    def seccomp_policy_sha256(self):
        code, output = run_owned([str(self.installed), "dump-filter"], self.timeout, **{
            key: value for key, value in self.operator_options().items() if key not in ("env", "cwd",
                                                                                         "start_new_session")})
        if code != 0 or not output or len(output) % 8:
            raise RuntimeError("filter dump failed")
        return hashlib.sha256(output).hexdigest()

    def replace_installed(self):
        """n8: a fresh inode at the installed path; the attacker still holds the old one."""
        upcoming = self.base / "run" / "remozio.next"
        write_root_file(upcoming, self.frontend_bytes, 0o2755, self.gid)
        os.replace(upcoming, self.installed)

    def run_case(self, case):
        spec = CASES[case]
        path = self.base / "s" / f"{case}.sock"
        listener = make_listener(path, self.gid)
        monitor = attacker = None
        deadline = time.monotonic() + self.timeout
        monitor_raw = monitor_rc = queued = None
        error = None
        try:
            if spec["monitorMode"]:
                monitor = subprocess.Popen(
                    [str(self.base / "run" / spec["monitorBinary"]), spec["monitorMode"], str(listener.fileno()), str(self.gid),
                     str(self.installed), str(self.monitor_uid), str(self.monitor_gid), self.fixture_seconds],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    pass_fds=(listener.fileno(),), env={}, cwd="/", start_new_session=True)
            attacker = subprocess.Popen(
                [str(self.attacker), spec["argument"], str(self.installed), str(self.control), str(path), str(self.gid),
                 self.fixture_seconds],
                stdin=subprocess.PIPE if case == "n8" else subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, **self.operator_options(spec["member"]))
            if case == "n8":
                if _read_exact(attacker, deadline, 2) != b"R\n":
                    raise ValueError("unexpected handshake")
                self.replace_installed()
                attacker.stdin.write(b"g")
                attacker.stdin.close()
                attacker.stdin = None
            attacker_raw = _read_output(attacker, deadline)
            if monitor is not None:
                monitor_raw = _read_output(monitor, deadline)
                monitor_rc = monitor.returncode
            else:
                queued = connection_queued(listener)
        except subprocess.TimeoutExpired:
            error = "TimeoutError"
        except OutputLimitError:
            error = "OutputLimitError"
        except (ValueError, OSError):
            error = "CaseFailure"
        finally:
            attacker_clean, monitor_clean = _retire(attacker), _retire(monitor)
            clean = attacker_clean and monitor_clean
            listener.close()
            path.unlink(missing_ok=True)
        result = {"passed": False, "error_type": error} if error else evaluate_case(
            case, attacker_raw, attacker.returncode, monitor_raw, monitor_rc, queued)
        result["cleanupReapedAllFixtureProcesses"] = clean
        result["passed"] = result["passed"] and clean
        return result

    def cleanup(self):
        """Processes are already reaped per case; remove files, then the user, then the group.
        Each step runs even when an earlier one fails; only state this run created is touched."""
        if self.base_created:
            _attempt(shutil.rmtree, self.base)
        if self.monitor_created and not _absent(pwd.getpwnam, self.monitor_name):
            _attempt(run_owned, ["userdel", self.monitor_name], self.timeout)
        if self.monitor_created and not _absent(grp.getgrnam, self.monitor_name):
            _attempt(run_owned, ["groupdel", self.monitor_name], self.timeout)
        if self.group_created and not _absent(grp.getgrnam, self.group_name):
            _attempt(run_owned, ["groupdel", self.group_name], self.timeout)
        return {"filesRemoved": not self.base.exists(),
                "monitorUserRemoved": _absent(pwd.getpwnam, self.monitor_name)
                and _absent(grp.getgrnam, self.monitor_name),
                "frontendGroupRemoved": _absent(grp.getgrnam, self.group_name)}


def _attempt(action, *arguments):
    try:
        action(*arguments)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        pass


def _absent(lookup, name):
    try:
        lookup(name)
    except KeyError:
        return True
    return False


def operator_account():
    """The account that ran sudo; the attacks run as that ordinary user."""
    try:
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    except (KeyError, ValueError):
        raise RuntimeError("run through sudo from the operator's session") from None
    account = pwd.getpwuid(uid)
    if uid == 0 or gid == 0 or account.pw_gid != gid:
        raise RuntimeError("operator must be an ordinary account")
    return account


def measure(timeout=15):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("requires Linux x86_64")
    if os.geteuid() != 0 or os.getuid() != 0:
        raise RuntimeError("requires root")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 5 <= timeout <= 60:
        raise ValueError("timeout must be at least 5 and at most 60 seconds")
    operator = operator_account()
    if not root_owned_ancestry(BASE_PARENT) or os.statvfs(BASE_PARENT).f_flag & os.ST_NOSUID:
        raise RuntimeError("experiment parent must be root-owned and allow set-ID execution")
    host = host_metadata()
    run = Run(operator, timeout)
    with subreaper():
        try:
            setup = run.setup()
            # A failed setup check (a group member, a wrong image, a dynamic executable) means the
            # cases would not measure the design, so none starts.
            policy, cases = "not-measured", {}
            if all(setup.values()):
                policy = run.seccomp_policy_sha256()
                cases = {case: run.run_case(case) for case in CASES}
        finally:
            cleanup = run.cleanup()
            if not all(cleanup.values()):
                sys.stderr.write(f"Disposable state not fully removed: inspect {BASE_PARENT}/{BASE_PREFIX}* and the "
                                 "rmzpl*/rmzpm* system accounts.\n")
    passed = (all(setup.values()) and all(cleanup.values()) and set(cases) == set(CASES)
              and all(item["passed"] for item in cases.values()))
    return {"experiment": "linux-protected-launch-v1",
            "measuredAtUTC": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "supervised": True, "trustedCode": False, "productionAdmission": False,
            "host": host, "sources": source_hashes(), "seccompPolicySha256": policy,
            "installedImageSha256": getattr(run, "frontend_sha256", "not-measured"),
            "setup": setup, "cases": cases, "cleanup": cleanup, "passed": passed,
            "limits": ["C measurement fixture, not the production frontend",
                       "the monitor is not confined beyond its capability set",
                       "no stopped handoff, executor, installed services, packaging, TPM or phone approval",
                       "one host, one kernel; set-ID exec semantics are pinned to the recorded version"]}


def _cancel(_signum, _frame):
    raise KeyboardInterrupt()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--timeout", type=float, default=15, help="seconds per case (5 <= timeout <= 60)")
    args = parser.parse_args()
    previous = {number: signal.signal(number, _cancel) for number in (signal.SIGTERM, signal.SIGHUP)}
    try:
        try:
            report = measure(args.timeout)
        except KeyboardInterrupt:
            parser.exit(130, "Protected launch experiment cancelled.\n")
        except (RuntimeError, ValueError, OSError, KeyError, subprocess.SubprocessError):
            parser.exit(2, "Protected launch experiment unavailable; no raw diagnostic data published.\n")
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
