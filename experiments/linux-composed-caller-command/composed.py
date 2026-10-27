#!/usr/bin/env python3
"""Composed caller/command fixture worker: supervisor R and ptrace monitor M for one case.

R owns the subreaper, pipes, sockets and fault injection. M traces the fixed frontend C,
receives its submission carrier and hands a retained bundle to the Swift owner A, which
alone consumes the decision and may spawn the fixed command. Never production admission.
"""
import array
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import signal
import socket
import struct
import subprocess
import sys
import time

PROBE = Path(__file__).resolve().parents[1] / "linux-caller-monitor/probe.py"
_spec = importlib.util.spec_from_file_location("remozio_monitor_probe", PROBE)
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)

TIMEOUT = probe.TIMEOUT
OWNER_TIMEOUT = 60.0
SUBMISSION = b"remozio-composed-submit-v1"
INPUT_LINE = b"remozio-composed-output\n"
BARRIERS = ("B0", "B1", "B3", "B4", "B4L")
# frontend: carrier mode; advance: probe Monitor case; barrier/inject: R's fault at a named point.
CASES = {
    "healthy-approve": {},
    "healthy-decline": {},
    "carrier-missing-stream": {"frontend": "missing-stream"},
    "carrier-extra-stream": {"frontend": "extra-stream"},
    "fork-before-final": {"frontend": "fork", "advance": "fork"},
    "stop-release": {"advance": "stop-release"},
    "grant-revoked-B0": {"barrier": "B0", "inject": "grant-revoked"},
    "monitor-death-B1": {"barrier": "B1", "inject": "kill-monitor"},
    "monitor-death-B3": {"barrier": "B3", "inject": "kill-monitor"},
    "grant-changed-B3": {"barrier": "B3", "inject": "grant-changed"},
    "command-changed-B3": {"barrier": "B3", "inject": "command-changed"},
    "cwd-replaced-B3": {"barrier": "B3", "inject": "cwd-replaced"},
    "stream-flags-B3": {"barrier": "B3", "inject": "stream-nonblock"},
    "monitor-death-B4": {"barrier": "B4", "inject": "kill-monitor"},
    "dispatch-race-limitation": {"barrier": "B4L", "inject": "kill-monitor"},
}


def close_all_except(keep):
    for value in os.listdir("/proc/self/fd"):
        descriptor = int(value)
        if descriptor not in keep:
            try:
                os.close(descriptor)
            except OSError:
                pass


class CarrierMonitor(probe.Monitor):
    """Probe event handling; launch keeps real stdio/cwd and the carrier requires three streams."""

    def __init__(self, case, binary, frontend_mode, directory, stdio):
        super().__init__(case, binary)
        self.frontend_mode, self.directory, self.stdio = frontend_mode, directory, stdio
        self.sender = None
        self.streams = []

    def launch_carrier(self):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        receiver.settimeout(TIMEOUT)
        receiver.setsockopt(socket.SOL_SOCKET, probe.SO_PASSPIDFD, 1)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        try:
            self.pid = os.fork()
            if self.pid == 0:
                try:
                    for target, source in enumerate(self.stdio):
                        os.dup2(source, target)
                    channel = os.dup2(sender.fileno(), 3)
                    close_all_except({0, 1, 2, channel})
                    os.set_inheritable(channel, True)
                    os.chdir(self.directory)
                    probe.ptrace(probe.TRACEME, 0)
                    os.kill(os.getpid(), signal.SIGSTOP)
                    os.execve(self.binary, [self.binary, self.frontend_mode, str(channel)],
                              {"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
                except BaseException:
                    os._exit(1)
            for descriptor in self.stdio:
                os.close(descriptor)
            self.stdio = ()
            _, value = probe.wait(self.pid)
            if not os.WIFSTOPPED(value) or os.WSTOPSIG(value) != signal.SIGSTOP:
                raise RuntimeError("bootstrap stop")
            self.stop_owned = True
            self.tasks.add(self.pid)
            self.pidfd = probe.pidfd_open(self.pid)
            probe.ptrace(probe.SETOPTIONS, self.pid, probe.OPTIONS)
            self.resume()
            child, value = probe.wait(self.pid)
            self.event(child, value)
            if not (os.WIFSTOPPED(value) and value >> 16 == probe.EVENT_EXEC and self.execs == 1 and
                    os.path.samefile(f"/proc/{self.pid}/exe", self.binary) and
                    len(os.listdir(f"/proc/{self.pid}/task")) == 1):
                raise RuntimeError("first exec")
            sender.close()
            self.resume()
            child, value = probe.wait(self.pid)
            self.event(child, value)
            if not (os.WIFSTOPPED(value) and value >> 16 == 0 and os.WSTOPSIG(value) == signal.SIGSTOP and
                    self.confirm_stop()):
                raise RuntimeError("submission stop")
            return self.carrier(receiver)
        finally:
            receiver.close()
            sender.close()

    def carrier(self, channel):
        """Exactly one kernel pidfd, one credential record and three stream descriptors."""
        data, ancillary, flags, _ = channel.recvmsg(64, 512, socket.MSG_CMSG_CLOEXEC)
        pidfds, credentials, streams = [], [], []
        try:
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind in (probe.SCM_PIDFD, socket.SCM_RIGHTS):
                    descriptors = array.array("i")
                    descriptors.frombytes(value[:len(value) - len(value) % descriptors.itemsize])
                    (pidfds if kind == probe.SCM_PIDFD else streams).extend(descriptors)
                    if len(value) % descriptors.itemsize:
                        raise ValueError("descriptor size")
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                    credentials.append(struct.unpack("3i", value))
                else:
                    raise ValueError("carrier ancillary")
            if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or data != SUBMISSION or
                    len(pidfds) != 1 or len(credentials) != 1 or len(streams) != 3):
                raise ValueError("carrier shape")
            sender = probe.pidfd_pid(pidfds[0])
            if sender != credentials[0][0] or sender != self.pid or credentials[0][1:] != (os.getuid(), os.getgid()):
                raise ValueError("carrier sender")
            self.sender = {"pid": credentials[0][0], "uid": credentials[0][1], "gid": credentials[0][2]}
            self.streams = streams
            streams = []
        finally:
            for descriptor in pidfds + streams:
                os.close(descriptor)

    def retain_proc(self):
        # Opened while the retained caller is live, unreaped and in our ptrace stop.
        proc = os.open(f"/proc/{self.pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            executable = os.open("exe", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc)
            directory = os.open("cwd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=proc)
        except BaseException:
            os.close(proc)
            raise
        if probe.poll_exit(self.pidfd) or not self.confirm_stop():
            for descriptor in (proc, executable, directory):
                os.close(descriptor)
            raise RuntimeError("caller changed while retaining")
        return [proc, executable, directory]


def run_monitor(case, binary, directory, stdio, control, handshake):
    spec = CASES[case]
    monitor = CarrierMonitor(spec.get("advance", "healthy"), binary, spec.get("frontend", "submit"), directory, stdio)
    own_pidfd = None
    retained = []
    try:
        try:
            monitor.launch_carrier()
        except ValueError:
            probe.send(control, {"phase": "carrier-rejected"})
            return
        probe.send(control, {"phase": "launched", "caller": monitor.pid})
        retained = monitor.retain_proc()
        challenge, _ = probe.receive(handshake)
        if challenge.get("phase") != "challenge":
            raise ValueError("challenge")
        nonce, binding = challenge["nonce"], os.urandom(16).hex()
        own_pidfd = probe.pidfd_open(os.getpid())
        prepared_generation = monitor.generation
        bundle = [monitor.pidfd, own_pidfd, *retained, *monitor.streams]
        probe.send(handshake, {"phase": "prepare", "nonce": nonce, "binding": binding, "monitor": os.getpid(),
                               "caller": monitor.pid, "generation": prepared_generation, "execEpoch": monitor.execs,
                               "sender": monitor.sender, "stopConfirmed": monitor.confirm_stop()}, bundle)
        # The owner now holds the bundle; this monitor keeps only its trace and caller pidfd.
        for descriptor in retained + monitor.streams:
            os.close(descriptor)
        retained, monitor.streams = [], []
        ack, _ = probe.receive(handshake)
        lease = probe.AcknowledgmentLease(nonce, binding, prepared_generation)
        valid = lease.accept(ack)
        complete, _ = probe.receive(handshake)
        if complete != {"phase": "ack-complete", "nonce": nonce, "binding": binding}:
            valid = False
        probe.send(handshake, {"phase": "ack-result", "valid": valid})
        probe.send(control, {"phase": "prepared"})
        command, _ = probe.receive(control)
        if command != {"phase": "advance"}:
            raise ValueError("advance")
        monitor.advance()
        confirmed = monitor.confirm_stop() if monitor.reason != "exit" else False
        # Nothing after this resumes the caller; R freezes this monitor next.
        probe.send(handshake, {"phase": "final-state", "nonce": nonce, "binding": binding,
                               "generation": monitor.generation, "reason": monitor.reason, "stopConfirmed": confirmed})
        probe.send(control, {"phase": "handoff"})
        control.settimeout(OWNER_TIMEOUT)
        command, _ = probe.receive(control)
        if command != {"phase": "finish"}:
            raise ValueError("finish")
    finally:
        for descriptor in retained + monitor.streams + list(monitor.stdio):
            os.close(descriptor)
        if monitor.pidfd is not None:
            os.close(monitor.pidfd)
        if own_pidfd is not None:
            os.close(own_pidfd)
        if not probe.cleanup_children(monitor.tasks):
            raise TimeoutError("monitor cleanup")


class Supervisor:
    def __init__(self, case, workspace, frontend, owner):
        self.case, self.spec = case, CASES[case]
        self.workspace, self.frontend, self.owner = Path(workspace), frontend, owner
        self.monitor = self.owner_process = self.caller = None
        self.alternate_output = None

    def inject(self, name):
        if name != self.spec.get("barrier"):
            return
        fault = self.spec["inject"]
        if fault == "kill-monitor":
            os.kill(self.monitor, signal.SIGKILL)
            _, value = probe.wait(self.monitor)
            self.monitor = None
            if not os.WIFSIGNALED(value):
                raise RuntimeError("monitor kill")
            # EXITKILL ends the caller; this subreaper adopts and reaps it before continuing.
            deadline = time.monotonic() + TIMEOUT
            while True:
                try:
                    got, _ = os.waitpid(self.caller, probe.WALL | os.WNOHANG)
                except ChildProcessError:
                    break
                if got:
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError("caller exitkill")
                time.sleep(0.002)
        elif fault in ("grant-revoked", "grant-changed"):
            os.replace(self.workspace / f"{fault}.cbor", self.workspace / "grant.cbor")
        elif fault == "command-changed":
            with (self.workspace / "cmd/tee").open("ab") as stream:
                stream.write(b"\0")
        elif fault == "cwd-replaced":
            os.rename(self.workspace / "work", self.workspace / "work-replaced")
            os.mkdir(self.workspace / "work", 0o700)
        elif fault == "stream-nonblock":
            # Same open file description as the caller's stdout; flags are shared state.
            flags = fcntl.fcntl(self.alternate_output, fcntl.F_GETFL)
            fcntl.fcntl(self.alternate_output, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self.injected = fault

    def owner_messages(self, channel, stop):
        """Serve barriers until a message in `stop` arrives."""
        while True:
            message, _ = probe.receive(channel)
            if message.get("phase") == "barrier" and message.get("name") in BARRIERS:
                self.inject(message["name"])
                probe.send(channel, {"phase": "continue"})
                continue
            if message.get("phase") in stop:
                return message
            raise ValueError("owner message")

    def run(self):
        workspace = self.workspace
        input_read, input_write = os.pipe()
        output_read, output_write = os.pipe()
        error_read, error_write = os.pipe()
        os.write(input_write, INPUT_LINE)
        os.close(input_write)
        self.alternate_output = os.dup(output_write)
        monitor_parent, monitor_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        owner_parent, owner_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        monitor_handshake, owner_handshake = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        sockets = (monitor_parent, monitor_control, owner_parent, owner_control, monitor_handshake, owner_handshake)
        for channel in sockets:
            channel.settimeout(TIMEOUT)
        owner_parent.settimeout(OWNER_TIMEOUT)
        self.injected = None
        observations = {}
        try:
            stdio = (input_read, output_write, error_write)
            self.monitor = os.fork()
            if self.monitor == 0:
                for descriptor in (output_read, error_read, self.alternate_output):
                    os.close(descriptor)
                for channel in (monitor_parent, owner_parent, owner_control, owner_handshake):
                    channel.close()
                probe.execute_child(lambda: run_monitor(self.case, self.frontend, str(workspace / "work"), stdio,
                                                        monitor_control, monitor_handshake),
                                    (monitor_control, monitor_handshake))
            for descriptor in stdio:
                os.close(descriptor)
            output_write = None
            self.owner_process = subprocess.Popen(
                [self.owner, "run", self.case, str(workspace), str(owner_handshake.fileno()), str(owner_control.fileno())],
                pass_fds=(owner_handshake.fileno(), owner_control.fileno()), cwd=workspace, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"LANG": "C", "PATH": "/usr/bin:/bin"})
            for channel in (monitor_control, owner_control, monitor_handshake, owner_handshake):
                channel.close()
            launched, _ = probe.receive(monitor_parent)
            orderly = False
            if launched.get("phase") == "carrier-rejected":
                probe.send(owner_parent, {"phase": "abort"})
                result = self.owner_messages(owner_parent, {"result"})
                observations["carrierRejected"] = True
            else:
                if launched.get("phase") != "launched":
                    raise ValueError("monitor launch")
                self.caller = launched["caller"]
                probe.send(owner_parent, {"phase": "start"})
                captured = self.owner_messages(owner_parent, {"captured", "result"})
                if captured["phase"] == "result":
                    result = captured
                else:
                    prepared, _ = probe.receive(monitor_parent)
                    if prepared != {"phase": "prepared"}:
                        raise ValueError("monitor prepared")
                    probe.send(monitor_parent, {"phase": "advance"})
                    handoff, _ = probe.receive(monitor_parent)
                    if handoff != {"phase": "handoff"}:
                        raise ValueError("handoff")
                    os.kill(self.monitor, signal.SIGSTOP)
                    _, frozen = probe.wait(self.monitor, os.WUNTRACED)
                    if not os.WIFSTOPPED(frozen):
                        raise RuntimeError("monitor freeze")
                    probe.send(owner_parent, {"phase": "final"})
                    orderly = True
                    result = self.owner_messages(owner_parent, {"result"})
            self.owner_process.wait(timeout=TIMEOUT)
            observations["ownerExit"] = self.owner_process.returncode
            if self.monitor is not None:
                # An owner refusal before the final phase leaves the monitor mid-handshake: retire it.
                if orderly:
                    os.kill(self.monitor, signal.SIGCONT)
                    probe.send(monitor_parent, {"phase": "finish"})
                elif not observations.get("carrierRejected"):
                    os.kill(self.monitor, signal.SIGKILL)
                _, value = probe.wait(self.monitor)
                observations["monitorExit"] = os.WEXITSTATUS(value) if os.WIFEXITED(value) else -os.WTERMSIG(value)
                self.monitor = None
            marker = workspace / "work/command.marker"
            observations["markerLines"] = marker.read_bytes().count(b"\n") if marker.exists() else 0
            observations["markerExact"] = (not marker.exists()) or marker.read_bytes() in (b"", INPUT_LINE)
            readable = select.select([output_read], [], [], 0)[0]
            observations["outputBytes"] = len(os.read(output_read, 4096)) if readable else 0
            observations["injected"] = self.injected
            return result, observations
        finally:
            for channel in sockets:
                channel.close()
            for descriptor in (output_read, error_read, self.alternate_output, output_write):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
            if self.owner_process is not None and self.owner_process.poll() is None:
                self.owner_process.kill()
                self.owner_process.wait()
            observations["allOwnedChildrenReaped"] = probe.cleanup_children()


def measure(case, workspace, frontend, owner):
    if (case not in CASES or platform.system() != "Linux" or platform.machine() != "x86_64" or
            sys.version_info < (3, 11) or os.geteuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid()):
        raise ValueError("unsupported invocation")
    if probe.libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(probe.ctypes.get_errno(), "subreaper")
    result, observations = Supervisor(case, workspace, frontend, owner).run()
    return {"case": case, "owner": result, "supervisor": observations}


def main():
    try:
        if len(sys.argv) != 5:
            raise ValueError("arguments")
        report = measure(sys.argv[1], sys.argv[2], os.path.abspath(sys.argv[3]), os.path.abspath(sys.argv[4]))
    except BaseException as error:
        report = {"case": sys.argv[1] if len(sys.argv) > 1 else None, "error_type": type(error).__name__,
                  "errno": getattr(error, "errno", None)}
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if "error_type" not in report else 1


if __name__ == "__main__":
    raise SystemExit(main())
