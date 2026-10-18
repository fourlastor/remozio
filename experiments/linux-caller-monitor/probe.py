#!/usr/bin/env python3
"""Owned-process monitoring mechanics, never protected-code or production admission."""
import array
import ctypes
import hashlib
import json
import os
import platform
import select
import signal
import socket
import struct
import sys
import time

TIMEOUT = 3.0
WALL = 0x40000000
SO_PASSPIDFD, SCM_PIDFD = 76, 4
TRACEME, CONT, GETREGS, SETOPTIONS, GETEVENTMSG = 0, 7, 12, 0x4200, 0x4201
EVENT_FORK, EVENT_VFORK, EVENT_CLONE, EVENT_EXEC, EVENT_EXIT = 1, 2, 3, 4, 6
OPTIONS = sum(1 << event for event in (EVENT_FORK, EVENT_VFORK, EVENT_CLONE, EVENT_EXEC, EVENT_EXIT)) | (1 << 20)
CASES = ("healthy", "same-path-exec", "fork", "vfork", "thread-clone", "sender-mismatch", "caller-exit",
         "stop-release", "bad-ack", "duplicate-ack", "monitor-failure", "memory-modification")
EVENT_CASES = {"same-path-exec": (EVENT_EXEC, "exec", "same_path_second_exec_observed"),
               "fork": (EVENT_FORK, "task", "fork_event_observed"),
               "vfork": (EVENT_VFORK, "task", "vfork_event_observed"),
               "thread-clone": (EVENT_CLONE, "task", "clone_event_observed"),
               "caller-exit": (EVENT_EXIT, "exit", "exit_event_observed")}
REASONS = {"healthy": "held_stop", "sender-mismatch": "sender_mismatch", "stop-release": "stop_released",
           "bad-ack": "bad_ack", "duplicate-ack": "duplicate_ack", "monitor-failure": "monitor_loss",
           "memory-modification": "code_mutation", **{case: values[1] for case, values in EVENT_CASES.items()}}
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]


def ptrace(request, pid, data=0):
    if libc.ptrace(request, pid, None, ctypes.c_void_p(data)) == -1:
        raise OSError(ctypes.get_errno(), "ptrace")


def pidfd_open(pid):
    result = libc.pidfd_open(ctypes.c_int(pid), ctypes.c_uint(0))
    if result == -1:
        raise OSError(ctypes.get_errno(), "pidfd")
    return result


def poll_exit(fd, timeout=0):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    return any(flags & select.POLLIN for _, flags in poller.poll(int(timeout * 1000)))


def pidfd_pid(fd):
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as source:
        for line in source:
            if line.startswith("Pid:"):
                return int(line.split(":", 1)[1])
    raise ValueError("pidfd metadata")


def status(pid):
    result = {}
    with open(f"/proc/{pid}/status", encoding="ascii") as source:
        for line in source:
            if line.startswith(("State:", "TracerPid:")):
                key, value = line.split(":", 1)
                result[key] = value.split()[0]
    return result


def send(channel, value, fds=()):
    data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")
    if len(data) > 4096:
        raise ValueError("frame size")
    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))] if fds else []
    if channel.sendmsg([data], ancillary) != len(data):
        raise RuntimeError("short frame")


def receive(channel, descriptor_count=0):
    """Close every imported descriptor on malformed ancillary data or JSON."""
    imported = []
    try:
        data, ancillary, flags, _ = channel.recvmsg(4096, 256, socket.MSG_CMSG_CLOEXEC)
        for level, kind, value in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise ValueError("unexpected ancillary")
            descriptors = array.array("i")
            descriptors.frombytes(value[:len(value) - len(value) % descriptors.itemsize])
            imported.extend(descriptors)
            if len(value) % descriptors.itemsize:
                raise ValueError("descriptor size")
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(imported) != descriptor_count:
            raise ValueError("frame descriptors")
        value = json.loads(data)
        if type(value) is not dict:
            raise ValueError("frame shape")
        return value, imported
    except BaseException:
        for descriptor in imported:
            os.close(descriptor)
        raise


def wait(pid, flags=0):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        got, value = os.waitpid(pid, os.WNOHANG | WALL | flags)
        if got:
            return got, value
        time.sleep(0.002)
    raise TimeoutError("wait")


def close_except(retained):
    # The launcher passes only its designated socket, never monitor/executor endpoints.
    for value in os.listdir("/proc/self/fd"):
        descriptor = int(value)
        if descriptor > 2 and descriptor not in retained:
            try:
                os.close(descriptor)
            except OSError:
                pass
    null = os.open("/dev/null", os.O_RDWR)
    for descriptor in range(3):
        os.dup2(null, descriptor)
    if null > 2:
        os.close(null)


def cleanup_children(traced=()):
    """This worker is a subreaper; signal only children waitpid proves it owns."""
    deadline = time.monotonic() + TIMEOUT
    # Enumerating own children also finds stopped tracees adopted after monitor loss.
    while time.monotonic() < deadline:
        try:
            got, value = os.waitpid(-1, WALL | os.WNOHANG)
        except ChildProcessError:
            return True
        if got:
            if os.WIFSTOPPED(value):
                try:
                    ptrace(CONT, got, signal.SIGKILL)
                except OSError:
                    os.kill(got, signal.SIGKILL)
            continue
        with open(f"/proc/self/task/{os.getpid()}/children", encoding="ascii") as source:
            children = set(int(value) for value in source.read().split()) | set(traced)
        for child in children:
            try:
                child_id, child_status = os.waitpid(child, WALL | os.WNOHANG)
            except ChildProcessError:
                continue
            if child_id and (os.WIFEXITED(child_status) or os.WIFSIGNALED(child_status)):
                continue
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # A consumed ptrace event stop (especially TRACEEXIT) still needs
            # continuation. Fork/clone tracees need not be our natural children.
            try:
                ptrace(CONT, child, signal.SIGKILL)
            except OSError:
                pass
        time.sleep(0.002)
    return False


class Monitor:
    def __init__(self, case, binary):
        self.case, self.binary = case, binary
        self.pid = None
        self.pidfd = None
        self.checks = {}
        self.reason = "held_stop"
        self.generation = 0
        self.stop_owned = False
        self.events = 0
        self.execs = 0
        self.message_fds = []
        self.tasks = set()

    def event(self, pid, value):
        self.events += 1
        if pid != self.pid:
            self.reason = "task"
            return
        self.stop_owned = os.WIFSTOPPED(value)
        if os.WIFEXITED(value) or os.WIFSIGNALED(value):
            self.reason = "exit"
            return
        event = value >> 16
        if event == EVENT_EXEC:
            self.execs += 1
            if self.execs > 1:
                self.reason = "exec"
        elif event in (EVENT_FORK, EVENT_VFORK, EVENT_CLONE):
            self.reason = "task"
            new_task = ctypes.c_ulong()
            ptrace(GETEVENTMSG, self.pid, ctypes.addressof(new_task))
            self.tasks.add(new_task.value)
        elif event == EVENT_EXIT:
            self.reason = "exit"
        if event and self.execs:
            self.generation += 1

    def confirm_stop(self):
        if not self.stop_owned or poll_exit(self.pidfd):
            return False
        registers = (ctypes.c_ulonglong * 27)()
        ptrace(GETREGS, self.pid, ctypes.addressof(registers))
        observation = status(self.pid)
        return observation.get("State") == "t" and observation.get("TracerPid") == str(os.getpid())

    def drain(self):
        while True:
            try:
                child, value = os.waitpid(-1, WALL | os.WNOHANG)
            except ChildProcessError:
                return
            if not child:
                return
            self.event(child, value)

    def resume(self):
        ptrace(CONT, self.pid)
        self.stop_owned = False
        self.generation += 1

    def kernel_message(self, channel):
        data, ancillary, flags, _ = channel.recvmsg(64, 256, socket.MSG_CMSG_CLOEXEC)
        credentials, pidfds = [], []
        try:
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind in (SCM_PIDFD, socket.SCM_RIGHTS):
                    descriptors = array.array("i")
                    descriptors.frombytes(value[:len(value) - len(value) % descriptors.itemsize])
                    self.message_fds.extend(descriptors)
                    if kind != SCM_PIDFD or len(value) != descriptors.itemsize:
                        raise ValueError("message pidfd")
                    pidfds.extend(descriptors)
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                    credentials.append(struct.unpack("3i", value))
                else:
                    raise ValueError("message ancillary")
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or data != b"request" or len(pidfds) != 1 or len(credentials) != 1:
                raise ValueError("kernel identity frame")
            observed_pid = pidfd_pid(pidfds[0])
            if observed_pid != credentials[0][0]:
                raise ValueError("kernel identity discrepancy")
            matched = observed_pid == self.pid and credentials[0][1:] == (os.getuid(), os.getgid())
            self.checks["kernel_message_identity_received"] = True
            self.checks["kernel_sender_matches_admitted_process" if matched else "kernel_sender_mismatch_observed"] = matched or observed_pid != self.pid
            if not matched:
                self.reason = "sender_mismatch"
                self.checks["binding_invalidated"] = True
        except BaseException:
            for descriptor in self.message_fds:
                os.close(descriptor)
            self.message_fds.clear()
            raise

    def launch(self):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        receiver.settimeout(TIMEOUT)
        receiver.setsockopt(socket.SOL_SOCKET, SO_PASSPIDFD, 1)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        try:
            self.pid = os.fork()
            if self.pid == 0:
                try:
                    channel = sender.fileno()
                    close_except({channel})
                    os.set_inheritable(channel, True)
                    if self.case != "memory-modification":
                        ptrace(TRACEME, 0)
                        os.kill(os.getpid(), signal.SIGSTOP)
                    os.execve(self.binary, [self.binary, self.case, str(channel)], {"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
                except BaseException:
                    os._exit(1)
            _, value = wait(self.pid)
            if not os.WIFSTOPPED(value) or os.WSTOPSIG(value) != signal.SIGSTOP:
                raise RuntimeError("bootstrap stop")
            self.stop_owned = True
            self.tasks.add(self.pid)
            self.pidfd = pidfd_open(self.pid)
            ptrace(SETOPTIONS, self.pid, OPTIONS)
            if self.case == "memory-modification":
                self.memory_control(receiver)
                return
            self.checks.update(pre_exec_stop_observed=True,
                               pidfd_retained_before_approved_exec=not poll_exit(self.pidfd) and pidfd_pid(self.pidfd) == self.pid and self.execs == 0,
                               monitor_options_set_before_exec=True)
            self.resume()
            child, value = wait(self.pid)
            self.event(child, value)
            first_exec = os.WIFSTOPPED(value) and value >> 16 == EVENT_EXEC and self.execs == 1
            self.checks["first_exec_matches_fixture"] = (first_exec and os.path.samefile(f"/proc/{self.pid}/exe", self.binary) and
                                                          len(os.listdir(f"/proc/{self.pid}/task")) == 1)
            if not self.checks["first_exec_matches_fixture"]:
                raise RuntimeError("first exec")
            if self.case == "sender-mismatch":
                # An independently launched harness child, not a new admitted-process task.
                helper = os.fork()
                if helper == 0:
                    try:
                        channel = sender.fileno()
                        close_except({channel})
                        sender.sendall(b"request")
                        while True:
                            signal.pause()
                    except BaseException:
                        os._exit(1)
            sender.close()
            self.resume()
            child, value = wait(self.pid)
            self.event(child, value)
            self.checks["initial_request_stop_observed"] = os.WIFSTOPPED(value) and value >> 16 == 0 and os.WSTOPSIG(value) == signal.SIGSTOP and self.confirm_stop()
            self.kernel_message(receiver)
            self.checks["monitor_observed_wait_events"] = self.events >= 2
        finally:
            receiver.close()
            sender.close()

    def memory_control(self, channel):
        imported = []
        try:
            data, ancillary, flags, _ = channel.recvmsg(8, 256, socket.MSG_CMSG_CLOEXEC)
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, SCM_PIDFD):
                    descriptors = array.array("i")
                    descriptors.frombytes(value[:len(value) - len(value) % descriptors.itemsize])
                    self.message_fds.extend(descriptors)
                    if kind == socket.SCM_RIGHTS:
                        imported.extend(descriptors)
                elif level != socket.SOL_SOCKET or kind != socket.SCM_CREDENTIALS:
                    raise ValueError("memory ancillary")
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(data) != 8 or len(imported) != 1:
                raise ValueError("memory descriptor")
            address = struct.unpack("=Q", data)[0]
            executable_mapping = False
            with open(f"/proc/{self.pid}/maps", encoding="utf-8") as mappings:
                for line in mappings:
                    fields = line.split()
                    first, last = (int(part, 16) for part in fields[0].split("-"))
                    if first <= address < last:
                        executable_mapping = "x" in fields[1] and len(fields) >= 6 and os.path.samefile(fields[5], self.binary)
                        break
            if not executable_mapping:
                raise RuntimeError("not fixture executable mapping")
            with open(self.binary, "rb") as source:
                before_hash = hashlib.sha256(source.read()).digest()
            memory = imported[0]
            original = os.pread(memory, 1, address)
            if len(original) != 1:
                raise RuntimeError("memory read")
            changed = bytes([original[0] ^ 1])
            writer_parent, writer_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            writer_parent.settimeout(TIMEOUT)
            writer_child.settimeout(TIMEOUT)
            try:
                writer = os.fork()
                if writer == 0:
                    try:
                        close_except({memory, writer_child.fileno()})
                        written = os.pwrite(memory, changed, address)
                        send(writer_child, {"written": written, "uid": os.getuid()})
                        command, _ = receive(writer_child)
                        if command != {"phase": "restore"}:
                            os._exit(1)
                        send(writer_child, {"restored": os.pwrite(memory, original, address) == 1})
                        os._exit(0)
                    except BaseException:
                        os._exit(1)
                writer_child.close()
                mutation, _ = receive(writer_parent)
                # The writer is a separate same-UID process, never this caller's tracer.
                independent_writer = (writer != int(status(self.pid)["TracerPid"]) and
                                      status(writer).get("TracerPid") == "0" and mutation.get("uid") == os.getuid())
                changed_observed = os.pread(memory, 1, address) == changed and self.confirm_stop()
                send(writer_parent, {"phase": "restore"})
                restoration, _ = receive(writer_parent)
                _, writer_status = wait(writer)
                restored = restoration.get("restored") is True and os.pread(memory, 1, address) == original
                written = mutation.get("written") == 1 and independent_writer and os.WIFEXITED(writer_status) and os.WEXITSTATUS(writer_status) == 0
            finally:
                writer_parent.close()
                writer_child.close()
            with open(self.binary, "rb") as source:
                backing_unchanged = hashlib.sha256(source.read()).digest() == before_hash
            self.checks.update(pretrace_memory_descriptor_received=True,
                               bootstrap_ptrace_stop_observed=self.confirm_stop(),
                               retained_memory_write_succeeded=written and restored,
                               executable_mapping_bytes_changed=changed_observed,
                               executable_backing_bytes_unchanged=backing_unchanged)
            self.reason = "code_mutation"
        except BaseException:
            # All descriptors, including automatically supplied pidfds, belong to the monitor.
            raise

    def advance(self):
        if self.case in EVENT_CASES:
            self.resume()
            child, value = wait(self.pid)
            self.event(child, value)
            expected_event, reason, key = EVENT_CASES[self.case]
            observed = os.WIFSTOPPED(value) and value >> 16 == expected_event
            self.checks[key] = observed
            if self.case == "same-path-exec":
                self.checks[key] = observed and self.execs == 2 and os.path.samefile(f"/proc/{self.pid}/exe", self.binary)
            self.checks["event_between_prepare_and_final_observed"] = observed
            self.checks["binding_invalidated"] = observed and self.reason == reason
            if self.case == "caller-exit":
                self.resume()
                child, exited = wait(self.pid)
                self.event(child, exited)
                if not os.WIFEXITED(exited) or os.WEXITSTATUS(exited) != 0:
                    raise RuntimeError("caller exit")
        elif self.case == "stop-release":
            self.resume()
            self.reason = "stop_released"
            self.checks["caller_stop_released_before_final"] = not self.stop_owned
        self.drain()


class AcknowledgmentLease:
    """One prepared generation can consume precisely one matching acknowledgment."""
    def __init__(self, nonce, binding, generation):
        self.expected = {"phase": "ack", "nonce": nonce, "binding": binding, "generation": generation}
        self.pending = True

    def accept(self, value):
        if not self.pending or value != self.expected:
            self.pending = False
            return False
        self.pending = False
        return True


def run_monitor(case, binary, control, handshake):
    monitor = Monitor(case, binary)
    own_pidfd = None
    try:
        monitor.launch()
        challenge, _ = receive(handshake)
        nonce = challenge["nonce"]
        binding = os.urandom(16).hex()
        own_pidfd = pidfd_open(os.getpid())
        prepared_generation = monitor.generation
        send(handshake, {"phase": "prepare", "nonce": nonce, "binding": binding,
                         "monitor": os.getpid(), "caller": monitor.pid, "generation": prepared_generation,
                         "reason": monitor.reason, "stopConfirmed": monitor.confirm_stop()}, [monitor.pidfd, own_pidfd])
        ack, _ = receive(handshake)
        lease = AcknowledgmentLease(nonce, binding, prepared_generation)
        ack_valid = lease.accept(ack)
        if not ack_valid:
            monitor.reason = "bad_ack"
            monitor.checks["invalid_ack_rejected"] = True
        duplicate_rejected = False
        # Every case uses the same one-use receiver. Only the executor fixture
        # chooses whether to inject a second ACK before closing this bounded batch.
        following, _ = receive(handshake)
        complete = {"phase": "ack-complete", "nonce": nonce, "binding": binding}
        if following != complete:
            duplicate_rejected = not lease.accept(following)
            monitor.reason = "duplicate_ack" if following == ack else "bad_ack"
            monitor.checks["invalid_ack_rejected"] = ack_valid and following == ack and duplicate_rejected
            end, _ = receive(handshake)
            if end != complete:
                raise ValueError("ack batch")
        send(handshake, {"phase": "ack-result", "valid": ack_valid and not duplicate_rejected, "reason": monitor.reason})
        send(control, {"phase": "prepared", "caller": monitor.pid}, [monitor.pidfd])
        command, _ = receive(control)
        if command != {"phase": "advance"}:
            raise ValueError("advance")
        monitor.advance()
        confirmed = monitor.confirm_stop() if monitor.reason != "exit" else False
        # Final status drain and a consumed stop belong to this tracer. Nothing after
        # this send resumes the caller; the supervisor freezes this monitor next.
        send(handshake, {"phase": "final-state", "nonce": nonce, "binding": binding,
                         "generation": monitor.generation, "reason": monitor.reason,
                         "stopConfirmed": confirmed})
        checks = monitor.checks.copy()
        if case == "healthy":
            checks["prepare_ack_nonce_bound"] = ack_valid and prepared_generation == monitor.generation
        send(control, {"phase": "handoff", "checks": checks})
        command, _ = receive(control)
        if command != {"phase": "finish"}:
            raise ValueError("finish")
    finally:
        for descriptor in monitor.message_fds:
            os.close(descriptor)
        if monitor.pidfd is not None:
            os.close(monitor.pidfd)
        if own_pidfd is not None:
            os.close(own_pidfd)
        if not cleanup_children(monitor.tasks):
            raise TimeoutError("monitor cleanup")


def run_executor(case, control, handshake):
    descriptors = []
    try:
        nonce = os.urandom(32).hex()
        send(handshake, {"phase": "challenge", "nonce": nonce})
        prepared, descriptors = receive(handshake, 2)
        if prepared.get("phase") != "prepare" or prepared.get("nonce") != nonce:
            raise ValueError("prepare")
        caller_fd, monitor_fd = descriptors
        if pidfd_pid(caller_fd) != prepared["caller"] or pidfd_pid(monitor_fd) != prepared["monitor"]:
            raise ValueError("prepare process binding")
        ack = {"phase": "ack", "nonce": nonce, "binding": prepared["binding"], "generation": prepared["generation"]}
        send(handshake, {**ack, "nonce": "0" * 64} if case == "bad-ack" else ack)
        if case == "duplicate-ack":
            send(handshake, ack)
        send(handshake, {"phase": "ack-complete", "nonce": nonce, "binding": prepared["binding"]})
        acknowledged, _ = receive(handshake)
        if acknowledged.get("phase") != "ack-result":
            raise ValueError("ack result")
        send(control, {"phase": "prepared"})
        command, _ = receive(control)
        if command != {"phase": "final"}:
            raise ValueError("final")
        final, _ = receive(handshake)
        # A frozen monitor cannot release its tracee while this executor checks the
        # handoff. Acceptance records this one instant, never a future guarantee.
        monitor_lost = poll_exit(monitor_fd)
        readable = select.select([handshake], [], [], 0)[0]
        if readable and handshake.recv(1, socket.MSG_PEEK) == b"":
            monitor_lost = True
        frozen = stopped = False
        if not monitor_lost:
            monitor_state = status(prepared["monitor"])
            frozen = monitor_state.get("State") == "T"
            if not poll_exit(caller_fd):
                caller_state = status(prepared["caller"])
                stopped = caller_state.get("State") == "t" and caller_state.get("TracerPid") == str(prepared["monitor"])
        valid_final = final.get("phase") == "final-state" and final.get("nonce") == nonce and final.get("binding") == prepared["binding"]
        same_generation = final.get("generation") == prepared["generation"]
        reason = final.get("reason")
        if monitor_lost:
            reason = "monitor_loss"
        elif reason == "held_stop" and (not frozen or not stopped or final.get("stopConfirmed") is not True):
            reason = "stop_released"
        accepted = (valid_final and same_generation and acknowledged.get("valid") is True and
                    prepared.get("stopConfirmed") is True and final.get("stopConfirmed") is True and
                    reason == "held_stop" and frozen and stopped and not monitor_lost)
        send(control, {"phase": "result", "accepted": accepted, "reason": reason,
                       "monitorFrozen": frozen, "callerStopped": stopped, "monitorLost": monitor_lost})
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def execute_child(operation, channels):
    try:
        operation()
        code = 0
    except BaseException:
        code = 1
    for channel in channels:
        channel.close()
    os._exit(code)


def measure(case, binary):
    if (case not in CASES or platform.system() != "Linux" or platform.machine() != "x86_64" or
            sys.version_info < (3, 11) or os.geteuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid()):
        raise ValueError("unsupported invocation")
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "subreaper")
    monitor_parent, monitor_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    executor_parent, executor_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    monitor_handshake, executor_handshake = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sockets = (monitor_parent, monitor_control, executor_parent, executor_control, monitor_handshake, executor_handshake)
    for channel in sockets:
        channel.settimeout(TIMEOUT)
    caller_fd = None
    monitor = executor = None
    checks = {}
    try:
        executor = os.fork()
        if executor == 0:
            for channel in (monitor_parent, monitor_control, executor_parent, monitor_handshake):
                channel.close()
            execute_child(lambda: run_executor(case, executor_control, executor_handshake), (executor_control, executor_handshake))
        monitor = os.fork()
        if monitor == 0:
            for channel in (monitor_parent, executor_parent, executor_control, executor_handshake):
                channel.close()
            execute_child(lambda: run_monitor(case, binary, monitor_control, monitor_handshake), (monitor_control, monitor_handshake))
        for channel in (monitor_control, executor_control, monitor_handshake, executor_handshake):
            channel.close()
        prepared, imported = receive(monitor_parent, 1)
        caller_fd = imported[0]
        if prepared.get("phase") != "prepared":
            raise ValueError("monitor prepared")
        executor_ready, _ = receive(executor_parent)
        if executor_ready != {"phase": "prepared"}:
            raise ValueError("executor prepared")
        send(monitor_parent, {"phase": "advance"})
        handoff, _ = receive(monitor_parent)
        if handoff.get("phase") != "handoff":
            raise ValueError("handoff")
        checks.update(handoff["checks"])
        os.kill(monitor, signal.SIGSTOP)
        _, stopped_monitor = wait(monitor, os.WUNTRACED)
        monitor_frozen = os.WIFSTOPPED(stopped_monitor) and os.WSTOPSIG(stopped_monitor) == signal.SIGSTOP
        if not monitor_frozen:
            raise RuntimeError("monitor freeze")
        if case == "monitor-failure":
            os.kill(monitor, signal.SIGKILL)
            _, dead_monitor = wait(monitor)
            monitor = None
            checks["monitor_killed_after_prepare"] = os.WIFSIGNALED(dead_monitor) and os.WTERMSIG(dead_monitor) == signal.SIGKILL
            checks["exitkill_caller_exit_observed"] = poll_exit(caller_fd, TIMEOUT)
        send(executor_parent, {"phase": "final"})
        result, _ = receive(executor_parent)
        checks["executor_result_received"] = result.get("phase") == "result"
        if case == "healthy":
            checks.update(monitor_frozen_at_final_check=result["monitorFrozen"],
                          caller_ptrace_stop_confirmed_at_final=result["callerStopped"],
                          simulated_acceptance_observed=result["accepted"])
        else:
            checks["simulated_rejection_observed"] = result.get("accepted") is False and result.get("reason") == REASONS[case]
        if case == "stop-release":
            checks["executor_detected_missing_stop"] = result.get("callerStopped") is False
        if case == "monitor-failure":
            checks["executor_observed_monitor_loss"] = result.get("monitorLost") is True
        if monitor is not None:
            os.kill(monitor, signal.SIGCONT)
            send(monitor_parent, {"phase": "finish"})
            _, value = wait(monitor)
            if not os.WIFEXITED(value) or os.WEXITSTATUS(value) != 0:
                raise RuntimeError("monitor exit")
            monitor = None
        _, value = wait(executor)
        if not os.WIFEXITED(value) or os.WEXITSTATUS(value) != 0:
            raise RuntimeError("executor exit")
        executor = None
        checks["all_owned_children_reaped"] = cleanup_children()
        return {"passed": bool(checks) and all(value is True for value in checks.values()), "checks": checks,
                "observations": {"trustedCode": False, "productionAdmission": False,
                                 "authorization": "accepted" if result["accepted"] else "rejected", "reason": result["reason"]}}
    finally:
        for channel in sockets:
            channel.close()
        if caller_fd is not None:
            os.close(caller_fd)
        if not cleanup_children():
            raise TimeoutError("probe cleanup")


def main():
    try:
        if len(sys.argv) != 4 or not os.path.isdir(sys.argv[2]):
            raise ValueError("arguments")
        result = measure(sys.argv[1], os.path.abspath(sys.argv[3]))
    except BaseException as error:
        # No raw exception messages, paths, identities, nonce or child stdout.
        result = {"passed": False, "error_type": type(error).__name__, "errno": getattr(error, "errno", None)}
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
