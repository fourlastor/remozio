#!/usr/bin/env python3
"""Disposable Linux caller fixtures. Invoked by the bounded experiment runner."""
import array
import ctypes
import fcntl
import json
import os
import select
import signal
import socket
import struct
import sys
import tempfile
import time

# Linux UAPI: asm-generic/socket.h, bits/socket.h and linux/ptrace.h.
SO_PASSPIDFD, SO_PEERPIDFD, SCM_PIDFD = 76, 77, 4
PTRACE_TRACEME, PTRACE_CONT = 0, 7
PTRACE_SETOPTIONS, PTRACE_GETEVENTMSG = 0x4200, 0x4201
PTRACE_EVENT_EXEC = 4
PTRACE_O_TRACEEXEC, PTRACE_O_EXITKILL = 1 << 4, 1 << 20
PR_SET_CHILD_SUBREAPER = 36
TIMEOUT = 3
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]


def ptrace(request, pid, value=0):
    ctypes.set_errno(0)
    result = libc.ptrace(request, pid, None, ctypes.c_void_p(value))
    if result == -1:
        code = ctypes.get_errno()
        raise OSError(code, "ptrace failed")
    return result


def close(fd):
    if fd is not None:
        os.close(fd)


def pidfd_open(pid):
    # Some Python builds omit os.pidfd_open despite a capable host libc/kernel.
    result = libc.pidfd_open(ctypes.c_int(pid), ctypes.c_uint(0))
    if result == -1:
        raise OSError(ctypes.get_errno(), "pidfd_open failed")
    return result


def wait_child(child):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        waited, status = os.waitpid(child, os.WNOHANG)
        if waited:
            return status
        time.sleep(0.005)
    raise TimeoutError("child deadline")


def retire(child):
    if child is None:
        return
    # Error paths may already have reaped this child. Never signal a recycled PID.
    try:
        waited, status = os.waitpid(child, os.WNOHANG)
    except ChildProcessError:
        return
    if waited and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
        return
    # A still-owned live or stopped child retains its PID until we reap it.
    try:
        os.kill(child, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        wait_child(child)
    except ChildProcessError:
        pass


def pidfd_pid(fd):
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as source:
        for line in source:
            if line.startswith("Pid:"):
                return int(line.split(":", 1)[1])
    raise ValueError("missing pidfd metadata")


def ready(fd, timeout=0):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    return any(event & select.POLLIN for _, event in poller.poll(int(timeout * 1000)))


def receive(sock, owned):
    data, ancillary, flags, _ = sock.recvmsg(64, 256, socket.MSG_CMSG_CLOEXEC)
    pidfds, credentials = [], []
    for level, kind, value in ancillary:
        if level == socket.SOL_SOCKET and kind in (SCM_PIDFD, socket.SCM_RIGHTS):
            fds = array.array("i")
            fds.frombytes(value[:len(value) - len(value) % fds.itemsize])
            owned.extend(fds)
            if kind != SCM_PIDFD or len(value) != fds.itemsize:
                raise ValueError("unexpected descriptor framing")
            pidfds.extend(fds)
        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
            credentials.append(struct.unpack("3i", value))
        else:
            raise ValueError("unexpected ancillary metadata")
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(pidfds) != 1 or len(credentials) != 1:
        raise ValueError("missing or truncated identity metadata")
    return data, pidfds[0], credentials[0]


def ipc(transfer=False):
    """A connector sends directly, or passes its connected socket with SCM_RIGHTS."""
    children, owned = [], []
    peer = None
    with tempfile.TemporaryDirectory(prefix="ipc-", dir=sys.argv[2]) as directory:
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.settimeout(TIMEOUT)
            listener.setsockopt(socket.SOL_SOCKET, SO_PASSPIDFD, 1)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            address = directory + "/peer.sock"
            listener.bind(address)
            listener.listen(1)
            control_r, control_w = os.pipe()
            # A private, separate socket transfers the connected endpoint to another child.
            with _transfer_pair() as pair:
                receiver, donor = pair
                try:
                    connector = os.fork()
                    if connector == 0:
                        try:
                            listener.close()
                            receiver.close()
                            close(control_w)
                            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as sender:
                                sender.settimeout(TIMEOUT)
                                sender.connect(address)
                                if transfer:
                                    donor.sendmsg([b"socket"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                                 array.array("i", [sender.fileno()]))])
                                else:
                                    if sender.recv(8) != b"go":
                                        os._exit(2)
                                    sender.sendall(b"claimed-pid=-1;claimed-uid=-1")
                                    if sender.recv(8) != b"end":
                                        os._exit(3)
                                if os.read(control_r, 1) != b"x":
                                    os._exit(4)
                            os._exit(0)
                        except BaseException:
                            os._exit(1)
                    children.append(connector)
                    donor.close()
                    actual_sender = connector
                    if transfer:
                        actual_sender = os.fork()
                        if actual_sender == 0:
                            try:
                                listener.close()
                                close(control_r)
                                close(control_w)
                                receiver.settimeout(TIMEOUT)
                                _, ancillary, flags, _ = receiver.recvmsg(8, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
                                if flags & socket.MSG_CTRUNC or len(ancillary) != 1:
                                    os._exit(5)
                                level, kind, value = ancillary[0]
                                if (level, kind, len(value)) != (socket.SOL_SOCKET, socket.SCM_RIGHTS, 4):
                                    os._exit(6)
                                with socket.socket(fileno=struct.unpack("i", value)[0]) as sender:
                                    sender.settimeout(TIMEOUT)
                                    if sender.recv(8) != b"go":
                                        os._exit(7)
                                    sender.sendall(b"claimed-pid=-1;claimed-uid=-1")
                                    if sender.recv(8) != b"end":
                                        os._exit(8)
                                os._exit(0)
                            except BaseException:
                                os._exit(1)
                        children.append(actual_sender)
                    receiver.close()
                    peer, _ = listener.accept()
                    peer.settimeout(TIMEOUT)
                    peer.setsockopt(socket.SOL_SOCKET, SO_PASSPIDFD, 1)
                    peer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                    peer_creds = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    peer_fd = struct.unpack("i", peer.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4))[0]
                    owned.append(peer_fd)
                    peer.sendall(b"go")
                    payload, message_fd, message_creds = receive(peer, owned)
                    checks = {
                        "connection_credentials_identify_connector": peer_creds == (connector, os.getuid(), os.getgid()),
                        "connection_pidfd_identifies_connector": pidfd_pid(peer_fd) == connector,
                        "message_credentials_identify_actual_sender": message_creds == (actual_sender, os.getuid(), os.getgid()),
                        "message_pidfd_identifies_actual_sender": pidfd_pid(message_fd) == actual_sender,
                        "payload_identity_claim_ignored": payload == b"claimed-pid=-1;claimed-uid=-1" and message_creds[0] != -1,
                        "kernel_pidfds_have_cloexec": all(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC for fd in owned),
                        "kernel_pidfds_not_ready_while_peers_alive": all(not ready(fd) for fd in owned),
                        "connection_and_message_identity_relationship": (pidfd_pid(peer_fd) != pidfd_pid(message_fd)) == transfer,
                    }
                    peer.sendall(b"end")
                    os.write(control_w, b"x")
                    for child in children[:]:
                        status = wait_child(child)
                        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                            raise RuntimeError("peer failed")
                        children.remove(child)
                    checks["both_kernel_pidfds_ready_after_exit"] = all(ready(fd, TIMEOUT) for fd in owned)
                    checks["all_owned_peers_reaped"] = not children
                    return checks
                finally:
                    if peer is not None:
                        peer.close()
                    for fd in owned:
                        close(fd)
                    close(control_r)
                    close(control_w)
                    for child in children:
                        retire(child)


class _transfer_pair:
    def __enter__(self):
        self.sockets = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        return self.sockets

    def __exit__(self, *_args):
        for sock in self.sockets:
            sock.close()


def exec_observation():
    child = fd = None
    try:
        child = os.fork()
        if child == 0:
            try:
                ptrace(PTRACE_TRACEME, 0)
                os.kill(os.getpid(), signal.SIGSTOP)
                os.execv("/usr/bin/true", ["true"])
            except BaseException:
                os._exit(1)
        status = wait_child(child)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            raise RuntimeError("missing initial trace stop")
        fd = pidfd_open(child)
        original_image = os.stat(f"/proc/{child}/exe")
        ptrace(PTRACE_SETOPTIONS, child, PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL)
        ptrace(PTRACE_CONT, child)
        status = wait_child(child)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP or status >> 16 != PTRACE_EVENT_EXEC:
            raise RuntimeError("missing exec event")
        previous_tid = ctypes.c_ulong()
        ptrace(PTRACE_GETEVENTMSG, child, ctypes.addressof(previous_tid))
        replacement = os.stat(f"/proc/{child}/exe")
        checks = {
            "owned_child_exec_event_stopped": True,
            "single_thread_exec_preserved_pid": previous_tid.value == child == pidfd_pid(fd),
            "pidfd_not_ready_at_exec_stop": not ready(fd),
            "executable_inode_changed_at_exec_stop": (original_image.st_dev, original_image.st_ino) != (replacement.st_dev, replacement.st_ino),
            "replacement_is_expected_fixture": os.path.samefile(f"/proc/{child}/exe", "/usr/bin/true"),
        }
        ptrace(PTRACE_CONT, child)
        status = wait_child(child)
        checks["exit_observed_and_reaped_after_exec"] = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            child = None
        checks["pidfd_ready_after_exit"] = ready(fd, TIMEOUT)
        return checks
    finally:
        close(fd)
        retire(child)


def monitor_failure():
    """An owned tracer dies; EXITKILL terminates its stopped owned tracee."""
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "subreaper failed")
    read_fd, write_fd = os.pipe()
    tracer = tracee = fd = None
    try:
        tracer = os.fork()
        if tracer == 0:
            close(read_fd)
            target = None
            try:
                target = os.fork()
                if target == 0:
                    try:
                        ptrace(PTRACE_TRACEME, 0)
                        os.kill(os.getpid(), signal.SIGSTOP)
                        os._exit(9)
                    except BaseException:
                        os._exit(1)
                status = wait_child(target)
                if not os.WIFSTOPPED(status):
                    os._exit(2)
                ptrace(PTRACE_SETOPTIONS, target, PTRACE_O_EXITKILL)
                os.write(write_fd, struct.pack("i", target))
                # The parent deliberately kills this tracer after retaining its tracee.
                while True:
                    signal.pause()
            except BaseException:
                retire(target)
                os._exit(1)
        close(write_fd)
        write_fd = None
        if not select.select([read_fd], [], [], TIMEOUT)[0]:
            raise TimeoutError("monitor setup deadline")
        data = os.read(read_fd, 4)
        if len(data) != 4:
            raise RuntimeError("monitor setup failed")
        tracee = struct.unpack("i", data)[0]
        # Numeric lookup is safe only for this cooperative, stopped, owned fixture.
        fd = pidfd_open(tracee)
        checks = {"tracee_alive_before_monitor_failure": not ready(fd)}
        os.kill(tracer, signal.SIGKILL)
        status = wait_child(tracer)
        tracer = None
        checks["owned_monitor_killed_and_reaped"] = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        checks["exitkill_tracee_pidfd_ready"] = ready(fd, TIMEOUT)
        status = wait_child(tracee)
        tracee = None
        checks["exitkill_tracee_killed_and_reaped"] = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        return checks
    finally:
        retire(tracer)
        retire(tracee)
        close(fd)
        close(read_fd)
        close(write_fd)


CASES = {"kernel_ipc": ipc, "transferred_socket": lambda: ipc(True),
         "same_pid_exec": exec_observation, "monitor_failure": monitor_failure}


def main():
    # Raw exception strings can contain private paths. Emit stable categories only.
    try:
        checks = CASES[sys.argv[1]]()
        result = {"passed": all(checks.values()), "checks": checks}
    except Exception as error:
        result = {"passed": False, "error_type": type(error).__name__, "errno": getattr(error, "errno", None)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
