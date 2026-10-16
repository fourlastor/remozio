#!/usr/bin/env python3
"""Measure file-lock lifetimes with disposable files and owned children."""
import contextlib
import errno
import fcntl
import json
import os
import pathlib
import select
import signal
import stat
import sys
import tempfile
import time

FILES = {}
CHILDREN = {}
CHANNELS = set()
SPAWNED = 0
REAPED = 0


class File:
    def __init__(self, fd):
        self.fd = fd
        FILES[fd] = self

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            FILES.pop(fd, None)
            os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def open_file(path):
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        os.close(fd)
        raise RuntimeError("Unexpected fixture metadata")
    return File(fd)


def take(fd, mode):
    try:
        fcntl.flock(fd, mode | fcntl.LOCK_NB)
        return True
    except OSError as error:
        if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
            raise
        return False


def exclusive(path):
    with open_file(path) as file:
        return take(file.fd, fcntl.LOCK_EX)


def receive(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    if not poll.poll(5000):
        raise RuntimeError("Fixture control timed out")
    value = os.read(fd, 1)
    if len(value) != 1:
        raise RuntimeError("Fixture control closed")
    return value


def send(fd, value):
    if os.write(fd, value) != 1:
        raise RuntimeError("Fixture control write failed")


class Child:
    def __init__(self, action, inherit=()):
        global SPAWNED
        request_r, request_w = os.pipe()
        reply_r, reply_w = os.pipe()
        try:
            pid = os.fork()
        except BaseException:
            for fd in (request_r, request_w, reply_r, reply_w):
                os.close(fd)
            raise
        if pid == 0:
            try:
                for fd in set(FILES) - set(inherit):
                    os.close(fd)
                for fd in CHANNELS | {request_w, reply_r}:
                    os.close(fd)
                action(request_r, reply_w)
            except BaseException:
                os._exit(70)
            os._exit(0)
        os.close(request_r)
        os.close(reply_w)
        self.pid, self.request, self.reply = pid, request_w, reply_r
        CHANNELS.update((request_w, reply_r))
        CHILDREN[pid] = self
        SPAWNED += 1

    def receive(self):
        return receive(self.reply)

    def send(self, value=b"x"):
        send(self.request, value)

    def _record_reaped(self):
        global REAPED
        CHILDREN.pop(self.pid)
        self.pid = None
        REAPED += 1

    def join(self, expected_signal=None):
        deadline = time.monotonic() + 5
        while True:
            try:
                pid, status = os.waitpid(self.pid, os.WNOHANG)
            except InterruptedError:
                continue
            if pid:
                self._record_reaped()
                if expected_signal is None:
                    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                        raise RuntimeError("Owned child failed")
                elif not os.WIFSIGNALED(status) or os.WTERMSIG(status) != expected_signal:
                    raise RuntimeError("Unexpected owned child outcome")
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned child did not exit")
            time.sleep(0.005)

    def abort(self):
        if self.pid is None:
            return
        # A waitable child cannot have its PID reused. Never signal after ECHILD.
        try:
            while True:
                try:
                    pid, _ = os.waitpid(self.pid, os.WNOHANG)
                    break
                except InterruptedError:
                    continue
            if pid == 0:
                os.kill(self.pid, signal.SIGKILL)
                while True:
                    try:
                        os.waitpid(self.pid, 0)
                        break
                    except InterruptedError:
                        continue
            self._record_reaped()
        except ChildProcessError:
            CHILDREN.pop(self.pid, None)
            self.pid = None
            raise RuntimeError("Owned child became unobservable") from None

    def close(self):
        try:
            self.abort()
        finally:
            for fd in (self.request, self.reply):
                CHANNELS.remove(fd)
                os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def holder(path, mode):
    def action(request, reply):
        with open_file(path) as file:
            acquired = take(file.fd, mode)
            send(reply, b"1" if acquired else b"0")
            if acquired and receive(request) != b"x":
                raise RuntimeError("Wrong fixture control")
    return Child(action)


def shared_owners(path):
    with open_file(path) as first:
        assert take(first.fd, fcntl.LOCK_SH)
        with holder(path, fcntl.LOCK_SH) as second:
            assert second.receive() == b"1"
            assert not exclusive(path)
            first.close()
            assert not exclusive(path)
            second.send()
            second.join()
            assert exclusive(path)


def exclusive_owner(path):
    with holder(path, fcntl.LOCK_EX) as updater:
        assert updater.receive() == b"1"
        with holder(path, fcntl.LOCK_SH) as authority:
            assert authority.receive() == b"0"
            authority.join()
        assert not exclusive(path)
        updater.send()
        updater.join()
        with holder(path, fcntl.LOCK_SH) as authority:
            assert authority.receive() == b"1"
            authority.send()
            authority.join()


def failed_automatic_attempt(path):
    with open_file(path) as existing:
        assert take(existing.fd, fcntl.LOCK_SH)
        with holder(path, fcntl.LOCK_EX) as updater:
            assert updater.receive() == b"0"
            updater.join()
        with holder(path, fcntl.LOCK_SH) as arriving:
            assert arriving.receive() == b"1"
            assert not exclusive(path)
            arriving.send()
            arriving.join()


def duplicate_close(path):
    with open_file(path) as first:
        assert take(first.fd, fcntl.LOCK_SH)
        with File(os.dup(first.fd)) as duplicate:
            first.close()
            assert not exclusive(path)
            duplicate.close()
            assert exclusive(path)


def fork_close(path):
    with open_file(path) as parent:
        assert take(parent.fd, fcntl.LOCK_SH)
        inherited = parent.fd
        def action(request, reply):
            os.close(inherited)
            send(reply, b"1")
            assert receive(request) == b"x"
        with Child(action, inherit=(inherited,)) as child:
            assert child.receive() == b"1"
            assert not exclusive(path)
            parent.close()
            assert exclusive(path)
            child.send()
            child.join()


def fork_unlock_negative(path):
    with open_file(path) as parent:
        assert take(parent.fd, fcntl.LOCK_SH)
        inherited = parent.fd
        def action(request, reply):
            fcntl.flock(inherited, fcntl.LOCK_UN)
            send(reply, b"1")
            assert receive(request) == b"x"
        with Child(action, inherit=(inherited,)) as child:
            assert child.receive() == b"1"
            # Negative control: an inherited explicit unlock releases the parent's lock.
            assert exclusive(path)
            child.send()
            child.join()


def exec_close(path):
    def action(request, reply):
        with open_file(path) as file:
            assert take(file.fd, fcntl.LOCK_SH)
            os.dup2(file.fd, 200, inheritable=False)
            file.close()
            send(reply, b"1")
            assert receive(request) == b"e"
            os.set_inheritable(request, True)
            os.set_inheritable(reply, True)
            os.execv(sys.executable, [sys.executable, "-I", str(pathlib.Path(__file__).resolve()),
                                     "--exec-stage", str(request), str(reply), "200"])
    with Child(action) as child:
        assert child.receive() == b"1"
        assert not exclusive(path)
        child.send(b"e")
        assert child.receive() == b"2"
        assert exclusive(path)
        child.send()
        child.join()


def exec_stage(arguments):
    if len(arguments) != 3 or any(not value.isdecimal() for value in arguments):
        return 64
    request, reply, barrier = map(int, arguments)
    if len({request, reply, barrier}) != 3 or any(fd < 3 or fd > 4096 for fd in (request, reply, barrier)):
        return 64
    try:
        os.fstat(barrier)
    except OSError as error:
        if error.errno != errno.EBADF:
            return 70
    else:
        return 70
    send(reply, b"2")
    return 0 if receive(request) == b"x" else 70


def crash_release(path):
    with holder(path, fcntl.LOCK_SH) as child:
        assert child.receive() == b"1"
        assert not exclusive(path)
        os.kill(child.pid, signal.SIGKILL)
        child.join(expected_signal=signal.SIGKILL)
        assert exclusive(path)


def replaced_path_negative(path):
    old = path.with_name("old.lock")
    try:
        with open_file(path) as shared:
            assert take(shared.fd, fcntl.LOCK_SH)
            held = os.fstat(shared.fd)
            path.rename(old)
            with File(os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)) as replacement:
                named = os.fstat(replacement.fd)
                assert (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                # Negative control: locks cannot protect a replaceable pathname.
                assert take(replacement.fd, fcntl.LOCK_EX)
    finally:
        if old.exists():
            path.unlink(missing_ok=True)
            old.rename(path)


def run():
    cases = {
        "sharedOwnersBlockUntilLastClose": shared_owners,
        "exclusiveOwnerBlocksNewActivity": exclusive_owner,
        "failedAutomaticAttemptAllowsNewActivity": failed_automatic_attempt,
        "duplicateCloseRetainsLock": duplicate_close,
        "forkCloseRetainsParentLock": fork_close,
        "forkUnlockReleasesParentLockNegative": fork_unlock_negative,
        "closeOnExecReleasesWhileChildLives": exec_close,
        "reapedCrashReleasesLock": crash_release,
        "pathReplacementBypassesLockNegative": replaced_path_negative,
    }
    results = {}
    try:
        with tempfile.TemporaryDirectory(prefix="remozio-release-activity-", dir="/private/tmp") as directory:
            path = pathlib.Path(directory) / "activity.lock"
            with File(os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)):
                pass
            for name, case in cases.items():
                case(path)
                assert not CHILDREN and not FILES and not CHANNELS
                results[name] = True
    finally:
        for child in list(CHILDREN.values()):
            child.close()
    assert SPAWNED == REAPED
    return {"schemaVersion": 1, "passed": True, "cases": results,
            "childrenSpawned": SPAWNED, "childrenReaped": REAPED, "unreapedChildren": len(CHILDREN),
            "rootOperations": False, "servicesRegistered": False, "productionActivationTested": False}


def main(arguments):
    if os.getuid() == 0 or os.geteuid() == 0 or os.getuid() != os.geteuid():
        return 77
    if sys.platform != "darwin":
        return 77
    if not __debug__:
        return 78
    if arguments[:1] == ["--exec-stage"]:
        return exec_stage(arguments[1:])
    if arguments:
        return 64
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    print(json.dumps(run(), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
