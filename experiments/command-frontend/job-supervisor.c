/* Debug-only supervisor for a frontend in its own non-orphaned job group and private terminal. */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <util.h>
static uint64_t now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000; }
static volatile sig_atomic_t cancelled;
static void cancel(int number) { (void)number; cancelled = 1; }
static bool same(const struct termios *a, const struct termios *b) {
    return a->c_iflag == b->c_iflag && a->c_oflag == b->c_oflag && a->c_cflag == b->c_cflag &&
        (a->c_lflag & ~PENDIN) == (b->c_lflag & ~PENDIN) && a->c_ispeed == b->c_ispeed && a->c_ospeed == b->c_ospeed &&
        !memcmp(a->c_cc, b->c_cc, sizeof(a->c_cc));
}
static bool passive_frontend_complete(bool reaped, int status, int slave, const struct termios *original,
                                      uint64_t started, uint64_t deadline) {
    struct termios seen; int terminal_error = 0; bool checked = false, inspected = false, restored = false;
    if (reaped) {
        checked = true;
        if (tcgetattr(slave, &seen)) terminal_error = errno;
        else { inspected = true; restored = same(original, &seen); }
    }
    if (reaped && !terminal_error && restored) return true;
    uint64_t stopped = now();
    fprintf(stderr, "Passive frontend result: reaped=%d cancelled=%d waitStatus=%d elapsedMilliseconds=%llu "
        "deadlineReached=%d terminalChecked=%d terminalRead=%d terminalErrno=%d\n", reaped, cancelled != 0, status,
        (unsigned long long)(stopped - started), stopped >= deadline, checked, inspected, terminal_error);
    if (inspected) {
        fprintf(stderr, "Passive terminal mismatch: iflagChanged=%d oflagChanged=%d cflagChanged=%d lflagChanged=%d "
            "ispeedChanged=%d ospeedChanged=%d controlCharactersChanged=%d\n",
            original->c_iflag != seen.c_iflag, original->c_oflag != seen.c_oflag, original->c_cflag != seen.c_cflag,
            (original->c_lflag & ~PENDIN) != (seen.c_lflag & ~PENDIN), original->c_ispeed != seen.c_ispeed,
            original->c_ospeed != seen.c_ospeed, memcmp(original->c_cc, seen.c_cc, sizeof(original->c_cc)) != 0);
    }
    return false;
}
static int export_descriptor(const char *name, int descriptor) {
    char text[32]; snprintf(text, sizeof(text), "%d", descriptor);
    return setenv(name, text, 1);
}
static bool target_resumed(const char *path) {
    if (!path) return true;
    int descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) return false;
    struct stat value; char bytes[15] = {0};
    bool result = !fstat(descriptor, &value) && S_ISREG(value.st_mode) && value.st_uid == geteuid() &&
        value.st_size == 14 && read(descriptor, bytes, sizeof(bytes)) == 14 && !strcmp(bytes, "TARGET_RESUMED");
    close(descriptor); return result;
}
int main(int argc, char **argv) {
    if (argc < 3 || geteuid() == 0 || getsid(0) != getpid() || signal(SIGCHLD, SIG_DFL) == SIG_ERR ||
        signal(SIGTERM, cancel) == SIG_ERR) return 64;
    int master, slave, report[2], start[2];
    if (openpty(&master, &slave, NULL, NULL, NULL) || ioctl(slave, TIOCSCTTY, 0) ||
        signal(SIGTTOU, SIG_IGN) == SIG_ERR || pipe(report) || pipe(start) ||
        fcntl(master, F_SETFL, O_NONBLOCK) || fcntl(report[0], F_SETFL, O_NONBLOCK)) return 65;
    struct termios original, seen; if (tcgetattr(slave, &original)) return 66;
    bool passive = getenv("REMOZIO_FIXTURE_RESUME_MARKER") && argc == 7 &&
        (!strcmp(argv[3], "stale") || !strcmp(argv[3], "nested"));
    pid_t child = fork(); if (child < 0) return 67;
    if (!child) {
        close(start[1]); close(report[0]); char ready;
        if (read(start[0], &ready, 1) != 1 || ready != 'F' || getpgrp() != getpid() ||
            getsid(0) != getppid() || tcgetpgrp(slave) != getpgrp()) _exit(68);
        close(start[0]);
        if (signal(SIGTERM, SIG_DFL) == SIG_ERR) _exit(69);
        if (export_descriptor("REMOZIO_FIXTURE_TTY_MASTER", master) || export_descriptor("REMOZIO_FIXTURE_TTY_SLAVE", slave) ||
            export_descriptor("REMOZIO_FIXTURE_JOB_REPORT", report[1])) _exit(69);
        execv(argv[1], argv + 1); _exit(70);
    }
    close(start[0]); close(report[1]);
    int error = 0, status = 0; bool reaped = false, stopped = false;
    if ((setpgid(child, child) && errno != EACCES) || tcsetpgrp(slave, child) || write(start[1], "F", 1) != 1) error = 71;
    close(start[1]);
    uint64_t started = now(), deadline = started + (passive ? 45000 : 15000);
    if (passive) {
        while (!error && !cancelled && !reaped && now() < deadline) {
            pid_t found = waitpid(child, &status, WNOHANG | WUNTRACED);
            if (found == child) {
                reaped = WIFEXITED(status) || WIFSIGNALED(status);
                if (!reaped || !WIFEXITED(status) || WEXITSTATUS(status) != 13) {
                    error = 84;
                    fprintf(stderr, "Passive frontend: exited=%d status=%d signalled=%d signal=%d stopped=%d stop=%d\n",
                        WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                        WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : -1,
                        WIFSTOPPED(status), WIFSTOPPED(status) ? WSTOPSIG(status) : -1);
                }
            } else if (found < 0 && errno != EINTR) error = 85;
            usleep(1000);
        }
        if (!error && !passive_frontend_complete(reaped, status, slave, &original, started, deadline)) error = 86;
        goto cleanup;
    }
    while (!error && !cancelled && !stopped && now() < deadline) {
        pid_t found = waitpid(child, &status, WNOHANG | WUNTRACED);
        if (found == child) {
            stopped = WIFSTOPPED(status) && WSTOPSIG(status) == SIGTSTP;
            if (!stopped) {
                reaped = WIFEXITED(status) || WIFSIGNALED(status); error = 72;
                fprintf(stderr, "Frontend before expected stop: exited=%d status=%d signalled=%d signal=%d stopped=%d stop=%d\n",
                    WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                    WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : -1,
                    WIFSTOPPED(status), WIFSTOPPED(status) ? WSTOPSIG(status) : -1);
            }
        } else if (found < 0 && errno != EINTR) error = 73;
        usleep(1000);
    }
    if (!error && (!stopped || tcgetattr(slave, &seen) || !same(&original, &seen))) error = 74;
    const char *stop_barrier = getenv("REMOZIO_FIXTURE_STOP_BARRIER");
    if (!error && stop_barrier) {
        int descriptor = open(stop_barrier, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (descriptor < 0) error = 87;
        else {
            if (write(descriptor, "READY", 5) != 5) error = 87;
            if (close(descriptor)) error = 87;
        }
        deadline = now() + 30000;
        while (!error && !cancelled && now() < deadline) {
            pid_t found = waitpid(child, &status, WNOHANG);
            if (found == child) { reaped = true; break; }
            if (found < 0 && errno != EINTR) error = 88;
            usleep(1000);
        }
        goto cleanup;
    }
    struct winsize size = {.ws_row = 79, .ws_col = 121};
    if (!error && (tcsetpgrp(slave, getpgrp()) || ioctl(slave, TIOCSWINSZ, &size) || kill(child, SIGCONT))) error = 75;
    const char *resume_marker = getenv("REMOZIO_FIXTURE_RESUME_MARKER");
    bool background = false, resumed = false; deadline = now() + 5000;
    while (!error && !cancelled && (!background || !resumed) && now() < deadline) {
        if (!background) {
            char marker; ssize_t count = read(report[0], &marker, 1);
            if (count == 1) { if (marker != 'B') error = 76; else background = true; }
            else if (!count || (errno != EAGAIN && errno != EINTR)) error = 77;
        }
        resumed = target_resumed(resume_marker);
        usleep(1000);
    }
    if (!error && (!background || !resumed || tcgetattr(slave, &seen) || !same(&original, &seen) || tcsetpgrp(slave, child))) error = 78;
    deadline = now() + 5000;
    while (!error && !cancelled && !reaped && now() < deadline) {
        pid_t found = waitpid(child, &status, WNOHANG);
        if (found == child) { reaped = true; if (!WIFEXITED(status) || WEXITSTATUS(status) != 13) error = 79; }
        else if (found < 0 && errno != EINTR) error = 80;
        usleep(1000);
    }
    if (!error && (!reaped || tcgetattr(slave, &seen) || !same(&original, &seen))) error = 81;
cleanup:
    if (!reaped) {
        kill(child, SIGKILL);
        pid_t found; do { found = waitpid(child, &status, 0); } while (found < 0 && errno == EINTR);
        if (found != child) error = 82;
    }
    /* The last master close hangs up this supervisor's own controlling terminal. */
    if (signal(SIGHUP, SIG_IGN) == SIG_ERR && !error) error = 83;
    close(master); close(slave); close(report[0]);
    if (error) fprintf(stderr, "Owned frontend job supervisor failed at stage %d\n", error);
    return error ? error : 13;
}
