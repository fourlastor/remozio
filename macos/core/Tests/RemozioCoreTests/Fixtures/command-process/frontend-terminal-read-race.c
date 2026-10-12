#include "RemozioFrontendTerminal.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <util.h>
int fixture_fake_foreground;
static volatile sig_atomic_t saw_input;
static void route(int number) { if (number == SIGTTIN) saw_input = 1; }
static int transfer(int fd, char *byte, bool sending) {
    ssize_t n;
    do { n = sending ? write(fd, byte, 1) : read(fd, byte, 1); } while (n < 0 && errno == EINTR);
    return n == 1 ? 0 : 1;
}
static long now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static pid_t await_until(pid_t child, int *status, long end) {
    while (now() < end) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result > 0 || (result < 0 && errno != EINTR)) return result;
        usleep(1000);
    }
    return 0;
}
static pid_t await(pid_t child, int *status) { return await_until(child, status, now() + 5000); }
static bool same(const struct termios *a, const struct termios *b) {
    return a->c_iflag == b->c_iflag && a->c_oflag == b->c_oflag && a->c_cflag == b->c_cflag &&
        (a->c_lflag & ~PENDIN) == (b->c_lflag & ~PENDIN) && a->c_ispeed == b->c_ispeed &&
        a->c_ospeed == b->c_ospeed && !memcmp(a->c_cc, b->c_cc, sizeof(a->c_cc));
}
static int worker(int slave, int command, int report, int control) {
    if (setpgid(0, 0)) return 10;
    struct sigaction action = {0}; action.sa_handler = route; sigemptyset(&action.sa_mask);
    if (sigaction(SIGTTIN, &action, NULL) || sigaction(SIGTTOU, &action, NULL)) return 11;
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGTTIN); sigaddset(&mask, SIGTTOU);
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) return 12;
    char byte;
    if (transfer(command, &byte, false)) return 13;
    if (control == 1) { close(report); usleep(20000); return 87; }
    if (control == 2) {
        close(report); usleep(20000);
        sigset_t death; sigemptyset(&death); sigaddset(&death, SIGTERM);
        if (signal(SIGTERM, SIG_DFL) == SIG_ERR || sigprocmask(SIG_UNBLOCK, &death, NULL)) return 88;
        kill(getpid(), SIGTERM); return 89;
    }
    if (control == 3) {
        byte = 'X';
        if (transfer(report, &byte, true) || transfer(command, &byte, false)) return 90;
        return 91;
    }
    struct termios original, seen;
    if (tcgetattr(slave, &original)) return 14;
    remozio_frontend_terminal_t *terminal = NULL;
    if (remozio_frontend_terminal_open(slave, &terminal) || remozio_frontend_terminal_activate(terminal)) return 15;
    if (tcgetattr(slave, &seen) || (seen.c_lflag & (ICANON | ECHO | ISIG))) return 16;
    char path[256]; if (ttyname_r(slave, path, sizeof(path))) return 17;
    int fd = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    if (fd < 0 || tcgetpgrp(fd) != getpgrp()) return 18;
    // Reject unsafe input signal routes without reading queued bytes.
    size_t guarded_count = 7; unsigned char guarded;
    if (signal(SIGTTIN, SIG_IGN) == SIG_ERR ||
        remozio_frontend_terminal_read(terminal, &guarded, 1, &guarded_count) != ENOTSUP || guarded_count) return 41;
    if (signal(SIGTTIN, SIG_DFL) == SIG_ERR ||
        remozio_frontend_terminal_read(terminal, &guarded, 1, &guarded_count) != ENOTSUP || guarded_count) return 42;
    action.sa_flags = SA_RESTART;
    if (sigaction(SIGTTIN, &action, NULL) ||
        remozio_frontend_terminal_read(terminal, &guarded, 1, &guarded_count) != ENOTSUP || guarded_count) return 43;
    action.sa_flags = 0;
    sigset_t input_mask; sigemptyset(&input_mask); sigaddset(&input_mask, SIGTTIN);
    if (sigaction(SIGTTIN, &action, NULL) || sigprocmask(SIG_BLOCK, &input_mask, NULL) ||
        remozio_frontend_terminal_read(terminal, &guarded, 1, &guarded_count) != ENOTSUP || guarded_count) return 44;
    if (sigprocmask(SIG_UNBLOCK, &input_mask, NULL)) return 45;
    byte = 'R'; if (transfer(report, &byte, true) || transfer(command, &byte, false)) return 19;
    char input[10]; size_t count = 7;
    if (remozio_frontend_terminal_read(terminal, input, sizeof(input), &count) != EAGAIN || count || saw_input) return 46;
    // Replace only the pre-check. The actual read still reaches the real background kernel path.
    fixture_fake_foreground = 1;
    int error = remozio_frontend_terminal_read(terminal, input, sizeof(input), &count);
    fixture_fake_foreground = 0;
    if (error != EINTR || count || !saw_input) return 20;
    if (remozio_frontend_terminal_restore(terminal) != EAGAIN || !remozio_frontend_terminal_needs_restore(terminal)) return 21;
    count = 7;
    if (remozio_frontend_terminal_read(terminal, input, sizeof(input), &count) != ENOTCONN || count) return 47;
    byte = 'B'; if (transfer(report, &byte, true) || transfer(command, &byte, false)) return 22;
    if (remozio_frontend_terminal_restore(terminal) || remozio_frontend_terminal_needs_restore(terminal)) return 23;
    if (tcgetattr(slave, &seen) || !same(&original, &seen)) return 24;
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    if (poll(&ready, 1, 1000) != 1 || read(fd, input, sizeof(input)) != sizeof(input) || memcmp(input, "untouched\n", sizeof(input))) return 25;
    if (remozio_frontend_terminal_close(terminal)) return 26;
    close(fd); close(slave); return 0;
}
struct worker_diagnostics {
    int phase, report_result, report_errno, report_byte, wait_errno;
    int exit_code, signal_number;
    bool status_known, reaped, observed_before_cleanup, cleanup_kill_attempted;
};
static void record_status(struct worker_diagnostics *d, int status, bool before_cleanup) {
    d->status_known = WIFEXITED(status) || WIFSIGNALED(status);
    d->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    d->signal_number = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    d->reaped = true; d->observed_before_cleanup = before_cleanup;
}
static int receive_report(int fd, char expected, struct worker_diagnostics *d) {
    char byte = 0; ssize_t result;
    do { result = read(fd, &byte, 1); } while (result < 0 && errno == EINTR);
    d->report_result = (int)result; d->report_errno = result < 0 ? errno : 0;
    d->report_byte = result == 1 ? (unsigned char)byte : -1;
    return result != 1 || byte != expected;
}
static int supervise(int slave, int diagnostics_fd, int control, struct worker_diagnostics *d) {
    const long cleanup_deadline = now() + 5000;
    if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) || signal(SIGTTOU, SIG_IGN) == SIG_ERR) return 30;
    int command[2], report[2]; if (pipe(command) || pipe(report)) return 31;
    pid_t child = fork(); if (child < 0) return 32;
    if (!child) {
        close(diagnostics_fd); close(command[1]); close(report[0]);
        _exit(worker(slave, command[0], report[1], control));
    }
    close(command[0]); close(report[1]);
    int error = 0, status = 0; char byte = 'S'; bool owned = true;
    d->phase = 1;
    if ((setpgid(child, child) && errno != EACCES) || tcsetpgrp(slave, child) || transfer(command[1], &byte, true)) error = 33;
    if (!error) d->phase = 2;
    if (!error && receive_report(report[0], 'R', d)) error = 34;
    if (!error && (tcsetpgrp(slave, getpgrp()) || transfer(command[1], &byte, true))) error = 35;
    if (!error) d->phase = 3;
    if (!error && receive_report(report[0], 'B', d)) error = 36;
    if (!error && (tcsetpgrp(slave, child) || transfer(command[1], &byte, true))) error = 37;
    if (!error) {
        d->phase = 4;
        pid_t result = await(child, &status);
        if (result == child) { owned = false; record_status(d, status, true); error = WIFEXITED(status) ? WEXITSTATUS(status) : 38; }
        else if (result < 0) { owned = false; d->wait_errno = errno; error = 39; } else error = 40;
    }
    if (owned) {
        pid_t result;
        if ((d->phase == 2 || d->phase == 3) && d->report_result == 0 && d->report_byte == -1) {
            result = await_until(child, &status, cleanup_deadline);
        } else {
            do { result = waitpid(child, &status, WNOHANG); } while (result < 0 && errno == EINTR);
        }
        if (result == child) { owned = false; record_status(d, status, true); }
        else if (result < 0) { owned = false; d->wait_errno = errno; }
        if (owned) {
            d->cleanup_kill_attempted = true; kill(child, SIGKILL);
            do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
            if (result == child) record_status(d, status, false);
            else if (result < 0) d->wait_errno = errno;
        }
    }
    close(command[1]); close(report[0]); close(slave); return error;
}
int main(int argc, char **argv) {
    int control = 0;
    if (argc == 2 && !strcmp(argv[1], "--worker-exit-before-ready")) control = 1;
    else if (argc == 2 && !strcmp(argv[1], "--worker-signal-before-ready")) control = 2;
    else if (argc == 2 && !strcmp(argv[1], "--worker-invalid-ready")) control = 3;
    else if (argc != 1) return 2;
    if (getuid() == 0 || signal(SIGCHLD, SIG_DFL) == SIG_ERR) return 2;
    int master, slave; if (openpty(&master, &slave, NULL, NULL, NULL)) return 3;
    if (write(master, "untouched\n", 10) != 10) return 4;
    int diagnostics[2]; if (pipe(diagnostics)) return 9;
    pid_t child = fork(); if (child < 0) return 5;
    if (!child) {
        close(master); close(diagnostics[0]);
        struct worker_diagnostics detail = {.report_byte = -1, .exit_code = -1};
        int outcome = supervise(slave, diagnostics[1], control, &detail);
        ssize_t sent; do { sent = write(diagnostics[1], &detail, sizeof(detail)); } while (sent < 0 && errno == EINTR);
        close(diagnostics[1]); _exit(outcome);
    }
    close(diagnostics[1]);
    fcntl(master, F_SETFL, fcntl(master, F_GETFL) | O_NONBLOCK);
    long end = now() + 6000; pid_t result = 0; int status = 0, error = 0;
    while (now() < end) {
        char output[256]; while (read(master, output, sizeof(output)) > 0) {}
        result = waitpid(child, &status, WNOHANG);
        if (result > 0 || (result < 0 && errno != EINTR)) break;
        usleep(1000);
    }
    if (result == child) error = WIFEXITED(status) ? WEXITSTATUS(status) : 6;
    else if (result < 0) error = 7;
    else {
        error = 8; close(master); master = -1; close(slave); slave = -1;
        kill(child, SIGKILL);
        do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    }
    struct worker_diagnostics detail = {.report_byte = -1, .exit_code = -1};
    fcntl(diagnostics[0], F_SETFL, fcntl(diagnostics[0], F_GETFL) | O_NONBLOCK);
    ssize_t received; do { received = read(diagnostics[0], &detail, sizeof(detail)); } while (received < 0 && errno == EINTR);
    bool diagnostic_present = received == (ssize_t)sizeof(detail); close(diagnostics[0]);
    if (master >= 0) close(master); if (slave >= 0) close(slave);
    printf("{\"failure\":%d,\"backgroundReadInterrupted\":%s,\"restorationRetainedThenCompleted\":%s,\"queuedInputPreserved\":%s,\"sessionOwnerReaped\":%s,"
        "\"workerDiagnosticPresent\":%s,\"supervisorPhase\":%d,\"reportReadResult\":%d,\"reportReadErrno\":%d,\"reportByte\":%d,"
        "\"workerStatusKnown\":%s,\"workerExitCode\":%d,\"workerSignal\":%d,\"workerReaped\":%s,\"statusObservedBeforeCleanup\":%s,\"cleanupKillAttempted\":%s,\"workerWaitErrno\":%d}\n",
        error, error ? "false" : "true", error ? "false" : "true", error ? "false" : "true", result == child ? "true" : "false",
        diagnostic_present ? "true" : "false", detail.phase, detail.report_result, detail.report_errno, detail.report_byte,
        detail.status_known ? "true" : "false", detail.exit_code, detail.signal_number, detail.reaped ? "true" : "false",
        detail.observed_before_cleanup ? "true" : "false", detail.cleanup_kill_attempted ? "true" : "false", detail.wait_errno);
    return error;
}
