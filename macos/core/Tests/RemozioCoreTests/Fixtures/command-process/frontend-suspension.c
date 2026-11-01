#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <mach/mach_time.h>
static int queued_kill(pthread_t thread, int number);
static unsigned captured_add(_Atomic unsigned *value, unsigned increment, memory_order order);
static uint64_t controlled_time(void);
#define mach_continuous_time controlled_time
#define pthread_kill queued_kill
#undef atomic_fetch_add_explicit
#define atomic_fetch_add_explicit(value, increment, order) captured_add(value, increment, order)
#include "FrontendRuntime.c"
#undef mach_continuous_time
#undef pthread_kill
#undef atomic_fetch_add_explicit
#include "include/RemozioFrontendTerminal.h"
static _Atomic bool inject_after_queue, pause_capture, captured, released;
static _Atomic bool inject_expiry_after_queue;
static _Atomic bool inject_resize_after_queue;
static _Atomic uint64_t overridden_time;
static uint64_t controlled_time(void) {
    uint64_t value = atomic_load(&overridden_time);
    return value ? value : mach_continuous_time();
}
static uint64_t confirmation_deadline(remozio_frontend_runtime_t *owner) {
    return (uint64_t)((__uint128_t)mach_continuous_time() * owner->timebase.numer /
        ((__uint128_t)owner->timebase.denom * 1000000)) + 3000;
}
static unsigned captured_add(_Atomic unsigned *value, unsigned increment, memory_order order) {
    unsigned previous = __c11_atomic_fetch_add(value, increment, order);
    if (value == &handlers && atomic_load_explicit(&pause_capture, memory_order_relaxed)) {
        atomic_store_explicit(&captured, true, memory_order_release);
        while (!atomic_load_explicit(&released, memory_order_acquire)) {}
    }
    return previous;
}
static void *continue_worker(void *unused) {
    (void)unused;
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGCONT);
    int error = pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
    if (!error) error = pthread_kill(pthread_self(), SIGCONT);
    return (void *)(intptr_t)error;
}
static int send_continue(void) {
    pthread_t worker; void *result = NULL;
    int error = pthread_create(&worker, NULL, continue_worker, NULL);
    if (!error) error = pthread_join(worker, &result);
    return error ? error : (int)(intptr_t)result;
}
static int queued_kill(pthread_t thread, int number) {
    int error = pthread_kill(thread, number);
    if (!error && number == SIGTSTP && atomic_exchange(&inject_resize_after_queue, false)) error = pthread_kill(thread, SIGWINCH);
    if (!error && number == SIGTSTP && atomic_exchange(&inject_expiry_after_queue, false)) atomic_store(&overridden_time, UINT64_MAX);
    if (!error && number == SIGTSTP && atomic_exchange(&inject_after_queue, false)) error = send_continue();
    return error;
}
static void *release_capture(void *unused) {
    (void)unused; usleep(50000);
    atomic_store_explicit(&released, true, memory_order_release); return NULL;
}
static int request_stop(remozio_frontend_runtime_t *owner) {
    uint32_t signals = 0;
    int error = pthread_kill(pthread_self(), SIGTSTP);
    if (!error) error = remozio_frontend_runtime_take_signals(owner, &signals);
    return error ? error : (signals == REMOZIO_FRONTEND_SUSPEND ? 0 : EINVAL);
}
#include <errno.h>
#include <fcntl.h>
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
static long now(void) {
    struct timespec time; clock_gettime(CLOCK_MONOTONIC, &time);
    return time.tv_sec * 1000 + time.tv_nsec / 1000000;
}
static bool same(const struct termios *a, const struct termios *b) {
    return a->c_iflag == b->c_iflag && a->c_oflag == b->c_oflag && a->c_cflag == b->c_cflag &&
        (a->c_lflag & ~PENDIN) == (b->c_lflag & ~PENDIN) && a->c_ispeed == b->c_ispeed &&
        a->c_ospeed == b->c_ospeed && !memcmp(a->c_cc, b->c_cc, sizeof(a->c_cc));
}
static bool byte(int fd, char value) { return write(fd, &value, 1) == 1; }
static bool receive(int fd, char expected) {
    char value = 0; long deadline = now() + 3000;
    while (now() < deadline) {
        ssize_t count = read(fd, &value, 1);
        if (count == 1) return value == expected;
        if (!count || (errno != EAGAIN && errno != EINTR)) return false;
        usleep(1000);
    }
    return false;
}
static pid_t wait_for(pid_t child, int *status, int options) {
    long deadline = now() + 10000;
    while (now() < deadline) {
        pid_t result = waitpid(child, status, options | WNOHANG);
        if (result > 0 || (result < 0 && errno != EINTR)) return result;
        usleep(1000);
    }
    return 0;
}
static bool returning_stop_route(void) {
    struct sigaction action = {0}; sigset_t mask;
    return !sigaction(SIGTSTP, NULL, &action) && action.sa_handler == signal_route &&
        !pthread_sigmask(SIG_BLOCK, NULL, &mask) && !sigismember(&mask, SIGTSTP) && !sigismember(&mask, SIGCONT);
}
static int orphaned_group(void) {
    pid_t child = fork();
    if (child < 0) return 50;
    if (!child) {
        if (setsid() < 0) _exit(51);
        remozio_frontend_runtime_t *owner = NULL;
        if (remozio_frontend_runtime_open(&owner) || request_stop(owner)) _exit(52);
        if (remozio_frontend_runtime_suspend(owner, 50)) _exit(53);
        struct sigaction action = {0};
        if (sigaction(SIGTSTP, NULL, &action) || action.sa_handler != signal_route) _exit(54);
        if (remozio_frontend_runtime_close(owner)) _exit(55);
        _exit(0);
    }
    int status = 0;
    pid_t result = wait_for(child, &status, WUNTRACED);
    if (result == child && WIFEXITED(status)) return WEXITSTATUS(status);
    kill(child, SIGKILL);
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    return 56;
}
static int worker(int slave, int command, int report) {
    if (setpgid(0, 0) || !receive(command, 'F')) return 10;
    remozio_frontend_runtime_t *owner = NULL;
    if (remozio_frontend_runtime_open(&owner)) return 11;
    mach_port_t reply = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply) != KERN_SUCCESS ||
        remozio_frontend_runtime_attach(owner, reply, slave)) return 57;
    struct termios original, seen;
    if (tcgetattr(slave, &original)) return 13;
    remozio_frontend_terminal_t *terminal = NULL;
    if (remozio_frontend_terminal_open(slave, &terminal) || remozio_frontend_terminal_activate(terminal)) return 14;
    if (tcgetattr(slave, &seen) || seen.c_lflag & (ICANON | ECHO | ISIG)) return 15;
    if (request_stop(owner) || remozio_frontend_terminal_restore(terminal)) return 16;
    if (tcgetattr(slave, &seen) || !same(&original, &seen) || remozio_frontend_terminal_needs_restore(terminal)) return 17;
    // CONT while restoration was in progress must cancel the already observed stop.
    if (send_continue() || remozio_frontend_runtime_suspend(owner, 50) || !byte(report, 'C') || !receive(command, 'S')) return 25;
    // CONT on another thread after the main-thread stop was queued must cancel it too.
    if (request_stop(owner)) return 26;
    atomic_store(&inject_after_queue, true);
    if (remozio_frontend_runtime_suspend(owner, 50) || !byte(report, 'D') || !receive(command, 'S')) return 27;
    // Hold an actual CONT handler after it has retained the route, before intent publication.
    if (request_stop(owner)) return 28;
    atomic_store(&pause_capture, true); atomic_store(&released, false); atomic_store(&captured, false);
    pthread_t worker, releaser; void *continued = NULL;
    if (pthread_create(&worker, NULL, continue_worker, NULL)) return 29;
    long deadline = now() + 3000;
    while (!atomic_load_explicit(&captured, memory_order_acquire) && now() < deadline) usleep(1000);
    if (!atomic_load_explicit(&captured, memory_order_acquire) || pthread_create(&releaser, NULL, release_capture, NULL)) return 46;
    int suspended = remozio_frontend_runtime_suspend(owner, 50);
    if (pthread_join(worker, &continued) || pthread_join(releaser, NULL) || continued || suspended) return 47;
    atomic_store(&pause_capture, false);
    if (!byte(report, 'H') || !receive(command, 'S')) return 48;
    uint64_t ticket = 0; bool queued = true;
    uint32_t delivered = 0;
    if (remozio_frontend_runtime_job_ticket(owner, &ticket) || send_continue() ||
        remozio_frontend_runtime_take_signals(owner, &delivered) || delivered != REMOZIO_FRONTEND_CONTINUE ||
        remozio_frontend_runtime_suspend_confirmed(owner, ticket, confirmation_deadline(owner), 50, &queued) || queued ||
        !byte(report, 'Q') || !receive(command, 'S')) return 58;
    if (remozio_frontend_runtime_job_ticket(owner, &ticket)) return 59;
    atomic_store(&inject_after_queue, true);
    if (remozio_frontend_runtime_suspend_confirmed(owner, ticket, confirmation_deadline(owner), 50, &queued) || queued ||
        !byte(report, 'J') || !receive(command, 'S')) return 60;
    if (remozio_frontend_runtime_job_ticket(owner, &ticket) ||
        remozio_frontend_runtime_suspend_confirmed(owner, ticket, 0, 50, &queued) || queued ||
        !byte(report, 'O') || !receive(command, 'S')) return 65;
    if (remozio_frontend_runtime_take_signals(owner, &delivered)) return 67;
    atomic_store(&inject_expiry_after_queue, true);
    int expired = remozio_frontend_runtime_suspend_confirmed(owner, ticket, confirmation_deadline(owner), 50, &queued);
    atomic_store(&overridden_time, 0);
    if (remozio_frontend_runtime_take_signals(owner, &delivered) || delivered & REMOZIO_FRONTEND_CONTINUE) {
        fprintf(stderr, "Expired stop produced a continuation event: %u\n", delivered);
        return 68;
    }
    if (expired || queued || atomic_load(&inject_expiry_after_queue) || !returning_stop_route() ||
        !byte(report, 'E') || !receive(command, 'S')) return 66;
    if (remozio_frontend_runtime_job_ticket(owner, &ticket)) return 69;
    atomic_store(&inject_resize_after_queue, true);
    if (remozio_frontend_runtime_suspend_confirmed(owner, ticket, confirmation_deadline(owner), 50, &queued) || queued ||
        remozio_frontend_runtime_take_signals(owner, &delivered) || delivered != REMOZIO_FRONTEND_RESIZE ||
        !returning_stop_route() || !byte(report, 'W') || !receive(command, 'S')) return 70;
    /* A ticket captured after an earlier CONT can authorize a new cooperative stop without fabricating local TSTP history. */
    if (remozio_frontend_runtime_job_ticket(owner, &ticket) ||
        remozio_frontend_runtime_suspend_confirmed(owner, ticket, confirmation_deadline(owner), 50, &queued) || !queued) return 61;
    if (remozio_frontend_runtime_job_ticket(owner, &ticket) ||
        remozio_frontend_runtime_suspend_confirmed(owner, ticket, confirmation_deadline(owner), 50, &queued) || queued) return 62;
    if (!byte(report, 'R') || !receive(command, 'F')) return 63;
    if (request_stop(owner) || remozio_frontend_runtime_suspend(owner, 50)) return 18;
    if (remozio_frontend_terminal_check_foreground(terminal) != EAGAIN ||
        remozio_frontend_terminal_activate(terminal) != EAGAIN || remozio_frontend_terminal_needs_restore(terminal)) return 19;
    if (!byte(report, 'B') || !receive(command, 'F')) return 20;
    if (remozio_frontend_terminal_activate(terminal)) return 21;
    struct winsize size;
    if (remozio_frontend_terminal_dimensions(terminal, &size) || size.ws_row != 79 || size.ws_col != 121) return 22;
    if (tcgetattr(slave, &seen) || seen.c_lflag & (ICANON | ECHO | ISIG)) return 23;
    if (remozio_frontend_terminal_close(terminal) || tcgetattr(slave, &seen) || !same(&original, &seen)) return 24;
    if (remozio_frontend_runtime_close(owner)) return 49;
    if (mach_port_mod_refs(mach_task_self(), reply, MACH_PORT_RIGHT_RECEIVE, -1) != KERN_SUCCESS) return 64;
    close(slave); close(command); close(report); return 0;
}
static int supervise(int slave) {
    if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) || signal(SIGTTOU, SIG_IGN) == SIG_ERR) return 30;
    struct termios original, seen;
    if (tcgetattr(slave, &original)) return 31;
    int command[2], report[2]; if (pipe(command) || pipe(report)) return 32;
    if (fcntl(command[0], F_SETFL, O_NONBLOCK) || fcntl(report[0], F_SETFL, O_NONBLOCK)) return 33;
    pid_t child = fork(); if (child < 0) return 34;
    if (!child) { close(command[1]); close(report[0]); _exit(worker(slave, command[0], report[1])); }
    close(command[0]); close(report[1]);
    int error = 0, status = 0; bool reaped = false;
    if ((setpgid(child, child) && errno != EACCES) || tcsetpgrp(slave, child) || !byte(command[1], 'F')) error = 35;
    for (unsigned i = 0; !error && i < 8; i++) {
        const char expected[] = {'C', 'D', 'H', 'Q', 'J', 'O', 'E', 'W'};
        bool received = receive(report[0], expected[i]), sent = false;
        pid_t observed = 0; int wait_error = 0;
        if (received) {
            observed = waitpid(child, &status, WNOHANG | WUNTRACED);
            if (observed < 0) wait_error = errno;
            if (!observed) sent = byte(command[1], 'S');
        }
        if (!received || observed != 0 || !sent) {
            fprintf(stderr, "frontend suspension handshake phase=%u expected=%c received=%d observed=%ld status=%d waitError=%d sent=%d\n",
                i, expected[i], received, (long)observed, status, wait_error, sent);
            error = 45;
        }
    }
    if (!error && (wait_for(child, &status, WUNTRACED) != child || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTSTP)) error = 65;
    if (!error && (tcgetattr(slave, &seen) || !same(&original, &seen) || tcsetpgrp(slave, getpgrp()) || kill(child, SIGCONT))) error = 66;
    if (!error && (!receive(report[0], 'R') || tcsetpgrp(slave, child) || !byte(command[1], 'F'))) error = 67;
    if (!error && (wait_for(child, &status, WUNTRACED) != child || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTSTP)) error = 36;
    if (!error && (tcgetattr(slave, &seen) || !same(&original, &seen))) error = 37;
    struct winsize size = {.ws_row = 79, .ws_col = 121};
    if (!error && (tcsetpgrp(slave, getpgrp()) || ioctl(slave, TIOCSWINSZ, &size) || kill(child, SIGCONT))) error = 38;
    if (!error && !receive(report[0], 'B')) error = 39;
    if (!error && (tcsetpgrp(slave, child) || !byte(command[1], 'F'))) error = 40;
    if (!error) {
        pid_t result = wait_for(child, &status, 0);
        if (result == child) { reaped = true; error = WIFEXITED(status) ? WEXITSTATUS(status) : 41; }
        else error = 42;
    }
    if (!reaped) {
        kill(child, SIGKILL);
        pid_t result; do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
        if (result != child && errno != ECHILD) error = 43;
        if (error) fprintf(stderr, "frontend suspension cleanup observed=%ld status=%d exited=%d exit=%d signaled=%d signal=%d\n",
            (long)result, status, WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
            WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    }
    close(command[1]); close(report[0]); close(slave); return error;
}
int main(void) {
    if (getuid() == 0 || signal(SIGCHLD, SIG_DFL) == SIG_ERR) return 2;
    int orphaned = orphaned_group();
    if (orphaned) { fprintf(stderr, "frontend orphan fixture failed at stage %d\n", orphaned); return orphaned; }
    int master, slave; if (openpty(&master, &slave, NULL, NULL, NULL)) return 3;
    pid_t child = fork(); if (child < 0) return 4;
    if (!child) { close(master); _exit(supervise(slave)); }
    int status = 0, error = 0; pid_t result = wait_for(child, &status, 0);
    if (result == child) error = WIFEXITED(status) ? WEXITSTATUS(status) : 5;
    else {
        error = 6; close(master); master = -1; close(slave); slave = -1;
        kill(child, SIGKILL);
        do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    }
    if (master >= 0) close(master); if (slave >= 0) close(slave);
    if (error) fprintf(stderr, "frontend suspension fixture failed at stage %d\n", error);
    printf("{\"failure\":%d,\"orphanedGroupDoesNotHang\":true,\"noSyntheticContinueChecked\":%s,\"confirmedStopTicketChecked\":%s,\"restoredBeforeActualStop\":%s,\"crossThreadContinueCancelsStop\":%s,\"backgroundResumeNeverActivates\":%s,"
        "\"foregroundResumeFreshActivation\":%s,\"latestDimensionsCopied\":%s,\"finalSettingsRestored\":%s,\"sessionOwnerReaped\":%s}\n",
        error, error ? "false" : "true", error ? "false" : "true", error ? "false" : "true", error ? "false" : "true", error ? "false" : "true", error ? "false" : "true",
        error ? "false" : "true", error ? "false" : "true", result == child ? "true" : "false");
    return error;
}
