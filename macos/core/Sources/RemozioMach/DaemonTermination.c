#include "include/RemozioDaemonTermination.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <unistd.h>

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "Daemon termination requires lock-free signal state");
static _Atomic int installed, requested;
static _Atomic int wake_descriptor = -1;

static void request_termination(int signal_number) {
    (void)signal_number;
    int saved_errno = errno;
    atomic_store(&requested, 1);
    int descriptor = atomic_load(&wake_descriptor);
    if (descriptor >= 0) {
        const unsigned char byte = 1;
        ssize_t result;
        do { result = write(descriptor, &byte, 1); } while (result < 0 && errno == EINTR);
        /* A full pipe already contains a wakeup. */
    }
    errno = saved_errno;
}

bool remozio_daemon_termination_requested(void) {
    return atomic_load(&requested) != 0;
}

int remozio_daemon_termination_install(int *read_descriptor) {
    if (!read_descriptor) return EINVAL;
    if (atomic_exchange(&installed, 1)) return EALREADY;

    struct sigaction action = {0}, previous_term, previous_int;
    action.sa_handler = request_termination;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGTERM);
    sigaddset(&action.sa_mask, SIGINT);
    action.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &action, &previous_term) != 0) return errno;
    if (sigaction(SIGINT, &action, &previous_int) != 0) {
        int error = errno;
        (void)sigaction(SIGTERM, &previous_term, NULL);
        return error;
    }

    int wake[2] = {-1, -1};
    if (pipe(wake) != 0 ||
        fcntl(wake[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(wake[1], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(wake[1], F_SETFL, O_NONBLOCK) != 0) {
        int error = errno;
        if (wake[0] >= 0) close(wake[0]);
        if (wake[1] >= 0) close(wake[1]);
        (void)sigaction(SIGINT, &previous_int, NULL);
        (void)sigaction(SIGTERM, &previous_term, NULL);
        return error;
    }

    atomic_store(&wake_descriptor, wake[1]);
    *read_descriptor = wake[0];
    return 0;
}
