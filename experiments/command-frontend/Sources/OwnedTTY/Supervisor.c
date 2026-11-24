#include "OwnedTTY.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/task_special_ports.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t cancelled;
static void cancel(int number) { (void)number; cancelled = 1; }
int remozio_fixture_install_cancellation(void) {
    if (geteuid() == 0 || getsid(0) != getpid()) return EPERM;
    struct sigaction action = {0}; action.sa_handler = cancel; sigemptyset(&action.sa_mask);
    return sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ? errno : 0;
}
int remozio_fixture_cancelled(void) { return cancelled != 0; }

int remozio_fixture_spawn_supervisor(const char *path, char *const arguments[],
    mach_port_t authority, const char *resume_marker, pid_t *child, int *output) {
    if (!child || !output) return EINVAL;
    *child = -1; *output = -1;
    mach_port_urefs_t references = 0;
    if (!path || path[0] != '/' || !resume_marker || resume_marker[0] != '/' || !arguments || !arguments[0] ||
        geteuid() == 0 || getsid(0) != getpid() ||
        mach_port_get_refs(mach_task_self(), authority, MACH_PORT_RIGHT_SEND, &references) != KERN_SUCCESS || !references) return EPERM;
    for (int fd = 0; fd < 3; ++fd) if (fcntl(fd, F_GETFD) < 0) return EBADF;
    int descriptors[2];
    if (pipe(descriptors)) return errno;
    int error = 0;
    if (fcntl(descriptors[0], F_SETFD, FD_CLOEXEC) || fcntl(descriptors[1], F_SETFD, FD_CLOEXEC) ||
        fcntl(descriptors[0], F_SETFL, O_NONBLOCK)) error = errno;
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_t actions;
    int attributes_ready = 0, actions_ready = 0;
    if (!error && !(error = posix_spawnattr_init(&attributes))) attributes_ready = 1;
    if (!error && !(error = posix_spawn_file_actions_init(&actions))) actions_ready = 1;
    sigset_t empty, defaults; sigemptyset(&empty); sigfillset(&defaults);
    if (!error) error = posix_spawnattr_setflags(&attributes,
        POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    if (!error) error = posix_spawnattr_setsigmask(&attributes, &empty);
    if (!error) error = posix_spawnattr_setsigdefault(&attributes, &defaults);
    if (!error) error = posix_spawnattr_setspecialport_np(&attributes, authority, TASK_BOOTSTRAP_PORT);
    if (!error) error = posix_spawn_file_actions_addinherit_np(&actions, STDIN_FILENO);
    if (!error) error = posix_spawn_file_actions_addinherit_np(&actions, STDERR_FILENO);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, descriptors[1], STDOUT_FILENO);
    if (!error) error = posix_spawn_file_actions_addclose(&actions, descriptors[0]);
    if (!error) error = posix_spawn_file_actions_addclose(&actions, descriptors[1]);
    char marker[PATH_MAX + 64];
    int count = snprintf(marker, sizeof(marker), "REMOZIO_FIXTURE_RESUME_MARKER=%s", resume_marker);
    if (!error && (count < 0 || (size_t)count >= sizeof(marker))) error = EINVAL;
    const char *barrier_path = getenv("REMOZIO_FIXTURE_STOP_BARRIER");
    char barrier[PATH_MAX + 64];
    if (!error && barrier_path) {
        count = snprintf(barrier, sizeof(barrier), "REMOZIO_FIXTURE_STOP_BARRIER=%s", barrier_path);
        if (barrier_path[0] != '/' || count < 0 || (size_t)count >= sizeof(barrier)) error = EINVAL;
    }
    char *environment[] = {"PATH=/usr/bin:/bin", marker, NULL, NULL, NULL};
    int environment_count = 2;
    if (barrier_path) environment[environment_count++] = barrier;
    if (getenv("REMOZIO_CI_STALE_TRACE")) environment[environment_count] = "REMOZIO_CI_STALE_TRACE=1";
    if (!error) error = posix_spawn(child, path, &actions, &attributes, arguments, environment);
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    if (attributes_ready) posix_spawnattr_destroy(&attributes);
    close(descriptors[1]);
    if (error) { close(descriptors[0]); *child = -1; }
    else *output = descriptors[0];
    return error;
}
