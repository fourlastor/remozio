#include "RemozioCommandChild.h"
#include "RemozioCommandProcess.h"
#include "RemozioCommandMonitorProtocol.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <termios.h>
#include <unistd.h>

enum { configuration_fd = 3, directory_fd = 4, status_fd = 5, release_fd = 6, control_fd = 7, terminal_fd = 8 };
typedef struct {
    int configuration, directory, status, release, control_pipe;
    remozio_command_process_t *target;
    remozio_command_process_observation_t observed;
    mach_timebase_info_data_t timebase;
    unsigned char header[REMOZIO_CHILD_HEADER_BYTES], *frame;
    size_t frame_used, frame_count;
    uint64_t started, deadline, sequence, control_sequence, applied_control_sequence, reported_control_sequence, reported_revision;
    bool configured, cancelled, release_consumed, prepared_sent, failure_sent, terminal_sent, status_broken;
    int failure;
    unsigned char pending[REMOZIO_MONITOR_RECORD_BYTES], control[REMOZIO_MONITOR_CONTROL_BYTES];
    size_t pending_used, pending_count, control_used;
    uint32_t pending_tag;
} monitor_t;
static void close_descriptor(int *descriptor) { if (*descriptor >= 0) { close(*descriptor); *descriptor = -1; } }
static int system_error(void) { return errno ? errno : EIO; }
static uint64_t milliseconds(monitor_t *monitor) {
    return (uint64_t)(((__uint128_t)mach_continuous_time() * monitor->timebase.numer) / ((uint64_t)monitor->timebase.denom * 1000000));
}
static uint32_t word(const unsigned char *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
}
static void clear_frame(monitor_t *monitor) {
    if (monitor->frame) {
        volatile unsigned char *bytes = monitor->frame;
        for (size_t i = 0; i < monitor->frame_count; ++i) bytes[i] = 0;
        free(monitor->frame); monitor->frame = NULL;
    }
}
static int private_descriptor(int descriptor, bool writing) {
    struct stat value;
    int flags = fcntl(descriptor, F_GETFL), fd_flags = fcntl(descriptor, F_GETFD);
    if (flags < 0 || fd_flags < 0 || fstat(descriptor, &value)) return system_error();
    if (!S_ISFIFO(value.st_mode) || (flags & O_ACCMODE) != (writing ? O_WRONLY : O_RDONLY)) return EINVAL;
    if (fcntl(descriptor, F_SETFD, fd_flags | FD_CLOEXEC) < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) return system_error();
    if (writing && fcntl(descriptor, F_SETNOSIGPIPE, 1) < 0) return system_error();
    return 0;
}
static int close_other_descriptors(void) {
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (bytes <= 0 || bytes > 1024 * 1024 || bytes % sizeof(struct proc_fdinfo)) return EIO;
    struct proc_fdinfo *items = malloc((size_t)bytes); if (!items) return ENOMEM;
    int received = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, items, bytes);
    if (received < 0 || received > bytes || received % sizeof(*items)) { free(items); return EIO; }
    for (size_t i = 0; i < (size_t)received / sizeof(*items); ++i) if (items[i].proc_fd >= 9) close(items[i].proc_fd);
    free(items); return 0;
}
static void fail(monitor_t *monitor, int error) {
    if (!monitor->failure) monitor->failure = error ? error : EIO;
    monitor->cancelled = true;
}
static void observe_failure(monitor_t *monitor, int error) {
    if (!monitor->observed.release_attempted || monitor->observed.ownership_lost) { fail(monitor, error); return; }
    if (!monitor->failure) monitor->failure = error ? error : EIO;
}
static int pump_configuration(monitor_t *monitor) {
    if (monitor->configured || monitor->cancelled || monitor->target) return 0;
    if (milliseconds(monitor) >= monitor->deadline) return ETIMEDOUT;
    for (unsigned turn = 0; turn < 16; ++turn) {
        unsigned char extra, *destination;
        size_t remaining;
        if (!monitor->frame) { destination = monitor->header + monitor->frame_used; remaining = sizeof(monitor->header) - monitor->frame_used; }
        else { remaining = monitor->frame_count - monitor->frame_used; destination = remaining ? monitor->frame + monitor->frame_used : &extra; }
        ssize_t received = read(monitor->configuration, destination, remaining ? (remaining < 16384 ? remaining : 16384) : 1);
        if (received < 0) return errno == EAGAIN || errno == EINTR ? 0 : system_error();
        if (!received) {
            if (!monitor->frame || monitor->frame_used != monitor->frame_count) return EPROTO;
            monitor->configured = true; close_descriptor(&monitor->configuration); return 0;
        }
        if (!remaining) return EPROTO;
        monitor->frame_used += (size_t)received;
        if (!monitor->frame && monitor->frame_used == sizeof(monitor->header)) {
            uint32_t count = word(monitor->header + 4), budget = word(monitor->header + 28);
            if ((word(monitor->header) != REMOZIO_CHILD_FRAME_V1 && word(monitor->header) != REMOZIO_CHILD_FRAME_V2 && word(monitor->header) != REMOZIO_CHILD_FRAME_V3) || count > REMOZIO_CHILD_MAX_BYTES - sizeof(monitor->header) || budget < 100 || budget > 60000) return EPROTO;
            monitor->deadline = monitor->started + budget;
            monitor->frame_count = sizeof(monitor->header) + count;
            monitor->frame = malloc(monitor->frame_count); if (!monitor->frame) return ENOMEM;
            memcpy(monitor->frame, monitor->header, sizeof(monitor->header));
        }
    }
    return milliseconds(monitor) < monitor->deadline ? 0 : ETIMEDOUT;
}
static int prepare_target(monitor_t *monitor, const char *child) {
    if (!monitor->configured || monitor->cancelled || monitor->target) return 0;
    remozio_child_spec_t spec = {0}; int error = remozio_child_spec_decode(monitor->frame, monitor->frame_count, &spec);
    if (error) return error;
    bool mapped = spec.io_mode == 2;
    if (spec.io_mode != 0) {
        int controlling = mapped ? terminal_fd : 0;
        if (mapped) {
            int streams[3] = {0, 1, 2};
            error = remozio_child_spec_validate_stdio(&spec, controlling, streams);
        } else {
            struct stat first, next;
            if (fstat(0, &first)) error = system_error();
            for (int descriptor = 1; !error && descriptor < 3; ++descriptor) {
                if (fstat(descriptor, &next)) error = system_error();
                else if (first.st_dev != next.st_dev || first.st_ino != next.st_ino || first.st_rdev != next.st_rdev) error = EINVAL;
            }
        }
        if (!error && ioctl(controlling, TIOCSCTTY, 0)) error = system_error();
        if (!error && (tcgetsid(controlling) != getsid(0) || tcgetpgrp(controlling) != getpgrp())) error = EINVAL;
        if (!error && signal(SIGTTOU, SIG_IGN) == SIG_ERR) error = system_error();
    }
    remozio_child_spec_close(&spec);
    if (!mapped) close(terminal_fd);
    if (!error && milliseconds(monitor) >= monitor->deadline) error = ETIMEDOUT;
    if (!error) {
        if (mapped) error = remozio_command_process_spawn_in_session_with_terminal(child, monitor->frame,
            monitor->frame_count, 0, 1, 2, monitor->directory, terminal_fd, &monitor->target);
        else error = remozio_command_process_spawn_in_session(child, monitor->frame,
            monitor->frame_count, 0, 1, 2, monitor->directory, &monitor->target);
    }
    clear_frame(monitor); close_descriptor(&monitor->directory);
    return error;
}
static int pump_release(monitor_t *monitor) {
    if (monitor->cancelled || monitor->release_consumed || !monitor->prepared_sent || !monitor->target) return 0;
    unsigned char byte;
    ssize_t received = read(monitor->release, &byte, 1);
    if (received < 0) return errno == EAGAIN || errno == EINTR ? 0 : system_error();
    if (!received) { monitor->cancelled = true; return 0; }
    monitor->release_consumed = true; close_descriptor(&monitor->release);
    if (byte != 1) return EPROTO;
    int error = remozio_command_process_release(monitor->target);
    int observed_error = remozio_command_process_poll(monitor->target, &monitor->observed);
    if (observed_error) observe_failure(monitor, observed_error);
    return error;
}
static int pump_control(monitor_t *monitor) {
    if (monitor->cancelled) return 0;
    for (unsigned turn = 0; turn < 4; ++turn) {
        ssize_t received = read(monitor->control_pipe, monitor->control + monitor->control_used, sizeof(monitor->control) - monitor->control_used);
        if (received < 0) return errno == EAGAIN || errno == EINTR ? 0 : system_error();
        if (!received) {
            if (monitor->control_used) return EPROTO;
            monitor->cancelled = true; return 0;
        }
        monitor->control_used += (size_t)received;
        if (monitor->control_used == sizeof(monitor->control)) {
            remozio_monitor_control_t record;
            int error = remozio_monitor_control_decode(monitor->control, sizeof(monitor->control), &record);
            if (error) return error;
            if (monitor->control_sequence == UINT64_MAX || record.sequence != monitor->control_sequence + 1) return EPROTO;
            monitor->control_sequence = record.sequence; monitor->control_used = 0;
            if (record.tag == REMOZIO_MONITOR_CANCEL) { monitor->cancelled = true; return 0; }
            if (!monitor->release_consumed || !monitor->observed.release_attempted || !monitor->target) return EPROTO;
            error = remozio_command_process_signal(monitor->target, (int)record.signal);
            if (error) return error;
            monitor->applied_control_sequence = record.sequence;
        }
    }
    return 0;
}
static int queue_status(monitor_t *monitor) {
    if (monitor->pending_count || monitor->status_broken) return 0;
    remozio_monitor_record_t record = {0};
    if (monitor->observed.prepared && !monitor->prepared_sent && !monitor->failure) record.tag = REMOZIO_MONITOR_PREPARED;
    else if (monitor->failure && !monitor->failure_sent) { record.tag = REMOZIO_MONITOR_FAILURE; record.detail = (uint32_t)monitor->failure; }
    else if (monitor->observed.reaped && !monitor->terminal_sent) {
        record.tag = REMOZIO_MONITOR_TARGET_REAPED; record.detail = (uint32_t)monitor->observed.wait_status; record.job_revision = monitor->observed.job_control_revision;
    } else if (monitor->prepared_sent && !monitor->failure && monitor->observed.release_attempted &&
        !monitor->observed.reaped && !monitor->observed.ownership_lost && monitor->applied_control_sequence > monitor->reported_control_sequence) {
        record.tag = REMOZIO_MONITOR_CONTROL_APPLIED;
        record.applied_control_sequence = monitor->applied_control_sequence;
    } else if (monitor->prepared_sent && !monitor->failure && monitor->observed.release_attempted && !monitor->observed.reaped && !monitor->observed.ownership_lost && monitor->observed.job_control_revision > monitor->reported_revision) {
        record.tag = REMOZIO_MONITOR_JOB_STATE; record.job_revision = monitor->observed.job_control_revision;
        if (monitor->observed.stopped) {
            record.flags |= REMOZIO_MONITOR_STOPPED; record.detail = (uint32_t)monitor->observed.stop_signal; record.stop_code = (uint32_t)monitor->observed.stop_code;
            if (monitor->observed.stop_tracing_known) record.flags |= REMOZIO_MONITOR_TRACING_KNOWN;
            if (monitor->observed.stop_traced) record.flags |= REMOZIO_MONITOR_TRACED;
        }
    } else return 0;
    record.target_pid = (uint32_t)monitor->observed.pid;
    if (monitor->observed.birth_known) {
        record.flags |= REMOZIO_MONITOR_BIRTH_KNOWN; record.birth_seconds = monitor->observed.birth_seconds; record.birth_microseconds = monitor->observed.birth_microseconds;
    }
    if (record.tag != REMOZIO_MONITOR_PREPARED && monitor->observed.release_attempted) record.flags |= REMOZIO_MONITOR_TARGET_RELEASE_ATTEMPTED;
    if (monitor->sequence == UINT64_MAX) return EOVERFLOW;
    record.sequence = monitor->sequence + 1;
    int error = remozio_monitor_record_encode(&record, monitor->pending); if (error) return error;
    monitor->sequence = record.sequence; monitor->pending_tag = record.tag; monitor->pending_count = sizeof(monitor->pending); monitor->pending_used = 0;
    if (record.tag == REMOZIO_MONITOR_JOB_STATE) monitor->reported_revision = record.job_revision;
    if (record.tag == REMOZIO_MONITOR_CONTROL_APPLIED) monitor->reported_control_sequence = record.applied_control_sequence;
    return 0;
}
static int pump_status(monitor_t *monitor) {
    if (!monitor->pending_count || monitor->status_broken) return 0;
    ssize_t written = write(monitor->status, monitor->pending + monitor->pending_used, monitor->pending_count - monitor->pending_used);
    if (written < 0) return errno == EAGAIN || errno == EINTR ? 0 : system_error();
    if (!written) return EIO;
    monitor->pending_used += (size_t)written;
    if (monitor->pending_used == monitor->pending_count) {
        if (monitor->pending_tag == REMOZIO_MONITOR_PREPARED) monitor->prepared_sent = true;
        else if (monitor->pending_tag == REMOZIO_MONITOR_FAILURE) monitor->failure_sent = true;
        else if (monitor->pending_tag == REMOZIO_MONITOR_TARGET_REAPED) monitor->terminal_sent = true;
        monitor->pending_count = monitor->pending_used = 0;
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--monitor") || argv[2][0] != '/' || strnlen(argv[2], PATH_MAX) >= PATH_MAX) return EX_USAGE;
    if (geteuid() != 0 || getuid() != 0) return EX_NOPERM;
    if (getsid(0) != getpid() || getpgrp() != getpid()) return EX_CONFIG;
    monitor_t monitor = {.configuration = configuration_fd, .directory = directory_fd, .status = status_fd, .release = release_fd, .control_pipe = control_fd};
    if (mach_timebase_info(&monitor.timebase) != KERN_SUCCESS || !monitor.timebase.numer || !monitor.timebase.denom) return EX_CONFIG;
    monitor.started = milliseconds(&monitor); monitor.deadline = monitor.started + 60000;
    int error = private_descriptor(status_fd, true); if (error) return EX_CONFIG;
    if ((error = private_descriptor(configuration_fd, false)) || (error = private_descriptor(release_fd, false)) ||
        (error = private_descriptor(control_fd, false)) || (error = close_other_descriptors())) fail(&monitor, error);
    struct stat directory; int directory_flags = fcntl(directory_fd, F_GETFD);
    if (!monitor.failure && (directory_flags < 0 || fstat(directory_fd, &directory) || !S_ISDIR(directory.st_mode) || fcntl(directory_fd, F_SETFD, directory_flags | FD_CLOEXEC) < 0)) fail(&monitor, EINVAL);
    bool cancel_attempted = false;
    for (;;) {
        if ((error = pump_configuration(&monitor)) || (error = prepare_target(&monitor, argv[2]))) fail(&monitor, error);
        if (monitor.target) {
            error = remozio_command_process_poll(monitor.target, &monitor.observed);
            if (error) observe_failure(&monitor, error);
            if (monitor.observed.preparation_failed) observe_failure(&monitor, monitor.observed.preparation_error);
            if (monitor.observed.reaped && !monitor.observed.prepared) fail(&monitor, EPROTO);
        }
        if (!monitor.release_consumed && !monitor.cancelled && milliseconds(&monitor) >= monitor.deadline) fail(&monitor, ETIMEDOUT);
        if (!monitor.observed.reaped && !monitor.observed.ownership_lost) {
            if ((error = pump_release(&monitor)) || (error = pump_control(&monitor))) fail(&monitor, error);
        }
        if (monitor.cancelled && !cancel_attempted) {
            cancel_attempted = true; close_descriptor(&monitor.configuration); close_descriptor(&monitor.release); close_descriptor(&monitor.control_pipe); clear_frame(&monitor);
            if (monitor.target) {
                error = remozio_command_process_cancel(monitor.target); if (error) fail(&monitor, error);
                (void)remozio_command_process_poll(monitor.target, &monitor.observed);
            }
            if (!monitor.observed.prepared && !monitor.failure) fail(&monitor, ECANCELED);
        }
        if ((error = queue_status(&monitor))) { monitor.status_broken = true; fail(&monitor, error); }
        if ((error = pump_status(&monitor))) { monitor.status_broken = true; fail(&monitor, error); close_descriptor(&monitor.status); }
        bool retired = !monitor.target || monitor.observed.reaped || monitor.observed.ownership_lost;
        bool reported = monitor.observed.reaped ? monitor.terminal_sent : monitor.failure_sent;
        if (retired && (reported || monitor.status_broken)) break;
        struct pollfd items[4] = {
            {.fd = monitor.target || monitor.configured || monitor.cancelled ? -1 : monitor.configuration, .events = POLLIN},
            {.fd = monitor.cancelled || monitor.release_consumed || !monitor.prepared_sent ? -1 : monitor.release, .events = POLLIN},
            {.fd = monitor.cancelled || monitor.observed.reaped || monitor.observed.ownership_lost ? -1 : monitor.control_pipe, .events = POLLIN},
            {.fd = monitor.status_broken || !monitor.pending_count ? -1 : monitor.status, .events = POLLOUT}
        };
        if (poll(items, 4, 20) < 0 && errno != EINTR) fail(&monitor, system_error());
    }
    clear_frame(&monitor);
    if (remozio_command_process_dispose(monitor.target)) return EX_SOFTWARE;
    close_descriptor(&monitor.configuration); close_descriptor(&monitor.directory); close_descriptor(&monitor.status);
    close_descriptor(&monitor.release); close_descriptor(&monitor.control_pipe);
    close(terminal_fd);
    return monitor.failure ? EX_SOFTWARE : EX_OK;
}
