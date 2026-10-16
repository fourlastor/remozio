#include "include/RemozioCommandMonitor.h"
#include "include/RemozioCommandChild.h"
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
struct remozio_command_monitor {
    remozio_command_monitor_observation_t state;
    pid_t parent;
    int configuration, status, release, control, events;
    unsigned char *frame, status_bytes[REMOZIO_MONITOR_RECORD_BYTES];
    size_t frame_count, written, status_count;
    bool resumed;
    uint64_t control_sequence, deadline;
    mach_timebase_info_data_t timebase;
};
static int system_error(void) { return errno ? errno : EIO; }
static void close_descriptor(int *value) { if (*value >= 0) { close(*value); *value = -1; } }
static void clear_frame(remozio_command_monitor_t *monitor) {
    if (monitor->frame) {
        volatile unsigned char *bytes = monitor->frame;
        for (size_t i = 0; i < monitor->frame_count; ++i) bytes[i] = 0;
        free(monitor->frame); monitor->frame = NULL;
    }
}
static void close_resources(remozio_command_monitor_t *monitor) {
    close_descriptor(&monitor->configuration); close_descriptor(&monitor->status);
    close_descriptor(&monitor->release); close_descriptor(&monitor->control); close_descriptor(&monitor->events); clear_frame(monitor);
}
static uint64_t milliseconds(remozio_command_monitor_t *monitor) {
    return (uint64_t)(((__uint128_t)mach_continuous_time() * monitor->timebase.numer) / ((uint64_t)monitor->timebase.denom * 1000000));
}
static int mark_private(int descriptor, bool nonblocking, bool writing) {
    int flags = fcntl(descriptor, F_GETFD);
    if (flags < 0 || fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) < 0) return system_error();
    if (nonblocking) {
        flags = fcntl(descriptor, F_GETFL);
        if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) return system_error();
    }
    if (writing && fcntl(descriptor, F_SETNOSIGPIPE, 1) < 0) return system_error();
    return 0;
}
static int private_pipe(int ends[2]) {
    if (pipe(ends)) return system_error();
    int error = mark_private(ends[0], false, false);
    if (!error) error = mark_private(ends[1], false, false);
    if (error) { close_descriptor(&ends[0]); close_descriptor(&ends[1]); }
    return error;
}
static int spawn_monitor(const char *path, const char *child, const void *frame, size_t count,
    int input, int output, int error, int directory, int terminal, bool mapped, remozio_command_monitor_t **result) {
    if (!result) return EINVAL;
    *result = NULL;
    if (!path || path[0] != '/' || strnlen(path, PATH_MAX) >= PATH_MAX || !child || child[0] != '/' || strnlen(child, PATH_MAX) >= PATH_MAX) return EINVAL;
    struct sigaction action;
    if (sigaction(SIGCHLD, NULL, &action)) return system_error();
    if (action.sa_handler == SIG_IGN || (action.sa_flags & SA_NOCLDWAIT)) return EINVAL;
    remozio_child_spec_t spec = {0}; int failure = remozio_child_spec_decode(frame, count, &spec);
    if (failure) return failure;
    if (spec.format_version == 3 ? ((spec.io_mode == 2) != mapped) : spec.format_version != (mapped ? 2U : 1U)) { remozio_child_spec_close(&spec); return ENOTSUP; }
    if (mapped) {
        int streams[3] = {input, output, error};
        failure = remozio_child_spec_validate_stdio(&spec, terminal, streams);
        if (failure) { remozio_child_spec_close(&spec); return failure; }
    }
    uint32_t budget = spec.preparation_milliseconds; remozio_child_spec_close(&spec);
    int descriptor_count = mapped ? 9 : 8;
    int original[9] = {input, output, error, -1, directory, -1, -1, -1, terminal}, copies[9];
    int configuration[2] = {-1,-1}, status[2] = {-1,-1}, release[2] = {-1,-1}, control[2] = {-1,-1};
    for (int i = 0; i < descriptor_count; ++i) copies[i] = -1;
    remozio_command_monitor_t *monitor = calloc(1, sizeof(*monitor)); if (!monitor) return ENOMEM;
    monitor->parent = getpid();
    monitor->configuration = monitor->status = monitor->release = monitor->control = monitor->events = -1;
    remozio_monitor_stream_init(&monitor->state.status);
    monitor->frame_count = count; monitor->frame = malloc(count);
    if (!monitor->frame) { failure = ENOMEM; goto cleanup; }
    memcpy(monitor->frame, frame, count);
    if (mach_timebase_info(&monitor->timebase) != KERN_SUCCESS || !monitor->timebase.numer || !monitor->timebase.denom) { failure = EIO; goto cleanup; }
    monitor->deadline = milliseconds(monitor) + budget;
    for (int i = 0; i < 3; ++i) {
        int flags = fcntl(original[i], F_GETFL);
        if (flags < 0) { failure = system_error(); goto cleanup; }
        if ((flags & O_EVTONLY) || (i == 0 ? (flags & O_ACCMODE) == O_WRONLY : (flags & O_ACCMODE) == O_RDONLY)) { failure = EINVAL; goto cleanup; }
    }
    struct stat cwd;
    if (fstat(directory, &cwd)) { failure = system_error(); goto cleanup; }
    if (!S_ISDIR(cwd.st_mode)) { failure = EINVAL; goto cleanup; }
    if ((failure = private_pipe(configuration)) || (failure = private_pipe(status)) ||
        (failure = private_pipe(release)) || (failure = private_pipe(control))) goto cleanup;
    monitor->configuration = configuration[1]; configuration[1] = -1;
    monitor->status = status[0]; status[0] = -1;
    monitor->release = release[1]; release[1] = -1;
    monitor->control = control[1]; control[1] = -1;
    if ((failure = mark_private(monitor->configuration, true, true)) || (failure = mark_private(monitor->status, true, false)) ||
        (failure = mark_private(monitor->release, true, true)) || (failure = mark_private(monitor->control, true, true))) goto cleanup;
    original[3] = configuration[0]; original[5] = status[1]; original[6] = release[0]; original[7] = control[0];
    for (int i = 0; i < descriptor_count; ++i) { copies[i] = fcntl(original[i], F_DUPFD_CLOEXEC, 128); if (copies[i] < 0) { failure = system_error(); goto cleanup; } }
    close_descriptor(&configuration[0]); close_descriptor(&status[1]); close_descriptor(&release[0]); close_descriptor(&control[0]);
    monitor->events = kqueue(); if (monitor->events < 0) { failure = system_error(); goto cleanup; }
    if ((failure = mark_private(monitor->events, false, false))) goto cleanup;
    posix_spawn_file_actions_t actions;
    if ((failure = posix_spawn_file_actions_init(&actions))) goto cleanup;
    for (int i = 0; i < descriptor_count; ++i) {
        failure = posix_spawn_file_actions_adddup2(&actions, copies[i], i);
        if (failure) { posix_spawn_file_actions_destroy(&actions); goto cleanup; }
    }
    posix_spawnattr_t attributes;
    if ((failure = posix_spawnattr_init(&attributes))) { posix_spawn_file_actions_destroy(&actions); goto cleanup; }
    sigset_t empty, defaults; sigemptyset(&empty); sigfillset(&defaults);
    failure = posix_spawnattr_setsigmask(&attributes, &empty);
    if (!failure) failure = posix_spawnattr_setsigdefault(&attributes, &defaults);
    if (!failure) failure = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSID | POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    char *arguments[] = {(char *)path, "--monitor", (char *)child, NULL}, *environment[] = {NULL};
    if (!failure) failure = posix_spawn(&monitor->state.monitor_pid, path, &actions, &attributes, arguments, environment);
    posix_spawnattr_destroy(&attributes); posix_spawn_file_actions_destroy(&actions);
    if (failure) goto cleanup;
    *result = monitor;
    struct kevent change; EV_SET(&change, monitor->state.monitor_pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXIT, 0, NULL);
    if (kevent(monitor->events, &change, 1, NULL, 0, NULL)) { failure = system_error(); goto cleanup; }
    if (kill(monitor->state.monitor_pid, SIGCONT)) { failure = system_error(); goto cleanup; }
    monitor->resumed = true;
cleanup:
    for (int i = 0; i < descriptor_count; ++i) close_descriptor(&copies[i]);
    for (int i = 0; i < 2; ++i) { close_descriptor(&configuration[i]); close_descriptor(&status[i]); close_descriptor(&release[i]); close_descriptor(&control[i]); }
    if (failure && !*result) { close_resources(monitor); free(monitor); }
    if (failure && *result) monitor->state.fault = failure;
    return failure;
}
int remozio_command_monitor_spawn(const char *path, const char *child, const void *frame, size_t count,
    int input, int output, int error, int directory, remozio_command_monitor_t **result) {
    return spawn_monitor(path, child, frame, count, input, output, error, directory, -1, false, result);
}
int remozio_command_monitor_spawn_with_terminal(const char *path, const char *child, const void *frame, size_t count,
    int input, int output, int error, int directory, int terminal, remozio_command_monitor_t **result) {
    return spawn_monitor(path, child, frame, count, input, output, error, directory, terminal, true, result);
}
static int pump_configuration(remozio_command_monitor_t *monitor) {
    if (monitor->configuration < 0) return 0;
    for (unsigned turn = 0; turn < 16 && monitor->written < monitor->frame_count; ++turn) {
        size_t remaining = monitor->frame_count - monitor->written;
        ssize_t sent = write(monitor->configuration, monitor->frame + monitor->written, remaining < 16384 ? remaining : 16384);
        if (sent > 0) monitor->written += (size_t)sent;
        else if (sent < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
        else return sent < 0 ? system_error() : EIO;
    }
    if (monitor->written == monitor->frame_count) {
        close_descriptor(&monitor->configuration); clear_frame(monitor); monitor->state.configured = true;
    }
    return 0;
}
static int target_snapshot(remozio_command_monitor_t *monitor, const remozio_monitor_record_t *record, struct proc_bsdinfo *snapshot) {
    if (!record->target_pid || record->target_pid == (uint32_t)monitor->state.monitor_pid || monitor->state.monitor_reaped || monitor->state.monitor_ownership_lost) return EPROTO;
    memset(snapshot, 0, sizeof(*snapshot));
    if (proc_pidinfo((int)record->target_pid, PROC_PIDTBSDINFO, 0, snapshot, sizeof(*snapshot)) != sizeof(*snapshot)) return ESRCH;
    if (snapshot->pbi_pid != record->target_pid || snapshot->pbi_ppid != (uint32_t)monitor->state.monitor_pid || !snapshot->pbi_start_tvsec || snapshot->pbi_start_tvusec >= 1000000 ||
        snapshot->pbi_status == SZOMB || (snapshot->pbi_flags & PROC_FLAG_INEXIT)) return ESRCH;
    if ((record->flags & REMOZIO_MONITOR_BIRTH_KNOWN) && (snapshot->pbi_start_tvsec != record->birth_seconds || snapshot->pbi_start_tvusec != record->birth_microseconds)) return EPROTO;
    return 0;
}
int remozio_command_monitor_current_job(remozio_command_monitor_t *monitor, remozio_command_current_job_t *job) {
    if (!monitor || !job) return EINVAL;
    memset(job, 0, sizeof(*job));
    if (getpid() != monitor->parent) return EPERM;
    const remozio_command_monitor_observation_t *state = &monitor->state;
    const remozio_monitor_record_t *record = &state->status.latest;
    if (state->fault || state->cancelled || state->protocol_failed || !state->release_attempted ||
        !state->target_kernel_registered || !state->target_exec_observed || state->target_exit_observed ||
        state->monitor_reaped || state->monitor_ownership_lost || state->monitor_exit_observed || state->status_closed ||
        !state->status.prepared || state->status.failed || state->status.reaped || !state->status.target_release_attempted ||
        !(record->flags & REMOZIO_MONITOR_BIRTH_KNOWN) ||
        state->status.last_applied_control_sequence != monitor->control_sequence) return 0;
    struct proc_bsdinfo before, after;
    if (target_snapshot(monitor, record, &before)) return 0;
    mach_port_t name = MACH_PORT_NULL;
    if (task_name_for_pid(mach_task_self(), (int)record->target_pid, &name) != KERN_SUCCESS) return 0;
    mach_task_basic_info_data_t first = {0}, second = {0};
    mach_msg_type_number_t first_count = MACH_TASK_BASIC_INFO_COUNT, second_count = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t first_status = task_info(name, MACH_TASK_BASIC_INFO, (task_info_t)&first, &first_count);
    kern_return_t second_status = task_info(name, MACH_TASK_BASIC_INFO, (task_info_t)&second, &second_count);
    mach_port_deallocate(mach_task_self(), name);
    if (first_status != KERN_SUCCESS || second_status != KERN_SUCCESS ||
        first_count != MACH_TASK_BASIC_INFO_COUNT || second_count != MACH_TASK_BASIC_INFO_COUNT ||
        first.suspend_count < 0 || first.suspend_count != second.suspend_count ||
        target_snapshot(monitor, record, &after)) return 0;
    if (before.pbi_status != after.pbi_status || before.pbi_pgid != after.pbi_pgid ||
        (before.pbi_flags & PROC_FLAG_TRACED) != (after.pbi_flags & PROC_FLAG_TRACED)) return 0;
    bool stopped = after.pbi_status == SSTOP && second.suspend_count > 0;
    if (second.suspend_count > 0 && !stopped) return 0;
    if (after.pbi_status != SSTOP && after.pbi_status != SRUN && after.pbi_status != SSLEEP) return 0;
    if (stopped && (record->tag != REMOZIO_MONITOR_JOB_STATE || !(record->flags & REMOZIO_MONITOR_STOPPED) ||
        !record->job_revision || !record->detail || record->detail >= NSIG)) return 0;
    job->known = true; job->stopped = stopped;
    job->traced = (after.pbi_flags & PROC_FLAG_TRACED) != 0;
    job->original_group = after.pbi_pgid == record->target_pid;
    job->job_revision = state->status.last_job_revision;
    job->stop_signal = stopped ? record->detail : 0;
    return 0;
}
static int register_target(remozio_command_monitor_t *monitor, const remozio_monitor_record_t *record) {
    struct proc_bsdinfo before, after;
    int error = target_snapshot(monitor, record, &before); if (error) return error;
    struct kevent change; EV_SET(&change, record->target_pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXEC | NOTE_EXIT, 0, NULL);
    if (kevent(monitor->events, &change, 1, NULL, 0, NULL)) return system_error();
    error = target_snapshot(monitor, record, &after); if (error) return error;
    if (before.pbi_start_tvsec != after.pbi_start_tvsec || before.pbi_start_tvusec != after.pbi_start_tvusec) return EPROTO;
    monitor->state.target_kernel_registered = true;
    return 0;
}
static int fail_status_protocol(remozio_command_monitor_t *monitor, int error) {
    monitor->state.protocol_failed = true;
    close_descriptor(&monitor->status); monitor->state.status_closed = true;
    return error;
}
static int pump_status(remozio_command_monitor_t *monitor) {
    if (monitor->status < 0 || monitor->state.protocol_failed) return 0;
    for (unsigned turn = 0; turn < 4; ++turn) {
        ssize_t received = read(monitor->status, monitor->status_bytes + monitor->status_count, sizeof(monitor->status_bytes) - monitor->status_count);
        if (received < 0) return errno == EAGAIN || errno == EINTR ? 0 : system_error();
        if (!received) {
            close_descriptor(&monitor->status); monitor->state.status_closed = true;
            if (monitor->status_count) return fail_status_protocol(monitor, EPROTO);
            return 0;
        }
        monitor->status_count += (size_t)received;
        if (monitor->status_count == sizeof(monitor->status_bytes)) {
            remozio_monitor_record_t record;
            int error = remozio_monitor_record_decode(monitor->status_bytes, sizeof(monitor->status_bytes), &record);
            if (!error && record.tag == REMOZIO_MONITOR_CONTROL_APPLIED && record.applied_control_sequence > monitor->control_sequence) error = EPROTO;
            if (!error) error = remozio_monitor_stream_accept(&monitor->state.status, &record);
            if (error) return fail_status_protocol(monitor, error);
            monitor->status_count = 0;
            if (record.tag == REMOZIO_MONITOR_PREPARED) {
                if (!monitor->state.configured) return fail_status_protocol(monitor, EPROTO);
                error = register_target(monitor, &record); if (error) return error;
                monitor->state.prepared = true;
            }
        }
    }
    return 0;
}
int remozio_command_monitor_poll(remozio_command_monitor_t *monitor, remozio_command_monitor_observation_t *observation) {
    if (!monitor || !observation) return EINVAL;
    int error = monitor->state.fault;
    if (!error && !monitor->state.cancelled && !monitor->state.release_attempted && !monitor->state.monitor_reaped) {
        if (milliseconds(monitor) >= monitor->deadline) error = ETIMEDOUT;
        else error = pump_configuration(monitor);
    }
    int status_error = pump_status(monitor); if (!error) error = status_error;
    struct timespec immediate = {0,0};
    for (unsigned turn = 0; turn < 8; ++turn) {
        struct kevent event; int count = kevent(monitor->events, NULL, 0, &event, 1, &immediate);
        if (count < 0) { if (errno != EINTR && !error) error = system_error(); break; }
        if (!count) break;
        if ((event.flags & EV_ERROR) || event.filter != EVFILT_PROC) { if (!error) error = EIO; break; }
        if (event.ident == (uintptr_t)monitor->state.monitor_pid) monitor->state.monitor_exit_observed |= (event.fflags & NOTE_EXIT) != 0;
        else if (monitor->state.target_kernel_registered && event.ident == monitor->state.status.latest.target_pid) {
            monitor->state.target_exec_observed |= (event.fflags & NOTE_EXEC) != 0;
            monitor->state.target_exit_observed |= (event.fflags & NOTE_EXIT) != 0;
            if (monitor->state.target_exec_observed && !monitor->state.release_attempted && !error) error = EPROTO;
        } else if (!error) error = EPROTO;
    }
    if (!monitor->state.monitor_reaped && !monitor->state.monitor_ownership_lost && (monitor->state.monitor_exit_observed || error)) {
        int status = 0; pid_t ended = waitpid(monitor->state.monitor_pid, &status, WNOHANG);
        if (ended == monitor->state.monitor_pid) { monitor->state.monitor_reaped = true; monitor->state.monitor_wait_status = status; }
        else if (ended < 0 && errno != EINTR) { if (errno == ECHILD) monitor->state.monitor_ownership_lost = true; if (!error) error = system_error(); }
    }
    if (error) monitor->state.fault = error;
    *observation = monitor->state;
    return error;
}
int remozio_command_monitor_release(remozio_command_monitor_t *monitor) {
    if (!monitor) return EINVAL;
    if (monitor->state.release_attempted) return EALREADY;
    remozio_command_monitor_observation_t observed;
    int error = remozio_command_monitor_poll(monitor, &observed); if (error) return error;
    if (observed.cancelled || observed.monitor_reaped || observed.monitor_ownership_lost || observed.monitor_exit_observed || observed.status_closed || observed.status.failed || observed.status.reaped || observed.target_exit_observed) return ECANCELED;
    if (!observed.configured || !observed.prepared || !observed.target_kernel_registered) return EAGAIN;
    error = remozio_monitor_stream_note_release(&monitor->state.status); if (error) return error;
    monitor->state.release_attempted = true;
    unsigned char byte = 1; ssize_t written = write(monitor->release, &byte, 1);
    error = written == 1 ? 0 : written < 0 ? system_error() : EIO;
    close_descriptor(&monitor->release); if (error) monitor->state.fault = error;
    return error;
}
int remozio_command_monitor_signal(remozio_command_monitor_t *monitor, int number) {
    if (!monitor || number <= 0 || number >= NSIG) return EINVAL;
    remozio_command_monitor_observation_t observed;
    int error = remozio_command_monitor_poll(monitor, &observed); if (error) return error;
    if (observed.cancelled || observed.monitor_reaped || observed.monitor_ownership_lost || observed.status.reaped || observed.target_exit_observed) return ESRCH;
    if (!observed.release_attempted || !observed.prepared) return EAGAIN;
    if (monitor->control_sequence == UINT64_MAX) return EOVERFLOW;
    remozio_monitor_control_t record = {.tag = REMOZIO_MONITOR_SIGNAL, .signal = (uint32_t)number, .sequence = monitor->control_sequence + 1};
    unsigned char bytes[REMOZIO_MONITOR_CONTROL_BYTES]; error = remozio_monitor_control_encode(&record, bytes); if (error) return error;
    ssize_t written = write(monitor->control, bytes, sizeof(bytes));
    if (written == sizeof(bytes)) { monitor->control_sequence = record.sequence; return 0; }
    error = written < 0 ? system_error() : EIO;
    if (error != EAGAIN) monitor->state.fault = error;
    return error;
}
int remozio_command_monitor_cancel(remozio_command_monitor_t *monitor) {
    if (!monitor) return EINVAL;
    monitor->state.cancelled = true;
    close_descriptor(&monitor->control); close_descriptor(&monitor->configuration); close_descriptor(&monitor->release); clear_frame(monitor);
    if (!monitor->resumed && monitor->state.monitor_pid > 0 && !monitor->state.monitor_reaped && !monitor->state.monitor_ownership_lost) {
        remozio_command_monitor_observation_t observation;
        (void)remozio_command_monitor_poll(monitor, &observation);
        if (!observation.monitor_reaped && !observation.monitor_ownership_lost) {
            monitor->resumed = true;
            if (kill(monitor->state.monitor_pid, SIGCONT) && errno != ESRCH) return system_error();
        }
    }
    return 0;
}
int remozio_command_monitor_dispose(remozio_command_monitor_t *monitor) {
    if (!monitor) return 0;
    if (!monitor->state.monitor_reaped && !monitor->state.monitor_ownership_lost) return EBUSY;
    close_resources(monitor); free(monitor); return 0;
}
