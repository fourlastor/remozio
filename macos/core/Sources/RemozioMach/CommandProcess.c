#include "include/RemozioCommandProcess.h"
#include "include/RemozioCommandChild.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libproc.h>
#include <sys/proc.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

struct remozio_command_process {
    remozio_command_process_observation_t state;
    int configuration, status, release, events, retained_terminal;
    unsigned char *frame;
    size_t frame_count, written;
    unsigned char status_bytes[12];
    size_t status_count;
    unsigned status_records;
    int fault;
    bool cancelled;
    uint64_t deadline;
    mach_timebase_info_data_t timebase;
};
static int system_error(void) { return errno ? errno : EIO; }
static void close_descriptor(int *value) { if (*value >= 0) { close(*value); *value = -1; } }
static void clear_frame(remozio_command_process_t *process) {
    if (process->frame) {
        volatile unsigned char *bytes = process->frame;
        for (size_t i = 0; i < process->frame_count; ++i) bytes[i] = 0;
        free(process->frame); process->frame = NULL;
    }
}
static void close_resources(remozio_command_process_t *process) {
    close_descriptor(&process->configuration); close_descriptor(&process->status);
    close_descriptor(&process->release); close_descriptor(&process->events);
    close_descriptor(&process->retained_terminal); clear_frame(process);
}
static uint64_t now(remozio_command_process_t *process) {
    return (uint64_t)(((__uint128_t)mach_continuous_time() * process->timebase.numer) / ((uint64_t)process->timebase.denom * 1000000));
}
static uint32_t word(const unsigned char *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
}
static int mark_private(int fd, bool nonblocking, bool writing) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) return system_error();
    if (nonblocking) {
        flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return system_error();
    }
    if (writing && fcntl(fd, F_SETNOSIGPIPE, 1) < 0) return system_error();
    return 0;
}
static int private_pipe(int ends[2]) {
    if (pipe(ends) < 0) return system_error();
    int error = mark_private(ends[0], false, false);
    if (!error) error = mark_private(ends[1], false, false);
    if (error) { close_descriptor(&ends[0]); close_descriptor(&ends[1]); }
    return error;
}
static void clear_stop(remozio_command_process_t *process) {
    process->state.stopped = false; process->state.stop_signal = process->state.stop_code = 0;
    process->state.stop_tracing_known = process->state.stop_traced = false;
}
static void capture_birth(remozio_command_process_t *process) {
    struct proc_bsdinfo details = {0};
    int bytes = proc_pidinfo(process->state.pid, PROC_PIDTBSDINFO, 0, &details, sizeof(details));
    if (bytes == sizeof(details) && details.pbi_pid == (uint32_t)process->state.pid && details.pbi_start_tvsec && details.pbi_start_tvusec < 1000000) {
        process->state.birth_seconds = details.pbi_start_tvsec; process->state.birth_microseconds = details.pbi_start_tvusec;
        process->state.birth_known = true;
    }
}
static int spawn_child(const char *path, const void *frame, size_t count,
    int input, int output, int error, int directory, int terminal, bool mapped, bool monitor_session, remozio_command_process_t **result) {
    if (!result) return EINVAL;
    *result = NULL;
    if (monitor_session && (getsid(0) != getpid() || getpgrp() != getpid())) return EINVAL;
    if (!path || path[0] != '/' || strnlen(path, PATH_MAX) >= PATH_MAX) return EINVAL;
    struct sigaction child_action;
    if (sigaction(SIGCHLD, NULL, &child_action) < 0) return system_error();
    if (child_action.sa_handler == SIG_IGN || (child_action.sa_flags & SA_NOCLDWAIT)) return EINVAL;
    remozio_child_spec_t spec = {0};
    int failure = remozio_child_spec_decode(frame, count, &spec);
    if (failure) return failure;
    if (spec.format_version == 3 ? ((spec.io_mode == 2) != mapped) : spec.format_version != (mapped ? 2U : 1U)) { remozio_child_spec_close(&spec); return ENOTSUP; }
    if (mapped) {
        int streams[3] = {input, output, error};
        failure = remozio_child_spec_validate_stdio(&spec, terminal, streams);
        if (failure) { remozio_child_spec_close(&spec); return failure; }
    }
    uint32_t budget = spec.preparation_milliseconds, io_mode = spec.io_mode;
    remozio_child_spec_close(&spec);
    int controlling = mapped ? terminal : input;
    if (monitor_session && io_mode != 0 && (tcgetsid(controlling) != getsid(0) || tcgetpgrp(controlling) != getpgrp())) return EINVAL;
    size_t descriptor_count = mapped ? 8 : 7;
    int original[8] = {input, output, error, -1, directory, -1, -1, terminal}, copies[8];
    int config[2] = {-1,-1}, status[2] = {-1,-1}, release[2] = {-1,-1};
    for (size_t i = 0; i < descriptor_count; ++i) copies[i] = -1;
    remozio_command_process_t *process = calloc(1, sizeof(*process));
    if (!process) return ENOMEM;
    process->configuration = process->status = process->release = process->events = process->retained_terminal = -1;
    if (mapped && !monitor_session) {
        process->retained_terminal = fcntl(terminal, F_DUPFD_CLOEXEC, 128);
        if (process->retained_terminal < 0) { failure = system_error(); goto cleanup; }
    }
    process->frame = malloc(count); process->frame_count = count;
    if (!process->frame) { failure = ENOMEM; goto cleanup; }
    memcpy(process->frame, frame, count);
    if (mach_timebase_info(&process->timebase) != KERN_SUCCESS || !process->timebase.denom || !process->timebase.numer) { failure = EIO; goto cleanup; }
    process->deadline = now(process) + budget;
    for (int i = 0; i < 3; ++i) {
        int flags = fcntl(original[i], F_GETFL);
        if (flags < 0) { failure = system_error(); goto cleanup; }
        if ((flags & O_EVTONLY) || (i == 0 ? (flags & O_ACCMODE) == O_WRONLY : (flags & O_ACCMODE) == O_RDONLY)) { failure = EINVAL; goto cleanup; }
    }
    struct stat cwd;
    if (fstat(directory, &cwd) < 0) { failure = system_error(); goto cleanup; }
    if (!S_ISDIR(cwd.st_mode)) { failure = EINVAL; goto cleanup; }
    if ((failure = private_pipe(config)) || (failure = private_pipe(status)) ||
        (failure = private_pipe(release))) goto cleanup;
    process->configuration = config[1]; config[1] = -1;
    process->status = status[0]; status[0] = -1;
    process->release = release[1]; release[1] = -1;
    if ((failure = mark_private(process->configuration, true, true)) ||
        (failure = mark_private(process->status, true, false)) ||
        (failure = mark_private(process->release, true, true))) goto cleanup;
    original[3] = config[0]; original[5] = status[1]; original[6] = release[0];
    for (size_t i = 0; i < descriptor_count; ++i) {
        copies[i] = fcntl(original[i], F_DUPFD_CLOEXEC, 128);
        if (copies[i] < 0) { failure = system_error(); goto cleanup; }
    }
    close_descriptor(&config[0]); close_descriptor(&status[1]); close_descriptor(&release[0]);
    process->events = kqueue();
    if (process->events < 0) { failure = system_error(); goto cleanup; }
    if ((failure = mark_private(process->events, false, false))) goto cleanup;
    posix_spawn_file_actions_t actions;
    if ((failure = posix_spawn_file_actions_init(&actions))) goto cleanup;
    for (size_t i = 0; i < descriptor_count; ++i) {
        failure = posix_spawn_file_actions_adddup2(&actions, copies[i], (int)i);
        if (failure) { posix_spawn_file_actions_destroy(&actions); goto cleanup; }
    }
    posix_spawnattr_t attributes;
    if ((failure = posix_spawnattr_init(&attributes))) { posix_spawn_file_actions_destroy(&actions); goto cleanup; }
    sigset_t empty, defaults; sigemptyset(&empty); sigfillset(&defaults);
    short flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
    flags |= io_mode != 0 && !monitor_session ? POSIX_SPAWN_SETSID : POSIX_SPAWN_SETPGROUP;
    failure = posix_spawnattr_setsigmask(&attributes, &empty);
    if (!failure) failure = posix_spawnattr_setsigdefault(&attributes, &defaults);
    if (!failure && (io_mode == 0 || monitor_session)) failure = posix_spawnattr_setpgroup(&attributes, 0);
    if (!failure) failure = posix_spawnattr_setflags(&attributes, flags);
    char *arguments[] = {(char *)path, monitor_session ? "--execute-in-session" : "--execute", NULL}, *environment[] = {NULL};
    if (!failure) failure = posix_spawn(&process->state.pid, path, &actions, &attributes, arguments, environment);
    posix_spawnattr_destroy(&attributes); posix_spawn_file_actions_destroy(&actions);
    if (failure) goto cleanup;
    *result = process;
    struct kevent change;
    EV_SET(&change, process->state.pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXEC | NOTE_EXIT, 0, NULL);
    if (kevent(process->events, &change, 1, NULL, 0, NULL) < 0) { failure = system_error(); goto cleanup; }
    capture_birth(process);
    if (monitor_session && io_mode != 0 && tcsetpgrp(controlling, process->state.pid) < 0) { failure = system_error(); goto cleanup; }
    if (kill(process->state.pid, SIGCONT) < 0) { failure = system_error(); goto cleanup; }
cleanup:
    for (size_t i = 0; i < descriptor_count; ++i) close_descriptor(&copies[i]);
    for (size_t i = 0; i < 2; ++i) { close_descriptor(&config[i]); close_descriptor(&status[i]); close_descriptor(&release[i]); }
    if (failure && !*result) { close_resources(process); free(process); }
    if (failure && *result) process->fault = failure;
    return failure;
}
int remozio_command_process_spawn(const char *path, const void *frame, size_t count,
    int input, int output, int error, int directory, remozio_command_process_t **result) {
    return spawn_child(path, frame, count, input, output, error, directory, -1, false, false, result);
}
int remozio_command_process_spawn_in_session(const char *path, const void *frame, size_t count,
    int input, int output, int error, int directory, remozio_command_process_t **result) {
    return spawn_child(path, frame, count, input, output, error, directory, -1, false, true, result);
}
int remozio_command_process_spawn_with_terminal(const char *path, const void *frame, size_t count,
    int input, int output, int error, int directory, int terminal, remozio_command_process_t **result) {
    return spawn_child(path, frame, count, input, output, error, directory, terminal, true, false, result);
}
int remozio_command_process_spawn_in_session_with_terminal(const char *path, const void *frame, size_t count,
    int input, int output, int error, int directory, int terminal, remozio_command_process_t **result) {
    return spawn_child(path, frame, count, input, output, error, directory, terminal, true, true, result);
}
static int pump_configuration(remozio_command_process_t *process) {
    if (process->configuration < 0) return 0;
    for (unsigned turn = 0; turn < 16 && process->written < process->frame_count; ++turn) {
        size_t remaining = process->frame_count - process->written;
        ssize_t sent = write(process->configuration, process->frame + process->written, remaining < 16384 ? remaining : 16384);
        if (sent > 0) process->written += (size_t)sent;
        else if (sent < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
        else return sent < 0 ? system_error() : EIO;
    }
    if (process->written == process->frame_count) {
        close_descriptor(&process->configuration); clear_frame(process); process->state.configured = true;
    }
    return 0;
}
static int status_record(remozio_command_process_t *process) {
    uint32_t tag = word(process->status_bytes + 4), detail = word(process->status_bytes + 8);
    if (word(process->status_bytes) != 0x524d5231 || ++process->status_records > 2) return EPROTO;
    if (tag == 1 && detail == 0 && !process->state.prepared && !process->state.preparation_failed && process->state.configured) process->state.prepared = true;
    else if (tag == 2 && detail > 0 && detail <= INT_MAX && !process->state.preparation_failed) {
        process->state.preparation_failed = true; process->state.preparation_error = (int)detail;
    } else return EPROTO;
    process->status_count = 0; return 0;
}
static int pump_status(remozio_command_process_t *process) {
    if (process->status < 0) return 0;
    for (unsigned turn = 0; turn < 4; ++turn) {
        ssize_t received = read(process->status, process->status_bytes + process->status_count, 12 - process->status_count);
        if (received < 0) return errno == EAGAIN || errno == EINTR ? 0 : system_error();
        if (received == 0) {
            close_descriptor(&process->status); process->state.status_closed = true;
            return process->status_count == 0 ? 0 : EPROTO;
        }
        process->status_count += (size_t)received;
        if (process->status_count == 12) { int error = status_record(process); if (error) return error; }
    }
    return 0;
}
static int observe_job_control(remozio_command_process_t *process) {
    if (process->state.reaped || process->state.ownership_lost) return 0;
    for (unsigned turn = 0; turn < 4; ++turn) {
        siginfo_t info = {0};
        if (waitid(P_PID, (id_t)process->state.pid, &info, WSTOPPED | WCONTINUED | WNOHANG) < 0) {
            if (errno == EINTR) return 0;
            if (errno == ECHILD) { process->state.ownership_lost = true; clear_stop(process); }
            return system_error();
        }
        if (info.si_signo == 0 && info.si_code == 0 && info.si_pid == 0) return 0;
        if (info.si_signo != SIGCHLD || (info.si_code != CLD_STOPPED && info.si_code != CLD_TRAPPED && info.si_code != CLD_CONTINUED)) return EPROTO;
        if (info.si_code != CLD_CONTINUED && info.si_pid != process->state.pid) return EPROTO;
        if (process->state.job_control_revision == UINT64_MAX) return EOVERFLOW;
        if (info.si_code == CLD_STOPPED || info.si_code == CLD_TRAPPED) {
            if (info.si_status <= 0 || info.si_status >= NSIG) return EPROTO;
            process->state.stopped = true; process->state.stop_signal = info.si_status; process->state.stop_code = info.si_code;
            process->state.stop_tracing_known = process->state.stop_traced = false;
            struct proc_bsdinfo details = {0};
            int bytes = proc_pidinfo(process->state.pid, PROC_PIDTBSDINFO, 0, &details, sizeof(details));
            if (process->state.birth_known && bytes == sizeof(details) && details.pbi_pid == (uint32_t)process->state.pid &&
                details.pbi_start_tvsec == process->state.birth_seconds && details.pbi_start_tvusec == process->state.birth_microseconds &&
                details.pbi_status == SSTOP && !(details.pbi_flags & PROC_FLAG_INEXIT)) {
                process->state.stop_tracing_known = true;
                process->state.stop_traced = (details.pbi_flags & PROC_FLAG_TRACED) != 0;
            }
        } else { clear_stop(process); }
        ++process->state.job_control_revision;
    }
    return 0;
}
static int reap_owned(remozio_command_process_t *process) {
    if (process->state.reaped || process->state.ownership_lost) return 0;
    int status = 0; pid_t ended = waitpid(process->state.pid, &status, WNOHANG);
    if (ended == process->state.pid) { process->state.reaped = true; process->state.wait_status = status; clear_stop(process); }
    else if (ended < 0 && errno != EINTR) {
        if (errno == ECHILD) { process->state.ownership_lost = true; clear_stop(process); }
        return system_error();
    }
    return 0;
}
int remozio_command_process_poll(remozio_command_process_t *process, remozio_command_process_observation_t *observation) {
    if (!process || !observation) return EINVAL;
    int error = process->fault;
    struct timespec immediate = {0,0};
    for (unsigned turn = 0; turn < 8 && !process->state.exit_observed && !process->state.ownership_lost; ++turn) {
        struct kevent event;
        int count = kevent(process->events, NULL, 0, &event, 1, &immediate);
        if (count < 0) { if (errno != EINTR && !error) error = system_error(); break; }
        if (!count) break;
        if ((event.flags & EV_ERROR) || event.ident != (uintptr_t)process->state.pid || event.filter != EVFILT_PROC) { if (!error) error = EIO; break; }
        process->state.exec_observed |= (event.fflags & NOTE_EXEC) != 0;
        process->state.exit_observed |= (event.fflags & NOTE_EXIT) != 0;
        if (process->state.exec_observed && !process->state.release_attempted && !error) error = EPROTO;
    }
    if (!error && !process->cancelled && !process->state.release_attempted && !process->state.reaped) {
        if (now(process) >= process->deadline) error = ETIMEDOUT;
        else error = pump_configuration(process);
    }
    int status_error = pump_status(process);
    if (!error) error = status_error;
    int job_error = observe_job_control(process);
    if (!error) error = job_error;
    /* A fault still permits a nonblocking reap of the exclusively owned child, without killing released work.
     * Never infer exec from this fallback. */
    if (!process->state.reaped && !process->state.ownership_lost && (process->state.exit_observed || error)) {
        int wait_error = reap_owned(process);
        if (!error) error = wait_error;
    }
    if (error) { process->fault = error; close_descriptor(&process->configuration); close_descriptor(&process->release); clear_frame(process); }
    *observation = process->state;
    return error;
}
int remozio_command_process_release(remozio_command_process_t *process) {
    if (!process) return EINVAL;
    if (process->state.release_attempted) return EALREADY;
    remozio_command_process_observation_t observation;
    int error = remozio_command_process_poll(process, &observation);
    if (error) return error;
    if (process->cancelled || observation.reaped || observation.exit_observed || observation.preparation_failed || observation.status_closed) return ECANCELED;
    if (!observation.configured || !observation.prepared) return EAGAIN;
    process->state.release_attempted = true;
    const unsigned char byte = 1;
    ssize_t written = write(process->release, &byte, 1);
    error = written == 1 ? 0 : written < 0 ? system_error() : EIO;
    close_descriptor(&process->release);
    if (error) process->fault = error;
    return error;
}
int remozio_command_process_signal(remozio_command_process_t *process, int number) {
    if (!process || number <= 0 || number >= NSIG) return EINVAL;
    if (process->state.reaped || process->state.ownership_lost || process->state.pid <= 0) return ESRCH;
    return kill(-process->state.pid, number) == 0 ? 0 : system_error();
}
static bool owned_exit_in_progress(remozio_command_process_t *process) {
    if (!process->state.birth_known || process->state.reaped || process->state.ownership_lost) return false;
    struct kinfo_proc info = {0}; size_t count = sizeof(info);
    int selector[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, process->state.pid};
    if (sysctl(selector, 4, &info, &count, NULL, 0) || count != sizeof(info)) return false;
    return info.kp_proc.p_pid == process->state.pid && info.kp_eproc.e_ppid == getpid() &&
        (info.kp_proc.p_flag & P_WEXIT) &&
        (uint64_t)info.kp_proc.p_starttime.tv_sec == process->state.birth_seconds &&
        (uint64_t)info.kp_proc.p_starttime.tv_usec == process->state.birth_microseconds;
}
int remozio_command_process_cancel(remozio_command_process_t *process) {
    if (!process) return EINVAL;
    process->cancelled = true;
    int error = process->state.reaped ? 0 : remozio_command_process_signal(process, SIGKILL);
    close_descriptor(&process->configuration); close_descriptor(&process->release); clear_frame(process);
    if (error == EPERM) {
        remozio_command_process_observation_t observation;
        (void)remozio_command_process_poll(process, &observation);
        if (!observation.reaped && !observation.ownership_lost) (void)reap_owned(process);
        if (process->state.reaped || owned_exit_in_progress(process)) return 0;
    }
    return error == ESRCH ? 0 : error;
}
int remozio_command_process_dispose(remozio_command_process_t *process) {
    if (!process) return 0;
    if (!process->state.reaped && !process->state.ownership_lost) return EBUSY;
    close_resources(process); free(process); return 0;
}
