/* Disposable unprivileged driver. It never installs or launches a root service. */
#include "RemozioCommandMonitorProtocol.h"
#include "RemozioCommandPTY.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static uint64_t milliseconds(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static int send_control(int fd, uint32_t tag, int signal, uint64_t sequence, bool bad_version, bool partial) {
    remozio_monitor_control_t record = {.tag = tag, .signal = (uint32_t)signal, .sequence = sequence};
    unsigned char bytes[32]; int error = remozio_monitor_control_encode(&record, bytes); if (error) return error;
    if (bad_version) bytes[7] ^= 1;
    size_t count = partial ? 7 : sizeof(bytes);
    return write(fd, bytes, count) == (ssize_t)count ? 0 : EIO;
}
int main(int argc, char **argv) {
    if (argc != 5) return 1;
    const char *mode = argv[4];
    bool before = !strcmp(mode, "cancel_before_configuration"), stopped_cancel = !strcmp(mode, "stopped_cancel"), normal_stop = !strcmp(mode, "stop_resume");
    bool prepared_cancel = !strcmp(mode, "prepared_cancel") || !strcmp(mode, "large_configuration"), release_eof = !strcmp(mode, "release_eof"), bad_release = !strcmp(mode, "bad_release");
    bool bad_control = !strcmp(mode, "bad_control"), partial_control = !strcmp(mode, "partial_control"), replay = !strcmp(mode, "replayed_control");
    bool typed = !strcmp(mode, "typed_resume"), terminal = typed || !strcmp(mode, "pty_stop_resume");
    bool blocked_status = !strcmp(mode, "blocked_status"), broken_status = !strcmp(mode, "broken_status"), after_exec_cancel = !strcmp(mode, "cancel_after_exec");
    bool closed_release = !strcmp(mode, "closed_release");
    bool stalled_config = !strcmp(mode, "stalled_configuration"), partial_config = !strcmp(mode, "partial_configuration"), malformed = !strcmp(mode, "malformed_configuration");
    bool expected_failure = before || bad_release || bad_control || partial_control || replay || stalled_config || partial_config || malformed || broken_status || !strcmp(mode, "exec_failure") || !strcmp(mode, "stalled_child") || !strcmp(mode, "malformed_child");
    FILE *file = fopen(argv[3], "rb"); if (!file) return 2;
    fseek(file, 0, SEEK_END); long length = ftell(file); rewind(file);
    if (length < 40 || length > 8 * 1024 * 1024) { fclose(file); return 2; }
    size_t frame_count = (size_t)length; unsigned char *frame = malloc(frame_count);
    if (!frame || fread(frame, 1, frame_count, file) != frame_count) { fclose(file); free(frame); return 2; }
    fclose(file); if (malformed) frame[0] ^= 1;
    int input[2] = {-1,-1}, output[2] = {-1,-1}, error_pipe[2] = {-1,-1}, configuration[2] = {-1,-1}, status[2] = {-1,-1}, release[2] = {-1,-1}, control[2] = {-1,-1};
    int directory = -1, copies[8]; for (int i = 0; i < 8; ++i) copies[i] = -1;
    pid_t monitor = 0; int failure = 0, monitor_status = 0, events = -1; bool monitor_reaped = false, exec_seen = false, exit_seen = false, status_closed = false, stop_seen = false, sent_stop = false, stop_handled = false, signal_sent = false, target_not_waitable = false;
    remozio_command_pty_t *pty = NULL; int slave = -1; bool pty_eof = false;
    remozio_monitor_stream_t stream; remozio_monitor_stream_init(&stream);
    if (pipe(input) || pipe(output) || pipe(error_pipe) || pipe(configuration) || pipe(status) || pipe(release) || pipe(control)) { failure = 3; goto cleanup; }
    int *all[] = {input, output, error_pipe, configuration, status, release, control};
    for (unsigned p = 0; p < sizeof(all) / sizeof(all[0]); ++p) for (int i = 0; i < 2; ++i) fcntl(all[p][i], F_SETFD, FD_CLOEXEC);
    directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0 || write(input[1], "unread", 6) != 6) { failure = 4; goto cleanup; }
    int input_flags = fcntl(input[0], F_GETFL); close(input[1]); input[1] = -1;
    size_t filler_count = 0;
    if (terminal) {
        if (remozio_command_pty_create(NULL, NULL, &pty) || remozio_command_pty_borrow_slave(pty, &slave)) { failure = 6; goto cleanup; }
        struct termios attributes; if (tcgetattr(slave, &attributes)) { failure = 6; goto cleanup; }
        cfmakeraw(&attributes); if (typed) attributes.c_lflag |= ISIG;
        if (tcsetattr(slave, TCSANOW, &attributes)) { failure = 6; goto cleanup; }
    }
    int original[8] = {terminal ? slave : input[0], terminal ? slave : output[1], terminal ? slave : error_pipe[1], configuration[0], directory, status[1], release[0], control[0]};
    for (int i = 0; i < 8; ++i) { copies[i] = fcntl(original[i], F_DUPFD_CLOEXEC, 128); if (copies[i] < 0) { failure = 7; goto cleanup; } }
    posix_spawn_file_actions_t actions; posix_spawnattr_t attributes;
    posix_spawn_file_actions_init(&actions); posix_spawnattr_init(&attributes);
    for (int i = 0; i < 8; ++i) posix_spawn_file_actions_adddup2(&actions, copies[i], i);
    sigset_t empty, defaults; sigemptyset(&empty); sigfillset(&defaults);
    posix_spawnattr_setsigmask(&attributes, &empty); posix_spawnattr_setsigdefault(&attributes, &defaults);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    char *arguments[] = {argv[1], "--monitor", argv[2], NULL}, *environment[] = {NULL};
    int spawned = posix_spawn(&monitor, argv[1], &actions, &attributes, arguments, environment);
    posix_spawnattr_destroy(&attributes); posix_spawn_file_actions_destroy(&actions);
    if (spawned) { failure = 8; goto cleanup; }
    for (int i = 0; i < 8; ++i) { close(copies[i]); copies[i] = -1; }
    close(configuration[0]); configuration[0] = -1; if (!blocked_status) { close(status[1]); status[1] = -1; } close(release[0]); release[0] = -1; close(control[0]); control[0] = -1;
    close(output[1]); output[1] = -1; close(error_pipe[1]); error_pipe[1] = -1;
    if (pty) remozio_command_pty_seal_slave(pty);
    fcntl(configuration[1], F_SETFL, O_NONBLOCK); fcntl(configuration[1], F_SETNOSIGPIPE, 1); fcntl(status[0], F_SETFL, O_NONBLOCK);
    fcntl(control[1], F_SETNOSIGPIPE, 1); fcntl(release[1], F_SETNOSIGPIPE, 1);
    if (before) { if (send_control(control[1], REMOZIO_MONITOR_CANCEL, 0, 1, false, false)) { failure = 9; goto cleanup; } }
    size_t written = 0, status_used = 0; unsigned char status_bytes[64];
    bool blocked_cancel_sent = false;
    uint64_t started = milliseconds(), deadline = started + 12000;
    while ((!status_closed || !monitor_reaped) && milliseconds() < deadline) {
        if (configuration[1] >= 0 && !before) {
            size_t wanted = stalled_config ? 40 : partial_config ? 47 : frame_count;
            if (written < wanted) {
                size_t remaining = wanted - written; ssize_t n = write(configuration[1], frame + written, remaining < 16384 ? remaining : 16384);
                if (n > 0) written += (size_t)n; else if (errno != EAGAIN && errno != EINTR && errno != EPIPE) { failure = 10; goto cleanup; }
            }
            if (written == wanted && !stalled_config) { close(configuration[1]); configuration[1] = -1; }
        }
        if (blocked_status && blocked_cancel_sent && exit_seen && filler_count) {
            unsigned char discard[4096]; size_t wanted = filler_count < sizeof(discard) ? filler_count : sizeof(discard);
            ssize_t n = read(status[0], discard, wanted); if (n > 0) filler_count -= (size_t)n;
        }
        if (!status_closed && (!blocked_status || !filler_count)) {
            for (unsigned turn = 0; turn < 4; ++turn) {
                ssize_t n = read(status[0], status_bytes + status_used, sizeof(status_bytes) - status_used);
                if (n == 0) { status_closed = true; if (status_used) { failure = 11; goto cleanup; } break; }
                if (n < 0) { if (errno == EAGAIN || errno == EINTR) break; failure = 11; goto cleanup; }
                status_used += (size_t)n; if (status_used != sizeof(status_bytes)) continue;
                remozio_monitor_record_t record;
                if (remozio_monitor_record_decode(status_bytes, sizeof(status_bytes), &record) || remozio_monitor_stream_accept(&stream, &record)) { failure = 12; goto cleanup; }
                status_used = 0;
                if (record.tag == REMOZIO_MONITOR_PREPARED) {
                    int available = 0; if (ioctl(input[0], FIONREAD, &available) || available != 6 || fcntl(input[0], F_GETFL) != input_flags) { failure = 13; goto cleanup; }
                    {
                        events = kqueue(); struct kevent change; EV_SET(&change, record.target_pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_EXEC | NOTE_EXIT, 0, NULL);
                        if (events < 0 || kevent(events, &change, 1, NULL, 0, NULL)) { failure = 14; goto cleanup; }
                        int target_status = 0; errno = 0; target_not_waitable = waitpid((pid_t)record.target_pid, &target_status, WNOHANG) == -1 && errno == ECHILD;
                        if (!target_not_waitable || !record.birth_seconds || !(record.flags & REMOZIO_MONITOR_BIRTH_KNOWN)) { failure = 15; goto cleanup; }
                    }
                    if (blocked_status) {
                        if (fcntl(status[1], F_SETFL, O_NONBLOCK)) { failure = 5; goto cleanup; }
                        unsigned char filler[512]; memset(filler, 0xa5, sizeof(filler));
                        for (;;) {
                            ssize_t filled = write(status[1], filler, sizeof(filler));
                            if (filled > 0) filler_count += (size_t)filled;
                            else if (errno == EAGAIN) break;
                            else { failure = 5; goto cleanup; }
                        }
                        close(status[1]); status[1] = -1; close(control[1]); control[1] = -1;
                        blocked_cancel_sent = true;
                    } else if (prepared_cancel || broken_status) { close(control[1]); control[1] = -1; if (broken_status) { close(status[0]); status[0] = -1; status_closed = true; } }
                    else if (release_eof) { close(release[1]); release[1] = -1; }
                    else if (bad_control || partial_control) {
                        if (send_control(control[1], REMOZIO_MONITOR_SIGNAL, SIGTERM, 1, bad_control, partial_control)) { failure = 16; goto cleanup; }
                        if (partial_control) { close(control[1]); control[1] = -1; }
                    } else if (!blocked_status) {
                        if (remozio_monitor_stream_note_release(&stream)) { failure = 17; goto cleanup; }
                        unsigned char byte = bad_release ? 0 : 1;
                        if (write(release[1], &byte, 1) != 1) { failure = 17; goto cleanup; }
                        close(release[1]); release[1] = -1;
                    }
                } else if (record.tag == REMOZIO_MONITOR_JOB_STATE && (record.flags & REMOZIO_MONITOR_STOPPED) && !stop_handled) {
                    stop_seen = true; stop_handled = true;
                    if (record.detail != (uint32_t)(typed ? SIGTSTP : SIGSTOP) || !(record.flags & REMOZIO_MONITOR_TRACING_KNOWN) || (record.flags & REMOZIO_MONITOR_TRACED)) { failure = 18; goto cleanup; }
                    if (stopped_cancel) { if (send_control(control[1], REMOZIO_MONITOR_CANCEL, 0, 1, false, false)) { failure = 19; goto cleanup; } }
                    else if (replay) {
                        if (send_control(control[1], REMOZIO_MONITOR_SIGNAL, SIGCONT, 2, false, false) || send_control(control[1], REMOZIO_MONITOR_SIGNAL, SIGTERM, 2, false, false)) { failure = 19; goto cleanup; }
                    } else if (send_control(control[1], REMOZIO_MONITOR_SIGNAL, SIGCONT, 1, false, false)) { failure = 19; goto cleanup; }
                } else if (typed && stop_handled && record.tag == REMOZIO_MONITOR_JOB_STATE && !(record.flags & REMOZIO_MONITOR_STOPPED) && !signal_sent) {
                    if (send_control(control[1], REMOZIO_MONITOR_SIGNAL, SIGTERM, 2, false, false)) { failure = 20; goto cleanup; }
                    signal_sent = true;
                }
                if (status_closed || (blocked_status && filler_count)) break;
            }
        }
        if (events >= 0) {
            struct kevent event; struct timespec immediate = {0,0}; int count = kevent(events, NULL, 0, &event, 1, &immediate);
            if (count < 0 || (count == 1 && (event.flags & EV_ERROR))) { failure = 21; goto cleanup; }
            if (count == 1) { exec_seen |= (event.fflags & NOTE_EXEC) != 0; exit_seen |= (event.fflags & NOTE_EXIT) != 0; }
        }
        if (exec_seen && (typed || replay) && !sent_stop) {
            if (typed) { unsigned char byte = 0x1a; size_t sent = 0; if (remozio_command_pty_write(pty, &byte, 1, &sent) || sent != 1) { failure = 22; goto cleanup; } }
            else if (send_control(control[1], REMOZIO_MONITOR_SIGNAL, SIGSTOP, 1, false, false)) { failure = 22; goto cleanup; }
            sent_stop = true;
        }
        if (exec_seen && after_exec_cancel && !signal_sent) {
            if (send_control(control[1], REMOZIO_MONITOR_CANCEL, 0, 1, false, false)) { failure = 23; goto cleanup; }
            signal_sent = true;
        }
        if (pty && !pty_eof) { unsigned char discard[4096]; size_t count = 0; if (remozio_command_pty_read(pty, discard, sizeof(discard), &count, &pty_eof)) { failure = 24; goto cleanup; } }
        if (!monitor_reaped) {
            pid_t got = waitpid(monitor, &monitor_status, WNOHANG); if (got == monitor) monitor_reaped = true; else if (got < 0) { failure = 25; goto cleanup; }
        }
        usleep(1000);
    }
    if (!monitor_reaped || !status_closed || !WIFEXITED(monitor_status) || WEXITSTATUS(monitor_status) != (expected_failure ? 70 : 0)) { failure = 26; goto cleanup; }
    if (!broken_status && (stream.failed != expected_failure || (stream.latest.target_pid != 0 && !stream.reaped))) { failure = 27; goto cleanup; }
    if ((normal_stop || terminal || stopped_cancel || replay) && !stop_seen) { failure = 28; goto cleanup; }
    if (!broken_status && stream.reaped) {
        int actual = (int)stream.latest.detail;
        if (stopped_cancel || prepared_cancel || release_eof || closed_release || bad_release || bad_control || partial_control || replay || after_exec_cancel || blocked_status || !strcmp(mode,"stalled_child") || !strcmp(mode,"malformed_child")) {
            if (!(WIFSIGNALED(actual) && WTERMSIG(actual) == SIGKILL) && !(WIFEXITED(actual) && WEXITSTATUS(actual) == 70)) { failure = 29; goto cleanup; }
        } else if (typed) { if (!WIFSIGNALED(actual) || WTERMSIG(actual) != SIGTERM) { failure = 29; goto cleanup; } }
        else if (!strcmp(mode,"exec_failure")) { if (!WIFEXITED(actual) || WEXITSTATUS(actual) != 70) { failure = 29; goto cleanup; } }
        else if (!WIFEXITED(actual) || WEXITSTATUS(actual) != 7) { failure = 29; goto cleanup; }
    }
    if (events >= 0 && (!exit_seen || (exec_seen != (normal_stop || terminal || stopped_cancel || replay || after_exec_cancel || !strcmp(mode,"output"))))) { failure = 30; goto cleanup; }
    if (!strcmp(mode,"output")) {
        unsigned char out[64], err[16]; ssize_t out_count = read(output[0], out, sizeof(out)), err_count = read(error_pipe[0], err, sizeof(err));
        if (out_count != 10 || memcmp(out,"OUT:unread",10) || err_count != 3 || memcmp(err,"ERR",3)) { failure = 31; goto cleanup; }
    }
    if (strcmp(mode,"output")) {
        int available = 0; if (ioctl(input[0], FIONREAD, &available) || available != 6 || fcntl(input[0], F_GETFL) != input_flags) failure = 32;
    }
cleanup:
    if (control[1] >= 0) { close(control[1]); control[1] = -1; }
    if (configuration[1] >= 0) { close(configuration[1]); configuration[1] = -1; }
    if (release[1] >= 0) { close(release[1]); release[1] = -1; }
    if (monitor > 0 && !monitor_reaped) {
        uint64_t deadline = milliseconds() + 15000;
        while (!monitor_reaped && milliseconds() < deadline) {
            if (status[0] >= 0) { unsigned char discard[4096]; (void)read(status[0], discard, sizeof(discard)); }
            if (pty && !pty_eof) { unsigned char discard[4096]; size_t count = 0; (void)remozio_command_pty_read(pty, discard, sizeof(discard), &count, &pty_eof); }
            pid_t got = waitpid(monitor, &monitor_status, WNOHANG); if (got == monitor || (got < 0 && errno == ECHILD)) monitor_reaped = true;
            usleep(1000);
        }
        if (!monitor_reaped) { kill(monitor, SIGKILL); while (waitpid(monitor, NULL, 0) < 0 && errno == EINTR) {} failure = 33; }
    }
    for (int i = 0; i < 8; ++i) if (copies[i] >= 0) close(copies[i]);
    int *closing[] = {input, output, error_pipe, configuration, status, release, control};
    for (unsigned p = 0; p < sizeof(closing) / sizeof(closing[0]); ++p) for (int i = 0; i < 2; ++i) if (closing[p][i] >= 0) close(closing[p][i]);
    if (directory >= 0) close(directory); if (events >= 0) close(events); if (pty) remozio_command_pty_close(pty); free(frame);
    printf("{\"case\":\"%s\",\"failure\":%d,\"monitorReaped\":%s,\"targetReapedReport\":%s,\"independentExec\":%s,\"independentExit\":%s,\"rootCannotWaitTarget\":%s,\"monitorWaitStatus\":%d,\"reportedFailureErrno\":%u}\n", mode, failure, monitor_reaped ? "true" : "false", stream.reaped ? "true" : "false", exec_seen ? "true" : "false", exit_seen ? "true" : "false", target_not_waitable ? "true" : "false", monitor_status, stream.failure_error);
    return failure ? 1 : 0;
}
