/* Private terminal execution tests. No service, borrowed target signals, or privileged credential changes. */
#include "RemozioCommandChild.h"
#include "RemozioCommandMonitor.h"
#include "RemozioCommandPTY.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
typedef struct { unsigned char bytes[256]; size_t count; bool eof; } buffer_t;
static uint64_t milliseconds(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static int drain_pty(remozio_command_pty_t *pty, buffer_t *buffer) {
    if (!pty || buffer->eof) return 0;
    size_t count = 0; bool eof = false;
    int error = remozio_command_pty_read(pty, buffer->bytes + buffer->count, sizeof(buffer->bytes) - buffer->count, &count, &eof);
    if (error) return error;
    buffer->count += count; buffer->eof = eof;
    return 0;
}
static int drain_pipe(int fd, buffer_t *buffer) {
    if (buffer->eof) return 0;
    struct pollfd item = {.fd = fd, .events = POLLIN};
    int ready = poll(&item, 1, 0);
    if (ready < 0) return errno;
    if (!ready) return 0;
    ssize_t n = read(fd, buffer->bytes + buffer->count, sizeof(buffer->bytes) - buffer->count);
    if (n < 0) return errno == EINTR ? 0 : errno;
    buffer->count += (size_t)n; buffer->eof = n == 0;
    return 0;
}
static bool ends_with_control(const buffer_t *buffer) {
    return buffer->count >= 8 && !memcmp(buffer->bytes + buffer->count - 8, "CONTROL\n", 8);
}
static bool matches(const buffer_t *buffer, const void *bytes, size_t count) {
    return buffer->count == count && !memcmp(buffer->bytes, bytes, count);
}
static void put_word(unsigned char *bytes, uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) bytes[index] = (unsigned char)(value >> ((3U - index) * 8));
}
int main(int argc, char **argv) {
    if (argc != 6) return 1;
    unsigned mask = (unsigned)atoi(argv[4]);
    bool distinct = !strcmp(argv[5], "distinct"), cancel = !strcmp(argv[5], "cancel"), stop = !strcmp(argv[5], "stop");
    bool prepared_cancel = !strcmp(argv[5], "prepared_cancel");
    FILE *file = fopen(argv[3], "rb"); if (!file) return 2;
    unsigned char frame[8192]; size_t count = fread(frame, 1, sizeof(frame), file); fclose(file);
    int input[2], output[2], errors[2];
    if (pipe(input) || pipe(output) || pipe(errors)) return 3;
    int directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC), slave = -1, other_slave = -1, inspection = -1;
    remozio_command_pty_t *pty = NULL, *other = NULL;
    remozio_command_monitor_t *monitor = NULL; remozio_command_monitor_observation_t state = {0};
    buffer_t terminal_bytes = {0}, out = {0}, err = {0}, other_bytes = {0};
    int failure = 0, native_error = 0, streams[3] = {-1, -1, -1}, initial_flags[3] = {0};
    int flag_inspectors[3] = {-1, -1, -1}, observed_flags[3] = {-1, -1, -1};
    if (directory < 0 || remozio_command_pty_create(NULL, NULL, &pty) || remozio_command_pty_borrow_slave(pty, &slave)) { failure = 4; goto cleanup; }
    struct termios attributes;
    if (tcgetattr(slave, &attributes)) { failure = 5; goto cleanup; }
    cfmakeraw(&attributes);
    if (tcsetattr(slave, TCSANOW, &attributes)) { failure = 5; goto cleanup; }
    if (distinct) {
        if (mask != 5 || remozio_command_pty_create(&attributes, NULL, &other) || remozio_command_pty_borrow_slave(other, &other_slave)) { failure = 6; goto cleanup; }
    }
    streams[0] = mask & 1 ? slave : input[0];
    streams[1] = mask & 2 ? slave : distinct ? other_slave : output[1];
    streams[2] = mask & 4 ? slave : errors[1];
    for (int index = 0; index < 3; ++index) {
        initial_flags[index] = fcntl(streams[index], F_GETFL);
        if (!(mask & (1U << index))) {
            flag_inspectors[index] = fcntl(streams[index], F_DUPFD_CLOEXEC, 32);
            if (flag_inspectors[index] < 0) { failure = 8; goto cleanup; }
        }
    }
    inspection = fcntl(streams[0], F_DUPFD_CLOEXEC, 32);
    const unsigned char bytes[] = {'I', 0, 0xfd, '\n'};
    if (mask & 1) {
        size_t written = 0;
        if (remozio_command_pty_write(pty, bytes, sizeof(bytes), &written) || written != sizeof(bytes)) { failure = 7; goto cleanup; }
    } else if (write(input[1], bytes, sizeof(bytes)) != sizeof(bytes)) { failure = 7; goto cleanup; }
    close(input[1]); input[1] = -1;
    if (inspection < 0) { failure = 8; goto cleanup; }
    if (!strcmp(argv[5], "preflight")) {
        if (remozio_command_monitor_spawn(argv[1], argv[2], frame, count, streams[0], streams[1], streams[2], directory, &monitor) != ENOTSUP || monitor) { failure = 9; goto cleanup; }
        remozio_child_spec_t spec = {0};
        if (remozio_child_spec_decode(frame, count, &spec)) { failure = 10; goto cleanup; }
        size_t groups_end = 44 + spec.group_count * 4U, payload = groups_end + 4 + strlen(spec.account_name);
        size_t removed = 4 + payload - groups_end, legacy_count = count - removed;
        unsigned char legacy[8192]; memcpy(legacy, frame, 40);
        memcpy(legacy + 40, frame + 44, spec.group_count * 4U);
        memcpy(legacy + groups_end - 4, frame + payload, count - payload);
        remozio_child_spec_close(&spec);
        put_word(legacy, REMOZIO_CHILD_FRAME_V1); put_word(legacy + 4, (uint32_t)(legacy_count - 40)); put_word(legacy + 36, 0);
        if (remozio_command_monitor_spawn_with_terminal(argv[1], argv[2], legacy, legacy_count, input[0], output[1], errors[1], directory, slave, &monitor) != ENOTSUP || monitor) { failure = 10; goto cleanup; }
        int mismatch = mask & 1 ? input[0] : slave;
        if (remozio_command_monitor_spawn_with_terminal(argv[1], argv[2], frame, count, mismatch, streams[1], streams[2], directory, slave, &monitor) != EINVAL || monitor) { failure = 11; goto cleanup; }
        goto retained;
    }
    native_error = remozio_command_monitor_spawn_with_terminal(argv[1], argv[2], frame, count, streams[0], streams[1], streams[2], directory, slave, &monitor);
    if (native_error || !monitor) { failure = 12; goto cleanup; }
    uint64_t deadline = milliseconds() + 8000;
    while (!state.prepared && milliseconds() < deadline) {
        native_error = remozio_command_monitor_poll(monitor, &state);
        if (native_error) { failure = 13; goto cleanup; }
        usleep(1000);
    }
    if (!state.prepared || !state.target_kernel_registered || state.target_exec_observed || state.release_attempted) { failure = 14; goto cleanup; }
retained:;
    int available = 0;
    if (ioctl(inspection, FIONREAD, &available) || available != sizeof(bytes)) { failure = 15; goto cleanup; }
    for (int index = 0; index < 3; ++index)
        if (fcntl(streams[index], F_GETFL) != initial_flags[index]) { failure = 16; goto cleanup; }
    if (!monitor) goto cleanup;
    close(inspection); inspection = -1;
    remozio_command_pty_seal_slave(pty); remozio_command_pty_seal_slave(other);
    close(output[1]); output[1] = -1; close(errors[1]); errors[1] = -1;
    if (prepared_cancel) {
        for (int index = 0; index < 3; ++index) if (flag_inspectors[index] >= 0) { close(flag_inspectors[index]); flag_inspectors[index] = -1; }
        if (remozio_command_monitor_cancel(monitor)) { failure = 17; goto cleanup; }
    } else if (remozio_command_monitor_release(monitor) || remozio_command_monitor_release(monitor) != EALREADY) { failure = 17; goto cleanup; }
    bool sent = prepared_cancel, resumed = false;
    deadline = milliseconds() + 10000;
    while (milliseconds() < deadline) {
        native_error = remozio_command_monitor_poll(monitor, &state);
        if (native_error || drain_pty(pty, &terminal_bytes) || drain_pty(other, &other_bytes) ||
            drain_pipe(output[0], &out) || drain_pipe(errors[0], &err)) { failure = 18; goto cleanup; }
        if (!sent && ends_with_control(&terminal_bytes) && (!stop || (state.status.latest.tag == REMOZIO_MONITOR_JOB_STATE && (state.status.latest.flags & REMOZIO_MONITOR_STOPPED)))) {
            if (terminal_bytes.eof) { failure = 19; goto cleanup; }
            for (int index = 0; index < 3; ++index) if (flag_inspectors[index] >= 0) {
                observed_flags[index] = fcntl(flag_inspectors[index], F_GETFL);
                /* XNU FWASWRITTEN records writes. Do not clear that kernel bookkeeping bit. */
                if (observed_flags[index] < 0 || ((observed_flags[index] ^ initial_flags[index]) & ~0x10000)) { failure = 27; goto cleanup; }
                close(flag_inspectors[index]); flag_inspectors[index] = -1;
            }
            if (stop) { if (remozio_command_monitor_signal(monitor, SIGCONT)) { failure = 20; goto cleanup; } resumed = true; }
            if (cancel) {
                if (remozio_command_monitor_cancel(monitor)) { failure = 21; goto cleanup; }
            } else {
                struct winsize size = {.ws_row = 53, .ws_col = 143};
                if (remozio_command_pty_resize(pty, &size) || remozio_command_pty_signal(pty, SIGUSR1) || remozio_command_monitor_signal(monitor, SIGUSR2)) { failure = 22; goto cleanup; }
            }
            sent = true;
        }
        if (state.monitor_reaped && state.status_closed && terminal_bytes.eof && out.eof && err.eof && (!other || other_bytes.eof)) break;
        usleep(1000);
    }
    if (!sent || (stop && !resumed) || !state.monitor_reaped || !state.status_closed || !terminal_bytes.eof || !out.eof || !err.eof || (other && !other_bytes.eof)) { failure = 23; goto cleanup; }
    if (state.target_exec_observed == prepared_cancel || !state.target_exit_observed || !state.status.reaped || state.status.failed || state.monitor_ownership_lost || state.monitor_wait_status != 0 || state.status.target_release_attempted == prepared_cancel) { failure = 24; goto cleanup; }
    int actual = (int)state.status.latest.detail;
    if (cancel || prepared_cancel ? (!WIFSIGNALED(actual) || WTERMSIG(actual) != SIGKILL) : (!WIFEXITED(actual) || WEXITSTATUS(actual) != 7)) { failure = 25; goto cleanup; }
    if (prepared_cancel) {
        if (state.release_attempted || terminal_bytes.count || out.count || err.count) failure = 29;
        goto cleanup;
    }
    const unsigned char expected_out[] = {'O', 'U', 'T', 0, 0xff, '\n'};
    const unsigned char expected_err[] = {'E', 'R', 'R', 0, 0xfe, '\n'};
    unsigned char expected_terminal[20]; size_t expected_count = 0;
    if (mask & 2) { memcpy(expected_terminal + expected_count, expected_out, sizeof(expected_out)); expected_count += sizeof(expected_out); }
    if (mask & 4) { memcpy(expected_terminal + expected_count, expected_err, sizeof(expected_err)); expected_count += sizeof(expected_err); }
    memcpy(expected_terminal + expected_count, "CONTROL\n", 8); expected_count += 8;
    if (!matches(&terminal_bytes, expected_terminal, expected_count) ||
        !matches(&out, expected_out, !(mask & 2) && !distinct ? sizeof(expected_out) : 0) ||
        !matches(&err, expected_err, !(mask & 4) ? sizeof(expected_err) : 0) ||
        (distinct && !matches(&other_bytes, expected_out, sizeof(expected_out)))) { failure = 26; goto cleanup; }
    if (!(mask & 1) && fcntl(input[0], F_GETFL) != initial_flags[0]) { failure = 27; goto cleanup; }
cleanup:
    if (monitor) {
        (void)remozio_command_monitor_cancel(monitor); uint64_t cleanup_deadline = milliseconds() + 10000;
        while (!state.monitor_reaped && !state.monitor_ownership_lost && milliseconds() < cleanup_deadline) {
            (void)remozio_command_monitor_poll(monitor, &state);
            (void)drain_pty(pty, &terminal_bytes); (void)drain_pty(other, &other_bytes);
            (void)drain_pipe(output[0], &out); (void)drain_pipe(errors[0], &err); usleep(1000);
        }
        if (remozio_command_monitor_dispose(monitor)) failure = 28;
    }
    if (inspection >= 0) close(inspection);
    for (int index = 0; index < 3; ++index) if (flag_inspectors[index] >= 0) close(flag_inspectors[index]);
    remozio_command_pty_close(pty); remozio_command_pty_close(other);
    close(input[0]); if (input[1] >= 0) close(input[1]); close(output[0]); close(errors[0]);
    if (output[1] >= 0) close(output[1]); if (errors[1] >= 0) close(errors[1]); if (directory >= 0) close(directory);
    printf("{\"mask\":%u,\"mode\":\"%s\",\"failure\":%d,\"nativeError\":%d,\"targetStatus\":%u,\"helperError\":%u,\"independentExec\":%s,\"independentExit\":%s,\"monitorActuallyReaped\":%s,\"terminalEOF\":%s,\"initialFlags\":[%d,%d,%d],\"observedDirectFlags\":[%d,%d,%d]}\n",
        mask, argv[5], failure, native_error, state.status.latest.detail, state.status.failure_error,
        state.target_exec_observed ? "true" : "false", state.target_exit_observed ? "true" : "false",
        state.monitor_reaped ? "true" : "false", terminal_bytes.eof ? "true" : "false",
        initial_flags[0], initial_flags[1], initial_flags[2], observed_flags[0], observed_flags[1], observed_flags[2]);
    return failure ? 1 : 0;
}
