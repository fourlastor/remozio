/* Disposable ordinary-owner fixture. Private parent fields let us close the control
 * channel without adding a production API that abandons monitor ownership. */
#include "CommandMonitor.c"
#include "RemozioCommandPTY.h"
#include <stdio.h>
#include <sys/file.h>
#include <time.h>
static uint64_t now(void) {
    struct timespec value; clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static int await_monitor(remozio_command_monitor_t *monitor, remozio_command_monitor_observation_t *state, bool finished) {
    uint64_t until = now() + 8000;
    do {
        int error = remozio_command_monitor_poll(monitor, state);
        if (finished ? state->monitor_reaped && state->status_closed : state->prepared) return 0;
        if (error) return error;
        usleep(1000);
    } while (now() < until);
    return ETIMEDOUT;
}
static bool busy(int descriptor) {
    if (flock(descriptor, LOCK_EX | LOCK_NB) == 0) { flock(descriptor, LOCK_UN); return false; }
    return errno == EWOULDBLOCK;
}
int main(int argc, char **argv) {
    if (argc != 5) return 1;
    FILE *frame_file = fopen(argv[3], "rb"); if (!frame_file) return 2;
    unsigned char frame[8192]; size_t count = fread(frame, 1, sizeof(frame), frame_file); fclose(frame_file);
    int activity = open("activity.lock", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    int observer = open("activity.lock", O_RDWR | O_CLOEXEC), directory = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int input = open("/dev/null", O_RDONLY | O_CLOEXEC), output[2], errors[2];
    if (activity < 0 || observer < 0 || directory < 0 || input < 0 || pipe(output) || pipe(errors)) return 3;
    remozio_command_monitor_t *monitor = NULL; remozio_command_monitor_observation_t state = {0};
    remozio_command_pty_t *pty = NULL; int slave = -1, failure = 0; bool paused = false;
    if (!strcmp(argv[4], "invalid")) {
        int pipe_ends[2]; if (pipe(pipe_ends)) return 4;
        for (unsigned variant = 0; variant < 7; ++variant) {
            int supplied = activity;
            if (variant == 0) supplied = -1;
            if (variant == 1) supplied = pipe_ends[0];
            if (variant == 2) supplied = directory;
            if (variant == 3 && fchmod(activity, 0644)) return 5;
            if (variant == 4 && ftruncate(activity, 1)) return 6;
            if (variant == 5 && fcntl(activity, F_SETFD, 0)) return 7;
            if (variant == 6 && link("activity.lock", "activity.alias")) return 8;
            int error = remozio_command_monitor_spawn_with_activity(argv[1], argv[2], frame, count,
                input, output[1], errors[1], directory, -1, supplied, &monitor);
            if (!error || monitor) return 9;
            if (fchmod(activity, 0600) || ftruncate(activity, 0) || fcntl(activity, F_SETFD, FD_CLOEXEC)) return 10;
        }
        close(pipe_ends[0]); close(pipe_ends[1]); goto cleanup;
    }
    bool terminal = strstr(argv[4], "terminal") != NULL;
    bool mapped = !strcmp(argv[4], "mapped-terminal");
    if (terminal) {
        if (remozio_command_pty_create(NULL, NULL, &pty) || remozio_command_pty_borrow_slave(pty, &slave)) return 11;
        struct termios attributes; if (tcgetattr(slave, &attributes)) return 12;
        cfmakeraw(&attributes); if (tcsetattr(slave, TCSANOW, &attributes)) return 13;
    }
    if (flock(activity, LOCK_SH | LOCK_NB)) return 14;
    if (remozio_command_monitor_spawn_with_activity(argv[1], argv[2], frame, count,
        terminal ? slave : input, terminal ? slave : output[1], terminal ? slave : errors[1], directory, mapped ? slave : -1, activity, &monitor)) { failure = 15; goto cleanup; }
    if (pty) remozio_command_pty_seal_slave(pty);
    close_descriptor(&output[1]); close_descriptor(&errors[1]);
    if (await_monitor(monitor, &state, false) || !state.target_kernel_registered) { failure = 16; goto cleanup; }
    if (strcmp(argv[4], "cancel")) {
        if (remozio_command_monitor_release(monitor)) { failure = 17; goto cleanup; }
        unsigned char received[5]; size_t used = 0; uint64_t until = now() + 5000;
        int flags = fcntl(output[0], F_GETFL); fcntl(output[0], F_SETFL, flags | O_NONBLOCK);
        while (used < sizeof(received) && now() < until) {
            if (pty) {
                size_t bytes = 0; bool eof = false;
                if (remozio_command_pty_read(pty, received + used, sizeof(received) - used, &bytes, &eof) || eof) break;
                used += bytes;
            } else {
                ssize_t bytes = read(output[0], received + used, sizeof(received) - used);
                if (bytes > 0) used += (size_t)bytes;
                else if (!bytes || (errno != EAGAIN && errno != EINTR)) break;
            }
            usleep(1000);
        }
        if (used != sizeof(received) || memcmp(received, "WAIT\n", sizeof(received))) { failure = 18; goto cleanup; }
        /* The fixture program checks every private descriptor before emitting WAIT. */
    }
    if (kill(state.monitor_pid, SIGSTOP)) { failure = 19; goto cleanup; }
    paused = true;
    int stopped = 0;
    if (waitpid(state.monitor_pid, &stopped, WUNTRACED) != state.monitor_pid || !WIFSTOPPED(stopped)) { failure = 20; goto cleanup; }
    close_descriptor(&activity);
    if (!busy(observer)) { failure = 21; goto cleanup; }
    if (!strcmp(argv[4], "cancel")) {
        if (remozio_command_monitor_cancel(monitor)) { failure = 22; goto cleanup; }
    } else {
        /* Root-side EOF while retaining actual wait ownership for the experiment. */
        close_descriptor(&monitor->control);
    }
    if (!busy(observer)) { failure = 23; goto cleanup; }
    if (kill(state.monitor_pid, SIGCONT)) { failure = 24; goto cleanup; }
    paused = false;
    if (await_monitor(monitor, &state, true) || !state.status.reaped || !state.target_exit_observed || state.monitor_ownership_lost) { failure = 25; goto cleanup; }
    if (flock(observer, LOCK_EX | LOCK_NB)) { failure = 26; goto cleanup; }
    flock(observer, LOCK_UN);
cleanup:
    if (monitor) {
        if (paused) kill(state.monitor_pid, SIGCONT);
        remozio_command_monitor_cancel(monitor);
        if (!state.monitor_reaped) (void)await_monitor(monitor, &state, true);
        if (remozio_command_monitor_dispose(monitor) && !failure) failure = 27;
    }
    if (pty) remozio_command_pty_close(pty);
    close_descriptor(&activity); close(observer); close(directory); close(input);
    close_descriptor(&output[0]); close_descriptor(&output[1]); close_descriptor(&errors[0]); close_descriptor(&errors[1]);
    printf("{\"failure\":%d,\"monitorActuallyReaped\":%s}\n", failure, state.monitor_reaped ? "true" : "false");
    return failure ? 1 : 0;
}
