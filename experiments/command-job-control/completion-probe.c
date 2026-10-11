/* Tests the disposable monitor's completion code. Never embed or install this fixture. */
#define main prototype_monitor_main
#include "monitor.c"
#undef main
#include <stdbool.h>
#include <string.h>

#ifdef REMOZIO_COMPLETION_LEGACY
static int legacy_completion(int failure_fd, uint32_t status) {
    (void)failure_fd;
    return report('X', status);
}
#define report_reaped_target legacy_completion
#endif

static void close_owned(int *fd) {
    if (*fd >= 0) { close(*fd); *fd = -1; }
}

static int check_case(const char *missing_path, int mode) {
    int failure[2] = {-1, -1}, gate[2] = {-1, -1}, wire[2] = {-1, -1}, written[2] = {-1, -1};
    pid_t target = -1;
    bool reaped = false, lost = false, mapped = false;
    int result = 1, status = 0;
    if (pipe(failure) || pipe(gate) || pipe(wire) || pipe(written)) goto cleanup;
    if (fcntl(failure[0], F_SETFL, O_NONBLOCK) || fcntl(failure[1], F_SETFD, FD_CLOEXEC)) goto cleanup;
    target = fork();
    if (target < 0) goto cleanup;
    if (!target) {
        close(failure[0]); close(gate[1]); close(wire[0]); close(wire[1]); close(written[0]);
        unsigned char release = 0;
        if (read(gate[0], &release, 1) != 1 || release != 1) _exit(74);
        close(gate[0]);
        if (mode == 3 || mode == 4) {
            uint16_t partial = ENOENT;
            if (write(failure[1], &partial, sizeof partial) != sizeof partial) _exit(74);
            if (mode == 4 && write(written[1], &release, 1) != 1) _exit(74);
            _exit(127);
        }
        const char *path = mode == 2 ? "/usr/bin/true" : missing_path;
        char *args[] = {(char *)path, NULL}, *environment[] = {NULL};
        execve(path, args, environment);
        int error = errno;
        if (write(failure[1], &error, sizeof error) != sizeof error) _exit(74);
        _exit(127);
    }
    close_owned(&failure[1]); close_owned(&gate[0]); close_owned(&written[1]);
    if (dup2(wire[1], 5) != 5) goto cleanup;
    mapped = true;
    close_owned(&wire[1]);
    if (fcntl(wire[0], F_SETFL, O_NONBLOCK)) goto cleanup;

    /* The child gate proves the first read precedes the exec error. No timing delay creates the race. */
    if (report_exec_error(failure[0], 1)) goto cleanup;
    unsigned char release = 1;
    if (write(gate[1], &release, 1) != 1) goto cleanup;
    close_owned(&gate[1]);
    bool early_rejected = false;
    if (mode == 4) {
        unsigned char committed = 0;
        /* The acknowledgement proves the malformed record is available before the first waitpid. */
        if (read(written[0], &committed, 1) != 1 || committed != 1) goto cleanup;
        early_rejected = report_exec_error(failure[0], 1) != 0;
        if (!early_rejected) goto cleanup;
    }
    close_owned(&written[0]);
    for (int turn = 0; turn < 5000 && !reaped; ++turn) {
        pid_t ended = waitpid(target, &status, WNOHANG);
        if (ended == target) reaped = true;
        else if (ended < 0 && errno != EINTR) { lost = errno == ECHILD; goto cleanup; }
        else usleep(1000);
    }
    if (!reaped || !WIFEXITED(status) || WEXITSTATUS(status) != (mode == 2 ? 0 : 127)) goto cleanup;
    if (mode == 1) {
        if (report_exec_error(failure[0], 1)) goto cleanup;
    }
    int completed = early_rejected ? 1 : report_reaped_target(failure[0], (uint32_t)status);
    close(5); mapped = false;
    uint32_t records[9] = {0};
    ssize_t count = read(wire[0], records, sizeof records);
    if (mode == 3 || mode == 4) {
        if (completed && count == 0) result = 0;
        goto cleanup;
    }
    if (completed) goto cleanup;
    if (mode == 2) {
        if (count == 12 && records[0] == 0x524d5431 && records[1] == 'X' && records[2] == (uint32_t)status) result = 0;
    } else {
        if (count == 24 && records[0] == 0x524d5431 && records[1] == 'F' && records[2] == ENOENT &&
            records[3] == 0x524d5431 && records[4] == 'X' && records[5] == (uint32_t)status) result = 0;
    }
cleanup:
    if (target > 0 && !reaped && !lost) {
        kill(target, SIGKILL);
        while (waitpid(target, NULL, 0) < 0 && errno == EINTR) {}
    }
    if (mapped) close(5);
    for (int i = 0; i < 2; ++i) { close_owned(&failure[i]); close_owned(&gate[i]); close_owned(&wire[i]); close_owned(&written[i]); }
    return result;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1 || getuid() == 0 || geteuid() == 0) return 77;
    char directory[] = "/tmp/remozio-completion-XXXXXX", missing[sizeof directory + 16];
    if (!mkdtemp(directory)) return 1;
    int count = snprintf(missing, sizeof missing, "%s/missing", directory);
    int result = count <= 0 || (size_t)count >= sizeof missing;
    for (int mode = 0; mode < 5 && !result; ++mode) {
        result = check_case(missing, mode);
        if (result) fprintf(stderr, "completion case %d failed\n", mode);
    }
    if (rmdir(directory)) result = 1;
    if (!result) printf("{\"lateExecErrorBeforeTerminal\":true,\"observedExecErrorNotRepeated\":true,\"normalEOFReportsWait\":true,\"partialFinalErrorBlocksTerminal\":true,\"partialPreWaitErrorBlocksTerminal\":true}\n");
    return result;
}
