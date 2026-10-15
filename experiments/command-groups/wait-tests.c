#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static int kill_calls, clock_calls, fail_clock_at;
static bool reverse_clock, child_owned;
static pid_t active_child = -1;
static struct timespec first_clock;
static int observed_kill(pid_t pid, int signal);
static int observed_clock(clockid_t clock, struct timespec *time);
#define kill observed_kill
#define clock_gettime observed_clock
#define main credential_probe_main
#include "probe.c"
#undef main
#undef clock_gettime
#undef kill

static int observed_kill(pid_t pid, int signal) {
    kill_calls++;
    int status = 0;
    if (!child_owned || pid != active_child || waitpid(pid, &status, WNOHANG) != 0) {
        errno = ECHILD; return -1;
    }
    return kill(pid, signal);
}
static int observed_clock(clockid_t clock, struct timespec *time) {
    clock_calls++;
    if (clock_calls == fail_clock_at) { errno = EIO; return -1; }
    int status = clock_gettime(clock, time);
    if (status == 0 && clock_calls == 1) first_clock = *time;
    if (status == 0 && reverse_clock && clock_calls == 2) {
        *time = first_clock; time->tv_sec--;
    }
    return status;
}
static void cleanup(void) {
    if (child_owned && active_child > 0) {
        int status = 0; pid_t waited;
        do { waited = waitpid(active_child, &status, WNOHANG); } while (waited < 0 && errno == EINTR);
        if (waited == 0) {
            kill(active_child, SIGKILL);
            while (waitpid(active_child, &status, 0) < 0 && errno == EINTR) {}
        }
    }
}
static pid_t spawn_child(bool finish) {
    kill_calls = clock_calls = fail_clock_at = 0; reverse_clock = false;
    pid_t pid = fork();
    if (pid == 0) { if (finish) _exit(0); for (;;) pause(); }
    if (pid > 0) { active_child = pid; child_owned = true; }
    return pid;
}
static bool reaped(pid_t pid) {
    int status = 0; errno = 0;
    bool gone = waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD;
    if (gone) { child_owned = false; active_child = -1; }
    return gone;
}
#define CHECK(value) do { if (!(value)) { fprintf(stderr, "Owned child check failed at line %d\n", __LINE__); return 1; } } while (0)
int main(void) {
    if (getuid() == 0 || geteuid() == 0) return 77;
    CHECK(atexit(cleanup) == 0);
    struct sigaction normal, ignored;
    memset(&normal, 0, sizeof(normal)); normal.sa_handler = SIG_DFL;
    CHECK(sigemptyset(&normal.sa_mask) == 0 && sigaction(SIGCHLD, &normal, NULL) == 0);
    int status = 0; pid_t pid = spawn_child(true); CHECK(pid > 0);
    CHECK(wait_for_owned_child(pid, &status, 2.0) == 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0 && kill_calls == 0 && reaped(pid));

    pid = spawn_child(false); CHECK(pid > 0);
    CHECK(wait_for_owned_child(pid, &status, 0.05) == -1);
    CHECK(kill_calls == 1 && reaped(pid));

    pid = spawn_child(true); CHECK(pid > 0);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    child_owned = false;
    CHECK(wait_for_owned_child(pid, &status, 0.05) == -1);
    CHECK(kill_calls == 0 && reaped(pid));

    ignored = normal; ignored.sa_handler = SIG_IGN;
    CHECK(sigaction(SIGCHLD, &ignored, NULL) == 0);
    pid = spawn_child(true); CHECK(pid > 0); child_owned = false;
    CHECK(wait_for_owned_child(pid, &status, 2.0) == -1);
    CHECK(kill_calls == 0 && reaped(pid));
    CHECK(sigaction(SIGCHLD, &normal, NULL) == 0);

    for (int failure = 1; failure <= 2; failure++) {
        pid = spawn_child(false); CHECK(pid > 0); fail_clock_at = failure;
        CHECK(wait_for_owned_child(pid, &status, 0.1) == -1);
        CHECK(kill_calls == 1 && clock_calls == failure && reaped(pid));
    }
    pid = spawn_child(false); CHECK(pid > 0); reverse_clock = true;
    CHECK(wait_for_owned_child(pid, &status, 0.1) == -1);
    CHECK(kill_calls == 1 && clock_calls == 2 && reaped(pid));
    puts("{\"schemaVersion\":1,\"passed\":true,\"cases\":7,\"privilegedControlsRun\":false,\"unreapedChildren\":0}");
    return 0;
}
