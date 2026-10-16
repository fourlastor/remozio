/* Actual product monitor and child. No credential substitution or service installation. */
#include "RemozioCommandCredentials.h"
#include "RemozioCommandMonitor.h"
#include "result.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>
#define CAPACITY 1024
struct account { uid_t uid; gid_t gid; char name[256]; gid_t groups[CAPACITY]; int count; };
struct result { int credential_error; int observed_count; int access_result; int access_error; };
static int compare_group(const void *a, const void *b) {
    gid_t lhs = *(const gid_t *)a, rhs = *(const gid_t *)b;
    return lhs > rhs ? 1 : lhs < rhs ? -1 : 0;
}
static int distinct(gid_t *groups, int count) {
    qsort(groups, (size_t)count, sizeof(gid_t), compare_group);
    int kept = 0;
    for (int i = 0; i < count; i++) if (!kept || groups[i] != groups[kept - 1]) groups[kept++] = groups[i];
    return kept;
}
static int account(uid_t uid, struct account *out) {
    char storage[65536]; struct passwd entry, *found = NULL;
    int error = getpwuid_r(uid, &entry, storage, sizeof(storage), &found);
    if (error || !found || entry.pw_uid != uid || entry.pw_gid == UINT32_MAX || !entry.pw_name || !*entry.pw_name || strlen(entry.pw_name) >= sizeof(out->name)) return -1;
    out->uid = uid; out->gid = entry.pw_gid; memcpy(out->name, entry.pw_name, strlen(entry.pw_name) + 1);
    int values[CAPACITY], count = CAPACITY;
    if (getgrouplist(out->name, (int)out->gid, values, &count) < 0 || count < 1 || count > CAPACITY) return -1;
    for (int i = 0; i < count; i++) { if ((gid_t)values[i] == UINT32_MAX) return -1; out->groups[i] = (gid_t)values[i]; }
    out->count = distinct(out->groups, count);
    return 0;
}
static bool contains(const gid_t *groups, int count, gid_t group) {
    for (int i = 0; i < count; i++) if (groups[i] == group) return true;
    return false;
}

enum case_kind { positive, wrong_name, missing_group, legacy, cancel_prepared };
static char directory[PATH_MAX], monitor_path[PATH_MAX], child_path[PATH_MAX], target_path[PATH_MAX];
static bool path(char *out, const char *name) {
    return snprintf(out, PATH_MAX, "%s/%s", directory, name) < PATH_MAX;
}
static bool locate(void) {
    char executable[PATH_MAX]; uint32_t size = sizeof(executable);
    if (_NSGetExecutablePath(executable, &size) || !realpath(executable, directory)) return false;
    char *name = strrchr(directory, '/'); if (!name) return false; *name = 0;
    return path(monitor_path, "monitor") && path(child_path, "child") && path(target_path, "target");
}
static bool protected_helpers(void) {
    const char *prefix = "/private/var/tmp/remozio-production-child.";
    struct stat st;
    if (strncmp(directory, prefix, strlen(prefix)) || lstat(directory, &st) || !S_ISDIR(st.st_mode) ||
        st.st_uid || st.st_gid || (st.st_mode & 0777) != 0755) return false;
    const char *names[] = {"probe", "monitor", "child", "target"};
    for (unsigned i = 0; i < 4; ++i) {
        char file[PATH_MAX];
        if (!path(file, names[i]) || lstat(file, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
            st.st_uid || st.st_gid || (st.st_mode & 0777) != 0555) return false;
    }
    return true;
}
static void word(unsigned char *frame, size_t *count, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) frame[(*count)++] = (unsigned char)(value >> (24 - 8 * i));
}
static void string(unsigned char *frame, size_t *count, const char *value) {
    size_t length = strlen(value); word(frame, count, (uint32_t)length);
    memcpy(frame + *count, value, length); *count += length;
}
/* Only fixed paths and Root/current-account captures enter this private test frame. */
static size_t frame(const struct account *target, enum case_kind kind, unsigned char bytes[16384]) {
    uint32_t groups[CAPACITY]; unsigned group_count = 0;
    bool omitted = false;
    for (int i = 0; i < target->count && kind != legacy; ++i) {
        if (kind == missing_group && !omitted && target->groups[i] != target->gid) { omitted = true; continue; }
        groups[group_count++] = target->groups[i];
    }
    if (kind == legacy) groups[group_count++] = target->gid;
    size_t count = 0;
    uint32_t header[] = {kind == legacy ? REMOZIO_CHILD_FRAME_V1 : REMOZIO_CHILD_FRAME_V3, 0,
        target->uid, target->gid, group_count, 3, 0, 10000, 0027, 0};
    for (unsigned i = 0; i < 10; ++i) word(bytes, &count, header[i]);
    if (kind != legacy) word(bytes, &count, 0);
    for (unsigned i = 0; i < group_count; ++i) word(bytes, &count, groups[i]);
    if (kind != legacy) string(bytes, &count, kind == wrong_name ? "remozio-no-such-account" : target->name);
    char uid[16], gid[16]; snprintf(uid, sizeof(uid), "%u", target->uid); snprintf(gid, sizeof(gid), "%u", target->gid);
    string(bytes, &count, target_path); string(bytes, &count, target_path); string(bytes, &count, uid); string(bytes, &count, gid);
    size_t offset = 4; word(bytes, &offset, (uint32_t)(count - 40)); return count;
}
static uint64_t now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) || value.tv_sec < 0) return 0;
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static bool before(uint64_t began, unsigned budget) {
    uint64_t current = now(); return began && current >= began && current - began < budget;
}
struct control_diagnostic {
    int primary_stage, stage, poll_error;
    remozio_command_monitor_observation_t state;
};
static bool awaiting_retirement(const remozio_command_monitor_observation_t *state) {
    return !state->monitor_reaped || (!state->status.reaped && !state->status_closed);
}
static int one(const struct account *target, enum case_kind kind, bool *all_reaped,
               struct control_diagnostic *diagnostic) {
    *diagnostic = (struct control_diagnostic){0};
    unsigned char bytes[16384]; size_t count = frame(target, kind, bytes);
    int input[2] = {-1,-1}, output[2] = {-1,-1}, sink = -1, cwd = -1, failure = 0;
    remozio_command_monitor_t *owner = NULL; remozio_command_monitor_observation_t state = {0};
    if (pipe(input) || pipe(output) || (sink = open("/dev/null", O_WRONLY | O_CLOEXEC)) < 0 ||
        (cwd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) { failure = 1; goto cleanup; }
    if (write(input[1], "Q", 1) != 1) { failure = 2; goto cleanup; }
    close(input[1]); input[1] = -1;
    if (fcntl(output[0], F_SETFL, O_NONBLOCK) < 0) { failure = 3; goto cleanup; }
    int error = remozio_command_monitor_spawn(monitor_path, child_path, bytes, count, input[0], output[1], sink, cwd, &owner);
    if (error || !owner) { failure = 4; goto cleanup; }
    close(output[1]); output[1] = -1;
    uint64_t began = now();
    while (!state.prepared && awaiting_retirement(&state) && !state.monitor_ownership_lost && before(began, 15000)) {
        error = remozio_command_monitor_poll(owner, &state);
        if (error) { diagnostic->poll_error = error; failure = 13; goto cleanup; }
        if (state.status.failed) break;
        usleep(1000);
    }
    bool should_prepare = kind == positive || kind == cancel_prepared;
    if (state.fault || state.protocol_failed || (should_prepare && state.status.failed)) { failure = 13; goto cleanup; }
    int available = 0, produced = 0;
    if (state.prepared != should_prepare || state.target_exec_observed || state.release_attempted ||
        ioctl(input[0], FIONREAD, &available) || available != 1 ||
        ioctl(output[0], FIONREAD, &produced) || produced != 0) { failure = 5; goto cleanup; }
    if (!should_prepare && (!state.status.failed || state.status.failure_error != (uint32_t)(kind == legacy ? EINVAL : ESTALE))) { failure = 5; goto cleanup; }
    if (kind == positive) {
        if (remozio_command_monitor_release(owner) || remozio_command_monitor_release(owner) != EALREADY) { failure = 6; goto cleanup; }
    } else if (kind == cancel_prepared) {
        if (remozio_command_monitor_cancel(owner)) { failure = 7; goto cleanup; }
    }
    began = now();
    while (awaiting_retirement(&state) && !state.monitor_ownership_lost && before(began, 15000)) {
        error = remozio_command_monitor_poll(owner, &state);
        if (error) diagnostic->poll_error = error;
        if (error || state.fault || state.protocol_failed || (should_prepare && state.status.failed)) { failure = 13; goto cleanup; }
        usleep(1000);
    }
    if (state.fault || state.protocol_failed || (should_prepare && state.status.failed)) { failure = 13; goto cleanup; }
    if (!state.monitor_reaped || state.monitor_ownership_lost || !state.status.reaped) { failure = 8; goto cleanup; }
    if (!WIFEXITED(state.monitor_wait_status) ||
        WEXITSTATUS(state.monitor_wait_status) != (should_prepare ? EX_OK : EX_SOFTWARE)) { failure = 14; goto cleanup; }
    unsigned char result_bytes[sizeof(fixed_result_t) + 1] = {0};
    ssize_t received = read(output[0], result_bytes, sizeof(result_bytes));
    if (kind == positive) {
        fixed_result_t result; memcpy(&result, result_bytes, sizeof(result));
        if (received != sizeof(result) || result.magic != FIXED_RESULT_MAGIC || !result.identity || !result.input ||
            !result.private_fds_closed || !result.extra_group_access || !state.target_exec_observed || !state.target_exit_observed ||
            !state.status.reaped || state.status.latest.tag != REMOZIO_MONITOR_TARGET_REAPED ||
            state.status.latest.detail != 0 || !state.status.target_release_attempted) failure = 9;
    } else if (received != 0 || state.release_attempted || state.target_exec_observed ||
               ioctl(input[0], FIONREAD, &available) || available != 1) failure = 10;
cleanup:
    diagnostic->primary_stage = failure;
    if (owner) {
        (void)remozio_command_monitor_cancel(owner);
        uint64_t began = now();
        while (awaiting_retirement(&state) && !state.monitor_ownership_lost && before(began, 15000)) {
            int poll_error = remozio_command_monitor_poll(owner, &state);
            if (poll_error) diagnostic->poll_error = poll_error;
            usleep(1000);
        }
        if (!state.monitor_reaped || state.monitor_ownership_lost || !state.status.reaped) { *all_reaped = false; failure = 11; }
        if (state.monitor_reaped && remozio_command_monitor_dispose(owner)) { *all_reaped = false; failure = 12; }
    }
    int descriptors[] = {input[0], input[1], output[0], output[1], sink, cwd};
    for (unsigned i = 0; i < 6; ++i) if (descriptors[i] >= 0) close(descriptors[i]);
    diagnostic->stage = failure; diagnostic->state = state;
    return failure;
}
int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "--inspect") && strcmp(argv[1], "--privileged-controls"))) return 64;
    char *end = NULL; errno = 0; unsigned long uid = strtoul(argv[2], &end, 10);
    if (errno || !*argv[2] || *end || uid == 0 || uid >= UINT32_MAX) return 64;
    bool inspect = !strcmp(argv[1], "--inspect");
    if (!inspect && (getuid() || geteuid())) return 77;
    if (!locate()) return 70;
    struct account target, root;
    if (account((uid_t)uid, &target) || account(0, &root)) return 70;
    const struct account *accounts[] = {&root, &target, &target, &target, &target, &target};
    const enum case_kind kinds[] = {positive, positive, wrong_name, missing_group, legacy, cancel_prepared};
    if (inspect) {
        for (unsigned i = 0; i < 6; ++i) {
            enum case_kind kind = kinds[i];
            unsigned char bytes[16384]; size_t count = frame(accounts[i], kind, bytes);
            remozio_child_spec_t spec = {0}; int error = remozio_child_spec_decode(bytes, count, &spec);
            if (!error) error = remozio_child_account_validate(&spec);
            remozio_child_spec_close(&spec);
            if ((kind == positive || kind == cancel_prepared) ? error != 0 : error == 0) return 71;
        }
        puts("{\"schemaVersion\":1,\"codecControls\":6,\"privilegedControlsRun\":false}"); return 0;
    }
    if (!protected_helpers()) return 78;
    long limit = sysconf(_SC_NGROUPS_MAX);
    if (limit < 1 || target.count <= limit || limit >= CAPACITY) return 78;
    struct sigaction action = {0}; action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGCHLD, &action, NULL)) return 70;
    signal(SIGPIPE, SIG_IGN);
    gid_t initial[CAPACITY]; int initial_count = getgroups(CAPACITY, initial);
    if (initial_count < 0) return 70;
    initial_count = distinct(initial, initial_count); gid_t initial_gid = getgid(), initial_egid = getegid();
    gid_t subset[CAPACITY]; int kept = 1; subset[0] = target.gid;
    for (int i = 0; i < target.count && kept < limit; ++i) if (target.groups[i] != target.gid) subset[kept++] = target.groups[i];
    gid_t extra = 0; bool found = false;
    for (int i = 0; i < target.count; ++i) if (!contains(subset, kept, target.groups[i])) { extra = target.groups[i]; found = true; break; }
    if (!found) return 78;
    char fixture[PATH_MAX]; if (!path(fixture, "group-read")) return 70;
    int file = open(fixture, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (file < 0) return 70;
    int failure = fchown(file, 0, extra) || fchmod(file, 0640) || write(file, "G", 1) != 1;
    close(file); bool all_reaped = true; int passed = 0;
    for (unsigned i = 0; !failure && i < 6; ++i) {
        struct control_diagnostic diagnostic;
        int result = one(accounts[i], kinds[i], &all_reaped, &diagnostic);
        if (result) {
            remozio_command_monitor_observation_t observed = diagnostic.state;
            fprintf(stderr, "Production child control %u failed at stage %d.\n", i, result);
            fprintf(stderr, "Control diagnostic: {\"control\":%u,\"stage\":%d,\"primaryStage\":%d,"
                "\"pollError\":%d,\"prepared\":%d,\"monitorReaped\":%d,\"ownershipLost\":%d,"
                "\"targetReaped\":%d,\"statusClosed\":%d,\"statusFailed\":%d,\"statusError\":%u,"
                "\"fault\":%d,\"protocolFailed\":%d,\"lastTag\":%u,\"lastDetail\":%u,\"monitorWaitStatus\":%d}\n",
                i, diagnostic.stage, diagnostic.primary_stage, diagnostic.poll_error,
                observed.prepared, observed.monitor_reaped, observed.monitor_ownership_lost,
                observed.status.reaped, observed.status_closed, observed.status.failed, observed.status.failure_error,
                observed.fault, observed.protocol_failed, observed.status.latest.tag, observed.status.latest.detail,
                observed.monitor_wait_status);
            failure = 1;
        }
        else passed++;
    }
    gid_t after[CAPACITY]; int after_count = getgroups(CAPACITY, after);
    bool unchanged = after_count >= 0 && distinct(after, after_count) == initial_count &&
        !memcmp(initial, after, (size_t)initial_count * sizeof(gid_t)) && !getuid() && !geteuid() &&
        getgid() == initial_gid && getegid() == initial_egid;
    bool removed = false;
    if (all_reaped) removed = unlink(fixture) == 0;
    char summary[512];
    snprintf(summary, sizeof(summary), "{\"schemaVersion\":1,\"privilegedControlsRun\":true,\"passed\":%d,\"parentCredentialsUnchanged\":%s,\"allOwnedCleanupConfirmed\":%s,\"fixtureRemoved\":%s,\"installedRemozio\":false}\n",
        passed, unchanged ? "true" : "false", all_reaped ? "true" : "false", removed ? "true" : "false");
    fputs(summary, stdout);
    if (failure || passed != 6 || !unchanged || !all_reaped || !removed) fputs(summary, stderr);
    return !failure && passed == 6 && unchanged && all_reaped && removed ? 0 : 71;
}
