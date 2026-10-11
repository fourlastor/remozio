#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(_DARWIN_UNLIMITED_GETGROUPS) || defined(_DARWIN_C_SOURCE)
#define GROUPS_INTERFACE "darwin-unlimited"
#else
#define GROUPS_INTERFACE "posix"
#endif
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
static double monotonic(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}
/* Only forked children alter credentials. The parent owns the bounded wait and fixture cleanup. */
static int trial(const struct account *target, bool dynamic, const gid_t *groups, int count,
                 const char *fixture, struct result *result) {
    int descriptors[2];
    if (pipe(descriptors) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(descriptors[0]); close(descriptors[1]); return -1; }
    if (pid == 0) {
        close(descriptors[0]); struct result observed = {0, -1, -1, 0};
        int status = dynamic ? initgroups(target->name, (int)target->gid) : setgroups(count, groups);
        if (status != 0) observed.credential_error = errno;
        if (!observed.credential_error && setgid(target->gid) != 0) observed.credential_error = errno;
        if (!observed.credential_error && setuid(target->uid) != 0) observed.credential_error = errno;
        if (!observed.credential_error && (getuid() != target->uid || geteuid() != target->uid || getgid() != target->gid || getegid() != target->gid)) observed.credential_error = EINVAL;
        if (!observed.credential_error) {
            observed.observed_count = getgroups(0, NULL);
            if (fixture) {
                int fd = open(fixture, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                observed.access_result = fd >= 0 ? 1 : 0;
                if (fd >= 0) close(fd); else observed.access_error = errno;
            }
        }
        ssize_t sent = write(descriptors[1], &observed, sizeof(observed));
        close(descriptors[1]); _exit(sent == sizeof(observed) ? 0 : 1);
    }
    close(descriptors[1]);
    double began = monotonic(); int status = 0;
    bool completed = false;
    while (began >= 0 && monotonic() - began < 20.0) {
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) { completed = true; break; }
        if (waited < 0 && errno != EINTR) break;
        struct timespec pause = {0, 10000000}; nanosleep(&pause, NULL);
    }
    if (!completed) {
        kill(pid, SIGKILL); while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        close(descriptors[0]); return -1;
    }
    ssize_t bytes;
    do { bytes = read(descriptors[0], result, sizeof(*result)); } while (bytes < 0 && errno == EINTR);
    close(descriptors[0]);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 && bytes == sizeof(*result) ? 0 : -1;
}
static void emit(const char *name, struct result result) {
    printf("\"%s\":{\"credentialError\":%d,\"observedGroupCount\":%d,\"fixtureReadable\":%d,\"accessError\":%d}",
           name, result.credential_error, result.observed_count, result.access_result, result.access_error);
}
int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "--inspect") && strcmp(argv[1], "--privileged-controls"))) return 64;
    char *end = NULL; errno = 0; unsigned long parsed = strtoul(argv[2], &end, 10);
    if (errno || !*argv[2] || *end || parsed >= UINT32_MAX) return 64;
    struct account target, root;
    if (account((uid_t)parsed, &target) != 0 || account(0, &root) != 0) return 70;
    long limit = sysconf(_SC_NGROUPS_MAX);
    if (!strcmp(argv[1], "--inspect")) {
        printf("{\"schemaVersion\":1,\"getgroupsInterface\":\"%s\",\"privilegedControlsRun\":false,\"kernelReportedLimit\":%ld,\"rootDirectoryGroups\":%d,\"targetDirectoryGroups\":%d,\"currentProcessGroups\":%d}\n",
               GROUPS_INTERFACE, limit, root.count, target.count, getgroups(0, NULL));
        return 0;
    }
    if (getuid() != 0 || geteuid() != 0 || target.uid == 0) return 77;
    if (limit < 1 || limit >= CAPACITY || target.count <= limit) return 78;
    gid_t initial[CAPACITY]; int initial_count = getgroups(CAPACITY, initial);
    if (initial_count < 0) return 70;
    initial_count = distinct(initial, initial_count);
    gid_t subset[CAPACITY]; int count = 1; subset[0] = target.gid;
    for (int i = 0; i < target.count && count < limit; i++) if (target.groups[i] != target.gid) subset[count++] = target.groups[i];
    gid_t extra = 0; bool found = false;
    for (int i = 0; i < target.count; i++) if (!contains(subset, count, target.groups[i])) { extra = target.groups[i]; found = true; break; }
    if (!found) return 78;
    char directory[] = "/private/tmp/remozio-command-groups.XXXXXX", fixture[PATH_MAX];
    if (!mkdtemp(directory)) return 70;
    int failure = 0;
    if (snprintf(fixture, sizeof(fixture), "%s/group-read", directory) >= (int)sizeof(fixture) || chmod(directory, 0755) != 0) failure = 1;
    int fd = failure ? -1 : open(fixture, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 || fchown(fd, 0, extra) != 0 || fchmod(fd, 0640) != 0) failure = 1;
    if (fd >= 0) close(fd);
    struct result root_full, target_full, target_subset, target_dynamic;
    if (!failure && (trial(&root, false, root.groups, root.count, NULL, &root_full) ||
        trial(&target, false, target.groups, target.count, fixture, &target_full) ||
        trial(&target, false, subset, count, fixture, &target_subset) ||
        trial(&target, true, NULL, 0, fixture, &target_dynamic))) failure = 1;
    int cleanup = unlink(fixture); int cleanup_error = errno;
    int directory_cleanup = rmdir(directory);
    if ((cleanup && cleanup_error != ENOENT) || directory_cleanup) failure = 1;
    gid_t after[CAPACITY]; int after_count = getgroups(CAPACITY, after);
    if (after_count < 0) failure = 1;
    else { after_count = distinct(after, after_count); if (after_count != initial_count || memcmp(initial, after, (size_t)initial_count * sizeof(gid_t))) failure = 1; }
    if (getuid() != 0 || geteuid() != 0) failure = 1;
    if (failure) return 70;
    printf("{\"schemaVersion\":1,\"getgroupsInterface\":\"%s\",\"privilegedControlsRun\":true,\"kernelReportedLimit\":%ld,\"rootDirectoryGroups\":%d,\"targetDirectoryGroups\":%d,\"parentCredentialsUnchanged\":true,\"fixtureRemoved\":true,", GROUPS_INTERFACE, limit, root.count, target.count);
    emit("rootFullSetgroups", root_full); printf(","); emit("targetFullSetgroups", target_full); printf(",");
    emit("targetStaticSubset", target_subset); printf(","); emit("targetInitgroups", target_dynamic); printf("}\n");
    return 0;
}
