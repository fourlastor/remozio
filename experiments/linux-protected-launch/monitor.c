/*
 * Protected-launch monitor fixture. The supervised runner starts it as root with
 * an inherited listening socket; it first drops to a disposable system user that
 * keeps only CAP_SYS_PTRACE ("cap") or no capability ("nocap"). It accepts one
 * frontend, seizes it, checks it from outside and answers 'A' or 'R'. It prints
 * one JSON object of booleans and errno names; it never prints numbers or paths.
 *
 * usage: monitor cap|nocap <listen-fd> <frontend-gid> <installed-frontend> <uid> <gid> <seconds>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
/* The runner's missing-pidfd control builds a second monitor with an unknown option here,
 * so getsockopt fails as it would on a kernel without SO_PEERPIDFD. */
#ifndef RMZPL_PEERPIDFD_OPTION
#define RMZPL_PEERPIDFD_OPTION SO_PEERPIDFD
#endif
#define CAPBIT(c) (1ULL << (c))

static char json[8192];
static size_t used;
static int overflow;

static void field(const char *key, const char *value) {
    int n = snprintf(json + used, sizeof json - used, "%s\"%s\":\"%s\"", used > 1 ? "," : "", key, value);
    if (n > 0 && (size_t)n < sizeof json - used) used += (size_t)n;
    else overflow = 1;
}

static void flag(const char *key, int value) { field(key, value ? "yes" : "no"); }

static const char *errname(int error) {
    switch (error) {
    case 0: return "ok";
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case ESRCH: return "ESRCH";
    case ENOPROTOOPT: return "ENOPROTOOPT";
    case EINVAL: return "EINVAL";
    case EBADF: return "EBADF";
    default: return "other";
    }
}

static int finish(int code) {
    if (overflow || sizeof json - used < 3) {
        fputs("{\"error\":\"overflow\"}\n", stdout); /* a dropped key must not look like a property */
        fflush(stdout);
        return 3;
    }
    used += (size_t)snprintf(json + used, sizeof json - used, "}\n");
    fputs(json, stdout);
    fflush(stdout);
    return code;
}

static int parse_u32(const char *text, uint32_t *out) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || end == text || *end || value > UINT32_MAX) return -1;
    *out = (uint32_t)value;
    return 0;
}

/* Reads a small procfs file through a directory descriptor; returns bytes or -1. A file
 * that does not fit the buffer is an error, so no check ever passes on a partial view. */
static ssize_t read_at(int dir, const char *name, char *buffer, size_t size) {
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t total = 0;
    int complete = 0;
    while (total + 1 < size) {
        ssize_t n = read(fd, buffer + total, size - 1 - total);
        if (n < 0) { close(fd); return -1; }
        if (n == 0) { complete = 1; break; }
        total += (size_t)n;
    }
    char extra;
    if (!complete && read(fd, &extra, 1) != 0) { close(fd); return -1; }
    close(fd);
    buffer[total] = 0;
    return (ssize_t)total;
}

static const char *status_line(const char *status, const char *key) {
    size_t length = strlen(key);
    for (const char *line = status; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL)
        if (strncmp(line, key, length) == 0) return line + length;
    return NULL;
}

static int status_u64(const char *status, const char *key, unsigned long long *out, int base) {
    const char *value = status_line(status, key);
    if (!value) return -1;
    char *end = NULL;
    errno = 0;
    *out = strtoull(value, &end, base);
    return errno || end == value ? -1 : 0;
}

/* Drops to uid/gid with an empty group list and exactly the requested capability set. */
static int drop_privileges(int keep_ptrace, uid_t uid, gid_t gid) {
    char text[64];
    int fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY | O_CLOEXEC);
    ssize_t n = fd < 0 ? -1 : read(fd, text, sizeof text - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) return -1;
    text[n] = 0;
    int last = atoi(text);
    for (int cap = 0; cap <= last; cap++)
        if (!(keep_ptrace && cap == CAP_SYS_PTRACE) && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) return -1;
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) return -1;
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) return -1;
    if (setgroups(0, NULL) != 0 || setresgid(gid, gid, gid) != 0 || setresuid(uid, uid, uid) != 0) return -1;
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    if (keep_ptrace) data[0].effective = data[0].permitted = 1U << CAP_SYS_PTRACE;
    if (syscall(SYS_capset, &header, data) != 0) return -1;
    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return 0;
}

static int own_credentials_exact(int keep_ptrace, uid_t uid, gid_t gid) {
    char status[8192];
    if (read_at(AT_FDCWD, "/proc/self/status", status, sizeof status) < 0) return 0;
    unsigned long long eff, prm, inh, bnd, amb;
    unsigned long long want = keep_ptrace ? CAPBIT(CAP_SYS_PTRACE) : 0;
    if (status_u64(status, "CapEff:", &eff, 16) || status_u64(status, "CapPrm:", &prm, 16) ||
        status_u64(status, "CapInh:", &inh, 16) || status_u64(status, "CapBnd:", &bnd, 16) ||
        status_u64(status, "CapAmb:", &amb, 16))
        return 0;
    if (eff != want || prm != want || inh != 0 || amb != 0 || bnd != want) return 0;
    const char *groups = status_line(status, "Groups:");
    if (!groups || strspn(groups, " \t") != strcspn(groups, "\n")) return 0;
    char expected[64];
    snprintf(expected, sizeof expected, "\t%u\t%u\t%u\t%u\n", (unsigned)uid, (unsigned)uid, (unsigned)uid, (unsigned)uid);
    const char *uids = status_line(status, "Uid:");
    if (!uids || strncmp(uids, expected, strlen(expected)) != 0) return 0;
    snprintf(expected, sizeof expected, "\t%u\t%u\t%u\t%u\n", (unsigned)gid, (unsigned)gid, (unsigned)gid, (unsigned)gid);
    const char *gids = status_line(status, "Gid:");
    return gids && strncmp(gids, expected, strlen(expected)) == 0;
}

/* Every listed supplementary group, and the four GID roles, against the frontend group. */
static void check_groups(const char *status, uint32_t group, int *roles_ok, int *groups_exclude) {
    unsigned long real = 0, effective = 0, saved = 0, filesystem = 0;
    const char *gids = status_line(status, "Gid:");
    *roles_ok = gids && sscanf(gids, "%lu %lu %lu %lu", &real, &effective, &saved, &filesystem) == 4 &&
                real != group && effective == group && saved == group && filesystem == group;
    const char *list = status_line(status, "Groups:");
    *groups_exclude = list != NULL;
    while (list && *list && *list != '\n') {
        char *end = NULL;
        unsigned long member = strtoul(list, &end, 10);
        if (end == list) { list++; continue; }
        if (member == group) *groups_exclude = 0;
        list = end;
    }
}

static int maps_allowed(int dir, const struct stat *image) {
    static char maps[65536];
    if (read_at(dir, "maps", maps, sizeof maps) <= 0) return 0;
    char *save = NULL;
    for (char *line = strtok_r(maps, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char perms[8] = {0}, path[512] = {0};
        unsigned int major = 0, minor = 0;
        unsigned long long inode = 0;
        if (sscanf(line, "%*[0-9a-f]-%*[0-9a-f] %7s %*[0-9a-f] %x:%x %llu %511[^\n]", perms, &major, &minor, &inode, path) < 4)
            return 0;
        if (strchr(perms, 'w') && strchr(perms, 'x')) return 0;
        char *name = path + strspn(path, " ");
        if (inode != 0) {
            if (inode != (unsigned long long)image->st_ino || makedev(major, minor) != image->st_dev) return 0;
        } else {
            if (*name && strcmp(name, "[heap]") && strcmp(name, "[stack]") && strcmp(name, "[vdso]") &&
                strcmp(name, "[vvar]") && strcmp(name, "[vvar_vclock]") && strcmp(name, "[vsyscall]"))
                return 0;
            /* Only the kernel's own pages may execute outside the image. */
            if (strchr(perms, 'x') && strcmp(name, "[vdso]") && strcmp(name, "[vsyscall]")) return 0;
        }
    }
    return 1;
}

static int namespaces_match(int dir) {
    static const char *const kinds[] = {"cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"};
    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        char name[32], own[64] = {0}, theirs[64] = {0}, self[48];
        snprintf(name, sizeof name, "ns/%s", kinds[i]);
        snprintf(self, sizeof self, "/proc/self/ns/%s", kinds[i]);
        if (readlink(self, own, sizeof own - 1) <= 0 || readlinkat(dir, name, theirs, sizeof theirs - 1) <= 0 ||
            strcmp(own, theirs) != 0)
            return 0;
    }
    return 1;
}

/* Descriptor inventory without listing the root-owned fd directory. */
static int descriptors_exact(int pidfd, unsigned long long fdsize) {
    if (fdsize == 0 || fdsize > 65536) return 0;
    int found = 0, socket_at_three = 0;
    for (unsigned long long number = 0; number < fdsize; number++) {
        int copy = (int)syscall(SYS_pidfd_getfd, pidfd, (int)number, 0);
        if (copy < 0) {
            if (errno == EBADF) continue;
            return 0;
        }
        struct stat info;
        int ok = fstat(copy, &info) == 0;
        close(copy);
        if (!ok || number > 3) return 0;
        if (number == 3) socket_at_three = S_ISSOCK(info.st_mode);
        found++;
    }
    return found == 4 && socket_at_three;
}

/* The pidfd's fdinfo shows Pid: -1 once its task is gone, so a match after the seize
 * proves the seized PID is the connecting process. pidfd_send_signal is not used: its
 * kill-permission check needs CAP_KILL across UIDs, which the monitor does not hold. */
static int association(int pidfd, pid_t pid) {
    char path[64], info[1024];
    snprintf(path, sizeof path, "/proc/self/fdinfo/%d", pidfd);
    if (read_at(AT_FDCWD, path, info, sizeof info) <= 0) return 0;
    unsigned long long recorded;
    return status_u64(info, "Pid:", &recorded, 10) == 0 && recorded == (unsigned long long)pid;
}

/* AT_SECURE from the auxiliary vector that exec wrote on the stack. /proc/<pid>/auxv is
 * root-owned mode 0400 for a task that is not dumpable, so CAP_SYS_PTRACE alone cannot open
 * it. /proc/<pid>/stat (0444) gives the stack start (field 28, the address of argc) and
 * arg_start (field 48, the argument strings above the tables), and process_vm_readv reads
 * the stopped frontend. Layout: argc, argv, NULL, envp, NULL, auxv pairs up to AT_NULL.
 * Passes only with an AT_NULL and exactly one AT_SECURE, whose value is 1. */
static int stack_at_secure(int dir, pid_t pid) {
    char stat_text[4096];
    if (read_at(dir, "stat", stat_text, sizeof stat_text) <= 0) return 0;
    char *cursor = strrchr(stat_text, ')'); /* the command name may hold spaces */
    if (!cursor) return 0;
    unsigned long long fields[64] = {0}; /* fields[i] is stat field i + 4 */
    int count = 0;
    char *save = NULL;
    char *token = strtok_r(cursor + 1, " \n", &save); /* field 3, the state letter */
    for (token = token ? strtok_r(NULL, " \n", &save) : NULL; token && count < 64;
         token = strtok_r(NULL, " \n", &save))
        fields[count++] = strtoull(token, NULL, 10);
    if (count < 45) return 0;
    unsigned long long start = fields[28 - 4], arg_start = fields[48 - 4];
    static unsigned long long words[8192];
    if (start == 0 || start % 8 || arg_start <= start || arg_start - start > sizeof words) return 0;
    size_t span = (size_t)(arg_start - start);
    struct iovec local = {words, span}, remote = {(void *)(uintptr_t)start, span};
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) != (ssize_t)span) return 0;
    size_t n = span / 8;
    if (n == 0 || words[0] >= n) return 0;
    size_t i = 1 + (size_t)words[0];
    if (i >= n || words[i] != 0) return 0;
    for (i++; i < n && words[i] != 0; i++) {}
    if (i >= n) return 0;
    int seen = 0, secure = 0;
    for (i++; i + 1 < n; i += 2) {
        if (words[i] == 0) return seen == 1 && secure;
        if (words[i] == 23 /* AT_SECURE */) { seen++; secure = words[i + 1] == 1; }
    }
    return 0;
}

/* A category only; the label text never enters the report. */
static const char *apparmor_label(int dir) {
    char label[256];
    ssize_t n = read_at(dir, "attr/apparmor/current", label, sizeof label);
    if (n <= 0) n = read_at(dir, "attr/current", label, sizeof label);
    if (n <= 0) return "unavailable";
    return strcmp(label, "unconfined\n") == 0 || strcmp(label, "unconfined") == 0 ? "unconfined" : "confined";
}

int main(int argc, char **argv) {
    used = (size_t)snprintf(json, sizeof json, "{");
    uint32_t listen_fd, group, uid, gid, seconds;
    if (argc != 8 || (strcmp(argv[1], "cap") && strcmp(argv[1], "nocap")) || parse_u32(argv[2], &listen_fd) ||
        parse_u32(argv[3], &group) || parse_u32(argv[5], &uid) || parse_u32(argv[6], &gid) ||
        parse_u32(argv[7], &seconds) || seconds == 0 || seconds > 60 || uid == 0 || gid == 0) {
        field("error", "usage");
        return finish(4);
    }
    int keep = strcmp(argv[1], "cap") == 0;
    if (geteuid() != 0 || drop_privileges(keep, uid, gid) != 0) {
        field("error", "privilege-drop");
        return finish(3);
    }
    flag("monitorCredentialsExact", own_credentials_exact(keep, uid, gid));
    int self = open("/proc/self", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    field("monitorAppArmor", self >= 0 ? apparmor_label(self) : "unavailable");
    if (self >= 0) close(self);
    alarm(seconds + 2); /* backstop for the whole run; the wait below is bounded first */

    struct pollfd ready = {.fd = (int)listen_fd, .events = POLLIN};
    if (poll(&ready, 1, (int)seconds * 1000) != 1) {
        field("error", "accept-timeout");
        return finish(3);
    }
    int conn = accept4((int)listen_fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0) {
        field("error", "accept");
        return finish(3);
    }
    int pidfd = -1;
    socklen_t length = sizeof pidfd;
    int pidfd_ok = getsockopt(conn, SOL_SOCKET, RMZPL_PEERPIDFD_OPTION, &pidfd, &length) == 0 && pidfd >= 0;
    field("peerPidfd", pidfd_ok ? "ok" : errname(errno));
    struct ucred cred;
    length = sizeof cred;
    int cred_ok = getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &length) == 0;
    flag("peerCredEffectiveGidIsGroup", cred_ok && cred.gid == group);
    /* One 16-byte message: "RMZPL1 ", the frontend's personality as 8 hex digits, "\n". */
    char hello[32] = {0};
    unsigned long long reported_personality = 1;
    int hello_ok = read(conn, hello, sizeof hello) == 16 && memcmp(hello, "RMZPL1 ", 7) == 0 &&
                   strspn(hello + 7, "0123456789abcdef") == 8 && hello[15] == '\n';
    if (hello_ok) {
        hello[15] = 0;
        reported_personality = strtoull(hello + 7, NULL, 16);
    }
    flag("helloReceived", hello_ok);

    int accepted = pidfd_ok && cred_ok && cred.gid == group && hello_ok;
    int seized = 0, stopped = 0;
    pid_t pid = cred_ok ? cred.pid : -1;
    if (pidfd_ok && cred_ok) {
        long options = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                       PTRACE_O_TRACEEXEC;
        seized = ptrace(PTRACE_SEIZE, pid, 0, options) == 0;
        field("seize", seized ? "ok" : errname(errno));
    } else {
        field("seize", "not-attempted");
    }
    int associated = seized && association(pidfd, pid);
    flag("pidfdAssociated", associated);
    if (associated && ptrace(PTRACE_INTERRUPT, pid, 0, 0) == 0) {
        int wait_status = 0;
        stopped = waitpid(pid, &wait_status, __WALL) == pid && WIFSTOPPED(wait_status) &&
                  (wait_status >> 16) == PTRACE_EVENT_STOP;
    }
    flag("stopHeld", stopped);
    accepted = accepted && seized && associated && stopped;

    int roles_ok = 0, groups_exclude = 0, single_thread = 0, filter_mode = 0, one_filter = 0, nnp_set = 0;
    int tracer_ok = 0, signals_ok = 0, personality_ok = 0, at_secure = 0, not_dumpable = 0, identity = 0;
    int maps_ok = 0, namespaces_ok = 0, descriptors = 0, listing_refused = 0;
    const char *listing_result = "not-attempted", *frontend_label = "not-attempted";
    if (stopped) {
        char path[64];
        snprintf(path, sizeof path, "/proc/%d", (int)pid);
        int dir = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        int dir_ok = dir >= 0 && association(pidfd, pid);
        static char status[8192];
        int status_ok = dir_ok && read_at(dir, "status", status, sizeof status) > 0;
        if (status_ok) check_groups(status, group, &roles_ok, &groups_exclude);
        unsigned long long threads = 0, seccomp = 9, filters = 0, nnp = 0, tracer = 0, fdsize = 0, sigign = 1,
                           sigblk = 1;
        int fields_ok = status_ok && !status_u64(status, "Threads:", &threads, 10) &&
                        !status_u64(status, "Seccomp:", &seccomp, 10) &&
                        !status_u64(status, "Seccomp_filters:", &filters, 10) &&
                        !status_u64(status, "NoNewPrivs:", &nnp, 10) &&
                        !status_u64(status, "TracerPid:", &tracer, 10) &&
                        !status_u64(status, "FDSize:", &fdsize, 10) &&
                        !status_u64(status, "SigIgn:", &sigign, 16) && !status_u64(status, "SigBlk:", &sigblk, 16);
        single_thread = fields_ok && threads == 1;
        filter_mode = fields_ok && seccomp == 2;
        one_filter = fields_ok && filters == 1;
        nnp_set = fields_ok && nnp == 1;
        tracer_ok = fields_ok && tracer == (unsigned long long)getpid();
        signals_ok = fields_ok && sigign == 0 && sigblk == 0;

        /* Self-reported in the hello: no procfs path gives it to CAP_SYS_PTRACE alone. The
         * value counts only together with the identity and memory checks of this stop. */
        personality_ok = hello_ok && reported_personality == 0;
        at_secure = dir_ok && stack_at_secure(dir, pid);

        /* procfs gives a task's entries a root owner when it is not dumpable (dumpable is not
         * 1); the frontend's UID is never 0, so a root-owned environ means "not dumpable". */
        struct stat environ_info;
        not_dumpable = dir_ok && fstatat(dir, "environ", &environ_info, 0) == 0 && environ_info.st_uid == 0;

        struct stat running, installed;
        int exe = dir_ok ? openat(dir, "exe", O_RDONLY | O_CLOEXEC) : -1;
        identity = exe >= 0 && fstat(exe, &running) == 0 && stat(argv[4], &installed) == 0 &&
                   running.st_dev == installed.st_dev && running.st_ino == installed.st_ino &&
                   S_ISREG(installed.st_mode) && installed.st_uid == 0 && installed.st_gid == group &&
                   (installed.st_mode & 07777) == 02755 && installed.st_nlink == 1;
        if (exe >= 0) close(exe);
        maps_ok = identity && maps_allowed(dir, &installed);
        namespaces_ok = dir_ok && namespaces_match(dir);
        if (dir_ok) frontend_label = apparmor_label(dir);

        int listing = dir_ok ? openat(dir, "fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC) : -1;
        int listing_errno = listing < 0 ? errno : 0;
        listing_result = !dir_ok ? "not-attempted" : listing >= 0 ? "ok" : errname(listing_errno);
        listing_refused = dir_ok && listing < 0 && (listing_errno == EACCES || listing_errno == EPERM);
        if (listing >= 0) close(listing);
        descriptors = fields_ok && descriptors_exact(pidfd, fdsize);
        if (dir >= 0) close(dir);
        ptrace(PTRACE_DETACH, pid, 0, 0);
    }
    flag("statusGidRolesExact", roles_ok);
    flag("groupsExcludeFrontendGroup", groups_exclude);
    flag("singleThread", single_thread);
    flag("seccompFilterMode", filter_mode);
    flag("singleSeccompFilter", one_filter);
    flag("noNewPrivs", nnp_set);
    flag("tracerIsMonitor", tracer_ok);
    flag("signalsReset", signals_ok);
    flag("personalityCleared", personality_ok);
    flag("atSecure", at_secure);
    flag("notDumpable", not_dumpable);
    flag("exeIsCurrentInstalledImage", identity);
    flag("mapsAllowed", maps_ok);
    flag("hostNamespaces", namespaces_ok);
    field("fdDirectoryListing", listing_result);
    flag("descriptorsExact", descriptors);
    field("frontendAppArmor", frontend_label);
    accepted = accepted && roles_ok && groups_exclude && single_thread && filter_mode && one_filter && nnp_set &&
               tracer_ok && signals_ok && personality_ok && at_secure && not_dumpable && identity && maps_ok &&
               namespaces_ok && listing_refused && descriptors;
    flag("accepted", accepted);
    char verdict = accepted ? 'A' : 'R';
    flag("verdictSent", write(conn, &verdict, 1) == 1);
    return finish(0);
}
