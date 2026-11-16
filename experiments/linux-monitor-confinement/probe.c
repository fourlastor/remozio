/*
 * Monitor-confinement probe fixture. The supervised runner builds it static and uses it in
 * three modes. It prints one JSON object of closed-vocabulary values and never prints a
 * number, path, address or label, except the sleeper's handshake line, which the runner
 * reads and never publishes.
 *
 *   sleeper <seconds>
 *       A target. It fills a buffer with 16 random bytes and keeps one pipe end open, then
 *       writes "S <buffer address, 16 hex> <descriptor, 4 digits> <canary, 32 hex>\n" and
 *       waits for end of input or the deadline.
 *   probe drop|nodrop <uid> <gid> <seconds> <writable-directory|-> [role=target ...]
 *       The subject. "drop" first performs the self-drop of the #728 monitor (the
 *       launch shape with aa-exec); "nodrop" keeps the identity that systemd gave it.
 *       It writes "R\n", waits for one byte, then runs every action and reports.
 *       A target is kind:pid:address:descriptor:canary. Kind "s" is a sleeper (the full
 *       action set); kind "f" is a frontend in hold mode (seize, interrupt, memory read
 *       of its marker, /proc/<pid>/mem open, detach), with "-" for descriptor and canary.
 *   userns-bind <installed> <image> <socket>
 *       As the operator: a user and mount namespace, then a bind mount of the image over
 *       the installed path. It reports each step; after a mount that succeeds it executes
 *       the installed path in hold mode.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define CAPBIT(c) (1ULL << (c))
#define MAX_TARGETS 4

static char json[8192];
static size_t used;
static int overflow;

static void field(const char *key, const char *value) {
    int n = snprintf(json + used, sizeof json - used, "%s\"%s\":\"%s\"", used > 1 ? "," : "", key, value);
    if (n > 0 && (size_t)n < sizeof json - used) used += (size_t)n;
    else overflow = 1;
}

static void role_field(const char *role, const char *key, const char *value) {
    char name[64];
    snprintf(name, sizeof name, "%.15s.%.24s", role, key);
    field(name, value);
}

static const char *errname(int error) {
    switch (error) {
    case 0: return "ok";
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case ESRCH: return "ESRCH";
    case EFAULT: return "EFAULT";
    case EINVAL: return "EINVAL";
    case ENOSYS: return "ENOSYS";
    case EBADF: return "EBADF";
    case ENOENT: return "ENOENT";
    default: return "other";
    }
}

static int finish(int code) {
    if (overflow || sizeof json - used < 3) {
        fputs("{\"error\":\"overflow\"}\n", stdout); /* a dropped key must not look like a result */
        fflush(stdout);
        return 3;
    }
    used += (size_t)snprintf(json + used, sizeof json - used, "}\n");
    fputs(json, stdout);
    fflush(stdout);
    return code;
}

static int parse_u64(const char *text, int base, unsigned long long *out) {
    /* Digits only: strtoull would accept a sign or leading space and wrap. */
    if (!*text || strspn(text, base == 16 ? "0123456789abcdef" : "0123456789") != strlen(text)) return -1;
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, base);
    if (errno || end == text || *end) return -1;
    *out = value;
    return 0;
}

static int parse_hex16(const char *text, unsigned char out[16]) {
    if (strlen(text) != 32 || strspn(text, "0123456789abcdef") != 32) return -1;
    for (int i = 0; i < 16; i++) {
        char pair[3] = {text[2 * i], text[2 * i + 1], 0};
        out[i] = (unsigned char)strtoul(pair, NULL, 16);
    }
    return 0;
}

static ssize_t read_file(const char *path, char *buffer, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total + 1 < size) {
        ssize_t n = read(fd, buffer + total, size - 1 - total);
        if (n < 0) { int saved = errno; close(fd); errno = saved; return -1; }
        if (n == 0) break;
        total += (size_t)n;
    }
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

/* The self-drop of experiments/linux-protected-launch/monitor.c, unchanged in effect: an
 * empty group list, the given IDs, and CAP_SYS_PTRACE as the only capability anywhere. */
static int drop_privileges(uid_t uid, gid_t gid) {
    char text[64];
    int fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY | O_CLOEXEC);
    ssize_t n = fd < 0 ? -1 : read(fd, text, sizeof text - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) return -1;
    text[n] = 0;
    int last = atoi(text);
    for (int cap = 0; cap <= last; cap++)
        if (cap != CAP_SYS_PTRACE && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) return -1;
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) return -1;
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) return -1;
    if (setgroups(0, NULL) != 0 || setresgid(gid, gid, gid) != 0 || setresuid(uid, uid, uid) != 0) return -1;
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    data[0].effective = data[0].permitted = 1U << CAP_SYS_PTRACE;
    if (syscall(SYS_capset, &header, data) != 0) return -1;
    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return 0;
}

static const char *cap_category(const char *status, const char *key) {
    const char *value = status_line(status, key);
    unsigned long long bits;
    char *end = NULL;
    if (!value) return "other";
    errno = 0;
    bits = strtoull(value, &end, 16);
    if (errno || end == value) return "other";
    return bits == 0 ? "none" : bits == CAPBIT(CAP_SYS_PTRACE) ? "ptrace-only" : "other";
}

/* Real, effective, saved and filesystem IDs exact; supplementary groups at most the GID. */
static int credentials_exact(const char *status, uid_t uid, gid_t gid) {
    char expected[64];
    snprintf(expected, sizeof expected, "\t%u\t%u\t%u\t%u\n", (unsigned)uid, (unsigned)uid, (unsigned)uid, (unsigned)uid);
    const char *uids = status_line(status, "Uid:");
    if (!uids || strncmp(uids, expected, strlen(expected)) != 0) return 0;
    snprintf(expected, sizeof expected, "\t%u\t%u\t%u\t%u\n", (unsigned)gid, (unsigned)gid, (unsigned)gid, (unsigned)gid);
    const char *gids = status_line(status, "Gid:");
    if (!gids || strncmp(gids, expected, strlen(expected)) != 0) return 0;
    const char *list = status_line(status, "Groups:");
    while (list && *list && *list != '\n') {
        char *end = NULL;
        unsigned long member = strtoul(list, &end, 10);
        if (end == list) { list++; continue; }
        if (member != gid) return 0;
        list = end;
    }
    return list != NULL;
}

static void record_identity(uid_t uid, gid_t gid) {
    static char status[8192];
    if (read_file("/proc/self/status", status, sizeof status) <= 0) status[0] = 0;
    field("credentialsExact", credentials_exact(status, uid, gid) ? "yes" : "no");
    field("capsEffective", cap_category(status, "CapEff:"));
    field("capsPermitted", cap_category(status, "CapPrm:"));
    field("capsBounding", cap_category(status, "CapBnd:"));
    field("capsInheritable", cap_category(status, "CapInh:"));
    field("capsAmbient", cap_category(status, "CapAmb:"));
    const char *nnp = status_line(status, "NoNewPrivs:");
    field("noNewPrivs", nnp && strncmp(nnp, "\t1\n", 3) == 0 ? "yes" : "no");
}

struct target {
    char role[16];
    char kind;
    pid_t pid;
    unsigned long long address;
    int descriptor;
    unsigned char canary[16];
};

static const unsigned char frontend_marker[16] = "RMZPL-MARKER-v1";

static int parse_target(const char *text, struct target *out) {
    char copy[160];
    if (strlen(text) >= sizeof copy) return -1;
    strcpy(copy, text);
    char *equals = strchr(copy, '=');
    if (!equals || equals == copy || (size_t)(equals - copy) >= sizeof out->role) return -1;
    *equals = 0;
    if (strspn(copy, "abcdefghijklmnopqrstuvwxyz") != strlen(copy)) return -1;
    strcpy(out->role, copy);
    char *fields[5];
    char *cursor = equals + 1;
    for (int i = 0; i < 5; i++) {
        fields[i] = cursor;
        char *colon = strchr(cursor, ':');
        if (i < 4) {
            if (!colon) return -1;
            *colon = 0;
            cursor = colon + 1;
        } else if (colon) {
            return -1;
        }
    }
    unsigned long long pid, descriptor = 0;
    if (strlen(fields[0]) != 1 || (fields[0][0] != 's' && fields[0][0] != 'f')) return -1;
    out->kind = fields[0][0];
    if (parse_u64(fields[1], 10, &pid) || pid == 0 || pid > 4194304) return -1;
    out->pid = (pid_t)pid;
    if (strlen(fields[2]) != 16 || parse_u64(fields[2], 16, &out->address) || out->address == 0) return -1;
    if (out->kind == 's') {
        if (parse_u64(fields[3], 10, &descriptor) || descriptor > 1023 || parse_hex16(fields[4], out->canary)) return -1;
        out->descriptor = (int)descriptor;
    } else {
        if (strcmp(fields[3], "-") || strcmp(fields[4], "-")) return -1;
        out->descriptor = -1;
        memcpy(out->canary, frontend_marker, sizeof out->canary);
    }
    return 0;
}

/* process_vm_readv of 16 bytes: "match", "mismatch", "short" or the errno name. */
static const char *vm_read(pid_t pid, unsigned long long address, const unsigned char expected[16]) {
    unsigned char buffer[16] = {0};
    struct iovec local = {buffer, sizeof buffer}, remote = {(void *)(uintptr_t)address, sizeof buffer};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n < 0) return errname(errno);
    if (n != (ssize_t)sizeof buffer) return "short";
    return memcmp(buffer, expected, sizeof buffer) == 0 ? "match" : "mismatch";
}

static int mem_open(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", (int)pid);
    return open(path, O_RDONLY | O_CLOEXEC);
}

static void probe_sleeper(const struct target *t) {
    /* Seize, then release: PTRACE_DETACH needs a ptrace-stop, so interrupt first. */
    int seized = ptrace(PTRACE_SEIZE, t->pid, 0, 0) == 0;
    role_field(t->role, "seize", seized ? "ok" : errname(errno));
    /* Detach only from a stop; otherwise the probe's exit releases the tracee. */
    if (seized) {
        int wait_status = 0;
        if (ptrace(PTRACE_INTERRUPT, t->pid, 0, 0) == 0 && waitpid(t->pid, &wait_status, __WALL) == t->pid &&
            WIFSTOPPED(wait_status))
            ptrace(PTRACE_DETACH, t->pid, 0, 0);
    }

    int mem = mem_open(t->pid);
    role_field(t->role, "memOpen", mem >= 0 ? "ok" : errname(errno));
    if (mem >= 0) {
        unsigned char buffer[16] = {0};
        ssize_t n = pread(mem, buffer, sizeof buffer, (off_t)t->address);
        role_field(t->role, "memRead", n < 0 ? errname(errno) : n != (ssize_t)sizeof buffer ? "short"
                   : memcmp(buffer, t->canary, sizeof buffer) == 0 ? "match" : "mismatch");
        close(mem);
    } else {
        role_field(t->role, "memRead", "not-attempted");
    }
    role_field(t->role, "vmRead", vm_read(t->pid, t->address, t->canary));

    int pidfd = (int)syscall(SYS_pidfd_open, t->pid, 0);
    role_field(t->role, "pidfdOpen", pidfd >= 0 ? "ok" : errname(errno));
    if (pidfd >= 0) {
        int copy = (int)syscall(SYS_pidfd_getfd, pidfd, t->descriptor, 0);
        role_field(t->role, "pidfdGetfd", copy >= 0 ? "ok" : errname(errno));
        struct stat info;
        role_field(t->role, "getfdCopyIsPipe", copy < 0 ? "not-attempted"
                   : fstat(copy, &info) == 0 && S_ISFIFO(info.st_mode) ? "yes" : "no");
        if (copy >= 0) close(copy);
        close(pidfd);
    } else {
        role_field(t->role, "pidfdGetfd", "not-attempted");
        role_field(t->role, "getfdCopyIsPipe", "not-attempted");
    }

    /* /proc/<pid>/maps is checked with PTRACE_MODE_READ: AppArmor's ptrace read permission. */
    char path[64];
    static char maps[8192];
    snprintf(path, sizeof path, "/proc/%d/maps", (int)t->pid);
    role_field(t->role, "mapsRead", read_file(path, maps, sizeof maps) > 0 ? "ok" : errname(errno));

    /* /proc/<pid>/status is not ptrace-checked: readable whatever the policy. */
    static char status[8192];
    snprintf(path, sizeof path, "/proc/%d/status", (int)t->pid);
    role_field(t->role, "statusRead", read_file(path, status, sizeof status) > 0 ? "ok" : errname(errno));
}

static void probe_frontend(const struct target *t) {
    int seized = ptrace(PTRACE_SEIZE, t->pid, 0, 0) == 0;
    role_field(t->role, "seize", seized ? "ok" : errname(errno));
    int stopped = 0;
    if (seized && ptrace(PTRACE_INTERRUPT, t->pid, 0, 0) == 0) {
        int wait_status = 0;
        stopped = waitpid(t->pid, &wait_status, __WALL) == t->pid && WIFSTOPPED(wait_status) &&
                  (wait_status >> 16) == PTRACE_EVENT_STOP;
    }
    role_field(t->role, "interrupt", !seized ? "not-attempted" : stopped ? "yes" : "no");
    role_field(t->role, "vmRead", vm_read(t->pid, t->address, t->canary));
    int mem = mem_open(t->pid);
    role_field(t->role, "memOpen", mem >= 0 ? "ok" : errname(errno));
    if (mem >= 0) close(mem);
    role_field(t->role, "detach", !seized ? "not-attempted" : ptrace(PTRACE_DETACH, t->pid, 0, 0) == 0 ? "ok"
               : errname(errno));
}

/* File creation, execution and an IP socket: the policy forbids all three. */
static void probe_side_effects(const char *directory) {
    char path[512];
    if ((size_t)snprintf(path, sizeof path, "%s/probe-created", directory) >= sizeof path) {
        field("fileCreate", "other");
    } else {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        field("fileCreate", fd >= 0 ? "ok" : errname(errno));
        if (fd >= 0) {
            close(fd);
            unlink(path);
        }
    }

    /* The child reports a failed execve through a close-on-exec pipe; no bytes means it ran. */
    int report[2];
    if (pipe2(report, O_CLOEXEC) != 0) {
        field("exec", "other");
    } else {
        pid_t child = fork();
        if (child == 0) {
            close(report[0]);
            char *const arguments[] = {"true", NULL};
            char *const environment[] = {NULL};
            execve("/bin/true", arguments, environment);
            int code = errno;
            if (write(report[1], &code, sizeof code) != (ssize_t)sizeof code) _exit(126);
            _exit(127);
        }
        close(report[1]);
        int code = 0;
        ssize_t n = child < 0 ? -1 : read(report[0], &code, sizeof code);
        close(report[0]);
        int wait_status = 0;
        int reaped = child > 0 && waitpid(child, &wait_status, 0) == child;
        if (child < 0) field("exec", "other");
        else if (n == (ssize_t)sizeof code) field("exec", errname(code));
        else field("exec", n == 0 && reaped && WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0 ? "ok" : "other");
    }

    int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    field("inetSocket", sock >= 0 ? "ok" : errname(errno));
    if (sock >= 0) close(sock);
}

static int run_probe(int argc, char **argv) {
    unsigned long long uid, gid, seconds;
    int drop = argc >= 7 && strcmp(argv[2], "drop") == 0;
    if (argc < 7 || argc > 7 + MAX_TARGETS || (!drop && strcmp(argv[2], "nodrop")) ||
        parse_u64(argv[3], 10, &uid) || parse_u64(argv[4], 10, &gid) || parse_u64(argv[5], 10, &seconds) ||
        uid == 0 || gid == 0 || uid > UINT32_MAX || gid > UINT32_MAX || seconds == 0 || seconds > 60) {
        field("error", "usage");
        return finish(4);
    }
    struct target targets[MAX_TARGETS];
    int count = argc - 7;
    for (int i = 0; i < count; i++) {
        if (parse_target(argv[7 + i], &targets[i]) != 0) {
            field("error", "usage");
            return finish(4);
        }
    }
    alarm((unsigned)seconds + 2); /* backstop; the runner kills at its own deadline first */
    if (drop) {
        int dropped = geteuid() == 0 && drop_privileges((uid_t)uid, (gid_t)gid) == 0;
        field("selfDrop", dropped ? "ok" : "failed");
        if (!dropped) return finish(3);
    } else {
        field("selfDrop", "not-requested");
    }
    record_identity((uid_t)uid, (gid_t)gid);
    int regained = setresuid(0, 0, 0) == 0;
    field("rootRegain", regained ? "ok" : errname(errno));
    if (regained) return finish(3); /* never act with an identity the case did not ask for */

    if (write(1, "R\n", 2) != 2) return 3;
    char go = 0;
    if (read(0, &go, 1) != 1 || go != 'g') {
        field("error", "no-go");
        return finish(3);
    }
    for (int i = 0; i < count; i++) {
        if (targets[i].kind == 's') probe_sleeper(&targets[i]);
        else probe_frontend(&targets[i]);
    }
    if (strcmp(argv[6], "-") != 0) probe_side_effects(argv[6]);
    return finish(0);
}

static int run_sleeper(int argc, char **argv) {
    static volatile unsigned char canary[16];
    unsigned long long seconds;
    if (argc != 3 || parse_u64(argv[2], 10, &seconds) || seconds == 0 || seconds > 120) return 4;
    unsigned char random_bytes[16];
    if (getrandom(random_bytes, sizeof random_bytes, 0) != (ssize_t)sizeof random_bytes) return 5;
    for (size_t i = 0; i < sizeof random_bytes; i++) canary[i] = random_bytes[i];
    int known[2];
    if (pipe2(known, O_CLOEXEC) != 0 || known[0] > 9999) return 5;
    char line[64];
    int n = snprintf(line, sizeof line, "S %016llx %04d ", (unsigned long long)(uintptr_t)canary, known[0]);
    for (size_t i = 0; i < sizeof random_bytes; i++) n += snprintf(line + n, sizeof line - (size_t)n, "%02x", random_bytes[i]);
    line[n++] = '\n';
    if (write(1, line, (size_t)n) != n) return 5;
    alarm((unsigned)seconds);
    char ignored;
    while (read(0, &ignored, 1) > 0) {}
    return 0;
}

static int write_text(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    ssize_t length = (ssize_t)strlen(text);
    int result = write(fd, text, (size_t)length) == length ? 0 : errno;
    close(fd);
    return result;
}

static int run_userns_bind(int argc, char **argv) {
    if (argc != 5) {
        field("error", "usage");
        return finish(4);
    }
    uid_t uid = getuid();
    gid_t gid = getgid();
    int created = unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0;
    field("userns", created ? "ok" : errname(errno));
    int mounted = 0;
    if (created) {
        char map[64];
        int error = write_text("/proc/self/setgroups", "deny");
        snprintf(map, sizeof map, "0 %u 1\n", (unsigned)uid);
        if (!error) error = write_text("/proc/self/uid_map", map);
        snprintf(map, sizeof map, "0 %u 1\n", (unsigned)gid);
        if (!error) error = write_text("/proc/self/gid_map", map);
        field("uidMap", errname(error));
        /* No bind unless the private remount worked, so nothing can propagate out. */
        mounted = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0 &&
                  mount(argv[3], argv[2], NULL, MS_BIND, NULL) == 0;
        field("mount", mounted ? "ok" : errname(errno));
    } else {
        field("uidMap", "not-attempted");
        field("mount", "not-attempted");
    }
    int code = finish(0);
    if (code != 0 || !mounted) return code;
    char *const arguments[] = {"remozio", "hold", argv[4], NULL};
    char *const environment[] = {NULL};
    execve(argv[2], arguments, environment);
    return 5;
}

int main(int argc, char **argv) {
    used = (size_t)snprintf(json, sizeof json, "{");
    if (argc >= 2 && strcmp(argv[1], "sleeper") == 0) return run_sleeper(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "probe") == 0) return run_probe(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "userns-bind") == 0) return run_userns_bind(argc, argv);
    field("error", "usage");
    return finish(4);
}
