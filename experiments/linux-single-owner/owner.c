/*
 * Single-owner fixture (issue #988, PR1). One process O is the ptrace tracer of the
 * frontend C and the parent of the command. It holds C's stop from the seize until the
 * go byte, starts the command through a prepared child K, and reports the result to a
 * stub authority. See docs/linux-single-owner-design.md.
 *
 * The runner starts O with the three capabilities in its ambient set (setpriv), as the
 * unit's AmbientCapabilities= would. O clears the ambient and inheritable sets at once.
 *
 * Reports on stdout are JSON lines of closed-set strings; they never hold numbers, paths
 * or secrets. Numbers go only to the runner over the control socket and the restart log.
 *
 * usage: owner <listen-fd> <authority-socket> <control-fd> <log-fd> <dispatches> <deadline-ms>
 *              <command> <marker>
 *
 * Build options (tests and controls only):
 *   RMZSO_FIXTURE_UNPRIVILEGED  run without capabilities as one account: O expects empty
 *                               capability sets and K skips setgroups. Not a measurement.
 *   RMZSO_TEST_THREAD           start a second thread, so O must refuse before the fork.
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
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef RMZSO_TEST_THREAD
#include <pthread.h>
#endif

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#define CAPBIT(c) (1ULL << (c))
#define OWNER_CAPS (CAPBIT(CAP_SYS_PTRACE) | CAPBIT(CAP_SETUID) | CAPBIT(CAP_SETGID))

/* K's reserved exit codes. Before execve, K exits only with one of these. */
#define K_SETUP_FAILED 120
#define K_GO_REFUSED 121
#define K_EXEC_FAILED 122
#define K_CAPS_NOT_EMPTY 123
#define GO_BYTE 'G'
#define MAX_GROUPS 64
#define LIMITS 16

static int log_fd = -1, control_fd = -1;

/* ---------------------------------------------------------------- small helpers */

static void out_line(const char *text) {
    fputs(text, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

static const char *errname(int error) {
    switch (error) {
    case 0: return "ok";
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case ENOENT: return "ENOENT";
    case ENOEXEC: return "ENOEXEC";
    case ESRCH: return "ESRCH";
    case EINVAL: return "EINVAL";
    default: return "other";
    }
}

static int parse_u32(const char *text, uint32_t *out) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || end == text || *end || value > UINT32_MAX) return -1;
    *out = (uint32_t)value;
    return 0;
}

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static long long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* Reads a small file whole; a file that does not fit is an error. */
static ssize_t read_file(int dir, const char *name, char *buffer, size_t size) {
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

/* Field 3 (state letter) and field 22 (start time) of /proc/<pid>/stat. */
static int stat_fields(pid_t pid, char *state, unsigned long long *start) {
    char path[64], text[4096];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
    if (read_file(AT_FDCWD, path, text, sizeof text) <= 0) return -1;
    char *cursor = strrchr(text, ')');
    if (!cursor || cursor[1] != ' ') return -1;
    if (state) *state = cursor[2];
    if (start) {
        char *save = NULL;
        int field = 3;
        for (char *token = strtok_r(cursor + 2, " ", &save); token; token = strtok_r(NULL, " ", &save), field++)
            if (field == 22) { *start = strtoull(token, NULL, 10); return 0; }
        return -1;
    }
    return 0;
}

static void hex(const unsigned char *bytes, size_t count, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < count; i++) {
        out[2 * i] = digits[bytes[i] >> 4];
        out[2 * i + 1] = digits[bytes[i] & 15];
    }
    out[2 * count] = 0;
}

static int random_hex(char *out) {
    unsigned char bytes[16];
    if (getrandom(bytes, sizeof bytes, 0) != (ssize_t)sizeof bytes) return -1;
    hex(bytes, sizeof bytes, out);
    return 0;
}

/* The append-only restart log: every ptrace request and the go byte, with a monotonic time. */
static void log_event(int dispatch, const char *what) {
    char line[128];
    int n = snprintf(line, sizeof line, "%lld %d %s\n", now_ns(), dispatch, what);
    if (n > 0 && log_fd >= 0 && write(log_fd, line, (size_t)n) != n) { /* the runner sees the gap */ }
}

static long traced(int dispatch, const char *name, enum __ptrace_request request, pid_t pid, long data) {
    log_event(dispatch, name);
    return ptrace(request, pid, 0, data);
}

/* A named pause. The runner may act (kill, signal, inspect) and then answers 'C'. */
static int barrier(const char *name, int dispatch, pid_t c_pid, pid_t k_pid) {
    char message[160];
    int n = snprintf(message, sizeof message, "BARRIER %s %d %d %d", name, dispatch, (int)c_pid, (int)k_pid);
    if (n <= 0 || send(control_fd, message, (size_t)n, MSG_NOSIGNAL) != n) return -1;
    char reply;
    return recv(control_fd, &reply, 1, 0) == 1 && reply == 'C' ? 0 : -1;
}

/* ---------------------------------------------------------------- O's own state */

static int own_threads(void) {
    char status[8192];
    unsigned long long threads = 0;
    if (read_file(AT_FDCWD, "/proc/self/status", status, sizeof status) <= 0 ||
        status_u64(status, "Threads:", &threads, 10))
        return -1;
    return (int)threads;
}

static int set_caps(unsigned long long permitted_effective) {
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    data[0].permitted = data[0].effective = (uint32_t)permitted_effective;
    data[1].permitted = data[1].effective = (uint32_t)(permitted_effective >> 32);
    return (int)syscall(SYS_capset, &header, data);
}

static int caps_are(unsigned long long want) {
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct data[2];
    if (syscall(SYS_capget, &header, data) != 0) return 0;
    unsigned long long prm = data[0].permitted | ((unsigned long long)data[1].permitted << 32);
    unsigned long long eff = data[0].effective | ((unsigned long long)data[1].effective << 32);
    unsigned long long inh = data[0].inheritable | ((unsigned long long)data[1].inheritable << 32);
    if (prm != want || eff != want || inh != 0) return 0;
    char status[8192];
    unsigned long long p, e, i, a;
    if (read_file(AT_FDCWD, "/proc/self/status", status, sizeof status) <= 0 ||
        status_u64(status, "CapPrm:", &p, 16) || status_u64(status, "CapEff:", &e, 16) ||
        status_u64(status, "CapInh:", &i, 16) || status_u64(status, "CapAmb:", &a, 16))
        return 0;
    return p == want && e == want && i == 0 && a == 0;
}

static int owner_capabilities(void) {
#ifdef RMZSO_FIXTURE_UNPRIVILEGED
    const unsigned long long want = 0;
#else
    const unsigned long long want = OWNER_CAPS;
#endif
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) return 0;
    if (set_caps(want) != 0) return 0;
    return caps_are(want);
}

struct generation {
    char boot_id[40];
    pid_t pid;
    unsigned long long start;
    char random[33];
};

static int make_generation(struct generation *g) {
    char text[64];
    if (read_file(AT_FDCWD, "/proc/sys/kernel/random/boot_id", text, sizeof text) <= 0) return -1;
    size_t length = strcspn(text, "\n");
    if (length != 36) return -1;
    memcpy(g->boot_id, text, length);
    g->boot_id[length] = 0;
    g->pid = getpid();
    return stat_fields(g->pid, NULL, &g->start) || random_hex(g->random) ? -1 : 0;
}

/* ---------------------------------------------------------------- authority stub */

static int authority_connect(const char *path) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (fd < 0 || strlen(path) >= sizeof address.sun_path) return -1;
    strcpy(address.sun_path, path);
    if (connect(fd, (struct sockaddr *)&address, sizeof address) != 0) { close(fd); return -1; }
    return fd;
}

static int ask(int fd, const char *message, char *reply, size_t size) {
    size_t length = strlen(message);
    if (send(fd, message, length, MSG_NOSIGNAL) != (ssize_t)length) return -1;
    ssize_t n = recv(fd, reply, size - 1, 0);
    if (n <= 0) return -1;
    reply[n] = 0;
    return 0;
}

struct permit {
    char token[33];
    uid_t uid;
    gid_t gid;
    char mode[16];
    int group_count;
    gid_t groups[MAX_GROUPS];
};

static int parse_permit(char *reply, struct permit *p) {
    char *save = NULL;
    char *word = strtok_r(reply, " ", &save);
    if (!word || strcmp(word, "PERMIT")) return -1;
    char *token = strtok_r(NULL, " ", &save), *uid = strtok_r(NULL, " ", &save),
         *gid = strtok_r(NULL, " ", &save), *mode = strtok_r(NULL, " ", &save),
         *count = strtok_r(NULL, " ", &save);
    uint32_t u, g, c;
    if (!token || strlen(token) != 32 || !uid || !gid || !mode || strlen(mode) >= sizeof p->mode || !count ||
        parse_u32(uid, &u) || parse_u32(gid, &g) || parse_u32(count, &c) || c > MAX_GROUPS)
        return -1;
    strcpy(p->token, token);
    strcpy(p->mode, mode);
    p->uid = u;
    p->gid = g;
    p->group_count = (int)c;
    for (uint32_t i = 0; i < c; i++) {
        char *member = strtok_r(NULL, " ", &save);
        uint32_t value;
        if (!member || parse_u32(member, &value)) return -1;
        p->groups[i] = value;
    }
    return strtok_r(NULL, " ", &save) ? -1 : 0;
}

/* ---------------------------------------------------------------- the frontend under the stop */

/* C is in O's stop: no pending wait event, procfs state 't' and O as its tracer. */
static int in_stop(pid_t pid) {
    int status;
    pid_t waited = waitpid(pid, &status, WNOHANG | __WALL);
    if (waited != 0) return 0;
    char text[8192];
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/status", (int)pid);
    unsigned long long tracer = 0, threads = 0;
    if (read_file(AT_FDCWD, path, text, sizeof text) <= 0 || status_u64(text, "TracerPid:", &tracer, 10) ||
        status_u64(text, "Threads:", &threads, 10))
        return 0;
    const char *state = status_line(text, "State:");
    while (state && (*state == ' ' || *state == '\t')) state++;
    return state && *state == 't' && tracer == (unsigned long long)getpid() && threads == 1;
}

struct inherited {
    mode_t umask;
    struct rlimit limits[LIMITS];
};

static int parse_limit(const char *text, rlim_t *out) {
    if (strncmp(text, "unlimited", 9) == 0) { *out = RLIM_INFINITY; return 0; }
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || end == text) return -1;
    *out = (rlim_t)value;
    return 0;
}

/* The caller's umask and limits, read while C is in O's stop. The kernel prints the
 * limits in RLIMIT_* order, one per line after the header, value columns at 26 and 47. */
static int read_inherited(pid_t pid, struct inherited *inherited) {
    char path[64], text[8192];
    snprintf(path, sizeof path, "/proc/%d/status", (int)pid);
    unsigned long long mask;
    if (read_file(AT_FDCWD, path, text, sizeof text) <= 0 || status_u64(text, "Umask:", &mask, 8) || mask > 0777)
        return -1;
    inherited->umask = (mode_t)mask;
    snprintf(path, sizeof path, "/proc/%d/limits", (int)pid);
    if (read_file(AT_FDCWD, path, text, sizeof text) <= 0) return -1;
    char *line = strchr(text, '\n');
    for (int i = 0; i < LIMITS; i++) {
        if (!line) return -1;
        line++;
        char *next = strchr(line, '\n');
        if (!next || next - line < 47) return -1;
        if (parse_limit(line + 26, &inherited->limits[i].rlim_cur) ||
            parse_limit(line + 47, &inherited->limits[i].rlim_max))
            return -1;
        line = next;
    }
    return 0;
}

/* ---------------------------------------------------------------- K */

struct child_plan {
    int streams[3], cwd, go_read, status_write;
    struct permit permit;
    struct inherited inherited;
    uid_t owner_uid;
    const char *command, *marker;
};

static void k_exit(int status_write, int code, int error) {
    if (code == K_EXEC_FAILED) {
        unsigned char record[5] = {'E', (unsigned char)(error >> 24), (unsigned char)(error >> 16),
                                   (unsigned char)(error >> 8), (unsigned char)error};
        if (write(status_write, record, sizeof record) != (ssize_t)sizeof record) { /* O sees EOF */ }
    }
    _exit(code);
}

/* Runs in K only. Every call here is async-signal-safe. */
static void run_child(const struct child_plan *plan) {
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = SIG_DFL;
    for (int signo = 1; signo < NSIG; signo++) sigaction(signo, &action, NULL); /* KILL/STOP fail: fine */
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL) != 0) _exit(K_SETUP_FAILED);
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) _exit(K_SETUP_FAILED);

    /* Move the five kept descriptors above every target number, then into place. */
    int kept[6] = {plan->streams[0], plan->streams[1], plan->streams[2], plan->go_read, plan->status_write,
                   plan->cwd};
    int high[6];
    for (int i = 0; i < 6; i++)
        if ((high[i] = fcntl(kept[i], F_DUPFD_CLOEXEC, 64)) < 0) _exit(K_SETUP_FAILED);
    for (int i = 0; i < 5; i++)
        if (dup2(high[i], i) != i) _exit(K_SETUP_FAILED);
    int status_write = 4;
    if (fcntl(3, F_SETFD, FD_CLOEXEC) != 0 || fcntl(4, F_SETFD, FD_CLOEXEC) != 0) _exit(K_SETUP_FAILED);
    if (fchdir(high[5]) != 0) _exit(K_SETUP_FAILED);
    if (syscall(SYS_close_range, 5, ~0U, 0) != 0) _exit(K_SETUP_FAILED);

    umask(plan->inherited.umask);
    for (int i = 0; i < LIMITS; i++)
        if (setrlimit(i, &plan->inherited.limits[i]) != 0) _exit(K_SETUP_FAILED);
    if (setsid() < 0) _exit(K_SETUP_FAILED);
    const struct permit *p = &plan->permit;
#ifndef RMZSO_FIXTURE_UNPRIVILEGED
    if (setgroups((size_t)p->group_count, p->groups) != 0) _exit(K_SETUP_FAILED);
#endif
    if (setresgid(p->gid, p->gid, p->gid) != 0) _exit(K_SETUP_FAILED);
    /* The saved UID stays O's until the go byte, so O can end K without CAP_KILL. */
    if (setresuid(p->uid, p->uid, plan->owner_uid) != 0) _exit(K_SETUP_FAILED);
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) _exit(K_SETUP_FAILED);
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 || set_caps(0) != 0) _exit(K_CAPS_NOT_EMPTY);
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct data[2];
    if (syscall(SYS_capget, &header, data) != 0 || data[0].permitted || data[1].permitted || data[0].effective ||
        data[1].effective || data[0].inheritable || data[1].inheritable)
        _exit(K_CAPS_NOT_EMPTY);

    if (strcmp(p->mode, "khang") == 0)
        for (;;) {
            struct timespec second = {1, 0};
            nanosleep(&second, NULL);
        }
    if (write(status_write, "R", 1) != 1) _exit(K_SETUP_FAILED);
    char go = 0;
    if (read(3, &go, 1) != 1 || go != GO_BYTE) _exit(K_GO_REFUSED);
    if (setresuid(p->uid, p->uid, p->uid) != 0) _exit(K_SETUP_FAILED);
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) _exit(K_SETUP_FAILED); /* reset by the UID change */
    if (strcmp(p->mode, "kpause") == 0) {
        if (write(status_write, "P", 1) != 1) _exit(K_SETUP_FAILED);
        for (;;) pause();
    }
    close(3);

    char path[4096];
    const char *argument = "normal";
    if (strcmp(p->mode, "short") == 0 || strcmp(p->mode, "sleep") == 0) argument = p->mode;
    if (strcmp(p->mode, "missing") == 0) {
        size_t length = strlen(plan->command);
        if (length + 9 > sizeof path) k_exit(status_write, K_EXEC_FAILED, ENAMETOOLONG);
        memcpy(path, plan->command, length);
        memcpy(path + length, ".missing", 9);
    } else {
        size_t length = strlen(plan->command);
        if (length + 1 > sizeof path) k_exit(status_write, K_EXEC_FAILED, ENAMETOOLONG);
        memcpy(path, plan->command, length + 1);
    }
    char *const argv[] = {path, (char *)argument, (char *)plan->marker, NULL};
    char *const envp[] = {"LANG=C", "PATH=/usr/local/bin:/usr/bin:/bin", NULL};
    execve(path, argv, envp);
    k_exit(status_write, K_EXEC_FAILED, errno);
}

/* ---------------------------------------------------------------- one dispatch */

struct result {
    const char *admitted, *permit, *final_check, *result, *exec_errno, *lost, *go, *deadline_kill, *reported;
};

static void report(int dispatch, const struct result *r) {
    char line[768];
    snprintf(line, sizeof line,
             "{\"dispatch\":\"%d\",\"admitted\":\"%s\",\"permit\":\"%s\",\"finalCheck\":\"%s\",\"result\":\"%s\","
             "\"execErrno\":\"%s\",\"requesterLostAfterCheck\":\"%s\",\"goWritten\":\"%s\","
             "\"killedAtDeadline\":\"%s\",\"reported\":\"%s\"}",
             dispatch, r->admitted, r->permit, r->final_check, r->result, r->exec_errno, r->lost, r->go,
             r->deadline_kill, r->reported);
    out_line(line);
}

static int k_state(pid_t pid, char *state) { return stat_fields(pid, state, NULL); }

static void kill_k(int pidfd) { syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0); }

/* waitid without reaping: 0 alive, 1 exited normally (code), 2 killed or reserved, -1 error. */
static int k_outcome(int pidfd, int *code) {
    siginfo_t info;
    memset(&info, 0, sizeof info);
    if (syscall(SYS_waitid, P_PIDFD, pidfd, &info, WEXITED | WNOHANG | WNOWAIT, NULL) != 0) return -1;
    if (info.si_pid == 0) return 0;
    *code = info.si_status;
    return info.si_code == CLD_EXITED ? 1 : 2;
}

static int reserved(int code) { return code >= K_SETUP_FAILED && code <= K_CAPS_NOT_EMPTY; }

/* The exec gets its own deadline after the go byte. Returns the S6 category. */
static int same_image(pid_t pid) {
    char path[64];
    struct stat k, own;
    snprintf(path, sizeof path, "/proc/%d/exe", (int)pid);
    if (stat(path, &k) != 0 || stat("/proc/self/exe", &own) != 0) return -1; /* exiting: no mm */
    return k.st_dev == own.st_dev && k.st_ino == own.st_ino;
}

static int wait_exit(int pidfd, long long deadline) {
    struct pollfd exit_watch = {.fd = pidfd, .events = POLLIN};
    long long left = deadline - now_ms();
    return left > 0 && poll(&exit_watch, 1, (int)left) == 1 ? 0 : -1;
}

static const char *classify(int status_read, int k_pidfd, pid_t k_pid, int deadline_ms, int dispatch, pid_t c_pid,
                            const char **exec_errno) {
    long long deadline = now_ms() + deadline_ms;
    for (;;) {
        struct pollfd wait_status = {.fd = status_read, .events = POLLIN};
        long long left = deadline - now_ms();
        if (left <= 0 || poll(&wait_status, 1, (int)left) != 1) return "unknown";
        unsigned char byte;
        ssize_t n = read(status_read, &byte, 1);
        if (n == 1 && byte == 'P') {
            barrier("k-paused", dispatch, c_pid, k_pid);
            continue;
        }
        int code = 0, outcome;
        if (n == 1 && byte == 'E') {
            unsigned char rest[4];
            if (read(status_read, rest, 4) != 4 || wait_exit(k_pidfd, deadline) != 0) return "unknown";
            outcome = k_outcome(k_pidfd, &code);
            if (outcome != 1 || code != K_EXEC_FAILED) return "unknown";
            *exec_errno = errname((rest[0] << 24) | (rest[1] << 16) | (rest[2] << 8) | rest[3]);
            return "execFailed";
        }
        if (n != 0) return "unknown";
        /* EOF: the exec closed the write end, or K is dying. A K that is still alive in O's
         * image (or has no image left) is dying, so O waits for its exit status. */
        outcome = k_outcome(k_pidfd, &code);
        if (outcome == 0) {
            if (same_image(k_pid) == 0) return "dispatched";
            if (wait_exit(k_pidfd, deadline) != 0) return "unknown";
            outcome = k_outcome(k_pidfd, &code);
        }
        return outcome == 1 && !reserved(code) ? "dispatched" : "unknown";
    }
}

static void dispatch_one(int dispatch, int listen_fd, int authority, int deadline_ms, const char *command,
                         const char *marker) {
    struct result r = {"no", "no", "no", "refused", "none", "no", "no", "no", "no"};
    struct pollfd ready = {.fd = listen_fd, .events = POLLIN};
    if (poll(&ready, 1, 30000) != 1) { report(dispatch, &r); return; }
    int conn = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0) { report(dispatch, &r); return; }
    int c_pidfd = -1;
    socklen_t length = sizeof c_pidfd;
    struct ucred cred;
    socklen_t cred_length = sizeof cred;
    char hello[16] = {0};
    char control[CMSG_SPACE(3 * sizeof(int))];
    struct iovec iov = {hello, sizeof hello - 1};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control,
                             .msg_controllen = sizeof control};
    int streams[3] = {-1, -1, -1};
    ssize_t got = getsockopt(conn, SOL_SOCKET, SO_PEERPIDFD, &c_pidfd, &length) == 0 &&
                          getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cred, &cred_length) == 0
                      ? recvmsg(conn, &message, MSG_CMSG_CLOEXEC)
                      : -1;
    struct cmsghdr *header = got == 7 ? CMSG_FIRSTHDR(&message) : NULL;
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(3 * sizeof(int)) || memcmp(hello, "RMZSO1\n", 7) ||
        (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC))) {
        report(dispatch, &r);
        close(conn);
        return;
    }
    memcpy(streams, CMSG_DATA(header), sizeof streams);
    pid_t c_pid = cred.pid;
    long options = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACEEXEC;
    int status = 0;
    if (traced(dispatch, "SEIZE", PTRACE_SEIZE, c_pid, options) != 0 ||
        traced(dispatch, "INTERRUPT", PTRACE_INTERRUPT, c_pid, 0) != 0 ||
        waitpid(c_pid, &status, __WALL) != c_pid || !WIFSTOPPED(status) || (status >> 16) != PTRACE_EVENT_STOP) {
        report(dispatch, &r);
        close(conn);
        return;
    }
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/cwd", (int)c_pid);
    int cwd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
    struct inherited inherited;
    char nonce[33], message_text[256], reply[1024];
    int admitted = cwd >= 0 && in_stop(c_pid) && read_inherited(c_pid, &inherited) == 0 && random_hex(nonce) == 0;
    r.admitted = admitted ? "yes" : "no";
    struct permit permit;
    snprintf(message_text, sizeof message_text, "SUBMIT %s %d", admitted ? nonce : "-", (int)c_pid);
    if (!admitted || ask(authority, message_text, reply, sizeof reply) || parse_permit(reply, &permit)) {
        report(dispatch, &r);
        close(conn); /* C dies with O or stays stopped until O exits */
        return;
    }
    r.permit = "yes";
    barrier("s1", dispatch, c_pid, 0);

    /* S2: the final check, with the stop held. */
    if (!in_stop(c_pid)) { report(dispatch, &r); close(conn); return; }
    r.final_check = "yes";
    if (own_threads() != 1) {
        r.result = "ownerThreads";
        snprintf(message_text, sizeof message_text, "OUTCOME %s notStarted no", permit.token);
        r.reported = ask(authority, message_text, reply, sizeof reply) == 0 && strcmp(reply, "OK") == 0 ? "yes" : "no";
        report(dispatch, &r);
        close(conn);
        return;
    }

    /* S3: the prepared child. */
    int go[2], state_pipe[2];
    if (pipe2(go, O_CLOEXEC) != 0 || pipe2(state_pipe, O_CLOEXEC) != 0) { report(dispatch, &r); return; }
    struct child_plan plan = {.streams = {streams[0], streams[1], streams[2]}, .cwd = cwd, .go_read = go[0],
                              .status_write = state_pipe[1], .permit = permit, .inherited = inherited,
                              .owner_uid = getuid(), .command = command, .marker = marker};
    pid_t k_pid = fork();
    if (k_pid == 0) run_child(&plan);
    close(go[0]);
    close(state_pipe[1]);
    for (int i = 0; i < 3; i++) close(streams[i]);
    close(cwd);
    if (k_pid < 0) { report(dispatch, &r); return; }
    int k_pidfd = (int)syscall(SYS_pidfd_open, k_pid, 0);
    barrier("after-fork", dispatch, c_pid, k_pid);

    long long deadline = now_ms() + deadline_ms;
    int k_ready = 0;
    struct pollfd watch = {.fd = state_pipe[0], .events = POLLIN};
    while (!k_ready) {
        long long left = deadline - now_ms();
        if (left <= 0) break;
        if (poll(&watch, 1, (int)left) == 1) {
            char byte;
            k_ready = read(state_pipe[0], &byte, 1) == 1 && byte == 'R';
            if (!k_ready) break; /* K ended before readiness */
        }
    }
    int not_started = !k_ready;
    if (k_ready) {
        barrier("k-ready", dispatch, c_pid, k_pid);
        /* K must sleep in its read of the go pipe; a stopped K waits for the deadline. */
        for (;;) {
            char state = '?';
            int code;
            if (k_outcome(k_pidfd, &code) != 0 || k_state(k_pid, &state) != 0) { not_started = 1; break; }
            if (state == 'S') break;
            if (now_ms() >= deadline) {
                kill_k(k_pidfd);
                r.deadline_kill = "yes";
                not_started = 1;
                break;
            }
            struct timespec pause_time = {0, 10 * 1000 * 1000};
            nanosleep(&pause_time, NULL);
        }
    } else if (now_ms() >= deadline) {
        kill_k(k_pidfd);
        r.deadline_kill = "yes";
    }
    if (!not_started) {
        barrier("before-go", dispatch, c_pid, k_pid);
        /* The last check of C, immediately before the go byte. */
        if (!in_stop(c_pid)) {
            kill_k(k_pidfd); /* C left the stop before the go byte: no command */
            close(go[1]);
            close(state_pipe[0]);
            r.result = "refused";
            r.lost = "yes";
            snprintf(message_text, sizeof message_text, "OUTCOME %s refused yes", permit.token);
            r.reported =
                ask(authority, message_text, reply, sizeof reply) == 0 && strcmp(reply, "OK") == 0 ? "yes" : "no";
            report(dispatch, &r);
            close(conn);
            return;
        }
        barrier("after-check", dispatch, c_pid, k_pid);
        char byte = GO_BYTE;
        log_event(dispatch, "GO");
        if (write(go[1], &byte, 1) == 1) r.go = "yes";
        else not_started = 1; /* EPIPE: K is gone (SIGPIPE is ignored) */
    }
    close(go[1]);

    if (not_started) {
        r.result = "notStarted";
    } else {
        barrier("after-go", dispatch, c_pid, k_pid);
        r.result = classify(state_pipe[0], k_pidfd, k_pid, deadline_ms, dispatch, c_pid, &r.exec_errno);
        if (!in_stop(c_pid)) r.lost = "yes";
    }
    close(state_pipe[0]);
    snprintf(message_text, sizeof message_text, "OUTCOME %s %s %s", permit.token, r.result, r.lost);
    r.reported = ask(authority, message_text, reply, sizeof reply) == 0 && strcmp(reply, "OK") == 0 ? "yes" : "no";
    report(dispatch, &r);
    barrier("after-s6", dispatch, c_pid, k_pid);
    /* The post-dispatch contract is out of scope: O lets C go and closes its connection. */
    if (strcmp(r.lost, "no") == 0) traced(dispatch, "DETACH", PTRACE_DETACH, c_pid, 0);
    close(conn);
    close(c_pidfd);
    if (k_pidfd >= 0) close(k_pidfd);
}

#ifdef RMZSO_TEST_THREAD
static void *idle(void *unused) {
    (void)unused;
    for (;;) pause();
    return NULL;
}
#endif

int main(int argc, char **argv) {
    uint32_t listen_fd, control, log, dispatches, deadline_ms;
    if (argc != 9 || parse_u32(argv[1], &listen_fd) || parse_u32(argv[3], &control) || parse_u32(argv[4], &log) ||
        parse_u32(argv[5], &dispatches) || parse_u32(argv[6], &deadline_ms) || dispatches < 1 || dispatches > 4 ||
        deadline_ms < 100 || deadline_ms > 30000) {
        out_line("{\"error\":\"usage\"}");
        return 4;
    }
    control_fd = (int)control;
    log_fd = (int)log;
    signal(SIGPIPE, SIG_IGN);
    for (uint32_t fd = 0; fd < 3; fd++) fcntl((int)fd, F_SETFD, FD_CLOEXEC);
    fcntl((int)listen_fd, F_SETFD, FD_CLOEXEC);
    fcntl(control_fd, F_SETFD, FD_CLOEXEC);
    fcntl(log_fd, F_SETFD, FD_CLOEXEC);
    int caps = owner_capabilities();
#ifdef RMZSO_TEST_THREAD
    pthread_t thread;
    pthread_create(&thread, NULL, idle, NULL);
#endif
    struct generation g;
    int generation = make_generation(&g) == 0;
    int authority = generation ? authority_connect(argv[2]) : -1;
    char text[256], reply[64];
    snprintf(text, sizeof text, "HELLO %s %d %llu %s", g.boot_id, (int)g.pid, g.start, g.random);
    int accepted = authority >= 0 && ask(authority, text, reply, sizeof reply) == 0 && strcmp(reply, "OK") == 0;
    snprintf(text, sizeof text,
             "{\"ownerCapabilitiesExact\":\"%s\",\"generation\":\"%s\",\"authorityAccepted\":\"%s\"}",
             caps ? "yes" : "no", generation ? "yes" : "no", accepted ? "yes" : "no");
    out_line(text);
    if (!caps || !accepted) return 3;
    if (barrier("start", 0, 0, 0) != 0) return 3;
    for (uint32_t d = 1; d <= dispatches; d++)
        dispatch_one((int)d, (int)listen_fd, authority, (int)deadline_ms, argv[7], argv[8]);
    barrier("end", 0, 0, 0);
    return 0;
}
