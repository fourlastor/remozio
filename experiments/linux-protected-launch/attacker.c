/*
 * Same-UID attacker fixture for the protected-launch experiment. The supervised
 * runner starts it as the ordinary operator account with no capability. It
 * launches the frontend itself, so it is the frontend's parent, and applies one
 * case's pre-exec or post-exec attack. It prints one JSON object of fixed keys
 * with string values (errno names, exit categories, yes/no); never numbers or paths.
 *
 * usage: attacker <case> <installed-frontend> <control-frontend> <socket> <frontend-gid> <seconds>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static char json[4096];
static size_t used;
static int overflow;
static const char *installed, *control, *socket_path;
static unsigned long frontend_gid;

static void field(const char *key, const char *value) {
    int n = snprintf(json + used, sizeof json - used, "%s\"%s\":\"%s\"", used > 1 ? "," : "", key, value);
    if (n > 0 && (size_t)n < sizeof json - used) used += (size_t)n;
    else overflow = 1;
}

static void close_pair(int pair[2]) {
    for (int i = 0; i < 2; i++)
        if (pair[i] >= 0) close(pair[i]);
}

static void prefixed(const char *prefix, const char *key, const char *value) {
    char name[96];
    snprintf(name, sizeof name, "%s%s", prefix, key);
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
    default: return "other";
    }
}

static void send_all(int fd, const void *data, size_t length) {
    const char *cursor = data;
    while (length > 0) {
        ssize_t written = write(fd, cursor, length);
        if (written <= 0) return;
        cursor += written;
        length -= (size_t)written;
    }
}

static const char *exit_category(int status) {
    if (status == -1) return "wait-failed";
    if (WIFSIGNALED(status)) return WTERMSIG(status) == SIGSYS ? "SIGSYS" : "signaled";
    if (!WIFEXITED(status)) return "unknown";
    switch (WEXITSTATUS(status)) {
    case 0: return "accepted";
    case 2: return "rejected";
    case 3: return "forbidden-returned";
    case 4: return "usage";
    case 5: return "policy-setup-failed";
    case 10: return "connect-EACCES";
    case 11: return "socket-failure";
    case 12: return "protocol-failure";
    default: return "other";
    }
}

enum setup { PLAIN, TRACEME, NNP, PERSONALITY, NOISY_FDS, CORE_LIMIT, USERNS };

struct child {
    pid_t pid;
    int in, out; /* our ends of the child's stdin and stdout, or -1 */
};

/* Runs in the child just before exec. Returns 0, or an errno for USERNS refusal. */
static int prepare(enum setup setup) {
    switch (setup) {
    case TRACEME: return ptrace(PTRACE_TRACEME, 0, 0, 0) == 0 ? 0 : errno;
    case NNP: return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 ? 0 : errno;
    case PERSONALITY: return personality(READ_IMPLIES_EXEC | ADDR_NO_RANDOMIZE) < 0 ? errno : 0;
    case NOISY_FDS: {
        int null = open("/dev/null", O_RDONLY);
        if (null < 0 || dup2(0, 7) < 0 || dup2(null, 40) < 0) return errno;
        signal(SIGINT, SIG_IGN);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGTERM);
        return sigprocmask(SIG_BLOCK, &set, NULL) == 0 ? 0 : errno;
    }
    case CORE_LIMIT: {
        /* RLIMIT_CORE of 1 also disables piped core handlers for the expected SIGSYS. Under
         * sudo the hard limit is already 0 (sudoers rlimit_core defaults to 0), and an ordinary
         * user cannot raise it, so keep 0 then. The SIGSYS outcome is the same either way. */
        struct rlimit current;
        if (getrlimit(RLIMIT_CORE, &current) != 0) return errno;
        struct rlimit limit = {current.rlim_max >= 1 ? 1 : 0, current.rlim_max >= 1 ? 1 : 0};
        return setrlimit(RLIMIT_CORE, &limit) == 0 ? 0 : errno;
    }
    case USERNS: return unshare(CLONE_NEWUSER) == 0 ? 0 : errno;
    default: return 0;
    }
}

#define EXEC_FAILED 1000 /* report codes: setup errno, or EXEC_FAILED + exec errno */

/* Starts image with argv; share_fs uses clone(CLONE_FS) so the parent shares fs_struct.
 * Returns 0 once the exec happened (the close-on-exec report pipe reached EOF). */
static int spawn(struct child *child, const char *image, const char *mode, enum setup setup, int piped, int share_fs) {
    int to_child[2] = {-1, -1}, from_child[2] = {-1, -1}, report[2] = {-1, -1};
    pid_t pid = -1;
    if ((!piped || (!pipe2(to_child, O_CLOEXEC) && !pipe2(from_child, O_CLOEXEC))) && !pipe2(report, O_CLOEXEC))
        pid = share_fs ? (pid_t)syscall(SYS_clone, CLONE_FS | SIGCHLD, 0, 0, 0, 0) : fork();
    if (pid < 0) {
        close_pair(to_child);
        close_pair(from_child);
        close_pair(report);
        return -1;
    }
    if (pid == 0) {
        if (piped && (dup2(to_child[0], 0) < 0 || dup2(from_child[1], 1) < 0)) _exit(120);
        int code = prepare(setup);
        if (code) {
            send_all(report[1], &code, sizeof code);
            _exit(121);
        }
        int with_socket = !strcmp(mode, "run") || !strcmp(mode, "hold");
        char *const arguments[] = {"remozio", (char *)mode, with_socket ? (char *)socket_path : NULL, NULL};
        char *const environment[] = {NULL};
        execve(image, arguments, environment);
        code = EXEC_FAILED + errno;
        send_all(report[1], &code, sizeof code);
        _exit(122);
    }
    close(report[1]);
    if (piped) { close(to_child[0]); close(from_child[1]); }
    child->pid = pid;
    child->in = piped ? to_child[1] : -1;
    child->out = piped ? from_child[0] : -1;
    int code = 0;
    ssize_t n = read(report[0], &code, sizeof code); /* EOF at exec, also before a TRACEME exec stop */
    close(report[0]);
    if (n > 0) waitpid(pid, NULL, __WALL);
    return n > 0 ? code : n == 0 ? 0 : -1;
}

static int wait_exit(pid_t pid) {
    int status = 0;
    while (waitpid(pid, &status, __WALL) == pid) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) return status;
        if (WIFSTOPPED(status)) ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status) == SIGTRAP ? 0 : WSTOPSIG(status));
    }
    return -1;
}

/* Reads "R<16 hex>\n" from a holding frontend; returns the marker address or 0. */
static uintptr_t await_ready(const struct child *child) {
    char line[19] = {0};
    size_t total = 0;
    while (total < 18) {
        ssize_t n = read(child->out, line + total, 18 - total);
        if (n <= 0) return 0;
        total += (size_t)n;
    }
    if (line[0] != 'R' || line[17] != '\n') return 0;
    line[17] = 0;
    return (uintptr_t)strtoull(line + 1, NULL, 16);
}

static void release(const struct child *child) { send_all(child->in, "g", 1); }

static const char *effective_gid_elevated(pid_t pid) {
    char path[64], status[8192];
    snprintf(path, sizeof path, "/proc/%d/status", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "unreadable";
    ssize_t n = read(fd, status, sizeof status - 1);
    close(fd);
    if (n <= 0) return "unreadable";
    status[n] = 0;
    const char *line = strstr(status, "\nGid:");
    unsigned long real, effective;
    if (!line || sscanf(line + 5, "%lu %lu", &real, &effective) != 2) return "unreadable";
    return effective == frontend_gid ? "yes" : "no";
}

/* N1: the launching parent attacks a holding frontend before it connects. */
static void attack(const char *prefix, const char *image) {
    struct child child;
    if (spawn(&child, image, "hold", PLAIN, 1, 0) != 0) { prefixed(prefix, "spawn", "failed"); return; }
    uintptr_t marker = await_ready(&child);
    prefixed(prefix, "ready", marker ? "yes" : "no");
    char path[64], expected[16], buffer[16];
    memcpy(expected, "RMZPL-MARKER-v1", 16);
    snprintf(path, sizeof path, "/proc/%d/mem", (int)child.pid);
    int mem = open(path, O_RDWR | O_CLOEXEC);
    prefixed(prefix, "procMemOpen", mem >= 0 ? "ok" : errname(errno));
    if (mem >= 0) {
        int read_ok = pread(mem, buffer, 16, (off_t)marker) == 16 && memcmp(buffer, expected, 16) == 0;
        prefixed(prefix, "procMemReadMarker", read_ok ? "yes" : "no");
        prefixed(prefix, "procMemWrite", pwrite(mem, expected, 16, (off_t)marker) == 16 ? "ok" : errname(errno));
        close(mem);
    } else {
        prefixed(prefix, "procMemReadMarker", "not-attempted");
        prefixed(prefix, "procMemWrite", "not-attempted");
    }
    struct iovec local = {buffer, 16}, remote = {(void *)marker, 16};
    ssize_t got = process_vm_readv(child.pid, &local, 1, &remote, 1, 0);
    prefixed(prefix, "vmRead", got == 16 && memcmp(buffer, expected, 16) == 0 ? "ok" : got < 0 ? errname(errno) : "mismatch");
    struct iovec source = {expected, 16};
    ssize_t put = process_vm_writev(child.pid, &source, 1, &remote, 1, 0);
    prefixed(prefix, "vmWrite", put == 16 ? "ok" : put < 0 ? errname(errno) : "short");
    int pidfd = (int)syscall(SYS_pidfd_open, child.pid, 0);
    int copy = pidfd < 0 ? -1 : (int)syscall(SYS_pidfd_getfd, pidfd, 0, 0);
    prefixed(prefix, "pidfdGetfd", copy >= 0 ? "ok" : errname(errno));
    if (copy >= 0) close(copy);
    if (pidfd >= 0) close(pidfd);
    prefixed(prefix, "seize", ptrace(PTRACE_SEIZE, child.pid, 0, 0) == 0 ? "ok" : errname(errno));
    kill(child.pid, SIGKILL);
    waitpid(child.pid, NULL, __WALL);
}

/* N2-N4, N9, N12: launch with a setup, record the effective GID, then let it try to connect. */
static void launch_and_observe(enum setup setup, int share_fs, int detach_after_exec) {
    struct child child;
    int code = spawn(&child, installed, "hold", setup, 1, share_fs);
    if (setup == USERNS) {
        /* The unshare errno itself; only EPERM and EACCES count as a policy refusal. */
        if (code > 0 && code < EXEC_FAILED) { field("userNamespace", errname(code)); return; }
        field("userNamespace", "created");
    }
    if (code) { field("spawn", "failed"); return; }
    if (setup == TRACEME) {
        int status = 0;
        if (waitpid(child.pid, &status, __WALL) != child.pid || !WIFSTOPPED(status)) { field("execStop", "no"); return; }
        field("execStop", "yes");
        field("effectiveGidElevated", effective_gid_elevated(child.pid));
        ptrace(detach_after_exec ? PTRACE_DETACH : PTRACE_CONT, child.pid, 0, 0);
        field("ready", await_ready(&child) ? "yes" : "no");
    } else {
        field("ready", await_ready(&child) ? "yes" : "no");
        field("effectiveGidElevated", effective_gid_elevated(child.pid));
    }
    release(&child);
    field("frontendExit", exit_category(wait_exit(child.pid)));
}

static void run_plain(enum setup setup) {
    struct child child;
    if (spawn(&child, installed, "run", setup, 0, 0) != 0) { field("spawn", "failed"); return; }
    field("frontendExit", exit_category(wait_exit(child.pid)));
}

static void selftests(void) {
    static const char *const tests[] = {"selftest-exec", "selftest-mprotect", "selftest-mmap-exec",
                                        "selftest-shared", "selftest-clone", "selftest-x32"};
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        struct child child;
        int ok = spawn(&child, installed, tests[i], CORE_LIMIT, 0, 0) == 0;
        field(tests[i] + 9, ok ? exit_category(wait_exit(child.pid)) : "spawn-failed");
    }
}

/* N8: hold an O_PATH descriptor across the runner's replacement, then execute the old inode. */
static void old_inode(void) {
    int image = open(installed, O_PATH | O_CLOEXEC);
    field("oPathOpen", image >= 0 ? "ok" : errname(errno));
    if (image < 0) return;
    printf("R\n");
    fflush(stdout);
    char go = 0;
    if (read(0, &go, 1) != 1) { field("go", "missing"); return; }
    pid_t pid = fork();
    if (pid == 0) {
        char *const arguments[] = {"remozio", "run", (char *)socket_path, NULL};
        char *const environment[] = {NULL};
        syscall(SYS_execveat, image, "", arguments, environment, AT_EMPTY_PATH);
        _exit(122);
    }
    field("frontendExit", pid > 0 ? exit_category(wait_exit(pid)) : "spawn-failed");
}

int main(int argc, char **argv) {
    used = (size_t)snprintf(json, sizeof json, "{");
    char *end = NULL;
    if (argc != 7) return 4;
    installed = argv[2];
    control = argv[3];
    socket_path = argv[4];
    frontend_gid = strtoul(argv[5], &end, 10);
    unsigned long seconds = strtoul(argv[6], NULL, 10);
    if (*end || seconds == 0 || seconds > 60 || geteuid() == 0) return 4;
    alarm((unsigned)seconds);
    const char *name = argv[1];
    if (!strcmp(name, "p1") || !strcmp(name, "n10")) run_plain(PLAIN);
    else if (!strcmp(name, "n1")) { attack("installed.", installed); attack("control.", control); }
    else if (!strcmp(name, "n2")) launch_and_observe(TRACEME, 0, 0);
    else if (!strcmp(name, "n3")) launch_and_observe(NNP, 0, 0);
    else if (!strcmp(name, "n4")) launch_and_observe(PLAIN, 1, 0);
    else if (!strcmp(name, "n5")) run_plain(PERSONALITY);
    else if (!strcmp(name, "n6")) run_plain(NOISY_FDS);
    else if (!strcmp(name, "n7")) selftests();
    else if (!strcmp(name, "n8")) old_inode();
    else if (!strcmp(name, "n9-untraced")) launch_and_observe(PLAIN, 0, 0);
    else if (!strcmp(name, "n9-traced")) launch_and_observe(TRACEME, 0, 1);
    else if (!strcmp(name, "n12")) launch_and_observe(USERNS, 0, 0);
    else return 4;
    if (overflow || sizeof json - used < 3) {
        fputs("{\"error\":\"overflow\"}\n", stdout); /* a dropped key must not look like a result */
        return 0;
    }
    used += (size_t)snprintf(json + used, sizeof json - used, "}\n");
    fputs(json, stdout);
    return 0;
}
