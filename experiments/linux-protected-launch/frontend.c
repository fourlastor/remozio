/*
 * Protected-launch frontend fixture: a static, non-PIE image that the supervised
 * runner installs as root:<disposable group> 2755. At the start of main, after the
 * static C library startup, it reads its personality and applies its code policy,
 * before it reads argv or creates a socket, and it never executes another program.
 * It is a measurement fixture, not the product frontend.
 *
 * Exit codes: 0 monitor accepted, 2 monitor rejected, 3 a forbidden self-test
 * operation returned, 4 usage, 5 code policy setup failed, 10 connect refused with
 * EACCES, 11 other socket failure, 12 protocol failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

/* Writable data at a fixed address (non-PIE) for the same-UID memory controls. */
volatile char rmz_marker[16] __attribute__((used)) = "RMZPL-MARKER-v1";

/* The personality the kernel left after exec, read before the filter forbids the call.
 * The monitor cannot read /proc/<pid>/personality (root-owned, mode 0400, for a task that
 * is not dumpable) with CAP_SYS_PTRACE alone, so the hello carries this value. */
static unsigned long start_personality = ~0UL;

#define LO(i) ((uint32_t)(offsetof(struct seccomp_data, args) + 8 * (i)))
#define HI(i) ((uint32_t)(offsetof(struct seccomp_data, args) + 8 * (i) + 4))
#define LOAD(off) BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (off))
#define ALLOW BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
#define KILL BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
#define JEQ(value, jt, jf) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (value), (jt), (jf))
#define SIMPLE(nr) JEQ((nr), 0, 1), ALLOW

/* The allowlist covers the fixture's full protocol path and nothing else. */
static struct sock_filter policy[] = {
    LOAD(offsetof(struct seccomp_data, arch)),
    JEQ(AUDIT_ARCH_X86_64, 1, 0),
    KILL,
    LOAD(offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1), /* x32 syscall numbers */
    KILL,
    SIMPLE(__NR_read), SIMPLE(__NR_write), SIMPLE(__NR_close), SIMPLE(__NR_connect),
    SIMPLE(__NR_sendmsg), SIMPLE(__NR_recvmsg), SIMPLE(__NR_exit), SIMPLE(__NR_exit_group),
    SIMPLE(__NR_rt_sigreturn), SIMPLE(__NR_rt_sigprocmask), SIMPLE(__NR_restart_syscall),
    SIMPLE(__NR_brk), SIMPLE(__NR_munmap),
    /* mmap: private anonymous memory only, never executable. */
    JEQ(__NR_mmap, 0, 10),
    LOAD(HI(2)), JEQ(0, 0, 7),
    LOAD(LO(2)), BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 5, 0),
    LOAD(HI(3)), JEQ(0, 0, 3),
    LOAD(LO(3)), JEQ(MAP_PRIVATE | MAP_ANONYMOUS, 0, 1),
    ALLOW,
    KILL,
    /* mprotect: never executable. */
    JEQ(__NR_mprotect, 0, 6),
    LOAD(HI(2)), JEQ(0, 0, 3),
    LOAD(LO(2)), BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, 1, 0),
    ALLOW,
    KILL,
    /* socket: one close-on-exec Unix sequenced-packet socket. */
    JEQ(__NR_socket, 0, 10),
    LOAD(HI(0)), JEQ(0, 0, 7),
    LOAD(LO(0)), JEQ(AF_UNIX, 0, 5),
    LOAD(HI(1)), JEQ(0, 0, 3),
    LOAD(LO(1)), JEQ(SOCK_SEQPACKET | SOCK_CLOEXEC, 0, 1),
    ALLOW,
    KILL,
    KILL,
};

struct kernel_sigaction {
    void (*handler)(int);
    unsigned long flags;
    void (*restorer)(void);
    unsigned long mask;
};

static void put(int fd, const char *text, size_t length) {
    while (length > 0) {
        ssize_t written = write(fd, text, length);
        if (written <= 0) return;
        text += written;
        length -= (size_t)written;
    }
}

/* Runs before argv is read: descriptors, signals, no_new_privs, then the filter. */
static int apply_code_policy(void) {
    if (syscall(SYS_close_range, 3U, ~0U, 0U) != 0) return -1;
    struct kernel_sigaction dfl = {.handler = SIG_DFL};
    for (int number = 1; number <= 64; number++) {
        if (number == SIGKILL || number == SIGSTOP) continue;
        if (syscall(SYS_rt_sigaction, number, &dfl, NULL, sizeof(unsigned long)) != 0) return -1;
    }
    unsigned long none = 0;
    if (syscall(SYS_rt_sigprocmask, SIG_SETMASK, &none, NULL, sizeof none) != 0) return -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    struct sock_fprog program = {.len = sizeof policy / sizeof policy[0], .filter = policy};
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}

static int submit(const char *path) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    size_t length = strlen(path);
    if (length == 0 || length >= sizeof address.sun_path) return 11;
    memcpy(address.sun_path, path, length);
    int sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (sock < 0) return 11;
    if (connect(sock, (struct sockaddr *)&address, sizeof address) != 0)
        return errno == EACCES ? 10 : 11;
    /* "RMZPL1 " + the personality as 8 hex digits + "\n": one 16-byte message. */
    char hello[16] = "RMZPL1 ";
    for (int digit = 0; digit < 8; digit++)
        hello[7 + digit] = "0123456789abcdef"[(start_personality >> (28 - 4 * digit)) & 0xf];
    hello[15] = '\n';
    if (write(sock, hello, sizeof hello) != (ssize_t)sizeof hello) return 12;
    char verdict = 0;
    if (read(sock, &verdict, 1) != 1) return 12;
    return verdict == 'A' ? 0 : verdict == 'R' ? 2 : 12;
}

/* Reports readiness and the marker address, then waits for one byte on stdin. */
static int hold(void) {
    char line[19] = "R";
    uintptr_t address = (uintptr_t)rmz_marker;
    for (int digit = 0; digit < 16; digit++)
        line[1 + digit] = "0123456789abcdef"[(address >> (60 - 4 * digit)) & 0xf];
    line[17] = '\n';
    put(1, line, 18);
    char go = 0;
    return read(0, &go, 1) == 1 ? 0 : -1;
}

static int forbidden(const char *test) {
    if (strcmp(test, "selftest-exec") == 0) {
        char *const arguments[] = {"true", NULL};
        syscall(SYS_execve, "/usr/bin/true", arguments, NULL);
    } else if (strcmp(test, "selftest-mprotect") == 0) {
        mprotect((void *)((uintptr_t)rmz_marker & ~(uintptr_t)4095), 4096, PROT_READ | PROT_EXEC);
    } else if (strcmp(test, "selftest-mmap-exec") == 0) {
        mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    } else if (strcmp(test, "selftest-shared") == 0) {
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    } else if (strcmp(test, "selftest-clone") == 0) {
        if (syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0) == 0) _exit(3);
    } else if (strcmp(test, "selftest-x32") == 0) {
        syscall(0x40000000L | SYS_getpid);
    } else {
        return 4;
    }
    return 3;
}

int main(int argc, char **argv) {
    start_personality = (unsigned long)syscall(SYS_personality, 0xffffffffUL); /* query only */
    if (apply_code_policy() != 0) _exit(5);
    if (argc == 2 && strcmp(argv[1], "dump-filter") == 0) {
        put(1, (const char *)policy, sizeof policy);
        _exit(0);
    }
    if (argc == 3 && strcmp(argv[1], "run") == 0) _exit(submit(argv[2]));
    if (argc == 3 && strcmp(argv[1], "hold") == 0) {
        if (hold() != 0) _exit(12);
        _exit(submit(argv[2]));
    }
    if (argc == 2 && strncmp(argv[1], "selftest-", 9) == 0) _exit(forbidden(argv[1]));
    _exit(4);
}
