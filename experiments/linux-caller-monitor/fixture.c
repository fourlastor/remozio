#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Disposable fixture only: no command argument, shell, installation or network. */
static volatile int marker_value = 41;
__attribute__((noinline, used)) static int code_marker(void) {
    return marker_value + 1;
}

static void wait_forever(void) {
    for (;;) pause();
}

static void *thread_body(void *unused) {
    (void)unused;
    wait_forever();
    return NULL;
}

static int memory_bootstrap(int channel) {
    /* This is deliberately NOT the supervised-first-exec admission topology. */
    int memory = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    if (memory == -1) return 20;
    uint64_t address = (uint64_t)(uintptr_t)(void *)code_marker;
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct iovec io = {.iov_base = &address, .iov_len = sizeof(address)};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &memory, sizeof(memory));
    if (sendmsg(channel, &message, MSG_NOSIGNAL) != (ssize_t)sizeof(address)) return 21;
    close(memory);
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) return 22;
    if (raise(SIGSTOP) != 0) return 23;
    wait_forever();
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char *end = NULL;
    errno = 0;
    long parsed = strtol(argv[2], &end, 10);
    if (errno || !end || *end || parsed < 3 || parsed > 1024) return 3;
    int channel = (int)parsed;
    if (strcmp(argv[1], "memory-modification") == 0) return memory_bootstrap(channel);
    if (strcmp(argv[1], "sender-mismatch") != 0 &&
        send(channel, "request", 7, MSG_NOSIGNAL) != 7) return 4;
    if (raise(SIGSTOP) != 0) return 5;
    if (strcmp(argv[1], "same-path-exec") == 0) {
        char *arguments[] = {argv[0], "second-image", argv[2], NULL};
        char *environment[] = {"LC_ALL=C", "PATH=/usr/bin:/bin", NULL};
        execve(argv[0], arguments, environment);
        return 6;
    }
    if (strcmp(argv[1], "fork") == 0) {
        if (fork() == -1) return 7;
    } else if (strcmp(argv[1], "vfork") == 0) {
        pid_t child = vfork();
        if (child == -1) return 8;
        if (child == 0) _exit(0);
    } else if (strcmp(argv[1], "thread-clone") == 0) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, thread_body, NULL) != 0) return 9;
    } else if (strcmp(argv[1], "caller-exit") == 0) {
        return 0;
    }
    wait_forever();
    return 0;
}
