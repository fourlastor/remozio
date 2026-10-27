#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Disposable fixed frontend: no command argument, shell, installation or network.
 * It sends one fixed submission carrying its own stdin/stdout/stderr, then stops. */
static const char submission[] = "remozio-composed-submit-v1";

static void wait_forever(void) {
    for (;;) pause();
}

static int submit(int channel, const int *descriptors, int count) {
    char control[CMSG_SPACE(4 * sizeof(int))];
    memset(control, 0, sizeof(control));
    struct iovec io = {.iov_base = (void *)submission, .iov_len = sizeof(submission) - 1};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = CMSG_SPACE((size_t)count * sizeof(int))};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN((size_t)count * sizeof(int));
    memcpy(CMSG_DATA(header), descriptors, (size_t)count * sizeof(int));
    return sendmsg(channel, &message, MSG_NOSIGNAL) == (ssize_t)io.iov_len ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char *end = NULL;
    errno = 0;
    long parsed = strtol(argv[2], &end, 10);
    if (errno || !end || *end || parsed < 3 || parsed > 1024) return 3;
    int channel = (int)parsed;
    const int streams[] = {0, 1, 2, 0};
    int count = 3;
    if (strcmp(argv[1], "missing-stream") == 0) count = 2;
    else if (strcmp(argv[1], "extra-stream") == 0) count = 4;
    else if (strcmp(argv[1], "submit") != 0 && strcmp(argv[1], "fork") != 0) return 4;
    if (submit(channel, streams, count) != 0) return 5;
    if (raise(SIGSTOP) != 0) return 6;
    /* Only reached after the monitor releases this stop. */
    if (strcmp(argv[1], "fork") == 0 && fork() == -1) return 7;
    wait_forever();
    return 0;
}
