#define _GNU_SOURCE
#include "composed_support.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/xattr.h>
#include <unistd.h>

ssize_t ccs_receive(int socket, void *buffer, size_t length, int *descriptors, int capacity, int *count,
                    int timeout_ms) {
    *count = 0;
    struct pollfd ready = {.fd = socket, .events = POLLIN};
    int polled;
    do polled = poll(&ready, 1, timeout_ms); while (polled < 0 && errno == EINTR);
    if (polled <= 0) {
        if (polled == 0) errno = ETIMEDOUT;
        return -1;
    }
    char control[CMSG_SPACE(16 * sizeof(int))];
    struct iovec io = {.iov_base = buffer, .iov_len = length};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = control,
                             .msg_controllen = sizeof(control)};
    ssize_t received;
    do received = recvmsg(socket, &message, MSG_CMSG_CLOEXEC); while (received < 0 && errno == EINTR);
    if (received < 0) return -1;
    int failed = received == 0 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS) {
            failed = 1;
            continue;
        }
        size_t bytes = header->cmsg_len - CMSG_LEN(0);
        int values[16];
        size_t items = bytes / sizeof(int);
        if (bytes % sizeof(int) != 0 || items > 16) {
            failed = 1;
            items = items > 16 ? 16 : items;
        }
        memcpy(values, CMSG_DATA(header), items * sizeof(int));
        for (size_t index = 0; index < items; index++) {
            if (*count < capacity) descriptors[(*count)++] = values[index];
            else {
                close(values[index]);
                failed = 1;
            }
        }
    }
    if (failed) {
        for (int index = 0; index < *count; index++) close(descriptors[index]);
        *count = 0;
        errno = EPROTO;
        return -1;
    }
    return received;
}

int ccs_send(int socket, const void *buffer, size_t length) {
    ssize_t sent;
    do sent = send(socket, buffer, length, MSG_NOSIGNAL); while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)length ? 0 : -1;
}

int ccs_spawn(pid_t *pid, const char *path, char *const argv[], char *const envp[], const int streams[3],
              int directory) {
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    int result = posix_spawn_file_actions_init(&actions);
    if (result) return result;
    result = posix_spawnattr_init(&attributes);
    if (result) {
        posix_spawn_file_actions_destroy(&actions);
        return result;
    }
    /* The owner ignores SIGPIPE while writing frames; the command gets the default back. */
    sigset_t empty, all;
    sigemptyset(&empty);
    sigemptyset(&all);
    sigaddset(&all, SIGPIPE);
    for (int target = 0; target < 3 && !result; target++)
        result = posix_spawn_file_actions_adddup2(&actions, streams[target], target);
    if (!result) result = posix_spawn_file_actions_addfchdir_np(&actions, directory);
    if (!result) result = posix_spawnattr_setsigmask(&attributes, &empty);
    if (!result) result = posix_spawnattr_setsigdefault(&attributes, &all);
    if (!result) result = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    if (!result) result = posix_spawn(pid, path, &actions, &attributes, argv, envp);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    return result;
}

int ccs_file_capability_absent(int descriptor) {
    ssize_t size = fgetxattr(descriptor, "security.capability", NULL, 0);
    if (size >= 0) return 0;
    return errno == ENODATA ? 1 : -1;
}
