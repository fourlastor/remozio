/*
 * Single-owner frontend fixture (issue #988, PR1). It plays the caller's frontend C:
 * it sets a fixed umask and a fixed RLIMIT_NOFILE soft limit (the state the command
 * must inherit), connects to the owner, sends a fixed hello with its three standard
 * descriptors, and then blocks until the owner closes the connection. It never
 * executes another program.
 *
 * Build option (tests only): RMZSO_FIXTURE_PTRACER lets any process of the same
 * account trace it (PR_SET_PTRACER_ANY), so an unprivileged owner can seize it under
 * Yama scope 1. A measurement build never sets it.
 *
 * Exit codes: 0 the owner closed the connection, 4 usage, 11 socket failure,
 * 12 protocol failure.
 */
#define _GNU_SOURCE
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define FIXTURE_UMASK 027
#define FIXTURE_NOFILE 777

int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 4;
#ifdef RMZSO_FIXTURE_PTRACER
    if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) != 0) return 11;
#endif
    umask(FIXTURE_UMASK);
    struct rlimit nofile;
    if (getrlimit(RLIMIT_NOFILE, &nofile) != 0 || nofile.rlim_max < FIXTURE_NOFILE) return 11;
    nofile.rlim_cur = FIXTURE_NOFILE;
    if (setrlimit(RLIMIT_NOFILE, &nofile) != 0) return 11;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, argv[1]);
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof address) != 0) return 11;

    static const char hello[] = "RMZSO1\n";
    int streams[3] = {0, 1, 2};
    char control[CMSG_SPACE(sizeof streams)];
    memset(control, 0, sizeof control);
    struct iovec iov = {(void *)hello, sizeof hello - 1};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control,
                             .msg_controllen = sizeof control};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof streams);
    memcpy(CMSG_DATA(header), streams, sizeof streams);
    if (sendmsg(fd, &message, MSG_NOSIGNAL) != (ssize_t)(sizeof hello - 1)) return 12;

    /* Block until the owner closes the connection. */
    char byte;
    while (read(fd, &byte, 1) > 0) {
    }
    return 0;
}
