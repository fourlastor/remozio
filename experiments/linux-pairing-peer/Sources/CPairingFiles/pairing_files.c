#define _GNU_SOURCE
#include "PairingFiles.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int remozio_pairing_open_directory_path(const char *path) {
    return open(path, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

int remozio_pairing_chmod_directory_path(int fd, mode_t mode) {
    struct stat info;
    if (fstat(fd, &info) != 0) return -1;
    if (!S_ISDIR(info.st_mode) || info.st_uid != geteuid()) {
        errno = EPERM;
        return -1;
    }
    char path[64];
    int length = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        errno = EOVERFLOW;
        return -1;
    }
    /* This procfs link names the pinned inode, even after a rename. */
    return chmod(path, mode);
}
