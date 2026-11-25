#include "include/RemozioCommandPTY.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <util.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>

struct remozio_command_pty { int master, slave; bool eof; };
static void close_descriptor(int *descriptor) {
    if (*descriptor >= 0) { close(*descriptor); *descriptor = -1; }
}
static int private_descriptor(int descriptor, bool nonblocking) {
    int flags = fcntl(descriptor, F_GETFD);
    if (flags < 0 || fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) < 0) return errno;
    if (nonblocking) {
        flags = fcntl(descriptor, F_GETFL);
        if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) return errno;
    }
    return 0;
}
static bool same_terminal(const struct stat *first, const struct stat *second) {
    return S_ISCHR(first->st_mode) && S_ISCHR(second->st_mode) &&
        first->st_dev == second->st_dev && first->st_ino == second->st_ino && first->st_rdev == second->st_rdev;
}
static int set_slave_owner(int descriptor, uid_t uid, gid_t gid) {
    struct stat original, current;
    if (fstat(descriptor, &original)) return errno;
    if (!S_ISCHR(original.st_mode) || !isatty(descriptor)) return ENOTTY;
    const mode_t owner_only = S_IRUSR | S_IWUSR;
    if (fchmod(descriptor, owner_only) || fchown(descriptor, uid, gid)) return errno;
    if (fstat(descriptor, &current)) return errno;
    if (!same_terminal(&original, &current) || current.st_uid != uid || current.st_gid != gid ||
        (current.st_mode & ALLPERMS) != owner_only) return ESTALE;
    return 0;
}
int remozio_command_pty_create_for_target(const struct termios *attributes, const struct winsize *size,
    uid_t uid, gid_t gid, remozio_command_pty_t **output) {
    if (!output) return EINVAL;
    *output = NULL;
    if (uid == (uid_t)-1 || gid == (gid_t)-1) return EINVAL;
    remozio_command_pty_t *pty = calloc(1, sizeof(*pty));
    if (!pty) return ENOMEM;
    pty->master = pty->slave = -1;
    struct termios copied_attributes; struct winsize copied_size;
    if (attributes) copied_attributes = *attributes;
    if (size) copied_size = *size;
    int error = 0;
    if (openpty(&pty->master, &pty->slave, NULL, attributes ? &copied_attributes : NULL, size ? &copied_size : NULL)) error = errno;
    if (!error) error = private_descriptor(pty->master, true);
    if (!error) error = private_descriptor(pty->slave, false);
    if (!error && uid != 0) error = set_slave_owner(pty->slave, uid, gid);
    if (error) { remozio_command_pty_close(pty); return error; }
    *output = pty; return 0;
}
int remozio_command_pty_create(const struct termios *attributes, const struct winsize *size,
    remozio_command_pty_t **output) {
    return remozio_command_pty_create_for_target(attributes, size, 0, 0, output);
}
int remozio_command_pty_borrow_slave(remozio_command_pty_t *pty, int *descriptor) {
    if (!pty || !descriptor) return EINVAL;
    *descriptor = -1;
    if (pty->slave < 0) return EBADF;
    *descriptor = pty->slave; return 0;
}
void remozio_command_pty_seal_slave(remozio_command_pty_t *pty) {
    if (pty) close_descriptor(&pty->slave);
}
int remozio_command_pty_read(remozio_command_pty_t *pty, void *bytes, size_t capacity, size_t *count, bool *eof) {
    if (!pty || !bytes || !count || !eof || !capacity || capacity > REMOZIO_PTY_MAX_CHUNK) return EINVAL;
    *count = 0; *eof = pty->eof;
    if (pty->eof) return 0;
    ssize_t result = read(pty->master, bytes, capacity);
    if (result > 0) { *count = (size_t)result; return 0; }
    if (result == 0 || (result < 0 && errno == EIO)) { pty->eof = true; *eof = true; return 0; }
    if (errno == EAGAIN || errno == EINTR) return 0;
    return errno;
}
int remozio_command_pty_write(remozio_command_pty_t *pty, const void *bytes, size_t count, size_t *written) {
    if (!pty || !written || (!bytes && count) || count > REMOZIO_PTY_MAX_CHUNK) return EINVAL;
    *written = 0;
    if (pty->eof) return EPIPE;
    if (!count) return 0;
    ssize_t result = write(pty->master, bytes, count);
    if (result >= 0) { *written = (size_t)result; return 0; }
    if (errno == EAGAIN || errno == EINTR) return 0;
    return errno;
}
int remozio_command_pty_resize(remozio_command_pty_t *pty, const struct winsize *size) {
    if (!pty || !size) return EINVAL;
    if (pty->eof) return EPIPE;
    return ioctl(pty->master, TIOCSWINSZ, size) < 0 ? errno : 0;
}
void remozio_command_pty_close(remozio_command_pty_t *pty) {
    if (!pty) return;
    close_descriptor(&pty->slave); close_descriptor(&pty->master); free(pty);
}

int remozio_command_pty_signal(remozio_command_pty_t *pty, int number) {
    if (!pty || number <= 0 || number >= NSIG) return EINVAL;
    if (pty->eof) return EPIPE;
    return ioctl(pty->master, TIOCSIG, number) < 0 ? errno : 0;
}
int remozio_command_pty_foreground_group(remozio_command_pty_t *pty, int *group) {
    if (!pty || !group) return EINVAL;
    *group = 0;
    if (pty->eof) return 0;
    pid_t observed = tcgetpgrp(pty->master);
    if (observed < 0) return errno == EIO || errno == ENXIO || errno == ENOTTY ? 0 : errno;
    if (observed > 0) *group = observed;
    return 0;
}
int remozio_command_pty_eof_sequence(remozio_command_pty_t *pty, unsigned char bytes[2], size_t *count) {
    if (!pty || !bytes || !count) return EINVAL;
    *count = 0;
    if (pty->eof) return EPIPE;
    struct termios current;
    if (tcgetattr(pty->master, &current) < 0) return errno;
    if (!(current.c_lflag & ICANON) || current.c_cc[VEOF] == _POSIX_VDISABLE) return 0;
    bytes[0] = bytes[1] = current.c_cc[VEOF]; *count = 2;
    return 0;
}

int remozio_command_pty_copy_stream(remozio_command_pty_t *pty, uint32_t access, uint32_t semantic_flags, int *output) {
    if (!output) return EINVAL;
    *output = -1;
    if (!pty || access > 2 || semantic_flags > 15) return EINVAL;
    if (pty->slave < 0) return EBADF;
    struct stat original = {0}, opened = {0}, current = {0};
    if (fstat(pty->slave, &original)) return errno;
    if (!S_ISCHR(original.st_mode) || isatty(pty->slave) != 1) return EINVAL;
    char path[PATH_MAX] = {0};
    if (fcntl(pty->slave, F_GETPATH, path)) return errno;
    if (path[0] != '/' || !memchr(path, 0, sizeof(path))) return EINVAL;
    int mode = access == 0 ? O_RDONLY : access == 1 ? O_WRONLY : O_RDWR;
    int flags = (semantic_flags & 1 ? O_APPEND : 0) | (semantic_flags & 2 ? O_NONBLOCK : 0) |
        (semantic_flags & 4 ? O_ASYNC : 0) | (semantic_flags & 8 ? O_SYNC : 0);
    int descriptor = open(path, mode | flags | O_NOCTTY | O_CLOEXEC);
    if (descriptor < 0) return errno;
    int error = 0;
    if (fstat(descriptor, &opened) || fstat(pty->slave, &current)) error = errno;
    if (!error && (!same_terminal(&original, &opened) || !same_terminal(&original, &current) || isatty(descriptor) != 1)) error = ESTALE;
    int status = !error ? fcntl(descriptor, F_GETFL) : -1;
    if (!error && status < 0) error = errno;
    const int semantic_mask = O_APPEND | O_NONBLOCK | O_ASYNC | O_SYNC;
    if (!error && fcntl(descriptor, F_SETFL, (status & ~semantic_mask) | flags)) error = errno;
    if (!error) {
        status = fcntl(descriptor, F_GETFL);
        if (status < 0) error = errno;
        else if ((status & O_ACCMODE) != mode || (status & semantic_mask) != flags) error = EINVAL;
    }
    if (error) { close(descriptor); return error; }
    *output = descriptor; return 0;
}
