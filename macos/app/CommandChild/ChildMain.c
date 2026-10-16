#include "RemozioCommandChild.h"
#include "RemozioCommandCredentials.h"
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <termios.h>
#include <unistd.h>

/* Root supplies private descriptors 3 through 6 and the format-2 terminal at 7. Stdin stays unread until exec. */
enum { configuration_fd = 3, directory_fd = 4, status_fd = 5, release_fd = 6, terminal_fd = 7 };
static mach_timebase_info_data_t timebase;
static uint64_t milliseconds(void) {
    return (uint64_t)(((__uint128_t)mach_continuous_time() * timebase.numer) / ((uint64_t)timebase.denom * 1000000));
}
static uint32_t word(const unsigned char *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
}
static void put_word(unsigned char *bytes, uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) bytes[index] = (unsigned char)(value >> ((3U - index) * 8));
}
static int report(uint32_t tag, int error) {
    unsigned char bytes[12]; put_word(bytes, 0x524d5231); put_word(bytes + 4, tag); put_word(bytes + 8, (uint32_t)error);
    ssize_t written = write(status_fd, bytes, sizeof(bytes));
    return written == sizeof(bytes) ? 0 : written < 0 ? errno : EIO;
}
static int read_exact(int descriptor, void *buffer, size_t count, uint64_t deadline) {
    size_t used = 0;
    while (used < count) {
        uint64_t now = milliseconds();
        if (now >= deadline) return ETIMEDOUT;
        struct pollfd item = { .fd = descriptor, .events = POLLIN };
        int ready = poll(&item, 1, (int)(deadline - now));
        if (ready < 0) { if (errno == EINTR) continue; return errno; }
        if (ready == 0) continue;
        if (item.revents & (POLLERR | POLLNVAL)) return EIO;
        ssize_t received = read(descriptor, (unsigned char *)buffer + used, count - used);
        if (received == 0) return ECANCELED;
        if (received < 0) { if (errno == EINTR || errno == EAGAIN) continue; return errno; }
        used += (size_t)received;
    }
    return milliseconds() < deadline ? 0 : ETIMEDOUT;
}
static int read_end(int descriptor, uint64_t deadline) {
    while (true) {
        uint64_t now = milliseconds();
        if (now >= deadline) return ETIMEDOUT;
        struct pollfd item = { .fd = descriptor, .events = POLLIN };
        int ready = poll(&item, 1, (int)(deadline - now));
        if (ready < 0) { if (errno == EINTR) continue; return errno; }
        if (ready == 0) continue;
        if (item.revents & (POLLERR | POLLNVAL)) return EIO;
        unsigned char extra;
        ssize_t received = read(descriptor, &extra, 1);
        if (received == 0) return milliseconds() < deadline ? 0 : ETIMEDOUT;
        if (received > 0) return EINVAL;
        if (errno != EINTR && errno != EAGAIN) return errno;
    }
}
static int private_descriptor(int descriptor, bool writing) {
    struct stat value;
    int flags = fcntl(descriptor, F_GETFL), fd_flags = fcntl(descriptor, F_GETFD);
    if (flags < 0 || fd_flags < 0 || fstat(descriptor, &value) != 0) return errno;
    if (!S_ISFIFO(value.st_mode) || (flags & O_ACCMODE) != (writing ? O_WRONLY : O_RDONLY)) return EINVAL;
    if (fcntl(descriptor, F_SETFD, fd_flags | FD_CLOEXEC) == -1 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == -1) return errno;
    return 0;
}
static int close_other_descriptors(void) {
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (bytes <= 0 || bytes > 1024 * 1024 || bytes % sizeof(struct proc_fdinfo) != 0) return EIO;
    struct proc_fdinfo *items = malloc((size_t)bytes);
    if (!items) return ENOMEM;
    int received = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, items, bytes);
    if (received < 0 || received > bytes || received % sizeof(*items) != 0) { free(items); return EIO; }
    for (size_t index = 0; index < (size_t)received / sizeof(*items); ++index)
        if (items[index].proc_fd >= 8) close(items[index].proc_fd);
    free(items); return 0;
}
static void wipe(void *buffer, size_t count) {
    volatile unsigned char *bytes = buffer;
    for (size_t index = 0; index < count; ++index) bytes[index] = 0;
}
int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "--execute") != 0 && strcmp(argv[1], "--execute-in-session") != 0)) return EX_USAGE;
    bool in_session = strcmp(argv[1], "--execute-in-session") == 0;
    if (geteuid() != 0 || getuid() != 0) return EX_NOPERM;
    if (in_session && (getsid(0) == getpid() || getsid(0) != getsid(getppid()) || getpgrp() != getpid())) return EX_CONFIG;
    signal(SIGPIPE, SIG_IGN);
    int error = private_descriptor(status_fd, true);
    if (error) return EX_CONFIG;
    remozio_child_spec_t spec = {0};
    unsigned char *frame = NULL;
    size_t frame_count = 0;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || !timebase.denom || !timebase.numer) { error = EIO; goto fail; }
    uint64_t started = milliseconds(), deadline = started + 60000;
    if ((error = private_descriptor(configuration_fd, false)) || (error = private_descriptor(release_fd, false)) ||
        (error = close_other_descriptors())) goto fail;
    struct stat directory;
    if (fstat(directory_fd, &directory) != 0) { error = errno; goto fail; }
    int directory_flags = fcntl(directory_fd, F_GETFD);
    if (!S_ISDIR(directory.st_mode) || directory_flags < 0 || fcntl(directory_fd, F_SETFD, directory_flags | FD_CLOEXEC) != 0 || getpgrp() != getpid()) { error = EINVAL; goto fail; }
    for (int descriptor = 0; descriptor < 3; ++descriptor) {
        int flags = fcntl(descriptor, F_GETFL);
        if (flags < 0 || (flags & O_EVTONLY) || (descriptor == 0 ? (flags & O_ACCMODE) == O_WRONLY : (flags & O_ACCMODE) == O_RDONLY)) { error = EINVAL; goto fail; }
    }
    unsigned char header[REMOZIO_CHILD_HEADER_BYTES];
    if ((error = read_exact(configuration_fd, header, sizeof(header), deadline))) goto fail;
    uint32_t body_count = word(header + 4), budget = word(header + 28);
    if ((word(header) != REMOZIO_CHILD_FRAME_V3) || body_count > REMOZIO_CHILD_MAX_BYTES - sizeof(header) || budget < 100 || budget > 60000) { error = EINVAL; goto fail; }
    deadline = started + budget;
    frame_count = sizeof(header) + body_count;
    frame = malloc(frame_count);
    if (!frame) { error = ENOMEM; goto fail; }
    memcpy(frame, header, sizeof(header));
    if ((error = read_exact(configuration_fd, frame + sizeof(header), body_count, deadline))) goto fail;
    if ((error = read_end(configuration_fd, deadline))) goto fail;
    close(configuration_fd);
    if ((error = remozio_child_spec_decode(frame, frame_count, &spec))) goto fail;
    wipe(frame, frame_count); free(frame); frame = NULL;
    if ((error = remozio_child_account_apply(&spec))) goto fail;
    close(configuration_fd);
    if ((error = close_other_descriptors())) goto fail;
    if (fchdir(directory_fd) != 0) { error = errno; goto fail; }
    close(directory_fd); umask(spec.file_creation_mask);
    if (spec.io_mode != 0) {
        int controlling = spec.io_mode == 2 ? terminal_fd : 0;
        int streams[3] = {0, 1, 2};
        if (spec.io_mode == 2 && (error = remozio_child_spec_validate_stdio(&spec, controlling, streams))) goto fail;
        if (in_session) {
            if (tcgetsid(controlling) != getsid(0) || tcgetpgrp(controlling) != getpgrp()) { error = EINVAL; goto fail; }
        } else {
            if (getsid(0) != getpid()) { error = EINVAL; goto fail; }
            if (ioctl(controlling, TIOCSCTTY, 0) != 0) { error = errno; goto fail; }
        }
    }
    close(terminal_fd);
    if (milliseconds() >= deadline) { error = ETIMEDOUT; goto fail; }
    if ((error = report(1, 0))) goto fail;
    unsigned char release;
    if ((error = read_exact(release_fd, &release, 1, deadline))) goto fail;
    if (release != 1) { error = EINVAL; goto fail; }
    close(release_fd); signal(SIGPIPE, SIG_DFL);
    execve(spec.executable, spec.arguments, spec.environment);
    error = errno;
fail:
    (void)report(2, error);
    if (frame) { wipe(frame, frame_count); free(frame); }
    remozio_child_spec_close(&spec);
    return EX_SOFTWARE;
}
