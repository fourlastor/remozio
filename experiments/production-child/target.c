/* Fixed disposable target. It reads one test byte and reports booleans only. */
#include "result.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static bool identifier(const char *text, uint32_t *out) {
    char *end = NULL; errno = 0; unsigned long value = strtoul(text, &end, 10);
    if (errno || !*text || *end || value >= UINT32_MAX) return false;
    *out = (uint32_t)value; return true;
}
static bool private_descriptors_closed(void) {
    struct proc_fdinfo descriptors[1024];
    int bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, descriptors, sizeof(descriptors));
    if (bytes <= 0 || bytes >= (int)sizeof(descriptors) || bytes % sizeof(*descriptors)) return false;
    for (size_t i = 0; i < (size_t)bytes / sizeof(*descriptors); ++i)
        if (descriptors[i].proc_fd >= 3) return false;
    return true;
}
static int descriptor_controls(void) {
    if (!private_descriptors_closed()) return 71;
    int original = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (original < 0) return 71;
    int high = fcntl(original, F_DUPFD_CLOEXEC, 128); close(original);
    if (high < 0) return 71;
    bool refused = !private_descriptors_closed(); close(high);
    if (!refused || !private_descriptors_closed()) return 71;
    puts("{\"schemaVersion\":1,\"descriptorControls\":3,\"privilegedControlsRun\":false}"); return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--descriptor-controls")) return descriptor_controls();
    uint32_t uid, gid;
    if (argc != 3 || !identifier(argv[1], &uid) || !identifier(argv[2], &gid)) return 64;
    fixed_result_t result = { .magic = FIXED_RESULT_MAGIC,
        .identity = getuid() == uid && geteuid() == uid && getgid() == gid && getegid() == gid,
        .private_fds_closed = private_descriptors_closed(), .extra_group_access = uid == 0 };
    unsigned char input[2] = {0};
    ssize_t count; do { count = read(0, input, sizeof(input)); } while (count < 0 && errno == EINTR);
    result.input = count == 1 && input[0] == 'Q';
    if (uid != 0) {
        char executable[PATH_MAX], path[PATH_MAX]; uint32_t size = sizeof(executable);
        if (_NSGetExecutablePath(executable, &size) || !realpath(executable, path)) return 70;
        char *name = strrchr(path, '/'); if (!name) return 70;
        if ((size_t)(name + 1 - path) + sizeof("group-read") > sizeof(path)) return 70;
        strcpy(name + 1, "group-read");
        int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            struct stat st; unsigned char byte = 0;
            result.extra_group_access = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == 0 &&
                st.st_nlink == 1 && (st.st_mode & 0777) == 0640 && read(fd, &byte, 1) == 1 && byte == 'G';
            close(fd);
        }
    }
    ssize_t sent = write(1, &result, sizeof(result));
    return sent == sizeof(result) && result.identity && result.input && result.private_fds_closed && result.extra_group_access ? 0 : 71;
}
