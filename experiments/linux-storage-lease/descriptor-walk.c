#define _GNU_SOURCE
#include "descriptor-walk.h"
#include <fcntl.h>
#include <limits.h>
#include <string.h>

bool rdw_valid_path(const char *path, bool absolute) {
    if (!path || !*path || strnlen(path, RDW_MAX_PATH) == RDW_MAX_PATH ||
        (absolute ? path[0] != '/' : path[0] == '/')) return false;
    const char *component = path + (absolute ? 1 : 0);
    while (*component) {
        const char *end = strchr(component, '/');
        size_t length = end ? (size_t)(end - component) : strlen(component);
        if (length == 0 || length > NAME_MAX || (length == 1 && component[0] == '.') ||
            (length == 2 && component[0] == '.' && component[1] == '.')) return false;
        if (!end) return true;
        component = end + 1;
    }
    return false; /* No '/', empty relative path or trailing slash. */
}
void rdw_begin(rdw_cursor *cursor, const char *path, bool absolute) {
    memcpy(cursor->copy, path, strlen(path) + 1);
    cursor->component = cursor->copy + (absolute ? 1 : 0);
}
const char *rdw_next(rdw_cursor *cursor, bool *last) {
    char *component = cursor->component;
    if (!component) return NULL;
    char *next = strchr(component, '/');
    *last = next == NULL;
    if (next) *next = 0;
    cursor->component = next ? next + 1 : NULL;
    return component;
}
int rdw_open_root(void) { return open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); }
int rdw_open_directory(int parent, const char *name) {
    return openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
}
int rdw_open_file(int parent, const char *name, int access) {
    return openat(parent, name, access | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
}
rdw_recheck_result rdw_recheck(int parent, const char *name, int fd, dev_t device, ino_t inode,
                               bool directory, struct stat *held) {
    struct stat named;
    if (fstat(fd, held) || fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW)) return RDW_UNAVAILABLE;
    return held->st_dev == device && held->st_ino == inode && named.st_dev == device && named.st_ino == inode &&
           (named.st_mode & S_IFMT) == (directory ? S_IFDIR : S_IFREG) ? RDW_SAME : RDW_CHANGED;
}
