#define _GNU_SOURCE
#include "lease.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#define RSL_MAX_NODES 64
#define RSL_MAX_PATH 4096
struct node {
    int fd;
    int parent;
    char name[NAME_MAX + 1];
    dev_t device;
    ino_t inode;
    bool directory;
    bool private_object;
};
struct rsl_lease {
    struct node nodes[RSL_MAX_NODES];
    size_t count;
    uid_t owner;
    pid_t process;
    dev_t private_device;
    long filesystem;
    bool anchor_recorded;
    bool retired;
    bool closed;
};

static rsl_result no_acl(int fd, bool directory) {
    const char *names[] = {"system.posix_acl_access", "system.posix_acl_default"};
    for (size_t i = 0; i < (directory ? 2U : 1U); ++i) {
        /* Query presence only; any stored ACL (even a masked or malformed one) refuses.
         * ENODATA means absent. Unsupported, inaccessible and other errors are unavailable. */
        errno = 0;
        if (fgetxattr(fd, names[i], NULL, 0) >= 0) return RSL_ACL_PRESENT;
        if (errno != ENODATA) return RSL_ACL_UNAVAILABLE;
    }
    return RSL_OK;
}
static rsl_result filesystem(int fd, dev_t device, rsl_lease *lease) {
    struct statfs value;
    if (fstatfs(fd, &value)) return RSL_FILESYSTEM_UNAVAILABLE;
    /* Explicit fixture admission only. These filesystem kinds do not establish durability,
     * trusted mounts, at-rest integrity, or suitability for production protected storage. */
    if (value.f_type != TMPFS_MAGIC && value.f_type != EXT4_SUPER_MAGIC &&
        value.f_type != XFS_SUPER_MAGIC && value.f_type != BTRFS_SUPER_MAGIC)
        return RSL_FILESYSTEM_UNAVAILABLE;
    if (lease->anchor_recorded) {
        if (device != lease->private_device || value.f_type != lease->filesystem)
            return RSL_FILESYSTEM_UNAVAILABLE;
    } else {
        lease->private_device = device;
        lease->filesystem = value.f_type;
        lease->anchor_recorded = true;
    }
    return RSL_OK;
}
static rsl_result metadata(rsl_lease *lease, const struct node *node, const struct stat *info) {
    if ((info->st_mode & S_IFMT) != (node->directory ? S_IFDIR : S_IFREG)) return RSL_METADATA;
    if (!node->private_object) return RSL_OK; /* Explicit anchor excludes ancestor ownership policy. */
    if (info->st_uid != lease->owner || (info->st_mode & 07777) != (node->directory ? 0700 : 0600) ||
        (!node->directory && info->st_nlink != 1)) return RSL_METADATA;
    rsl_result result = filesystem(node->fd, info->st_dev, lease);
    return result == RSL_OK ? no_acl(node->fd, node->directory) : result;
}
static rsl_result add(rsl_lease *lease, int fd, int parent, const char *name,
                      bool directory, bool private_object) {
    if (lease->count == RSL_MAX_NODES) { close(fd); return RSL_ARGUMENT; }
    struct stat info;
    if (fstat(fd, &info)) { close(fd); return RSL_SYSTEM; }
    struct node node = {.fd = fd, .parent = parent, .device = info.st_dev, .inode = info.st_ino,
                        .directory = directory, .private_object = private_object};
    if (strlen(name) > NAME_MAX) { close(fd); return RSL_ARGUMENT; }
    memcpy(node.name, name, strlen(name) + 1);
    rsl_result result = metadata(lease, &node, &info);
    if (result != RSL_OK) { close(fd); return result; }
    lease->nodes[lease->count++] = node;
    return RSL_OK;
}
static bool valid_path(const char *path, bool absolute) {
    if (!path || !*path || strnlen(path, RSL_MAX_PATH) == RSL_MAX_PATH ||
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
static rsl_result walk(rsl_lease *lease, const char *path, bool anchor_path) {
    char copy[RSL_MAX_PATH];
    memcpy(copy, path, strlen(path) + 1);
    char *component = copy + (anchor_path ? 1 : 0);
    while (*component) {
        char *next = strchr(component, '/');
        if (next) *next = 0;
        int parent = (int)lease->count - 1;
        int fd = openat(lease->nodes[parent].fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) return RSL_SYSTEM;
        rsl_result result = add(lease, fd, parent, component, true, !anchor_path || next == NULL);
        if (result != RSL_OK) return result;
        if (!next) break;
        component = next + 1;
    }
    return RSL_OK;
}
rsl_result rsl_acquire(const char *anchor, const char *relative, uid_t fixture_owner, rsl_lease **out) {
    if (!out) return RSL_ARGUMENT;
    *out = NULL;
    if (!valid_path(anchor, true) || !valid_path(relative, false) ||
        strlen(anchor) + strlen(relative) + 1 >= RSL_MAX_PATH) return RSL_ARGUMENT;
    if (fixture_owner == 0 || fixture_owner != getuid() || getuid() != geteuid() || getgid() != getegid())
        return RSL_ORDINARY_OWNER_REQUIRED;
    rsl_lease *lease = calloc(1, sizeof(*lease));
    if (!lease) return RSL_SYSTEM;
    lease->owner = fixture_owner;
    lease->process = getpid();
    int root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    rsl_result result = root < 0 ? RSL_SYSTEM : add(lease, root, -1, "/", true, false);
    if (result == RSL_OK) result = walk(lease, anchor, true);
    if (result == RSL_OK) result = walk(lease, relative, false);
    int parent = (int)lease->count - 1;
    const char *names[] = {"writer.lock", "fixture.data"};
    for (size_t i = 0; result == RSL_OK && i < 2; ++i) {
        int fd = openat(lease->nodes[parent].fd, names[i], O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) { result = RSL_SYSTEM; break; }
        result = add(lease, fd, parent, names[i], false, true);
        if (result == RSL_OK && i == 0 && flock(fd, LOCK_EX | LOCK_NB))
            result = errno == EWOULDBLOCK || errno == EAGAIN ? RSL_BUSY : RSL_SYSTEM;
    }
    if (result == RSL_OK) result = rsl_validate(lease);
    if (result != RSL_OK) { rsl_destroy(lease); return result; }
    *out = lease;
    return RSL_OK;
}
rsl_result rsl_validate(rsl_lease *lease) {
    if (!lease) return RSL_ARGUMENT;
    if (lease->closed) return RSL_CLOSED;
    if (lease->retired) return RSL_RETIRED;
    rsl_result result = RSL_OK;
    if (getpid() != lease->process) result = RSL_WRONG_PROCESS;
    else if (getuid() != lease->owner || geteuid() != lease->owner || getgid() != getegid())
        result = RSL_ORDINARY_OWNER_REQUIRED;
    for (size_t i = 0; result == RSL_OK && i < lease->count; ++i) {
        const struct node *node = &lease->nodes[i];
        struct stat held, named;
        if (fstat(node->fd, &held) ||
            fstatat(node->parent < 0 ? AT_FDCWD : lease->nodes[node->parent].fd,
                    node->name, &named, AT_SYMLINK_NOFOLLOW)) result = RSL_SYSTEM;
        else if (held.st_dev != node->device || held.st_ino != node->inode ||
                 named.st_dev != node->device || named.st_ino != node->inode ||
                 (named.st_mode & S_IFMT) != (node->directory ? S_IFDIR : S_IFREG)) result = RSL_CHANGED;
        else result = metadata(lease, node, &held);
    }
    if (result != RSL_OK) lease->retired = true;
    return result;
}
rsl_result rsl_data_identity(rsl_lease *lease, rsl_identity *out) {
    if (!out) return RSL_ARGUMENT;
    rsl_result result = rsl_validate(lease);
    if (result != RSL_OK) return result;
    const struct node *node = &lease->nodes[lease->count - 1];
    *out = (rsl_identity){.device = node->device, .inode = node->inode};
    return RSL_OK;
}
void rsl_close(rsl_lease *lease) {
    if (!lease || lease->closed) return;
    lease->closed = true;
    /* close(), rather than LOCK_UN, preserves the parent's lock in forked copies. */
    for (size_t i = lease->count; i > 0; --i) close(lease->nodes[i - 1].fd);
    lease->count = 0;
}
void rsl_destroy(rsl_lease *lease) { rsl_close(lease); free(lease); }
