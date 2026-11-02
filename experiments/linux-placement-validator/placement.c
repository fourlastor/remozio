#define _GNU_SOURCE
#include "placement.h"
#include "../linux-storage-lease/descriptor-walk.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#define RPV_MAX_NODES 64
#define RPV_MAX_ACL_ENTRIES 64
struct node {
    int fd;
    int parent;
    char name[NAME_MAX + 1];
    dev_t device;
    ino_t inode;
    bool checked; /* Components before the anchor keep identity but carry no policy. */
    rpv_object object;
};
struct rpv_placement {
    struct node nodes[RPV_MAX_NODES];
    size_t count;
    uid_t user;
    pid_t process;
    dev_t device;
    uint64_t mount;
    bool anchor_recorded;
    bool retired;
    bool closed;
};
struct stored_acl {
    struct posix_acl_xattr_header header;
    struct posix_acl_xattr_entry entries[RPV_MAX_ACL_ENTRIES];
};

static bool ordinary_user(uid_t user) {
    return user != 0 && getuid() == user && geteuid() == user && getgid() == getegid();
}
static bool valid_object(const rpv_object *object) {
    return (object->kind == RPV_DIRECTORY || object->kind == RPV_FILE) &&
           (object->acl == RPV_ACL_NONE || object->acl == RPV_ACL_NO_WRITE_GRANTS) &&
           (object->mode & ~(mode_t)0777) == 0 && (object->mode & 022) == 0;
}
static rpv_result write_grants(const struct stored_acl *acl, size_t size) {
    size_t header = sizeof(acl->header), entry = sizeof(acl->entries[0]);
    if (size < header || (size - header) % entry || le32toh(acl->header.a_version) != POSIX_ACL_XATTR_VERSION)
        return RPV_ACL_UNAVAILABLE;
    for (size_t i = 0; i < (size - header) / entry; ++i) {
        unsigned tag = le16toh(acl->entries[i].e_tag), permissions = le16toh(acl->entries[i].e_perm);
        if (tag != ACL_USER_OBJ && tag != ACL_USER && tag != ACL_GROUP_OBJ &&
            tag != ACL_GROUP && tag != ACL_MASK && tag != ACL_OTHER) return RPV_ACL_UNAVAILABLE;
        /* The mask is ignored: the owner can widen it without changing the stored grant. */
        if (tag != ACL_USER_OBJ && tag != ACL_MASK && (permissions & ACL_WRITE)) return RPV_ACL_REFUSED;
    }
    return RPV_OK;
}
static rpv_result stored_acls(int fd, const rpv_object *object) {
    const char *names[] = {"system.posix_acl_access", "system.posix_acl_default"};
    for (size_t i = 0; i < (object->kind == RPV_DIRECTORY ? 2U : 1U); ++i) {
        struct stored_acl acl;
        /* ENODATA means absent. Unsupported, inaccessible, oversized and other errors refuse. */
        errno = 0;
        ssize_t size = fgetxattr(fd, names[i], &acl, sizeof(acl));
        if (size < 0) {
            if (errno == ENODATA) continue;
            return RPV_ACL_UNAVAILABLE;
        }
        if (object->acl == RPV_ACL_NONE) return RPV_ACL_REFUSED;
        rpv_result result = write_grants(&acl, (size_t)size);
        if (result != RPV_OK) return result;
    }
    return RPV_OK;
}
static rpv_result same_mount(rpv_placement *placement, int fd, dev_t device) {
    struct statx value;
    if (statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, STATX_MNT_ID, &value) ||
        !(value.stx_mask & STATX_MNT_ID)) return RPV_MOUNT_UNAVAILABLE;
    if (!placement->anchor_recorded) {
        placement->device = device;
        placement->mount = value.stx_mnt_id;
        placement->anchor_recorded = true;
    }
    return device == placement->device && value.stx_mnt_id == placement->mount ? RPV_OK : RPV_MOUNT;
}
static rpv_result metadata(rpv_placement *placement, const struct node *node, const struct stat *info) {
    bool directory = !node->checked || node->object.kind == RPV_DIRECTORY;
    if ((info->st_mode & S_IFMT) != (directory ? S_IFDIR : S_IFREG)) return RPV_TYPE;
    if (!node->checked) return RPV_OK; /* Explicit anchor excludes ancestor ownership policy. */
    if (info->st_uid != node->object.owner) return RPV_OWNER;
    if (info->st_gid != node->object.group) return RPV_GROUP;
    if ((info->st_mode & 07777) != node->object.mode) return RPV_MODE;
    if (!directory && info->st_nlink != 1) return RPV_LINKS;
    rpv_result result = stored_acls(node->fd, &node->object);
    return result == RPV_OK ? same_mount(placement, node->fd, info->st_dev) : result;
}
static rpv_result add(rpv_placement *placement, int fd, int parent, const char *name, const rpv_object *object) {
    if (placement->count == RPV_MAX_NODES || strlen(name) > NAME_MAX) { close(fd); return RPV_ARGUMENT; }
    struct stat info;
    if (fstat(fd, &info)) { close(fd); return RPV_SYSTEM; }
    for (size_t i = 0; i < placement->count; ++i)
        if (placement->nodes[i].device == info.st_dev && placement->nodes[i].inode == info.st_ino) {
            close(fd);
            return RPV_ALIAS;
        }
    struct node node = {.fd = fd, .parent = parent, .device = info.st_dev, .inode = info.st_ino, .checked = object != NULL};
    if (object) node.object = *object;
    memcpy(node.name, name, strlen(name) + 1);
    rpv_result result = metadata(placement, &node, &info);
    if (result != RPV_OK) { close(fd); return result; }
    placement->nodes[placement->count++] = node;
    return RPV_OK;
}
static rpv_result open_failure(int parent, const char *name) {
    int error = errno;
    struct stat info;
    if (error == ENOENT) return RPV_MISSING;
    if (fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW)) return RPV_SYSTEM;
    if (S_ISLNK(info.st_mode)) return RPV_SYMLINK;
    return error == ENOTDIR ? RPV_TYPE : RPV_SYSTEM;
}
static rpv_result walk_anchor(rpv_placement *placement, const char *anchor, const rpv_object *object) {
    rdw_cursor cursor;
    rdw_begin(&cursor, anchor, true);
    const char *component;
    bool last;
    while ((component = rdw_next(&cursor, &last))) {
        int parent = (int)placement->count - 1;
        int fd = rdw_open_directory(placement->nodes[parent].fd, component);
        if (fd < 0) return open_failure(placement->nodes[parent].fd, component);
        rpv_result result = add(placement, fd, parent, component, last ? object : NULL);
        if (result != RPV_OK) return result;
    }
    return RPV_OK;
}
/* Returns the entry index of the directory that holds entries[index], -1 for the anchor,
 * or -2 when the entry repeats a path or names a parent the caller did not list. */
static int parent_entry(const rpv_entry *entries, size_t index) {
    const char *path = entries[index].path, *slash = strrchr(path, '/');
    size_t length = slash ? (size_t)(slash - path) : 0;
    int parent = slash ? -2 : -1;
    for (size_t i = 0; i < index; ++i) {
        if (!strcmp(entries[i].path, path)) return -2;
        if (slash && entries[i].object.kind == RPV_DIRECTORY && strlen(entries[i].path) == length &&
            !memcmp(entries[i].path, path, length)) parent = (int)i;
    }
    return parent;
}
static bool valid_expectations(const char *anchor, const rpv_object *anchor_object,
                               const rpv_entry *entries, size_t count) {
    if (!rdw_valid_path(anchor, true) || !anchor_object || !valid_object(anchor_object) ||
        anchor_object->kind != RPV_DIRECTORY || count >= RPV_MAX_NODES || (count && !entries)) return false;
    for (size_t i = 0; i < count; ++i)
        if (!rdw_valid_path(entries[i].path, false) || !valid_object(&entries[i].object) ||
            parent_entry(entries, i) == -2) return false;
    return true;
}
static rpv_result walk_entries(rpv_placement *placement, const rpv_entry *entries, size_t count) {
    size_t anchor = placement->count - 1;
    for (size_t i = 0; i < count; ++i) {
        int parent_index = parent_entry(entries, i);
        int parent = (int)anchor + (parent_index < 0 ? 0 : parent_index + 1);
        const char *slash = strrchr(entries[i].path, '/');
        const char *name = slash ? slash + 1 : entries[i].path;
        int fd = entries[i].object.kind == RPV_DIRECTORY ? rdw_open_directory(placement->nodes[parent].fd, name)
                                                         : rdw_open_file(placement->nodes[parent].fd, name, O_RDONLY);
        if (fd < 0) return open_failure(placement->nodes[parent].fd, name);
        rpv_result result = add(placement, fd, parent, name, &entries[i].object);
        if (result != RPV_OK) return result;
    }
    return RPV_OK;
}
rpv_result rpv_acquire(const char *anchor, const rpv_object *anchor_object,
                       const rpv_entry *entries, size_t count, rpv_placement **out) {
    if (!out) return RPV_ARGUMENT;
    *out = NULL;
    if (!valid_expectations(anchor, anchor_object, entries, count)) return RPV_ARGUMENT;
    if (!ordinary_user(getuid())) return RPV_ORDINARY_USER_REQUIRED;
    rpv_placement *placement = calloc(1, sizeof(*placement));
    if (!placement) return RPV_SYSTEM;
    placement->user = getuid();
    placement->process = getpid();
    int root = rdw_open_root();
    rpv_result result = root < 0 ? RPV_SYSTEM : add(placement, root, -1, "/", NULL);
    if (result == RPV_OK) result = walk_anchor(placement, anchor, anchor_object);
    if (result == RPV_OK) result = walk_entries(placement, entries, count);
    if (result == RPV_OK) result = rpv_validate(placement);
    if (result != RPV_OK) { rpv_destroy(placement); return result; }
    *out = placement;
    return RPV_OK;
}
rpv_result rpv_validate(rpv_placement *placement) {
    if (!placement) return RPV_ARGUMENT;
    if (placement->closed) return RPV_CLOSED;
    if (placement->retired) return RPV_RETIRED;
    rpv_result result = RPV_OK;
    if (getpid() != placement->process) result = RPV_WRONG_PROCESS;
    else if (!ordinary_user(placement->user)) result = RPV_ORDINARY_USER_REQUIRED;
    for (size_t i = 0; result == RPV_OK && i < placement->count; ++i) {
        const struct node *node = &placement->nodes[i];
        struct stat held;
        bool directory = !node->checked || node->object.kind == RPV_DIRECTORY;
        rdw_recheck_result recheck = rdw_recheck(node->parent < 0 ? AT_FDCWD : placement->nodes[node->parent].fd,
                                                 node->name, node->fd, node->device, node->inode, directory, &held);
        if (recheck == RDW_UNAVAILABLE) result = RPV_SYSTEM;
        else if (recheck == RDW_CHANGED) result = RPV_CHANGED;
        else result = metadata(placement, node, &held);
    }
    if (result != RPV_OK) placement->retired = true;
    return result;
}
void rpv_close(rpv_placement *placement) {
    if (!placement || placement->closed) return;
    placement->closed = true;
    for (size_t i = placement->count; i > 0; --i) close(placement->nodes[i - 1].fd);
    placement->count = 0;
}
void rpv_destroy(rpv_placement *placement) { rpv_close(placement); free(placement); }
