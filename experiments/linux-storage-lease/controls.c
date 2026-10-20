#define _GNU_SOURCE
#include "lease.h"
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#define CHECK(value) do { if (!(value)) return 1; } while (0)
static int acl_fault, filesystem_fault;
static bool stored_owner_fault;
static dev_t stored_owner_device;
static ino_t stored_owner_inode;
static unsigned stored_owner_injections;
ssize_t __real_fgetxattr(int, const char *, void *, size_t);
int __real_fstatfs(int, struct statfs *);
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *value) {
    int result = __real_fstat(fd, value);
    if (!result && stored_owner_fault && value->st_dev == stored_owner_device && value->st_ino == stored_owner_inode) {
        /* Inject only the fixture data object's observed UID. No chown, extra account,
         * privilege or actual foreign-owned file is involved in this control. */
        value->st_uid = getuid() ^ 1U;
        ++stored_owner_injections;
    }
    return result;
}
ssize_t __wrap_fgetxattr(int fd, const char *name, void *value, size_t size) {
    if (acl_fault) { errno = acl_fault; return -1; }
    return __real_fgetxattr(fd, name, value, size);
}
int __wrap_fstatfs(int fd, struct statfs *value) {
    if (filesystem_fault == 1) { errno = EIO; return -1; }
    int result = __real_fstatfs(fd, value);
    if (!result && filesystem_fault == 2) value->f_type = NFS_SUPER_MAGIC;
    return result;
}
static int path(char *out, const char *base, const char *name) {
    int size = snprintf(out, 4096, "%s/%s", base, name);
    return size > 0 && size < 4096 ? 0 : -1;
}
static int directory(const char *name) {
    if (mkdir(name, 0700)) return -1;
    int fd = open(name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    int result = fchmod(fd, 0700);
    close(fd);
    return result;
}
static int file(const char *name) {
    int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int result = fchmod(fd, 0600);
    close(fd);
    return result;
}
static int provision(const char *name) {
    char lock[4096], data[4096];
    return directory(name) || path(lock, name, "writer.lock") || file(lock) ||
           path(data, name, "fixture.data") || file(data);
}
static int remove_store(const char *name) {
    char lock[4096], data[4096];
    return path(lock, name, "writer.lock") || path(data, name, "fixture.data") ||
           unlink(lock) || unlink(data) || rmdir(name);
}
static int wait_success(pid_t child) {
    int status;
    pid_t result;
    do { result = waitpid(child, &status, 0); } while (result < 0 && errno == EINTR);
    return result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int descriptor_count(void) {
    DIR *stream = opendir("/proc/self/fd");
    if (!stream) return -1;
    int count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(stream))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
    int saved_error = errno;
    closedir(stream);
    return saved_error ? -1 : count;
}
static int extended_acl(const char *name, bool default_acl, unsigned owner_permissions) {
    /* Real Linux POSIX ACL xattr. The named-user entry has no effective permissions;
     * it still must refuse even though mode bits remain private. No libacl dependency. */
    struct {
        struct posix_acl_xattr_header header;
        struct posix_acl_xattr_entry entries[5];
    } __attribute__((packed)) acl;
    memset(&acl, 0, sizeof(acl));
    acl.header.a_version = htole32(POSIX_ACL_XATTR_VERSION);
    const uint16_t tags[] = {ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER};
    for (size_t i = 0; i < 5; ++i) {
        acl.entries[i].e_tag = htole16(tags[i]);
        acl.entries[i].e_perm = htole16(i == 0 ? owner_permissions : 0);
        /* The current UID is mapped even in an isolated user namespace. A named entry
         * for that UID remains an extended ACL; ACL_USER_OBJ still wins access checks. */
        acl.entries[i].e_id = htole32(i == 1 ? (uint32_t)getuid() : ACL_UNDEFINED_ID);
    }
    return setxattr(name, default_acl ? "system.posix_acl_default" : "system.posix_acl_access", &acl, sizeof(acl), 0);
}
static int refused(const char *anchor, const char *relative, uid_t owner, rsl_result expected) {
    rsl_lease *lease = NULL;
    rsl_result result = rsl_acquire(anchor, relative, owner, &lease);
    if (lease) { rsl_destroy(lease); return 0; }
    return result == expected;
}
static int retired_control(const char *case_name, const char *anchor, const char *store,
                            const char *lock, const char *data) {
    rsl_lease *lease = NULL, *fresh = NULL;
    CHECK(rsl_acquire(anchor, "store", getuid(), &lease) == RSL_OK);
    rsl_identity before, after;
    CHECK(rsl_data_identity(lease, &before) == RSL_OK);
    char old[4096];
    const char *changed = data;
    rsl_result expected = RSL_CHANGED;
    if (!strcmp(case_name, "directory-replacement")) changed = store;
    else if (!strcmp(case_name, "anchor-replacement")) changed = anchor;
    else if (!strcmp(case_name, "lock-replacement")) changed = lock;
    else if (!strcmp(case_name, "mode-change")) expected = RSL_METADATA;
    else if (!strcmp(case_name, "acl-change")) expected = RSL_ACL_PRESENT;
    if (expected == RSL_METADATA) CHECK(chmod(data, 0640) == 0);
    else if (expected == RSL_ACL_PRESENT) CHECK(extended_acl(data, false, 6) == 0);
    else {
        int size = snprintf(old, sizeof(old), "%s-old", changed);
        CHECK(size > 0 && size < (int)sizeof(old) && rename(changed, old) == 0);
        if (changed == store) CHECK(provision(store) == 0);
        else if (changed == anchor) { CHECK(directory(anchor) == 0); CHECK(provision(store) == 0); }
        else CHECK(file(changed) == 0);
    }
    CHECK(rsl_validate(lease) == expected);
    /* Restore exactly the old named object or metadata, then prove no resurrection. */
    if (expected == RSL_METADATA) CHECK(chmod(data, 0600) == 0);
    else if (expected == RSL_ACL_PRESENT) CHECK(removexattr(data, "system.posix_acl_access") == 0);
    else {
        if (changed == store) CHECK(remove_store(store) == 0);
        else if (changed == anchor) { CHECK(remove_store(store) == 0); CHECK(rmdir(anchor) == 0); }
        else CHECK(unlink(changed) == 0);
        CHECK(rename(old, changed) == 0);
    }
    CHECK(rsl_validate(lease) == RSL_RETIRED);
    CHECK(rsl_data_identity(lease, &after) == RSL_RETIRED);
    CHECK(refused(anchor, "store", getuid(), RSL_BUSY));
    rsl_close(lease);
    rsl_close(lease);
    CHECK(rsl_validate(lease) == RSL_CLOSED);
    CHECK(rsl_acquire(anchor, "store", getuid(), &fresh) == RSL_OK);
    CHECK(rsl_data_identity(fresh, &after) == RSL_OK && before.device == after.device && before.inode == after.inode);
    rsl_destroy(fresh);
    rsl_destroy(lease);
    return 0;
}
static int control(const char *case_name, const char *base, const char *self) {
    char anchor[4096], store[4096], lock[4096], data[4096], extra[4096];
    CHECK(path(anchor, base, "anchor") == 0 && directory(anchor) == 0);
    CHECK(path(store, anchor, "store") == 0 && provision(store) == 0);
    CHECK(path(lock, store, "writer.lock") == 0 && path(data, store, "fixture.data") == 0);
    CHECK(path(extra, base, "extra") == 0);
    if (!strcmp(case_name, "healthy") || !strcmp(case_name, "close-reopen")) {
        rsl_lease *lease = NULL;
        CHECK(rsl_acquire(anchor, "store", getuid(), &lease) == RSL_OK);
        rsl_identity before, after;
        CHECK(rsl_validate(lease) == RSL_OK && rsl_data_identity(lease, &before) == RSL_OK);
        rsl_close(lease); rsl_close(lease);
        CHECK(rsl_validate(lease) == RSL_CLOSED);
        rsl_destroy(lease); lease = NULL;
        CHECK(rsl_acquire(anchor, "store", getuid(), &lease) == RSL_OK);
        CHECK(rsl_data_identity(lease, &after) == RSL_OK && before.device == after.device && before.inode == after.inode);
        rsl_destroy(lease);
    } else if (!strcmp(case_name, "competing-writer") || !strcmp(case_name, "fork-copy") || !strcmp(case_name, "close-on-exec")) {
        rsl_lease *lease = NULL;
        CHECK(rsl_acquire(anchor, "store", getuid(), &lease) == RSL_OK);
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            if (!strcmp(case_name, "close-on-exec")) { execl(self, self, "--check-fds", NULL); _exit(1); }
            int ok = strcmp(case_name, "fork-copy") ||
                (rsl_validate(lease) == RSL_WRONG_PROCESS && rsl_validate(lease) == RSL_RETIRED);
            rsl_destroy(lease); /* No LOCK_UN: parent must retain its lock. */
            _exit(ok && refused(anchor, "store", getuid(), RSL_BUSY) ? 0 : 1);
        }
        CHECK(wait_success(child));
        CHECK(rsl_validate(lease) == RSL_OK && refused(anchor, "store", getuid(), RSL_BUSY));
        rsl_destroy(lease);
        CHECK(rsl_acquire(anchor, "store", getuid(), &lease) == RSL_OK);
        rsl_destroy(lease);
    } else if (!strcmp(case_name, "file-replacement") || !strcmp(case_name, "directory-replacement") ||
               !strcmp(case_name, "anchor-replacement") || !strcmp(case_name, "lock-replacement") ||
               !strcmp(case_name, "mode-change") || !strcmp(case_name, "acl-change")) {
        CHECK(retired_control(case_name, anchor, store, lock, data) == 0);
    } else if (!strcmp(case_name, "invalid-path")) {
        const char *paths[] = {"", "/store", ".", "..", "store/..", "store/", "store//child", "store/./child"};
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) CHECK(refused(anchor, paths[i], getuid(), RSL_ARGUMENT));
        CHECK(refused("/", "store", getuid(), RSL_ARGUMENT));
        char long_name[4097]; memset(long_name, 'a', sizeof(long_name)); long_name[4096] = 0;
        CHECK(refused(anchor, long_name, getuid(), RSL_ARGUMENT));
    } else if (!strcmp(case_name, "owner-mismatch")) {
        CHECK(refused(anchor, "store", getuid() + 1, RSL_ORDINARY_OWNER_REQUIRED));
    } else if (!strcmp(case_name, "stored-owner-mismatch")) {
        rsl_lease *lease = NULL;
        CHECK(rsl_acquire(anchor, "store", getuid(), &lease) == RSL_OK);
        rsl_destroy(lease);
        struct stat actual;
        CHECK(lstat(data, &actual) == 0 && S_ISREG(actual.st_mode) && actual.st_uid == getuid());
        stored_owner_device = actual.st_dev;
        stored_owner_inode = actual.st_ino;
        stored_owner_injections = 0;
        stored_owner_fault = true;
        CHECK(refused(anchor, "store", getuid(), RSL_METADATA) && stored_owner_injections > 0);
        stored_owner_fault = false;
        CHECK(lstat(data, &actual) == 0 && actual.st_uid == getuid());
        CHECK(rsl_acquire(anchor, "store", getuid(), &lease) == RSL_OK);
        rsl_destroy(lease);
    } else if (!strcmp(case_name, "acl-unavailable") || !strcmp(case_name, "acl-denied")) {
        acl_fault = !strcmp(case_name, "acl-denied") ? EACCES : EOPNOTSUPP;
        CHECK(refused(anchor, "store", getuid(), RSL_ACL_UNAVAILABLE)); acl_fault = 0;
    } else if (!strcmp(case_name, "filesystem-unavailable") || !strcmp(case_name, "unknown-filesystem")) {
        filesystem_fault = !strcmp(case_name, "filesystem-unavailable") ? 1 : 2;
        CHECK(refused(anchor, "store", getuid(), RSL_FILESYSTEM_UNAVAILABLE)); filesystem_fault = 0;
    } else if (!strcmp(case_name, "access-acl") || !strcmp(case_name, "default-acl")) {
        bool default_acl = !strcmp(case_name, "default-acl");
        CHECK(extended_acl(default_acl ? store : data, default_acl, default_acl ? 7 : 6) == 0);
        CHECK(refused(anchor, "store", getuid(), RSL_ACL_PRESENT));
    } else if (!strcmp(case_name, "directory-mode") || !strcmp(case_name, "anchor-mode") ||
               !strcmp(case_name, "file-mode") || !strcmp(case_name, "special-mode")) {
        const char *target = !strcmp(case_name, "directory-mode") ? store : !strcmp(case_name, "anchor-mode") ? anchor : data;
        CHECK(chmod(target, target == data ? (!strcmp(case_name, "special-mode") ? 04600 : 0640) : 0750) == 0);
        CHECK(refused(anchor, "store", getuid(), RSL_METADATA));
    } else if (!strcmp(case_name, "file-symlink") || !strcmp(case_name, "fifo") || !strcmp(case_name, "directory-as-file") ||
               !strcmp(case_name, "missing-file")) {
        CHECK(unlink(data) == 0);
        if (!strcmp(case_name, "file-symlink")) CHECK(symlink(lock, data) == 0);
        else if (!strcmp(case_name, "fifo")) CHECK(mkfifo(data, 0600) == 0);
        else if (!strcmp(case_name, "directory-as-file")) CHECK(directory(data) == 0);
        CHECK(refused(anchor, "store", getuid(), !strcmp(case_name, "fifo") ? RSL_METADATA : RSL_SYSTEM));
    } else if (!strcmp(case_name, "directory-symlink") || !strcmp(case_name, "anchor-symlink")) {
        const char *target = !strcmp(case_name, "directory-symlink") ? store : anchor;
        CHECK(rename(target, extra) == 0 && symlink(extra, target) == 0);
        CHECK(refused(anchor, "store", getuid(), RSL_SYSTEM));
    } else if (!strcmp(case_name, "ancestor-symlink")) {
        char via_alias[4096];
        CHECK(symlink(base, extra) == 0 && path(via_alias, extra, "anchor") == 0);
        CHECK(refused(via_alias, "store", getuid(), RSL_SYSTEM));
    } else if (!strcmp(case_name, "hardlink-data") || !strcmp(case_name, "hardlink-lock")) {
        CHECK(link(!strcmp(case_name, "hardlink-data") ? data : lock, extra) == 0);
        CHECK(refused(anchor, "store", getuid(), RSL_METADATA));
    } else if (!strcmp(case_name, "failed-acquire-cleanup")) {
        int before = descriptor_count(); CHECK(before >= 0);
        CHECK(chmod(data, 0640) == 0);
        for (int i = 0; i < 64; ++i) CHECK(refused(anchor, "store", getuid(), RSL_METADATA));
        CHECK(descriptor_count() == before && chmod(data, 0600) == 0);
        rsl_lease *lease = NULL; CHECK(rsl_acquire(anchor, "store", getuid(), &lease) == RSL_OK); rsl_destroy(lease);
    } else return 1;
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--check-fds")) return descriptor_count() == 4 ? 0 : 1;
    if (argc != 3 || getuid() == 0 || getuid() != geteuid() || getgid() != getegid()) return 64;
    /* Fixture provisioning only; the lease implementation never changes a process mask or object modes. */
    umask(0077);
    struct statfs filesystem;
    if (statfs(argv[2], &filesystem)) return 77;
    const char *kind = filesystem.f_type == TMPFS_MAGIC ? "tmpfs" :
        filesystem.f_type == EXT4_SUPER_MAGIC ? "ext-family" :
        filesystem.f_type == XFS_SUPER_MAGIC ? "xfs" : filesystem.f_type == BTRFS_SUPER_MAGIC ? "btrfs" : NULL;
    if (!kind) return 77;
    int before = descriptor_count();
    if (before < 0 || control(argv[1], argv[2], argv[0]) || descriptor_count() != before) return 1;
    printf("{\"case\":\"%s\",\"passed\":true,\"fixtureOnly\":true,\"protectedInstallation\":false,\"descriptorsClosed\":true,\"fixtureFilesystem\":\"%s\"%s}\n",
           argv[1], kind, !strcmp(argv[1], "stored-owner-mismatch") ? ",\"storedOwnerComparisonExercised\":true" : "");
    return 0;
}
