#define _GNU_SOURCE
#include "placement.h"
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
enum { TARGET_NONE, TARGET_DEVICE, TARGET_ALIAS, TARGET_MOUNT, TARGET_MOUNT_MISSING };
static int acl_fault;
static bool acl_malformed;
static int target_fault;
static dev_t target_device, alias_device;
static ino_t target_inode, alias_inode;
static unsigned injections;
static const char *replace_from, *replace_saved;
static bool replaced;
ssize_t __real_fgetxattr(int, const char *, void *, size_t);
int __real_fstat(int, struct stat *);
int __real_fstatat(int, const char *, struct stat *, int);
int __real_statx(int, const char *, int, unsigned, struct statx *);
static bool is_target(const struct stat *value) {
    return value->st_dev == target_device && value->st_ino == target_inode;
}
static void disguise(struct stat *value) {
    if (target_fault == TARGET_DEVICE && is_target(value)) { value->st_dev ^= (dev_t)1; ++injections; }
    if (target_fault == TARGET_ALIAS && is_target(value)) {
        value->st_dev = alias_device;
        value->st_ino = alias_inode;
        ++injections;
    }
}
int __wrap_fstat(int fd, struct stat *value) {
    int result = __real_fstat(fd, value);
    if (!result) disguise(value);
    return result;
}
int __wrap_fstatat(int fd, const char *name, struct stat *value, int flags) {
    /* Live replacement at the exact point between the walk and its recheck. */
    if (replace_from && !replaced && !strcmp(name, strrchr(replace_from, '/') + 1)) {
        replaced = rename(replace_from, replace_saved) == 0;
        int created = open(replace_from, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (created >= 0) close(created);
    }
    int result = __real_fstatat(fd, name, value, flags);
    if (!result) disguise(value);
    return result;
}
int __wrap_statx(int fd, const char *name, int flags, unsigned mask, struct statx *value) {
    int result = __real_statx(fd, name, flags, mask, value);
    if (result || (target_fault != TARGET_MOUNT && target_fault != TARGET_MOUNT_MISSING)) return result;
    struct stat actual;
    if (__real_fstat(fd, &actual) || !is_target(&actual)) return result;
    ++injections;
    if (target_fault == TARGET_MOUNT) value->stx_mnt_id ^= 1;
    else value->stx_mask &= ~(unsigned)STATX_MNT_ID;
    return result;
}
ssize_t __wrap_fgetxattr(int fd, const char *name, void *value, size_t size) {
    if (acl_fault) { errno = acl_fault; ++injections; return -1; }
    if (acl_malformed) {
        const uint32_t header[3] = {htole32(POSIX_ACL_XATTR_VERSION + 1), 0, 0};
        memcpy(value, header, sizeof(header));
        ++injections;
        return sizeof(header);
    }
    return __real_fgetxattr(fd, name, value, size);
}

struct fixture {
    char anchor[4096], bin[4096], tool[4096], state[4096], store[4096], extra[4096], saved[4096];
    rpv_object anchor_object;
    rpv_entry entries[4];
};
static int path(char *out, const char *base, const char *name) {
    int size = snprintf(out, 4096, "%s/%s", base, name);
    return size > 0 && size < 4096 ? 0 : -1;
}
static int directory(const char *name, mode_t mode) {
    if (mkdir(name, 0700)) return -1;
    return chmod(name, mode);
}
static int file(const char *name, mode_t mode) {
    int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int result = fchmod(fd, mode);
    close(fd);
    return result;
}
static rpv_object expected(rpv_kind kind, mode_t mode) {
    return (rpv_object){.kind = kind, .owner = getuid(), .group = getegid(), .mode = mode, .acl = RPV_ACL_NONE};
}
static int provision(struct fixture *f, const char *base) {
    CHECK(path(f->anchor, base, "anchor") == 0 && directory(f->anchor, 0755) == 0);
    CHECK(path(f->bin, f->anchor, "bin") == 0 && directory(f->bin, 0755) == 0);
    CHECK(path(f->tool, f->bin, "tool") == 0 && file(f->tool, 0755) == 0);
    CHECK(path(f->state, f->anchor, "state") == 0 && directory(f->state, 0700) == 0);
    CHECK(path(f->store, f->state, "store") == 0 && file(f->store, 0600) == 0);
    CHECK(path(f->extra, base, "extra") == 0 && path(f->saved, base, "saved") == 0);
    f->anchor_object = expected(RPV_DIRECTORY, 0755);
    f->entries[0] = (rpv_entry){"bin", expected(RPV_DIRECTORY, 0755)};
    f->entries[1] = (rpv_entry){"bin/tool", expected(RPV_FILE, 0755)};
    f->entries[2] = (rpv_entry){"state", expected(RPV_DIRECTORY, 0700)};
    f->entries[3] = (rpv_entry){"state/store", expected(RPV_FILE, 0600)};
    return 0;
}
static rpv_result attempt(const struct fixture *f) {
    rpv_placement *placement = NULL;
    rpv_result result = rpv_acquire(f->anchor, &f->anchor_object, f->entries, 4, &placement);
    if (placement) rpv_destroy(placement);
    return result;
}
static int refused(const struct fixture *f, rpv_result wanted) {
    rpv_placement *placement = NULL;
    rpv_result result = rpv_acquire(f->anchor, &f->anchor_object, f->entries, 4, &placement);
    if (placement) { rpv_destroy(placement); return 0; }
    return result == wanted;
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
/* Real Linux POSIX ACL xattr, written without a libacl dependency. The named entry uses the
 * current UID, which stays mapped in an isolated user namespace; ACL_USER_OBJ still wins access. */
static int extended_acl(const char *name, bool default_acl, unsigned owner, unsigned named, unsigned mask) {
    struct {
        struct posix_acl_xattr_header header;
        struct posix_acl_xattr_entry entries[5];
    } __attribute__((packed)) acl;
    memset(&acl, 0, sizeof(acl));
    acl.header.a_version = htole32(POSIX_ACL_XATTR_VERSION);
    const uint16_t tags[] = {ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER};
    const unsigned permissions[] = {owner, named, 0, mask, 0};
    for (size_t i = 0; i < 5; ++i) {
        acl.entries[i].e_tag = htole16(tags[i]);
        acl.entries[i].e_perm = htole16(permissions[i]);
        acl.entries[i].e_id = htole32(i == 1 ? (uint32_t)getuid() : ACL_UNDEFINED_ID);
    }
    return setxattr(name, default_acl ? "system.posix_acl_default" : "system.posix_acl_access", &acl, sizeof(acl), 0);
}
static int set_target(const char *name, int fault) {
    struct stat actual;
    CHECK(lstat(name, &actual) == 0);
    target_device = actual.st_dev;
    target_inode = actual.st_ino;
    injections = 0;
    target_fault = fault;
    return 0;
}
static int retired_control(const char *case_name, struct fixture *f) {
    rpv_placement *placement = NULL, *fresh = NULL;
    CHECK(rpv_acquire(f->anchor, &f->anchor_object, f->entries, 4, &placement) == RPV_OK);
    CHECK(rpv_validate(placement) == RPV_OK);
    const char *changed = !strcmp(case_name, "directory-replacement") ? f->state :
                          !strcmp(case_name, "anchor-replacement") ? f->anchor : f->store;
    rpv_result wanted = RPV_CHANGED;
    if (!strcmp(case_name, "mode-change")) {
        wanted = RPV_MODE;
        CHECK(chmod(f->store, 0640) == 0);
    } else if (!strcmp(case_name, "acl-change")) {
        wanted = RPV_ACL_REFUSED;
        CHECK(extended_acl(f->store, false, 6, 0, 0) == 0);
    } else {
        CHECK(rename(changed, f->saved) == 0);
        if (changed == f->store) CHECK(file(changed, 0600) == 0);
        else CHECK(directory(changed, changed == f->state ? 0700 : 0755) == 0);
    }
    CHECK(rpv_validate(placement) == wanted);
    /* Restoring the old object must not revive the retired instance. */
    if (wanted == RPV_MODE) CHECK(chmod(f->store, 0600) == 0);
    else if (wanted == RPV_ACL_REFUSED) CHECK(removexattr(f->store, "system.posix_acl_access") == 0);
    else {
        if (changed == f->store) CHECK(unlink(changed) == 0);
        else CHECK(rmdir(changed) == 0);
        CHECK(rename(f->saved, changed) == 0);
    }
    CHECK(rpv_validate(placement) == RPV_RETIRED);
    rpv_close(placement);
    rpv_close(placement);
    CHECK(rpv_validate(placement) == RPV_CLOSED);
    CHECK(rpv_acquire(f->anchor, &f->anchor_object, f->entries, 4, &fresh) == RPV_OK);
    rpv_destroy(fresh);
    rpv_destroy(placement);
    return 0;
}
static int control(const char *case_name, const char *base, const char *self) {
    struct fixture f;
    CHECK(provision(&f, base) == 0);
    rpv_entry *bin = &f.entries[0], *tool = &f.entries[1], *state = &f.entries[2], *store = &f.entries[3];
    if (!strcmp(case_name, "healthy")) {
        rpv_placement *placement = NULL;
        CHECK(rpv_acquire(f.anchor, &f.anchor_object, f.entries, 4, &placement) == RPV_OK);
        CHECK(rpv_validate(placement) == RPV_OK);
        rpv_close(placement);
        rpv_close(placement);
        CHECK(rpv_validate(placement) == RPV_CLOSED);
        rpv_destroy(placement);
        CHECK(attempt(&f) == RPV_OK);
    } else if (!strcmp(case_name, "invalid-path")) {
        const char *paths[] = {"", "/state", ".", "..", "state/..", "state/", "state//store", "state/./store"};
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
            state->path = paths[i];
            store->path = "state/store";
            CHECK(refused(&f, RPV_ARGUMENT));
        }
        state->path = "state";
        const char *anchor = "/";
        rpv_placement *placement = NULL;
        CHECK(rpv_acquire(anchor, &f.anchor_object, f.entries, 4, &placement) == RPV_ARGUMENT);
        CHECK(rpv_acquire("relative", &f.anchor_object, f.entries, 4, &placement) == RPV_ARGUMENT);
        CHECK(rpv_acquire(f.anchor, NULL, f.entries, 4, &placement) == RPV_ARGUMENT);
        CHECK(rpv_acquire(f.anchor, &f.anchor_object, NULL, 1, &placement) == RPV_ARGUMENT);
        CHECK(rpv_acquire(f.anchor, &f.anchor_object, f.entries, 4, NULL) == RPV_ARGUMENT);
    } else if (!strcmp(case_name, "unsafe-expectation")) {
        /* The caller cannot permit a write, special bit or file anchor by expecting it. */
        const mode_t modes[] = {0775, 0757, 04755, 02755, 01755, 010755};
        for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
            tool->object.mode = modes[i];
            CHECK(refused(&f, RPV_ARGUMENT));
        }
        tool->object.mode = 0755;
        tool->object.kind = 7;
        CHECK(refused(&f, RPV_ARGUMENT));
        tool->object.kind = RPV_FILE;
        tool->object.acl = 7;
        CHECK(refused(&f, RPV_ARGUMENT));
        tool->object.acl = RPV_ACL_NONE;
        f.anchor_object.kind = RPV_FILE;
        CHECK(refused(&f, RPV_ARGUMENT));
    } else if (!strcmp(case_name, "duplicate-entry")) {
        store->path = "bin/tool";
        store->object = tool->object;
        CHECK(refused(&f, RPV_ARGUMENT));
    } else if (!strcmp(case_name, "unlisted-parent")) {
        /* Every component needs its own expectation: no directory is walked unchecked. */
        rpv_entry only = {"state/store", expected(RPV_FILE, 0600)};
        rpv_placement *placement = NULL;
        CHECK(rpv_acquire(f.anchor, &f.anchor_object, &only, 1, &placement) == RPV_ARGUMENT);
        store->path = "bin/tool/store";
        CHECK(refused(&f, RPV_ARGUMENT));
    } else if (!strcmp(case_name, "missing-entry")) {
        CHECK(unlink(f.store) == 0);
        CHECK(refused(&f, RPV_MISSING));
    } else if (!strcmp(case_name, "file-symlink") || !strcmp(case_name, "fifo") || !strcmp(case_name, "directory-as-file")) {
        CHECK(unlink(f.store) == 0);
        if (!strcmp(case_name, "file-symlink")) CHECK(symlink(f.tool, f.store) == 0);
        else if (!strcmp(case_name, "fifo")) CHECK(mkfifo(f.store, 0600) == 0);
        else CHECK(directory(f.store, 0600) == 0);
        CHECK(refused(&f, !strcmp(case_name, "file-symlink") ? RPV_SYMLINK : RPV_TYPE));
    } else if (!strcmp(case_name, "file-as-directory")) {
        CHECK(unlink(f.tool) == 0 && rmdir(f.bin) == 0 && file(f.bin, 0755) == 0);
        CHECK(refused(&f, RPV_TYPE));
    } else if (!strcmp(case_name, "directory-symlink") || !strcmp(case_name, "anchor-symlink")) {
        const char *target = !strcmp(case_name, "directory-symlink") ? f.state : f.anchor;
        CHECK(rename(target, f.extra) == 0 && symlink(f.extra, target) == 0);
        CHECK(refused(&f, RPV_SYMLINK));
    } else if (!strcmp(case_name, "ancestor-symlink")) {
        struct fixture via = f;
        CHECK(symlink(base, f.extra) == 0 && path(via.anchor, f.extra, "anchor") == 0);
        CHECK(refused(&via, RPV_SYMLINK));
    } else if (!strcmp(case_name, "extra-link")) {
        CHECK(link(f.store, f.extra) == 0);
        CHECK(refused(&f, RPV_LINKS));
    } else if (!strcmp(case_name, "entry-alias")) {
        /* Two expected names for one file refuse at the first name, by its link count. */
        CHECK(unlink(f.store) == 0 && link(f.tool, f.store) == 0);
        store->object = tool->object;
        CHECK(refused(&f, RPV_LINKS));
    } else if (!strcmp(case_name, "owner-mismatch") || !strcmp(case_name, "anchor-owner-mismatch")) {
        (!strcmp(case_name, "owner-mismatch") ? &tool->object : &f.anchor_object)->owner = getuid() + 1;
        CHECK(refused(&f, RPV_OWNER));
    } else if (!strcmp(case_name, "group-mismatch")) {
        state->object.group = getegid() + 1;
        CHECK(refused(&f, RPV_GROUP));
    } else if (!strcmp(case_name, "group-write") || !strcmp(case_name, "other-write") ||
               !strcmp(case_name, "directory-write") || !strcmp(case_name, "anchor-write") ||
               !strcmp(case_name, "special-mode") || !strcmp(case_name, "sticky-directory")) {
        const char *target = !strcmp(case_name, "directory-write") ? f.state :
                             !strcmp(case_name, "anchor-write") ? f.anchor :
                             !strcmp(case_name, "sticky-directory") ? f.bin : f.tool;
        mode_t mode = !strcmp(case_name, "group-write") ? 0775 : !strcmp(case_name, "other-write") ? 0757 :
                      !strcmp(case_name, "directory-write") ? 0770 : !strcmp(case_name, "anchor-write") ? 0775 :
                      !strcmp(case_name, "sticky-directory") ? 01755 : 04755;
        CHECK(chmod(target, mode) == 0);
        CHECK(refused(&f, RPV_MODE));
    } else if (!strcmp(case_name, "refusal-repairs-nothing")) {
        CHECK(chmod(f.store, 0640) == 0);
        struct stat before, after;
        CHECK(lstat(f.store, &before) == 0);
        CHECK(refused(&f, RPV_MODE));
        CHECK(lstat(f.store, &after) == 0);
        CHECK(before.st_mode == after.st_mode && before.st_uid == after.st_uid && before.st_gid == after.st_gid &&
              before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec);
    } else if (!strcmp(case_name, "acl-refused-by-policy")) {
        /* A masked read-only grant still refuses when the caller expects no ACL. */
        CHECK(extended_acl(f.store, false, 6, 4, 0) == 0);
        CHECK(refused(&f, RPV_ACL_REFUSED));
    } else if (!strcmp(case_name, "read-grant-admitted")) {
        CHECK(extended_acl(f.store, false, 6, 4, 4) == 0);
        CHECK(extended_acl(f.state, true, 7, 5, 5) == 0);
        store->object.acl = RPV_ACL_NO_WRITE_GRANTS;
        store->object.mode = 0640;
        state->object.acl = RPV_ACL_NO_WRITE_GRANTS;
        CHECK(attempt(&f) == RPV_OK);
    } else if (!strcmp(case_name, "masked-write-grant") || !strcmp(case_name, "default-write-grant")) {
        bool masked = !strcmp(case_name, "masked-write-grant");
        /* The stored grant has no effective write today; the owner could widen its mask later. */
        CHECK(extended_acl(masked ? f.store : f.state, !masked, masked ? 6 : 7, masked ? 6 : 7, masked ? 4 : 7) == 0);
        (masked ? store : state)->object.acl = RPV_ACL_NO_WRITE_GRANTS;
        if (masked) store->object.mode = 0640;
        CHECK(refused(&f, RPV_ACL_REFUSED));
    } else if (!strcmp(case_name, "unmasked-write-grant")) {
        /* The mask is reported as group write, which no expectation may permit. */
        CHECK(extended_acl(f.store, false, 6, 6, 6) == 0);
        store->object.acl = RPV_ACL_NO_WRITE_GRANTS;
        store->object.mode = 0640;
        CHECK(refused(&f, RPV_MODE));
    } else if (!strcmp(case_name, "file-replacement") || !strcmp(case_name, "directory-replacement") ||
               !strcmp(case_name, "anchor-replacement") || !strcmp(case_name, "mode-change") ||
               !strcmp(case_name, "acl-change")) {
        CHECK(retired_control(case_name, &f) == 0);
    } else if (!strcmp(case_name, "replaced-during-acquire")) {
        replace_from = f.store;
        replace_saved = f.saved;
        CHECK(refused(&f, RPV_CHANGED) && replaced);
        replace_from = NULL;
        CHECK(unlink(f.store) == 0 && rename(f.saved, f.store) == 0);
        CHECK(attempt(&f) == RPV_OK);
    } else if (!strcmp(case_name, "fork-copy") || !strcmp(case_name, "close-on-exec")) {
        rpv_placement *placement = NULL;
        CHECK(rpv_acquire(f.anchor, &f.anchor_object, f.entries, 4, &placement) == RPV_OK);
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            if (!strcmp(case_name, "close-on-exec")) { execl(self, self, "--check-fds", NULL); _exit(1); }
            _exit(rpv_validate(placement) == RPV_WRONG_PROCESS && rpv_validate(placement) == RPV_RETIRED ? 0 : 1);
        }
        CHECK(wait_success(child));
        CHECK(rpv_validate(placement) == RPV_OK);
        rpv_destroy(placement);
    } else if (!strcmp(case_name, "failed-acquire-cleanup")) {
        int before = descriptor_count();
        CHECK(before >= 0 && chmod(f.store, 0640) == 0);
        for (int i = 0; i < 64; ++i) CHECK(refused(&f, RPV_MODE));
        CHECK(descriptor_count() == before);
    } else if (!strcmp(case_name, "acl-unavailable") || !strcmp(case_name, "acl-denied")) {
        acl_fault = !strcmp(case_name, "acl-denied") ? EACCES : EOPNOTSUPP;
        CHECK(refused(&f, RPV_ACL_UNAVAILABLE) && injections > 0);
        acl_fault = 0;
    } else if (!strcmp(case_name, "acl-malformed")) {
        CHECK(extended_acl(f.store, false, 6, 4, 4) == 0);
        store->object.acl = RPV_ACL_NO_WRITE_GRANTS;
        store->object.mode = 0640;
        f.anchor_object.acl = bin->object.acl = tool->object.acl = state->object.acl = RPV_ACL_NO_WRITE_GRANTS;
        acl_malformed = true;
        CHECK(refused(&f, RPV_ACL_UNAVAILABLE) && injections > 0);
        acl_malformed = false;
    } else if (!strcmp(case_name, "mount-crossing") || !strcmp(case_name, "mount-unavailable") ||
               !strcmp(case_name, "device-crossing")) {
        CHECK(set_target(f.store, !strcmp(case_name, "mount-crossing") ? TARGET_MOUNT :
                         !strcmp(case_name, "device-crossing") ? TARGET_DEVICE : TARGET_MOUNT_MISSING) == 0);
        CHECK(refused(&f, !strcmp(case_name, "mount-unavailable") ? RPV_MOUNT_UNAVAILABLE : RPV_MOUNT) && injections > 0);
        target_fault = TARGET_NONE;
    } else if (!strcmp(case_name, "directory-alias")) {
        /* Stands in for a bind mount: two expected directories reporting one identity. */
        struct stat first;
        CHECK(lstat(f.bin, &first) == 0);
        alias_device = first.st_dev;
        alias_inode = first.st_ino;
        CHECK(set_target(f.state, TARGET_ALIAS) == 0);
        CHECK(refused(&f, RPV_ALIAS) && injections > 0);
        target_fault = TARGET_NONE;
    } else return 1;
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--check-fds")) return descriptor_count() == 4 ? 0 : 1;
    if (argc != 3 || getuid() == 0 || getuid() != geteuid() || getgid() != getegid()) return 64;
    /* Fixture provisioning only; the validator never changes a process mask or object modes. */
    umask(0077);
    struct statfs filesystem;
    if (statfs(argv[2], &filesystem)) return 77;
    const char *kind = filesystem.f_type == TMPFS_MAGIC ? "tmpfs" :
        filesystem.f_type == EXT4_SUPER_MAGIC ? "ext-family" :
        filesystem.f_type == XFS_SUPER_MAGIC ? "xfs" : filesystem.f_type == BTRFS_SUPER_MAGIC ? "btrfs" : NULL;
    if (!kind) return 77;
    int before = descriptor_count();
    if (before < 0 || control(argv[1], argv[2], argv[0]) || descriptor_count() != before) return 1;
    bool injected = injections > 0;
    printf("{\"case\":\"%s\",\"passed\":true,\"fixtureOnly\":true,\"protectedInstallation\":false,\"descriptorsClosed\":true,\"fixtureFilesystem\":\"%s\"%s}\n",
           argv[1], kind, injected ? ",\"injectionObserved\":true" : "");
    return 0;
}
