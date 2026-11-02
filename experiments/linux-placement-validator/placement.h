#ifndef REMOZIO_FIXTURE_PLACEMENT_VALIDATOR_H
#define REMOZIO_FIXTURE_PLACEMENT_VALIDATOR_H

#include <stddef.h>
#include <sys/types.h>

/* Fixture mechanics only. Every expectation comes from the caller. This component
 * selects no production name, UID, filesystem policy or service layout. */
typedef struct rpv_placement rpv_placement;
typedef enum {
    RPV_OK, RPV_ARGUMENT, RPV_ORDINARY_USER_REQUIRED, RPV_SYSTEM, RPV_MISSING, RPV_SYMLINK,
    RPV_TYPE, RPV_OWNER, RPV_GROUP, RPV_MODE, RPV_LINKS, RPV_ALIAS, RPV_ACL_REFUSED,
    RPV_ACL_UNAVAILABLE, RPV_MOUNT, RPV_MOUNT_UNAVAILABLE, RPV_CHANGED, RPV_WRONG_PROCESS,
    RPV_RETIRED, RPV_CLOSED
} rpv_result;
typedef enum { RPV_DIRECTORY, RPV_FILE } rpv_kind;
/* NONE refuses any stored ACL, even a masked one. NO_WRITE_GRANTS admits read and
 * execute grants and refuses a write grant to anyone but the owning user. */
typedef enum { RPV_ACL_NONE, RPV_ACL_NO_WRITE_GRANTS } rpv_acl_policy;
typedef struct {
    rpv_kind kind;
    uid_t owner;
    gid_t group;
    mode_t mode;
    rpv_acl_policy acl;
} rpv_object;
/* path is relative to the anchor. Its parent must be the anchor or an earlier directory entry. */
typedef struct {
    const char *path;
    rpv_object object;
} rpv_entry;

/* Reads only. Opens existing objects without following symlinks and retains them for
 * revalidation. Components before the anchor have no ownership policy, and "/" is not
 * an accepted anchor. An expected mode may hold no special, group-write or other-write
 * bit, and every file must have exactly one link. A mismatch refuses; nothing is repaired.
 * Serialize calls. No descriptors may escape this owner. Failed acquisition leaves *out NULL. */
rpv_result rpv_acquire(const char *anchor, const rpv_object *anchor_object,
                       const rpv_entry *entries, size_t count, rpv_placement **out);
/* A failed live validation permanently retires this instance. */
rpv_result rpv_validate(rpv_placement *placement);
void rpv_close(rpv_placement *placement);
void rpv_destroy(rpv_placement *placement);
#endif
