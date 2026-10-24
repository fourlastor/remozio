#ifndef REMOZIO_FIXTURE_STORAGE_LEASE_H
#define REMOZIO_FIXTURE_STORAGE_LEASE_H

#include <sys/types.h>

/* Fixture mechanics only. No production owner, installation or journal format. */
typedef struct rsl_lease rsl_lease;
typedef enum {
    RSL_OK, RSL_ARGUMENT, RSL_ORDINARY_OWNER_REQUIRED, RSL_SYSTEM,
    RSL_METADATA, RSL_FILESYSTEM_UNAVAILABLE, RSL_ACL_UNAVAILABLE,
    RSL_ACL_PRESENT, RSL_BUSY, RSL_CHANGED, RSL_WRONG_PROCESS,
    RSL_RETIRED, RSL_CLOSED
} rsl_result;
typedef struct { dev_t device; ino_t inode; } rsl_identity;

/* Opens existing objects only: private anchor / relative directory / {writer.lock,fixture.data}.
 * The explicit ordinary-user anchor is the trust starting point, not a protected installation.
 * All traversal components are opened without following symlinks and retained for revalidation.
 * Serialize calls. No descriptors may escape this owner. Failed acquisition leaves *out NULL. */
rsl_result rsl_acquire(const char *anchor, const char *relative, uid_t fixture_owner, rsl_lease **out);
/* A failed live validation permanently retires this instance, retaining locks until close/destroy. */
rsl_result rsl_validate(rsl_lease *lease);
rsl_result rsl_data_identity(rsl_lease *lease, rsl_identity *out);
/* Idempotent. Never deletes, replaces, chmods or unlocks another process's objects. */
void rsl_close(rsl_lease *lease);
void rsl_destroy(rsl_lease *lease);
#endif
