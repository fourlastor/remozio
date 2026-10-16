#include "include/RemozioCommandCredentials.h"
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int compare_group(const void *a, const void *b) {
    uint32_t left = *(const uint32_t *)a, right = *(const uint32_t *)b;
    return left > right ? 1 : left < right ? -1 : 0;
}
int remozio_child_account_validate(const remozio_child_spec_t *spec) {
    if (!spec || spec->format_version != 3 || !spec->account_name || !*spec->account_name ||
        strnlen(spec->account_name, REMOZIO_CHILD_MAX_ACCOUNT_NAME + 1U) > REMOZIO_CHILD_MAX_ACCOUNT_NAME ||
        spec->uid == UINT32_MAX || spec->gid == UINT32_MAX || !spec->groups ||
        !spec->group_count || spec->group_count > REMOZIO_CHILD_MAX_ACCOUNT_GROUPS) return EINVAL;
    bool primary = false;
    for (uint32_t i = 0; i < spec->group_count; ++i) {
        if (spec->groups[i] == UINT32_MAX || (i && spec->groups[i - 1] >= spec->groups[i])) return EINVAL;
        if (spec->groups[i] == spec->gid) primary = true;
    }
    if (!primary) return EINVAL;
    char storage[65536]; struct passwd account, *found = NULL;
    int error = getpwuid_r(spec->uid, &account, storage, sizeof(storage), &found);
    if (error) return error;
    if (!found || account.pw_uid != spec->uid || account.pw_gid != spec->gid ||
        !account.pw_name || strcmp(account.pw_name, spec->account_name)) return ESTALE;
    found = NULL;
    error = getpwnam_r(spec->account_name, &account, storage, sizeof(storage), &found);
    if (error) return error;
    if (!found || account.pw_uid != spec->uid || account.pw_gid != spec->gid ||
        !account.pw_name || strcmp(account.pw_name, spec->account_name)) return ESTALE;
    int values[REMOZIO_CHILD_MAX_ACCOUNT_GROUPS], count = REMOZIO_CHILD_MAX_ACCOUNT_GROUPS;
    if (getgrouplist(spec->account_name, (int)spec->gid, values, &count) < 0 ||
        count < 1 || count > (int)REMOZIO_CHILD_MAX_ACCOUNT_GROUPS) return ESTALE;
    uint32_t groups[REMOZIO_CHILD_MAX_ACCOUNT_GROUPS];
    for (int i = 0; i < count; ++i) {
        groups[i] = (uint32_t)values[i];
        if (groups[i] == UINT32_MAX) return ESTALE;
    }
    qsort(groups, (size_t)count, sizeof(*groups), compare_group);
    uint32_t distinct = 0;
    for (int i = 0; i < count; ++i) {
        if (i && groups[i] == groups[i - 1]) continue;
        if (distinct >= spec->group_count || groups[i] != spec->groups[distinct]) return ESTALE;
        distinct++;
    }
    return distinct == spec->group_count ? 0 : ESTALE;
}
int remozio_child_account_apply(const remozio_child_spec_t *spec) {
    if (getuid() != 0 || geteuid() != 0) return EPERM;
    int error = remozio_child_account_validate(spec);
    if (error) return error;
    if (initgroups(spec->account_name, (int)spec->gid) || setgid(spec->gid) || setuid(spec->uid)) return errno ? errno : EIO;
    if (getuid() != spec->uid || geteuid() != spec->uid || getgid() != spec->gid || getegid() != spec->gid) return EPERM;
    return remozio_child_account_validate(spec);
}
