/* Disposable same-user credential seam. The product launcher still parses, validates and executes its frame. */
#ifndef REMOZIO_OWNED_LIVE_FIXTURE
#error "This credential seam requires an explicit disposable fixture build."
#endif
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "RemozioCommandCredentials.h"
static uid_t fixture_getuid(void) { return 0; }
static uid_t fixture_geteuid(void) { return 0; }
static int fixture_account_apply(const remozio_child_spec_t *spec) {
    return spec && spec->format_version == 3 && spec->uid == getuid() && spec->gid == getgid() &&
        spec->group_count == 1 && spec->groups && spec->groups[0] == getgid() &&
        spec->account_name && !strcmp(spec->account_name, "fixture") ? 0 : EPERM;
}
#define getuid fixture_getuid
#define geteuid fixture_geteuid
#define remozio_child_account_apply fixture_account_apply
#include "../../macos/app/CommandChild/ChildMain.c"
