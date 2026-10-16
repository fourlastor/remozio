#include "account-credentials-hooks.h"
#include "RemozioCommandCredentials.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
static int scenario;
static uid_t real_uid, effective_uid;
static gid_t real_gid, effective_gid;
static char trace[32];
static void step(char c) { size_t n = strlen(trace); if (n + 1 < sizeof(trace)) trace[n] = c; }
uid_t fixture_getuid(void) { return real_uid; }
uid_t fixture_geteuid(void) { return effective_uid; }
gid_t fixture_getgid(void) { return real_gid; }
gid_t fixture_getegid(void) { return effective_gid; }
static int account(struct passwd *value, char *buffer, size_t count, struct passwd **found) {
    if (count < 8) return ERANGE;
    strcpy(buffer, "fixture"); memset(value, 0, sizeof(*value));
    value->pw_name = buffer; value->pw_uid = 501; value->pw_gid = 20;
    if (real_uid == 501 && scenario == 8) value->pw_uid = 502;
    if (real_uid == 501 && scenario == 9) strcpy(buffer, "changed");
    *found = value; return 0;
}
int fixture_getpwuid_r(uid_t uid, struct passwd *value, char *buffer, size_t count, struct passwd **found) {
    step('u'); if (uid != 501 || scenario == 1) return EIO;
    return account(value, buffer, count, found);
}
int fixture_getpwnam_r(const char *name, struct passwd *value, char *buffer, size_t count, struct passwd **found) {
    step('n'); if (strcmp(name, "fixture") || scenario == 2) return EIO;
    int result = account(value, buffer, count, found);
    if (!result && scenario == 11) value->pw_uid = 502;
    return result;
}
int fixture_getgrouplist(const char *name, int gid, int *values, int *count) {
    step('g'); if (strcmp(name, "fixture") || gid != 20 || *count < 3 || scenario == 3) return -1;
    values[0] = 100; values[1] = 20; values[2] = real_uid == 501 && scenario == 10 ? 201 : 200;
    *count = 3; return 3;
}
int fixture_initgroups(const char *name, int gid) {
    step('i'); if (strcmp(name, "fixture") || gid != 20 || scenario == 4) { errno = EACCES; return -1; }
    return 0;
}
int fixture_setgid(gid_t gid) {
    step('d'); if (gid != 20 || scenario == 5) { errno = EACCES; return -1; }
    real_gid = effective_gid = gid; return 0;
}
int fixture_setuid(uid_t uid) {
    step('s'); if (uid != 501 || scenario == 6) { errno = EACCES; return -1; }
    real_uid = uid; effective_uid = scenario == 7 ? uid + 1 : uid; return 0;
}
int main(void) {
    const int errors[] = {0, EIO, EIO, ESTALE, EACCES, EACCES, EACCES, EPERM, ESTALE, ESTALE, ESTALE, ESTALE};
    const char *expected[] = {"ungidsung", "u", "un", "ung", "ungi", "ungid", "ungids", "ungids", "ungidsu", "ungidsu", "ungidsung", "un"};
    uint32_t groups[] = {20, 100, 200};
    remozio_child_spec_t spec = {.uid = 501, .gid = 20, .group_count = 3, .groups = groups,
        .format_version = 3, .account_name = "fixture"};
    for (scenario = 0; scenario < 12; ++scenario) {
        real_uid = effective_uid = 0; real_gid = effective_gid = 0; memset(trace, 0, sizeof(trace));
        int error = remozio_child_account_apply(&spec);
        if (error != errors[scenario] || strcmp(trace, expected[scenario])) {
            fprintf(stderr, "Credential fixture case %d: error %d, trace %s\n", scenario, error, trace); return 1;
        }
    }
    puts("Credential API controls: 12 passed; no real credential operations."); return 0;
}
