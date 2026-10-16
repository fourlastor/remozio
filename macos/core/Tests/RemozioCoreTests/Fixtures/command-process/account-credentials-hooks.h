#ifndef REMOZIO_ACCOUNT_CREDENTIALS_HOOKS_H
#define REMOZIO_ACCOUNT_CREDENTIALS_HOOKS_H
#ifndef REMOZIO_ACCOUNT_CREDENTIALS_FIXTURE
#error "Credential API substitution is only available in a disposable fixture."
#endif
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
uid_t fixture_getuid(void);
uid_t fixture_geteuid(void);
gid_t fixture_getgid(void);
gid_t fixture_getegid(void);
int fixture_getpwuid_r(uid_t, struct passwd *, char *, size_t, struct passwd **);
int fixture_getpwnam_r(const char *, struct passwd *, char *, size_t, struct passwd **);
int fixture_getgrouplist(const char *, int, int *, int *);
int fixture_initgroups(const char *, int);
int fixture_setgid(gid_t);
int fixture_setuid(uid_t);
#define getuid fixture_getuid
#define geteuid fixture_geteuid
#define getgid fixture_getgid
#define getegid fixture_getegid
#define getpwuid_r fixture_getpwuid_r
#define getpwnam_r fixture_getpwnam_r
#define getgrouplist fixture_getgrouplist
#define initgroups fixture_initgroups
#define setgid fixture_setgid
#define setuid fixture_setuid
#endif
