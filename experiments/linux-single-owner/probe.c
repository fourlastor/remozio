/*
 * Single-owner command fixture (issue #988, PR1). The owner starts it as the
 * authorized command. It appends one line to the marker file, then reports the state
 * it inherited as one JSON object of strings on stdout.
 *
 * usage: probe <normal|short|sleep> <marker>
 *   normal  append, report, exit 0
 *   short   append, exit 0 at once (a command that ends before the owner looks)
 *   sleep   append, report, then sleep (a command that is still alive at S6)
 *
 * The values are raw (hex masks, octal umask, decimal limits) for the runner only; the
 * runner publishes booleans derived from them. The exit codes avoid the owner's
 * reserved range 120-123.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void copy_field(const char *status, const char *key, char *out, size_t size) {
    const char *line = strstr(status, key);
    snprintf(out, size, "missing");
    if (!line) return;
    line += strlen(key);
    while (*line == ' ' || *line == '\t') line++;
    size_t length = strcspn(line, "\n");
    if (length == 0 || length >= size) return;
    for (size_t i = 0; i < length; i++)
        if (!strchr("0123456789abcdef \t", line[i])) return;
    memcpy(out, line, length);
    out[length] = 0;
    for (char *c = out; *c; c++)
        if (*c == '\t') *c = ' ';
}

int main(int argc, char **argv) {
    if (argc != 3) return 4;
    int marker = open(argv[2], O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (marker < 0 || write(marker, "ran\n", 4) != 4) return 5;
    close(marker);
    if (strcmp(argv[1], "short") == 0) return 0;

    char status[8192] = {0};
    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    ssize_t n = fd < 0 ? -1 : read(fd, status, sizeof status - 1);
    if (fd >= 0) close(fd);
    if (n <= 0) return 6;
    status[n] = 0;
    char prm[32], eff[32], inh[32], amb[32], bnd[32], nnp[32], uid[64], gid[64];
    copy_field(status, "\nCapPrm:", prm, sizeof prm);
    copy_field(status, "\nCapEff:", eff, sizeof eff);
    copy_field(status, "\nCapInh:", inh, sizeof inh);
    copy_field(status, "\nCapAmb:", amb, sizeof amb);
    copy_field(status, "\nCapBnd:", bnd, sizeof bnd);
    copy_field(status, "\nNoNewPrivs:", nnp, sizeof nnp);
    copy_field(status, "\nUid:", uid, sizeof uid);
    copy_field(status, "\nGid:", gid, sizeof gid);
    mode_t mask = umask(0);
    umask(mask);
    struct rlimit nofile;
    if (getrlimit(RLIMIT_NOFILE, &nofile) != 0) return 6;
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    printf("{\"capPrm\":\"%s\",\"capEff\":\"%s\",\"capInh\":\"%s\",\"capAmb\":\"%s\",\"capBnd\":\"%s\","
           "\"noNewPrivs\":\"%s\",\"uid\":\"%s\",\"gid\":\"%s\",\"umask\":\"%04o\",\"nofileSoft\":\"%llu\","
           "\"sessionLeader\":\"%s\",\"dumpable\":\"%d\"}\n",
           prm, eff, inh, amb, bnd, nnp, uid, gid, (unsigned)mask, (unsigned long long)nofile.rlim_cur,
           getsid(0) == getpid() ? "yes" : "no", dumpable);
    fflush(stdout);
    if (strcmp(argv[1], "sleep") == 0)
        for (;;) {
            struct timespec second = {1, 0};
            nanosleep(&second, NULL);
        }
    return 0;
}
