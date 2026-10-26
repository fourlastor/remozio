#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int signal) { (void)signal; stopping = 1; }
static void output(const char *bytes, size_t size) {
    while (size) {
        ssize_t count = write(STDOUT_FILENO, bytes, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) _exit(70);
        bytes += count; size -= (size_t)count;
    }
}
int main(int argc, char **argv) {
    alarm(10);
    if (argc != 4 || getpgrp() != (pid_t)strtol(argv[2], NULL, 10)) return 64;
    int unrelated = (int)strtol(argv[3], NULL, 10);
    if (unrelated >= 0 && (fcntl(unrelated, F_GETFD) >= 0 || errno != EBADF)) return 65;
    struct stat lock;
    if (fstat(3, &lock) || !S_ISREG(lock.st_mode) || lock.st_size != 0) return 66;
    for (int fd = 3; fd <= 5; ++fd) {
        if ((fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDONLY || (fcntl(fd, F_GETFD) & FD_CLOEXEC)) return 67;
    }
    if (lseek(4, 0, SEEK_CUR) != 0) return 68;
    char token[8193], configuration[16], cwd[PATH_MAX];
    ssize_t token_count = read(4, token, sizeof(token));
    ssize_t config_count = read(5, configuration, sizeof(configuration));
    if (token_count <= 0 || token_count > 8192 || config_count != 3 || memcmp(configuration, "{}\n", 3)) return 69;
    if (!getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/")) return 71;
    if (getenv("TUNNEL_TOKEN") || getenv("HTTP_PROXY") || strcmp(getenv("HOME") ? getenv("HOME") : "", "/var/empty")) return 72;
    if (!strcmp(argv[1], "exit")) return 42;
    if (signal(SIGTERM, !strcmp(argv[1], "ignore") ? SIG_IGN : stop) == SIG_ERR) return 73;
    if (!strcmp(argv[1], "flood")) {
        char noise[8192]; memset(noise, 'x', sizeof(noise));
        for (int index = 0; index < 16; ++index) output(noise, sizeof(noise));
        output("\n", 1);
    }
    const char identifier[] = "{\"message\":\"Generated Connector ID: 12345678-1234-4234-9234-123456789012\"}\n";
    const char metrics[] = "{\"message\":\"Starting metrics server on 127.0.0.1:32123/metrics\"}\n";
    const char invalid[] = "{\"message\":\"Starting metrics server on 0.0.0.0:32123/metrics\"}\n";
    if (strcmp(argv[1], "silent")) {
        output(identifier, sizeof(identifier)-1);
        if (!strcmp(argv[1], "invalid")) output(invalid, sizeof(invalid)-1);
        else output(metrics, sizeof(metrics)-1);
    }
    while (!stopping) usleep(1000);
    return 0;
}
