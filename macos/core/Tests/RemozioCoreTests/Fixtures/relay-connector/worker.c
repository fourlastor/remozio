#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
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
static int serve_readiness(const char *mode) {
    int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server < 0) return 74;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_len = sizeof(address); address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) || listen(server, 2)) { close(server); return 75; }
    socklen_t size = sizeof(address);
    if (getsockname(server, (struct sockaddr *)&address, &size)) { close(server); return 76; }
    const char identifier[] = "{\"message\":\"Generated Connector ID: 12345678-1234-4234-9234-123456789012\"}\n";
    char diagnostic[160];
    int length = snprintf(diagnostic, sizeof(diagnostic), "{\"message\":\"Starting metrics server on 127.0.0.1:%u/metrics\"}\n", (unsigned)ntohs(address.sin_port));
    if (length <= 0 || (size_t)length >= sizeof(diagnostic)) { close(server); return 77; }
    output(identifier, sizeof(identifier)-1); output(diagnostic, (size_t)length);
    unsigned requests = 0;
    while (!stopping) {
        struct pollfd readiness = { .fd = server, .events = POLLIN, .revents = 0 };
        int available = poll(&readiness, 1, 25);
        if (available < 0 && errno == EINTR) continue;
        if (available < 0) { close(server); return 78; }
        if (!available) continue;
        int client = accept(server, NULL, NULL);
        if (client < 0 && errno == EINTR) continue;
        if (client < 0) { close(server); return 79; }
        const int no_pipe = 1;
        struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
        if (setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &no_pipe, sizeof(no_pipe)) ||
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) { close(client); close(server); return 80; }
        char request[4097]; size_t received = 0;
        request[0] = 0;
        while (received < sizeof(request)-1 && !strstr(request, "\r\n\r\n")) {
            ssize_t count = read(client, request + received, sizeof(request)-1-received);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            received += (size_t)count; request[received] = 0;
        }
        if (received < 11 || memcmp(request, "GET /ready ", 11) || !strstr(request, "\r\n\r\n")) { close(client); continue; }
        ++requests;
        if (!strncmp(mode, "http-stall@", 11)) {
            const char *path = mode + 11;
            if (*path != '/') { close(client); close(server); return 82; }
            int marker = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (marker < 0) { close(client); close(server); return 83; }
            const unsigned char accepted = 1;
            ssize_t written = write(marker, &accepted, 1); close(marker);
            if (written != 1) { close(client); close(server); return 84; }
            while (!stopping) usleep(1000);
            close(client); break;
        }
        int connected = strcmp(mode, "http-recover") || requests > 2;
        int status = connected ? 200 : 503;
        const char *identity = !strcmp(mode, "http-wrong-identity") ?
            "12345678-1234-4234-9234-123456789013" : "12345678-1234-4234-9234-123456789012";
        char body[256], reply[512];
        int body_length = snprintf(body, sizeof(body), "{\"status\":%d,\"readyConnections\":%d,\"connectorId\":\"%s\"}", status, connected, identity);
        int reply_length = snprintf(reply, sizeof(reply), "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
            status, connected ? "OK" : "Service Unavailable", body_length, body);
        if (body_length <= 0 || (size_t)body_length >= sizeof(body) || reply_length <= 0 || (size_t)reply_length >= sizeof(reply)) {
            close(client); close(server); return 81;
        }
        size_t sent = 0;
        while (sent < (size_t)reply_length) {
            ssize_t count = write(client, reply + sent, (size_t)reply_length - sent);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            sent += (size_t)count;
        }
        close(client);
    }
    close(server); return 0;
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
    if (!strncmp(argv[1], "http-", 5)) return serve_readiness(argv[1]);
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
