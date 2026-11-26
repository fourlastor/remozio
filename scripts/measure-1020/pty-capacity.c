/* Measurement for #1020: bytes a raw PTY accepts in each direction before a nonblocking write returns EAGAIN. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <termios.h>
#include <util.h>
#include <unistd.h>
static long fill(int fd) {
    unsigned char chunk[256] = {0}; long total = 0;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    for (;;) {
        ssize_t n = write(fd, chunk, sizeof(chunk));
        if (n > 0) { total += n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return n < 0 && errno == EAGAIN ? total : -1;
    }
}
int main(void) {
    for (int pass = 0; pass < 2; ++pass) {
        int master, slave;
        if (openpty(&master, &slave, NULL, NULL, NULL)) return 1;
        struct termios a; tcgetattr(slave, &a); cfmakeraw(&a); tcsetattr(slave, TCSANOW, &a);
        if (pass == 0) printf("PTY-CAPACITY slave_to_master_output=%ld\n", fill(slave));
        else printf("PTY-CAPACITY master_to_slave_input=%ld\n", fill(master));
        close(master); close(slave);
    }
    return 0;
}
