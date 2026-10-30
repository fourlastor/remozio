#include <errno.h>
#include <termios.h>
#include <unistd.h>
static int output(const unsigned char *bytes, size_t count) {
    size_t used = 0;
    while (used < count) {
        ssize_t written = write(1, bytes + used, count - used);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return 1;
        used += (size_t)written;
    }
    return 0;
}
int main(void) {
    if (!isatty(0) || !isatty(1) || !isatty(2)) return 40;
    struct termios attributes;
    if (tcgetattr(0, &attributes) || (attributes.c_lflag & ICANON)) return 41;
    unsigned char bytes[4096]; size_t used = 0;
    while (used < 131072) {
        size_t remaining = 131072 - used;
        ssize_t count = read(0, bytes, remaining < sizeof(bytes) ? remaining : sizeof(bytes));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 42;
        for (ssize_t i = 0; i < count; ++i) if (bytes[i] != (unsigned char)((used + (size_t)i) % 251)) return 43;
        if (output(bytes, (size_t)count)) return 44;
        used += (size_t)count;
    }
    used = 0;
    while (used < 262144) {
        for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = (unsigned char)(((used + i) * 17 + 3) % 251);
        if (output(bytes, sizeof(bytes))) return 45;
        used += sizeof(bytes);
    }
    return 7;
}
