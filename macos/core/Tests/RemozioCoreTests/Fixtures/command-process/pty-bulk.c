#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
/* Measurement build for #1020: argv[1] input bytes, argv[2] output bytes, argv[3] stats file. */
static unsigned long slow_writes, writes;
static long long now_us(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
static int output(const unsigned char *bytes, size_t count) {
    size_t used = 0;
    while (used < count) {
        long long start = now_us();
        ssize_t written = write(1, bytes + used, count - used);
        if (now_us() - start > 1000) ++slow_writes;
        ++writes;
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return 1;
        used += (size_t)written;
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 4) return 46;
    size_t input_total = strtoul(argv[1], NULL, 10), output_total = strtoul(argv[2], NULL, 10);
    if (!isatty(0) || !isatty(1) || !isatty(2)) return 40;
    struct termios attributes;
    if (tcgetattr(0, &attributes) || (attributes.c_lflag & ICANON)) return 41;
    unsigned char bytes[4096]; size_t used = 0;
    long long started = now_us();
    while (used < input_total) {
        size_t remaining = input_total - used;
        ssize_t count = read(0, bytes, remaining < sizeof(bytes) ? remaining : sizeof(bytes));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 42;
        for (ssize_t i = 0; i < count; ++i) if (bytes[i] != (unsigned char)((used + (size_t)i) % 251)) return 43;
        if (output(bytes, (size_t)count)) return 44;
        used += (size_t)count;
    }
    unsigned long echo_slow = slow_writes, echo_writes = writes;
    long long echoed = now_us();
    used = 0;
    while (used < output_total) {
        for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = (unsigned char)(((used + i) * 17 + 3) % 251);
        if (output(bytes, sizeof(bytes))) return 45;
        used += sizeof(bytes);
    }
    FILE *stats = fopen(argv[3], "w");
    if (stats) {
        fprintf(stats, "echo_ms=%lld echo_writes=%lu echo_slow_writes=%lu bulk_ms=%lld bulk_writes=%lu bulk_slow_writes=%lu\n",
            (echoed - started) / 1000, echo_writes, echo_slow, (now_us() - echoed) / 1000,
            writes - echo_writes, slow_writes - echo_slow);
        fclose(stats);
    }
    return 7;
}
