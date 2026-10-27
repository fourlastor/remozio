#ifndef COMPOSED_SUPPORT_H
#define COMPOSED_SUPPORT_H

#include <stddef.h>
#include <sys/types.h>

/* Waits up to timeout_ms, then receives one SEQPACKET frame with only SCM_RIGHTS descriptors
 * (close-on-exec). Any truncation, foreign ancillary data or more than `capacity` descriptors
 * closes everything received and returns -1. Returns the frame length otherwise. */
ssize_t ccs_receive(int socket, void *buffer, size_t length, int *descriptors, int capacity, int *count,
                    int timeout_ms);

/* Sends one complete frame without descriptors; returns 0 on success. */
int ccs_send(int socket, const void *buffer, size_t length);

/* Spawns `path` with exactly the three given descriptors as stdin/stdout/stderr, changing to the
 * retained directory descriptor first, with default SIGPIPE and an empty signal mask.
 * Returns 0 or an errno value. */
int ccs_spawn(pid_t *pid, const char *path, char *const argv[], char *const envp[], const int streams[3],
              int directory);

/* 1 when the descriptor's file has no security.capability attribute (ENODATA),
 * 0 when one is present, -1 for any other error (denied or unknown refuses). */
int ccs_file_capability_absent(int descriptor);

#endif
