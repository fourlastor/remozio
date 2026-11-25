#ifndef REMOZIO_COMMAND_PTY_H
#define REMOZIO_COMMAND_PTY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <termios.h>

#define REMOZIO_PTY_MAX_CHUNK 65536
typedef struct remozio_command_pty remozio_command_pty_t;
/* Creates only a private terminal. No caller, child, execution or control permission is established. */
int remozio_command_pty_create(const struct termios * _Nullable attributes, const struct winsize * _Nullable size,
    remozio_command_pty_t * _Nullable * _Nonnull output);
/* For a checked non-Root target, set ownership and 0600 on the fresh slave before returning it. */
int remozio_command_pty_create_for_target(const struct termios * _Nullable attributes, const struct winsize * _Nullable size,
    uid_t uid, gid_t gid, remozio_command_pty_t * _Nullable * _Nonnull output);
/* Borrow the slave only for spawning the bound child; never close or retain this descriptor. */
int remozio_command_pty_borrow_slave(remozio_command_pty_t * _Nonnull pty, int * _Nonnull descriptor);
/* Own a separate description of this private slave. Access tags are read 0,
 * write 1, read/write 2. Semantic bits are append 1, nonblocking 2, async 4,
 * sync 8. Recheck the opened object and change only its independent flags.
 * The caller closes the returned descriptor after the bounded spawn callback. */
int remozio_command_pty_copy_stream(remozio_command_pty_t * _Nonnull pty, uint32_t access,
    uint32_t semantic_flags, int * _Nonnull output);
/* Close the owner's slave after spawning. The child owns its separate copies. */
void remozio_command_pty_seal_slave(remozio_command_pty_t * _Nonnull pty);
/* Nonblocking bounded reads. EOF refers only to the stream and never establishes child exit or execution. */
int remozio_command_pty_read(remozio_command_pty_t * _Nonnull pty, void * _Nonnull bytes, size_t capacity,
    size_t * _Nonnull count, bool * _Nonnull eof);
/* Nonblocking bounded writes. A short write or zero count retains the caller's unsent bytes. */
int remozio_command_pty_write(remozio_command_pty_t * _Nonnull pty, const void * _Nullable bytes, size_t count,
    size_t * _Nonnull written);
int remozio_command_pty_resize(remozio_command_pty_t * _Nonnull pty, const struct winsize * _Nonnull size);
/* Only the authorized owner may signal its owned terminal's current foreground group. Normal terminal flushing applies. */
int remozio_command_pty_signal(remozio_command_pty_t * _Nonnull pty, int number);
/* Read only this private terminal's foreground group. Zero means unavailable. This grants no process ownership. */
int remozio_command_pty_foreground_group(remozio_command_pty_t * _Nonnull pty, int * _Nonnull group);
/* Returns two current EOF characters for canonical mode, or zero bytes for raw or disabled EOF. Changes no attributes. */
int remozio_command_pty_eof_sequence(remozio_command_pty_t * _Nonnull pty, unsigned char * _Nonnull bytes, size_t * _Nonnull count);
/* Closing the master can hang up a live slave. Retain the owner through child cleanup and output drain. */
void remozio_command_pty_close(remozio_command_pty_t * _Nullable pty);
#endif
