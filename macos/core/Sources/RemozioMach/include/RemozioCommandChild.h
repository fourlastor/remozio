#ifndef REMOZIO_COMMAND_CHILD_H
#define REMOZIO_COMMAND_CHILD_H
#include <stddef.h>
#include <stdint.h>
#define REMOZIO_CHILD_MAX_BYTES (8U * 1024U * 1024U)
#define REMOZIO_CHILD_MAX_ENTRIES 262144U
#define REMOZIO_CHILD_HEADER_BYTES 40U
#define REMOZIO_CHILD_FRAME_V1 0x524d4331U
#define REMOZIO_CHILD_FRAME_V2 0x524d4332U
#define REMOZIO_CHILD_FRAME_V3 0x524d4333U
#define REMOZIO_CHILD_MAX_ACCOUNT_GROUPS 1024U
#define REMOZIO_CHILD_MAX_ACCOUNT_NAME 65535U
/* This decoder only owns data. It grants no execution permission. */
typedef struct {
    uint32_t uid, gid, group_count, argument_count, environment_count;
    uint32_t preparation_milliseconds, file_creation_mask, io_mode;
    /* Format 2 binds a private controlling terminal separately from the three streams.
     * Bits 0, 1 and 2 select stdin, stdout and stderr on that terminal. */
    uint32_t format_version, stdio_pty_mask;
    uint32_t *groups;
    /* Format 3 binds native account initialization to the complete captured account identity. */
    char *account_name;
    char *executable;
    char **arguments;
    char **environment;
    char *storage;
    size_t storage_count;
} remozio_child_spec_t;
/* Output must be fresh or closed. Close wipes and frees the decoded string storage. */
int remozio_child_spec_decode(const void *bytes, size_t count, remozio_child_spec_t *output);
void remozio_child_spec_close(remozio_child_spec_t *spec);
/* Output has room for 16 entries. The approved primary GID occupies the first slot. */
int remozio_child_spec_groups(const remozio_child_spec_t *spec, uint32_t *groups, uint32_t *count);
/* Checks only descriptor layout. No input is read and no flags, attributes or
 * foreground group change. The caller must separately verify authority and code.
 * Direct streams must not alias the supplied private terminal. */
int remozio_child_spec_validate_stdio(const remozio_child_spec_t *spec, int terminal, const int streams[3]);
#endif
