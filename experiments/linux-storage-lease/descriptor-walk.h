#ifndef REMOZIO_FIXTURE_DESCRIPTOR_WALK_H
#define REMOZIO_FIXTURE_DESCRIPTOR_WALK_H

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Path syntax, no-follow opens and retained identity checks shared by the fixture
 * storage lease and the placement validator. Neither ownership nor policy lives here. */
#define RDW_MAX_PATH 4096
typedef struct {
    char copy[RDW_MAX_PATH];
    char *component;
} rdw_cursor;
typedef enum { RDW_SAME, RDW_CHANGED, RDW_UNAVAILABLE } rdw_recheck_result;

/* Refuses empty, dot, dot-dot, repeated or trailing separators and oversized values.
 * An absolute path must name at least one component, so "/" alone refuses. */
bool rdw_valid_path(const char *path, bool absolute);
/* Iterates one rdw_valid_path value. rdw_next returns NULL after the last component. */
void rdw_begin(rdw_cursor *cursor, const char *path, bool absolute);
const char *rdw_next(rdw_cursor *cursor, bool *last);
int rdw_open_root(void);
int rdw_open_directory(int parent, const char *name);
/* Nonblocking, so a FIFO cannot hang the walk before the caller checks its type. */
int rdw_open_file(int parent, const char *name, int access);
/* Compares a retained descriptor and its name in the retained parent with the recorded identity.
 * The root node passes AT_FDCWD and "/". */
rdw_recheck_result rdw_recheck(int parent, const char *name, int fd, dev_t device, ino_t inode,
                               bool directory, struct stat *held);
#endif
