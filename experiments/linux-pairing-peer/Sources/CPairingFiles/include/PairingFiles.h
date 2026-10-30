#ifndef REMOZIO_PAIRING_FILES_H
#define REMOZIO_PAIRING_FILES_H

#include <sys/types.h>

/* Returns a no-follow O_PATH directory descriptor, or -1 with errno set. */
int remozio_pairing_open_directory_path(const char *path);

/* The caller must keep the descriptor open until this call returns. */
int remozio_pairing_chmod_directory_path(int fd, mode_t mode);

#endif
