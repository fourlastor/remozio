#ifndef REMOZIO_DAEMON_TERMINATION_H
#define REMOZIO_DAEMON_TERMINATION_H

#include <stdbool.h>

/* Install once during daemon startup. The native ingress owns both pipe ends until process exit. */
int remozio_daemon_termination_install(int *read_descriptor);
bool remozio_daemon_termination_requested(void);

#endif
