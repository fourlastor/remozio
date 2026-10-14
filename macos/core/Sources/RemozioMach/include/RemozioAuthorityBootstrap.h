#ifndef REMOZIO_AUTHORITY_BOOTSTRAP_H
#define REMOZIO_AUTHORITY_BOOTSTRAP_H
#include <mach/mach.h>

/* Root only. Success transfers one registered receive right, never an anonymous right.
   The owner must first validate current protected code, configuration, inventory and signed job metadata.
   Kernel check-in alone is not an installation proof. Failure returns a null output. */
kern_return_t remozio_authority_check_in_service(const char * _Nonnull name, mach_port_t * _Nonnull output);
#endif
