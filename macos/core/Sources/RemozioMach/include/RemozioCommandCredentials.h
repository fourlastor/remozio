#ifndef REMOZIO_COMMAND_CREDENTIALS_H
#define REMOZIO_COMMAND_CREDENTIALS_H
#include "RemozioCommandChild.h"
/* Checks the current directory account against the full captured identity. Changes no credentials. */
int remozio_child_account_validate(const remozio_child_spec_t *spec);
/* Root-only, disposable child operation. Failure must terminate the child without executing a target. */
int remozio_child_account_apply(const remozio_child_spec_t *spec);
#endif
