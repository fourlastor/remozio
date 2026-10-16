#ifndef REMOZIO_PRODUCTION_CHILD_RESULT_H
#define REMOZIO_PRODUCTION_CHILD_RESULT_H
#include <stdint.h>
#define FIXED_RESULT_MAGIC 0x52504331U
typedef struct { uint32_t magic, identity, input, private_fds_closed, extra_group_access; } fixed_result_t;
#endif
