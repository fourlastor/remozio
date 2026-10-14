#include "include/RemozioAuthorityBootstrap.h"
#include <servers/bootstrap.h>
#include <string.h>
#include <unistd.h>

kern_return_t remozio_authority_check_in_service(const char *name, mach_port_t *output) {
    if (!output) return KERN_INVALID_ARGUMENT;
    *output = MACH_PORT_NULL;
    if (!name || !name[0] || strnlen(name, sizeof(name_t)) >= sizeof(name_t)) return KERN_INVALID_ARGUMENT;
    if (getuid() != 0 || geteuid() != 0) return KERN_NO_ACCESS;
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t result = bootstrap_check_in(bootstrap_port, name, &port);
    if (result != KERN_SUCCESS) {
        if (MACH_PORT_VALID(port)) mach_port_destroy(mach_task_self(), port);
        return result;
    }
    if (!MACH_PORT_VALID(port)) return KERN_INVALID_RIGHT;
    *output = port;
    return KERN_SUCCESS;
}
