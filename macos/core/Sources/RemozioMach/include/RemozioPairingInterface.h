#ifndef REMOZIO_PAIRING_INTERFACE_H
#define REMOZIO_PAIRING_INTERFACE_H

#include <stdint.h>

// Read-only queries for the named, current interface. Zero means success.
int remozio_pairing_ipv4_primary(const char *name, uint8_t address[4]);
int remozio_pairing_ipv6_flags(const char *name, const uint8_t address[16], uint32_t *flags);

enum {
    RemozioPairingIPv6Unusable = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0080 | 0x0200 | 0x1000
};

#endif
