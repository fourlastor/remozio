#include "RemozioPairingInterface.h"
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#if __has_include(<netinet6/in6_var.h>)
#include <netinet6/in6_var.h>
#endif
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <unistd.h>

#if defined(SIOCGIFAFLAG_IN6) && defined(IN6_IFF_OPTIMISTIC) && defined(IN6_IFF_CLAT46)
#define REMOZIO_HAS_IPV6_FLAGS 1
_Static_assert(RemozioPairingIPv6Unusable == (IN6_IFF_ANYCAST | IN6_IFF_TENTATIVE | IN6_IFF_DUPLICATED |
    IN6_IFF_DETACHED | IN6_IFF_DEPRECATED | IN6_IFF_TEMPORARY | IN6_IFF_OPTIMISTIC | IN6_IFF_CLAT46), "IPv6 flags changed");
#endif

int remozio_pairing_ipv4_primary(const char *name, uint8_t address[4]) {
    struct ifreq request = {0};
    if (strlcpy(request.ifr_name, name, sizeof(request.ifr_name)) >= sizeof(request.ifr_name)) return EINVAL;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return errno;
    int result = ioctl(fd, SIOCGIFADDR, &request) == 0 ? 0 : errno;
    close(fd);
    if (result != 0) return result;
    if (request.ifr_addr.sa_family != AF_INET) return EADDRNOTAVAIL;
    struct sockaddr_in primary;
    memcpy(&primary, &request.ifr_addr, sizeof(primary));
    memcpy(address, &primary.sin_addr, 4);
    return 0;
}

int remozio_pairing_ipv6_flags(const char *name, const uint8_t address[16], uint32_t *flags) {
#ifdef REMOZIO_HAS_IPV6_FLAGS
    struct in6_ifreq request = {0};
    if (strlcpy(request.ifr_name, name, sizeof(request.ifr_name)) >= sizeof(request.ifr_name)) return EINVAL;
    request.ifr_ifru.ifru_addr.sin6_len = sizeof(struct sockaddr_in6);
    request.ifr_ifru.ifru_addr.sin6_family = AF_INET6;
    memcpy(&request.ifr_ifru.ifru_addr.sin6_addr, address, 16);
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd == -1) return errno;
    int result = ioctl(fd, SIOCGIFAFLAG_IN6, &request) == 0 ? 0 : errno;
    close(fd);
    if (result == 0) *flags = (uint32_t)request.ifr_ifru.ifru_flags6;
    return result;
#else
#warning "Scoped LAN pairing IPv6 requires the SDK address flags and ioctl."
    (void)name;
    (void)address;
    (void)flags;
    return ENOTSUP;
#endif
}
