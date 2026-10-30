#ifndef REMOZIO_PAIRING_TLS_TEST_SUPPORT_H
#define REMOZIO_PAIRING_TLS_TEST_SUPPORT_H
#include <stddef.h>
#include <stdint.h>

/* Test-only OpenSSL peers and certificates. They exercise the pairing adapter from the outside: a ticket-issuing
 * server, a client that offers a saved session or an arbitrary ALPN list, and peers presenting extra chain
 * certificates. Nothing here is part of the adapter. Every handle is an opaque OpenSSL pointer. */

typedef struct {
    const uint8_t *cert;       /* leaf DER; required */
    size_t cert_length;
    const uint8_t *key;        /* leaf private key DER; required */
    size_t key_length;
    const uint8_t *extra;      /* optional additional chain certificate DER, sent after the leaf */
    size_t extra_length;
    const uint8_t *alpn_wire;  /* client: offered protocol list in wire format; NULL offers the pairing ALPN */
    size_t alpn_length;
    int issue_tickets;         /* server: send two TLS 1.3 tickets and keep a session cache */
} RemozioTestPeerOptions;

/* P-256 leaf signed by a separate P-256 key. same_name gives the issuer the leaf's own subject, so the leaf is
 * self-issued but not self-signed. Buffers are freed with remozio_test_free. Returns 1 on success. */
int remozio_test_make_issued_identity(int same_name, uint8_t **cert_der, size_t *cert_length, uint8_t **key_der,
                                      size_t *key_length);
/* The 65-byte uncompressed public point of a DER private key, read independently of any handshake. */
int remozio_test_public_point(const uint8_t *key_der, size_t key_length, uint8_t point[65]);
void remozio_test_free(void *pointer);

void *remozio_test_server_context_new(const RemozioTestPeerOptions *options);
void *remozio_test_client_context_new(const RemozioTestPeerOptions *options);
void remozio_test_context_free(void *context);
/* Tickets this client context has received. */
int remozio_test_tickets_received(void *context);

/* Blocking, bounded by 5 s socket timeouts; both take ownership of fd and close it.
 * serve_once: accept, write one byte, then read until the peer closes. Returns 1 if the handshake completed.
 * connect_once: connect offering session (or none), read one byte, report reuse and the latest session (free it
 * with remozio_test_session_free). Returns 1 if the handshake completed and the byte arrived. */
int remozio_test_serve_once(void *context, int fd);
int remozio_test_connect_once(void *context, int fd, void *session, int *reused, void **latest_session);
void remozio_test_session_free(void *session);

#endif
