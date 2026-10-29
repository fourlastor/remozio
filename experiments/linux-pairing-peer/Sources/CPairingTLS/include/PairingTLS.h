#ifndef REMOZIO_PAIRING_TLS_H
#define REMOZIO_PAIRING_TLS_H
#include <stddef.h>
#include <stdint.h>

#define REMOZIO_TLS_ALPN "remozio-pairing/1"
#define REMOZIO_TLS_POINT_LENGTH 65
#define REMOZIO_TLS_DEFAULT_HANDSHAKE_MS 15000
#define REMOZIO_TLS_MAX_HANDSHAKE_MS 60000

typedef enum {
    REMOZIO_TLS_OK = 0,
    REMOZIO_TLS_TIMEOUT = 1,
    REMOZIO_TLS_CANCELLED = 2,
    REMOZIO_TLS_HANDSHAKE_FAILED = 3,
    REMOZIO_TLS_PEER_CERTIFICATE = 4,
    REMOZIO_TLS_CLOSED = 5,
    REMOZIO_TLS_IO = 6,
    REMOZIO_TLS_INVALID_ARGUMENT = 7,
    REMOZIO_TLS_INTERNAL = 8,
    REMOZIO_TLS_PROTOCOL = 9 /* TLS failure on an established connection */
} RemozioTLSStatus;

typedef struct RemozioTLSContext RemozioTLSContext;
typedef struct RemozioTLSConnection RemozioTLSConnection;

typedef struct {
    int min_version;   /* 0 = TLS 1.3 */
    int max_version;   /* 0 = TLS 1.3; test clients may pick TLS 1.2 (0x0303) */
    const char *alpn;  /* NULL = offer REMOZIO_TLS_ALPN */
    int offer_no_alpn;
} RemozioTLSClientOptions;

/* Milliseconds on CLOCK_BOOTTIME, which keeps counting across suspend. */
int64_t remozio_tls_now_ms(void);

/* Self-signed P-256 leaf: CN "Remozio transport", critical CA:FALSE, digitalSignature, EKU serverAuth+clientAuth.
 * not_before is rounded up and not_after rounded down by the caller (whole seconds). curve is "P-256" in production;
 * tests pass another name to build a wrong-curve identity. Output buffers are freed with remozio_tls_free. */
RemozioTLSStatus remozio_tls_make_identity(const char *curve, int64_t not_before, int64_t not_after,
                                           uint8_t **cert_der, size_t *cert_length,
                                           uint8_t **key_der, size_t *key_length);
void remozio_tls_free(void *pointer);

/* Server context: TLS 1.3 only, exactly the pairing ALPN, no tickets, no early data, no session cache,
 * mandatory client certificate. */
RemozioTLSContext *remozio_tls_server_context_new(const uint8_t *cert_der, size_t cert_length,
                                                  const uint8_t *key_der, size_t key_length);
RemozioTLSContext *remozio_tls_client_context_new(const RemozioTLSClientOptions *options,
                                                  const uint8_t *cert_der, size_t cert_length,
                                                  const uint8_t *key_der, size_t key_length);
/* A context must outlive every connection made from it. */
void remozio_tls_context_free(RemozioTLSContext *context);
/* Tickets a client context received (tests assert zero). */
int remozio_tls_context_tickets_received(const RemozioTLSContext *context);

/* Takes ownership of fd on success and on failure; fd must be a stream socket (sends use MSG_NOSIGNAL, and the
 * process's SIGPIPE disposition is never changed). cancel_fd is polled for readability (-1 = none).
 * deadline_ms is absolute (remozio_tls_now_ms scale). On success peer_point holds the peer leaf's 65-byte
 * uncompressed P-256 point. */
RemozioTLSStatus remozio_tls_accept(RemozioTLSContext *context, int fd, int cancel_fd, int64_t deadline_ms,
                                    RemozioTLSConnection **connection, uint8_t peer_point[REMOZIO_TLS_POINT_LENGTH]);
RemozioTLSStatus remozio_tls_connect(RemozioTLSContext *context, int fd, int cancel_fd, int64_t deadline_ms,
                                     RemozioTLSConnection **connection,
                                     uint8_t peer_point[REMOZIO_TLS_POINT_LENGTH]);

/* Reads at least one byte (up to capacity) or reports why not. */
RemozioTLSStatus remozio_tls_read(RemozioTLSConnection *connection, uint8_t *buffer, size_t capacity,
                                  int cancel_fd, int64_t deadline_ms, size_t *count);
/* Writes every byte or reports why not. After any error other than success the connection is dead: a partial
 * write is not reported, so the caller must close it and never retry on the same connection. */
RemozioTLSStatus remozio_tls_write(RemozioTLSConnection *connection, const uint8_t *buffer, size_t length,
                                   int cancel_fd, int64_t deadline_ms);

/* Negotiated settings, for tests that assert them instead of library defaults. */
int remozio_tls_negotiated_version(const RemozioTLSConnection *connection);
const char *remozio_tls_negotiated_alpn(const RemozioTLSConnection *connection);
int remozio_tls_session_was_reused(const RemozioTLSConnection *connection);
void remozio_tls_connection_close(RemozioTLSConnection *connection); /* shuts down, closes the fd, frees */

#endif
