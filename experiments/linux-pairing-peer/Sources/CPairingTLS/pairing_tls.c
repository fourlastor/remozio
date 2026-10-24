#define _GNU_SOURCE
#include "PairingTLS.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct RemozioTLSContext {
    SSL_CTX *ctx;
    int is_server;
    int tickets_received;
};

struct RemozioTLSConnection {
    SSL *ssl;
    int fd;
};

static const unsigned char alpn_wire[] = {17, 'r', 'e', 'm', 'o', 'z', 'i', 'o', '-', 'p', 'a', 'i', 'r', 'i', 'n', 'g', '/', '1'};

int64_t remozio_tls_now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0) return 0;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

void remozio_tls_free(void *pointer) { OPENSSL_free(pointer); }

/* Waits for the socket, the deadline or the cancel descriptor, whichever comes first. */
static RemozioTLSStatus wait_for(int fd, short events, int cancel_fd, int64_t deadline_ms) {
    for (;;) {
        int64_t remaining = deadline_ms - remozio_tls_now_ms();
        if (remaining <= 0) return REMOZIO_TLS_TIMEOUT;
        struct pollfd fds[2] = {{.fd = fd, .events = events}, {.fd = cancel_fd, .events = POLLIN}};
        int ready = poll(fds, cancel_fd >= 0 ? 2 : 1, remaining > INT_MAX ? INT_MAX : (int)remaining);
        if (ready < 0) {
            if (errno == EINTR) continue;
            return REMOZIO_TLS_IO;
        }
        if (ready == 0) continue;
        if (cancel_fd >= 0 && (fds[1].revents & POLLNVAL)) return REMOZIO_TLS_INVALID_ARGUMENT;
        if (cancel_fd >= 0 && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) return REMOZIO_TLS_CANCELLED;
        if (fds[0].revents & POLLNVAL) return REMOZIO_TLS_IO;
        if (fds[0].revents & (events | POLLHUP | POLLERR)) return REMOZIO_TLS_OK;
    }
}

/* Runs one nonblocking OpenSSL call to completion. operation returns the SSL_* result and sets *ret. */
typedef int (*SSLOperation)(SSL *ssl, void *argument, size_t *transferred);

static RemozioTLSStatus drive(SSL *ssl, int fd, int cancel_fd, int64_t deadline_ms, SSLOperation operation,
                              void *argument, size_t *transferred) {
    for (;;) {
        /* Honour a passed deadline or a signalled cancel even when OpenSSL never needs to wait. */
        if (deadline_ms - remozio_tls_now_ms() <= 0) return REMOZIO_TLS_TIMEOUT;
        if (cancel_fd >= 0) {
            struct pollfd cancel = {.fd = cancel_fd, .events = POLLIN};
            if (poll(&cancel, 1, 0) > 0) return (cancel.revents & POLLNVAL) ? REMOZIO_TLS_INVALID_ARGUMENT : REMOZIO_TLS_CANCELLED;
        }
        ERR_clear_error();
        errno = 0;
        int result = operation(ssl, argument, transferred);
        if (result > 0) return REMOZIO_TLS_OK;
        switch (SSL_get_error(ssl, result)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE: {
            short events = SSL_want_write(ssl) ? POLLOUT : POLLIN;
            RemozioTLSStatus waited = wait_for(fd, events, cancel_fd, deadline_ms);
            if (waited != REMOZIO_TLS_OK) return waited;
            break;
        }
        case SSL_ERROR_ZERO_RETURN: return REMOZIO_TLS_CLOSED;
        case SSL_ERROR_SYSCALL: return errno == 0 || errno == ECONNRESET || errno == EPIPE ? REMOZIO_TLS_CLOSED : REMOZIO_TLS_IO;
        case SSL_ERROR_SSL: {
            /* A peer that closes the transport without close_notify is a close, not a TLS failure. */
            unsigned long error = ERR_peek_last_error();
            unsigned long reason = ERR_GET_REASON(error);
            int reset = ERR_SYSTEM_ERROR(error) && (reason == EPIPE || reason == ECONNRESET);
            if (reset || (!ERR_SYSTEM_ERROR(error) && reason == SSL_R_UNEXPECTED_EOF_WHILE_READING)) return REMOZIO_TLS_CLOSED;
            return SSL_is_init_finished(ssl) ? REMOZIO_TLS_PROTOCOL : REMOZIO_TLS_HANDSHAKE_FAILED;
        }
        default: return REMOZIO_TLS_INTERNAL;
        }
    }
}

static int do_accept(SSL *ssl, void *argument, size_t *transferred) { (void)argument; (void)transferred; return SSL_accept(ssl); }
static int do_connect(SSL *ssl, void *argument, size_t *transferred) { (void)argument; (void)transferred; return SSL_connect(ssl); }

typedef struct { uint8_t *buffer; size_t length; } IOBuffer;
static int do_read(SSL *ssl, void *argument, size_t *transferred) {
    IOBuffer *io = argument;
    return SSL_read_ex(ssl, io->buffer, io->length, transferred);
}
static int do_write_some(SSL *ssl, void *argument, size_t *transferred) {
    IOBuffer *io = argument;
    return SSL_write_ex(ssl, io->buffer, io->length, transferred);
}

static int accept_any_certificate(int preverified, X509_STORE_CTX *store) {
    (void)preverified; (void)store;
    return 1; /* The pin is the leaf key, checked by check_peer after the handshake. */
}

static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                       unsigned int inlen, void *argument) {
    (void)ssl; (void)argument;
    if (inlen != sizeof(alpn_wire) || memcmp(in, alpn_wire, sizeof(alpn_wire)) != 0) return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out = alpn_wire + 1;
    *outlen = sizeof(alpn_wire) - 1;
    return SSL_TLSEXT_ERR_OK;
}

static int count_ticket(SSL *ssl, SSL_SESSION *session) {
    (void)session;
    RemozioTLSContext *context = SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
    if (context) context->tickets_received++;
    return 0; /* Never keep a session: the peer must not resume. */
}

int remozio_tls_context_tickets_received(const RemozioTLSContext *context) { return context ? context->tickets_received : -1; }

static RemozioTLSContext *context_new(int is_server, int min_version, int max_version, const uint8_t *cert_der,
                                      size_t cert_length, const uint8_t *key_der, size_t key_length) {
    signal(SIGPIPE, SIG_IGN); /* Process-wide: a peer reset must surface as an error, not kill the peer. */
    RemozioTLSContext *context = calloc(1, sizeof(*context));
    if (!context) return NULL;
    context->is_server = is_server;
    context->ctx = SSL_CTX_new(is_server ? TLS_server_method() : TLS_client_method());
    if (!context->ctx) goto fail;
    SSL_CTX *ctx = context->ctx;
    if (!SSL_CTX_set_min_proto_version(ctx, min_version) || !SSL_CTX_set_max_proto_version(ctx, max_version)) goto fail;
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_app_data(ctx, context);
    if (is_server) {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    } else { /* Count tickets so tests can prove the server sends none; the callback keeps nothing. */
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(ctx, count_ticket);
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | (is_server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), accept_any_certificate);
    if (is_server) {
        if (!SSL_CTX_set_num_tickets(ctx, 0) || !SSL_CTX_set_max_early_data(ctx, 0)) goto fail;
        SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    }
    if (cert_der) {
        const unsigned char *cursor = cert_der;
        X509 *certificate = d2i_X509(NULL, &cursor, (long)cert_length);
        cursor = key_der;
        EVP_PKEY *key = key_der ? d2i_AutoPrivateKey(NULL, &cursor, (long)key_length) : NULL;
        int ok = certificate && key && SSL_CTX_use_certificate(ctx, certificate) == 1 &&
                 SSL_CTX_use_PrivateKey(ctx, key) == 1 && SSL_CTX_check_private_key(ctx) == 1;
        X509_free(certificate);
        EVP_PKEY_free(key);
        if (!ok) goto fail;
    }
    return context;
fail:
    remozio_tls_context_free(context);
    return NULL;
}

RemozioTLSContext *remozio_tls_server_context_new(const uint8_t *cert_der, size_t cert_length, const uint8_t *key_der,
                                                  size_t key_length) {
    if (!cert_der || !key_der) return NULL;
    return context_new(1, TLS1_3_VERSION, TLS1_3_VERSION, cert_der, cert_length, key_der, key_length);
}

RemozioTLSContext *remozio_tls_client_context_new(const RemozioTLSClientOptions *options, const uint8_t *cert_der,
                                                  size_t cert_length, const uint8_t *key_der, size_t key_length) {
    int min = options && options->min_version ? options->min_version : TLS1_3_VERSION;
    int max = options && options->max_version ? options->max_version : TLS1_3_VERSION;
    RemozioTLSContext *context = context_new(0, min, max, cert_der, cert_length, key_der, key_length);
    if (!context) return NULL;
    if (!options || !options->offer_no_alpn) {
        const char *alpn = options && options->alpn ? options->alpn : REMOZIO_TLS_ALPN;
        size_t length = strlen(alpn);
        unsigned char wire[256];
        if (length == 0 || length > 255) { remozio_tls_context_free(context); return NULL; }
        wire[0] = (unsigned char)length;
        memcpy(wire + 1, alpn, length);
        if (SSL_CTX_set_alpn_protos(context->ctx, wire, (unsigned)length + 1) != 0) {
            remozio_tls_context_free(context);
            return NULL;
        }
    }
    return context;
}

void remozio_tls_context_free(RemozioTLSContext *context) {
    if (!context) return;
    SSL_CTX_free(context->ctx);
    free(context);
}

/* The peer leaf must be one self-signed, currently valid P-256 certificate; export its 65-byte point. */
static int check_peer(SSL *ssl, uint8_t point[REMOZIO_TLS_POINT_LENGTH]) {
    int ok = 0;
    X509 *peer = SSL_get1_peer_certificate(ssl);
    EVP_PKEY *key = peer ? X509_get0_pubkey(peer) : NULL;
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    int extras = chain ? sk_X509_num(chain) : 0;
    char group[32];
    size_t length = 0;
    if (!peer || !key) goto done;
    if (extras != (SSL_is_server(ssl) ? 0 : 1)) goto done;
    if (X509_cmp_current_time(X509_get0_notBefore(peer)) >= 0 || X509_cmp_current_time(X509_get0_notAfter(peer)) <= 0) goto done;
    if (X509_NAME_cmp(X509_get_subject_name(peer), X509_get_issuer_name(peer)) != 0 || X509_verify(peer, key) != 1) goto done;
    if (EVP_PKEY_get_base_id(key) != EVP_PKEY_EC) goto done;
    if (!EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), &length) ||
        strcmp(group, "prime256v1") != 0) goto done;
    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, point, REMOZIO_TLS_POINT_LENGTH, &length) ||
        length != REMOZIO_TLS_POINT_LENGTH || point[0] != 0x04) goto done;
    ok = 1;
done:
    X509_free(peer);
    return ok;
}

static int alpn_is_pairing(SSL *ssl) {
    const unsigned char *selected = NULL;
    unsigned int length = 0;
    SSL_get0_alpn_selected(ssl, &selected, &length);
    return selected && length == sizeof(alpn_wire) - 1 && memcmp(selected, alpn_wire + 1, length) == 0;
}

static RemozioTLSStatus handshake(RemozioTLSContext *context, int fd, int cancel_fd, int64_t deadline_ms,
                                  RemozioTLSConnection **connection, uint8_t point[REMOZIO_TLS_POINT_LENGTH]) {
    RemozioTLSStatus status = REMOZIO_TLS_INTERNAL;
    SSL *ssl = NULL;
    if (!connection || !point) { close(fd); return REMOZIO_TLS_INVALID_ARGUMENT; }
    *connection = NULL;
    int64_t bound = remozio_tls_now_ms() + REMOZIO_TLS_MAX_HANDSHAKE_MS;
    if (deadline_ms > bound) deadline_ms = bound;
    int flags = fcntl(fd, F_GETFL);
    if (!context || flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 || !(ssl = SSL_new(context->ctx)) ||
        !SSL_set_fd(ssl, fd)) {
        status = REMOZIO_TLS_INVALID_ARGUMENT;
        goto fail;
    }
    status = drive(ssl, fd, cancel_fd, deadline_ms, context->is_server ? do_accept : do_connect, NULL, NULL);
    if (status != REMOZIO_TLS_OK) goto fail;
    if (SSL_version(ssl) != TLS1_3_VERSION) { status = REMOZIO_TLS_HANDSHAKE_FAILED; goto fail; }
    if (!alpn_is_pairing(ssl)) { status = REMOZIO_TLS_HANDSHAKE_FAILED; goto fail; }
    if (!check_peer(ssl, point)) { status = REMOZIO_TLS_PEER_CERTIFICATE; goto fail; }
    RemozioTLSConnection *created = calloc(1, sizeof(*created));
    if (!created) { status = REMOZIO_TLS_INTERNAL; goto fail; }
    created->ssl = ssl;
    created->fd = fd;
    *connection = created;
    return REMOZIO_TLS_OK;
fail:
    SSL_free(ssl);
    close(fd);
    return status;
}

RemozioTLSStatus remozio_tls_accept(RemozioTLSContext *context, int fd, int cancel_fd, int64_t deadline_ms,
                                    RemozioTLSConnection **connection, uint8_t peer_point[REMOZIO_TLS_POINT_LENGTH]) {
    if (!context || !context->is_server) { close(fd); return REMOZIO_TLS_INVALID_ARGUMENT; }
    return handshake(context, fd, cancel_fd, deadline_ms, connection, peer_point);
}

RemozioTLSStatus remozio_tls_connect(RemozioTLSContext *context, int fd, int cancel_fd, int64_t deadline_ms,
                                     RemozioTLSConnection **connection,
                                     uint8_t peer_point[REMOZIO_TLS_POINT_LENGTH]) {
    if (!context || context->is_server) { close(fd); return REMOZIO_TLS_INVALID_ARGUMENT; }
    return handshake(context, fd, cancel_fd, deadline_ms, connection, peer_point);
}

RemozioTLSStatus remozio_tls_read(RemozioTLSConnection *connection, uint8_t *buffer, size_t capacity, int cancel_fd,
                                  int64_t deadline_ms, size_t *count) {
    IOBuffer io = {buffer, capacity};
    if (!count) return REMOZIO_TLS_INVALID_ARGUMENT;
    *count = 0;
    if (!connection || !buffer || capacity == 0) return REMOZIO_TLS_INVALID_ARGUMENT;
    return drive(connection->ssl, connection->fd, cancel_fd, deadline_ms, do_read, &io, count);
}

RemozioTLSStatus remozio_tls_write(RemozioTLSConnection *connection, const uint8_t *buffer, size_t length,
                                   int cancel_fd, int64_t deadline_ms) {
    if (!connection || (!buffer && length)) return REMOZIO_TLS_INVALID_ARGUMENT;
    while (length > 0) {
        size_t written = 0;
        IOBuffer io = {(uint8_t *)buffer, length};
        RemozioTLSStatus status = drive(connection->ssl, connection->fd, cancel_fd, deadline_ms, do_write_some, &io, &written);
        if (status != REMOZIO_TLS_OK) return status;
        buffer += written;
        length -= written;
    }
    return REMOZIO_TLS_OK;
}

int remozio_tls_negotiated_version(const RemozioTLSConnection *connection) { return connection ? SSL_version(connection->ssl) : 0; }
const char *remozio_tls_negotiated_alpn(const RemozioTLSConnection *connection) {
    const unsigned char *selected = NULL;
    unsigned int length = 0;
    static _Thread_local char name[256];
    if (!connection) return NULL;
    SSL_get0_alpn_selected(connection->ssl, &selected, &length);
    if (!selected || length >= sizeof(name)) return NULL;
    memcpy(name, selected, length);
    name[length] = 0;
    return name;
}
int remozio_tls_session_was_reused(const RemozioTLSConnection *connection) { return connection ? SSL_session_reused(connection->ssl) : 0; }

void remozio_tls_connection_close(RemozioTLSConnection *connection) {
    if (!connection) return;
    SSL_shutdown(connection->ssl); /* Best effort on a nonblocking socket; the fd closes either way. */
    SSL_free(connection->ssl);
    close(connection->fd);
    free(connection);
}

RemozioTLSStatus remozio_tls_make_identity(const char *curve, int64_t not_before, int64_t not_after, uint8_t **cert_der,
                                           size_t *cert_length, uint8_t **key_der, size_t *key_length) {
    RemozioTLSStatus status = REMOZIO_TLS_INTERNAL;
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    X509_NAME *name = NULL;
    BIGNUM *serial = NULL;
    ASN1_INTEGER *serial_asn1 = NULL;
    ASN1_TIME *before = NULL, *after = NULL;
    unsigned char random_bytes[16];
    if (!cert_der || !key_der || !cert_length || !key_length) return REMOZIO_TLS_INVALID_ARGUMENT;
    *cert_der = NULL; *key_der = NULL; *cert_length = 0; *key_length = 0;
    if (!curve || not_after <= not_before) return REMOZIO_TLS_INVALID_ARGUMENT;
    key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", curve);
    certificate = X509_new();
    name = X509_NAME_new();
    if (!key || !certificate || !name || RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) goto done;
    random_bytes[0] = (random_bytes[0] & 0x7f) | 0x40; /* positive and never zero */
    serial = BN_bin2bn(random_bytes, sizeof(random_bytes), NULL);
    serial_asn1 = serial ? BN_to_ASN1_INTEGER(serial, NULL) : NULL;
    before = ASN1_TIME_set(NULL, (time_t)not_before);
    after = ASN1_TIME_set(NULL, (time_t)not_after);
    if (!serial_asn1 || !before || !after) goto done;
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, (const unsigned char *)"Remozio transport", -1, -1, 0)) goto done;
    if (!X509_set_version(certificate, X509_VERSION_3) || !X509_set_serialNumber(certificate, serial_asn1) ||
        !X509_set1_notBefore(certificate, before) || !X509_set1_notAfter(certificate, after) ||
        !X509_set_subject_name(certificate, name) || !X509_set_issuer_name(certificate, name) ||
        !X509_set_pubkey(certificate, key)) goto done;
    struct { int nid; const char *value; } extensions[] = {
        {NID_basic_constraints, "critical,CA:FALSE"},
        {NID_key_usage, "critical,digitalSignature"},
        {NID_ext_key_usage, "serverAuth,clientAuth"},
    };
    for (size_t index = 0; index < sizeof(extensions) / sizeof(extensions[0]); index++) {
        X509_EXTENSION *extension = X509V3_EXT_conf_nid(NULL, NULL, extensions[index].nid, extensions[index].value);
        int added = extension && X509_add_ext(certificate, extension, -1);
        X509_EXTENSION_free(extension);
        if (!added) goto done;
    }
    if (!X509_sign(certificate, key, EVP_sha256())) goto done;
    int cert_size = i2d_X509(certificate, cert_der);
    int key_size = i2d_PrivateKey(key, key_der);
    if (cert_size <= 0 || key_size <= 0) goto done;
    *cert_length = (size_t)cert_size;
    *key_length = (size_t)key_size;
    status = REMOZIO_TLS_OK;
done:
    if (status != REMOZIO_TLS_OK) {
        OPENSSL_free(*cert_der); OPENSSL_free(*key_der);
        *cert_der = NULL; *key_der = NULL;
    }
    EVP_PKEY_free(key); X509_free(certificate); X509_NAME_free(name); BN_free(serial);
    ASN1_INTEGER_free(serial_asn1); ASN1_TIME_free(before); ASN1_TIME_free(after);
    return status;
}
