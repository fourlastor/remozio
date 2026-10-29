#include "PairingTLSTestSupport.h"
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const unsigned char pairing_alpn[] = {17, 'r', 'e', 'm', 'o', 'z', 'i', 'o', '-', 'p', 'a', 'i', 'r', 'i', 'n', 'g', '/', '1'};
static int tickets_index = -1; /* SSL_CTX ex_data slot holding the ticket count; the tests run serially */

void remozio_test_free(void *pointer) { OPENSSL_free(pointer); }

static int add_name(X509_NAME *name, const char *common_name) {
    return X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, (const unsigned char *)common_name, -1, -1, 0);
}

int remozio_test_make_issued_identity(int same_name, uint8_t **cert_der, size_t *cert_length, uint8_t **key_der,
                                      size_t *key_length) {
    int ok = 0;
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    EVP_PKEY *issuer_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    X509 *certificate = X509_new();
    X509_NAME *subject = X509_NAME_new(), *issuer = X509_NAME_new();
    *cert_der = NULL; *key_der = NULL;
    if (!key || !issuer_key || !certificate || !subject || !issuer) goto done;
    if (!add_name(subject, "Remozio transport") || !add_name(issuer, same_name ? "Remozio transport" : "Remozio test issuer")) goto done;
    if (!X509_set_version(certificate, X509_VERSION_3) || !ASN1_INTEGER_set(X509_get_serialNumber(certificate), 2) ||
        !X509_gmtime_adj(X509_getm_notBefore(certificate), -60) || !X509_gmtime_adj(X509_getm_notAfter(certificate), 3600) ||
        !X509_set_subject_name(certificate, subject) || !X509_set_issuer_name(certificate, issuer) ||
        !X509_set_pubkey(certificate, key) || !X509_sign(certificate, issuer_key, EVP_sha256())) goto done;
    int cert_size = i2d_X509(certificate, cert_der);
    int key_size = i2d_PrivateKey(key, key_der);
    if (cert_size <= 0 || key_size <= 0) goto done;
    *cert_length = (size_t)cert_size;
    *key_length = (size_t)key_size;
    ok = 1;
done:
    if (!ok) { OPENSSL_free(*cert_der); OPENSSL_free(*key_der); *cert_der = NULL; *key_der = NULL; }
    EVP_PKEY_free(key); EVP_PKEY_free(issuer_key); X509_free(certificate); X509_NAME_free(subject); X509_NAME_free(issuer);
    return ok;
}

int remozio_test_public_point(const uint8_t *key_der, size_t key_length, uint8_t point[65]) {
    const unsigned char *cursor = key_der;
    EVP_PKEY *key = d2i_AutoPrivateKey(NULL, &cursor, (long)key_length);
    size_t length = 0;
    int ok = key && EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, point, 65, &length) && length == 65;
    EVP_PKEY_free(key);
    return ok;
}

static int accept_any(int preverified, X509_STORE_CTX *store) { (void)preverified; (void)store; return 1; }

static int select_pairing(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *argument) {
    (void)ssl; (void)argument;
    if (inlen != sizeof(pairing_alpn) || memcmp(in, pairing_alpn, sizeof(pairing_alpn)) != 0) return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out = pairing_alpn + 1;
    *outlen = sizeof(pairing_alpn) - 1;
    return SSL_TLSEXT_ERR_OK;
}

static int count_ticket(SSL *ssl, SSL_SESSION *session) {
    (void)session;
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    SSL_CTX_set_ex_data(ctx, tickets_index, (void *)((intptr_t)SSL_CTX_get_ex_data(ctx, tickets_index) + 1));
    return 0; /* The session stays on the connection; connect_once reads it with SSL_get1_session. */
}

static SSL_CTX *context_new(int is_server, const RemozioTestPeerOptions *options) {
    if (tickets_index < 0) tickets_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    SSL_CTX *ctx = SSL_CTX_new(is_server ? TLS_server_method() : TLS_client_method());
    const unsigned char *cursor;
    X509 *certificate = NULL, *extra = NULL;
    EVP_PKEY *key = NULL;
    int ok = 0;
    if (!ctx || !options || !options->cert || !options->key) goto done;
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) || !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) goto done;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | (is_server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0), accept_any);
    cursor = options->cert;
    certificate = d2i_X509(NULL, &cursor, (long)options->cert_length);
    cursor = options->key;
    key = d2i_AutoPrivateKey(NULL, &cursor, (long)options->key_length);
    if (!certificate || !key || SSL_CTX_use_certificate(ctx, certificate) != 1 || SSL_CTX_use_PrivateKey(ctx, key) != 1) goto done;
    if (options->extra) {
        cursor = options->extra;
        extra = d2i_X509(NULL, &cursor, (long)options->extra_length);
        if (!extra || !SSL_CTX_add1_chain_cert(ctx, extra)) goto done;
    }
    if (is_server) {
        SSL_CTX_set_alpn_select_cb(ctx, select_pairing, NULL);
        if (!SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"remozio-test", 12)) goto done;
        if (options->issue_tickets) {
            if (!SSL_CTX_set_num_tickets(ctx, 2)) goto done;
        } else {
            SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
            if (!SSL_CTX_set_num_tickets(ctx, 0)) goto done;
        }
    } else {
        const unsigned char *wire = options->alpn_wire ? options->alpn_wire : pairing_alpn;
        size_t length = options->alpn_wire ? options->alpn_length : sizeof(pairing_alpn);
        if (SSL_CTX_set_alpn_protos(ctx, wire, (unsigned)length) != 0) goto done;
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(ctx, count_ticket);
    }
    ok = 1;
done:
    X509_free(certificate); X509_free(extra); EVP_PKEY_free(key);
    if (!ok) { SSL_CTX_free(ctx); return NULL; }
    return ctx;
}

void *remozio_test_server_context_new(const RemozioTestPeerOptions *options) { return context_new(1, options); }
void *remozio_test_client_context_new(const RemozioTestPeerOptions *options) { return context_new(0, options); }
void remozio_test_context_free(void *context) { SSL_CTX_free(context); }
int remozio_test_tickets_received(void *context) {
    return context ? (int)(intptr_t)SSL_CTX_get_ex_data(context, tickets_index) : -1;
}
void remozio_test_session_free(void *session) { SSL_SESSION_free(session); }

static SSL *bounded_ssl(SSL_CTX *ctx, int fd) {
    struct timeval limit = {.tv_sec = 5};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)) != 0) return NULL;
    SSL *ssl = ctx ? SSL_new(ctx) : NULL;
    if (ssl && !SSL_set_fd(ssl, fd)) { SSL_free(ssl); ssl = NULL; }
    return ssl;
}

int remozio_test_serve_once(void *context, int fd) {
    SSL *ssl = bounded_ssl(context, fd);
    int accepted = ssl && SSL_accept(ssl) == 1;
    if (accepted) {
        unsigned char byte = 'x';
        size_t count = 0;
        if (SSL_write_ex(ssl, &byte, 1, &count)) {
            while (SSL_read_ex(ssl, &byte, 1, &count)) {}
        }
        SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    close(fd);
    return accepted;
}

int remozio_test_connect_once(void *context, int fd, void *session, int *reused, void **latest_session) {
    SSL *ssl = bounded_ssl(context, fd);
    int ok = 0;
    if (reused) *reused = 0;
    if (latest_session) *latest_session = NULL;
    if (ssl && (!session || SSL_set_session(ssl, session)) && SSL_connect(ssl) == 1) {
        unsigned char byte = 0;
        size_t count = 0;
        ok = SSL_read_ex(ssl, &byte, 1, &count) && count == 1; /* processes any tickets sent before the byte */
        if (reused) *reused = SSL_session_reused(ssl);
        if (latest_session) *latest_session = SSL_get1_session(ssl);
        SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    close(fd);
    return ok;
}
