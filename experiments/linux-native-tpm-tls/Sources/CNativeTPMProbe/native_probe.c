#define _GNU_SOURCE
#include "NativeTPMProbe.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    OSSL_LIB_CTX *library;
    OSSL_PROVIDER *software;
    OSSL_PROVIDER *tpm;
    EVP_PKEY *key;
} ProbeKey;

static void release_key(ProbeKey *key) {
    EVP_PKEY_free(key->key);
    OSSL_PROVIDER_unload(key->tpm);
    OSSL_PROVIDER_unload(key->software);
    OSSL_LIB_CTX_free(key->library);
}

static int equal_environment(const char *name, const char *expected) {
    const char *value = getenv(name);
    return value && strcmp(value, expected) == 0;
}

static int simulator_environment(void) {
    char directory[PATH_MAX], expected_bus[PATH_MAX + 32], unavailable[PATH_MAX + 64];
    const char *tcti = getenv("TPM2OPENSSL_TCTI");
    if (getuid() == 0 || getuid() != geteuid() || !getcwd(directory, sizeof(directory))) return 0;
    snprintf(expected_bus, sizeof(expected_bus), "unix:path=%s/bus.sock", directory);
    snprintf(unavailable, sizeof(unavailable), "swtpm:path=%s/absent-tpm.sock", directory);
    return equal_environment("OPENSSL_CONF", "/dev/null") &&
        equal_environment("DBUS_SESSION_BUS_ADDRESS", expected_bus) &&
        equal_environment("TPM2TOOLS_TCTI", "tabrmd:bus_type=session") &&
        !getenv("TPM2OPENSSL_PARENT_AUTH") && tcti &&
        (strcmp(tcti, "tabrmd:bus_type=session") == 0 || strcmp(tcti, unavailable) == 0);
}

static int provider_is_tpm2(const OSSL_PROVIDER *provider) {
    return provider && strcmp(OSSL_PROVIDER_get0_name(provider), "tpm2") == 0;
}

static int load_key(ProbeKey *key, const char *record, const char *public_record,
                    RemozioNativeProbeResult *result) {
    int status = REMOZIO_PROBE_PROVIDER;
    OSSL_STORE_CTX *store = NULL;
    OSSL_STORE_INFO *info = NULL;
    BIO *public_file = NULL;
    EVP_PKEY *expected = NULL;
    if (!simulator_environment()) return REMOZIO_PROBE_ENVIRONMENT;
    key->library = OSSL_LIB_CTX_new();
    if (!key->library || !(key->software = OSSL_PROVIDER_load(key->library, "default")) ||
        !(key->tpm = OSSL_PROVIDER_load(key->library, "tpm2"))) goto done;
    status = REMOZIO_PROBE_KEY_LOAD;
    store = OSSL_STORE_open_ex(record, key->library, "?provider=default", UI_null(), NULL, NULL, NULL, NULL);
    if (!store) goto done;
    info = OSSL_STORE_load(store);
    if (!info || OSSL_STORE_INFO_get_type(info) != OSSL_STORE_INFO_PKEY ||
        !(key->key = OSSL_STORE_INFO_get1_PKEY(info))) goto done;
    status = REMOZIO_PROBE_WRONG_PROVIDER;
    if (!provider_is_tpm2(EVP_PKEY_get0_provider(key->key))) goto done;
    result->key_provider_tpm2 = 1;
    status = REMOZIO_PROBE_PUBLIC_KEY;
    public_file = BIO_new_file(public_record, "r");
    if (!public_file || !(expected = PEM_read_bio_PUBKEY_ex(public_file, NULL, NULL, NULL,
        key->library, "?provider=default")) || EVP_PKEY_eq(key->key, expected) != 1 ||
        !EVP_PKEY_is_a(key->key, "EC") || EVP_PKEY_get_bits(key->key) != 256) goto done;
    status = REMOZIO_PROBE_OK;
done:
    EVP_PKEY_free(expected);
    BIO_free(public_file);
    OSSL_STORE_INFO_free(info);
    OSSL_STORE_close(store);
    return status;
}

RemozioNativeProbeResult remozio_probe_sign(int healthy_fixture) {
    RemozioNativeProbeResult result = {0};
    ProbeKey key = {0};
    EVP_MD_CTX *digest = NULL;
    EVP_PKEY_CTX *signature_context = NULL;
    unsigned char signature[80];
    size_t size = sizeof(signature);
    int output = -1;
    static const unsigned char message[] = "Remozio disposable authority signature fixture v1";
    if (healthy_fixture != 0 && healthy_fixture != 1) {
        result.status = REMOZIO_PROBE_ARGUMENT;
        return result;
    }
    result.status = load_key(&key, healthy_fixture ? "healthy.pem" : "authority.pem",
        healthy_fixture ? "healthy.spki" : "authority.spki", &result);
    if (result.status != REMOZIO_PROBE_OK) goto done;
    result.status = REMOZIO_PROBE_SIGN;
    digest = EVP_MD_CTX_new();
    if (!digest || EVP_DigestSignInit_ex(digest, &signature_context, "SHA256", key.library,
        "?provider=default", key.key, NULL) != 1 ||
        !provider_is_tpm2(EVP_PKEY_CTX_get0_provider(signature_context))) goto done;
    result.signature_provider_tpm2 = 1;
    if (EVP_DigestSignUpdate(digest, message, sizeof(message) - 1) != 1 ||
        EVP_DigestSignFinal(digest, signature, &size) != 1 || size == 0 || size > sizeof(signature)) goto done;
    result.status = REMOZIO_PROBE_IO;
    output = open("signature.der", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0 || write(output, signature, size) != (ssize_t)size) goto done;
    result.signature_bytes = (int)size;
    result.status = REMOZIO_PROBE_OK;
done:
    if (output >= 0) close(output);
    EVP_MD_CTX_free(digest);
    release_key(&key);
    return result;
}

static int64_t milliseconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static int await_io(int fd, short events, int64_t deadline) {
    while (1) {
        int64_t now = milliseconds();
        if (now < 0) return REMOZIO_PROBE_IO;
        if (now >= deadline) return REMOZIO_PROBE_TIMEOUT;
        struct pollfd item = {.fd = fd, .events = events};
        int ready = poll(&item, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready == 0) return REMOZIO_PROBE_TIMEOUT;
        if (ready < 0 || (item.revents & POLLNVAL)) return REMOZIO_PROBE_IO;
        return REMOZIO_PROBE_OK;
    }
}

static int ssl_retry(SSL *channel, int operation, int fd, int64_t deadline) {
    int error = SSL_get_error(channel, operation);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
        return await_io(fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
    if (error == SSL_ERROR_ZERO_RETURN) return REMOZIO_PROBE_PEER_CLOSED;
    return REMOZIO_PROBE_TLS;
}

static int select_alpn(SSL *channel, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *context) {
    (void)channel;
    static const unsigned char allowed[] = "\x14remozio-experiment/1";
    if (SSL_select_next_proto((unsigned char **)out, outlen, allowed, sizeof(allowed) - 1,
        in, inlen) == OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_OK;
    ((RemozioNativeProbeResult *)context)->alpn_rejected = 1;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

RemozioNativeProbeResult remozio_probe_tls(int listening_fd) {
    RemozioNativeProbeResult result = {0};
    ProbeKey key = {0};
    SSL_CTX *context = NULL;
    SSL *channel = NULL;
    int connection = -1;
    int64_t started = milliseconds();
    int64_t deadline = started + 4000;
    unsigned char request[64];
    size_t used = 0;
    static const unsigned char expected[] = "remozio-tpm-test\n";
    static const unsigned char response[] = "tset-mpt-oizomer\n";
    if (listening_fd < 3 || started < 0 || signal(SIGPIPE, SIG_IGN) == SIG_ERR) { result.status = REMOZIO_PROBE_ARGUMENT; return result; }
    result.status = load_key(&key, "transport.pem", "transport.spki", &result);
    if (result.status != REMOZIO_PROBE_OK) goto done;
    result.status = REMOZIO_PROBE_TLS;
    context = SSL_CTX_new_ex(key.library, "?provider=default", TLS_server_method());
    if (!context || SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_load_verify_locations(context, "client.crt", NULL) != 1 ||
        SSL_CTX_set_num_tickets(context, 0) != 1 || SSL_CTX_set_max_early_data(context, 0) != 1) goto done;
    result.status = REMOZIO_PROBE_CERTIFICATE;
    if (SSL_CTX_use_certificate_chain_file(context, "server.crt") != 1 ||
        SSL_CTX_use_PrivateKey(context, key.key) != 1 || SSL_CTX_check_private_key(context) != 1) goto done;
    SSL_CTX_set_options(context, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_alpn_select_cb(context, select_alpn, &result);
    result.status = REMOZIO_PROBE_IO;
    int flags = fcntl(listening_fd, F_GETFL);
    if (flags < 0 || fcntl(listening_fd, F_SETFL, flags | O_NONBLOCK) != 0) goto done;
    while ((connection = accept4(listening_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) < 0) {
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) goto done;
        result.status = await_io(listening_fd, POLLIN, deadline);
        if (result.status != REMOZIO_PROBE_OK) goto done;
    }
    result.status = REMOZIO_PROBE_TLS;
    channel = SSL_new(context);
    if (!channel || SSL_set_fd(channel, connection) != 1) goto done;
    while (1) {
        int operation = SSL_accept(channel);
        if (operation == 1) break;
        result.status = ssl_retry(channel, operation, connection, deadline);
        if (result.status != REMOZIO_PROBE_OK) {
            if (result.alpn_rejected) result.status = REMOZIO_PROBE_ALPN;
            else if (SSL_get_verify_result(channel) != X509_V_OK) {
                result.client_verification_rejected = 1;
                result.status = REMOZIO_PROBE_CLIENT_VERIFY;
            }
            goto done;
        }
    }
    // The selection callback is not called when the peer omits ALPN entirely.
    // Require the negotiated application protocol before any application read.
    const unsigned char *selected = NULL;
    unsigned int selected_size = 0;
    static const unsigned char required_alpn[] = "remozio-experiment/1";
    SSL_get0_alpn_selected(channel, &selected, &selected_size);
    if (selected_size != sizeof(required_alpn) - 1 ||
        memcmp(selected, required_alpn, sizeof(required_alpn) - 1) != 0) {
        result.alpn_rejected = 1;
        result.status = REMOZIO_PROBE_ALPN;
        goto done;
    }
    while (used < sizeof(request)) {
        size_t count = 0;
        int operation = SSL_read_ex(channel, request + used, sizeof(request) - used, &count);
        if (operation != 1) {
            result.status = ssl_retry(channel, operation, connection, deadline);
            if (result.status != REMOZIO_PROBE_OK) goto done;
            continue;
        }
        used += count;
        result.application_received = (int)used;
        if (memchr(request, '\n', used)) break;
    }
    result.status = REMOZIO_PROBE_PAYLOAD;
    if (used != sizeof(expected) - 1 || memcmp(request, expected, used) != 0) goto done;
    used = 0;
    while (used < sizeof(response) - 1) {
        size_t count = 0;
        int operation = SSL_write_ex(channel, response + used, sizeof(response) - 1 - used, &count);
        if (operation != 1) {
            result.status = ssl_retry(channel, operation, connection, deadline);
            if (result.status != REMOZIO_PROBE_OK) goto done;
            continue;
        }
        used += count;
        result.application_sent = (int)used;
    }
    (void)SSL_shutdown(channel);
    result.status = REMOZIO_PROBE_OK;
done:
    SSL_free(channel);
    SSL_CTX_free(context);
    if (connection >= 0) close(connection);
    release_key(&key);
    return result;
}
