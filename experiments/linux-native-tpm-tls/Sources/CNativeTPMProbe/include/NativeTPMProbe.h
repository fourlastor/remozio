#ifndef REMOZIO_NATIVE_TPM_PROBE_H
#define REMOZIO_NATIVE_TPM_PROBE_H

// Internal experiment ABI. No key handle or arbitrary signing input leaves this target.
typedef struct {
    int status;
    int key_provider_tpm2;
    int signature_provider_tpm2;
    int client_verification_rejected;
    int alpn_rejected;
    int application_received;
    int application_sent;
    int signature_bytes;
} RemozioNativeProbeResult;

enum {
    REMOZIO_PROBE_OK, REMOZIO_PROBE_ENVIRONMENT, REMOZIO_PROBE_PROVIDER,
    REMOZIO_PROBE_KEY_LOAD, REMOZIO_PROBE_WRONG_PROVIDER, REMOZIO_PROBE_PUBLIC_KEY,
    REMOZIO_PROBE_SIGN, REMOZIO_PROBE_IO, REMOZIO_PROBE_TIMEOUT,
    REMOZIO_PROBE_CLIENT_VERIFY, REMOZIO_PROBE_ALPN, REMOZIO_PROBE_PEER_CLOSED,
    REMOZIO_PROBE_PAYLOAD, REMOZIO_PROBE_TLS, REMOZIO_PROBE_ARGUMENT, REMOZIO_PROBE_CERTIFICATE
};

// authority/healthy are disposable signing fixtures; transport is used only by the TLS path.
RemozioNativeProbeResult remozio_probe_sign(int healthy_fixture);
RemozioNativeProbeResult remozio_probe_tls(int listening_fd);
#endif
