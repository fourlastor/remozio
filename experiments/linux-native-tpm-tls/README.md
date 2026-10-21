# Disposable native Swift TPM/provider experiment

This Linux-only executable exercises Swift → an internal C shim → OpenSSL 3 → the
`tpm2` provider. It signs one fixed synthetic message with the separate authority
fixture key and serves one fixed loopback TLS exchange with the transport fixture
key. It is an experiment, not a production signing API, identity store or TLS-stack
decision. It changes no shared host core or protocol bytes.

The [runner](../../scripts/run-linux-native-tpm-tls-experiment.py) reuses the existing
[TPM harness](../../scripts/run-linux-tpm-tls-experiment.py) for private simulator,
session bus/resource manager, exact key templates, wrapped-record validation,
certificates and independent OpenSSL signature verification. The native executable
performs the private signing and server TLS calls; it does not launch OpenSSL CLI
commands. Only newly generated disposable records are used. There is no hardware
mode, provisioning API, device discovery or software-private-key fallback.

The C shim owns an OpenSSL library context and explicitly loads the default and TPM
providers. It checks the key's provider and expected public key before use. The fixed
message signing path also checks the selected signature provider. Signatures are
ASN.1 DER ECDSA/SHA-256, verified independently by the CLI. This does not exercise a
Remozio wire signature or approve arbitrary signing messages.

The native server requires TLS 1.3, a client certificate anchored to the designated
self-signed client fixture, exact `remozio-experiment/1` ALPN and the fixed request.
The Python peer checks SHA-256 of the server SPKI before application delivery.
The server also checks the negotiated protocol after handshake completion, since
an omitted ALPN extension does not invoke OpenSSL's selection callback.
Tickets, session caching and early data are disabled. The server's client check is
fixture certificate anchoring, not a production enrollment/SPKI callback. The
network-facing operation loads only `transport.pem`; there is no transport-key
arbitrary-message sign entry point. This does not prove protected service/account
separation between authority and transport.

Each native process has a 12-second execution budget, followed by bounded
terminate/reap cleanup when required. The TLS peer, public-key
inspection and final child wait share the deadline measured before server spawn;
the final wait does not start a new timeout budget. Nonblocking accept/handshake/I/O
share one four-second monotonic poll deadline; a synchronous provider call is still
bounded by the outer process deadline. Listener descriptors are inherited from an
already bound loopback socket. Child processes are terminated/reaped and temporary
state is removed on success and ordinary exceptions, including a native child
timeout. Arbitrary runner termination and host-crash cleanup are not established. Reports contain fixed status names, bounded
counters, source/binary hashes and runtime metadata; raw provider diagnostics and key
records are not published.

The runner tests create/reopen/sign, simulator restart, absent/corrupt records,
unavailable simulator, inherited device-route rejection before provider loading,
software-key rejection, mismatched SPKI and certificate/key binding, actual mutual
TLS, wrong host pin/client certificate/ALPN/payload, omitted ALPN with attempted
application delivery, a stalled handshake deadline,
and copied wrapped-record refusal on an independently initialized simulator after
a healthy new-key signing control. Existing
[hardware-adapter controls](../linux-tpm-tls/check_hardware_adapter.py) remain separate.

## Run explicitly

Use Swift 6.2 or later, OpenSSL 3 development headers/library and the existing
[private simulator prerequisites](../../docs/experiments/linux-tpm-tls.md#reproduce-explicitly).
The C shim needs OpenSSL development headers only; it does not call TSS2 directly.
The simulator/provider need their existing runtime dependencies. No package install
or device-permission change is performed by the runner.

With distro development dependencies already available:

```sh
swift build --package-path experiments/linux-native-tpm-tls \
  --scratch-path /tmp/remozio-native-probe-build --jobs 4
python3 -m unittest discover -s tests -p 'test_linux_native_tpm_tls_experiment.py'
timeout 120s python3 scripts/run-linux-native-tpm-tls-experiment.py \
  --simulator --runtime-root /tmp/remozio-tpm-runtime/root \
  --probe /tmp/remozio-native-probe-build/debug/NativeTPMProbe
```

For an extracted Ubuntu amd64 `libssl-dev` plus matching `libssl3t64` package tree,
set `PKG_CONFIG_SYSROOT_DIR` to that tree and `PKG_CONFIG_PATH` to its
`usr/lib/x86_64-linux-gnu/pkgconfig`. Add the extracted
`usr/include/x86_64-linux-gnu` with `-Xcc -I...` to the Swift build so OpenSSL's
architecture-specific configuration headers resolve. Keep caches/builds outside
source directories. The optional build environment must not replace system files.

Exit 0 means all listed controls passed. Exit 77 means blocked/failed and does not
satisfy a simulator or hardware gate. The report sets `hardwareTPMTested: false`,
`productionSwiftBridgeTested: false`, `nativeSwiftProviderSignTested: true` and
`nativeSwiftTLSProbeTested: true` only after a successful run. It proves neither
physical TPM custody, Android interoperability, production certificates, protected
identity storage nor production command approval. No historical hardware fixture
is read or reused.

The Ubuntu 24.04 Linux Swift CI job also builds this probe and requires the private
simulator run. It uses distro development/provider/tool dependencies and extracts
checksum-pinned `tpm2-abrmd` 3.0.0-1ubuntu2 into a private prefix; its service is not
installed or activated. The harness launches only its own session bus, resource
manager and simulator. Missing prerequisites, exit 77 and failed controls fail the
job. Only the sanitized JSON report is uploaded. Local OpenSSL 3.5 simulator results
and compilation against Ubuntu 24.04 OpenSSL 3.0 headers do not establish that CI
run's success; its actual result must be checked separately.

Primary API references: [key loading with a library context](https://docs.openssl.org/3.5/man3/OSSL_STORE_open/),
[provider-backed message signing](https://docs.openssl.org/3.5/man3/EVP_DigestSignInit/),
[TLS context/provider selection](https://docs.openssl.org/3.5/man3/SSL_CTX_new/), and
[TPM provider key behavior](https://github.com/tpm2-software/tpm2-openssl/blob/1.3.0/docs/keys.md).
