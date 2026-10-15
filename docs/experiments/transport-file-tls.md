# File transport identity across processes

This experiment reloads one disposable transport identity in two fresh processes.
Each process uses the core file decoder, signs test data, and completes native mutual TLS 1.3 over IPv4 loopback.
The parent checks that neither process changes the identity file or its public-key pin.

[Recorded result](evidence/2026-10-10-transport-file-tls.json): both processes passed on macOS 27.0.1, build 26A434.
The report includes source hashes and explicitly leaves the production account and prelogin gates untested.

```mermaid
sequenceDiagram
    participant Runner as Ordinary-user runner
    participant Create as Fixture creator
    participant File as Private temporary files
    participant Child as Fresh probe process
    participant Client as Disposable TLS client
    Runner->>Create: Create software key and synthetic certificate
    Create->>File: Exclusive creation with mode 0600
    loop Two separate process launches
        Runner->>Child: Open the same private fixture
        Child->>File: Read with retained descriptors
        Child->>Child: Decode, check pin, and verify a native signature
        Child->>Client: Pinned mutual TLS 1.3 and exact echo
        Client-->>Child: Matching pinned peer and payload
        Client->>Child: Reject the wrong server pin
        Child-->>Runner: Metadata-only result
        Runner->>File: Check that identity and pin are unchanged
    end
    Runner->>Child: Refuse mode 0640 and a different identity pin
    Runner->>File: Remove the temporary directory
```

The TLS checks reuse the native exchange from the Secure Enclave experiment.
They require the experiment ALPN (`remozio-enclave-probe/1`) and reject early data.
Resumption and tickets are disabled.
A failed connection alone cannot pass the wrong-peer control.
The client verifier must record rejection before the probe reports success.

The file reader uses an ordinary-user fixture anchor.
It checks file mode, ownership, ACLs, links, and retained descriptor identity.
The core decoder checks the transport role, private key, certificate, configured pin, and certificate validity.
No Keychain search or import supplies the server identity.
All keys and certificates are disposable fixtures. The current creator calls the production transport file producer and typed certificate issuer.

The [15 October result](evidence/2026-10-15-transport-issued-file-tls.json) repeats these controls with the production producer.
The issuer uses Apple swift-certificates 1.21.0 and native Security.framework signing.
The generated leaf permits client and server authentication, prohibits certificate signing, and retains the existing P-256 pin format.
Unit tests cover renewal with the same key, wrong keys, invalid dates, and conservative whole-second validity encoding.
This adds no automatic renewal, custody selection UI, protected credential writer, or service activation.
The runtime caller must retain the selected identity. It must not generate another key during ordinary reload.

## Run

```sh
swift build --package-path experiments/key-custody --triple arm64-apple-macosx26.0 --disable-keychain --disable-netrc
python3 scripts/run-transport-file-tls-experiment.py
```

The native gate runs this software-only experiment after building the probe.
Run as an ordinary user in a debug build.
The creator refuses existing files and opens no socket.
Each TLS child binds an ephemeral loopback port and has a 15-second watchdog.
The Python owner also gives each child 25 seconds, then kills and reaps it on timeout.
The temporary-directory owner removes fixture files after success or failure.
It reports only assertions and runtime metadata, never keys, certificates, signatures, or temporary paths.

## Scope of the evidence

Success establishes software file persistence across process launches and native TLS signing after each reload.
It also establishes rejection of unsafe file permissions, a mismatched identity pin, and a mismatched TLS peer pin.
This is an experiment with the core identity decoder and byte channel, not an installed approval service.

It does not test production Root-owned ancestry, isolation from the interactive user, or a dedicated service account.
It does not test LaunchDaemon registration, Developer ID restrictions, login, logout, restart, or availability before login.
It does not test Android keys, the authority feed, request delivery, FCM, or the internet carrier.
Production activation still requires those applicable gates and explicit custody selection.
The app has no custody-selection or service-activation flow yet.
