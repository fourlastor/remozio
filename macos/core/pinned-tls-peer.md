# Mac TLS peer pin policy

`PinnedTLSPeer` checks the leaf certificate against a canonical P-256 DER SubjectPublicKeyInfo pin. The pin must come from an authenticated enrollment. It must never come from the connection being checked.

The policy accepts a renewed certificate with the same public key. It checks the leaf validity interval, including both endpoints. Empty, malformed, oversized, wrong-key, wrong-curve, expired, and future certificates fail. A nonfinite verification time also fails.

The Security framework parses the presented leaf certificate and extracts its public key and dates.
The policy does not evaluate system certificate authority (CA) trust, match DNS names, fetch certificates, or fall back to another authority.
An outer HTTPS relay still requires ordinary CA and hostname checks.

A successful result is only the certificate check. The TLS implementation must still prove possession of the corresponding private key. It must enforce TLS 1.3, mutual authentication, the expected ALPN, and the early-data and resumption restrictions. The owner must separately check current enrollment, account, role, protocol compatibility, and request authority. A pin does not authorize an approval or survive revocation by itself.

The synthetic `TLSPeer` listener now uses this policy in its Network.framework verification callback. It extracts the first presented certificate directly from TLS metadata, without accessing a `SecTrust` chain. Its controller supplies a disposable phone SPKI pin. No app listener, enrollment store, or production identity is configured by this change.

Native tests use public certificate fixtures and explicit verification dates. They cover renewal, validity boundaries, malformed inputs, other keys, and wrong-curve pins. The JVM/native tests also reject expired and future client certificates during actual loopback handshakes. Device keys, real enrollment changes, relay deployment, and production channel ownership remain untested.

Apple API references: [certificate key](https://developer.apple.com/documentation/security/seccertificatecopykey(_:)), [validity start](https://developer.apple.com/documentation/security/seccertificatecopynotvalidbeforedate(_:)), and [validity end](https://developer.apple.com/documentation/security/seccertificatecopynotvalidafterdate(_:)).
