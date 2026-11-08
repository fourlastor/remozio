import CryptoKit
import Foundation
import Network
import RemozioUI
import Security
import X509

/// The three P-256 keys of one setup attempt. They exist only in this object: nothing goes to the keychain or to disk.
/// The transport key signs the TLS client certificate, so the proposal and the handshake always carry the same key.
final class NativePairingKeys: NSObject, PlatformPairingKeys {
    private let transport = P256.Signing.PrivateKey()
    private let decision = P256.Signing.PrivateKey()
    private let biometric = P256.Signing.PrivateKey()
    /// Test builds may connect to a fixed address instead of browsing. Nil browses for the advertised service.
    private let endpoint: NWEndpoint?

    init(endpoint: NWEndpoint? = nil) {
        self.endpoint = endpoint
    }

    var transportPublicKey: KotlinByteArray { PairingBytesKt.pairingBytes(data: transport.publicKey.x963Representation) }
    var decisionPublicKey: KotlinByteArray { PairingBytesKt.pairingBytes(data: decision.publicKey.x963Representation) }
    var biometricPublicKey: KotlinByteArray { PairingBytesKt.pairingBytes(data: biometric.publicKey.x963Representation) }

    func openTransport(macID: KotlinByteArray, accountID: KotlinByteArray, pin: KotlinByteArray,
                       applicationProtocol: String) -> PairingTransport {
        let target = endpoint.map(NetworkPairingTransport.Target.fixed) ?? .service(PairingServiceName.make(
            macID: PairingBytesKt.pairingData(bytes: macID), accountID: PairingBytesKt.pairingData(bytes: accountID)))
        return NetworkPairingTransport(target: target, pin: PairingBytesKt.pairingData(bytes: pin),
            applicationProtocol: applicationProtocol, identity: { [transport] in try PairingClientIdentity.make(transport) })
    }

    override var description: String { "NativePairingKeys(redacted)" }
}

/// `R-` and the unpadded base64url Mac and account IDs: the name the computer advertises for setup.
enum PairingServiceName {
    static let type = "_remozio-pairing._tcp"

    static func make(macID: Data, accountID: Data) -> String {
        "R-\(base64URL(macID))-\(base64URL(accountID))"
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// A self-signed leaf in the transport profile the computers expect, held only in memory.
enum PairingClientIdentity {
    enum Failure: Error { case key, certificate, identity }

    static func make(_ key: P256.Signing.PrivateKey, now: Date = Date()) throws -> SecIdentity {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256]
        guard let native = SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, nil) else {
            throw Failure.key
        }
        let signer = Certificate.PrivateKey(key)
        let name = try DistinguishedName { CommonName("Remozio transport") }
        // Whole seconds, with a small margin for clock skew between the phone and the computer.
        let start = Date(timeIntervalSince1970: (now.timeIntervalSince1970 - 300).rounded(.down))
        let certificate = try Certificate(version: .v3, serialNumber: .init(), publicKey: signer.publicKey,
            notValidBefore: start, notValidAfter: start.addingTimeInterval(3_600), issuer: name, subject: name,
            signatureAlgorithm: .ecdsaWithSHA256, extensions: Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.serverAuth, .clientAuth])
            }, issuerPrivateKey: signer)
        guard let native509 = try? SecCertificate.makeWithCertificate(certificate) else { throw Failure.certificate }
        guard let identity = SecIdentityCreate(nil, native509, native) else { throw Failure.identity }
        return identity
    }
}

/// Network.framework TLS 1.3 client for the pairing channel. See `PairingTransport` in the shared module for the
/// contract. All state lives on one serial queue.
final class NetworkPairingTransport: NSObject, PairingTransport {
    enum Target {
        case service(String)
        case fixed(NWEndpoint)
    }

    private static let maximumDelivery = Int(PairingTransportCompanion.shared.MAXIMUM_DELIVERY)
    private static let spkiPrefix = Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00])

    private let queue = DispatchQueue(label: "dev.remozio.pairing.transport")
    private let target: Target
    private let pin: Data
    private let applicationProtocol: String
    private let identity: () throws -> SecIdentity
    private var events: PairingTransportEvents?
    private var browser: NWBrowser?
    private var connection: NWConnection?
    private var cancelled = false
    private var finished = false
    private var open = false
    private var peerEnded = false

    init(target: Target, pin: Data, applicationProtocol: String, identity: @escaping () throws -> SecIdentity) {
        self.target = target
        self.pin = pin
        self.applicationProtocol = applicationProtocol
        self.identity = identity
    }

    func start(events: PairingTransportEvents) {
        queue.async { [self] in
            self.events = events
            guard !cancelled else { return finish("cancelled") }
            guard pin.count == 91, pin.prefix(26) == Self.spkiPrefix else { return finish("invalid pin") }
            switch target {
            case .fixed(let endpoint): connect(endpoint)
            case .service(let name): browse(name)
            }
        }
    }

    func requestBytes() {
        queue.async { [self] in
            guard !finished, let connection, open else { return }
            if peerEnded { return finish(nil) }
            connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maximumDelivery) { [self] data, _, complete, error in
                queue.async { [self] in
                    guard !finished else { return }
                    if let error { return finish("receive failed: \(error)") }
                    if complete { peerEnded = true }
                    if let data, !data.isEmpty {
                        events?.received(bytes: PairingBytesKt.pairingBytes(data: data))
                    } else if complete {
                        finish(nil)
                    } else {
                        finish("empty delivery")
                    }
                }
            }
        }
    }

    func send(bytes: KotlinByteArray, completion: PairingSendCompletion) {
        let data = PairingBytesKt.pairingData(bytes: bytes)
        queue.async { [self] in
            guard !finished, open, let connection else { return completion.done(error: "closed") }
            connection.send(content: data, completion: .contentProcessed { error in
                completion.done(error: error.map { "send failed: \($0)" })
            })
        }
    }

    func cancel() {
        queue.async { [self] in
            cancelled = true
            // Before start there is nobody to tell. start() reports closed when it sees the flag.
            if events != nil { finish("cancelled") }
        }
    }

    override var description: String { "NetworkPairingTransport(redacted)" }

    // MARK: - Queue-confined steps

    private func browse(_ name: String) {
        let browser = NWBrowser(for: .bonjour(type: PairingServiceName.type, domain: nil), using: .tcp)
        self.browser = browser
        browser.stateUpdateHandler = { [self] state in
            queue.async { [self] in
                switch state {
                case .failed(let error): finish("discovery failed: \(error)")
                case .waiting(let error): finish("discovery waiting: \(error)")
                default: break
                }
            }
        }
        browser.browseResultsChangedHandler = { [self] results, _ in
            queue.async { [self] in
                guard !finished, connection == nil else { return }
                let match = results.first { result in
                    if case .service(let found, _, _, _) = result.endpoint { return found == name }
                    return false
                }
                guard let match else { return }
                browser.cancel(); self.browser = nil
                connect(match.endpoint)
            }
        }
        browser.start(queue: queue)
    }

    private func connect(_ endpoint: NWEndpoint) {
        let local: SecIdentity
        do { local = try identity() } catch { return finish("identity failed") }
        guard let secIdentity = sec_identity_create(local) else { return finish("identity failed") }
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_add_tls_application_protocol(options, applicationProtocol)
        sec_protocol_options_set_tls_tickets_enabled(options, false)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_set_local_identity(options, secIdentity)
        let pin = pin
        sec_protocol_options_set_verify_block(options, { _, trust, complete in
            complete(Self.matches(trust: sec_trust_copy_ref(trust).takeRetainedValue(), pin: pin))
        }, queue)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.includePeerToPeer = false
        let connection = NWConnection(to: endpoint, using: parameters)
        self.connection = connection
        connection.stateUpdateHandler = { [self] state in
            queue.async { [self] in
                switch state {
                case .ready: ready(connection)
                case .failed(let error): finish("connection failed: \(error)")
                case .waiting(let error): finish("connection waiting: \(error)")
                default: break
                }
            }
        }
        connection.start(queue: queue)
    }

    private func ready(_ connection: NWConnection) {
        guard !finished, !open else { return }
        guard let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
            return finish("no TLS metadata")
        }
        let security = metadata.securityProtocolMetadata
        guard sec_protocol_metadata_get_negotiated_tls_protocol_version(security) == .TLSv13,
              let negotiated = sec_protocol_metadata_get_negotiated_protocol(security),
              String(cString: negotiated) == applicationProtocol else {
            return finish("wrong TLS version or protocol")
        }
        open = true
        events?.opened()
    }

    private func finish(_ error: String?) {
        guard !finished else { return }
        finished = true
        browser?.cancel(); browser = nil
        connection?.cancel(); connection = nil
        events?.closed(error: error)
        events = nil
    }

    /// Exactly one P-256 leaf whose SubjectPublicKeyInfo equals the pin byte for byte.
    static func matches(trust: SecTrust, pin: Data) -> Bool {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], chain.count == 1,
              let key = SecCertificateCopyKey(chain[0]),
              let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              let point = SecKeyCopyExternalRepresentation(key, nil) as Data?, point.count == 65 else { return false }
        return spkiPrefix + point == pin
    }
}
