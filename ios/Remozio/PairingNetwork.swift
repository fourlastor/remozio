import CryptoKit
import Foundation
import Network
import os
import RemozioUI
import Security
import X509

/// Stages and error codes only. Never key data or addresses.
private let pairingLog = Logger(subsystem: "dev.remozio.pairing", category: "transport")

/// The three P-256 keys of one setup attempt, all temporary: nothing is stored in the keychain or on disk.
/// The transport key signs the TLS client certificate, so the proposal and the handshake always carry the same key.
final class NativePairingKeys: NSObject, PlatformPairingKeys {
    private let transport: Result<SecKey, Error>
    private let transportPoint: Data
    private let decision = P256.Signing.PrivateKey()
    private let biometric = P256.Signing.PrivateKey()
    /// Test builds may connect to a fixed address instead of browsing. Nil browses for the advertised service.
    private let endpoint: NWEndpoint?

    init(endpoint: NWEndpoint? = nil, makeTransportKey: () throws -> SecKey = PairingTransportKey.make) {
        self.endpoint = endpoint
        do {
            let key = try makeTransportKey()
            transportPoint = try PairingTransportKey.point(of: key)
            transport = .success(key)
        } catch {
            // This point only fills the proposal object. The transport stops before it opens, so it never leaves the phone.
            transportPoint = P256.Signing.PrivateKey().publicKey.x963Representation
            transport = .failure(error)
        }
    }

    var transportPublicKey: KotlinByteArray { PairingBytesKt.pairingBytes(data: transportPoint) }
    var decisionPublicKey: KotlinByteArray { PairingBytesKt.pairingBytes(data: decision.publicKey.x963Representation) }
    var biometricPublicKey: KotlinByteArray { PairingBytesKt.pairingBytes(data: biometric.publicKey.x963Representation) }

    func openTransport(macID: KotlinByteArray, accountID: KotlinByteArray, pin: KotlinByteArray,
                       applicationProtocol: String) -> PairingTransport {
        let target = endpoint.map(NetworkPairingTransport.Target.fixed) ?? .service(PairingServiceName.make(
            macID: PairingBytesKt.pairingData(bytes: macID), accountID: PairingBytesKt.pairingData(bytes: accountID)))
        return NetworkPairingTransport(target: target, pin: PairingBytesKt.pairingData(bytes: pin),
            applicationProtocol: applicationProtocol, identity: { [transport] in try PairingClientIdentity.make(transport.get()) })
    }

    override var description: String { "NativePairingKeys(redacted)" }
}

/// `R-` and the unpadded base64url Mac and account IDs: the name the computer advertises for setup.
enum PairingServiceName {
    static let type = "_remozio-pairing._tcp"

    /// DNS-SD instance names are at most 63 bytes. 16-byte IDs give 47.
    static let maximumBytes = 63

    static func make(macID: Data, accountID: Data) -> String {
        "R-\(base64URL(macID))-\(base64URL(accountID))"
    }

    static func base64URL(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// The transport key of one setup attempt, held only in memory. On a phone it is a Secure Enclave key, and nothing
/// replaces it: if the enclave refuses, the attempt fails. The simulator has no enclave, so it uses a software key.
enum PairingTransportKey {
    enum Failure: Error { case refused }

    static func make() throws -> SecKey {
        var error: Unmanaged<CFError>?
        #if targetEnvironment(simulator)
        let placement: [CFString: Any] = [kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false]]
        #else
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                           .privateKeyUsage, &error) else {
            throw refused("access control", error)
        }
        let placement: [CFString: Any] = [kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false, kSecAttrAccessControl: access]]
        #endif
        let attributes = placement.merging([kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256]) { $1 }
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else { throw refused("creation", error) }
        #if !targetEnvironment(simulator)
        try requireEnclave(key)
        pairingLog.notice("transport key: in the Secure Enclave, export refused")
        #endif
        return key
    }

    /// The two checks of the Mac enclave probe. With them, a completed handshake on a phone proves where the key is.
    static func requireEnclave(_ key: SecKey) throws {
        let attributes = SecKeyCopyAttributes(key) as? [String: Any]
        guard attributes?[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String else {
            throw refused("token check", nil)
        }
        guard SecKeyCopyExternalRepresentation(key, nil) == nil else { throw refused("export check", nil) }
    }

    /// The 65-byte uncompressed public point.
    static func point(of key: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(key),
              let point = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?, point.count == 65 else {
            throw refused("public key", nil)
        }
        return point
    }

    private static func refused(_ stage: String, _ error: Unmanaged<CFError>?) -> Failure {
        let code = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? 0
        pairingLog.error("transport key: \(stage, privacy: .public) failed, code \(code, privacy: .public)")
        return .refused
    }
}

/// A self-signed leaf in the transport profile the computers expect, held only in memory.
enum PairingClientIdentity {
    enum Failure: Error { case certificate, identity }

    static func make(_ key: SecKey, now: Date = Date()) throws -> SecIdentity {
        let signer = try Certificate.PrivateKey(key)
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
        guard let identity = SecIdentityCreate(nil, native509, key) else { throw Failure.identity }
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
    // Apple advises a queue other than the connection's for the verify block.
    private let verifyQueue = DispatchQueue(label: "dev.remozio.pairing.verify")
    private let target: Target
    private let pin: Data
    private let applicationProtocol: String
    private let identity: () throws -> SecIdentity
    private var events: PairingTransportEvents?
    private var browser: NWBrowser?
    private var connection: NWConnection?
    private var clientIdentity: sec_identity_t?
    private var cancelled = false
    private var finished = false
    private var open = false
    private var peerEnded = false
    private var receiving = false

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
            // Before discovery: a phone with no key stops now, not at the end of the setup budget.
            do {
                guard let made = sec_identity_create(try identity()) else { throw PairingClientIdentity.Failure.identity }
                clientIdentity = made
            } catch {
                pairingLog.error("client identity: \(String(reflecting: type(of: error)), privacy: .public) code \((error as NSError).code, privacy: .public)")
                return finish("identity failed")
            }
            switch target {
            case .fixed(let endpoint): connect(endpoint)
            case .service(let name):
                guard name.utf8.count <= PairingServiceName.maximumBytes else { return finish("service name too long") }
                browse(name)
            }
        }
    }

    func requestBytes() {
        queue.async { [self] in
            guard !finished, let connection, open, !receiving else { return }
            if peerEnded { return finish(nil) }
            receiving = true
            connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maximumDelivery) { [self] data, _, complete, error in
                queue.async { [self] in
                    receiving = false
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
        let parameters = NWParameters.tcp
        parameters.includePeerToPeer = false
        let browser = NWBrowser(for: .bonjour(type: PairingServiceName.type, domain: nil), using: parameters)
        self.browser = browser
        browser.stateUpdateHandler = { [self] state in
            queue.async { [self] in
                switch state {
                case .failed(let error): finish("discovery failed: \(error)")
                // Waiting is normal while iOS asks for local network access or has no path yet.
                // The shared setup budget ends the attempt if it never recovers.
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
        guard let secIdentity = clientIdentity else { return finish("identity failed") }
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_add_tls_application_protocol(options, applicationProtocol)
        sec_protocol_options_set_tls_tickets_enabled(options, false)
        sec_protocol_options_set_tls_resumption_enabled(options, false)
        sec_protocol_options_set_local_identity(options, secIdentity)
        let pin = pin
        // The chain the peer presented, not a chain built by trust evaluation, which can drop extra certificates.
        sec_protocol_options_set_verify_block(options, { metadata, _, complete in
            var chain: [SecCertificate] = []
            _ = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
                chain.append(sec_certificate_copy_ref(certificate).takeRetainedValue())
            }
            complete(Self.matches(chain: chain, pin: pin, at: Date()))
        }, verifyQueue)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        parameters.includePeerToPeer = false
        let connection = NWConnection(to: endpoint, using: parameters)
        self.connection = connection
        connection.stateUpdateHandler = { [self] state in
            queue.async { [self] in
                switch state {
                case .ready: ready(connection)
                case .failed(let error): finish("connection failed: \(error)")
                // A TLS refusal (a wrong pin, protocol or version) is final. Other waits retry within the budget.
                case .waiting(let error):
                    if case .tls = error { finish("connection refused: \(error)") }
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
        if let error { pairingLog.notice("transport closed: \(error, privacy: .public)") }
        browser?.cancel(); browser = nil
        connection?.cancel(); connection = nil
        clientIdentity = nil
        events?.closed(error: error)
        events = nil
    }

    /// Exactly one P-256 leaf, valid at [now], whose SubjectPublicKeyInfo equals the pin byte for byte.
    /// The JVM and Mac clients check the same validity window.
    static func matches(chain: [SecCertificate], pin: Data, at now: Date) -> Bool {
        guard chain.count == 1,
              let parsed = try? Certificate(chain[0]),
              parsed.notValidBefore <= now, now < parsed.notValidAfter,
              let key = SecCertificateCopyKey(chain[0]),
              let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              let point = SecKeyCopyExternalRepresentation(key, nil) as Data?, point.count == 65 else { return false }
        return spkiPrefix + point == pin
    }
}
