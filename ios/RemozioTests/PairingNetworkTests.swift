import CryptoKit
import Network
@testable import Remozio
import RemozioUI
import Security
import X509
import XCTest

/// Native checks for the pairing transport: the service name, the client certificate, the pin predicate, and real
/// TLS 1.3 handshakes against a local Network.framework server.
final class PairingNetworkTests: XCTestCase {
    private static let prefix = Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00])

    func testServiceNameIsUnpaddedBase64URL() {
        XCTAssertEqual(PairingServiceName.make(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16)),
                       "R-AQEBAQEBAQEBAQEBAQEBAQ-AgICAgICAgICAgICAgICAg")
        XCTAssertEqual(PairingServiceName.base64URL(Data([0xfb, 0xff])), "-_8")
        XCTAssertLessThanOrEqual(PairingServiceName.make(macID: Data(count: 16), accountID: Data(count: 16)).utf8.count,
                                 PairingServiceName.maximumBytes)
    }

    func testClientCertificateUsesTheTransportProfile() throws {
        let key = P256.Signing.PrivateKey()
        let now = Date()
        let certificate = try Certificate(Self.certificate(of: PairingClientIdentity.make(key.secKey, now: now)))
        let name = try DistinguishedName { CommonName("Remozio transport") }
        XCTAssertEqual(certificate.subject, name)
        XCTAssertEqual(certificate.issuer, name)
        XCTAssertTrue(certificate.notValidBefore <= now && now < certificate.notValidAfter)
        XCTAssertEqual(try certificate.extensions.basicConstraints, .notCertificateAuthority)
        XCTAssertEqual(try certificate.extensions.keyUsage, KeyUsage(digitalSignature: true))
        XCTAssertEqual(try certificate.extensions.extendedKeyUsage, try ExtendedKeyUsage([.serverAuth, .clientAuth]))
        XCTAssertTrue(certificate.extensions.allSatisfy { $0.critical == ($0.oid != .X509ExtensionID.extendedKeyUsage) })
        XCTAssertTrue(certificate.publicKey.isValidSignature(certificate.signature, for: certificate))
        XCTAssertEqual(P256.Signing.PublicKey(certificate.publicKey)?.x963Representation, key.publicKey.x963Representation)
    }

    func testThePinAcceptsOnlyOneLeafWithTheExactKey() throws {
        let key = P256.Signing.PrivateKey(), other = P256.Signing.PrivateKey()
        let leaf = try Self.certificate(of: PairingClientIdentity.make(key.secKey))
        let second = try Self.certificate(of: PairingClientIdentity.make(other.secKey))
        let pin = Self.prefix + key.publicKey.x963Representation
        XCTAssertTrue(NetworkPairingTransport.matches(chain: [leaf], pin: pin, at: Date()))
        XCTAssertFalse(NetworkPairingTransport.matches(chain: [second], pin: pin, at: Date()))
        XCTAssertFalse(NetworkPairingTransport.matches(chain: [leaf, second], pin: pin, at: Date()))
        var flipped = pin; flipped[0] ^= 1
        XCTAssertFalse(NetworkPairingTransport.matches(chain: [leaf], pin: flipped, at: Date()))
        XCTAssertFalse(NetworkPairingTransport.matches(chain: [leaf], pin: pin.dropLast(), at: Date()))
        XCTAssertFalse(NetworkPairingTransport.matches(chain: [], pin: pin, at: Date()))
        // The window is now - 300 s to now + 3300 s, in whole seconds.
        let expired = try Self.certificate(of: PairingClientIdentity.make(key.secKey, now: Date().addingTimeInterval(-7_200)))
        let future = try Self.certificate(of: PairingClientIdentity.make(key.secKey, now: Date().addingTimeInterval(7_200)))
        XCTAssertFalse(NetworkPairingTransport.matches(chain: [expired], pin: pin, at: Date()))
        XCTAssertFalse(NetworkPairingTransport.matches(chain: [future], pin: pin, at: Date()))
    }

    func testRightPinOpensAndCarriesBytesWithTheTransportKey() throws {
        let server = try LocalServer(alpn: "remozio-pairing/1")
        let key = P256.Signing.PrivateKey()
        let events = Recorder(self, expectBytes: true)
        let transport = try server.transport(pin: Self.prefix + server.key.publicKey.x963Representation, key: key)
        transport.start(events: events)
        wait(for: [events.openedExpectation], timeout: 10)
        transport.requestBytes()
        wait(for: [try XCTUnwrap(events.receivedExpectation)], timeout: 10)
        XCTAssertEqual(events.received, [Data("hi".utf8)])
        XCTAssertEqual(server.clientPoint, key.publicKey.x963Representation)
        transport.cancel()
        wait(for: [events.closedExpectation], timeout: 10)
        XCTAssertEqual(events.closedCount, 1)
    }

    func testWrongPinNeverOpens() throws {
        let server = try LocalServer(alpn: "remozio-pairing/1")
        let events = Recorder(self, expectOpen: false)
        let transport = try server.transport(pin: Self.prefix + P256.Signing.PrivateKey().publicKey.x963Representation,
                                             key: P256.Signing.PrivateKey())
        transport.start(events: events)
        wait(for: [events.closedExpectation], timeout: 10)
        wait(for: [events.openedExpectation], timeout: 0.5)
        XCTAssertEqual(events.closedCount, 1)
        XCTAssertNotNil(events.closedError)
    }

    func testWrongProtocolNeverOpens() throws {
        let server = try LocalServer(alpn: "remozio-other/1")
        let events = Recorder(self, expectOpen: false)
        let transport = try server.transport(pin: Self.prefix + server.key.publicKey.x963Representation,
                                             key: P256.Signing.PrivateKey())
        transport.start(events: events)
        wait(for: [events.closedExpectation], timeout: 10)
        wait(for: [events.openedExpectation], timeout: 0.5)
        XCTAssertEqual(events.closedCount, 1)
    }

    func testATypedAddressWinsOverTheDebugOverride() {
        XCTAssertEqual(NativePhoneServices.endpoint(address: ComputerAddress(host: "192.0.2.10", port: 7443), override: "198.51.100.1:9"),
                       .hostPort(host: "192.0.2.10", port: 7443))
        XCTAssertEqual(NativePhoneServices.endpoint(address: ComputerAddress(host: "fd7a:115c:a1e0::1", port: 7443), override: nil),
                       .hostPort(host: NWEndpoint.Host("fd7a:115c:a1e0::1"), port: 7443))
    }

    func testTheDebugOverrideAppliesOnlyWithoutAnAddress() {
        XCTAssertEqual(NativePhoneServices.endpoint(address: nil, override: "[fd7a::1]:7443"),
                       .hostPort(host: NWEndpoint.Host("fd7a::1"), port: 7443))
    }

    func testAnOutOfRangeTypedPortNeverFallsBackToBonjour() {
        XCTAssertEqual(NativePhoneServices.endpoint(address: ComputerAddress(host: "192.0.2.10", port: 70_000), override: "[fd7a::1]:7443"),
                       .hostPort(host: "192.0.2.10", port: .any))
    }

    func testNoAddressMeansBonjourDiscovery() {
        XCTAssertNil(NativePhoneServices.endpoint(address: nil, override: nil))
        XCTAssertNil(NativePhoneServices.endpoint(address: nil, override: "no-port"))
    }

    func testCancelBeforeStartReportsClosedOnStart() {
        let events = Recorder(self, expectOpen: false)
        let transport = NetworkPairingTransport(target: .fixed(.hostPort(host: "127.0.0.1", port: 9)),
            pin: Self.prefix + P256.Signing.PrivateKey().publicKey.x963Representation,
            applicationProtocol: "remozio-pairing/1", identity: { try PairingClientIdentity.make(P256.Signing.PrivateKey().secKey) })
        transport.cancel()
        transport.start(events: events)
        wait(for: [events.closedExpectation], timeout: 10)
        wait(for: [events.openedExpectation], timeout: 0.5)
        XCTAssertEqual(events.closedError, "cancelled")
    }

    func testASoftwareKeyIsNotAcceptedAsAnEnclaveKey() {
        XCTAssertThrowsError(try PairingTransportKey.requireEnclave(P256.Signing.PrivateKey().secKey))
    }

    func testTheProposedKeyIsTheKeyTheTransportPresents() throws {
        let server = try LocalServer(alpn: "remozio-pairing/1")
        let keys = NativePairingKeys(endpoint: try server.endpoint())
        let events = Recorder(self, expectBytes: true)
        let transport = keys.openTransport(macID: Self.bytes(16), accountID: Self.bytes(16),
            pin: PairingBytesKt.pairingBytes(data: Self.prefix + server.key.publicKey.x963Representation),
            applicationProtocol: "remozio-pairing/1")
        transport.start(events: events)
        wait(for: [events.openedExpectation], timeout: 10)
        // TLS 1.3 opens the client before the server reads its certificate. The first bytes come after that.
        transport.requestBytes()
        wait(for: [try XCTUnwrap(events.receivedExpectation)], timeout: 10)
        let proposed = PairingBytesKt.pairingData(bytes: keys.transportPublicKey)
        XCTAssertEqual(proposed.count, 65)
        XCTAssertEqual(server.clientPoint, proposed)
        transport.cancel()
        wait(for: [events.closedExpectation], timeout: 10)
    }

    func testNoKeyMeansNoConnectionToAnAddress() throws {
        let server = try LocalServer(alpn: "remozio-pairing/1")
        let keys = NativePairingKeys(endpoint: try server.endpoint(), makeTransportKey: { throw PairingTransportKey.Failure.refused })
        XCTAssertEqual(PairingBytesKt.pairingData(bytes: keys.transportPublicKey).count, 65)
        XCTAssertEqual(PairingBytesKt.pairingData(bytes: keys.transportPublicKey), PairingBytesKt.pairingData(bytes: keys.transportPublicKey))
        let events = Recorder(self, expectOpen: false)
        keys.openTransport(macID: Self.bytes(16), accountID: Self.bytes(16),
            pin: PairingBytesKt.pairingBytes(data: Self.prefix + server.key.publicKey.x963Representation),
            applicationProtocol: "remozio-pairing/1").start(events: events)
        wait(for: [events.closedExpectation], timeout: 10)
        wait(for: [events.openedExpectation], timeout: 0.5)
        XCTAssertEqual(events.closedError, "identity failed")
        XCTAssertEqual(server.connections, 0)
    }

    func testNoKeyStopsBeforeDiscovery() {
        assertStopsBeforeDiscovery(NativePairingKeys(makeTransportKey: { throw PairingTransportKey.Failure.refused }))
    }

    func testAKeyWithNoP256PointStopsBeforeDiscovery() throws {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 384]
        let wrong = try XCTUnwrap(SecKeyCreateWithData(P384.Signing.PrivateKey().x963Representation as CFData, attributes as CFDictionary, nil))
        assertStopsBeforeDiscovery(NativePairingKeys(makeTransportKey: { wrong }))
    }

    private func assertStopsBeforeDiscovery(_ keys: NativePairingKeys) {
        let events = Recorder(self, expectOpen: false)
        keys.openTransport(macID: Self.bytes(16), accountID: Self.bytes(16),
            pin: PairingBytesKt.pairingBytes(data: Self.prefix + P256.Signing.PrivateKey().publicKey.x963Representation),
            applicationProtocol: "remozio-pairing/1").start(events: events)
        // Discovery would wait for a service that does not exist, so a close inside this limit means it never started.
        wait(for: [events.closedExpectation], timeout: 2)
        wait(for: [events.openedExpectation], timeout: 0.2)
        XCTAssertEqual(events.closedError, "identity failed")
    }

    // MARK: - Helpers

    static func bytes(_ count: Int) -> KotlinByteArray { PairingBytesKt.pairingBytes(data: Data(repeating: 1, count: count)) }

    static func certificate(of identity: SecIdentity) throws -> SecCertificate {
        var certificate: SecCertificate?
        XCTAssertEqual(SecIdentityCopyCertificate(identity, &certificate), errSecSuccess)
        return try XCTUnwrap(certificate)
    }

}

private extension P256.Signing.PrivateKey {
    /// The same software key as a `SecKey`, the type the production signer takes.
    var secKey: SecKey {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits: 256]
        return SecKeyCreateWithData(x963Representation as CFData, attributes as CFDictionary, nil)!
    }
}

private final class Recorder: NSObject, PairingTransportEvents {
    let openedExpectation: XCTestExpectation
    let receivedExpectation: XCTestExpectation?
    let closedExpectation: XCTestExpectation
    private let lock = NSLock()
    private(set) var received: [Data] = []
    private(set) var closedCount = 0
    private(set) var closed = false
    private(set) var closedError: String?

    init(_ test: XCTestCase, expectOpen: Bool = true, expectBytes: Bool = false) {
        openedExpectation = test.expectation(description: "opened")
        openedExpectation.isInverted = !expectOpen
        receivedExpectation = expectBytes ? test.expectation(description: "received") : nil
        closedExpectation = test.expectation(description: "closed")
    }

    func opened() { openedExpectation.fulfill() }

    func received(bytes: KotlinByteArray) {
        lock.withLock { received.append(PairingBytesKt.pairingData(bytes: bytes)) }
        receivedExpectation?.fulfill()
    }

    func closed(error: String?) {
        lock.withLock { closedCount += 1; closed = true; closedError = error }
        closedExpectation.fulfill()
    }
}

/// A TLS 1.3 server with a pairing-profile identity. It requires a client certificate, records its key, and sends "hi".
private final class LocalServer {
    let key = P256.Signing.PrivateKey()
    private let queue = DispatchQueue(label: "dev.remozio.tests.server")
    private let listener: NWListener
    private let box: PointBox
    var clientPoint: Data? { box.get() }
    var connections: Int { box.connections() }

    init(alpn: String) throws {
        let identity = try PairingClientIdentity.make(key.secKey)
        let box = PointBox()
        self.box = box
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
        sec_protocol_options_add_tls_application_protocol(options, alpn)
        sec_protocol_options_set_local_identity(options, sec_identity_create(identity)!)
        sec_protocol_options_set_peer_authentication_required(options, true)
        // The options are copied into the parameters, so the verify block comes first. The box breaks the cycle
        // between the block and self.
        sec_protocol_options_set_verify_block(options, { metadata, _, complete in
            _ = sec_protocol_metadata_access_peer_certificate_chain(metadata) { certificate in
                if let key = SecCertificateCopyKey(sec_certificate_copy_ref(certificate).takeRetainedValue()),
                   let point = SecKeyCopyExternalRepresentation(key, nil) as Data? { box.set(point) }
            }
            complete(true)
        }, queue)
        listener = try NWListener(using: NWParameters(tls: tls), on: .any)
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
        listener.newConnectionHandler = { [queue] connection in
            box.connected()
            connection.stateUpdateHandler = { state in
                if case .ready = state { connection.send(content: Data("hi".utf8), completion: .idempotent) }
            }
            connection.start(queue: queue)
        }
        listener.start(queue: queue)
        guard ready.wait(timeout: .now() + 10) == .success else { throw URLError(.timedOut) }
    }

    deinit { listener.cancel() }

    func endpoint() throws -> NWEndpoint { .hostPort(host: "127.0.0.1", port: try XCTUnwrap(listener.port)) }

    func transport(pin: Data, key: P256.Signing.PrivateKey) throws -> NetworkPairingTransport {
        NetworkPairingTransport(target: .fixed(try endpoint()), pin: pin,
            applicationProtocol: "remozio-pairing/1", identity: { try PairingClientIdentity.make(key.secKey) })
    }
}

private final class PointBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Data?
    private var count = 0
    func set(_ point: Data) { lock.withLock { if value == nil { value = point } } }
    func get() -> Data? { lock.withLock { value } }
    func connected() { lock.withLock { count += 1 } }
    func connections() -> Int { lock.withLock { count } }
}
