import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class TransportWakeAuthorizationTests: XCTestCase, @unchecked Sendable {
    private final class Flag: Sendable { let value = Mutex(true) }
    private final class Counter: Sendable { let value = Mutex(0) }
    private struct Revoked: Error {}
    private final class GatewayDriver: GatewayWakeDriver, Sendable {
        let calls = Mutex([String]())
        let hello: @Sendable () -> Void
        let challenge: @Sendable () -> Void
        let accepted: @Sendable () -> Void
        init(hello: @escaping @Sendable () -> Void = {}, challenge: @escaping @Sendable () -> Void = {}, accepted: @escaping @Sendable () -> Void = {}) {
            self.hello = hello; self.challenge = challenge; self.accepted = accepted
        }
        func start(closed: @escaping @Sendable () -> Void) {}
        func close() { calls.withLock { $0.append("close") } }
        func invoke(_ call: GatewayWakeCall, reply: @escaping @Sendable (GatewayWakeResponse) -> Void) {
            switch call {
            case .hello: calls.withLock { $0.append("hello") }; hello(); reply(.version(1))
            case .challenge: calls.withLock { $0.append("challenge") }; challenge(); reply(.challenge(Data(repeating: 1, count: 32)))
            case .wake: calls.withLock { $0.append("wake") }; accepted(); reply(.accepted(true))
            }
        }
    }
    private final class HintDriver: AuthorityWakeHintDriver, Sendable {
        let bytes: Data
        let read: @Sendable () -> Void
        let handshake: @Sendable () -> Void
        let calls = Mutex([String]())
        init(bytes: Data, read: @escaping @Sendable () -> Void = {}, handshake: @escaping @Sendable () -> Void = {}) {
            self.bytes = bytes; self.read = read; self.handshake = handshake
        }
        func start(closed: @escaping @Sendable () -> Void) {}
        func close() { calls.withLock { $0.append("close") } }
        func invoke(_ call: AuthorityWakeHintCall, reply: @escaping @Sendable (AuthorityWakeHintResponse) -> Void) {
            switch call {
            case .hello, .version: calls.withLock { $0.append("version") }; handshake(); reply(.version(1))
            case .hints: calls.withLock { $0.append("hints") }; read(); reply(.hints(bytes))
            }
        }
    }
    private func binding() throws -> GatewaySubmissionBinding {
        let id = Data(repeating: 2, count: 16)
        return try .init(ownerID: id, macID: id, accountID: id, gatewayID: id, lifecycleEpoch: id)
    }
    func testRevocationWhileAwaitingChallengePreventsAnySignatureOrWake() async throws {
        let live = Flag(), signatures = Counter(), driver = GatewayDriver(challenge: { live.value.withLock { $0 = false } })
        let channel = GatewayWakeChannel(driver: driver, verifyAccount: { guard live.value.withLock({ $0 }) else { throw Revoked() } })
        try await channel.start()
        do {
            try await channel.wake(binding: binding(), credentialID: Data(repeating: 3, count: 16), deliveryID: UUID(), sign: { _ in
                signatures.value.withLock { $0 += 1 }; return Data(repeating: 1, count: 64)
            }); XCTFail()
        } catch { XCTAssertTrue(error is Revoked) }
        XCTAssertEqual(signatures.value.withLock { $0 }, 0); XCTAssertFalse(driver.calls.withLock { $0.contains("wake") })
        XCTAssertTrue(driver.calls.withLock { $0.contains("close") })
    }
    func testRevocationDuringSignaturePreventsSubmission() async throws {
        let live = Flag(), driver = GatewayDriver()
        let channel = GatewayWakeChannel(driver: driver, verifyAccount: { guard live.value.withLock({ $0 }) else { throw Revoked() } })
        try await channel.start()
        do {
            try await channel.wake(binding: binding(), credentialID: Data(repeating: 3, count: 16), deliveryID: UUID(), sign: { _ in
                live.value.withLock { $0 = false }; return Data(repeating: 1, count: 64)
            }); XCTFail()
        } catch { XCTAssertTrue(error is Revoked) }
        XCTAssertFalse(driver.calls.withLock { $0.contains("wake") })
    }
    func testRevokedWakeResponseCannotBecomeSuccessfulLocalAcceptance() async throws {
        let live = Flag(), driver = GatewayDriver(accepted: { live.value.withLock { $0 = false } })
        let channel = GatewayWakeChannel(driver: driver, verifyAccount: { guard live.value.withLock({ $0 }) else { throw Revoked() } })
        try await channel.start()
        do {
            try await channel.wake(binding: binding(), credentialID: Data(repeating: 3, count: 16), deliveryID: UUID(), sign: { _ in Data(repeating: 1, count: 64) }); XCTFail()
        } catch { XCTAssertTrue(error is Revoked) }
        XCTAssertTrue(driver.calls.withLock { $0.contains("close") })
    }
    func testRevokedHintResponseCannotEscapeAsCurrentGrants() async throws {
        let live = Flag(), binding = try binding()
        let driver = try HintDriver(bytes: AuthorityWakeHints(binding: binding, deliveryIDs: [UUID()]).encode(), read: { live.value.withLock { $0 = false } })
        let channel = AuthorityWakeHintChannel(driver: driver, binding: binding, verifyAccount: { guard live.value.withLock({ $0 }) else { throw Revoked() } })
        try await channel.start()
        do { _ = try await channel.current(); XCTFail() } catch { XCTAssertTrue(error is Revoked) }
        XCTAssertTrue(driver.calls.withLock { $0.contains("close") })
    }
    private func signer(_ binding: GatewaySubmissionBinding) throws -> GatewayWakeSigner {
        let key = P256.Signing.PrivateKey(), credential = Data(repeating: 3, count: 16)
        let configuration = try GatewayWakeSignerConfiguration(binding: binding, credentialID: credential, transportUID: 401,
            ownerUID: 501, gatewayUID: 402, serviceName: "dev.remozio.gateway.wake", teamID: "TEAMID1234",
            gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [Data(repeating: 4, count: 20)],
            custody: .protectedFile, keyRecordPath: "/Library/Remozio/transport/wake.cbor", publicKey: key.publicKey.x963Representation)
        let record = try GatewayWakeKeyRecord(binding: binding, credentialID: credential, fileKey: key)
        return try GatewayWakeSigner.load(configuration: configuration, realUID: 401, effectiveUID: 401,
            read: { _, _ in try record.encode() })
    }
    func testRuntimeGuardRejectsBeforeStartingAnyChannel() async throws {
        let binding = try binding(), hints = try HintDriver(bytes: AuthorityWakeHints(binding: binding, deliveryIDs: []).encode())
        let gateway = GatewayDriver()
        let runtime = try TransportWakeRuntime(hints: .init(driver: hints, binding: binding), gateway: .init(driver: gateway),
            signer: signer(binding), verifyCurrent: { throw Revoked() })
        do { try await runtime.start(); XCTFail() } catch { XCTAssertTrue(error is Revoked) }
        XCTAssertTrue(hints.calls.withLock { $0.isEmpty }); XCTAssertTrue(gateway.calls.withLock { $0.isEmpty })
        await runtime.close()
    }
    func testRuntimeGuardAfterHintResponsePreventsChallengeEvenWithIndependentChannelGuards() async throws {
        let binding = try binding(), live = Flag()
        let hints = try HintDriver(bytes: AuthorityWakeHints(binding: binding, deliveryIDs: [UUID()]).encode(),
            read: { live.value.withLock { $0 = false } }), gateway = GatewayDriver()
        let runtime = try TransportWakeRuntime(hints: .init(driver: hints, binding: binding), gateway: .init(driver: gateway),
            signer: signer(binding), verifyCurrent: { guard live.value.withLock({ $0 }) else { throw Revoked() } })
        try await runtime.start()
        do { try await runtime.poll(); XCTFail() } catch { XCTAssertTrue(error is Revoked) }
        XCTAssertFalse(gateway.calls.withLock { $0.contains("challenge") }); XCTAssertTrue(gateway.calls.withLock { $0.contains("close") })
        await runtime.close()
    }
    func testNativeRuntimeConstructionRejectsOrdinaryAccountBeforeGuardOrPrivateKeyRestoration() throws {
        let binding = try binding()
        let transport = try ApprovalTransportConfiguration(macID: binding.macID, accountID: binding.accountID,
            ownerUID: 501, serviceUID: 401, authorityServiceName: "dev.remozio.authority", teamID: "TEAMID1234",
            authorityIdentifier: "dev.remozio.authority", authorityHashes: [Data(repeating: 4, count: 20)],
            identityReference: Data([1]), identityPublicKeyInfo: P256.Signing.PrivateKey().publicKey.derRepresentation)
        let wake = try GatewayWakeSignerConfiguration(binding: binding, credentialID: Data(repeating: 3, count: 16), transportUID: 401,
            ownerUID: 501, gatewayUID: 402, serviceName: "dev.remozio.gateway.wake", teamID: "TEAMID1234",
            gatewayIdentifier: "dev.remozio.gateway", gatewayHashes: [Data(repeating: 4, count: 20)],
            custody: .protectedFile, keyRecordPath: "/Library/Remozio/transport/wake.cbor", publicKey: P256.Signing.PrivateKey().publicKey.x963Representation)
        let configuration = try TransportWakeStartupConfiguration(transport: transport, wake: wake)
        XCTAssertThrowsError(try configuration.makeRuntime(verifyCurrent: { XCTFail("Native process admission must run first") })) {
            XCTAssertEqual($0 as? ApprovalTransportStartupError, .wrongAccount)
        }
    }

    func testRevokedGatewayHandshakeCannotOpenTheChannel() async throws {
        let live = Flag(), driver = GatewayDriver(hello: { live.value.withLock { $0 = false } })
        let channel = GatewayWakeChannel(driver: driver, verifyAccount: {
            guard live.value.withLock({ $0 }) else { throw Revoked() }
        })
        do { try await channel.start(); XCTFail() } catch { XCTAssertTrue(error is Revoked) }
        XCTAssertEqual(driver.calls.withLock { $0 }, ["hello", "close"])
    }
    func testRevokedFinalHintHandshakeCannotOpenTheChannel() async throws {
        let live = Flag(), count = Counter(), binding = try binding()
        let driver = try HintDriver(bytes: AuthorityWakeHints(binding: binding, deliveryIDs: []).encode(), handshake: {
            if count.value.withLock({ $0 += 1; return $0 }) == 2 { live.value.withLock { $0 = false } }
        })
        let channel = AuthorityWakeHintChannel(driver: driver, binding: binding, verifyAccount: {
            guard live.value.withLock({ $0 }) else { throw Revoked() }
        })
        do { try await channel.start(); XCTFail() } catch { XCTAssertTrue(error is Revoked) }
        XCTAssertEqual(driver.calls.withLock { $0 }, ["version", "version", "close"])
    }
}
