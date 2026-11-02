import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class GatewayWakeChannelTests: XCTestCase, @unchecked Sendable {
    private final class Driver: GatewayWakeDriver {
        struct State {
            var calls: [GatewayWakeCall] = []
            var version: UInt64 = 1
            var challenge: Data? = Data(repeating: 1, count: 32)
            var accepted = true
            var closed = 0
            var hold = false
            var reply: (@Sendable (GatewayWakeResponse) -> Void)?
        }
        let value = Mutex(State())
        func start(closed: @escaping @Sendable () -> Void) {}
        func invoke(_ call: GatewayWakeCall, reply: @escaping @Sendable (GatewayWakeResponse) -> Void) {
            let result: GatewayWakeResponse? = value.withLock { state in
                state.calls.append(call)
                if state.hold { state.reply = reply; return nil }
                switch call {
                case .hello: return .version(state.version)
                case .challenge: return .challenge(state.challenge)
                case .wake: return .accepted(state.accepted)
                }
            }
            if let result { reply(result) }
        }
        func close() { value.withLock { $0.closed += 1 } }
    }
    private func binding() throws -> GatewaySubmissionBinding {
        let id = Data(repeating: 2, count: 16)
        return try GatewaySubmissionBinding(ownerID: id, macID: id, accountID: id, gatewayID: id, lifecycleEpoch: id)
    }
    private func wake(_ channel: GatewayWakeChannel, key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) async throws {
        try await channel.wake(binding: binding(), credentialID: Data(repeating: 3, count: 16), deliveryID: UUID(),
            sign: { try key.signature(for: $0).rawRepresentation })
    }
    func testHandshakeRejectsUnsupportedPeersBeforeSigningOrSensitiveSubmission() async throws {
        for version: UInt64 in [0, 2, UInt64.max] {
            let driver = Driver(), channel = GatewayWakeChannel(driver: driver)
            driver.value.withLock { $0.version = version }
            do { try await wake(channel); XCTFail() } catch { XCTAssertEqual(error as? GatewayWakeChannelError, .closed) }
            XCTAssertEqual(driver.value.withLock { $0.calls.count }, 0)
            do { try await channel.start(); XCTFail() } catch { XCTAssertEqual(error as? GatewayWakeChannelError, .unsupportedVersion) }
            XCTAssertEqual(driver.value.withLock { $0.calls.count }, 1)
        }
    }
    func testClientSignsExactServerChallengeScopeAndOpaqueGrant() async throws {
        let driver = Driver(), channel = GatewayWakeChannel(driver: driver), key = P256.Signing.PrivateKey(), delivery = UUID()
        let credential = Data(repeating: 3, count: 16), binding = try binding()
        try await channel.start()
        try await channel.wake(binding: binding, credentialID: credential, deliveryID: delivery,
            sign: { try key.signature(for: $0).rawRepresentation })
        let calls = driver.value.withLock { $0.calls }
        XCTAssertEqual(calls.count, 3)
        guard case .hello = calls[0], case .challenge = calls[1], case .wake(let payload, let rawSignature) = calls[2] else { return XCTFail() }
        let submission = try GatewayWakeSubmission.decode(payload)
        XCTAssertEqual(submission.binding, binding); XCTAssertEqual(submission.credentialID, credential)
        XCTAssertEqual(submission.deliveryID, GatewayHostSnapshot.bytes(delivery))
        XCTAssertEqual(submission.challenge, Data(repeating: 1, count: 32))
        XCTAssertTrue(try key.publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: rawSignature), for: submission.signingInput()))
        await channel.close()
    }
    func testInvalidChallengeOrLocalSignatureNeverSendsWake() async throws {
        for size in [0, 31, 33, 32] {
            let driver = Driver(), channel = GatewayWakeChannel(driver: driver)
            driver.value.withLock { $0.challenge = Data(repeating: 1, count: size) }
            try await channel.start()
            do {
                try await channel.wake(binding: binding(), credentialID: Data(repeating: 3, count: 16), deliveryID: UUID(), sign: { _ in Data() })
                XCTFail()
            } catch { XCTAssertEqual(error as? GatewayWakeChannelError, .invalidMessage) }
            XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
            XCTAssertEqual(driver.value.withLock { $0.closed }, 1)
        }
    }
    func testConcurrentWakeCannotReplaceFirstChallengeAndRejectionAllowsFreshRetry() async throws {
        let driver = Driver(), channel = GatewayWakeChannel(driver: driver)
        try await channel.start()
        driver.value.withLock { $0.hold = true }
        let first = Task { try await wake(channel) }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while driver.value.withLock({ $0.reply == nil }) && ContinuousClock.now < deadline { await Task.yield() }
        let reply = try XCTUnwrap(driver.value.withLock { $0.reply })
        do { try await wake(channel); XCTFail() } catch { XCTAssertEqual(error as? GatewayWakeChannelError, .busy) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
        driver.value.withLock { $0.hold = false; $0.accepted = false }
        reply(.challenge(Data(repeating: 1, count: 32)))
        do { try await first.value; XCTFail() } catch { XCTAssertEqual(error as? GatewayWakeChannelError, .rejected) }
        driver.value.withLock { $0.challenge = Data(repeating: 2, count: 32); $0.accepted = true }
        try await wake(channel)
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 5)
        await channel.close()
    }
    func testTimeoutClosesChannelAndLateResponseCannotSubmitWake() async throws {
        let driver = Driver(), channel = GatewayWakeChannel(driver: driver, timeoutMilliseconds: 20)
        try await channel.start()
        driver.value.withLock { $0.hold = true }
        do { try await wake(channel); XCTFail() } catch { XCTAssertEqual(error as? GatewayWakeChannelError, .timedOut) }
        driver.value.withLock { $0.reply }?(.challenge(Data(repeating: 1, count: 32)))
        do { try await wake(channel); XCTFail() } catch { XCTAssertEqual(error as? GatewayWakeChannelError, .closed) }
        XCTAssertEqual(driver.value.withLock { $0.calls.count }, 2)
        XCTAssertEqual(driver.value.withLock { $0.closed }, 1)
    }
    func testTypedProtectedFileSignerUsesItsPinnedIdentityAndFreshChallenge() async throws {
        let key = P256.Signing.PrivateKey(), binding = try binding(), credential = Data(repeating: 3, count: 16)
        let config = try GatewayWakeSignerConfiguration(binding: binding, credentialID: credential, transportUID: 401,
            ownerUID: 501, gatewayUID: 402, serviceName: "dev.remozio.gateway.wake", teamID: "TEAMID1234",
            gatewayIdentifier: "dev.sebastiano.remozio.macos.gateway", gatewayHashes: [Data(repeating: 4, count: 20)],
            custody: .protectedFile, keyRecordPath: "/Library/Remozio/transport/wake.cbor", publicKey: key.publicKey.x963Representation)
        let record = try GatewayWakeKeyRecord(binding: binding, credentialID: credential, fileKey: key)
        let signer = try GatewayWakeSigner.load(configuration: config, realUID: 401, effectiveUID: 401, read: { _, _ in try record.encode() })
        let driver = Driver(), channel = GatewayWakeChannel(driver: driver), id = UUID()
        try await channel.start()
        try await channel.wake(deliveryID: id, signer: signer)
        guard case .wake(let payload, let signature) = driver.value.withLock({ $0.calls.last }) else { return XCTFail() }
        let submission = try GatewayWakeSubmission.decode(payload)
        XCTAssertEqual(submission.binding, binding); XCTAssertEqual(submission.credentialID, credential)
        XCTAssertEqual(submission.deliveryID, GatewayHostSnapshot.bytes(id))
        XCTAssertEqual(submission.challenge, Data(repeating: 1, count: 32))
        XCTAssertTrue(try key.publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: signature), for: submission.signingInput()))
        await channel.close()
    }
}
