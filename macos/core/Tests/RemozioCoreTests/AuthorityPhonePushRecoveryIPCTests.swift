import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityPhonePushRecoveryIPCTests: XCTestCase, @unchecked Sendable {
    private final class Count: @unchecked Sendable {
        private let lock = NSLock(); private var count = 0
        func add() { lock.withLock { count += 1 } }
        var value: Int { lock.withLock { count } }
    }
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        let versions = Count(), calls = Count(), closes = Count()
        let version: UInt64
        let handler: @Sendable (PhonePushRecoveryFrame) throws -> Data
        init(version: UInt64 = 2, handler: @escaping @Sendable (PhonePushRecoveryFrame) throws -> Data) {
            self.version = version; self.handler = handler
        }
        func start(invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func recoveryVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { versions.add(); reply(.recoveryVersion(version)) }
        func recovery(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            calls.add()
            do { reply(.recovery(try handler(PhonePushRecoveryFrame.decode(frame)))) } catch { reply(.failed) }
        }
        func close() { closes.add() }
    }
    private func binding() throws -> AuthorityPeerBinding {
        try .init(scope: ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
    }
    private func resume() throws -> PhonePushRecoveryFrame {
        try .resume(correlationID: Data(repeating: 5, count: 16), offer: PhonePushTokenOffer(token: "synthetic-token",
            projectID: "project", senderID: "123", packageName: "dev.remozio.android"))
    }
    private func metadata(_ binding: AuthorityPeerBinding, token: String = "synthetic-token") throws -> PhonePushRegistrationMetadata {
        let s = binding.scope
        let b = try GatewayTokenBinding(ownerID: Data(repeating: 40, count: 16), macID: s.macID, accountID: s.accountID,
            gatewayID: Data(repeating: 41, count: 16), lifecycleEpoch: Data(repeating: 42, count: 16), phoneID: s.phoneID,
            enrollmentEpoch: s.enrollmentEpoch, candidateID: Data(repeating: 8, count: 16),
            tokenDigest: Data(SHA256.hash(data: Data(token.utf8))), challenge: Data(repeating: 170, count: 32), enrollmentTag: Data(repeating: 10, count: 32))
        return try .init(GatewayTokenCandidate(binding: b, revision: 7, operationID: Data(repeating: 12, count: 16), issuedAtUnixMillis: 1000, expiresAtUnixMillis: 2000))
    }
    func testUnsupportedVersionsSendNoBindingOrTokenAndPreserveBasicChannel() async throws {
        for version: UInt64 in [0, 1, 3] {
            let driver = Driver(version: version) { _ in XCTFail("Private fields must not be sent"); return Data() }
            let channel = AuthorityXPCChannel(driver: driver); try await channel.start()
            let peer = try binding()
            for _ in 0..<2 {
                do { _ = try await channel.phonePushRecovery(binding: peer, frame: resume()); XCTFail("Expected unsupported recovery") }
                catch AuthorityXPCError.unsupportedPhonePushRecovery {}
            }
            XCTAssertEqual(driver.versions.value, 1); XCTAssertEqual(driver.calls.value, 0); XCTAssertEqual(driver.closes.value, 0)
            let allowed = try await channel.validatePeer(peer); XCTAssertTrue(allowed); await channel.close()
        }
    }
    func testHarmlessPreflightSendsNoPrivateFieldsAndCachesItsCapability() async throws {
        let driver = Driver { _ in XCTFail("Preflight must not send a token"); return Data() }
        let channel = AuthorityXPCChannel(driver: driver); try await channel.start()
        try await channel.requirePhonePushRecoverySupport(); try await channel.requirePhonePushRecoverySupport()
        XCTAssertEqual(driver.versions.value, 1); XCTAssertEqual(driver.calls.value, 0); await channel.close()
    }
    func testCachedCapabilityDoesNotSurviveChannelRetirement() async throws {
        let driver = Driver { _ in XCTFail("Must not send private fields"); return Data() }
        let channel = AuthorityXPCChannel(driver: driver); try await channel.start()
        try await channel.requirePhonePushRecoverySupport(); await channel.close()
        do { try await channel.requirePhonePushRecoverySupport(); XCTFail("Retired capability must not open recovery") }
        catch AuthorityXPCError.closed {}
        XCTAssertEqual(driver.calls.value, 0)
    }
    func testClientAcceptsOnlyBoundStateWithTheCurrentTokenDigest() async throws {
        let peer = try binding(), metadata = try metadata(peer)
        let driver = Driver { request in try PhonePushRecoveryFrame.state(correlationID: request.correlationID,
            state: PhonePushRecoveryState(metadata: metadata, phase: .proofCommitted)).encode() }
        let channel = AuthorityXPCChannel(driver: driver); try await channel.start()
        let response = try await channel.phonePushRecovery(binding: peer, frame: resume())
        guard case .state(_, let state) = response else { return XCTFail("Missing recovery state") }
        XCTAssertEqual(state.phase, .proofCommitted); XCTAssertNil(state.observationAgeMilliseconds)
        XCTAssertEqual(driver.calls.value, 1); await channel.close()
    }
    func testWrongCorrelationRoleDigestMalformedAndOversizedRepliesRetireClient() async throws {
        let peer = try binding(), request = try resume(), wrong = try metadata(peer, token: "different-token")
        let responses = [try PhonePushRecoveryFrame.outcome(correlationID: Data(count: 16), failure: .unavailable).encode(),
            try request.encode(), try PhonePushRecoveryFrame.state(correlationID: request.correlationID,
                state: PhonePushRecoveryState(metadata: wrong, phase: .proofCommitted)).encode(),
            Data([1]), Data(count: PhonePushRecoveryFrame.maximumBytes + 1)]
        for bytes in responses {
            let driver = Driver { _ in bytes }
            let active = AuthorityXPCChannel(driver: driver); try await active.start()
            do { _ = try await active.phonePushRecovery(binding: peer, frame: request); XCTFail("Expected rejection") } catch {}
            XCTAssertGreaterThan(driver.closes.value, 0)
            do { _ = try await active.phonePushRecovery(binding: peer, frame: request); XCTFail("Closed connection must not replay") } catch {}
            XCTAssertEqual(driver.calls.value, 1); await active.close()
        }
    }
    func testResponseRoleCannotReachCapabilityOrPrivateOperation() async throws {
        let driver = Driver { _ in XCTFail("Must not send response role"); return Data() }
        let channel = AuthorityXPCChannel(driver: driver); try await channel.start()
        do {
            _ = try await channel.phonePushRecovery(binding: binding(), frame: .outcome(correlationID: Data(count: 16), failure: .unavailable))
            XCTFail("Expected invalid request role")
        } catch {}
        XCTAssertEqual(driver.versions.value, 0); XCTAssertEqual(driver.calls.value, 0); await channel.close()
    }
    private func endpoint(_ binding: AuthorityPeerBinding, calls: Count, checks: Count, closes: Count,
                          rejectAfter: Int = Int.max, configured: Bool = true) throws -> AuthorityXPCEndpoint {
        let trust = DirectApprovalTrust(macID: binding.scope.macID, accountID: binding.scope.accountID, revision: binding.revision, peers: [])
        let metadata = try metadata(binding)
        let recovery: (@Sendable (AuthorityPeerBinding, PhonePushRecoveryFrame) throws -> PhonePushRecoveryFrame)?
        if configured {
            recovery = { _, request in
                calls.add(); return .state(correlationID: request.correlationID, state: try .init(metadata: metadata, phase: .proofCommitted))
            }
        } else { recovery = nil }
        return try AuthorityXPCEndpoint(macID: binding.scope.macID, accountID: binding.scope.accountID, budget: AuthorityXPCWorkBudget(),
            verify: { checks.add(); if checks.value > rejectAfter { throw XPCPeerPolicyError.wrongPeer } }, invalidate: { closes.add() },
            snapshot: { trust }, validate: { _ in true }, phonePushRegistration: { _, request in .outcome(correlationID: request.correlationID, outcome: .incompatible) },
            phonePushRecovery: recovery)
    }
    func testEndpointKeepsVersion1AndVersion2CapabilitiesIndependent() throws {
        let peer = try binding(), calls = Count(), checks = Count(), closes = Count()
        for configured in [false, true] {
            let endpoint = try endpoint(peer, calls: calls, checks: checks, closes: closes, configured: configured)
            endpoint.hello { XCTAssertEqual($0, 1) }
            endpoint.phonePushRegistrationVersion { XCTAssertEqual($0, 1) }
            endpoint.phonePushRecoveryVersion { XCTAssertEqual($0, configured ? 2 : 0) }
            endpoint.validatePeer(try AuthorityTrustCodec.encodeBinding(peer)) { XCTAssertTrue($0) }
            XCTAssertEqual(calls.value, 0); endpoint.close()
        }
    }
    func testEndpointRejectsUnnegotiatedAndChangedInvocationIdentity() throws {
        let peer = try binding(), encoded = try AuthorityTrustCodec.encodeBinding(peer), frame = try resume().encode()
        for negotiate in [false, true] {
            let calls = Count(), checks = Count(), closes = Count()
            let endpoint = try endpoint(peer, calls: calls, checks: checks, closes: closes, rejectAfter: negotiate ? 2 : Int.max)
            endpoint.hello { XCTAssertEqual($0, 1) }
            if negotiate { endpoint.phonePushRecoveryVersion { XCTAssertEqual($0, 2) } }
            endpoint.phonePushRecovery(encoded, frame: frame) { XCTAssertNil($0) }
            XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
        }
    }
    func testEndpointBoundsAndRoleChecksPrecedeHandlerAndValidStateIsBound() throws {
        let peer = try binding(), encoded = try AuthorityTrustCodec.encodeBinding(peer), request = try resume()
        let invalid = [Data([1]), Data(count: PhonePushRecoveryFrame.maximumBytes + 1),
            try PhonePushRecoveryFrame.outcome(correlationID: request.correlationID, failure: .unavailable).encode()]
        for bytes in invalid {
            let calls = Count(), checks = Count(), closes = Count(), endpoint = try endpoint(peer, calls: calls, checks: checks, closes: closes)
            endpoint.hello { XCTAssertEqual($0, 1) }; endpoint.phonePushRecoveryVersion { XCTAssertEqual($0, 2) }
            endpoint.phonePushRecovery(encoded, frame: bytes) { XCTAssertNil($0) }
            XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
        }
        let calls = Count(), checks = Count(), closes = Count(), endpoint = try endpoint(peer, calls: calls, checks: checks, closes: closes)
        endpoint.hello { XCTAssertEqual($0, 1) }; endpoint.phonePushRecoveryVersion { XCTAssertEqual($0, 2) }
        endpoint.phonePushRecovery(encoded, frame: try request.encode()) { bytes in
            guard let bytes, let response = try? PhonePushRecoveryFrame.decode(bytes), case .state(let id, let state) = response else { return XCTFail("Missing state") }
            XCTAssertEqual(id, request.correlationID); XCTAssertEqual(state.phase, .proofCommitted)
        }
        XCTAssertEqual(calls.value, 1); XCTAssertEqual(closes.value, 0); endpoint.close()
    }
}
