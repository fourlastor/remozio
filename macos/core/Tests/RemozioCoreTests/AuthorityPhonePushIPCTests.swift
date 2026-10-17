import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityPhonePushIPCTests: XCTestCase, @unchecked Sendable {
    private final class Count: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func add() { lock.withLock { count += 1 } }
        var value: Int { lock.withLock { count } }
    }
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        let versions = Count(), calls = Count(), closes = Count()
        let version: UInt64
        let handler: @Sendable (PhonePushRegistrationFrame) throws -> Data
        init(version: UInt64 = 1, handler: @escaping @Sendable (PhonePushRegistrationFrame) throws -> Data) {
            self.version = version; self.handler = handler
        }
        func start(invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func registrationVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { versions.add(); reply(.registrationVersion(version)) }
        func registration(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            calls.add()
            do { reply(.registration(try handler(PhonePushRegistrationFrame.decode(frame)))) }
            catch { reply(.failed) }
        }
        func close() { closes.add() }
    }
    private func binding() throws -> AuthorityPeerBinding {
        try .init(scope: ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
    }
    private func offer() throws -> PhonePushRegistrationFrame {
        try .offer(correlationID: Data(repeating: 5, count: 16), offer: PhonePushTokenOffer(token: "synthetic-token", projectID: "project", senderID: "123", packageName: "dev.remozio.android"))
    }
    func testCapabilityZeroSendsNoBindingOrTokenAndPreservesBasicChannel() async throws {
        let driver = Driver(version: 0) { _ in XCTFail("Must not send token"); return Data() }
        let channel = AuthorityXPCChannel(driver: driver); try await channel.start()
        let binding = try binding(), request = try offer()
        for _ in 0..<2 {
            do { _ = try await channel.phonePushRegistration(binding: binding, frame: request); XCTFail("Expected unsupported extension") }
            catch AuthorityXPCError.unsupportedPhonePushRegistration { }
        }
        XCTAssertEqual(driver.versions.value, 1); XCTAssertEqual(driver.calls.value, 0); XCTAssertEqual(driver.closes.value, 0)
        let allowed = try await channel.validatePeer(binding); XCTAssertTrue(allowed)
        await channel.close()
    }
    func testClientMatchesCorrelationAndKeepsProofStatusDistinct() async throws {
        let driver = Driver { request in try PhonePushRegistrationFrame.outcome(correlationID: request.correlationID, outcome: .proofCommitted).encode() }
        let channel = AuthorityXPCChannel(driver: driver); try await channel.start()
        let reply = try await channel.phonePushRegistration(binding: binding(), frame: offer())
        guard case .outcome(_, let result) = reply else { return XCTFail("Missing status") }
        XCTAssertEqual(result, .proofCommitted); XCTAssertNotEqual(result, .mappingConfirmed)
        XCTAssertEqual(driver.calls.value, 1); await channel.close()
    }
    func testWrongCorrelationRoleMalformedAndOversizedRepliesRetireClient() async throws {
        let request = try offer()
        let responses = [try PhonePushRegistrationFrame.outcome(correlationID: Data(count: 16), outcome: .mappingConfirmed).encode(),
                         try request.encode(), Data([1]), Data(count: PhonePushRegistrationFrame.maximumBytes + 1)]
        for response in responses {
            let driver = Driver { _ in response }; let channel = AuthorityXPCChannel(driver: driver); try await channel.start()
            do { _ = try await channel.phonePushRegistration(binding: binding(), frame: request); XCTFail("Expected invalid response") } catch { }
            XCTAssertGreaterThan(driver.closes.value, 0)
            do { _ = try await channel.phonePushRegistration(binding: binding(), frame: request); XCTFail("Closed channel must not retry") } catch { }
            XCTAssertEqual(driver.calls.value, 1)
        }
    }
    func testClientRejectsResponseRolesBeforeAnyCapabilityOrPrivateData() async throws {
        let driver = Driver { _ in XCTFail("Must not transmit response role"); return Data() }
        let channel = AuthorityXPCChannel(driver: driver); try await channel.start()
        do {
            _ = try await channel.phonePushRegistration(binding: binding(), frame: .outcome(correlationID: Data(count: 16), outcome: .mappingConfirmed))
            XCTFail("Expected invalid role")
        } catch { }
        XCTAssertEqual(driver.versions.value, 0); XCTAssertEqual(driver.calls.value, 0)
        await channel.close()
    }
    private func endpoint(binding: AuthorityPeerBinding, calls: Count, checks: Count, closes: Count,
                          rejectAfter: Int = Int.max, configured: Bool = true) throws -> AuthorityXPCEndpoint {
        let trust = DirectApprovalTrust(macID: binding.scope.macID, accountID: binding.scope.accountID, revision: binding.revision, peers: [])
        let handler: (@Sendable (AuthorityPeerBinding, PhonePushRegistrationFrame) throws -> PhonePushRegistrationFrame)?
        if configured { handler = { _, request in calls.add(); return .outcome(correlationID: request.correlationID, outcome: .proofCommitted) } }
        else { handler = nil }
        return try AuthorityXPCEndpoint(macID: binding.scope.macID, accountID: binding.scope.accountID, budget: AuthorityXPCWorkBudget(),
            verify: { checks.add(); if checks.value > rejectAfter { throw XPCPeerPolicyError.wrongPeer } },
            invalidate: { closes.add() }, snapshot: { trust }, validate: { _ in true }, phonePushRegistration: handler)
    }
    func testEndpointRequiresNegotiationAndCurrentInvocationIdentity() throws {
        let binding = try binding(), encoded = try AuthorityTrustCodec.encodeBinding(binding), request = try offer().encode()
        for negotiate in [false, true] {
            let calls = Count(), checks = Count(), closes = Count()
            let endpoint = try endpoint(binding: binding, calls: calls, checks: checks, closes: closes, rejectAfter: negotiate ? 2 : Int.max)
            endpoint.hello { XCTAssertEqual($0, 1) }
            if negotiate { endpoint.phonePushRegistrationVersion { XCTAssertEqual($0, 1) } }
            endpoint.phonePushRegistration(encoded, frame: request) { XCTAssertNil($0) }
            XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
        }
    }
    func testEndpointChecksRoleAndBoundsBeforeHandlerThenReturnsBoundStatus() throws {
        let binding = try binding(), encoded = try AuthorityTrustCodec.encodeBinding(binding)
        let malformed = [Data([1]), Data(count: PhonePushRegistrationFrame.maximumBytes + 1),
                         try PhonePushRegistrationFrame.outcome(correlationID: Data(count: 16), outcome: .mappingConfirmed).encode()]
        for bytes in malformed {
            let calls = Count(), checks = Count(), closes = Count()
            let endpoint = try endpoint(binding: binding, calls: calls, checks: checks, closes: closes)
            endpoint.hello { XCTAssertEqual($0, 1) }; endpoint.phonePushRegistrationVersion { XCTAssertEqual($0, 1) }
            endpoint.phonePushRegistration(encoded, frame: bytes) { XCTAssertNil($0) }
            XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
        }
        let calls = Count(), checks = Count(), closes = Count()
        let endpoint = try endpoint(binding: binding, calls: calls, checks: checks, closes: closes)
        let request = try offer()
        endpoint.hello { XCTAssertEqual($0, 1) }; endpoint.phonePushRegistrationVersion { XCTAssertEqual($0, 1) }
        endpoint.phonePushRegistration(encoded, frame: try request.encode()) { bytes in
            guard let bytes, let response = try? PhonePushRegistrationFrame.decode(bytes), case .outcome(let correlation, let result) = response else { return XCTFail("Missing result") }
            XCTAssertEqual(correlation, request.correlationID); XCTAssertEqual(result, .proofCommitted)
        }
        XCTAssertEqual(calls.value, 1); XCTAssertEqual(checks.value, 3); XCTAssertEqual(closes.value, 0)
        endpoint.close()
    }
    func testUnconfiguredEndpointDeclaresZeroWithoutClosingOtherOperations() throws {
        let binding = try binding(), calls = Count(), checks = Count(), closes = Count()
        let endpoint = try endpoint(binding: binding, calls: calls, checks: checks, closes: closes, configured: false)
        endpoint.hello { XCTAssertEqual($0, 1) }; endpoint.phonePushRegistrationVersion { XCTAssertEqual($0, 0) }
        endpoint.validatePeer(try AuthorityTrustCodec.encodeBinding(binding)) { XCTAssertTrue($0) }
        XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 0); endpoint.close()
    }
}
