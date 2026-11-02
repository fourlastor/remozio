import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityPhoneRoutingIPCTests: XCTestCase, @unchecked Sendable {
    private final class Count: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func add() { lock.withLock { count += 1 } }
        var value: Int { lock.withLock { count } }
    }
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        let versions = Count(), calls = Count(), closes = Count()
        let version: UInt64
        let handler: @Sendable (PhoneRoutingFrame) throws -> Data
        let sent = XCTestExpectation(description: "routing sent")
        private let lock = NSLock()
        private var pending: (@Sendable (AuthorityXPCReply) -> Void)?
        private let hold: Bool
        init(version: UInt64 = 1, hold: Bool = false, handler: @escaping @Sendable (PhoneRoutingFrame) throws -> Data) {
            self.version = version; self.handler = handler; self.hold = hold
        }
        func start(invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func routingVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { versions.add(); reply(.routingVersion(version)) }
        func routing(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            calls.add()
            if hold { lock.withLock { pending = reply }; sent.fulfill(); return }
            do { reply(.routing(try handler(PhoneRoutingFrame.decode(frame)))) } catch { reply(.failed) }
        }
        func finish(_ bytes: Data) { lock.withLock { pending }?(.routing(bytes)) }
        func close() { closes.add() }
    }
    private func binding(account: UInt8 = 2) throws -> AuthorityPeerBinding {
        try .init(scope: ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: account, count: 16),
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
    }
    private func query(_ n: UInt8 = 5) -> PhoneRoutingFrame { .status(queryNonce: Data(repeating: n, count: 32)) }
    private func control(_ peer: AuthorityPeerBinding, expected: UInt64 = 0) throws -> Data {
        try RoutingAwayControl(macID: peer.scope.macID, accountID: peer.scope.accountID,
            phoneID: peer.scope.phoneID, enrollmentEpoch: peer.scope.enrollmentEpoch, operationID: Data(repeating: 6, count: 16),
            challenge: Data(repeating: 7, count: 32), keyID: Data(repeating: 8, count: 16), expectedRevision: expected,
            issuedAtUnixMillis: 100, expiresAtUnixMillis: 200).encode(limits: .init(maxBytes: 1024, maxDepth: 2, maxItems: 32))
    }
    private func response(_ request: PhoneRoutingFrame, peer: AuthorityPeerBinding,
                          outcome: RoutingStatusOutcome = .status, revision: UInt64 = 0,
                          challenge: Data? = nil, digest: Data? = nil, applied: UInt64? = nil) throws -> PhoneRoutingFrame {
        let body = try RoutingStatusResponse(scope: peer.scope, queryNonce: request.queryNonce, outcome: outcome,
            clockEpoch: Data(repeating: 9, count: 16), sampledAtMilliseconds: 10,
            state: .init(mode: .present, revision: revision, destination: .localMac, reason: .manualPresent, detectionLimited: false),
            canonicalChallenge: challenge, controlDigest: digest, appliedRevision: applied).encode()
        // IPC validates shape. Root and phone signature validation use separate real-signature tests.
        return .response(queryNonce: request.queryNonce, canonicalPayload: body, signature: Data(count: 64))
    }
    func testUnsupportedVersionsSendNoBindingAndPreserveExistingOperations() async throws {
        for version: UInt64 in [0, 2, .max] {
            let driver = Driver(version: version) { _ in XCTFail("Unsupported routing transmitted"); return Data() }
            let channel = AuthorityXPCChannel(driver: driver), peer = try binding()
            try await channel.start()
            for _ in 0..<2 {
                do { _ = try await channel.phoneRouting(binding: peer, frame: query()); XCTFail("Expected unsupported") }
                catch AuthorityXPCError.unsupportedPhoneRouting {}
            }
            XCTAssertEqual(driver.versions.value, 1); XCTAssertEqual(driver.calls.value, 0)
            let allowed = try await channel.validatePeer(peer); XCTAssertTrue(allowed)
            XCTAssertEqual(driver.closes.value, 0); await channel.close()
        }
    }
    func testClientNegotiatesOnceAndPreservesCurrentStateBesideHistoricalReceipt() async throws {
        let peer = try binding(), control = try control(peer), digest = Data(SHA256.hash(data: control))
        let request = PhoneRoutingFrame.apply(queryNonce: query().queryNonce, canonicalControl: control, signature: Data(count: 64))
        let reply = try response(request, peer: peer, outcome: .applied, revision: 3, digest: digest, applied: 1)
        let bytes = try reply.encode(), driver = Driver { _ in bytes }, channel = AuthorityXPCChannel(driver: driver)
        try await channel.start()
        for _ in 0..<2 {
            let result = try await channel.phoneRouting(binding: peer, frame: request)
            guard case .response(_, let body, _) = result else { return XCTFail("Missing reply") }
            let value = try RoutingStatusResponse.decode(body)
            XCTAssertEqual(value.state.mode, .present); XCTAssertEqual(value.state.revision, 3); XCTAssertEqual(value.appliedRevision, 1)
        }
        XCTAssertEqual(driver.versions.value, 1); XCTAssertEqual(driver.calls.value, 2); await channel.close()
    }
    func testInvalidRequestsSendNoCapabilityOrPrivateData() async throws {
        let peer = try binding(), wrongControl = try control(binding(account: 12))
        let invalid: [PhoneRoutingFrame] = [.status(queryNonce: Data(count: 31)), .failure(queryNonce: query().queryNonce, reason: .unavailable),
            try response(query(), peer: peer), .apply(queryNonce: query().queryNonce, canonicalControl: wrongControl, signature: Data(count: 64))]
        for request in invalid {
            let driver = Driver { _ in XCTFail("Invalid request transmitted"); return Data() }, channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.phoneRouting(binding: peer, frame: request); XCTFail("Expected invalid request") } catch {}
            XCTAssertEqual(driver.versions.value, 0); XCTAssertEqual(driver.calls.value, 0); await channel.close()
        }
    }
    func testMalformedWrongScopeNonceAndResponseRoleRetireClientWithoutRetry() async throws {
        let peer = try binding(), request = query()
        let replies = [Data(), Data([1]), Data(count: PhoneRoutingFrame.maximumBytes + 1), try request.encode(),
            try response(query(11), peer: peer).encode(), try response(request, peer: binding(account: 12)).encode(),
            try response(request, peer: peer, outcome: .conflict).encode()]
        for bytes in replies {
            let driver = Driver { _ in bytes }, channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.phoneRouting(binding: peer, frame: request); XCTFail("Expected invalid reply") } catch {}
            do { _ = try await channel.phoneRouting(binding: peer, frame: request); XCTFail("Must not replay") } catch {}
            XCTAssertEqual(driver.calls.value, 1); XCTAssertGreaterThan(driver.closes.value, 0)
        }
    }
    func testApplyRequiresExactDigestAndOriginalAppliedRevision() async throws {
        let peer = try binding(), bytes = try control(peer), digest = Data(SHA256.hash(data: bytes))
        let request = PhoneRoutingFrame.apply(queryNonce: query().queryNonce, canonicalControl: bytes, signature: Data(count: 64))
        let invalid = [try response(request, peer: peer),
            try response(request, peer: peer, outcome: .conflict),
            try response(request, peer: peer, outcome: .conflict, digest: Data(count: 32)),
            try response(request, peer: peer, outcome: .applied, revision: 3, digest: digest, applied: 2)]
        for reply in invalid { XCTAssertThrowsError(try AuthorityPhoneRoutingExchange.response(reply, to: request, binding: peer)) }
        try AuthorityPhoneRoutingExchange.response(response(request, peer: peer, outcome: .conflict, digest: digest), to: request, binding: peer)
    }
    func testChallengeOnlyAcceptsMatchingRevisionOrUndigestedConflict() throws {
        let peer = try binding(), request = PhoneRoutingFrame.challenge(queryNonce: query().queryNonce, expectedRevision: 0)
        try AuthorityPhoneRoutingExchange.response(response(request, peer: peer, outcome: .challenge, challenge: control(peer)), to: request, binding: peer)
        try AuthorityPhoneRoutingExchange.response(response(request, peer: peer, outcome: .conflict, revision: 2), to: request, binding: peer)
        XCTAssertThrowsError(try AuthorityPhoneRoutingExchange.response(response(request, peer: peer, outcome: .challenge, revision: 1, challenge: control(peer, expected: 1)), to: request, binding: peer))
        XCTAssertThrowsError(try AuthorityPhoneRoutingExchange.response(response(request, peer: peer, outcome: .conflict, digest: Data(count: 32)), to: request, binding: peer))
    }
    func testUnsignedFailureIsOnlyAnUnavailableOutcomeAndKeepsChannelUsable() async throws {
        let driver = Driver { request in try PhoneRoutingFrame.failure(queryNonce: request.queryNonce, reason: .unavailable).encode() }
        let channel = AuthorityXPCChannel(driver: driver), peer = try binding(); try await channel.start()
        let result = try await channel.phoneRouting(binding: peer, frame: query())
        guard case .failure(_, .unavailable) = result else { return XCTFail("Failure became status") }
        let allowed = try await channel.validatePeer(peer); XCTAssertTrue(allowed); await channel.close()
    }
    func testTimeoutAndCancellationFenceLateRepliesAndNeverResendAway() async throws {
        let peer = try binding(), request = PhoneRoutingFrame.apply(queryNonce: query().queryNonce, canonicalControl: try control(peer), signature: Data(count: 64))
        for cancel in [false, true] {
            let driver = Driver(hold: true) { _ in Data() }, channel = AuthorityXPCChannel(driver: driver, timeoutMilliseconds: cancel ? 5000 : 100)
            try await channel.start()
            let operation = Task { try await channel.phoneRouting(binding: peer, frame: request) }
            await fulfillment(of: [driver.sent], timeout: 2)
            if cancel { operation.cancel() }
            do { _ = try await operation.value; XCTFail("Must not accept after retirement") } catch {}
            driver.finish(try PhoneRoutingFrame.failure(queryNonce: request.queryNonce, reason: .unavailable).encode())
            do { _ = try await channel.phoneRouting(binding: peer, frame: request); XCTFail("Must not resend") } catch {}
            XCTAssertEqual(driver.calls.value, 1)
        }
    }
    private func endpoint(peer: AuthorityPeerBinding, calls: Count, checks: Count, closes: Count,
                          configured: Bool = true, rejectAfter: Int = .max,
                          policy: @escaping @Sendable () throws -> Void = {},
                          handler: (@Sendable (AuthorityPeerBinding, PhoneRoutingFrame) throws -> PhoneRoutingFrame)? = nil) throws -> AuthorityXPCEndpoint {
        let trust = DirectApprovalTrust(macID: peer.scope.macID, accountID: peer.scope.accountID, revision: peer.revision, peers: [])
        let selected: (@Sendable (AuthorityPeerBinding, PhoneRoutingFrame) throws -> PhoneRoutingFrame)?
        if configured { selected = { binding, request in calls.add(); return try handler?(binding, request) ?? .failure(queryNonce: request.queryNonce, reason: .unavailable) } }
        else { selected = nil }
        return try AuthorityXPCEndpoint(macID: peer.scope.macID, accountID: peer.scope.accountID, budget: AuthorityXPCWorkBudget(),
            verify: { checks.add(); if checks.value > rejectAfter { throw XPCPeerPolicyError.wrongPeer } },
            verifyHandshakePolicy: policy, invalidate: { closes.add() }, snapshot: { trust }, validate: { _ in true }, phoneRouting: selected)
    }
    func testEndpointRequiresHandshakeNegotiationAndInvocationIdentity() throws {
        let peer = try binding(), encoded = try AuthorityTrustCodec.encodeBinding(peer), request = try query().encode()
        for mode in 0..<3 {
            let calls = Count(), checks = Count(), closes = Count()
            let e = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes, rejectAfter: mode == 2 ? 2 : .max)
            if mode > 0 { e.hello { XCTAssertEqual($0, 1) } }
            if mode == 2 { e.phoneRoutingVersion { XCTAssertEqual($0, 1) } }
            e.phoneRouting(encoded, frame: request) { XCTAssertNil($0) }
            XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
        }
    }
    func testEndpointCapabilityChecksCurrentPolicyAndLeavesLegacyChannelUsable() throws {
        let peer = try binding()
        let calls = Count(), checks = Count(), closes = Count(), policyChecks = Count()
        let legacy = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes, configured: false, policy: { policyChecks.add() })
        legacy.hello { XCTAssertEqual($0, 1) }; legacy.phoneRoutingVersion { XCTAssertEqual($0, 0) }
        legacy.validatePeer(try AuthorityTrustCodec.encodeBinding(peer)) { XCTAssertTrue($0) }
        XCTAssertEqual(policyChecks.value, 2); XCTAssertEqual(closes.value, 0); legacy.close()
        let deny = Count()
        let stale = try endpoint(peer: peer, calls: Count(), checks: Count(), closes: Count(), policy: {
            deny.add(); if deny.value == 2 { throw AuthorityTransportAccessError.policyMismatch }
        })
        stale.hello { XCTAssertEqual($0, 1) }; stale.phoneRoutingVersion { XCTAssertEqual($0, 0) }
    }
    func testEndpointRejectsWrongScopeRoleAndBoundsBeforeHandler() throws {
        let peer = try binding(), encoded = try AuthorityTrustCodec.encodeBinding(peer)
        let invalid = [Data([1]), Data(count: PhoneRoutingFrame.maximumBytes + 1),
            try PhoneRoutingFrame.failure(queryNonce: query().queryNonce, reason: .unavailable).encode(),
            try PhoneRoutingFrame.apply(queryNonce: query().queryNonce, canonicalControl: control(binding(account: 12)), signature: Data(count: 64)).encode()]
        for bytes in invalid {
            let calls = Count(), checks = Count(), closes = Count(), e = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes)
            e.hello { XCTAssertEqual($0, 1) }; e.phoneRoutingVersion { XCTAssertEqual($0, 1) }
            e.phoneRouting(encoded, frame: bytes) { XCTAssertNil($0) }
            XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
        }
    }
    func testEndpointCorrelatesOutputAndChecksCurrentStateRoleAfterHandler() throws {
        let peer = try binding(), request = query(), encoded = try AuthorityTrustCodec.encodeBinding(peer)
        let replies = [try response(request, peer: peer), try response(query(11), peer: peer),
            try response(request, peer: binding(account: 12)), try response(request, peer: peer, outcome: .conflict)]
        for (index, reply) in replies.enumerated() {
            let calls = Count(), checks = Count(), closes = Count()
            let e = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes, handler: { _, _ in reply })
            e.hello { XCTAssertEqual($0, 1) }; e.phoneRoutingVersion { XCTAssertEqual($0, 1) }
            e.phoneRouting(encoded, frame: try request.encode()) { if index == 0 { XCTAssertNotNil($0) } else { XCTAssertNil($0) } }
            XCTAssertEqual(calls.value, 1); XCTAssertEqual(closes.value, index == 0 ? 0 : 1); e.close()
        }
    }
}
