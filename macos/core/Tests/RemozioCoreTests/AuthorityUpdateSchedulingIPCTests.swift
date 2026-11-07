import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityUpdateSchedulingIPCTests: XCTestCase, @unchecked Sendable {
    private final class Count: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func add() { lock.withLock { count += 1 } }
        var value: Int { lock.withLock { count } }
    }
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        let versions = Count(), calls = Count(), closes = Count()
        let sent = XCTestExpectation(description: "update control sent")
        let version: UInt64
        let handler: @Sendable (PhoneUpdateSchedulingFrame) throws -> Data
        private let hold: Bool
        private let lock = NSLock()
        private var pending: (@Sendable (AuthorityXPCReply) -> Void)?
        init(version: UInt64 = 1, hold: Bool = false, handler: @escaping @Sendable (PhoneUpdateSchedulingFrame) throws -> Data) {
            self.version = version; self.hold = hold; self.handler = handler
        }
        func start(invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func updateSchedulingVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { versions.add(); reply(.updateSchedulingVersion(version)) }
        func updateScheduling(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            calls.add()
            if hold { lock.withLock { pending = reply }; sent.fulfill(); return }
            do { reply(.updateScheduling(try handler(PhoneUpdateSchedulingFrame.decode(frame)))) } catch { reply(.failed) }
        }
        func finish(_ bytes: Data) { lock.withLock { pending }?(.updateScheduling(bytes)) }
        func close() { closes.add() }
    }
    private func binding(account: UInt8 = 2) throws -> AuthorityPeerBinding {
        try .init(scope: ChannelScope(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: account, count: 16),
            phoneID: Data(repeating: 3, count: 16), enrollmentEpoch: Data(repeating: 4, count: 16)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
    }
    private func query(_ n: UInt8 = 5) -> PhoneUpdateSchedulingFrame { .status(queryNonce: Data(repeating: n, count: 32)) }
    private func status(_ request: PhoneUpdateSchedulingFrame, peer: AuthorityPeerBinding,
                        digest: Data? = nil) throws -> PhoneUpdateSchedulingFrame {
        let bytes = try UpdateSchedulingStatusResponse(scope: peer.scope, queryNonce: request.queryNonce,
            updateID: Data(repeating: 6, count: 32), generation: 1, revision: digest == nil ? 0 : 1,
            requestedAction: digest == nil ? nil : .deferUpdate, controlDigest: digest).encode()
        // These tests check IPC correlation. Separate Root and phone tests verify real signatures.
        return .stateResponse(queryNonce: request.queryNonce, canonicalPayload: bytes, signature: Data(count: 64))
    }
    private func control(_ peer: AuthorityPeerBinding, revision: UInt64 = 0,
                         action: UpdateSchedulingAction = .deferUpdate) throws -> Data {
        try UpdateSchedulingControl(macID: peer.scope.macID, accountID: peer.scope.accountID,
            phoneID: peer.scope.phoneID, enrollmentEpoch: peer.scope.enrollmentEpoch, operationID: Data(repeating: 7, count: 16),
            challenge: Data(repeating: 8, count: 32), keyID: Data(repeating: 9, count: 16), updateID: Data(repeating: 6, count: 32),
            expectedGeneration: 1, expectedRevision: revision, issuedAtUnixMillis: 100, expiresAtUnixMillis: 200,
            action: action).encode(limits: AuthorityPhoneUpdateSchedulingExchange.limits)
    }
    func testUnsupportedVersionSendsNoBindingAndPreservesApprovalOperations() async throws {
        for version: UInt64 in [0, 2, .max] {
            let driver = Driver(version: version) { _ in XCTFail("Unsupported update sent"); return Data() }
            let channel = AuthorityXPCChannel(driver: driver), peer = try binding()
            try await channel.start()
            for _ in 0..<2 {
                do { _ = try await channel.phoneUpdateScheduling(binding: peer, frame: query()); XCTFail("Expected unsupported") }
                catch AuthorityXPCError.unsupportedPhoneUpdateScheduling {}
            }
            XCTAssertEqual(driver.versions.value, 1); XCTAssertEqual(driver.calls.value, 0)
            let valid = try await channel.validatePeer(peer); XCTAssertTrue(valid)
            XCTAssertEqual(driver.closes.value, 0); await channel.close()
        }
    }
    func testStatusNegotiatesOnceAndDoesNotBecomeAnAcceptedReceipt() async throws {
        let peer = try binding(), reply = try status(query(), peer: peer).encode()
        let driver = Driver { _ in reply }, channel = AuthorityXPCChannel(driver: driver)
        try await channel.start()
        for _ in 0..<2 {
            guard case .stateResponse(_, let payload, _) = try await channel.phoneUpdateScheduling(binding: peer, frame: query()) else {
                return XCTFail("Missing observation")
            }
            XCTAssertNil(try UpdateSchedulingStatusResponse.decode(payload).controlDigest)
        }
        XCTAssertEqual(driver.versions.value, 1); XCTAssertEqual(driver.calls.value, 2); await channel.close()
    }
    func testClientCarriesTheExactChallengeAndAcceptedControlReceipt() async throws {
        let peer = try binding(), nonce = query().queryNonce, bytes = try control(peer)
        let challenge = PhoneUpdateSchedulingFrame.challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32),
            generation: 1, revision: 0, action: .deferUpdate)
        let challengePayload = try RootUpdateSchedulingChallenge(queryNonce: nonce, canonicalControl: bytes,
            limits: AuthorityPhoneUpdateSchedulingExchange.limits).encode(limits: AuthorityPhoneUpdateSchedulingExchange.limits)
        let challengeReply = try PhoneUpdateSchedulingFrame.challengeResponse(queryNonce: nonce,
            canonicalPayload: challengePayload, signature: Data(count: 64)).encode()
        let apply = PhoneUpdateSchedulingFrame.apply(queryNonce: nonce, canonicalControl: bytes, signature: Data(count: 64))
        let accepted = try status(apply, peer: peer, digest: Data(SHA256.hash(data: bytes))).encode()
        let driver = Driver { request in
            switch request {
            case .challenge: return challengeReply
            case .apply: return accepted
            default: XCTFail("Unexpected update request"); return Data()
            }
        }
        let channel = AuthorityXPCChannel(driver: driver); try await channel.start()
        guard case .challengeResponse(_, let issued, _) = try await channel.phoneUpdateScheduling(binding: peer, frame: challenge) else {
            return XCTFail("Missing challenge")
        }
        XCTAssertEqual(try RootUpdateSchedulingChallenge.decode(issued, limits: AuthorityPhoneUpdateSchedulingExchange.limits).canonicalControl, bytes)
        guard case .stateResponse(_, let receipt, _) = try await channel.phoneUpdateScheduling(binding: peer, frame: apply) else {
            return XCTFail("Missing receipt")
        }
        XCTAssertEqual(try UpdateSchedulingStatusResponse.decode(receipt).controlDigest, Data(SHA256.hash(data: bytes)))
        XCTAssertEqual(driver.versions.value, 1); XCTAssertEqual(driver.calls.value, 2); await channel.close()
    }
    func testInvalidRequestCannotTriggerNegotiationOrSendPrivateData() async throws {
        let peer = try binding()
        let invalid: [PhoneUpdateSchedulingFrame] = [.status(queryNonce: Data(count: 31)),
            .failure(queryNonce: query().queryNonce, reason: .unavailable), try status(query(), peer: peer),
            .apply(queryNonce: query().queryNonce, canonicalControl: try control(binding(account: 12)), signature: Data(count: 64))]
        for request in invalid {
            let driver = Driver { _ in XCTFail("Invalid request sent"); return Data() }, channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.phoneUpdateScheduling(binding: peer, frame: request); XCTFail("Expected rejection") } catch {}
            XCTAssertEqual(driver.versions.value, 0); XCTAssertEqual(driver.calls.value, 0); await channel.close()
        }
    }
    func testMalformedWrongScopeNonceAndReceiptRoleRetireTheClientWithoutRetry() async throws {
        let peer = try binding(), request = query()
        let bad = [Data(), Data([1]), Data(count: PhoneUpdateSchedulingFrame.maximumBytes + 1),
            try status(query(11), peer: peer).encode(), try status(request, peer: binding(account: 12)).encode(),
            try status(request, peer: peer, digest: Data(count: 32)).encode(), try query().encode()]
        for bytes in bad {
            let driver = Driver { _ in bytes }, channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.phoneUpdateScheduling(binding: peer, frame: request); XCTFail("Expected rejection") } catch {}
            do { _ = try await channel.phoneUpdateScheduling(binding: peer, frame: request); XCTFail("Retired client resent") } catch {}
            XCTAssertEqual(driver.calls.value, 1)
        }
    }
    func testUnavailableReplyDoesNotBecomeAcceptanceOrRetireOtherOperations() async throws {
        let driver = Driver { try PhoneUpdateSchedulingFrame.failure(queryNonce: $0.queryNonce, reason: .unavailable).encode() }
        let channel = AuthorityXPCChannel(driver: driver), peer = try binding(); try await channel.start()
        guard case .failure(_, .unavailable) = try await channel.phoneUpdateScheduling(binding: peer, frame: query()) else {
            return XCTFail("Unavailable became acceptance")
        }
        let valid = try await channel.validatePeer(peer); XCTAssertTrue(valid); await channel.close()
    }
    func testTimeoutAndCancellationFenceLateRepliesAndNeverReplayAControl() async throws {
        let peer = try binding(), request = PhoneUpdateSchedulingFrame.apply(queryNonce: query().queryNonce,
            canonicalControl: try control(peer), signature: Data(count: 64))
        for cancel in [false, true] {
            let driver = Driver(hold: true) { _ in Data() }, channel = AuthorityXPCChannel(driver: driver, timeoutMilliseconds: cancel ? 5000 : 100)
            try await channel.start()
            let operation = Task { try await channel.phoneUpdateScheduling(binding: peer, frame: request) }
            await fulfillment(of: [driver.sent], timeout: 2)
            if cancel { operation.cancel() }
            do { _ = try await operation.value; XCTFail("Late result accepted") } catch {}
            driver.finish(try PhoneUpdateSchedulingFrame.failure(queryNonce: request.queryNonce, reason: .unavailable).encode())
            do { _ = try await channel.phoneUpdateScheduling(binding: peer, frame: request); XCTFail("Control replayed") } catch {}
            XCTAssertEqual(driver.calls.value, 1)
        }
    }
    private func endpoint(peer: AuthorityPeerBinding, calls: Count, checks: Count, closes: Count,
        configured: Bool = true, rejectAfter: Int = .max, policy: @escaping @Sendable () throws -> Void = {},
        handler: (@Sendable (AuthorityPeerBinding, PhoneUpdateSchedulingFrame) throws -> PhoneUpdateSchedulingFrame)? = nil) throws -> AuthorityXPCEndpoint {
        let trust = DirectApprovalTrust(macID: peer.scope.macID, accountID: peer.scope.accountID, revision: peer.revision, peers: [])
        let selected: (@Sendable (AuthorityPeerBinding, PhoneUpdateSchedulingFrame) throws -> PhoneUpdateSchedulingFrame)?
        if configured { selected = { binding, request in calls.add(); return try handler?(binding, request) ?? .failure(queryNonce: request.queryNonce, reason: .unavailable) } }
        else { selected = nil }
        return try AuthorityXPCEndpoint(macID: peer.scope.macID, accountID: peer.scope.accountID, budget: AuthorityXPCWorkBudget(),
            verify: { checks.add(); if checks.value > rejectAfter { throw XPCPeerPolicyError.wrongPeer } },
            verifyHandshakePolicy: policy, invalidate: { closes.add() }, snapshot: { trust }, validate: { _ in true },
            phoneUpdateScheduling: selected)
    }
    func testEndpointRequiresHandshakeNegotiationAndCurrentInvocationIdentity() throws {
        let peer = try binding(), encoded = try AuthorityTrustCodec.encodeBinding(peer), request = try query().encode()
        for mode in 0..<3 {
            let calls = Count(), checks = Count(), closes = Count()
            let e = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes, rejectAfter: mode == 2 ? 2 : .max)
            if mode > 0 { e.hello { XCTAssertEqual($0, 1) } }
            if mode == 2 { e.phoneUpdateSchedulingVersion { XCTAssertEqual($0, 1) } }
            e.phoneUpdateScheduling(encoded, frame: request) { XCTAssertNil($0) }
            XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
        }
    }
    func testEndpointChecksCapabilityPolicyAndLeavesLegacyApprovalUsable() throws {
        let peer = try binding(), calls = Count(), checks = Count(), closes = Count(), policyChecks = Count()
        let legacy = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes, configured: false, policy: { policyChecks.add() })
        legacy.hello { XCTAssertEqual($0, 1) }; legacy.phoneUpdateSchedulingVersion { XCTAssertEqual($0, 0) }
        legacy.validatePeer(try AuthorityTrustCodec.encodeBinding(peer)) { XCTAssertTrue($0) }
        XCTAssertEqual(policyChecks.value, 2); XCTAssertEqual(closes.value, 0); legacy.close()
        let denied = Count(), stale = try endpoint(peer: peer, calls: Count(), checks: Count(), closes: Count(), policy: {
            denied.add(); if denied.value == 2 { throw AuthorityTransportAccessError.policyMismatch }
        })
        stale.hello { XCTAssertEqual($0, 1) }; stale.phoneUpdateSchedulingVersion { XCTAssertEqual($0, 0) }
    }
    func testEndpointRejectsWrongScopeRoleAndBoundsBeforeCallingTheProvider() throws {
        let peer = try binding(), encoded = try AuthorityTrustCodec.encodeBinding(peer)
        let bad = [Data([1]), Data(count: PhoneUpdateSchedulingFrame.maximumBytes + 1),
            try PhoneUpdateSchedulingFrame.failure(queryNonce: query().queryNonce, reason: .unavailable).encode(),
            try PhoneUpdateSchedulingFrame.apply(queryNonce: query().queryNonce, canonicalControl: control(binding(account: 12)), signature: Data(count: 64)).encode()]
        for bytes in bad {
            let calls = Count(), checks = Count(), closes = Count(), e = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes)
            e.hello { XCTAssertEqual($0, 1) }; e.phoneUpdateSchedulingVersion { XCTAssertEqual($0, 1) }
            e.phoneUpdateScheduling(encoded, frame: bytes) { XCTAssertNil($0) }
            XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
        }
    }
    func testEndpointRejectsWrongNonceScopeAndAcceptedStatusAfterTheProviderReturns() throws {
        let peer = try binding(), request = query(), encoded = try AuthorityTrustCodec.encodeBinding(peer)
        let replies = [try status(request, peer: peer), try status(query(11), peer: peer),
            try status(request, peer: binding(account: 12)), try status(request, peer: peer, digest: Data(count: 32))]
        for (index, reply) in replies.enumerated() {
            let calls = Count(), checks = Count(), closes = Count()
            let e = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes, handler: { _, _ in reply })
            e.hello { XCTAssertEqual($0, 1) }; e.phoneUpdateSchedulingVersion { XCTAssertEqual($0, 1) }
            e.phoneUpdateScheduling(encoded, frame: try request.encode()) { if index == 0 { XCTAssertNotNil($0) } else { XCTAssertNil($0) } }
            XCTAssertEqual(calls.value, 1); XCTAssertEqual(closes.value, index == 0 ? 0 : 1); e.close()
        }
    }
    func testChallengeReplyMustMatchTheRequestedActionAndCurrentSnapshot() throws {
        let peer = try binding(), bytes = try control(peer), nonce = query().queryNonce
        let payload = try RootUpdateSchedulingChallenge(queryNonce: nonce, canonicalControl: bytes,
            limits: AuthorityPhoneUpdateSchedulingExchange.limits).encode(limits: AuthorityPhoneUpdateSchedulingExchange.limits)
        let response = PhoneUpdateSchedulingFrame.challengeResponse(queryNonce: nonce, canonicalPayload: payload, signature: Data(count: 64))
        let requests: [PhoneUpdateSchedulingFrame] = [.challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32), generation: 1, revision: 0, action: .deferUpdate),
            .challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32), generation: 1, revision: 0, action: .cancelDrain),
            .challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32), generation: 2, revision: 0, action: .deferUpdate),
            .challenge(queryNonce: nonce, updateID: Data(repeating: 6, count: 32), generation: 1, revision: 1, action: .deferUpdate),
            .challenge(queryNonce: nonce, updateID: Data(repeating: 10, count: 32), generation: 1, revision: 0, action: .deferUpdate)]
        for (index, request) in requests.enumerated() {
            if index == 0 { XCTAssertNoThrow(try AuthorityPhoneUpdateSchedulingExchange.response(response, to: request, binding: peer)) }
            else { XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(response, to: request, binding: peer)) }
        }
    }
    func testAcceptedReceiptBindsDigestGenerationActionAndNextRevisionWithoutOverflow() throws {
        let peer = try binding(), nonce = query().queryNonce, bytes = try control(peer), digest = Data(SHA256.hash(data: bytes))
        let request = PhoneUpdateSchedulingFrame.apply(queryNonce: nonce, canonicalControl: bytes, signature: Data(count: 64))
        let values: [(Data, UInt64, UInt64, UpdateSchedulingAction, Data)] = [
            (Data(repeating: 6, count: 32), 1, 1, .deferUpdate, digest),
            (Data(repeating: 6, count: 32), 2, 1, .deferUpdate, digest),
            (Data(repeating: 6, count: 32), 1, 2, .deferUpdate, digest),
            (Data(repeating: 6, count: 32), 1, 1, .cancelDrain, digest),
            (Data(repeating: 10, count: 32), 1, 1, .deferUpdate, digest),
            (Data(repeating: 6, count: 32), 1, 1, .deferUpdate, Data(count: 32))]
        for (index, value) in values.enumerated() {
            let payload = try UpdateSchedulingStatusResponse(scope: peer.scope, queryNonce: nonce, updateID: value.0,
                generation: value.1, revision: value.2, requestedAction: value.3, controlDigest: value.4).encode()
            let response = PhoneUpdateSchedulingFrame.stateResponse(queryNonce: nonce, canonicalPayload: payload, signature: Data(count: 64))
            if index == 0 { XCTAssertNoThrow(try AuthorityPhoneUpdateSchedulingExchange.response(response, to: request, binding: peer)) }
            else { XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(response, to: request, binding: peer)) }
        }
        let exhausted = PhoneUpdateSchedulingFrame.apply(queryNonce: nonce, canonicalControl: try control(peer, revision: .max), signature: Data(count: 64))
        let wrapped = try UpdateSchedulingStatusResponse(scope: peer.scope, queryNonce: nonce, updateID: Data(repeating: 6, count: 32),
            generation: 1, revision: 0, requestedAction: nil, controlDigest: nil).encode()
        XCTAssertThrowsError(try AuthorityPhoneUpdateSchedulingExchange.response(.stateResponse(queryNonce: nonce, canonicalPayload: wrapped,
            signature: Data(count: 64)), to: exhausted, binding: peer))
    }
}
