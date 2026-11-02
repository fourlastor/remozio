import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class AuthorityPhoneAuditIPCTests: XCTestCase, @unchecked Sendable {
    private final class Count: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func add() { lock.withLock { count += 1 } }
        var value: Int { lock.withLock { count } }
    }
    private final class Driver: AuthorityXPCDriver, @unchecked Sendable {
        let versions = Count(), calls = Count(), closes = Count()
        let version: UInt64
        let handler: @Sendable (PhoneAuditFrame) throws -> Data
        let sent = XCTestExpectation(description: "audit sent")
        private let lock = NSLock()
        private var pending: (@Sendable (AuthorityXPCReply) -> Void)?
        private let hold: Bool
        init(version: UInt64 = 1, hold: Bool = false, handler: @escaping @Sendable (PhoneAuditFrame) throws -> Data) {
            self.version = version; self.handler = handler; self.hold = hold
        }
        func start(invalidated: @escaping @Sendable () -> Void) {}
        func hello(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.hello(1)) }
        func snapshot(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.failed) }
        func validate(_ binding: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { reply(.validation(true)) }
        func auditVersion(_ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) { versions.add(); reply(.auditVersion(version)) }
        func audit(_ binding: Data, frame: Data, _ reply: @escaping @Sendable (AuthorityXPCReply) -> Void) {
            calls.add()
            if hold { lock.withLock { pending = reply }; sent.fulfill(); return }
            do { reply(.audit(try handler(PhoneAuditFrame.decode(frame)))) } catch { reply(.failed) }
        }
        func finish(_ bytes: Data) { lock.withLock { pending }?(.audit(bytes)) }
        func close() { closes.add() }
    }
    private let key = P256.Signing.PrivateKey()
    private func id(_ n: UInt8, _ size: Int = 16) -> Data { Data(repeating: n, count: size) }
    private func binding(account: UInt8 = 2) throws -> AuthorityPeerBinding {
        try .init(scope: ChannelScope(macID: id(1), accountID: id(account), phoneID: id(3), enrollmentEpoch: id(4)),
            transportPublicKey: P256.Signing.PrivateKey().publicKey.derRepresentation, revision: UUID())
    }
    private func query(page: Bool = false, nonce: UInt8 = 5, epoch: UInt8 = 7, generation: UInt64 = 8, after: UInt64 = 0) -> PhoneAuditFrame {
        page ? .pageQuery(queryNonce: id(nonce, 32), epoch: id(epoch), generation: generation, after: after) :
            .historyQuery(queryNonce: id(nonce, 32), epoch: nil, after: nil)
    }
    private func response(_ request: PhoneAuditFrame, peer: AuthorityPeerBinding) throws -> PhoneAuditFrame {
        let limits = try AuditReplyLimits.phoneFrame(maximumBytes: PhoneAuditFrame.maximumBytes)
        let replies = try AuditReplyBuilder(macID: peer.scope.macID, accountID: peer.scope.accountID,
            authorityPublicKey: key.publicKey.x963Representation, limits: limits, signer: { try self.key.signature(for: $0).rawRepresentation })
        let epoch: Data, generation: UInt64, head: UInt64
        if case .pageQuery(_, let e, let g, let after) = request { epoch = e; generation = g; head = after }
        else { epoch = id(7); generation = 8; head = 0 }
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(peer.scope.macID), 2: .bytes(peer.scope.accountID), 3: .bytes(epoch),
            4: .unsigned(generation), 5: .unsigned(1), 6: .null, 7: .null, 8: .null,
        ]), limits: limits.descriptor), limits: limits.descriptor)
        let read = try AuditEpochRead(descriptor: descriptor, retainedAfter: 0, head: head)
        switch request {
        case .historyQuery(let nonce, let epoch, let after):
            let signed = try replies.history(.init(nonce: nonce, epoch: epoch, after: after), current: read)
            return .historyResponse(queryNonce: nonce, canonicalPayload: signed.canonicalBody, signature: signed.signature)
        case .pageQuery(let nonce, let epoch, let generation, let after):
            let signed = try replies.page(.init(nonce: nonce, epoch: epoch, generation: generation, after: after), epoch: read, canonicalRecords: [])
            return .pageResponse(queryNonce: nonce, canonicalPayload: signed.canonicalBody, signature: signed.signature)
        default: throw AuthorityXPCError.invalidMessage
        }
    }
    func testClientNegotiatesOnceAndPreservesBothSignedPayloadKinds() async throws {
        let peer = try binding()
        let driver = Driver { try self.response($0, peer: peer).encode() }, channel = AuthorityXPCChannel(driver: driver)
        try await channel.start()
        for request in [query(), query(page: true), query(page: true, generation: .max, after: .max)] {
            let reply = try await channel.phoneAudit(binding: peer, frame: request)
            try AuthorityPhoneAuditExchange.response(reply, to: request, binding: peer)
            let limits = try AuditReplyLimits.phoneFrame(maximumBytes: PhoneAuditFrame.maximumBytes)
            switch reply {
            case .historyResponse(_, let body, let signature):
                XCTAssertTrue(try AuditHistoryStatusSignature.verify(signature: signature, publicKey: key.publicKey.x963Representation,
                    wireVersion: 1, canonicalPayload: body, payloadLimits: limits.history, inputLimits: limits.signing))
            case .pageResponse(_, let body, let signature):
                XCTAssertTrue(try AuditBatchSignature.verify(signature: signature, publicKey: key.publicKey.x963Representation,
                    wireVersion: 1, canonicalPayload: body, payloadLimits: limits.batch, inputLimits: limits.signing))
            default: XCTFail("Missing signed reply")
            }
        }
        XCTAssertEqual(driver.versions.value, 1); XCTAssertEqual(driver.calls.value, 3); await channel.close()
    }
    func testUnsupportedVersionTransmitsNoBindingAndPreservesOtherOperations() async throws {
        for version: UInt64 in [0, 2, .max] {
            let driver = Driver(version: version) { _ in XCTFail("Unsupported audit sent"); return Data() }
            let channel = AuthorityXPCChannel(driver: driver), peer = try binding(); try await channel.start()
            for _ in 0..<2 {
                do { _ = try await channel.phoneAudit(binding: peer, frame: query()); XCTFail("Expected unsupported") }
                catch AuthorityXPCError.unsupportedPhoneAudit {}
            }
            XCTAssertEqual(driver.versions.value, 1); XCTAssertEqual(driver.calls.value, 0)
            let valid = try await channel.validatePeer(peer); XCTAssertTrue(valid); XCTAssertEqual(driver.closes.value, 0)
            await channel.close()
        }
    }
    func testInvalidQueriesAreRejectedBeforeCapabilityOrBindingTransmission() async throws {
        let peer = try binding()
        let invalid: [PhoneAuditFrame] = [.historyQuery(queryNonce: id(5, 31), epoch: nil, after: nil),
            .historyQuery(queryNonce: id(5, 32), epoch: id(7), after: nil),
            .failure(queryNonce: id(5, 32), reason: .unavailable), try response(query(), peer: peer)]
        for frame in invalid {
            let driver = Driver { _ in XCTFail("Invalid request sent"); return Data() }, channel = AuthorityXPCChannel(driver: driver)
            try await channel.start()
            do { _ = try await channel.phoneAudit(binding: peer, frame: frame); XCTFail("Expected invalid") } catch {}
            XCTAssertEqual(driver.versions.value, 0); XCTAssertEqual(driver.calls.value, 0); await channel.close()
        }
    }
    func testClientRejectsWrongOuterAndInnerNonceTypeScopeAndCursorWithoutRetry() async throws {
        let peer = try binding(), request = query(page: true)
        let wrongNonce = try response(query(page: true, nonce: 11), peer: peer)
        guard case .pageResponse(_, let wrongBody, let signature) = wrongNonce else { throw AuthorityXPCError.invalidMessage }
        let invalid = [Data(), Data([1]), Data(count: PhoneAuditFrame.maximumBytes + 1), try request.encode(),
            try response(query(), peer: peer).encode(), try wrongNonce.encode(),
            try PhoneAuditFrame.pageResponse(queryNonce: request.queryNonce, canonicalPayload: wrongBody, signature: signature).encode(),
            try response(request, peer: binding(account: 12)).encode(),
            try response(query(page: true, epoch: 9), peer: peer).encode(),
            try response(query(page: true, generation: 9), peer: peer).encode(),
            try response(query(page: true, after: 1), peer: peer).encode()]
        for bytes in invalid {
            let driver = Driver { _ in bytes }, channel = AuthorityXPCChannel(driver: driver); try await channel.start()
            do { _ = try await channel.phoneAudit(binding: peer, frame: request); XCTFail("Invalid reply accepted") } catch {}
            do { _ = try await channel.phoneAudit(binding: peer, frame: request); XCTFail("Retired channel reused") } catch {}
            XCTAssertEqual(driver.calls.value, 1); XCTAssertGreaterThan(driver.closes.value, 0)
        }
    }
    func testHistoryReplyMustMatchTheRequestedReconciliationCursor() throws {
        let peer = try binding(), request = PhoneAuditFrame.historyQuery(queryNonce: id(5, 32), epoch: id(7), after: 0)
        try AuthorityPhoneAuditExchange.response(response(request, peer: peer), to: request, binding: peer)
        for wrong in [query(), .historyQuery(queryNonce: id(5, 32), epoch: id(7), after: 1),
                      .historyQuery(queryNonce: id(5, 32), epoch: id(8), after: 0)] {
            XCTAssertThrowsError(try AuthorityPhoneAuditExchange.response(response(wrong, peer: peer), to: request, binding: peer))
        }
    }
    func testUnsignedFailureIsUnavailableAndDoesNotBecomeEmptyHistory() async throws {
        let driver = Driver { try PhoneAuditFrame.failure(queryNonce: $0.queryNonce, reason: .unavailable).encode() }
        let channel = AuthorityXPCChannel(driver: driver), peer = try binding(); try await channel.start()
        for request in [query(), query(page: true)] {
            guard case .failure(_, .unavailable) = try await channel.phoneAudit(binding: peer, frame: request) else { return XCTFail("Failure became history") }
        }
        let valid = try await channel.validatePeer(peer); XCTAssertTrue(valid); await channel.close()
    }
    func testTimeoutCancellationAndLateRepliesNeverReuseTheChannel() async throws {
        for cancel in [false, true] {
            let driver = Driver(hold: true) { _ in Data() }, channel = AuthorityXPCChannel(driver: driver, timeoutMilliseconds: cancel ? 5000 : 100)
            let peer = try binding(), request = query(); try await channel.start()
            let operation = Task { try await channel.phoneAudit(binding: peer, frame: request) }
            await fulfillment(of: [driver.sent], timeout: 2)
            if cancel { operation.cancel() }
            do { _ = try await operation.value; XCTFail("Late result accepted") } catch {}
            driver.finish(try response(request, peer: peer).encode())
            do { _ = try await channel.phoneAudit(binding: peer, frame: request); XCTFail("Retired channel reused") } catch {}
            XCTAssertEqual(driver.calls.value, 1)
        }
    }
    private func endpoint(peer: AuthorityPeerBinding, calls: Count, checks: Count, closes: Count,
                          configured: Bool = true, rejectAfter: Int = .max,
                          policy: @escaping @Sendable () throws -> Void = {},
                          handler: (@Sendable (AuthorityPeerBinding, PhoneAuditFrame) throws -> PhoneAuditFrame)? = nil) throws -> AuthorityXPCEndpoint {
        let trust = DirectApprovalTrust(macID: peer.scope.macID, accountID: peer.scope.accountID, revision: peer.revision, peers: [])
        let selected: (@Sendable (AuthorityPeerBinding, PhoneAuditFrame) throws -> PhoneAuditFrame)?
        if configured { selected = { binding, request in calls.add(); return try handler?(binding, request) ?? .failure(queryNonce: request.queryNonce, reason: .unavailable) } }
        else { selected = nil }
        return try AuthorityXPCEndpoint(macID: peer.scope.macID, accountID: peer.scope.accountID, budget: AuthorityXPCWorkBudget(),
            verify: { checks.add(); if checks.value > rejectAfter { throw XPCPeerPolicyError.wrongPeer } },
            verifyHandshakePolicy: policy, invalidate: { closes.add() }, snapshot: { trust }, validate: { _ in true }, phoneAudit: selected)
    }
    func testEndpointRequiresHandshakeCapabilityAndCurrentInvocationIdentity() throws {
        let peer = try binding(), encoded = try AuthorityTrustCodec.encodeBinding(peer), bytes = try query().encode()
        for mode in 0..<3 {
            let calls = Count(), checks = Count(), closes = Count()
            let e = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes, rejectAfter: mode == 2 ? 2 : .max)
            if mode > 0 { e.hello { XCTAssertEqual($0, 1) } }
            if mode == 2 { e.phoneAuditVersion { XCTAssertEqual($0, 1) } }
            e.phoneAudit(encoded, frame: bytes) { XCTAssertNil($0) }
            XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
        }
    }
    func testEndpointMissingProviderLeavesLegacyOperationsUsableAndChecksCurrentPolicy() throws {
        let peer = try binding(), calls = Count(), checks = Count(), closes = Count(), policies = Count()
        let legacy = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes, configured: false, policy: { policies.add() })
        legacy.hello { XCTAssertEqual($0, 1) }; legacy.phoneAuditVersion { XCTAssertEqual($0, 0) }
        legacy.validatePeer(try AuthorityTrustCodec.encodeBinding(peer)) { XCTAssertTrue($0) }
        XCTAssertEqual(policies.value, 2); XCTAssertEqual(closes.value, 0); legacy.close()
        let stalePolicy = Count()
        let stale = try endpoint(peer: peer, calls: Count(), checks: Count(), closes: Count(), policy: {
            stalePolicy.add(); if stalePolicy.value == 2 { throw AuthorityTransportAccessError.policyMismatch }
        })
        stale.hello { XCTAssertEqual($0, 1) }; stale.phoneAuditVersion { XCTAssertEqual($0, 0) }
    }
    func testEndpointRejectsOversizedMalformedAndNonQueryFramesBeforeHandler() throws {
        let peer = try binding(), encoded = try AuthorityTrustCodec.encodeBinding(peer)
        let invalid = [Data(), Data([1]), Data(count: PhoneAuditFrame.maximumQueryBytes + 1),
            try response(query(), peer: peer).encode(), try PhoneAuditFrame.failure(queryNonce: id(5, 32), reason: .unavailable).encode()]
        for bytes in invalid {
            let calls = Count(), checks = Count(), closes = Count(), e = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes)
            e.hello { XCTAssertEqual($0, 1) }; e.phoneAuditVersion { XCTAssertEqual($0, 1) }
            e.phoneAudit(encoded, frame: bytes) { XCTAssertNil($0) }
            XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
        }
    }
    func testEndpointRejectsWrongScopeBindingBeforeHandler() throws {
        let peer = try binding(), calls = Count(), checks = Count(), closes = Count()
        let e = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes)
        e.hello { XCTAssertEqual($0, 1) }; e.phoneAuditVersion { XCTAssertEqual($0, 1) }
        e.phoneAudit(try AuthorityTrustCodec.encodeBinding(binding(account: 12)), frame: try query().encode()) { XCTAssertNil($0) }
        XCTAssertEqual(calls.value, 0); XCTAssertEqual(closes.value, 1)
    }
    func testEndpointCorrelatesTheOutputBeforeReplying() throws {
        let peer = try binding(), request = query(page: true), encoded = try AuthorityTrustCodec.encodeBinding(peer)
        let replies = [try response(request, peer: peer), try response(query(), peer: peer),
            try response(query(page: true, nonce: 11), peer: peer), try response(request, peer: binding(account: 12))]
        for (index, result) in replies.enumerated() {
            let calls = Count(), checks = Count(), closes = Count()
            let e = try endpoint(peer: peer, calls: calls, checks: checks, closes: closes, handler: { _, _ in result })
            e.hello { XCTAssertEqual($0, 1) }; e.phoneAuditVersion { XCTAssertEqual($0, 1) }
            e.phoneAudit(encoded, frame: try request.encode()) { if index == 0 { XCTAssertNotNil($0) } else { XCTAssertNil($0) } }
            XCTAssertEqual(calls.value, 1); XCTAssertEqual(closes.value, index == 0 ? 0 : 1); e.close()
        }
    }
}
