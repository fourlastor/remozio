import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class LiveGatewayPolicyInstallationTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private func policy(_ h: AuthorityPhonePushRegistrationTests.Harness) throws -> GatewayAuthorityPolicy {
        try .init(payloadLimits: h.limits, signingLimits: h.limits, maximumControls: 30, candidateLifetimeMillis: 1000, clockEpoch: h.clock)
    }
    func testLiveEnablePreservesPairingPendingRequestDeadlineAndCommittedCheckpoint() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let now = AuthorityMoment(epoch: h.clock, milliseconds: 100)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let draft = ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: Data([0xa0]),
            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
            firstObservedAt: now, deadlineMilliseconds: 1100, createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 2000)
        let request = try journal.withRequests { try $0.admitFixture(draft, now: now, receiptTimeMs: 1000) }
        let pending = try journal.withRequests { try $0.state(requestID: request.requestID) }
        let checkpoint = try h.store.read(), trust = try journal.read { try $0.approvalTrustSnapshot().revision }
        let registration = h.registration, policy = try policy(h)
        XCTAssertTrue(try journal.enableGatewayPolicy(policy, macID: registration.macID, accountID: registration.accountID, verifyCurrent: {}))
        XCTAssertEqual(try h.store.read(), checkpoint)
        XCTAssertEqual(try journal.withRequests { try $0.state(requestID: request.requestID) }, pending)
        XCTAssertEqual(try journal.read { try $0.approvalTrustSnapshot().revision }, trust)
        XCTAssertTrue(try journal.validatePeer(h.binding)); try h.assertCheckpoint()
        XCTAssertFalse(try journal.enableGatewayPolicy(policy, macID: registration.macID, accountID: registration.accountID, verifyCurrent: {}))
        XCTAssertEqual(try journal.withRequests { try $0.state(requestID: request.requestID).deadlineMilliseconds }, 1100)
    }
    func testProviderConfigurationAfterEnableUsesTheSameCheckpointedOwner() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let registration = h.registration, policy = try policy(h)
        _ = try journal.enableGatewayPolicy(policy, macID: registration.macID, accountID: registration.accountID, verifyCurrent: {})
        try journal.withRequests { try $0.preparePhonePushRegistration(h.provider, now: .init(epoch: h.clock, milliseconds: 100)) }
        try h.assertCheckpoint(); XCTAssertTrue(try journal.validatePeer(h.binding))
        let reply = try journal.withRequests { try $0.phonePushRegistration(h.offer(), binding: h.binding, provider: h.provider,
            now: .init(epoch: h.clock, milliseconds: 110), wall: 1010, validateTransport: { _ in }) }
        guard case .prepared = reply else { return XCTFail("The original enrolled phone must retain registration access") }
        try h.assertCheckpoint(); XCTAssertGreaterThan(h.signs.value, 0)
    }
    func testReentryRejectsBeforeCallingTheSetupVerifierAndDoesNotRetireForegroundWork() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let registration = h.registration, policy = try policy(h), verifies = PushSignCount()
        try journal.withRequests { _ in
            XCTAssertThrowsError(try journal.enableGatewayPolicy(policy, macID: registration.macID, accountID: registration.accountID,
                verifyCurrent: { verifies.increment() })) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
        }
        try journal.read { _ in
            XCTAssertThrowsError(try journal.enableGatewayPolicy(policy, macID: registration.macID, accountID: registration.accountID,
                verifyCurrent: { verifies.increment() })) { XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive) }
        }
        XCTAssertEqual(verifies.value, 0); XCTAssertTrue(try journal.validatePeer(h.binding))
        XCTAssertTrue(try journal.enableGatewayPolicy(policy, macID: registration.macID, accountID: registration.accountID, verifyCurrent: {}))
        try h.assertCheckpoint()
    }
    func testWrongClockCannotPoisonTheRunningOwnerOrInvokeTheSetupVerifier() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let registration = h.registration, verifies = PushSignCount()
        let wrong = try GatewayAuthorityPolicy(payloadLimits: h.limits, signingLimits: h.limits, maximumControls: 30,
            candidateLifetimeMillis: 1000, clockEpoch: UUID())
        XCTAssertThrowsError(try journal.enableGatewayPolicy(wrong, macID: registration.macID, accountID: registration.accountID,
            verifyCurrent: { verifies.increment() })) { XCTAssertEqual($0 as? ApprovalCoordinatorError, .invalidClock) }
        XCTAssertEqual(verifies.value, 0); XCTAssertTrue(try journal.validatePeer(h.binding))
        XCTAssertThrowsError(try journal.read { try $0.gatewayAuthorityHead(registration) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .disabled) }
        XCTAssertTrue(try journal.enableGatewayPolicy(policy(h), macID: registration.macID, accountID: registration.accountID, verifyCurrent: {}))
        try h.assertCheckpoint()
    }
    func testFailedHostVerificationDoesNotEnableThePolicyOrChangeForegroundTrust() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let registration = h.registration, checkpoint = try h.store.read(), policy = try policy(h)
        XCTAssertThrowsError(try journal.enableGatewayPolicy(policy, macID: registration.macID, accountID: registration.accountID,
            verifyCurrent: { throw Denied() })) { XCTAssertTrue($0 is Denied) }
        XCTAssertThrowsError(try journal.read { try $0.gatewayAuthorityHead(registration) }) { XCTAssertEqual($0 as? GatewayAuthorityError, .disabled) }
        XCTAssertEqual(try h.store.read(), checkpoint); XCTAssertTrue(try journal.validatePeer(h.binding))
        XCTAssertTrue(try journal.enableGatewayPolicy(policy, macID: registration.macID, accountID: registration.accountID, verifyCurrent: {}))
    }
}
