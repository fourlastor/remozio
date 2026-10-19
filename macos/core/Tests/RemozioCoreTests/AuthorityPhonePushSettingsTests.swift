import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityPhonePushSettingsTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private let old = Data(repeating: 71, count: 32)
    private let next = Data(repeating: 72, count: 32)
    private func change(_ revision: UInt8 = 1, previous: Data? = nil, selected: Data? = nil) throws -> AuthorityPhonePushSettingsChange {
        try .init(revisionDigest: Data(repeating: revision, count: 32), previousCommitDigest: previous ?? old,
            selectedCommitDigest: selected ?? next)
    }
    private final class Fixture: @unchecked Sendable {
        let h: AuthorityPhonePushRegistrationTests.Harness
        let journal: AuthorityJournal
        let capability: AuthorityPhonePushCapability
        let options: AuthorityPhonePushStartupConfiguration
        let constructions = PushSignCount()
        init() throws {
            h = try .init(configureGateway: false, gatewayLedgerEnabled: false)
            journal = AuthorityJournal(requests: h.owner)
            options = try .init(projectID: "project", senderID: "123", packageName: "dev.remozio.android",
                gatewayReceiptPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                maximumControls: 30, candidateLifetimeMilliseconds: 1000)
            let h = h, constructions = constructions
            capability = .init(journal: journal, registration: h.registration,
                clock: { .init(epoch: h.clock, milliseconds: 110) }, wall: { 1010 },
                makeProvider: { _ in constructions.increment(); return h.provider })
            try capability.install(options, commitDigest: Data(repeating: 71, count: 32), verifyCurrent: {})
        }
        deinit { capability.close(); try? journal.close() }
        func prepared() throws -> PhonePushRegistrationMetadata {
            let handler = capability.registrationProvider(), offer = try h.offer()
            guard case .prepared(_, let value) = try journal.withRequests({ try handler($0, h.binding, offer, { _ in }) }) else { throw Denied() }
            return value
        }
    }
    func testExplicitAdmissionPreservesTheProviderPairingPendingRequestAndDeadline() throws {
        let f = try Fixture(), cap = f.capability, h = f.h, change = try change()
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let draft = ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: Data([0xa0]),
            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
            firstObservedAt: .init(epoch: h.clock, milliseconds: 100), deadlineMilliseconds: 5000,
            createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 5900)
        let request = try f.journal.withRequests { try $0.admitFixture(draft, now: .init(epoch: h.clock, milliseconds: 110), receiptTimeMs: nil) }
        let original = try f.journal.withRequests { try $0.state(requestID: request.requestID) }
        let prepared = try f.prepared(), checkpoint = try h.store.read(), head = try h.head
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: next, verifyCurrent: {}))
        XCTAssertTrue(try cap.quiesceSettings(change, verifyCurrent: {})); XCTAssertNil(cap.publication)
        XCTAssertFalse(try cap.quiesceSettings(change, verifyCurrent: {}))
        for digest in [old, next] {
            XCTAssertThrowsError(try cap.install(f.options, commitDigest: digest, verifyCurrent: { XCTFail("A monitor cannot bypass the pending transition") }))
        }
        let handler = cap.registrationProvider(), offer = try h.offer()
        guard case .outcome(_, .unavailable) = try f.journal.withRequests({ try handler($0, h.binding, offer, { _ in }) }) else { return XCTFail() }
        XCTAssertTrue(try cap.acceptSettings(change, verifyCurrent: {})); XCTAssertNil(cap.publication)
        XCTAssertNil(cap.installedCommitDigest); XCTAssertEqual(try h.store.read(), checkpoint)
        XCTAssertTrue(try cap.install(f.options, commitDigest: next, verifyCurrent: {}))
        XCTAssertEqual(cap.installedCommitDigest, next); XCTAssertEqual(f.constructions.value, 1)
        let recovery = cap.recoveryProvider()
        let resume = PhonePushRecoveryFrame.resume(correlationID: offer.correlationID,
            offer: try .init(token: "synthetic-token", projectID: "project", senderID: "123", packageName: "dev.remozio.android"))
        guard case .state(_, let recovered) = try f.journal.withRequests({ try recovery($0, h.binding, resume, { _ in }) }) else { return XCTFail() }
        XCTAssertEqual(recovered.metadata, prepared); XCTAssertEqual(try h.head, head)
        let restored = try h.store.read()
        XCTAssertEqual(restored.committed.ledgerDigest, checkpoint.committed.ledgerDigest)
        XCTAssertEqual(restored.committed.authorityDigest, checkpoint.committed.authorityDigest)
        XCTAssertEqual(restored.committed.authorityGeneration, checkpoint.committed.authorityGeneration)
        XCTAssertEqual(restored.committed.journalEpoch, checkpoint.committed.journalEpoch)
        XCTAssertEqual(restored.committed.journalHead, checkpoint.committed.journalHead)
        let retained = try f.journal.withRequests { try $0.state(requestID: request.requestID) }
        XCTAssertEqual(retained, original); XCTAssertEqual(retained.deadlineMilliseconds, 5000)
        XCTAssertEqual(retained.firstObservedAt.epoch, h.clock); XCTAssertTrue(try f.journal.validatePeer(h.binding)); try h.assertCheckpoint()
    }
    func testACompetingOrUnquiescedChangeCannotAlterTheInstalledProvider() throws {
        let f = try Fixture(), cap = f.capability, first = try change(), competing = try change(2)
        XCTAssertThrowsError(try cap.acceptSettings(first, verifyCurrent: { XCTFail() }))
        XCTAssertThrowsError(try cap.quiesceSettings(change(previous: next, selected: old), verifyCurrent: { XCTFail() }))
        XCTAssertEqual(cap.installedCommitDigest, old)
        try cap.quiesceSettings(first, verifyCurrent: {})
        XCTAssertThrowsError(try cap.quiesceSettings(competing, verifyCurrent: { XCTFail() }))
        XCTAssertThrowsError(try cap.acceptSettings(competing, verifyCurrent: { XCTFail() }))
        XCTAssertNil(cap.publication); XCTAssertTrue(try cap.acceptSettings(first, verifyCurrent: {}))
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: old, verifyCurrent: { XCTFail() }))
    }
    func testVerificationFailureBeforeTheFenceKeepsAvailabilityButAfterTheFenceRequiresAnExplicitRetry() throws {
        let f = try Fixture(), cap = f.capability, change = try change()
        XCTAssertThrowsError(try cap.quiesceSettings(change, verifyCurrent: { throw Denied() }))
        XCTAssertEqual(cap.installedCommitDigest, old)
        var checks = 0
        XCTAssertThrowsError(try cap.quiesceSettings(change, verifyCurrent: {
            checks += 1; if checks == 2 { throw Denied() }
        }))
        XCTAssertNil(cap.publication)
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: old, verifyCurrent: { XCTFail() }))
        XCTAssertFalse(try cap.quiesceSettings(change, verifyCurrent: {}))
        XCTAssertTrue(try cap.acceptSettings(change, verifyCurrent: {})); XCTAssertNil(cap.publication)
    }
    func testFailedAcceptanceKeepsTheFenceAndMatchingLostReplyRetriesDoNotRepublish() throws {
        let f = try Fixture(), cap = f.capability, first = try change()
        try cap.quiesceSettings(first, verifyCurrent: {})
        var checks = 0
        XCTAssertThrowsError(try cap.acceptSettings(first, verifyCurrent: {
            checks += 1; if checks == 2 { throw Denied() }
        }))
        XCTAssertNil(cap.publication)
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: next, verifyCurrent: { XCTFail() }))
        XCTAssertTrue(try cap.acceptSettings(first, verifyCurrent: {}))
        XCTAssertFalse(try cap.acceptSettings(first, verifyCurrent: {})); XCTAssertNil(cap.publication)
        try cap.install(f.options, commitDigest: next, verifyCurrent: {})
        XCTAssertFalse(try cap.acceptSettings(first, verifyCurrent: {})); XCTAssertEqual(cap.installedCommitDigest, next)
        let second = try change(2, previous: next, selected: Data(repeating: 73, count: 32))
        try cap.quiesceSettings(second, verifyCurrent: {})
        XCTAssertThrowsError(try cap.acceptSettings(first, verifyCurrent: { XCTFail() }))
        XCTAssertTrue(try cap.acceptSettings(second, verifyCurrent: {})); XCTAssertNil(cap.publication)
    }
    func testTheQuiescenceBarrierWaitsForTheExistingOwnerWithoutHoldingTheCapabilityLock() throws {
        let f = try Fixture(), cap = f.capability, journal = f.journal, change = try change()
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let checking = DispatchSemaphore(value: 0), ownerDone = expectation(description: "Owner settled")
        let barrierDone = expectation(description: "Barrier settled"), completed = Mutex(false)
        DispatchQueue.global().async {
            defer { ownerDone.fulfill() }
            do { try journal.withRequests { _ in
                entered.signal(); guard release.wait(timeout: .now() + 5) == .success else { throw Denied() }
            } } catch { XCTFail("Owner failed: \(error)") }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
        DispatchQueue.global().async {
            defer { barrierDone.fulfill() }
            do {
                try cap.quiesceSettings(change, verifyCurrent: { checking.signal() })
                completed.withLock { $0 = true }
            } catch { XCTFail("Barrier failed: \(error)") }
        }
        XCTAssertEqual(checking.wait(timeout: .now() + 5), .success)
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while cap.publication != nil && ContinuousClock.now < deadline { Thread.sleep(forTimeInterval: 0.001) }
        XCTAssertNil(cap.publication); XCTAssertFalse(completed.withLock { $0 })
        release.signal(); wait(for: [ownerDone, barrierDone], timeout: 5)
        XCTAssertTrue(completed.withLock { $0 }); XCTAssertTrue(try journal.validatePeer(f.h.binding))
    }
    func testConcurrentAcceptanceRefusesAndCloseCannotBeUndoneByALateVerifier() throws {
        let f = try Fixture(), cap = f.capability, change = try change()
        try cap.quiesceSettings(change, verifyCurrent: {})
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = expectation(description: "Acceptance settled")
        DispatchQueue.global().async {
            defer { done.fulfill() }
            do {
                _ = try cap.acceptSettings(change, verifyCurrent: {
                    entered.signal(); guard release.wait(timeout: .now() + 5) == .success else { throw Denied() }
                }); XCTFail("Closed capability cannot accept settings")
            } catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
        XCTAssertThrowsError(try cap.quiesceSettings(change, verifyCurrent: { XCTFail() })) {
            XCTAssertEqual($0 as? AuthorityWakePublisherError, .busy)
        }
        XCTAssertThrowsError(try cap.acceptSettings(change, verifyCurrent: { XCTFail() })) {
            XCTAssertEqual($0 as? AuthorityWakePublisherError, .busy)
        }
        cap.close(); release.signal(); release.signal(); wait(for: [done], timeout: 5)
        XCTAssertNil(cap.publication); XCTAssertNil(cap.installedCommitDigest)
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: next, verifyCurrent: { XCTFail() }))
    }
    func testJournalReentryKeepsTheFenceAndCanResumeOnTheSameOwner() throws {
        let f = try Fixture(), cap = f.capability, change = try change()
        try f.journal.withRequests { _ in
            XCTAssertThrowsError(try cap.quiesceSettings(change, verifyCurrent: {})) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
        }
        XCTAssertNil(cap.publication)
        XCTAssertFalse(try cap.quiesceSettings(change, verifyCurrent: {}))
        XCTAssertTrue(try cap.acceptSettings(change, verifyCurrent: {})); XCTAssertTrue(try f.journal.validatePeer(f.h.binding))
    }
    func testChangeRejectsMalformedAndUnchangedCommitDigests() throws {
        for length in [0, 31, 33] {
            let bad = Data(repeating: 1, count: length)
            XCTAssertThrowsError(try AuthorityPhonePushSettingsChange(revisionDigest: bad, previousCommitDigest: old, selectedCommitDigest: next))
            XCTAssertThrowsError(try AuthorityPhonePushSettingsChange(revisionDigest: old, previousCommitDigest: bad, selectedCommitDigest: next))
            XCTAssertThrowsError(try AuthorityPhonePushSettingsChange(revisionDigest: old, previousCommitDigest: next, selectedCommitDigest: bad))
        }
        XCTAssertThrowsError(try change(selected: old))
    }
    func testThePublicationPlanDerivesBothObservationKeysAndPreservesAuthorityConfiguration() throws {
        let f = try GatewayJournalSetupExchangeTests.Fixture(); try f.retainCompletion(.decode(f.initialize()))
        let inventory = try XCTUnwrap(f.runtime.machine.inventory())
        let activation = try GatewayRuntimeActivationPlan(journal: f.state(), foreground: f.runtime.plan, inventory: inventory)
        let revision = try GatewayRuntimeSettingsRevision(id: Data(repeating: 84, count: 16), selection: .init(
            service: f.intent.configuration.settings, activation: .init(wakePollMilliseconds: 2000, wakeTimeoutMilliseconds: 6000)),
            activation: activation, journal: f.state(), foreground: f.runtime.plan, inventory: inventory)
        let plan = try GatewayRuntimeSettingsPublicationPlan(revision: revision, previous: nil, activation: activation,
            journal: f.state(), foreground: f.runtime.plan, inventory: inventory)
        let change = try AuthorityPhonePushSettingsChange(plan)
        XCTAssertEqual(change.revisionDigest, try revision.digest)
        XCTAssertEqual(change.previousCommitDigest, try GatewayRuntimeCommit(activation.extensions).observationDigest)
        XCTAssertEqual(change.selectedCommitDigest, try plan.commit.observationDigest)
        XCTAssertEqual(plan.commit.authorityDigest, try GatewayRuntimeCommit(activation.extensions).authorityDigest)
    }
}
