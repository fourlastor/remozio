import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityPhonePushCapabilityTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private let commit = Data(repeating: 71, count: 32)
    private func options(_ h: AuthorityPhonePushRegistrationTests.Harness) throws -> AuthorityPhonePushStartupConfiguration {
        try .init(projectID: "project", senderID: "123", packageName: "dev.remozio.android",
            gatewayReceiptPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation, maximumControls: 30, candidateLifetimeMilliseconds: 1000)
    }
    private func capability(_ h: AuthorityPhonePushRegistrationTests.Harness, _ journal: AuthorityJournal,
                            make: (@Sendable (AuthorityPhonePushStartupConfiguration) throws -> AuthorityPhonePushRegistration)? = nil) -> AuthorityPhonePushCapability {
        .init(journal: journal, registration: h.registration, clock: { .init(epoch: h.clock, milliseconds: 100) }, wall: { 1000 },
            makeProvider: make ?? { _ in h.provider })
    }
    func testExistingProviderClosuresBecomeAvailableAfterInstallationOnTheSameOwner() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let cap = capability(h, journal), registration = cap.registrationProvider(), recovery = cap.recoveryProvider()
        let offer = try h.offer(), checkpoint = try h.store.read()
        let resume = PhonePushRecoveryFrame.resume(correlationID: offer.correlationID,
            offer: try .init(token: "synthetic-token", projectID: "project", senderID: "123", packageName: "dev.remozio.android"))
        let unavailable = try journal.withRequests { try registration($0, h.binding, offer, { _ in }) }
        guard case .outcome(_, .unavailable) = unavailable else { return XCTFail() }
        guard case .outcome(_, .unavailable) = try journal.withRequests({ try recovery($0, h.binding, resume, { _ in }) }) else { return XCTFail() }
        XCTAssertNil(cap.publication); XCTAssertNil(cap.installedCommitDigest); XCTAssertEqual(try h.store.read(), checkpoint)
        XCTAssertTrue(try cap.install(options(h), commitDigest: commit, verifyCurrent: {}))
        XCTAssertEqual(cap.installedCommitDigest, commit); XCTAssertNotNil(cap.publication)
        let reply = try journal.withRequests { try registration($0, h.binding, offer, { _ in }) }
        guard case .prepared = reply else { return XCTFail("The already retained handler must use the installed provider") }
        guard case .state(_, let state) = try journal.withRequests({ try recovery($0, h.binding, resume, { _ in }) }) else { return XCTFail() }
        XCTAssertEqual(state.phase, .awaitingProviderProof); XCTAssertTrue(try journal.validatePeer(h.binding)); try h.assertCheckpoint()
        cap.close()
        guard case .outcome(_, .unavailable) = try journal.withRequests({ try registration($0, h.binding, offer, { _ in }) }) else { return XCTFail() }
    }
    func testMatchingRetryPreservesCandidateAndRejectsDifferentSettingsOrPublication() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let cap = capability(h, journal), options = try options(h), registration = cap.registrationProvider(), offer = try h.offer()
        try cap.install(options, commitDigest: commit, verifyCurrent: {})
        guard case .prepared(_, let first) = try journal.withRequests({ try registration($0, h.binding, offer, { _ in }) }) else { return XCTFail() }
        let checkpoint = try h.store.read(), head = try h.head
        XCTAssertFalse(try cap.install(options, commitDigest: commit, verifyCurrent: {}))
        XCTAssertEqual(try h.store.read(), checkpoint); XCTAssertEqual(try h.head, head)
        let recovery = cap.recoveryProvider()
        let resume = PhonePushRecoveryFrame.resume(correlationID: offer.correlationID,
            offer: try .init(token: "synthetic-token", projectID: "project", senderID: "123", packageName: "dev.remozio.android"))
        guard case .state(_, let second) = try journal.withRequests({ try recovery($0, h.binding, resume, { _ in }) }) else { return XCTFail() }
        XCTAssertEqual(first, second.metadata)
        XCTAssertThrowsError(try cap.install(self.options(h), commitDigest: commit, verifyCurrent: {}))
        XCTAssertThrowsError(try cap.install(options, commitDigest: Data(repeating: 72, count: 32), verifyCurrent: {}))
        XCTAssertEqual(cap.installedCommitDigest, commit); try h.assertCheckpoint()
    }
    func testFailedVerificationDoesNotPublishAndCanRetryWithoutAReplacementOwner() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let cap = capability(h, journal), options = try options(h), checkpoint = try h.store.read()
        XCTAssertThrowsError(try cap.install(options, commitDigest: commit, verifyCurrent: { throw Denied() }))
        XCTAssertNil(cap.publication); XCTAssertNil(cap.installedCommitDigest)
        XCTAssertEqual(try h.store.read(), checkpoint); XCTAssertTrue(try journal.validatePeer(h.binding))
        XCTAssertTrue(try cap.install(options, commitDigest: commit, verifyCurrent: {})); try h.assertCheckpoint()
    }
    func testCloseWhilePreparationIsInFlightPreventsLatePublication() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = expectation(description: "Settled")
        let cap = capability(h, journal, make: { _ in entered.signal(); guard release.wait(timeout: .now() + 5) == .success else { throw Denied() }; return h.provider })
        let options = try options(h), commit = commit
        DispatchQueue.global().async {
            defer { done.fulfill() }
            do { _ = try cap.install(options, commitDigest: commit, verifyCurrent: {}); XCTFail("Closed capability must not publish") }
            catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success); cap.close(); release.signal()
        wait(for: [done], timeout: 5)
        XCTAssertNil(cap.publication); XCTAssertNil(cap.installedCommitDigest); XCTAssertTrue(try journal.validatePeer(h.binding))
    }
    func testConcurrentInstallationRejectsWithoutWaitingOnTheJournalOrPublishingEarly() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), done = expectation(description: "Installed")
        let cap = capability(h, journal), options = try options(h), commit = commit
        DispatchQueue.global().async {
            defer { done.fulfill() }
            let first = Mutex(true)
            do { _ = try cap.install(options, commitDigest: commit, verifyCurrent: {
                if first.withLock({ let value = $0; $0 = false; return value }) {
                    entered.signal(); guard release.wait(timeout: .now() + 5) == .success else { throw Denied() }
                }
            }) } catch { XCTFail("Installation failed: \(error)") }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success)
        XCTAssertNil(cap.publication); XCTAssertTrue(try journal.validatePeer(h.binding))
        XCTAssertThrowsError(try cap.install(options, commitDigest: commit, verifyCurrent: { XCTFail("No second verifier") })) {
            XCTAssertEqual($0 as? AuthorityWakePublisherError, .busy)
        }
        release.signal(); wait(for: [done], timeout: 5); XCTAssertNotNil(cap.publication)
    }
    func testJournalReentryAndWrongProviderRefuseWithoutExposingACapability() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let cap = capability(h, journal), options = try options(h), commit = commit
        try journal.withRequests { _ in
            XCTAssertThrowsError(try cap.install(options, commitDigest: commit, verifyCurrent: {})) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
        }
        XCTAssertNil(cap.publication); XCTAssertTrue(try journal.validatePeer(h.binding))
        let wrong = try AuthorityPhonePushStartupConfiguration(projectID: "another-project", senderID: "123", packageName: "dev.remozio.android",
            gatewayReceiptPublicKey: options.gatewayReceiptPublicKey, maximumControls: 30, candidateLifetimeMilliseconds: 1000)
        XCTAssertThrowsError(try cap.install(wrong, commitDigest: commit, verifyCurrent: {}))
        XCTAssertNil(cap.publication); XCTAssertTrue(try cap.install(options, commitDigest: commit, verifyCurrent: {}))
    }
    func testFailedFinalVerificationKeepsProviderUnavailableAfterDurablePreparationAndRetryWorks() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let flags = Mutex((prepared: false, reject: true))
        let provider = AuthorityPhonePushRegistration(policy: h.provider.policy, signing: { try h.key.signature(for: $0).rawRepresentation },
            verifySelf: { _ in flags.withLock { $0.prepared = true } })
        let cap = capability(h, journal, make: { _ in provider }), options = try options(h)
        func verify() throws { if flags.withLock({ $0.prepared && $0.reject }) { throw Denied() } }
        XCTAssertThrowsError(try cap.install(options, commitDigest: commit, verifyCurrent: verify)) { XCTAssertTrue($0 is Denied) }
        XCTAssertTrue(flags.withLock { $0.prepared }); XCTAssertNil(cap.publication); XCTAssertNil(cap.installedCommitDigest)
        XCTAssertTrue(try journal.validatePeer(h.binding)); try h.assertCheckpoint()
        flags.withLock { $0.reject = false }
        XCTAssertTrue(try cap.install(options, commitDigest: commit, verifyCurrent: verify))
        XCTAssertNotNil(cap.publication); XCTAssertEqual(cap.installedCommitDigest, commit); try h.assertCheckpoint()
    }

    func testConcurrentRequestClockAdvanceCannotMakeProviderPreparationUseAStaleMoment() throws {
        let h = try AuthorityPhonePushRegistrationTests.Harness(configureGateway: false, gatewayLedgerEnabled: false)
        let journal = AuthorityJournal(requests: h.owner); defer { try? journal.close() }
        let sampled = Mutex(false)
        let cap = AuthorityPhonePushCapability(journal: journal, registration: h.registration, clock: {
            let first = sampled.withLock { let first = !$0; $0 = true; return first }
            if first {
                // Model another request acquiring the owner after the first clock read and before setup acquires it.
                _ = try journal.withRequests { try $0.expirePending(now: .init(epoch: h.clock, milliseconds: 105), receiptTimeMs: nil) }
                return .init(epoch: h.clock, milliseconds: 100)
            }
            return .init(epoch: h.clock, milliseconds: 110)
        }, wall: { 1010 }, makeProvider: { _ in h.provider })
        XCTAssertTrue(try cap.install(options(h), commitDigest: commit, verifyCurrent: {}))
        XCTAssertNotNil(cap.publication); XCTAssertTrue(try journal.validatePeer(h.binding)); try h.assertCheckpoint()
    }

}
