import CryptoKit
import Foundation
import RemozioProtocol
import Synchronization
import XCTest
@testable import RemozioCore

final class AuthorityPhonePushStartupCapabilityTests: XCTestCase, @unchecked Sendable {
    private struct Denied: Error {}
    private let old = Data(repeating: 71, count: 32)
    private let next = Data(repeating: 72, count: 32)
    private func change() throws -> AuthorityPhonePushSettingsChange {
        try .init(revisionDigest: Data(repeating: 11, count: 32), previousCommitDigest: old, selectedCommitDigest: next)
    }
    private final class Fixture: @unchecked Sendable {
        let h: AuthorityPhonePushRegistrationTests.Harness
        let journal: AuthorityJournal
        let options: AuthorityPhonePushStartupConfiguration
        init() throws {
            h = try .init(configureGateway: false, gatewayLedgerEnabled: false)
            journal = AuthorityJournal(requests: h.owner)
            options = try .init(projectID: "project", senderID: "123", packageName: "dev.remozio.android",
                gatewayReceiptPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                maximumControls: 30, candidateLifetimeMilliseconds: 1000)
        }
        deinit { try? journal.close() }
        func capability(make: (@Sendable (AuthorityPhonePushStartupConfiguration) throws -> AuthorityPhonePushRegistration)? = nil) -> AuthorityPhonePushCapability {
            let h = h
            return .init(journal: journal, registration: h.registration, clock: { .init(epoch: h.clock, milliseconds: 110) },
                wall: { 1010 }, makeProvider: make ?? { _ in h.provider })
        }
        func unavailable(_ cap: AuthorityPhonePushCapability) throws {
            XCTAssertNil(cap.publication); XCTAssertNil(cap.installedCommitDigest)
            let offer = try h.offer(), handler = cap.registrationProvider()
            guard case .outcome(_, .unavailable) = try journal.withRequests({ try handler($0, h.binding, offer, { _ in }) }) else {
                return XCTFail("Startup restoration must not admit optional registration")
            }
            XCTAssertTrue(try journal.validatePeer(h.binding))
        }
    }
    func testActiveStartupPreparesUnavailableAndOnlyMatchingMonitorRestoresIt() throws {
        let f = try Fixture(), count = PushSignCount(), h = f.h
        let cap = f.capability(make: { _ in count.increment(); return h.provider }); defer { cap.close() }
        XCTAssertTrue(try cap.restoreStartup(f.options, commitDigest: next, pendingChange: nil, verifyCurrent: {}))
        try f.unavailable(cap)
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: old, verifyCurrent: { XCTFail("Reject the old floor before admission") }))
        XCTAssertTrue(try cap.install(f.options, commitDigest: next, verifyCurrent: {}))
        XCTAssertEqual(cap.installedCommitDigest, next); XCTAssertEqual(count.value, 1)
        XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: next, pendingChange: nil, verifyCurrent: { XCTFail() }))
        XCTAssertEqual(cap.installedCommitDigest, next)
    }
    func testFailureBeforeProviderCreationRetainsTheFloorAndPermitsExactRetry() throws {
        let f = try Fixture(), count = PushSignCount(), h = f.h
        let cap = f.capability(make: { _ in count.increment(); return h.provider }); defer { cap.close() }
        let checkpoint = try h.store.read()
        XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: next, pendingChange: nil, verifyCurrent: { throw Denied() }))
        XCTAssertEqual(count.value, 0); XCTAssertEqual(try h.store.read(), checkpoint); try f.unavailable(cap)
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: old, verifyCurrent: { XCTFail() }))
        let other = try Fixture()
        XCTAssertThrowsError(try cap.restoreStartup(other.options, commitDigest: next, pendingChange: nil, verifyCurrent: { XCTFail() }))
        XCTAssertTrue(try cap.restoreStartup(f.options, commitDigest: next, pendingChange: nil, verifyCurrent: {}))
        try f.unavailable(cap); XCTAssertEqual(count.value, 1)
        try cap.install(f.options, commitDigest: next, verifyCurrent: {})
        XCTAssertEqual(cap.installedCommitDigest, next); XCTAssertTrue(try f.journal.validatePeer(h.binding))
    }
    func testPendingRestoreFailureAndRetryCannotAdmitEitherCommitBeforeFreshQuiescence() throws {
        let f = try Fixture(), reject = Mutex(true), count = PushSignCount(), h = f.h, change = try change()
        let cap = f.capability(make: { _ in count.increment(); if reject.withLock({ $0 }) { throw Denied() }; return h.provider })
        defer { cap.close() }
        XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: old, pendingChange: change, verifyCurrent: {}))
        for digest in [old, next] { XCTAssertThrowsError(try cap.install(f.options, commitDigest: digest, verifyCurrent: { XCTFail() })) }
        XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: old, pendingChange: nil, verifyCurrent: { XCTFail() }))
        reject.withLock { $0 = false }
        XCTAssertTrue(try cap.restoreStartup(f.options, commitDigest: old, pendingChange: change, verifyCurrent: {}))
        try f.unavailable(cap); XCTAssertEqual(count.value, 2)
        XCTAssertThrowsError(try cap.acceptSettings(change, verifyCurrent: { XCTFail("Historical state cannot replace a fresh barrier") }))
        var checks = 0
        XCTAssertThrowsError(try cap.quiesceSettings(change, verifyCurrent: { checks += 1; if checks == 2 { throw Denied() } }))
        XCTAssertThrowsError(try cap.acceptSettings(change, verifyCurrent: { XCTFail() }))
        XCTAssertFalse(try cap.quiesceSettings(change, verifyCurrent: {}))
        XCTAssertTrue(try cap.acceptSettings(change, verifyCurrent: {})); try f.unavailable(cap)
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: old, verifyCurrent: { XCTFail() }))
        XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: old, pendingChange: change, verifyCurrent: { XCTFail() }))
        XCTAssertTrue(try cap.install(f.options, commitDigest: next, verifyCurrent: {}))
        XCTAssertEqual(cap.installedCommitDigest, next); XCTAssertEqual(count.value, 2)
    }
    func testFailedFinalVerificationKeepsPendingStateUnavailableForAnExactRetry() throws {
        let f = try Fixture(), prepared = Mutex(false), reject = Mutex(true), h = f.h, change = try change()
        let provider = AuthorityPhonePushRegistration(policy: h.provider.policy,
            signing: { try h.key.signature(for: $0).rawRepresentation }, verifySelf: { _ in prepared.withLock { $0 = true } })
        let cap = f.capability(make: { _ in provider }); defer { cap.close() }
        XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: old, pendingChange: change, verifyCurrent: {
            if prepared.withLock({ $0 }) && reject.withLock({ $0 }) { throw Denied() }
        }))
        XCTAssertTrue(prepared.withLock { $0 }); reject.withLock { $0 = false }; try f.unavailable(cap)
        for digest in [old, next] { XCTAssertThrowsError(try cap.install(f.options, commitDigest: digest, verifyCurrent: { XCTFail() })) }
        XCTAssertTrue(try cap.restoreStartup(f.options, commitDigest: old, pendingChange: change, verifyCurrent: {}))
        try f.unavailable(cap)
        XCTAssertThrowsError(try cap.acceptSettings(change, verifyCurrent: { XCTFail() }))
        try cap.quiesceSettings(change, verifyCurrent: {}); try cap.acceptSettings(change, verifyCurrent: {})
        try cap.install(f.options, commitDigest: next, verifyCurrent: {}); XCTAssertEqual(cap.installedCommitDigest, next)
    }
    func testInFlightRestorationRejectsConcurrentInstallAndCannotPublishBeforeSettlement() throws {
        let f = try Fixture(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let done = expectation(description: "Restoration settled"), h = f.h, old = old, options = f.options
        let cap = f.capability(make: { _ in entered.signal(); guard release.wait(timeout: .now() + 5) == .success else { throw Denied() }; return h.provider })
        defer { cap.close() }
        DispatchQueue.global().async {
            defer { done.fulfill() }
            do { try cap.restoreStartup(options, commitDigest: old, pendingChange: nil, verifyCurrent: {}) }
            catch { XCTFail("Restoration failed: \(error)") }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success); defer { release.signal() }
        try f.unavailable(cap)
        XCTAssertThrowsError(try cap.install(options, commitDigest: old, verifyCurrent: { XCTFail() })) {
            XCTAssertEqual($0 as? AuthorityWakePublisherError, .busy)
        }
        XCTAssertThrowsError(try cap.restoreStartup(options, commitDigest: old, pendingChange: nil, verifyCurrent: { XCTFail() }))
        release.signal(); wait(for: [done], timeout: 5); try f.unavailable(cap)
        try cap.install(options, commitDigest: old, verifyCurrent: {}); XCTAssertEqual(cap.installedCommitDigest, old)
    }
    func testCloseDuringRestorationPreventsLateAvailabilityAndRetry() throws {
        let f = try Fixture(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let done = expectation(description: "Closed restoration settled"), h = f.h, options = f.options, old = old
        let cap = f.capability(make: { _ in entered.signal(); guard release.wait(timeout: .now() + 5) == .success else { throw Denied() }; return h.provider })
        DispatchQueue.global().async {
            defer { done.fulfill() }
            do { try cap.restoreStartup(options, commitDigest: old, pendingChange: nil, verifyCurrent: {}); XCTFail("Closed restoration must fail") }
            catch { XCTAssertEqual(error as? AuthorityWakePublisherError, .closed) }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 5), .success); cap.close(); release.signal()
        wait(for: [done], timeout: 5); try f.unavailable(cap)
        XCTAssertThrowsError(try cap.restoreStartup(options, commitDigest: old, pendingChange: nil, verifyCurrent: { XCTFail() }))
    }
    func testJournalReentryRetainsTheFenceUntilPreparationCanRetryOnTheSameOwner() throws {
        let f = try Fixture(), cap = f.capability(), change = try change(); defer { cap.close() }
        try f.journal.withRequests { _ in
            XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: old, pendingChange: change, verifyCurrent: {})) {
                XCTAssertEqual($0 as? JournalDatabaseError, .transactionActive)
            }
        }
        try f.unavailable(cap)
        XCTAssertThrowsError(try cap.install(f.options, commitDigest: old, verifyCurrent: { XCTFail() }))
        XCTAssertTrue(try cap.restoreStartup(f.options, commitDigest: old, pendingChange: change, verifyCurrent: {}))
        try cap.quiesceSettings(change, verifyCurrent: {}); try cap.acceptSettings(change, verifyCurrent: {})
        try cap.install(f.options, commitDigest: next, verifyCurrent: {}); XCTAssertEqual(cap.installedCommitDigest, next)
    }
    func testOptionalStartupFailureAndRecoveryPreserveTheForegroundRequestAndItsDeadline() throws {
        let f = try Fixture(), cap = f.capability(), h = f.h, change = try change(); defer { cap.close() }
        let contract = try RequestContract(requestKind: .command, wireVersion: 1, schemaVersion: 1)
        let draft = ApprovalRequestDraft(contract: contract, requiredFeatures: [], capture: Data([0xa0]),
            actions: [.init(choice: .execute, scope: .currentRequest), .init(choice: .decline, scope: .currentRequest)],
            firstObservedAt: .init(epoch: h.clock, milliseconds: 100), deadlineMilliseconds: 5000,
            createdUnixMilliseconds: 1000, expiresUnixMilliseconds: 5900)
        let request = try f.journal.withRequests { try $0.admitFixture(draft, now: .init(epoch: h.clock, milliseconds: 110), receiptTimeMs: nil) }
        let before = try f.journal.withRequests { try $0.state(requestID: request.requestID) }
        XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: old, pendingChange: change, verifyCurrent: { throw Denied() }))
        XCTAssertEqual(try f.journal.withRequests { try $0.state(requestID: request.requestID) }, before)
        try cap.restoreStartup(f.options, commitDigest: old, pendingChange: change, verifyCurrent: {})
        try f.unavailable(cap)
        try cap.quiesceSettings(change, verifyCurrent: {}); try cap.acceptSettings(change, verifyCurrent: {})
        try cap.install(f.options, commitDigest: next, verifyCurrent: {})
        let after = try f.journal.withRequests { try $0.state(requestID: request.requestID) }
        XCTAssertEqual(after, before); XCTAssertEqual(after.deadlineMilliseconds, 5000)
        XCTAssertEqual(after.firstObservedAt.epoch, h.clock); XCTAssertTrue(try f.journal.validatePeer(h.binding))
    }
    func testInvalidStartupScopeAndLateStartupCannotReplaceAnExistingProvider() throws {
        let f = try Fixture(), cap = f.capability(), change = try change(); defer { cap.close() }
        XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: next, pendingChange: change, verifyCurrent: { XCTFail() }))
        XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: Data(), pendingChange: nil, verifyCurrent: { XCTFail() }))
        try cap.install(f.options, commitDigest: old, verifyCurrent: {}); cap.suspend()
        XCTAssertThrowsError(try cap.restoreStartup(f.options, commitDigest: old, pendingChange: change, verifyCurrent: { XCTFail() }))
        try cap.install(f.options, commitDigest: old, verifyCurrent: {}); XCTAssertEqual(cap.installedCommitDigest, old)
    }
}
