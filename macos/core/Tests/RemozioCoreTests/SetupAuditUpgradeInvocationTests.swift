import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned cutover fixtures and fake rights only. Native XPC, Root execution and installed services remain unqualified.
final class SetupAuditUpgradeInvocationTests: XCTestCase {
    typealias Harness = RuntimeAuditUpgradeOperationTests.Harness
    private struct Refused: Error {}
    private func progress(_ owner: SetupAccountOwner) throws -> SetupAuditUpgradeProgress {
        try XCTUnwrap(owner.auditUpgradeProgress(callerUID: getuid()))
    }
    private func begin(_ h: Harness, _ owner: SetupAccountOwner, expected: SetupAuditUpgradeProgress? = nil,
                       rights: @escaping () throws -> Void = {}) throws -> SetupAuditUpgradeInvocation {
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: rights)
        do {
            return try .openOwned(owner: owner, expected: expected ?? progress(owner), authorization: grant,
                openOperation: h.operation(scope:))
        } catch { grant.close(); throw error }
    }
    func testCompleteInvocationKeepsAdmissionThroughReplyAndReportsOnlyObservedRegistrations() throws {
        let h = try Harness(gateway: true), owner = try h.owner(); defer { try? owner.close() }
        let expected = try progress(owner), invocation = try begin(h, owner)
        var replies = 0
        try invocation.run { bytes in
            replies += 1
            let result = try SetupAuditUpgradeProgress.decode(bytes)
            try result.validateScope(of: expected)
            XCTAssertEqual(result.stage, .registrationObserved)
            XCTAssertEqual(result.registrationObserved, [.authority, .transport, .notificationGateway])
            XCTAssertThrowsError(try owner.verifyCurrent()); XCTAssertThrowsError(try invocation.close())
        }
        XCTAssertEqual(replies, 1); XCTAssertThrowsError(try invocation.run { _ in XCTFail("Duplicate reply") })
        XCTAssertThrowsError(try owner.verifyCurrent()); try invocation.close(); try owner.verifyCurrent()
        let retained = try progress(owner)
        XCTAssertEqual(retained.stage, .metadataCommitted); XCTAssertTrue(retained.registrationObserved.isEmpty)
        try retained.validateScope(of: expected)
        XCTAssertTrue(h.bootstraps.values.allSatisfy { $0 == 1 })
    }
    func testBusyActivityReturnsOneObservationWithoutPollingOrHoldingTheMachineWriter() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let blocker = try h.activity.open().acquireShared(); defer { blocker.close() }
        let invocation = try begin(h, owner)
        try invocation.run { bytes in XCTAssertEqual(try SetupAuditUpgradeProgress.decode(bytes).stage, .waitingForActivity) }
        XCTAssertEqual(h.preparations, 0); XCTAssertFalse(try h.fencePresent()); try h.machine { _ in () }
        try invocation.close(); blocker.close()
        let retry = try begin(h, owner); defer { try? retry.close() }
        try retry.run { bytes in XCTAssertEqual(try SetupAuditUpgradeProgress.decode(bytes).stage, .registrationObserved) }
    }
    func testFencedRecoveryReadDoesNotOpenNormalSetupAndResumesTheSelectedGraph() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let original = try progress(owner), first = try h.operation(owner)
        _ = try first.advance(); _ = try first.advance(); try first.close()
        XCTAssertThrowsError(try owner.runtimeProgress(callerUID: getuid()))
        XCTAssertEqual(try progress(owner).stage, .filesChanging)
        let invocation = try begin(h, owner, expected: original.observing(.alreadyCurrent)); defer { try? invocation.close() }
        try invocation.run { bytes in XCTAssertEqual(try SetupAuditUpgradeProgress.decode(bytes).stage, .registrationObserved) }
        XCTAssertEqual(h.preparations, 1); XCTAssertEqual(h.restores, 1)
    }
    func testForeignScopeRefusesBeforeOpeningOperationAndReleasesItsReservation() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let other = try Harness(), otherOwner = try other.owner(); defer { try? otherOwner.close() }
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
        var opened = false
        XCTAssertThrowsError(try SetupAuditUpgradeInvocation.openOwned(owner: owner, expected: progress(otherOwner), authorization: grant,
            openOperation: { scope in opened = true; return try h.operation(scope: scope) }))
        XCTAssertFalse(opened); XCTAssertThrowsError(try grant.validate()); try owner.verifyCurrent()
    }
    func testFailedDrainCleanupRetainsMachineAndRootActivityUntilRetryWithoutRights() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        h.quiescenceValidationFails = true; h.quiescenceCloseFails = true
        var valid = true
        let invocation = try begin(h, owner, rights: { if !valid { throw Refused() } })
        XCTAssertThrowsError(try invocation.run { _ in XCTFail("Unverified result") })
        XCTAssertThrowsError(try invocation.close()); XCTAssertThrowsError(try owner.verifyCurrent())
        XCTAssertThrowsError(try h.installer.acquireShared()); XCTAssertThrowsError(try h.machine { _ in () })
        valid = false; try XCTUnwrap(h.q).closeFails = false
        try invocation.close(); try owner.verifyCurrent(); try h.machine { _ in () }
        XCTAssertTrue(try h.fencePresent())
    }
    func testSetupOwnerRetainsFailedCleanupAfterConnectionDropsItsLastReference() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        h.quiescenceValidationFails = true; h.quiescenceCloseFails = true
        var valid = true
        var invocation: SetupAuditUpgradeInvocation? = try begin(h, owner, rights: { if !valid { throw Refused() } })
        weak var observed = invocation
        defer { observed = nil }
        XCTAssertThrowsError(try XCTUnwrap(invocation).run { _ in XCTFail("Unverified result") })
        XCTAssertFalse(owner.settleAuditUpgradeInvocation(try XCTUnwrap(invocation)))
        XCTAssertFalse(owner.settleAuditUpgradeInvocation(try XCTUnwrap(invocation)))
        invocation = nil
        XCTAssertNotNil(observed); XCTAssertFalse(owner.retryAuditUpgradeCleanup())
        XCTAssertThrowsError(try owner.close()); XCTAssertThrowsError(try h.installer.acquireShared())
        valid = false; try XCTUnwrap(h.q).closeFails = false
        XCTAssertTrue(owner.retryAuditUpgradeCleanup()); XCTAssertNil(observed)
        try owner.close(); try h.machine { _ in () }
        XCTAssertTrue(owner.retryAuditUpgradeCleanup())
    }
    func testFailedReplyHoldsAdmissionUntilTheSetupOwnerSettlesTheInvocation() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let blocker = try h.activity.open().acquireShared(); defer { blocker.close() }
        var invocation: SetupAuditUpgradeInvocation? = try begin(h, owner)
        weak var observed = invocation
        defer { observed = nil }
        XCTAssertThrowsError(try XCTUnwrap(invocation).run { _ in throw Refused() })
        // The failed reply retires the invocation. It still owns the operation, the setup scope and both admissions.
        XCTAssertThrowsError(try owner.verifyCurrent())
        XCTAssertThrowsError(try owner.acquireAuditUpgradeScope(authorization: .openOwned(verifyRights: {})))
        XCTAssertTrue(owner.settleAuditUpgradeInvocation(try XCTUnwrap(invocation)))
        invocation = nil
        XCTAssertNil(observed); XCTAssertTrue(owner.retryAuditUpgradeCleanup())
        try owner.verifyCurrent(); try h.machine { _ in () }
    }
    func testShutdownFinishesRetainedCleanupWithoutNewRightsOrConnections() throws {
        let h = try Harness(), owner = try h.owner()
        h.quiescenceValidationFails = true; h.quiescenceCloseFails = true
        var valid = true
        var invocation: SetupAuditUpgradeInvocation? = try begin(h, owner, rights: { if !valid { throw Refused() } })
        XCTAssertThrowsError(try XCTUnwrap(invocation).run { _ in XCTFail("Unverified result") })
        XCTAssertFalse(owner.settleAuditUpgradeInvocation(try XCTUnwrap(invocation)))
        invocation = nil; valid = false
        // A failed close leaves the owner closing. It refuses new work but keeps the retained cleanup.
        XCTAssertThrowsError(try owner.close())
        XCTAssertThrowsError(try owner.acquireAuditUpgradeScope(authorization: .openOwned(verifyRights: {})))
        XCTAssertThrowsError(try h.installer.acquireShared())
        let closed = expectation(description: "Owner closed after retained cleanup")
        Task.detached {
            do { try await owner.closeWhenIdle() } catch { XCTFail("Shutdown: \(error)") }
            closed.fulfill()
        }
        // Shutdown keeps retrying while cleanup fails. The exclusive Root activity token stays with the retained operation.
        Thread.sleep(forTimeInterval: 0.5)
        XCTAssertThrowsError(try h.installer.acquireShared())
        try XCTUnwrap(h.q).closeFails = false
        wait(for: [closed], timeout: 10)
        XCTAssertTrue(owner.retryAuditUpgradeCleanup()); XCTAssertThrowsError(try owner.verifyCurrent())
        let update = try h.installer.acquireExclusive(); update.close()
        try h.machine { _ in () }
    }
    func testRightsExpiryAfterRegistrationPreventsReplyAndLeavesRecoveryAvailable() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        var valid = true; h.afterRestart = { valid = false }
        let invocation = try begin(h, owner, rights: { if !valid { throw Refused() } })
        XCTAssertThrowsError(try invocation.run { _ in XCTFail("Expired reply") })
        try invocation.close(); XCTAssertEqual(try progress(owner).stage, .metadataCommitted)
        h.afterRestart = nil
        let retry = try begin(h, owner); defer { try? retry.close() }
        try retry.run { bytes in XCTAssertEqual(try SetupAuditUpgradeProgress.decode(bytes).stage, .registrationObserved) }
        XCTAssertTrue(h.bootstraps.values.allSatisfy { $0 == 1 }); XCTAssertEqual(h.preparations, 1)
    }
    func testCancelledTaskCannotStartTheCutoverAndCleanupNeedsNoLiveTask() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let invocation = try begin(h, owner)
        let (stream, continuation) = AsyncStream<Void>.makeStream()
        let completed = expectation(description: "Cancelled invocation settled")
        let task = Task { [stream, invocation, completed] in
            defer { completed.fulfill() }
            for await _ in stream {}
            do { try invocation.run { _ in throw Refused() }; XCTFail("Cancelled invocation") }
            catch is CancellationError {} catch { XCTFail("Unexpected error: \(error)") }
        }
        task.cancel(); continuation.finish()
        wait(for: [completed], timeout: 5)
        XCTAssertEqual(h.preparations, 0); XCTAssertFalse(try h.fencePresent())
        XCTAssertThrowsError(try invocation.run { _ in XCTFail("Retired invocation") })
        try invocation.close(); try owner.verifyCurrent(); try h.machine { _ in () }
    }
    func testReplyFailureCannotResendAndKeepsOwnershipUntilCleanup() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let blocker = try h.activity.open().acquireShared(); defer { blocker.close() }
        let invocation = try begin(h, owner)
        XCTAssertThrowsError(try invocation.run { _ in throw Refused() })
        XCTAssertThrowsError(try invocation.run { _ in XCTFail("Duplicate reply") })
        XCTAssertThrowsError(try owner.verifyCurrent()); try invocation.close(); try owner.verifyCurrent()
    }
    func testNativeFactoryRefusesOrdinaryIdentityAndLeavesAuthorizationWithCaller() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary owner") }
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {}); defer { grant.close() }
        XCTAssertThrowsError(try SetupAuditUpgradeInvocation.open(owner: owner, expected: progress(owner), authorization: grant)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        try grant.validate(); try owner.verifyCurrent()
    }
    func testAlreadySelectedAuditReturnsWithoutPreparingOrRegisteringAnything() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true, phoneAudit: true, auditDelivery: true)
        let activity = try ReleaseActivityFixture(), policy = f.plan.host.codePolicy
        try f.machine.close()
        let owner = try SetupAccountOwner(openMachine: { try f.f.open() }, expectedReleaseDigest: f.f.release,
            resume: { _, _ in throw Refused() }, accountCodePolicy: policy, lookupAccount: { _ in f.f.identity }, releaseActivity: activity.open())
        defer { try? owner.close() }
        let expected = try progress(owner); XCTAssertEqual(expected.stage, .alreadyCurrent)
        let grant = try SetupAuditUpgradeAuthorization.openOwned(verifyRights: {})
        let invocation = try SetupAuditUpgradeInvocation.openOwned(owner: owner, expected: expected, authorization: grant, openOperation: { scope in
            try RuntimeAuditUpgradeOperation.openOwned(scope: scope, installedRelease: XCTUnwrap(f.nativeRelease), activity: activity.open(),
                openMachine: { try f.f.open() }, adapters: .init(fencePresent: { false }, prepare: { _, _, _ in nil },
                    restore: { _, _, _ in throw Refused() }, coordinator: { _, _, _, _ in throw Refused() }, restart: { _, _ in throw Refused() }))
        })
        defer { try? invocation.close() }
        try invocation.run { bytes in
            let result = try SetupAuditUpgradeProgress.decode(bytes)
            XCTAssertEqual(result, expected); XCTAssertTrue(result.registrationObserved.isEmpty)
        }
    }
    func testProgressRoundTripsEveryObservationAndRejectsMalformedAuthorityClaims() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let base = try progress(owner)
        let observations: [RuntimeAuditUpgradeOperation.Progress] = [.waitingForActivity, .waitingForMachine, .graphPrepared,
            .waitingForQuiescence, .filesChanging, .filesVerified, .metadataCommitted, .readyToRestart, .alreadyCurrent,
            .registrationObserved(.init(selectedRoles: [], registrationConfirmed: [])),
            .registrationObserved(.init(selectedRoles: [.authority, .transport], registrationConfirmed: [.authority, .transport]))]
        for observation in observations {
            let value = try base.observing(observation)
            XCTAssertEqual(try SetupAuditUpgradeProgress.decode(value.bytes), value); try value.validateScope(of: base)
        }
        XCTAssertEqual(base.description, "SetupAuditUpgradeProgress(redacted)")
        XCTAssertThrowsError(try base.observing(.registrationObserved(.init(selectedRoles: [.authority, .transport], registrationConfirmed: [.authority]))))
        let limits = try CBORLimits(maxBytes: 4096, maxDepth: 2, maxItems: 64)
        guard case .map(let fields) = try DeterministicCBOR.decode(base.bytes, limits: limits) else { return XCTFail() }
        for edit: [UInt64: CBORValue] in [[0: .unsigned(2)], [7: .null], [5: .unsigned(99)], [4: .bytes(Data())],
            [6: .array([.unsigned(AuthorityCodeRole.app.rawValue)])],
            [5: .unsigned(SetupAuditUpgradeProgress.Stage.registrationObserved.rawValue), 6: .array([.unsigned(2), .unsigned(2)])],
            [5: .unsigned(SetupAuditUpgradeProgress.Stage.registrationObserved.rawValue), 6: .array([.unsigned(6)])]] {
            var changed = fields; for (key, value) in edit { changed[key] = value }
            XCTAssertThrowsError(try SetupAuditUpgradeProgress.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        var changed = fields; changed[4] = .bytes(Data(repeating: 71, count: 32))
        let foreign = try SetupAuditUpgradeProgress.decode(DeterministicCBOR.encode(.map(changed), limits: limits))
        XCTAssertThrowsError(try foreign.validateScope(of: base))
    }
}
