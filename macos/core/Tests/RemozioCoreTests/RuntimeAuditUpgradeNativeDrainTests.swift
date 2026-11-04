import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeAuditUpgradeNativeDrainTests: XCTestCase {
    private enum Failure: Error { case expected }
    private final class Harness {
        let base: RuntimeAuditUpgradeCutoverTests.Fixture
        let activity: ReleaseActivityFixture
        let rootBarrier: ReleaseActivityBarrier
        let root: ReleaseActivityToken
        let roles: ServiceReleaseActivityFixture
        let journals: CutoverJournalFixture
        let gateway: GatewayCutoverLeaseFixture
        var temporaryStopped = true
        var absent = true
        var valid = true
        var sessionFactories = 0
        var stops = 0
        var temporaryStops = 0
        var roleOpens = 0
        var gatewayOpens = 0
        init() throws {
            base = try .init(); activity = try .init(); rootBarrier = try activity.open(); root = try rootBarrier.acquireExclusive()
            roles = try .init(); journals = try .init(); gateway = try .init()
            try journals.journal.close(); journals.store.close()
        }
        deinit { root.close() }
        func make() throws -> RuntimeAuditUpgradeNativeDrain {
            try .openOwned(graph: base.stored, rootActivity: root, verifyOwner: { if !self.valid { throw Failure.expected } },
                makeSessions: { _ in
                    self.sessionFactories += 1
                    return [RuntimeJobStopSession(verifyCurrent: {}, inspect: { self.absent ? .absent : .matching(nil) },
                        capture: { _ in throw Failure.expected }, bootout: { self.stops += 1 })]
                }, stopTemporary: { self.temporaryStops += 1; return self.temporaryStopped }, requireTemporaryAbsent: {
                    guard self.temporaryStopped else { throw Failure.expected }
                }, openRole: { role in
                    self.roleOpens += 1; return try self.roles.open(role: role, update: true).acquireExclusive()
                }, openAuthority: {
                    try AuthorityJournalCutoverInspection(storage: self.journals.openTransferredStorage(readOnlyForCutover: true),
                        expectedPolicy: nil, verifyCurrent: {})
                }, openGateway: { self.gatewayOpens += 1; return try self.gateway.open() })
        }
        func current() throws -> RuntimeAuditUpgradeCutoverRecord { try base.select() }
        func assertAllRolesHeld() throws {
            for role in ServiceAccountPlan.roles { XCTAssertThrowsError(try roles.open(role: role).acquireShared()) }
        }
        func assertRolesReleased() throws {
            for role in ServiceAccountPlan.roles { let token = try roles.open(role: role).acquireShared(); token.close() }
        }
    }
    func testRealRoleJournalAndGatewayLocksRemainHeldThroughReadOnlyValidation() throws {
        let h = try Harness(), drain = try h.make(); defer { try? drain.close() }
        let current = try h.current(); XCTAssertNotNil(try drain.acquire(current)); try drain.validateLifetime(); try drain.validateComplete()
        try h.assertAllRolesHeld(); XCTAssertThrowsError(try h.journals.openJournal()); XCTAssertThrowsError(try h.gateway.open())
        XCTAssertEqual(h.stops, 0); XCTAssertEqual(h.sessionFactories, 1); XCTAssertEqual(h.roleOpens, 2)
        try drain.close(); try h.assertRolesReleased(); let journal = try h.journals.openJournal(); try journal.close()
        let gateway = try h.gateway.open(); gateway.close(); try h.root.validateExclusive()
        XCTAssertThrowsError(try drain.validateLifetime())
    }
    func testBusySecondRoleRetainsTheFirstTokenAndRetriesWithoutRecreatingSessions() throws {
        let h = try Harness(), drain = try h.make(), blocker = try h.roles.open(role: .gateway).acquireShared()
        defer { blocker.close(); try? drain.close() }
        let current = try h.current(); XCTAssertNil(try drain.acquire(current))
        XCTAssertThrowsError(try h.roles.open(role: .transport).acquireShared()); XCTAssertEqual(h.gatewayOpens, 0)
        blocker.close(); XCTAssertNotNil(try drain.acquire(current)); XCTAssertEqual(h.sessionFactories, 1)
        try drain.close(); try h.assertRolesReleased()
    }
    func testBusyAuthorityJournalWaitsWithBothRoleTokensHeld() throws {
        let h = try Harness(), drain = try h.make(), blocker = try h.journals.openJournal()
        defer { try? blocker.close(); try? drain.close() }
        let current = try h.current(); XCTAssertNil(try drain.acquire(current)); try h.assertAllRolesHeld()
        XCTAssertEqual(h.gatewayOpens, 0); try blocker.close(); XCTAssertNotNil(try drain.acquire(current))
        XCTAssertEqual(h.roleOpens, 2)
    }
    func testBusyGatewayRetainsThePairedAuthorityLeasesUntilRetry() throws {
        let h = try Harness(), drain = try h.make(), blocker = try h.gateway.open()
        defer { blocker.close(); try? drain.close() }
        let current = try h.current(); XCTAssertNil(try drain.acquire(current)); XCTAssertThrowsError(try h.journals.openJournal())
        blocker.close(); XCTAssertNotNil(try drain.acquire(current)); XCTAssertEqual(h.roleOpens, 2); XCTAssertEqual(h.gatewayOpens, 2)
    }
    func testTemporaryJobMustSettleBeforeAnyRoleOrStoreAcquisition() throws {
        let h = try Harness(); h.temporaryStopped = false
        let drain = try h.make(); defer { try? drain.close() }; let current = try h.current()
        XCTAssertNil(try drain.acquire(current)); XCTAssertEqual(h.roleOpens, 0)
        h.temporaryStopped = true; XCTAssertNotNil(try drain.acquire(current)); XCTAssertEqual(h.sessionFactories, 1)
        h.temporaryStopped = false; XCTAssertThrowsError(try drain.validateComplete()); try h.assertAllRolesHeld()
        h.temporaryStopped = true; XCTAssertThrowsError(try drain.validateComplete())
    }
    func testValidationNeverRetriesRemovalWhenAJobReappears() throws {
        let h = try Harness(), drain = try h.make(); defer { try? drain.close() }
        XCTAssertNotNil(try drain.acquire(h.current())); let temporaryStops = h.temporaryStops
        h.absent = false; XCTAssertThrowsError(try drain.validateComplete())
        XCTAssertEqual(h.stops, 0); XCTAssertEqual(h.temporaryStops, temporaryStops); try h.assertAllRolesHeld()
    }
    func testCoordinatorCleanupClosesPartiallyAcquiredDrainBeforeReleasingRoot() throws {
        let h = try Harness(), drain = try h.make(), blocker = try h.gateway.open()
        defer { blocker.close(); try? drain.close() }
        let c = try RuntimeAuditUpgradeCutoverCoordinator.openOwned(machine: h.base.runtime.machine, graph: h.base.graph,
            record: h.base.stored, installedRelease: h.base.release, currentPolicy: h.base.policy, rootActivity: h.root,
            directories: h.base.collector.files.directories, owner: getuid(), verifyOwner: {},
            acquireQuiescence: drain.acquire, closePendingQuiescence: drain.close)
        XCTAssertEqual(try c.advance(), .waitingForQuiescence); try h.assertAllRolesHeld()
        try c.close(); try h.assertRolesReleased(); let journal = try h.journals.openJournal(); try journal.close()
        XCTAssertThrowsError(try h.root.validate())
    }
    func testCompleteOwnedCutoverUsesRealResourcesAndKeepsThemUntilRestartRelease() throws {
        let h = try Harness(), drain = try h.make(); defer { try? drain.close() }
        let c = try RuntimeAuditUpgradeCutoverCoordinator.openOwned(machine: h.base.runtime.machine, graph: h.base.graph,
            record: h.base.stored, installedRelease: h.base.release, currentPolicy: h.base.policy, rootActivity: h.root,
            directories: h.base.collector.files.directories, owner: getuid(), verifyOwner: {},
            acquireQuiescence: drain.acquire, closePendingQuiescence: drain.close)
        defer { try? c.close() }
        for expected in [RuntimeAuditUpgradeCutoverCoordinator.Progress.filesChanging, .filesVerified, .metadataCommitted, .eligibleForRestart] {
            let progress = try c.advance(); XCTAssertEqual(progress, expected)
        }
        try h.base.assertTarget(self); try h.assertAllRolesHeld(); XCTAssertEqual(h.stops, 0)
        try c.releaseForRestart(); try h.assertRolesReleased(); XCTAssertThrowsError(try h.root.validate())
    }
    func testNativeFactoriesRefuseBeforeCallbacksAndFilesystemOrLaunchdAccess() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary owner") }
        let h = try Harness()
        XCTAssertThrowsError(try RuntimeAuditUpgradeNativeDrain.open(graph: h.base.graph, record: h.base.stored,
            rootActivity: h.root, verifyOwner: { XCTFail("Root guard first") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try GatewayJournalCutoverLease.open(graph: h.base.graph, rootActivity: h.root,
            verifyOwner: { XCTFail("Root guard first") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try RuntimeAuditUpgradeCutoverCoordinator.openWithNativeDrain(machine: h.base.runtime.machine,
            graph: h.base.graph, record: h.base.stored, installedRelease: h.base.release, currentPolicy: h.base.policy,
            rootActivity: h.root, verifyOwner: { XCTFail("Root guard first") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        try h.root.validateExclusive()
    }
}
