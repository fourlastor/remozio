import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Disposable owned files and SQLite exercise the sequence. Native runtime settlement remains unqualified.
final class RuntimeAuditUpgradeCutoverCoordinatorTests: XCTestCase {
    private enum Failure: Error { case expected }
    private final class Quiescence: RuntimeAuditCutoverQuiescence {
        var valid = true
        var complete = true
        var closeFails = false
        var closes = 0
        var lifetimeChecks = 0
        var completeChecks = 0
        var afterComplete: (() throws -> Void)?
        func validateLifetime() throws {
            lifetimeChecks += 1
            guard valid, closes == 0 else { throw Failure.expected }
        }
        func validateComplete() throws {
            completeChecks += 1
            guard complete, closes == 0 else { throw Failure.expected }
            try afterComplete?()
        }
        func close() throws { if closeFails { throw Failure.expected }; closes += 1 }
    }
    private final class Harness {
        let base: RuntimeAuditUpgradeCutoverTests.Fixture
        let activity: ReleaseActivityFixture
        let barrier: ReleaseActivityBarrier
        let observer: ReleaseActivityBarrier
        var token: ReleaseActivityToken
        var ready = true
        var valid = true
        var acquisitions = 0
        var retained: [Quiescence] = []
        var ownerCheck: (() throws -> Void)?
        private let ownsToken: Bool
        init(_ base: RuntimeAuditUpgradeCutoverTests.Fixture, activity: ReleaseActivityFixture? = nil,
             token: ReleaseActivityToken? = nil) throws {
            self.base = base; self.activity = try activity ?? .init()
            barrier = try self.activity.open(); observer = try self.activity.open()
            self.token = try token ?? barrier.acquireExclusive(); ownsToken = token == nil
        }
        deinit { if ownsToken { token.close() } }
        func verify() throws { guard valid else { throw Failure.expected }; try ownerCheck?() }
        func open(rootActivityOwnership: RuntimeAuditUpgradeCutoverCoordinator.RootActivityOwnership = .owned,
                  closePending: @escaping () throws -> Void = {}) throws -> RuntimeAuditUpgradeCutoverCoordinator {
            try .openOwned(machine: base.runtime.machine, graph: base.graph, record: base.stored,
                installedRelease: base.release, currentPolicy: base.policy, rootActivity: token,
                rootActivityOwnership: rootActivityOwnership,
                directories: base.collector.files.directories, owner: getuid(), verifyOwner: verify,
                acquireQuiescence: { _ in
                    self.acquisitions += 1
                    guard self.ready else { return nil }
                    let result = Quiescence(); self.retained.append(result); return result
                }, closePendingQuiescence: closePending)
        }
        func phase() throws -> RuntimeAuditUpgradeCutoverRecord.Phase? {
            try base.runtime.machine.runtimeAuditCutover(accountID: base.runtime.account.accountID)?.phase
        }
        func fenceExists() throws -> Bool {
            let directory = try XCTUnwrap(base.collector.files.directories[.services])
            return FileManager.default.fileExists(atPath: directory.path + "/" + AdministrativeSetupPublication.File.auditUpgradeStartupFence.name)
        }
        func inspect(_ expectation: RuntimeAuditUpgradeFiles.Expectation) throws {
            _ = try RuntimeAuditUpgradeFiles.validate(base.graph, directories: base.collector.files.directories,
                owner: getuid(), expectation: expectation, verifyOwnerAndBarrier: verify)
        }
        func changingPath() throws -> URL {
            let leaf = try XCTUnwrap(base.graph.snapshot.leaves.first { $0.source != $0.target && $0.source != nil })
            return URL(fileURLWithPath: try XCTUnwrap(base.collector.files.directories[leaf.entry.directory]).path)
                .appendingPathComponent(leaf.entry.file.name)
        }
        func assertHeld() { XCTAssertThrowsError(try observer.acquireShared()) }
        func assertReleased() throws { let shared = try observer.acquireShared(); try shared.validate(); shared.close() }
        func finish(_ coordinator: RuntimeAuditUpgradeCutoverCoordinator) throws {
            for expected in [RuntimeAuditUpgradeCutoverCoordinator.Progress.filesChanging, .filesVerified, .metadataCommitted, .eligibleForRestart] {
                let actual = try coordinator.advance(); XCTAssertEqual(actual, expected)
            }
        }
    }
    func testWaitingPublishesOnlyTheFenceAndKeepsTheRootLock() throws {
        let h = try Harness(.init()); h.ready = false
        let coordinator = try h.open(); defer { try? coordinator.close() }
        XCTAssertEqual(try coordinator.advance(), .waitingForQuiescence)
        XCTAssertEqual(try h.phase(), .selected); XCTAssertTrue(try h.fenceExists()); try h.inspect(.sourceOnly)
        h.assertHeld(); XCTAssertThrowsError(try coordinator.releaseForRestart())
        h.ready = true; try h.finish(coordinator)
        XCTAssertEqual(h.acquisitions, 2); XCTAssertEqual(h.retained.count, 1)
        h.assertHeld(); try coordinator.releaseForRestart(); try h.assertReleased()
    }
    func testRealFilesAndMetadataFinishBeforeRestartEligibilityReleasesResources() throws {
        let imported = try RuntimeAuditUpgradeImportTests.Fixture()
        for base in [try RuntimeAuditUpgradeCutoverTests.Fixture(registered: false),
                     try .init(gateway: true, activeAndPending: true), try .init(imported: imported)] {
            let h = try Harness(base), coordinator = try h.open(); defer { try? coordinator.close() }
            try h.finish(coordinator); try base.assertTarget(self); try h.inspect(.targetOnly)
            XCTAssertEqual(try h.phase(), .metadataCommitted); XCTAssertFalse(try h.fenceExists())
            XCTAssertEqual(h.acquisitions, 1); XCTAssertEqual(h.retained[0].closes, 0)
            XCTAssertGreaterThan(h.retained[0].lifetimeChecks, h.retained[0].completeChecks)
            h.assertHeld(); try coordinator.releaseForRestart()
            XCTAssertEqual(h.retained[0].closes, 1); try h.assertReleased()
            XCTAssertThrowsError(try coordinator.advance()); try coordinator.close()
        }
    }
    func testFreshOwnersReacquireQuiescenceAtEveryDurablePhaseIncludingCommittedCleanup() throws {
        let h = try Harness(.init(gateway: true, activeAndPending: true))
        var coordinator = try h.open()
        let expected: [RuntimeAuditUpgradeCutoverCoordinator.Progress] = [.filesChanging, .filesVerified, .metadataCommitted, .eligibleForRestart]
        for progress in expected {
            XCTAssertEqual(try coordinator.advance(), progress)
            try coordinator.close(); try h.assertReleased()
            h.token = try h.barrier.acquireExclusive(); coordinator = try h.open()
        }
        XCTAssertEqual(try coordinator.advance(), .eligibleForRestart)
        XCTAssertEqual(h.acquisitions, 5); XCTAssertEqual(h.retained.filter { $0.closes == 1 }.count, 4)
        try coordinator.releaseForRestart(); try h.assertReleased(); try h.base.assertTarget(self)
    }
    func testInterruptedAtomicPublicationResumesWithMixedFilesAndTheSameGraph() throws {
        let h = try Harness(.init()), first = try h.open()
        XCTAssertEqual(try first.advance(), .filesChanging)
        let current = try XCTUnwrap(h.base.runtime.machine.runtimeAuditCutover(accountID: h.base.runtime.account.accountID))
        var interrupted = false
        XCTAssertThrowsError(try RuntimeAuditUpgradeFiles.applyOwned(machine: h.base.runtime.machine, expected: current,
            graph: h.base.graph, installedRelease: h.base.release, currentPolicy: h.base.policy,
            directories: h.base.collector.files.directories, owner: getuid(), rootActivity: h.token,
            verifyOwnerAndBarrier: h.verify, didStage: { _, stage in
                if !interrupted && stage == .published { interrupted = true; throw Failure.expected }
            }))
        XCTAssertTrue(interrupted); XCTAssertTrue(try h.fenceExists()); try first.close()
        h.token = try h.barrier.acquireExclusive(); let resumed = try h.open(); defer { try? resumed.close() }
        XCTAssertEqual(try resumed.advance(), .filesVerified)
        XCTAssertEqual(try resumed.advance(), .metadataCommitted)
        XCTAssertEqual(try resumed.advance(), .eligibleForRestart)
        try resumed.releaseForRestart(); try h.base.assertTarget(self)
    }
    func testFailedSettlementRetiresTheInstanceAndPreservesTheFenceUntilFreshRecovery() throws {
        let h = try Harness(.init()), first = try h.open()
        XCTAssertEqual(try first.advance(), .filesChanging); h.retained[0].complete = false
        XCTAssertThrowsError(try first.advance()); XCTAssertEqual(try h.phase(), .filesChanging)
        XCTAssertTrue(try h.fenceExists()); try h.inspect(.sourceOnly); h.assertHeld()
        h.retained[0].complete = true; XCTAssertThrowsError(try first.advance())
        try first.close(); h.token = try h.barrier.acquireExclusive()
        let resumed = try h.open(); defer { try? resumed.close() }
        XCTAssertEqual(try resumed.advance(), .filesVerified)
        XCTAssertEqual(try resumed.advance(), .metadataCommitted)
        XCTAssertEqual(try resumed.advance(), .eligibleForRestart)
        try resumed.releaseForRestart(); XCTAssertEqual(h.acquisitions, 2)
    }
    func testLifetimeLossDuringCompleteValidationRefusesBeforeTheNextFileWrite() throws {
        let h = try Harness(.init()), coordinator = try h.open(); defer { try? coordinator.close() }
        XCTAssertEqual(try coordinator.advance(), .filesChanging)
        h.retained[0].afterComplete = { h.retained[0].valid = false }
        XCTAssertThrowsError(try coordinator.advance()); try h.inspect(.sourceOnly)
        XCTAssertEqual(try h.phase(), .filesChanging); XCTAssertTrue(try h.fenceExists()); h.assertHeld()
        h.retained[0].afterComplete = nil
    }
    func testChangedTargetAfterFileVerificationCannotCommitMachineRows() throws {
        let h = try Harness(.init()), coordinator = try h.open(); defer { try? coordinator.close() }
        XCTAssertEqual(try coordinator.advance(), .filesChanging); XCTAssertEqual(try coordinator.advance(), .filesVerified)
        try Data([0]).write(to: h.changingPath())
        XCTAssertThrowsError(try coordinator.advance()); XCTAssertEqual(try h.phase(), .filesVerified)
        XCTAssertEqual(try h.base.runtime.machine.runtimePreparation(accountID: h.base.runtime.account.accountID).reference,
            h.base.graph.upgrade.intent.source)
        XCTAssertTrue(try h.fenceExists()); h.assertHeld()
    }
    func testRestartReleaseRechecksTheTargetAfterEligibilityWasReported() throws {
        let h = try Harness(.init()), coordinator = try h.open(); defer { try? coordinator.close() }
        try h.finish(coordinator); try Data([0]).write(to: h.changingPath())
        XCTAssertThrowsError(try coordinator.releaseForRestart()); h.assertHeld()
        XCTAssertEqual(h.retained[0].closes, 0); XCTAssertThrowsError(try coordinator.advance())
    }
    func testFailedQuiescenceCleanupRetainsTheRootLockAndCanBeRetried() throws {
        let h = try Harness(.init()), coordinator = try h.open()
        XCTAssertEqual(try coordinator.advance(), .filesChanging)
        h.retained[0].closeFails = true
        XCTAssertThrowsError(try coordinator.close()); h.assertHeld(); XCTAssertTrue(try h.fenceExists())
        h.retained[0].closeFails = false; try coordinator.close(); try coordinator.close()
        XCTAssertEqual(h.retained[0].closes, 1); try h.assertReleased()
    }
    func testFailedConstructionLeavesTheCallersTokenOwnedByTheCaller() throws {
        let h = try Harness(.init()); h.token.close(); h.token = try h.barrier.acquireShared()
        XCTAssertThrowsError(try h.open()); try h.token.validate(); h.token.close()
        h.token = try h.barrier.acquireExclusive(); h.valid = false
        XCTAssertThrowsError(try h.open()); try h.token.validateExclusive(); h.assertHeld()
    }
    func testReentrantAdvanceAndCleanupCannotDropAnActiveBarrier() throws {
        let h = try Harness(.init()), coordinator = try h.open(); defer { try? coordinator.close() }
        var attempted = false
        h.ownerCheck = { [weak coordinator] in
            guard !attempted else { return }; attempted = true
            let current = try XCTUnwrap(coordinator)
            XCTAssertThrowsError(try current.advance()); XCTAssertThrowsError(try current.close())
        }
        XCTAssertEqual(try coordinator.advance(), .filesChanging); XCTAssertTrue(attempted); h.assertHeld()
        h.ownerCheck = nil
    }
    func testNativeEntryPointsRefuseBeforeOwnerCallbacksOrNativeFilesystemAccess() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary owner") }
        let h = try Harness(.init())
        XCTAssertThrowsError(try RuntimeAuditUpgradeCutoverCoordinator.open(machine: h.base.runtime.machine,
            graph: h.base.graph, record: h.base.stored, installedRelease: h.base.release, currentPolicy: h.base.policy,
            rootActivity: h.token, verifyOwner: { XCTFail("Native Root guard first") },
            acquireQuiescence: { _ in XCTFail("Native Root guard first"); return nil })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        XCTAssertThrowsError(try RuntimeAuditUpgradeFiles.validateNative(h.base.graph, expectation: .sourceOnly,
            verifyOwnerAndBarrier: { XCTFail("Native Root guard first") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        try h.token.validateExclusive()
    }

    func testBorrowedCutoverCompletesWithoutReleasingTheOuterAdmissionBoundary() throws {
        let f = try UpdateAdmissionTestFixture()
        let updater = try UpdateActivationAdmission(anchor: f.activity.root.path, relativeDirectory: "Machine",
            owner: getuid(), expected: f.identity)
        let lease = try XCTUnwrap(updater.automatic())
        try lease.withExclusiveActivity { token in
            let h = try Harness(.init(), activity: f.activity, token: token)
            let coordinator = try h.open(rootActivityOwnership: .borrowed)
            defer { try? coordinator.close() }
            try h.finish(coordinator); try coordinator.releaseForRestart()
            try h.base.assertTarget(self); h.assertHeld(); try token.validateExclusive()
            XCTAssertThrowsError(try f.open().acquireAdmission()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        }
        try lease.validate(); lease.close()
        let admitted = try f.open().acquireAdmission(), work = try f.activity.open().acquireShared()
        admitted.close(); work.close()
    }

    func testBorrowedCloseCleansPendingQuiescenceOnceAndPreservesTheFenceAndOuterLock() throws {
        let h = try Harness(.init()); h.ready = false
        var pendingCloses = 0
        var coordinator: RuntimeAuditUpgradeCutoverCoordinator? = try h.open(rootActivityOwnership: .borrowed,
            closePending: { pendingCloses += 1 })
        XCTAssertEqual(try coordinator!.advance(), .waitingForQuiescence)
        try coordinator!.close(); try coordinator!.close(); coordinator = nil
        XCTAssertEqual(pendingCloses, 1); XCTAssertTrue(try h.fenceExists())
        try h.token.validateExclusive(); h.assertHeld(); h.token.close(); try h.assertReleased()
    }

    func testDeinitializationCleansPendingOwnersWithoutClosingBorrowedActivity() throws {
        for ownership: RuntimeAuditUpgradeCutoverCoordinator.RootActivityOwnership in [.owned, .borrowed] {
            let h = try Harness(.init()); h.ready = false
            var pendingCloses = 0
            var coordinator: RuntimeAuditUpgradeCutoverCoordinator? = try h.open(rootActivityOwnership: ownership,
                closePending: { pendingCloses += 1 })
            XCTAssertEqual(try coordinator!.advance(), .waitingForQuiescence); coordinator = nil
            XCTAssertEqual(pendingCloses, 1); XCTAssertTrue(try h.fenceExists())
            if ownership == .borrowed { try h.token.validateExclusive(); h.assertHeld(); h.token.close() }
            else { XCTAssertThrowsError(try h.token.validateExclusive()) }
            try h.assertReleased()
        }
    }

    func testFailedBorrowedConstructionAdoptsNeitherTheOuterTokenNorPendingCleanup() throws {
        let h = try Harness(.init()); h.valid = false
        var pendingCloses = 0
        XCTAssertThrowsError(try h.open(rootActivityOwnership: .borrowed, closePending: { pendingCloses += 1 }))
        XCTAssertEqual(pendingCloses, 0); try h.token.validateExclusive(); h.assertHeld()
    }
}
