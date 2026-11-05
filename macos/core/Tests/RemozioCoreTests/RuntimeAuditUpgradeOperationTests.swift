import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeAuditUpgradeOperationTests: XCTestCase {
    private enum Failure: Error { case interrupted }
    final class Quiescence: RuntimeAuditCutoverQuiescence {
        var closeFails = false, validationFails = false
        func validateLifetime() throws {}
        func validateComplete() throws { if validationFails { throw Failure.interrupted } }
        func close() throws { if closeFails { throw Failure.interrupted } }
    }
    final class Harness {
        let base: RuntimeAuditUpgradeCutoverTests.Fixture
        let activity: ReleaseActivityFixture
        let installer: ReleaseActivityBarrier
        var preparations = 0, restores = 0, coordinators = 0, restarts = 0
        var q: Quiescence?
        var registered: [AuthorityCodeRole: RuntimeJobRegistration.Observation] = [:]
        var bootstraps: [AuthorityCodeRole: Int] = [:]
        var loseRestartReply = false
        var quiescenceValidationFails = false, quiescenceCloseFails = false
        var afterRestart: (() -> Void)?
        init(gateway: Bool = false, pending: Bool = false) throws {
            base = try .init(gateway: gateway, activeAndPending: pending)
            activity = try .init(); installer = try activity.open(); try base.runtime.machine.close()
        }
        func owner() throws -> SetupAccountOwner {
            try .init(openMachine: { try self.base.runtime.f.open() }, expectedReleaseDigest: base.runtime.f.release,
                resume: { _, _ in throw Failure.interrupted }, accountCodePolicy: base.policy,
                lookupAccount: { _ in self.base.runtime.f.identity }, releaseActivity: activity.open(),
                verifyAccountStartup: { _, _ in if try self.fencePresent() { throw RuntimeAuditUpgradeStartupError.recoveryRequired } })
        }
        func fencePresent() throws -> Bool {
            let dir = try XCTUnwrap(base.collector.files.directories[.services])
            return try ProtectedServiceConfiguration.readOptional(anchor: dir.path,
                relativePath: RuntimeAuditUpgradeStartupFence.fileName, owner: getuid()) != nil
        }
        func machine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            let m = try base.runtime.f.open(); defer { try? m.close() }; return try body(m)
        }
        func operation(_ owner: SetupAccountOwner) throws -> RuntimeAuditUpgradeOperation {
            let scope = try owner.acquireAuditUpgradeScope(authorization: .openOwned(verifyRights: {}))
            return try operation(scope: scope)
        }
        func operation(scope: SetupAuditUpgradeScope) throws -> RuntimeAuditUpgradeOperation {
            try .openOwned(scope: scope, installedRelease: base.release, activity: activity.open(),
                openMachine: { try self.base.runtime.f.open() }, adapters: .init(fencePresent: fencePresent, prepare: { _, token, verify in
                    try token.validateExclusive(); try verify(); self.preparations += 1
                    return .init(graph: self.base.graph, record: self.base.stored)
                }, restore: { machine, record, verify in
                    self.restores += 1
                    let stored = try RuntimeAuditUpgradeGraphStorage.restoreOwned(machine: machine, expected: record,
                        installedRelease: self.base.release, currentPolicy: self.base.policy,
                        directory: XCTUnwrap(self.base.collector.files.directories[.runtime]), owner: getuid(), verifyOwner: verify)
                    let graph = try RuntimeAuditUpgradeGraph.decode(machine.runtimeAuditGraphBytes(stored), expectedDigest: stored.contentDigest,
                        installedRelease: self.base.release, currentPolicy: self.base.policy, ownership: .ordinaryOwnerFixture)
                    return .init(graph: graph, record: stored)
                }, coordinator: { machine, binding, token, verify in
                    self.coordinators += 1
                    return try .openOwned(machine: machine, graph: binding.graph, record: binding.record,
                        installedRelease: self.base.release, currentPolicy: self.base.policy, rootActivity: token,
                        rootActivityOwnership: .borrowed,
                        directories: self.base.collector.files.directories, owner: getuid(), verifyOwner: verify,
                        acquireQuiescence: { _ in
                            let q = Quiescence(); q.validationFails = self.quiescenceValidationFails
                            q.closeFails = self.quiescenceCloseFails; self.q = q; return q
                        })
                }, restart: { binding, verify in
                    self.restarts += 1
                    let shared = try self.activity.open().acquireShared(); defer { shared.close() }
                    let ops = RuntimeAuditUpgradeRestartOperations(validateJob: { job, inventory, release, check in
                        try check(); try job.validate(job.bytes, inventory: inventory, release: release)
                        try AdministrativeSetupPublication.validateRetained(job.bytes,
                            file: .accountJob(accountID: self.base.runtime.account.accountID, role: job.declaration.role),
                            directory: XCTUnwrap(self.base.collector.files.directories[.jobs]), owner: getuid(), verify: check)
                    }, ensure: { job, check in
                        try self.machine { _ in () }
                        try RuntimeJobRegistration.reconcile(verifyCurrent: check,
                            inspect: { self.registered[job.declaration.role] ?? .absent }, bootstrap: {
                                self.bootstraps[job.declaration.role, default: 0] += 1
                                self.registered[job.declaration.role] = .matching
                            })
                    }, inspect: { job, check in try check(); return self.registered[job.declaration.role] ?? .absent })
                    let result = try RuntimeAuditUpgradeRestart.resumeOwned(graph: binding.graph, record: binding.record,
                        installedRelease: self.base.release, currentPolicy: self.base.policy,
                        openMachine: { try self.base.runtime.f.open() }, verifyOwnerAndActivity: { try shared.validate(); try verify() },
                        requireFenceAbsent: { if try self.fencePresent() { throw RuntimeAuditUpgradeStartupError.recoveryRequired } }, operations: ops)
                    self.afterRestart?()
                    if self.loseRestartReply { throw Failure.interrupted }
                    return result
                }))
        }
        func driveToRestart(_ op: RuntimeAuditUpgradeOperation) throws {
            for expected in [RuntimeAuditUpgradeOperation.Progress.graphPrepared, .filesChanging, .filesVerified, .metadataCommitted, .readyToRestart] {
                let result = try op.advance(); XCTAssertEqual(result, expected)
            }
        }
    }
    func testCompleteOwnedOperationClosesWriterBeforeRegistrationAndKeepsAdmissionUntilReplyCleanup() throws {
        let h = try Harness(gateway: true), owner = try h.owner(); defer { try? owner.close() }
        let op = try h.operation(owner); defer { try? op.close() }
        try h.driveToRestart(op)
        XCTAssertFalse(try h.fencePresent()); try h.machine { _ in () }
        let expected = RuntimeAuditUpgradeRestart.Result(selectedRoles: [.authority, .transport, .notificationGateway],
            registrationConfirmed: [.authority, .transport, .notificationGateway])
        XCTAssertEqual(try op.advance(), .registrationObserved(expected)); XCTAssertEqual(try op.advance(), .registrationObserved(expected))
        XCTAssertEqual(h.restarts, 1); XCTAssertThrowsError(try owner.verifyCurrent())
        try op.close(); try owner.verifyCurrent(); XCTAssertTrue(h.bootstraps.values.allSatisfy { $0 == 1 })
    }
    func testBorrowedRootActivityStaysHeldUntilTheCompletedCutoverClosesTheMachineWriter() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let op = try h.operation(owner); defer { try? op.close() }
        XCTAssertEqual(try op.advance(), .graphPrepared)
        XCTAssertThrowsError(try h.installer.acquireShared()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        for expected in [RuntimeAuditUpgradeOperation.Progress.filesChanging, .filesVerified, .metadataCommitted] {
            XCTAssertEqual(try op.advance(), expected)
            XCTAssertThrowsError(try h.installer.acquireShared()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        }
        XCTAssertEqual(try op.advance(), .readyToRestart)
        let update = try h.installer.acquireExclusive(); update.close()
        try h.machine { _ in () }; XCTAssertFalse(try h.fencePresent())
        XCTAssertEqual(h.restarts, 0); XCTAssertThrowsError(try owner.verifyCurrent())
    }
    func testBusyRootActivityDoesNotPublishAFenceOrRetainTheMachineWriter() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let blocker = try h.activity.open().acquireShared(); defer { blocker.close() }
        let op = try h.operation(owner); defer { try? op.close() }
        XCTAssertEqual(try op.advance(), .waitingForActivity); XCTAssertFalse(try h.fencePresent())
        XCTAssertEqual(h.preparations, 0); try h.machine { _ in () }
        blocker.close(); XCTAssertEqual(try op.advance(), .graphPrepared)
    }
    func testInterruptedFilePhaseRestoresTheSelectedGraphWithoutRecapturingSource() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let first = try h.operation(owner)
        XCTAssertEqual(try first.advance(), .graphPrepared); XCTAssertEqual(try first.advance(), .filesChanging)
        try first.close(); XCTAssertTrue(try h.fencePresent())
        let next = try h.operation(owner); defer { try? next.close() }
        XCTAssertEqual(try next.advance(), .graphPrepared); XCTAssertEqual(h.restores, 1); XCTAssertEqual(h.preparations, 1)
        XCTAssertEqual(try next.advance(), .filesVerified); XCTAssertEqual(try next.advance(), .metadataCommitted)
        XCTAssertEqual(try next.advance(), .readyToRestart)
    }
    func testMissingFenceAfterCommitUsesRegistrationRecoveryWithoutStoppingRunningTargetJobs() throws {
        let h = try Harness(gateway: true, pending: true), owner = try h.owner(); defer { try? owner.close() }
        let first = try h.operation(owner); try h.driveToRestart(first)
        h.loseRestartReply = true; XCTAssertThrowsError(try first.advance()); try first.close()
        let previousCoordinators = h.coordinators
        try h.machine { machine in
            let pending = try XCTUnwrap(machine.gatewaySettingsTransition(accountID: h.base.runtime.account.accountID).pending)
            try machine.markGatewaySettingsTransition(pending, phase: .filesPublished)
            try machine.markGatewaySettingsTransition(pending, phase: .consumersObserved)
            try machine.completeGatewaySettingsTransition(pending)
        }
        h.loseRestartReply = false
        let activeWork = try h.activity.open().acquireShared(); defer { activeWork.close() }
        let next = try h.operation(owner); defer { try? next.close() }
        XCTAssertEqual(try next.advance(), .readyToRestart)
        _ = try next.advance(); XCTAssertEqual(h.coordinators, previousCoordinators)
        XCTAssertTrue(h.bootstraps.values.allSatisfy { $0 == 1 }); XCTAssertEqual(h.preparations, 1)
    }
    func testCleanupFailureRetainsMachineRootActivityAndSetupAdmissionUntilRetry() throws {
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let op = try h.operation(owner)
        _ = try op.advance(); _ = try op.advance(); let q = try XCTUnwrap(h.q); q.closeFails = true
        XCTAssertThrowsError(try op.close()); XCTAssertThrowsError(try op.advance()); XCTAssertThrowsError(try owner.verifyCurrent())
        XCTAssertThrowsError(try h.installer.acquireShared()); XCTAssertThrowsError(try h.machine { _ in () })
        q.closeFails = false; try op.close(); try owner.verifyCurrent(); try h.machine { _ in () }
        XCTAssertTrue(try h.fencePresent())
    }
    func testNativeFactoryRefusesOrdinaryIdentityWithoutTakingTheCallersScope() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary owner") }
        let h = try Harness(), owner = try h.owner(); defer { try? owner.close() }
        let scope = try owner.acquireAuditUpgradeScope(authorization: .openOwned(verifyRights: {})); defer { try? scope.close() }
        XCTAssertThrowsError(try RuntimeAuditUpgradeOperation.open(scope: scope)) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        try scope.validateLifetime()
    }
}
