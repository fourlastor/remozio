import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeAuditUpgradeRestartTests: XCTestCase {
    private enum Failure: Error { case expected }
    private final class Quiescence: RuntimeAuditCutoverQuiescence {
        func validateLifetime() throws {}
        func validateComplete() throws {}
        func close() throws {}
    }
    private final class Harness {
        let base: RuntimeAuditUpgradeCutoverTests.Fixture
        let activity: ReleaseActivityFixture
        let barrier: ReleaseActivityBarrier
        var token: ReleaseActivityToken
        var registered: [AuthorityCodeRole: RuntimeJobRegistration.Observation] = [:]
        var bootstraps: [AuthorityCodeRole: Int] = [:]
        var loseReply = false
        var valid = true
        var afterRegister: (AuthorityCodeRole) throws -> Void = { _ in }
        init(_ base: RuntimeAuditUpgradeCutoverTests.Fixture, advances: Int = 4) throws {
            self.base = base; activity = try .init(); barrier = try activity.open(); token = try barrier.acquireExclusive()
            let c = try RuntimeAuditUpgradeCutoverCoordinator.openOwned(machine: base.runtime.machine, graph: base.graph,
                record: base.stored, installedRelease: base.release, currentPolicy: base.policy, rootActivity: token,
                directories: base.collector.files.directories, owner: getuid(), verifyOwner: {}, acquireQuiescence: { _ in Quiescence() })
            for _ in 0..<advances { _ = try c.advance() }
            if advances == 4 { try c.releaseForRestart() } else { try c.close() }
            try base.runtime.machine.close(); token = try barrier.acquireShared()
        }
        deinit { token.close() }
        func probeMachineAvailable() throws {
            let machine = try base.runtime.f.open(); try machine.close()
        }
        func fence() throws {
            let directory = try XCTUnwrap(base.collector.files.directories[.services])
            try RuntimeAuditUpgradeStartupFence.requireOpen(macID: base.runtime.account.macID, accountID: base.runtime.account.accountID,
                read: { try ProtectedServiceConfiguration.readOptional(anchor: directory.path,
                    relativePath: RuntimeAuditUpgradeStartupFence.fileName, owner: getuid()) })
        }
        func createFence() throws {
            let directory = try XCTUnwrap(base.collector.files.directories[.services])
            let bytes = try RuntimeAuditUpgradeStartupFence(.init(graph: base.stored, phase: .metadataCommitted)).encoded
            let path = directory.path + "/" + RuntimeAuditUpgradeStartupFence.fileName
            try bytes.write(to: URL(fileURLWithPath: path)); XCTAssertEqual(chmod(path, 0o644), 0)
        }
        func operations() -> RuntimeAuditUpgradeRestartOperations {
            .init(validateJob: { job, inventory, release, verify in
                try verify(); try job.validate(job.bytes, inventory: inventory, release: release)
                let directory = try XCTUnwrap(self.base.collector.files.directories[.jobs])
                try AdministrativeSetupPublication.validateRetained(job.bytes,
                    file: .accountJob(accountID: self.base.runtime.account.accountID, role: job.declaration.role),
                    directory: directory, owner: getuid(), verify: verify)
            }, ensure: { job, verify in
                try self.probeMachineAvailable()
                let role = job.declaration.role
                try RuntimeJobRegistration.reconcile(verifyCurrent: verify, inspect: { self.registered[role] ?? .absent }, bootstrap: {
                    try self.probeMachineAvailable()
                    self.bootstraps[role, default: 0] += 1; self.registered[role] = .matching
                    if self.loseReply { throw Failure.expected }
                })
                try self.probeMachineAvailable()
            }, inspect: { job, verify in
                try self.probeMachineAvailable(); try verify(); return self.registered[job.declaration.role] ?? .absent
            })
        }
        func run() throws -> RuntimeAuditUpgradeRestart.Result {
            try RuntimeAuditUpgradeRestart.resumeOwned(graph: base.graph, record: base.stored, installedRelease: base.release, currentPolicy: base.policy,
                openMachine: { try self.base.runtime.f.open() }, verifyOwnerAndActivity: {
                    try self.token.validate(); if !self.valid { throw Failure.expected }
                }, requireFenceAbsent: fence, operations: operations(), didRegister: { try self.afterRegister($0) })
        }
    }
    func testOnlyTheOriginalRegistrationChoicesRestartAndNoFlagsAreRewritten() throws {
        for base in [try RuntimeAuditUpgradeCutoverTests.Fixture(registered: false),
                     try .init(), try .init(gateway: true), try .init(partialGateway: true)] {
            let h = try Harness(base), result = try h.run(), p = base.graph.snapshot.plan
            var expected = Set<AuthorityCodeRole>()
            if p.sourceJobsRegistered { expected.formUnion([.authority, .transport]) }
            if p.gateway.activation.jobRegistered { expected.insert(.notificationGateway) }
            XCTAssertEqual(result.selectedRoles, expected); XCTAssertEqual(result.registrationConfirmed, expected)
            XCTAssertEqual(Set(h.bootstraps.keys), expected); XCTAssertTrue(h.bootstraps.values.allSatisfy { $0 == 1 })
            let machine = try base.runtime.f.open(); defer { try? machine.close() }
            XCTAssertEqual(try machine.runtimeActivation(accountID: base.runtime.account.accountID).jobsRegistered, p.sourceJobsRegistered)
            XCTAssertEqual(try machine.gatewayRuntimeActivation(accountID: base.runtime.account.accountID).jobRegistered, p.gateway.activation.jobRegistered)
        }
    }
    func testLostBootstrapRepliesReconcileWithoutDuplicateRegistration() throws {
        let h = try Harness(.init(gateway: true)); h.loseReply = true
        let first = try h.run(), second = try h.run()
        XCTAssertEqual(first, second); XCTAssertEqual(first.registrationConfirmed, [.authority, .transport, .notificationGateway])
        XCTAssertTrue(h.bootstraps.values.allSatisfy { $0 == 1 })
    }
    func testInterruptionAfterOneJobResumesFromActualMatchingRegistrations() throws {
        let h = try Harness(.init(gateway: true))
        h.afterRegister = { if $0 == .authority { throw Failure.expected } }
        XCTAssertThrowsError(try h.run()); XCTAssertEqual(h.bootstraps, [.authority: 1])
        h.afterRegister = { _ in }; let result = try h.run()
        XCTAssertEqual(result.registrationConfirmed, [.authority, .transport, .notificationGateway])
        XCTAssertTrue(h.bootstraps.values.allSatisfy { $0 == 1 })
    }
    func testNormalPendingSettingsRecoveryCanAdvanceAfterTheFirstJobStarts() throws {
        let h = try Harness(.init(gateway: true, activeAndPending: true))
        h.afterRegister = { [weak h] role in
            guard role == .authority else { return }
            let h = try XCTUnwrap(h)
            let machine = try h.base.runtime.f.open(); defer { try? machine.close() }
            let pending = try XCTUnwrap(machine.gatewaySettingsTransition(accountID: h.base.runtime.account.accountID).pending)
            try machine.markGatewaySettingsTransition(pending, phase: .filesPublished)
            try machine.markGatewaySettingsTransition(pending, phase: .consumersObserved)
            try machine.completeGatewaySettingsTransition(pending)
        }
        XCTAssertEqual(try h.run().registrationConfirmed, [.authority, .transport, .notificationGateway])
    }
    func testUncommittedMetadataOrExistingFenceCannotStartAnyJob() throws {
        for committed in [false, true] {
            let h = try Harness(.init(), advances: committed ? 4 : 2)
            if committed { try h.createFence() }
            XCTAssertThrowsError(try h.run()); XCTAssertTrue(h.bootstraps.isEmpty)
        }
    }
    func testEverySelectedPlistIsValidatedBeforeAnyJobCanStart() throws {
        let h = try Harness(.init(gateway: true)), job = try XCTUnwrap(h.base.graph.snapshot.plan.gateway.activation.plan).gatewayJob
        let directory = try XCTUnwrap(h.base.collector.files.directories[.jobs])
        let file = AdministrativeSetupPublication.File.accountJob(accountID: h.base.runtime.account.accountID, role: job.declaration.role)
        try Data([0]).write(to: URL(fileURLWithPath: directory.path + "/" + file.name))
        XCTAssertThrowsError(try h.run()); XCTAssertTrue(h.bootstraps.isEmpty)
    }
    func testNewFenceBetweenJobsStopsFurtherRegistrationWithoutUndoingTheFirst() throws {
        let h = try Harness(.init(gateway: true))
        h.afterRegister = { [weak h] in if $0 == .authority { try XCTUnwrap(h).createFence() } }
        XCTAssertThrowsError(try h.run()); XCTAssertEqual(h.bootstraps, [.authority: 1])
    }
    func testConflictingRegistrationIsNeverReplacedOrCountedAsSuccess() throws {
        let h = try Harness(.init(gateway: true)); h.registered[.authority] = .conflicting
        XCTAssertThrowsError(try h.run()) { XCTAssertEqual($0 as? RuntimeActivationError, .conflictingPlan) }
        XCTAssertTrue(h.bootstraps.isEmpty); XCTAssertEqual(h.registered[.authority], .conflicting)
    }
    func testOwnerLossAfterFirstJobStopsRemainingRegistrations() throws {
        let h = try Harness(.init(gateway: true)); h.afterRegister = { [weak h] in if $0 == .authority { try XCTUnwrap(h).valid = false } }
        XCTAssertThrowsError(try h.run()); XCTAssertEqual(h.bootstraps, [.authority: 1])
    }
    func testNativeFactoriesRefuseOrdinaryIdentityBeforeOwnerOrJobCommands() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary owner") }
        let base = try RuntimeAuditUpgradeCutoverTests.Fixture()
        XCTAssertThrowsError(try RuntimeAuditUpgradeRestart.resume(graph: base.graph, record: base.stored,
            installedRelease: base.release, currentPolicy: base.policy, verifyOwner: { XCTFail("Root guard first") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        XCTAssertThrowsError(try RuntimeJobRegistration.inspect(base.graph.snapshot.plan.preparation.target.authorityJob)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
