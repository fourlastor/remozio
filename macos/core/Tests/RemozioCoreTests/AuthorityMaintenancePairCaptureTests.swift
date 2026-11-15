import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class AuthorityMaintenancePairCaptureTests: XCTestCase {
    private func stores(_ policy: AuthorityCodePolicy) throws -> CheckpointedJournalTests.Fixture {
        let f = try CheckpointedJournalTests.Fixture()
        _ = try CheckpointedJournal(journal: f.journal, continuity: f.store).write(epoch: f.epoch) {
            try $0.installCodePolicy(policy, expectedRevision: nil)
        }
        try f.journal.close(); f.store.close(); return f
    }
    private func open(_ f: MaintenanceStopTestFixture, scope: UpdateOrdinaryAdmissionLease.Scope,
        drain: UpdateDrainToken? = nil, expected: PreparationFileIdentity? = nil,
        stores: CheckpointedJournalTests.Fixture, opened: (() -> Void)? = nil,
        verify: @escaping () throws -> Void = {}) throws -> AuthorityJournalCutoverInspection {
        try .openOwnedForMaintenance(accountID: f.cohort.accountID, policy: f.runtime.plan.host.codePolicy,
            scope: scope, drain: drain ?? f.drain, directory: f.directory, machineIdentity: f.cohort.machineIdentity,
            accountIdentity: expected ?? f.cohort.accountIdentity, verifyOwner: verify,
            openStorage: { opened?(); return try stores.openTransferredStorage(readOnlyForCutover: true) })
    }
    func testSharedMachineAndExactAccountDrainHoldBothRealStoreLocksWithoutTakingMachineExclusive() throws {
        let f = try MaintenanceStopTestFixture(), storage = try stores(f.runtime.plan.host.codePolicy)
        try f.ordinary.withMachineAdmission { scope in
            let pair = try open(f, scope: scope, stores: storage); defer { try? pair.close() }
            try pair.validate(); XCTAssertFalse(pair.snapshot.requiresStartupOutcomeRecovery)
            let machine = try f.files.open().acquireAdmission(); defer { machine.close() }; try machine.validate()
            XCTAssertThrowsError(try f.files.activity.open().acquireExclusive())
            XCTAssertThrowsError(try storage.openJournal()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            XCTAssertThrowsError(try storage.openStore()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        }
        let journal = try storage.openJournal(); try journal.close()
        let continuity = try storage.openStore(); continuity.close()
        try f.drain.validate(); try f.ordinary.validate()
    }
    func testWrongAccountOrMachineDrainFailsBeforeOpeningEitherStore() throws {
        let f = try MaintenanceStopTestFixture(), storage = try stores(f.runtime.plan.host.codePolicy)
        let (other, _) = try f.files.provisionAccount(maintenanceCloseBytes(96))
        let otherDrain = try other.beginDrain(); defer { otherDrain.close() }
        let foreign = try UpdateAdmissionTestFixture(), machineDrain = try foreign.open().beginDrain(); defer { machineDrain.close() }
        var opens = 0
        try f.ordinary.withMachineAdmission { scope in
            for drain in [otherDrain, machineDrain] {
                XCTAssertThrowsError(try open(f, scope: scope, drain: drain, stores: storage, opened: { opens += 1 }))
            }
        }
        XCTAssertEqual(opens, 0)
    }
    func testChangedGateAndOwnerLossCannotReachStorage() throws {
        let f = try MaintenanceStopTestFixture(), storage = try stores(f.runtime.plan.host.codePolicy)
        var opens = 0
        try f.ordinary.withMachineAdmission { scope in
            let wrong = PreparationFileIdentity(device: f.cohort.accountIdentity.device, inode: f.cohort.accountIdentity.inode + 1)
            XCTAssertThrowsError(try open(f, scope: scope, expected: wrong, stores: storage, opened: { opens += 1 }))
            XCTAssertThrowsError(try open(f, scope: scope, stores: storage, opened: { opens += 1 }, verify: { f.drain.close() }))
        }
        XCTAssertEqual(opens, 0)
    }
    func testEscapedScopeCannotValidateAndBothLocksStayOwnedUntilExplicitClose() throws {
        let f = try MaintenanceStopTestFixture(), storage = try stores(f.runtime.plan.host.codePolicy)
        let pair = try f.ordinary.withMachineAdmission { try open(f, scope: $0, stores: storage) }
        XCTAssertThrowsError(try pair.validateLifetime())
        XCTAssertThrowsError(try storage.openJournal())
        XCTAssertThrowsError(try storage.openStore())
        try pair.close()
        let journal = try storage.openJournal(); try journal.close()
        let continuity = try storage.openStore(); continuity.close()
    }
    func testAuditFactoryRetainsItsRootEntryInsteadOfAcceptingOwnedSharedActivity() throws {
        let f = try MaintenanceStopTestFixture(), activity = try f.files.activity.open().acquireShared()
        defer { activity.close() }
        try f.ordinary.withMachineAdmission { _ in
            XCTAssertThrowsError(try AuthorityJournalCutoverInspection.openInitialized(initialization: f.initialization,
                policy: f.runtime.plan.host.codePolicy, rootActivity: activity, verifyOwnerAndFence: {})) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
    func testOwnedControlsRejectRootAndMismatchedUIDsWithoutAnOverridableFactoryIdentity() throws {
        XCTAssertFalse(RuntimeMaintenanceOwnedControl.allows(realUID: 0, effectiveUID: 0))
        XCTAssertFalse(RuntimeMaintenanceOwnedControl.allows(realUID: 0, effectiveUID: 501))
        XCTAssertFalse(RuntimeMaintenanceOwnedControl.allows(realUID: 501, effectiveUID: 0))
        XCTAssertFalse(RuntimeMaintenanceOwnedControl.allows(realUID: 501, effectiveUID: 502))
        XCTAssertTrue(RuntimeMaintenanceOwnedControl.allows(realUID: 501, effectiveUID: 501))
        try RuntimeMaintenanceOwnedControl.require()
    }
}
