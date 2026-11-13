import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Real owned SQLite and admission controls. They grant no installed caller, key or native storage authority.
struct StableAccountReservationWriterFixture {
    let machine: () -> PreparationIntentStore
    let owner: LocalAccountIdentity
    let candidate: SignedReleaseEvidence
    let directory: ReleaseDestinationLease
    let admission: UpdateOrdinaryAdmissionLease
    let gate: UpdateAdmissionBarrier
    let activity: ReleaseActivityBarrier
    let initial: (Data, Data) throws -> AuthorityJournalInitialization
    let reopen: ((() throws -> Void)?) throws -> Void
    let mutate: (String) throws -> Void
    let scalar: (String) throws -> Int64
}

final class StableAccountReservationWriterTests: XCTestCase {
    private enum Fault: Error { case factory, stage, commit }
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage

    private func fixture(_ body: (StableAccountReservationWriterFixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withStableAccountReservationWriterFixture(body)
    }
    private func nextOwner(_ f: StableAccountReservationWriterFixture) -> LocalAccountIdentity {
        .init(uid: f.owner.uid + 1, primaryGroupID: f.owner.primaryGroupID, directoryID: UUID())
    }
    private func snapshot(_ f: StableAccountReservationWriterFixture, owner: LocalAccountIdentity? = nil) throws
        -> MachineUpdateStableAccountSetupSnapshot {
        try f.machine().stableAccountSetupSnapshot(owner: owner ?? f.owner, candidate: f.candidate)
    }
    private func begin(_ f: StableAccountReservationWriterFixture, owner: LocalAccountIdentity? = nil,
        expected: MachineUpdateStableAccountSetupSnapshot? = nil, targets: Set<UInt32> = [0], accepted: Bool = true,
        admission: UpdateOrdinaryAdmissionLease? = nil,
        initial: ((Data, Data) throws -> AuthorityJournalInitialization)? = nil,
        verify: (Stage, MachineUpdateStableAccountSetupSnapshot) throws -> Void = { _, _ in }) throws -> AccountPreparationIntent {
        let owner = owner ?? f.owner
        return try f.machine().beginStableAccountPreparation(owner: owner, allowedTargetUIDs: targets, disclosureAccepted: accepted,
            expected: expected ?? snapshot(f, owner: owner), candidate: f.candidate, directory: f.directory,
            admission: admission ?? f.admission, makeInitial: initial ?? f.initial, verifyScoped: verify)
    }
    private func requireHeld(_ f: StableAccountReservationWriterFixture) throws {
        try f.admission.validate()
        XCTAssertThrowsError(try f.gate.beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        XCTAssertThrowsError(try f.activity.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
    }

    func testActualReservationHoldsAdmissionAndChangesOnlyTheSelectedAccountRow() throws {
        try fixture { f in
            let before = try snapshot(f)
            XCTAssertNil(before.preparation)
            let count = try f.scalar("SELECT COUNT(*) FROM account_preparation_v1")
            var calls = 0, stages: [Stage] = []
            let value = try begin(f, initial: { mac, account in calls += 1; return try f.initial(mac, account) }) { stage, actual in
                stages.append(stage); try self.requireHeld(f)
                XCTAssertEqual(actual.owner, before.owner)
                XCTAssertEqual(actual.source.actual.inventory, before.source.actual.inventory)
            }
            XCTAssertEqual(calls, 1)
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            let after = try snapshot(f)
            try after.requireReservation(value, from: before)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM account_preparation_v1"), count + 1)
            XCTAssertEqual(after.preparation, value)
            XCTAssertNil(value.authorityPublicKey); XCTAssertFalse(value.storagePrepared)
            XCTAssertNil(after.account?.initialization)
            XCTAssertEqual(after.source.actual.inventory, before.source.actual.inventory)
            XCTAssertEqual(try after.source.actual.seal.encoded, try before.source.actual.seal.encoded)
            XCTAssertEqual(after.source.preparations.filter { $0.ownerUID != f.owner.uid }, before.source.preparations)
            XCTAssertEqual(after.source.initializations, before.source.initializations)
            try requireHeld(f)
        }
    }

    func testRecoveryReturnsTheExactReservationWithoutAnotherFactoryOrCommit() throws {
        try fixture { f in
            let value = try begin(f), before = try snapshot(f)
            try f.reopen { throw Fault.commit }
            var calls = 0, stages: [Stage] = []
            let recovered = try begin(f, initial: { _, _ in calls += 1; throw Fault.factory }) { stage, _ in stages.append(stage) }
            XCTAssertEqual(recovered, value); XCTAssertEqual(calls, 0)
            XCTAssertEqual(stages, [.beforeTransaction])
            try snapshot(f).requireSame(as: before)
            XCTAssertEqual(try recovered.bytes, try value.bytes)
        }
    }

    func testRecoveryCannotChangeGrantsOrBypassDisclosure() throws {
        try fixture { f in
            let value = try begin(f), before = try snapshot(f)
            for (targets, accepted) in [(Set<UInt32>([1]), true), (Set<UInt32>([0]), false)] {
                XCTAssertEqual(try begin(f), value)
                var calls = 0
                XCTAssertThrowsError(try begin(f, targets: targets, accepted: accepted,
                    initial: { _, _ in calls += 1; throw Fault.factory })) {
                    XCTAssertEqual($0 as? AccountPreparationError, .conflict)
                }
                XCTAssertEqual(calls, 0); try snapshot(f).requireSame(as: before)
            }
        }
    }

    func testNewReservationRejectsInvalidTargetSetsAndMissingDisclosureBeforeTheFactory() throws {
        try fixture { f in
            _ = try begin(f)
            let owner = nextOwner(f), before = try snapshot(f, owner: owner)
            for (targets, accepted) in [(Set<UInt32>([UInt32.max]), true), (Set<UInt32>((1...65).map(UInt32.init)), true),
                                        (Set<UInt32>([0]), false)] {
                XCTAssertNoThrow(try begin(f))
                var calls = 0
                XCTAssertThrowsError(try begin(f, owner: owner, expected: before, targets: targets, accepted: accepted,
                    initial: { _, _ in calls += 1; throw Fault.factory }))
                XCTAssertEqual(calls, 0); try snapshot(f, owner: owner).requireSame(as: before)
            }
        }
    }

    func testAChangedOwnerOrDirectoryCannotUseTheExpectedFrame() throws {
        try fixture { f in
            _ = try begin(f)
            let before = try snapshot(f)
            let wrongUID = LocalAccountIdentity(uid: f.owner.uid + 1, primaryGroupID: f.owner.primaryGroupID,
                directoryID: f.owner.directoryID)
            let wrongDirectory = LocalAccountIdentity(uid: f.owner.uid, primaryGroupID: f.owner.primaryGroupID, directoryID: UUID())
            for owner in [wrongUID, wrongDirectory] {
                XCTAssertNoThrow(try begin(f))
                var calls = 0
                XCTAssertThrowsError(try begin(f, owner: owner, expected: before,
                    initial: { _, _ in calls += 1; throw Fault.factory })) {
                    XCTAssertEqual($0 as? LocalAccountLookupError, .ownershipChanged)
                }
                XCTAssertEqual(calls, 0); try snapshot(f).requireSame(as: before)
            }
        }
    }

    func testStaleInventoryAndPreparationRevisionsRefuseBeforeTheFactory() throws {
        try fixture { f in
            let value = try begin(f), before = try snapshot(f), source = before.source, actual = before.source.actual
            let old = actual.inventory
            let inventory = try InstallationInventory(macID: old.macID, installationID: old.installationID,
                revision: AccountPreparationIntent.randomID(), bundlePath: old.bundlePath, releaseDigest: old.releaseDigest,
                accounts: old.accounts, services: old.services, formatVersion: old.formatVersion)
            let frame = MachineUpdateStableReleaseSnapshot(schemaVersion: actual.schemaVersion, inventory: inventory,
                activation: actual.activation, admission: actual.admission, candidate: actual.candidate,
                installed: actual.installed, seal: actual.seal, currentRowsDigest: actual.currentRowsDigest)
            let revised = try AccountPreparationIntent(setupID: value.setupID, revision: AccountPreparationIntent.randomID(),
                macID: value.macID, installationID: value.installationID, releaseDigest: value.releaseDigest,
                accountID: value.accountID, ownerUID: value.ownerUID, directoryID: value.directoryID,
                policyBytes: value.policyBytes, initializationBytes: value.initializationBytes)
            let revisions = [try MachineUpdateStableRuntimeSource(actual: frame, preparations: source.preparations,
                initializations: source.initializations, candidate: f.candidate),
                try MachineUpdateStableRuntimeSource(actual: actual,
                    preparations: source.preparations.map { $0.ownerUID == f.owner.uid ? revised : $0 },
                    initializations: source.initializations, candidate: f.candidate)]
            for source in revisions {
                XCTAssertEqual(try begin(f), value)
                let expected = try MachineUpdateStableAccountSetupSnapshot(source: source, owner: f.owner)
                var calls = 0
                XCTAssertThrowsError(try begin(f, expected: expected, initial: { _, _ in calls += 1; throw Fault.factory })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
                XCTAssertEqual(calls, 0); try snapshot(f).requireSame(as: before)
            }
        }
    }

    func testClosedAdmissionRefusesWithoutReachingTheVerifierOrFactory() throws {
        try fixture { f in
            _ = try begin(f)
            let before = try snapshot(f)
            f.admission.close()
            var calls = 0, verified = 0
            XCTAssertThrowsError(try begin(f, expected: before, initial: { _, _ in calls += 1; throw Fault.factory },
                verify: { _, _ in verified += 1 })) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertEqual(calls, 0); XCTAssertEqual(verified, 0)
            try snapshot(f).requireSame(as: before)
        }
    }

    func testAnotherMachinesRealAdmissionCannotAuthorizeTheReservation() throws {
        try fixture { f in
            _ = try begin(f)
            let before = try snapshot(f)
            try fixture { other in
                _ = try begin(other)
                var calls = 0
                XCTAssertThrowsError(try begin(f, expected: before, admission: other.admission,
                    initial: { _, _ in calls += 1; throw Fault.factory })) {
                    XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
                }
                XCTAssertEqual(calls, 0); try snapshot(f).requireSame(as: before)
            }
        }
    }

    func testEveryPrecommitStageFailureRollsBackAndReleasesThePrivateAuthorization() throws {
        try fixture { f in
            _ = try begin(f)
            let owner = nextOwner(f), before = try snapshot(f, owner: owner)
            for fault in [Stage.beforeTransaction, .inTransaction, .afterMutation] {
                XCTAssertNoThrow(try begin(f))
                XCTAssertThrowsError(try begin(f, owner: owner, expected: before, verify: { stage, _ in
                    if stage == fault { throw Fault.stage }
                })) { XCTAssertTrue($0 is Fault) }
                try snapshot(f, owner: owner).requireSame(as: before)
                XCTAssertNil(try snapshot(f, owner: owner).preparation)
                try requireHeld(f)
            }
            let value = try begin(f, owner: owner, expected: before)
            try snapshot(f, owner: owner).requireReservation(value, from: before)
        }
    }

    func testFactoryFailureAndForeignInitializationLeaveNoReservation() throws {
        try fixture { f in
            _ = try begin(f)
            let owner = nextOwner(f), before = try snapshot(f, owner: owner)
            var calls = 0
            XCTAssertThrowsError(try begin(f, owner: owner, expected: before,
                initial: { _, _ in calls += 1; throw Fault.factory })) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(calls, 1); try snapshot(f, owner: owner).requireSame(as: before)
            XCTAssertNoThrow(try begin(f))
            XCTAssertThrowsError(try begin(f, owner: owner, expected: before, initial: { mac, _ in
                calls += 1; return try f.initial(mac, Data(repeating: 211, count: 16))
            }))
            XCTAssertEqual(calls, 2); try snapshot(f, owner: owner).requireSame(as: before)
        }
    }

    func testAfterCommitVerificationFailureClosesTheStoreAndRecoveryDoesNotRepeatTheFactory() throws {
        try fixture { f in
            _ = try begin(f)
            let owner = nextOwner(f), before = try snapshot(f, owner: owner)
            var value: AccountPreparationIntent?, calls = 0
            XCTAssertThrowsError(try begin(f, owner: owner, expected: before, initial: { mac, account in
                calls += 1; return try f.initial(mac, account)
            }, verify: { stage, actual in
                if stage == .afterMutation { value = actual.preparation }
                if stage == .afterCommit { throw Fault.stage }
            })) { XCTAssertTrue($0 is Fault) }
            XCTAssertEqual(calls, 1)
            XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil)
            let committed = try XCTUnwrap(value)
            XCTAssertEqual(try snapshot(f, owner: owner).preparation, committed)
            XCTAssertEqual(try begin(f, owner: owner, initial: { _, _ in calls += 1; throw Fault.factory }), committed)
            XCTAssertEqual(calls, 1)
        }
    }

    func testAnUncertainCommitKeepsTheCommittedRowWithoutReplayingTheWrite() throws {
        try fixture { f in
            _ = try begin(f)
            let owner = nextOwner(f), before = try snapshot(f, owner: owner)
            var commits = 0, calls = 0, value: AccountPreparationIntent?
            try f.reopen { commits += 1; throw Fault.commit }
            XCTAssertThrowsError(try begin(f, owner: owner, expected: before, initial: { mac, account in
                calls += 1; return try f.initial(mac, account)
            }, verify: { stage, actual in if stage == .afterMutation { value = actual.preparation } })) {
                XCTAssertTrue($0 is Fault)
            }
            XCTAssertEqual(commits, 1); XCTAssertEqual(calls, 1)
            XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil)
            let committed = try XCTUnwrap(value)
            XCTAssertEqual(try snapshot(f, owner: owner).preparation, committed)
            XCTAssertEqual(try begin(f, owner: owner, initial: { _, _ in calls += 1; throw Fault.factory }), committed)
            XCTAssertEqual(commits, 1); XCTAssertEqual(calls, 1)
        }
    }

    func testOrdinaryWritersAndReentrantReservationRemainClosed() throws {
        try fixture { f in
            let value = try begin(f), before = try snapshot(f)
            let recovered = try begin(f, verify: { _, actual in
                XCTAssertThrowsError(try self.begin(f, expected: actual)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                XCTAssertThrowsError(try f.machine().writeInventory(actual.source.actual.inventory,
                    expectedRevision: actual.source.actual.inventory.revision)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
            })
            XCTAssertEqual(recovered, value)
            XCTAssertThrowsError(try f.machine().writeInventory(before.source.actual.inventory,
                expectedRevision: before.source.actual.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try snapshot(f).requireSame(as: before)
        }
    }

    func testPostCommitCatalogChangeCannotBeAcknowledgedAsASuccessfulReservation() throws {
        try fixture { f in
            _ = try begin(f)
            let owner = nextOwner(f), before = try snapshot(f, owner: owner)
            var commits = 0, calls = 0
            try f.reopen {
                commits += 1
                _ = try f.scalar("CREATE INDEX reservation_fixture_extra ON account_preparation_v1(revision)")
            }
            XCTAssertThrowsError(try begin(f, owner: owner, expected: before, initial: { mac, account in
                calls += 1; return try f.initial(mac, account)
            }))
            XCTAssertEqual(commits, 1); XCTAssertEqual(calls, 1)
            XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            // Remove only the fixture's injected index. The writer performs no catalog repair.
            _ = try f.scalar("DROP INDEX reservation_fixture_extra")
            try f.reopen(nil)
            XCTAssertNotNil(try snapshot(f, owner: owner).preparation)
            let recovered = try begin(f, owner: owner, initial: { _, _ in calls += 1; throw Fault.factory })
            XCTAssertEqual(recovered, try snapshot(f, owner: owner).preparation)
            XCTAssertEqual(calls, 1)
        }
    }

    func testChangedUnrelatedRowsRefuseThePinnedBeforeFrame() throws {
        try fixture { f in
            _ = try begin(f)
            let owner = nextOwner(f), before = try snapshot(f, owner: owner)
            try f.mutate("UPDATE runtime_activation_v1 SET registered=1-registered")
            var calls = 0
            XCTAssertThrowsError(try begin(f, owner: owner, expected: before,
                initial: { _, _ in calls += 1; throw Fault.factory })) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(calls, 0)
            XCTAssertNil(try snapshot(f, owner: owner).preparation)
        }
    }
}
