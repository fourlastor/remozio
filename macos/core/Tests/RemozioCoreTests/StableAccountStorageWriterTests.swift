import CryptoKit
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Actual owned SQL and admission. Key bytes and canonical paths grant no native key or directory authority.
final class StableAccountStorageWriterTests: XCTestCase {
    private typealias Fixture = StableAccountReservationWriterFixture
    private typealias Snapshot = MachineUpdateStableAccountSetupSnapshot
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Fault: Error { case stage, commit }
    private enum Operation: CaseIterable { case pin, initialization }
    private func key() -> Data { P256.Signing.PrivateKey().publicKey.x963Representation }
    private func snapshot(_ f: Fixture, owner: LocalAccountIdentity? = nil) throws -> Snapshot {
        try f.machine().stableAccountSetupSnapshot(owner: owner ?? f.owner, candidate: f.candidate)
    }
    private func reserve(_ f: Fixture, owner: LocalAccountIdentity) throws -> Snapshot {
        _ = try f.machine().beginStableAccountPreparation(owner: owner, allowedTargetUIDs: [0], disclosureAccepted: true,
            expected: snapshot(f, owner: owner), candidate: f.candidate, directory: f.directory, admission: f.admission,
            makeInitial: f.initial, verifyScoped: { _, _ in })
        return try snapshot(f, owner: owner)
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withStableAccountReservationWriterFixture { f in
            _ = try self.reserve(f, owner: f.owner); try body(f)
        }
    }
    private func otherOwner(_ f: Fixture) -> LocalAccountIdentity {
        .init(uid: f.owner.uid + 1, primaryGroupID: f.owner.primaryGroupID, directoryID: UUID())
    }
    private func paths(_ expected: Snapshot) throws -> (String, String) {
        let root = try AccountPreparationController.authorityDirectory(accountID: XCTUnwrap(expected.preparation).accountID)
        return (root + "/Journal/journal.sqlite", root + "/Continuity/continuity.sqlite")
    }
    private func pin(_ f: Fixture, key: Data, expected: Snapshot? = nil, admission: UpdateOrdinaryAdmissionLease? = nil,
        verify: (Stage, Snapshot) throws -> Void = { _, _ in }) throws -> AccountPreparationIntent {
        try f.machine().pinStableAccountPreparation(publicKey: key, expected: expected ?? snapshot(f), candidate: f.candidate,
            directory: f.directory, admission: admission ?? f.admission, verifyScoped: verify)
    }
    private func begin(_ f: Fixture, expected: Snapshot? = nil, selectedPaths: (String, String)? = nil,
        admission: UpdateOrdinaryAdmissionLease? = nil, verify: (Stage, Snapshot) throws -> Void = { _, _ in }) throws
        -> AuthorityInitializationIntent {
        let before = try expected ?? snapshot(f), selected = try selectedPaths ?? paths(before)
        return try f.machine().beginStableAccountInitialization(journalPath: selected.0, continuityPath: selected.1,
            expected: before, candidate: f.candidate, directory: f.directory, admission: admission ?? f.admission, verifyScoped: verify)
    }
    private func perform(_ operation: Operation, _ f: Fixture, expected: Snapshot, key: Data,
        admission: UpdateOrdinaryAdmissionLease? = nil, verify: (Stage, Snapshot) throws -> Void = { _, _ in }) throws -> Snapshot {
        switch operation {
        case .pin: _ = try pin(f, key: key, expected: expected, admission: admission, verify: verify)
        case .initialization: _ = try begin(f, expected: expected, admission: admission, verify: verify)
        }
        return try snapshot(f, owner: expected.owner)
    }
    private func validControl(_ f: Fixture) throws -> Data {
        let value = self.key(); _ = try pin(f, key: value); _ = try begin(f); return value
    }

    func testPinCommitsOnlyTheExactKeyAndPreparationRevisionUnderActualAdmission() throws {
        try fixture { f in
            let before = try snapshot(f), key = self.key()
            var stages: [Stage] = []
            let value = try pin(f, key: key, verify: { stage, actual in
                stages.append(stage); try f.admission.validate()
                XCTAssertThrowsError(try f.gate.beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
                XCTAssertEqual(actual.source.actual.inventory, before.source.actual.inventory)
            })
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(value.authorityPublicKey, key)
            XCTAssertNotEqual(value.revision, before.preparation?.revision)
            XCTAssertEqual(value.setupID, before.preparation?.setupID)
            XCTAssertFalse(value.storagePrepared)
            let after = try snapshot(f)
            try after.requireAccountStorageState(preparation: value, initialization: nil, from: before)
            XCTAssertEqual(after.source.initializations, before.source.initializations)
            XCTAssertEqual(after.source.preparations.filter { $0.ownerUID != f.owner.uid },
                before.source.preparations.filter { $0.ownerUID != f.owner.uid })
        }
    }

    func testCanonicalInitializationCommitsFrozenMetadataWithoutCompletingStorage() throws {
        try fixture { f in
            let key = self.key(); _ = try pin(f, key: key)
            let before = try snapshot(f), selected = try paths(before)
            var stages: [Stage] = []
            let initial = try begin(f, verify: { stage, _ in stages.append(stage); try f.admission.validate() })
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(initial.journalPath, selected.0); XCTAssertEqual(initial.continuityPath, selected.1)
            XCTAssertEqual(initial.initializationBytes, before.preparation?.initializationBytes)
            XCTAssertEqual(initial.releaseDigest, before.preparation?.releaseDigest)
            XCTAssertNil(initial.checkpoint); XCTAssertFalse(initial.complete)
            let after = try snapshot(f), preparation = try XCTUnwrap(after.preparation)
            XCTAssertEqual(after.preparation, before.preparation)
            XCTAssertEqual(preparation.authorityPublicKey, key); XCTAssertFalse(preparation.storagePrepared)
            try after.requireAccountStorageState(preparation: preparation, initialization: initial, from: before)
            XCTAssertEqual(after.source.actual.inventory, before.source.actual.inventory)
            XCTAssertEqual(try after.source.actual.seal.encoded, try before.source.actual.seal.encoded)
        }
    }

    func testExactPinAndInitializationRecoveryPerformNoCommitOrRevisionChange() throws {
        try fixture { f in
            let key = try validControl(f), before = try snapshot(f)
            try f.reopen { throw Fault.commit }
            for operation in Operation.allCases {
                var stages: [Stage] = []
                let after = try perform(operation, f, expected: before, key: key, verify: { stage, _ in stages.append(stage) })
                XCTAssertEqual(stages, [.beforeTransaction]); try after.requireSame(as: before)
            }
        }
    }

    func testAnotherValidKeyAndMalformedKeysCannotReplaceThePin() throws {
        try fixture { f in
            let original = try validControl(f), before = try snapshot(f)
            for invalid in [self.key(), Data(), Data(repeating: 4, count: 65)] {
                XCTAssertEqual(try pin(f, key: original).authorityPublicKey, original)
                XCTAssertThrowsError(try pin(f, key: invalid))
                try snapshot(f).requireSame(as: before)
            }
        }
    }

    func testInitializationNeedsAPinnedKeyAndAnExistingPreparation() throws {
        try fixture { f in
            _ = try validControl(f)
            let owner = otherOwner(f), empty = try snapshot(f, owner: owner)
            XCTAssertNil(empty.preparation)
            XCTAssertThrowsError(try pin(f, key: self.key(), expected: empty)) {
                XCTAssertEqual($0 as? AccountPreparationError, .missing)
            }
            let unpinned = try reserve(f, owner: owner)
            XCTAssertNoThrow(try begin(f))
            XCTAssertThrowsError(try begin(f, expected: unpinned)) {
                XCTAssertEqual($0 as? AccountPreparationError, .incomplete)
            }
            try snapshot(f, owner: owner).requireSame(as: unpinned)
        }
    }

    func testNewInitializationRejectsEachForeignCanonicalPathBeforeTheWrite() throws {
        try fixture { f in
            _ = try validControl(f)
            let owner = otherOwner(f), unpinned = try reserve(f, owner: owner)
            _ = try pin(f, key: self.key(), expected: unpinned)
            let before = try snapshot(f, owner: owner), selected = try paths(before)
            for invalid in [(selected.0 + ".foreign", selected.1), (selected.0, selected.1 + ".foreign"), (selected.0, selected.0)] {
                XCTAssertNoThrow(try begin(f))
                var stages: [Stage] = []
                XCTAssertThrowsError(try begin(f, expected: before, selectedPaths: invalid,
                    verify: { stage, _ in stages.append(stage) })) {
                    XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
                }
                XCTAssertEqual(stages, [.beforeTransaction])
                try snapshot(f, owner: owner).requireSame(as: before)
            }
        }
    }

    func testExistingInitializationCannotChangeEitherStoredPath() throws {
        try fixture { f in
            _ = try validControl(f)
            let before = try snapshot(f), selected = try paths(before)
            for invalid in [(selected.0 + ".foreign", selected.1), (selected.0, selected.1 + ".foreign")] {
                XCTAssertNoThrow(try begin(f))
                XCTAssertThrowsError(try begin(f, selectedPaths: invalid)) {
                    XCTAssertEqual($0 as? AuthorityInitializationError, .conflictingIntent)
                }
                try snapshot(f).requireSame(as: before)
            }
        }
    }

    func testStalePreparationAndInitializationFramesRefuseBothWriters() throws {
        try fixture { f in
            let unpinned = try snapshot(f), key = self.key()
            _ = try pin(f, key: key)
            let pinned = try snapshot(f)
            XCTAssertThrowsError(try pin(f, key: key, expected: unpinned)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try snapshot(f).requireSame(as: pinned)
            _ = try begin(f)
            let initialized = try snapshot(f)
            XCTAssertThrowsError(try begin(f, expected: pinned)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try snapshot(f).requireSame(as: initialized)
        }
    }

    func testClosedAndForeignRealAdmissionCannotReachEitherMutation() throws {
        try fixture { f in
            let key = try validControl(f), before = try snapshot(f)
            try fixture { other in
                _ = try validControl(other)
                for operation in Operation.allCases {
                    XCTAssertThrowsError(try perform(operation, f, expected: before, key: key, admission: other.admission)) {
                        XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
                    }
                    try snapshot(f).requireSame(as: before)
                }
            }
            f.admission.close()
            for operation in Operation.allCases {
                var verified = 0
                XCTAssertThrowsError(try perform(operation, f, expected: before, key: key,
                    verify: { _, _ in verified += 1 })) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                XCTAssertEqual(verified, 0); try snapshot(f).requireSame(as: before)
            }
        }
    }

    func testPrecommitFailuresRollBackEachMutationAndReleaseThePrivateGate() throws {
        try fixture { f in
            let controlOwner = otherOwner(f), control = try reserve(f, owner: controlOwner), controlKey = self.key()
            _ = try pin(f, key: controlKey, expected: control)
            _ = try begin(f, expected: snapshot(f, owner: controlOwner))
            let key = self.key()
            for operation in Operation.allCases {
                let before = try snapshot(f)
                for fault in [Stage.beforeTransaction, .inTransaction, .afterMutation] {
                    XCTAssertNoThrow(try begin(f, expected: snapshot(f, owner: controlOwner)))
                    XCTAssertThrowsError(try perform(operation, f, expected: before, key: key, verify: { stage, _ in
                        if stage == fault { throw Fault.stage }
                    })) { XCTAssertTrue($0 is Fault) }
                    try snapshot(f).requireSame(as: before); try f.admission.validate()
                }
                _ = try perform(operation, f, expected: before, key: key)
            }
        }
    }

    func testUncertainCommitsPersistOnceAndRecoveryDoesNotReplayEitherWrite() throws {
        for operation in Operation.allCases {
            try fixture { f in
                _ = try validControl(f)
                let owner = otherOwner(f), reserved = try reserve(f, owner: owner), key = self.key()
                if case .initialization = operation { _ = try pin(f, key: key, expected: reserved) }
                let before = try snapshot(f, owner: owner)
                var commits = 0, mutated: Snapshot?
                try f.reopen { commits += 1; throw Fault.commit }
                XCTAssertThrowsError(try perform(operation, f, expected: before, key: key, verify: { stage, actual in
                    if stage == .afterMutation { mutated = actual }
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertEqual(commits, 1)
                XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                try f.reopen(nil)
                let actual = try snapshot(f, owner: owner)
                try actual.requireSame(as: XCTUnwrap(mutated))
                try perform(operation, f, expected: actual, key: key).requireSame(as: actual)
                XCTAssertEqual(commits, 1)
            }
        }
    }

    func testPostCommitVerifierFailureClosesTheStoreAndRetainsTheActualRow() throws {
        for operation in Operation.allCases {
            try fixture { f in
                _ = try validControl(f)
                let owner = otherOwner(f), reserved = try reserve(f, owner: owner), key = self.key()
                if case .initialization = operation { _ = try pin(f, key: key, expected: reserved) }
                let before = try snapshot(f, owner: owner)
                var mutated: Snapshot?
                XCTAssertThrowsError(try perform(operation, f, expected: before, key: key, verify: { stage, actual in
                    if stage == .afterMutation { mutated = actual }
                    if stage == .afterCommit { throw Fault.stage }
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                try f.reopen(nil)
                let actual = try snapshot(f, owner: owner)
                try actual.requireSame(as: XCTUnwrap(mutated))
                try perform(operation, f, expected: actual, key: key).requireSame(as: actual)
            }
        }
    }

    func testChangedOtherRowsAndCatalogCannotBeAcknowledgedAsSuccess() throws {
        for sql in ["UPDATE runtime_activation_v1 SET registered=1-registered",
                    "CREATE INDEX storage_fixture_extra ON account_preparation_v1(revision)"] {
            try fixture { f in
                _ = try validControl(f)
                let owner = otherOwner(f), before = try reserve(f, owner: owner)
                var commits = 0
                try f.reopen { commits += 1; _ = try f.scalar(sql) }
                XCTAssertThrowsError(try pin(f, key: self.key(), expected: before))
                XCTAssertEqual(commits, 1)
                XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                // Remove only an index injected by this fixture. The writer performs no repair.
                if sql.hasPrefix("CREATE INDEX") { _ = try f.scalar("DROP INDEX storage_fixture_extra") }
                try f.reopen(nil)
                XCTAssertNotNil(try snapshot(f, owner: owner).preparation?.authorityPublicKey)
            }
        }
    }

    func testOrdinaryReservationAndReentrantStorageCannotBorrowThisPrivateGate() throws {
        try fixture { f in
            let key = self.key(), before = try snapshot(f)
            _ = try pin(f, key: key, verify: { _, actual in
                XCTAssertThrowsError(try self.pin(f, key: key, expected: actual)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                XCTAssertThrowsError(try f.machine().beginStableAccountPreparation(owner: actual.owner,
                    allowedTargetUIDs: [0], disclosureAccepted: true, expected: actual, candidate: f.candidate,
                    directory: f.directory, admission: f.admission, makeInitial: f.initial, verifyScoped: { _, _ in })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                XCTAssertThrowsError(try f.machine().writeInventory(actual.source.actual.inventory,
                    expectedRevision: actual.source.actual.inventory.revision)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
            })
            XCTAssertEqual(try snapshot(f).preparation?.authorityPublicKey, key)
            XCTAssertThrowsError(try f.machine().writeInventory(before.source.actual.inventory,
                expectedRevision: before.source.actual.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
        }
    }
}
