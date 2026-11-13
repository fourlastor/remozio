import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned existing SQLite stores. These fixtures prove no installed path, key custody, or native caller authority.
final class StableAccountStorageCompletionWriterTests: XCTestCase {
    private typealias Fixture = StableAccountReservationWriterFixture
    private typealias Snapshot = MachineUpdateStableAccountSetupSnapshot
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Operation: CaseIterable, Equatable { case capture, initialization, preparation }
    private enum Fault: Error { case stage, commit }
    private struct Pair {
        let root: URL
        let journal: JournalDatabase
        let continuity: ContinuityStore
        let intent: AuthorityInitializationIntent
        let checkpoint: ContinuityCheckpoint
    }
    private func snapshot(_ f: Fixture, owner: LocalAccountIdentity? = nil) throws -> Snapshot {
        try f.machine().stableAccountSetupSnapshot(owner: owner ?? f.owner, candidate: f.candidate)
    }
    private func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    private func openJournal(_ root: URL, preparation: AccountPreparationIntent, initialize: Bool) throws -> JournalDatabase {
        let limits = try CBORLimits(maxBytes: 262144, maxDepth: 16, maxItems: 10000)
        return try JournalDatabase(lease: .init(anchor: root.path, relativeDirectory: "Journal", owner: getuid()),
            macID: preparation.macID, accountID: preparation.accountID, recordLimits: limits,
            descriptorLimits: limits, decisionLimits: limits, maximumConsumptions: 10, busyMilliseconds: 100,
            initialize: initialize, initialAuthority: initialize ? preparation.initialAuthority : nil)
    }
    private func withPair(preparation: AccountPreparationIntent, _ body: (Pair) throws -> Void) throws {
        let root = URL(fileURLWithPath: "/private/tmp/remozio-A02b2-pair-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        defer { try? FileManager.default.removeItem(at: root) }
        for (name, kind): (String, SetupDatabaseKind) in [("Journal", .journal), ("Continuity", .continuity)] {
            let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: name, owner: getuid())
            defer { directory.close() }
            _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: kind, owner: getuid())
        }
        let journal = try openJournal(root, preparation: preparation, initialize: true)
        defer { try? journal.close() }
        let checkpoint = try journal.initialAuthorityCheckpoint(initial: preparation.initialAuthority,
            databasePath: root.path + "/Journal/journal.sqlite")
        let continuity = try ContinuityStore(lease: .init(anchor: root.path, relativeDirectory: "Continuity", owner: getuid()),
            macID: preparation.macID, accountID: preparation.accountID, initialize: checkpoint)
        defer { continuity.close() }
        let intent = try AuthorityInitializationIntent(setupID: AccountPreparationIntent.randomID(),
            revision: AccountPreparationIntent.randomID(), installationID: preparation.installationID,
            macID: preparation.macID, accountID: preparation.accountID, releaseDigest: preparation.releaseDigest,
            initializationDigest: preparation.initialAuthority.initializationDigest,
            initializationBytes: preparation.initializationBytes, journalPath: root.path + "/Journal/journal.sqlite",
            continuityPath: root.path + "/Continuity/continuity.sqlite")
        try body(.init(root: root, journal: journal, continuity: continuity, intent: intent, checkpoint: checkpoint))
    }
    private func fixture(_ body: (Fixture, Pair) throws -> Void) throws {
        try MachineUpdateReplacementTests.withStableAccountReservationWriterFixture { f in
            _ = try f.machine().beginStableAccountPreparation(owner: f.owner, allowedTargetUIDs: [0], disclosureAccepted: true,
                expected: snapshot(f), candidate: f.candidate, directory: f.directory, admission: f.admission,
                makeInitial: f.initial, verifyScoped: { _, _ in })
            let pinned = try f.machine().pinStableAccountPreparation(publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                expected: snapshot(f), candidate: f.candidate, directory: f.directory, admission: f.admission,
                verifyScoped: { _, _ in })
            try withPair(preparation: pinned) { pair in
                // Install an existing owned initialization. The product begin path keeps its canonical G3 check.
                try f.mutate("INSERT INTO authority_initialization_v1 VALUES(x'\(hex(pair.intent.accountID))',x'\(hex(pair.intent.revision))',x'\(try hex(pair.intent.bytes))')")
                XCTAssertEqual(try snapshot(f).account?.origin, .currentRelease)
                XCTAssertEqual(try snapshot(f).account?.initialization, pair.intent)
                try body(f, pair)
            }
        }
    }
    private func perform(_ operation: Operation, _ f: Fixture, _ pair: Pair, expected: Snapshot? = nil,
        journal: JournalDatabase? = nil, continuity: ContinuityStore? = nil,
        admission: UpdateOrdinaryAdmissionLease? = nil,
        verify: (Stage, Snapshot) throws -> Void = { _, _ in }) throws -> Snapshot {
        let before = try expected ?? snapshot(f)
        switch operation {
        case .capture:
            _ = try f.machine().captureStableAccountInitialization(journal: journal ?? pair.journal, expected: before,
                candidate: f.candidate, directory: f.directory, admission: admission ?? f.admission, verifyScoped: verify)
        case .initialization:
            _ = try f.machine().completeStableAccountInitialization(journal: journal ?? pair.journal,
                continuity: continuity ?? pair.continuity, expected: before, candidate: f.candidate,
                directory: f.directory, admission: admission ?? f.admission, verifyScoped: verify)
        case .preparation:
            _ = try f.machine().completeStableAccountPreparation(expected: before, candidate: f.candidate,
                directory: f.directory, admission: admission ?? f.admission, verifyScoped: verify)
        }
        return try snapshot(f, owner: before.owner)
    }
    private func requireHeld(_ f: Fixture) throws {
        try f.admission.validate()
        XCTAssertThrowsError(try f.gate.beginDrain()) { XCTAssertEqual($0 as? UpdateAdmissionBarrierError, .busy) }
        XCTAssertThrowsError(try f.activity.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
    }

    func testActualExistingPairAdvancesOnlyTheSelectedRowsAndPreservesTheNativeBytes() throws {
        try fixture { f, pair in
            let original = try snapshot(f)
            let journalBytes = try Data(contentsOf: URL(fileURLWithPath: pair.intent.journalPath))
            var before = original
            for operation in Operation.allCases {
                var stages: [Stage] = []
                let after = try perform(operation, f, pair, verify: { stage, actual in
                    stages.append(stage); try self.requireHeld(f)
                    XCTAssertEqual(actual.source.actual.inventory, original.source.actual.inventory)
                })
                XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit])
                try after.requireAccountStorageState(preparation: XCTUnwrap(after.preparation),
                    initialization: after.account?.initialization, from: before)
                XCTAssertEqual(after.source.historicalInventory, original.source.historicalInventory)
                before = after
            }
            XCTAssertTrue(try XCTUnwrap(before.account?.initialization).complete)
            XCTAssertEqual(before.account?.initialization?.checkpoint, pair.checkpoint)
            XCTAssertTrue(try XCTUnwrap(before.preparation).storagePrepared)
            XCTAssertFalse(try XCTUnwrap(before.account).inInventory)
            XCTAssertEqual(try pair.continuity.read().committed, pair.checkpoint)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: pair.intent.journalPath)), journalBytes)
        }
    }

    func testExactRecoveryPerformsNoAdditionalCommitAndCaptureCannotFollowCompletion() throws {
        try fixture { f, pair in
            var commits = 0
            try f.reopen { commits += 1 }
            for operation in Operation.allCases {
                let first = try perform(operation, f, pair)
                XCTAssertEqual(commits, Operation.allCases.firstIndex(of: operation)! + 1)
                var stages: [Stage] = []
                let recovered = try perform(operation, f, pair, verify: { stage, _ in stages.append(stage) })
                try recovered.requireSame(as: first)
                XCTAssertEqual(stages, [.beforeTransaction])
                XCTAssertEqual(commits, Operation.allCases.firstIndex(of: operation)! + 1)
            }
            let before = try snapshot(f)
            XCTAssertThrowsError(try perform(.capture, f, pair)) { XCTAssertEqual($0 as? AuthorityInitializationError, .completed) }
            try snapshot(f).requireSame(as: before); XCTAssertEqual(commits, 3)
        }
    }

    func testRetainedOriginRefusesEveryCompletionBeforeAccessToClosedPair() throws {
        try fixture { f, pair in
            _ = try perform(.capture, f, pair); _ = try perform(.initialization, f, pair)
            let before = try snapshot(f, owner: f.retainedOwner)
            XCTAssertEqual(before.account?.origin, .retained)
            try pair.journal.close(); pair.continuity.close()
            var commits = 0, callbacks = 0
            try f.reopen { commits += 1 }
            for operation in Operation.allCases {
                XCTAssertThrowsError(try perform(operation, f, pair, expected: before,
                    verify: { _, _ in callbacks += 1 })) { XCTAssertEqual($0 as? AccountPreparationError, .conflict) }
                try snapshot(f, owner: f.retainedOwner).requireSame(as: before)
            }
            XCTAssertEqual(commits, 0); XCTAssertEqual(callbacks, 0)
        }
    }

    func testPrecommitFailuresRollBackEveryCompletionAndReleaseItsAuthorization() throws {
        try fixture { f, pair in
            for operation in Operation.allCases {
                let before = try snapshot(f)
                for failure in [Stage.beforeTransaction, .inTransaction, .afterMutation] {
                    XCTAssertThrowsError(try perform(operation, f, pair, verify: { stage, _ in
                        if stage == failure { throw Fault.stage }
                    })) { XCTAssertTrue($0 is Fault) }
                    try snapshot(f).requireSame(as: before); try requireHeld(f)
                }
                XCTAssertNoThrow(try perform(operation, f, pair))
            }
        }
    }

    func testUncertainCommitsRetainEachActualRowWithoutReplayingTheWrite() throws {
        try fixture { f, pair in
            for operation in Operation.allCases {
                var commits = 0, committed: Snapshot?
                try f.reopen { commits += 1; throw Fault.commit }
                XCTAssertThrowsError(try perform(operation, f, pair, verify: { stage, actual in
                    if stage == .afterMutation { committed = actual }
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertEqual(commits, 1)
                XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                try f.reopen(nil)
                try snapshot(f).requireSame(as: XCTUnwrap(committed))
                let recovered = try perform(operation, f, pair)
                try recovered.requireSame(as: XCTUnwrap(committed)); XCTAssertEqual(commits, 1)
            }
        }
    }

    func testPostCommitVerifierFailureRetiresTheConnectionAndPreservesEachActualMutation() throws {
        try fixture { f, pair in
            for operation in Operation.allCases {
                var committed: Snapshot?
                XCTAssertThrowsError(try perform(operation, f, pair, verify: { stage, actual in
                    if stage == .afterMutation { committed = actual }
                    if stage == .afterCommit { throw Fault.stage }
                })) { XCTAssertTrue($0 is Fault) }
                XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                try f.reopen(nil)
                try snapshot(f).requireSame(as: XCTUnwrap(committed))
                try perform(operation, f, pair).requireSame(as: XCTUnwrap(committed))
            }
        }
    }

    func testForeignExistingPathsAndPrematureCompletionCannotChangeMetadata() throws {
        try fixture { f, pair in
            let before = try snapshot(f)
            XCTAssertThrowsError(try perform(.initialization, f, pair)) { XCTAssertEqual($0 as? AuthorityInitializationError, .invalidBoundary) }
            XCTAssertThrowsError(try perform(.preparation, f, pair)) { XCTAssertEqual($0 as? AccountPreparationError, .incomplete) }
            try withPair(preparation: XCTUnwrap(before.preparation)) { other in
                XCTAssertThrowsError(try perform(.capture, f, pair, journal: other.journal))
                try snapshot(f).requireSame(as: before)
                _ = try perform(.capture, f, pair)
                let captured = try snapshot(f)
                XCTAssertThrowsError(try perform(.initialization, f, pair, journal: other.journal))
                XCTAssertThrowsError(try perform(.initialization, f, pair, continuity: other.continuity))
                try snapshot(f).requireSame(as: captured)
                XCTAssertNoThrow(try perform(.initialization, f, pair))
            }
        }
    }

    func testStaleFramesAndClosedAdmissionCannotAdvanceAnyCompletion() throws {
        try fixture { f, pair in
            let original = try snapshot(f)
            _ = try perform(.capture, f, pair)
            for operation in Operation.allCases {
                XCTAssertThrowsError(try perform(operation, f, pair, expected: original)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
            let captured = try snapshot(f)
            f.admission.close()
            for operation in Operation.allCases { XCTAssertThrowsError(try perform(operation, f, pair, expected: captured)) }
            try snapshot(f).requireSame(as: captured)
        }
    }

    func testClosedJournalAfterMutationRollsBackAndTheGateCannotAuthorizeOrdinaryOrReentrantWrites() throws {
        try fixture { f, pair in
            let before = try snapshot(f)
            XCTAssertThrowsError(try perform(.capture, f, pair, verify: { stage, actual in
                XCTAssertThrowsError(try self.perform(.capture, f, pair, expected: actual)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                XCTAssertThrowsError(try f.machine().writeInventory(actual.source.actual.inventory,
                    expectedRevision: actual.source.actual.inventory.revision)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
                if stage == .afterMutation { try pair.journal.close() }
            }))
            XCTAssertThrowsError(try f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil)
            try snapshot(f).requireSame(as: before)
            let reopened = try openJournal(pair.root, preparation: XCTUnwrap(before.preparation), initialize: false)
            defer { try? reopened.close() }
            XCTAssertNoThrow(try perform(.capture, f, pair, journal: reopened))
            XCTAssertThrowsError(try f.machine().writeInventory(before.source.actual.inventory,
                expectedRevision: before.source.actual.inventory.revision)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
        }
    }

    func testContinuityPendingAndRecoveryStatesCannotCompleteOrBeRepaired() throws {
        try fixture { f, pair in
            _ = try perform(.capture, f, pair)
            let before = try snapshot(f), checkpoint = pair.checkpoint
            let next = try ContinuityCheckpoint(generation: checkpoint.generation + 1,
                authorityDigest: checkpoint.authorityDigest, ledgerDigest: checkpoint.ledgerDigest,
                journalEpoch: checkpoint.journalEpoch, journalHead: checkpoint.journalHead,
                authorityGeneration: checkpoint.authorityGeneration)
            try pair.continuity.prepare(expected: checkpoint, candidate: next)
            let pending = try pair.continuity.read()
            XCTAssertThrowsError(try perform(.initialization, f, pair))
            XCTAssertEqual(try pair.continuity.read(), pending); try snapshot(f).requireSame(as: before)
            try pair.continuity.discardPreparation(expected: pending)
            try pair.continuity.requireRecovery()
            let recovery = try pair.continuity.read()
            XCTAssertThrowsError(try perform(.initialization, f, pair))
            XCTAssertEqual(try pair.continuity.read(), recovery); try snapshot(f).requireSame(as: before)
        }
    }
}
