import CryptoKit
import Foundation
import XCTest
@testable import RemozioCore

/// Values grant no writer authority. A02 still needs private authorization and the protected digest of every other row.
final class StableAccountStorageValueTests: XCTestCase {
    private struct State {
        let snapshot: MachineUpdateStableAccountSetupSnapshot
        let preparation: AccountPreparationIntent
        let initialization: AuthorityInitializationIntent?

        func check(from before: State) throws {
            try snapshot.requireAccountStorageState(preparation: preparation, initialization: initialization,
                from: before.snapshot)
        }
    }

    private struct Control {
        let source: MachineUpdateStableRuntimeSource
        let candidate: SignedReleaseEvidence
        let owner: LocalAccountIdentity
        let original: AccountPreparationIntent

        func state(_ preparation: AccountPreparationIntent, initial: AuthorityInitializationIntent? = nil,
            actual: MachineUpdateStableReleaseSnapshot? = nil, extra: [AccountPreparationIntent] = [],
            otherInitializations: [AuthorityInitializationIntent]? = nil) throws -> State {
            let nextSource = try MachineUpdateStableRuntimeSource(actual: actual ?? source.actual,
                preparations: source.preparations.filter { $0.ownerUID != owner.uid } + [preparation] + extra,
                initializations: (otherInitializations ?? source.initializations).filter { $0.accountID != original.accountID }
                    + (initial.map { [$0] } ?? []), candidate: candidate)
            return try .init(snapshot: .init(source: nextSource, owner: owner), preparation: preparation, initialization: initial)
        }

        func initial(_ preparation: AccountPreparationIntent) throws -> AuthorityInitializationIntent {
            let root = try AccountPreparationController.authorityDirectory(accountID: preparation.accountID)
            return try .init(setupID: AccountPreparationIntent.randomID(), revision: AccountPreparationIntent.randomID(),
                installationID: preparation.installationID, macID: preparation.macID, accountID: preparation.accountID,
                releaseDigest: preparation.releaseDigest, initializationDigest: preparation.initialAuthority.initializationDigest,
                initializationBytes: preparation.initializationBytes,
                journalPath: root + "/Journal/journal.sqlite", continuityPath: root + "/Continuity/continuity.sqlite")
        }

        func checkpoint(_ initial: AuthorityInitializationIntent, byte: UInt8 = 0x41) throws -> ContinuityCheckpoint {
            try .init(generation: 1, authorityDigest: Data(repeating: byte, count: 32),
                ledgerDigest: Data(repeating: byte, count: 32), journalEpoch: initial.initialAuthority.descriptor.epoch,
                journalHead: 0, authorityGeneration: 1)
        }

        func copy(_ preparation: AccountPreparationIntent, revision: Data? = nil, setupID: Data? = nil,
            key: Data?, prepared: Bool, policy: Data? = nil) throws -> AccountPreparationIntent {
            try .init(setupID: setupID ?? preparation.setupID, revision: revision ?? AccountPreparationIntent.randomID(),
                macID: preparation.macID, installationID: preparation.installationID,
                releaseDigest: preparation.releaseDigest, accountID: preparation.accountID,
                ownerUID: preparation.ownerUID, directoryID: preparation.directoryID,
                policyBytes: policy ?? preparation.policyBytes, initializationBytes: preparation.initializationBytes,
                authorityPublicKey: key, storagePrepared: prepared)
        }

        func copy(_ initial: AuthorityInitializationIntent, revision: Data? = nil, setupID: Data? = nil,
            journalPath: String? = nil, continuityPath: String? = nil,
            checkpoint: ContinuityCheckpoint?, complete: Bool) throws -> AuthorityInitializationIntent {
            try .init(setupID: setupID ?? initial.setupID, revision: revision ?? AccountPreparationIntent.randomID(),
                installationID: initial.installationID, macID: initial.macID, accountID: initial.accountID,
                releaseDigest: initial.releaseDigest, initializationDigest: initial.initializationDigest,
                initializationBytes: initial.initializationBytes, journalPath: journalPath ?? initial.journalPath,
                continuityPath: continuityPath ?? initial.continuityPath, checkpoint: checkpoint, complete: complete)
        }

        func frame(schema: Int64? = nil, digest: Data? = nil) -> MachineUpdateStableReleaseSnapshot {
            let base = source.actual
            return .init(schemaVersion: schema ?? base.schemaVersion, inventory: base.inventory,
                activation: base.activation, admission: base.admission, candidate: base.candidate,
                installed: base.installed, seal: base.seal, currentRowsDigest: digest ?? base.currentRowsDigest)
        }
    }

    private func fixture(_ body: (Control) throws -> Void) throws {
        try StableAccountReservationValueTests.withAccountStorageComparisonValues {
            try body(.init(source: $0, candidate: $1, owner: $2, original: $3))
        }
    }

    private func key() -> Data { P256.Signing.PrivateKey().publicKey.x963Representation }

    private func reject(_ bad: State, from before: State, control: State,
        file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertNoThrow(try control.check(from: before), file: file, line: line)
        XCTAssertThrowsError(try bad.check(from: before), file: file, line: line)
    }

    func testStorageValuesAllowPinInitializationCheckpointAndCompletionProgress() throws {
        try fixture { c in
            let before = try c.state(c.original), pinned = try c.original.pinning(key())
            let pin = try c.state(pinned)
            XCTAssertNoThrow(try pin.check(from: before))
            let initial = try c.initial(pinned), began = try c.state(pinned, initial: initial)
            XCTAssertNoThrow(try began.check(from: pin))
            let checkpoint = try c.checkpoint(initial)
            let observed = try initial.advancing(checkpoint: checkpoint, complete: false)
            let observedState = try c.state(pinned, initial: observed)
            XCTAssertNoThrow(try observedState.check(from: began))
            let completed = try observed.advancing(checkpoint: checkpoint, complete: true)
            let completedState = try c.state(pinned, initial: completed)
            XCTAssertNoThrow(try completedState.check(from: observedState))
            let prepared = try pinned.prepared(initialization: completed)
            let final = try c.state(prepared, initial: completed)
            XCTAssertNoThrow(try final.check(from: completedState))
            XCTAssertNoThrow(try final.check(from: final))
            XCTAssertTrue(final.preparation.storagePrepared)
        }
    }

    func testAnAlreadyPinnedKeyCannotBeReplacedByAnotherValidKey() throws {
        try fixture { c in
            let first = key(), second = key()
            XCTAssertNotEqual(first, second)
            let pinned = try c.original.pinning(first), before = try c.state(pinned)
            let replacement = try c.copy(pinned, key: second, prepared: false)
            XCTAssertEqual(replacement.authorityPublicKey, second)
            XCTAssertNoThrow(try P256.Signing.PublicKey(x963Representation: second))
            try reject(c.state(replacement), from: before, control: before)
        }
    }

    func testCheckpointCompletionAndPreparedStorageCannotRegress() throws {
        try fixture { c in
            let pinned = try c.original.pinning(key()), initial = try c.initial(pinned)
            let checkpoint = try c.checkpoint(initial)
            let complete = try initial.advancing(checkpoint: checkpoint, complete: true)
            let before = try c.state(pinned, initial: complete)
            let changed = try c.copy(complete, checkpoint: c.checkpoint(initial, byte: 0x42), complete: true)
            try reject(c.state(pinned, initial: changed), from: before, control: before)
            let incomplete = try c.copy(complete, checkpoint: checkpoint, complete: false)
            try reject(c.state(pinned, initial: incomplete), from: before, control: before)
            try reject(c.state(pinned), from: before, control: before)
            let prepared = try pinned.prepared(initialization: complete), preparedState = try c.state(prepared, initial: complete)
            let regressed = try c.copy(prepared, key: prepared.authorityPublicKey, prepared: false)
            try reject(c.state(regressed, initial: complete), from: preparedState, control: preparedState)
        }
    }

    func testChangedRowsNeedNewRevisionsAndKeepTheirSetupAndPaths() throws {
        try fixture { c in
            let before = try c.state(c.original), pinned = try c.original.pinning(key()), pin = try c.state(pinned)
            let reused = try c.copy(pinned, revision: c.original.revision, key: pinned.authorityPublicKey, prepared: false)
            try reject(c.state(reused), from: before, control: pin)
            let initial = try c.initial(pinned), began = try c.state(pinned, initial: initial), checkpoint = try c.checkpoint(initial)
            let progressed = try initial.advancing(checkpoint: checkpoint, complete: false)
            let good = try c.state(pinned, initial: progressed)
            let reusedInitial = try c.copy(initial, revision: initial.revision, checkpoint: checkpoint, complete: false)
            try reject(c.state(pinned, initial: reusedInitial), from: began, control: good)
            let changedSetup = try c.copy(initial, setupID: AccountPreparationIntent.randomID(), checkpoint: checkpoint, complete: false)
            try reject(c.state(pinned, initial: changedSetup), from: began, control: good)
            let changedPath = try c.copy(initial, journalPath: "/private/tmp/remozio-A02a-other/Journal/journal.sqlite",
                checkpoint: checkpoint, complete: false)
            try reject(c.state(pinned, initial: changedPath), from: began, control: good)
        }
    }

    func testImmutableOperandsOtherAccountsAndSchemaStayFixed() throws {
        try fixture { c in
            let before = try c.state(c.original), pinned = try c.original.pinning(key()), control = try c.state(pinned)
            let changedSetup = try c.copy(pinned, setupID: AccountPreparationIntent.randomID(), key: pinned.authorityPublicKey, prepared: false)
            try reject(c.state(changedSetup), from: before, control: control)
            let policy = try CommandElevationPolicy(macID: pinned.macID, accountID: pinned.accountID,
                callerUID: pinned.ownerUID, allowedTargetUIDs: [0, 1], independentPolicyDisclosureAccepted: true)
            let changedPolicy = try c.copy(pinned, key: pinned.authorityPublicKey, prepared: false, policy: policy.canonicalBytes)
            try reject(c.state(changedPolicy), from: before, control: control)
            let otherOwner = LocalAccountIdentity(uid: c.owner.uid + 1, primaryGroupID: c.owner.primaryGroupID, directoryID: UUID())
            let extra = try StableAccountReservationValueTests.accountStorageReservationValue(source: c.source,
                candidate: c.candidate, owner: otherOwner)
            try reject(c.state(pinned, extra: [extra]), from: before, control: control)
            XCTAssertFalse(c.source.initializations.isEmpty)
            try reject(c.state(pinned, otherInitializations: Array(c.source.initializations.dropFirst())), from: before, control: control)
            try reject(c.state(pinned, actual: c.frame(schema: c.source.actual.schemaVersion + 1)), from: before, control: control)
            let mismatched = State(snapshot: control.snapshot, preparation: changedSetup, initialization: nil)
            try reject(mismatched, from: before, control: control)
        }
    }

    func testInitializationNeedsAPinnedKeyAndPreparedStorageNeedsCompletion() throws {
        try fixture { c in
            let before = try c.state(c.original), pinned = try c.original.pinning(key()), control = try c.state(pinned)
            let initial = try c.initial(pinned)
            try reject(c.state(c.original, initial: initial), from: before, control: control)
            let premature = try c.copy(pinned, key: pinned.authorityPublicKey, prepared: true)
            try reject(c.state(premature), from: before, control: control)
            try reject(c.state(premature, initial: initial), from: before, control: control)
        }
    }

    func testNewInitializationRequiresTheCanonicalJournalAndContinuityPaths() throws {
        try fixture { c in
            let pinned = try c.original.pinning(key()), before = try c.state(pinned)
            let initial = try c.initial(pinned), control = try c.state(pinned, initial: initial)
            let authority = try AccountPreparationController.authorityDirectory(accountID: pinned.accountID)
            XCTAssertEqual(initial.journalPath, authority + "/Journal/journal.sqlite")
            XCTAssertEqual(initial.continuityPath, authority + "/Continuity/continuity.sqlite")
            let foreignJournal = try c.copy(initial, journalPath: "/private/tmp/remozio-A02a-foreign/Journal/journal.sqlite",
                checkpoint: nil, complete: false)
            let foreignContinuity = try c.copy(initial, continuityPath: "/private/tmp/remozio-A02a-foreign/Continuity/continuity.sqlite",
                checkpoint: nil, complete: false)
            for foreign in [foreignJournal, foreignContinuity] {
                XCTAssertNoThrow(try control.check(from: before))
                let state = try c.state(pinned, initial: foreign)
                XCTAssertThrowsError(try state.check(from: before)) {
                    XCTAssertEqual($0 as? MachineUpdateActivationError, .wrongBoundary)
                }
            }
        }
    }

    func testPureValuesCannotProveTheWriterAuthorityOrOtherDatabaseRowsDigest() throws {
        try fixture { c in
            let before = try c.state(c.original), pinned = try c.original.pinning(key())
            let control = try c.state(pinned)
            XCTAssertNoThrow(try control.check(from: before))
            // This supplied digest has no database provenance. A02 must still protect actual rows under private authorization.
            let supplied = try c.state(pinned, actual: c.frame(digest: Data(repeating: 0xA7, count: 32)))
            XCTAssertNoThrow(try supplied.check(from: before))
            try c.source.requireSame(as: before.snapshot.source)
        }
    }
}
