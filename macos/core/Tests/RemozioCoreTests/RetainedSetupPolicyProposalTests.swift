import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

struct RetainedPolicyProposalFixture {
    let source: MachineUpdateRetainedSetupActivationSource
    let candidate: SignedReleaseEvidence
    let capture: () throws -> MachineUpdateRetainedSetupActivationSource
    let read: () throws -> AuthorityJournal.MachineUpdatePolicyBoundary
    let commit: (AuthorityCodePolicy, UUID) throws -> AuthorityJournal.MachineUpdatePolicyBoundary
    let verifyMachine: () throws -> Void
}

/// Owned pairs exercise value proposals. They grant no permit, machine acknowledgement, native identity or policy write authority.
final class RetainedSetupPolicyProposalTests: XCTestCase {
    private typealias Record = MachineUpdateRetainedSetupPolicyIntentRecord
    private typealias Fixture = RetainedPolicyProposalFixture
    private typealias Boundary = AuthorityJournal.MachineUpdatePolicyBoundary
    private func fixture(noPolicyChange: Bool = false, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyProposalFixture(noPolicyChange: noPolicyChange, body)
    }
    private func changed(_ record: Record, _ edit: (inout [String: Any]) throws -> Void) throws -> Record {
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: record.encoded) as? [String: Any])
        try edit(&fields)
        return try .decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
    }
    private func recorded(_ writing: Record, _ boundary: Boundary) throws -> Record {
        guard case .recorded(let result) = try writing.reconciling(boundary) else {
            throw PreparationStoreError.invalidTransition
        }
        return result
    }

    func testPreparedV2SourceProposesWritingWithoutChangingTheOriginalRecord() throws {
        try fixture { f in
            let prepared = try Record(source: f.source), original = try prepared.encoded
            try prepared.requireSource(f.capture())
            let writing = try prepared.preparingWrite(expected: f.source)
            XCTAssertEqual(prepared.formatVersion, 2); XCTAssertEqual(writing.formatVersion, 2)
            XCTAssertEqual(prepared.phase, .prepared); XCTAssertEqual(writing.phase, .writing)
            XCTAssertEqual(writing.id, prepared.id); XCTAssertNotEqual(writing.revision, prepared.revision)
            XCTAssertEqual(try prepared.encoded, original)
            XCTAssertNil(writing.committedPolicy); XCTAssertNil(writing.committedCheckpoint)
            try writing.requireTransition(from: prepared)
            XCTAssertEqual(try Record.decode(writing.encoded), writing)
            try f.verifyMachine()
        }
    }

    func testWritingUnchangedSourceNeverProposesARetry() throws {
        try fixture { f in
            let prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            XCTAssertNotEqual(f.source.policy.startupPolicy, f.source.policy.source.policy)
            XCTAssertEqual(try writing.reconciling(f.read()), .sourceUnchanged)
            XCTAssertThrowsError(try writing.preparingWrite(expected: f.source)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            XCTAssertThrowsError(try prepared.reconciling(f.read())) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try f.verifyMachine()
        }
    }

    func testSecondPairedCommitProposesAnExactFreshRecordedBoundary() throws {
        try fixture { f in
            let prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            let before = try f.read()
            let current = try f.commit(f.source.policy.startupPolicy, before.policy.revision)
            XCTAssertNotEqual(current.policy.revision, before.policy.revision)
            XCTAssertEqual(current.checkpoint.generation, before.checkpoint.generation + 1)
            XCTAssertEqual(current.checkpoint.currentAuthorityGeneration, before.checkpoint.currentAuthorityGeneration + 1)
            XCTAssertEqual(current.checkpoint.ledgerDigest, before.checkpoint.ledgerDigest)
            XCTAssertEqual(current.checkpoint.journalHead, before.checkpoint.journalHead)
            for (old, next) in zip(before.policy.policy.entries, current.policy.policy.entries) {
                XCTAssertEqual(old == next, before.policy.roleRevisions[old.role] == current.policy.roleRevisions[old.role])
            }
            let result = try recorded(writing, f.read())
            XCTAssertEqual(result.phase, .recorded); XCTAssertEqual(result.id, prepared.id)
            XCTAssertNotEqual(result.revision, writing.revision)
            XCTAssertEqual(try result.committedPolicy?.snapshot(), current.policy)
            XCTAssertEqual(result.committedCheckpoint, try current.checkpoint.bytes)
            try result.requireRecorded(f.read()); try result.requireTransition(from: writing)
            XCTAssertEqual(try Record.decode(result.encoded), result)
            try f.verifyMachine()
        }
    }

    func testNoOpRecordsOnlyTheUnchangedActualPair() throws {
        try fixture(noPolicyChange: true) { f in
            let prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            XCTAssertEqual(f.source.policy.startupPolicy, f.source.policy.source.policy)
            let before = try f.read(), result = try recorded(writing, f.read())
            XCTAssertEqual(try result.committedPolicy?.snapshot(), before.policy)
            XCTAssertEqual(result.committedCheckpoint, try before.checkpoint.bytes)
            try result.requireRecorded(f.read()); try result.requireTransition(from: writing)
            XCTAssertEqual(try f.read(), before)
            // A no-op observes the exact pair. It neither writes the journal nor constructs a private commit receipt.
            try f.verifyMachine()
        }
    }

    func testNoOpRefusesARealRedundantCommitThatChangedTheCheckpoint() throws {
        try fixture(noPolicyChange: true) { f in
            let prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            let before = try f.read(), after = try f.commit(before.policy.policy, before.policy.revision)
            XCTAssertEqual(after.policy, before.policy)
            XCTAssertNotEqual(after.checkpoint, before.checkpoint)
            XCTAssertThrowsError(try writing.reconciling(after)) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            try f.verifyMachine()
        }
    }

    func testSourceRequiresTheExactGlobalRevisionInitializationAndV2Scope() throws {
        try fixture { f in
            let prepared = try Record(source: f.source)
            let wrongRevision = try changed(prepared) { fields in
                var policy = try XCTUnwrap(fields["sourcePolicy"] as? [String: Any])
                policy["revision"] = UUID().uuidString; fields["sourcePolicy"] = policy
            }
            let wrongInitialization = try changed(prepared) {
                $0["initializationDigest"] = Data(repeating: 233, count: 32).base64EncodedString()
            }
            let wrongScope = try changed(prepared) { $0["sourceDigest"] = Data(repeating: 234, count: 32).base64EncodedString() }
            let wrongInstallation = try changed(prepared) {
                $0["installationID"] = Data(repeating: 236, count: 16).base64EncodedString()
            }
            let wrongOwner = try changed(prepared) { $0["ownerUID"] = f.source.runtime.preparation.ownerUID == 1 ? 2 : 1 }
            let wrongAccount = try changed(prepared) { $0["accountID"] = Data(repeating: 237, count: 16).base64EncodedString() }
            let wrongMachine = try changed(prepared) { $0["macID"] = Data(repeating: 238, count: 16).base64EncodedString() }
            for value in [wrongRevision, wrongInitialization, wrongScope, wrongInstallation, wrongOwner, wrongAccount, wrongMachine] {
                XCTAssertThrowsError(try value.preparingWrite(expected: f.capture())) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
            try f.verifyMachine()
        }
    }

    func testRecoveredReceiptRejectsOldRoleTokensAndTheSourceCheckpoint() throws {
        try fixture { f in
            let prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            let before = try f.read(), current = try f.commit(f.source.policy.startupPolicy, before.policy.revision)
            _ = try recorded(writing, current)
            let changedRole = try XCTUnwrap(before.policy.policy.entries.first { old in
                !current.policy.policy.entries.contains(old)
            })
            var roles = current.policy.roleRevisions
            roles[changedRole.role] = before.policy.roleRevisions[changedRole.role]
            let staleRoles = Boundary(macID: current.macID, accountID: current.accountID,
                policy: .init(revision: current.policy.revision, policy: current.policy.policy, roleRevisions: roles),
                checkpoint: current.checkpoint)
            let staleCheckpoint = Boundary(macID: current.macID, accountID: current.accountID,
                policy: current.policy, checkpoint: before.checkpoint)
            for value in [staleRoles, staleCheckpoint] {
                XCTAssertThrowsError(try writing.reconciling(value)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
                }
            }
            try f.verifyMachine()
        }
    }

    func testTransitionsRejectOtherIDsScopeOperandsAndSkippedOrRepeatedPhases() throws {
        try fixture { f in
            let prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            let result = try recorded(writing, f.commit(f.source.policy.startupPolicy, f.source.accountPolicy.policy.revision))
            for pair in [(writing, writing), (prepared, writing), (result, prepared), (result, result)] {
                XCTAssertThrowsError(try pair.0.requireTransition(from: pair.1)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                }
            }
            let foreignID = try changed(writing) { $0["id"] = UUID().uuidString }
            let foreignScope = try changed(writing) { $0["sourceDigest"] = Data(repeating: 235, count: 32).base64EncodedString() }
            for value in [foreignID, foreignScope] {
                XCTAssertThrowsError(try value.requireTransition(from: prepared)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                }
            }
            try f.verifyMachine()
        }
    }

    func testRecordedProposalRejectsAnotherGlobalRevisionAndLegacyRecordVersion() throws {
        try fixture { f in
            let prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            let current = try f.commit(f.source.policy.startupPolicy, f.source.accountPolicy.policy.revision)
            let result = try recorded(writing, current)
            let different = Boundary(macID: current.macID, accountID: current.accountID,
                policy: .init(revision: UUID(), policy: current.policy.policy, roleRevisions: current.policy.roleRevisions),
                checkpoint: current.checkpoint)
            XCTAssertThrowsError(try result.requireRecorded(different)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertThrowsError(try changed(prepared) { $0["formatVersion"] = 1 }) {
                XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
            }
            try f.verifyMachine()
        }
    }
}
