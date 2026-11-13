import Foundation
import XCTest
@testable import RemozioCore

/// Owned stores exercise the complete storage sequence. Native caller, installed code and custody remain unproved.
final class RetainedSetupPolicyOwnerTests: XCTestCase {
    private typealias Owner = MachineUpdateRetainedSetupPolicyOwner
    private typealias Frame = MachineUpdateRetainedSetupPolicyFrame
    private typealias Fixture = RetainedPolicyWriterFixture
    private enum Fault: Error { case stopped }
    private final class Trace {
        var startupOpens = 0
        var stages: [Owner.Stage] = []
        var journalStages: [AuthorityJournal.MachineUpdatePolicyCommitStage] = []
    }
    private func fixture(noPolicyChange: Bool = false, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(noPolicyChange: noPolicyChange, body)
    }
    private func disk(_ f: Fixture) throws -> Frame.Snapshot {
        try f.reopen(nil); defer { try? f.machine().close() }
        return try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
    }
    private func pair(_ f: Fixture) throws -> AuthorityJournal.MachineUpdatePolicyBoundary {
        let journal = try f.openPolicyJournal(.readOnly); defer { try? journal.close() }
        return try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(f.source.runtime.setup.account?.initialization))
    }
    private func resume(_ f: Fixture, expected: Frame.Snapshot? = nil, trace: Trace,
        wrongStartup: Bool = false,
        storage: @escaping (Owner.StorageStep, PreparationIntentStore.CompletionIntentStorageStage, Frame.Scope) throws -> Void = { _, _, _ in },
        journal: @escaping (AuthorityJournal.MachineUpdatePolicyCommitStage, @escaping Owner.Verify) throws -> Void = { _, _ in },
        stage: @escaping (Owner.Stage) throws -> Void = { _ in }) throws -> Frame.Snapshot {
        try Owner.resume(expected: expected ?? disk(f), candidate: f.candidate, directory: f.directory,
            admission: f.admission, useMachine: { body in
                try f.reopen(nil); let machine = f.machine(); defer { try? machine.close() }; return try body(machine)
            }, openJournal: { access in
                switch access {
                case .readOnly: return try f.openPolicyJournal(.readOnly)
                case .startup:
                    trace.startupOpens += 1
                    return try f.openPolicyJournal(wrongStartup ? .foreignStartup : .startup)
                }
            }, verifySnapshot: { _ in }, didStorageStage: storage,
            didJournalStage: { actual, verify in trace.journalStages.append(actual); try journal(actual, verify) },
            didStage: { actual in trace.stages.append(actual); try stage(actual) })
    }

    func testFreshOwnerPersistsEveryPhaseAndCommitsOnlyTheActualStartupPair() throws {
        try fixture { f in
            let trace = Trace(), before = try pair(f)
            let result = try resume(f, trace: trace)
            XCTAssertEqual(trace.stages, [.intentRetained, .writingRetained, .policyCommitted, .recorded])
            XCTAssertEqual(trace.journalStages, [.beforeCommit, .inTransaction, .afterMutation, .afterCommit])
            XCTAssertEqual(trace.startupOpens, 1)
            let intent = try XCTUnwrap(result.intent), actual = try pair(f)
            XCTAssertEqual(intent.phase, .recorded); try intent.requireRecorded(actual)
            XCTAssertEqual(actual.policy.policy, f.source.policy.startupPolicy)
            XCTAssertEqual(actual.checkpoint.generation, before.checkpoint.generation + 1)
            XCTAssertEqual(actual.checkpoint.currentAuthorityGeneration, before.checkpoint.currentAuthorityGeneration + 1)
            try disk(f).requireSame(as: result)
            XCTAssertFalse(result.activation.runtime.state.configurationPublished)
            XCTAssertNil(result.activation.state.plan); XCTAssertFalse(result.activation.state.jobsRegistered)
        }
    }

    func testRecordedOwnerOnlyRechecksFreshDiskAndPairWithoutAnotherCommit() throws {
        try fixture { f in
            let first = Trace(), result = try resume(f, trace: first), before = try pair(f), repeated = Trace()
            let second = try resume(f, trace: repeated)
            try second.requireSame(as: result); XCTAssertEqual(try pair(f), before)
            XCTAssertEqual(repeated.startupOpens, 0); XCTAssertTrue(repeated.journalStages.isEmpty); XCTAssertTrue(repeated.stages.isEmpty)
        }
    }

    func testPreparedInterruptionResumesFromTheActualRetainedPreparedRow() throws {
        try fixture { f in
            let trace = Trace()
            XCTAssertThrowsError(try resume(f, trace: trace, stage: { if $0 == .intentRetained { throw Fault.stopped } })) {
                XCTAssertTrue($0 is Fault)
            }
            let retained = try disk(f), prepared = try XCTUnwrap(retained.intent)
            XCTAssertEqual(prepared.phase, .prepared); XCTAssertEqual(trace.startupOpens, 0)
            XCTAssertEqual(try pair(f), f.source.accountPolicy)
            let next = Trace(), result = try resume(f, expected: retained, trace: next)
            XCTAssertEqual(result.intent?.id, prepared.id); XCTAssertEqual(result.intent?.phase, .recorded)
            XCTAssertEqual(next.stages, [.writingRetained, .policyCommitted, .recorded]); XCTAssertEqual(next.startupOpens, 1)
        }
    }

    func testUnresolvedWritingWithUnchangedSourceRefusesAutomaticReplay() throws {
        try fixture { f in
            let first = Trace()
            XCTAssertThrowsError(try resume(f, trace: first, stage: { if $0 == .writingRetained { throw Fault.stopped } })) {
                XCTAssertTrue($0 is Fault)
            }
            let retained = try disk(f), writing = try XCTUnwrap(retained.intent)
            XCTAssertEqual(writing.phase, .writing); XCTAssertEqual(first.startupOpens, 0)
            XCTAssertNotEqual(f.source.policy.startupPolicy, f.source.policy.source.policy)
            XCTAssertEqual(try writing.reconciling(pair(f)), .sourceUnchanged)
            let next = Trace()
            XCTAssertThrowsError(try resume(f, expected: retained, trace: next)) { XCTAssertEqual($0 as? RuntimeActivationError, .unavailable) }
            XCTAssertEqual(next.startupOpens, 0); XCTAssertTrue(next.journalStages.isEmpty)
            try disk(f).requireSame(as: retained); XCTAssertEqual(try pair(f), f.source.accountPolicy)
        }
    }

    func testLostAfterCommitAcknowledgementRecoversTheExactPairWithoutASecondCommit() throws {
        try fixture { f in
            let first = Trace(); var oldScope: Frame.Scope?
            XCTAssertThrowsError(try resume(f, trace: first, storage: { kind, stage, scope in
                if kind == .writing && stage == .afterMutation { oldScope = scope }
            }, journal: { stage, _ in if stage == .afterCommit { throw Fault.stopped } })) { XCTAssertTrue($0 is Fault) }
            let retained = try disk(f), committed = try pair(f)
            XCTAssertEqual(retained.intent?.phase, .writing); XCTAssertEqual(first.startupOpens, 1)
            XCTAssertEqual(committed.policy.policy, f.source.policy.startupPolicy)
            XCTAssertEqual(committed.checkpoint.generation, f.source.accountPolicy.checkpoint.generation + 1)
            XCTAssertThrowsError(try XCTUnwrap(oldScope).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            let next = Trace()
            let result = try resume(f, expected: retained, trace: next, storage: { _, _, _ in
                XCTAssertThrowsError(try XCTUnwrap(oldScope).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            })
            XCTAssertEqual(next.startupOpens, 0); XCTAssertTrue(next.journalStages.isEmpty)
            XCTAssertEqual(next.stages, [.recorded]); XCTAssertEqual(try pair(f), committed)
            try XCTUnwrap(result.intent).requireRecorded(committed)
        }
    }

    func testAfterMutationRollbackExpiresTheStepAndRetryUsesANewInvocationAndDiskFrame() throws {
        try fixture { f in
            let first = Trace(); var oldScope: Frame.Scope?, uncommitted: Frame.Snapshot?
            XCTAssertThrowsError(try resume(f, trace: first, storage: { kind, stage, scope in
                if kind == .writing && stage == .afterMutation {
                    oldScope = scope; uncommitted = try scope.read(); throw Fault.stopped
                }
            })) { XCTAssertTrue($0 is Fault) }
            let actual = try disk(f), prepared = try XCTUnwrap(actual.intent)
            XCTAssertEqual(prepared.phase, .prepared); XCTAssertEqual(first.startupOpens, 0)
            XCTAssertEqual(try pair(f), f.source.accountPolicy)
            XCTAssertThrowsError(try XCTUnwrap(oldScope).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            let stale = Trace()
            XCTAssertThrowsError(try resume(f, expected: XCTUnwrap(uncommitted), trace: stale)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            XCTAssertEqual(stale.startupOpens, 0)
            let next = Trace(); var freshWritingRevision: UUID?
            let result = try resume(f, expected: actual, trace: next, storage: { kind, stage, scope in
                XCTAssertThrowsError(try XCTUnwrap(oldScope).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                if kind == .writing && stage == .afterMutation { freshWritingRevision = try scope.read().intent?.revision }
            })
            XCTAssertNotNil(freshWritingRevision); XCTAssertNotEqual(freshWritingRevision, uncommitted?.intent?.revision)
            XCTAssertEqual(result.intent?.id, prepared.id); XCTAssertEqual(result.intent?.phase, .recorded)
            XCTAssertEqual(next.startupOpens, 1)
        }
    }

    func testNoOpOwnerRecordsTheActualUnchangedPairWithoutAdvancingItsCheckpoint() throws {
        try fixture(noPolicyChange: true) { f in
            let before = try pair(f), trace = Trace(), result = try resume(f, trace: trace)
            XCTAssertEqual(trace.startupOpens, 1); XCTAssertEqual(trace.journalStages, [.beforeCommit, .afterCommit])
            XCTAssertEqual(try pair(f), before); XCTAssertEqual(result.intent?.phase, .recorded)
            try XCTUnwrap(result.intent).requireRecorded(before)
        }
    }

    func testStorageAndJournalVerificationLoansExpireBeforeOwnerReturn() throws {
        try fixture { f in
            var escapedStorage: Frame.Scope?, escapedJournal: Owner.Verify?
            let result = try resume(f, trace: Trace(), storage: { _, _, scope in escapedStorage = scope },
                journal: { _, verify in escapedJournal = verify; try verify() }, stage: { stage in
                    if stage == .policyCommitted {
                        XCTAssertThrowsError(try XCTUnwrap(escapedJournal)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                        XCTAssertThrowsError(try XCTUnwrap(escapedStorage).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                    }
                })
            XCTAssertEqual(result.intent?.phase, .recorded)
            XCTAssertThrowsError(try XCTUnwrap(escapedStorage).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try XCTUnwrap(escapedJournal)()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testForeignStartupFactoryCannotWriteAndItsUnresolvedMarkerCannotReplay() throws {
        try fixture { f in
            let first = Trace()
            XCTAssertThrowsError(try resume(f, trace: first, wrongStartup: true))
            XCTAssertEqual(first.startupOpens, 1); XCTAssertEqual(try pair(f), f.source.accountPolicy)
            let retained = try disk(f)
            XCTAssertEqual(retained.intent?.phase, .writing)
            let next = Trace()
            XCTAssertThrowsError(try resume(f, expected: retained, trace: next)) { XCTAssertEqual($0 as? RuntimeActivationError, .unavailable) }
            XCTAssertEqual(next.startupOpens, 0); XCTAssertEqual(try pair(f), f.source.accountPolicy)
        }
    }
}
