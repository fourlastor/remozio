import Dispatch
import Foundation
import Synchronization
import XCTest
@testable import RemozioCore

/// Owned stores test scoped frames. No production sequence, journal write or native custody is introduced.
final class RetainedSetupPolicyFrameTests: XCTestCase {
    private typealias Frame = MachineUpdateRetainedSetupPolicyFrame
    private typealias Fixture = RetainedPolicyWriterFixture
    private typealias Record = MachineUpdateRetainedSetupPolicyIntentRecord
    private typealias Receipt = PreparationIntentStore.RetainedSetupPolicyWriteReceipt
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private final class SharedScope: @unchecked Sendable {
        let scope: Frame.Scope
        init(_ scope: Frame.Scope) { self.scope = scope }
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(body)
    }
    private func snapshot(_ f: Fixture) throws -> Frame.Snapshot {
        try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
    }
    private func invoke(_ f: Fixture, expected: Frame.Snapshot? = nil,
        verify: @escaping (Frame.Snapshot) throws -> Void = { _ in }, body: (Frame.Invocation) throws -> Void) throws {
        try Frame.withInvocation(expected: expected ?? snapshot(f), candidate: f.candidate,
            directory: f.directory, admission: f.admission, verifySnapshot: verify, body: body)
    }
    private func provide(_ f: Fixture, body: @escaping Frame.MachineBody) throws -> Frame.Snapshot {
        let machine = f.machine(); defer { try? machine.close() }; return try body(machine)
    }

    func testActualReadReturnsOnlyAClosedMachineAndExpiresTheStepScope() throws {
        try fixture { f in
            let before = try snapshot(f); var escaped: Frame.Scope?, closed: Frame.ClosedMachine?
            try invoke(f, expected: before) { invocation in
                closed = try invocation.machineStep(expected: before, useMachine: { try self.provide(f, body: $0) }) { _, step in
                    escaped = step.scope; try step.scope.verify(); return try step.read()
                }
                try XCTUnwrap(closed).snapshot.requireSame(as: before)
                try XCTUnwrap(closed).withClosedMachine { try f.machine().requireClosedForRetainedSetupPolicyWrite() }
                XCTAssertThrowsError(try XCTUnwrap(escaped).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            }
            XCTAssertThrowsError(try XCTUnwrap(closed).withClosedMachine { _ = 1 }) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
        }
    }

    func testProviderCannotReturnWithItsMachineConnectionStillOpen() throws {
        try fixture { f in
            let before = try snapshot(f)
            try invoke(f, expected: before) { invocation in
                XCTAssertThrowsError(try invocation.machineStep(expected: before, useMachine: { try $0(f.machine()) }) { _, step in
                    try step.read()
                }) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
            }
            try snapshot(f).requireSame(as: before)
        }
    }

    func testProviderMustEnterAndAnEscapedBodyCannotRunAfterReturn() throws {
        try fixture { f in
            let before = try snapshot(f); var escaped: Frame.MachineBody?, called = false
            try invoke(f, expected: before) { invocation in
                XCTAssertThrowsError(try invocation.machineStep(expected: before, useMachine: { body in
                    escaped = body; return before
                }, body: { _, step in called = true; return try step.read() })) {
                    XCTAssertEqual($0 as? RuntimeActivationError, .unavailable)
                }
            }
            XCTAssertFalse(called)
            XCTAssertThrowsError(try XCTUnwrap(escaped)(f.machine())) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            try snapshot(f).requireSame(as: before)
        }
    }

    func testASecondProviderEntryPoisonsTheResultEvenWhenItsErrorIsCaught() throws {
        try fixture { f in
            let before = try snapshot(f); var entries = 0
            try invoke(f, expected: before) { invocation in
                XCTAssertThrowsError(try invocation.machineStep(expected: before, useMachine: { body in
                    let value = try body(f.machine())
                    XCTAssertThrowsError(try body(f.machine())) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
                    try f.machine().close(); return value
                }, body: { _, step in entries += 1; return try step.read() })) {
                    XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
                }
            }
            XCTAssertEqual(entries, 1)
        }
    }

    func testProviderCannotReportAnUnwrittenSnapshotWithAProposedMarker() throws {
        try fixture { f in
            let before = try snapshot(f), proposed = try Record(source: f.source)
            let fabricated = try Frame.Snapshot(activation: before.activation, intent: proposed, candidate: f.candidate)
            try invoke(f, expected: before) { invocation in
                XCTAssertThrowsError(try invocation.machineStep(expected: before, useMachine: { body in
                    _ = try self.provide(f, body: body); return fabricated
                }, body: { _, step in try step.read() })) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            }
            try f.reopen(nil); try snapshot(f).requireSame(as: before)
        }
    }

    func testStorageCallbacksLendActualFramesWithoutReenteringTheMachineTransaction() throws {
        try fixture { f in
            let before = try snapshot(f), prepared = try Record(source: f.source); var stages: [Stage] = []
            try invoke(f, expected: before) { invocation in
                let closed = try invocation.machineStep(expected: before, useMachine: { try self.provide(f, body: $0) }) { machine, step in
                    _ = try machine.retainRetainedSetupPolicyIntent(prepared, expected: step.read(), candidate: f.candidate,
                        directory: f.directory, admission: f.admission, verifyScoped: { stage, actual in
                            stages.append(stage)
                            try step.storage(actual, stage: stage, intent: prepared, change: .retention, verifyAccount: f.verifyPair) { scope in
                                try scope.read().requireSame(as: actual)
                                XCTAssertThrowsError(try self.snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
                            }
                        })
                    return try step.read()
                }
                XCTAssertEqual(closed.snapshot.intent, prepared)
                try closed.snapshot.requireRetention(prepared, from: before)
                try closed.withClosedMachine { try f.machine().requireClosedForRetainedSetupPolicyWrite() }
            }
            XCTAssertEqual(stages, [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit]); try f.verifyPair()
        }
    }

    func testSnapshotVerifierCannotReenterItsOwnRead() throws {
        try fixture { f in
            let before = try snapshot(f); var current: Frame.Scope?, armed = false, refused = 0
            try invoke(f, expected: before, verify: { _ in
                if armed {
                    XCTAssertThrowsError(try XCTUnwrap(current).read()) { XCTAssertEqual($0 as? PreparationStoreError, .transactionActive) }
                    refused += 1
                }
            }) { invocation in
                _ = try invocation.machineStep(expected: before, useMachine: { try self.provide(f, body: $0) }) { _, step in
                    current = step.scope; armed = true; defer { armed = false }; return try step.read()
                }
            }
            XCTAssertGreaterThan(refused, 0)
        }
    }

    func testFrameScopeRejectsAnotherThreadBeforeReadingTheMachine() throws {
        try fixture { f in
            let before = try snapshot(f)
            try invoke(f, expected: before) { invocation in
                _ = try invocation.machineStep(expected: before, useMachine: { try self.provide(f, body: $0) }) { _, step in
                    let shared = SharedScope(step.scope), refused = Mutex(false), done = DispatchSemaphore(value: 0)
                    Thread.detachNewThread {
                        do { _ = try shared.scope.read() }
                        catch { refused.withLock { $0 = error as? JournalLeaseError == .invalidated } }
                        done.signal()
                    }
                    XCTAssertEqual(done.wait(timeout: .now() + 5), .success); XCTAssertTrue(refused.withLock { $0 })
                    return try step.read()
                }
            }
        }
    }

    func testClosedResultKeepsTheWeakAcknowledgementWriterAliveForReadOnlyDiskVerification() throws {
        try fixture { f in
            let before = try snapshot(f), prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            var acknowledged: Receipt?
            try invoke(f, expected: before) { invocation in
                let closed = try invocation.machineStep(expected: before, useMachine: { try self.provide(f, body: $0) }) { machine, step in
                    _ = try machine.retainRetainedSetupPolicyIntent(prepared, expected: step.read(), candidate: f.candidate,
                        directory: f.directory, admission: f.admission, verifyScoped: { stage, actual in
                            try step.storage(actual, stage: stage, intent: prepared, change: .retention, verifyAccount: f.verifyPair, didStage: { _ in })
                        })
                    acknowledged = try machine.beginRetainedSetupPolicyWrite(writing, source: f.source, expected: step.read(),
                        candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { stage, actual in
                            try step.storage(actual, stage: stage, intent: writing, change: .transition, verifyAccount: f.verifyPair, didStage: { _ in })
                        })
                    return try step.read()
                }
                try f.reopen(nil); XCTAssertEqual(try snapshot(f).intent, writing); try f.machine().close()
                try closed.withClosedMachine {
                    try XCTUnwrap(acknowledged).withFirstWritingUse { use in
                        try use.validate(); try use.verifyCurrentMarker(candidate: f.candidate)
                    }
                }
            }
            try f.verifyPair()
        }
    }
}
