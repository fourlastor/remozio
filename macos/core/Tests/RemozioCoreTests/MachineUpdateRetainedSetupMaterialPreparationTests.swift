import Darwin
import Dispatch
import Foundation
import XCTest
@testable import RemozioCore

/// Injected owned producers prove callback and metadata rules, without native files, hardware keys or service identity proof.
final class MachineUpdateRetainedSetupMaterialPreparationTests: XCTestCase {
    private typealias Preparation = MachineUpdateRetainedSetupMaterialPreparation
    private typealias Frame = MachineUpdateRetainedSetupMaterialSnapshot
    private typealias Scope = MachineUpdateStableRuntimePublication.Scope
    private typealias Fixture = RetainedMaterialWriterFixture
    private typealias Stage = PreparationIntentStore.CompletionIntentStorageStage
    private enum Fault: Error { case callback }
    private final class CallbackBox: @unchecked Sendable {
        private let lock = NSLock()
        private let scope: Scope
        private var failure: JournalLeaseError?
        init(_ scope: Scope) { self.scope = scope }
        func invoke() {
            do { try scope.verify() }
            catch { lock.withLock { failure = error as? JournalLeaseError } }
        }
        func result() -> JournalLeaseError? { lock.withLock { failure } }
    }
    private func fixture(hasReference: Bool = false, _ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(hasReference: hasReference, body)
    }
    private func snapshot(_ f: Fixture) throws -> Frame {
        try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)
    }
    private func prepare(_ f: Fixture, custody: Bool = true,
        verifyCurrent: @escaping (Frame) throws -> Void = { _ in },
        restore: ((ServiceAccountPlan, RuntimeMaterialReference?, Scope) throws -> RuntimePreparationMaterial)? = nil,
        validate: ((RuntimePreparationMaterial, Scope) throws -> Void)? = nil,
        stage: (RuntimePublicationController.Stage) throws -> Void = { _ in },
        storageStage: (Stage, Scope) throws -> Void = { _, _ in }, inspect: (Scope) throws -> Void = { _ in }) throws -> RuntimePreparationState {
        let expected = try snapshot(f)
        return try Preparation.prepare(machine: f.machine(), expected: expected, candidate: f.candidate,
            directory: f.directory, admission: f.admission, fileCustodyAccepted: custody,
            verifyCurrent: { actual in try f.directory.validate(); try verifyCurrent(actual) },
            verifyServices: { try $0.validate(account: expected.runtime.preparation) }, verifyAuthority: { _ in },
            restoreMaterial: restore ?? { _, _, scope in try scope.verify(); return f.material },
            validateMaterial: validate ?? { material, scope in
                try scope.verify(); XCTAssertEqual(try material.encoded, try f.material.encoded)
            }, didStage: stage, didStorageStage: storageStage, inspectScope: inspect)
    }

    func testPreparationBorrowsTheActualWriterFramesAndRetainsWithoutPublication() throws {
        try fixture { f in
            var escaped: Scope?, restored = false, frames = 0
            var events: [RuntimePublicationController.Stage] = []
            let result = try prepare(f, restore: { plan, previous, scope in
                XCTAssertNil(previous); XCTAssertEqual(plan, f.material.services)
                XCTAssertNil(try scope.read().state.reference); restored = true
                return f.material
            }, stage: { events.append($0) }, storageStage: { stage, scope in
                frames += 1
                let raw = try scope.read(); try scope.verify()
                if stage == .beforeTransaction || stage == .inTransaction { XCTAssertNil(raw.state.reference) }
                else { XCTAssertEqual(raw.state.reference, try f.material.reference) }
                XCTAssertThrowsError(try self.snapshot(f)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                }
            }, inspect: { escaped = $0 })
            XCTAssertTrue(restored); XCTAssertEqual(frames, 4)
            XCTAssertEqual(events, [.materialRestored, .referenceRetained])
            XCTAssertEqual(result.reference, try f.material.reference); XCTAssertFalse(result.configurationPublished)
            XCTAssertEqual(try snapshot(f).runtime.state, result)
            XCTAssertThrowsError(try XCTUnwrap(escaped).verify()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            XCTAssertThrowsError(try XCTUnwrap(escaped).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testExistingIdenticalMaterialIsRestoredWithoutAnotherCommit() throws {
        try fixture(hasReference: true) { f in
            var commits = 0; try f.reopen { commits += 1 }
            let before = try snapshot(f)
            let result = try prepare(f, restore: { _, previous, scope in
                XCTAssertEqual(previous, try f.material.reference); try scope.verify(); return f.material
            })
            XCTAssertEqual(result, before.runtime.state); XCTAssertEqual(commits, 0)
            try snapshot(f).requireSame(as: before)
        }
    }

    func testDifferentRestoredMaterialCannotReplaceTheHistoricalReference() throws {
        try fixture(hasReference: true) { f in
            let before = try snapshot(f), now = Date(); var validated = false
            var escaped: Scope?
            let different = try RuntimePreparationMaterial.create(services: before.runtime.plan,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
            XCTAssertThrowsError(try prepare(f, restore: { _, _, _ in different }, validate: { _, _ in validated = true },
                inspect: { escaped = $0 })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .conflictingMaterial)
            }
            XCTAssertFalse(validated); try snapshot(f).requireSame(as: before)
            XCTAssertThrowsError(try XCTUnwrap(escaped).verify()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testCustodyRefusalPrecedesAllProducerCallbacks() throws {
        try fixture { f in
            let before = try snapshot(f); var called = false
            XCTAssertThrowsError(try prepare(f, custody: false, verifyCurrent: { _ in called = true },
                restore: { _, _, _ in called = true; return f.material }, inspect: { _ in called = true })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
            }
            XCTAssertFalse(called); try snapshot(f).requireSame(as: before)
        }
    }

    func testNativeOrdinaryUIDRefusesBeforeCustodyOrProtectedIdentityAccess() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("This refusal requires an ordinary UID") }
        try fixture { f in
            let before = try snapshot(f); var called = false
            XCTAssertThrowsError(try Preparation.prepareNative(machine: f.machine(), expected: before, candidate: f.candidate,
                currentCodePolicy: before.runtime.preparation.initialAuthority.codePolicy, directory: f.directory,
                admission: f.admission, fileCustodyAccepted: false, verifyCurrent: { _ in called = true })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            XCTAssertFalse(called); try snapshot(f).requireSame(as: before)
        }
    }

    func testForeignThreadCannotUseTheLiveVerificationScope() throws {
        try fixture { f in
            _ = try prepare(f, inspect: { scope in
                let box = CallbackBox(scope), done = DispatchSemaphore(value: 0)
                DispatchQueue.global().async { box.invoke(); done.signal() }
                XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
                XCTAssertEqual(box.result(), .invalidated)
                try scope.verify()
            })
        }
    }

    func testRecursiveVerificationRefusesWithoutEscapingItsOwnerRead() throws {
        try fixture { f in
            var escaped: Scope?, recursiveChecks = 0
            _ = try prepare(f, verifyCurrent: { _ in
                if let escaped {
                    recursiveChecks += 1
                    XCTAssertThrowsError(try escaped.verify()) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                }
            }, inspect: { escaped = $0 })
            XCTAssertGreaterThan(recursiveChecks, 0)
        }
    }

    func testStorageCallbackFailuresRollBackOrPreserveTheActualCommittedReference() throws {
        for stopped: Stage in [.beforeTransaction, .inTransaction, .afterMutation, .afterCommit] {
            try fixture { f in
                let before = try snapshot(f); var escaped: Scope?
                XCTAssertThrowsError(try prepare(f, storageStage: { stage, scope in
                    escaped = scope; if stage == stopped { throw Fault.callback }
                })) { XCTAssertTrue($0 is Fault, "\($0)") }
                XCTAssertThrowsError(try XCTUnwrap(escaped).verify()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                if stopped == .afterCommit {
                    XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
                    try f.reopen(nil)
                    XCTAssertEqual(try snapshot(f).runtime.state.reference, try f.material.reference)
                    XCTAssertFalse(try snapshot(f).runtime.state.configurationPublished)
                } else { try snapshot(f).requireSame(as: before) }
            }
        }
    }

    func testProducerStageFailuresNeverMarkConfigurationPublished() throws {
        for stopped: RuntimePublicationController.Stage in [.materialRestored, .referenceRetained] {
            try fixture { f in
                var escaped: Scope?
                XCTAssertThrowsError(try prepare(f, stage: { if $0 == stopped { throw Fault.callback } },
                    inspect: { escaped = $0 })) { XCTAssertTrue($0 is Fault) }
                XCTAssertThrowsError(try XCTUnwrap(escaped).verify()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
                let actual = try snapshot(f)
                XCTAssertFalse(actual.runtime.state.configurationPublished)
                XCTAssertEqual(actual.runtime.state.reference != nil, stopped == .referenceRetained)
            }
        }
    }
}
