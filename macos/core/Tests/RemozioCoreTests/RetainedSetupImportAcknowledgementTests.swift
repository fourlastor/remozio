import Darwin
import Dispatch
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned journals test storage isolation only. The no-op file verifier proves no native custody, file bytes or paired policy compatibility.
final class RetainedSetupImportAcknowledgementTests: XCTestCase {
    private typealias Entry = MachineUpdateRetainedSetupInitialRuntimeEntry
    private typealias Inputs = MachineUpdateRetainedSetupRuntimeInputs
    private typealias Frame = PreparationIntentStore.RetainedImportFrame
    private typealias Scope = PreparationIntentStore.RetainedImportScope
    private typealias Stage = PreparationIntentStore.RetainedImportStage
    private typealias Read = PreparationIntentStore.InitialRuntimeRead
    private enum Fault: Error { case before, afterCommit }
    private final class SharedScope: @unchecked Sendable {
        let scope: Scope
        private let lock = NSLock()
        private var failure: JournalLeaseError?
        init(_ scope: Scope) { self.scope = scope }
        func invoke() {
            let caught: JournalLeaseError?
            do { _ = try scope.read(); caught = nil } catch { caught = error as? JournalLeaseError }
            lock.lock(); failure = caught; lock.unlock()
        }
        func result() -> JournalLeaseError? { lock.lock(); defer { lock.unlock() }; return failure }
    }
    private final class State {
        let f: RetainedPolicyWriterFixture
        let initial: SharedSetupImportIntent
        var journal: SharedSetupImportJournal!
        var armed = false, commits = 0
        var onCommit: (() throws -> Void)?
        var last: Frame?
        init(_ f: RetainedPolicyWriterFixture) throws {
            self.f = f
            let runtime = f.source.runtime, account = runtime.preparation
            let inventory = try runtime.setup.source.provisioningInventory(accountID: account.accountID,
                ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
            let defaults = try SharedSetupDefaults(presence: .init(idleMilliseconds: 540_000,
                observationLifetimeMilliseconds: 7000, unavailableGraceMilliseconds: 45_000),
                gateway: GatewaySetupForm().settingsSelection())
            initial = try .init(scope: .init(account: account, inventory: inventory), proposal: .init(defaults: defaults))
            try open(initialize: true); try journal.begin(initial); armed = true
        }
        func open(initialize: Bool) throws {
            let machine = URL(fileURLWithPath: f.directory.path), anchor = machine.deletingLastPathComponent().path
            let relative = machine.lastPathComponent + "/SharedSetupImport"
            if initialize {
                let directory = try ProtectedSetupDirectory(anchor: anchor, relativePath: relative, owner: getuid())
                defer { directory.close() }
                _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .sharedSetupImport, owner: getuid())
            }
            journal = try .init(lease: .init(anchor: anchor, relativeDirectory: relative, owner: getuid(), ancestorOwner: getuid(),
                databaseName: "setup-import.sqlite"), owner: getuid(), macID: initial.scope.macID,
                installationID: initial.scope.installationID, initialize: initialize, didCommit: { [weak self] in
                    guard let self, self.armed else { return }
                    self.commits += 1; try self.onCommit?()
                })
        }
        func reopen() throws { try? journal.close(); try f.reopen(nil); try open(initialize: false) }
    }
    private func fixture(_ body: (State) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(sharedImportFormats: true) { f in
            let before = try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
            let recorded = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: before, candidate: f.candidate,
                directory: f.directory, admission: f.admission, useMachine: { body in
                    try f.reopen(nil); let machine = f.machine(); defer { try? machine.close() }; return try body(machine)
                }, openJournal: { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) }, verifySnapshot: { _ in })
            try f.reopen(nil)
            _ = try f.machine().completeRetainedSetupRuntimePublication(f.material.reference,
                expected: recorded.activation.runtime, policy: XCTUnwrap(recorded.intent), candidate: f.candidate,
                directory: f.directory, admission: f.admission, fileCustodyAccepted: true, verifyScoped: { _, _ in })
            let state = try State(f); defer { try? state.journal.close(); try? f.machine().close() }
            try body(state)
        }
    }
    private func withFrame<Value>(_ s: State, _ body: (Frame) throws -> Value) throws -> Value {
        let machine = s.f.machine()
        return try machine.withSharedImportSnapshot(journal: s.journal) { directory, owner in
            let entry = try machine.retainedSetupInitialRuntimeEntry(owner: s.f.source.runtime.setup.owner, candidate: s.f.candidate)
            let inputs = try Inputs.capture(expected: entry.runtime, journal: s.journal,
                verifyCurrent: { try machine.validateStorageLease() }, readRelay: { try .read($0, directory: directory, owner: owner) })
            return try body((entry, inputs))
        }
    }
    private func invoke(_ s: State, expected: Frame? = nil, custody: Bool = true,
        didPrepare: (PreparationIntentStore) -> Void = { _ in }, verify: (Stage, Scope) throws -> Void = { _, _ in }) throws
        -> (frame: Frame, advanced: Bool) {
        try withFrame(s) { actual in
            s.last = actual
            let machine = s.f.machine(); didPrepare(machine); defer { machine.observeStoreRead = nil }
            return try machine.acknowledgeRetainedSetupImport(expected: expected?.entry ?? actual.entry,
                expectedInputs: expected?.inputs ?? actual.inputs, journal: s.journal, candidate: s.f.candidate,
                directory: s.f.directory, admission: s.f.admission, fileCustodyAccepted: custody, verifyScoped: verify)
        }
    }
    private var budget: [Read: Int] {
        [.readTransaction: 2, .runtime: 4, .frame: 12, .activation: 4, .policyMarker: 2,
         .policyScan: 14, .sharedImport: 16, .protectedRows: 2, .importInputs: 2]
    }
    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    func testOneConditionalAdvanceKeepsAllMachineRowsAndTheApprovedReadBudget() throws {
        try fixture { s in
            let rows = try s.f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1")
            var counts: [Read: Int] = [:], scopes: [Scope] = [], stages: [Stage] = []
            let result = try invoke(s, didPrepare: { $0.observeStoreRead = { counts[$0, default: 0] += 1 } }) { stage, scope in
                stages.append(stage); scopes.append(scope)
                let before = counts
                _ = try scope.read(); _ = try scope.read()
                try scope.withActive { _ in
                    XCTAssertThrowsError(try scope.withActive { _ in () }) {
                        XCTAssertEqual($0 as? PreparationStoreError, .transactionActive)
                    }
                }
                XCTAssertEqual(counts, before)
            }
            XCTAssertEqual(counts, budget); XCTAssertEqual(stages, [.beforeJournal, .afterJournal])
            XCTAssertTrue(result.advanced); XCTAssertEqual(s.commits, 1)
            XCTAssertEqual(result.frame.inputs.intent?.phase, .runtimePublished)
            XCTAssertNotEqual(result.frame.inputs.intent?.revision, s.initial.revision)
            try result.frame.entry.requireAcknowledgement(inputs: result.frame.inputs,
                from: XCTUnwrap(s.last).entry, previousInputs: XCTUnwrap(s.last).inputs)
            XCTAssertEqual(try s.f.scalar("SELECT COUNT(*) FROM runtime_preparation_v1"), rows)
            for scope in scopes { XCTAssertThrowsError(try scope.read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) } }
        }
    }
    func testPublishedRecoveryObservesTheFreshExactFrameWithoutAnotherAdvance() throws {
        try fixture { s in
            let first = try invoke(s); var counts: [Read: Int] = [:]
            let second = try invoke(s, didPrepare: { $0.observeStoreRead = { counts[$0, default: 0] += 1 } })
            XCTAssertFalse(second.advanced); XCTAssertEqual(s.commits, 1); XCTAssertEqual(counts, budget)
            try second.frame.entry.requireSame(as: first.frame.entry)
            try second.frame.inputs.requireSame(as: first.frame.inputs)
            XCTAssertNotEqual(second.frame.inputs.intent?.revision, s.initial.revision)
        }
    }
    func testMachineWriterLockSurvivesAdvanceAndRejectsCloseOtherTransactionsAndSecondOpen() throws {
        try fixture { s in
            var refused = 0
            s.onCommit = {
                let machine = s.f.machine()
                let operations: [() throws -> Void] = [
                    { try machine.close() }, { _ = try machine.inventory() },
                    { try machine.requireRetainedSetupPromotionWriterAvailable() },
                    { try machine.withSharedImportRelayDirectory { _, _ in XCTFail("Borrow re-entered") } }
                ]
                for operation in operations {
                    do { try operation(); XCTFail("Machine operation re-entered") }
                    catch { XCTAssertEqual(error as? PreparationStoreError, .transactionActive); refused += 1 }
                }
                let path = URL(fileURLWithPath: s.f.directory.path)
                do {
                    let second = try PreparationIntentStore(lease: .init(anchor: path.deletingLastPathComponent().path,
                        relativeDirectory: path.lastPathComponent, owner: getuid()), macID: s.initial.scope.macID,
                        maximumRecords: 64, initialize: false)
                    try second.close(); XCTFail("Second machine opened")
                } catch { XCTAssertEqual(error as? JournalLeaseError, .busy); refused += 1 }
            }
            XCTAssertTrue(try invoke(s).advanced); XCTAssertEqual(refused, 5); XCTAssertEqual(s.commits, 1)
        }
    }
    func testNoCommitFailureClosesTheInvocationAndPermitsOneFreshConditionalAttempt() throws {
        try fixture { s in
            XCTAssertThrowsError(try invoke(s, verify: { stage, _ in if stage == .beforeJournal { throw Fault.before } }))
            XCTAssertEqual(s.commits, 0)
            XCTAssertThrowsError(try s.f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try s.reopen()
            XCTAssertEqual(try s.journal.current(scope: s.initial.scope), s.initial)
            XCTAssertTrue(try invoke(s).advanced); XCTAssertEqual(s.commits, 1)
        }
    }
    func testLostCommitAcknowledgementReopensAndObservesCompletionWithoutReplay() throws {
        try fixture { s in
            s.onCommit = { throw Fault.afterCommit }
            XCTAssertThrowsError(try invoke(s)); XCTAssertEqual(s.commits, 1)
            XCTAssertThrowsError(try s.f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            s.onCommit = nil; try s.reopen()
            let committed = try XCTUnwrap(s.journal.current(scope: s.initial.scope))
            XCTAssertEqual(committed.phase, .runtimePublished); XCTAssertNotEqual(committed.revision, s.initial.revision)
            let result = try invoke(s)
            XCTAssertFalse(result.advanced); XCTAssertEqual(s.commits, 1); XCTAssertEqual(result.frame.inputs.intent, committed)
        }
    }
    func testProtectedRowChangeRefusesEvenWhenTheValueOnlyComparisonWouldAccept() throws {
        try fixture { s in
            let extra = try PreparationIntentRecord(id: UUID(), revision: UUID(), parent: "/private/tmp/retained-import-unused",
                ancestry: [.init(device: 1, inode: 1)], phase: .intent)
            let id = extra.id.uuidString.replacingOccurrences(of: "-", with: "")
            let revision = extra.revision.uuidString.replacingOccurrences(of: "-", with: "")
            s.onCommit = {
                _ = try s.f.scalar("INSERT INTO preparation_intents_v1 VALUES(X'\(id)',X'\(revision)',X'\(try self.hex(extra.encoded))')")
            }
            XCTAssertThrowsError(try invoke(s)) { XCTAssertEqual($0 as? PreparationStoreError, .staleRevision) }
            let before = try XCTUnwrap(s.last)
            s.onCommit = nil; try s.reopen()
            try withFrame(s) { actual in
                try actual.entry.requireAcknowledgement(inputs: actual.inputs, from: before.entry, previousInputs: before.inputs)
            }
            XCTAssertEqual(s.commits, 1)
        }
    }
    func testCatalogChangeDuringAdvanceIsRefusedAndLeavesTheStoreUnavailable() throws {
        try fixture { s in
            s.onCommit = { _ = try s.f.scalar("CREATE INDEX retained_import_fixture_extra ON runtime_preparation_v1(complete)") }
            XCTAssertThrowsError(try invoke(s)); XCTAssertEqual(s.commits, 1)
            XCTAssertThrowsError(try s.f.machine().inventory()) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
        }
    }
    func testMissingCustodyAndStaleInputsCannotInvokeTheVerifierOrAdvanceAgain() throws {
        try fixture { s in
            var callbacks = 0, counts: [Read: Int] = [:]
            XCTAssertThrowsError(try invoke(s, custody: false,
                didPrepare: { $0.observeStoreRead = { counts[$0, default: 0] += 1 } }, verify: { _, _ in callbacks += 1 })) {
                XCTAssertEqual($0 as? RuntimePreparationError, .custodyNotAccepted)
            }
            XCTAssertEqual(callbacks, 0); XCTAssertTrue(counts.isEmpty); XCTAssertEqual(s.commits, 0)
            let before = try withFrame(s) { $0 }
            _ = try s.journal.advance(s.initial, to: .runtimePublished)
            XCTAssertThrowsError(try invoke(s, expected: before, verify: { _, _ in callbacks += 1 }))
            XCTAssertEqual(callbacks, 0); XCTAssertEqual(s.commits, 1)
        }
    }
    func testScopesRejectForeignThreadsAndExpireBeforeTheJournalCommitCallback() throws {
        try fixture { s in
            var previous: Scope?
            s.onCommit = {
                XCTAssertThrowsError(try XCTUnwrap(previous).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
            }
            _ = try invoke(s, verify: { _, scope in
                previous = scope
                let shared = SharedScope(scope), done = DispatchSemaphore(value: 0)
                DispatchQueue.global().async { shared.invoke(); done.signal() }
                XCTAssertEqual(done.wait(timeout: .now() + 2), .success)
                XCTAssertEqual(shared.result(), JournalLeaseError.invalidated)
            })
            XCTAssertThrowsError(try XCTUnwrap(previous).read()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }
}
