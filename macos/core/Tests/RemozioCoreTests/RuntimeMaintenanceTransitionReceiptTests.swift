import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Real SQL transitions and actual admission. Synthetic release declarations grant no installed C02 authority.
final class RuntimeMaintenanceTransitionReceiptTests: XCTestCase {
    private typealias Row = RuntimeMaintenanceWindowRecord
    private typealias Receipt = PreparationIntentStore.RuntimeMaintenanceTransition
    private enum Fault: Error { case expected }
    private func bytes(_ value: UInt8, _ count: Int = 16) -> Data { Data(repeating: value, count: count) }
    private func initial(_ f: RuntimeMaintenanceWriterFixture) throws -> Row {
        let snapshot = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
        return try .init(id: bytes(51), revision: bytes(52), purpose: .retainedRuntime,
            scope: .init(macID: snapshot.inventory.macID, installationID: snapshot.inventory.installationID,
                authority: f.authority, target: f.target, releaseDigest: snapshot.inventory.releaseDigest,
                candidateDigest: bytes(1, 32), authorityPolicyDigest: bytes(2, 32), operationDigest: bytes(3, 32),
                restorationDigest: bytes(4, 32), mutationFootprintDigest: bytes(5, 32), authorityGrantDigest: bytes(6, 32),
                targetConsentDigest: bytes(7, 32), administratorIntentDigest: bytes(8, 32)))
    }
    private func write(_ row: Row, previous: Row?, f: RuntimeMaintenanceWriterFixture,
        drain: UpdateDrainToken? = nil, verify: (PreparationIntentStore.CompletionIntentStorageStage) throws -> Void = { _ in }) throws -> Receipt {
        try f.machine().writeRuntimeMaintenanceTransition(row, replacing: previous,
            expected: f.machine().stableMachineUpdateSnapshot(candidate: f.candidate), candidate: f.candidate,
            directory: f.directory, admission: f.admission, accountDrain: drain, verifyScoped: verify)
    }
    private func withChain(_ body: (RuntimeMaintenanceWriterFixture, MachineUpdateStableReleaseSnapshot, [Receipt], Receipt) throws -> Void) throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let before = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            let authorized = try initial(f), first = try write(authorized, previous: nil, f: f)
            let gate = try XCTUnwrap(before.admission.accounts.first { $0.accountID == f.authority.accountID })
            let anchor = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent().deletingLastPathComponent().path
            let barrier = try UpdateAdmissionBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
                owner: getuid(), expected: gate.identity, scope: .account(gate.accountID))
            let drain = try barrier.beginDrain(); defer { drain.close() }
            let draining = try Row(id: authorized.id, revision: bytes(53), purpose: authorized.purpose, scope: authorized.scope, phase: .draining)
            var receipts = [first, try write(draining, previous: authorized, f: f, drain: drain)]
            let binding = try AuthorityMaintenanceBinding(accountID: f.authority.accountID, attemptID: authorized.id,
                revision: draining.revision, incarnation: bytes(54), connectionID: bytes(55))
            let bound = try f.machine().persistRuntimeMaintenanceBindingTransition(binding, window: draining,
                expected: f.machine().stableMachineUpdateSnapshot(candidate: f.candidate), candidate: f.candidate,
                directory: f.directory, admission: f.admission, accountDrain: drain)
            receipts.append(bound); var previous = bound.record
            for phase in [Row.Phase.stopping, .stopped, .executing] {
                let row = try Row(id: previous.id, revision: AccountPreparationIntent.randomID(), purpose: previous.purpose,
                    scope: previous.scope, phase: phase, operation: phase == .executing ? .unknown : .notStarted,
                    service: phase == .stopping ? .notStopped : .stopped, shutdownBinding: binding)
                receipts.append(try write(row, previous: previous, f: f)); previous = row
            }
            try body(f, before, receipts, bound)
        }
    }
    func testRealAuthorizedDrainBindingStopAndExecutingChainPreservesEveryOtherRow() throws {
        try withChain { f, before, receipts, binding in
            let after = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            XCTAssertEqual(receipts.count, 6)
            let value = try Receipt.requireChain(receipts, from: before, to: after, binding: binding)
            XCTAssertEqual(value, receipts.last?.record); XCTAssertEqual(value.phase, .executing)
            XCTAssertEqual(value.shutdownBinding, binding.record.shutdownBinding)
            XCTAssertThrowsError(try after.requireSame(as: before))
            XCTAssertEqual(after.inventory, before.inventory); XCTAssertEqual(after.admission, before.admission)
        }
    }
    func testOmittedReorderedAndReplayedBindingReceiptsCannotBridgeTheActualChain() throws {
        try withChain { f, before, receipts, binding in
            let after = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            var missing = receipts; missing.remove(at: 2)
            XCTAssertThrowsError(try Receipt.requireChain(missing, from: before, to: after, binding: binding))
            var reordered = receipts; reordered.swapAt(1, 2)
            XCTAssertThrowsError(try Receipt.requireChain(reordered, from: before, to: after, binding: binding))
            var replayed = receipts; replayed.insert(binding, at: 3)
            XCTAssertThrowsError(try Receipt.requireChain(replayed, from: before, to: after, binding: binding))
            XCTAssertThrowsError(try Receipt.requireChain(receipts, from: after, to: after, binding: binding))
        }
    }
    func testPostCommitFailureReturnsNoReceiptAndRetiresWithoutRepeatingTheWrite() throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let row = try initial(f); var commits = 0
            XCTAssertThrowsError(try write(row, previous: nil, f: f, verify: { stage in
                if stage == .afterCommit { commits += 1; throw Fault.expected }
            }))
            XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
            try f.reopen(nil)
            XCTAssertEqual(f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate).revision, row.revision)
        }
    }
}
