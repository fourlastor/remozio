import Darwin
import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

/// Owned files with synthetic signature evidence. These checks grant no installed Root authority.
final class UpdateSchedulingPreparedReleaseTests: XCTestCase {
    private enum Fault: Error { case injected }
    private typealias Fixture = UpdateCandidateStorageFixture

    private func select(_ f: Fixture, _ copy: PreparationIntentRecord,
                        replacing old: UpdateSchedulingCandidateRecord? = nil) throws -> UpdateSchedulingCandidateRecord {
        try f.binding(copy).selectCurrentInLease(macID: f.mac, accountID: f.account, destination: f.destination,
            store: f.store, replacing: old, readPolicy: { f.policy }, inspect: { _, _, _ in f.release })
    }
    private func withCurrent<Value: Sendable>(_ f: Fixture, _ record: UpdateSchedulingCandidateRecord,
                                              _ body: () throws -> Value) throws -> Value {
        try f.binding(record.preparation).withCurrentCandidateInLease(macID: f.mac, accountID: f.account,
            expected: record, destination: f.destination, store: f.store,
            readPolicy: { f.policy }, inspect: { _, _, _ in f.release }, body)
    }
    func testCallbackFailureReleasesNoSuccessAndKeepsTheSelectionForReconciliation() throws {
        let f = try Fixture(), selected = try select(f, try f.copy())
        var released = false
        XCTAssertThrowsError(try { _ = try withCurrent(f, selected) { throw Fault.injected }; released = true }())
        XCTAssertFalse(released); XCTAssertEqual(try f.store.updateCandidate(), selected)
        XCTAssertEqual(try withCurrent(f, selected) { 31 }, 31)
    }
    func testCopyReplacementDuringTheAccountCommitCannotReleaseAResult() throws {
        let f = try Fixture(), selected = try select(f, try f.copy())
        var released = false
        XCTAssertThrowsError(try {
            _ = try withCurrent(f, selected) {
                let path = URL(fileURLWithPath: f.destination.path).appendingPathComponent(selected.preparation.bundleName)
                try FileManager.default.moveItem(at: path, to: path.appendingPathExtension("old"))
                try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false)
                XCTAssertEqual(chmod(path.path, 0o755), 0)
                return 23
            }
            released = true
        }())
        XCTAssertFalse(released); XCTAssertEqual(try f.store.updateCandidate(), selected)
    }
    func testPolicyFailureAfterTheAccountCommitCannotReleaseAResult() throws {
        let f = try Fixture(), selected = try select(f, try f.copy()), binding = try f.binding(selected.preparation)
        var failed = false, released = false
        XCTAssertThrowsError(try {
            _ = try binding.withCurrentCandidateInLease(macID: f.mac, accountID: f.account, expected: selected,
                destination: f.destination, store: f.store, readPolicy: {
                    if failed { throw Fault.injected }; return f.policy
                }, inspect: { _, _, _ in f.release }) { failed = true; return 23 }
            released = true
        }())
        XCTAssertFalse(released); XCTAssertEqual(try f.store.updateCandidate(), selected)
    }
    func testInventoryChangeInvalidatesAnOldSelectionUntilExplicitReselection() throws {
        let f = try Fixture(), copy = try f.copy(), selected = try select(f, copy)
        let inventory = try XCTUnwrap(f.store.inventory())
        _ = try f.store.writeInventory(inventory, expectedRevision: inventory.revision)
        XCTAssertThrowsError(try withCurrent(f, selected) { XCTFail("Old inventory reached commit") })
        let renewed = try select(f, copy, replacing: selected)
        XCTAssertEqual(renewed.generation, selected.generation + 1)
        XCTAssertNotEqual(renewed.inventoryRevision, selected.inventoryRevision)
    }
    func testChangedPreparationAndWrongAccountCannotSelectAnUnverifiedCopy() throws {
        let f = try Fixture(), copy = try f.copy(), binding = try f.binding(copy)
        XCTAssertThrowsError(try binding.selectCurrentInLease(macID: f.mac, accountID: Data(repeating: 99, count: 16),
            destination: f.destination, store: f.store, replacing: nil,
            readPolicy: { f.policy }, inspect: { _, _, _ in f.release }))
        _ = try f.store.abandon(id: copy.id, expectedRevision: copy.revision)
        XCTAssertThrowsError(try binding.selectCurrentInLease(macID: f.mac, accountID: f.account,
            destination: f.destination, store: f.store, replacing: nil,
            readPolicy: { f.policy }, inspect: { _, _, _ in f.release }))
        XCTAssertNil(try f.store.updateCandidate())
    }
    func testUnknownCommitResultRetiresTheOwnerAndReopensTheDurableSelection() throws {
        let f = try Fixture(), copy = try f.copy()
        try f.reopen(hook: { throw Fault.injected })
        var released = false
        XCTAssertThrowsError(try { _ = try select(f, copy); released = true }())
        XCTAssertFalse(released); XCTAssertThrowsError(try f.store.updateCandidate())
        f.store = try f.f.f.open()
        let durable = try XCTUnwrap(f.store.updateCandidate())
        XCTAssertEqual(durable.preparation, copy); XCTAssertEqual(durable.generation, 1)
        XCTAssertEqual(try withCurrent(f, durable) { 1 }, 1)
    }
    func testNativeEntriesRefuseAnOrdinaryAccountBeforeCallbacksOrStorageChanges() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary account control") }
        let f = try Fixture(enable: false)
        XCTAssertThrowsError(try UpdateSchedulingCurrentCandidate.enableStorage(installedRelease: f.release, policy: f.policy, store: f.store)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(try f.store.retainedRuntimeCompatibilityInputs().schemaVersion, 7)
        try f.enable()
        let selected = try select(f, try f.copy()), binding = try f.binding(selected.preparation)
        XCTAssertThrowsError(try binding.selectCurrent(macID: f.mac, accountID: f.account, destination: f.destination,
            store: f.store, replacing: selected, readPolicy: { XCTFail("Native refusal precedes policy"); return f.policy })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertThrowsError(try binding.withCurrentCandidate(macID: f.mac, accountID: f.account, expected: selected,
            destination: f.destination, store: f.store, readPolicy: { XCTFail("Native refusal precedes policy"); return f.policy }) {
            XCTFail("Native refusal precedes account commit")
        }) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertThrowsError(try binding.withCurrentCandidateLease(macID: f.mac, accountID: f.account, expected: selected,
            destination: f.destination, store: f.store, readPolicy: { XCTFail("Native refusal precedes policy"); return f.policy }) { _ in
            XCTFail("Native refusal precedes lease creation")
        }) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertEqual(try f.store.updateCandidate(), selected)
    }
}
