import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Real SQLite and admission files with an explicit synthetic writer 2 declaration. No installed C02 entry is exercised.
final class RuntimeMaintenanceBindingWriterTests: XCTestCase {
    private typealias Row = RuntimeMaintenanceWindowRecord
    private enum Fault: Error { case injected }
    private func d(_ n: UInt8, _ count: Int = 16) -> Data { Data(repeating: n, count: count) }
    private func draining(_ f: RuntimeMaintenanceWriterFixture) throws -> (Row, UpdateDrainToken) {
        let snapshot = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
        let scope = try Row.Scope(macID: snapshot.inventory.macID, installationID: snapshot.inventory.installationID,
            authority: f.authority, target: f.target, releaseDigest: snapshot.inventory.releaseDigest,
            candidateDigest: d(1, 32), authorityPolicyDigest: d(2, 32), operationDigest: d(3, 32), restorationDigest: d(4, 32),
            mutationFootprintDigest: d(5, 32), authorityGrantDigest: d(6, 32), targetConsentDigest: d(7, 32), administratorIntentDigest: d(8, 32))
        let initial = try Row(id: d(9), revision: d(10), purpose: .retainedPolicy, scope: scope)
        _ = try f.machine().writeRuntimeMaintenanceWindow(initial, replacing: nil, expected: snapshot, candidate: f.candidate,
            directory: f.directory, admission: f.admission)
        let current = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
        let account = try XCTUnwrap(current.admission.accounts.first { $0.accountID == f.authority.accountID })
        let anchor = URL(fileURLWithPath: f.databasePath).deletingLastPathComponent().deletingLastPathComponent().path
        let barrier = try UpdateAdmissionBarrier(directory: .init(anchor: anchor, relativeDirectory: "machine", owner: getuid()),
            owner: getuid(), expected: account.identity, scope: .account(account.accountID))
        let drain = try barrier.beginDrain()
        do {
            let row = try Row(id: initial.id, revision: d(11), purpose: initial.purpose, scope: scope, phase: .draining)
            _ = try f.machine().writeRuntimeMaintenanceWindow(row, replacing: initial, expected: current, candidate: f.candidate,
                directory: f.directory, admission: f.admission, accountDrain: drain)
            return (row, drain)
        } catch { drain.close(); throw error }
    }
    private func target(_ row: Row) throws -> AuthorityMaintenanceBinding {
        try .init(accountID: row.scope.authority.accountID, attemptID: row.id, revision: row.revision, incarnation: d(12), connectionID: d(13))
    }
    private func persist(_ row: Row, _ drain: UpdateDrainToken, _ f: RuntimeMaintenanceWriterFixture,
        verify: (PreparationIntentStore.CompletionIntentStorageStage) throws -> Void = { _ in }) throws -> Row {
        try f.machine().persistRuntimeMaintenanceBinding(target(row), window: row,
            expected: f.machine().stableMachineUpdateSnapshot(candidate: f.candidate), candidate: f.candidate,
            directory: f.directory, admission: f.admission, accountDrain: drain, verifyScoped: verify)
    }
    func testBindingCommitsANewRevisionAndReadsBackTheExactTargetAfterReopening() throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let (row, drain) = try draining(f); defer { drain.close() }
            let other = try runtimeMaintenanceFixtureRows(f.databasePath, omitMaintenance: true)
            let saved = try persist(row, drain, f)
            XCTAssertNotEqual(saved.revision, row.revision); XCTAssertEqual(saved.shutdownBinding, try target(row))
            XCTAssertEqual(saved.formatVersion, 2); XCTAssertEqual(saved.scope, row.scope)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath, omitMaintenance: true), other)
            try f.reopen(nil)
            let snapshot = try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)
            XCTAssertEqual(snapshot.schemaVersion, 29)
            let gate = try XCTUnwrap(snapshot.admission.accounts.first { $0.accountID == f.authority.accountID }).identity
            for action in [AuthorityMaintenanceChannelRequest.Action.observe, .arm, .cancel] {
                let q = try AuthorityMaintenanceChannelRequest(action: action, accountID: f.authority.accountID, attemptID: row.id,
                    revision: row.revision, installationID: row.scope.installationID, gate: gate, binding: target(row), challenge: d(14, 32))
                XCTAssertEqual(try f.machine().runtimeMaintenanceCommandRecord(q, account: f.authority,
                    incarnation: d(12), candidate: f.candidate), saved)
            }
        }
    }
    func testFailureBeforeBindingCommitRollsBackEveryRowAndLeavesTheOriginalRevision() throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let (row, drain) = try draining(f); defer { drain.close() }
            let before = try runtimeMaintenanceFixtureRows(f.databasePath)
            XCTAssertThrowsError(try persist(row, drain, f, verify: { if $0 == .afterMutation { throw Fault.injected } }))
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), before)
            XCTAssertEqual(f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate).revision, row.revision)
        }
    }
    func testFailureAfterBindingCommitRetiresTheWriterAndDoesNotReplayTheCommit() throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let (row, drain) = try draining(f); defer { drain.close() }; var commits = 0
            XCTAssertThrowsError(try persist(row, drain, f, verify: { if $0 == .afterCommit { commits += 1; throw Fault.injected } }))
            XCTAssertEqual(commits, 1)
            XCTAssertThrowsError(try f.machine().stableMachineUpdateSnapshot(candidate: f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .unavailable)
            }
            try f.reopen(nil)
            let actual = f.machine().runtimeMaintenanceStartupProjection(account: f.authority, candidate: f.candidate)
            XCTAssertNotEqual(actual.revision, row.revision); XCTAssertTrue(actual.requiresLocalHold)
            let before = try runtimeMaintenanceFixtureRows(f.databasePath)
            XCTAssertThrowsError(try persist(row, drain, f)); XCTAssertEqual(commits, 1)
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), before)
        }
    }
    func testAClosedDrainCannotWriteTheBindingAndLeavesAllRowsExact() throws {
        try MachineUpdateReplacementTests.withMaintenanceWriterFixture { f in
            let (row, drain) = try draining(f); drain.close()
            let before = try runtimeMaintenanceFixtureRows(f.databasePath)
            XCTAssertThrowsError(try persist(row, drain, f))
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), before)
        }
    }
}
