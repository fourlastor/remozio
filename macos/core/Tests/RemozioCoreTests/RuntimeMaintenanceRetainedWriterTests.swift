import Foundation
import XCTest
@testable import RemozioCore

/// Owns real schema 29 SQLite files. Synthetic custody proves no installed window execution or service operation.
final class RuntimeMaintenanceRetainedWriterTests: XCTestCase {
    private typealias Policy = MachineUpdateRetainedSetupPolicyIntentRecord
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private enum Fault: Error { case injected }
    private func snapshot(_ f: RetainedPolicyWriterFixture) throws -> Snapshot {
        try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
    }
    private func policyRows(_ f: RetainedPolicyWriterFixture) throws -> [String: [Data]] {
        try runtimeMaintenanceFixtureRows(f.databasePath,
            excludingRowsForAccounts: [MachineUpdateRetainedSetupPolicyStorage.tableName: f.source.runtime.preparation.accountID])
    }
    private func materialRows(_ path: String, account: Data) throws -> [String: [Data]] {
        try runtimeMaintenanceFixtureRows(path, excludingRowsForAccounts: ["runtime_preparation_v1": account])
    }
    private func withoutSetupStorageWriter(_ candidate: SignedReleaseEvidence) throws -> SignedReleaseEvidence {
        let components = try candidate.manifest.components.map { component in
            let formats = try component.formats.map { format in
                guard component.role == .setupController, format.name == "authority.installation-preparation" else { return format }
                return try ReleaseFormat(name: format.name, readers: format.readers, writers: format.writers.subtracting([29]),
                    migrations: format.migrations.filter { $0.value != 29 })
            }
            return try ReleaseComponent(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                teamID: component.teamID, formats: formats, requests: component.requests)
        }
        return try .init(manifest: .init(release: candidate.manifest.release, build: candidate.manifest.build,
            components: components, dependencies: candidate.manifest.dependencies), codeDirectoryHashes: candidate.codeDirectoryHashes,
            dependencyCodeDirectoryHashes: candidate.dependencyCodeDirectoryHashes)
    }
    func testPolicyRetentionAndPhaseCASOn29PreserveTheWindowAndAllOtherRows() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(schema29: true) { f in
            let before = try snapshot(f), rows = try policyRows(f), prepared = try Policy(source: f.source)
            XCTAssertEqual(before.activation.runtime.setup.source.actual.schemaVersion, 29)
            XCTAssertEqual(try f.scalar("SELECT COUNT(*) FROM runtime_maintenance_windows_v1"), 1)
            let retained = try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: before, candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: { _, _ in try f.verifyPair() })
            XCTAssertEqual(retained, prepared)
            let retainedFrame = try snapshot(f), writing = try prepared.preparingWrite(expected: f.source)
            let receipt = try f.machine().beginRetainedSetupPolicyWrite(writing, source: f.source, expected: retainedFrame,
                candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in try f.verifyPair() })
            XCTAssertTrue(receipt.changed); XCTAssertEqual(receipt.current, writing)
            XCTAssertThrowsError(try f.machine().beginRetainedSetupPolicyWrite(writing, source: f.source, expected: retainedFrame,
                candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try f.reopen(nil)
            XCTAssertEqual(try snapshot(f).intent, writing); XCTAssertEqual(try f.scalar("PRAGMA user_version"), 29)
            XCTAssertEqual(try policyRows(f), rows); try f.verifyPair()
        }
    }
    func testPolicy29RequiresTheSetupWriterBeforeAnyCallback() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(schema29: true, setupWriter29: false) { f in
            let before = try snapshot(f), rows = try runtimeMaintenanceFixtureRows(f.databasePath)
            var called = false
            XCTAssertThrowsError(try f.machine().retainRetainedSetupPolicyIntent(Policy(source: f.source), expected: before,
                candidate: f.candidate, directory: f.directory, admission: f.admission,
                verifyScoped: { _, _ in called = true })) { XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore) }
            XCTAssertFalse(called); XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
        }
    }
    func testPolicy29RollsBackBeforeCommitAndRetiresAfterCommitUncertainty() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(schema29: true) { f in
            let before = try snapshot(f), rows = try runtimeMaintenanceFixtureRows(f.databasePath), prepared = try Policy(source: f.source)
            XCTAssertThrowsError(try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: before, candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: { stage, _ in
                    if stage == .afterMutation { throw Fault.injected }
                }))
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
            try f.reopen { throw Fault.injected }
            XCTAssertThrowsError(try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: before, candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: { _, _ in }))
            XCTAssertThrowsError(try snapshot(f)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            try f.reopen(nil); XCTAssertEqual(try snapshot(f).intent, prepared)
            XCTAssertEqual(try f.scalar("PRAGMA user_version"), 29)
        }
    }
    func testMaterial29RetainsOnlyItsReferenceAndKeepsTheWindowExact() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(schema29: true) { f in
            let before = try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)
            let rows = try materialRows(f.databasePath, account: before.runtime.preparation.accountID)
            XCTAssertEqual(before.runtime.setup.source.actual.schemaVersion, 29)
            var commits = 0; try f.reopen { commits += 1 }
            let actual = try f.machine().retainRetainedSetupRuntimeMaterial(f.material.reference, expected: before,
                candidate: f.candidate, directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                verifyScoped: { _, _ in })
            XCTAssertEqual(actual.reference, try f.material.reference); XCTAssertFalse(actual.configurationPublished)
            let retained = try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)
            _ = try f.machine().retainRetainedSetupRuntimeMaterial(f.material.reference, expected: retained,
                candidate: f.candidate, directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                verifyScoped: { _, _ in })
            XCTAssertEqual(commits, 1); try f.reopen(nil)
            XCTAssertEqual(try materialRows(f.databasePath, account: before.runtime.preparation.accountID), rows)
            XCTAssertEqual(try f.scalar("PRAGMA user_version"), 29)
        }
    }
    func testMaterial29RequiresTheSetupWriterBeforeAnyCallback() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(schema29: true, setupWriter29: false) { f in
            let before = try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)
            let rows = try runtimeMaintenanceFixtureRows(f.databasePath); var called = false
            XCTAssertThrowsError(try f.machine().retainRetainedSetupRuntimeMaterial(f.material.reference, expected: before,
                candidate: f.candidate, directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                verifyScoped: { _, _ in called = true })) { XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore) }
            XCTAssertFalse(called); XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
        }
    }
    func testMaterial29PostCommitFailureRetiresWithoutReplaying() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture(schema29: true) { f in
            let before = try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate)
            let rows = try materialRows(f.databasePath, account: before.runtime.preparation.accountID)
            var commits = 0; try f.reopen { commits += 1 }
            XCTAssertThrowsError(try f.machine().retainRetainedSetupRuntimeMaterial(f.material.reference, expected: before,
                candidate: f.candidate, directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                verifyScoped: { stage, _ in if stage == .afterCommit { throw Fault.injected } }))
            XCTAssertThrowsError(try f.machine().retainRetainedSetupRuntimeMaterial(f.material.reference, expected: before,
                candidate: f.candidate, directory: f.directory, admission: f.admission, fileCustodyAccepted: true,
                verifyScoped: { _, _ in })) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            XCTAssertEqual(commits, 1); try f.reopen(nil)
            XCTAssertEqual(try f.machine().retainedSetupMaterialSnapshot(owner: f.owner, candidate: f.candidate).runtime.state.reference,
                try f.material.reference)
            XCTAssertEqual(try materialRows(f.databasePath, account: before.runtime.preparation.accountID), rows)
        }
    }
    private func withRecorded29(_ body: (RetainedPolicyWriterFixture, Snapshot) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture(schema29: true) { f in
            let recorded = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: snapshot(f), candidate: f.candidate,
                directory: f.directory, admission: f.admission, useMachine: { body in
                    try f.reopen(nil); let machine = f.machine(); defer { try? machine.close() }; return try body(machine)
                }, openJournal: { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) }, verifySnapshot: { _ in })
            try f.reopen(nil); defer { try? f.machine().close() }
            try body(f, recorded)
        }
    }
    private func publish(_ f: RetainedPolicyWriterFixture, before: Snapshot, candidate: SignedReleaseEvidence? = nil,
        failAfterCommit: Bool = false) throws -> Snapshot {
        let record = try XCTUnwrap(before.intent), reference = try XCTUnwrap(before.activation.runtime.state.reference)
        return try f.machine().completeRetainedSetupRuntimePublication(reference, expected: before.activation.runtime,
            policy: record, candidate: candidate ?? f.candidate, directory: f.directory, admission: f.admission,
            fileCustodyAccepted: true, verifyScoped: { stage, _ in
                let pair = try f.openPolicyJournal(.readOnly); defer { try? pair.close() }
                try record.requireRecorded(pair.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(f.source.runtime.setup.account?.initialization)))
                if failAfterCommit && stage == .afterCommit { throw Fault.injected }
            })
    }
    func testPublication29ChangesOnlyItsFlagAndRetainsTheRecordedPolicyAndWindow() throws {
        try withRecorded29 { f, before in
            let rows = try materialRows(f.databasePath, account: before.activation.runtime.preparation.accountID)
            XCTAssertEqual(before.activation.runtime.setup.source.actual.schemaVersion, 29)
            let actual = try publish(f, before: before)
            XCTAssertTrue(actual.activation.runtime.state.configurationPublished); XCTAssertEqual(actual.intent, before.intent)
            try actual.requirePublication(from: before, reference: XCTUnwrap(before.activation.runtime.state.reference))
            try f.reopen(nil)
            XCTAssertTrue(try snapshot(f).activation.runtime.state.configurationPublished)
            XCTAssertEqual(try materialRows(f.databasePath, account: before.activation.runtime.preparation.accountID), rows)
            XCTAssertEqual(try f.scalar("PRAGMA user_version"), 29)
        }
    }
    func testPublication29RejectsAMissingSetupWriterBeforeMutation() throws {
        try withRecorded29 { f, before in
            let rows = try runtimeMaintenanceFixtureRows(f.databasePath)
            XCTAssertThrowsError(try publish(f, before: before, candidate: withoutSetupStorageWriter(f.candidate))) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            XCTAssertEqual(try runtimeMaintenanceFixtureRows(f.databasePath), rows)
        }
    }
    func testPublication29CommitUncertaintyRetiresWithoutReplaying() throws {
        try withRecorded29 { f, before in
            let rows = try materialRows(f.databasePath, account: before.activation.runtime.preparation.accountID)
            var commits = 0; try f.reopen { commits += 1 }
            XCTAssertThrowsError(try publish(f, before: before, failAfterCommit: true))
            XCTAssertThrowsError(try publish(f, before: before)) { XCTAssertEqual($0 as? PreparationStoreError, .unavailable) }
            XCTAssertEqual(commits, 1); try f.reopen(nil)
            XCTAssertTrue(try snapshot(f).activation.runtime.state.configurationPublished)
            XCTAssertEqual(try materialRows(f.databasePath, account: before.activation.runtime.preparation.accountID), rows)
        }
    }
}
