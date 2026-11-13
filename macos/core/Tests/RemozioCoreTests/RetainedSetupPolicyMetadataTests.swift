import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Metadata comparison controls grant no SQL migration, journal permit or native authority.
final class RetainedSetupPolicyMetadataTests: XCTestCase {
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Record = MachineUpdateRetainedSetupPolicyIntentRecord
    private typealias Storage = MachineUpdateRetainedSetupPolicyStorage
    private typealias Fixture = RetainedPolicyProposalFixture
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedPolicyProposalFixture(body)
    }
    private func value(_ before: Snapshot, schema: Int64, intent: Record?, candidate: SignedReleaseEvidence,
        numbers: Set<UInt32>? = nil, rows: Data? = nil) throws -> Snapshot {
        let old = before.activation.runtime, original = old.setup.source, actual = original.actual
        let frame = MachineUpdateStableReleaseSnapshot(schemaVersion: schema, inventory: actual.inventory,
            activation: actual.activation, admission: actual.admission, candidate: actual.candidate,
            installed: actual.installed, seal: actual.seal, currentRowsDigest: rows ?? actual.currentRowsDigest)
        let source = try MachineUpdateStableRuntimeSource(actual: frame, preparations: original.preparations,
            initializations: original.initializations, candidate: candidate)
        let setup = try MachineUpdateStableAccountSetupSnapshot(source: source, owner: old.setup.owner)
        let runtime = try MachineUpdateStableRuntimePreparationSnapshot(setup: setup,
            services: .init(plan: old.plan, complete: true), state: old.state, reservedNumbers: numbers ?? old.reservedNumbers)
        let activation = try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(
            runtime: runtime, state: before.activation.state, candidate: candidate)
        return try .init(activation: activation, intent: intent, candidate: candidate)
    }
    private func release(_ original: SignedReleaseEvidence, migration: Bool = true,
        missingWriter: AuthorityCodeRole? = nil, legacyPolicy: Bool = false) throws -> SignedReleaseEvidence {
        let components = try original.manifest.components.map { component in
            var formats = component.formats
            for requirement in try Storage.requirements where requirement.role == component.role {
                let index = formats.firstIndex { $0.name == requirement.name }
                let previous = index.map { formats[$0] }
                let readers = (previous?.readers ?? []).union(requirement.readVersions)
                var migrations = previous?.migrations ?? [:]
                if requirement.name == "authority.installation-preparation" {
                    if migration { migrations[24] = 25 } else { migrations.removeValue(forKey: 24) }
                }
                let writerVersions: Set<UInt64> = missingWriter == component.role ? [] : requirement.writeVersions
                let policyFormat = requirement.name == Record.formatName
                let format = try ReleaseFormat(name: requirement.name,
                    readers: legacyPolicy && policyFormat ? [1] : readers,
                    writers: legacyPolicy && policyFormat ? [1] : (previous?.writers ?? []).union(writerVersions),
                    migrations: migrations)
                if let index { formats[index] = format } else { formats.append(format) }
            }
            return try ReleaseComponent(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                build: component.build, teamID: component.teamID, formats: formats, requests: component.requests)
        }
        return try .init(manifest: .init(release: original.manifest.release, build: original.manifest.build,
            components: components, dependencies: original.manifest.dependencies), codeDirectoryHashes: original.codeDirectoryHashes,
            dependencyCodeDirectoryHashes: original.dependencyCodeDirectoryHashes)
    }

    func testRetentionComparisonAcceptsOnlyTheModeledPreparedRowAnd24To25Step() throws {
        try fixture { f in
            let before = try f.snapshot(), prepared = try Record(source: f.source)
            XCTAssertEqual(before.activation.runtime.setup.source.actual.schemaVersion, 24); XCTAssertNil(before.intent)
            // These are comparison values. No migration or row insert is executed.
            let after = try value(before, schema: 25, intent: prepared, candidate: f.candidate,
                rows: Data(repeating: 241, count: 32))
            try after.requireRetention(prepared, from: before)
            XCTAssertThrowsError(try after.requireSame(as: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try f.snapshot().requireSame(as: before); try f.verifyMachine()
        }
    }

    func testRetentionComparisonAllowsAnExisting25CatalogWithoutAnotherMigration() throws {
        try fixture { f in
            let actual = try f.snapshot(), prepared = try Record(source: f.source)
            let before = try value(actual, schema: 25, intent: nil, candidate: f.candidate)
            let after = try value(actual, schema: 25, intent: prepared, candidate: f.candidate)
            try after.requireRetention(prepared, from: before)
            XCTAssertThrowsError(try after.requireRetention(prepared, from: after)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try f.verifyMachine()
        }
    }

    func testRetentionComparisonRejectsSkippedReverseAndUnsupportedSchemaSteps() throws {
        try fixture { f in
            let actual = try f.snapshot(), prepared = try Record(source: f.source)
            for schema: Int64 in [24, 26, 29] {
                let after = try value(actual, schema: schema, intent: prepared, candidate: f.candidate)
                XCTAssertThrowsError(try after.requireRetention(prepared, from: actual)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }
            try f.verifyMachine()
        }
    }

    func testTransitionComparisonPinsTheSchemaAndEveryRuntimeOperand() throws {
        try fixture { f in
            let actual = try f.snapshot(), prepared = try Record(source: f.source)
            let writing = try prepared.preparingWrite(expected: f.source)
            let before = try value(actual, schema: 25, intent: prepared, candidate: f.candidate)
            let after = try value(actual, schema: 25, intent: writing, candidate: f.candidate)
            try after.requireTransition(writing, from: before)
            let migrated = try value(actual, schema: 26, intent: writing, candidate: f.candidate)
            XCTAssertThrowsError(try migrated.requireTransition(writing, from: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            var numbers = actual.activation.runtime.reservedNumbers
            var extra: UInt32 = 49999; while numbers.contains(extra) { extra += 1 }; numbers.insert(extra)
            let changed = try value(actual, schema: 25, intent: writing, candidate: f.candidate, numbers: numbers)
            XCTAssertThrowsError(try changed.requireTransition(writing, from: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }
            try f.verifyMachine()
        }
    }

    func testTransitionComparisonUsesP01PhaseAndFreshRevisionChecks() throws {
        try fixture { f in
            let actual = try f.snapshot(), prepared = try Record(source: f.source)
            let before = try value(actual, schema: 25, intent: prepared, candidate: f.candidate)
            XCTAssertThrowsError(try before.requireTransition(prepared, from: before)) {
                XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition)
            }
            try f.verifyMachine()
        }
    }

    func testReaderDeclarationsAloneCannotAuthorizeTheFutureWriterContract() throws {
        try fixture { f in
            XCTAssertNoThrow(try Storage.requireReaderFormats(f.candidate))
            XCTAssertThrowsError(try Storage.requireFormats(f.candidate)) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            let declared = try release(f.candidate)
            try Storage.requireFormats(declared); try Storage.requireSchema(24, candidate: declared)
            try Storage.requireSchema(25, candidate: declared)
            try f.verifyMachine()
        }
    }

    func testMigrationContractRequiresTheExact24To25Mapping() throws {
        try fixture { f in
            let missing = try release(f.candidate, migration: false)
            try Storage.requireFormats(missing); try Storage.requireSchema(25, candidate: missing)
            XCTAssertThrowsError(try Storage.requireMigrationFormats(missing)) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            XCTAssertThrowsError(try Storage.requireSchema(24, candidate: missing)) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            try f.verifyMachine()
        }
    }

    func testBothRolesMustDeclareTheWriterAndLegacyPolicyV1IsRefused() throws {
        try fixture { f in
            for role in [AuthorityCodeRole.authority, .setupController] {
                let missing = try release(f.candidate, migration: false, missingWriter: role)
                XCTAssertThrowsError(try Storage.requireFormats(missing)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                }
            }
            XCTAssertThrowsError(try Storage.requireFormats(release(f.candidate, legacyPolicy: true))) {
                XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
            }
            try f.verifyMachine()
        }
    }

    func testFutureWriterSchemaGuardRejectsVersionsOutsideTheReviewedRange() throws {
        try fixture { f in
            let declared = try release(f.candidate)
            for version: Int64 in [23, 29] {
                XCTAssertThrowsError(try Storage.requireSchema(version, candidate: declared)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .incompatibleStore)
                }
            }
            try f.verifyMachine()
        }
    }
}
