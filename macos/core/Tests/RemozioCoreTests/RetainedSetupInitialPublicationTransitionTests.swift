import Foundation
import XCTest
@testable import RemozioCore

/// Owned value images test the comparison. They grant no publication, SQL write, native custody or registration authority.
final class RetainedSetupInitialPublicationTransitionTests: XCTestCase {
    private typealias Snapshot = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Record = MachineUpdateRetainedSetupPolicyIntentRecord
    private func fixture(_ body: (Snapshot, SignedReleaseEvidence) throws -> Void) throws {
        try MachineUpdateReplacementTests.withRetainedInitialConfigurationValueFixture { snapshot, _, candidate, _, unchanged in
            try body(snapshot, candidate); try unchanged()
        }
    }
    private func image(_ before: Snapshot, candidate: SignedReleaseEvidence, published: Bool, intent: Record?,
        reserved: Set<UInt32>? = nil, schema: Int64? = nil, rowsDigest: Data? = nil) throws -> Snapshot {
        let runtime = before.activation.runtime, old = runtime.setup.source, actual = old.actual
        let frame = MachineUpdateStableReleaseSnapshot(schemaVersion: schema ?? actual.schemaVersion,
            inventory: actual.inventory, activation: actual.activation, admission: actual.admission,
            candidate: actual.candidate, installed: actual.installed, seal: actual.seal,
            currentRowsDigest: rowsDigest ?? actual.currentRowsDigest)
        let source = try MachineUpdateStableRuntimeSource(actual: frame, preparations: old.preparations,
            initializations: old.initializations, candidate: candidate)
        let setup = try MachineUpdateStableAccountSetupSnapshot(source: source, owner: runtime.setup.owner)
        let next = try MachineUpdateStableRuntimePreparationSnapshot(setup: setup,
            services: .init(plan: runtime.plan, complete: true),
            state: .init(reference: runtime.state.reference, configurationPublished: published),
            reservedNumbers: reserved ?? runtime.reservedNumbers)
        let activation = try MachineUpdateStableRuntimeActivationSnapshot.retainedSetupPolicyMaterial(runtime: next,
            state: before.activation.state, candidate: candidate)
        return try Snapshot(activation: activation, intent: intent, candidate: candidate)
    }
    private func record(_ original: Record, changing: (inout [String: Any]) -> Void) throws -> Record {
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: original.encoded) as? [String: Any])
        changing(&fields)
        return try .decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
    }

    func testExactRecordedTransitionAcceptsOnlyPublicationAndAChangedRowsDigest() throws {
        try fixture { before, candidate in
            let reference = try XCTUnwrap(before.activation.runtime.state.reference)
            var digest = before.activation.runtime.setup.source.actual.currentRowsDigest; digest[digest.startIndex] ^= 1
            let after = try image(before, candidate: candidate, published: true, intent: before.intent, rowsDigest: digest)
            XCTAssertNoThrow(try after.requirePublication(from: before, reference: reference))
            XCTAssertEqual(after.intent, before.intent); XCTAssertEqual(after.activation.runtime.state.reference, reference)
            XCTAssertNil(after.activation.state.plan); XCTAssertFalse(after.activation.state.jobsRegistered)
            XCTAssertFalse(before.activation.runtime.state.configurationPublished)
        }
    }

    func testMissingPreparedAndWritingMarkersCannotAuthorizePublication() throws {
        try fixture { before, candidate in
            let original = try XCTUnwrap(before.intent), reference = try XCTUnwrap(before.activation.runtime.state.reference)
            var markers: [Record?] = [nil]
            for phase in [Record.Phase.prepared, .writing] {
                markers.append(try record(original) { fields in
                    fields["phase"] = phase.rawValue; fields["committedPolicy"] = nil; fields["committedCheckpoint"] = nil
                })
            }
            for marker in markers {
                let initial = try image(before, candidate: candidate, published: false, intent: marker)
                let proposed = try image(initial, candidate: candidate, published: true, intent: marker)
                XCTAssertThrowsError(try proposed.requirePublication(from: initial, reference: reference)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }

        }
    }

    func testAnotherValidMarkerIdentityOrRevisionCannotReplaceTheRecordedRow() throws {
        try fixture { before, candidate in
            let original = try XCTUnwrap(before.intent), reference = try XCTUnwrap(before.activation.runtime.state.reference)
            for field in ["id", "revision"] {
                let changed = try record(original) { $0[field] = UUID().uuidString }
                let after = try image(before, candidate: candidate, published: true, intent: changed)
                XCTAssertNotEqual(after.intent, before.intent)
                XCTAssertThrowsError(try after.requirePublication(from: before, reference: reference)) {
                    XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
                }
            }

        }
    }

    func testPublicationRequiresUnpublishedBeforeAndPublishedAfter() throws {
        try fixture { before, candidate in
            let reference = try XCTUnwrap(before.activation.runtime.state.reference)
            let published = try image(before, candidate: candidate, published: true, intent: before.intent)
            XCTAssertThrowsError(try before.requirePublication(from: before, reference: reference))
            XCTAssertThrowsError(try published.requirePublication(from: published, reference: reference))
            XCTAssertThrowsError(try before.requirePublication(from: published, reference: reference))
            XCTAssertNoThrow(try published.requireSame(as: published))
        }
    }

    func testAnotherValidAccountsRequestedMaterialReferenceIsRefused() throws {
        try fixture { before, candidate in
            let after = try image(before, candidate: candidate, published: true, intent: before.intent)
            try fixture { other, _ in
                let foreign = try XCTUnwrap(other.activation.runtime.state.reference)
                XCTAssertNotEqual(foreign.services.accountID, before.activation.runtime.preparation.accountID)
                XCTAssertThrowsError(try after.requirePublication(from: before, reference: foreign))

            }

        }
    }

    func testAnAdditionalValidReservationCannotHideInsideThePublicationFrame() throws {
        try fixture { before, candidate in
            var extra: UInt32 = 29999
            while before.activation.runtime.reservedNumbers.contains(extra) { extra += 1 }
            let after = try image(before, candidate: candidate, published: true, intent: before.intent,
                reserved: before.activation.runtime.reservedNumbers.union([extra]))
            XCTAssertThrowsError(try after.requirePublication(from: before, reference: XCTUnwrap(before.activation.runtime.state.reference))) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }

        }
    }

    func testSchemaMigrationIsNotAPublicationTransition() throws {
        try fixture { before, candidate in
            let reference = try XCTUnwrap(before.activation.runtime.state.reference)
            let changedSchema = before.activation.runtime.setup.source.actual.schemaVersion + 1
            let after = try image(before, candidate: candidate, published: true, intent: before.intent, schema: changedSchema)
            XCTAssertThrowsError(try after.requirePublication(from: before, reference: reference)) {
                XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
            }

        }
    }

    func testPublicationComparisonDoesNotGrantPolicyRetentionOrTransitionAuthority() throws {
        try fixture { before, candidate in
            let reference = try XCTUnwrap(before.activation.runtime.state.reference), marker = try XCTUnwrap(before.intent)
            let after = try image(before, candidate: candidate, published: true, intent: marker)
            XCTAssertNoThrow(try after.requirePublication(from: before, reference: reference))
            XCTAssertThrowsError(try after.requireRetention(marker, from: before))
            XCTAssertThrowsError(try after.requireTransition(marker, from: before))
            XCTAssertThrowsError(try after.requireSame(as: before))
        }
    }

    func testPublishedValueIsRefusedByEveryExistingPolicyWriterBeforeCallbacks() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture { f in
            let before = try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
            let recorded = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: before, candidate: f.candidate,
                directory: f.directory, admission: f.admission, useMachine: { body in
                    try f.reopen(nil); let machine = f.machine(); defer { try? machine.close() }; return try body(machine)
                }, openJournal: { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) }, verifySnapshot: { _ in })
            let journal = try f.openPolicyJournal(.readOnly)
            let boundary = try journal.captureRetainedSetupPolicyBoundary(expected: XCTUnwrap(f.source.runtime.setup.account?.initialization))
            try journal.close()
            let after = try image(recorded, candidate: f.candidate, published: true, intent: recorded.intent)
            try after.requirePublication(from: recorded, reference: XCTUnwrap(recorded.activation.runtime.state.reference))
            let prepared = try Record(source: f.source), writing = try prepared.preparingWrite(expected: f.source)
            var callbacks = 0
            let verify: (PreparationIntentStore.CompletionIntentStorageStage, Snapshot) throws -> Void = { _, _ in callbacks += 1 }
            func refuses<T>(_ body: () throws -> T) {
                XCTAssertThrowsError(try body()) { XCTAssertEqual($0 as? PreparationStoreError, .invalidTransition) }
            }
            try f.reopen(nil); defer { try? f.machine().close() }
            refuses { try f.machine().retainRetainedSetupPolicyIntent(prepared, expected: after, candidate: f.candidate,
                directory: f.directory, admission: f.admission, verifyScoped: verify) }
            refuses { try f.machine().beginRetainedSetupPolicyWrite(writing, source: f.source, expected: after,
                candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: verify) }
            refuses { try f.machine().recordRetainedSetupPolicyWrite(XCTUnwrap(recorded.intent), boundary: boundary,
                expected: after, candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: verify) }
            XCTAssertEqual(callbacks, 0)
            try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate).requireSame(as: recorded)
        }
    }
}
