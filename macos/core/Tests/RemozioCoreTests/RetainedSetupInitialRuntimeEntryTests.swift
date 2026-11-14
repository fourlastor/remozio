import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Owned stores and value images prove read and comparison boundaries. They prove no native file custody or acknowledgement writer.
final class RetainedSetupInitialRuntimeEntryTests: XCTestCase {
    private typealias Entry = MachineUpdateRetainedSetupInitialRuntimeEntry
    private typealias Runtime = MachineUpdateStableRuntimePreparationSnapshot
    private typealias Policy = MachineUpdateRetainedSetupPolicySnapshot
    private typealias Record = MachineUpdateRetainedSetupPolicyIntentRecord
    private typealias Inputs = MachineUpdateRetainedSetupRuntimeInputs
    private typealias Read = PreparationIntentStore.InitialRuntimeRead
    private typealias Fixture = RetainedPolicyWriterFixture
    private enum Fault: Error { case unexpected }
    private func entry(_ policy: Policy, candidate: SignedReleaseEvidence) throws -> Entry {
        try .init(runtime: policy.activation.runtime, activation: policy.activation.state, intent: policy.intent, candidate: candidate)
    }
    private func capture(_ machine: PreparationIntentStore, owner: LocalAccountIdentity,
        candidate: SignedReleaseEvidence, schema: Int64) throws -> Entry {
        var counts: [Read: Int] = [:]
        machine.observeInitialRuntimeRead = { counts[$0, default: 0] += 1 }
        defer { machine.observeInitialRuntimeRead = nil }
        let result = try machine.retainedSetupInitialRuntimeEntry(owner: owner, candidate: candidate)
        var expected: [Read: Int] = [.readTransaction: 1, .runtime: 2, .frame: 6, .activation: 2, .sharedImport: 6]
        if schema >= 25 { expected[.policyMarker] = 1; expected[.policyScan] = 7 }
        XCTAssertEqual(counts, expected)
        counts.removeAll()
        try result.requireSame(as: result)
        XCTAssertTrue(counts.isEmpty)
        XCTAssertEqual(result.description, "MachineUpdateRetainedSetupInitialRuntimeEntry(redacted)")
        XCTAssertEqual(result.debugDescription, result.description)
        return result
    }
    private func image(_ before: Entry, candidate: SignedReleaseEvidence, reference: RuntimeMaterialReference?,
        published: Bool = false, intent: Record? = nil, reserved: Set<UInt32>? = nil,
        schema: Int64? = nil, digest: Data? = nil) throws -> Entry {
        let runtime = before.runtime, old = runtime.setup.source, actual = old.actual
        let frame = MachineUpdateStableReleaseSnapshot(schemaVersion: schema ?? actual.schemaVersion,
            inventory: actual.inventory, activation: actual.activation, admission: actual.admission,
            candidate: actual.candidate, installed: actual.installed, seal: actual.seal,
            currentRowsDigest: digest ?? actual.currentRowsDigest)
        let source = try MachineUpdateStableRuntimeSource(actual: frame, preparations: old.preparations,
            initializations: old.initializations, candidate: candidate)
        let setup = try MachineUpdateStableAccountSetupSnapshot(source: source, owner: runtime.setup.owner)
        let next = try Runtime(setup: setup, services: .init(plan: runtime.plan, complete: true),
            state: .init(reference: reference, configurationPublished: published), reservedNumbers: reserved ?? runtime.reservedNumbers)
        return try .init(runtime: next, activation: before.activation, intent: intent, candidate: candidate)
    }
    private func changed(_ record: Record, _ edit: (inout [String: Any]) -> Void) throws -> Record {
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: record.encoded) as? [String: Any])
        edit(&fields)
        return try .decode(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]))
    }
    private func recorded(_ f: Fixture) throws -> Policy {
        let before = try f.machine().retainedSetupPolicySnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
        let result = try MachineUpdateRetainedSetupPolicyOwner.resume(expected: before, candidate: f.candidate,
            directory: f.directory, admission: f.admission, useMachine: { body in
                try f.reopen(nil); let machine = f.machine(); defer { try? machine.close() }; return try body(machine)
            }, openJournal: { try f.openPolicyJournal($0 == .readOnly ? .readOnly : .startup) }, verifySnapshot: { _ in })
        try f.reopen(nil); return result
    }

    func testMissingReferenceIsAnActualMaterialEntryWithOneReadTransaction() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            var commits = 0; try f.reopen { commits += 1 }
            let machine = try f.machine(), schema = try f.scalar("PRAGMA user_version")
            let before = try capture(machine, owner: f.owner, candidate: f.candidate, schema: schema)
            XCTAssertNil(before.runtime.state.reference); XCTAssertNil(before.policy); XCTAssertNil(before.intent)
            XCTAssertNil(before.activation.plan); XCTAssertFalse(before.activation.jobsRegistered)
            XCTAssertEqual(commits, 0)
            let wrongOwner = LocalAccountIdentity(uid: f.owner.uid, primaryGroupID: f.owner.primaryGroupID, directoryID: UUID())
            XCTAssertThrowsError(try machine.retainedSetupInitialRuntimeEntry(owner: wrongOwner, candidate: f.candidate))
            var attempts = 0
            machine.observeInitialRuntimeRead = { event in
                if event == .readTransaction {
                    attempts += 1
                    do {
                        _ = try machine.stableRuntimePreparationSnapshot(owner: f.owner, candidate: f.candidate)
                        XCTFail("Nested public read succeeded")
                    } catch { XCTAssertEqual(error as? PreparationStoreError, .transactionActive) }
                }
            }
            defer { machine.observeInitialRuntimeRead = nil }
            try machine.retainedSetupInitialRuntimeEntry(owner: f.owner, candidate: f.candidate).requireSame(as: before)
            XCTAssertEqual(attempts, 1); XCTAssertEqual(commits, 0)
        }
    }
    func testActualMaterialRetentionMovesToThePolicyVariantWithoutQueriesInComparisons() throws {
        try MachineUpdateReplacementTests.withRetainedMaterialWriterFixture { f in
            let machine = try f.machine(), schema = try f.scalar("PRAGMA user_version")
            let before = try capture(machine, owner: f.owner, candidate: f.candidate, schema: schema)
            _ = try machine.retainRetainedSetupRuntimeMaterial(f.material.reference,
                expected: .init(runtime: before.runtime, activation: before.activation), candidate: f.candidate,
                directory: f.directory, admission: f.admission, fileCustodyAccepted: true, verifyScoped: { _, _ in })
            let after = try capture(machine, owner: f.owner, candidate: f.candidate, schema: schema)
            XCTAssertNotNil(after.policy); XCTAssertNil(after.intent)
            var reads = 0; machine.observeInitialRuntimeRead = { _ in reads += 1 }
            defer { machine.observeInitialRuntimeRead = nil }
            try after.requireMaterial(f.material.reference, from: before)
            try after.requireMaterial(f.material.reference, from: after)
            XCTAssertThrowsError(try before.requireSame(as: after))
            let now = Date()
            let foreign = try RuntimePreparationMaterial.create(services: after.runtime.plan,
                notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600)).reference
            XCTAssertThrowsError(try after.requireMaterial(foreign, from: before))
            XCTAssertEqual(reads, 0)
        }
    }
    func testPreparedAndWritingPolicyEntriesKeepTheApprovedReadBudget() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture { f in
            let machine = f.machine(), owner = f.source.runtime.setup.owner
            let before = try capture(machine, owner: owner, candidate: f.candidate, schema: 24)
            let proposed = try Record(source: f.source)
            _ = try machine.retainRetainedSetupPolicyIntent(proposed, expected: XCTUnwrap(before.policy),
                candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
            let prepared = try capture(machine, owner: owner, candidate: f.candidate, schema: 25)
            try prepared.requirePolicyRetention(proposed, from: before)
            let writing = try proposed.preparingWrite(expected: f.source)
            _ = try machine.beginRetainedSetupPolicyWrite(writing, source: f.source, expected: XCTUnwrap(prepared.policy),
                candidate: f.candidate, directory: f.directory, admission: f.admission, verifyScoped: { _, _ in })
            let after = try capture(machine, owner: owner, candidate: f.candidate, schema: 25)
            XCTAssertEqual(after.intent?.phase, .writing)
            try after.requirePolicyTransition(writing, from: prepared)
            XCTAssertThrowsError(try after.requirePolicyRetention(writing, from: before))
            XCTAssertThrowsError(try after.requirePolicyTransition(writing, from: before))
            XCTAssertThrowsError(try after.requireMaterial(f.material.reference, from: prepared))
        }
    }
    func testRecordedAndPublishedEntriesReadActualRowsWithoutAnotherCommit() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture { f in
            let recorded = try recorded(f), machine = f.machine(), owner = f.source.runtime.setup.owner
            let before = try capture(machine, owner: owner, candidate: f.candidate, schema: 25)
            try XCTUnwrap(before.policy).requireSame(as: recorded)
            _ = try machine.completeRetainedSetupRuntimePublication(f.material.reference, expected: recorded.activation.runtime,
                policy: XCTUnwrap(recorded.intent), candidate: f.candidate,
                directory: f.directory, admission: f.admission, fileCustodyAccepted: true, verifyScoped: { _, _ in })
            var commits = 0; try f.reopen { commits += 1 }
            let after = try capture(f.machine(), owner: owner, candidate: f.candidate, schema: 25)
            XCTAssertTrue(after.runtime.state.configurationPublished); XCTAssertEqual(after.intent?.phase, .recorded)
            try after.requirePublication(from: before, reference: f.material.reference)
            try capture(f.machine(), owner: owner, candidate: f.candidate, schema: 25).requireSame(as: after)
            XCTAssertEqual(commits, 0)
        }
    }
    func testEntryRejectsContradictoryMarkersPublicationAndActivation() throws {
        try MachineUpdateReplacementTests.withRetainedPolicyWriterFixture { f in
            let before = try f.machine().retainedSetupInitialRuntimeEntry(owner: f.source.runtime.setup.owner, candidate: f.candidate)
            let marker = try Record(source: f.source), reference = try f.material.reference
            XCTAssertThrowsError(try image(before, candidate: f.candidate, reference: nil, intent: marker))
            XCTAssertThrowsError(try image(before, candidate: f.candidate, reference: reference, published: true))
            XCTAssertThrowsError(try image(before, candidate: f.candidate, reference: reference, published: true, intent: marker))
            let writing = try marker.preparingWrite(expected: f.source)
            XCTAssertThrowsError(try image(before, candidate: f.candidate, reference: reference, published: true, intent: writing))
            XCTAssertThrowsError(try Entry(runtime: before.runtime, activation: .init(plan: nil, jobsRegistered: true),
                intent: nil, candidate: f.candidate))
            let ordinary = try f.machine().stableRuntimePreparationSnapshot(owner: f.source.runtime.setup.owner, candidate: f.candidate)
            XCTAssertThrowsError(try ordinary.requirePublished(from: ordinary)) {
                XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
            }
        }
    }
    func testPolicyComparisonsRejectSkippedPhasesAndChangedRecordIdentity() throws {
        try MachineUpdateReplacementTests.withRetainedInitialConfigurationValueFixture { snapshot, _, candidate, _, unchanged in
            let original = try entry(snapshot, candidate: candidate), record = try XCTUnwrap(snapshot.intent)
            let preparedRecord = try changed(record) { fields in
                fields["phase"] = Record.Phase.prepared.rawValue
                fields["committedPolicy"] = nil; fields["committedCheckpoint"] = nil
            }
            let prepared = try image(original, candidate: candidate, reference: original.runtime.state.reference, intent: preparedRecord)
            XCTAssertThrowsError(try original.requirePolicyTransition(record, from: prepared))
            XCTAssertThrowsError(try original.requirePolicyRetention(record, from: prepared))
            let other = try changed(record) { $0["revision"] = UUID().uuidString }
            let changedEntry = try image(original, candidate: candidate, reference: original.runtime.state.reference, intent: other)
            XCTAssertThrowsError(try changedEntry.requireSame(as: original))
            XCTAssertThrowsError(try changedEntry.requireMaterial(XCTUnwrap(original.runtime.state.reference), from: original))
            try unchanged()
        }
    }
    func testPublicationComparisonKeepsReservationsSchemaAndMarkerExact() throws {
        try MachineUpdateReplacementTests.withRetainedInitialConfigurationValueFixture { snapshot, _, candidate, _, unchanged in
            let before = try entry(snapshot, candidate: candidate), reference = try XCTUnwrap(before.runtime.state.reference)
            let after = try image(before, candidate: candidate, reference: reference, published: true, intent: before.intent)
            try after.requirePublication(from: before, reference: reference)
            XCTAssertThrowsError(try after.requirePublication(from: after, reference: reference))
            var extra: UInt32 = 29999
            while before.runtime.reservedNumbers.contains(extra) { extra += 1 }
            let reserved = try image(before, candidate: candidate, reference: reference, published: true,
                intent: before.intent, reserved: before.runtime.reservedNumbers.union([extra]))
            XCTAssertThrowsError(try reserved.requirePublication(from: before, reference: reference))
            let schema = try image(before, candidate: candidate, reference: reference, published: true,
                intent: before.intent, schema: before.runtime.setup.source.actual.schemaVersion + 1)
            XCTAssertThrowsError(try schema.requirePublication(from: before, reference: reference))
            let marker = try changed(XCTUnwrap(before.intent)) { $0["id"] = UUID().uuidString }
            let replaced = try image(before, candidate: candidate, reference: reference, published: true, intent: marker)
            XCTAssertThrowsError(try replaced.requirePublication(from: before, reference: reference))
            try unchanged()
        }
    }
    func testAcknowledgementComparisonRequiresRealImportAndCannotAcceptAbsentInputs() throws {
        try MachineUpdateReplacementTests.withRetainedInitialConfigurationValueFixture { snapshot, _, candidate, _, unchanged in
            let before = try entry(snapshot, candidate: candidate), reference = try XCTUnwrap(before.runtime.state.reference)
            let published = try image(before, candidate: candidate, reference: reference, published: true, intent: before.intent)
            let absent = try Inputs.capture(expected: published.runtime, journal: nil, verifyCurrent: {},
                readRelay: { _ in XCTFail("Absent input read relay"); throw Fault.unexpected })
            XCTAssertThrowsError(try published.requireAcknowledgement(inputs: absent, from: published, previousInputs: absent))
            XCTAssertThrowsError(try before.requireAcknowledgement(inputs: absent, from: before, previousInputs: absent))
            try unchanged()
        }
    }
    func testAcknowledgementComparesActualJournalAdvanceAndRejectsReplayOrOtherMachineChanges() throws {
        try MachineUpdateReplacementTests.withRetainedInitialConfigurationValueFixture { snapshot, _, candidate, _, unchanged in
            let entry = try entry(snapshot, candidate: candidate), reference = try XCTUnwrap(entry.runtime.state.reference)
            let before = try image(entry, candidate: candidate, reference: reference, published: true, intent: entry.intent)
            let runtime = before.runtime, account = runtime.preparation
            let inventory = try runtime.setup.source.provisioningInventory(accountID: account.accountID,
                ownerUID: account.ownerUID, releaseDigest: account.releaseDigest)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            let defaults = try SharedSetupDefaults(presence: .init(idleMilliseconds: 540_000,
                observationLifetimeMilliseconds: 7000, unavailableGraceMilliseconds: 45_000),
                gateway: GatewaySetupForm().settingsSelection())
            let intent = try SharedSetupImportIntent(scope: scope, proposal: .init(defaults: defaults))
            let root = URL(fileURLWithPath: "/private/tmp/remozio-initial-entry-import-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: root) }
            let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Import", owner: getuid())
            defer { directory.close() }
            _ = try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .sharedSetupImport, owner: getuid())
            let journal = try SharedSetupImportJournal(lease: .init(anchor: root.path, relativeDirectory: "Import",
                owner: getuid(), ancestorOwner: getuid(), databaseName: "setup-import.sqlite"), owner: getuid(),
                macID: account.macID, installationID: account.installationID, initialize: true)
            defer { try? journal.close() }
            try journal.begin(intent)
            func inputs(_ runtime: Runtime) throws -> Inputs {
                try Inputs.capture(expected: runtime, journal: journal, verifyCurrent: {},
                    readRelay: { _ in try .init(plan: nil, snapshot: nil) })
            }
            let previous = try inputs(runtime)
            let committed = try journal.advance(intent, to: .runtimePublished)
            var digest = runtime.setup.source.actual.currentRowsDigest; digest[digest.startIndex] ^= 1
            let after = try image(before, candidate: candidate, reference: reference, published: true,
                intent: before.intent, digest: digest)
            let actual = try inputs(after.runtime)
            XCTAssertEqual(actual.intent, committed)
            try after.requireAcknowledgement(inputs: actual, from: before, previousInputs: previous)
            XCTAssertThrowsError(try after.requireSame(as: before))
            XCTAssertThrowsError(try after.requireAcknowledgement(inputs: actual, from: after, previousInputs: actual))
            XCTAssertThrowsError(try before.requireAcknowledgement(inputs: previous, from: before, previousInputs: previous))
            var extra: UInt32 = 29999
            while before.runtime.reservedNumbers.contains(extra) { extra += 1 }
            let changed = try image(before, candidate: candidate, reference: reference, published: true,
                intent: before.intent, reserved: before.runtime.reservedNumbers.union([extra]))
            XCTAssertThrowsError(try changed.requireAcknowledgement(inputs: actual, from: before, previousInputs: previous))
            XCTAssertEqual(try journal.current(scope: scope), committed)
            try unchanged()
        }
    }
}
