import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

private struct RelayProvisioningFixtureStop: Error {}
final class RelayProvisioningFixture: @unchecked Sendable {
        let f: SharedSetupImportFixture
        let intent: SharedSetupImportIntent
        let services: ServiceAccountPlan
        init() throws {
            let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .commandFrontend, .commandMonitor, .commandChild, .setupController]
            let policy = try AuthorityCodePolicy(entries: roles.map { role in
                try .init(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\(role.rawValue)",
                    installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
            })
            f = try .init(relativeDirectory: "machine/SharedSetupImport", policy: policy)
            intent = try f.intent()
            services = try .init(account: f.account, planID: AccountPreparationIntent.randomID(), claims: [
                .init(accountID: f.account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
                .init(accountID: f.account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
            let machine = try f.accountFixture.open(); defer { try? machine.close() }
            try machine.retainServiceAccountPlan(services); try machine.completeServiceAccountPlan(services)
            let journal = try f.open(initialize: true); try journal.begin(intent); try journal.close()
        }
        func machine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            let value = try f.accountFixture.open(); defer { try? value.close() }; return try body(value)
        }
        func directory<Value>(_ body: (ProtectedSetupDirectory) throws -> Value) throws -> Value {
            let directory = try ProtectedSetupDirectory(anchor: f.accountFixture.root.path, relativePath: f.relativeDirectory, owner: getuid(), createIfMissing: false)
            defer { directory.close() }; return try body(directory)
        }
        var path: String { f.accountFixture.root.path + "/" + f.relativeDirectory + "/" + AdministrativeSetupPublication.File.importRelayPlan(accountID: f.account.accountID).name }
        func prepare(_ expected: SharedSetupImportIntent? = nil, records: [SharedSetupImportIntent]? = nil,
                     published: Bool = false, select: (Set<UInt16>) throws -> UInt16 = { _ in 51001 },
                     verify: () throws -> Void = {}) throws -> SharedSetupImportRelayPlan {
            try directory { try SharedSetupImportRelayStorage.prepare(expected: expected ?? intent, records: records ?? [intent],
                runtimePublished: published, directory: $0, owner: getuid(), select: select, verifyCurrent: verify) }
        }
        func readPlan(_ expected: SharedSetupImportIntent? = nil) throws -> SharedSetupImportRelayPlan? {
            try directory { try SharedSetupImportRelayStorage.read(expected: expected ?? intent, directory: $0, owner: getuid()) }
        }
        func owner(operations: RuntimeActivationOperations = .native) throws -> SetupAccountOwner {
            try .init(openMachine: { try self.f.accountFixture.open() }, expectedReleaseDigest: f.accountFixture.release,
                resume: { _, _ in throw RelayProvisioningFixtureStop() }, accountCodePolicy: f.accountFixture.policy,
                lookupAccount: { uid in guard uid == self.f.accountFixture.identity.uid else { throw AdministrativeSetupError.wrongAccount }; return self.f.accountFixture.identity },
                activationOperations: operations)
        }
        func progress(_ owner: SetupAccountOwner) throws -> SetupPortableImportProgress { try XCTUnwrap(owner.portableImportProgress(callerUID: getuid())) }
    }


final class SharedSetupRelayProvisioningTests: XCTestCase {
    private func begin(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan) throws -> SharedSetupRelayProvisioningRecord {
        try h.directory { try SharedSetupRelayProvisioningStorage.begin(expected: h.intent, plan: plan, directory: $0, owner: getuid(), verifyCurrent: {}) }
    }
    private func store(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan, next: SharedSetupRelayProvisioningRecord,
                       old: SharedSetupRelayProvisioningRecord, stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws {
        try h.directory { try SharedSetupRelayProvisioningStorage.replace(next, previous: old, expected: h.intent, plan: plan,
            directory: $0, owner: getuid(), verifyCurrent: {}, didStage: stage) }
    }
    private func read(_ h: RelayProvisioningFixture, plan: SharedSetupImportRelayPlan?) throws -> SharedSetupRelayProvisioningRecord? {
        try h.directory { try SharedSetupRelayProvisioningStorage.read(expected: h.intent, plan: plan, directory: $0, owner: getuid()) }
    }
    private func path(_ h: RelayProvisioningFixture) -> String {
        URL(fileURLWithPath: h.path).deletingLastPathComponent().path + "/" + AdministrativeSetupPublication.File.importRelayProvisioning(accountID: h.intent.scope.accountID).name
    }
    func testCanonicalRecordBindsTheLocalPlanAndContainsNoCredential() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), record = try begin(h, plan: plan)
        XCTAssertEqual(try SharedSetupRelayProvisioningRecord.decode(record.bytes, expected: h.intent, plan: plan), record)
        XCTAssertEqual(record.phase, .prepared); XCTAssertEqual(record.attemptNumber, 1)
        XCTAssertEqual(String(reflecting: record), "SharedSetupRelayProvisioningRecord(redacted)")
        XCTAssertNil(record.bytes.range(of: Data("synthetic-provider-token-only".utf8)))
        let other = try h.f.intent(), crossed = try SharedSetupImportRelayPlan(expected: other, port: plan.port)
        XCTAssertThrowsError(try SharedSetupRelayProvisioningRecord.decode(record.bytes, expected: other, plan: crossed))
    }
    func testMalformedVersionsFieldsPayloadsAndAttemptNumbersAreRejected() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), record = try begin(h, plan: plan)
        let limits = try CBORLimits(maxBytes: 8192, maxDepth: 1, maxItems: 40)
        guard case let .map(fields) = try DeterministicCBOR.decode(record.bytes, limits: limits) else { return XCTFail() }
        for (key, value): (UInt64, CBORValue) in [(0, .unsigned(2)), (1, .text("other-purpose")), (6, .unsigned(0)), (7, .unsigned(99)),
            (8, .text("11111111-1111-4111-8111-111111111111")), (11, .bytes(Data(repeating: 0, count: 32))), (12, .null)] {
            var changed = fields; changed[key] = value
            XCTAssertThrowsError(try SharedSetupRelayProvisioningRecord.decode(DeterministicCBOR.encode(.map(changed), limits: limits), expected: h.intent, plan: plan))
        }
    }
    func testOnlyDispatchCanLeadToAnOutcomeAndTerminalStateCannotRestart() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), prepared = try begin(h, plan: plan)
        XCTAssertThrowsError(try prepared.transition(to: .created, tunnelID: "11111111-1111-4111-8111-111111111111"))
        let sent = try prepared.transition(to: .dispatched), unknown = try sent.transition(to: .unknown)
        XCTAssertThrowsError(try unknown.retryAfterRefusal()); XCTAssertThrowsError(try unknown.transition(to: .dispatched))
        let created = try sent.transition(to: .created, tunnelID: "11111111-1111-4111-8111-111111111111")
        XCTAssertThrowsError(try created.transition(to: .dispatched)); XCTAssertThrowsError(try created.retryAfterRefusal())
    }
    func testOnlyExplicitRefusalRetryCreatesANewAttemptIdentity() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), prepared = try begin(h, plan: plan)
        let sent = try prepared.transition(to: .dispatched), refused = try sent.transition(to: .rejected, refusal: .unauthorized)
        let retry = try refused.retryAfterRefusal()
        XCTAssertEqual(retry.recordID, prepared.recordID); XCTAssertEqual(retry.requestDigest, prepared.requestDigest)
        XCTAssertNotEqual(retry.attemptID, prepared.attemptID); XCTAssertEqual(retry.attemptNumber, 2)
        XCTAssertNoThrow(try retry.validateTransition(from: refused))
        XCTAssertThrowsError(try retry.validateTransition(from: sent))
    }
    func testExistingBeginRetainsTheSameBytesAndInode() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), record = try begin(h, plan: plan)
        let before = try h.directory { try SharedSetupRelayProvisioningStorage.snapshot(expected: h.intent, plan: plan, directory: $0, owner: getuid()) }
        XCTAssertEqual(try begin(h, plan: plan), record)
        let after = try h.directory { try SharedSetupRelayProvisioningStorage.snapshot(expected: h.intent, plan: plan, directory: $0, owner: getuid()) }
        XCTAssertEqual(before, after)
        var info = stat(); XCTAssertEqual(lstat(path(h), &info), 0); XCTAssertEqual(info.st_mode & 0o777, 0o600)
    }
    func testStoredDispatchAndUnknownOutcomeSurviveReopenWithoutNewAttempt() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), prepared = try begin(h, plan: plan), sent = try prepared.transition(to: .dispatched)
        try store(h, plan: plan, next: sent, old: prepared)
        XCTAssertEqual(try read(h, plan: plan), sent); XCTAssertEqual(try begin(h, plan: plan), sent)
        let unknown = try sent.transition(to: .unknown); try store(h, plan: plan, next: unknown, old: sent)
        XCTAssertEqual(try begin(h, plan: plan), unknown); XCTAssertEqual(try read(h, plan: plan)?.attemptID, prepared.attemptID)
    }
    func testAResourceRecordPreventsReselectingAMissingLocalPlan() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(); _ = try begin(h, plan: plan)
        XCTAssertEqual(unlink(h.path), 0)
        var selected = false
        XCTAssertThrowsError(try h.prepare(select: { _ in selected = true; return 51002 }))
        XCTAssertFalse(selected); XCTAssertFalse(FileManager.default.fileExists(atPath: h.path))
        XCTAssertThrowsError(try h.machine { try $0.retainedRuntimeCompatibilityInputs() })
    }
    func testCorruptAndSymbolicRecordFilesAreNotOverwritten() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(); _ = try begin(h, plan: plan)
        let corrupt = Data("malformed-public-state".utf8); try corrupt.write(to: URL(fileURLWithPath: path(h)))
        XCTAssertThrowsError(try begin(h, plan: plan)); XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(h))), corrupt)
        XCTAssertEqual(unlink(path(h)), 0); XCTAssertEqual(symlink(h.path, path(h)), 0)
        XCTAssertThrowsError(try begin(h, plan: plan))
    }
    func testStaleCompareAndSwapCannotUndoADispatch() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), prepared = try begin(h, plan: plan), sent = try prepared.transition(to: .dispatched)
        try store(h, plan: plan, next: sent, old: prepared)
        let another = try prepared.transition(to: .dispatched)
        XCTAssertThrowsError(try store(h, plan: plan, next: another, old: prepared))
        XCTAssertEqual(try read(h, plan: plan), sent)
    }
    func testLostPublicationReplyRetainsThePublishedDispatchAsUnresolved() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), prepared = try begin(h, plan: plan), sent = try prepared.transition(to: .dispatched)
        XCTAssertThrowsError(try store(h, plan: plan, next: sent, old: prepared, stage: { stage in if stage == .published { throw RelayProvisioningFixtureStop() } }))
        XCTAssertEqual(try read(h, plan: plan), sent); XCTAssertEqual(try begin(h, plan: plan), sent)
        // Process-level publication evidence only. This does not simulate power loss.
    }
    func testUpdateSnapshotTracksStateRevisionsAndRequiresItsReaderAndWriter() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), prepared = try begin(h, plan: plan)
        let snapshot = try h.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        XCTAssertNotNil(snapshot.inputs.sharedImport?.records.first?.relayProvisioning)
        let requirement = try XCTUnwrap(snapshot.requirements.formats.first { $0.name == SharedSetupRelayProvisioningRecord.formatName })
        XCTAssertEqual(requirement.role, .setupController); XCTAssertEqual(requirement.readVersions, [1]); XCTAssertEqual(requirement.writeVersions, [1])
        let sent = try prepared.transition(to: .dispatched); try store(h, plan: plan, next: sent, old: prepared)
        XCTAssertThrowsError(try h.machine { try snapshot.requireCurrent(machine: $0) })
    }
    func testReplacingIdenticalBytesChangesTheRetainedFileIdentity() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), prepared = try begin(h, plan: plan)
        let snapshot = try h.machine { try RuntimeReleaseCompatibilitySnapshot.capture(machine: $0) }
        let replacement = path(h) + ".replacement"; try prepared.bytes.write(to: URL(fileURLWithPath: replacement))
        XCTAssertEqual(chmod(replacement, 0o600), 0); XCTAssertEqual(rename(replacement, path(h)), 0)
        XCTAssertThrowsError(try h.machine { try snapshot.requireCurrent(machine: $0) })
    }
    func testOrphanResourceFilesInvalidateTheGlobalImportSnapshot() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(); _ = try begin(h, plan: plan)
        let orphan = URL(fileURLWithPath: path(h)).deletingLastPathComponent().appendingPathComponent("import-relay-state-unknown.cbor")
        try Data("orphan".utf8).write(to: orphan); XCTAssertEqual(chmod(orphan.path, 0o600), 0)
        XCTAssertThrowsError(try h.machine { try $0.retainedRuntimeCompatibilityInputs() })
    }
    func testGenericSettingsPublisherCannotWriteAProvisioningRecord() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), prepared = try begin(h, plan: plan)
        XCTAssertThrowsError(try h.directory { directory in
            try AdministrativeSetupPublication.replaceSettings(prepared.bytes, expected: prepared.bytes,
                file: .importRelayProvisioning(accountID: h.intent.scope.accountID), directory: directory, owner: getuid(), verify: {})
        })
    }
    func testTheSameOperationCanReadItsHistoryAfterImportPhaseAdvances() throws {
        let h = try RelayProvisioningFixture(), plan = try h.prepare(), prepared = try begin(h, plan: plan)
        let later = try h.intent.advanced(to: .runtimePublished)
        XCTAssertEqual(try SharedSetupRelayProvisioningRecord.decode(prepared.bytes, expected: later, plan: plan), prepared)
    }
}
