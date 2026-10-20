import Darwin
import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

final class RuntimeReleaseCompatibilityTests: XCTestCase {
    private typealias Snapshot = RuntimeReleaseCompatibilitySnapshot
    private func signature(_ f: RuntimeActivationFixture, edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws -> SignedReleaseEvidence {
        try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy, edit: edit)
    }
    private func without(_ f: RuntimeActivationFixture, role: AuthorityCodeRole, format: String) throws -> SignedReleaseEvidence {
        try signature(f) { component in
            guard component.role == role else { return component }
            return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                teamID: component.teamID, formats: component.formats.filter { $0.name != format })
        }
    }
    private func destination(_ f: RuntimeActivationFixture) throws -> ReleaseDestinationLease {
        let path = f.f.root.appendingPathComponent("Inactive")
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(path.path, 0o755), 0)
        return try .init(anchor: f.f.root.path, relativeDirectory: "Inactive", owner: getuid())
    }
    private func recordedCopy(_ f: RuntimeActivationFixture, _ destination: ReleaseDestinationLease,
                              signed: SignedReleaseEvidence) throws -> PreparationIntentRecord {
        let intent = try f.machine.begin(parent: destination.path, ancestry: destination.preparationAncestry())
        let copy = URL(fileURLWithPath: destination.path).appendingPathComponent(intent.bundleName)
        try FileManager.default.createDirectory(at: copy, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(copy.path, 0o755), 0)
        let file = copy.appendingPathComponent("owned-file"); try Data("fixture".utf8).write(to: file)
        XCTAssertEqual(chmod(file.path, 0o644), 0)
        return try f.machine.recordCopy(id: intent.id, expectedRevision: intent.revision,
            identity: destination.preparationCopyIdentity(name: intent.bundleName), digest: DurableReleasePreparation.digest(signed))
    }
    func testUnpublishedAndUnenrolledNativeReferencesStillRequireTheCompleteNativeReaderFamily() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true)
        XCTAssertTrue(try XCTUnwrap(f.machine.inventory()).accounts.isEmpty)
        XCTAssertEqual(try f.f.sql("UPDATE runtime_preparation_v1 SET complete=0"), 0)
        let snapshot = try Snapshot.capture(machine: f.machine), runtime = try XCTUnwrap(snapshot.inputs.runtimes.first)
        XCTAssertEqual(snapshot.inputs.runtimes.count, 1); XCTAssertFalse(runtime.configurationPublished)
        XCTAssertNil(runtime.activationRecord); XCTAssertFalse(runtime.jobsRegistered)
        let required = snapshot.requirements.formats
        for role in [AuthorityCodeRole.authority, .setupController] {
            XCTAssertEqual(required.first { $0.role == role && $0.name == RuntimeActivationPlan.formatName }?.readVersions, [1, 2])
        }
        for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
            XCTAssertTrue(try XCTUnwrap(required.first { $0.role == role && $0.name == "transport.pairing-config" }).readVersions.contains(2))
            XCTAssertTrue(try XCTUnwrap(required.first { $0.role == role && $0.name == "gateway.service-config" }).readVersions.contains(2))
        }
        try snapshot.validate(signature(f), policy: f.plan.host.codePolicy, machine: f.machine)
        XCTAssertThrowsError(try snapshot.validate(without(f, role: .authority, format: RuntimeActivationPlan.formatName),
            policy: f.plan.host.codePolicy, machine: f.machine))
    }
    func testLegacyRecordsUseTheirExistingSchemaAndHostContractsWithoutClaimingNativeParticipation() throws {
        let f = try RuntimeActivationFixture(), snapshot = try Snapshot.capture(machine: f.machine)
        XCTAssertFalse(snapshot.requirements.formats.contains { $0.name == RuntimeActivationPlan.formatName })
        let host = try XCTUnwrap(snapshot.requirements.formats.first { $0.role == .authority && $0.name == "authority.command-host-config" })
        XCTAssertEqual(host.readVersions, [2])
        let legacy = try signature(f) { component in
            try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash, build: component.build,
                teamID: component.teamID, formats: component.formats.filter {
                    ["authority.installation-preparation", "authority.command-host-config"].contains($0.name)
                })
        }
        try snapshot.validate(legacy, policy: f.plan.host.codePolicy, machine: f.machine)
        XCTAssertThrowsError(try snapshot.validate(without(f, role: .authority, format: "authority.installation-preparation"),
            policy: f.plan.host.codePolicy, machine: f.machine))
    }
    func testNewActivationEnrollmentAndPublishedStateInvalidateAnEarlierSnapshotWithoutMutatingRecords() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), first = try Snapshot.capture(machine: f.machine)
        let original = try f.machine.runtimePreparation(accountID: f.account.accountID)
        try f.machine.retainRuntimeActivation(f.plan)
        XCTAssertThrowsError(try first.requireCurrent(machine: f.machine))
        let retained = try Snapshot.capture(machine: f.machine)
        XCTAssertEqual(retained.inputs.runtimes.first?.activationRecord, try f.plan.encoded)
        _ = try f.machine.enrollRuntimeActivation(f.plan)
        XCTAssertThrowsError(try retained.requireCurrent(machine: f.machine))
        let enrolled = try Snapshot.capture(machine: f.machine); try enrolled.requireCurrent(machine: f.machine)
        XCTAssertEqual(try f.machine.runtimePreparation(accountID: f.account.accountID), original)
        let other = try RuntimeActivationFixture(nativeConsumerHosts: true)
        XCTAssertThrowsError(try enrolled.requireCurrent(machine: other.machine))
    }
    func testCorruptReferenceAndOrphanActivationCannotBeHiddenByInventoryScanning() throws {
        let corrupt = try RuntimeActivationFixture(nativeConsumerHosts: true)
        _ = try corrupt.f.sql("UPDATE runtime_preparation_v1 SET digest=zeroblob(32)")
        XCTAssertThrowsError(try Snapshot.capture(machine: corrupt.machine))
        let orphan = try RuntimeActivationFixture(nativeConsumerHosts: true)
        try orphan.machine.retainRuntimeActivation(orphan.plan)
        _ = try orphan.f.sql("DELETE FROM runtime_preparation_v1")
        XCTAssertThrowsError(try Snapshot.capture(machine: orphan.machine))
    }
    func testCompatiblePreflightReinspectsTheExactInactiveCopyAndKeepsTheRuntimeUnregistered() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), dest = try destination(f)
        defer { dest.close() }
        let signed = try signature(f), before = try Snapshot.capture(machine: f.machine), record = try recordedCopy(f, dest, signed: signed)
        try before.requireCurrent(machine: f.machine)
        try f.machine.close()
        let reopened = try f.f.open(); defer { try? reopened.close() }
        try before.requireCurrent(machine: reopened)
        var inspections = 0
        let result = try DurableReleasePreparation.validateRuntimeCompatibilityInLease(attemptID: record.id, destination: dest,
            store: reopened, readPolicy: { f.plan.host.codePolicy }, inspect: { _, _, _ in inspections += 1; return signed })
        XCTAssertEqual(result.attemptID, record.id); XCTAssertEqual(inspections, 1)
        XCTAssertEqual(try reopened.records(), [record]); XCTAssertFalse(try reopened.runtimeActivation(accountID: f.account.accountID).jobsRegistered)
        try before.requireCurrent(machine: reopened)
    }
    func testAStoredSigningDigestCannotOverrideMissingReadersOrChangedNativeExecutablePaths() throws {
        for move in [false, true] {
            let f = try RuntimeActivationFixture(nativeConsumerHosts: true), dest = try destination(f)
            defer { dest.close() }
            let signed: SignedReleaseEvidence
            if move {
                signed = try signature(f) { c in
                    guard c.role == .transport else { return c }
                    return try .init(role: c.role, identifier: c.identifier, generation: c.generation,
                        relativePath: "Contents/Helpers/moved", codeDirectoryHash: c.codeDirectoryHash,
                        build: c.build, teamID: c.teamID, formats: c.formats)
                }
            } else { signed = try without(f, role: .notificationGateway, format: "transport.pairing-config") }
            let record = try recordedCopy(f, dest, signed: signed)
            XCTAssertThrowsError(try DurableReleasePreparation.validateRuntimeCompatibilityInLease(attemptID: record.id,
                destination: dest, store: f.machine, readPolicy: { f.plan.host.codePolicy }, inspect: { _, _, _ in signed }))
            XCTAssertEqual(try f.machine.records(), [record])
        }
    }
    func testPrivateScopeChangesDuringInspectionCannotReturnOldCompatibilityEvidence() throws {
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), dest = try destination(f)
        defer { dest.close() }
        let signed = try signature(f), record = try recordedCopy(f, dest, signed: signed)
        XCTAssertThrowsError(try DurableReleasePreparation.validateRuntimeCompatibilityInLease(attemptID: record.id,
            destination: dest, store: f.machine, readPolicy: { f.plan.host.codePolicy }, inspect: { _, _, _ in
                try f.machine.retainRuntimeActivation(f.plan); return signed
            })) { XCTAssertEqual($0 as? RuntimeActivationError, .changedScope) }
        XCTAssertEqual(try f.machine.records(), [record])
    }
    func testNativeEntryRefusesOrdinaryAccountsBeforeInspectionOrRecordChanges() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary account control") }
        let f = try RuntimeActivationFixture(nativeConsumerHosts: true), dest = try destination(f)
        defer { dest.close() }
        XCTAssertThrowsError(try DurableReleasePreparation.validateRuntimeCompatibility(attemptID: UUID(), destination: dest,
            store: f.machine, readPolicy: { XCTFail("Native refusal must precede policy access"); return f.plan.host.codePolicy })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(try f.machine.records(), [])
    }
}
