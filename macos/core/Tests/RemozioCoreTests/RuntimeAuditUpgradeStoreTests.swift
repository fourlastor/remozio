import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeAuditUpgradeStoreTests: XCTestCase {
    private struct Interrupted: Error {}
    private func fixture(edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws -> RuntimeActivationFixture {
        try .init(nativeConsumerHosts: true, phoneAudit: true, auditDelivery: true, materialAuditDelivery: false, releaseEdit: edit)
    }
    private func intent(_ f: RuntimeActivationFixture, id: Data? = nil) throws -> RuntimeAuditUpgradeIntent {
        let target = try RuntimeAuditMaterialUpgrade.prepare(material: f.material, expected: f.material.reference,
            account: f.account, activity: XCTUnwrap(f.material.serviceActivity),
            installedRelease: XCTUnwrap(f.nativeRelease), policy: f.plan.host.codePolicy)
        return try .init(id: id ?? AccountPreparationIntent.randomID(), source: f.material.reference,
            target: target.reference, policy: f.plan.host.codePolicy)
    }
    func testRetentionUpgradesStorageWithoutChangingAnyRuntimeOrEnrollmentMarker() throws {
        let f = try fixture(), intent = try intent(f)
        try f.machine.retainRuntimeActivation(f.plan)
        _ = try f.machine.enrollRuntimeActivation(f.plan); try f.machine.markRuntimeJobsRegistered(f.plan)
        let before = try f.machine.runtimePreparation(accountID: f.account.accountID), inventory = try f.machine.inventory()
        let activation = try f.machine.runtimeActivation(accountID: f.account.accountID)
        let first = try f.machine.retainRuntimeAuditUpgrade(intent, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))
        XCTAssertEqual(first.phase, .retained); XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 12)
        XCTAssertEqual(try f.machine.retainRuntimeAuditUpgrade(intent, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease)), first)
        XCTAssertEqual(try f.machine.runtimePreparation(accountID: f.account.accountID), before)
        XCTAssertEqual(try f.machine.inventory(), inventory)
        let after = try f.machine.runtimeActivation(accountID: f.account.accountID)
        XCTAssertEqual(try after.plan?.encoded, try activation.plan?.encoded); XCTAssertTrue(after.jobsRegistered)
        XCTAssertTrue(try f.machine.gatewayPreparation(accountID: f.account.accountID).reference == nil)
        XCTAssertNil(f.material.auditDeliveryVersion)
    }
    func testReopenAndMatchingStagingReplayKeepTheSameIntentAndRevision() throws {
        let f = try fixture(), intent = try intent(f)
        let first = try f.machine.retainRuntimeAuditUpgrade(intent, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))
        let staged = try f.machine.markRuntimeAuditMaterialStaged(first, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))
        XCTAssertEqual(staged.phase, .materialStaged); XCTAssertNotEqual(staged.revision, first.revision)
        XCTAssertEqual(try f.machine.markRuntimeAuditMaterialStaged(first, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease)), staged)
        try f.machine.close(); let reopened = try f.f.open(); defer { try? reopened.close() }
        XCTAssertEqual(try reopened.runtimeAuditUpgrade(accountID: f.account.accountID), staged)
        XCTAssertEqual(try reopened.retainRuntimeAuditUpgrade(intent, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease)), staged)
        XCTAssertEqual(try reopened.runtimePreparation(accountID: f.account.accountID).reference, try f.material.reference)
    }
    func testWrongCurrentPolicyAndDifferentIntentDoNotReplaceAnEstablishedAttempt() throws {
        let f = try fixture(), intent = try intent(f)
        let current = try AuthorityCodePolicy(entries: f.plan.host.codePolicy.entries.map { entry in
            try .init(role: entry.role, teamID: entry.teamID, identifier: entry.identifier, installedGeneration: 2,
                minimumGeneration: 2, codeDirectoryHash: entry.codeDirectoryHash, active: entry.active)
        })
        XCTAssertThrowsError(try f.machine.retainRuntimeAuditUpgrade(intent, currentPolicy: current, installedRelease: XCTUnwrap(f.nativeRelease)))
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 6)
        let first = try f.machine.retainRuntimeAuditUpgrade(intent, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))
        XCTAssertThrowsError(try f.machine.retainRuntimeAuditUpgrade(self.intent(f), currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease)))
        XCTAssertThrowsError(try f.machine.markRuntimeAuditMaterialStaged(first, currentPolicy: current, installedRelease: XCTUnwrap(f.nativeRelease)))
        let stale = try RuntimeAuditUpgradeRecord(intent: intent, phase: .retained)
        XCTAssertThrowsError(try f.machine.markRuntimeAuditMaterialStaged(stale, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))) {
            XCTAssertEqual($0 as? PreparationStoreError, .staleRevision)
        }
        XCTAssertEqual(try f.machine.runtimeAuditUpgrade(accountID: f.account.accountID), first)
    }
    func testLostRetentionAndStagingCommitRepliesRecoverWithoutRepeatingOrClearingState() throws {
        for stage in [false, true] {
            let f = try fixture(), intent = try intent(f)
            let retained = stage ? try f.machine.retainRuntimeAuditUpgrade(intent, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease)) : nil
            try f.machine.close(); var armed = false
            let writer = try f.f.open(hook: { if armed { throw Interrupted() } }); armed = true
            XCTAssertThrowsError(try stage ? writer.markRuntimeAuditMaterialStaged(XCTUnwrap(retained), currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))
                : writer.retainRuntimeAuditUpgrade(intent, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertThrowsError(try writer.runtimeAuditUpgrade(accountID: f.account.accountID)); try writer.close()
            let recovered = try f.f.open(); defer { try? recovered.close() }
            let result = try XCTUnwrap(recovered.runtimeAuditUpgrade(accountID: f.account.accountID))
            XCTAssertEqual(result.intent, intent); XCTAssertEqual(result.phase, stage ? .materialStaged : .retained)
            XCTAssertEqual(try recovered.retainRuntimeAuditUpgrade(intent, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease)), result)
            XCTAssertEqual(try recovered.runtimePreparation(accountID: f.account.accountID).reference, try f.material.reference)
        }
    }
    func testPendingTargetRequiresBothSchemasAndTheRecordReaderBeforeAnyCutover() throws {
        let f = try fixture(), intent = try intent(f)
        let before = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
        let first = try f.machine.retainRuntimeAuditUpgrade(intent, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))
        XCTAssertThrowsError(try before.requireCurrent(machine: f.machine))
        let snapshot = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
        XCTAssertEqual(snapshot.inputs.auditUpgrades, [first])
        for role in [AuthorityCodeRole.authority, .transport, .notificationGateway, .setupController] {
            let format = try XCTUnwrap(snapshot.requirements.formats.first { $0.role == role && $0.name == RuntimeMaterialReference.formatName })
            XCTAssertEqual(format.readVersions, [2, 3])
        }
        try snapshot.validate(XCTUnwrap(f.nativeRelease), policy: f.plan.host.codePolicy, machine: f.machine)
        for name in [RuntimeAuditUpgradeRecord.formatName, RuntimeMaterialReference.formatName] {
            let missing = try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy, phoneAudit: true, auditDelivery: true) { c in
                guard c.role == .setupController else { return c }
                return try .init(role: c.role, identifier: c.identifier, generation: c.generation, relativePath: c.relativePath,
                    codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: c.formats.filter { $0.name != name }, requests: c.requests)
            }
            XCTAssertThrowsError(try snapshot.validate(missing, policy: f.plan.host.codePolicy, machine: f.machine))
        }
        _ = try f.machine.markRuntimeAuditMaterialStaged(first, currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))
        XCTAssertThrowsError(try snapshot.requireCurrent(machine: f.machine))
    }
    func testPendingTargetRejectsAReaderThatWasCompatibleBeforeRetention() throws {
        let f = try fixture()
        let oldReader = try NativeHostReleaseFixture.make(policy: f.plan.host.codePolicy, phoneAudit: true, auditDelivery: true) { c in
            guard c.role == .transport else { return c }
            let formats = try c.formats.map { value in
                guard value.name == RuntimeMaterialReference.formatName else { return value }
                return try ReleaseFormat(name: value.name, readers: [1, 2], writers: value.writers)
            }
            return try .init(role: c.role, identifier: c.identifier, generation: c.generation, relativePath: c.relativePath,
                codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: formats, requests: c.requests)
        }
        let before = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
        try before.validate(oldReader, policy: f.plan.host.codePolicy, machine: f.machine)
        _ = try f.machine.retainRuntimeAuditUpgrade(intent(f), currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))
        let pending = try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine)
        XCTAssertThrowsError(try pending.validate(oldReader, policy: f.plan.host.codePolicy, machine: f.machine)) {
            XCTAssertEqual($0 as? ReleaseCompatibilityError, .missingReader(.transport, RuntimeMaterialReference.formatName, 3))
        }
    }
    func testCorruptStoredDigestCannotBecomeARecoveryRecordOrCompatibilitySnapshot() throws {
        let f = try fixture()
        _ = try f.machine.retainRuntimeAuditUpgrade(intent(f), currentPolicy: f.plan.host.codePolicy, installedRelease: XCTUnwrap(f.nativeRelease))
        _ = try f.f.sql("UPDATE runtime_audit_upgrade_v1 SET digest=zeroblob(32)")
        XCTAssertThrowsError(try f.machine.runtimeAuditUpgrade(accountID: f.account.accountID)) {
            XCTAssertEqual($0 as? PreparationStoreError, .corruptRecord)
        }
        XCTAssertThrowsError(try RuntimeReleaseCompatibilitySnapshot.capture(machine: f.machine))
    }
    func testPreparationCannotRaiseStorageBeforeTheInstalledReadersDeclareItsFormats() throws {
        for name in [RuntimeAuditUpgradeRecord.formatName, "authority.installation-preparation"] {
            let f = try fixture { c in
                guard c.role == .authority else { return c }
                let formats = try c.formats.compactMap { value -> ReleaseFormat? in
                    guard value.name == name else { return value }
                    if name == RuntimeAuditUpgradeRecord.formatName { return nil }
                    return try .init(name: value.name, readers: Set(UInt64(1)...11), writers: Set(UInt64(1)...11))
                }
                return try .init(role: c.role, identifier: c.identifier, generation: c.generation, relativePath: c.relativePath,
                    codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: formats, requests: c.requests)
            }
            XCTAssertThrowsError(try f.machine.retainRuntimeAuditUpgrade(intent(f), currentPolicy: f.plan.host.codePolicy,
                installedRelease: XCTUnwrap(f.nativeRelease)))
            XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 6)
            XCTAssertNil(try f.machine.runtimeAuditUpgrade(accountID: f.account.accountID))
        }
    }
    func testWrongAccountIntentCannotAdvanceTheSchema() throws {
        let f = try fixture(), other = try fixture(), foreign = try intent(other)
        XCTAssertThrowsError(try f.machine.retainRuntimeAuditUpgrade(foreign, currentPolicy: other.plan.host.codePolicy, installedRelease: XCTUnwrap(other.nativeRelease)))
        XCTAssertEqual(try f.f.sql("PRAGMA user_version"), 6)
        XCTAssertNil(try f.machine.runtimeAuditUpgrade(accountID: f.account.accountID))
    }
}
