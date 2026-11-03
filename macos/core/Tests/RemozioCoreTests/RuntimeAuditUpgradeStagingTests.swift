import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeAuditUpgradeStagingTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Fixture {
        let runtime: RuntimeActivationFixture
        let directory: ProtectedSetupDirectory
        let record: RuntimeAuditUpgradeRecord
        let target: RuntimePreparationMaterial
        var activityValid = true
        init() throws {
            runtime = try .init(nativeConsumerHosts: true, phoneAudit: true, auditDelivery: true, materialAuditDelivery: false)
            directory = try .init(anchor: runtime.f.root.path, relativePath: "audit-runtime", owner: getuid())
            _ = try AdministrativeSetupPublication.publish(runtime.material.encoded, file: .runtimeRecord, directory: directory, owner: getuid())
            target = try RuntimeAuditMaterialUpgrade.prepare(material: runtime.material, expected: runtime.material.reference,
                account: runtime.account, activity: XCTUnwrap(runtime.material.serviceActivity),
                installedRelease: XCTUnwrap(runtime.nativeRelease), policy: runtime.plan.host.codePolicy)
            let intent = try RuntimeAuditUpgradeIntent(source: runtime.material.reference, target: target.reference, policy: runtime.plan.host.codePolicy)
            record = try runtime.machine.retainRuntimeAuditUpgrade(intent, currentPolicy: runtime.plan.host.codePolicy,
                installedRelease: XCTUnwrap(runtime.nativeRelease))
        }
        deinit { directory.close() }
        var sourcePath: String { directory.path + "/" + AdministrativeSetupPublication.File.runtimeRecord.name }
        var targetFile: AdministrativeSetupPublication.File { .auditUpgradeMaterial(intentID: record.intent.id) }
        var targetPath: String { directory.path + "/" + targetFile.name }
        func stage(expected: RuntimeAuditUpgradeRecord? = nil,
                   hook: (RuntimeAuditUpgradeStaging.Stage) throws -> Void = { _ in },
                   publication: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> RuntimeAuditUpgradeRecord {
            try RuntimeAuditUpgradeStaging.stageOwned(machine: runtime.machine, account: runtime.account,
                expected: expected ?? record, currentPolicy: runtime.plan.host.codePolicy,
                installedRelease: XCTUnwrap(runtime.nativeRelease), directory: directory, owner: getuid(), verifyCurrent: {},
                verifyActivity: { activity in
                    guard self.activityValid, activity == self.runtime.material.serviceActivity else { throw Interrupted() }
                }, didStage: hook, publicationStage: publication)
        }
    }
    private func fixture() throws -> Fixture {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owned publication fixture") }
        return try .init()
    }
    func testStagesPrivateCandidateBeforeItsMarkerAndLeavesTheSourceAndRuntimeReferenceUntouched() throws {
        let f = try fixture(), source = try Data(contentsOf: URL(fileURLWithPath: f.sourcePath))
        let state = try f.stage()
        XCTAssertEqual(state.phase, .materialStaged)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.targetPath)), try f.target.encoded)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.sourcePath)), source)
        XCTAssertEqual(try f.runtime.machine.runtimePreparation(accountID: f.runtime.account.accountID).reference, try f.runtime.material.reference)
        var info = stat(); XCTAssertEqual(lstat(f.targetPath, &info), 0)
        XCTAssertEqual(info.st_mode & 0o777, 0o600); XCTAssertEqual(info.st_nlink, 1)
        XCTAssertEqual(try f.stage(), state)
        var after = stat(); XCTAssertEqual(lstat(f.targetPath, &after), 0); XCTAssertEqual(after.st_ino, info.st_ino)
    }
    func testEveryInterruptedCoordinatorStageRecoversTheSameKeyAndIntent() throws {
        for stop in RuntimeAuditUpgradeStaging.Stage.allCases {
            let f = try fixture(), original = try Data(contentsOf: URL(fileURLWithPath: f.sourcePath))
            XCTAssertThrowsError(try f.stage(hook: { if $0 == stop { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            let result = try f.stage()
            XCTAssertEqual(result.intent, f.record.intent); XCTAssertEqual(result.phase, .materialStaged)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.targetPath)), try f.target.encoded)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.sourcePath)), original)
            XCTAssertEqual(try f.runtime.machine.runtimePreparation(accountID: f.runtime.account.accountID).reference, try f.runtime.material.reference)
        }
    }
    func testPublicationInterruptionBeforeAndAfterRenameDoesNotRequireAReplacementKey() throws {
        for published in [false, true] {
            let f = try fixture()
            XCTAssertThrowsError(try f.stage(publication: { stage in
                if (published && stage == .published) || (!published && stage == .staged) { throw Interrupted() }
            })) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertEqual(try f.runtime.machine.runtimeAuditUpgrade(accountID: f.runtime.account.accountID)?.phase, .retained)
            XCTAssertEqual(FileManager.default.fileExists(atPath: f.targetPath), published)
            _ = try f.stage()
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.targetPath)), try f.target.encoded)
        }
    }
    func testMissingStagedCandidateIsRebuiltFromTheSameRetainedSourceWithoutChangingTheMarker() throws {
        let f = try fixture(), staged = try f.stage(), before = try Data(contentsOf: URL(fileURLWithPath: f.targetPath))
        try FileManager.default.removeItem(atPath: f.targetPath)
        XCTAssertEqual(try f.stage(), staged)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.targetPath)), before)
    }
    func testMissingOrChangedSourceCannotCreateACandidateOrRegenerateMaterial() throws {
        for missing in [false, true] {
            let f = try fixture()
            if missing { try FileManager.default.removeItem(atPath: f.sourcePath) }
            else { try Data("invalid source".utf8).write(to: URL(fileURLWithPath: f.sourcePath)) }
            XCTAssertThrowsError(try f.stage())
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.targetPath))
            XCTAssertEqual(try f.runtime.machine.runtimeAuditUpgrade(accountID: f.runtime.account.accountID), f.record)
        }
    }
    func testConflictingCandidateAndDestinationLinkAreNeverReplaced() throws {
        for link in [false, true] {
            let f = try fixture(), source = try Data(contentsOf: URL(fileURLWithPath: f.sourcePath))
            let conflict = Data("conflicting private artifact".utf8)
            if link { try FileManager.default.createSymbolicLink(atPath: f.targetPath, withDestinationPath: f.sourcePath) }
            else { _ = try AdministrativeSetupPublication.publish(conflict, file: f.targetFile, directory: f.directory, owner: getuid()) }
            XCTAssertThrowsError(try f.stage())
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.sourcePath)), source)
            if !link { XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.targetPath)), conflict) }
            else { XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: f.targetPath), f.sourcePath) }
            XCTAssertEqual(try f.runtime.machine.runtimeAuditUpgrade(accountID: f.runtime.account.accountID), f.record)
        }
    }
    func testActivityFailureBeforePublicationAndAfterReadbackCannotAdvanceTheLedger() throws {
        for later in [false, true] {
            let f = try fixture(); f.activityValid = later
            XCTAssertThrowsError(try f.stage(hook: { if later && $0 == .candidateVerified { f.activityValid = false } }))
            XCTAssertEqual(try f.runtime.machine.runtimeAuditUpgrade(accountID: f.runtime.account.accountID), f.record)
            XCTAssertEqual(FileManager.default.fileExists(atPath: f.targetPath), later)
        }
    }
    func testNativeEntryAndMalformedIntentFileNameFailBeforeScopeOrFilesystemWork() throws {
        let f = try fixture()
        XCTAssertThrowsError(try AdministrativeSetupPublication.File.auditUpgradeMaterial(intentID: Data()).validate())
        XCTAssertFalse(f.targetFile.requiresSharedDirectory); XCTAssertEqual(f.targetFile.mode, 0o600)
        XCTAssertThrowsError(try RuntimeAuditUpgradeStaging.stage(machine: f.runtime.machine, account: f.runtime.account,
            expected: f.record, currentPolicy: f.runtime.plan.host.codePolicy, installedRelease: XCTUnwrap(f.runtime.nativeRelease),
            verifyCurrent: { XCTFail("Root guard must precede scope access") })) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.targetPath))
    }
}
