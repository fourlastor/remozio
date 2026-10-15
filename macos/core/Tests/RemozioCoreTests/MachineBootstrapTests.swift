import Darwin
import Foundation
import SQLite3
import XCTest
@testable import RemozioCore

final class MachineBootstrapTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Fixture {
        let root: URL
        let directory: ProtectedSetupDirectory
        let seed: MachineBootstrap.Seed
        var freshCalls = 0
        var prepareCalls = 0
        var commitHook: (() throws -> Void)?
        var machine: URL { URL(fileURLWithPath: directory.path).appendingPathComponent("Machine") }
        var database: URL { machine.appendingPathComponent("installation.sqlite") }
        init() throws {
            root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remozio-machine-bootstrap-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Shared", owner: getuid(), visibility: .sharedMetadata)
            let policy = try AuthorityCodePolicy(entries: [
                .init(role: .app, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.mac", installedGeneration: 1,
                    minimumGeneration: 1, codeDirectoryHash: Data(repeating: 1, count: 20), active: true),
                .init(role: .setupController, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.setup-controller", installedGeneration: 1,
                    minimumGeneration: 1, codeDirectoryHash: Data(repeating: 2, count: 20), active: true)])
            let config = try AdministrativeSetupConfiguration(machineDirectory: directory.path + "/Machine",
                macID: Data(repeating: 1, count: 16), installationID: Data(repeating: 2, count: 16),
                releaseDigest: Data(repeating: 4, count: 32), codePolicy: policy)
            seed = try .init(configuration: config, inventory: .machineBootstrap(macID: config.macID,
                installationID: config.installationID, revision: Data(repeating: 3, count: 16),
                bundlePath: "/Library/Remozio/Remozio.app", releaseDigest: config.releaseDigest))
        }
        func file(_ kind: AdministrativeSetupPublication.File) -> URL { URL(fileURLWithPath: directory.path).appendingPathComponent(kind.name) }
        func prepare() throws {
            prepareCalls += 1
            let scope = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Shared/Machine", owner: getuid())
            defer { scope.close() }
            _ = try SetupDatabaseFileProvisioning.prepare(directory: scope, kind: .installation, owner: getuid())
        }
        func store(_ initialize: Bool = false, macID: Data? = nil) throws -> PreparationIntentStore {
            try .init(lease: InstallationStorageLease(anchor: root.path, relativeDirectory: "Shared/Machine", owner: getuid()),
                macID: macID ?? seed.configuration.macID, maximumRecords: 2, initialize: initialize, didCommit: commitHook)
        }
        func run(verify: ((MachineBootstrap.Seed) throws -> Void)? = nil,
                 didStage: @escaping (MachineBootstrap.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
            try MachineBootstrap.run(directory: directory, owner: getuid(), fresh: { self.freshCalls += 1; return self.seed },
                requireFreshStorage: {
                    try self.directory.withDirectory { fd in
                        var value = stat()
                        if fstatat(fd, "Machine", &value, AT_SYMLINK_NOFOLLOW) == 0 { throw MachineBootstrapError.existingStorage }
                        guard errno == ENOENT else { throw JournalLeaseError.system(errno) }
                    }
                }, prepareStore: prepare, openStore: { try self.store($0, macID: $1) },
                verify: verify ?? { value in
                    guard value.bytes == self.seed.bytes else { throw MachineBootstrapError.inconsistentState }
                }, didStage: didStage)
        }
        func write(_ bytes: Data, to kind: AdministrativeSetupPublication.File) throws {
            try bytes.write(to: file(kind)); guard chmod(file(kind).path, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
        }
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner fixture") }
        let f = try Fixture()
        defer { f.directory.close(); XCTAssertNoThrow(try FileManager.default.removeItem(at: f.root)) }
        try body(f)
    }

    func testBootstrapRetainsPrivateIdentityInventoryAndImmutableReplay() throws {
        try fixture { f in
            XCTAssertEqual(try f.run(), .created)
            let first = try f.store(), retained = try XCTUnwrap(first.inventory()); try first.close()
            XCTAssertEqual(retained.macID, f.seed.configuration.macID)
            XCTAssertEqual(retained.installationID, f.seed.configuration.installationID)
            XCTAssertTrue(retained.accounts.isEmpty)
            var before = stat(), after = stat()
            XCTAssertEqual(lstat(f.file(.bootstrapIntent).path, &before), 0)
            XCTAssertEqual(try f.run(), .retained)
            XCTAssertEqual(lstat(f.file(.bootstrapIntent).path, &after), 0)
            XCTAssertEqual(before.st_ino, after.st_ino)
            XCTAssertEqual(before.st_mtimespec.tv_sec, after.st_mtimespec.tv_sec)
            XCTAssertEqual(before.st_mtimespec.tv_nsec, after.st_mtimespec.tv_nsec)
            XCTAssertEqual(before.st_ctimespec.tv_sec, after.st_ctimespec.tv_sec)
            XCTAssertEqual(before.st_ctimespec.tv_nsec, after.st_ctimespec.tv_nsec)
            let second = try f.store(); defer { try? second.close() }
            XCTAssertEqual(try second.inventory(), retained)
            XCTAssertEqual(f.freshCalls, 1); XCTAssertEqual(f.prepareCalls, 1)
            for kind: AdministrativeSetupPublication.File in [.startup, .bootstrapIntent, .bootstrapCompletion] {
                var info = stat(); XCTAssertEqual(lstat(f.file(kind).path, &info), 0)
                XCTAssertEqual(info.st_mode & 0o777, 0o600); XCTAssertEqual(info.st_nlink, 1)
            }
        }
    }
    func testEveryInterruptedStageResumesTheSameIdentityWithoutReplacingInventory() throws {
        for interrupted in MachineBootstrap.Stage.allCases {
            try fixture { f in
                XCTAssertThrowsError(try f.run(didStage: { if $0 == interrupted { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
                let intent = try Data(contentsOf: f.file(.bootstrapIntent))
                _ = try f.run()
                XCTAssertEqual(f.freshCalls, 1)
                XCTAssertEqual(try Data(contentsOf: f.file(.bootstrapIntent)), intent)
                let store = try f.store(); defer { try? store.close() }
                let inventory = try XCTUnwrap(store.inventory())
                XCTAssertEqual(inventory.macID, f.seed.inventory.macID)
                XCTAssertEqual(inventory.installationID, f.seed.inventory.installationID)
                XCTAssertEqual(try Data(contentsOf: f.file(.bootstrapCompletion)), intent)
                XCTAssertEqual(try Data(contentsOf: f.file(.startup)), f.seed.configuration.canonicalBytes)
            }
        }
    }
    func testCompletedBootstrapNeverRecreatesMissingOrEmptyMachineDatabase() throws {
        for remove in [true, false] { try fixture { f in
            _ = try f.run()
            if remove { try FileManager.default.removeItem(at: f.database) }
            else { let fd = open(f.database.path, O_WRONLY | O_TRUNC); XCTAssertGreaterThanOrEqual(fd, 0); _ = Darwin.close(fd) }
            XCTAssertThrowsError(try f.run())
            XCTAssertEqual(f.freshCalls, 1); XCTAssertEqual(f.prepareCalls, 1)
            if remove { XCTAssertFalse(FileManager.default.fileExists(atPath: f.database.path)) }
            else { XCTAssertEqual(try Data(contentsOf: f.database), Data()) }
        } }
    }
    func testUnknownMachineStorageWithoutAnIntentIsNotAdopted() throws {
        try fixture { f in
            try f.prepare()
            XCTAssertThrowsError(try f.run()) { XCTAssertEqual($0 as? MachineBootstrapError, .existingStorage) }
            XCTAssertEqual(f.freshCalls, 0)
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.file(.bootstrapIntent).path))
            XCTAssertEqual(try Data(contentsOf: f.database), Data())
        }
    }
    func testPendingBootstrapRejectsUnknownDatabaseWithoutErasingIt() throws {
        try fixture { f in
            XCTAssertThrowsError(try f.run(didStage: { if $0 == .intentRetained { throw Interrupted() } }))
            try f.prepare()
            let bytes = Data("not a sqlite database".utf8); try bytes.write(to: f.database)
            XCTAssertEqual(chmod(f.database.path, 0o600), 0)
            XCTAssertThrowsError(try f.run())
            XCTAssertEqual(try Data(contentsOf: f.database), bytes)
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.file(.startup).path))
        }
    }
    func testPendingBootstrapRejectsAnotherMachineIdentity() throws {
        try fixture { f in
            XCTAssertThrowsError(try f.run(didStage: { if $0 == .intentRetained { throw Interrupted() } }))
            try f.prepare(); let otherID = Data(repeating: 9, count: 16)
            let other = try f.store(true, macID: otherID); try other.close()
            XCTAssertThrowsError(try f.run()) { XCTAssertEqual($0 as? PreparationStoreError, .wrongMac) }
            let retained = try f.store(macID: otherID); defer { try? retained.close() }
            XCTAssertEqual(try retained.records(), [])
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.file(.startup).path))
        }
    }
    func testMissingIntentOrCompletionCannotBeTreatedAsFreshSetup() throws {
        try fixture { f in
            try f.write(f.seed.bytes, to: .bootstrapCompletion)
            XCTAssertThrowsError(try f.run()); XCTAssertEqual(f.freshCalls, 0)
        }
        try fixture { f in
            _ = try f.run(); try FileManager.default.removeItem(at: f.file(.bootstrapCompletion))
            XCTAssertThrowsError(try f.run()); XCTAssertEqual(f.prepareCalls, 1)
        }
    }
    func testChangedReleaseOrCorruptIntentCannotResume() throws {
        try fixture { f in
            _ = try f.run()
            XCTAssertThrowsError(try f.run(verify: { _ in throw Interrupted() }))
            XCTAssertEqual(f.prepareCalls, 1)
            try f.write(f.seed.bytes + Data([0]), to: .bootstrapIntent)
            XCTAssertThrowsError(try f.run()); XCTAssertEqual(f.freshCalls, 1)
        }
    }
    func testReboundParentCannotReceiveNewStorage() throws {
        try fixture { f in
            let moved = f.root.appendingPathComponent("Moved")
            XCTAssertThrowsError(try f.run(didStage: { if $0 == .intentRetained {
                try FileManager.default.moveItem(atPath: f.directory.path, toPath: moved.path)
                try FileManager.default.createDirectory(atPath: f.directory.path, withIntermediateDirectories: false)
                XCTAssertEqual(chmod(f.directory.path, 0o755), 0)
            } }))
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.machine.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: moved.appendingPathComponent("Machine").path))
        }
    }
    func testInventoryCommitWithLostAcknowledgmentIsRecoveredWithoutNewIdentity() throws {
        try fixture { f in
            var commits = 0
            f.commitHook = { commits += 1; if commits == 3 { throw Interrupted() } }
            XCTAssertThrowsError(try f.run()) { XCTAssertTrue($0 is Interrupted) }
            f.commitHook = nil
            let store = try f.store(), retained = try XCTUnwrap(store.inventory()); try store.close()
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.file(.bootstrapCompletion).path))
            _ = try f.run()
            let reopened = try f.store(); defer { try? reopened.close() }
            XCTAssertEqual(try reopened.inventory(), retained); XCTAssertEqual(f.freshCalls, 1)
        }
    }
    func testPendingUpgradedStoreFinishesWithoutRegeneratingIdentity() throws {
        try fixture { f in
            XCTAssertThrowsError(try f.run(didStage: { if $0 == .intentRetained { throw Interrupted() } }))
            try f.prepare()
            let store = try f.store(true); try store.upgradeInventoryStorage(); try store.close()
            XCTAssertEqual(try f.run(), .created); XCTAssertEqual(f.freshCalls, 1)
        }
    }
    func testCompletedReplayPreservesEnrolledAccountsAndInventoryRevision() throws {
        try fixture { f in
            _ = try f.run()
            let store = try f.store(), previous = try XCTUnwrap(store.inventory())
            let account = try InstallationAccount(accountID: Data(repeating: 8, count: 16), ownerUID: getuid())
            let authority = try InstallationService(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
                label: "dev.remozio.authority", plistName: "dev.remozio.authority.plist", accountID: account.accountID)
            let value = try InstallationInventory(macID: previous.macID, installationID: previous.installationID,
                revision: previous.revision, bundlePath: previous.bundlePath, releaseDigest: previous.releaseDigest,
                accounts: [account], services: previous.services + [authority], formatVersion: 2)
            let enrolled = try store.writeInventory(value, expectedRevision: previous.revision); try store.close()
            XCTAssertEqual(try f.run(), .retained)
            let reopened = try f.store(); defer { try? reopened.close() }
            XCTAssertEqual(try reopened.inventory(), enrolled); XCTAssertEqual(f.prepareCalls, 1)
        }
    }
    func testRemovedIntentOrCompletionAtMutationBoundaryStopsConfigurationPublication() throws {
        for (stage, file): (MachineBootstrap.Stage, AdministrativeSetupPublication.File) in [
            (.intentRetained, .bootstrapIntent), (.completionPublished, .bootstrapCompletion)] {
            try fixture { f in
                XCTAssertThrowsError(try f.run(didStage: { if $0 == stage { try FileManager.default.removeItem(at: f.file(file)) } }))
                XCTAssertFalse(FileManager.default.fileExists(atPath: f.file(.startup).path))
                if stage == .intentRetained { XCTAssertFalse(FileManager.default.fileExists(atPath: f.machine.path)) }
            }
        }
    }
    func testCompletionByAnotherAttemptPreventsRecreatingItsLostDatabase() throws {
        try fixture { f in
            var otherAttemptFinished = false
            XCTAssertThrowsError(try f.run(didStage: { stage in
                if stage == .intentRetained && !otherAttemptFinished {
                    otherAttemptFinished = true
                    _ = try f.run()
                    try FileManager.default.removeItem(at: f.database)
                }
            }))
            XCTAssertTrue(otherAttemptFinished)
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.database.path))
            XCTAssertEqual(f.freshCalls, 1)
        }
    }
    func testPublicEntryRequiresRootBeforeAnyProtectedOperation() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-user refusal") }
        XCTAssertThrowsError(try MachineBootstrap.run(teamID: "ABCDEFGHIJ")) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
    }
}
