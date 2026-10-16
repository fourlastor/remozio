import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class SetupDatabaseFileProvisioningTests: XCTestCase {
    private enum Fault: Error { case interrupted }
    private func fixture(_ body: (URL, ProtectedSetupDirectory) throws -> Void) throws {
        guard let resolved = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
        defer { free(resolved) }
        let root = URL(fileURLWithPath: String(cString: resolved)).appendingPathComponent("remozio-store-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "store", owner: getuid())
        defer { directory.close() }; try body(root, directory)
    }
    private func prepare(_ directory: ProtectedSetupDirectory, kind: SetupDatabaseKind = .journal,
                         hook: (SetupDatabaseFileProvisioning.Stage) throws -> Void = { _ in }) throws -> SetupDatabaseFiles {
        try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: kind, owner: getuid(), didStage: hook)
    }
    private func place(_ directory: ProtectedSetupDirectory, name: String, bytes: Data, mode: mode_t = 0o600) throws {
        let path = directory.path + "/" + name; try bytes.write(to: URL(fileURLWithPath: path)); XCTAssertEqual(chmod(path, mode), 0)
    }
    private func inode(_ path: String) throws -> ino_t {
        var info = stat(); guard lstat(path, &info) == 0 else { throw JournalLeaseError.system(errno) }; return info.st_ino
    }
    private func journal(_ root: URL, initialize: Bool) throws -> JournalDatabase {
        let bounds = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        return try JournalDatabase(lease: ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
            macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            recordLimits: bounds, descriptorLimits: bounds, decisionLimits: bounds, maximumConsumptions: 10,
            busyMilliseconds: 100, initialize: initialize)
    }
    func testFreshFilesSupportActualJournalInitializationAndRetainedReopen() throws {
        try fixture { root, directory in
            let first = try prepare(directory)
            XCTAssertEqual(first.createdFileNames, ["writer.lock", "journal.sqlite"])
            XCTAssertEqual(first.description, "SetupDatabaseFiles(redacted)")
            let database = try journal(root, initialize: true)
            XCTAssertEqual(try database.read { try $0.storageSchemaVersion }, 12); try database.close()
            let path = directory.path + "/journal.sqlite", before = try Data(contentsOf: URL(fileURLWithPath: path)), id = try inode(path)
            XCTAssertTrue(try prepare(directory).createdFileNames.isEmpty)
            XCTAssertEqual(try inode(path), id); XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), before)
            let retained = try journal(root, initialize: false); defer { try? retained.close() }
            XCTAssertEqual(try retained.read { try $0.storageSchemaVersion }, 12)
        }
    }
    func testFreshFilesSupportActualInstallationStoreInitialization() throws {
        try fixture { root, directory in
            XCTAssertEqual(try prepare(directory, kind: .installation).createdFileNames, ["writer.lock", "activity.lock", "installation.sqlite"])
            let store = try PreparationIntentStore(lease: InstallationStorageLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: Data(repeating: 1, count: 16), maximumRecords: 64, initialize: true)
            try store.upgradeInventoryStorage(); XCTAssertNil(try store.inventory()); try store.close()
            XCTAssertTrue(try prepare(directory, kind: .installation).createdFileNames.isEmpty)
            let restored = try PreparationIntentStore(lease: InstallationStorageLease(anchor: root.path, relativeDirectory: "store", owner: getuid()),
                macID: Data(repeating: 1, count: 16), maximumRecords: 64, initialize: false)
            defer { try? restored.close() }; XCTAssertNil(try restored.inventory())
        }
    }
    func testMissingInstallationActivityFileIsNotRecreated() throws {
        try fixture { _, directory in
            _ = try prepare(directory, kind: .installation)
            let path = directory.path + "/activity.lock"
            XCTAssertEqual(unlink(path), 0)
            XCTAssertThrowsError(try prepare(directory, kind: .installation)) {
                XCTAssertEqual($0 as? JournalLeaseError, .system(ENOENT))
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }
    func testInterruptedActivityPublicationRecoversBeforeDatabaseCreation() throws {
        try fixture { _, directory in
            XCTAssertThrowsError(try prepare(directory, kind: .installation) { stage in
                if stage == .published("activity.lock") { throw Fault.interrupted }
            })
            let path = directory.path + "/activity.lock", identity = try inode(path)
            XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path + "/installation.sqlite"))
            XCTAssertEqual(try prepare(directory, kind: .installation).createdFileNames, ["installation.sqlite"])
            XCTAssertEqual(try inode(path), identity)
        }
    }
    func testNonemptyInstallationActivityFileIsNotRepaired() throws {
        try fixture { _, directory in
            try place(directory, name: "activity.lock", bytes: Data([1]))
            XCTAssertThrowsError(try prepare(directory, kind: .installation)) {
                XCTAssertEqual($0 as? JournalLeaseError, .identityChanged)
            }
            XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path + "/installation.sqlite"))
        }
    }

    func testContinuityFilesSatisfyTheIndependentProtectedLease() throws {
        try fixture { root, directory in
            XCTAssertEqual(try prepare(directory, kind: .continuity).createdFileNames, ["writer.lock", "continuity.sqlite"])
            let lease = try ProtectedContinuityLease(anchor: root.path, relativeDirectory: "store", owner: getuid())
            defer { lease.close() }; try lease.validate()
        }
    }
    func testExistingBytesAndBothFileIdentitiesRemainUnchanged() throws {
        try fixture { _, directory in
            try place(directory, name: "writer.lock", bytes: Data([5])); try place(directory, name: "journal.sqlite", bytes: Data([9, 8]))
            let lock = try inode(directory.path + "/writer.lock"), database = try inode(directory.path + "/journal.sqlite")
            XCTAssertTrue(try prepare(directory).createdFileNames.isEmpty)
            XCTAssertEqual(try inode(directory.path + "/writer.lock"), lock); XCTAssertEqual(try inode(directory.path + "/journal.sqlite"), database)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: directory.path + "/writer.lock")), Data([5]))
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: directory.path + "/journal.sqlite")), Data([9, 8]))
        }
    }
    func testBusyWriterPreventsDatabaseCreation() throws {
        try fixture { _, directory in
            try place(directory, name: "writer.lock", bytes: Data())
            let fd = Darwin.open(directory.path + "/writer.lock", O_RDWR | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
            XCTAssertEqual(flock(fd, LOCK_EX | LOCK_NB), 0)
            XCTAssertThrowsError(try prepare(directory)) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path + "/journal.sqlite"))
        }
    }
    func testActiveActualJournalLeasePreventsProvisioning() throws {
        try fixture { root, directory in
            _ = try prepare(directory)
            let lease = try ProtectedJournalLease(anchor: root.path, relativeDirectory: "store", owner: getuid()); defer { lease.close() }
            XCTAssertThrowsError(try prepare(directory)) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            try lease.validate()
        }
    }
    func testUnsafeRetainedFilesAreNotRepaired() throws {
        try fixture { _, directory in
            try place(directory, name: "writer.lock", bytes: Data(), mode: 0o644)
            XCTAssertThrowsError(try prepare(directory))
            XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path + "/journal.sqlite"))
            XCTAssertEqual(chmod(directory.path + "/writer.lock", 0o600), 0)
            try place(directory, name: "journal.sqlite", bytes: Data([7]), mode: 0o644)
            XCTAssertThrowsError(try prepare(directory))
            let attrs = try FileManager.default.attributesOfItem(atPath: directory.path + "/journal.sqlite")
            XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o644)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: directory.path + "/journal.sqlite")), Data([7]))
        }
    }
    func testSymlinkFIFOAndHardlinkAliasAreRejected() throws {
        for artifact in 0...2 {
            try fixture { root, directory in
                try place(directory, name: "writer.lock", bytes: Data())
                let final = directory.path + "/journal.sqlite", target = root.path + "/target"
                try Data([7]).write(to: URL(fileURLWithPath: target)); XCTAssertEqual(chmod(target, 0o600), 0)
                if artifact == 0 { XCTAssertEqual(symlink(target, final), 0) }
                else if artifact == 1 { XCTAssertEqual(mkfifo(final, 0o600), 0) }
                else { XCTAssertEqual(link(target, final), 0) }
                XCTAssertThrowsError(try prepare(directory))
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: target)), Data([7]))
            }
        }
    }
    func testCompetingPublicationCannotReplaceAnEmptyDestination() throws {
        try fixture { _, directory in
            try place(directory, name: "writer.lock", bytes: Data())
            let final = directory.path + "/journal.sqlite"; var id: ino_t?
            XCTAssertThrowsError(try prepare(directory) { stage in
                if stage == .prepared("journal.sqlite") { try self.place(directory, name: "journal.sqlite", bytes: Data()); id = try self.inode(final) }
            })
            XCTAssertEqual(try inode(final), id)
        }
    }
    func testPreparedInterruptionRetriesWithoutAdoptingStagingBytes() throws {
        try fixture { _, directory in
            XCTAssertThrowsError(try prepare(directory) { if $0 == .prepared("journal.sqlite") { throw Fault.interrupted } })
            XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path + "/journal.sqlite"))
            XCTAssertEqual(try prepare(directory).createdFileNames, ["journal.sqlite"])
        }
    }
    func testPublishedInterruptionKeepsThePublishedIdentity() throws {
        try fixture { _, directory in
            XCTAssertThrowsError(try prepare(directory) { if $0 == .published("journal.sqlite") { throw Fault.interrupted } })
            let before = try inode(directory.path + "/journal.sqlite")
            XCTAssertTrue(try prepare(directory).createdFileNames.isEmpty)
            XCTAssertEqual(try inode(directory.path + "/journal.sqlite"), before)
        }
    }
    func testClosedAndReplacedDirectoriesPreventFileCreation() throws {
        try fixture { root, directory in
            try FileManager.default.moveItem(atPath: directory.path, toPath: root.path + "/old")
            let other = try ProtectedSetupDirectory(anchor: root.path, relativePath: "store", owner: getuid()); defer { other.close() }
            XCTAssertThrowsError(try prepare(directory))
            XCTAssertFalse(FileManager.default.fileExists(atPath: other.path + "/writer.lock"))
        }
        try fixture { _, directory in
            directory.close(); XCTAssertThrowsError(try prepare(directory))
        }
    }
    func testPublicationCallbackCannotUseAClosedBorrowedDirectory() throws {
        try fixture { _, directory in
            XCTAssertThrowsError(try prepare(directory) { stage in
                if stage == .published("writer.lock") { directory.close() }
            }) { XCTAssertEqual($0 as? JournalLeaseError, .closed) }
        }
    }
    func testFullDatabasePathBudgetRefusesBeforeCreatingFiles() throws {
        try fixture { root, _ in
            var parts = ["long"]
            var path = root.appendingPathComponent("long").path
            while path.utf8.count + 101 < Int(PATH_MAX) - 40 {
                parts.append(String(repeating: "x", count: 100)); path += "/" + parts.last!
            }
            let remaining = Int(PATH_MAX) - 10 - path.utf8.count - 1
            XCTAssertGreaterThan(remaining, 0); XCTAssertLessThanOrEqual(remaining, 255)
            parts.append(String(repeating: "z", count: remaining)); path += "/" + parts.last!
            try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            XCTAssertEqual(chmod(path, 0o700), 0)
            let long = try ProtectedSetupDirectory(anchor: root.path, relativePath: parts.joined(separator: "/"), owner: getuid())
            defer { long.close() }
            XCTAssertThrowsError(try prepare(long, kind: .installation)) { XCTAssertEqual($0 as? JournalLeaseError, .invalidPath) }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: path), [])
        }
    }
    func testSharedDirectoryWrongOwnerAndOrdinaryPublicAPIRefuse() throws {
        try fixture { root, directory in
            XCTAssertThrowsError(try SetupDatabaseFileProvisioning.prepare(directory: directory, kind: .journal, owner: UInt32.max))
            XCTAssertEqual(chmod(root.path, 0o755), 0)
            let shared = try ProtectedSetupDirectory(anchor: root.path, relativePath: "shared", owner: getuid(), visibility: .sharedMetadata)
            defer { shared.close() }; XCTAssertThrowsError(try prepare(shared))
            XCTAssertFalse(FileManager.default.fileExists(atPath: shared.path + "/writer.lock"))
            if getuid() != 0 {
                XCTAssertThrowsError(try SetupDatabaseFileProvisioning.prepare(directoryPath: root.path + "/refused", kind: .journal)) {
                    XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                }
                XCTAssertFalse(FileManager.default.fileExists(atPath: root.path + "/refused"))
            }
        }
    }
}
