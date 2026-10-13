import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class ProtectedSetupDirectoryTests: XCTestCase {
    private enum Fault: Error { case interrupted }
    private func fixture(_ body: (URL) throws -> Void) throws {
        guard let resolved = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
        defer { free(resolved) }
        let root = URL(fileURLWithPath: String(cString: resolved)).appendingPathComponent("remozio-directory-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root)
    }
    private func open(_ root: URL, path: String = "state", visibility: ProtectedSetupDirectory.Visibility = .privateState,
                      hook: (ProtectedSetupDirectory.Stage) throws -> Void = { _ in }) throws -> ProtectedSetupDirectory {
        try .init(anchor: root.path, relativePath: path, owner: getuid(), visibility: visibility, didStage: hook)
    }
    private func mode(_ url: URL) throws -> Int {
        let info = try FileManager.default.attributesOfItem(atPath: url.path)
        return try XCTUnwrap(info[.posixPermissions] as? NSNumber).intValue
    }
    private func inode(_ url: URL) throws -> ino_t {
        var info = stat(); guard lstat(url.path, &info) == 0 else { throw JournalLeaseError.system(errno) }; return info.st_ino
    }

    func testPrivateCreationSupportsExistingKeyStorageWithoutCreatingKeys() throws {
        try fixture { root in
            let directory = try open(root); defer { directory.close() }
            XCTAssertTrue(directory.created); XCTAssertEqual(directory.description, "ProtectedSetupDirectory(redacted)")
            XCTAssertEqual(try mode(root.appendingPathComponent("state")), 0o700); try directory.validate()
            let keyStorage = try AuthorityKeyProvisioningStorage(anchor: root.path, relativeDirectory: "state", owner: getuid())
            keyStorage.close()
            XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path + "/authority-key.cbor"))
        }
    }
    func testSharedMetadataCreationSupportsProtectedPublicReader() throws {
        try fixture { root in
            XCTAssertEqual(chmod(root.path, 0o755), 0)
            let directory = try open(root, visibility: .sharedMetadata); defer { directory.close() }
            XCTAssertEqual(try mode(root.appendingPathComponent("state")), 0o755)
            let file = root.appendingPathComponent("state/frontend.cbor"), bytes = Data([1, 2, 3])
            try bytes.write(to: file); XCTAssertEqual(chmod(file.path, 0o644), 0)
            XCTAssertEqual(try ProtectedServiceConfiguration.read(anchor: root.path, relativePath: "state/frontend.cbor",
                owner: getuid(), privateFile: false), bytes)
        }
    }
    func testSharedMetadataRejectsNontraversableAncestorsBeforeCreation() throws {
        try fixture { root in
            for requestedMode in [0o700, 0o750, 0o705, 0o711] {
                XCTAssertEqual(chmod(root.path, mode_t(requestedMode)), 0)
                let name = "blocked-" + String(requestedMode)
                XCTAssertThrowsError(try open(root, path: name, visibility: .sharedMetadata))
                XCTAssertFalse(FileManager.default.fileExists(atPath: root.path + "/" + name))
                XCTAssertEqual(try mode(root), requestedMode)
            }
        }
    }
    func testSharedAncestorLosingTraversalRetiresTheLease() throws {
        try fixture { root in
            XCTAssertEqual(chmod(root.path, 0o755), 0)
            let directory = try open(root, visibility: .sharedMetadata); defer { directory.close() }
            XCTAssertEqual(chmod(root.path, 0o700), 0)
            XCTAssertThrowsError(try directory.validate())
            XCTAssertThrowsError(try directory.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }
    private func chmodACL(_ arguments: [String], path: String) throws {
        let command = Process(); command.executableURL = URL(fileURLWithPath: "/bin/chmod")
        command.arguments = arguments + [path]
        try command.run(); command.waitUntilExit(); XCTAssertEqual(command.terminationStatus, 0)
    }
    func testPublicAccessRejectsACLReadSearchAndMetadataDenials() throws {
        try fixture { root in
            XCTAssertEqual(chmod(root.path, 0o755), 0)
            let fd = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
            for permission in ["search", "list", "readattr", "readsecurity"] {
                try chmodACL(["+a", "everyone deny " + permission], path: root.path)
                do {
                    var info = stat(); XCTAssertEqual(fstat(fd, &info), 0)
                    XCTAssertThrowsError(try ProtectedStorageMetadata.validatePublicDirectoryAccess(fd, info))
                }
                try chmodACL(["-N"], path: root.path)
            }
        }
    }
    func testPublicAccessKeepsUnrelatedAndInheritanceOnlyDenials() throws {
        try fixture { root in
            XCTAssertEqual(chmod(root.path, 0o755), 0)
            try chmodACL(["+a", "everyone deny delete"], path: root.path)
            try chmodACL(["+a", "everyone deny search,directory_inherit,only_inherit"], path: root.path)
            let fd = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(fd, 0); defer { _ = Darwin.close(fd) }
            var info = stat(); XCTAssertEqual(fstat(fd, &info), 0)
            try ProtectedStorageMetadata.validatePublicDirectoryAccess(fd, info)
            let directory = try open(root, visibility: .sharedMetadata); defer { directory.close() }
            try directory.validate()
        }
    }
    func testReopenRetainsInodeContentsAndPermissionsWithoutPreparation() throws {
        try fixture { root in
            let first = try open(root); first.close()
            let state = root.appendingPathComponent("state"), id = try inode(state), file = state.appendingPathComponent("retained")
            try Data([7]).write(to: file)
            let second = try open(root) { _ in XCTFail("Existing directory must not be prepared") }; defer { second.close() }
            XCTAssertFalse(second.created); XCTAssertEqual(try inode(state), id)
            XCTAssertEqual(try Data(contentsOf: file), Data([7])); XCTAssertEqual(try mode(state), 0o700)
        }
    }
    func testUnsafeExistingDirectoryIsNeverRepaired() throws {
        try fixture { root in
            let state = root.appendingPathComponent("state")
            try FileManager.default.createDirectory(at: state, withIntermediateDirectories: false)
            for requestedMode in [0o755, 0o777] {
                XCTAssertEqual(chmod(state.path, mode_t(requestedMode)), 0)
                XCTAssertThrowsError(try open(root))
                XCTAssertEqual(try mode(state), requestedMode)
            }
            XCTAssertEqual(chmod(state.path, 0o700), 0)
            XCTAssertEqual(chmod(root.path, 0o755), 0)
            XCTAssertThrowsError(try open(root, visibility: .sharedMetadata))
            XCTAssertEqual(try mode(state), 0o700)
        }
    }
    func testRejectsFinalFilesAndSymlinksWithoutChangingTheirTargets() throws {
        try fixture { root in
            let final = root.appendingPathComponent("state"), target = root.appendingPathComponent("target")
            try Data([9]).write(to: final); XCTAssertThrowsError(try open(root))
            XCTAssertEqual(try Data(contentsOf: final), Data([9])); try FileManager.default.removeItem(at: final)
            try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
            XCTAssertEqual(chmod(target.path, 0o755), 0)
            XCTAssertEqual(symlink(target.path, final.path), 0); XCTAssertThrowsError(try open(root))
            XCTAssertEqual(try mode(target), 0o755)
        }
    }
    func testMissingUnsafeAndSymlinkedParentsRefuseBeforeCreatingLeaf() throws {
        try fixture { root in
            XCTAssertThrowsError(try open(root, path: "missing/state"))
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.path + "/missing"))
            let parent = root.appendingPathComponent("parent")
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
            XCTAssertEqual(chmod(parent.path, 0o777), 0); XCTAssertThrowsError(try open(root, path: "parent/state"))
            XCTAssertFalse(FileManager.default.fileExists(atPath: parent.path + "/state"))
            XCTAssertEqual(chmod(parent.path, 0o700), 0)
            XCTAssertEqual(symlink(parent.path, root.path + "/alias"), 0)
            XCTAssertThrowsError(try open(root, path: "alias/state"))
            XCTAssertFalse(FileManager.default.fileExists(atPath: parent.path + "/state"))
        }
    }
    func testReplacementRetiresTheHeldDirectory() throws {
        try fixture { root in
            let directory = try open(root); defer { directory.close() }
            try FileManager.default.moveItem(atPath: directory.path, toPath: root.path + "/old")
            let other = try open(root); defer { other.close() }
            XCTAssertThrowsError(try directory.validate())
            XCTAssertThrowsError(try directory.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }
    func testNativePublicationCannotReplaceDestinationCreatedAfterPreparation() throws {
        try fixture { root in
            let final = root.appendingPathComponent("state"); var existing: ino_t?
            XCTAssertThrowsError(try open(root) { stage in
                if stage == .prepared {
                    try FileManager.default.createDirectory(at: final, withIntermediateDirectories: false)
                    XCTAssertEqual(chmod(final.path, 0o700), 0); existing = try self.inode(final)
                }
            })
            XCTAssertEqual(try inode(final), existing)
        }
    }
    func testInheritedReadACLIsRemovedOnlyFromTheNewDirectory() throws {
        try fixture { root in
            let command = Process(); command.executableURL = URL(fileURLWithPath: "/bin/chmod")
            command.arguments = ["+a", "everyone allow read,directory_inherit", root.path]
            try command.run(); command.waitUntilExit(); XCTAssertEqual(command.terminationStatus, 0)
            let existing = root.appendingPathComponent("existing")
            try FileManager.default.createDirectory(at: existing, withIntermediateDirectories: false)
            XCTAssertEqual(chmod(existing.path, 0o700), 0)
            XCTAssertThrowsError(try open(root, path: "existing"))
            let created = try open(root); defer { created.close() }; try created.validate()
            XCTAssertThrowsError(try open(root, path: "existing"))
        }
    }
    func testChangedParentAfterPreparationCannotPublishThroughItsHeldAlias() throws {
        try fixture { root in
            let parent = root.appendingPathComponent("parent"), moved = root.appendingPathComponent("moved")
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
            XCTAssertEqual(chmod(parent.path, 0o700), 0)
            XCTAssertThrowsError(try open(root, path: "parent/state") { stage in
                if stage == .prepared {
                    try FileManager.default.moveItem(at: parent, to: moved)
                    try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
                    XCTAssertEqual(chmod(parent.path, 0o700), 0)
                }
            })
            XCTAssertFalse(FileManager.default.fileExists(atPath: parent.path + "/state"))
            XCTAssertFalse(FileManager.default.fileExists(atPath: moved.path + "/state"))
        }
    }
    func testPreparedInterruptionDoesNotPublishOrBlockASeparateRetry() throws {
        try fixture { root in
            XCTAssertThrowsError(try open(root) { if $0 == .prepared { throw Fault.interrupted } })
            XCTAssertFalse(FileManager.default.fileExists(atPath: root.path + "/state"))
            let retry = try open(root); defer { retry.close() }; XCTAssertTrue(retry.created); try retry.validate()
        }
    }
    func testPublishedInterruptionReopensTheSameDirectory() throws {
        try fixture { root in
            XCTAssertThrowsError(try open(root) { if $0 == .published { throw Fault.interrupted } })
            let before = try inode(root.appendingPathComponent("state"))
            let retry = try open(root); defer { retry.close() }
            XCTAssertFalse(retry.created); XCTAssertEqual(try inode(root.appendingPathComponent("state")), before)
        }
    }
    func testInvalidPathsClosedLeaseAndOrdinaryPublicCallerRefuse() throws {
        try fixture { root in
            for path in ["", "/state", "../state", "state/", "a//state", "a/./state", "a/../state", "bad\0name", String(repeating: "x", count: 256)] {
                XCTAssertThrowsError(try open(root, path: path))
            }
            let directory = try open(root); directory.close(); directory.close()
            XCTAssertThrowsError(try directory.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .closed) }
            if getuid() != 0 {
                XCTAssertThrowsError(try ProtectedSetupDirectory.createOrOpen(path: root.path + "/public-refusal")) {
                    XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                }
                XCTAssertFalse(FileManager.default.fileExists(atPath: root.path + "/public-refusal"))
            }
        }
    }
}
