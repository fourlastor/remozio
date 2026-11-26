import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class ProtectedExecutablePathTests: XCTestCase {
    private final class Fixture {
        let root: String
        var executable: String { root + "/bin/service" }
        init() throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
            defer { free(canonical) }
            root = String(cString: canonical) + "/" + UUID().uuidString
            try FileManager.default.createDirectory(atPath: root + "/bin", withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try Data("executable fixture".utf8).write(to: URL(fileURLWithPath: executable))
            guard chmod(executable, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
        }
        deinit { try? FileManager.default.removeItem(atPath: root) }
        func acquire() throws -> ProtectedExecutablePath {
            try ProtectedExecutablePath(anchor: root, relativePath: "bin/service", owner: getuid())
        }
    }
    func testRetainsValidExecutableAndCloseRetiresIt() throws {
        let fixture = try Fixture(), path = try fixture.acquire()
        XCTAssertEqual(path.path, fixture.executable)
        try path.validate()
        let info = try path.commandExecutableInfo()
        XCTAssertEqual(info.st_size, Int64("executable fixture".utf8.count))
        let protected = CommandExecutableLaunch(mode: .protectedPath, info: info)
        let pathBound = CommandExecutableLaunch(mode: .pathBound, info: info)
        try CommandExecution.requireCurrentExecutable(protected, observed: protected)
        XCTAssertThrowsError(try CommandExecution.requireCurrentExecutable(protected, observed: pathBound)) {
            XCTAssertEqual($0 as? CommandFilesystemCaptureError, .changed)
        }
        try CommandExecution.requireCurrentExecutable(pathBound, observed: pathBound)
        path.close(); path.close()
        XCTAssertThrowsError(try path.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }
    func testReplacementPermanentlyRetiresPath() throws {
        let fixture = try Fixture(), path = try fixture.acquire()
        XCTAssertEqual(rename(fixture.executable, fixture.executable + ".old"), 0)
        try Data("replacement".utf8).write(to: URL(fileURLWithPath: fixture.executable))
        XCTAssertEqual(chmod(fixture.executable, 0o755), 0)
        XCTAssertThrowsError(try path.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try path.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }
    func testRejectsWritableNonExecutableAndSpecialFiles() throws {
        for mode: mode_t in [0o777, 0o775, 0o644, 0o4755] {
            let fixture = try Fixture()
            XCTAssertEqual(chmod(fixture.executable, mode), 0)
            XCTAssertThrowsError(try fixture.acquire())
        }
        for kind in ["symlink", "hardlink", "fifo"] {
            let fixture = try Fixture(), original = fixture.executable + ".old"
            XCTAssertEqual(rename(fixture.executable, original), 0)
            if kind == "symlink" { XCTAssertEqual(symlink(original, fixture.executable), 0) }
            else if kind == "hardlink" { XCTAssertEqual(link(original, fixture.executable), 0) }
            else { XCTAssertEqual(mkfifo(fixture.executable, 0o700), 0) }
            XCTAssertThrowsError(try fixture.acquire())
        }
    }
    func testDetectsContentAndAncestorPermissionChanges() throws {
        let fixture = try Fixture(), path = try fixture.acquire()
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: fixture.executable))
        try handle.seekToEnd(); try handle.write(contentsOf: Data([1])); try handle.close()
        XCTAssertThrowsError(try path.validate())
        let next = try fixture.acquire()
        XCTAssertEqual(chmod(fixture.root + "/bin", 0o777), 0)
        XCTAssertThrowsError(try next.validate())
        XCTAssertThrowsError(try fixture.acquire())
    }
    func testRejectsParentSymlinkAndDetectsDirectoryReplacement() throws {
        let fixture = try Fixture(), path = try fixture.acquire()
        XCTAssertEqual(rename(fixture.root + "/bin", fixture.root + "/old"), 0)
        XCTAssertEqual(symlink(fixture.root + "/old", fixture.root + "/bin"), 0)
        XCTAssertThrowsError(try path.validate())
        XCTAssertThrowsError(try fixture.acquire())
    }
    func testRejectsAmbiguousPathsAndWrongOwner() throws {
        let fixture = try Fixture()
        for relative in ["", "/bin/service", "bin//service", "bin/../service", "bin/./service", "bin/service/", "bin/a\0"] {
            XCTAssertThrowsError(try ProtectedExecutablePath(anchor: fixture.root, relativePath: relative, owner: getuid()))
        }
        XCTAssertThrowsError(try ProtectedExecutablePath(anchor: fixture.root, relativePath: "bin/service", owner: getuid() + 1))
        if geteuid() != 0 {
            XCTAssertThrowsError(try ProtectedExecutablePath.acquire(path: fixture.executable)) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
    func testReadACLAllowedButWriteACLRetiresPath() throws {
        let fixture = try Fixture()
        func acl(_ arguments: [String]) throws {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = arguments
            try process.run(); process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 0)
        }
        defer { try? acl(["-N", fixture.executable]) }
        try acl(["+a", "everyone allow read", fixture.executable])
        let path = try fixture.acquire()
        try path.validate()
        try acl(["+a", "everyone allow write", fixture.executable])
        XCTAssertThrowsError(try path.validate())
        XCTAssertThrowsError(try fixture.acquire())
    }

    func testCommandLaunchMountRequiresBootOwnershipSemantics() throws {
        var system = fsid_t(), data = fsid_t()
        system.val = (11, 1)
        data.val = (12, 1)
        var mount = statfs()
        mount.f_flags = UInt32(MNT_LOCAL)
        mount.f_owner = 0
        for volume in [system, data] {
            mount.f_fsid = volume
            try ProtectedExecutablePath.validateLaunchMount(mount, system: system, data: data)
        }
        mount.f_flags |= UInt32(MNT_IGNORE_OWNERSHIP)
        XCTAssertThrowsError(try ProtectedExecutablePath.validateLaunchMount(mount, system: system, data: data))
        mount.f_flags = UInt32(MNT_LOCAL)
        mount.f_fsid.val = (13, 1)
        XCTAssertThrowsError(try ProtectedExecutablePath.validateLaunchMount(mount, system: system, data: data))
    }

    func testLocalMountMustBeRootOwned() throws {
        var filesystem = statfs()
        filesystem.f_flags = UInt32(MNT_LOCAL)
        filesystem.f_owner = 0
        XCTAssertNoThrow(try ProtectedStorageMetadata.validateMount(filesystem))
        filesystem.f_owner = 501
        XCTAssertThrowsError(try ProtectedStorageMetadata.validateMount(filesystem)) {
            XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
        }
        filesystem.f_owner = 0
        filesystem.f_flags = 0
        XCTAssertThrowsError(try ProtectedStorageMetadata.validateMount(filesystem))
    }

}
