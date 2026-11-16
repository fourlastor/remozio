import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Real file locks in owned directories. Installed Root startup remains an attended qualification.
final class SetupProcessLeaseTests: XCTestCase {
    private struct FailedChild: Error {}
    private final class Fixture {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-setup-process-" + UUID().uuidString).standardizedFileURL
        var directory: URL { root.appendingPathComponent("Host") }
        var file: URL { directory.appendingPathComponent(SetupProcessLease.fileName) }
        init() throws { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true) }
        deinit { try? FileManager.default.removeItem(at: root) }
        func acquire() throws -> SetupProcessLease {
            try .openOwned(directory: ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Host", owner: getuid()))
        }
        func create() throws {
            let fd = open(file.path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw JournalLeaseError.system(errno) }; _ = Darwin.close(fd)
        }
        func identity() throws -> stat {
            var value = stat(); guard lstat(file.path, &value) == 0 else { throw JournalLeaseError.system(errno) }; return value
        }
    }
    private final class Child {
        let process = Process(), input = Pipe(), output = Pipe(), errors = Pipe()
        init(_ script: String, path: String) throws {
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = ["python3", "-c", script, path]
            process.standardInput = input; process.standardOutput = output; process.standardError = errors
            try process.run()
            guard output.fileHandleForReading.readData(ofLength: 1) == Data("R".utf8) else {
                process.waitUntilExit()
                XCTFail("Child did not acquire its declared state: " + String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
                throw FailedChild()
            }
        }
        func stop() {
            if process.isRunning { process.terminate() }
            process.waitUntilExit()
        }
        deinit { stop() }
    }
    func testNativeFactoryRefusesTheOrdinaryCallerBeforeOpeningTheFixedPath() throws {
        guard getuid() > 0, getuid() == geteuid() else { return XCTFail("Requires the ordinary owner") }
        XCTAssertThrowsError(try SetupProcessLease.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .rootRequired) }
    }
    func testASecondInstanceIsBusyAndDoesNotChangeThePrivateFile() throws {
        let f = try Fixture(), first = try f.acquire(); defer { first.close() }
        let before = try f.identity()
        XCTAssertThrowsError(try f.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        let after = try f.identity()
        XCTAssertEqual(after.st_dev, before.st_dev); XCTAssertEqual(after.st_ino, before.st_ino)
        XCTAssertEqual(after.st_size, 0); XCTAssertEqual(after.st_mode & 0o777, 0o600)
        XCTAssertNoThrow(try first.validate())
    }
    func testCloseIsIdempotentAndDoesNotReleaseTheNextInstance() throws {
        let f = try Fixture(), first = try f.acquire()
        first.close(); let second = try f.acquire(); defer { second.close() }
        first.close()
        XCTAssertThrowsError(try first.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertThrowsError(try f.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        try second.validate()
    }
    func testADeadProcessLeavesTheSameStaleFileForNormalAcquisition() throws {
        let f = try Fixture()
        let child = try Child("""
        import os, sys, fcntl
        fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(1, b'R')
        sys.stdin.buffer.read(1)
        """, path: f.file.path)
        let before = try f.identity()
        XCTAssertThrowsError(try f.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        child.stop()
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1)], ofItemAtPath: f.file.path)
        let next = try f.acquire(); defer { next.close() }
        XCTAssertEqual(try f.identity().st_ino, before.st_ino); XCTAssertEqual(try Data(contentsOf: f.file).count, 0)
        try next.validate()
    }
    func testAnExecutedChildDoesNotRetainTheLeaseAfterItsOwnerCloses() throws {
        let f = try Fixture(), first = try f.acquire()
        let child = try Child("import os, sys; os.write(1, b'R'); sys.stdin.buffer.read(1)", path: f.file.path)
        first.close()
        let next = try f.acquire(); defer { next.close() }
        XCTAssertTrue(child.process.isRunning); try next.validate()
        child.stop()
    }
    func testSymlinkIsRefusedWithoutChangingItsTarget() throws {
        let f = try Fixture(), target = f.root.appendingPathComponent("Target")
        try Data("preserve".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: f.file, withDestinationURL: target)
        XCTAssertThrowsError(try f.acquire()); XCTAssertEqual(try Data(contentsOf: target), Data("preserve".utf8))
    }
    func testHardLinkedFileIsRefusedWithoutRemovingEitherName() throws {
        let f = try Fixture(); try f.create()
        let alias = f.root.appendingPathComponent("Alias")
        XCTAssertEqual(link(f.file.path, alias.path), 0)
        XCTAssertThrowsError(try f.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        XCTAssertEqual(try f.identity().st_nlink, 2)
    }
    func testPublicModeAndNonemptyFilesAreRefusedWithoutRepair() throws {
        let f = try Fixture(); try f.create()
        XCTAssertEqual(chmod(f.file.path, 0o644), 0)
        XCTAssertThrowsError(try f.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        XCTAssertEqual(try f.identity().st_mode & 0o777, 0o644)
        XCTAssertEqual(chmod(f.file.path, 0o600), 0)
        let writer = try FileHandle(forWritingTo: f.file); try writer.write(contentsOf: Data([7])); try writer.close()
        XCTAssertThrowsError(try f.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        XCTAssertEqual(try Data(contentsOf: f.file), Data([7]))
    }
    func testFifoIsRefusedWithoutBlocking() throws {
        let f = try Fixture(); XCTAssertEqual(mkfifo(f.file.path, 0o600), 0)
        XCTAssertThrowsError(try f.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
    }
    func testPrivateFileAclIsRefused() throws {
        let f = try Fixture(); try f.create()
        let child = Process(); child.executableURL = URL(fileURLWithPath: "/bin/chmod")
        child.arguments = ["+a", "everyone allow read", f.file.path]
        try child.run(); child.waitUntilExit(); XCTAssertEqual(child.terminationStatus, 0)
        XCTAssertThrowsError(try f.acquire()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
    }
    func testReplacedFileRetiresTheLeaseButKeepsTheOldKernelLockUntilClose() throws {
        let f = try Fixture(), lease = try f.acquire(), old = f.directory.appendingPathComponent("Old")
        try FileManager.default.moveItem(at: f.file, to: old); try f.create()
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        let probe = open(old.path, O_RDWR | O_CLOEXEC); XCTAssertGreaterThanOrEqual(probe, 0)
        defer { if probe >= 0 { _ = Darwin.close(probe) } }
        XCTAssertEqual(flock(probe, LOCK_EX | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        lease.close(); XCTAssertEqual(flock(probe, LOCK_EX | LOCK_NB), 0)
    }
    func testMetadataFailureKeepsTheKernelLockUntilClose() throws {
        let f = try Fixture(), lease = try f.acquire()
        XCTAssertEqual(chmod(f.file.path, 0o644), 0)
        XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        let probe = open(f.file.path, O_RDWR | O_CLOEXEC); XCTAssertGreaterThanOrEqual(probe, 0)
        defer { if probe >= 0 { _ = Darwin.close(probe) } }
        XCTAssertEqual(flock(probe, LOCK_EX | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        lease.close(); XCTAssertEqual(flock(probe, LOCK_EX | LOCK_NB), 0)
    }
}
