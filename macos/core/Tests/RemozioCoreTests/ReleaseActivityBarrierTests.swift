import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class ReleaseActivityFixture {
    let root: URL
    let directory: URL
    init() throws {
        guard let path = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
        defer { free(path) }
        root = URL(fileURLWithPath: String(cString: path)).appendingPathComponent("remozio-activity-" + UUID().uuidString)
        directory = root.appendingPathComponent("Machine")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let fd = Darwin.open(directory.appendingPathComponent(ReleaseActivityBarrier.fileName).path,
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }; _ = Darwin.close(fd)
    }
    func open() throws -> ReleaseActivityBarrier {
        try .init(directory: ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Machine", owner: getuid()), owner: getuid())
    }
    deinit { try? FileManager.default.removeItem(at: root) }
}

final class ReleaseActivityBarrierTests: XCTestCase {
    func testRootEntryPointRefusesOrdinaryIdentityBeforeOpeningPaths() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary owner") }
        XCTAssertThrowsError(try ReleaseActivityBarrier.open(machineDirectory: "/missing")) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testIndependentSharedOwnersExcludeInstallerUntilTheLastReferenceCloses() throws {
        let fixture = try ReleaseActivityFixture(), first = try fixture.open(), second = try fixture.open(), installer = try fixture.open()
        let one = try first.acquireShared(), two = try first.acquireShared(), three = try second.acquireShared()
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        one.close(); one.close(); three.close()
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        try two.validate(); two.close()
        let update = try installer.acquireExclusive(); defer { update.close() }
        XCTAssertThrowsError(try first.acquireShared()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        XCTAssertThrowsError(try installer.acquireExclusive()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
        XCTAssertThrowsError(try installer.acquireShared()) { XCTAssertEqual($0 as? ReleaseActivityError, .busy) }
    }
    func testFailedAutomaticAttemptAllowsAnotherRequestWithoutDraining() throws {
        let fixture = try ReleaseActivityFixture(), authority = try fixture.open(), installer = try fixture.open()
        let pending = try authority.acquireShared()
        XCTAssertThrowsError(try installer.acquireExclusive())
        let another = try authority.acquireShared(); pending.close(); another.close()
        let update = try installer.acquireExclusive(); update.close()
        let retry = try authority.acquireShared(); try retry.validate(); retry.close()
    }
    func testTokenDeinitReleasesItsReferenceAndClosedTokensCannotValidate() throws {
        let fixture = try ReleaseActivityFixture(), authority = try fixture.open(), installer = try fixture.open()
        var token: ReleaseActivityToken? = try authority.acquireShared()
        XCTAssertNotNil(token); XCTAssertThrowsError(try installer.acquireExclusive())
        token = nil
        let update = try installer.acquireExclusive(); update.close()
        XCTAssertThrowsError(try update.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
    }
    func testReplacementRetiresNewWorkButKeepsTheOldInodeLockedThroughCleanup() throws {
        let fixture = try ReleaseActivityFixture(), authority = try fixture.open()
        let token = try authority.acquireShared(), path = fixture.directory.appendingPathComponent("activity.lock").path
        let observer = Darwin.open(path, O_RDWR | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(observer, 0); defer { _ = Darwin.close(observer) }
        XCTAssertEqual(rename(path, path + ".old"), 0)
        let replacement = Darwin.open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(replacement, 0); _ = Darwin.close(replacement)
        XCTAssertThrowsError(try token.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
        XCTAssertThrowsError(try authority.acquireShared()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        token.close(); XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), 0)
    }
    func testMissingUnsafeAndNonemptyFilesAreNeverRepaired() throws {
        for mutation in 0..<4 {
            let fixture = try ReleaseActivityFixture(), path = fixture.directory.appendingPathComponent("activity.lock").path
            if mutation == 0 { XCTAssertEqual(unlink(path), 0) }
            else if mutation == 1 { XCTAssertEqual(chmod(path, 0o644), 0) }
            else if mutation == 2 { try Data([1]).write(to: URL(fileURLWithPath: path)) }
            else { XCTAssertEqual(link(path, path + ".alias"), 0) }
            XCTAssertThrowsError(try fixture.open())
            if mutation == 0 { XCTAssertFalse(FileManager.default.fileExists(atPath: path)) }
        }
    }
    func testManyRequestReferencesKeepTheInstallerExcludedUntilAllClose() throws {
        let fixture = try ReleaseActivityFixture(), authority = try fixture.open(), installer = try fixture.open()
        let tokens = try (0..<4096).map { _ in try authority.acquireShared() }
        XCTAssertThrowsError(try installer.acquireExclusive())
        for token in tokens { token.close() }
        let update = try installer.acquireExclusive(); update.close()
    }
}
