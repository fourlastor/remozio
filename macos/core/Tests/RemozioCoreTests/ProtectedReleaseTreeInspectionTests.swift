import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class ProtectedReleaseTreeInspectionTests: XCTestCase {
    private func fixture(_ body: (URL, ReleaseDestinationLease) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-placement-unit-" + UUID().uuidString)
        let parent = root.appendingPathComponent("Target"), source = root.appendingPathComponent("Source")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: source, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        XCTAssertEqual(chmod(root.path, 0o700), 0)
        try Data("data".utf8).write(to: source.appendingPathComponent("file"))
        try FileManager.default.createDirectory(at: source.appendingPathComponent("nested"), withIntermediateDirectories: false)
        try Data("abc".utf8).write(to: source.appendingPathComponent("nested/file"))
        try FileManager.default.createSymbolicLink(atPath: source.appendingPathComponent("alias").path, withDestinationPath: "nested/file")
        let lease = try ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Target", owner: geteuid())
        defer { lease.close() }
        _ = try DescriptorTreeCopy.copy(source: source, destination: lease)
        try body(parent.appendingPathComponent("Fixture.app"), lease)
    }

    func testWholeTreeCountsEachNodeAndDoesNotFollowTheAlias() throws {
        try fixture { _, lease in
            let value = try lease.inspectCopiedTree(name: "Fixture.app")
            XCTAssertEqual(value.entries, 4); XCTAssertEqual(value.files, 2)
            XCTAssertEqual(value.links, 1); XCTAssertEqual(value.bytes, 7)
        }
    }
    func testWritableCopiedFileIsRejected() throws {
        try fixture { copy, lease in
            XCTAssertEqual(chmod(copy.appendingPathComponent("file").path, 0o666), 0)
            XCTAssertThrowsError(try lease.inspectCopiedTree(name: "Fixture.app")) {
                XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
            }
        }
    }
    func testMutationACLOnCopiedFileIsRejected() throws {
        try fixture { copy, lease in
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = ["+a", "everyone allow write,writeattr,writeextattr", copy.appendingPathComponent("file").path]
            try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus, 0)
            XCTAssertThrowsError(try lease.inspectCopiedTree(name: "Fixture.app")) {
                XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
            }
        }
    }
    func testHardlinkAddedAfterCopyIsRejected() throws {
        try fixture { copy, lease in
            XCTAssertEqual(link(copy.appendingPathComponent("file").path, copy.appendingPathComponent("hardlink").path), 0)
            XCTAssertThrowsError(try lease.inspectCopiedTree(name: "Fixture.app")) {
                XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
            }
        }
    }
    func testInspectionHasAggregateBounds() throws {
        try fixture { _, lease in
            for limits in [try ReleaseCopyLimits(entries: 1), try ReleaseCopyLimits(depth: 0), try ReleaseCopyLimits(bytes: 1)] {
                XCTAssertThrowsError(try lease.inspectCopiedTree(name: "Fixture.app", limits: limits)) {
                    XCTAssertEqual($0 as? ReleaseCopyError, .limit)
                }
            }
            XCTAssertThrowsError(try lease.inspectCopiedTree(name: "../Fixture.app")) {
                XCTAssertEqual($0 as? ReleaseCopyError, .invalidInput)
            }
        }
    }
    func testClosedLeaseCannotInspectACopy() throws {
        try fixture { _, lease in
            lease.close()
            XCTAssertThrowsError(try lease.inspectCopiedTree(name: "Fixture.app")) {
                XCTAssertEqual($0 as? JournalLeaseError, .invalidated)
            }
        }
    }
    func testPublicPreparationRefusesOrdinaryIdentityBeforePolicyOrSourceAccess() throws {
        struct UnexpectedRead: Error {}
        try fixture { _, lease in
            var read = false
            XCTAssertThrowsError(try ProtectedReleasePreparation.prepare(source: URL(fileURLWithPath: "/missing"),
                destination: lease, bundleName: "Other.app", readPolicy: { read = true; throw UnexpectedRead() })) {
                    XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
                }
            XCTAssertFalse(read)
        }
    }

    private func descriptor(_ path: URL, _ body: (Int32) throws -> Void) throws {
        var info = stat()
        guard lstat(path.path, &info) == 0 else { throw JournalLeaseError.system(errno) }
        let flags = O_RDONLY | O_CLOEXEC | (info.st_mode & S_IFMT == S_IFLNK ? O_SYMLINK : O_NOFOLLOW | O_NONBLOCK)
        let fd = open(path.path, flags)
        guard fd >= 0 else { throw JournalLeaseError.system(errno) }
        defer { close(fd) }
        try body(fd)
    }
    private func attribute(_ fd: Int32, _ name: String, _ value: Data) throws {
        guard value.withUnsafeBytes({ fsetxattr(fd, name, $0.baseAddress, $0.count, 0, 0) }) == 0 else {
            throw JournalLeaseError.system(errno)
        }
    }
    private func rejectsMetadata(_ lease: ReleaseDestinationLease) {
        XCTAssertThrowsError(try lease.inspectCopiedTree(name: "Fixture.app")) {
            XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
        }
    }
    func testUnexpectedAttributeOnCopiedFileIsRejected() throws {
        try fixture { copy, lease in
            try descriptor(copy.appendingPathComponent("file")) { fd in
                try attribute(fd, "dev.remozio.fixture", Data([1]))
                rejectsMetadata(lease)
            }
        }
    }
    func testUnexpectedAttributeOnCopiedDirectoryIsRejected() throws {
        try fixture { copy, lease in
            try descriptor(copy.appendingPathComponent("nested")) { fd in
                try attribute(fd, "dev.remozio.fixture", Data([1]))
                rejectsMetadata(lease)
            }
        }
    }
    func testUnexpectedAttributeOnCopiedLinkIsRejected() throws {
        try fixture { copy, lease in
            try descriptor(copy.appendingPathComponent("alias")) { fd in
                try attribute(fd, "dev.remozio.fixture", Data([1]))
                rejectsMetadata(lease)
            }
        }
    }
    func testCopiedResourceFinderAndQuarantineAttributesAreRejected() throws {
        try fixture { copy, lease in
            try descriptor(copy.appendingPathComponent("file")) { fd in
                let attributes = [("com.apple.ResourceFork", Data([1])),
                    ("com.apple.FinderInfo", Data([1]) + Data(repeating: 0, count: 31)),
                    ("com.apple.quarantine", Data("0081;00000000;RemozioFixture;".utf8))]
                for (name, value) in attributes {
                    try attribute(fd, name, value)
                    defer { XCTAssertEqual(fremovexattr(fd, name, 0), 0) }
                    rejectsMetadata(lease)
                }
            }
        }
    }
    func testCopiedFileAndDirectoryFlagsAreRejected() throws {
        try fixture { copy, lease in
            for name in ["file", "nested"] {
                try descriptor(copy.appendingPathComponent(name)) { fd in
                    XCTAssertEqual(fchflags(fd, UInt32(UF_NODUMP)), 0)
                    defer { XCTAssertEqual(fchflags(fd, 0), 0) }
                    rejectsMetadata(lease)
                }
                XCTAssertNoThrow(try lease.inspectCopiedTree(name: "Fixture.app"))
            }
        }
    }
    func testInvalidMetadataDescriptorCannotBecomeAnEmptyInventory() {
        XCTAssertThrowsError(try CopiedReleaseMetadata.validate(-1, stat())) {
            XCTAssertEqual($0 as? JournalLeaseError, .system(EBADF))
        }
    }
}
