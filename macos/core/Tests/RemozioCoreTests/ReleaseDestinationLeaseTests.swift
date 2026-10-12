import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class ReleaseDestinationLeaseTests: XCTestCase {
    private func fixture(_ body: (URL, URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-copy-lease-" + UUID().uuidString).standardizedFileURL
        let parent = root.appendingPathComponent("Store/Releases")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root, parent)
    }
    func testPublicEntryPointRefusesOrdinaryIdentityBeforePaths() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary account") }
        XCTAssertThrowsError(try ReleaseDestinationLease.acquire(path: "/missing")) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testLeaseKeepsDirectoryIdentityWhenUnrelatedContentChanges() throws {
        try fixture { root, parent in
            let lease = try ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Store/Releases", owner: geteuid())
            defer { lease.close() }
            try Data([1]).write(to: parent.appendingPathComponent("unrelated"))
            try lease.validate()
            XCTAssertGreaterThanOrEqual(try lease.withDirectory { $0 }, 0)
        }
    }
    func testWritableAncestorIsRejected() throws {
        try fixture { root, _ in
            XCTAssertEqual(chmod(root.appendingPathComponent("Store").path, 0o777), 0)
            XCTAssertThrowsError(try ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Store/Releases", owner: geteuid())) {
                XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
            }
        }
    }
    func testMutationACLIsRejectedEvenWithSafeModeBits() throws {
        try fixture { root, parent in
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
            process.arguments = ["+a", "everyone allow write,delete,writeattr", parent.path]
            try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus, 0)
            XCTAssertThrowsError(try ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Store/Releases", owner: geteuid())) {
                XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
            }
        }
    }
    func testSymlinkedAncestorIsRejected() throws {
        try fixture { root, parent in
            try FileManager.default.moveItem(at: parent.deletingLastPathComponent(), to: root.appendingPathComponent("Moved"))
            try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("Store").path, withDestinationPath: "Moved")
            XCTAssertThrowsError(try ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Store/Releases", owner: geteuid()))
        }
    }
    func testNamedDirectoryReplacementRetiresTheLease() throws {
        try fixture { root, parent in
            let lease = try ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Store/Releases", owner: geteuid())
            try FileManager.default.moveItem(at: parent, to: parent.deletingLastPathComponent().appendingPathComponent("Old"))
            try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
            XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
            XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }
    func testOwnershipAndRelativePathCannotBeClaimedByCaller() throws {
        try fixture { root, _ in
            XCTAssertThrowsError(try ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Store/Releases", owner: geteuid() + 1)) {
                XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
            }
            for path in ["../Releases", "Store//Releases", "Store/./Releases", ""] {
                XCTAssertThrowsError(try ReleaseDestinationLease(anchor: root.path, relativeDirectory: path, owner: geteuid())) {
                    XCTAssertEqual($0 as? JournalLeaseError, .invalidPath)
                }
            }
        }
    }
    func testBoundedCopyUsesTheRetainedDestinationDescriptor() throws {
        try fixture { root, parent in
            let source = root.appendingPathComponent("Source")
            try FileManager.default.createDirectory(at: source, withIntermediateDirectories: true)
            try Data("content".utf8).write(to: source.appendingPathComponent("file"))
            let lease = try ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Store/Releases", owner: geteuid())
            defer { lease.close() }
            let counts = try DescriptorTreeCopy.copy(source: source, destination: lease)
            XCTAssertEqual(counts.files, 1)
            XCTAssertEqual(try Data(contentsOf: parent.appendingPathComponent("Fixture.app/file")), Data("content".utf8))
            try lease.validate()
        }
    }
    func testFailedCallbackCannotHideDestinationReplacement() throws {
        struct Cancelled: Error {}
        try fixture { root, parent in
            let lease = try ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Store/Releases", owner: geteuid())
            XCTAssertThrowsError(try lease.withDirectory { _ -> Void in
                try FileManager.default.moveItem(at: parent, to: parent.deletingLastPathComponent().appendingPathComponent("Old"))
                try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
                throw Cancelled()
            }) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
            XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

    func testSuccessfulCallbackPreservesTheIdentityFailureReason() throws {
        try fixture { root, parent in
            let lease = try ReleaseDestinationLease(anchor: root.path, relativeDirectory: "Store/Releases", owner: geteuid())
            XCTAssertThrowsError(try lease.withDirectory { _ -> Int in
                try FileManager.default.moveItem(at: parent, to: parent.deletingLastPathComponent().appendingPathComponent("Old"))
                try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
                return 1
            }) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
            XCTAssertThrowsError(try lease.validate()) { XCTAssertEqual($0 as? JournalLeaseError, .invalidated) }
        }
    }

}
