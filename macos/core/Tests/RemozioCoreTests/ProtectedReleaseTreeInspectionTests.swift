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
}
