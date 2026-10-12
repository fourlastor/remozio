import Darwin
import Foundation
import XCTest
@testable import AttributeInspection

final class AttributeInspectionTests: XCTestCase {
    private func fixture(_ body: (Int32, URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("remozio-xattr-experiment-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("file")
        let fd = open(path.path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { close(fd) }
        try body(fd, path)
    }
    private func set(_ fd: Int32, _ name: String, _ data: Data) {
        XCTAssertEqual(data.withUnsafeBytes { fsetxattr(fd, name, $0.baseAddress, $0.count, 0, 0) }, 0)
    }
    func testFreshFileInventoryContainsOnlyKnownOSMetadata() throws {
        try fixture { fd, _ in
            let names = try AttributeInspection.names(fd: fd)
            XCTAssertTrue(names.isSubset(of: ["com.apple.provenance"]))
        }
    }
    func testResourceForkIsVisibleOnTheHeldDescriptor() throws {
        try fixture { fd, _ in
            set(fd, "com.apple.ResourceFork", Data("resource content".utf8))
            XCTAssertTrue(try AttributeInspection.names(fd: fd).contains("com.apple.ResourceFork"))
        }
    }
    func testFinderInfoIsVisibleOnTheHeldDescriptor() throws {
        try fixture { fd, _ in
            var info = Data(repeating: 0, count: 32); info[0] = 1
            set(fd, "com.apple.FinderInfo", info)
            XCTAssertTrue(try AttributeInspection.names(fd: fd).contains("com.apple.FinderInfo"))
        }
    }
    func testQuarantineAndUnknownAttributesRemainDistinguishable() throws {
        try fixture { fd, _ in
            set(fd, "com.apple.quarantine", Data("0081;00000000;RemozioProbe;".utf8))
            set(fd, "dev.remozio.experiment.content", Data([1]))
            let names = try AttributeInspection.names(fd: fd)
            XCTAssertTrue(names.contains("com.apple.quarantine"))
            XCTAssertTrue(names.contains("dev.remozio.experiment.content"))
        }
    }
    func testBoundsRejectRatherThanTruncateTheInventory() throws {
        try fixture { fd, _ in
            set(fd, "dev.remozio.experiment.first", Data([1]))
            set(fd, "dev.remozio.experiment.second", Data([2]))
            for parameters in [(1,64),(8192,1)] {
                XCTAssertThrowsError(try AttributeInspection.names(fd: fd, maximumBytes: parameters.0, maximumNames: parameters.1)) {
                    XCTAssertEqual($0 as? AttributeError, .limit)
                }
            }
        }
    }
    func testInvalidDescriptorDoesNotBecomeAnEmptyInventory() throws {
        XCTAssertThrowsError(try AttributeInspection.names(fd: -1)) {
            XCTAssertEqual($0 as? AttributeError, .system(EBADF))
        }
    }
    func testSymlinkDescriptorInventoryDoesNotFollowTargetAttributes() throws {
        try fixture { fd, target in
            set(fd, "dev.remozio.experiment.target-only", Data([1]))
            let link = target.deletingLastPathComponent().appendingPathComponent("link")
            try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "file")
            let linkFD = open(link.path, O_RDONLY | O_SYMLINK | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(linkFD, 0); defer { close(linkFD) }
            var info = stat(); XCTAssertEqual(fstat(linkFD, &info), 0)
            XCTAssertEqual(info.st_mode & S_IFMT, S_IFLNK)
            XCTAssertFalse(try AttributeInspection.names(fd: linkFD).contains("dev.remozio.experiment.target-only"))
            XCTAssertTrue(try AttributeInspection.names(fd: fd).contains("dev.remozio.experiment.target-only"))
        }
    }
    func testContradictoryNoFollowAndSymlinkOpenFlagsFail() throws {
        try fixture { _, target in
            let link = target.deletingLastPathComponent().appendingPathComponent("link")
            try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "file")
            let linkFD = open(link.path, O_RDONLY | O_SYMLINK | O_NOFOLLOW | O_CLOEXEC)
            if linkFD >= 0 { close(linkFD) }
            XCTAssertEqual(linkFD, -1)
            XCTAssertEqual(errno, ELOOP)
        }
    }
}
