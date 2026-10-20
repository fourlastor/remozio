import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class ProtectedOptionalConfigurationTests: XCTestCase {
    private func fixture(_ body: (URL) throws -> Void) throws {
        let root = URL(fileURLWithPath: "/private/tmp/remozio-optional-reader-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: root)) }
        XCTAssertEqual(chmod(root.path, 0o755), 0)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("Service"), withIntermediateDirectories: false)
        XCTAssertEqual(chmod(root.appendingPathComponent("Service").path, 0o755), 0)
        try body(root)
    }
    private func read(_ root: URL, _ relative: String = "Service/fence.cbor") throws -> Data? {
        try ProtectedServiceConfiguration.readOptional(anchor: root.path, relativePath: relative, owner: getuid())
    }
    func testOnlyTheFinalMissingLeafCanReturnAbsence() throws {
        try fixture { root in
            XCTAssertNil(try read(root))
            XCTAssertThrowsError(try read(root, "Missing/fence.cbor"))
            XCTAssertThrowsError(try ProtectedServiceConfiguration.readOptional(anchor: root.path + "/Missing", relativePath: "fence.cbor", owner: getuid()))
            XCTAssertThrowsError(try read(root, "Service/../fence.cbor"))
        }
    }
    func testExistingPublicRecordMatchesTheRequiredReaderAndKeepsItsMetadata() throws {
        try fixture { root in
            let path = root.appendingPathComponent("Service/fence.cbor"), bytes = Data([1, 2, 3])
            try bytes.write(to: path); XCTAssertEqual(chmod(path.path, 0o644), 0)
            var before = stat(); XCTAssertEqual(lstat(path.path, &before), 0)
            XCTAssertEqual(try read(root), bytes)
            XCTAssertEqual(try ProtectedServiceConfiguration.read(anchor: root.path, relativePath: "Service/fence.cbor", owner: getuid(), privateFile: false), bytes)
            var after = stat(); XCTAssertEqual(lstat(path.path, &after), 0)
            XCTAssertEqual(before.st_ino, after.st_ino); XCTAssertEqual(before.st_mode, after.st_mode)
        }
    }
    func testUnsafeAncestorAndLeafLinksNeverBecomeAbsence() throws {
        for mode in 0...2 {
            try fixture { root in
                let service = root.appendingPathComponent("Service"), path = service.appendingPathComponent("fence.cbor")
                if mode == 0 { XCTAssertEqual(chmod(service.path, 0o777), 0) }
                if mode == 1 { try FileManager.default.createSymbolicLink(atPath: path.path, withDestinationPath: "/dev/null") }
                if mode == 2 {
                    try FileManager.default.moveItem(atPath: service.path, toPath: service.path + ".original")
                    try FileManager.default.createSymbolicLink(atPath: service.path, withDestinationPath: service.path + ".original")
                }
                XCTAssertThrowsError(try read(root))
            }
        }
    }
    func testEmptyWritableAndMultiplyLinkedRecordsAreRejected() throws {
        for mode in 0...2 {
            try fixture { root in
                let path = root.appendingPathComponent("Service/fence.cbor")
                try (mode == 0 ? Data() : Data([1])).write(to: path); XCTAssertEqual(chmod(path.path, mode == 1 ? 0o666 : 0o644), 0)
                if mode == 2 { XCTAssertEqual(link(path.path, path.path + ".linked"), 0) }
                XCTAssertThrowsError(try read(root))
            }
        }
    }
}
