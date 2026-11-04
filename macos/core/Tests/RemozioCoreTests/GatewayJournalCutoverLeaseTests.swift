import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewayCutoverLeaseFixture {
    let root: URL
    let parent: ProtectedSetupDirectory
    let identity: GatewayJournalFileIdentity?
    init(present: Bool = true) throws {
        root = URL(fileURLWithPath: "/private/tmp/remozio-gateway-cutover-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
        parent = try .init(anchor: root.path, relativePath: "Services", owner: getuid(), visibility: .sharedMetadata)
        identity = try present ? GatewayJournalFileProvisioning.prepare(parent: parent, processOwner: getuid(),
            serviceUID: getuid(), serviceGID: getgid(), mode: .createIfAbsent, expected: nil, verifyCurrent: {}).identity : nil
    }
    func path(_ name: String) -> String { parent.path + "/Gateway/" + name }
    func open(verify: @escaping () throws -> Void = {}) throws -> GatewayJournalCutoverLease {
        try .openOwned(parent: parent, expected: identity, verifyCurrent: verify)
    }
    func files() throws -> [String: Data] {
        guard identity != nil else { return [:] }
        var result: [String: Data] = [:]
        for name in try FileManager.default.contentsOfDirectory(atPath: parent.path + "/Gateway") {
            result[name] = try Data(contentsOf: URL(fileURLWithPath: path(name)))
        }
        return result
    }
    deinit { parent.close(); try? FileManager.default.removeItem(at: root) }
}
final class GatewayJournalCutoverLeaseTests: XCTestCase {
    private enum Failure: Error { case expected }
    func testExistingDataAndSidecarsArePreservedWhileTheWriterLockStaysExclusive() throws {
        let f = try GatewayCutoverLeaseFixture()
        for name in ["gateway.sqlite", "gateway.sqlite-wal", "gateway.sqlite-shm"] {
            try Data(("fixture " + name).utf8).write(to: URL(fileURLWithPath: f.path(name)))
        }
        let before = try f.files(), lease = try f.open(); defer { lease.close() }
        let observer = Darwin.open(f.path("writer.lock"), O_RDONLY | O_CLOEXEC); XCTAssertGreaterThanOrEqual(observer, 0)
        defer { _ = Darwin.close(observer) }
        try lease.validate(); XCTAssertEqual(try f.files(), before)
        XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), -1); XCTAssertEqual(errno, EWOULDBLOCK)
        lease.close(); XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), 0); XCTAssertEqual(try f.files(), before)
        XCTAssertThrowsError(try lease.validate())
    }
    func testBusyAcquisitionDoesNotReleaseTheOriginalLease() throws {
        let f = try GatewayCutoverLeaseFixture(), first = try f.open(); defer { first.close() }
        XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
        try first.validate(); first.close(); let second = try f.open(); second.close()
    }
    func testAbsentDirectoryRemainsAbsentAndUnexpectedCreationRetiresObservation() throws {
        let f = try GatewayCutoverLeaseFixture(present: false), lease = try f.open(); defer { lease.close() }
        try lease.validate(); XCTAssertFalse(FileManager.default.fileExists(atPath: f.parent.path + "/Gateway"))
        try FileManager.default.createDirectory(atPath: f.parent.path + "/Gateway", withIntermediateDirectories: false)
        XCTAssertThrowsError(try lease.validate()); XCTAssertTrue(FileManager.default.fileExists(atPath: f.parent.path + "/Gateway"))
    }
    func testReplacementRetiresValidationButRetainsTheOldWriterLockThroughCleanup() throws {
        let f = try GatewayCutoverLeaseFixture(), lease = try f.open(); defer { lease.close() }
        let path = f.path("writer.lock"), observer = Darwin.open(path, O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(observer, 0); defer { _ = Darwin.close(observer) }
        XCTAssertEqual(rename(path, path + ".old"), 0)
        let replacement = Darwin.open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
        XCTAssertGreaterThanOrEqual(replacement, 0); _ = Darwin.close(replacement)
        XCTAssertThrowsError(try lease.validate()); XCTAssertThrowsError(try f.open())
        XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), -1)
        lease.close(); XCTAssertEqual(flock(observer, LOCK_EX | LOCK_NB), 0)
    }
    func testChangedDatabaseIdentityAndUnsafeModeAreNeverRepaired() throws {
        for replace in [false, true] {
            let f = try GatewayCutoverLeaseFixture(), lease = try f.open(); defer { lease.close() }
            if replace {
                let path = f.path("gateway.sqlite"); XCTAssertEqual(rename(path, path + ".old"), 0)
                try Data().write(to: URL(fileURLWithPath: path)); XCTAssertEqual(chmod(path, 0o600), 0)
            } else { XCTAssertEqual(chmod(f.path("gateway.sqlite"), 0o644), 0) }
            let before = try f.files(); XCTAssertThrowsError(try lease.validate()); XCTAssertEqual(try f.files(), before)
        }
    }
    func testOwnerFailurePermanentlyRetiresTheLeaseWithoutUnlockingIt() throws {
        let f = try GatewayCutoverLeaseFixture(); var valid = true
        let lease = try f.open { if !valid { throw Failure.expected } }; defer { lease.close() }
        valid = false; XCTAssertThrowsError(try lease.validate()); valid = true; XCTAssertThrowsError(try lease.validate())
        XCTAssertThrowsError(try f.open()) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
    }
}
