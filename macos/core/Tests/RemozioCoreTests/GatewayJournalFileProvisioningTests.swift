import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayJournalFileProvisioningTests: XCTestCase {
    private typealias Provisioning = GatewayJournalFileProvisioning
    private struct Interrupted: Error {}
    private func fixture(_ body: (URL, ProtectedSetupDirectory) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner journal file fixture") }
        let root = URL(fileURLWithPath: "/private/tmp/remozio-gateway-journal-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { XCTAssertNoThrow(try FileManager.default.removeItem(at: root)) }
        guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
        let parent = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Service", owner: getuid(), visibility: .sharedMetadata)
        defer { parent.close() }
        try body(root, parent)
    }
    private func prepare(_ parent: ProtectedSetupDirectory, mode: Provisioning.Mode = .createIfAbsent,
                         expected: GatewayJournalFileIdentity? = nil, verify: () throws -> Void = {},
                         stage: (Provisioning.Stage) throws -> Void = { _ in }) throws -> Provisioning.Result {
        try Provisioning.prepare(parent: parent, processOwner: getuid(), serviceUID: getuid(), serviceGID: getgid(),
            mode: mode, expected: expected, verifyCurrent: verify, didStage: stage)
    }
    private func path(_ parent: ProtectedSetupDirectory, _ name: String? = nil) -> String {
        parent.path + "/Gateway" + (name.map { "/" + $0 } ?? "")
    }
    private func metadata(_ path: String) throws -> stat {
        var info = stat(); guard lstat(path, &info) == 0 else { throw JournalLeaseError.system(errno) }; return info
    }

    func testCreatesCompleteEmptyPrivateFilesAndRetainsTheirIdentities() throws {
        try fixture { _, parent in
            let first = try prepare(parent); XCTAssertTrue(first.created)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: parent.path), ["Gateway"])
            XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: path(parent))), ["writer.lock", "gateway.sqlite"])
            for (name, mode): (String?, mode_t) in [(nil, 0o700), ("writer.lock", 0o600), ("gateway.sqlite", 0o600)] {
                let info = try metadata(path(parent, name))
                XCTAssertEqual(info.st_uid, getuid()); XCTAssertEqual(info.st_gid, getgid()); XCTAssertEqual(info.st_mode & 0o7777, mode)
                if name != nil { XCTAssertEqual(info.st_size, 0) }
            }
            let retained = try prepare(parent, mode: .requireExisting, expected: first.identity)
            XCTAssertFalse(retained.created); XCTAssertEqual(retained.identity, first.identity)
            XCTAssertEqual(try prepare(parent).identity, first.identity)
        }
    }
    func testPublishedReplyLossRecoversTheSameFilesWithoutTruncatingExistingData() throws {
        try fixture { _, parent in
            XCTAssertThrowsError(try prepare(parent, stage: { if case .published = $0 { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            let before = try metadata(path(parent, "gateway.sqlite"))
            let bytes = Data("synthetic-existing-database-content".utf8)
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path(parent, "gateway.sqlite")))
            try handle.write(contentsOf: bytes); try handle.close()
            let retained = try prepare(parent)
            XCTAssertFalse(retained.created); XCTAssertEqual(retained.identity.database.inode, before.st_ino)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(parent, "gateway.sqlite"))), bytes)
        }
    }
    func testStagedInterruptionDoesNotExposeTheDestinationAndKeepsTheStageIntact() throws {
        try fixture { _, parent in
            XCTAssertThrowsError(try prepare(parent, stage: { if case .staged = $0 { throw Interrupted() } })) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(parent)))
            let names = try FileManager.default.contentsOfDirectory(atPath: parent.path)
            XCTAssertEqual(names.count, 1); XCTAssertTrue(names[0].hasPrefix(".remozio-gateway-"))
            let stage = parent.path + "/" + names[0]
            XCTAssertEqual(Set(try FileManager.default.contentsOfDirectory(atPath: stage)), ["writer.lock", "gateway.sqlite"])
            XCTAssertThrowsError(try prepare(parent, mode: .requireExisting))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: parent.path), names)
        }
    }
    func testAnExistingIncompleteDirectoryCannotHaveMissingFilesRecreated() throws {
        for missing in ["writer.lock", "gateway.sqlite"] {
            try fixture { _, parent in
                let initial = try prepare(parent)
                try FileManager.default.removeItem(atPath: path(parent, missing))
                XCTAssertThrowsError(try prepare(parent, expected: initial.identity))
                XCTAssertThrowsError(try prepare(parent))
                XCTAssertFalse(FileManager.default.fileExists(atPath: path(parent, missing)))
            }
        }
        try fixture { _, parent in
            XCTAssertThrowsError(try prepare(parent, mode: .requireExisting))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: parent.path), [])
        }
    }
    func testRetainedDirectoryAndFileIdentitiesCannotBeReplaced() throws {
        for name: String? in [nil, "writer.lock", "gateway.sqlite"] {
            try fixture { _, parent in
                let initial = try prepare(parent), target = path(parent, name)
                try FileManager.default.moveItem(atPath: target, toPath: target + ".original")
                if name == nil { _ = try prepare(parent) }
                else { XCTAssertTrue(FileManager.default.createFile(atPath: target, contents: Data(), attributes: [.posixPermissions: 0o600])) }
                XCTAssertThrowsError(try prepare(parent, expected: initial.identity)) {
                    XCTAssertEqual($0 as? JournalLeaseError, .identityChanged)
                }
                XCTAssertTrue(FileManager.default.fileExists(atPath: target + ".original"))
            }
        }
    }
    func testSymlinksAndIncorrectPermissionsAreRejectedWithoutRepair() throws {
        for name: String? in [nil, "writer.lock", "gateway.sqlite"] {
            try fixture { _, parent in
                _ = try prepare(parent)
                let target = path(parent, name), changed: mode_t = name == nil ? 0o755 : 0o644
                XCTAssertEqual(chmod(target, changed), 0)
                XCTAssertThrowsError(try prepare(parent))
                XCTAssertEqual(try metadata(target).st_mode & 0o7777, changed)
            }
            try fixture { _, parent in
                if name != nil { _ = try prepare(parent) }
                let target = path(parent, name)
                if name != nil { try FileManager.default.removeItem(atPath: target) }
                try FileManager.default.createSymbolicLink(atPath: target, withDestinationPath: "/dev/null")
                XCTAssertThrowsError(try prepare(parent))
                XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: target), "/dev/null")
            }
        }
    }
    func testHardLinksAndChangedStagesAreRejectedWithoutPublication() throws {
        try fixture { _, parent in
            _ = try prepare(parent)
            try FileManager.default.linkItem(atPath: path(parent, "gateway.sqlite"), toPath: parent.path + "/alias")
            XCTAssertThrowsError(try prepare(parent)) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
        }
        try fixture { _, parent in
            XCTAssertThrowsError(try prepare(parent, stage: {
                if case .staged = $0 {
                    let name = try XCTUnwrap(FileManager.default.contentsOfDirectory(atPath: parent.path).first)
                    let target = parent.path + "/" + name + "/gateway.sqlite"
                    let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: target))
                    try handle.write(contentsOf: Data("changed".utf8)); try handle.close()
                }
            })) { XCTAssertEqual($0 as? JournalLeaseError, .identityChanged) }
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(parent)))
        }
    }
    func testWriterLeasePreventsConcurrentPreparationAndScopeFailureCreatesNothing() throws {
        try fixture { root, parent in
            _ = try prepare(parent)
            let lease = try ProtectedGatewayLease(anchor: root.path, relativeDirectory: "Service/Gateway", serviceUID: getuid(), ancestorUID: getuid())
            XCTAssertThrowsError(try prepare(parent)) { XCTAssertEqual($0 as? JournalLeaseError, .busy) }
            lease.close(); XCTAssertNoThrow(try prepare(parent))
        }
        try fixture { _, parent in
            XCTAssertThrowsError(try prepare(parent, verify: { throw Interrupted() })) { XCTAssertTrue($0 is Interrupted) }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: parent.path), [])
        }
    }
    func testNativeEntryRefusesOrdinaryIdentityBeforeProtectedOperations() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary-owner control") }
        let f = try RuntimeActivationFixture()
        XCTAssertThrowsError(try Provisioning.prepare(account: f.account, services: f.services, mode: .createIfAbsent,
            expected: nil, verifyCurrent: { XCTFail("No protected access") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
