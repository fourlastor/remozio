import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class AdministrativeSetupPublicationTests: XCTestCase {
    private struct Fixture {
        let root: URL
        let directory: ProtectedSetupDirectory
        var file: URL { URL(fileURLWithPath: directory.path).appendingPathComponent("setup.cbor") }
        init() throws {
            root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remozio-setup-publication-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Shared", owner: getuid(), visibility: .sharedMetadata)
        }
    }
    private func fixture(_ body: (Fixture) throws -> Void) throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner fixture") }
        let f = try Fixture()
        defer { f.directory.close(); XCTAssertNoThrow(try FileManager.default.removeItem(at: f.root)) }
        try body(f)
    }
    private func configuration(_ release: UInt8 = 3) throws -> AdministrativeSetupConfiguration {
        let policy = try AuthorityCodePolicy(entries: [
            .init(role: .app, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.mac", installedGeneration: 1,
                minimumGeneration: 1, codeDirectoryHash: Data(repeating: 1, count: 20), active: true),
            .init(role: .setupController, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.setup-controller", installedGeneration: 1,
                minimumGeneration: 1, codeDirectoryHash: Data(repeating: 2, count: 20), active: true)])
        return try .init(machineDirectory: "/Library/Remozio/Machine", macID: Data(repeating: 1, count: 16),
            installationID: Data(repeating: 2, count: 16), releaseDigest: Data(repeating: release, count: 32), codePolicy: policy)
    }
    private func metadata(_ file: URL) throws -> stat {
        var value = stat(); guard lstat(file.path, &value) == 0 else { throw JournalLeaseError.system(errno) }; return value
    }

    func testPrivatePublicationAndMatchingReplayPreserveTheExistingFile() throws {
        try fixture { f in
            let value = try configuration()
            XCTAssertEqual(try AdministrativeSetupPublication.publish(value, directory: f.directory, owner: getuid()), .created)
            let first = try metadata(f.file)
            XCTAssertEqual(first.st_uid, getuid()); XCTAssertEqual(first.st_mode & 0o777, 0o600); XCTAssertEqual(first.st_nlink, 1)
            XCTAssertEqual(try Data(contentsOf: f.file), value.canonicalBytes)
            XCTAssertEqual(try AdministrativeSetupPublication.publish(value, directory: f.directory, owner: getuid()), .retained)
            let second = try metadata(f.file)
            XCTAssertEqual(first.st_ino, second.st_ino)
            XCTAssertEqual(first.st_mtimespec.tv_sec, second.st_mtimespec.tv_sec)
            XCTAssertEqual(first.st_mtimespec.tv_nsec, second.st_mtimespec.tv_nsec)
            XCTAssertEqual(first.st_ctimespec.tv_sec, second.st_ctimespec.tv_sec)
            XCTAssertEqual(first.st_ctimespec.tv_nsec, second.st_ctimespec.tv_nsec)
        }
    }

    func testConflictingExistingConfigurationIsNeverReplaced() throws {
        try fixture { f in
            let first = try configuration()
            _ = try AdministrativeSetupPublication.publish(first, directory: f.directory, owner: getuid())
            XCTAssertThrowsError(try AdministrativeSetupPublication.publish(configuration(4), directory: f.directory, owner: getuid())) {
                XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
            }
            XCTAssertEqual(try Data(contentsOf: f.file), first.canonicalBytes)
        }
    }

    func testExistingLinksAndPublicPermissionsAreRefused() throws {
        for kind in 0...2 {
            try fixture { f in
                let value = try configuration(), other = f.root.appendingPathComponent("Other")
                try value.canonicalBytes.write(to: other); XCTAssertEqual(chmod(other.path, 0o600), 0)
                if kind == 0 { try FileManager.default.createSymbolicLink(at: f.file, withDestinationURL: other) }
                else if kind == 1 { XCTAssertEqual(link(other.path, f.file.path), 0) }
                else { try value.canonicalBytes.write(to: f.file); XCTAssertEqual(chmod(f.file.path, 0o644), 0) }
                XCTAssertThrowsError(try AdministrativeSetupPublication.publish(value, directory: f.directory, owner: getuid()))
                XCTAssertEqual(try Data(contentsOf: other), value.canonicalBytes)
            }
        }
    }

    func testFailedFinalVerificationDoesNotPublishOrLeaveAnOwnedStagingFile() throws {
        struct Refused: Error {}
        try fixture { f in
            var calls = 0
            XCTAssertThrowsError(try AdministrativeSetupPublication.publish(configuration(), directory: f.directory, owner: getuid(),
                verify: { calls += 1; if calls == 2 { throw Refused() } })) { XCTAssertTrue($0 is Refused) }
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.file.path))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.directory.path), [])
        }
    }

    func testLostPublicationAcknowledgmentCanReadTheRetainedIdenticalFile() throws {
        struct LostAcknowledgment: Error {}
        try fixture { f in
            let value = try configuration()
            XCTAssertThrowsError(try AdministrativeSetupPublication.publish(value, directory: f.directory, owner: getuid(),
                didStage: { if case .published = $0 { throw LostAcknowledgment() } })) { XCTAssertTrue($0 is LostAcknowledgment) }
            let retained = try metadata(f.file)
            XCTAssertEqual(try Data(contentsOf: f.file), value.canonicalBytes)
            XCTAssertEqual(try AdministrativeSetupPublication.publish(value, directory: f.directory, owner: getuid()), .retained)
            XCTAssertEqual(try metadata(f.file).st_ino, retained.st_ino)
        }
    }

    func testReboundDirectoryCannotReceiveThePublication() throws {
        try fixture { f in
            let moved = f.root.appendingPathComponent("Moved")
            XCTAssertThrowsError(try AdministrativeSetupPublication.publish(configuration(), directory: f.directory, owner: getuid(),
                didStage: { stage in
                    if case .staged = stage {
                        try FileManager.default.moveItem(atPath: f.directory.path, toPath: moved.path)
                        try FileManager.default.createDirectory(atPath: f.directory.path, withIntermediateDirectories: false)
                        XCTAssertEqual(chmod(f.directory.path, 0o755), 0)
                    }
                }))
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.file.path))
            XCTAssertFalse(FileManager.default.fileExists(atPath: moved.appendingPathComponent("setup.cbor").path))
        }
    }

    func testSubstitutedOrModifiedStagingFileIsRejectedBeforePublication() throws {
        for substitute in [true, false] { try fixture { f in
            let replacement = try configuration(4).canonicalBytes
            XCTAssertThrowsError(try AdministrativeSetupPublication.publish(configuration(), directory: f.directory, owner: getuid(),
                didStage: { stage in
                    if case .staged = stage {
                        let name = try XCTUnwrap(FileManager.default.contentsOfDirectory(atPath: f.directory.path).first)
                        let path = URL(fileURLWithPath: f.directory.path).appendingPathComponent(name)
                        if substitute { try FileManager.default.removeItem(at: path) }
                        try replacement.write(to: path)
                        XCTAssertEqual(chmod(path.path, 0o600), 0)
                    }
                }))
            XCTAssertFalse(FileManager.default.fileExists(atPath: f.file.path))
        } }
    }

    func testPublicPublisherRejectsOrdinaryUserBeforeReadingOrWritingProtectedPaths() throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-user refusal") }
        XCTAssertThrowsError(try AdministrativeSetupPublication.publish(configuration())) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
