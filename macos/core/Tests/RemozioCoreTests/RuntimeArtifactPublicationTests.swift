import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RuntimeArtifactPublicationTests: XCTestCase {
    private typealias File = AdministrativeSetupPublication.File
    private struct Fixture {
        let root: URL
        let directory: ProtectedSetupDirectory
        init(shared: Bool) throws {
            root = URL(fileURLWithPath: "/private/tmp").appendingPathComponent("remozio-runtime-publication-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            guard chmod(root.path, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            directory = try ProtectedSetupDirectory(anchor: root.path, relativePath: "Artifacts", owner: getuid(),
                visibility: shared ? .sharedMetadata : .privateState)
        }
        func path(_ file: File) -> String { directory.path + "/" + file.name }
        func metadata(_ file: File) throws -> stat {
            var value = stat()
            guard lstat(path(file), &value) == 0 else { throw JournalLeaseError.system(errno) }
            return value
        }
        func publish(_ bytes: Data, file: File,
                     didStage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
            try AdministrativeSetupPublication.publish(bytes, file: file, directory: directory, owner: getuid(), didStage: didStage)
        }
    }
    private func fixture(shared: Bool = true, _ body: (Fixture) throws -> Void) throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Ordinary-owner file fixture") }
        let value = try Fixture(shared: shared)
        defer { value.directory.close(); XCTAssertNoThrow(try FileManager.default.removeItem(at: value.root)) }
        try body(value)
    }
    private var transport: File { .transportIdentity(ownerUID: getuid(), groupID: getgid()) }

    func testPublicClientAndTransportMetadataHasExactModesAndMatchingReplay() throws {
        try fixture { f in
            let files: [File] = [.transportConfiguration, .presenceClient(ownerUID: getuid()), .pairingClient(ownerUID: getuid())]
            XCTAssertEqual(Set(files.map(\.name)).count, files.count)
            for file in files {
                let bytes = Data(("disposable-" + file.name).utf8)
                XCTAssertEqual(try f.publish(bytes, file: file), .created)
                let before = try f.metadata(file)
                XCTAssertEqual(before.st_mode & 0o777, 0o644)
                XCTAssertEqual(before.st_uid, getuid())
                XCTAssertEqual(try ProtectedServiceConfiguration.read(anchor: f.directory.path, relativePath: file.name,
                    owner: getuid(), privateFile: false), bytes)
                XCTAssertEqual(try f.publish(bytes, file: file), .retained)
                let after = try f.metadata(file)
                XCTAssertEqual(before.st_ino, after.st_ino)
                XCTAssertEqual(before.st_ctimespec.tv_sec, after.st_ctimespec.tv_sec)
                XCTAssertEqual(before.st_ctimespec.tv_nsec, after.st_ctimespec.tv_nsec)
            }
        }
    }

    func testRootRecordsAndCommandInputsRemainPrivate() throws {
        try fixture(shared: false) { f in
            for file: File in [.runtimeRecord, .commandConfiguration, .elevationPolicy] {
                let bytes = Data("private-runtime-input".utf8)
                XCTAssertEqual(try f.publish(bytes, file: file), .created)
                XCTAssertEqual(try f.metadata(file).st_mode & 0o777, 0o600)
                XCTAssertEqual(try f.publish(bytes, file: file), .retained)
            }
        }
    }

    func testTransportKeySurvivesLostAcknowledgmentAndRetainsItsPin() throws {
        struct LostAcknowledgment: Error {}
        try fixture { f in
            let now = Date(), file = transport
            let material = try TransportFileIdentity.create(notValidBefore: now.addingTimeInterval(-60),
                notValidAfter: now.addingTimeInterval(600))
            // Same-owner bytes prove recovery, not Root-to-service ownership transfer or account isolation.
            XCTAssertThrowsError(try f.publish(material.encoded, file: file, didStage: {
                if case .published = $0 { throw LostAcknowledgment() }
            })) { XCTAssertTrue($0 is LostAcknowledgment) }
            let before = try f.metadata(file)
            XCTAssertEqual(before.st_mode & 0o777, 0o600)
            XCTAssertEqual(before.st_uid, getuid()); XCTAssertEqual(before.st_gid, getgid())
            XCTAssertEqual(try f.publish(material.encoded, file: file), .retained)
            XCTAssertEqual(try f.metadata(file).st_ino, before.st_ino)
            let retained = try ProtectedServiceConfiguration.read(anchor: f.directory.path, relativePath: file.name,
                owner: getuid(), ancestorOwner: getuid())
            XCTAssertNoThrow(try TransportFileIdentity.load(bytes: retained, publicKeyInfo: material.subjectPublicKeyInfo))
            XCTAssertThrowsError(try f.publish(Data("replacement-identity".utf8), file: file)) {
                XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .conflictingConfiguration)
            }
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path(file))), material.encoded)
        }
    }

    func testServiceReadableFilesCannotBePublishedBelowAPrivateDirectory() throws {
        try fixture(shared: false) { f in
            for file: File in [.transportConfiguration, .presenceClient(ownerUID: getuid()), .pairingClient(ownerUID: getuid()), transport] {
                XCTAssertThrowsError(try f.publish(Data([1]), file: file)) {
                    XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata)
                }
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.directory.path), [])
        }
    }

    func testInvalidInteractiveAndServiceIdentifiersAreRefusedBeforeWrites() throws {
        try fixture { f in
            for file: File in [.presenceClient(ownerUID: 0), .pairingClient(ownerUID: UInt32.max),
                .transportIdentity(ownerUID: 0, groupID: getgid()), .transportIdentity(ownerUID: getuid(), groupID: 0),
                .transportIdentity(ownerUID: UInt32.max, groupID: getgid()), .transportIdentity(ownerUID: getuid(), groupID: UInt32.max)] {
                XCTAssertThrowsError(try f.publish(Data([1]), file: file)) {
                    XCTAssertEqual($0 as? AdministrativeSetupPublicationError, .invalidArtifact)
                }
            }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.directory.path), [])
        }
    }

    func testRetainedPermissionsAndGroupAreNeverRepaired() throws {
        for (file, changedMode): (File, mode_t) in [(.transportConfiguration, 0o600), (transport, 0o644)] {
            try fixture { f in
                let bytes = Data("retained-input".utf8)
                _ = try f.publish(bytes, file: file)
                XCTAssertEqual(chmod(f.path(file), changedMode), 0)
                let before = try f.metadata(file)
                XCTAssertThrowsError(try f.publish(bytes, file: file))
                let after = try f.metadata(file)
                XCTAssertEqual(before.st_ino, after.st_ino)
                XCTAssertEqual(after.st_mode & 0o777, changedMode)
                XCTAssertEqual(before.st_ctimespec.tv_sec, after.st_ctimespec.tv_sec)
                XCTAssertEqual(before.st_ctimespec.tv_nsec, after.st_ctimespec.tv_nsec)
            }
        }
        try fixture { f in
            let bytes = Data("retained-input".utf8)
            _ = try f.publish(bytes, file: transport)
            let changed = File.transportIdentity(ownerUID: getuid(), groupID: getgid() + 1)
            XCTAssertThrowsError(try f.publish(bytes, file: changed))
            XCTAssertEqual(try f.metadata(transport).st_gid, getgid())
        }
    }

    func testTamperedServiceKeyStageCannotBePublished() throws {
        try fixture { f in
            XCTAssertThrowsError(try f.publish(Data("original".utf8), file: transport, didStage: {
                if case .staged = $0 {
                    let name = try XCTUnwrap(FileManager.default.contentsOfDirectory(atPath: f.directory.path).first)
                    let path = URL(fileURLWithPath: f.directory.path).appendingPathComponent(name)
                    try Data("modified".utf8).write(to: path)
                }
            }))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.directory.path), [])
        }
    }

    func testLostAcknowledgmentCannotHideChangedPublicPermissions() throws {
        try fixture { f in
            let file = File.transportConfiguration, bytes = Data("public-configuration".utf8)
            XCTAssertThrowsError(try f.publish(bytes, file: file, didStage: {
                if case .published = $0 { XCTAssertEqual(chmod(f.path(file), 0o600), 0) }
            })) { XCTAssertEqual($0 as? JournalLeaseError, .unsafeMetadata) }
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.path(file))), bytes)
            XCTAssertEqual(try f.metadata(file).st_mode & 0o777, 0o600)
            XCTAssertThrowsError(try f.publish(bytes, file: file))
            XCTAssertEqual(try f.metadata(file).st_mode & 0o777, 0o600)
        }
    }

    func testOrdinaryFixtureCannotPublishAsAnotherServiceUID() throws {
        try fixture { f in
            let foreign = File.transportIdentity(ownerUID: getuid() + 1000, groupID: getgid())
            XCTAssertThrowsError(try f.publish(Data("disposable".utf8), file: foreign))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.directory.path), [])
        }
    }
}
