import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class RelayConnectorStartupReferenceTests: XCTestCase, @unchecked Sendable {
    private struct Interrupted: Error {}
    private typealias Fixture = RelayRunCredentialPublicationTests.Fixture
    private func fixture() throws -> Fixture { try RelayRunCredentialPublicationTests().fixture() }
    private func shared(_ body: (ProtectedSetupDirectory) throws -> Void) throws {
        let base = "/private/tmp/remozio-connector-reference-" + UUID().uuidString
        try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(atPath: base) }
        XCTAssertEqual(chmod(base, 0o755), 0)
        let directory = try ProtectedSetupDirectory(anchor: base, relativePath: "Artifacts", owner: getuid(), visibility: .sharedMetadata)
        defer { directory.close() }; try body(directory)
    }
    private func context(_ f: Fixture, expected: SharedSetupImportIntent? = nil,
                         reference: RelayRunCredentialReference? = nil) -> RelayRunCredentialSetupContext {
        .init(account: f.account, inventory: f.inventory, expected: expected ?? f.expected, plan: f.plan,
            created: f.created, runtime: f.runtime, reference: reference)
    }
    private func publish(_ f: Fixture, _ directory: ProtectedSetupDirectory,
                         reference: RelayRunCredentialReference,
                         mode: RelayRunCredentialPublication.Mode = .prepareUnactivated,
                         expected: SharedSetupImportIntent? = nil, verify: () throws -> Void = {},
                         stage: (AdministrativeSetupPublication.Stage) throws -> Void = { _ in }) throws -> AdministrativeSetupPublicationResult {
        try RelayConnectorStartupPublication.publish(context: context(f, expected: expected, reference: mode == .validateRetained ? reference : nil), reference: reference,
            relayPort: f.plan.port, directory: directory, owner: getuid(), mode: mode, verifyCurrent: verify, didStage: stage)
    }
    private func read(_ f: Fixture, _ directory: ProtectedSetupDirectory) throws -> RelayConnectorStartupReference? {
        try .load(runtime: f.runtime, relayPort: f.plan.port,
            read: { try ProtectedServiceConfiguration.readOptional(anchor: directory.path,
                relativePath: AdministrativeSetupPublication.File.transportRelayReference.name, owner: getuid()) },
            verifyCurrent: { try directory.validate() })
    }
    private func path(_ directory: ProtectedSetupDirectory) -> String {
        directory.path + "/" + AdministrativeSetupPublication.File.transportRelayReference.name
    }
    func testPublicationIsPublicMetadataAndRetainsItsExactBytesAndInode() throws {
        let f = try fixture(), material = try f.material(), reference = try material.reference
        try shared { directory in
            XCTAssertNil(try read(f, directory))
            XCTAssertEqual(try publish(f, directory, reference: reference), .created)
            var first = stat(); XCTAssertEqual(lstat(path(directory), &first), 0)
            XCTAssertEqual(first.st_mode & 0o7777, 0o644); XCTAssertEqual(first.st_uid, getuid())
            XCTAssertEqual(try read(f, directory)?.reference, reference)
            XCTAssertEqual(try publish(f, directory, reference: reference), .retained)
            var retained = stat(); XCTAssertEqual(lstat(path(directory), &retained), 0)
            XCTAssertEqual(first.st_ino, retained.st_ino)
            let bytes = try Data(contentsOf: URL(fileURLWithPath: path(directory)))
            XCTAssertEqual(bytes, try reference.encoded)
            material.withCredentialBytes { XCTAssertNil(bytes.range(of: $0)) }
        }
    }
    func testLostPublicationReplyCanRecoverWithoutReplacingTheAcceptedReference() throws {
        let f = try fixture(), reference = try f.material().reference
        try shared { directory in
            XCTAssertThrowsError(try publish(f, directory, reference: reference,
                stage: { if $0 == .published { throw Interrupted() } }))
            let bytes = try Data(contentsOf: URL(fileURLWithPath: path(directory)))
            XCTAssertEqual(try publish(f, directory, reference: reference), .retained)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(directory))), bytes)
            XCTAssertEqual(try read(f, directory)?.reference, reference)
        }
    }
    func testChangedScopeAndPortCannotPublishAndNoSelectedPortCannotLoad() throws {
        let f = try fixture(), other = try fixture(), reference = try f.material().reference
        try shared { directory in
            XCTAssertThrowsError(try publish(other, directory, reference: reference))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
            XCTAssertThrowsError(try RelayConnectorStartupPublication.publish(context: context(f), reference: reference,
                relayPort: 0, directory: directory, owner: getuid(), mode: .prepareUnactivated, verifyCurrent: {}))
            XCTAssertThrowsError(try RelayConnectorStartupReference.load(runtime: f.runtime, relayPort: nil,
                read: { try reference.encoded }, verifyCurrent: {}))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
        }
    }
    func testOnlyAMissingLeafIsOptionalAndUnsafeOrMalformedFilesRefuse() throws {
        let f = try fixture(), reference = try f.material().reference
        try shared { directory in
            XCTAssertNil(try read(f, directory))
            try Data("malformed".utf8).write(to: URL(fileURLWithPath: path(directory)))
            XCTAssertEqual(chmod(path(directory), 0o644), 0)
            XCTAssertThrowsError(try read(f, directory))
            XCTAssertEqual(unlink(path(directory)), 0)
            XCTAssertEqual(symlink("missing-target", path(directory)), 0)
            XCTAssertThrowsError(try read(f, directory))
            XCTAssertEqual(unlink(path(directory)), 0)
            _ = try publish(f, directory, reference: reference)
            XCTAssertEqual(chmod(path(directory), 0o666), 0)
            XCTAssertThrowsError(try read(f, directory))
            XCTAssertEqual(chmod(path(directory), 0o644), 0)
        }
    }
    func testMetadataChangingDuringLoadAndFailedScopeVerificationCannotSucceed() throws {
        let f = try fixture(), reference = try f.material().reference
        var reads = 0
        XCTAssertThrowsError(try RelayConnectorStartupReference.load(runtime: f.runtime, relayPort: f.plan.port,
            read: { reads += 1; return reads == 1 ? try reference.encoded : nil }, verifyCurrent: {}))
        reads = 0
        XCTAssertThrowsError(try RelayConnectorStartupReference.load(runtime: f.runtime, relayPort: f.plan.port,
            read: { reads += 1; return reads == 1 ? nil : try reference.encoded }, verifyCurrent: {}))
        XCTAssertThrowsError(try RelayConnectorStartupReference.load(runtime: f.runtime, relayPort: f.plan.port,
            read: { XCTFail("Verification did not precede the read"); return nil }, verifyCurrent: { throw Interrupted() }))
        try shared { directory in
            XCTAssertThrowsError(try publish(f, directory, reference: reference, verify: { throw Interrupted() }))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
        }
    }
    func testAcceptedReferenceCannotBeSubstitutedOrLostDuringValidation() throws {
        let f = try fixture(), accepted = try f.material().reference, replacement = try f.material().reference
        XCTAssertNotEqual(accepted, replacement)
        try shared { directory in
            XCTAssertThrowsError(try RelayConnectorStartupPublication.publish(context: context(f, reference: accepted),
                reference: replacement, relayPort: f.plan.port, directory: directory, owner: getuid(),
                mode: .prepareUnactivated, verifyCurrent: {}))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
            _ = try publish(f, directory, reference: accepted)
            let bytes = try Data(contentsOf: URL(fileURLWithPath: path(directory)))
            XCTAssertThrowsError(try RelayConnectorStartupPublication.publish(context: context(f), reference: accepted,
                relayPort: f.plan.port, directory: directory, owner: getuid(), mode: .validateRetained, verifyCurrent: {}))
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path(directory))), bytes)
        }
    }
    func testPostActivationValidationNeverRecreatesMissingAcceptedMetadata() throws {
        let f = try fixture(), reference = try f.material().reference
        let accepted = try f.expected.advanced(to: .gatewayPrepared).advanced(to: .relayPrepared)
        try shared { directory in
            XCTAssertThrowsError(try publish(f, directory, reference: reference, mode: .validateRetained, expected: accepted))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
            XCTAssertThrowsError(try publish(f, directory, reference: reference, expected: accepted))
            XCTAssertFalse(FileManager.default.fileExists(atPath: path(directory)))
            _ = try publish(f, directory, reference: reference)
            XCTAssertEqual(try publish(f, directory, reference: reference, mode: .validateRetained, expected: accepted), .retained)
        }
    }
}
