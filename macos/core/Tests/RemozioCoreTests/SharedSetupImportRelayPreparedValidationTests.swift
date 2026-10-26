import Darwin
import Foundation
import XCTest
@testable import RemozioCore

/// Disposable publication and database state prove immutable validation, not native Root or service registration.
final class SharedSetupImportRelayPreparedValidationTests: XCTestCase {
    private struct Interrupted: Error {}
    private final class Fixture {
        let f: SharedSetupRelayConnectorOwnerTests.Fixture
        let base: String
        let directory: ProtectedSetupDirectory
        let bootstrap: TransportPairingStartupConfiguration
        init() throws {
            f = try .init(native: true)
            let h = f.dns.base.h, accountID = f.intent.scope.accountID
            let initialization = try h.machine { try XCTUnwrap($0.initialization(accountID: accountID)) }
            bootstrap = try RuntimeConfigurationBundle.initial(account: h.f.account, initialization: initialization,
                reference: f.runtime, inventory: h.f.inventory, importIntent: f.intent, relayPlan: f.dns.base.plan).transport
            base = "/private/tmp/remozio-retained-relay-" + UUID().uuidString
            try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: false)
            guard chmod(base, 0o755) == 0 else { throw JournalLeaseError.system(errno) }
            directory = try .init(anchor: base, relativePath: "Artifacts", owner: getuid(), visibility: .sharedMetadata)
            let context = try h.machine { try SharedSetupImportRelayPreparedValidation.capture(machine: $0,
                account: h.f.account, retained: f.intent, verifyCurrent: {}).context }
            _ = try RelayConnectorStartupPublication.publishPrepared(context: context, reference: f.reference,
                directory: directory, owner: getuid(), mode: .prepareUnactivated, readBootstrap: { bootstrap.canonicalBytes },
                readToken: { f.token }, verifyCurrent: {})
        }
        deinit { directory.close(); try? FileManager.default.removeItem(atPath: base) }
        var path: String { directory.path + "/" + AdministrativeSetupPublication.File.transportRelayReference.name }
        func validate(token: Data? = nil, hook: (() throws -> Void)? = nil) throws {
            try f.dns.base.h.machine { machine in
                try SharedSetupImportRelayPreparedValidation.validate(machine: machine, account: f.dns.base.h.f.account,
                    retained: f.intent, verifyCurrent: {}) { context, verify in
                    try hook?()
                    _ = try RelayConnectorStartupPublication.publishPrepared(context: context, reference: f.reference,
                        directory: directory, owner: getuid(), mode: .validateRetained,
                        readBootstrap: { bootstrap.canonicalBytes }, readToken: { token ?? f.token }, verifyCurrent: verify)
                }
            }
        }
    }
    private func replace(_ path: String) throws {
        let bytes = try Data(contentsOf: URL(fileURLWithPath: path)), next = path + ".replacement"
        try bytes.write(to: URL(fileURLWithPath: next)); XCTAssertEqual(chmod(next, 0o600), 0); XCTAssertEqual(rename(next, path), 0)
    }
    func testValidationRetainsTheExactFileAndDoesNotAdvanceImportState() throws {
        let h = try Fixture(), bytes = try Data(contentsOf: URL(fileURLWithPath: h.path))
        var first = stat(); XCTAssertEqual(lstat(h.path, &first), 0)
        try h.validate(); try h.validate()
        var last = stat(); XCTAssertEqual(lstat(h.path, &last), 0); XCTAssertEqual(first.st_ino, last.st_ino)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: h.path)), bytes)
        let journal = try h.f.dns.base.h.f.open(); defer { try? journal.close() }
        XCTAssertEqual(try journal.current(scope: h.f.intent.scope), h.f.intent)
    }
    func testMissingStartupMetadataIsNotRepaired() throws {
        let h = try Fixture(); XCTAssertEqual(unlink(h.path), 0)
        XCTAssertThrowsError(try h.validate()); XCTAssertFalse(FileManager.default.fileExists(atPath: h.path))
    }
    func testChangedTokenAndFailedVerificationCannotValidatePublishedMetadata() throws {
        let h = try Fixture(), bytes = try Data(contentsOf: URL(fileURLWithPath: h.path))
        XCTAssertThrowsError(try h.validate(token: Data("changed-selected-token".utf8)))
        XCTAssertThrowsError(try h.validate(hook: { throw Interrupted() }))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: h.path)), bytes)
    }
    func testEveryMissingDependencyRefusesWithoutRecreation() throws {
        for index in 0..<5 {
            let h = try Fixture(), f = h.f, parent = URL(fileURLWithPath: f.dns.path).deletingLastPathComponent()
            let tunnel = parent.appendingPathComponent(AdministrativeSetupPublication.File.importRelayProvisioning(accountID: f.intent.scope.accountID).name).path
            let paths = [f.dns.base.h.path, tunnel, f.dns.base.path, f.dns.path, f.runPath], path = paths[index]
            XCTAssertEqual(unlink(path), 0); XCTAssertThrowsError(try h.validate())
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }
    func testIdenticalDependencyReplacementDuringValidationRefuses() throws {
        for index in 0..<5 {
            let h = try Fixture(), f = h.f, parent = URL(fileURLWithPath: f.dns.path).deletingLastPathComponent()
            let tunnel = parent.appendingPathComponent(AdministrativeSetupPublication.File.importRelayProvisioning(accountID: f.intent.scope.accountID).name).path
            let paths = [f.dns.base.h.path, tunnel, f.dns.base.path, f.dns.path, f.runPath]
            XCTAssertThrowsError(try h.validate(hook: { try self.replace(paths[index]) }))
        }
    }
    func testNativeValidationRefusesAnOrdinaryCallerBeforeOpeningInstalledFiles() throws {
        guard getuid() > 0 else { throw XCTSkip("Ordinary caller required") }
        let f = try SharedSetupRelayConnectorOwnerTests.Fixture(native: true)
        try f.dns.base.h.machine { machine in
            XCTAssertThrowsError(try SharedSetupImportRelayPreparedValidation.validateNative(machine: machine,
                account: f.dns.base.h.f.account, retained: f.intent, verifyCurrent: { XCTFail("Root gate must precede access") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
        }
    }
}
