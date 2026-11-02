import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandFrontendConfigurationTests: XCTestCase {
    private func configuration() throws -> CommandFrontendConfiguration {
        try CommandFrontendConfiguration(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            serviceName: "dev.sebastiano.remozio.macos.commands", teamID: "ABCDEFGHIJ", authorityIdentifier: "dev.sebastiano.remozio.macos.authority",
            authorityHashes: [Data(repeating: 4, count: 20), Data(repeating: 3, count: 20)],
            submissionLimits: CBORLimits(maxBytes: 262144, maxDepth: 16, maxItems: 4096),
            defaultIOMode: .pipes, defaultDisconnectBehavior: .terminate,
            readiness: CommandCallerReadinessConfiguration(timeoutMilliseconds: 30000))
    }
    private func changed(_ key: UInt64, _ value: CBORValue?) throws -> Data {
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 3, maxItems: 128)
        guard case .map(var fields) = try DeterministicCBOR.decode(configuration().canonicalBytes, limits: limits) else {
            throw CommandFrontendConfigurationError.invalidConfiguration
        }
        fields[key] = value
        return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    func testRoundTripFixesRootIdentityWithoutSecretOrStorageFields() throws {
        let value = try configuration(), loaded = try CommandFrontendConfiguration.decode(value.canonicalBytes)
        XCTAssertEqual(loaded.canonicalBytes, value.canonicalBytes)
        XCTAssertEqual(loaded.authorityPolicy.expectedUserID, 0)
        XCTAssertNil(loaded.authorityPolicy.expectedAuditSessionID)
        XCTAssertEqual(loaded.authorityPolicy.requirement, value.authorityPolicy.requirement)
        XCTAssertEqual(loaded.macID, value.macID); XCTAssertEqual(loaded.accountID, value.accountID)
        XCTAssertEqual(loaded.submissionLimits.maxBytes, 262144)
        XCTAssertEqual(loaded.defaultIOMode, .pipes); XCTAssertEqual(loaded.defaultDisconnectBehavior, .terminate)
        XCTAssertEqual(loaded.readiness.timeoutMilliseconds, 30000)
    }
    func testRejectsUnknownVersionsFieldsIdentityAndServiceValues() throws {
        for (key, value): (UInt64, CBORValue?) in [(0, .unsigned(2)), (11, .unsigned(501)), (4, nil),
            (1, .bytes(Data([1]))), (3, .text("other.service")), (3, .text("dev.remozio.bad\0service")),
            (3, .text("dev.remozio." + String(repeating: "x", count: 256))), (8, .unsigned(10)), (9, .unsigned(10))] {
            XCTAssertThrowsError(try CommandFrontendConfiguration.decode(changed(key, value)), "Field \(key)")
        }
        XCTAssertThrowsError(try CommandFrontendConfiguration.decode(configuration().canonicalBytes + Data([0])))
    }
    func testRejectsDuplicateAndNonCanonicalHashOrder() throws {
        let a = CBORValue.bytes(Data(repeating: 3, count: 20)), b = CBORValue.bytes(Data(repeating: 4, count: 20))
        for hashes in [CBORValue.array([a, a]), .array([b, a]), .array([]), .array([.bytes(Data([1]))])] {
            XCTAssertThrowsError(try CommandFrontendConfiguration.decode(changed(6, hashes)))
        }
    }
    func testRejectsInvalidSubmissionAndWaitBudgets() throws {
        for budget in [CBORValue.map([0: .unsigned(0), 1: .unsigned(16), 2: .unsigned(4096)]),
            .map([0: .unsigned(UInt64(UInt32.max)), 1: .unsigned(16), 2: .unsigned(4096)]),
            .map([0: .unsigned(1000), 1: .unsigned(65), 2: .unsigned(4096)]),
            .map([0: .unsigned(1000), 1: .unsigned(16), 2: .unsigned(0)]),
            .map([0: .unsigned(1000), 1: .unsigned(16), 2: .unsigned(4096), 3: .unsigned(1)])] {
            XCTAssertThrowsError(try CommandFrontendConfiguration.decode(changed(7, budget)))
        }
        for wait in [CBORValue.map([0: .unsigned(0), 1: .unsigned(250), 2: .unsigned(2000), 3: .unsigned(5000)]),
            .map([0: .unsigned(30000), 1: .unsigned(2000), 2: .unsigned(250), 3: .unsigned(5000)]),
            .map([0: .unsigned(30000), 1: .unsigned(250), 2: .unsigned(2000), 3: .unsigned(UInt64.max)])] {
            XCTAssertThrowsError(try CommandFrontendConfiguration.decode(changed(10, wait)))
        }
    }
    func testRefreshAcceptsNewPinsButKeepsInstallationIdentity() throws {
        let original = try configuration()
        let refreshed = try CommandFrontendConfiguration.decode(changed(6, .array([.bytes(Data(repeating: 8, count: 20))])))
        XCTAssertEqual(try original.refreshedAuthorityPolicy(refreshed).requirement, refreshed.authorityPolicy.requirement)
        XCTAssertNotEqual(original.authorityPolicy.requirement, refreshed.authorityPolicy.requirement)
        XCTAssertEqual(refreshed.teamID, original.teamID); XCTAssertEqual(refreshed.authorityIdentifier, original.authorityIdentifier)
        for (key, value): (UInt64, CBORValue) in [(1, .bytes(Data(repeating: 9, count: 16))),
            (2, .bytes(Data(repeating: 9, count: 16))), (3, .text("dev.remozio.replacement")),
            (4, .text("1234567890")), (5, .text("dev.remozio.other"))] {
            let replacement = try CommandFrontendConfiguration.decode(changed(key, value))
            XCTAssertThrowsError(try original.refreshedAuthorityPolicy(replacement)) {
                XCTAssertEqual($0 as? CommandFrontendConfigurationError, .invalidConfiguration)
            }
        }
        let fixture = try Fixture()
        try refreshed.canonicalBytes.write(to: URL(fileURLWithPath: fixture.path))
        XCTAssertThrowsError(try original.reloadAuthorityPolicy(path: fixture.path))
    }
    private final class Fixture {
        let root: URL
        var path: String { root.appendingPathComponent("frontend.cbor").path }
        init() throws {
            guard let canonical = realpath(NSTemporaryDirectory(), nil) else { throw JournalLeaseError.system(errno) }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try Data([1, 2, 3]).write(to: URL(fileURLWithPath: path))
            guard chmod(path, 0o644) == 0 else { throw JournalLeaseError.system(errno) }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func read() throws -> Data {
            try ProtectedServiceConfiguration.read(anchor: root.path, relativePath: "frontend.cbor", owner: getuid(), privateFile: false)
        }
        func acl(_ arguments: [String]) throws {
            let task = Process(); task.executableURL = URL(fileURLWithPath: "/bin/chmod"); task.arguments = arguments + [path]
            try task.run(); task.waitUntilExit(); XCTAssertEqual(task.terminationStatus, 0)
        }
    }
    func testPublicReadKeepsPrivateReadAndOwnershipRules() throws {
        let fixture = try Fixture()
        XCTAssertEqual(try fixture.read(), Data([1, 2, 3]))
        XCTAssertThrowsError(try ProtectedServiceConfiguration.read(anchor: fixture.root.path, relativePath: "frontend.cbor", owner: getuid()))
        XCTAssertThrowsError(try ProtectedServiceConfiguration.read(anchor: fixture.root.path, relativePath: "frontend.cbor", owner: getuid() + 1, privateFile: false))
        XCTAssertThrowsError(try CommandFrontendConfiguration.load(path: fixture.path))
        for mode: mode_t in [0o646, 0o664, 0o4644] {
            XCTAssertEqual(chmod(fixture.path, mode), 0); XCTAssertThrowsError(try fixture.read())
        }
        XCTAssertEqual(chmod(fixture.path, 0o644), 0)
        XCTAssertEqual(chmod(fixture.root.path, 0o770), 0); XCTAssertThrowsError(try fixture.read())
    }
    func testPublicReadPermitsReadACLButRejectsMutationACLAndLinks() throws {
        let fixture = try Fixture()
        try fixture.acl(["+a", "everyone allow read"]); XCTAssertNoThrow(try fixture.read())
        try fixture.acl(["+a", "everyone allow write"]); XCTAssertThrowsError(try fixture.read())
        try fixture.acl(["-N"])
        let alias = fixture.path + ".alias"
        XCTAssertEqual(link(fixture.path, alias), 0); XCTAssertThrowsError(try fixture.read())
        XCTAssertEqual(unlink(alias), 0)
        XCTAssertEqual(rename(fixture.path, alias), 0); XCTAssertEqual(symlink(alias, fixture.path), 0)
        XCTAssertThrowsError(try fixture.read())
    }
}
