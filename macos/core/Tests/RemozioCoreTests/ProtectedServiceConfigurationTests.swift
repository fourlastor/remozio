import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class ProtectedServiceConfigurationTests: XCTestCase {
    private final class Fixture {
        let root: URL
        var directory: String { root.appendingPathComponent("config").path }
        var path: String { directory + "/authority.cbor" }
        init(_ data: Data = Data([1, 2, 3])) throws {
            guard let canonical = realpath(FileManager.default.temporaryDirectory.path, nil) else { throw JournalLeaseError.system(errno) }
            defer { free(canonical) }
            root = URL(fileURLWithPath: String(cString: canonical)).appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            try data.write(to: URL(fileURLWithPath: path))
            guard chmod(path, 0o600) == 0 else { throw JournalLeaseError.system(errno) }
        }
        deinit { try? FileManager.default.removeItem(at: root) }
        func read() throws -> Data {
            try ProtectedServiceConfiguration.read(anchor: root.path, relativePath: "config/authority.cbor", owner: getuid())
        }
    }
    private func configuration(continuity: String? = nil) throws -> AuthorityServiceConfiguration {
        try AuthorityServiceConfiguration(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: 2, count: 16),
            journalDirectory: "/Library/Application Support/Remozio/journal", serviceName: "dev.remozio.authority",
            teamID: "ABCDEFGHIJ", transportIdentifier: "dev.remozio.transport",
            transportHashes: [Data(repeating: 3, count: 20), Data(repeating: 4, count: 20)], transportUID: 501,
            maximumPayloadBytes: 4096, minimumEnvelopeVersion: 2, auditVersions: [1, 2],
            maximumConnections: 4, handshakeTimeoutMilliseconds: 1234, maximumOperations: 3, continuityDirectory: continuity)
    }
    func testProtectedReadAndConfigurationRoundTrip() throws {
        let value = try configuration(), fixture = try Fixture(value.canonicalBytes)
        let decoded = try AuthorityServiceConfiguration.decode(fixture.read())
        XCTAssertEqual(decoded.canonicalBytes, value.canonicalBytes)
        XCTAssertEqual(decoded.macID, value.macID); XCTAssertEqual(decoded.accountID, value.accountID)
        XCTAssertEqual(decoded.journalDirectory, value.journalDirectory); XCTAssertEqual(decoded.serviceName, value.serviceName)
        XCTAssertEqual(decoded.transportPolicy.requirement, value.transportPolicy.requirement)
        XCTAssertEqual(decoded.transportPolicy.expectedUserID, 501)
        XCTAssertEqual(decoded.maximumPayloadBytes, 4096); XCTAssertEqual(decoded.maximumRequestBodyBytes, 3968); XCTAssertEqual(decoded.minimumEnvelopeVersion, 2)
        XCTAssertEqual(decoded.auditVersions, [1, 2]); XCTAssertEqual(decoded.maximumConnections, 4)
        XCTAssertEqual(decoded.handshakeTimeoutMilliseconds, 1234); XCTAssertEqual(decoded.maximumOperations, 3)
    }
    func testVersionTwoCarriesIndependentContinuityPathAndPreservesVersionOne() throws {
        let old = try configuration()
        XCTAssertNil(try AuthorityServiceConfiguration.decode(old.canonicalBytes).continuityDirectory)
        let path = "/Library/Application Support/Remozio/continuity"
        let value = try configuration(continuity: path)
        let decoded = try AuthorityServiceConfiguration.decode(value.canonicalBytes)
        XCTAssertEqual(decoded.continuityDirectory, path)
        XCTAssertEqual(decoded.canonicalBytes, value.canonicalBytes)
        for invalid in ["", "/", "relative", "/tmp/../continuity", "/tmp//continuity", "/tmp/continuity/",
                        old.journalDirectory, old.journalDirectory + "/continuity", "/Library/Application Support/Remozio"] {
            XCTAssertThrowsError(try configuration(continuity: invalid), invalid)
        }
    }

    func testVersionTwoRejectsMissingExtraAndWronglyTypedContinuityFields() throws {
        let value = try configuration(continuity: "/Library/Application Support/Remozio/continuity")
        let limits = try CBORLimits(maxBytes: 65536, maxDepth: 3, maxItems: 128)
        guard case .map(let fields) = try DeterministicCBOR.decode(value.canonicalBytes, limits: limits) else {
            return XCTFail("Expected map")
        }
        for (key, replacement): (UInt64, CBORValue?) in [(15, nil), (15, .null), (15, .unsigned(1)),
            (16, .text("extra")), (0, .unsigned(1)), (0, .unsigned(3))] {
            var changed = fields; changed[key] = replacement
            XCTAssertThrowsError(try AuthorityServiceConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)))
        }
        XCTAssertNoThrow(try configuration(continuity: "/Library/Application Support/Remozio/journal-backup"))
    }

    func testProductionReaderRequiresRoot() throws {
        guard geteuid() != 0 else { throw XCTSkip("Requires normal user") }
        let fixture = try Fixture()
        XCTAssertThrowsError(try AuthorityServiceConfiguration.load(path: fixture.path)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
    func testRejectsAmbiguousPathsEmptyAndOversizedFiles() throws {
        let fixture = try Fixture()
        for path in ["", "/config/authority.cbor", "config//authority.cbor", "config/../authority.cbor", "config/./authority.cbor", "config/authority.cbor/", "config/a\0", String(repeating: "a", count: 256)] {
            XCTAssertThrowsError(try ProtectedServiceConfiguration.read(anchor: fixture.root.path, relativePath: path, owner: getuid()))
        }
        for size in [0, ProtectedServiceConfiguration.maximumBytes + 1] {
            let invalid = try Fixture(Data(count: size)); XCTAssertThrowsError(try invalid.read())
        }
        let maximum = try Fixture(Data(count: ProtectedServiceConfiguration.maximumBytes))
        XCTAssertEqual(try maximum.read().count, ProtectedServiceConfiguration.maximumBytes)
    }
    func testRejectsSymlinksHardlinksFIFOsAndDirectories() throws {
        for kind in ["symlink", "hardlink", "fifo", "directory"] {
            let fixture = try Fixture(), original = fixture.path + ".old"
            XCTAssertEqual(rename(fixture.path, original), 0)
            switch kind {
            case "symlink": XCTAssertEqual(symlink(original, fixture.path), 0)
            case "hardlink": XCTAssertEqual(link(original, fixture.path), 0)
            case "fifo": XCTAssertEqual(mkfifo(fixture.path, 0o600), 0)
            default: XCTAssertEqual(mkdir(fixture.path, 0o700), 0)
            }
            XCTAssertThrowsError(try fixture.read())
        }
        let fixture = try Fixture(), original = fixture.directory + ".old"
        XCTAssertEqual(rename(fixture.directory, original), 0)
        XCTAssertEqual(symlink(original, fixture.directory), 0)
        XCTAssertThrowsError(try fixture.read())
    }
    func testRejectsUnsafeOwnershipAndPermissions() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try ProtectedServiceConfiguration.read(anchor: fixture.root.path, relativePath: "config/authority.cbor", owner: getuid() + 1))
        XCTAssertEqual(chmod(fixture.path, 0o640), 0); XCTAssertThrowsError(try fixture.read())
        XCTAssertEqual(chmod(fixture.path, 0o600), 0)
        XCTAssertEqual(chmod(fixture.directory, 0o770), 0); XCTAssertThrowsError(try fixture.read())
    }
    func testPrivateFileOwnerAndAncestorOwnerAreCheckedIndependently() throws {
        let fixture = try Fixture()
        XCTAssertEqual(try ProtectedServiceConfiguration.read(anchor: fixture.root.path,
            relativePath: "config/authority.cbor", owner: getuid(), ancestorOwner: getuid()), Data([1, 2, 3]))
        XCTAssertThrowsError(try ProtectedServiceConfiguration.read(anchor: fixture.root.path,
            relativePath: "config/authority.cbor", owner: getuid() + 1, ancestorOwner: getuid()))
        XCTAssertThrowsError(try ProtectedServiceConfiguration.read(anchor: fixture.root.path,
            relativePath: "config/authority.cbor", owner: getuid(), ancestorOwner: getuid() + 1))
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readServicePrivate(path: fixture.path, serviceUID: 0))
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readServicePrivate(path: fixture.path, serviceUID: getuid() + 1))
        // The ordinary-user fixture cannot satisfy the production Root-owned ancestor walk.
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readServicePrivate(path: fixture.path, serviceUID: getuid()))
    }
    func testRootServiceReaderRejectsOrdinaryCallersWithoutWeakeningServiceAdmission() throws {
        guard geteuid() != 0 else { throw XCTSkip("Requires normal user") }
        let fixture = try Fixture()
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readServicePrivateAsRoot(path: fixture.path, serviceUID: getuid())) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertThrowsError(try ProtectedServiceConfiguration.readServicePrivate(path: fixture.path, serviceUID: getuid() + 1)) {
            XCTAssertEqual($0 as? ApprovalTransportStartupError, .wrongAccount)
        }
    }
    func testNativePublicationUsesRootAdmissionForServiceOwnedArtifacts() throws {
        guard geteuid() != 0 else { throw XCTSkip("Requires normal user") }
        let fixture = try Fixture()
        let artifact = RuntimePublishedArtifactValidation.Artifact(path: fixture.path, bytes: Data([1, 2, 3]),
            access: .servicePrivate(getuid() + 1))
        XCTAssertThrowsError(try RuntimePublishedArtifactValidation.nativeRead(artifact)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }

    func testRejectsUnknownVersionFieldsDuplicatesAndInvalidBounds() throws {
        let value = try configuration(), limits = try CBORLimits(maxBytes: 65536, maxDepth: 3, maxItems: 128)
        guard case .map(let fields) = try DeterministicCBOR.decode(value.canonicalBytes, limits: limits) else { return XCTFail("Expected map") }
        let changes: [(UInt64, CBORValue?)] = [
            (0, .unsigned(2)), (15, .unsigned(1)), (5, nil), (1, .bytes(Data([1]))), (3, .text("/tmp/../journal")),
            (4, .text("other.service")), (5, .text("invalid")), (8, .unsigned(0)), (8, .unsigned(UInt64.max)),
            (9, .unsigned(0)), (9, .unsigned(UInt64.max)), (10, .unsigned(0)), (12, .unsigned(65)),
            (13, .unsigned(60001)), (14, .unsigned(0)), (11, .array([.unsigned(1), .unsigned(1)])),
            (7, .array([.bytes(Data(repeating: 3, count: 20)), .bytes(Data(repeating: 3, count: 20))])),
        ]
        for (key, replacement) in changes {
            var changed = fields; changed[key] = replacement
            XCTAssertThrowsError(try AuthorityServiceConfiguration.decode(DeterministicCBOR.encode(.map(changed), limits: limits)), "Field \(key)")
        }
        XCTAssertThrowsError(try AuthorityServiceConfiguration.decode(value.canonicalBytes + Data([0])))
    }
}
