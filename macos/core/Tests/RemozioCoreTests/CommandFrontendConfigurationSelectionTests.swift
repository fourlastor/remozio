import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class CommandFrontendConfigurationSelectionTests: XCTestCase {
    private func configuration(_ n: UInt8) throws -> CommandFrontendConfiguration {
        try .init(macID: Data(repeating: 1, count: 16), accountID: Data(repeating: n, count: 16),
            serviceName: "dev.remozio.commands-\(n)", teamID: "ABCDEFGHIJ", authorityIdentifier: "dev.remozio.authority",
            authorityHashes: [Data(repeating: 4, count: 20)], submissionLimits: .init(maxBytes: 65536, maxDepth: 8, maxItems: 4096),
            defaultIOMode: .pty, defaultDisconnectBehavior: .terminate, readiness: .init(timeoutMilliseconds: 5000))
    }
    func testAccountMetadataTakesPriorityAndRetainsTheSelectedPath() throws {
        let value = try configuration(2), expected = try CommandFrontendConfigurationSelection.accountPath(ownerUID: 501)
        var reads: [String] = []
        let selection = try CommandFrontendConfigurationSelection.load(ownerUID: 501, readPublic: { path in
            reads.append(path); XCTAssertEqual(path, expected); return value.canonicalBytes
        })
        XCTAssertEqual(selection.path, expected)
        XCTAssertEqual(selection.configuration.canonicalBytes, value.canonicalBytes)
        XCTAssertEqual(reads, [expected])
        XCTAssertNotEqual(expected, try CommandFrontendConfigurationSelection.accountPath(ownerUID: 502))
    }
    func testOnlyMissingAccountMetadataCanSelectTheLegacyPath() throws {
        let value = try configuration(2), scoped = try CommandFrontendConfigurationSelection.accountPath(ownerUID: 501)
        var reads: [String] = []
        let selection = try CommandFrontendConfigurationSelection.load(ownerUID: 501, readPublic: { path in
            reads.append(path)
            if path == scoped { throw JournalLeaseError.system(ENOENT) }
            XCTAssertEqual(path, CommandFrontendMain.configurationPath); return value.canonicalBytes
        })
        XCTAssertEqual(selection.path, CommandFrontendMain.configurationPath)
        XCTAssertEqual(reads, [scoped, CommandFrontendMain.configurationPath])
    }
    func testCorruptUnsafeAndUnreadableAccountMetadataCannotFallBack() throws {
        for failure: JournalLeaseError? in [nil, .unsafeMetadata, .identityChanged, .system(EIO), .system(EACCES)] {
            var reads = 0
            XCTAssertThrowsError(try CommandFrontendConfigurationSelection.load(ownerUID: 501, readPublic: { _ in
                reads += 1
                if let failure { throw failure }
                return Data([0xff])
            })) { XCTAssertEqual($0 as? CommandFrontendConfigurationError, .invalidConfiguration) }
            XCTAssertEqual(reads, 1)
        }
    }
    func testInvalidOwnerCannotReadAnyInstallationMetadata() {
        for owner in [UInt32(0), UInt32.max] {
            XCTAssertThrowsError(try CommandFrontendConfigurationSelection.load(ownerUID: owner, readPublic: { _ in
                XCTFail("Invalid owner must fail before lookup"); return Data()
            }))
        }
    }
    func testLegacyFallbackStillRequiresValidProtectedBytes() {
        var reads = 0
        XCTAssertThrowsError(try CommandFrontendConfigurationSelection.load(ownerUID: 501, readPublic: { _ in
            reads += 1
            if reads == 1 { throw JournalLeaseError.system(ENOENT) }
            return Data([0xff])
        }))
        XCTAssertEqual(reads, 2)
    }
}
