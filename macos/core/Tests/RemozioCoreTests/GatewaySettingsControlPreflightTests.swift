import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewaySettingsControlPreflightTests: XCTestCase {
    private let team = "ABCDEFGHIJ"
    private func entry(_ role: AuthorityCodeRole, active: Bool = true) throws -> AuthorityCodeEntry {
        try .init(role: role, teamID: team, identifier: "dev.remozio.role-\(role.rawValue)", installedGeneration: 4,
            minimumGeneration: 4, codeDirectoryHash: Data(repeating: 1, count: 20), active: active)
    }
    private func component(_ role: AuthorityCodeRole, formats: [ReleaseFormat]) throws -> ReleaseComponent {
        try .init(role: role, identifier: "dev.remozio.role-\(role.rawValue)", generation: 4,
            relativePath: "Contents/Helpers/role-\(role.rawValue)", codeDirectoryHash: role == .app ? nil : Data(repeating: 1, count: 20),
            build: "4", teamID: team, formats: formats)
    }
    private func release(_ formats: (AuthorityCodeRole) throws -> [ReleaseFormat],
                         edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws -> SignedReleaseEvidence {
        let components = try [AuthorityCodeRole.app, .authority, .setupController].map { try edit(component($0, formats: formats($0))) }
        return .init(manifest: try .init(release: "0.1.0", build: "4", components: components),
            codeDirectoryHashes: Dictionary(uniqueKeysWithValues: components.map { ($0.role, $0.codeDirectoryHash ?? Data(repeating: 1, count: 20)) }))
    }
    private func format(_ readers: Set<UInt64> = [1], writers: Set<UInt64> = [1]) throws -> ReleaseFormat {
        try .init(name: GatewaySettingsControlReleaseValidation.formatName, readers: readers, writers: writers)
    }
    func testBothParticipantsMustReadAndWriteTheSelectedVersion() throws {
        let authority = try entry(.authority), setup = try entry(.setupController)
        for versions: Set<UInt64> in [[1], [1, 2]] {
            let value = try release { _ in [try self.format(versions, writers: versions)] }
            XCTAssertNoThrow(try GatewaySettingsControlReleaseValidation.validate(value, authority: authority, setup: setup))
        }
        for role in [AuthorityCodeRole.authority, .setupController] {
            for formats in [[], [try format([2], writers: [2])], [try format([1], writers: [])]] {
                let value = try release { $0 == role ? formats : [try self.format()] }
                XCTAssertThrowsError(try GatewaySettingsControlReleaseValidation.validate(value, authority: authority, setup: setup))
            }
        }
    }
    func testRetainedCodeIdentityAndActualSignatureHashesMustBothMatch() throws {
        let authority = try entry(.authority), setup = try entry(.setupController)
        for role in [AuthorityCodeRole.authority, .setupController] {
            for mode in 0..<4 {
                let value = try release({ _ in [try self.format()] }, edit: { c in
                    guard c.role == role else { return c }
                    return try .init(role: c.role, identifier: mode == 0 ? c.identifier + ".other" : c.identifier,
                        generation: mode == 1 ? 5 : c.generation, relativePath: c.relativePath,
                        codeDirectoryHash: mode == 2 ? Data(repeating: 2, count: 20) : c.codeDirectoryHash,
                        build: c.build, teamID: mode == 3 ? nil : c.teamID, formats: c.formats)
                })
                XCTAssertThrowsError(try GatewaySettingsControlReleaseValidation.validate(value, authority: authority, setup: setup))
            }
            let original = try release { _ in [try self.format()] }; var hashes = original.codeDirectoryHashes; hashes.removeValue(forKey: role)
            XCTAssertThrowsError(try GatewaySettingsControlReleaseValidation.validate(.init(manifest: original.manifest,
                codeDirectoryHashes: hashes), authority: authority, setup: setup))
        }
        let value = try release { _ in [try self.format()] }
        XCTAssertThrowsError(try GatewaySettingsControlReleaseValidation.validate(value, authority: entry(.authority, active: false), setup: setup))
        XCTAssertThrowsError(try GatewaySettingsControlReleaseValidation.validate(value, authority: authority, setup: entry(.setupController, active: false)))
        XCTAssertThrowsError(try GatewaySettingsControlReleaseValidation.validate(value, authority: setup, setup: authority))
    }
    func testTheNativeFactoryRefusesAnOrdinaryCallerBeforeOpeningAConnection() throws {
        guard getuid() != 0 else { throw XCTSkip("Ordinary owner refusal") }
        let value = try release { _ in [try self.format()] }
        XCTAssertThrowsError(try GatewaySettingsControlChannel(accountID: Data(repeating: 1, count: 16), authorityCode: entry(.authority),
            setupCode: entry(.setupController), release: value, expectedRootEpoch: nil, verifyCurrent: { XCTFail("No native scope access") })) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
    }
}
