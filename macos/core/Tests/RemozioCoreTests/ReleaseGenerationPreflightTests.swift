import Foundation
import XCTest
@testable import RemozioCore

final class ReleaseGenerationPreflightTests: XCTestCase {
    private let team = "ABCDEFGHIJ"
    private func component(_ role: AuthorityCodeRole, generation: UInt64 = 4,
                           identifier: String? = nil, team: String? = "ABCDEFGHIJ", hash: UInt8 = 1) throws -> ReleaseComponent {
        try ReleaseComponent(role: role, identifier: identifier ?? "dev.remozio.role-\(role.rawValue)", generation: generation,
            relativePath: "Contents/Helpers/role-\(role.rawValue)",
            codeDirectoryHash: role == .app ? nil : Data(repeating: hash, count: 20), build: "4", teamID: team, formats: [])
    }
    private func evidence(_ components: [ReleaseComponent]) throws -> SignedReleaseEvidence {
        let manifest = try ReleaseManifest(release: "0.1.0", build: "4", components: components)
        return SignedReleaseEvidence(manifest: manifest, codeDirectoryHashes: Dictionary(uniqueKeysWithValues:
            components.map { ($0.role, $0.codeDirectoryHash ?? Data(repeating: 1, count: 20)) }))
    }
    private func retained(_ role: AuthorityCodeRole, installed: UInt64 = 4, minimum: UInt64 = 2, active: Bool = true) throws -> AuthorityCodeEntry {
        try AuthorityCodeEntry(role: role, teamID: team, identifier: "dev.remozio.role-\(role.rawValue)",
            installedGeneration: installed, minimumGeneration: minimum, codeDirectoryHash: Data(repeating: 1, count: 20), active: active)
    }
    func testCurrentAndHigherGenerationsPassWithoutChangingRetainedPolicy() throws {
        let policy = try AuthorityCodePolicy(entries: [retained(.app), retained(.authority)])
        let original = try policy.bytes
        for generation: UInt64 in [4, 5, .max] {
            // A new build may retain the security generation. Its old CDHash is not a replacement requirement.
            let candidate = try evidence([component(.app, generation: generation), component(.authority, generation: generation, hash: 2)])
            XCTAssertNoThrow(try ReleaseGenerationPreflight.validate(candidate, against: policy))
        }
        XCTAssertEqual(try policy.bytes, original)
    }
    func testInstalledGenerationPreventsDowngradeEvenAboveTheMinimum() throws {
        let policy = try AuthorityCodePolicy(entries: [retained(.app), retained(.authority, installed: 6, minimum: 2)])
        let candidate = try evidence([component(.app), component(.authority, generation: 5)])
        XCTAssertThrowsError(try ReleaseGenerationPreflight.validate(candidate, against: policy)) {
            XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .rollback(.authority))
        }
    }
    func testCommittedFloorAndAppGenerationCannotBeLowered() throws {
        let policy = try AuthorityCodePolicy(entries: [retained(.app, installed: 6, minimum: 6)])
        let candidate = try evidence([component(.app, generation: 5)])
        XCTAssertThrowsError(try ReleaseGenerationPreflight.validate(candidate, against: policy)) {
            XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .rollback(.app))
        }
    }
    func testTeamAndIdentifierChangesFailForActiveAndInactiveRoles() throws {
        for active in [true, false] {
            let policy = try AuthorityCodePolicy(entries: [retained(.authority, active: active)])
            for child in [try component(.authority, team: "OTHERTEAM1"), try component(.authority, identifier: "dev.remozio.other")] {
                let candidate = try evidence([component(.app), child])
                XCTAssertThrowsError(try ReleaseGenerationPreflight.validate(candidate, against: policy)) {
                    XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .identityChanged(.authority))
                }
            }
        }
    }
    func testMissingActiveRoleFailsButMissingInactiveRoleRetainsItsFloor() throws {
        let candidate = try evidence([component(.app)])
        for active in [true, false] {
            let policy = try AuthorityCodePolicy(entries: [retained(.app), retained(.guiAgent, installed: 7, minimum: 6, active: active)])
            let before = try policy.bytes
            if active {
                XCTAssertThrowsError(try ReleaseGenerationPreflight.validate(candidate, against: policy)) {
                    XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .missingActiveRole(.guiAgent))
                }
            } else { XCTAssertNoThrow(try ReleaseGenerationPreflight.validate(candidate, against: policy)) }
            XCTAssertEqual(try policy.bytes, before)
        }
    }
    func testReturningInactiveRoleMustMeetRetainedInstalledGeneration() throws {
        let policy = try AuthorityCodePolicy(entries: [retained(.app), retained(.guiAgent, installed: 7, minimum: 6, active: false)])
        let candidate = try evidence([component(.app), component(.guiAgent, generation: 6)])
        XCTAssertThrowsError(try ReleaseGenerationPreflight.validate(candidate, against: policy)) {
            XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .rollback(.guiAgent))
        }
    }
    func testCandidateCannotSupplyIncompleteOrContradictorySignatureEvidence() throws {
        let policy = try AuthorityCodePolicy(entries: [retained(.app)])
        let original = try evidence([component(.app), component(.authority)])
        for hashes: [AuthorityCodeRole: Data] in [[:], [.app: Data(repeating: 1, count: 20)],
            [.app: Data(repeating: 1, count: 19), .authority: Data(repeating: 1, count: 20)],
            [.app: Data(repeating: 1, count: 20), .authority: Data(repeating: 2, count: 20)],
            [.app: Data(repeating: 1, count: 20), .authority: Data(repeating: 1, count: 20), .guiAgent: Data(repeating: 1, count: 20)]] {
            let malformed = SignedReleaseEvidence(manifest: original.manifest, codeDirectoryHashes: hashes)
            XCTAssertThrowsError(try ReleaseGenerationPreflight.validate(malformed, against: policy)) {
                XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .invalidEvidence)
            }
        }
    }
    func testAdHocDeclarationsAreNotTrustedAndNewRolesGainNoPolicyEntry() throws {
        let policy = try AuthorityCodePolicy(entries: [retained(.app)])
        let adHoc = try evidence([component(.app, team: nil)])
        XCTAssertThrowsError(try ReleaseGenerationPreflight.validate(adHoc, against: policy)) {
            XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .invalidEvidence)
        }
        let candidate = try evidence([component(.app), component(.bridgeCommand)])
        XCTAssertNoThrow(try ReleaseGenerationPreflight.validate(candidate, against: policy))
        XCTAssertEqual(policy.entries.map(\.role), [.app])
    }
}
