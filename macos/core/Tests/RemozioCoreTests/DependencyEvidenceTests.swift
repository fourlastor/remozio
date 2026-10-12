import Foundation
import XCTest
@testable import RemozioCore

final class DependencyEvidenceTests: XCTestCase {
    private let team = "ABCDEFGHIJ"
    private let appHash = Data(repeating: 3, count: 20)
    private let dependencyHash = Data(repeating: 5, count: 20)
    private let path = "Contents/Frameworks/Tool"

    private func fixture(generation: UInt64 = 1, dependencyTeam: String? = "ABCDEFGHIJ") throws -> ReleaseManifest {
        let app = try ReleaseComponent(role: .app, identifier: "dev.remozio.app", generation: generation,
            relativePath: "Contents/MacOS/App", codeDirectoryHash: nil, build: "1", teamID: team, formats: [])
        let dependency = try ReleaseDependency(owner: .app, kind: .tool, signaturePath: path,
            executablePath: path, identifier: "org.vendor.Tool", codeDirectoryHash: dependencyHash,
            teamID: dependencyTeam, build: nil)
        return try .init(release: "0.1.0", build: "1", components: [app], dependencies: [dependency])
    }
    private func policy(generation: UInt64 = 1) throws -> AuthorityCodePolicy {
        try .init(entries: [.init(role: .app, teamID: team, identifier: "dev.remozio.app", installedGeneration: generation,
            minimumGeneration: 1, codeDirectoryHash: appHash, active: true)])
    }
    func testCompleteEvidenceDoesNotChangeRetainedPolicyOrGrantDependencyRoles() throws {
        let retained = try policy()
        let evidence = try SignedReleaseEvidence(manifest: fixture(), codeDirectoryHashes: [.app: appHash],
            dependencyCodeDirectoryHashes: [path: dependencyHash])
        try ReleaseGenerationPreflight.validate(evidence, against: retained)
        XCTAssertEqual(retained, try policy())
        XCTAssertEqual(retained.entries.map(\.role), [.app])
    }
    func testMissingExtraAndChangedDependencyHashesAreRejected() throws {
        for hashes in [[:], [path: dependencyHash, "Contents/Frameworks/Extra": dependencyHash],
                       [path: Data(repeating: 6, count: 20)], [path: Data(repeating: 5, count: 19)]] {
            let evidence = try SignedReleaseEvidence(manifest: fixture(), codeDirectoryHashes: [.app: appHash],
                dependencyCodeDirectoryHashes: hashes)
            XCTAssertThrowsError(try ReleaseGenerationPreflight.validate(evidence, against: policy())) {
                XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .invalidEvidence)
            }
        }
    }
    func testDependencyTeamMustMatchItsSignedOwner() throws {
        for value in [nil, "OTHERTEAM1"] {
            let evidence = try SignedReleaseEvidence(manifest: fixture(dependencyTeam: value), codeDirectoryHashes: [.app: appHash],
                dependencyCodeDirectoryHashes: [path: dependencyHash])
            XCTAssertThrowsError(try ReleaseGenerationPreflight.validate(evidence, against: policy())) {
                XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .invalidEvidence)
            }
        }
    }
    func testOwnerGenerationStillCannotRollBackWithValidDependencyEvidence() throws {
        let evidence = try SignedReleaseEvidence(manifest: fixture(), codeDirectoryHashes: [.app: appHash],
            dependencyCodeDirectoryHashes: [path: dependencyHash])
        XCTAssertThrowsError(try ReleaseGenerationPreflight.validate(evidence, against: policy(generation: 2))) {
            XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .rollback(.app))
        }
    }
}
