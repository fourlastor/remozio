import Foundation
import XCTest
import RemozioProtocol
@testable import RemozioCore

final class MachineUpdatePolicyPlanTests: XCTestCase {
    private let team = "ABCDEFGHIJ"
    private func entry(_ role: AuthorityCodeRole, installed: UInt64 = 6, minimum: UInt64 = 4,
                       active: Bool = true) throws -> AuthorityCodeEntry {
        try .init(role: role, teamID: team, identifier: "dev.remozio.role-\(role.rawValue)",
            installedGeneration: installed, minimumGeneration: minimum,
            codeDirectoryHash: Data(repeating: 1, count: 20), active: active)
    }
    private func source() throws -> AuthorityCodePolicySnapshot {
        let policy = try AuthorityCodePolicy(entries: [entry(.app), entry(.authority), entry(.transport, installed: 7, minimum: 5, active: false)])
        return .init(revision: UUID(), policy: policy,
            roleRevisions: Dictionary(uniqueKeysWithValues: policy.entries.map { ($0.role, UUID()) }))
    }
    private func candidate(generation: UInt64 = 8, transport: Bool = true, extra: Bool = false,
                           hash: UInt8 = 2, changedRole: AuthorityCodeRole? = nil) throws -> SignedReleaseEvidence {
        var roles: [AuthorityCodeRole] = [.app, .authority]
        if transport { roles.append(.transport) }
        if extra { roles.append(.guiAgent) }
        let components = try roles.map { role in
            try ReleaseComponent(role: role, identifier: changedRole == role ? "dev.remozio.changed" : "dev.remozio.role-\(role.rawValue)",
                generation: generation, relativePath: "Contents/Helpers/role-\(role.rawValue)",
                codeDirectoryHash: role == .app ? nil : Data(repeating: hash, count: 20), build: "8", teamID: team, formats: [])
        }
        let manifest = try ReleaseManifest(release: "0.1.0", build: "8", components: components)
        return .init(manifest: manifest, codeDirectoryHashes: Dictionary(uniqueKeysWithValues: components.map {
            ($0.role, $0.codeDirectoryHash ?? Data(repeating: hash, count: 20))
        }))
    }
    func testLegacyPolicyKeepsItsCurrentFormatWithoutRequiringAnUnplannedReaderUpgrade() throws {
        let old = try source(), limits = try CBORLimits(maxBytes: 8192, maxDepth: 4, maxItems: 256)
        guard case .map(var fields) = try DeterministicCBOR.decode(old.policy.bytes, limits: limits) else {
            return XCTFail("Invalid source fixture")
        }
        fields[0] = .unsigned(1)
        let legacy = try AuthorityCodePolicy.decode(DeterministicCBOR.encode(.map(fields), limits: limits))
        let snapshot = AuthorityCodePolicySnapshot(revision: old.revision, policy: legacy, roleRevisions: old.roleRevisions)
        let value = try MachineUpdatePolicyPlan(source: snapshot, candidate: candidate())
        XCTAssertEqual(value.startupPolicy.formatVersion, 1); XCTAssertEqual(value.completionPolicy.formatVersion, 1)
    }

    func testStartupValuesPreserveEveryMinimumAndActiveSelection() throws {
        let old = try source(), signed = try candidate(), value = try MachineUpdatePolicyPlan(source: old, candidate: signed)
        XCTAssertEqual(value.source, old)
        for entry in old.policy.entries {
            let next = try XCTUnwrap(value.startupPolicy.entries.first { $0.role == entry.role })
            XCTAssertEqual(next.minimumGeneration, entry.minimumGeneration)
            XCTAssertEqual(next.active, entry.active); XCTAssertEqual(next.installedGeneration, 8)
            XCTAssertEqual(next.codeDirectoryHash, signed.codeDirectoryHashes[entry.role])
        }
    }
    func testCompletionValuesRaiseFloorsWithoutMutatingTheProtectedSource() throws {
        let old = try source(), before = try old.storedBytes
        let value = try MachineUpdatePolicyPlan(source: old, candidate: candidate())
        XCTAssertEqual(value.completionPolicy.entries.map(\.minimumGeneration), [8, 8, 8])
        XCTAssertNoThrow(try value.completionPolicy.requireSuccessor(of: value.startupPolicy))
        XCTAssertEqual(try old.storedBytes, before); XCTAssertEqual(value.source, old)
    }
    func testMissingInactiveRoleRetainsItsExactIdentityAndFloors() throws {
        let old = try source(), value = try MachineUpdatePolicyPlan(source: old, candidate: candidate(transport: false))
        let retained = old.policy.entries.first { $0.role == .transport }
        XCTAssertEqual(value.startupPolicy.entries.first { $0.role == .transport }, retained)
        XCTAssertEqual(value.completionPolicy.entries.first { $0.role == .transport }, retained)
    }
    func testReturningInactiveRoleRemainsInactiveWithItsVerifiedHash() throws {
        let value = try MachineUpdatePolicyPlan(source: source(), candidate: candidate())
        let role = try XCTUnwrap(value.startupPolicy.entries.first { $0.role == .transport })
        XCTAssertFalse(role.active); XCTAssertEqual(role.minimumGeneration, 5)
        XCTAssertEqual(role.installedGeneration, 8); XCTAssertEqual(role.codeDirectoryHash, Data(repeating: 2, count: 20))
    }
    func testNewSignedRolesDoNotGainPolicyEntriesOrActivation() throws {
        let old = try source(), value = try MachineUpdatePolicyPlan(source: old, candidate: candidate(extra: true))
        XCTAssertEqual(value.startupPolicy.entries.map(\.role), old.policy.entries.map(\.role))
        XCTAssertEqual(value.completionPolicy.entries.map(\.role), old.policy.entries.map(\.role))
    }
    func testInstalledGenerationRejectsRollbackEvenAboveTheMinimum() throws {
        XCTAssertThrowsError(try MachineUpdatePolicyPlan(source: source(), candidate: candidate(generation: 5))) {
            XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .rollback(.app))
        }
    }
    func testInactiveIdentityCannotChangeDuringAReleaseUpdate() throws {
        XCTAssertThrowsError(try MachineUpdatePolicyPlan(source: source(), candidate: candidate(changedRole: .transport))) {
            XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .identityChanged(.transport))
        }
    }
    func testCurrentPolicyRequiresBothTheGlobalRevisionAndEveryRoleToken() throws {
        let old = try source(), value = try MachineUpdatePolicyPlan(source: old, candidate: candidate())
        XCTAssertNoThrow(try value.requireCurrent(old))
        var tokens = old.roleRevisions; tokens[.authority] = UUID()
        for changed in [AuthorityCodePolicySnapshot(revision: UUID(), policy: old.policy, roleRevisions: old.roleRevisions),
                        AuthorityCodePolicySnapshot(revision: old.revision, policy: old.policy, roleRevisions: tokens)] {
            XCTAssertThrowsError(try value.requireCurrent(changed)) { XCTAssertEqual($0 as? AuthorityCodePolicyError, .staleRevision) }
        }
    }
    func testFreshCandidateMustMatchTheEntireSignedReleaseDigest() throws {
        let signed = try candidate(), value = try MachineUpdatePolicyPlan(source: source(), candidate: signed)
        XCTAssertNoThrow(try value.requireCandidate(signed))
        XCTAssertThrowsError(try value.requireCandidate(candidate(hash: 3))) {
            XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
        }
    }
    func testIncompleteSignatureEvidenceCannotCreateAPlan() throws {
        let signed = try candidate(), malformed = SignedReleaseEvidence(manifest: signed.manifest,
            codeDirectoryHashes: [.app: Data(repeating: 2, count: 20)])
        XCTAssertThrowsError(try MachineUpdatePolicyPlan(source: source(), candidate: malformed)) {
            XCTAssertEqual($0 as? ReleaseGenerationPreflightError, .invalidEvidence)
        }
    }
    func testMaximumGenerationNeedsNoIncrementOrOverflow() throws {
        let value = try MachineUpdatePolicyPlan(source: source(), candidate: candidate(generation: .max))
        XCTAssertTrue(value.completionPolicy.entries.allSatisfy { $0.minimumGeneration == .max && $0.installedGeneration == .max })
    }
    func testDescriptionsRedactPolicyAndReleaseBindings() throws {
        let value = try MachineUpdatePolicyPlan(source: source(), candidate: candidate())
        XCTAssertEqual(value.description, "MachineUpdatePolicyPlan(redacted)")
        XCTAssertEqual(value.debugDescription, value.description)
    }
    func testAnIncompleteProtectedSourceSnapshotIsRefused() throws {
        let old = try source(), incomplete = AuthorityCodePolicySnapshot(revision: old.revision, policy: old.policy, roleRevisions: [:])
        XCTAssertThrowsError(try MachineUpdatePolicyPlan(source: incomplete, candidate: candidate())) {
            XCTAssertEqual($0 as? AuthorityCodePolicyError, .corruptData)
        }
    }
    func testSameGenerationCanSelectANewSignedBuildWithoutIncrementingTheFloor() throws {
        let previous = try source()
        let policy = try AuthorityCodePolicy(entries: previous.policy.entries.map {
            try entry($0.role, installed: 7, minimum: $0.minimumGeneration, active: $0.active)
        })
        let old = AuthorityCodePolicySnapshot(revision: previous.revision, policy: policy, roleRevisions: previous.roleRevisions)
        let value = try MachineUpdatePolicyPlan(source: old, candidate: candidate(generation: 7))
        XCTAssertTrue(value.startupPolicy.entries.allSatisfy { $0.installedGeneration == 7 && $0.codeDirectoryHash == Data(repeating: 2, count: 20) })
        XCTAssertTrue(value.completionPolicy.entries.allSatisfy { $0.minimumGeneration == 7 })
    }
}
