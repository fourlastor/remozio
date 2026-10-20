import Foundation
import XCTest
@testable import RemozioCore

final class GatewayRuntimeSettingsFenceReleaseValidationTests: XCTestCase {
    private typealias Validation = GatewayRuntimeSettingsFenceReleaseValidation
    private let roles: [AuthorityCodeRole] = [.authority, .transport, .notificationGateway, .setupController]
    private func release(_ policy: AuthorityCodePolicy, missing: AuthorityCodeRole? = nil,
                         formats: (AuthorityCodeRole) throws -> [ReleaseFormat]) throws -> SignedReleaseEvidence {
        let entries = policy.entries.filter { $0.active && $0.role != missing }
        let components = try entries.map { entry in
            try ReleaseComponent(role: entry.role, identifier: entry.identifier, generation: entry.installedGeneration,
                relativePath: "Contents/Helpers/role-\(entry.role.rawValue)", codeDirectoryHash: entry.role == .app ? nil : entry.codeDirectoryHash,
                build: "1", teamID: entry.teamID, formats: formats(entry.role))
        }
        return .init(manifest: try .init(release: "0.1.0", build: "1", components: components),
            codeDirectoryHashes: Dictionary(uniqueKeysWithValues: entries.map { ($0.role, $0.codeDirectoryHash) }))
    }
    private func format(_ role: AuthorityCodeRole, readers: Set<UInt64> = [1], writers: Set<UInt64>? = nil) throws -> ReleaseFormat {
        try .init(name: Validation.formatName, readers: readers, writers: writers ?? (role == .setupController ? [1] : []))
    }
    func testAllNativeConsumersMustDeclareReadersAndSetupMustDeclareItsWriter() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), policy = r.fixture.runtime.plan.host.codePolicy
        let valid = try release(policy) { roles.contains($0) ? [try format($0)] : [] }
        XCTAssertNoThrow(try Validation.validate(valid, policy: policy))
        for role in roles {
            for bad in [[], [try format(role, readers: [2], writers: [2])]] {
                let value = try release(policy) { $0 == role ? bad : roles.contains($0) ? [try format($0)] : [] }
                XCTAssertThrowsError(try Validation.validate(value, policy: policy))
            }
        }
        let readOnlySetup = try release(policy) { roles.contains($0) ? [try format($0, writers: [])] : [] }
        XCTAssertThrowsError(try Validation.validate(readOnlySetup, policy: policy))
    }
    func testManifestAndActualSignatureHashesMustMatchEveryRetainedRole() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), policy = r.fixture.runtime.plan.host.codePolicy
        let value = try release(policy) { roles.contains($0) ? [try format($0)] : [] }
        for role in roles {
            var hashes = value.codeDirectoryHashes; hashes[role] = Data(repeating: 91, count: 20)
            XCTAssertThrowsError(try Validation.validate(.init(manifest: value.manifest, codeDirectoryHashes: hashes), policy: policy))
            hashes.removeValue(forKey: role)
            XCTAssertThrowsError(try Validation.validate(.init(manifest: value.manifest, codeDirectoryHashes: hashes), policy: policy))
        }
    }
    func testAnotherRoleCannotSubstituteForAMissingConsumer() throws {
        let r = try GatewayRuntimeSettingsStoreTests.Ready(), policy = r.fixture.runtime.plan.host.codePolicy
        for role in roles {
            let value = try release(policy, missing: role) { roles.contains($0) ? [try format($0)] : [] }
            XCTAssertThrowsError(try Validation.validate(value, policy: policy))
        }
    }
}
