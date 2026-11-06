import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class MachineUpdateAuthorityReadinessDeclarationTests: XCTestCase {
    private func policy() throws -> AuthorityCodePolicy {
        try .init(entries: [.app, .authority, .transport, .notificationGateway, .commandFrontend,
            .commandMonitor, .commandChild, .setupController].map { role in
            try .init(role: role, teamID: "ABCDEFGHIJ",
                identifier: role == .app ? "dev.sebastiano.remozio.macos" : "dev.remozio.readiness.role-\(role.rawValue)",
                installedGeneration: 1, minimumGeneration: 1,
                codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
        })
    }
    private func release(_ policy: AuthorityCodePolicy,
        readinessRole: AuthorityCodeRole? = .authority, readinessReaders: Set<UInt64> = [1],
        readinessWriters: Set<UInt64> = [1],
        hostReaders: [AuthorityCodeRole: Set<UInt64>] = [:],
        hostWriters: [AuthorityCodeRole: Set<UInt64>] = [:]) throws -> SignedReleaseEvidence {
        try NativeHostReleaseFixture.make(policy: policy) { component in
            var formats = try component.formats.map { format in
                guard format.name == "authority.command-host-config" else { return format }
                return try ReleaseFormat(name: format.name,
                    readers: hostReaders[component.role] ?? format.readers.union([4]),
                    writers: hostWriters[component.role] ?? format.writers.union([4]),
                    migrations: format.migrations)
            }
            if component.role == readinessRole {
                formats.append(try .init(name: MachineUpdateAuthorityReadinessDeclaration.formatName,
                    readers: readinessReaders, writers: readinessWriters))
            }
            return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                build: component.build, teamID: component.teamID, formats: formats, requests: component.requests)
        }
    }
    private func changed(_ policy: AuthorityCodePolicy, role: AuthorityCodeRole,
        edit: (AuthorityCodeEntry) throws -> AuthorityCodeEntry) throws -> AuthorityCodePolicy {
        try .init(entries: policy.entries.map { $0.role == role ? try edit($0) : $0 })
    }
    private func entry(_ old: AuthorityCodeEntry, teamID: String? = nil, identifier: String? = nil,
        generation: UInt64? = nil, hash: Data? = nil, active: Bool? = nil) throws -> AuthorityCodeEntry {
        try .init(role: old.role, teamID: teamID ?? old.teamID, identifier: identifier ?? old.identifier,
            installedGeneration: generation ?? old.installedGeneration, minimumGeneration: old.minimumGeneration,
            codeDirectoryHash: hash ?? old.codeDirectoryHash, active: active ?? old.active)
    }
    private func refuses(_ release: SignedReleaseEvidence, _ policy: AuthorityCodePolicy,
        file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try MachineUpdateAuthorityReadinessDeclaration.validate(release, policy: policy),
            file: file, line: line) { XCTAssertEqual($0 as? InstalledAuthorityCommandError, .wrongRelease, file: file, line: line) }
    }
    func testReadinessServiceUsesTheExactAccountAuthorityNamespace() throws {
        let one = Data(repeating: 1, count: 16), two = Data(repeating: 2, count: 16)
        let first = try MachineUpdateAuthorityReadinessDeclaration.serviceName(accountID: one)
        XCTAssertEqual(first, try RuntimePreparationPaths(accountID: one).authorityService + ".readiness")
        XCTAssertNotEqual(first, try MachineUpdateAuthorityReadinessDeclaration.serviceName(accountID: two))
        XCTAssertTrue(GatewayWakeEndpointConfiguration.validServiceName(first))
    }
    func testReadinessServiceRefusesMalformedAccountIDs() throws {
        for length in [0, 15, 17] {
            XCTAssertThrowsError(try MachineUpdateAuthorityReadinessDeclaration.serviceName(
                accountID: Data(repeating: 1, count: length)))
        }
    }
    func testExplicitReadinessAndBothHostDeclarationsAreAccepted() throws {
        let policy = try policy(), candidate = try release(policy)
        XCTAssertNoThrow(try MachineUpdateAuthorityReadinessDeclaration.validate(candidate, policy: policy))
        XCTAssertEqual(MachineUpdateAuthorityReadinessDeclaration.formatName, "authority.installed-readiness")
        XCTAssertEqual(MachineUpdateAuthorityReadinessDeclaration.version, 1)
    }
    func testAnAbsentReadinessDeclarationIsRefused() throws {
        let policy = try policy()
        refuses(try release(policy, readinessRole: nil), policy)
    }
    func testAnUnknownOnlyReadinessVersionIsRefused() throws {
        let policy = try policy()
        refuses(try release(policy, readinessReaders: [2], readinessWriters: [2]), policy)
    }
    func testAReadOnlyReadinessDeclarationIsRefused() throws {
        let policy = try policy()
        refuses(try release(policy, readinessWriters: []), policy)
    }
    func testASetupControllerDeclarationCannotStandInForTheAuthority() throws {
        let policy = try policy()
        refuses(try release(policy, readinessRole: .setupController), policy)
    }
    func testBothParticipantsMustReadTheReadinessHostFormat() throws {
        let policy = try policy()
        for role in [AuthorityCodeRole.authority, .setupController] {
            refuses(try release(policy, hostReaders: [role: [1, 2, 3]],
                hostWriters: [role: [1, 2, 3]]), policy)
        }
    }
    func testBothParticipantsMustWriteTheReadinessHostFormat() throws {
        let policy = try policy()
        for role in [AuthorityCodeRole.authority, .setupController] {
            refuses(try release(policy, hostWriters: [role: [1, 2, 3]]), policy)
        }
    }
    func testMissingAndInactiveParticipantPolicyEntriesAreRefused() throws {
        let policy = try policy(), candidate = try release(policy)
        for role in [AuthorityCodeRole.authority, .setupController] {
            refuses(candidate, try .init(entries: policy.entries.filter { $0.role != role }))
            refuses(candidate, try changed(policy, role: role) { try self.entry($0, active: false) })
        }
    }
    func testEachParticipantMustMatchItsPolicyIdentityGenerationAndHash() throws {
        let policy = try policy(), candidate = try release(policy)
        for role in [AuthorityCodeRole.authority, .setupController] {
            let cases = try [
                changed(policy, role: role) { try self.entry($0, teamID: "KLMNOPQRST") },
                changed(policy, role: role) { try self.entry($0, identifier: $0.identifier + ".changed") },
                changed(policy, role: role) { try self.entry($0, generation: $0.installedGeneration + 1) },
                changed(policy, role: role) { try self.entry($0, hash: Data(repeating: 99, count: 20)) }
            ]
            for changed in cases { refuses(candidate, changed) }
        }
    }
    func testEachParticipantMustMatchItsObservedCodeHash() throws {
        let policy = try policy(), candidate = try release(policy)
        for role in [AuthorityCodeRole.authority, .setupController] {
            var hashes = candidate.codeDirectoryHashes; hashes[role] = Data(repeating: 100, count: 20)
            refuses(.init(manifest: candidate.manifest, codeDirectoryHashes: hashes), policy)
        }
    }
    func testMissingObservedParticipantHashesAreRefused() throws {
        let policy = try policy(), candidate = try release(policy)
        for role in [AuthorityCodeRole.authority, .setupController] {
            var hashes = candidate.codeDirectoryHashes; hashes.removeValue(forKey: role)
            refuses(.init(manifest: candidate.manifest, codeDirectoryHashes: hashes), policy)
        }
    }
    func testExtraDeclaredVersionsDoNotInvalidateSupportedVersions() throws {
        let policy = try policy()
        let candidate = try release(policy, readinessReaders: [1, 2], readinessWriters: [1, 2],
            hostReaders: [.authority: [4, 5], .setupController: [4, 5]],
            hostWriters: [.authority: [4, 5], .setupController: [4, 5]])
        XCTAssertNoThrow(try MachineUpdateAuthorityReadinessDeclaration.validate(candidate, policy: policy))
    }
    func testRepeatedValidationDoesNotChangeTheRetainedPolicyOrRelease() throws {
        let policy = try policy(), candidate = try release(policy)
        let bytes = try policy.bytes, digest = try InstallationInventory.digest(candidate)
        for _ in 0..<3 {
            try MachineUpdateAuthorityReadinessDeclaration.validate(candidate, policy: policy)
            XCTAssertEqual(try policy.bytes, bytes)
            XCTAssertEqual(try InstallationInventory.digest(candidate), digest)
        }
    }
}
