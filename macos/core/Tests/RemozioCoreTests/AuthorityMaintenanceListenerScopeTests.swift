import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class AuthorityMaintenanceListenerScopeTests: XCTestCase {
    private func identifier(_ role: AuthorityCodeRole) -> String {
        switch role { case .app: "dev.sebastiano.remozio.macos"; case .authority: "dev.sebastiano.remozio.macos.authority"; default: "dev.sebastiano.remozio.macos.setup-controller" }
    }
    private func path(_ role: AuthorityCodeRole) -> String {
        switch role { case .app: "Contents/MacOS/Remozio"; case .authority: InstalledAuthorityCommandConfiguration.executablePath; default: AdministrativeSetupConfiguration.executablePath }
    }
    private func entry(_ role: AuthorityCodeRole, active: Bool = true, team: String = "ABCDEFGHIJ") throws -> AuthorityCodeEntry {
        try .init(role: role, teamID: team, identifier: identifier(role), installedGeneration: 4, minimumGeneration: 4,
            codeDirectoryHash: Data(repeating: 1, count: 20), active: active)
    }
    private func format(readers: Set<UInt64> = [AuthorityMaintenanceChannelScope.protocolVersion],
                        writers: Set<UInt64> = [AuthorityMaintenanceChannelScope.protocolVersion]) throws -> ReleaseFormat {
        try .init(name: AuthorityMaintenanceChannelScope.formatName, readers: readers, writers: writers)
    }
    private func release(formats: (AuthorityCodeRole) throws -> [ReleaseFormat],
                         edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws -> SignedReleaseEvidence {
        let components = try [AuthorityCodeRole.app, .authority, .setupController].map { role in
            var selected = try formats(role)
            if role != .app { selected.append(try .init(name: AuthorityMaintenanceCloseMarker.formatName, readers: [1], writers: role == .authority ? [1] : [])) }
            if role != .app {
                for kind in [AuthorityMaintenanceUnboundRequest.Kind.release, .gate] {
                    selected.append(try .init(name: kind.rawValue, readers: [1], writers: [1]))
                }
            }
            return try edit(.init(role: role, identifier: identifier(role), generation: 4, relativePath: path(role),
                codeDirectoryHash: role == .app ? nil : Data(repeating: 1, count: 20), build: "4", teamID: "ABCDEFGHIJ", formats: selected))
        }
        return .init(manifest: try .init(release: "0.1.0", build: "4", components: components),
            codeDirectoryHashes: Dictionary(uniqueKeysWithValues: components.map { ($0.role, $0.codeDirectoryHash ?? Data(repeating: 1, count: 20)) }))
    }
    private func validRelease() throws -> SignedReleaseEvidence { try release { $0 == .app ? [] : [try self.format()] } }
    func testServiceAddressReusesOnlyTheExactPresenceInterfaceForItsAccount() throws {
        let account = Data(repeating: 1, count: 16), other = Data(repeating: 2, count: 16), paths = try RuntimePreparationPaths(accountID: account)
        let service = try AuthorityMaintenanceChannelScope.serviceName(accountID: account)
        XCTAssertEqual(service, paths.presenceService)
        XCTAssertNotEqual(service, paths.authorityService); XCTAssertNotEqual(service, paths.gatewaySettingsControlService)
        XCTAssertNotEqual(service, try AuthorityMaintenanceChannelScope.serviceName(accountID: other))
        for n in [0, 15, 17] { XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.serviceName(accountID: Data(repeating: 1, count: n))) }
    }
    func testBothParticipantsMustDeclareReadingAndWritingTheSelectedVersion() throws {
        let authority = try entry(.authority), setup = try entry(.setupController)
        XCTAssertEqual(AuthorityMaintenanceChannelScope.protocolVersion, 3)
        for versions: Set<UInt64> in [[3], [1, 3], [2, 3]] {
            let evidence = try release { $0 == .app ? [] : [try self.format(readers: versions, writers: versions)] }
            XCTAssertNoThrow(try AuthorityMaintenanceChannelScope.validate(evidence, authority: authority, setup: setup))
        }
        for role in [AuthorityCodeRole.authority, .setupController] {
            // The selected version must be present in both directions.
            for formats in [[], [try format(readers: [1], writers: [1])], [try format(readers: [2], writers: [2])], [try format(writers: [])],
                            [try format(readers: [1, 3], writers: [1])], [try format(readers: [2, 3], writers: [2])]] {
                let evidence = try release { $0 == role ? formats : [try self.format()] }
                XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.validate(evidence, authority: authority, setup: setup))
            }
        }
    }
    func testBothUnboundFormatsRemainRequiredForChannelThree() throws {
        let authority = try entry(.authority), setup = try entry(.setupController)
        for role in [AuthorityCodeRole.authority, .setupController] {
            for kind in [AuthorityMaintenanceUnboundRequest.Kind.release, .gate] {
                let evidence = try release(formats: { $0 == .app ? [] : [try self.format()] }, edit: { component in
                    guard component.role == role else { return component }
                    return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                        relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                        build: component.build, teamID: component.teamID,
                        formats: component.formats.filter { $0.name != kind.rawValue })
                })
                XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.validate(evidence, authority: authority, setup: setup))
            }
        }
    }
    func testCloseMarkerNeedsBothReadersAndOnlyTheAuthorityWriter() throws {
        let original = try validRelease(), authority = try entry(.authority), setup = try entry(.setupController)
        for role in [AuthorityCodeRole.authority, .setupController] {
            for mode in 0..<3 {
                let components = try original.manifest.components.map { c -> ReleaseComponent in
                    guard c.role == role else { return c }
                    var formats = c.formats.filter { $0.name != AuthorityMaintenanceCloseMarker.formatName }
                    if mode != 0 {
                        formats.append(try .init(name: AuthorityMaintenanceCloseMarker.formatName, readers: mode == 1 ? [2] : [1],
                            writers: mode == 2 ? (role == .authority ? [] : [1]) : (role == .authority ? [2] : [])))
                    }
                    return try .init(role: c.role, identifier: c.identifier, generation: c.generation, relativePath: c.relativePath,
                        codeDirectoryHash: c.codeDirectoryHash, build: c.build, teamID: c.teamID, formats: formats)
                }
                let evidence = try SignedReleaseEvidence(manifest: .init(release: "0.1.0", build: "4", components: components),
                    codeDirectoryHashes: original.codeDirectoryHashes)
                XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.validate(evidence, authority: authority, setup: setup))
            }
        }
    }
    func testEveryRetainedIdentityHashGenerationAndFixedPathMustMatch() throws {
        let authority = try entry(.authority), setup = try entry(.setupController)
        for role in [AuthorityCodeRole.authority, .setupController] {
            for mode in 0..<5 {
                let evidence = try release(formats: { _ in [try self.format()] }, edit: { c in
                    guard c.role == role else { return c }
                    return try .init(role: c.role, identifier: mode == 0 ? c.identifier + ".other" : c.identifier,
                        generation: mode == 1 ? 5 : c.generation, relativePath: mode == 4 ? c.relativePath + ".other" : c.relativePath,
                        codeDirectoryHash: mode == 2 ? Data(repeating: 2, count: 20) : c.codeDirectoryHash,
                        build: c.build, teamID: mode == 3 ? nil : c.teamID, formats: c.formats)
                })
                XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.validate(evidence, authority: authority, setup: setup))
            }
            let original = try validRelease(); var hashes = original.codeDirectoryHashes
            hashes[role] = Data(repeating: 99, count: 20)
            XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.validate(.init(manifest: original.manifest, codeDirectoryHashes: hashes), authority: authority, setup: setup))
            hashes.removeValue(forKey: role)
            XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.validate(.init(manifest: original.manifest, codeDirectoryHashes: hashes), authority: authority, setup: setup))
        }
    }
    func testInactiveCrossedRolesAndForeignTeamsCannotSelectTheListener() throws {
        let evidence = try validRelease(), authority = try entry(.authority), setup = try entry(.setupController)
        XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.validate(evidence, authority: entry(.authority, active: false), setup: setup))
        XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.validate(evidence, authority: authority, setup: entry(.setupController, active: false)))
        XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.validate(evidence, authority: setup, setup: authority))
        XCTAssertThrowsError(try AuthorityMaintenanceChannelScope.validate(evidence, authority: authority, setup: entry(.setupController, team: "KLMNOPQRST")))
    }
    func testAccountPreflightCannotReserveConnectionsOrAcceptClosedAdmission() throws {
        let account = Data(repeating: 1, count: 16), admission = try AuthorityMaintenancePairingAdmission(accountID: account, incarnation: Data(repeating: 4, count: 16))
        XCTAssertNoThrow(try admission.requireAccount(account)); XCTAssertEqual(try admission.connectionReservations(), 0)
        XCTAssertThrowsError(try admission.requireAccount(Data(repeating: 2, count: 16)))
        XCTAssertEqual(try admission.connectionReservations(), 0); admission.close(); XCTAssertThrowsError(try admission.requireAccount(account))
    }
    func testNativeListenerRefusesOrdinaryIdentityBeforeCreatingAService() throws {
        XCTAssertNotEqual(getuid(), 0)
        let account = Data(repeating: 1, count: 16), admission = try AuthorityMaintenancePairingAdmission(accountID: account, incarnation: Data(repeating: 4, count: 16))
        let access = try AuthorityMaintenanceChannelAccess.openOwned(admission: admission, check: { _ in XCTFail("No native scope read") }, observe: { _ in throw JournalLeaseError.rootRequired })
        XCTAssertThrowsError(try AuthorityMaintenanceConnections(accountID: account, authorityCode: entry(.authority), setupCode: entry(.setupController), release: validRelease(), access: access)) {
            XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
        }
        XCTAssertEqual(try admission.connectionReservations(), 0)
    }
}
