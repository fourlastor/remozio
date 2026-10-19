import Darwin
import Foundation
import XCTest
@testable import RemozioCore

final class GatewaySettingsConsumerPreflightTests: XCTestCase, @unchecked Sendable {
    private let team = "ABCDEFGHIJ"
    private func entry(_ role: AuthorityCodeRole, active: Bool = true) throws -> AuthorityCodeEntry {
        try .init(role: role, teamID: team, identifier: "dev.remozio.role-\(role.rawValue)", installedGeneration: 4,
            minimumGeneration: 4, codeDirectoryHash: Data(repeating: 1, count: 20), active: active)
    }
    private func release(role: GatewaySettingsConsumerRole, omit: AuthorityCodeRole? = nil, version: UInt64 = 1,
                         edit: (ReleaseComponent) throws -> ReleaseComponent = { $0 }) throws -> SignedReleaseEvidence {
        let codes: [AuthorityCodeRole] = [.app, role.codeRole, .setupController]
        let components: [ReleaseComponent] = try codes.map { code in
            var formats: [ReleaseFormat] = []
            if code != omit {
                let control = try ReleaseFormat(name: role.formatName, readers: [version], writers: [version])
                formats.append(control)
                if code != .app {
                    let writers: Set<UInt64> = code == .setupController ? [1] : []
                    let fence = try ReleaseFormat(name: GatewayRuntimeSettingsFence.formatName, readers: [1], writers: writers)
                    formats.append(fence)
                }
            }
            let codeHash: Data? = code == .app ? nil : Data(repeating: 1, count: 20)
            let component = try ReleaseComponent(role: code, identifier: "dev.remozio.role-\(code.rawValue)", generation: 4,
                relativePath: "Contents/Helpers/role-\(code.rawValue)", codeDirectoryHash: codeHash,
                build: "4", teamID: team, formats: formats)
            return try edit(component)
        }
        return .init(manifest: try .init(release: "0.1.0", build: "4", components: components),
            codeDirectoryHashes: Dictionary(uniqueKeysWithValues: components.map { ($0.role, $0.codeDirectoryHash ?? Data(repeating: 1, count: 20)) }))
    }
    func testEachRoleRequiresBothExactParticipantsAndItsOwnSignedControlFormat() throws {
        for role in GatewaySettingsConsumerRole.allCases {
            let consumer = try entry(role.codeRole), setup = try entry(.setupController)
            XCTAssertNoThrow(try GatewaySettingsConsumerReleaseValidation.validate(release(role: role), role: role, consumer: consumer, setup: setup))
            for code in [role.codeRole, .setupController] {
                XCTAssertThrowsError(try GatewaySettingsConsumerReleaseValidation.validate(release(role: role, omit: code), role: role, consumer: consumer, setup: setup))
            }
            XCTAssertThrowsError(try GatewaySettingsConsumerReleaseValidation.validate(release(role: role, version: 2), role: role, consumer: consumer, setup: setup))
            let other: GatewaySettingsConsumerRole = role == .gateway ? .transport : .gateway
            XCTAssertThrowsError(try GatewaySettingsConsumerReleaseValidation.validate(release(role: other), role: role, consumer: consumer, setup: setup))
            XCTAssertThrowsError(try GatewaySettingsConsumerReleaseValidation.validate(release(role: role), role: role, consumer: entry(role.codeRole, active: false), setup: setup))
            XCTAssertThrowsError(try GatewaySettingsConsumerReleaseValidation.validate(release(role: role), role: role, consumer: consumer, setup: entry(.setupController, active: false)))
        }
    }
    func testFenceReadersAndSetupWriterAreRequiredBeforeEitherNativeSideCanStart() throws {
        for role in GatewaySettingsConsumerRole.allCases {
            let consumer = try entry(role.codeRole), setup = try entry(.setupController)
            for code in [role.codeRole, .setupController] {
                for mode in 0..<3 {
                    let value = try release(role: role, edit: { component in
                        guard component.role == code else { return component }
                        let other = component.formats.filter { $0.name != GatewayRuntimeSettingsFence.formatName }
                        let replacement: [ReleaseFormat]
                        if mode == 0 { replacement = [] }
                        else if mode == 1 {
                            replacement = [try .init(name: GatewayRuntimeSettingsFence.formatName, readers: [2],
                                writers: code == .setupController ? [2] : [])]
                        } else {
                            // Consumers need no writer. Only Setup publishes retained fences.
                            guard code == .setupController else { return component }
                            replacement = [try .init(name: GatewayRuntimeSettingsFence.formatName, readers: [1, 2], writers: [2])]
                        }
                        return try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                            relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                            build: component.build, teamID: component.teamID, formats: other + replacement)
                    })
                    if mode == 2 && code != .setupController {
                        XCTAssertNoThrow(try GatewaySettingsConsumerReleaseValidation.validate(value, role: role, consumer: consumer, setup: setup))
                    } else {
                        XCTAssertThrowsError(try GatewaySettingsConsumerReleaseValidation.validate(value, role: role, consumer: consumer, setup: setup))
                    }
                }
            }
            XCTAssertNoThrow(try GatewaySettingsConsumerReleaseValidation.validate(release(role: role), role: role,
                consumer: consumer, setup: setup))
        }
    }
    func testRetainedIdentityAndActuallyInspectedCodeHashesCannotBeSubstituted() throws {
        for role in GatewaySettingsConsumerRole.allCases {
            let consumer = try entry(role.codeRole), setup = try entry(.setupController)
            for code in [role.codeRole, .setupController] {
                for mode in 0..<4 {
                    let value = try release(role: role, edit: { c in
                        guard c.role == code else { return c }
                        return try .init(role: c.role, identifier: mode == 0 ? c.identifier + ".other" : c.identifier,
                            generation: mode == 1 ? 5 : c.generation, relativePath: c.relativePath,
                            codeDirectoryHash: mode == 2 ? Data(repeating: 2, count: 20) : c.codeDirectoryHash,
                            build: c.build, teamID: mode == 3 ? nil : c.teamID, formats: c.formats)
                    })
                    XCTAssertThrowsError(try GatewaySettingsConsumerReleaseValidation.validate(value, role: role, consumer: consumer, setup: setup))
                }
                let value = try release(role: role); var hashes = value.codeDirectoryHashes; hashes[code] = nil
                XCTAssertThrowsError(try GatewaySettingsConsumerReleaseValidation.validate(.init(manifest: value.manifest, codeDirectoryHashes: hashes),
                    role: role, consumer: consumer, setup: setup))
            }
        }
    }
    func testNativeFactoriesRefuseTheOrdinaryOwnerBeforeScopeOrConnectionAccess() async throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary owner refusal") }
        let f = try GatewaySettingsConsumerControlFixture()
        let services = f.plan.pair.authority.material.runtime.services
        for role in GatewaySettingsConsumerRole.allCases {
            XCTAssertThrowsError(try GatewaySettingsConsumerChannel(role: role, services: services, consumerCode: entry(role.codeRole),
                setupCode: entry(.setupController), release: release(role: role), expectedGeneration: nil,
                verifyCurrent: { XCTFail("Root guard must precede scope access") })) {
                XCTAssertEqual($0 as? JournalLeaseError, .rootRequired)
            }
            let owner = try f.owner(role: role), access = try GatewaySettingsConsumerAccess(owner: owner, services: services,
                verifyCurrent: { XCTFail("Dedicated process guard must precede scope access") })
            XCTAssertThrowsError(try GatewaySettingsConsumerXPCListener(consumerCode: entry(role.codeRole), setupCode: entry(.setupController),
                release: release(role: role), access: access, acquireActivity: { XCTFail(); return nil }))
            try await owner.close()
        }
    }
    func testAccessUsesTheCurrentOwnerAndDoesNotConstructAProvider() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), services = f.plan.pair.authority.material.runtime.services
        for role in GatewaySettingsConsumerRole.allCases {
            let owner = try f.owner(role: role), access = try GatewaySettingsConsumerAccess(owner: owner, services: services, verifyCurrent: {})
            for (action, expected) in [(GatewaySettingsControlAction.observe, GatewaySettingsConsumerObservation.unknown), (.quiesce, .paused), (.accept, .accepted)] {
                let request = try GatewaySettingsConsumerRequest(binding: owner.binding, fence: f.fence, action: action, challenge: Data(repeating: 1, count: 32))
                let response = try await access.execute(request); XCTAssertEqual(response, expected)
            }
            try await owner.close()
        }
    }
    func testAccessRejectsForeignServicesAndCannotKeepAReleasedOwnerAlive() async throws {
        let f = try GatewaySettingsConsumerControlFixture(), other = try GatewaySettingsConsumerControlFixture()
        var owner: GatewaySettingsConsumerOwner? = try f.owner()
        let binding = try XCTUnwrap(owner).binding
        XCTAssertThrowsError(try GatewaySettingsConsumerAccess(owner: XCTUnwrap(owner), services: other.plan.pair.authority.material.runtime.services, verifyCurrent: {}))
        let access = try GatewaySettingsConsumerAccess(owner: XCTUnwrap(owner), services: f.plan.pair.authority.material.runtime.services, verifyCurrent: {})
        final class WeakOwner { weak var value: GatewaySettingsConsumerOwner?; init(_ value: GatewaySettingsConsumerOwner?) { self.value = value } }
        let weak = WeakOwner(owner); owner = nil; XCTAssertNil(weak.value)
        let request = try GatewaySettingsConsumerRequest(binding: binding, fence: f.fence, action: .observe, challenge: Data(repeating: 2, count: 32))
        do { _ = try await access.execute(request); XCTFail() } catch {}
    }
}
