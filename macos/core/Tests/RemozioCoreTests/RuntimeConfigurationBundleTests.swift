import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class RuntimeConfigurationBundleTests: XCTestCase {
    private let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .commandFrontend, .commandMonitor, .commandChild]
    private func policy(omitting omitted: AuthorityCodeRole? = nil) throws -> AuthorityCodePolicy {
        try .init(entries: roles.filter { $0 != omitted }.map { role in
            try .init(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\(role.rawValue)",
                installedGeneration: 1, minimumGeneration: 1, codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
        })
    }
    private func fixture(omitting role: AuthorityCodeRole? = nil,
                         _ body: (AccountPreparationFixture, AccountPreparationIntent, AuthorityInitializationIntent,
                                  RuntimePreparationMaterial, InstallationInventory) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner configuration fixture") }
        let f = try AccountPreparationFixture(policy: policy(omitting: role)), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        let plan = try ServiceAccountPlan(account: account, planID: AccountPreparationIntent.randomID(), claims: [
            .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
            .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
        let now = Date(), material = try RuntimePreparationMaterial.create(services: plan,
            notValidBefore: now.addingTimeInterval(-60), notValidAfter: now.addingTimeInterval(600))
        try body(f, account, XCTUnwrap(machine.initialization(accountID: account.accountID)), material, XCTUnwrap(machine.inventory()))
    }
    private func bundle(_ account: AccountPreparationIntent, _ initial: AuthorityInitializationIntent,
                        _ material: RuntimePreparationMaterial, _ inventory: InstallationInventory) throws -> RuntimeConfigurationBundle {
        try .init(account: account, initialization: initial, reference: material.reference, inventory: inventory,
            presencePolicy: .init(observationLifetimeMilliseconds: 5000, unavailableGraceMilliseconds: 1000), environment: [.init(name: Data("PATH".utf8), value: Data("/usr/bin:/bin:/usr/sbin:/sbin".utf8), source: .minimal)],
            submissionLimits: .init(maxBytes: 65536, maxDepth: 16, maxItems: 8192),
            captureLimits: .init(maxBytes: 65536, maxDepth: 16, maxItems: 8192))
    }

    func testRealStartupTypesShareTheRetainedIdentityAndAccountScope() throws {
        try fixture { _, account, initial, material, inventory in
            let value = try bundle(account, initial, material, inventory)
            let direct = value.transport.transport
            XCTAssertEqual(direct.macID, account.macID); XCTAssertEqual(direct.accountID, account.accountID)
            XCTAssertEqual(direct.ownerUID, account.ownerUID); XCTAssertEqual(direct.serviceUID, 20000)
            XCTAssertEqual(direct.identityPublicKeyInfo, material.transportPublicKeyInfo)
            XCTAssertEqual(direct.identitySource, .protectedFile(path: value.paths.transportIdentity))
            XCTAssertEqual(value.command.presence.pairing?.transportPublicKey,
                try material.reference.transportPublicKeyX963)
            XCTAssertEqual(value.command.presence.wake.request.authorityPublicKey, account.authorityPublicKey)
            XCTAssertEqual(value.command.presence.wake.registration, material.gateway)
            XCTAssertEqual(value.command.presence.wake.gatewayPolicy.expectedUserID, 20001)
            XCTAssertNil(value.transport.wake)
            XCTAssertEqual(value.elevationPolicy.canonicalBytes, account.policyBytes)
            XCTAssertEqual(value.command.presence.wake.request.service.journalDirectory,
                (initial.journalPath as NSString).deletingLastPathComponent)
            XCTAssertEqual(value.command.execution?.monitorPath, inventory.bundlePath + "/Contents/Helpers/RemozioCommandMonitor")
            XCTAssertEqual(value.presenceClient.ownerUID, account.ownerUID)
            XCTAssertEqual(value.presenceClient.rootPolicy.expectedUserID, 0)
            XCTAssertEqual(value.pairingClient.appPolicy.expectedUserID, account.ownerUID)
            XCTAssertEqual(value.pairingClient.transportPolicy.expectedUserID, 20000)
            XCTAssertEqual(value.frontendClient.serviceName, value.command.serviceName)
            XCTAssertEqual(value.frontendClient.accountID, account.accountID)
            XCTAssertEqual(value.frontendClient.authorityPolicy.expectedUserID, 0)
            XCTAssertEqual(value.frontendClient.submissionLimits.maxBytes, value.command.submissionLimits.maxBytes)
            XCTAssertFalse(value.paths.serviceDirectory.hasPrefix(AccountPreparationController.accountsDirectory + "/"))
        }
    }

    func testRepeatedConstructionAndNativeCodecsPreserveEveryPublishedByte() throws {
        try fixture { _, account, initial, material, inventory in
            let a = try bundle(account, initial, material, inventory), b = try bundle(account, initial, material, inventory)
            let publicBytes = [a.transport.canonicalBytes, a.presenceClient.canonicalBytes, a.pairingClient.canonicalBytes, a.frontendClient.canonicalBytes]
            XCTAssertEqual(a.command.canonicalBytes, b.command.canonicalBytes)
            XCTAssertEqual(publicBytes, [b.transport.canonicalBytes, b.presenceClient.canonicalBytes, b.pairingClient.canonicalBytes, b.frontendClient.canonicalBytes])
            XCTAssertEqual(try AuthorityCommandStartupConfiguration.decode(a.command.canonicalBytes).canonicalBytes, a.command.canonicalBytes)
            XCTAssertEqual(try TransportPairingStartupConfiguration.decode(publicBytes[0]).canonicalBytes, publicBytes[0])
            XCTAssertEqual(try AuthorityPresenceClientConfiguration.decode(publicBytes[1]).canonicalBytes, publicBytes[1])
            XCTAssertEqual(try TransportPairingControlConfiguration.decode(publicBytes[2]).canonicalBytes, publicBytes[2])
            XCTAssertEqual(try CommandFrontendConfiguration.decode(publicBytes[3]).canonicalBytes, publicBytes[3])
            for bytes in publicBytes { XCTAssertNil(bytes.range(of: material.transportIdentity)) }
        }
    }

    func testMissingActiveCodeRolesCannotProduceAConfiguration() throws {
        for role in roles {
            XCTAssertThrowsError(try fixture(omitting: role) { _, account, initial, material, inventory in
                _ = try bundle(account, initial, material, inventory)
            })
        }
    }

    func testAccountNamespacesKeepEndpointsAndPathsIndependent() throws {
        let first = try RuntimePreparationPaths(accountID: Data(repeating: 1, count: 16))
        let second = try RuntimePreparationPaths(accountID: Data(repeating: 2, count: 16))
        let endpoints = [first.authorityService, first.commandService, first.presenceService, first.pairingService, first.gatewayService]
        XCTAssertEqual(Set(endpoints).count, 5)
        XCTAssertTrue(Set(endpoints).isDisjoint(with: [second.authorityService, second.commandService, second.presenceService,
                                                    second.pairingService, second.gatewayService]))
        XCTAssertNotEqual(first.privateDirectory, second.privateDirectory)
        XCTAssertNotEqual(first.serviceDirectory, second.serviceDirectory)
        XCTAssertNotEqual(first.commandConfiguration, first.policy)
        for id in [Data(), Data(repeating: 0, count: 15), Data(repeating: 0, count: 17)] {
            XCTAssertThrowsError(try RuntimePreparationPaths(accountID: id))
        }
    }

    func testChangedInstallationOrReleaseCannotReuseThePreparedInputs() throws {
        try fixture { _, account, initial, material, inventory in
            for (installation, release) in [(Data(repeating: 19, count: 16), inventory.releaseDigest),
                                            (inventory.installationID, Data(repeating: 20, count: 32))] {
                let changed = try InstallationInventory(macID: inventory.macID, installationID: installation,
                    revision: inventory.revision, bundlePath: inventory.bundlePath, releaseDigest: release,
                    accounts: inventory.accounts, services: inventory.services, formatVersion: inventory.formatVersion)
                XCTAssertThrowsError(try bundle(account, initial, material, changed)) {
                    XCTAssertEqual($0 as? RuntimePreparationError, .changedScope)
                }
            }
        }
    }
}
