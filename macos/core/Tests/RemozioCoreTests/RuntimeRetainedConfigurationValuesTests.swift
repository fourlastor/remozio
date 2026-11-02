import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses owned SQLite and synthetic values. These tests do not register jobs or validate installed Root behavior.
final class RuntimeRetainedConfigurationValuesTests: XCTestCase {
    private struct Invalid: Error {}
    private func changing(_ bytes: Data, _ changes: [UInt64: CBORValue]) throws -> Data {
        let limits = try CBORLimits(maxBytes: 262144, maxDepth: 3, maxItems: 512)
        guard case .map(var fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw Invalid() }
        for (key, value) in changes { fields[key] = value }
        return try DeterministicCBOR.encode(.map(fields), limits: limits)
    }
    private final class Fixture {
        let f: RuntimeActivationFixture
        let initialization: AuthorityInitializationIntent
        let inventory: InstallationInventory
        let clients: RuntimeActivationClients
        init(auditDelivery: Bool = true) throws {
            f = try .init(nativeConsumerHosts: true, phoneRouting: true, phoneAudit: true, auditDelivery: auditDelivery)
            initialization = try XCTUnwrap(f.machine.initialization(accountID: f.account.accountID))
            inventory = try XCTUnwrap(f.machine.inventory())
            let bundle = try f.plan.configurationBundle(account: f.account, initialization: initialization, inventory: inventory)
            clients = .init(presence: bundle.presenceClient, pairing: bundle.pairingClient, frontend: bundle.frontendClient)
        }
        func retain(command: AuthorityCommandStartupConfiguration? = nil,
                    transport: TransportPairingStartupConfiguration? = nil,
                    host: InstalledAuthorityCommandConfiguration? = nil,
                    clients: RuntimeActivationClients? = nil,
                    release: SignedReleaseEvidence? = nil) throws -> RuntimeActivationPlan {
            try .retainingPublished(account: f.account, initialization: initialization, reference: f.material.reference,
                inventory: inventory, installedRelease: release ?? XCTUnwrap(f.nativeRelease),
                command: command ?? f.plan.host.command, transport: transport ?? f.plan.transport,
                host: host, gatewaySettingsHost: f.plan.gatewaySettingsHost, clients: clients ?? self.clients)
        }
    }
    func testRetainsStartupAndClientBytesWithoutChangingTheInventoryOrActivation() throws {
        let f = try Fixture(), before = try f.f.machine.runtimeActivation(accountID: f.f.account.accountID)
        let plan = try f.retain()
        let bundle = try plan.configurationBundle(account: f.f.account, initialization: f.initialization,
            inventory: f.inventory, clients: f.clients)
        XCTAssertEqual(bundle.command.canonicalBytes, f.f.plan.host.command.canonicalBytes)
        XCTAssertEqual(bundle.transport.canonicalBytes, f.f.plan.transport.canonicalBytes)
        XCTAssertEqual(bundle.presenceClient.canonicalBytes, f.clients.presence.canonicalBytes)
        XCTAssertEqual(bundle.pairingClient.canonicalBytes, f.clients.pairing.canonicalBytes)
        XCTAssertEqual(bundle.frontendClient.canonicalBytes, f.clients.frontend.canonicalBytes)
        XCTAssertEqual(try f.f.machine.inventory(), f.inventory)
        let after = try f.f.machine.runtimeActivation(accountID: f.f.account.accountID)
        XCTAssertEqual(try after.plan?.encoded, try before.plan?.encoded)
        XCTAssertEqual(after.jobsRegistered, before.jobsRegistered)
    }
    func testRetainsPushWakeCommandRelayAndFrontendTunables() throws {
        let f = try Fixture(), original = f.f.plan.host.command
        let push = try AuthorityPhonePushStartupConfiguration(projectID: "remozio-fixture", senderID: "123456789",
            packageName: "dev.sebastiano.remozio.android", gatewayReceiptPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
            maximumControls: 77, candidateLifetimeMilliseconds: 98765)
        let wake = try changing(original.presence.wake.canonicalBytes, [0: .unsigned(2), 8: .unsigned(20000),
            9: .unsigned(333), 10: .unsigned(1234), 11: .bytes(push.canonicalBytes)])
        let presence = try changing(original.presence.canonicalBytes, [1: .bytes(wake), 7: .unsigned(123000),
            8: .unsigned(9000), 9: .unsigned(41000)])
        let command = try AuthorityCommandStartupConfiguration.decode(changing(original.canonicalBytes,
            [1: .bytes(presence), 4: .array([.map([0: .bytes(Data("LANG".utf8)), 1: .bytes(Data("en_GB.UTF-8".utf8))])]),
             5: .map([0: .unsigned(70000), 1: .unsigned(17), 2: .unsigned(9000)]),
             7: .unsigned(17), 8: .unsigned(333), 9: .unsigned(7777), 10: .unsigned(23), 11: .unsigned(95000)]))
        let originalTransport = f.f.plan.transport
        let transport = try TransportPairingStartupConfiguration(transport: originalTransport.transport,
            control: originalTransport.control, wake: originalTransport.wake, relayPort: 45678,
            settingsHost: originalTransport.settingsHost)
        let authority = try XCTUnwrap(f.f.plan.host.codePolicy.entries.first { $0.role == .authority && $0.active })
        let frontend = try CommandFrontendConfiguration(macID: f.f.account.macID, accountID: f.f.account.accountID,
            serviceName: command.serviceName, teamID: authority.teamID, authorityIdentifier: authority.identifier,
            authorityHashes: [authority.codeDirectoryHash], submissionLimits: .init(maxBytes: 70000, maxDepth: 17, maxItems: 9000),
            defaultIOMode: .pty, defaultDisconnectBehavior: .terminate, readiness: .init(timeoutMilliseconds: 9000))
        let clients = RuntimeActivationClients(presence: f.clients.presence, pairing: f.clients.pairing, frontend: frontend)
        let plan = try f.retain(command: command, transport: transport, clients: clients)
        let bundle = try plan.configurationBundle(account: f.f.account, initialization: f.initialization,
            inventory: f.inventory, clients: clients)
        XCTAssertEqual(bundle.command.canonicalBytes, command.canonicalBytes)
        XCTAssertEqual(bundle.transport.canonicalBytes, transport.canonicalBytes)
        XCTAssertEqual(bundle.frontendClient.canonicalBytes, frontend.canonicalBytes)
        XCTAssertEqual(bundle.command.presence.wake.phonePush?.canonicalBytes, push.canonicalBytes)
        XCTAssertNil(try f.f.machine.runtimeActivation(accountID: f.f.account.accountID).plan)
    }
    func testRetainsAnExistingHostAndRejectsConflictingCommandBytes() throws {
        let f = try Fixture(), host = f.f.plan.host
        XCTAssertEqual(try f.retain(host: host).host.canonicalBytes, host.canonicalBytes)
        let changed = try AuthorityCommandStartupConfiguration.decode(changing(host.command.canonicalBytes, [7: .unsigned(17)]))
        XCTAssertThrowsError(try f.retain(command: changed, host: host))
        XCTAssertNil(try f.f.machine.runtimeActivation(accountID: f.f.account.accountID).plan)
    }
    func testRejectsForeignStartupAndBundleScope() throws {
        let f = try Fixture(), other = try Fixture()
        XCTAssertThrowsError(try f.retain(command: other.f.plan.host.command))
        XCTAssertThrowsError(try f.retain(transport: other.f.plan.transport))
        let plan = try f.retain()
        XCTAssertThrowsError(try plan.configurationBundle(account: f.f.account, initialization: other.initialization,
            inventory: f.inventory, clients: f.clients))
        XCTAssertThrowsError(try plan.configurationBundle(account: f.f.account, initialization: f.initialization,
            inventory: other.inventory, clients: f.clients))
        let wrongPath = try InstallationInventory(macID: f.inventory.macID, installationID: f.inventory.installationID,
            revision: f.inventory.revision, bundlePath: f.inventory.bundlePath + ".other",
            releaseDigest: f.inventory.releaseDigest, accounts: f.inventory.accounts,
            services: f.inventory.services, formatVersion: f.inventory.formatVersion)
        XCTAssertThrowsError(try plan.configurationBundle(account: f.f.account, initialization: f.initialization,
            inventory: wrongPath, clients: f.clients))
        XCTAssertNil(try f.f.machine.runtimeActivation(accountID: f.f.account.accountID).plan)
    }
    func testRejectsEachForeignClient() throws {
        let f = try Fixture(), other = try Fixture()
        for clients in [RuntimeActivationClients(presence: other.clients.presence, pairing: f.clients.pairing, frontend: f.clients.frontend),
                        .init(presence: f.clients.presence, pairing: other.clients.pairing, frontend: f.clients.frontend),
                        .init(presence: f.clients.presence, pairing: f.clients.pairing, frontend: other.clients.frontend)] {
            XCTAssertThrowsError(try f.retain(clients: clients))
        }
        XCTAssertNil(try f.f.machine.runtimeActivation(accountID: f.f.account.accountID).plan)
    }
    func testRejectsAnotherReleaseBeforeRetainingValues() throws {
        let f = try Fixture()
        let other = try NativeHostReleaseFixture.make(policy: f.f.plan.host.codePolicy,
            phoneRouting: true, phoneAudit: true, auditDelivery: true) { component in
            try .init(role: component.role, identifier: component.identifier, generation: component.generation,
                relativePath: component.relativePath, codeDirectoryHash: component.codeDirectoryHash,
                build: "changed", teamID: component.teamID, formats: component.formats, requests: component.requests)
        }
        XCTAssertThrowsError(try f.retain(release: other))
        XCTAssertNil(try f.f.machine.runtimeActivation(accountID: f.f.account.accountID).plan)
    }
    func testAuditSelectionRequiresDeliveryReadersBeyondCodecSupport() throws {
        let f = try Fixture(auditDelivery: false), source = f.f.plan
        let material = try RuntimePreparationMaterial(materialID: f.f.material.materialID, services: f.f.services,
            transportIdentity: f.f.material.transportIdentity, transportPublicKeyInfo: f.f.material.transportPublicKeyInfo,
            gateway: f.f.material.gateway, serviceActivity: f.f.material.serviceActivity, auditDeliveryVersion: 1)
        let hosts = try GatewaySettingsNativeHostPlan(reference: material.reference, bundlePath: f.inventory.bundlePath,
            policy: source.host.codePolicy)
        let transport = try TransportPairingStartupConfiguration(transport: source.transport.transport,
            control: source.transport.control, wake: source.transport.wake, relayPort: source.transport.relayPort,
            settingsHost: hosts.transport)
        XCTAssertThrowsError(try RuntimeActivationPlan.retainingPublished(account: f.f.account,
            initialization: f.initialization, reference: material.reference, inventory: f.inventory,
            installedRelease: XCTUnwrap(f.f.nativeRelease), command: RuntimeAuditUpgradeConfiguration.command(source.host.command),
            transport: transport, host: nil, gatewaySettingsHost: hosts.gateway, clients: f.clients))
        XCTAssertNil(try f.f.machine.runtimeActivation(accountID: f.f.account.accountID).plan)
    }
}
