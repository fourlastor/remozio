import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

final class GatewayConfigurationBundleTests: XCTestCase {
    private static let pem = Result { () throws -> String in
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run(); let bytes = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw PortableSetupError.rejected }; return String(decoding: bytes, as: UTF8.self)
    }
    private var limits: CBORLimits { get throws { try .init(maxBytes: 262144, maxDepth: 4, maxItems: 256) } }
    private func provider() throws -> SetupFCMConfiguration {
        try .init(project: "synthetic-project", clientEmail: "fixture@fixture.iam.gserviceaccount.com",
            privateKeyID: "fixture-key", privateKeyPEM: Self.pem.get())
    }
    private func settings(candidateLifetime: UInt64 = 300000, lease: UInt64 = 15000, storedControls: Int = 4096) throws -> GatewayServiceSettings {
        try .init(delivery: .init(maximumFlights: 4, minimumSendIntervalMillis: 1000),
            probe: .init(maximumAttempts: 3, minimumRetryDelayMillis: 1000, maximumTTLSeconds: 300),
            wake: .init(maximumEntries: 32, maximumAttempts: 3, minimumEnrollmentIntervalMillis: 1000,
                maximumLifetimeMillis: 300000, maximumTTLSeconds: 300), authorityLeaseMillis: lease,
            maximumStoredControls: storedControls, maximumCandidateLifetimeMillis: candidateLifetime)
    }
    private func map(_ bytes: Data) throws -> [UInt64: CBORValue] {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits) else { throw GatewayPreparationError.invalidRecord }
        return fields
    }
    private func encode(_ fields: [UInt64: CBORValue]) throws -> Data { try DeterministicCBOR.encode(.map(fields), limits: limits) }
    private func plan(_ original: RuntimeActivationPlan, host: InstalledAuthorityCommandConfiguration,
                      transport: TransportPairingStartupConfiguration) throws -> RuntimeActivationPlan {
        var fields = try map(original.encoded); fields[3] = .bytes(host.canonicalBytes); fields[4] = .bytes(transport.canonicalBytes)
        return try RuntimeActivationPlan.decode(encode(fields))
    }
    private func fixture(customized: Bool = false, maximumControls: Int = 4096,
                         _ body: (RuntimeActivationPlan, GatewayPreparationMaterial, InstallationInventory) throws -> Void) throws {
        guard getuid() > 0, getuid() == geteuid() else { throw XCTSkip("Ordinary-owner configuration fixture") }
        let roles: [AuthorityCodeRole] = [.app, .authority, .transport, .notificationGateway, .commandFrontend, .commandMonitor, .commandChild]
        let policy = try AuthorityCodePolicy(entries: roles.map { role in
            try .init(role: role, teamID: "ABCDEFGHIJ", identifier: "dev.remozio.role-\(role.rawValue)", installedGeneration: 1,
                minimumGeneration: 1, codeDirectoryHash: Data(repeating: UInt8(role.rawValue), count: 20), active: true)
        })
        let f = try AccountPreparationFixture(policy: policy), machine = try f.open(initialize: true)
        defer { try? machine.close() }
        let account = try f.resume(machine, f.begin(machine))
        let services = try ServiceAccountPlan(account: account, planID: AccountPreparationIntent.randomID(), claims: [
            .init(accountID: account.accountID, role: .transport, number: 20000, userID: UUID(), groupID: UUID()),
            .init(accountID: account.accountID, role: .gateway, number: 20001, userID: UUID(), groupID: UUID())])
        let runtime = try RuntimePreparationMaterial.create(services: services,
            notValidBefore: Date().addingTimeInterval(-60), notValidAfter: Date().addingTimeInterval(600))
        let inventory = try XCTUnwrap(machine.inventory())
        var foreground = try RuntimeActivationPlan(account: account, initialization: XCTUnwrap(machine.initialization(accountID: account.accountID)),
            runtime: .init(reference: runtime.reference, configurationPublished: true), inventory: inventory)
        if customized {
            let old = foreground.host.command
            let command = try AuthorityCommandStartupConfiguration(presence: old.presence, serviceName: old.serviceName, policyPath: old.policyPath,
                environment: old.environment, submissionLimits: old.submissionLimits, captureLimits: old.captureLimits, maximumSessions: 7,
                receiveWaitMilliseconds: 123, replyTimeoutMilliseconds: 3333, maximumAncestryEntries: 5,
                approvalLifetimeMilliseconds: 90000, execution: old.execution)
            let host = foreground.host
            let customHost = try InstalledAuthorityCommandConfiguration(machineDirectory: host.machineDirectory, installationID: host.installationID,
                releaseDigest: host.releaseDigest, codePolicy: host.codePolicy, command: command, label: host.label, plistName: host.plistName,
                jobPlacement: host.jobPlacement)
            let customTransport = try TransportPairingStartupConfiguration(transport: foreground.transport.transport,
                control: foreground.transport.control, relayPort: 52432)
            foreground = try plan(foreground, host: customHost, transport: customTransport)
        }
        let material = try GatewayPreparationMaterial.create(runtime: runtime.reference, provider: provider(), senderID: "123",
            packageName: "dev.remozio.android", fileWakeCustodyAccepted: true, maximumControls: maximumControls)
        try body(foreground, material, foreground.enrolledInventory(inventory))
    }
    private func bundle(_ foreground: RuntimeActivationPlan, _ material: GatewayPreparationMaterial,
                        _ inventory: InstallationInventory) throws -> GatewayConfigurationBundle {
        try .init(foreground: foreground, material: material.reference, inventory: inventory, settings: settings())
    }

    func testAllThreeServicesUseTheSameRetainedScopeAndIndependentCredentials() throws {
        try fixture { foreground, material, inventory in
            let value = try bundle(foreground, material, inventory)
            let paths = try RuntimePreparationPaths(accountID: foreground.accountID)
            XCTAssertEqual(value.gateway.registration, material.runtime.gateway)
            XCTAssertEqual(value.gateway.receiptPublicKey, material.phonePush.gatewayReceiptPublicKey)
            XCTAssertEqual(value.gateway.serviceUID, 20001); XCTAssertEqual(value.gateway.authorityPolicy.expectedUserID, 0)
            XCTAssertEqual(value.gateway.wakeEndpoint?.policy.expectedUserID, 20000)
            XCTAssertEqual(value.gateway.wakeEndpoint?.serviceName, paths.gatewayWakeService)
            XCTAssertEqual(value.gateway.directoryPath, paths.gatewayDirectory)
            XCTAssertEqual(value.gateway.providerPath, paths.gatewayProvider); XCTAssertEqual(value.gateway.receiptKeyPath, paths.gatewayReceiptKey)
            XCTAssertEqual(value.commandHost.command.presence.wake.phonePush?.canonicalBytes, material.phonePush.canonicalBytes)
            let wake = try XCTUnwrap(value.transport.wake)
            XCTAssertEqual(wake.wake.publicKey, try material.reference.wakePublicKey)
            XCTAssertEqual(wake.wake.credentialID, material.wakeCredentialID); XCTAssertEqual(wake.wake.custody, .protectedFile)
            XCTAssertEqual(wake.wake.transportUID, 20000); XCTAssertEqual(wake.wake.gatewayPolicy.expectedUserID, 20001)
            XCTAssertEqual(wake.wake.keyRecordPath, paths.transportWakeKey)
            XCTAssertEqual(wake.transport.canonicalBytes, foreground.transport.transport.canonicalBytes)
            XCTAssertEqual(value.gatewayJob.declaration.role, .notificationGateway)
            XCTAssertEqual(value.gatewayJob.declaration.executionUID, 20001)
            XCTAssertEqual(value.gatewayJob.configurationPath, paths.gatewayConfiguration)
            XCTAssertEqual(value.gatewayJob.machServices, [paths.gatewayService, paths.gatewayWakeService])
            XCTAssertEqual(try GatewayServiceConfiguration.decode(value.gateway.canonicalBytes).canonicalBytes, value.gateway.canonicalBytes)
            XCTAssertEqual(try TransportPairingStartupConfiguration.decode(value.transport.canonicalBytes).canonicalBytes, value.transport.canonicalBytes)
            XCTAssertEqual(try InstalledAuthorityCommandConfiguration.decode(value.commandHost.canonicalBytes).canonicalBytes, value.commandHost.canonicalBytes)
        }
    }
    func testOnlyOptionalPushAndWakeFieldsChangeInACustomizedForegroundConfiguration() throws {
        try fixture(customized: true) { foreground, material, inventory in
            let value = try bundle(foreground, material, inventory)
            let old = foreground.host.command, new = value.commandHost.command
            var wake = try map(new.presence.wake.canonicalBytes); wake[0] = .unsigned(1); wake.removeValue(forKey: 11)
            XCTAssertEqual(try encode(wake), old.presence.wake.canonicalBytes)
            var presence = try map(new.presence.canonicalBytes); presence[1] = .bytes(old.presence.wake.canonicalBytes)
            XCTAssertEqual(try encode(presence), old.presence.canonicalBytes)
            var command = try map(new.canonicalBytes); command[1] = .bytes(old.presence.canonicalBytes)
            XCTAssertEqual(try encode(command), old.canonicalBytes)
            var host = try map(value.commandHost.canonicalBytes); host[5] = .bytes(old.canonicalBytes)
            XCTAssertEqual(try encode(host), foreground.host.canonicalBytes)
            var transport = try map(value.transport.canonicalBytes); transport[2] = .null
            XCTAssertEqual(try encode(transport), foreground.transport.canonicalBytes)
            XCTAssertEqual(value.transport.relayPort, 52432)
            XCTAssertEqual(new.maximumSessions, 7); XCTAssertEqual(new.receiveWaitMilliseconds, 123)
            XCTAssertEqual(new.replyTimeoutMilliseconds, 3333); XCTAssertEqual(new.maximumAncestryEntries, 5)
            XCTAssertEqual(new.approvalLifetimeMilliseconds, 90000)
        }
    }
    func testReconstructionIsStableAndCannotImplicitlyRotateEstablishedKeys() throws {
        try fixture { foreground, material, inventory in
            let first = try bundle(foreground, material, inventory), next = try bundle(foreground, material, inventory)
            XCTAssertEqual(first.gateway.canonicalBytes, next.gateway.canonicalBytes)
            XCTAssertEqual(first.commandHost.canonicalBytes, next.commandHost.canonicalBytes)
            XCTAssertEqual(first.transport.canonicalBytes, next.transport.canonicalBytes)
            let adopted = try plan(foreground, host: first.commandHost, transport: first.transport)
            let repeated = try bundle(adopted, material, first.enrolledInventory(inventory))
            XCTAssertEqual(first.commandHost.canonicalBytes, repeated.commandHost.canonicalBytes)
            XCTAssertEqual(first.transport.canonicalBytes, repeated.transport.canonicalBytes)
            let replacement = try GatewayPreparationMaterial.create(runtime: material.runtime, provider: provider(), senderID: "123",
                packageName: "dev.remozio.android", fileWakeCustodyAccepted: true)
            XCTAssertThrowsError(try bundle(adopted, replacement, inventory))
        }
    }
    func testInventoryProposalAddsOnlyTheGatewayAndIsIdempotent() throws {
        try fixture { foreground, material, inventory in
            let value = try bundle(foreground, material, inventory), proposed = try value.enrolledInventory(inventory)
            XCTAssertEqual(proposed.services.count, inventory.services.count + 1)
            XCTAssertTrue(proposed.services.contains(value.gatewayJob.declaration))
            XCTAssertTrue(inventory.services.allSatisfy { proposed.services.contains($0) })
            XCTAssertEqual(proposed.accounts, inventory.accounts); XCTAssertEqual(proposed.revision, inventory.revision)
            XCTAssertEqual(proposed.releaseDigest, inventory.releaseDigest)
            XCTAssertEqual(try value.enrolledInventory(proposed), proposed)
        }
    }
    func testAnotherAccountMaterialAndMissingForegroundEnrollmentAreRejected() throws {
        try fixture { foreground, material, inventory in
            try fixture { _, other, _ in XCTAssertThrowsError(try bundle(foreground, other, inventory)) }
            XCTAssertThrowsError(try {
                let missing = try InstallationInventory(macID: inventory.macID, installationID: inventory.installationID,
                    revision: inventory.revision, bundlePath: inventory.bundlePath, releaseDigest: inventory.releaseDigest,
                    accounts: inventory.accounts, services: inventory.services.filter { $0 != foreground.transportJob.declaration },
                    formatVersion: inventory.formatVersion)
                return try bundle(foreground, material, missing)
            }())
        }
    }
    func testGatewayStorageMustCoverTheAuthorityControlBudget() throws {
        for authorityCapacity in [10, 4096] {
            try fixture(maximumControls: authorityCapacity) { foreground, material, inventory in
                XCTAssertThrowsError(try GatewayConfigurationBundle(foreground: foreground, material: material.reference,
                    inventory: inventory, settings: settings(storedControls: authorityCapacity - 1))) {
                    XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
                }
                for gatewayCapacity in [authorityCapacity, authorityCapacity + 1] {
                    let value = try GatewayConfigurationBundle(foreground: foreground, material: material.reference,
                        inventory: inventory, settings: settings(storedControls: gatewayCapacity))
                    XCTAssertEqual(value.gateway.settings.maximumStoredControls, gatewayCapacity)
                    XCTAssertEqual(value.commandHost.command.presence.wake.phonePush?.maximumControls, authorityCapacity)
                }
            }
        }
    }
    func testImpossibleLifetimeLeaseAndWakeSettingsCannotProduceAProposal() throws {
        try fixture { foreground, material, inventory in
            for policy in [try settings(candidateLifetime: 1), try settings(lease: 200)] {
                XCTAssertThrowsError(try GatewayConfigurationBundle(foreground: foreground, material: material.reference,
                    inventory: inventory, settings: policy))
            }
            XCTAssertThrowsError(try GatewayConfigurationBundle(foreground: foreground, material: material.reference,
                inventory: inventory, settings: settings(), wakeMaximumConnections: 0))
            XCTAssertThrowsError(try GatewayConfigurationBundle(foreground: foreground, material: material.reference,
                inventory: inventory, settings: settings(), wakePollMilliseconds: 99))
        }
    }
    func testPublicStartupBytesExcludeEveryPrivateRecordAndTLSIdentity() throws {
        try fixture { foreground, material, inventory in
            let value = try bundle(foreground, material, inventory)
            for bytes in [value.gateway.canonicalBytes, value.commandHost.canonicalBytes, value.transport.canonicalBytes, value.gatewayJob.bytes] {
                XCTAssertNil(bytes.range(of: material.providerJSON)); XCTAssertNil(bytes.range(of: material.receiptKeyRecord))
                XCTAssertNil(bytes.range(of: try material.wakeKeyRecord.encode()))
            }
            XCTAssertEqual(String(reflecting: value), "GatewayConfigurationBundle(redacted)")
        }
    }
    func testTypedPrivateFilesUseTheCorrectServiceOwnerAndFixedNames() throws {
        let files: [(AdministrativeSetupPublication.File, String, UInt32)] = [
            (.gatewayProvider(ownerUID: 20001, groupID: 20001), "gateway-provider.json", 20001),
            (.gatewayReceiptKey(ownerUID: 20001, groupID: 20001), "gateway-receipt-key.cbor", 20001),
            (.transportWakeKey(ownerUID: 20000, groupID: 20000), "transport-wake-key.cbor", 20000)]
        for (file, name, owner) in files {
            XCTAssertNoThrow(try file.validate()); XCTAssertEqual(file.name, name)
            XCTAssertEqual(file.fileOwner(processOwner: 0), owner); XCTAssertEqual(file.groupID, owner)
            XCTAssertEqual(file.mode, 0o600); XCTAssertTrue(file.requiresSharedDirectory)
        }
        XCTAssertEqual(AdministrativeSetupPublication.File.gatewayConfiguration.mode, 0o644)
        XCTAssertThrowsError(try AdministrativeSetupPublication.File.gatewayProvider(ownerUID: 0, groupID: 20001).validate())
        XCTAssertThrowsError(try AdministrativeSetupPublication.File.transportWakeKey(ownerUID: 20000, groupID: 0).validate())
    }
}
