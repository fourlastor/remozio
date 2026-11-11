import Foundation
import RemozioProtocol
import XCTest
@testable import RemozioCore

/// Uses owned records and a wire map from donor source. No bytes come from a donor execution.
final class RetainedSetupActivationArchiveTests: XCTestCase {
    final class Fixture {
        let source: RetainedSetupConsumerHostArchiveTests.Fixture
        let binding: RuntimeRetainedSetupReleaseBinding
        let host: InstalledAuthorityCommandConfiguration
        let transport: TransportPairingStartupConfiguration
        let gateway: GatewaySettingsConsumerHostConfiguration
        let inventory: InstallationInventory
        let fields: [UInt64: CBORValue]
        let limits = try! CBORLimits(maxBytes: 524288, maxDepth: 4, maxItems: 4096)

        init() throws {
            let source = try RetainedSetupConsumerHostArchiveTests.Fixture()
            let binding = try RuntimeRetainedSetupReleaseBinding.decode(source.json(source.startup))
            let original = source.f.f.plan.host
            let host = try InstalledAuthorityCommandConfiguration(machineDirectory: original.machineDirectory,
                installationID: original.installationID, releaseDigest: binding.installedReleaseDigest,
                codePolicy: original.codePolicy, command: original.command, label: original.label,
                plistName: original.plistName, jobPlacement: original.jobPlacement, gatewaySettingsControlEnabled: true)
            let gateway = try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(
                source.bytes(stage: 3, role: .gateway))
            let settings = try GatewaySettingsConsumerHostConfiguration.decodeForReleaseArchive(source.bytes(stage: 3))
            let base = source.f.f.plan.transport
            let transport = try TransportPairingStartupConfiguration(transport: base.transport, control: base.control,
                wake: base.wake, relayPort: base.relayPort, settingsHost: settings)
            let originalInventory = try XCTUnwrap(source.f.f.machine.inventory())
            let inventory = try InstallationInventory.machineBootstrap(macID: binding.macID,
                installationID: binding.installationID, revision: originalInventory.revision,
                bundlePath: gateway.bundlePath, releaseDigest: binding.installedReleaseDigest)
            self.source = source; self.binding = binding; self.host = host; self.transport = transport
            self.gateway = gateway; self.inventory = inventory
            // Frozen from RuntimeActivationPlan v6 in donor 1e5ee405. The implementation uses a separate archive type.
            fields = [0: .unsigned(6), 1: .bytes(try source.reference.encoded), 2: .text(gateway.bundlePath),
                3: .bytes(host.canonicalBytes), 4: .bytes(transport.canonicalBytes), 5: .bytes(try gateway.encoded),
                6: .null, 7: .null, 8: .null, 9: .bytes(try binding.encoded), 10: .bytes(inventory.canonicalBytes)]
        }
        func bytes(_ fields: [UInt64: CBORValue]? = nil) throws -> Data {
            try DeterministicCBOR.encode(.map(fields ?? self.fields), limits: limits)
        }
        func replacingInventory(macID: Data? = nil, installationID: Data? = nil, releaseDigest: Data? = nil,
                                path: String? = nil, account: InstallationAccount? = nil) throws -> Data {
            let services: [InstallationService]
            if let account {
                services = [try .init(role: .authority, kind: .daemon, domainUID: nil, executionUID: 0,
                    label: "dev.remozio.archive-fixture.authority", plistName: "dev.sebastiano.remozio.macos.archive-fixture.authority.plist", accountID: account.accountID)]
            } else { services = inventory.services }
            let changed = try InstallationInventory(macID: macID ?? inventory.macID,
                installationID: installationID ?? inventory.installationID, revision: inventory.revision,
                bundlePath: path ?? inventory.bundlePath, releaseDigest: releaseDigest ?? inventory.releaseDigest,
                accounts: account.map { [$0] } ?? [], services: services, formatVersion: 2)
            var fields = self.fields; fields[10] = .bytes(changed.canonicalBytes)
            return try bytes(fields)
        }
    }

    func testReadsTheSourceDerivedV6WireMapWithoutChangingOwnedState() throws {
        let f = try Fixture()
        let before = try XCTUnwrap(f.source.f.f.machine.inventory()).canonicalBytes
        let bytes = try f.bytes(), archive = try RuntimeRetainedSetupActivationArchive.decode(bytes)
        XCTAssertEqual(try archive.encoded, bytes)
        XCTAssertEqual(archive.reference, f.source.reference)
        XCTAssertEqual(archive.bundlePath, f.gateway.bundlePath)
        XCTAssertEqual(archive.host.canonicalBytes, f.host.canonicalBytes)
        XCTAssertEqual(archive.transport.canonicalBytes, f.transport.canonicalBytes)
        XCTAssertEqual(archive.gatewaySettingsHost, f.gateway)
        XCTAssertEqual(archive.binding, f.binding)
        XCTAssertEqual(archive.inventory, f.inventory)
        XCTAssertTrue(archive.inventory.accounts.isEmpty)
        XCTAssertNotEqual(archive.reference.services.releaseDigest, archive.inventory.releaseDigest)
        XCTAssertNil(archive.phoneRoutingVersion)
        XCTAssertNil(archive.phoneAuditVersion)
        XCTAssertNil(archive.phoneUpdateSchedulingVersion)
        XCTAssertEqual(try XCTUnwrap(f.source.f.f.machine.inventory()).canonicalBytes, before)
        XCTAssertEqual(archive.description, "RuntimeRetainedSetupActivationArchive(redacted)")
        XCTAssertEqual(archive.debugDescription, archive.description)
    }

    func testRejectsV6AtExecutablePlanAndActualNativeStartupEntries() throws {
        let f = try Fixture(), bytes = try f.bytes()
        let archive = try RuntimeRetainedSetupActivationArchive.decode(bytes)
        XCTAssertThrowsError(try RuntimeActivationPlan.decode(bytes))
        XCTAssertThrowsError(try RuntimeActivationState.Plan(encoded: bytes))
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeGatewayStartup(
            archive.gatewaySettingsHost.encoded, path: archive.gatewaySettingsHost.gatewayConfigurationPath)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
        let path = try RuntimePreparationPaths(accountID: archive.binding.accountID).transportConfiguration
        XCTAssertThrowsError(try GatewaySettingsConsumerNativeScope.decodeTransportStartup(
            archive.transport.canonicalBytes, path: path)) {
            XCTAssertEqual($0 as? GatewayPreparationError, .changedScope)
        }
    }

    func testPreservesEachNullableAndSelectedPhoneContract() throws {
        let f = try Fixture()
        for mask in 0..<8 {
            var fields = f.fields
            for bit in 0..<3 { fields[UInt64(6 + bit)] = mask & (1 << bit) == 0 ? .null : .unsigned(1) }
            let bytes = try f.bytes(fields), archive = try RuntimeRetainedSetupActivationArchive.decode(bytes)
            XCTAssertEqual(try archive.encoded, bytes)
            XCTAssertEqual(archive.phoneRoutingVersion, mask & 1 == 0 ? nil : 1)
            XCTAssertEqual(archive.phoneAuditVersion, mask & 2 == 0 ? nil : 1)
            XCTAssertEqual(archive.phoneUpdateSchedulingVersion, mask & 4 == 0 ? nil : 1)
        }
        for key in UInt64(6)...8 {
            for value in [CBORValue.unsigned(0), .unsigned(2), .text("1"), .bytes(Data())] {
                var fields = f.fields; fields[key] = value
                XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields)))
            }
        }
    }

    func testRejectsInventoryNamespaceReleasePathAndTargetEnrollment() throws {
        let f = try Fixture()
        func changed(_ bytes: Data) -> Data { var copy = bytes; copy[copy.startIndex] ^= 64; return copy }
        for bytes in [
            try f.replacingInventory(macID: changed(f.binding.macID)),
            try f.replacingInventory(installationID: changed(f.binding.installationID)),
            try f.replacingInventory(releaseDigest: f.binding.provisioningReleaseDigest),
            try f.replacingInventory(path: "/Applications/Other.app"),
            try f.replacingInventory(account: .init(accountID: f.binding.accountID, ownerUID: f.binding.ownerUID + 1)),
            try f.replacingInventory(account: .init(accountID: changed(f.binding.accountID), ownerUID: f.binding.ownerUID)),
        ] {
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(bytes))
        }
        let unrelated = try InstallationAccount(accountID: changed(f.binding.accountID), ownerUID: f.binding.ownerUID + 1)
        let archive = try RuntimeRetainedSetupActivationArchive.decode(f.replacingInventory(account: unrelated))
        XCTAssertEqual(archive.inventory.accounts, [unrelated])
    }

    func testRejectsCrossBoundHostsAndHistoricalReleaseSubstitution() throws {
        let f = try Fixture()
        var changedBinding = f.source.startup; changedBinding["activationAttempt"] = UUID().uuidString
        var fields = f.fields; fields[9] = .bytes(try f.source.json(changedBinding))
        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields)))
        fields = f.fields; fields[5] = .bytes(try f.source.bytes(stage: 3, role: .transport))
        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields)))
        fields = f.fields; fields[5] = .bytes(try f.source.bytes(stage: 4, role: .gateway))
        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields)))
        let original = f.source.f.f.plan
        fields = f.fields; fields[3] = .bytes(original.host.canonicalBytes)
        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields)))
        fields = f.fields; fields[4] = .bytes(original.transport.canonicalBytes)
        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields)))
        fields = f.fields; fields[1] = .bytes(try original.reference.encoded)
        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields)))

        let active = f.source.reference
        let withoutActivity = try RuntimeMaterialReference(materialID: active.materialID, services: active.services,
            materialDigest: active.materialDigest, transportPublicKeyInfo: active.transportPublicKeyInfo,
            gateway: active.gateway)
        XCTAssertNil(withoutActivity.serviceActivity)
        var inactiveBindingFields = f.source.startup
        inactiveBindingFields["runtimeReferenceDigest"] = MachineUpdateActivationRecord.digest(
            try withoutActivity.encoded).base64EncodedString()
        let inactiveBinding = try RuntimeRetainedSetupReleaseBinding.decode(f.source.json(inactiveBindingFields))
        XCTAssertNoThrow(try inactiveBinding.requireHistoricalRuntime(withoutActivity))
        XCTAssertNoThrow(try inactiveBinding.requireStartupPolicy(f.host.codePolicy))
        fields = f.fields; fields[1] = .bytes(try withoutActivity.encoded); fields[9] = .bytes(try inactiveBinding.encoded)
        // The external binding is coherent. The host equality checks also refuse this combination.
        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields))) {
            XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
        }

        let disabledHost = try InstalledAuthorityCommandConfiguration(machineDirectory: f.host.machineDirectory,
            installationID: f.host.installationID, releaseDigest: f.host.releaseDigest, codePolicy: f.host.codePolicy,
            command: f.host.command, label: f.host.label, plistName: f.host.plistName,
            jobPlacement: f.host.jobPlacement, gatewaySettingsControlEnabled: false)
        XCTAssertFalse(disabledHost.gatewaySettingsControlEnabled)
        XCTAssertNoThrow(try InstalledAuthorityCommandConfiguration.decode(disabledHost.canonicalBytes))
        XCTAssertNoThrow(try f.binding.requireStartupPolicy(disabledHost.codePolicy))
        fields = f.fields; fields[3] = .bytes(disabledHost.canonicalBytes)
        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields))) {
            XCTAssertEqual($0 as? RuntimeActivationError, .invalidPlan)
        }
    }

    func testRejectsMissingUnknownNoncanonicalAndOversizedRecords() throws {
        let f = try Fixture()
        for key in f.fields.keys {
            var fields = f.fields; fields[key] = nil
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields)))
        }
        for (key, value): (UInt64, CBORValue) in [
            (0, .unsigned(5)), (0, .unsigned(7)), (1, .null), (2, .text("relative.app")),
            (3, .bytes(Data())), (4, .bytes(Data())), (5, .bytes(Data())), (9, .bytes(Data())),
            (10, .bytes(Data())), (11, .null),
        ] {
            var fields = f.fields; fields[key] = value
            XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(f.bytes(fields)))
        }
        let bytes = try f.bytes()
        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(bytes + Data([0])))
        XCTAssertThrowsError(try RuntimeRetainedSetupActivationArchive.decode(
            Data(repeating: 0, count: RuntimeRetainedSetupActivationArchive.maximumBytes + 1)))
    }
}
