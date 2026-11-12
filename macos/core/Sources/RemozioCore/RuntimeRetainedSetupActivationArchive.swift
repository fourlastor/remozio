import Foundation
import RemozioProtocol

/// Reads frozen retained activation values. It creates no jobs, executable bundle, or startup authority.
struct RuntimeRetainedSetupActivationArchive: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private final class Storage: Sendable {
        let reference: RuntimeMaterialReference
        let bundlePath: String
        let host: InstalledAuthorityCommandConfiguration
        let transport: TransportPairingStartupConfiguration
        let gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration
        let phoneRoutingVersion: UInt64?
        let phoneAuditVersion: UInt64?
        let phoneUpdateSchedulingVersion: UInt64?
        let binding: RuntimeRetainedSetupReleaseBinding
        let inventory: InstallationInventory

        init(reference: RuntimeMaterialReference, bundlePath: String, host: InstalledAuthorityCommandConfiguration,
            transport: TransportPairingStartupConfiguration, gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration,
            phoneRoutingVersion: UInt64?, phoneAuditVersion: UInt64?, phoneUpdateSchedulingVersion: UInt64?,
            binding: RuntimeRetainedSetupReleaseBinding, inventory: InstallationInventory) {
            self.reference = reference; self.bundlePath = bundlePath; self.host = host; self.transport = transport
            self.gatewaySettingsHost = gatewaySettingsHost; self.phoneRoutingVersion = phoneRoutingVersion
            self.phoneAuditVersion = phoneAuditVersion; self.phoneUpdateSchedulingVersion = phoneUpdateSchedulingVersion
            self.binding = binding; self.inventory = inventory
        }
    }
    private let storage: Storage
    static let formatName = RuntimeActivationPlan.formatName
    static let formatVersion: UInt64 = 6
    static let maximumBytes = 262144
    var reference: RuntimeMaterialReference { storage.reference }
    var bundlePath: String { storage.bundlePath }
    var host: InstalledAuthorityCommandConfiguration { storage.host }
    var transport: TransportPairingStartupConfiguration { storage.transport }
    var gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration { storage.gatewaySettingsHost }
    var phoneRoutingVersion: UInt64? { storage.phoneRoutingVersion }
    var phoneAuditVersion: UInt64? { storage.phoneAuditVersion }
    var phoneUpdateSchedulingVersion: UInt64? { storage.phoneUpdateSchedulingVersion }
    var binding: RuntimeRetainedSetupReleaseBinding { storage.binding }
    var inventory: InstallationInventory { storage.inventory }
    var description: String { "RuntimeRetainedSetupActivationArchive(redacted)" }
    var debugDescription: String { description }

    init(reference: RuntimeMaterialReference, bundlePath: String, host: InstalledAuthorityCommandConfiguration,
        transport: TransportPairingStartupConfiguration, gatewaySettingsHost: GatewaySettingsConsumerHostConfiguration,
        phoneRoutingVersion: UInt64?, phoneAuditVersion: UInt64?, phoneUpdateSchedulingVersion: UInt64?,
        binding: RuntimeRetainedSetupReleaseBinding, inventory: InstallationInventory) throws {
        try binding.requireHistoricalRuntime(reference)
        try binding.requireStartupPolicy(host.codePolicy)
        guard reference.serviceActivity != nil, host.gatewaySettingsControlEnabled,
              inventory.macID == binding.macID, inventory.installationID == binding.installationID,
              inventory.releaseDigest == binding.installedReleaseDigest, inventory.bundlePath == bundlePath,
              !inventory.accounts.contains(where: { $0.accountID == binding.accountID || $0.ownerUID == binding.ownerUID }),
              let transportHost = transport.settingsHost else { throw RuntimeActivationError.invalidPlan }
        for (value, role) in [(gatewaySettingsHost, GatewaySettingsConsumerRole.gateway), (transportHost, .transport)] {
            guard value.role == role, value.formatVersion == GatewaySettingsConsumerHostConfiguration.retainedSetupVersion,
                  value.runtime == reference, value.bundlePath == bundlePath, value.codePolicy == host.codePolicy,
                  value.retainedSetupBinding == binding else { throw RuntimeActivationError.invalidPlan }
        }
        _ = try RuntimeActivationInputValidation.transportClaim(reference: reference, host: host, transport: transport,
            hasConsumerHosts: true, installedReleaseDigest: binding.installedReleaseDigest,
            phoneRoutingVersion: phoneRoutingVersion, phoneAuditVersion: phoneAuditVersion,
            phoneUpdateSchedulingVersion: phoneUpdateSchedulingVersion)
        storage = .init(reference: reference, bundlePath: bundlePath, host: host, transport: transport,
            gatewaySettingsHost: gatewaySettingsHost, phoneRoutingVersion: phoneRoutingVersion,
            phoneAuditVersion: phoneAuditVersion, phoneUpdateSchedulingVersion: phoneUpdateSchedulingVersion,
            binding: binding, inventory: inventory)
    }

    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([
            0: .unsigned(Self.formatVersion), 1: .bytes(reference.encoded), 2: .text(bundlePath),
            3: .bytes(host.canonicalBytes), 4: .bytes(transport.canonicalBytes), 5: .bytes(gatewaySettingsHost.encoded),
            6: phoneRoutingVersion.map(CBORValue.unsigned) ?? .null,
            7: phoneAuditVersion.map(CBORValue.unsigned) ?? .null,
            8: phoneUpdateSchedulingVersion.map(CBORValue.unsigned) ?? .null,
            9: .bytes(binding.encoded), 10: .bytes(inventory.canonicalBytes),
        ]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              fields[0] == .unsigned(formatVersion), Set(fields.keys) == Set(UInt64(0)...10),
              case .bytes(let reference) = fields[1], case .text(let path) = fields[2],
              case .bytes(let host) = fields[3], case .bytes(let transport) = fields[4],
              case .bytes(let gateway) = fields[5], case .bytes(let bindingBytes) = fields[9],
              case .bytes(let inventoryBytes) = fields[10] else { throw RuntimeActivationError.invalidPlan }
        func selection(_ key: UInt64, supported: UInt64) throws -> UInt64? {
            switch fields[key] {
            case .null: return nil
            case .unsigned(let value) where value == supported: return value
            default: throw RuntimeActivationError.invalidPlan
            }
        }
        let binding = try RuntimeRetainedSetupReleaseBinding.decode(bindingBytes)
        let value = try Self(reference: .decode(reference), bundlePath: path, host: .decode(host),
            transport: .decodeForReleaseArchive(transport), gatewaySettingsHost: .decodeForReleaseArchive(gateway),
            phoneRoutingVersion: selection(6, supported: PhoneRoutingReleaseContract.version),
            phoneAuditVersion: selection(7, supported: PhoneAuditReleaseContract.version),
            phoneUpdateSchedulingVersion: selection(8, supported: PhoneUpdateSchedulingReleaseContract.version),
            binding: binding, inventory: .decode(inventoryBytes, expectedMacID: binding.macID))
        guard try value.encoded == bytes else { throw RuntimeActivationError.invalidPlan }
        return value
    }
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 23)
}
