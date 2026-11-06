import Darwin
import Foundation
import RemozioProtocol

/// Original public configuration bytes. Decoding grants no protected placement or publication authority.
struct RuntimeReleaseConfigurationSource {
    static let formatName = "runtime.release-configuration-source"
    static let maximumBytes = 262400
    private final class Storage: Sendable {
        let host: InstalledAuthorityCommandConfiguration
        let transport: TransportPairingStartupConfiguration
        let gateway: GatewaySettingsConsumerHostConfiguration
        let clients: RuntimeActivationClients
        @inline(never)
        init(host: InstalledAuthorityCommandConfiguration, transport: TransportPairingStartupConfiguration,
            gateway: GatewaySettingsConsumerHostConfiguration, clients: RuntimeActivationClients) {
            self.host = host
            self.transport = transport
            self.gateway = gateway
            self.clients = clients
        }
    }
    private let storage: Storage
    var host: InstalledAuthorityCommandConfiguration { storage.host }
    var transport: TransportPairingStartupConfiguration { storage.transport }
    var gateway: GatewaySettingsConsumerHostConfiguration { storage.gateway }
    var clients: RuntimeActivationClients { storage.clients }
    @inline(never)
    init(host: InstalledAuthorityCommandConfiguration, transport: TransportPairingStartupConfiguration,
            gateway: GatewaySettingsConsumerHostConfiguration, clients: RuntimeActivationClients) {
        storage = .init(host: host, transport: transport, gateway: gateway, clients: clients)
    }
    static func loadNative(account: MachineUpdateRestartSource.Account,
                           verifyCurrent: () throws -> Void) throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let paths = try RuntimePreparationPaths(accountID: account.accountID)
        try verifyCurrent()
        if let preparation = account.preparation {
            try RuntimeAuditUpgradeStartupFence.requireOpen(macID: preparation.macID, accountID: account.accountID)
        }
        func directory(_ path: String, _ visibility: ProtectedSetupDirectory.Visibility) throws -> ProtectedSetupDirectory {
            try .init(anchor: "/", relativePath: String(path.dropFirst()), owner: 0, visibility: visibility, createIfMissing: false)
        }
        let runtime = try directory(paths.privateDirectory, .privateState); defer { runtime.close() }
        let services = try directory(paths.serviceDirectory, .sharedMetadata); defer { services.close() }
        let clients = try directory(RuntimePreparationPaths.sharedDirectory, .sharedMetadata); defer { clients.close() }
        return try load(account: account, runtime: runtime, services: services, clients: clients, owner: 0, verifyCurrent: verifyCurrent)
    }
    static func loadOwned(account: MachineUpdateRestartSource.Account, runtime: ProtectedSetupDirectory,
                          services: ProtectedSetupDirectory, clients: ProtectedSetupDirectory, owner: uid_t,
                          verifyCurrent: () throws -> Void) throws -> Self {
        guard owner > 0, getuid() == owner, geteuid() == owner else { throw JournalLeaseError.unsafeMetadata }
        return try load(account: account, runtime: runtime, services: services, clients: clients, owner: owner, verifyCurrent: verifyCurrent)
    }
    private static func load(account: MachineUpdateRestartSource.Account, runtime: ProtectedSetupDirectory,
                             services: ProtectedSetupDirectory, clients: ProtectedSetupDirectory, owner: uid_t,
                             verifyCurrent: () throws -> Void) throws -> Self {
        func read(_ file: AdministrativeSetupPublication.File, _ directory: ProtectedSetupDirectory) throws -> Data {
            try verifyCurrent(); try directory.validate()
            let bytes = try ProtectedServiceConfiguration.read(anchor: directory.path, relativePath: file.name,
                owner: owner, privateFile: file.mode == 0o600)
            try AdministrativeSetupPublication.validateRetained(bytes, file: file, directory: directory, owner: owner, verify: verifyCurrent)
            return bytes
        }
        let value = try Self(host: .decode(read(.commandHost, runtime)), transport: .decode(read(.transportConfiguration, services)),
            gateway: .decode(read(.gatewaySettingsHost, services)), clients: .load(directory: clients, owner: owner,
                ownerUID: account.ownerUID, verifyCurrent: verifyCurrent))
        guard try read(.commandHost, runtime) == value.host.canonicalBytes,
              try read(.transportConfiguration, services) == value.transport.canonicalBytes,
              try read(.gatewaySettingsHost, services) == value.gateway.encoded else { throw InstalledAuthorityCommandError.changedConfiguration }
        try value.clients.validateRetained(directory: clients, owner: owner, ownerUID: account.ownerUID, verifyCurrent: verifyCurrent)
        try verifyCurrent(); return value
    }
    var digest: Data { get throws {
        MachineUpdateActivationRecord.digest(Data("Remozio/RuntimeReleaseConfigurationSource/v1\0".utf8) + (try content))
    } }
    private var content: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .bytes(host.canonicalBytes), 1: .bytes(transport.canonicalBytes),
            2: .bytes(try gateway.encoded), 3: .bytes(clients.presence.canonicalBytes),
            4: .bytes(clients.pairing.canonicalBytes), 5: .bytes(clients.frontend.canonicalBytes)]), limits: Self.contentLimits)
    } }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.formatName), 2: .bytes(try content)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let outer) = try DeterministicCBOR.decode(bytes, limits: limits), Set(outer.keys) == [0, 1, 2],
              outer[0] == .unsigned(1), outer[1] == .text(formatName), case .bytes(let content) = outer[2],
              case .map(let f) = try DeterministicCBOR.decode(content, limits: contentLimits),
              Set(f.keys) == Set(UInt64(0)...5) else { throw RuntimeActivationError.invalidPlan }
        func data(_ key: UInt64) throws -> Data {
            guard case .bytes(let bytes) = f[key] else { throw RuntimeActivationError.invalidPlan }; return bytes
        }
        let value = try Self(host: .decode(data(0)), transport: .decode(data(1)), gateway: .decode(data(2)),
            clients: .init(presence: .decode(data(3)), pairing: .decode(data(4)), frontend: .decode(data(5))))
        guard try value.encoded == bytes else { throw RuntimeActivationError.invalidPlan }; return value
    }
    private static let contentLimits = try! CBORLimits(maxBytes: 262144, maxDepth: 1, maxItems: 23)
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 7)
}
