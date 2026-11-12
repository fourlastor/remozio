import Foundation
import RemozioProtocol

/// Reads completed consumer values. Source custody, publication, native health, and startup admission remain separate.
struct RuntimeRetainedSetupCompletionConfiguration: CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.retained-setup-completion-configuration"
    static let maximumBytes = 2_097_152
    let archive: RuntimeRetainedSetupCompletionArchive
    let sourceDigest: Data
    let host: InstalledAuthorityCommandConfiguration
    let transport: TransportPairingStartupConfiguration
    let gateway: GatewaySettingsConsumerHostConfiguration
    let clients: RuntimeActivationClients
    var description: String { "RuntimeRetainedSetupCompletionConfiguration(redacted)" }
    var debugDescription: String { description }

    init(snapshot: MachineUpdateRetainedSetupCompletionSnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence,
        clients: RuntimeActivationClients) throws {
        let values = try RuntimeReleaseConfigurationPlan.retainingCompletedSetup(snapshot: snapshot,
            current: current, candidate: candidate, clients: clients)
        try self.init(archive: values.archive, sourceDigest: values.sourceDigest, host: values.host,
            transport: values.transport, gateway: values.gateway, clients: values.clients)
    }
    private init(archive: RuntimeRetainedSetupCompletionArchive, sourceDigest: Data,
        host: InstalledAuthorityCommandConfiguration, transport: TransportPairingStartupConfiguration,
        gateway: GatewaySettingsConsumerHostConfiguration, clients: RuntimeActivationClients) throws {
        guard sourceDigest.count == 32 else { throw RuntimeActivationError.invalidPlan }
        _ = try archive.encoded
        try RuntimeReleaseConfigurationPlan.requireRetainedCompletionValues(archive: archive,
            host: host, transport: transport, gateway: gateway, clients: clients)
        self.archive = archive; self.sourceDigest = sourceDigest
        self.host = host; self.transport = transport; self.gateway = gateway; self.clients = clients
    }

    func requireSourceForPublication(_ snapshot: MachineUpdateRetainedSetupCompletionSnapshot,
        current: AuthorityJournal.MachineUpdatePolicyBoundary, candidate: SignedReleaseEvidence,
        clients: RuntimeActivationClients) throws {
        let proposed = try Self(snapshot: snapshot, current: current, candidate: candidate, clients: clients)
        guard try proposed.encoded == encoded else { throw RuntimeActivationError.changedScope }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.formatName),
            2: .bytes(archive.encoded), 3: .bytes(sourceDigest), 4: .bytes(host.canonicalBytes),
            5: .bytes(transport.canonicalBytes), 6: .bytes(gateway.encoded),
            7: .bytes(clients.presence.canonicalBytes), 8: .bytes(clients.pairing.canonicalBytes),
            9: .bytes(clients.frontend.canonicalBytes)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            guard !bytes.isEmpty, bytes.count <= maximumBytes,
                  case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
                  Set(fields.keys) == Set(UInt64(0)...9), fields[0] == .unsigned(1), fields[1] == .text(formatName) else {
                throw RuntimeActivationError.invalidPlan
            }
            func data(_ key: UInt64) throws -> Data {
                guard case .bytes(let bytes) = fields[key] else { throw RuntimeActivationError.invalidPlan }; return bytes
            }
            let value = try Self(archive: .decode(data(2)), sourceDigest: data(3), host: .decode(data(4)),
                transport: .decodeForReleaseArchive(data(5)), gateway: .decodeForReleaseArchive(data(6)),
                clients: .init(presence: .decode(data(7)), pairing: .decode(data(8)), frontend: .decode(data(9))))
            guard try value.encoded == bytes else { throw RuntimeActivationError.invalidPlan }
            return value
        } catch { throw RuntimeActivationError.invalidPlan }
    }
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 21)
}
