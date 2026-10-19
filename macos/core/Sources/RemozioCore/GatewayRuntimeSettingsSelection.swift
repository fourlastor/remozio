import Foundation
import RemozioProtocol

/// Operational settings only. A selection carries no provider credential or permission to change protected files.
public struct GatewayRuntimeSettingsSelection: Sendable {
    public let service: GatewayServiceSettings
    public let activation: GatewayRuntimeActivationSettings
    public let maximumWakeConnections: Int
    public let maximumWakeOperations: Int
    public let wakeChallengeLifetimeMilliseconds: UInt64

    public init(service: GatewayServiceSettings, activation: GatewayRuntimeActivationSettings,
                maximumWakeConnections: Int = 4, maximumWakeOperations: Int = 8,
                wakeChallengeLifetimeMilliseconds: UInt64 = 5000) throws {
        guard (1...64).contains(maximumWakeConnections), (1...64).contains(maximumWakeOperations),
              (1...60000).contains(wakeChallengeLifetimeMilliseconds) else { throw GatewayPreparationError.invalidRecord }
        self.service = service; self.activation = activation
        self.maximumWakeConnections = maximumWakeConnections; self.maximumWakeOperations = maximumWakeOperations
        self.wakeChallengeLifetimeMilliseconds = wakeChallengeLifetimeMilliseconds
    }
    init(activation plan: GatewayRuntimeActivationPlan, journal: GatewayJournalPreparationState,
         foreground: RuntimeActivationPlan, inventory: InstallationInventory) throws {
        let proposal = try plan.proposal(journal: journal, foreground: foreground, inventory: inventory)
        guard let endpoint = proposal.gateway.wakeEndpoint, let wake = proposal.transport.wake else { throw GatewayPreparationError.incomplete }
        try self.init(service: proposal.gateway.settings,
            activation: .init(wakePollMilliseconds: wake.pollMilliseconds, wakeTimeoutMilliseconds: wake.wake.timeoutMilliseconds),
            maximumWakeConnections: endpoint.maximumConnections, maximumWakeOperations: endpoint.maximumOperations,
            wakeChallengeLifetimeMilliseconds: endpoint.challengeLifetimeMillis)
    }
    public var bytes: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.purpose), 2: .bytes(service.setupBytes),
            3: .bytes(activation.bytes), 4: .unsigned(UInt64(maximumWakeConnections)),
            5: .unsigned(UInt64(maximumWakeOperations)), 6: .unsigned(wakeChallengeLifetimeMilliseconds)]), limits: Self.limits)
    } }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...6),
              fields[0] == .unsigned(1), fields[1] == .text(purpose), case .bytes(let service) = fields[2],
              case .bytes(let activation) = fields[3], case .unsigned(let connections) = fields[4],
              let connections = Int(exactly: connections), case .unsigned(let operations) = fields[5],
              let operations = Int(exactly: operations), case .unsigned(let challenge) = fields[6] else {
            throw GatewayPreparationError.invalidRecord
        }
        let result = try Self(service: .decodeSetupBytes(service), activation: .decode(activation),
            maximumWakeConnections: connections, maximumWakeOperations: operations, wakeChallengeLifetimeMilliseconds: challenge)
        guard try result.bytes == bytes else { throw GatewayPreparationError.invalidRecord }; return result
    }
    private static let purpose = "remozio-gateway-settings-selection"
    private static let limits = try! CBORLimits(maxBytes: 16384, maxDepth: 1, maxItems: 15)
}
