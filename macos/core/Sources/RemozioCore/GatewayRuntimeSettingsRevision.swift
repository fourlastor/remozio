import CryptoKit
import Foundation
import RemozioProtocol

/// A proposal for an authorized settings transition. Decoding or validating this value grants no mutation authority.
/// The durable owner must compare the current revision before retaining or applying a successor.
struct GatewayRuntimeSettingsRevision: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.gateway-settings-revision"
    static let supportedVersions: Set<UInt64> = [1]
    let id: Data
    let accountID: Data
    let activationDigest: Data
    let sequence: UInt64
    let previousDigest: Data
    let selection: GatewayRuntimeSettingsSelection
    let gatewayDigest: Data
    let transportWakeDigest: Data
    var description: String { "GatewayRuntimeSettingsRevision(redacted)" }
    var debugDescription: String { description }

    init(id: Data, selection: GatewayRuntimeSettingsSelection, activation: GatewayRuntimeActivationPlan,
         previous: Self? = nil, journal: GatewayJournalPreparationState,
         foreground: RuntimeActivationPlan, inventory: InstallationInventory) throws {
        let proposal = try Self.makeProposal(selection, activation: activation, journal: journal, foreground: foreground, inventory: inventory)
        let sequence: UInt64, previousDigest: Data
        if let previous {
            _ = try previous.proposal(activation: activation, journal: journal, foreground: foreground, inventory: inventory)
            guard previous.sequence < UInt64.max, previous.id != id else { throw GatewayPreparationError.invalidRecord }
            sequence = previous.sequence + 1; previousDigest = try previous.digest
        } else { sequence = 1; previousDigest = try activation.digest }
        guard let wake = proposal.transport.wake else { throw GatewayPreparationError.incomplete }
        try self.init(id: id, accountID: activation.accountID, activationDigest: activation.digest,
            sequence: sequence, previousDigest: previousDigest, selection: selection,
            gatewayDigest: Data(SHA256.hash(data: proposal.gateway.canonicalBytes)),
            transportWakeDigest: Data(SHA256.hash(data: wake.canonicalBytes)))
    }
    private init(id: Data, accountID: Data, activationDigest: Data, sequence: UInt64, previousDigest: Data,
                 selection: GatewayRuntimeSettingsSelection, gatewayDigest: Data, transportWakeDigest: Data) throws {
        guard id.count == 16, accountID.count == 16, activationDigest.count == 32, sequence > 0,
              previousDigest.count == 32, gatewayDigest.count == 32, transportWakeDigest.count == 32 else {
            throw GatewayPreparationError.invalidRecord
        }
        self.id = id; self.accountID = accountID; self.activationDigest = activationDigest; self.sequence = sequence
        self.previousDigest = previousDigest; self.selection = selection
        self.gatewayDigest = gatewayDigest; self.transportWakeDigest = transportWakeDigest
    }
    func validateSuccessor(of previous: Self?, activation: GatewayRuntimeActivationPlan) throws {
        guard accountID == activation.accountID, try activationDigest == activation.digest else { throw GatewayPreparationError.changedScope }
        if let previous {
            guard previous.accountID == accountID, previous.activationDigest == activationDigest,
                  previous.sequence < UInt64.max, sequence == previous.sequence + 1,
                  previous.id != id, try previousDigest == previous.digest else { throw GatewayPreparationError.changedScope }
        } else {
            guard sequence == 1, previousDigest == activationDigest else { throw GatewayPreparationError.changedScope }
        }
    }
    func proposal(activation: GatewayRuntimeActivationPlan, journal: GatewayJournalPreparationState,
                  foreground: RuntimeActivationPlan, inventory: InstallationInventory) throws -> GatewayConfigurationBundle {
        guard accountID == activation.accountID, try activationDigest == activation.digest else { throw GatewayPreparationError.changedScope }
        let proposal = try Self.makeProposal(selection, activation: activation, journal: journal, foreground: foreground, inventory: inventory)
        guard let wake = proposal.transport.wake,
              gatewayDigest == Data(SHA256.hash(data: proposal.gateway.canonicalBytes)),
              transportWakeDigest == Data(SHA256.hash(data: wake.canonicalBytes)) else { throw GatewayPreparationError.changedScope }
        return proposal
    }
    private static func makeProposal(_ selection: GatewayRuntimeSettingsSelection, activation: GatewayRuntimeActivationPlan,
                                     journal: GatewayJournalPreparationState, foreground: RuntimeActivationPlan,
                                     inventory: InstallationInventory) throws -> GatewayConfigurationBundle {
        _ = try activation.proposal(journal: journal, foreground: foreground, inventory: inventory)
        let proposal = try GatewayConfigurationBundle(foreground: foreground, material: activation.extensions.authority.material,
            inventory: inventory, settings: selection.service,
            wakePollMilliseconds: selection.activation.wakePollMilliseconds, wakeTimeoutMilliseconds: selection.activation.wakeTimeoutMilliseconds,
            wakeMaximumConnections: selection.maximumWakeConnections, wakeMaximumOperations: selection.maximumWakeOperations,
            wakeChallengeLifetimeMilliseconds: selection.wakeChallengeLifetimeMilliseconds)
        guard try proposal.gatewayJob.bytes == activation.gatewayJob.bytes else { throw GatewayPreparationError.changedScope }
        return proposal
    }
    var digest: Data { get throws { Data(SHA256.hash(data: try encoded)) } }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text(Self.purpose), 2: .bytes(id), 3: .bytes(accountID),
            4: .bytes(activationDigest), 5: .unsigned(sequence), 6: .bytes(previousDigest), 7: .bytes(selection.bytes),
            8: .bytes(gatewayDigest), 9: .bytes(transportWakeDigest)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...9),
              fields[0] == .unsigned(1), fields[1] == .text(purpose), case .unsigned(let sequence) = fields[5] else {
            throw GatewayPreparationError.invalidRecord
        }
        func data(_ key: UInt64) throws -> Data {
            guard case .bytes(let value) = fields[key] else { throw GatewayPreparationError.invalidRecord }; return value
        }
        let result = try Self(id: data(2), accountID: data(3), activationDigest: data(4), sequence: sequence,
            previousDigest: data(6), selection: .decode(data(7)), gatewayDigest: data(8), transportWakeDigest: data(9))
        guard try result.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return result
    }
    private static let purpose = "remozio-gateway-settings-revision"
    private static let limits = try! CBORLimits(maxBytes: 32768, maxDepth: 1, maxItems: 21)
}
