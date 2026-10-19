import CryptoKit
import Foundation
import RemozioProtocol

/// Immutable setup proposal. Retention and registration markers must never substitute for observed runtime health.
struct GatewayRuntimeActivationPlan: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    static let formatName = "runtime.gateway-activation-plan"
    static let supportedVersions: Set<UInt64> = [1]
    let extensions: GatewayRuntimeExtensions
    let bundlePath: String
    var description: String { "GatewayRuntimeActivationPlan(redacted)" }
    var debugDescription: String { description }
    var accountID: Data { extensions.authority.material.runtime.services.accountID }
    var journalIntentID: Data { extensions.authority.intentID }
    var journalIntentDigest: Data { extensions.authority.intentDigest }
    var gatewayJob: InstalledAccountJobManifest { get throws {
        let services = extensions.authority.material.runtime.services
        guard let claim = services.claims.first(where: { $0.role == .gateway }) else { throw GatewayPreparationError.incomplete }
        return try .init(accountID: accountID, role: .notificationGateway, executionUID: claim.number,
            userName: claim.name, bundlePath: bundlePath)
    } }

    init(journal: GatewayJournalPreparationState, foreground: RuntimeActivationPlan, inventory: InstallationInventory,
         wakePollMilliseconds: UInt64 = 1000, wakeTimeoutMilliseconds: UInt64 = 5000) throws {
        let pair = try GatewayRuntimeExtensions(journal: journal, foreground: foreground, inventory: inventory,
            wakePollMilliseconds: wakePollMilliseconds, wakeTimeoutMilliseconds: wakeTimeoutMilliseconds)
        try self.init(extensions: pair, bundlePath: foreground.bundlePath)
        _ = try proposal(journal: journal, foreground: foreground, inventory: inventory)
    }
    private init(extensions: GatewayRuntimeExtensions, bundlePath: String) throws {
        self.extensions = extensions; self.bundlePath = bundlePath
        _ = try gatewayJob; _ = try encoded
    }
    /// Reconstruct every operational input from the completed journal and unchanged foreground scope.
    func proposal(journal: GatewayJournalPreparationState, foreground: RuntimeActivationPlan,
                  inventory: InstallationInventory) throws -> GatewayConfigurationBundle {
        try extensions.validate(journal: journal, foreground: foreground, inventory: inventory)
        guard bundlePath == foreground.bundlePath, inventory.bundlePath == bundlePath,
              let intent = journal.intent, let endpoint = intent.configuration.wakeEndpoint,
              let wake = extensions.transport.wake else { throw GatewayPreparationError.changedScope }
        let proposal = try GatewayConfigurationBundle(foreground: foreground, material: intent.material, inventory: inventory,
            settings: intent.configuration.settings, wakePollMilliseconds: wake.pollMilliseconds,
            wakeTimeoutMilliseconds: wake.wake.timeoutMilliseconds, wakeMaximumConnections: endpoint.maximumConnections,
            wakeMaximumOperations: endpoint.maximumOperations, wakeChallengeLifetimeMilliseconds: endpoint.challengeLifetimeMillis)
        guard proposal.gateway.canonicalBytes == intent.configuration.canonicalBytes,
              proposal.transport.wake?.canonicalBytes == wake.canonicalBytes,
              try proposal.gatewayJob.bytes == gatewayJob.bytes else { throw GatewayPreparationError.changedScope }
        return proposal
    }
    var digest: Data { get throws { Data(SHA256.hash(data: try encoded)) } }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-runtime-activation"),
            2: .bytes(extensions.encoded), 3: .text(bundlePath)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...3),
              fields[0] == .unsigned(1), fields[1] == .text("remozio-gateway-runtime-activation"),
              case .bytes(let pair) = fields[2], case .text(let bundle) = fields[3] else { throw GatewayPreparationError.invalidRecord }
        let plan = try Self(extensions: .decode(pair), bundlePath: bundle)
        guard try plan.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return plan
    }
    static let maximumBytes = 270336
    private static let limits = try! CBORLimits(maxBytes: maximumBytes, maxDepth: 1, maxItems: 9)
}

/// Historical setup markers only. Native registration and current consumer state need independent observation.
struct GatewayRuntimeActivationState {
    let plan: GatewayRuntimeActivationPlan?
    let filesPublished: Bool
    let jobRegistered: Bool
}
