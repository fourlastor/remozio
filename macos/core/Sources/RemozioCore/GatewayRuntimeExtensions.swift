import CryptoKit
import Foundation
import RemozioProtocol

/// Prepare independent optional inputs. Foreground startup bytes, identities and request owners stay unchanged.
struct GatewayRuntimeExtensions: Sendable {
    static let formatName = "runtime.gateway-runtime-pair"
    static let supportedVersions: Set<UInt64> = [1]
    let authority: GatewayRuntimeExtension
    let transport: GatewayRuntimeExtension
    init(journal: GatewayJournalPreparationState, foreground: RuntimeActivationPlan, inventory: InstallationInventory,
         wakePollMilliseconds: UInt64 = 1000, wakeTimeoutMilliseconds: UInt64 = 5000) throws {
        guard journal.initialized, let intent = journal.intent, let endpoint = intent.configuration.wakeEndpoint else {
            throw GatewayPreparationError.incomplete
        }
        try intent.validate(foreground: foreground, inventory: inventory)
        let proposal = try GatewayConfigurationBundle(foreground: foreground, material: intent.material, inventory: inventory,
            settings: intent.configuration.settings, wakePollMilliseconds: wakePollMilliseconds, wakeTimeoutMilliseconds: wakeTimeoutMilliseconds,
            wakeMaximumConnections: endpoint.maximumConnections, wakeMaximumOperations: endpoint.maximumOperations,
            wakeChallengeLifetimeMilliseconds: endpoint.challengeLifetimeMillis)
        guard proposal.gateway.canonicalBytes == intent.configuration.canonicalBytes, let wake = proposal.transport.wake else {
            throw GatewayPreparationError.changedScope
        }
        let scope = Data(SHA256.hash(data: try foreground.encoded)), digest = try intent.digest
        let authority = try GatewayRuntimeExtension(target: .authority, intentID: intent.id, intentDigest: digest,
            foregroundDigest: scope, baseDigest: Data(SHA256.hash(data: foreground.host.canonicalBytes)),
            material: intent.material, codePolicy: foreground.host.codePolicy, wake: nil)
        let transport = try GatewayRuntimeExtension(target: .transport, intentID: intent.id, intentDigest: digest,
            foregroundDigest: scope, baseDigest: Data(SHA256.hash(data: foreground.transport.canonicalBytes)),
            material: intent.material, codePolicy: foreground.host.codePolicy, wake: wake)
        try authority.validate(authority: foreground.host); try transport.validate(transport: foreground.transport)
        try self.init(authority: authority, transport: transport)
        _ = try encoded
    }
    init(settings revision: GatewayRuntimeSettingsRevision, activation: GatewayRuntimeActivationPlan,
         journal: GatewayJournalPreparationState, foreground: RuntimeActivationPlan, inventory: InstallationInventory) throws {
        let proposal = try revision.proposal(activation: activation, journal: journal, foreground: foreground, inventory: inventory)
        let old = activation.extensions.transport
        let transport = try GatewayRuntimeExtension(target: .transport, intentID: old.intentID, intentDigest: old.intentDigest,
            foregroundDigest: old.foregroundDigest, baseDigest: old.baseDigest, material: old.material,
            codePolicy: old.codePolicy, wake: proposal.transport.wake)
        try self.init(authority: activation.extensions.authority, transport: transport)
        try validate(journal: journal, foreground: foreground, inventory: inventory)
    }
    private init(authority: GatewayRuntimeExtension, transport: GatewayRuntimeExtension) throws {
        guard authority.target == .authority, transport.target == .transport,
              authority.intentID == transport.intentID, authority.intentDigest == transport.intentDigest,
              authority.foregroundDigest == transport.foregroundDigest, authority.material == transport.material,
              authority.codePolicy == transport.codePolicy else { throw GatewayPreparationError.changedScope }
        self.authority = authority; self.transport = transport
    }
    func validate(journal: GatewayJournalPreparationState, foreground: RuntimeActivationPlan, inventory: InstallationInventory) throws {
        guard journal.initialized, let intent = journal.intent, try intent.digest == authority.intentDigest,
              intent.id == authority.intentID, intent.material == authority.material,
              authority.foregroundDigest == Data(SHA256.hash(data: try foreground.encoded)) else { throw GatewayPreparationError.changedScope }
        try intent.validate(foreground: foreground, inventory: inventory)
        try authority.validate(authority: foreground.host); try transport.validate(transport: foreground.transport)
    }
    var digest: Data { get throws { Data(SHA256.hash(data: try encoded)) } }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-runtime-extensions"),
            2: .bytes(authority.encoded), 3: .bytes(transport.encoded)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...3),
              f[0] == .unsigned(1), f[1] == .text("remozio-gateway-runtime-extensions"),
              case .bytes(let authority) = f[2], case .bytes(let transport) = f[3] else { throw GatewayPreparationError.invalidRecord }
        let result = try Self(authority: .decode(authority), transport: .decode(transport))
        guard try result.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return result
    }
    private static let limits = try! CBORLimits(maxBytes: 262144, maxDepth: 1, maxItems: 9)
}
