import CryptoKit
import Foundation
import RemozioProtocol

/// The final protected publication marker binds both role files. It does not report running service health.
struct GatewayRuntimeCommit: Sendable {
    static let formatName = "runtime.gateway-runtime-commit"
    static let supportedVersions: Set<UInt64> = [1, 2]
    static let releaseBoundVersion: UInt64 = 3
    let intentID: Data
    let intentDigest: Data
    let foregroundDigest: Data
    let pairDigest: Data
    let authorityDigest: Data
    let transportDigest: Data
    let settingsSequence: UInt64?
    let settingsRevisionDigest: Data?
    let gatewayConfigurationDigest: Data?
    let activationDigest: Data?
    struct Release: Sendable {
        let binding: RuntimeReleaseBinding
        let stage: RuntimeReleasePolicyStage
        let originalCommit: Data
        let transportWakeDigest: Data
        func original() throws -> GatewayRuntimeCommit {
            guard originalCommit.count <= 1024,
                  case .map(let fields) = try DeterministicCBOR.decode(originalCommit, limits: .init(maxBytes: 1024, maxDepth: 1, maxItems: 25)),
                  fields[0] == .unsigned(1) || fields[0] == .unsigned(2) else { throw GatewayPreparationError.invalidRecord }
            return try GatewayRuntimeCommit.decode(originalCommit)
        }
    }
    let release: Release?

    init(_ pair: GatewayRuntimeExtensions) throws {
        intentID = pair.authority.intentID; intentDigest = pair.authority.intentDigest
        foregroundDigest = pair.authority.foregroundDigest; pairDigest = try pair.digest
        authorityDigest = Data(SHA256.hash(data: try pair.authority.encoded))
        transportDigest = Data(SHA256.hash(data: try pair.transport.encoded))
        settingsSequence = nil; settingsRevisionDigest = nil; gatewayConfigurationDigest = nil; activationDigest = nil; release = nil
    }
    init(_ pair: GatewayRuntimeExtensions, settings revision: GatewayRuntimeSettingsRevision,
         gateway: GatewayServiceConfiguration) throws {
        let base = try Self(pair)
        guard pair.authority.material.runtime.services.accountID == revision.accountID,
              gateway.registration == pair.authority.material.runtime.gateway,
              Data(SHA256.hash(data: gateway.canonicalBytes)) == revision.gatewayDigest,
              let wake = pair.transport.wake,
              Data(SHA256.hash(data: wake.canonicalBytes)) == revision.transportWakeDigest else {
            throw GatewayPreparationError.changedScope
        }
        try self.init(id: base.intentID, intent: base.intentDigest, foreground: base.foregroundDigest,
            pair: base.pairDigest, authority: base.authorityDigest, transport: base.transportDigest,
            sequence: revision.sequence, revision: revision.digest, gateway: revision.gatewayDigest, activation: revision.activationDigest)
    }
    init(release plan: RuntimeReleaseBackendPlan, pair: GatewayRuntimeExtensions) throws {
        let expected = try GatewayRuntimeExtensions(release: plan)
        guard try pair.encoded == expected.encoded else { throw GatewayPreparationError.changedScope }
        let base = try Self(pair), original = plan.source.commit
        let release = try Release(binding: plan.binding, stage: plan.policyStage,
            originalCommit: original.encoded, transportWakeDigest: Data(SHA256.hash(data: plan.transportWake.canonicalBytes)))
        try self.init(id: base.intentID, intent: base.intentDigest, foreground: base.foregroundDigest,
            pair: base.pairDigest, authority: base.authorityDigest, transport: base.transportDigest,
            sequence: original.settingsSequence, revision: original.settingsRevisionDigest,
            gateway: Data(SHA256.hash(data: plan.gateway.canonicalBytes)), activation: original.activationDigest, release: release)
        try validate(pair)
    }
    func requireRelease(binding: RuntimeReleaseBinding?, stage: RuntimeReleasePolicyStage?) throws {
        if let release {
            guard release.binding == binding, release.stage == stage else { throw GatewayPreparationError.changedScope }
        } else {
            guard binding == nil, stage == nil else { throw GatewayPreparationError.changedScope }
        }
    }
    func validateGateway(_ gateway: GatewayServiceConfiguration) throws {
        guard release != nil, gatewayConfigurationDigest == Data(SHA256.hash(data: gateway.canonicalBytes)) else {
            throw GatewayPreparationError.changedScope
        }
    }
    private init(id: Data, intent: Data, foreground: Data, pair: Data, authority: Data, transport: Data,
                 sequence: UInt64? = nil, revision: Data? = nil, gateway: Data? = nil, activation: Data? = nil,
                 release: Release? = nil) throws {
        guard id.count == 16, [intent, foreground, pair, authority, transport].allSatisfy({ $0.count == 32 }) else {
            throw GatewayPreparationError.invalidRecord
        }
        if let release {
            let original = try release.original()
            _ = try release.binding.encoded
            guard release.transportWakeDigest.count == 32, gateway?.count == 32,
                  original.intentID == id, original.intentDigest == intent, original.foregroundDigest == foreground,
                  original.settingsSequence == sequence, original.settingsRevisionDigest == revision,
                  original.activationDigest == activation else { throw GatewayPreparationError.invalidRecord }
        } else {
            guard (sequence == nil && revision == nil && gateway == nil && activation == nil) ||
                (sequence != nil && sequence! > 0 && revision?.count == 32 && gateway?.count == 32 && activation?.count == 32) else {
                throw GatewayPreparationError.invalidRecord
            }
        }
        intentID = id; intentDigest = intent; foregroundDigest = foreground; pairDigest = pair
        authorityDigest = authority; transportDigest = transport
        settingsSequence = sequence; settingsRevisionDigest = revision; gatewayConfigurationDigest = gateway; activationDigest = activation
        self.release = release
    }
    func validate(_ pair: GatewayRuntimeExtensions) throws {
        if let release {
            try release.binding.requireHistoricalRuntime(pair.authority.material.runtime)
            try release.binding.requirePolicy(pair.authority.codePolicy, stage: release.stage)
            try release.binding.requirePolicy(pair.transport.codePolicy, stage: release.stage)
            guard let wake = pair.transport.wake,
                  release.transportWakeDigest == Data(SHA256.hash(data: wake.canonicalBytes)) else { throw GatewayPreparationError.changedScope }
        }
        let expected = try Self(pair)
        guard intentID == expected.intentID, intentDigest == expected.intentDigest, foregroundDigest == expected.foregroundDigest,
              pairDigest == expected.pairDigest, authorityDigest == expected.authorityDigest, transportDigest == expected.transportDigest else {
            throw GatewayPreparationError.changedScope
        }
    }
    func validate(_ role: GatewayRuntimeExtension) throws {
        if let release {
            try release.binding.requireHistoricalRuntime(role.material.runtime)
            try release.binding.requirePolicy(role.codePolicy, stage: release.stage)
            if role.target == .transport {
                guard let wake = role.wake,
                      release.transportWakeDigest == Data(SHA256.hash(data: wake.canonicalBytes)) else { throw GatewayPreparationError.changedScope }
            }
        }
        guard role.intentID == intentID, role.intentDigest == intentDigest, role.foregroundDigest == foregroundDigest,
              Data(SHA256.hash(data: try role.encoded)) == (role.target == .authority ? authorityDigest : transportDigest) else {
            throw GatewayPreparationError.changedScope
        }
    }
    /// Version 1 keeps its existing cache key. Settings and release commits use the complete marker digest.
    var observationDigest: Data { get throws {
        settingsSequence == nil && release == nil ? pairDigest : Data(SHA256.hash(data: try encoded))
    } }
    func validate(settings revision: GatewayRuntimeSettingsRevision, gateway: GatewayServiceConfiguration) throws {
        let source = try release?.original() ?? self
        guard settingsSequence == revision.sequence, settingsRevisionDigest == (try revision.digest),
              activationDigest == revision.activationDigest, source.gatewayConfigurationDigest == revision.gatewayDigest,
              gatewayConfigurationDigest == Data(SHA256.hash(data: gateway.canonicalBytes)) else {
            throw GatewayPreparationError.changedScope
        }
    }
    var encoded: Data { get throws {
        var fields: [UInt64: CBORValue] = [0: .unsigned(release != nil ? Self.releaseBoundVersion : settingsSequence == nil ? 1 : 2), 1: .text("remozio-gateway-runtime-commit"),
            2: .bytes(intentID), 3: .bytes(intentDigest), 4: .bytes(foregroundDigest), 5: .bytes(pairDigest),
            6: .bytes(authorityDigest), 7: .bytes(transportDigest)]
        if let sequence = settingsSequence, let revision = settingsRevisionDigest,
           let gateway = gatewayConfigurationDigest, let activation = activationDigest {
            fields[8] = .unsigned(sequence); fields[9] = .bytes(revision); fields[10] = .bytes(gateway); fields[11] = .bytes(activation)
        }
        if let release {
            fields[8] = settingsSequence.map(CBORValue.unsigned) ?? .null
            fields[9] = settingsRevisionDigest.map(CBORValue.bytes) ?? .null
            fields[10] = gatewayConfigurationDigest.map(CBORValue.bytes) ?? .null
            fields[11] = activationDigest.map(CBORValue.bytes) ?? .null
            fields[12] = try .bytes(release.binding.encoded); fields[13] = .unsigned(release.stage.rawValue)
            fields[14] = .bytes(release.originalCommit); fields[15] = .bytes(release.transportWakeDigest)
        }
        return try DeterministicCBOR.encode(.map(fields), limits: release == nil ? Self.limits : Self.releaseLimits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        try decode(bytes, allowReleaseBound: false)
    }
    static func decodeForReleaseArchive(_ bytes: Data) throws -> Self {
        try decode(bytes, allowReleaseBound: true)
    }
    private static func decode(_ bytes: Data, allowReleaseBound: Bool) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: allowReleaseBound ? releaseLimits : limits),
              case .unsigned(let version) = f[0],
              supportedVersions.contains(version) || (allowReleaseBound && version == releaseBoundVersion),
              Set(f.keys) == Set(UInt64(0)...(version == 1 ? 7 : version == 2 ? 11 : 15)),
              f[1] == .text("remozio-gateway-runtime-commit"), case .bytes(let id) = f[2],
              case .bytes(let intent) = f[3], case .bytes(let foreground) = f[4], case .bytes(let pair) = f[5],
              case .bytes(let authority) = f[6], case .bytes(let transport) = f[7] else { throw GatewayPreparationError.invalidRecord }
        let value: Self
        if version == 1 {
            value = try Self(id: id, intent: intent, foreground: foreground, pair: pair, authority: authority, transport: transport)
        } else if version == releaseBoundVersion {
            guard case .bytes(let gateway) = f[10], case .bytes(let binding) = f[12],
                  case .unsigned(let rawStage) = f[13], let stage = RuntimeReleasePolicyStage(rawValue: rawStage),
                  case .bytes(let original) = f[14], case .bytes(let wake) = f[15] else { throw GatewayPreparationError.invalidRecord }
            func optionalBytes(_ key: UInt64) throws -> Data? {
                switch f[key] { case .null?: return nil; case .bytes(let bytes)?: return bytes; default: throw GatewayPreparationError.invalidRecord }
            }
            let sequence: UInt64?
            switch f[8] { case .null?: sequence = nil; case .unsigned(let number)?: sequence = number; default: throw GatewayPreparationError.invalidRecord }
            value = try Self(id: id, intent: intent, foreground: foreground, pair: pair, authority: authority, transport: transport,
                sequence: sequence, revision: optionalBytes(9), gateway: gateway, activation: optionalBytes(11),
                release: .init(binding: RuntimeReleaseBinding.decode(binding), stage: stage,
                    originalCommit: original, transportWakeDigest: wake))
        } else {
            guard case .unsigned(let sequence) = f[8], case .bytes(let revision) = f[9],
                  case .bytes(let gateway) = f[10], case .bytes(let activation) = f[11] else { throw GatewayPreparationError.invalidRecord }
            value = try Self(id: id, intent: intent, foreground: foreground, pair: pair, authority: authority, transport: transport,
                sequence: sequence, revision: revision, gateway: gateway, activation: activation)
        }
        guard try value.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    private static let limits = try! CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 25)
    private static let releaseLimits = try! CBORLimits(maxBytes: 16384, maxDepth: 1, maxItems: 33)
}
