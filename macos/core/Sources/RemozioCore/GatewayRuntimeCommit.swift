import CryptoKit
import Foundation
import RemozioProtocol

/// The final protected publication marker binds both role files. It does not report running service health.
struct GatewayRuntimeCommit: Sendable {
    static let formatName = "runtime.gateway-runtime-commit"
    static let supportedVersions: Set<UInt64> = [1, 2]
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

    init(_ pair: GatewayRuntimeExtensions) throws {
        intentID = pair.authority.intentID; intentDigest = pair.authority.intentDigest
        foregroundDigest = pair.authority.foregroundDigest; pairDigest = try pair.digest
        authorityDigest = Data(SHA256.hash(data: try pair.authority.encoded))
        transportDigest = Data(SHA256.hash(data: try pair.transport.encoded))
        settingsSequence = nil; settingsRevisionDigest = nil; gatewayConfigurationDigest = nil; activationDigest = nil
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
    private init(id: Data, intent: Data, foreground: Data, pair: Data, authority: Data, transport: Data,
                 sequence: UInt64? = nil, revision: Data? = nil, gateway: Data? = nil, activation: Data? = nil) throws {
        guard id.count == 16, [intent, foreground, pair, authority, transport].allSatisfy({ $0.count == 32 }) else {
            throw GatewayPreparationError.invalidRecord
        }
        guard (sequence == nil && revision == nil && gateway == nil && activation == nil) ||
            (sequence != nil && sequence! > 0 && revision?.count == 32 && gateway?.count == 32 && activation?.count == 32) else {
            throw GatewayPreparationError.invalidRecord
        }
        intentID = id; intentDigest = intent; foregroundDigest = foreground; pairDigest = pair
        authorityDigest = authority; transportDigest = transport
        settingsSequence = sequence; settingsRevisionDigest = revision; gatewayConfigurationDigest = gateway; activationDigest = activation
    }
    func validate(_ pair: GatewayRuntimeExtensions) throws {
        let expected = try Self(pair)
        guard intentID == expected.intentID, intentDigest == expected.intentDigest, foregroundDigest == expected.foregroundDigest,
              pairDigest == expected.pairDigest, authorityDigest == expected.authorityDigest, transportDigest == expected.transportDigest else {
            throw GatewayPreparationError.changedScope
        }
    }
    func validate(_ role: GatewayRuntimeExtension) throws {
        guard role.intentID == intentID, role.intentDigest == intentDigest, role.foregroundDigest == foregroundDigest,
              Data(SHA256.hash(data: try role.encoded)) == (role.target == .authority ? authorityDigest : transportDigest) else {
            throw GatewayPreparationError.changedScope
        }
    }
    /// Version 1 keeps its existing cache key. Every settings revision changes the version 2 observation key.
    var observationDigest: Data { get throws {
        settingsSequence == nil ? pairDigest : Data(SHA256.hash(data: try encoded))
    } }
    func validate(settings revision: GatewayRuntimeSettingsRevision, gateway: GatewayServiceConfiguration) throws {
        guard settingsSequence == revision.sequence, settingsRevisionDigest == (try revision.digest),
              activationDigest == revision.activationDigest, gatewayConfigurationDigest == revision.gatewayDigest,
              gatewayConfigurationDigest == Data(SHA256.hash(data: gateway.canonicalBytes)) else {
            throw GatewayPreparationError.changedScope
        }
    }
    var encoded: Data { get throws {
        var fields: [UInt64: CBORValue] = [0: .unsigned(settingsSequence == nil ? 1 : 2), 1: .text("remozio-gateway-runtime-commit"),
            2: .bytes(intentID), 3: .bytes(intentDigest), 4: .bytes(foregroundDigest), 5: .bytes(pairDigest),
            6: .bytes(authorityDigest), 7: .bytes(transportDigest)]
        if let sequence = settingsSequence, let revision = settingsRevisionDigest,
           let gateway = gatewayConfigurationDigest, let activation = activationDigest {
            fields[8] = .unsigned(sequence); fields[9] = .bytes(revision); fields[10] = .bytes(gateway); fields[11] = .bytes(activation)
        }
        return try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits),
              case .unsigned(let version) = f[0], supportedVersions.contains(version),
              Set(f.keys) == Set(UInt64(0)...(version == 1 ? 7 : 11)),
              f[1] == .text("remozio-gateway-runtime-commit"), case .bytes(let id) = f[2],
              case .bytes(let intent) = f[3], case .bytes(let foreground) = f[4], case .bytes(let pair) = f[5],
              case .bytes(let authority) = f[6], case .bytes(let transport) = f[7] else { throw GatewayPreparationError.invalidRecord }
        let value: Self
        if version == 1 {
            value = try Self(id: id, intent: intent, foreground: foreground, pair: pair, authority: authority, transport: transport)
        } else {
            guard case .unsigned(let sequence) = f[8], case .bytes(let revision) = f[9],
                  case .bytes(let gateway) = f[10], case .bytes(let activation) = f[11] else { throw GatewayPreparationError.invalidRecord }
            value = try Self(id: id, intent: intent, foreground: foreground, pair: pair, authority: authority, transport: transport,
                sequence: sequence, revision: revision, gateway: gateway, activation: activation)
        }
        guard try value.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    private static let limits = try! CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 25)
}
