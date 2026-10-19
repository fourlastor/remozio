import CryptoKit
import Foundation
import RemozioProtocol

/// The final protected publication marker binds both role files. It does not report running service health.
struct GatewayRuntimeCommit: Sendable {
    let intentID: Data
    let intentDigest: Data
    let foregroundDigest: Data
    let pairDigest: Data
    let authorityDigest: Data
    let transportDigest: Data

    init(_ pair: GatewayRuntimeExtensions) throws {
        intentID = pair.authority.intentID; intentDigest = pair.authority.intentDigest
        foregroundDigest = pair.authority.foregroundDigest; pairDigest = try pair.digest
        authorityDigest = Data(SHA256.hash(data: try pair.authority.encoded))
        transportDigest = Data(SHA256.hash(data: try pair.transport.encoded))
    }
    private init(id: Data, intent: Data, foreground: Data, pair: Data, authority: Data, transport: Data) throws {
        guard id.count == 16, [intent, foreground, pair, authority, transport].allSatisfy({ $0.count == 32 }) else {
            throw GatewayPreparationError.invalidRecord
        }
        intentID = id; intentDigest = intent; foregroundDigest = foreground; pairDigest = pair
        authorityDigest = authority; transportDigest = transport
    }
    func validate(_ pair: GatewayRuntimeExtensions) throws {
        guard try encoded == Self(pair).encoded else { throw GatewayPreparationError.changedScope }
    }
    func validate(_ role: GatewayRuntimeExtension) throws {
        guard role.intentID == intentID, role.intentDigest == intentDigest, role.foregroundDigest == foregroundDigest,
              Data(SHA256.hash(data: try role.encoded)) == (role.target == .authority ? authorityDigest : transportDigest) else {
            throw GatewayPreparationError.changedScope
        }
    }
    var encoded: Data { get throws {
        try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .text("remozio-gateway-runtime-commit"), 2: .bytes(intentID),
            3: .bytes(intentDigest), 4: .bytes(foregroundDigest), 5: .bytes(pairDigest),
            6: .bytes(authorityDigest), 7: .bytes(transportDigest)]), limits: Self.limits)
    } }
    static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...7),
              f[0] == .unsigned(1), f[1] == .text("remozio-gateway-runtime-commit"), case .bytes(let id) = f[2],
              case .bytes(let intent) = f[3], case .bytes(let foreground) = f[4], case .bytes(let pair) = f[5],
              case .bytes(let authority) = f[6], case .bytes(let transport) = f[7] else { throw GatewayPreparationError.invalidRecord }
        let value = try Self(id: id, intent: intent, foreground: foreground, pair: pair, authority: authority, transport: transport)
        guard try value.encoded == bytes else { throw GatewayPreparationError.invalidRecord }; return value
    }
    private static let limits = try! CBORLimits(maxBytes: 1024, maxDepth: 1, maxItems: 17)
}
