import CryptoKit
import Foundation
import RemozioProtocol

/// Records an abandoned Root grant at its original revision. It carries no delivery material.
public struct GatewayControlTombstone: Sendable, Equatable {
    public enum GrantKind: UInt64, Sendable { case candidate = 1, activation = 2 }
    static let receiptKind: UInt64 = 6

    public let registration: GatewayRegistrationIdentity
    public let revision: UInt64
    public let originalKind: GrantKind
    public let operationID: Data
    public let originalDigest: Data

    init(registration: GatewayRegistrationIdentity, revision: UInt64, originalKind: GrantKind,
         operationID: Data, originalDigest: Data) throws {
        guard revision > 0, operationID.count == 16, originalDigest.count == 32 else {
            throw GatewayHeadReplyError.invalidReceipt
        }
        self.registration = registration; self.revision = revision; self.originalKind = originalKind
        self.operationID = operationID; self.originalDigest = originalDigest
    }

    func encode() throws -> Data {
        try DeterministicCBOR.encode(.array([.unsigned(1), .bytes(registration.encode()), .unsigned(revision),
            .unsigned(originalKind.rawValue), .bytes(operationID), .bytes(originalDigest)]), limits: Self.limits)
    }

    static func authenticate(_ payload: Data, signature: Data, registration: GatewayRegistrationIdentity) throws -> Self {
        guard case let .array(values) = try DeterministicCBOR.decode(payload, limits: limits), values.count == 6,
              values[0] == .unsigned(1), values[1] == .bytes(try registration.encode()), case let .unsigned(revision) = values[2],
              case let .unsigned(kind) = values[3], let originalKind = GrantKind(rawValue: kind),
              case let .bytes(operation) = values[4], case let .bytes(digest) = values[5],
              signature.count == 64, let key = try? P256.Signing.PublicKey(x963Representation: registration.rootPublicKey),
              let proof = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
              key.isValidSignature(proof, for: signingInput(payload)) else {
            throw GatewayHeadReplyError.invalidReceipt
        }
        let value = try Self(registration: registration, revision: revision, originalKind: originalKind,
            operationID: operation, originalDigest: digest)
        guard try value.encode() == payload else { throw GatewayHeadReplyError.invalidReceipt }
        return value
    }

    static func signingInput(_ payload: Data) -> Data {
        Data("remozio/gateway/control-tombstone/v1\0".utf8) + payload
    }

    static func digest(payload: Data, signature: Data) -> Data {
        // The verified Root signature is always the fixed 64-byte suffix.
        Data(SHA256.hash(data: Data("remozio/gateway/abandoned-grant/v1\0".utf8) + payload + signature))
    }

    private static var limits: CBORLimits { get throws { try .init(maxBytes: 1024, maxDepth: 1, maxItems: 8) } }
}

public struct GatewayControlTombstoneReceipt: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let tombstone: GatewayControlTombstone
    public let canonicalPayload: Data
    public let signature: Data
    public var description: String { "GatewayControlTombstoneReceipt(redacted)" }
    public var debugDescription: String { description }
}

struct GatewayControlTombstoneApplication: Sendable {
    let receipt: GatewayControlTombstoneReceipt
    let inserted: Bool
}
