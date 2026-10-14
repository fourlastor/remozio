import Foundation

/// Restricted setup messages. Administrator rights, commands and credential releases have no representation here.
public enum PairingSetupFrame: Sendable, CustomStringConvertible {
    case hello
    case proposal(PairingPhoneProposal)
    case transcript(PairingTranscript)
    case proof(setupID: Data, digest: Data, signature: Data)
    case receipt(setupID: Data, digest: Data, signature: Data)
    public static let maximumBytes = 132_256
    public static let applicationProtocol = "remozio-pairing/1"
    public var description: String { "PairingSetupFrame(redacted)" }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 20) } }
    public func encode() throws -> Data {
        let kind: UInt64, body: CBORValue
        switch self {
        case .hello: kind = 0; body = .null
        case .proposal(let value): kind = 1; body = .bytes(try value.encode())
        case .transcript(let value): kind = 2; body = .bytes(try value.encode())
        case .proof(let id, let digest, let signature): kind = 3; body = try Self.proofValue(id, digest, signature)
        case .receipt(let id, let digest, let signature): kind = 4; body = try Self.proofValue(id, digest, signature)
        }
        return try DeterministicCBOR.encode(.map([0: .text("dev.remozio.pairing.exchange"),
            1: .unsigned(1), 2: .unsigned(kind), 3: body]), limits: Self.limits)
    }
    private static func proofValue(_ id: Data, _ digest: Data, _ signature: Data) throws -> CBORValue {
        guard id.count == 16, digest.count == 32, signature.count == 64 else { throw PairingError.invalidTranscript }
        return .array([.bytes(id), .bytes(digest), .bytes(signature)])
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...3),
              f[0] == .text("dev.remozio.pairing.exchange"), f[1] == .unsigned(1),
              case .unsigned(let kind) = f[2] else { throw PairingError.invalidTranscript }
        let result: Self
        switch (kind, f[3]) {
        case (0, .null): result = .hello
        case (1, .bytes(let body)): result = .proposal(try PairingPhoneProposal.decode(body))
        case (2, .bytes(let body)): result = .transcript(try PairingTranscript.decode(body))
        case (3, .array(let row)), (4, .array(let row)):
            guard row.count == 3, case .bytes(let id) = row[0], case .bytes(let digest) = row[1],
                  case .bytes(let signature) = row[2] else { throw PairingError.invalidTranscript }
            _ = try proofValue(id, digest, signature)
            result = kind == 3 ? .proof(setupID: id, digest: digest, signature: signature) :
                .receipt(setupID: id, digest: digest, signature: signature)
        default: throw PairingError.invalidTranscript
        }
        guard try result.encode() == bytes else { throw PairingError.invalidTranscript }; return result
    }
}
