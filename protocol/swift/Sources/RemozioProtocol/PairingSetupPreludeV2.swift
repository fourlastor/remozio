import Foundation

/// The invitation proof precedes the existing transcript and receipt exchange.
public enum PairingSetupPreludeV2: Sendable, CustomStringConvertible {
    case challenge(Data)
    case proposal(PairingPhoneProposal, tag: Data)

    public static let applicationProtocol = "remozio-pairing/2"
    public static let maximumBytes = 66_128
    private static let domain = "dev.remozio.pairing.exchange"
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 13) } }
    public var description: String { "PairingSetupPreludeV2(redacted)" }

    public func encode() throws -> Data {
        let kind: UInt64, body: CBORValue
        switch self {
        case .challenge(let challenge):
            guard challenge.count == 32 else { throw PairingError.invalidTranscript }
            kind = 0; body = .bytes(challenge)
        case .proposal(let proposal, let tag):
            guard tag.count == 32 else { throw PairingError.invalidTranscript }
            kind = 1; body = .array([.bytes(try proposal.encode()), .bytes(tag)])
        }
        return try DeterministicCBOR.encode(.map([
            0: .text(Self.domain), 1: .unsigned(2), 2: .unsigned(kind), 3: body,
        ]), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...3), fields[0] == .text(domain), fields[1] == .unsigned(2) else {
            throw PairingError.invalidTranscript
        }
        let result: Self
        switch (fields[2], fields[3]) {
        case (.unsigned(0), .bytes(let challenge)) where challenge.count == 32:
            result = .challenge(challenge)
        case (.unsigned(1), .array(let row)):
            guard row.count == 2, case .bytes(let payload) = row[0],
                  case .bytes(let tag) = row[1], tag.count == 32 else { throw PairingError.invalidTranscript }
            result = .proposal(try PairingPhoneProposal.decode(payload), tag: tag)
        default:
            throw PairingError.invalidTranscript
        }
        guard try result.encode() == bytes else { throw PairingError.invalidTranscript }
        return result
    }
}
