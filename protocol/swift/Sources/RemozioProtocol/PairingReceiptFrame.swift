import Foundation

public enum PairingReceiptFrameError: Error { case invalidFrame }

/// Read-only recovery over an enrolled TLS channel. Only a verified Root receipt can activate the retained pairing.
public enum PairingReceiptFrame: Sendable, CustomStringConvertible {
    case query(setupID: Data)
    case response(setupID: Data, signature: Data?)
    public static let maximumBytes = 160
    public static let applicationProtocol = "remozio-receipt/1"
    public var description: String { "PairingReceiptFrame(redacted)" }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 1, maxItems: 11) } }

    public func encode() throws -> Data {
        let kind: UInt64, id: Data, signature: Data?
        switch self {
        case .query(let value): kind = 0; id = value; signature = nil
        case .response(let value, let proof): kind = 1; id = value; signature = proof
        }
        guard id.count == 16, signature == nil || signature?.count == 64 else { throw PairingReceiptFrameError.invalidFrame }
        return try DeterministicCBOR.encode(.map([0: .text("dev.remozio.pairing.receipt"), 1: .unsigned(1),
            2: .unsigned(kind), 3: .bytes(id), 4: signature.map(CBORValue.bytes) ?? .null]), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .text("dev.remozio.pairing.receipt"),
              fields[1] == .unsigned(1), case .unsigned(let kind) = fields[2],
              case .bytes(let id) = fields[3] else { throw PairingReceiptFrameError.invalidFrame }
        let result: Self
        switch (kind, fields[4]) {
        case (0, .null): result = .query(setupID: id)
        case (1, .null): result = .response(setupID: id, signature: nil)
        case (1, .bytes(let signature)): result = .response(setupID: id, signature: signature)
        default: throw PairingReceiptFrameError.invalidFrame
        }
        guard try result.encode() == bytes else { throw PairingReceiptFrameError.invalidFrame }
        return result
    }
}
