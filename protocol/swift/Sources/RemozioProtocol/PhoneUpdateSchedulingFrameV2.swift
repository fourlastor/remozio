import Foundation

/// An explicit scheduling version. Version1 readers never accept its messages.
public enum PhoneUpdateSchedulingFrameV2: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case message(PhoneUpdateSchedulingFrame)
    case tooLate(queryNonce: Data, canonicalPayload: Data, signature: Data)
    public static let applicationProtocol = "remozio-update-scheduling/2"
    public static let maximumBytes = 9216
    private static let domain = "dev.remozio.phone.update-scheduling"
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 3, maxItems: 32) } }
    public var queryNonce: Data {
        switch self {
        case .message(let frame): frame.queryNonce
        case .tooLate(let nonce, _, _): nonce
        }
    }
    public var description: String { "PhoneUpdateSchedulingFrameV2(redacted)" }
    public var debugDescription: String { description }

    public func encode() throws -> Data {
        let fields: [UInt64: CBORValue]
        switch self {
        case .message(let frame):
            guard case var .map(source) = try DeterministicCBOR.decode(frame.encode(), limits: Self.limits) else {
                throw PhoneUpdateSchedulingFrameError.invalidMessage
            }
            source[1] = .unsigned(2); fields = source
        case let .tooLate(nonce, payload, signature):
            guard nonce.count == 32, signature.count == 64,
                  try UpdateSchedulingTooLateResponse.decode(payload).progress.status.queryNonce == nonce else {
                throw PhoneUpdateSchedulingFrameError.invalidMessage
            }
            fields = [0: .text(Self.domain), 1: .unsigned(2), 2: .unsigned(6), 3: .bytes(nonce),
                4: .array([.bytes(payload), .bytes(signature)])]
        }
        return try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case var .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .text(domain), fields[1] == .unsigned(2),
              case let .unsigned(kind) = fields[2] else { throw PhoneUpdateSchedulingFrameError.invalidMessage }
        let frame: Self
        if kind == 6 {
            guard case let .bytes(nonce) = fields[3], case let .array(pair) = fields[4], pair.count == 2,
                  case let .bytes(payload) = pair[0], case let .bytes(signature) = pair[1] else {
                throw PhoneUpdateSchedulingFrameError.invalidMessage
            }
            frame = .tooLate(queryNonce: nonce, canonicalPayload: payload, signature: signature)
        } else {
            guard kind <= 5 else { throw PhoneUpdateSchedulingFrameError.invalidMessage }
            fields[1] = .unsigned(1)
            frame = .message(try PhoneUpdateSchedulingFrame.decode(DeterministicCBOR.encode(.map(fields), limits: limits)))
        }
        guard try frame.encode() == bytes else { throw PhoneUpdateSchedulingFrameError.invalidMessage }
        return frame
    }
}
