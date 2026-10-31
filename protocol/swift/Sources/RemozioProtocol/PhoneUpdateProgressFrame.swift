import Foundation

public enum PhoneUpdateProgressFailure: UInt64, Sendable { case unavailable = 0, incompatible = 1 }
public enum PhoneUpdateProgressFrameError: Error { case invalidMessage }

/// Carries observations only. Parsing a response does not verify its Root signature or establish freshness.
public enum PhoneUpdateProgressFrame: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case status(queryNonce: Data)
    case response(queryNonce: Data, canonicalPayload: Data, signature: Data)
    case failure(queryNonce: Data, reason: PhoneUpdateProgressFailure)
    public static let applicationProtocol = "remozio-update-progress/1"
    public static let maximumBytes = 8192
    private static let domain = "dev.remozio.phone.update-progress"
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: 32) } }
    public var queryNonce: Data {
        switch self {
        case .status(let nonce), .response(let nonce, _, _), .failure(let nonce, _): nonce
        }
    }
    public var description: String { "PhoneUpdateProgressFrame(redacted)" }
    public var debugDescription: String { description }
    public func encode() throws -> Data {
        guard queryNonce.count == 32 else { throw PhoneUpdateProgressFrameError.invalidMessage }
        let kind: UInt64, payload: CBORValue
        switch self {
        case .status: kind = 0; payload = .null
        case let .response(nonce, bytes, signature):
            guard signature.count == 64, try UpdateSchedulingProgressResponse.decode(bytes).status.queryNonce == nonce else {
                throw PhoneUpdateProgressFrameError.invalidMessage
            }
            kind = 1; payload = .array([.bytes(bytes), .bytes(signature)])
        case let .failure(_, reason): kind = 2; payload = .unsigned(reason.rawValue)
        }
        return try DeterministicCBOR.encode(.map([
            0: .text(Self.domain), 1: .unsigned(1), 2: .unsigned(kind), 3: .bytes(queryNonce), 4: payload,
        ]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              Set(fields.keys) == Set(UInt64(0)...4), fields[0] == .text(domain), fields[1] == .unsigned(1),
              case let .unsigned(kind) = fields[2], case let .bytes(nonce) = fields[3], let payload = fields[4] else {
            throw PhoneUpdateProgressFrameError.invalidMessage
        }
        let frame: Self
        switch (kind, payload) {
        case (0, .null): frame = .status(queryNonce: nonce)
        case let (1, .array(values)) where values.count == 2:
            guard case let .bytes(body) = values[0], case let .bytes(signature) = values[1] else {
                throw PhoneUpdateProgressFrameError.invalidMessage
            }
            frame = .response(queryNonce: nonce, canonicalPayload: body, signature: signature)
        case let (2, .unsigned(tag)):
            guard let reason = PhoneUpdateProgressFailure(rawValue: tag) else { throw PhoneUpdateProgressFrameError.invalidMessage }
            frame = .failure(queryNonce: nonce, reason: reason)
        default: throw PhoneUpdateProgressFrameError.invalidMessage
        }
        guard try frame.encode() == bytes else { throw PhoneUpdateProgressFrameError.invalidMessage }; return frame
    }
}
