import Foundation

public enum PhoneUpdateSchedulingFailure: UInt64, Sendable { case unavailable = 0, incompatible = 1 }
public enum PhoneUpdateSchedulingFrameError: Error { case invalidMessage }

/// Bounded scheduling messages for a dedicated enrolled channel. Parsing grants no authority.
public enum PhoneUpdateSchedulingFrame: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case status(queryNonce: Data)
    case challenge(queryNonce: Data, updateID: Data, generation: UInt64, revision: UInt64, action: UpdateSchedulingAction)
    case apply(queryNonce: Data, canonicalControl: Data, signature: Data)
    case challengeResponse(queryNonce: Data, canonicalPayload: Data, signature: Data)
    case stateResponse(queryNonce: Data, canonicalPayload: Data, signature: Data)
    case failure(queryNonce: Data, reason: PhoneUpdateSchedulingFailure)
    public static let applicationProtocol = "remozio-update-scheduling/1"
    public static let maximumBytes = 4096
    private static let domain = "dev.remozio.phone.update-scheduling"
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 3, maxItems: 32) } }
    private static var controlLimits: CBORLimits { get throws { try .init(maxBytes: 1024, maxDepth: 2, maxItems: 32) } }
    private static var responseLimits: CBORLimits { get throws { try .init(maxBytes: 2048, maxDepth: 2, maxItems: 32) } }
    public var queryNonce: Data {
        switch self {
        case .status(let n), .challenge(let n, _, _, _, _), .apply(let n, _, _),
             .challengeResponse(let n, _, _), .stateResponse(let n, _, _), .failure(let n, _): n
        }
    }
    public var description: String { "PhoneUpdateSchedulingFrame(redacted)" }
    public var debugDescription: String { description }
    public func encode() throws -> Data {
        guard queryNonce.count == 32 else { throw PhoneUpdateSchedulingFrameError.invalidMessage }
        let kind: UInt64, payload: CBORValue
        switch self {
        case .status: kind = 0; payload = .null
        case .challenge(_, let update, let generation, let revision, let action):
            guard update.count == 32, generation > 0 else { throw PhoneUpdateSchedulingFrameError.invalidMessage }
            kind = 1; payload = .array([.bytes(update), .unsigned(generation), .unsigned(revision), .unsigned(action.rawValue)])
        case .apply(_, let control, let signature):
            guard signature.count == 64 else { throw PhoneUpdateSchedulingFrameError.invalidMessage }
            _ = try UpdateSchedulingControl.decode(control, limits: Self.controlLimits)
            kind = 2; payload = .array([.bytes(control), .bytes(signature)])
        case .challengeResponse(_, let body, let signature):
            guard signature.count == 64, try RootUpdateSchedulingChallenge.decode(body, limits: Self.responseLimits).queryNonce == queryNonce else {
                throw PhoneUpdateSchedulingFrameError.invalidMessage
            }
            kind = 3; payload = .array([.bytes(body), .bytes(signature)])
        case .stateResponse(_, let body, let signature):
            guard signature.count == 64, try UpdateSchedulingStatusResponse.decode(body).queryNonce == queryNonce else {
                throw PhoneUpdateSchedulingFrameError.invalidMessage
            }
            kind = 4; payload = .array([.bytes(body), .bytes(signature)])
        case .failure(_, let reason): kind = 5; payload = .unsigned(reason.rawValue)
        }
        return try DeterministicCBOR.encode(.map([0: .text(Self.domain), 1: .unsigned(1), 2: .unsigned(kind),
            3: .bytes(queryNonce), 4: payload]), limits: Self.limits)
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case let .map(f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...4),
              f[0] == .text(domain), f[1] == .unsigned(1), case let .unsigned(kind) = f[2],
              case let .bytes(nonce) = f[3], let payload = f[4] else { throw PhoneUpdateSchedulingFrameError.invalidMessage }
        let frame: Self
        switch (kind, payload) {
        case (0, .null): frame = .status(queryNonce: nonce)
        case (1, .array(let fields)) where fields.count == 4:
            guard case let .bytes(update) = fields[0], case let .unsigned(generation) = fields[1],
                  case let .unsigned(revision) = fields[2], case let .unsigned(tag) = fields[3],
                  let action = UpdateSchedulingAction(rawValue: tag) else { throw PhoneUpdateSchedulingFrameError.invalidMessage }
            frame = .challenge(queryNonce: nonce, updateID: update, generation: generation, revision: revision, action: action)
        case (2...4, .array(let fields)) where fields.count == 2:
            guard case let .bytes(body) = fields[0], case let .bytes(signature) = fields[1] else { throw PhoneUpdateSchedulingFrameError.invalidMessage }
            if kind == 2 { frame = .apply(queryNonce: nonce, canonicalControl: body, signature: signature) }
            else if kind == 3 { frame = .challengeResponse(queryNonce: nonce, canonicalPayload: body, signature: signature) }
            else { frame = .stateResponse(queryNonce: nonce, canonicalPayload: body, signature: signature) }
        case (5, .unsigned(let tag)):
            guard let reason = PhoneUpdateSchedulingFailure(rawValue: tag) else { throw PhoneUpdateSchedulingFrameError.invalidMessage }
            frame = .failure(queryNonce: nonce, reason: reason)
        default: throw PhoneUpdateSchedulingFrameError.invalidMessage
        }
        guard try frame.encode() == bytes else { throw PhoneUpdateSchedulingFrameError.invalidMessage }; return frame
    }
}
