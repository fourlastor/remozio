import Foundation

public enum PhoneAuditError: Error, Equatable { case invalidMessage }
public enum PhoneAuditFailure: UInt64, Sendable { case unavailable = 0, incompatible = 1 }

/// Read-only carrier. Reply bodies remain opaque here; their typed parser, signature and pending query must all be checked.
public enum PhoneAuditFrame: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case historyQuery(queryNonce: Data, epoch: Data?, after: UInt64?)
    case pageQuery(queryNonce: Data, epoch: Data, generation: UInt64, after: UInt64)
    case historyResponse(queryNonce: Data, canonicalPayload: Data, signature: Data)
    case pageResponse(queryNonce: Data, canonicalPayload: Data, signature: Data)
    case failure(queryNonce: Data, reason: PhoneAuditFailure)

    public static let applicationProtocol = "remozio-audit/1"
    public static let maximumPayloadBytes = 1_048_576
    public static let overheadBytes = 256
    public static let maximumBytes = maximumPayloadBytes + overheadBytes
    public static let maximumQueryBytes = 256
    private static let domain = "dev.remozio.phone.audit"
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 3, maxItems: 20) } }
    public var queryNonce: Data {
        switch self {
        case .historyQuery(let nonce, _, _), .pageQuery(let nonce, _, _, _),
             .historyResponse(let nonce, _, _), .pageResponse(let nonce, _, _), .failure(let nonce, _): nonce
        }
    }
    public var isQuery: Bool {
        switch self { case .historyQuery, .pageQuery: true; default: false }
    }
    public var description: String { "PhoneAuditFrame(redacted)" }
    public var debugDescription: String { description }

    public func encode() throws -> Data {
        guard queryNonce.count == 32 else { throw PhoneAuditError.invalidMessage }
        let kind: UInt64, payload: CBORValue
        switch self {
        case .historyQuery(_, let epoch, let after):
            guard (epoch == nil) == (after == nil), epoch == nil || epoch?.count == 16 else { throw PhoneAuditError.invalidMessage }
            kind = 0; payload = .array([epoch.map(CBORValue.bytes) ?? .null, after.map(CBORValue.unsigned) ?? .null])
        case .pageQuery(_, let epoch, let generation, let after):
            guard epoch.count == 16 else { throw PhoneAuditError.invalidMessage }
            kind = 1; payload = .array([.bytes(epoch), .unsigned(generation), .unsigned(after)])
        case .historyResponse(_, let body, let signature), .pageResponse(_, let body, let signature):
            guard (1...Self.maximumPayloadBytes).contains(body.count), signature.count == 64 else { throw PhoneAuditError.invalidMessage }
            if case .historyResponse = self { kind = 2 } else { kind = 3 }
            payload = .array([.bytes(body), .bytes(signature)])
        case .failure(_, let reason): kind = 4; payload = .unsigned(reason.rawValue)
        }
        let bytes = try DeterministicCBOR.encode(.map([0: .text(Self.domain), 1: .unsigned(1), 2: .unsigned(kind),
            3: .bytes(queryNonce), 4: payload]), limits: Self.limits)
        guard !isQuery || bytes.count <= Self.maximumQueryBytes else { throw PhoneAuditError.invalidMessage }
        return bytes
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits), Set(f.keys) == Set(UInt64(0)...4),
              f[0] == .text(domain), f[1] == .unsigned(1), case .unsigned(let kind) = f[2],
              case .bytes(let nonce) = f[3], let payload = f[4] else { throw PhoneAuditError.invalidMessage }
        func array(_ count: Int) throws -> [CBORValue] {
            guard case .array(let fields) = payload, fields.count == count else { throw PhoneAuditError.invalidMessage }; return fields
        }
        let frame: Self
        switch kind {
        case 0:
            let fields = try array(2), epoch: Data?, after: UInt64?
            switch (fields[0], fields[1]) {
            case (.null, .null): epoch = nil; after = nil
            case (.bytes(let value), .unsigned(let cursor)): epoch = value; after = cursor
            default: throw PhoneAuditError.invalidMessage
            }
            frame = .historyQuery(queryNonce: nonce, epoch: epoch, after: after)
        case 1:
            let fields = try array(3)
            guard case .bytes(let epoch) = fields[0], case .unsigned(let generation) = fields[1],
                  case .unsigned(let after) = fields[2] else { throw PhoneAuditError.invalidMessage }
            frame = .pageQuery(queryNonce: nonce, epoch: epoch, generation: generation, after: after)
        case 2, 3:
            let fields = try array(2)
            guard case .bytes(let body) = fields[0], case .bytes(let signature) = fields[1] else { throw PhoneAuditError.invalidMessage }
            frame = kind == 2 ? .historyResponse(queryNonce: nonce, canonicalPayload: body, signature: signature) :
                .pageResponse(queryNonce: nonce, canonicalPayload: body, signature: signature)
        case 4:
            guard case .unsigned(let tag) = payload, let reason = PhoneAuditFailure(rawValue: tag) else { throw PhoneAuditError.invalidMessage }
            frame = .failure(queryNonce: nonce, reason: reason)
        default: throw PhoneAuditError.invalidMessage
        }
        guard try frame.encode() == bytes else { throw PhoneAuditError.invalidMessage }; return frame
    }
}
