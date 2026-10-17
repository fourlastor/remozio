import Foundation

public enum PendingRequestSnapshotError: Error { case invalidFrame }

/// Bounded discovery over enrolled TLS. Completion gives no request outcome or decision authority.
public enum PendingRequestSnapshotFrame: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case query(nonce: Data, maximumFrames: UInt64, maximumBytes: UInt64, retainedRequestIDs: [Data] = [])
    case item(nonce: Data, ordinal: UInt64, frame: Data)
    case complete(nonce: Data, frames: UInt64, bytes: UInt64)
    public static let applicationProtocol = "remozio-pending/1"
    public static let maximumFrames: UInt64 = 4096
    public static let maximumRetainedRequests = 4096
    public static let maximumSnapshotBytes: UInt64 = 67_108_864
    public static let maximumFrameBytes = 16_777_088
    public static let maximumBytes = maximumFrameBytes + 128
    public var description: String { "PendingRequestSnapshotFrame(redacted)" }
    public var debugDescription: String { description }
    private static var limits: CBORLimits { get throws { try .init(maxBytes: maximumBytes, maxDepth: 2, maxItems: maximumRetainedRequests + 15) } }

    public func encode() throws -> Data {
        let kind: UInt64, nonce: Data, a: UInt64, b: CBORValue
        var retained: [Data]?
        switch self {
        case .query(let value, let frames, let bytes, let ids):
            guard (1...Self.maximumFrames).contains(frames), (1...Self.maximumSnapshotBytes).contains(bytes),
                  ids.count <= Self.maximumRetainedRequests, ids.allSatisfy({ $0.count == 16 }), Set(ids).count == ids.count else {
                throw PendingRequestSnapshotError.invalidFrame
            }
            kind = 0; nonce = value; a = frames; b = .unsigned(bytes)
            retained = ids.sorted { $0.lexicographicallyPrecedes($1) }
        case .item(let value, let ordinal, let frame):
            guard ordinal < Self.maximumFrames, !frame.isEmpty, frame.count <= Self.maximumFrameBytes else {
                throw PendingRequestSnapshotError.invalidFrame
            }
            kind = 1; nonce = value; a = ordinal; b = .bytes(frame)
        case .complete(let value, let frames, let bytes):
            guard frames <= Self.maximumFrames, bytes <= Self.maximumSnapshotBytes,
                  (frames == 0) == (bytes == 0), bytes >= frames else { throw PendingRequestSnapshotError.invalidFrame }
            kind = 2; nonce = value; a = frames; b = .unsigned(bytes)
        }
        guard nonce.count == 32 else { throw PendingRequestSnapshotError.invalidFrame }
        var fields: [UInt64: CBORValue] = [0: .text("dev.remozio.pending.snapshot"), 1: .unsigned(1),
            2: .unsigned(kind), 3: .bytes(nonce), 4: .unsigned(a), 5: b]
        if let retained { fields[6] = .array(retained.map(CBORValue.bytes)) }
        return try DeterministicCBOR.encode(.map(fields), limits: Self.limits)
    }

    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits),
              fields[0] == .text("dev.remozio.pending.snapshot"),
              fields[1] == .unsigned(1), case .unsigned(let kind) = fields[2],
              case .bytes(let nonce) = fields[3], case .unsigned(let a) = fields[4] else {
            throw PendingRequestSnapshotError.invalidFrame
        }
        guard Set(fields.keys) == Set(UInt64(0)...(kind == 0 ? 6 : 5)) else { throw PendingRequestSnapshotError.invalidFrame }
        let result: Self
        switch (kind, fields[5]) {
        case (0, .unsigned(let b)):
            guard case .array(let values) = fields[6] else { throw PendingRequestSnapshotError.invalidFrame }
            let ids = try values.map { value -> Data in
                guard case .bytes(let id) = value else { throw PendingRequestSnapshotError.invalidFrame }
                return id
            }
            result = .query(nonce: nonce, maximumFrames: a, maximumBytes: b, retainedRequestIDs: ids)
        case (1, .bytes(let b)): result = .item(nonce: nonce, ordinal: a, frame: b)
        case (2, .unsigned(let b)): result = .complete(nonce: nonce, frames: a, bytes: b)
        default: throw PendingRequestSnapshotError.invalidFrame
        }
        guard try result.encode() == bytes else { throw PendingRequestSnapshotError.invalidFrame }
        return result
    }
}
