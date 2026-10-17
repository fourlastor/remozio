import Foundation

/// Transfer bookkeeping only. Verify every returned frame before using its request or status claims.
/// One channel owner retains this value. Omitted requests never become expired or terminal here.
public struct PendingRequestSnapshotProgress: CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "PendingRequestSnapshotProgress(redacted)" }
    public var debugDescription: String { description }
    private let nonce: Data
    private let maximumFrames: UInt64
    private let maximumBytes: UInt64
    private var frames: UInt64 = 0
    private var bytes: UInt64 = 0
    private var failed = false
    public private(set) var isComplete = false
    public init(query: PendingRequestSnapshotFrame) throws {
        guard case .query(let nonce, let frames, let bytes, _) = query else { throw PendingRequestSnapshotError.invalidFrame }
        _ = try query.encode()
        self.nonce = nonce; maximumFrames = frames; maximumBytes = bytes
    }
    public mutating func accept(_ encoded: Data) throws -> Data? {
        do {
            guard !failed, !isComplete else { throw PendingRequestSnapshotError.invalidFrame }
            switch try PendingRequestSnapshotFrame.decode(encoded) {
            case .item(let nonce, let ordinal, let frame):
                guard nonce == self.nonce, ordinal == frames, frames < maximumFrames,
                      UInt64(frame.count) <= maximumBytes - bytes else { throw PendingRequestSnapshotError.invalidFrame }
                frames += 1; bytes += UInt64(frame.count)
                return frame
            case .complete(let nonce, let frames, let bytes):
                guard nonce == self.nonce, frames == self.frames, bytes == self.bytes else {
                    throw PendingRequestSnapshotError.invalidFrame
                }
                isComplete = true
                return nil
            case .query: throw PendingRequestSnapshotError.invalidFrame
            }
        } catch { failed = true; isComplete = false; throw error }
    }
    /// EOF, cancellation and timeouts cannot complete a transfer without its exact marker.
    public mutating func requireComplete() throws {
        guard !failed, isComplete else { failed = true; throw PendingRequestSnapshotError.invalidFrame }
    }
}
