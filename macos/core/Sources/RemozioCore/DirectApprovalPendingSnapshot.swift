import Foundation
import RemozioProtocol

extension DirectApprovalTransportService {
    /// Sends one finite, read-only view. Each request and status retains its existing Root signature.
    /// The initial index defines this pass. New demand requires a fresh query and nonce.
    public func runPendingRequestSnapshot(for session: DirectApprovalSession, over channel: NegotiatedNetworkChannel,
                                          timeoutMilliseconds: UInt64 = 30_000) async throws {
        try await withTaskCancellationHandler {
            do {
                guard (1...60_000).contains(timeoutMilliseconds), channel.purpose == .pendingSnapshot else {
                    throw ApprovalChannelError.invalidInput
                }
                try await validate(session)
                let metadata = try await channel.negotiated()
                guard metadata.peer.role == .phone, metadata.peer.scope == session.peer.scope, metadata.envelopeVersion == 1,
                      session.peer.requests.contains(where: { local in metadata.peer.requests.contains {
                          $0.kind == local.kind && $0.wireVersion == local.wireVersion && $0.schemaVersion == local.schemaVersion
                      } }) else { throw ApprovalChannelError.invalidInput }
                let channelMaximum = session.peer.channelMaximumPayloadBytes(for: .pendingSnapshot)
                let deadline = ContinuousClock.now.advanced(by: .milliseconds(Int64(timeoutMilliseconds)))
                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask {
                        guard let encoded = try await channel.receive(maximumBytes: min(channelMaximum, PendingRequestSnapshotFrame.maximumBytes)),
                              case .query(let nonce, let maximumFrames, let maximumBytes, let retained) = try PendingRequestSnapshotFrame.decode(encoded) else {
                            throw ApprovalChannelError.invalidInput
                        }
                        try await self.sendPendingSnapshot(for: session, over: channel, nonce: nonce,
                            maximumFrames: maximumFrames, maximumBytes: maximumBytes, retained: retained,
                            remoteRequests: metadata.peer.requests, deadline: deadline)
                    }
                    group.addTask {
                        try await ContinuousClock().sleep(until: deadline)
                        channel.close()
                        throw ApprovalChannelError.timedOut
                    }
                    defer { group.cancelAll() }
                    _ = try await group.next()
                }
                await channel.closeAndWait()
            } catch { await channel.closeAndWait(); throw error }
        } onCancel: { channel.close() }
    }

    private func sendPendingSnapshot(for session: DirectApprovalSession, over channel: NegotiatedNetworkChannel,
                                     nonce: Data, maximumFrames: UInt64, maximumBytes: UInt64, retained: [Data],
                                     remoteRequests: [ChannelRequestCapability], deadline: ContinuousClock.Instant) async throws {
        let channelMaximum = session.peer.channelMaximumPayloadBytes(for: .pendingSnapshot)
        var budget = PendingSnapshotWriteBudget(nonce: nonce, maximumFrames: maximumFrames, maximumBytes: maximumBytes)
        let pending = try await pendingRequestIDs(for: session)
        var statuses = Set(retained)
        for id in pending {
            try await validate(session)
            guard let frame = try await requestFrame(for: session, requestID: id) else { throw ApprovalChannelError.invalidInput }
            guard try Self.supports(frame, maximumBytes: session.peer.maximumPayloadBytes,
                local: session.peer.requests, remote: remoteRequests) else { throw ApprovalChannelError.invalidInput }
            let item = try budget.item(frame, maximumPayloadBytes: channelMaximum)
            try await validate(session)
            try await Self.send(item, over: channel, deadline: deadline)
            try await validate(session)
            statuses.insert(id)
        }
        for id in statuses.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            try await validate(session)
            guard let frame = try await exchangeRequest(for: session, requestID: id) else { continue }
            let maximumBodyBytes = min(session.peer.maximumPayloadBytes, AuthorityRequestExchange.maximumFrameBytes) - ApprovalMessage.overheadBytes
            let message = try ApprovalMessage.decode(frame, maximumBodyBytes: maximumBodyBytes)
            guard message.type == .status, message.purpose == .status else { throw ApprovalChannelError.invalidInput }
            let item = try budget.item(frame, maximumPayloadBytes: channelMaximum)
            try await validate(session)
            try await Self.send(item, over: channel, deadline: deadline)
            try await validate(session)
        }
        let complete = try budget.complete()
        guard complete.count <= channelMaximum else { throw ApprovalChannelError.invalidInput }
        try await validate(session)
        try await Self.send(complete, over: channel, deadline: deadline)
        try await validate(session)
    }
}

private struct PendingSnapshotWriteBudget {
    let nonce: Data
    let maximumFrames: UInt64
    let maximumBytes: UInt64
    private var frames: UInt64 = 0
    private var bytes: UInt64 = 0
    init(nonce: Data, maximumFrames: UInt64, maximumBytes: UInt64) {
        self.nonce = nonce; self.maximumFrames = maximumFrames; self.maximumBytes = maximumBytes
    }
    mutating func item(_ frame: Data, maximumPayloadBytes: Int) throws -> Data {
        guard frames < maximumFrames, UInt64(frame.count) <= maximumBytes - bytes else { throw ApprovalChannelError.invalidInput }
        let encoded = try PendingRequestSnapshotFrame.item(nonce: nonce, ordinal: frames, frame: frame).encode()
        guard encoded.count <= maximumPayloadBytes else { throw ApprovalChannelError.invalidInput }
        frames += 1; bytes += UInt64(frame.count)
        return encoded
    }
    func complete() throws -> Data { try PendingRequestSnapshotFrame.complete(nonce: nonce, frames: frames, bytes: bytes).encode() }
}
