import Foundation
import RemozioProtocol

/// Owns the bounded application exchange after the listener admits recovery TLS.
actor PairingRecoveryNetworkExchange {
    private enum State { case new, readingLookup, sendingChallenge, readingProof, replying, closed }
    private let channel: NetworkByteChannel
    private let deadline: ContinuousClock.Instant
    private var buffered = Data()
    private var state = State.new

    init(channel: NetworkByteChannel, deadline: ContinuousClock.Instant) {
        self.channel = channel
        self.deadline = deadline
    }

    func run(lookup: @escaping @Sendable (PairingRecoveryQuery, PairingRecoveryNetworkExchange) async throws -> PairingRecoveryFrame,
             verifyReply: @escaping @Sendable () async throws -> Void = {}) async throws {
        guard state == .new else { throw NetworkChannelError.invalidState }
        state = .readingLookup
        defer { state = .closed }
        let deadline = deadline, channel = channel
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { try await self.exchange(lookup: lookup, verifyReply: verifyReply) }
            group.addTask {
                try await ContinuousClock().sleep(until: deadline)
                channel.abort()
                throw NetworkChannelError.timedOut
            }
            defer { group.cancelAll() }
            _ = try await group.next()
        }
    }

    /// Come here only after reading a valid first frame. Idle TLS peers do not get a Root connection.
    private func exchange(
        lookup: @Sendable (PairingRecoveryQuery, PairingRecoveryNetworkExchange) async throws -> PairingRecoveryFrame,
        verifyReply: @Sendable () async throws -> Void
    ) async throws {
        guard ContinuousClock.now < deadline, case let .lookup(query) = try await receive(), buffered.isEmpty else {
            throw PairingRecoveryFrameError.invalidFrame
        }
        state = .sendingChallenge
        let response = try await lookup(query, self)
        guard state == .replying else { throw PairingRecoveryFrameError.invalidFrame }
        switch response {
        case .committed, .expired, .refused:
            try await verifyReply()
            try await send(response)
        default:
            throw PairingRecoveryFrameError.invalidFrame
        }
    }

    func receiveProof(challenge: Data) async throws -> Data {
        guard state == .sendingChallenge else { throw NetworkChannelError.invalidState }
        state = .readingProof
        try await send(.challenge(challenge))
        guard case let .proof(proof) = try await receive(), buffered.isEmpty else {
            throw PairingRecoveryFrameError.invalidFrame
        }
        state = .replying
        return proof
    }

    private func receive() async throws -> PairingRecoveryFrame {
        try await fill(to: 4)
        let count = buffered.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard (1...PairingRecoveryFrame.maximumBytes).contains(count) else {
            throw PairingRecoveryFrameError.invalidFrame
        }
        try await fill(to: 4 + count)
        let body = Data(buffered.dropFirst(4).prefix(count))
        buffered = Data(buffered.dropFirst(4 + count))
        return try PairingRecoveryFrame.decode(body)
    }

    private func fill(to count: Int) async throws {
        while buffered.count < count {
            guard let bytes = try await channel.receive() else { throw NetworkChannelError.closed }
            buffered.append(bytes)
        }
    }

    private func send(_ frame: PairingRecoveryFrame) async throws {
        try Task.checkCancellation()
        guard ContinuousClock.now < deadline else { throw NetworkChannelError.timedOut }
        let payload = try frame.encode()
        let length = UInt32(payload.count)
        var packet = Data([UInt8(length >> 24), UInt8(truncatingIfNeeded: length >> 16),
                           UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)])
        packet.append(payload)
        try await channel.send(packet)
    }
}
