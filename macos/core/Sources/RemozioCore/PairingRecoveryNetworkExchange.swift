import Foundation
import RemozioProtocol

/// Owns the bounded application exchange after the listener admits recovery TLS.
struct PairingRecoveryNetworkExchange {
    let channel: NetworkByteChannel
    private var buffered = Data()

    init(channel: NetworkByteChannel) {
        self.channel = channel
    }

    mutating func run(deadline: ContinuousClock.Instant,
                      begin: (PairingRecoveryQuery) async throws -> Data,
                      finish: (Data) async throws -> PairingRecoveryFrame) async throws {
        let channel = channel
        let timer = Task {
            do { try await ContinuousClock().sleep(until: deadline) }
            catch { return }
            channel.abort()
        }
        do {
            try await exchange(deadline: deadline, begin: begin, finish: finish)
        } catch {
            timer.cancel()
            await timer.value
            throw error
        }
        timer.cancel()
        await timer.value
    }

    private mutating func exchange(deadline: ContinuousClock.Instant,
                                   begin: (PairingRecoveryQuery) async throws -> Data,
                                   finish: (Data) async throws -> PairingRecoveryFrame) async throws {
        guard ContinuousClock.now < deadline, case let .lookup(query) = try await receive() else {
            throw PairingRecoveryFrameError.invalidFrame
        }
        let challenge = try await begin(query)
        try await send(.challenge(challenge), deadline: deadline)
        guard case let .proof(proof) = try await receive(), buffered.isEmpty else {
            throw PairingRecoveryFrameError.invalidFrame
        }
        let response = try await finish(proof)
        switch response {
        case .committed, .expired, .refused:
            try await send(response, deadline: deadline)
        default:
            throw PairingRecoveryFrameError.invalidFrame
        }
    }

    private mutating func receive() async throws -> PairingRecoveryFrame {
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

    private mutating func fill(to count: Int) async throws {
        while buffered.count < count {
            guard let bytes = try await channel.receive() else { throw NetworkChannelError.closed }
            buffered.append(bytes)
        }
    }

    private func send(_ frame: PairingRecoveryFrame, deadline: ContinuousClock.Instant) async throws {
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
