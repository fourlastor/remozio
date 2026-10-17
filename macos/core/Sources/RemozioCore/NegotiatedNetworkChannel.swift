import Foundation
import Security
import RemozioProtocol

/// Selected by the enrolled TLS handshake, not by an application payload.
public enum EnrolledChannelPurpose: Sendable {
    case approvals, pairingReceipt, pendingSnapshot, pushRegistration, pushRecovery
    var applicationProtocol: String {
        switch self {
        case .approvals: "remozio/1"
        case .pairingReceipt: PairingReceiptFrame.applicationProtocol
        case .pendingSnapshot: PendingRequestSnapshotFrame.applicationProtocol
        case .pushRegistration: PhonePushRegistrationFrame.applicationProtocol
        case .pushRecovery: PhonePushRecoveryFrame.applicationProtocol
        }
    }
    init?(applicationProtocol: String) {
        switch applicationProtocol {
        case "remozio/1": self = .approvals
        case PairingReceiptFrame.applicationProtocol: self = .pairingReceipt
        case PendingRequestSnapshotFrame.applicationProtocol: self = .pendingSnapshot
        case PhonePushRegistrationFrame.applicationProtocol: self = .pushRegistration
        case PhonePushRecoveryFrame.applicationProtocol: self = .pushRecovery
        default: return nil
        }
    }
}

public enum ApprovalChannelError: Error { case closed, invalidInput, timedOut, concurrentOperation }

protocol ApprovalByteStream: Sendable {
    func awaitOpen(timeoutMilliseconds: UInt64) async throws
    func send(_ bytes: Data) async throws
    func receive() async throws -> Data?
    func close() async
}
private struct NetworkApprovalStream: ApprovalByteStream {
    let channel: NetworkByteChannel
    var alreadyStarted = false
    func awaitOpen(timeoutMilliseconds: UInt64) async throws {
        if !alreadyStarted { try await channel.start(timeoutMilliseconds: timeoutMilliseconds) }
    }
    func send(_ bytes: Data) async throws { try await channel.send(bytes) }
    func receive() async throws -> Data? { try await channel.receive() }
    func close() async { await channel.close() }
}

/// Owns framing, negotiation, and sequences for one enrolled TLS connection. No action authority is granted.
public actor NegotiatedNetworkChannel {
    private enum State { case negotiating, open, closed }
    public nonisolated let purpose: EnrolledChannelPurpose
    private let stream: any ApprovalByteStream
    private let maximumPayloadBytes: Int
    private let cancellation = ChannelCancellation()
    private var state = State.negotiating
    private var metadata: NegotiatedChannel?
    private var pending = Data()
    private var offset = 0
    private var reading = false
    private var writing = false
    private var incoming: UInt64? = 0
    private var outgoing: UInt64? = 0

    private init(stream: any ApprovalByteStream, maximumPayloadBytes: Int, purpose: EnrolledChannelPurpose) {
        self.stream = stream; self.maximumPayloadBytes = maximumPayloadBytes; self.purpose = purpose
    }
    public func negotiated() throws -> NegotiatedChannel {
        try active(); guard state == .open, let metadata else { throw ApprovalChannelError.closed }; return metadata
    }
    /// Takes exclusive ownership, including on failure. The caller configures enrolled TLS pins and admission.
    public static func accept(channel: NetworkByteChannel, scope: ChannelScope, requests: [ChannelRequestCapability],
                              auditVersions: Set<UInt64>, maximumPayloadBytes: Int,
                              trustedMinimum: UInt64 = 1, timeoutMilliseconds: UInt64 = 15_000,
                              purpose: EnrolledChannelPurpose = .approvals) async throws -> NegotiatedNetworkChannel {
        try await accept(stream: NetworkApprovalStream(channel: channel), scope: scope, requests: requests, auditVersions: auditVersions,
            maximumPayloadBytes: maximumPayloadBytes, trustedMinimum: trustedMinimum, timeoutMilliseconds: timeoutMilliseconds, purpose: purpose)
    }
    // Used only after the listener verifies the native TLS session and selects its enrolled peer.
    static func acceptStarted(channel: NetworkByteChannel, scope: ChannelScope, requests: [ChannelRequestCapability],
                              auditVersions: Set<UInt64>, maximumPayloadBytes: Int,
                              trustedMinimum: UInt64, timeoutMilliseconds: UInt64,
                              purpose: EnrolledChannelPurpose = .approvals) async throws -> NegotiatedNetworkChannel {
        try await accept(stream: NetworkApprovalStream(channel: channel, alreadyStarted: true), scope: scope,
            requests: requests, auditVersions: auditVersions, maximumPayloadBytes: maximumPayloadBytes,
            trustedMinimum: trustedMinimum, timeoutMilliseconds: timeoutMilliseconds, purpose: purpose)
    }

    static func accept(stream: any ApprovalByteStream, scope: ChannelScope, requests: [ChannelRequestCapability],
                       auditVersions: Set<UInt64>, maximumPayloadBytes: Int,
                       trustedMinimum: UInt64 = 1, timeoutMilliseconds: UInt64 = 15_000,
                              purpose: EnrolledChannelPurpose = .approvals) async throws -> NegotiatedNetworkChannel {
        let owner = NegotiatedNetworkChannel(stream: stream, maximumPayloadBytes: maximumPayloadBytes, purpose: purpose)
        try await owner.negotiate(scope: scope, requests: requests, auditVersions: auditVersions,
            trustedMinimum: trustedMinimum, timeoutMilliseconds: timeoutMilliseconds)
        return owner
    }
    public func send(_ payload: Data) async throws {
        do {
            try active()
            guard state == .open, !writing, (1...maximumPayloadBytes).contains(payload.count),
                  let metadata, let sequence = outgoing else { throw ApprovalChannelError.invalidInput }
            writing = true; defer { writing = false }
            try await writeFrame(SessionEnvelope(sessionID: metadata.sessionID, sequence: sequence, payload: payload)
                .encode(maximumPayloadBytes: maximumPayloadBytes))
            outgoing = sequence == .max ? nil : sequence + 1
        } catch { await finish(); throw error }
    }
    public func receive(maximumBytes: Int? = nil) async throws -> Data? {
        do {
            try active()
            let maximum = maximumBytes ?? maximumPayloadBytes
            guard state == .open, !reading, let metadata, (1...maximumPayloadBytes).contains(maximum) else {
                throw ApprovalChannelError.invalidInput
            }
            reading = true; defer { reading = false }
            guard let frame = try await readFrame(maximum: maximum + 64) else { await finish(); return nil }
            let envelope = try SessionEnvelope.decode(frame, maximumPayloadBytes: maximum)
            guard envelope.sessionID == metadata.sessionID, envelope.sequence == incoming else { throw ApprovalChannelError.invalidInput }
            incoming = envelope.sequence == .max ? nil : envelope.sequence + 1
            try active(); return envelope.payload
        } catch { await finish(); throw error }
    }
    /// Invalidates the incarnation immediately, then closes pending native I/O.
    public nonisolated func close() { cancellation.cancel(); Task { await self.finish() } }
    public func closeAndWait() async { await finish() }

    private func negotiate(scope: ChannelScope, requests: [ChannelRequestCapability], auditVersions: Set<UInt64>,
                           trustedMinimum: UInt64, timeoutMilliseconds: UInt64) async throws {
        do {
            try active()
            guard (1...60_000).contains(timeoutMilliseconds), (1...16_777_216).contains(maximumPayloadBytes) else {
                throw ApprovalChannelError.invalidInput
            }
            let result = try await withThrowingTaskGroup(of: NegotiatedChannel.self) { group in
                group.addTask { try await self.performNegotiation(scope: scope, requests: requests, auditVersions: auditVersions,
                    trustedMinimum: trustedMinimum, timeoutMilliseconds: timeoutMilliseconds) }
                group.addTask {
                    try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds)))
                    throw ApprovalChannelError.timedOut
                }
                defer { group.cancelAll() }
                return try await group.next()!
            }
            try active(); metadata = result; state = .open
        } catch { await finish(); throw error }
    }
    private func performNegotiation(scope: ChannelScope, requests: [ChannelRequestCapability], auditVersions: Set<UInt64>,
                                    trustedMinimum: UInt64, timeoutMilliseconds: UInt64) async throws -> NegotiatedChannel {
        var nonce = Data(count: 32)
        let status = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { throw ApprovalChannelError.invalidInput }
        let owner = try ChannelNegotiation(local: ChannelOffer(role: .mac, scope: scope, nonce: nonce, envelopeVersions: [1],
            requests: requests, auditVersions: auditVersions), trustedMinimum: trustedMinimum)
        defer { owner.close() }
        try await stream.awaitOpen(timeoutMilliseconds: timeoutMilliseconds); try active()
        let offer = try owner.offer()
        guard let peer = try await readFrame(maximum: 65_536) else { throw ApprovalChannelError.closed }
        try owner.receiveOffer(peer); try await writeFrame(offer)
        guard let confirmation = try await readFrame(maximum: 128) else { throw ApprovalChannelError.closed }
        try owner.receiveConfirmation(confirmation); try await writeFrame(owner.confirmation())
        try active(); return try owner.confirmed()
    }
    private func writeFrame(_ bytes: Data) async throws {
        try active()
        let count = UInt32(bytes.count)
        try await stream.send(Data([UInt8(truncatingIfNeeded: count >> 24), UInt8(truncatingIfNeeded: count >> 16),
            UInt8(truncatingIfNeeded: count >> 8), UInt8(truncatingIfNeeded: count)])); try active()
        var position = 0
        while position < bytes.count {
            let end = min(position + 32_768, bytes.count)
            try await stream.send(Data(bytes[position..<end])); try active(); position = end
        }
    }
    private func readFrame(maximum: Int) async throws -> Data? {
        guard let header = try await exact(4, allowEOF: true) else { return nil }
        let length = header.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        guard (1...UInt64(maximum)).contains(length) else { throw ApprovalChannelError.invalidInput }
        return try await exact(Int(length), allowEOF: false)
    }
    private func exact(_ count: Int, allowEOF: Bool) async throws -> Data? {
        var result = Data(); result.reserveCapacity(count)
        while result.count < count {
            try active()
            if offset == pending.count {
                let next = try await stream.receive(); try active()
                guard let next else {
                    if allowEOF && result.isEmpty { return nil }
                    throw ApprovalChannelError.closed
                }
                guard (1...32_768).contains(next.count) else { throw ApprovalChannelError.invalidInput }
                pending = next; offset = 0
            }
            let take = min(count - result.count, pending.count - offset)
            let start = pending.index(pending.startIndex, offsetBy: offset)
            result.append(pending[start..<pending.index(start, offsetBy: take)]); offset += take
        }
        return result
    }
    private func active() throws {
        try Task.checkCancellation()
        guard state != .closed, cancellation.ifActive({}) else { throw ApprovalChannelError.closed }
    }
    private func finish() async {
        cancellation.cancel(); state = .closed; metadata = nil
        await stream.close()
    }
}
