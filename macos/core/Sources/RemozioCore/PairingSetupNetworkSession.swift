import Foundation
import RemozioProtocol

public enum PairingSetupChannelError: Error { case rejected, closed, busy }

private struct PairingNetworkStream: ApprovalByteStream {
    let channel: NetworkByteChannel
    func awaitOpen(timeoutMilliseconds: UInt64) async throws {}
    func send(_ bytes: Data) async throws { try await channel.send(bytes) }
    func receive() async throws -> Data? { try await channel.receive() }
    func close() async { await channel.close() }
}

/// One unpaired TLS candidate. The signed app must independently confirm and authorize Root staging and commit.
/// No setup message can enter the enrolled request exchange through this owner.
public actor PairingSetupNetworkSession {
    private enum State { case opening, proposed, staged, proofReceived, finished, closed }
    private let stream: any ApprovalByteStream
    private let invitation: PairingInvitation
    private let peerPoint: Data
    private let abortIO: @Sendable () -> Void
    private let underlyingClosed: @Sendable () async -> Bool
    private let cancellation = ChannelCancellation()
    private var state = State.opening
    private var proposalValue: PairingPhoneProposal?
    private var staged: PairingTranscript?
    private var pending = Data()
    private var offset = 0
    private var busy = false
    private var timer: Task<Void, Never>?
    private var reader: Task<Void, Never>?
    private var inputWaiter: CheckedContinuation<Void, any Error>?
    private init(stream: any ApprovalByteStream, invitation: PairingInvitation, peerPoint: Data,
                 abortIO: @escaping @Sendable () -> Void, underlyingClosed: @escaping @Sendable () async -> Bool) {
        self.stream = stream; self.invitation = invitation; self.peerPoint = peerPoint
        self.abortIO = abortIO; self.underlyingClosed = underlyingClosed
    }
    deinit { timer?.cancel(); reader?.cancel() }
    static func acceptStarted(channel: NetworkByteChannel, invitation: PairingInvitation, peerPoint: Data,
                              timeoutMilliseconds: UInt64) async throws -> Self {
        try await accept(stream: PairingNetworkStream(channel: channel), invitation: invitation, peerPoint: peerPoint,
            timeoutMilliseconds: timeoutMilliseconds, abortIO: { channel.abort() }, underlyingClosed: { await channel.isClosed })
    }
    // Injected streams prove state and framing only, never native peer identity.
    static func accept(stream: any ApprovalByteStream, invitation: PairingInvitation, peerPoint: Data,
                       timeoutMilliseconds: UInt64 = 300_000, abortIO: @escaping @Sendable () -> Void = {},
                       underlyingClosed: @escaping @Sendable () async -> Bool = { false }) async throws -> Self {
        let owner = Self(stream: stream, invitation: invitation, peerPoint: peerPoint, abortIO: abortIO, underlyingClosed: underlyingClosed)
        do { try await owner.open(timeoutMilliseconds: timeoutMilliseconds); return owner }
        catch { await owner.closeAndWait(); throw error }
    }
    private func open(timeoutMilliseconds: UInt64) async throws {
        guard (1...300_000).contains(timeoutMilliseconds), peerPoint.count == 65 else { throw PairingSetupChannelError.rejected }
        timer = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(Int64(timeoutMilliseconds))) } catch { return }
            self?.abort()
        }
        try await stream.awaitOpen(timeoutMilliseconds: min(timeoutMilliseconds, 60_000))
        startReader()
        try await write(.hello)
        guard case .proposal(let value) = try await read(), value.transportKey.publicKey == peerPoint,
              value.phone.scope.macID == invitation.macID, value.phone.scope.accountID == invitation.accountID else {
            throw PairingSetupChannelError.rejected
        }
        proposalValue = value; state = .proposed
    }
    /// Reports owner closure only. It grants no enrollment or action authority.
    public var isClosed: Bool {
        get async {
            if state == .closed || !cancellation.ifActive({}) { return true }
            return await underlyingClosed()
        }
    }
    public func proposal() throws -> PairingPhoneProposal {
        try active(); guard let proposalValue else { throw PairingSetupChannelError.closed }; return proposalValue
    }
    /// Call with the actual Root-returned transcript after local administrator authorization and app checks.
    public func stage(_ transcript: PairingTranscript) async throws {
        try active(); guard !busy, state == .proposed, let proposalValue else { throw PairingSetupChannelError.busy }
        busy = true; defer { busy = false }
        do {
            try proposalValue.validate(transcript); try invitation.validateMacClaims(in: transcript)
            guard transcript.expiresAtUnixMillis - transcript.issuedAtUnixMillis <= 300_000 else { throw PairingSetupChannelError.rejected }
            staged = transcript; state = .staged
            try await write(.transcript(transcript))
        } catch { await close(); throw error }
    }
    /// Verifies mathematical possession only. Root still checks the biometric proof, consent, current policy and elapsed deadline.
    public func receiveProof() async throws -> Data {
        try active(); guard !busy, state == .staged, let staged else { throw PairingSetupChannelError.busy }
        busy = true; defer { busy = false }
        do {
            guard case .proof(let id, let digest, let signature) = try await read(), id == staged.setupID,
                  try digest == staged.digest(), try staged.verify(signature: signature,
                    publicKey: staged.biometricKey.publicKey, purpose: .phoneBiometric) else { throw PairingSetupChannelError.rejected }
            try active(); state = .proofReceived; return signature
        } catch { await close(); throw error }
    }
    /// Call once with a receipt from the existing durable Root commit. A failed send is ambiguous and must not retry the commit.
    public func sendReceipt(_ signature: Data) async throws {
        try active(); guard !busy, state == .proofReceived, let staged else { throw PairingSetupChannelError.busy }
        busy = true; defer { busy = false }
        do {
            guard try staged.verify(signature: signature, publicKey: invitation.authorityPublicKey, purpose: .macCommit) else {
                throw PairingSetupChannelError.rejected
            }
            state = .finished
            try await write(.receipt(setupID: staged.setupID, digest: staged.digest(), signature: signature))
            timer?.cancel(); timer = nil
        } catch { await close(); throw error }
    }
    public nonisolated func abort() { cancellation.cancel(); abortIO(); Task { await self.close() } }
    public func close() async {
        cancellation.cancel(); abortIO()
        guard state != .closed else { return }
        state = .closed; timer?.cancel(); timer = nil; reader?.cancel()
        let waiter = inputWaiter; inputWaiter = nil
        waiter?.resume(throwing: PairingSetupChannelError.closed)
        pending.removeAll(); offset = 0; proposalValue = nil; staged = nil
        await stream.close()
    }
    /// Close I/O and join the owned byte reader before reporting quiescence.
    public func closeAndWait() async {
        await close()
        await reader?.value
    }
    private func startReader() {
        let stream = stream
        reader = Task { [weak self] in
            do {
                while !Task.isCancelled {
                    guard let bytes = try await stream.receive(), !bytes.isEmpty else { break }
                    guard let self, await self.appendInput(bytes) else { break }
                }
            } catch {}
            await self?.close()
        }
    }
    private func appendInput(_ bytes: Data) -> Bool {
        guard state != .closed, cancellation.ifActive({}), bytes.count <= NetworkByteChannel.maximumChunkBytes else { return false }
        if offset > 0 { pending = pending.subdata(in: offset..<pending.count); offset = 0 }
        guard bytes.count <= PairingSetupFrame.maximumBytes + 4 + NetworkByteChannel.maximumChunkBytes - pending.count else { return false }
        pending.append(bytes)
        let waiter = inputWaiter; inputWaiter = nil; waiter?.resume()
        return true
    }
    private func active() throws {
        try Task.checkCancellation()
        guard state != .closed, cancellation.ifActive({}) else { throw PairingSetupChannelError.closed }
    }
    private func write(_ frame: PairingSetupFrame) async throws {
        try active(); let bytes = try frame.encode()
        let size = UInt32(bytes.count)
        var output = Data([UInt8(size >> 24), UInt8((size >> 16) & 255), UInt8((size >> 8) & 255), UInt8(size & 255)])
        output.append(bytes)
        for start in stride(from: 0, to: output.count, by: NetworkByteChannel.maximumChunkBytes) {
            try active(); try await stream.send(output.subdata(in: start..<min(start + NetworkByteChannel.maximumChunkBytes, output.count)))
            try active()
        }
    }
    private func read() async throws -> PairingSetupFrame {
        var length: Int?
        while true {
            try active()
            let available = pending.count - offset
            if length == nil, available >= 4 {
                let value = pending[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                guard value > 0, value <= PairingSetupFrame.maximumBytes else { throw PairingSetupChannelError.rejected }
                length = Int(value)
            }
            if let length, available >= length + 4 {
                let result = try PairingSetupFrame.decode(pending.subdata(in: offset + 4..<offset + 4 + length))
                try active(); offset += length + 4
                if offset == pending.count { pending.removeAll(keepingCapacity: true); offset = 0 }
                return result
            }
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (waiter: CheckedContinuation<Void, any Error>) in
                    inputWaiter = waiter
                }
            } onCancel: { self.abort() }
        }
    }
}
