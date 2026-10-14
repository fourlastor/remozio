import Darwin
import Foundation
import RemozioProtocol
import Security

protocol TransportPairingPeer: Sendable {
    var isClosed: Bool { get async }
    func proposal() async throws -> PairingPhoneProposal
    func stage(_ transcript: PairingTranscript) async throws
    func receiveProof() async throws -> Data
    func sendReceipt(_ signature: Data) async throws
    func abort()
    func close() async
}
extension PairingSetupNetworkSession: TransportPairingPeer {}
protocol TransportPairingIngress: Sendable {
    func start() throws
    func close()
    func closeAndWait() async
}
private final class NativePairingIngress: TransportPairingIngress, @unchecked Sendable {
    let listener: PairingSetupListener
    init(identity: SecIdentity, invitation: PairingInvitation, configuration: TransportPairingControlConfiguration,
         event: @escaping @Sendable (DirectListenerEvent) -> Void,
         handler: @escaping @Sendable (any TransportPairingPeer) async throws -> Void) throws {
        listener = try .init(identity: identity, invitation: invitation, maximumConnections: configuration.maximumCandidates,
            handshakeTimeoutMilliseconds: configuration.timeoutMilliseconds,
            setupTimeoutMilliseconds: configuration.setupTimeoutMilliseconds, event: event, handler: { try await handler($0) })
    }
    func start() throws { try listener.start() }
    func close() { listener.close() }
    func closeAndWait() async { await listener.closeAndWait() }
}
private final class PairingIdentityHolder: @unchecked Sendable {
    let identity: SecIdentity
    init(_ identity: SecIdentity) { self.identity = identity }
}
private final class PairingControlLifetime: @unchecked Sendable {
    private let lock = NSLock()
    private var closed = false
    private var aborts: [UUID: @Sendable () -> Void] = [:]
    var active: Bool { lock.withLock { !closed } }
    func register(_ id: UUID, abort: @escaping @Sendable () -> Void) -> Bool {
        lock.withLock { guard !closed else { return false }; aborts[id] = abort; return true }
    }
    func remove(_ id: UUID) { lock.withLock { aborts[id] = nil } }
    func close() {
        let actions = lock.withLock { () -> [@Sendable () -> Void] in
            guard !closed else { return [] }; closed = true
            let values = Array(aborts.values); aborts.removeAll(); return values
        }
        for action in actions { action() }
    }
}

/// One signed app connection owns one temporary setup listener. No method can stage or commit Root enrollment.
public actor TransportPairingSetupOwner {
    typealias Factory = @Sendable (PairingInvitation, @escaping @Sendable (DirectListenerEvent) -> Void,
        @escaping @Sendable (any TransportPairingPeer) async throws -> Void) throws -> any TransportPairingIngress
    private final class Entry {
        let id: UUID
        let peer: any TransportPairingPeer
        let proposal: PairingPhoneProposal
        var phase = TransportPairingPhase.proposed
        var proof: Data?
        init(id: UUID, peer: any TransportPairingPeer, proposal: PairingPhoneProposal) {
            self.id = id; self.peer = peer; self.proposal = proposal
        }
        var bytes: Data { var value = id.uuid; return withUnsafeBytes(of: &value) { Data($0) } }
    }
    private let configuration: TransportPairingControlConfiguration
    private let factory: Factory
    private let verifyAccount: @Sendable () throws -> Void
    private let lifetime = PairingControlLifetime()
    private var invitation: PairingInvitation?
    private var ingress: (any TransportPairingIngress)?
    private var port: UInt16?
    private var opening: CheckedContinuation<UInt16, any Error>?
    private var openingTimer: Task<Void, Never>?
    private var entries: [UUID: Entry] = [:]
    private var readers: [UUID: Task<Void, Never>] = [:]
    private var drainTask: Task<Void, Never>?
    private var started = false
    private var closed = false
    public init(configuration: TransportPairingControlConfiguration, identity: SecIdentity) throws {
        try DedicatedServiceAccount.requireCurrent(serviceUID: configuration.transportUID, ownerUID: configuration.ownerUID)
        self.configuration = configuration
        let holder = PairingIdentityHolder(identity), processID = getpid(), uid = configuration.transportUID
        factory = { invitation, event, handler in
            try NativePairingIngress(identity: holder.identity, invitation: invitation, configuration: configuration, event: event, handler: handler)
        }
        verifyAccount = {
            guard getpid() == processID, getuid() == uid, geteuid() == uid else { throw TransportPairingControlError.wrongAccount }
        }
    }
    // Logical ingress controls cannot prove native code signing, role accounts or TLS identity.
    init(configuration: TransportPairingControlConfiguration, factory: @escaping Factory,
         verifyAccount: @escaping @Sendable () throws -> Void = {}) {
        self.configuration = configuration; self.factory = factory; self.verifyAccount = verifyAccount
    }
    deinit { openingTimer?.cancel(); lifetime.close() }
    public func begin(_ invitation: PairingInvitation) async throws -> UInt16 {
        try active()
        guard !started, invitation.macID == configuration.macID, invitation.accountID == configuration.accountID,
              invitation.minimumEnvelopeVersion == 1 else { throw TransportPairingControlError.invalidMessage }
        started = true; self.invitation = invitation
        do {
            let listener = try factory(invitation, { [weak self] event in Task { await self?.changed(event) } },
                { [weak self] peer in guard let self else { peer.abort(); return }; try await self.accept(peer) })
            ingress = listener
            guard lifetime.register(UUID(), abort: { listener.close() }) else { throw TransportPairingControlError.closed }
            let value = try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    opening = continuation
                    openingTimer = Task { [weak self, configuration] in
                        do { try await Task.sleep(for: .milliseconds(Int64(configuration.timeoutMilliseconds))) } catch { return }
                        await self?.openingExpired()
                    }
                    do { try listener.start() } catch { settleOpening(.failure(error)) }
                }
            } onCancel: { self.abort() }
            try active(); return value
        } catch { await closeAndWait(); throw error }
    }
    public func snapshot() throws -> TransportPairingSnapshot {
        try active(); guard let port else { throw TransportPairingControlError.closed }
        return try .init(port: port, candidates: entries.values.sorted { $0.bytes.lexicographicallyPrecedes($1.bytes) }.map {
            try .init(id: $0.bytes, proposal: $0.proposal, phase: $0.phase, biometricProof: $0.proof)
        })
    }
    public func stage(candidateID: Data, transcript: PairingTranscript) async throws {
        let entry = try current(candidateID)
        guard entry.phase == .proposed, let invitation else { throw TransportPairingControlError.busy }
        try entry.proposal.validate(transcript); try invitation.validateMacClaims(in: transcript)
        entry.phase = .sendingTranscript
        do {
            try await entry.peer.stage(transcript); try active(); try retained(entry)
            entry.phase = .awaitingProof
            let id = entry.id
            let reader = Task { [weak self, peer = entry.peer] in
                do { let proof = try await peer.receiveProof(); await self?.received(id, proof: proof) }
                catch { await self?.finish(id) }
            }
            readers[id] = reader
            Task { [weak self] in await reader.value; await self?.readerEnded(id) }
        } catch { await finish(entry.id); throw error }
    }
    /// The app supplies only a receipt from its existing durable Root commit. This write is never repeated.
    public func deliverReceipt(candidateID: Data, signature: Data) async throws {
        let entry = try current(candidateID)
        guard entry.phase == .proofReady, signature.count == 64 else { throw TransportPairingControlError.invalidMessage }
        entry.phase = .sendingReceipt
        do {
            try await entry.peer.sendReceipt(signature); try active(); try retained(entry)
            entry.phase = .receiptSent
        } catch { await finish(entry.id); throw error }
    }
    public func cancel(candidateID: Data) async throws { let entry = try current(candidateID); await finish(entry.id) }
    public nonisolated func abort() { lifetime.close(); Task { await self.closeAndWait() } }
    /// Stop native I/O first, then await the actual proof readers and listener handlers.
    public func closeAndWait() async {
        if let drainTask { await drainTask.value; return }
        lifetime.close(); closed = true; settleOpening(.failure(TransportPairingControlError.closed))
        let listener = ingress; ingress = nil; listener?.close()
        let task = Task { await self.drain(listener) }
        drainTask = task
        await task.value
    }
    private func drain(_ listener: (any TransportPairingIngress)?) async {
        for id in Array(entries.keys) { await finish(id) }
        let tasks = Array(readers.values)
        for task in tasks { task.cancel(); await task.value }
        await listener?.closeAndWait()
        readers.removeAll(); invitation = nil; port = nil
    }
    private func active() throws {
        try verifyAccount(); try Task.checkCancellation()
        guard !closed, lifetime.active else { throw TransportPairingControlError.closed }
    }
    private func current(_ bytes: Data) throws -> Entry {
        try active(); guard bytes.count == 16, let entry = entries.values.first(where: { $0.bytes == bytes }) else {
            throw TransportPairingControlError.invalidMessage
        }; return entry
    }
    private func retained(_ entry: Entry) throws {
        guard entries[entry.id] === entry else { throw TransportPairingControlError.closed }
    }
    private func changed(_ event: DirectListenerEvent) {
        guard !closed, lifetime.active else { return }
        switch event {
        case .ready(let value): port = value; settleOpening(.success(value))
        case .failed, .stopped: abort()
        }
    }
    private func settleOpening(_ result: Result<UInt16, any Error>) {
        let previous = opening; opening = nil; openingTimer?.cancel(); openingTimer = nil; previous?.resume(with: result)
    }
    private func openingExpired() { settleOpening(.failure(TransportPairingControlError.timedOut)); abort() }
    private func accept(_ peer: any TransportPairingPeer) async throws {
        let id = UUID()
        do {
            try active(); guard entries.count < configuration.maximumCandidates, let invitation else {
                throw TransportPairingControlError.busy
            }
            let proposal = try await peer.proposal(); try active()
            guard entries.count < configuration.maximumCandidates,
                  proposal.phone.scope.macID == invitation.macID, proposal.phone.scope.accountID == invitation.accountID else {
                throw TransportPairingControlError.invalidMessage
            }
            guard lifetime.register(id, abort: { peer.abort() }) else { throw TransportPairingControlError.closed }
            entries[id] = Entry(id: id, peer: peer, proposal: proposal)
            while let entry = entries[id], entry.phase != .receiptSent, !(await peer.isClosed) {
                try active(); try await Task.sleep(for: .milliseconds(100))
            }
        } catch { await finish(id); peer.abort(); await peer.close(); throw error }
        await finish(id)
    }
    private func received(_ id: UUID, proof: Data) async {
        guard lifetime.active, let entry = entries[id], entry.phase == .awaitingProof, proof.count == 64 else {
            await finish(id); return
        }
        entry.proof = proof; entry.phase = .proofReady
    }
    private func readerEnded(_ id: UUID) { readers[id] = nil }
    private func finish(_ id: UUID) async {
        guard let entry = entries.removeValue(forKey: id) else { return }
        lifetime.remove(id); entry.peer.abort(); readers[id]?.cancel()
        await entry.peer.close()
    }
}
