import Darwin
import Foundation
import RemozioProtocol

// The driver represents only this local control connection, not a Root authorization channel.
enum TransportPairingCall: Sendable { case hello, begin(Data), snapshot, stage(Data, Data), receipt(Data, Data), cancel(Data), stop }
enum TransportPairingReply: Sendable { case number(UInt64), bytes(Data?), flag(Bool), failed }
protocol TransportPairingDriver: Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: TransportPairingCall, reply: @escaping @Sendable (TransportPairingReply) -> Void)
    func close()
}
final class NativeTransportPairingDriver: TransportPairingDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(configuration: TransportPairingControlConfiguration) {
        connection = NSXPCConnection(machServiceName: configuration.serviceName, options: .privileged)
        policy = configuration.transportPolicy
        connection.remoteObjectInterface = NSXPCInterface(with: TransportPairingXPCProtocol.self); policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: TransportPairingCall, reply: @escaping @Sendable (TransportPairingReply) -> Void) {
        if case .hello = call {} else {
            do { _ = try policy.verifyCredentials(connection) } catch { reply(.failed); return }
        }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any TransportPairingXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .hello: proxy.setupHello { [self] in checked(.number($0), reply) }
        case .begin(let invitation): proxy.beginSetup(invitation) { [self] in checked(.number($0), reply) }
        case .snapshot: proxy.setupCandidates { [self] in checked(.bytes($0), reply) }
        case .stage(let id, let transcript): proxy.stageSetup(id, transcript: transcript) { [self] in checked(.flag($0), reply) }
        case .receipt(let id, let signature): proxy.deliverSetupReceipt(id, signature: signature) { [self] in checked(.flag($0), reply) }
        case .cancel(let id): proxy.cancelSetupCandidate(id) { [self] in checked(.flag($0), reply) }
        case .stop: proxy.stopSetup { [self] in checked(.flag($0), reply) }
        }
    }
    private func checked(_ value: TransportPairingReply, _ reply: @Sendable (TransportPairingReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(value) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}
private final class TransportPairingClientLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    func close() { lock.withLock { closed = true } }
    func ifOpen(_ work: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; work(); return true } }
}

/// The app authenticates Root independently. This channel only transfers its verified setup transcript and receipt.
public actor TransportPairingChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any TransportPairingDriver
    private let configuration: TransportPairingControlConfiguration
    private let verifyAccount: @Sendable () throws -> Void
    private let lifetime = TransportPairingClientLifetime()
    private var state = State.new
    private var invitation: PairingInvitation?
    private var port: UInt16?
    private var candidates: [Data: TransportPairingCandidate] = [:]
    private var staged: [Data: PairingTranscript] = [:]
    private var submittedReceipts: Set<Data> = []
    private var pending: (id: UUID, continuation: CheckedContinuation<TransportPairingReply, any Error>)?
    private var timer: Task<Void, Never>?
    public init(configuration: TransportPairingControlConfiguration) throws {
        guard getuid() == configuration.ownerUID, geteuid() == configuration.ownerUID else { throw TransportPairingControlError.wrongAccount }
        let pid = getpid(), uid = configuration.ownerUID
        self.configuration = configuration; driver = NativeTransportPairingDriver(configuration: configuration)
        verifyAccount = { guard getpid() == pid, getuid() == uid, geteuid() == uid else { throw TransportPairingControlError.wrongAccount } }
    }
    // An injected driver cannot prove the native transport role, code signing or protected metadata.
    init(configuration: TransportPairingControlConfiguration, driver: any TransportPairingDriver,
         verifyAccount: @escaping @Sendable () throws -> Void = {}) {
        self.configuration = configuration; self.driver = driver; self.verifyAccount = verifyAccount
    }
    deinit { timer?.cancel(); driver.close() }
    public func start(invitation: PairingInvitation) async throws -> UInt16 {
        guard state == .new, invitation.macID == configuration.macID, invitation.accountID == configuration.accountID,
              invitation.minimumEnvelopeVersion == 1 else { throw TransportPairingControlError.invalidMessage }
        state = .opening
        do {
            guard case .number(1) = try await perform(.hello) else { throw TransportPairingControlError.unsupportedVersion }
            guard case .number(let value) = try await perform(.begin(invitation.encode())), let port = UInt16(exactly: value), port > 0 else {
                throw TransportPairingControlError.invalidMessage
            }
            self.invitation = invitation; self.port = port; state = .open; return port
        } catch { close(); throw error }
    }
    public func current() async throws -> TransportPairingSnapshot {
        guard pending == nil else { throw TransportPairingControlError.busy }
        do {
            guard case .bytes(let bytes) = try await perform(.snapshot), let bytes, bytes.count <= TransportPairingSnapshot.maximumBytes,
                  let invitation, let port else { throw TransportPairingControlError.invalidMessage }
            let snapshot = try TransportPairingSnapshot.decode(bytes)
            guard snapshot.port == port, snapshot.candidates.count <= configuration.maximumCandidates else { throw TransportPairingControlError.invalidMessage }
            var next: [Data: TransportPairingCandidate] = [:]
            for candidate in snapshot.candidates {
                let proposal = candidate.proposal
                guard proposal.phone.scope.macID == invitation.macID, proposal.phone.scope.accountID == invitation.accountID,
                      [proposal.transportKey, proposal.decisionKey, proposal.biometricKey].allSatisfy({
                          $0.publicKey != invitation.authorityPublicKey && $0.publicKey != invitation.transportPublicKey
                      }) else { throw TransportPairingControlError.invalidMessage }
                if let old = candidates[candidate.id] {
                    guard try old.proposal.encode() == proposal.encode(), candidate.phase.rawValue >= old.phase.rawValue else {
                        throw TransportPairingControlError.invalidMessage
                    }
                }
                if candidate.phase != .proposed {
                    guard let transcript = staged[candidate.id] else { throw TransportPairingControlError.invalidMessage }
                    try proposal.validate(transcript)
                    if let proof = candidate.biometricProof {
                        guard try transcript.verify(signature: proof, publicKey: transcript.biometricKey.publicKey, purpose: .phoneBiometric) else {
                            throw TransportPairingControlError.invalidMessage
                        }
                    }
                }
                next[candidate.id] = candidate
            }
            candidates = next; staged = staged.filter { next[$0.key] != nil }; submittedReceipts.formIntersection(Set(next.keys))
            return snapshot
        } catch { close(); throw error }
    }
    /// Pass the actual transcript from the app's authenticated Root staging call, after local administrator authorization.
    public func stage(candidateID: Data, transcript: PairingTranscript) async throws {
        guard let candidate = candidates[candidateID], candidate.phase == .proposed, let invitation,
              staged[candidateID] == nil, pending == nil else { throw TransportPairingControlError.busy }
        try candidate.proposal.validate(transcript); try invitation.validateMacClaims(in: transcript)
        staged[candidateID] = transcript
        do { try await flag(.stage(candidateID, transcript.encode())) }
        catch { close(); throw error }
    }
    /// A failed or lost reply is ambiguous. This incarnation cannot repeat the receipt submission or Root commit.
    public func deliverReceipt(candidateID: Data, signature: Data) async throws {
        guard let transcript = staged[candidateID], let candidate = candidates[candidateID], candidate.phase == .proofReady,
              !submittedReceipts.contains(candidateID), pending == nil else { throw TransportPairingControlError.busy }
        guard try transcript.verify(signature: signature, publicKey: transcript.macAuthorityKey, purpose: .macCommit) else {
            throw TransportPairingControlError.invalidMessage
        }
        submittedReceipts.insert(candidateID)
        do { try await flag(.receipt(candidateID, signature)) } catch { close(); throw error }
    }
    public func cancel(candidateID: Data) async throws {
        guard candidates[candidateID] != nil, pending == nil else { throw TransportPairingControlError.invalidMessage }
        do { try await flag(.cancel(candidateID)); candidates[candidateID] = nil; staged[candidateID] = nil; submittedReceipts.remove(candidateID) }
        catch { close(); throw error }
    }
    public func stop() async throws { do { try await flag(.stop); close() } catch { close(); throw error } }
    public nonisolated func abort() { lifetime.close(); driver.close(); Task { await self.close() } }
    public func close() {
        guard state != .closed else { return }; state = .closed; lifetime.close(); driver.close(); timer?.cancel(); timer = nil
        let previous = pending; pending = nil; invitation = nil; port = nil; candidates.removeAll(); staged.removeAll(); submittedReceipts.removeAll()
        previous?.continuation.resume(throwing: TransportPairingControlError.closed)
    }
    private func flag(_ call: TransportPairingCall) async throws {
        guard case .flag(true) = try await perform(call) else { throw TransportPairingControlError.invalidMessage }
    }
    private func perform(_ call: TransportPairingCall) async throws -> TransportPairingReply {
        do { try verifyAccount(); try Task.checkCancellation() } catch { close(); throw error }
        guard lifetime.ifOpen({}) else { close(); throw TransportPairingControlError.closed }
        switch call {
        case .hello, .begin: guard state == .opening else { throw TransportPairingControlError.closed }
        default: guard state == .open else { throw TransportPairingControlError.closed }
        }
        guard pending == nil else { throw TransportPairingControlError.busy }
        let id = UUID(), driver = driver, lifetime = lifetime
        let value = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, configuration] in
                    do { try await Task.sleep(for: .milliseconds(Int64(configuration.timeoutMilliseconds))) } catch { return }
                    await self?.expired(id)
                }
                if case .hello = call { driver.start { [weak self] in lifetime.close(); Task { await self?.close() } } }
                guard lifetime.ifOpen({
                    driver.invoke(call) { [weak self] value in Task { await self?.completed(id, value) } }
                }) else { close(); return }
            }
        } onCancel: { [weak self] in lifetime.close(); driver.close(); Task { await self?.close() } }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw TransportPairingControlError.closed }; return value
    }
    private func completed(_ id: UUID, _ value: TransportPairingReply) {
        guard let previous = pending, previous.id == id else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        if case .failed = value { close(); return }
        pending = nil; timer?.cancel(); timer = nil; previous.continuation.resume(returning: value)
    }
    private func expired(_ id: UUID) {
        guard let previous = pending, previous.id == id else { return }
        pending = nil; close(); previous.continuation.resume(throwing: TransportPairingControlError.timedOut)
    }
}
