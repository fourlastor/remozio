import CryptoKit
import Darwin
import Foundation
import RemozioProtocol
import Security

public enum AuthorityPairingChannelError: Error, Equatable {
    case wrongAccount, closed, busy, unsupportedVersion, invalidMessage, timedOut
}

/// Public parameters from the authenticated Root endpoint. They grant no enrollment or command authority.
public struct AuthorityPairingContext: Sendable, CustomStringConvertible {
    public let macID: Data
    public let accountID: Data
    public let authorityPublicKey: Data
    public let transportPublicKey: Data
    public let minimumEnvelopeVersion: UInt64
    public let lifetimeMilliseconds: UInt64
    public var description: String { "AuthorityPairingContext(redacted)" }
    /// Export only the pins obtained after the authenticated local Root handshake. This creates no setup attempt.
    public func invitation(label: String) throws -> PairingInvitation {
        try PairingInvitation(macID: macID, accountID: accountID, label: label,
            authorityPublicKey: authorityPublicKey, transportPublicKey: transportPublicKey,
            minimumEnvelopeVersion: minimumEnvelopeVersion)
    }
    static func decode(_ bytes: Data, macID: Data, accountID: Data) throws -> Self {
        let limits = try CBORLimits(maxBytes: 512, maxDepth: 1, maxItems: 15)
        guard case .map(let fields) = try DeterministicCBOR.decode(bytes, limits: limits), Set(fields.keys) == Set(UInt64(0)...6),
              fields[0] == .unsigned(1), fields[1] == .bytes(macID), fields[2] == .bytes(accountID),
              case .bytes(let authority) = fields[3], case .bytes(let transport) = fields[4],
              case .unsigned(let minimum) = fields[5], minimum == 1,
              case .unsigned(let lifetime) = fields[6], (1...300_000).contains(lifetime),
              authority.count == 65, transport.count == 65, authority != transport,
              (try? P256.Signing.PublicKey(x963Representation: authority)) != nil,
              (try? P256.Signing.PublicKey(x963Representation: transport)) != nil,
              try DeterministicCBOR.encode(.map(fields), limits: limits) == bytes else { throw AuthorityPairingChannelError.invalidMessage }
        return Self(macID: macID, accountID: accountID, authorityPublicKey: authority, transportPublicKey: transport,
            minimumEnvelopeVersion: minimum, lifetimeMilliseconds: lifetime)
    }
}

enum PairingClientCall: Sendable { case hello, context, stage(Data, Data), commit(Data, Data, Data, Data), cancel }
enum PairingClientReply: Sendable { case version(UInt64), bytes(Data?), cancelled(Bool), failed }
protocol PairingClientDriver: Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: PairingClientCall, reply: @escaping @Sendable (PairingClientReply) -> Void)
    func close()
}
private final class NativePairingClientDriver: PairingClientDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(configuration: AuthorityPresenceClientConfiguration) {
        policy = configuration.rootPolicy
        connection = NSXPCConnection(machServiceName: configuration.serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: AuthorityPairingXPCProtocol.self)
        policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: PairingClientCall, reply: @escaping @Sendable (PairingClientReply) -> Void) {
        if case .hello = call {} else {
            do { _ = try policy.verifyCredentials(connection) } catch { reply(.failed); return }
        }
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any AuthorityPairingXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .hello: proxy.pairingHello { [self] in checked(.version($0), reply: reply) }
        case .context: proxy.pairingContext { [self] in checked(.bytes($0), reply: reply) }
        case .stage(let proposal, let authorization):
            proxy.stagePairing(proposal, authorization: authorization) { [self] in checked(.bytes($0), reply: reply) }
        case .commit(let setup, let digest, let proof, let authorization):
            proxy.commitPairing(setup, confirmedDigest: digest, biometricProof: proof, authorization: authorization) {
                [self] in checked(.bytes($0), reply: reply)
            }
        case .cancel: proxy.cancelPairing { [self] in checked(.cancelled($0), reply: reply) }
        }
    }
    private func checked(_ value: PairingClientReply, reply: @Sendable (PairingClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(value) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}
private final class PairingClientLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    func close() { lock.withLock { closed = true } }
    func ifOpen(_ body: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; body(); return true } }
}

/// Authenticated local pairing client. Start before exporting administrator rights. This actor never prompts or retries a commit.
public actor AuthorityPairingChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any PairingClientDriver
    private let macID: Data
    private let accountID: Data
    private let timeout: UInt64
    private let verifyAccount: @Sendable () throws -> Void
    private let onClose: @Sendable () -> Void
    private let lifetime = PairingClientLifetime()
    private var state = State.new
    private var context: AuthorityPairingContext?
    private var staged: PairingTranscript?
    private var pending: (id: UUID, continuation: CheckedContinuation<PairingClientReply, any Error>)?
    private var timer: Task<Void, Never>?

    /// The configuration must come from verified Root-owned installation metadata.
    public init(configuration: AuthorityPresenceClientConfiguration, onClose: @escaping @Sendable () -> Void = {}) throws {
        guard getuid() == configuration.ownerUID, geteuid() == configuration.ownerUID else { throw AuthorityPairingChannelError.wrongAccount }
        let processID = getpid(), ownerUID = configuration.ownerUID
        driver = NativePairingClientDriver(configuration: configuration)
        macID = configuration.macID; accountID = configuration.accountID; timeout = configuration.timeoutMilliseconds; self.onClose = onClose
        verifyAccount = {
            guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw AuthorityPairingChannelError.wrongAccount }
        }
    }
    // Component drivers cannot establish native Root identity, code signing or administrator consent.
    init(driver: any PairingClientDriver, macID: Data, accountID: Data, timeoutMilliseconds: UInt64 = 5000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}, onClose: @escaping @Sendable () -> Void = {}) {
        self.driver = driver; self.macID = macID; self.accountID = accountID; timeout = timeoutMilliseconds
        self.verifyAccount = verifyAccount; self.onClose = onClose
    }
    deinit { timer?.cancel(); driver.close() }
    public func start() async throws -> AuthorityPairingContext {
        guard state == .new else { throw AuthorityPairingChannelError.closed }
        state = .opening
        do {
            guard case .version(1) = try await perform(.hello) else { throw AuthorityPairingChannelError.unsupportedVersion }
            let context = try AuthorityPairingContext.decode(bytes(await perform(.context)), macID: macID, accountID: accountID)
            self.context = context; state = .open; return context
        } catch { close(); throw error }
    }
    /// Adapt phone-only network claims to the existing local version-1 staging contract.
    /// The placeholder fields never leave local XPC. Only Root's returned transcript can be confirmed or signed.
    public func stage(_ proposal: PairingPhoneProposal, authorization: Data) async throws -> PairingTranscript {
        guard state == .open, let context else { throw AuthorityPairingChannelError.closed }
        var nonce = proposal.phone.nonce; nonce[0] ^= 1
        let mac = try ChannelOffer(role: .mac, scope: proposal.phone.scope, nonce: nonce, envelopeVersions: [1],
            requests: [], auditVersions: [])
        let local = try PairingTranscript(setupID: Data(count: 16), challenge: Data(count: 32), phone: proposal.phone, mac: mac,
            minimumEnvelopeVersion: context.minimumEnvelopeVersion,
            selectedEnvelopeVersion: CompatibilityPolicy.envelopeVersion(local: [1], peer: proposal.phone.envelopeVersions,
                trustedMinimum: context.minimumEnvelopeVersion), macAuthorityKey: context.authorityPublicKey,
            macTransportKey: context.transportPublicKey, transportKey: proposal.transportKey,
            decisionKey: proposal.decisionKey, biometricKey: proposal.biometricKey, enrollmentTag: Data(count: 32),
            replacement: nil, expectedTrustRevision: Data(count: 16), issuedAtUnixMillis: 0, expiresAtUnixMillis: 1)
        return try await stage(local, authorization: authorization)
    }
    /// Retain and show the returned transcript. The proposal's Mac-generated fields are replaced by Root.
    public func stage(_ proposal: PairingTranscript, authorization: Data) async throws -> PairingTranscript {
        guard state == .open, let context, staged == nil else { throw AuthorityPairingChannelError.closed }
        guard proposal.replacement == nil, proposal.phone.scope.macID == macID, proposal.phone.scope.accountID == accountID,
              authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AuthorityPairingChannelError.invalidMessage }
        do {
            let transcript = try PairingTranscript.decode(bytes(await perform(.stage(proposal.encode(), authorization))))
            guard try transcript.phone.encode() == proposal.phone.encode(), transcript.replacement == nil,
                  transcript.macAuthorityKey == context.authorityPublicKey, transcript.macTransportKey == context.transportPublicKey,
                  transcript.minimumEnvelopeVersion == context.minimumEnvelopeVersion,
                  transcript.expiresAtUnixMillis - transcript.issuedAtUnixMillis == context.lifetimeMilliseconds,
                  transcript.transportKey.keyID == proposal.transportKey.keyID, transcript.transportKey.publicKey == proposal.transportKey.publicKey,
                  transcript.decisionKey.keyID == proposal.decisionKey.keyID, transcript.decisionKey.publicKey == proposal.decisionKey.publicKey,
                  transcript.biometricKey.keyID == proposal.biometricKey.keyID, transcript.biometricKey.publicKey == proposal.biometricKey.publicKey else {
                throw AuthorityPairingChannelError.invalidMessage
            }
            staged = transcript; return transcript
        } catch AuthorityPairingChannelError.busy { throw AuthorityPairingChannelError.busy }
        catch { close(); throw error }
    }
    /// Call only after human transcript confirmation. A lost reply is ambiguous; use the phone's durable receipt recovery.
    public func commit(confirmedDigest: Data, biometricProof: Data, authorization: Data) async throws -> Data {
        guard state == .open, let staged, let context else { throw AuthorityPairingChannelError.closed }
        guard confirmedDigest.count == 32, try confirmedDigest == staged.digest(), biometricProof.count == 64,
              authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AuthorityPairingChannelError.invalidMessage }
        guard pending == nil else { throw AuthorityPairingChannelError.busy }
        self.staged = nil
        do {
            let receipt = try bytes(await perform(.commit(staged.setupID, confirmedDigest, biometricProof, authorization)))
            guard receipt.count == 64, try staged.verify(signature: receipt, publicKey: context.authorityPublicKey, purpose: .macCommit) else {
                throw AuthorityPairingChannelError.invalidMessage
            }
            return receipt
        } catch { close(); throw error }
    }
    /// Cancels only the uncommitted setup. It does not revoke an enrollment or require a biometric.
    public func cancelStaged() async throws {
        guard case .cancelled(true) = try await perform(.cancel) else { close(); throw AuthorityPairingChannelError.invalidMessage }
        staged = nil
    }
    public nonisolated func abort() { lifetime.close(); driver.close(); Task { await self.close() } }
    public func close() { finish(.closed) }
    private func bytes(_ reply: PairingClientReply) throws -> Data {
        guard case .bytes(let value) = reply, let value, value.count <= 132_000 else { throw AuthorityPairingChannelError.invalidMessage }
        return value
    }
    private func perform(_ call: PairingClientCall) async throws -> PairingClientReply {
        do { try verifyAccount() } catch { close(); throw error }
        try Task.checkCancellation()
        switch call {
        case .hello: guard state == .opening else { throw AuthorityPairingChannelError.closed }
        case .context: guard state == .opening else { throw AuthorityPairingChannelError.closed }
        case .stage, .commit, .cancel: guard state == .open else { throw AuthorityPairingChannelError.closed }
        }
        guard pending == nil else { throw AuthorityPairingChannelError.busy }
        let lifetime = lifetime, driver = driver, id = UUID()
        let value = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, timeout] in
                    do { try await Task.sleep(for: .milliseconds(timeout)) } catch { return }
                    await self?.expire(id)
                }
                if case .hello = call {
                    driver.start { [weak self] in lifetime.close(); Task { await self?.close() } }
                }
                guard lifetime.ifOpen({ driver.invoke(call) { [weak self] value in Task { await self?.complete(id, value: value) } } }) else {
                    close(); return
                }
            }
        } onCancel: { [weak self] in lifetime.close(); driver.close(); Task { await self?.close() } }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw AuthorityPairingChannelError.closed }
        return value
    }
    private func complete(_ id: UUID, value: PairingClientReply) {
        guard let previous = pending, previous.id == id else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        if case .failed = value { finish(.closed); return }
        pending = nil; timer?.cancel(); timer = nil; previous.continuation.resume(returning: value)
    }
    private func expire(_ id: UUID) { if pending?.id == id { finish(.timedOut) } }
    private func finish(_ error: AuthorityPairingChannelError) {
        guard state != .closed else { return }
        state = .closed; context = nil; staged = nil; lifetime.close(); timer?.cancel(); timer = nil
        let previous = pending; pending = nil; driver.close(); onClose(); previous?.continuation.resume(throwing: error)
    }
}
