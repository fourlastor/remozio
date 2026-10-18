import Darwin
import Foundation
import RemozioProtocol

public enum GatewayRootChannelError: Error, Equatable { case invalidConfiguration, closed, busy, timedOut, rejected, invalidMessage, unsupportedVersion }
enum GatewayRootCall: Sendable { case hello, synchronize(Data), command(Data) }
enum GatewayRootResponse: Sendable { case version(UInt64), synchronized(Bool), command(Data?), failed }
protocol GatewayRootDriver: AnyObject, Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: GatewayRootCall, reply: @escaping @Sendable (GatewayRootResponse) -> Void)
    func close()
}

private final class NativeGatewayRootDriver: GatewayRootDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(serviceName: String, policy: XPCPeerPolicy) {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: GatewayRootXPCProtocol.self)
        policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: GatewayRootCall, reply: @escaping @Sendable (GatewayRootResponse) -> Void) {
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any GatewayRootXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .hello: proxy.hello { [self] in checked(.version($0), reply: reply) }
        case .synchronize(let bytes): proxy.synchronize(bytes) { [self] in checked(.synchronized($0), reply: reply) }
        case .command(let bytes): proxy.command(bytes) { [self] in checked(.command($0), reply: reply) }
        }
    }
    private func checked(_ result: GatewayRootResponse, reply: @Sendable (GatewayRootResponse) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(result) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}

private final class GatewayRootLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    @discardableResult
    func close() -> Bool { lock.withLock { guard !closed else { return false }; closed = true; return true } }
    func ifOpen(_ body: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; body(); return !closed } }
}

/// Root-side control client. A harmless authenticated handshake precedes every sensitive call on a new connection.
/// The caller must independently verify recovery signatures and reconcile its retained journal before enabling delivery.
public actor GatewayRootChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any GatewayRootDriver
    private let timeout: UInt64
    private let verifyAccount: @Sendable () throws -> Void
    private let lifetime = GatewayRootLifetime()
    private var state = State.new
    private var peerVersion: UInt64?
    private var pending: (id: UUID, continuation: CheckedContinuation<GatewayRootResponse, any Error>)?
    private var timer: Task<Void, Never>?
    public init(serviceName: String, gatewayPolicy: XPCPeerPolicy, timeoutMilliseconds: UInt64 = 5000) throws {
        guard gatewayPolicy.expectedUserID > 0, (1...60_000).contains(timeoutMilliseconds),
              serviceName.hasPrefix("dev.remozio."), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }) else {
            throw GatewayRootChannelError.invalidConfiguration
        }
        driver = NativeGatewayRootDriver(serviceName: serviceName, policy: gatewayPolicy)
        timeout = timeoutMilliseconds
        verifyAccount = { guard getuid() == 0, geteuid() == 0 else { throw GatewayServiceError.wrongAccount } }
    }
    init(driver: any GatewayRootDriver, timeoutMilliseconds: UInt64 = 5000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}) {
        self.driver = driver; timeout = timeoutMilliseconds; self.verifyAccount = verifyAccount
    }
    deinit { timer?.cancel(); if lifetime.close() { driver.close() } }

    public func start() async throws {
        try verifyAccount()
        guard state == .new else { throw GatewayRootChannelError.closed }
        state = .opening
        let lifetime = lifetime, driver = driver
        driver.start { [weak self, weak driver] in
            if lifetime.close() { driver?.close() }
            Task { await self?.close() }
        }
        do {
            guard case .version(let version) = try await perform(.hello), (1...3).contains(version), state == .opening else { throw GatewayRootChannelError.invalidMessage }
            peerVersion = version
            state = .open
        } catch { close(); throw error }
    }
    public func synchronize(_ snapshot: GatewayHostSnapshot) async throws {
        guard case .synchronized(let accepted) = try await perform(.synchronize(snapshot.canonicalBytes)) else {
            close(); throw GatewayRootChannelError.invalidMessage
        }
        guard accepted else { throw GatewayRootChannelError.rejected }
    }
    /// Registration creates no provider work. Only a separately authenticated transport wake can start it.
    public func registerWake(_ delivery: PhoneRequestDelivery) async throws {
        try await requireAcceptance(.registerWake(delivery))
    }
    public func withdrawWake(_ deliveryID: UUID) async throws {
        try await requireAcceptance(.withdraw(deliveryID))
    }
    private func requireAcceptance(_ command: GatewayRootCommand) async throws {
        let fields = try await self.command(command)
        guard fields.count == 2, case .boolean(let accepted) = fields[1] else {
            close(); throw GatewayRootChannelError.invalidMessage
        }
        guard accepted else { throw GatewayRootChannelError.rejected }
    }
    /// Start a provider probe only for a retained candidate admitted on this control connection.
    public func probeCandidate(operationID: Data, phoneID: Data) async throws {
        guard operationID.count == 16, phoneID.count == 16 else { throw GatewayRootChannelError.invalidMessage }
        try await requireAcceptance(.probe(operationID: operationID, phoneID: phoneID))
    }

    /// Recovery replies remain unverified until GatewayHeadQueryOwner accepts the fresh response.
    public func head(query: Data) async throws -> GatewayHeadReply {
        let fields = try await command(.head(query))
        guard fields.count == 3, case .bytes(let payload) = fields[1], case .bytes(let signature) = fields[2], signature.count == 64 else {
            close(); throw GatewayRootChannelError.invalidMessage
        }
        return GatewayHeadReply(canonicalPayload: payload, signature: signature)
    }
    public func history(query: Data) async throws -> GatewayControlHistoryReply {
        let fields = try await command(.history(query))
        guard fields.count == 3, case .bytes(let payload) = fields[1], case .bytes(let signature) = fields[2], signature.count == 64 else {
            close(); throw GatewayRootChannelError.invalidMessage
        }
        return GatewayControlHistoryReply(canonicalPayload: payload, signature: signature)
    }
    /// Submit only a retained Root control. A receipt does not replace a fresh head query or grant wake authority.
    public func applySubmission(_ envelope: GatewayAuthorityEnvelope, registration: GatewayRegistrationIdentity) async throws -> GatewaySubmissionApplication {
        guard GatewaySubmissionKind(rawValue: envelope.kind) != nil, envelope.registrationToken == nil else {
            throw GatewayRootChannelError.invalidMessage
        }
        let limits = try CBORLimits(maxBytes: 65_536, maxDepth: 8, maxItems: 128)
        let signing = try CBORLimits(maxBytes: 131_072, maxDepth: 8, maxItems: 128)
        let sent = try GatewaySubmissionVerifier.authenticate(canonicalPayload: envelope.canonicalPayload, signature: envelope.signature,
            wireVersion: 1, registration: registration, payloadLimits: limits, signingLimits: signing)
        guard sent.kind.rawValue == envelope.kind, sent.revision == envelope.revision, sent.operationID == envelope.operationID else {
            throw GatewayRootChannelError.invalidMessage
        }
        let fields = try await command(.submission(payload: envelope.canonicalPayload, signature: envelope.signature, wireVersion: 1))
        do {
            guard fields.count == 4, case .bytes(let payload) = fields[1], case .bytes(let signature) = fields[2],
                  case .boolean(let inserted) = fields[3], payload == envelope.canonicalPayload else { throw GatewayRootChannelError.invalidMessage }
            let received = try GatewaySubmissionVerifier.authenticate(canonicalPayload: payload, signature: signature, wireVersion: 1,
                registration: registration, payloadLimits: limits, signingLimits: signing)
            return GatewaySubmissionApplication(receipt: GatewaySubmissionReceipt(control: received, canonicalPayload: payload, signature: signature), inserted: inserted)
        } catch { close(); throw error }
    }

    public func command(_ command: GatewayRootCommand) async throws -> [CBORValue] {
        guard state == .open else { throw GatewayRootChannelError.closed }
        guard let peerVersion, command.protocolVersion <= peerVersion else { throw GatewayRootChannelError.unsupportedVersion }
        guard case .command(let bytes) = try await perform(.command(command.encode())) else {
            close(); throw GatewayRootChannelError.invalidMessage
        }
        guard let bytes else { throw GatewayRootChannelError.rejected }
        do {
            guard case .array(let fields) = try DeterministicCBOR.decode(bytes,
                    limits: CBORLimits(maxBytes: 1_100_128, maxDepth: 1, maxItems: 8)), fields.first == .unsigned(command.protocolVersion) else {
                throw GatewayRootChannelError.invalidMessage
            }
            return fields
        } catch { close(); throw error }
    }
    public func close() {
        guard state != .closed else { return }
        state = .closed; timer?.cancel(); timer = nil
        if lifetime.close() { driver.close() }
        let previous = pending; pending = nil; previous?.continuation.resume(throwing: GatewayRootChannelError.closed)
    }
    private func perform(_ call: GatewayRootCall) async throws -> GatewayRootResponse {
        try verifyAccount(); try Task.checkCancellation()
        switch call {
        case .hello: guard state == .opening else { throw GatewayRootChannelError.closed }
        case .synchronize, .command: guard state == .open else { throw GatewayRootChannelError.closed }
        }
        guard lifetime.ifOpen({}) else { close(); throw GatewayRootChannelError.closed }
        guard pending == nil else { throw GatewayRootChannelError.busy }
        let id = UUID(), lifetime = lifetime, driver = driver
        let result = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, timeout] in
                    do { try await Task.sleep(for: .milliseconds(timeout)) } catch { return }
                    await self?.expire(id)
                }
                guard lifetime.ifOpen({
                    driver.invoke(call) { [weak self, weak driver] result in
                        if case .failed = result, lifetime.close() { driver?.close() }
                        Task { await self?.complete(id, result: result) }
                    }
                }) else { close(); return }
            }
        } onCancel: { [weak self] in
            if lifetime.close() { driver.close() }
            Task { await self?.close() }
        }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw GatewayRootChannelError.closed }
        return result
    }
    private func complete(_ id: UUID, result: GatewayRootResponse) {
        guard let pending, pending.id == id, state != .closed else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        self.pending = nil; timer?.cancel(); timer = nil
        if case .failed = result { pending.continuation.resume(throwing: GatewayRootChannelError.closed); close() }
        else { pending.continuation.resume(returning: result) }
    }
    private func expire(_ id: UUID) {
        guard let pending, pending.id == id else { return }
        self.pending = nil; pending.continuation.resume(throwing: GatewayRootChannelError.timedOut); close()
    }
}
