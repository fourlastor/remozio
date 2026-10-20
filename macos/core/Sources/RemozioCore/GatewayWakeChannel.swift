import Darwin
import Foundation
import RemozioProtocol

public enum GatewayWakeChannelError: Error, Equatable {
    case invalidConfiguration, closed, busy, timedOut, rejected, invalidMessage, unsupportedVersion
}
enum GatewayWakeCall: Sendable { case hello, challenge, wake(Data, Data) }
enum GatewayWakeResponse: Sendable { case version(UInt64), challenge(Data?), accepted(Bool), failed }
protocol GatewayWakeDriver: Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: GatewayWakeCall, reply: @escaping @Sendable (GatewayWakeResponse) -> Void)
    func close()
}

private final class NativeGatewayWakeDriver: GatewayWakeDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(serviceName: String, policy: XPCPeerPolicy) {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: GatewayWakeXPCProtocol.self)
        policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: GatewayWakeCall, reply: @escaping @Sendable (GatewayWakeResponse) -> Void) {
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any GatewayWakeXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .hello: proxy.hello { [self] in checked(.version($0), reply: reply) }
        case .challenge: proxy.challenge { [self] in checked(.challenge($0), reply: reply) }
        case .wake(let payload, let signature): proxy.wake(payload, signature: signature) { [self] in checked(.accepted($0), reply: reply) }
        }
    }
    private func checked(_ response: GatewayWakeResponse, reply: @Sendable (GatewayWakeResponse) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(response) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}

/// A transport client can name only opaque Root grants. The signer must use the current protected transport key.
/// This channel never selects a recipient, sets a deadline, reads provider credentials, or sends Root controls.
public actor GatewayWakeChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any GatewayWakeDriver
    private let timeout: UInt64
    private let verifyAccount: @Sendable () throws -> Void
    private var state = State.new
    private var submitting = false
    private var pending: (id: UUID, continuation: CheckedContinuation<GatewayWakeResponse, any Error>)?
    private var timer: Task<Void, Never>?

    public init(serviceName: String, transportUID: uid_t, gatewayPolicy: XPCPeerPolicy,
                timeoutMilliseconds: UInt64 = 5000) throws {
        try self.init(serviceName: serviceName, transportUID: transportUID, gatewayPolicy: gatewayPolicy,
            timeoutMilliseconds: timeoutMilliseconds, verifyCurrent: {})
    }
    init(serviceName: String, transportUID: uid_t, gatewayPolicy: XPCPeerPolicy,
         timeoutMilliseconds: UInt64 = 5000, verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        guard transportUID > 0, transportUID < UInt32.max, gatewayPolicy.expectedUserID > 0,
              gatewayPolicy.expectedUserID != transportUID, GatewayWakeEndpointConfiguration.validServiceName(serviceName),
              (1...60_000).contains(timeoutMilliseconds) else { throw GatewayWakeChannelError.invalidConfiguration }
        driver = NativeGatewayWakeDriver(serviceName: serviceName, policy: gatewayPolicy); timeout = timeoutMilliseconds
        verifyAccount = {
            guard getuid() == transportUID, geteuid() == transportUID else { throw GatewayServiceError.wrongAccount }
            try verifyCurrent()
        }
    }
    init(driver: any GatewayWakeDriver, timeoutMilliseconds: UInt64 = 5000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}) {
        self.driver = driver; timeout = timeoutMilliseconds; self.verifyAccount = verifyAccount
    }
    deinit { timer?.cancel(); driver.close() }
    public func start() async throws {
        try verifyAccount()
        guard state == .new else { throw GatewayWakeChannelError.closed }
        state = .opening
        driver.start { [weak self] in Task { await self?.close() } }
        do {
            guard case .version(let version) = try await perform(.hello) else { throw GatewayWakeChannelError.invalidMessage }
            guard version == 1 else { throw GatewayWakeChannelError.unsupportedVersion }
            try verifyAccount(); try Task.checkCancellation()
            guard state == .opening else { throw GatewayWakeChannelError.closed }
            state = .open
        } catch { close(); throw error }
    }
    /// Sign exactly the gateway's one-use challenge and current grant identifier, with a separate wake purpose.
    public func wake(binding: GatewaySubmissionBinding, credentialID: Data, deliveryID: UUID,
                     sign: @Sendable (Data) throws -> Data) async throws {
        try await submit(binding: binding, credentialID: credentialID, deliveryID: deliveryID,
            sign: { try sign($0.signingInput()) })
    }
    /// Uses only the provisioned wake key, with its protected scope and credential identity.
    public func wake(deliveryID: UUID, signer: GatewayWakeSigner) async throws {
        try await submit(binding: signer.binding, credentialID: signer.credentialID, deliveryID: deliveryID,
            sign: { try signer.sign($0) })
    }
    private func submit(binding: GatewaySubmissionBinding, credentialID: Data, deliveryID: UUID,
                        sign: @Sendable (GatewayWakeSubmission) throws -> Data) async throws {
        try verifyAccount(); try Task.checkCancellation()
        guard state == .open else { throw GatewayWakeChannelError.closed }
        guard !submitting else { throw GatewayWakeChannelError.busy }
        guard credentialID.count == 16 else { throw GatewayWakeChannelError.invalidMessage }
        submitting = true
        defer { submitting = false }
        do {
            guard case .challenge(let challenge) = try await perform(.challenge), let challenge, challenge.count == 32 else {
                throw GatewayWakeChannelError.invalidMessage
            }
            try requireCurrent()
            let submission = try GatewayWakeSubmission(binding: binding, credentialID: credentialID,
                deliveryID: GatewayHostSnapshot.bytes(deliveryID), challenge: challenge)
            let signature = try sign(submission)
            try requireCurrent()
            guard signature.count == 64 else { throw GatewayWakeChannelError.invalidMessage }
            guard case .accepted(let accepted) = try await perform(.wake(submission.encode(), signature)) else {
                throw GatewayWakeChannelError.invalidMessage
            }
            try requireCurrent()
            guard accepted else { throw GatewayWakeChannelError.rejected }
        } catch {
            if (error as? GatewayWakeChannelError) != .rejected { close() }
            throw error
        }
    }
    private func requireCurrent() throws {
        try verifyAccount(); try Task.checkCancellation()
        guard state == .open else { throw GatewayWakeChannelError.closed }
    }
    public func close() {
        guard state != .closed else { return }
        state = .closed; timer?.cancel(); timer = nil; driver.close()
        let previous = pending; pending = nil; previous?.continuation.resume(throwing: GatewayWakeChannelError.closed)
    }
    private func perform(_ call: GatewayWakeCall) async throws -> GatewayWakeResponse {
        try verifyAccount(); try Task.checkCancellation()
        switch call {
        case .hello: guard state == .opening else { throw GatewayWakeChannelError.closed }
        case .challenge, .wake: guard state == .open else { throw GatewayWakeChannelError.closed }
        }
        guard pending == nil else { throw GatewayWakeChannelError.busy }
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, timeout] in
                    do { try await Task.sleep(for: .milliseconds(timeout)) } catch { return }
                    await self?.expire(id)
                }
                driver.invoke(call) { [weak self] response in Task { await self?.complete(id, response: response) } }
            }
        } onCancel: { [weak self] in Task { await self?.close() } }
    }
    private func complete(_ id: UUID, response: GatewayWakeResponse) {
        guard let pending, pending.id == id, state != .closed else { return }
        self.pending = nil; timer?.cancel(); timer = nil
        if case .failed = response { pending.continuation.resume(throwing: GatewayWakeChannelError.closed); close() }
        else { pending.continuation.resume(returning: response) }
    }
    private func expire(_ id: UUID) {
        guard let pending, pending.id == id else { return }
        self.pending = nil; pending.continuation.resume(throwing: GatewayWakeChannelError.timedOut); close()
    }
}
