import Darwin
import Foundation
import RemozioProtocol

public enum AuthorityWakeHintChannelError: Error, Equatable {
    case invalidConfiguration, closed, busy, timedOut, unsupportedVersion, invalidMessage
}
enum AuthorityWakeHintCall: Sendable { case hello, version, hints }
enum AuthorityWakeHintResponse: Sendable { case version(UInt64), hints(Data?), failed }
protocol AuthorityWakeHintDriver: Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: AuthorityWakeHintCall, reply: @escaping @Sendable (AuthorityWakeHintResponse) -> Void)
    func close()
}
private final class NativeAuthorityWakeHintDriver: AuthorityWakeHintDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let policy: XPCPeerPolicy
    init(serviceName: String, policy: XPCPeerPolicy) {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: TransportAuthorityXPCProtocol.self)
        policy.configure(connection)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: AuthorityWakeHintCall, reply: @escaping @Sendable (AuthorityWakeHintResponse) -> Void) {
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any TransportAuthorityXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .hello: proxy.hello { [self] in checked(.version($0), reply) }
        case .version: proxy.requestWakeVersion { [self] in checked(.version($0), reply) }
        case .hints: proxy.wakeDeliveryHints { [self] in checked(.hints($0), reply) }
        }
    }
    private func checked(_ response: AuthorityWakeHintResponse, _ reply: @Sendable (AuthorityWakeHintResponse) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(response) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}

/// This optional extension owns a separate connection. An old Root selector cannot retire the ordinary approval channel.
public actor AuthorityWakeHintChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any AuthorityWakeHintDriver
    public nonisolated let binding: GatewaySubmissionBinding
    private let timeout: UInt64
    private let verifyAccount: @Sendable () throws -> Void
    private var state = State.new
    private var pending: (id: UUID, continuation: CheckedContinuation<AuthorityWakeHintResponse, any Error>)?
    private var timer: Task<Void, Never>?
    public init(serviceName: String, transportUID: uid_t, authorityPolicy: XPCPeerPolicy,
                binding: GatewaySubmissionBinding, timeoutMilliseconds: UInt64 = 5000) throws {
        try self.init(serviceName: serviceName, transportUID: transportUID, authorityPolicy: authorityPolicy,
            binding: binding, timeoutMilliseconds: timeoutMilliseconds, verifyCurrent: {})
    }
    init(serviceName: String, transportUID: uid_t, authorityPolicy: XPCPeerPolicy,
         binding: GatewaySubmissionBinding, timeoutMilliseconds: UInt64 = 5000,
         verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        guard transportUID > 0, transportUID < UInt32.max, authorityPolicy.expectedUserID == 0,
              GatewayWakeEndpointConfiguration.validServiceName(serviceName), (1...60_000).contains(timeoutMilliseconds) else {
            throw AuthorityWakeHintChannelError.invalidConfiguration
        }
        driver = NativeAuthorityWakeHintDriver(serviceName: serviceName, policy: authorityPolicy)
        self.binding = binding; timeout = timeoutMilliseconds
        verifyAccount = {
            guard getuid() == transportUID, geteuid() == transportUID else { throw GatewayServiceError.wrongAccount }
            try verifyCurrent()
        }
    }
    init(driver: any AuthorityWakeHintDriver, binding: GatewaySubmissionBinding, timeoutMilliseconds: UInt64 = 5000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}) {
        self.driver = driver; self.binding = binding; timeout = timeoutMilliseconds; self.verifyAccount = verifyAccount
    }
    deinit { timer?.cancel(); driver.close() }
    public func start() async throws {
        try verifyAccount()
        guard state == .new else { throw AuthorityWakeHintChannelError.closed }
        state = .opening
        driver.start { [weak self] in Task { await self?.close() } }
        do {
            guard case .version(let base) = try await perform(.hello), base == 1 else { throw AuthorityWakeHintChannelError.unsupportedVersion }
            guard case .version(let version) = try await perform(.version), version == 1 else { throw AuthorityWakeHintChannelError.unsupportedVersion }
            try verifyAccount(); try Task.checkCancellation()
            guard state == .opening else { throw AuthorityWakeHintChannelError.closed }
            state = .open
        } catch { close(); throw error }
    }
    public func current() async throws -> AuthorityWakeHints {
        guard state == .open else { throw AuthorityWakeHintChannelError.closed }
        guard pending == nil else { throw AuthorityWakeHintChannelError.busy }
        do {
            guard case .hints(let bytes) = try await perform(.hints), let bytes else { throw AuthorityWakeHintChannelError.invalidMessage }
            try verifyAccount(); try Task.checkCancellation()
            guard state == .open else { throw AuthorityWakeHintChannelError.closed }
            do { return try AuthorityWakeHints.decode(bytes, expectedBinding: binding) }
            catch { throw AuthorityWakeHintChannelError.invalidMessage }
        } catch { close(); throw error }
    }
    public func close() {
        guard state != .closed else { return }
        state = .closed; timer?.cancel(); timer = nil; driver.close()
        let previous = pending; pending = nil; previous?.continuation.resume(throwing: AuthorityWakeHintChannelError.closed)
    }
    private func perform(_ call: AuthorityWakeHintCall) async throws -> AuthorityWakeHintResponse {
        try verifyAccount(); try Task.checkCancellation()
        switch call {
        case .hello, .version: guard state == .opening else { throw AuthorityWakeHintChannelError.closed }
        case .hints: guard state == .open else { throw AuthorityWakeHintChannelError.closed }
        }
        guard pending == nil else { throw AuthorityWakeHintChannelError.busy }
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, timeout] in
                    do { try await Task.sleep(for: .milliseconds(timeout)) } catch { return }
                    await self?.expire(id)
                }
                driver.invoke(call) { [weak self] response in Task { await self?.complete(id, response) } }
            }
        } onCancel: { [weak self] in Task { await self?.close() } }
    }
    private func complete(_ id: UUID, _ response: AuthorityWakeHintResponse) {
        guard let pending, pending.id == id, state != .closed else { return }
        self.pending = nil; timer?.cancel(); timer = nil
        if case .failed = response { pending.continuation.resume(throwing: AuthorityWakeHintChannelError.closed); close() }
        else { pending.continuation.resume(returning: response) }
    }
    private func expire(_ id: UUID) {
        guard let pending, pending.id == id else { return }
        self.pending = nil; pending.continuation.resume(throwing: AuthorityWakeHintChannelError.timedOut); close()
    }
}
