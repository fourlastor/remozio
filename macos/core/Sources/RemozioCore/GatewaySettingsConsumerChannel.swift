import Darwin
import Foundation
import Security

final class NativeGatewaySettingsConsumerDriver: GatewaySettingsControlDriver, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let verifyPeer: () throws -> Void
    convenience init(serviceName: String, policy: XPCPeerPolicy) {
        let connection = NSXPCConnection(machServiceName: serviceName, options: .privileged)
        policy.configure(connection)
        self.init(connection: connection, verifyPeer: { _ = try policy.verifyCredentials(connection) })
    }
    // An owned anonymous connection can test transport shape, but cannot prove production peer admission.
    init(connection: NSXPCConnection, verifyPeer: @escaping () throws -> Void) {
        self.connection = connection; self.verifyPeer = verifyPeer
        connection.remoteObjectInterface = NSXPCInterface(with: GatewaySettingsConsumerXPCProtocol.self)
    }
    func start(closed: @escaping @Sendable () -> Void) {
        connection.interruptionHandler = closed; connection.invalidationHandler = closed; connection.activate()
    }
    func invoke(_ call: GatewaySettingsControlCall, reply: @escaping @Sendable (GatewaySettingsControlReply) -> Void) {
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.failed) }) as? any GatewaySettingsConsumerXPCProtocol else {
            reply(.failed); return
        }
        switch call {
        case .hello: proxy.hello { [weak self] version, bytes in self?.checked(.greeting(version, bytes), reply: reply) ?? reply(.failed) }
        case .control(let payload): proxy.control(payload) { [weak self] in self?.checked(.response($0), reply: reply) ?? reply(.failed) }
        }
    }
    private func checked(_ value: GatewaySettingsControlReply, reply: @Sendable (GatewaySettingsControlReply) -> Void) {
        do { try verifyPeer(); reply(value) } catch { reply(.failed) }
    }
    func close() { connection.invalidate() }
    deinit { connection.invalidate() }
}

private final class GatewaySettingsConsumerClientLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    @discardableResult
    func close() -> Bool { lock.withLock { guard !closed else { return false }; closed = true; return true } }
    func ifOpen(_ body: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; body(); return !closed } }
}

/// One control operation with no automatic retry. The owner must resolve an uncertain result through a fresh observation.
actor GatewaySettingsConsumerChannel {
    private enum State { case new, opening, open, closed }
    private let driver: any GatewaySettingsControlDriver
    private let role: GatewaySettingsConsumerRole
    private let macID: Data
    private let accountID: Data
    private let expectedGeneration: UUID?
    private let verifyAccount: @Sendable () throws -> Void
    private let verifyCurrent: @Sendable () throws -> Void
    private let challenge: @Sendable () throws -> Data
    private let timeout: UInt64
    private let lifetime = GatewaySettingsConsumerClientLifetime()
    private var state = State.new
    private var pending: (id: UUID, continuation: CheckedContinuation<GatewaySettingsControlReply, any Error>)?
    private var timer: Task<Void, Never>?

    init(role: GatewaySettingsConsumerRole, services: ServiceAccountPlan, consumerCode: AuthorityCodeEntry,
         setupCode: AuthorityCodeEntry, release: SignedReleaseEvidence, expectedGeneration: UUID?,
         timeoutMilliseconds: UInt64 = 5000, verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard (1...60_000).contains(timeoutMilliseconds),
              let claim = services.claims.first(where: { $0.role == (role == .gateway ? .gateway : .transport) }) else {
            throw GatewayPreparationError.invalidRecord
        }
        try GatewaySettingsConsumerReleaseValidation.validate(release, role: role, consumer: consumerCode, setup: setupCode)
        let policy = try XPCPeerPolicy(teamID: consumerCode.teamID, componentIdentifier: consumerCode.identifier,
            approvedCodeDirectoryHashes: [consumerCode.codeDirectoryHash], expectedUserID: claim.number)
        let local = try XPCPeerPolicy(teamID: setupCode.teamID, componentIdentifier: setupCode.identifier,
            approvedCodeDirectoryHashes: [setupCode.codeDirectoryHash], expectedUserID: 0)
        let verify: @Sendable () throws -> Void = {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try DynamicCodeValidation.validateSelf(requirement: local.requirement)
        }
        try verify(); try verifyCurrent()
        driver = NativeGatewaySettingsConsumerDriver(serviceName: try role.serviceName(accountID: services.accountID), policy: policy)
        self.role = role; macID = services.macID; accountID = services.accountID
        self.expectedGeneration = expectedGeneration; timeout = timeoutMilliseconds
        verifyAccount = verify; self.verifyCurrent = verifyCurrent; challenge = Self.randomChallenge
    }
    init(driver: any GatewaySettingsControlDriver, role: GatewaySettingsConsumerRole, macID: Data, accountID: Data,
         expectedGeneration: UUID?, timeoutMilliseconds: UInt64 = 5000,
         verifyAccount: @escaping @Sendable () throws -> Void = {}, verifyCurrent: @escaping @Sendable () throws -> Void = {},
         challenge: @escaping @Sendable () throws -> Data) throws {
        guard macID.count == 16, accountID.count == 16, (1...60_000).contains(timeoutMilliseconds) else {
            throw GatewayPreparationError.invalidRecord
        }
        self.driver = driver; self.role = role; self.macID = macID; self.accountID = accountID
        self.expectedGeneration = expectedGeneration; timeout = timeoutMilliseconds
        self.verifyAccount = verifyAccount; self.verifyCurrent = verifyCurrent; self.challenge = challenge
    }
    deinit { timer?.cancel(); if lifetime.close() { driver.close() } }

    func execute(_ fence: GatewayRuntimeSettingsFence, action: GatewaySettingsControlAction) async throws -> GatewaySettingsConsumerResponse {
        guard state == .new else { throw state == .closed ? GatewaySettingsControlChannelError.closed : .busy }
        do {
            guard action != .accept || expectedGeneration != nil else { throw GatewaySettingsControlChannelError.changedScope }
            try verifyAccount(); try verifyCurrent(); try Task.checkCancellation()
            state = .opening
            let lifetime = lifetime, driver = driver
            driver.start { [weak self, weak driver] in
                if lifetime.close() { driver?.close() }
                Task { await self?.close() }
            }
            guard case .greeting(let version, let bytes) = try await perform(.hello), let bytes else { throw GatewaySettingsControlChannelError.invalidReply }
            guard GatewaySettingsConsumerInterface.supportedVersions.contains(version) else { throw GatewaySettingsControlChannelError.unsupportedVersion }
            let binding = try GatewaySettingsConsumerBinding.decode(bytes)
            guard binding.role == role, binding.macID == macID, binding.accountID == accountID,
                  expectedGeneration == nil || expectedGeneration == binding.generation else {
                throw GatewaySettingsControlChannelError.changedScope
            }
            try verifyAccount(); try verifyCurrent(); try Task.checkCancellation()
            state = .open
            let request = try GatewaySettingsConsumerRequest(binding: binding, fence: fence, action: action, challenge: challenge())
            guard case .response(let reply) = try await perform(.control(request.encoded)), let reply else { throw GatewaySettingsControlChannelError.invalidReply }
            let result = try GatewaySettingsConsumerResponse.decode(reply, expected: request)
            try verifyAccount(); try verifyCurrent(); try Task.checkCancellation()
            guard state == .open, lifetime.ifOpen({}) else { throw GatewaySettingsControlChannelError.closed }
            close(); return result
        } catch { close(); throw error }
    }
    func close() {
        guard state != .closed else { return }
        state = .closed; timer?.cancel(); timer = nil
        if lifetime.close() { driver.close() }
        let old = pending; pending = nil; old?.continuation.resume(throwing: GatewaySettingsControlChannelError.closed)
    }
    private func perform(_ call: GatewaySettingsControlCall) async throws -> GatewaySettingsControlReply {
        try verifyAccount(); try verifyCurrent(); try Task.checkCancellation()
        switch call {
        case .hello: guard state == .opening else { throw GatewaySettingsControlChannelError.closed }
        case .control: guard state == .open else { throw GatewaySettingsControlChannelError.closed }
        }
        guard lifetime.ifOpen({}) else { close(); throw GatewaySettingsControlChannelError.closed }
        guard pending == nil else { throw GatewaySettingsControlChannelError.busy }
        let id = UUID(), lifetime = lifetime, driver = driver
        let result = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, timeout] in
                    do { try await Task.sleep(for: .milliseconds(timeout)) } catch { return }
                    await self?.expire(id)
                }
                guard lifetime.ifOpen({
                    driver.invoke(call) { [weak self, weak driver] value in
                        if case .failed = value, lifetime.close() { driver?.close() }
                        Task { await self?.complete(id, value) }
                    }
                }) else { close(); return }
            }
        } onCancel: { [weak self] in
            if lifetime.close() { driver.close() }
            Task { await self?.close() }
        }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw GatewaySettingsControlChannelError.closed }
        return result
    }
    private func complete(_ id: UUID, _ value: GatewaySettingsControlReply) {
        guard let pending, pending.id == id, state != .closed else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        self.pending = nil; timer?.cancel(); timer = nil
        if case .failed = value { pending.continuation.resume(throwing: GatewaySettingsControlChannelError.closed); close() }
        else { pending.continuation.resume(returning: value) }
    }
    private func expire(_ id: UUID) {
        guard let old = pending, old.id == id else { return }
        pending = nil; close(); old.continuation.resume(throwing: GatewaySettingsControlChannelError.timedOut)
    }
    private static func randomChallenge() throws -> Data {
        var bytes = Data(count: 32)
        guard bytes.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else {
            throw GatewayPreparationError.invalidRecord
        }
        return bytes
    }
}
