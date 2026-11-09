import Darwin
import Foundation

enum MachineUpdateConsumerHealthCall: Sendable { case hello, check(Data) }
enum MachineUpdateConsumerHealthReply: Sendable { case greeting(UInt64, Data?), response(Data?), failed }
enum MachineUpdateConsumerHealthChannelError: Error, Equatable {
    case closed, busy, timedOut, invalidReply, changedScope, gatewayRecoveryRequired
}

/// An authenticated failure. This value can never serve as a signed health packet.
enum MachineUpdateGatewayRecoverySignal {
    static let bytes = Data("remozio:update-health-recovery-required:v1".utf8)
}
protocol MachineUpdateConsumerHealthDriver: AnyObject, Sendable {
    func start(closed: @escaping @Sendable () -> Void)
    func invoke(_ call: MachineUpdateConsumerHealthCall, reply: @escaping @Sendable (MachineUpdateConsumerHealthReply) -> Void)
    func requirePeer() throws
    func close()
}

private final class MachineUpdateConsumerHealthClientLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var closed = false
    @discardableResult
    func close() -> Bool { lock.withLock { guard !closed else { return false }; closed = true; return true } }
    func ifOpen(_ body: () -> Void) -> Bool { lock.withLock { guard !closed else { return false }; body(); return !closed } }
    func requireOpen(_ body: () throws -> Void) throws {
        try lock.withLock {
            guard !closed else { throw MachineUpdateConsumerHealthChannelError.closed }
            try body()
            guard !closed else { throw MachineUpdateConsumerHealthChannelError.closed }
        }
    }
}

/// Retains the authenticated connection and restart scope. The proof alone grants no writer or admission change.
final class MachineUpdateConsumerHealthConnectionScope: Sendable {
    let proof: MachineUpdateConsumerHealthProof
    let exchange: MachineUpdateConsumerHealthExchange
    private let owner: MachineUpdateConsumerHealthChannel
    private let verifyCurrent: @Sendable () throws -> Void
    private let retire: @Sendable () -> Void
    fileprivate init(proof: MachineUpdateConsumerHealthProof, exchange: MachineUpdateConsumerHealthExchange, owner: MachineUpdateConsumerHealthChannel,
        verifyCurrent: @escaping @Sendable () throws -> Void, retire: @escaping @Sendable () -> Void) {
        self.proof = proof; self.exchange = exchange; self.owner = owner; self.verifyCurrent = verifyCurrent; self.retire = retire
    }
    func validate() throws {
        do { try verifyCurrent() }
        catch MachineUpdateHealthSourceError.busy { throw MachineUpdateHealthSourceError.busy }
        catch { retire(); let owner = owner; Task { await owner.close() }; throw error }
    }
    func close() async { await owner.close() }
    deinit { let owner = owner; Task { await owner.close() } }
}

/// One authenticated exchange. The returned evidence grants no floor commit or admission change.
actor MachineUpdateConsumerHealthChannel {
    static let wireVersion: UInt64 = 1

    private enum State { case new, opening, open, closed }
    private let driver: any MachineUpdateConsumerHealthDriver
    private let expectedHello: Data
    private let requirement: MachineUpdateRestartHealthPlan.Requirement
    private let session: MachineUpdateConsumerHealthChallengeSession
    private let authorityInstalledReadiness: Bool
    private var preparedAuthorityRequest: Data?
    private let verifyCurrent: @Sendable () throws -> Void
    private let release: @Sendable () -> Void
    private let timeout: UInt64
    private let lifetime = MachineUpdateConsumerHealthClientLifetime()
    private var state = State.new
    private var pending: (id: UUID, continuation: CheckedContinuation<MachineUpdateConsumerHealthReply, any Error>)?
    private var timer: Task<Void, Never>?

    /// Checks the retained startup selection before constructing any native connection.
    static func startupPeerPins(host: GatewaySettingsConsumerHostConfiguration,
        requirement: MachineUpdateRestartHealthPlan.Requirement, registration: GatewayRegistrationIdentity?,
        release: SignedReleaseEvidence) throws -> GatewaySettingsRecoveryNativePolicy {
        try MachineUpdateConsumerHealthReleaseValidation.validate(release, host: host)
        let pins = try GatewaySettingsRecoveryNativePolicy(host: host, release: release)
        guard host.releaseBinding == requirement.binding, pins.consumer == requirement.code,
              pins.serviceUID == requirement.executionUID, host.role.codeRole == requirement.role,
              host.runtime.services.macID == requirement.binding.macID,
              host.runtime.services.accountID == requirement.binding.accountID else {
            throw MachineUpdateConsumerHealthChannelError.changedScope
        }
        switch host.role {
        case .transport:
            guard registration == nil, try requirement.publicKey == host.runtime.transportPublicKeyX963 else {
                throw MachineUpdateConsumerHealthChannelError.changedScope
            }
        case .gateway:
            guard registration == host.runtime.gateway else { throw MachineUpdateConsumerHealthChannelError.changedScope }
        }
        return pins
    }

    /// Transfers the retained restart scope to the pinned connection. The driver activates only when an exchange opens.
    static func nativeStartup(host: GatewaySettingsConsumerHostConfiguration,
        requirement: MachineUpdateRestartHealthPlan.Requirement, registration: GatewayRegistrationIdentity?,
        release: SignedReleaseEvidence, authorityReadinessRequest: Data? = nil, timeoutMilliseconds: UInt64 = 5000,
        verifyCurrent: @escaping @Sendable () throws -> Void,
        releaseScope: @escaping @Sendable () -> Void) throws -> MachineUpdateConsumerHealthChannel {
        var opened: NativeMachineUpdateConsumerHealthDriver?
        do {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try verifyCurrent()
            guard authorityReadinessRequest == nil || requirement.role == .notificationGateway else {
                throw MachineUpdateConsumerHealthChannelError.changedScope
            }
            let pins = try startupPeerPins(host: host, requirement: requirement, registration: registration, release: release)
            let local = try AuthoritySelfValidation.requirement(for: pins.authority)
            let peer = try XPCPeerPolicy(teamID: pins.consumer.teamID, componentIdentifier: pins.consumer.identifier,
                approvedCodeDirectoryHashes: [pins.consumer.codeDirectoryHash], expectedUserID: pins.serviceUID)
            let executable = host.bundlePath + "/" + InstalledAuthorityCommandConfiguration.executablePath
            let verify: @Sendable () throws -> Void = {
                guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
                try DynamicCodeValidation.validateSelf(requirement: local)
                guard try DynamicCodeValidation.selfPath() == executable else {
                    throw MachineUpdateConsumerHealthChannelError.changedScope
                }
                try verifyCurrent()
            }
            try verify()
            let clock = try AuthorityClock()
            let driver = NativeMachineUpdateConsumerHealthDriver(
                serviceName: try host.role.recoveryServiceName(accountID: requirement.binding.accountID), policy: peer)
            opened = driver
            return try Self(driver: driver, expectedHello: host.encoded, requirement: requirement, registration: registration,
                authorityReadinessRequest: authorityReadinessRequest, timeoutMilliseconds: timeoutMilliseconds,
                clock: { try clock.now() }, verifyCurrent: verify, release: releaseScope)
        } catch {
            opened?.close()
            releaseScope()
            throw error
        }
    }

    /// Injected drivers exercise ordering only. They grant no native peer, store or key access.
    /// Ownership transfers on success. If initialization throws, the caller closes the driver and releases its scope.
    init(driver: any MachineUpdateConsumerHealthDriver, expectedHello: Data,
        requirement: MachineUpdateRestartHealthPlan.Requirement, registration: GatewayRegistrationIdentity?,
        authorityInstalledReadiness: Bool = false, authorityReadinessRequest: Data? = nil, timeoutMilliseconds: UInt64 = 5000, clock: @escaping @Sendable () throws -> AuthorityMoment,
        verifyCurrent: @escaping @Sendable () throws -> Void = {}, release: @escaping @Sendable () -> Void = {}) throws {
        guard (1...60_000).contains(timeoutMilliseconds), !expectedHello.isEmpty, expectedHello.count <= 1_000_000 else {
            throw MachineUpdateConsumerHealthChannelError.changedScope
        }
        self.driver = driver; self.expectedHello = expectedHello; self.requirement = requirement
        self.verifyCurrent = verifyCurrent; self.release = release; timeout = timeoutMilliseconds
        self.authorityInstalledReadiness = authorityInstalledReadiness
        session = try .init(requirement: requirement, registration: registration, authorityInstalledReadiness: authorityInstalledReadiness, authorityReadinessRequest: authorityReadinessRequest, clock: clock, verifyCurrent: verifyCurrent)
    }
    deinit { timer?.cancel(); session.close(); if lifetime.close() { driver.close(); release() } }

    func execute() async throws -> MachineUpdateConsumerHealthProof {
        let opened = try await openScope()
        do {
            try opened.validate()
            let proof = opened.proof
            await opened.close(); try Task.checkCancellation(); return proof
        } catch { await opened.close(); throw error }
    }
    /// Issues the Root nonce before a Gateway exchange. This method grants no native readiness.
    func prepareAuthorityReadinessChallenge() throws -> Data {
        guard state == .new, authorityInstalledReadiness, preparedAuthorityRequest == nil else {
            throw MachineUpdateConsumerHealthChannelError.busy
        }
        try verifyCurrent(); try Task.checkCancellation()
        let request = try session.makeRequest(); preparedAuthorityRequest = request; return request
    }
    func openScope(authorityGatewayExchange: MachineUpdateConsumerHealthExchange? = nil) async throws -> MachineUpdateConsumerHealthConnectionScope {
        guard state == .new else { throw state == .closed ? MachineUpdateConsumerHealthChannelError.closed : .busy }
        do {
            try verifyCurrent(); try Task.checkCancellation(); state = .opening
            let lifetime = lifetime, driver = driver, release = release
            driver.start { [weak self, weak driver] in
                if lifetime.close() { driver?.close(); release() }
                Task { await self?.close() }
            }
            guard case .greeting(let version, let bytes) = try await perform(.hello),
                  version == Self.wireVersion, bytes == expectedHello else {
                throw MachineUpdateConsumerHealthChannelError.invalidReply
            }
            try driver.requirePeer(); try verifyCurrent(); try Task.checkCancellation()
            guard state == .opening, lifetime.ifOpen({}) else { throw MachineUpdateConsumerHealthChannelError.closed }
            state = .open
            guard authorityInstalledReadiness || authorityGatewayExchange == nil else {
                throw MachineUpdateConsumerHealthChannelError.changedScope
            }
            let request = try preparedAuthorityRequest ?? session.makeRequest()
            let wireRequest = try authorityInstalledReadiness
                ? MachineUpdateAuthorityReadinessRequest(challenge: request, gateway: authorityGatewayExchange).encoded : request
            guard case .response(let bytes) = try await perform(.check(wireRequest)), let bytes else {
                throw MachineUpdateConsumerHealthChannelError.invalidReply
            }
            if bytes == MachineUpdateGatewayRecoverySignal.bytes {
                guard requirement.role == .notificationGateway else { throw MachineUpdateConsumerHealthChannelError.invalidReply }
                try driver.requirePeer(); try verifyCurrent(); try Task.checkCancellation()
                throw MachineUpdateConsumerHealthChannelError.gatewayRecoveryRequired
            }
            let expected = requirement
            let proof = try session.accept(bytes, authenticatePeer: { actual in
                guard actual == expected else { throw MachineUpdateConsumerHealthChannelError.changedScope }
                try driver.requirePeer()
            })
            try driver.requirePeer(); try verifyCurrent(); try Task.checkCancellation()
            guard state == .open, lifetime.ifOpen({}) else { throw MachineUpdateConsumerHealthChannelError.closed }
            let verify = verifyCurrent
            return .init(proof: proof, exchange: .init(request: request, response: bytes), owner: self, verifyCurrent: {
                try lifetime.requireOpen { try driver.requirePeer(); try verify(); try driver.requirePeer() }
            }, retire: {
                if lifetime.close() { driver.close(); release() }
            })
        } catch { close(); throw error }
    }
    func close() {
        guard state != .closed else { return }
        state = .closed; session.close(); timer?.cancel(); timer = nil
        if lifetime.close() { driver.close(); release() }
        let old = pending; pending = nil; old?.continuation.resume(throwing: MachineUpdateConsumerHealthChannelError.closed)
    }
    private func perform(_ call: MachineUpdateConsumerHealthCall) async throws -> MachineUpdateConsumerHealthReply {
        try verifyCurrent(); try Task.checkCancellation()
        switch call {
        case .hello: guard state == .opening else { throw MachineUpdateConsumerHealthChannelError.closed }
        case .check: guard state == .open else { throw MachineUpdateConsumerHealthChannelError.closed }; try driver.requirePeer()
        }
        guard lifetime.ifOpen({}) else { close(); throw MachineUpdateConsumerHealthChannelError.closed }
        guard pending == nil else { throw MachineUpdateConsumerHealthChannelError.busy }
        let id = UUID(), lifetime = lifetime, driver = driver, release = release
        let result = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                timer = Task { [weak self, timeout] in
                    do { try await Task.sleep(for: .milliseconds(timeout)) } catch { return }
                    await self?.expire(id)
                }
                guard lifetime.ifOpen({
                    driver.invoke(call) { [weak self, weak driver] value in
                        if case .failed = value, lifetime.close() { driver?.close(); release() }
                        Task { await self?.complete(id, value) }
                    }
                }) else { close(); return }
            }
        } onCancel: { [weak self] in
            if lifetime.close() { driver.close(); release() }
            Task { await self?.close() }
        }
        try Task.checkCancellation()
        guard state != .closed, lifetime.ifOpen({}) else { close(); throw MachineUpdateConsumerHealthChannelError.closed }
        return result
    }
    private func complete(_ id: UUID, _ value: MachineUpdateConsumerHealthReply) {
        guard let pending, pending.id == id, state != .closed else { return }
        guard lifetime.ifOpen({}) else { close(); return }
        self.pending = nil; timer?.cancel(); timer = nil
        if case .failed = value { pending.continuation.resume(throwing: MachineUpdateConsumerHealthChannelError.closed); close() }
        else { pending.continuation.resume(returning: value) }
    }
    private func expire(_ id: UUID) {
        guard let old = pending, old.id == id else { return }
        pending = nil; close(); old.continuation.resume(throwing: MachineUpdateConsumerHealthChannelError.timedOut)
    }
}
