import Darwin
import Foundation
import Security

enum AuthorityMaintenanceClientError: Error, Equatable { case invalidState, cancelled, needsOwnerRecovery }
enum AuthorityMaintenanceClientReply: Sendable { case hello(UInt64), bytes(Data?) }
protocol AuthorityMaintenanceClientDriver: Sendable {
    func start(_ invalidated: @escaping @Sendable () -> Void)
    func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void)
    func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void)
    func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void)
    func observeIncarnation(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void)
    func close()
}
extension AuthorityMaintenanceClientDriver {
    func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) { reply(.bytes(nil)) }
    func observeIncarnation(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) { reply(.bytes(nil)) }
}
private final class NativeMaintenanceClient: AuthorityMaintenanceClientDriver, @unchecked Sendable {
    private let connection: NSXPCConnection, policy: XPCPeerPolicy
    init(accountID: Data, policy: XPCPeerPolicy) throws {
        self.policy = policy
        connection = NSXPCConnection(machServiceName: try AuthorityMaintenanceChannelScope.serviceName(accountID: accountID), options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: AuthorityMaintenanceXPCProtocol.self); policy.configure(connection)
    }
    func start(_ invalidated: @escaping @Sendable () -> Void) {
        connection.invalidationHandler = invalidated; connection.interruptionHandler = invalidated; connection.activate()
    }
    func hello(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        proxy(reply)?.hello { [self] in checked(.hello($0), reply) }
    }
    func exchange(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); proxy(reply)?.exchange(bytes) { [self] in checked(.bytes($0), reply) } }
        catch { reply(.bytes(nil)) }
    }
    func readGate(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); proxy(reply)?.readGate(bytes) { [self] in checked(.bytes($0), reply) } }
        catch { reply(.bytes(nil)) }
    }
    func observeIncarnation(_ bytes: Data, _ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); proxy(reply)?.observeIncarnation(bytes) { [self] in checked(.bytes($0), reply) } }
        catch { reply(.bytes(nil)) }
    }
    private func proxy(_ reply: @escaping @Sendable (AuthorityMaintenanceClientReply) -> Void) -> (any AuthorityMaintenanceXPCProtocol)? {
        guard let p = connection.remoteObjectProxyWithErrorHandler({ _ in reply(.bytes(nil)) }) as? any AuthorityMaintenanceXPCProtocol else {
            reply(.bytes(nil)); return nil
        }; return p
    }
    private func checked(_ value: AuthorityMaintenanceClientReply, _ reply: @Sendable (AuthorityMaintenanceClientReply) -> Void) {
        do { _ = try policy.verifyCredentials(connection); reply(value) } catch { reply(.bytes(nil)) }
    }
    func replacement(accountID: Data) throws -> NativeMaintenanceClient { try .init(accountID: accountID, policy: policy) }
    func captureProcess(job: InstalledAccountJobManifest, code: AuthorityCodeEntry) throws -> RuntimeJobProcessObservation {
        let expected = try XPCPeerPolicy(teamID: code.teamID, componentIdentifier: code.identifier,
            approvedCodeDirectoryHashes: [code.codeDirectoryHash], expectedUserID: 0)
        guard expected.requirement == policy.requirement else { throw RuntimePreparationError.changedScope }
        let peer = try policy.verifyCredentials(connection)
        let witness = try RuntimeJobProcessObservation.open(job: job, code: code, processID: peer.processID)
        guard try policy.verifyCredentials(connection) == peer, try !witness.hasExited() else { throw RuntimePreparationError.changedScope }
        return witness
    }
    func requireProcess(_ witness: RuntimeJobProcessObservation) throws {
        guard try policy.verifyCredentials(connection).processID == witness.processID, try !witness.hasExited() else {
            throw RuntimePreparationError.changedScope
        }
    }
    func close() { connection.invalidate() }
    deinit { close() }
}
/// Serializes ordinary-owner fixture access to its real drain and directory. Root cannot construct this boundary.
private final class MaintenanceOwnedDrainBoundary: @unchecked Sendable {
    private let lock = NSLock(), processID = getpid(), ownerUID = getuid()
    private let drain: UpdateDrainToken, directory: ReleaseDestinationLease
    private let accountID: Data, identity: PreparationFileIdentity
    init(drain: UpdateDrainToken, directory: ReleaseDestinationLease, accountID: Data, identity: PreparationFileIdentity) throws {
        try RuntimeMaintenanceOwnedControl.require()
        self.drain = drain; self.directory = directory; self.accountID = accountID; self.identity = identity
    }
    func validate() throws {
        guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
        try lock.withLock { try drain.validateAccountBoundary(directory: directory, accountID: accountID, expected: identity) }
    }
    func release() throws { try validate(); lock.withLock { drain.close() } }
}
private final class MaintenanceHealthyPendingReceipt: @unchecked Sendable {
    private let lock = NSLock()
    private var receipt: PreparationIntentStore.RuntimeMaintenanceTransition?
    func store(_ value: PreparationIntentStore.RuntimeMaintenanceTransition) throws {
        try lock.withLock { guard receipt == nil else { throw JournalLeaseError.invalidated }; receipt = value }
    }
    func require() throws -> PreparationIntentStore.RuntimeMaintenanceTransition {
        try lock.withLock { guard let receipt else { throw JournalLeaseError.invalidated }; return receipt }
    }
}
/// Serial access to one process-bound witness. The witness protocol remains non-Sendable.
private final class MaintenanceStartupPeer: @unchecked Sendable {
    private let witness: any RuntimeJobExitWitness
    private let check: @Sendable (any RuntimeJobExitWitness) throws -> Void
    private let lock = NSLock(), processID = getpid()
    init(_ witness: any RuntimeJobExitWitness, check: @escaping @Sendable (any RuntimeJobExitWitness) throws -> Void) {
        self.witness = witness; self.check = check
    }
    func requireLive() throws {
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        try lock.withLock { try check(witness) }
    }
    func accept(_ owner: RuntimeMaintenanceRestoration) throws {
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        try lock.withLock { try check(witness); try owner.acceptWitness(witness); try check(witness) }
    }
}
private final class MaintenanceClientLifetime: @unchecked Sendable {
    private let lock = NSRecursiveLock(); private var active = true, expected: UUID?
    private var delivered: AuthorityMaintenanceClientReply?, observed: (accountID: Data, incarnation: Data)?
    func close() { lock.withLock { active = false; expected = nil; delivered = nil; observed = nil } }
    /// Records the latest verified incarnation reply. An inactive lifetime records nothing.
    func observe(accountID: Data, incarnation: Data) -> Bool {
        lock.withLock { guard active else { return false }; observed = (accountID, incarnation); return true }
    }
    func hasObserved(accountID: Data, incarnation: Data) -> Bool {
        lock.withLock { active && observed?.accountID == accountID && observed?.incarnation == incarnation }
    }
    func invalidate() { lock.withLock { active = false } }
    func begin(_ id: UUID) -> Bool { lock.withLock { guard active else { return false }; expected = id; delivered = nil; return true } }
    func record(_ id: UUID, _ value: AuthorityMaintenanceClientReply, until deadline: ContinuousClock.Instant) -> Bool {
        lock.withLock { guard active, expected == id, delivered == nil, ContinuousClock.now < deadline else { return false }; delivered = value; return true }
    }
    func reply(_ id: UUID) -> AuthorityMaintenanceClientReply? { lock.withLock { expected == id ? delivered : nil } }
    func ifActive(_ body: () -> Void = {}) -> Bool { lock.withLock { guard active else { return false }; body(); return true } }
}

/// One Setup connection. Lost replies require recovery; only stagesPending permits bounded arm retries.
actor AuthorityMaintenanceXPCClient {
    private typealias Request = AuthorityMaintenanceChannelRequest
    private typealias Response = AuthorityMaintenanceChannelResponse
    private enum State { case new, greeted, open, armed, closed }
    private let driver: any AuthorityMaintenanceClientDriver, context: Request
    private let verify: @Sendable () throws -> Void, timeout: Duration, interval: Duration
    private let recoveryPhases: SetupRetainedInvocationReservation.RestorationPhases?
    private let ownedSupervisorControl: OwnedSupervisorPhaseControl?
    private var ownedSupervisorContext: OwnedSupervisorPhaseControl.RestorationContext?
    private var ownedSupervisorReconnectContext: OwnedSupervisorPhaseControl.ReconnectContext?
    fileprivate nonisolated let lifetime = MaintenanceClientLifetime()
    private var state = State.new, busy = false, cleanupUsed = false, binding: AuthorityMaintenanceBinding?
    private var pending: (UUID, CheckedContinuation<AuthorityMaintenanceClientReply, Error>)?, timer: Task<Void, Never>?
    init(context: AuthorityMaintenanceChannelRequest, authority: AuthorityCodeEntry, setup: AuthorityCodeEntry,
         release: SignedReleaseEvidence, recoveryPhases: SetupRetainedInvocationReservation.RestorationPhases? = nil) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try AuthorityMaintenanceChannelScope.validate(release, authority: authority, setup: setup)
        let policy = try XPCPeerPolicy(teamID: authority.teamID, componentIdentifier: authority.identifier,
            approvedCodeDirectoryHashes: [authority.codeDirectoryHash], expectedUserID: 0)
        let selfPolicy = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
            approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
        let pid = getpid()
        let verify: @Sendable () throws -> Void = {
            guard getpid() == pid, getuid() == 0, geteuid() == 0,
                  try DynamicCodeValidation.selfPath() == MachineBootstrap.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath else {
                throw RuntimePreparationError.changedScope
            }
            try DynamicCodeValidation.validateSelf(requirement: selfPolicy.requirement + " and info[\"RemozioSecurityGeneration\"] = \"\(setup.installedGeneration)\"")
        }
        try verify(); guard context.action == .open else { throw RuntimePreparationError.invalidRecord }
        self.context = context; self.verify = verify; self.recoveryPhases = recoveryPhases; ownedSupervisorControl = nil
        timeout = .seconds(5); interval = .milliseconds(250)
        driver = try NativeMaintenanceClient(accountID: context.accountID, policy: policy)
    }
    private init(context: Request, driver: any AuthorityMaintenanceClientDriver, timeout: Duration, interval: Duration,
        verify: @escaping @Sendable () throws -> Void,
        recoveryPhases: SetupRetainedInvocationReservation.RestorationPhases?, ownedSupervisorControl: OwnedSupervisorPhaseControl?) {
        self.context = context; self.driver = driver; self.timeout = timeout; self.interval = interval; self.verify = verify
        self.recoveryPhases = recoveryPhases; self.ownedSupervisorControl = ownedSupervisorControl
    }
    static func openOwned(context: AuthorityMaintenanceChannelRequest, driver: any AuthorityMaintenanceClientDriver,
        timeoutMilliseconds: UInt64 = 5000, intervalMilliseconds: UInt64 = 250,
        verify: @escaping @Sendable () throws -> Void = {},
        recoveryPhases: SetupRetainedInvocationReservation.RestorationPhases? = nil,
        ownedSupervisorControl: OwnedSupervisorPhaseControl? = nil) throws -> AuthorityMaintenanceXPCClient {
        guard getuid() > 0, getuid() == geteuid(), context.action == .open,
              (1...60_000).contains(timeoutMilliseconds), (1...1000).contains(intervalMilliseconds) else { throw JournalLeaseError.unsafeMetadata }
        let pid = getpid(), uid = getuid()
        return .init(context: context, driver: driver, timeout: .milliseconds(timeoutMilliseconds), interval: .milliseconds(intervalMilliseconds), verify: {
            guard getpid() == pid, getuid() == uid, geteuid() == uid else { throw JournalLeaseError.invalidated }; try verify()
        }, recoveryPhases: recoveryPhases, ownedSupervisorControl: ownedSupervisorControl)
    }
    deinit { lifetime.close(); timer?.cancel(); driver.close() }
    func start(until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceChannelResponse {
        guard state == .new else { throw AuthorityMaintenanceClientError.invalidState }; try enter(); defer { busy = false }
        try await greet(until: deadline); return try await openGreeted(until: deadline)
    }
    /// Healthy open on the connection that produced the proof. It sends no second hello and needs a new Authority epoch.
    func startObserved(_ proof: AuthorityMaintenanceIncarnationProof, stopped: AuthorityMaintenanceBinding,
        until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceChannelResponse {
        guard state == .greeted else { throw AuthorityMaintenanceClientError.invalidState }; try enter(); defer { busy = false }
        do {
            try proof.requireObserved(by: self)
            guard proof.accountID == context.accountID, stopped.accountID == context.accountID,
                  proof.incarnation != stopped.incarnation else { throw RuntimePreparationError.changedScope }
        } catch { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        let response = try await openGreeted(until: deadline)
        do {
            try proof.requireObserved(by: self)
            guard response.binding.incarnation == proof.incarnation else { throw RuntimePreparationError.changedScope }
        } catch { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        return response
    }
    private func openGreeted(until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceChannelResponse {
        let response = try await send(.open, until: deadline); binding = response.binding; if state != .closed { state = .open }; return response
    }
    private func greet(until deadline: ContinuousClock.Instant) async throws {
        guard case .hello(let version) = try await invoke(nil, until: deadline), version == AuthorityMaintenanceChannelScope.protocolVersion else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        if state == .new { state = .greeted }
    }
    /// Root native entry. The proof is read-only evidence from this connection's authenticated Authority.
    func observeIncarnationNative(until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceIncarnationProof {
        guard getuid() == 0, geteuid() == 0, driver is NativeMaintenanceClient else { throw JournalLeaseError.rootRequired }
        return try await observeIncarnation(until: deadline)
    }
    /// Ordinary-owner tests use the same sequence. Root cannot select a callback driver for this proof.
    func observeIncarnationOwned(until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceIncarnationProof {
        try RuntimeMaintenanceOwnedControl.require(); return try await observeIncarnation(until: deadline)
    }
    /// Sends hello first when needed, then one fresh challenge. Any failure retires the connection.
    private func observeIncarnation(until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceIncarnationProof {
        guard state != .closed else { throw AuthorityMaintenanceClientError.invalidState }; try enter(); defer { busy = false }
        if state == .new { try await greet(until: deadline) }
        do {
            var challenge = Data(count: 16)
            guard challenge.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else { throw RuntimePreparationError.invalidRecord }
            let q = try AuthorityMaintenanceIncarnationRequest(accountID: context.accountID, challenge: challenge)
            guard case .bytes(let bytes) = try await invoke(nil, incarnation: q, until: deadline), let bytes else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            let response = try AuthorityMaintenanceIncarnationResponse.decode(bytes, expected: q)
            guard state != .closed, response.accountID == context.accountID,
                  lifetime.observe(accountID: response.accountID, incarnation: response.incarnation) else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            return .init(accountID: response.accountID, incarnation: response.incarnation, observer: ObjectIdentifier(lifetime))
        } catch { finish(); throw (error as? AuthorityMaintenanceClientError) ?? .needsOwnerRecovery }
    }
    /// Reports the authenticated hold and admission separately. It never grants a completion capability.
    func probeUnboundGate(joined: SetupRetainedOrphanClaim.Joined, row: RuntimeMaintenanceWindowRecord,
        gate: PreparationFileIdentity, until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceUnboundGateResponse {
        if getuid() == 0 {
            guard geteuid() == 0, driver is NativeMaintenanceClient else { throw JournalLeaseError.rootRequired }
        } else { try RuntimeMaintenanceOwnedControl.require() }
        guard row.scope.authority.accountID == context.accountID, row.scope.installationID == context.installationID,
              row.id == context.attemptID, gate == context.gate, binding == nil else {
            throw RuntimePreparationError.changedScope
        }
        let proof = try await observeIncarnation(until: deadline)
        try enter(); defer { busy = false }
        do {
            try proof.requireObserved(by: self)
            let challenge = try joined.issueUnboundGateChallenge(row: row, gate: gate, probedIncarnation: proof.incarnation)
            let reply = try await invokeUnbound(try challenge.request.encoded, kind: .gate, until: deadline)
            try proof.requireObserved(by: self)
            let response = try AuthorityMaintenanceUnboundGateResponse.decode(reply)
            guard response.request == challenge.request, response.request.authorityIncarnation == proof.incarnation else {
                throw RuntimePreparationError.changedScope
            }
            try challenge.requireCurrent(joined: joined, row: row, gate: gate)
            return response
        } catch { finish(); throw error }
    }
    /// A release acknowledgement is not a gate observation. Busy and stop refusal remain distinct outcomes.
    func releaseUnbound(joined: SetupRetainedOrphanClaim.Joined, row: RuntimeMaintenanceWindowRecord,
        gate: PreparationFileIdentity, until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceUnboundReleaseResponse {
        if getuid() == 0 {
            guard geteuid() == 0, driver is NativeMaintenanceClient else { throw JournalLeaseError.rootRequired }
        } else { try RuntimeMaintenanceOwnedControl.require() }
        guard row.scope.authority.accountID == context.accountID, row.scope.installationID == context.installationID,
              row.id == context.attemptID, gate == context.gate, binding == nil else {
            throw RuntimePreparationError.changedScope
        }
        let proof = try await observeIncarnation(until: deadline)
        try enter(); defer { busy = false }
        do {
            try proof.requireObserved(by: self)
            let challenge = try joined.issueUnboundGateChallenge(row: row, gate: gate, probedIncarnation: proof.incarnation)
            let template = challenge.request
            let request = try AuthorityMaintenanceUnboundRequest(kind: .release,
                installationID: template.installationID, accountID: template.accountID, attemptID: template.attemptID,
                revision: template.revision, rowDigest: template.rowDigest, pendingRevision: template.pendingRevision,
                intentID: template.intentID, gate: template.gate, authorityIncarnation: template.authorityIncarnation,
                challenge: template.challenge)
            let reply = try await invokeUnbound(try request.encoded, kind: .release, until: deadline)
            try proof.requireObserved(by: self)
            let response = try AuthorityMaintenanceUnboundReleaseResponse.decode(reply)
            guard response.request == request, response.request.authorityIncarnation == proof.incarnation else {
                throw RuntimePreparationError.changedScope
            }
            try challenge.requireCurrent(joined: joined, row: row, gate: gate)
            return response
        } catch { finish(); throw error }
    }
    /// The native driver authenticates both replies. Owned drivers remain unavailable to root.
    func observeUnboundGate(joined: SetupRetainedOrphanClaim.Joined, row: RuntimeMaintenanceWindowRecord,
        gate: PreparationFileIdentity, until deadline: ContinuousClock.Instant) async throws -> VerifiedUnboundGateObservation {
        if getuid() == 0 {
            guard geteuid() == 0, driver is NativeMaintenanceClient else { throw JournalLeaseError.rootRequired }
        } else { try RuntimeMaintenanceOwnedControl.require() }
        guard row.scope.authority.accountID == context.accountID, row.scope.installationID == context.installationID,
              row.id == context.attemptID, gate == context.gate, binding == nil else {
            throw RuntimePreparationError.changedScope
        }
        let proof = try await observeIncarnation(until: deadline)
        try enter(); defer { busy = false }
        do {
            try proof.requireObserved(by: self)
            let challenge = try joined.issueUnboundGateChallenge(row: row, gate: gate, probedIncarnation: proof.incarnation)
            let bytes = try challenge.request.encoded
            let reply = try await invokeUnboundGate(bytes, until: deadline)
            try proof.requireObserved(by: self)
            let response = try AuthorityMaintenanceUnboundGateResponse.decode(reply)
            guard response.request == challenge.request, response.request.authorityIncarnation == proof.incarnation else {
                throw RuntimePreparationError.changedScope
            }
            try challenge.requireCurrent(joined: joined, row: row, gate: gate)
            _ = try response.completedGateReadback()
            return .init(challenge: challenge, response: response)
        } catch { finish(); throw error }
    }
    private func invokeUnboundGate(_ bytes: Data, until deadline: ContinuousClock.Instant) async throws -> Data {
        try await invokeUnbound(bytes, kind: .gate, until: deadline)
    }
    // This selects a driver method only. The routing slice chooses the actual selectors.
    // The current native Authority endpoint does not route unbound messages.
    private func invokeUnbound(_ bytes: Data, kind: AuthorityMaintenanceUnboundRequest.Kind,
        until deadline: ContinuousClock.Instant) async throws -> Data {
        try Task.checkCancellation()
        let expectedState = state, verify = self.verify
        if let recoveryPhases { try await recoveryPhases.run(verify) } else { try verify() }
        guard state == expectedState, state == .greeted, binding == nil, lifetime.ifActive(), ContinuousClock.now < deadline else {
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        let id = UUID(), end = min(deadline, .now.advanced(by: timeout))
        let result: AuthorityMaintenanceClientReply = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                guard lifetime.begin(id) else { finish(); return }
                timer = Task { [weak self] in
                    do { try await ContinuousClock().sleep(until: end) } catch { return }; await self?.expire(id)
                }
                let reply: @Sendable (AuthorityMaintenanceClientReply) -> Void = { [weak self, lifetime] value in
                    guard lifetime.record(id, value, until: end) else { return }; Task { await self?.received(id) }
                }
                guard lifetime.ifActive({
                    switch kind {
                    case .gate: driver.readGate(bytes, reply)
                    case .release: driver.exchange(bytes, reply)
                    }
                }) else { finish(); return }
            }
        } onCancel: { [weak self, lifetime, driver] in
            lifetime.close(); driver.close(); Task { await self?.close() }
        }
        try Task.checkCancellation()
        if let recoveryPhases { try await recoveryPhases.run(verify) } else { try verify() }
        guard state == expectedState, lifetime.ifActive(), lifetime.reply(id) != nil,
              case .bytes(let response) = result, let response else {
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        return response
    }
    func observe(until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceChannelResponse {
        guard state == .open else { throw AuthorityMaintenanceClientError.invalidState }; try enter(); defer { busy = false }
        return try await send(.observe, until: deadline)
    }
    func arm(until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceChannelResponse {
        guard state == .open else { throw AuthorityMaintenanceClientError.invalidState }; try enter(); defer { busy = false }
        while ContinuousClock.now < deadline {
            let response = try await send(.arm, until: deadline)
            if response.outcome == .applied { if state != .closed { state = .armed }; return response }
            do { try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: interval))) }
            catch { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        }
        // Cancellation is cleanup. Its bounded RPC can extend the original wait by up to five seconds.
        _ = try await send(.cancel, until: .now.advanced(by: timeout)); finish(.cancelled); throw AuthorityMaintenanceClientError.cancelled
    }
    func captureNativeStop(window: RuntimeMaintenanceWindowRecord, cohort: RuntimeMaintenanceAuthorityCohort,
        admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken, directory: ReleaseDestinationLease,
        until deadline: ContinuousClock.Instant, persistBinding: (@Sendable (AuthorityMaintenanceBinding) throws -> RuntimeMaintenanceWindowRecord)? = nil,
        persistBindingTransition: (@Sendable (AuthorityMaintenanceBinding) throws -> PreparationIntentStore.RuntimeMaintenanceTransition)? = nil, verifyOwner: @escaping @Sendable () throws -> Void) async throws -> RuntimeMaintenanceStopCapture {
        guard getuid() == 0, geteuid() == 0, let native = driver as? NativeMaintenanceClient else { throw JournalLeaseError.rootRequired }
        let configuration = try InstalledAuthorityCommandConfiguration.load(path: cohort.job.configurationPath)
        guard let code = configuration.codePolicy.entries.first(where: { $0.role == .authority && $0.active }) else { throw RuntimePreparationError.changedScope }
        return try await captureStop(window: window, cohort: cohort, admission: admission, drain: drain, directory: directory,
            configuration: configuration, until: deadline, capture: { try native.captureProcess(job: cohort.job, code: code) },
            requireProcess: { witness in
                guard let nativeWitness = witness as? RuntimeJobProcessObservation else { throw RuntimePreparationError.changedScope }
                try native.requireProcess(nativeWitness)
            }, verifyConfiguration: {
                guard try InstalledAuthorityCommandConfiguration.load(path: cohort.job.configurationPath).canonicalBytes == configuration.canonicalBytes else {
                    throw InstalledAuthorityCommandError.changedConfiguration
                }
            }, persistBinding: persistBinding, persistBindingTransition: persistBindingTransition, verifyOwner: verifyOwner)
    }
    /// Same capture sequence with ordinary-owner controls. Root cannot select its callbacks.
    func captureOwnedStop(window: RuntimeMaintenanceWindowRecord, cohort: RuntimeMaintenanceAuthorityCohort,
        admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken, directory: ReleaseDestinationLease,
        configuration: InstalledAuthorityCommandConfiguration, until deadline: ContinuousClock.Instant,
        capture: @Sendable () throws -> any RuntimeJobExitWitness, requireProcess: @Sendable (any RuntimeJobExitWitness) throws -> Void,
        persistBinding: (@Sendable (AuthorityMaintenanceBinding) throws -> RuntimeMaintenanceWindowRecord)? = nil,
        persistBindingTransition: (@Sendable (AuthorityMaintenanceBinding) throws -> PreparationIntentStore.RuntimeMaintenanceTransition)? = nil, verifyOwner: @escaping @Sendable () throws -> Void = {}) async throws -> RuntimeMaintenanceStopCapture {
        try RuntimeMaintenanceOwnedControl.require()
        return try await captureStop(window: window, cohort: cohort, admission: admission, drain: drain, directory: directory,
            configuration: configuration, until: deadline, capture: capture, requireProcess: requireProcess,
            verifyConfiguration: {}, persistBinding: persistBinding, persistBindingTransition: persistBindingTransition, verifyOwner: verifyOwner)
    }
    /// The native driver captures the original process. Copied replies cannot construct this permit.
    private func captureStop(window: RuntimeMaintenanceWindowRecord, cohort: RuntimeMaintenanceAuthorityCohort,
        admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken, directory: ReleaseDestinationLease,
        configuration: InstalledAuthorityCommandConfiguration, until deadline: ContinuousClock.Instant,
        capture: @Sendable () throws -> any RuntimeJobExitWitness, requireProcess: @Sendable (any RuntimeJobExitWitness) throws -> Void,
        verifyConfiguration: @escaping @Sendable () throws -> Void,
        persistBinding: (@Sendable (AuthorityMaintenanceBinding) throws -> RuntimeMaintenanceWindowRecord)? = nil,
        persistBindingTransition: (@Sendable (AuthorityMaintenanceBinding) throws -> PreparationIntentStore.RuntimeMaintenanceTransition)? = nil,
        verifyOwner: @escaping @Sendable () throws -> Void) async throws -> RuntimeMaintenanceStopCapture {
        guard (persistBinding == nil) != (persistBindingTransition == nil), state == .open,
              window.phase == .draining, window.operation == .notStarted, window.service == .notStopped,
              context.attemptID == window.id, context.revision == window.revision,
              context.accountID == window.scope.authority.accountID, cohort.accountID == context.accountID,
              cohort.targetAccountID == window.scope.target.accountID, context.installationID == window.scope.installationID,
              context.gate == cohort.accountIdentity, deadline > .now else {
            throw RuntimePreparationError.changedScope
        }
        func check() throws {
            try verifyOwner(); try admission.validateMachineBoundary(directory: directory, expected: cohort.machineIdentity)
            try drain.validateAccountBoundary(directory: directory, accountID: cohort.accountID, expected: cohort.accountIdentity)
        }
        try check(); try verifyConfiguration()
        guard configuration.jobPlacement == .systemAccount, configuration.label == cohort.job.declaration.label,
              configuration.command.accountID == cohort.accountID, configuration.command.macID == window.scope.macID,
              configuration.command.callerUID == window.scope.authority.ownerUID,
              configuration.installationID == window.scope.installationID, configuration.releaseDigest == window.scope.releaseDigest,
              let code = configuration.codePolicy.entries.first(where: { $0.role == .authority && $0.active }) else {
            throw RuntimePreparationError.changedScope
        }
        let witness = try capture()
        let saved: RuntimeMaintenanceWindowRecord
        let bindingTransition: PreparationIntentStore.RuntimeMaintenanceTransition?
        do {
            guard let binding else { throw RuntimePreparationError.changedScope }
            if let persistBindingTransition {
                let receipt = try persistBindingTransition(binding)
                saved = receipt.record; bindingTransition = receipt
            } else {
                guard let persistBinding else { throw RuntimePreparationError.changedScope }
                saved = try persistBinding(binding); bindingTransition = nil
            }
            try saved.requireReplacing(window)
            guard saved.shutdownBinding == binding, saved == (try window.retainingShutdownBinding(binding, revision: saved.revision)) else {
                throw RuntimePreparationError.changedScope
            }
            try check(); try verifyConfiguration(); try requireProcess(witness)
        } catch { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        while true {
            try check(); let response = try await observe(until: deadline); try check()
            if response.work?.allowsMaintenanceStop == true { break }
            guard ContinuousClock.now < deadline else { throw AuthorityMaintenanceClientError.cancelled }
            try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: interval)))
        }
        let response = try await arm(until: deadline)
        do {
            try check(); try verifyConfiguration(); try requireProcess(witness)
            guard response.outcome == .applied, response.work?.allowsMaintenanceStop == true else {
                throw AuthorityMaintenanceClientError.cancelled
            }
            let marker = try AuthorityMaintenanceCloseMarker(binding: response.binding, macID: window.scope.macID,
                installationID: configuration.installationID, releaseDigest: configuration.releaseDigest,
                codeHash: code.codeDirectoryHash, directoryID: window.scope.authority.directoryID,
                ownerUID: window.scope.authority.ownerUID, gate: context.gate)
            return .init(window: saved, cohort: cohort, marker: marker, witness: witness, configuration: configuration,
                bindingTransition: bindingTransition,
                verifyOwner: verifyOwner, verifyConfiguration: verifyConfiguration)
        } catch {
            do { try await release(until: .now.advanced(by: timeout)) }
            catch { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            throw error
        }
    }
    func release(_ target: AuthorityMaintenanceBinding? = nil, reopen: Bool = false,
                 until deadline: ContinuousClock.Instant) async throws {
        guard state == .open || state == .armed else { throw AuthorityMaintenanceClientError.invalidState }; try enter(); defer { busy = false }
        guard target == nil || target?.incarnation == binding?.incarnation else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        _ = try await send(reopen ? .reopen : .cancel, target: target, until: deadline); finish(.cancelled)
    }
    typealias CleanupRecord = RuntimeMaintenanceWindowRecord
    typealias CleanupCommit = @Sendable (CleanupRecord, CleanupRecord) throws -> PreparationIntentStore.RuntimeMaintenanceTransition
    /// One pre-stop cleanup. The real writer must confirm each exact commit before another native action.
    func cancelAndReopenNative(window: CleanupRecord, drain: UpdateDrainToken, directory: ReleaseDestinationLease,
        until deadline: ContinuousClock.Instant, persist: @escaping CleanupCommit) async throws -> CleanupRecord {
        guard getuid() == 0, geteuid() == 0, let native = driver as? NativeMaintenanceClient else { throw JournalLeaseError.rootRequired }
        return try await cancelAndReopen(window: window, drain: drain, directory: directory, until: deadline,
            makeDriver: { try native.replacement(accountID: window.scope.authority.accountID) }, persist: { next, previous in
                let receipt = try persist(next, previous)
                try receipt.requireReplacement(next, replacing: previous); return receipt.record
            })
    }
    /// Ordinary-owner tests use the same ordering. Root cannot select callback drivers or record-only persistence.
    func cancelAndReopenOwned(window: CleanupRecord, drain: UpdateDrainToken, directory: ReleaseDestinationLease,
        until deadline: ContinuousClock.Instant, makeDriver: @escaping @Sendable () throws -> any AuthorityMaintenanceClientDriver,
        persist: @escaping @Sendable (CleanupRecord, CleanupRecord) throws -> CleanupRecord) async throws -> CleanupRecord {
        try RuntimeMaintenanceOwnedControl.require()
        return try await cancelAndReopen(window: window, drain: drain, directory: directory, until: deadline,
            makeDriver: makeDriver, persist: persist)
    }
    private func cancelAndReopen(window: CleanupRecord, drain: UpdateDrainToken, directory: ReleaseDestinationLease,
        until deadline: ContinuousClock.Instant, makeDriver: @escaping @Sendable () throws -> any AuthorityMaintenanceClientDriver,
        persist: @escaping @Sendable (CleanupRecord, CleanupRecord) throws -> CleanupRecord) async throws -> CleanupRecord {
        guard !cleanupUsed, !busy else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        cleanupUsed = true
        guard window.purpose == .retainedRuntime, window.phase == .draining, window.operation == .notStarted,
              window.service == .notStopped, let target = window.shutdownBinding, target == binding,
              target.accountID == context.accountID, window.id == context.attemptID,
              window.scope.installationID == context.installationID else {
            finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        if state == .open || state == .armed { try? await release(until: min(deadline, .now.advanced(by: timeout))) }
        finish()
        let pending: CleanupRecord
        do {
            try verify(); try drain.validateAccountBoundary(directory: directory, accountID: context.accountID, expected: context.gate)
            pending = try .init(id: window.id, revision: AccountPreparationIntent.randomID(), purpose: window.purpose,
                scope: window.scope, phase: .reopenPending, shutdownBinding: target)
            try pending.requireReplacing(window)
            guard try persist(pending, window) == pending else { throw RuntimePreparationError.changedScope }
        } catch { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        drain.close()
        var restorationCommitAttempted = false
        do {
            let q = try Request(action: .open, accountID: context.accountID, attemptID: context.attemptID,
                revision: pending.revision, installationID: context.installationID, gate: context.gate,
                binding: nil, challenge: AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID())
            let recovery = AuthorityMaintenanceXPCClient(context: q, driver: try makeDriver(), timeout: timeout, interval: interval,
                verify: verify, recoveryPhases: nil, ownedSupervisorControl: nil)
            // This joined task is independent of the cancelled operation. All three RPCs keep the caller's cleanup deadline.
            let readback = try await Task { try await recovery.reopenSaved(target, until: deadline) }.value
            guard readback.hold == .released, readback.admission == .available else { throw RuntimePreparationError.changedScope }
            let restored = try CleanupRecord(id: pending.id, revision: AccountPreparationIntent.randomID(), purpose: pending.purpose,
                scope: pending.scope, phase: .restored, gate: readback)
            try restored.requireReplacing(pending)
            restorationCommitAttempted = true
            guard try persist(restored, pending) == restored else { throw RuntimePreparationError.changedScope }
            return restored
        } catch {
            if !restorationCommitAttempted {
                if let failed = try? CleanupRecord(id: pending.id, revision: AccountPreparationIntent.randomID(), purpose: pending.purpose,
                    scope: pending.scope, phase: .needsOwnerRecovery, failure: .admissionUnconfirmed, shutdownBinding: target) {
                    _ = try? persist(failed, pending)
                }
            }
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
    }
    private func reopenSaved(_ target: AuthorityMaintenanceBinding, until deadline: ContinuousClock.Instant) async throws -> CleanupRecord.GateReadback {
        guard state == .new else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        defer { finish() }
        try await greet(until: deadline); return try await reopenGreeted(target, until: deadline)
    }
    /// Same-epoch reopen of the saved target on the connection that produced the proof. It sends no second hello.
    /// The client context must carry the pending cleanup revision, as the replacement recovery client does in cancelAndReopen.
    func reopenSavedObserved(_ proof: AuthorityMaintenanceIncarnationProof, target: AuthorityMaintenanceBinding,
        until deadline: ContinuousClock.Instant) async throws -> CleanupRecord.GateReadback {
        guard state == .greeted else { throw AuthorityMaintenanceClientError.invalidState }; try enter()
        defer { busy = false; finish() }
        do {
            try proof.requireObserved(by: self)
            guard proof.accountID == context.accountID, target.accountID == context.accountID, target.attemptID == context.attemptID,
                  proof.incarnation == target.incarnation else { throw RuntimePreparationError.changedScope }
        } catch { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        return try await reopenGreeted(target, until: deadline)
    }
    private func reopenGreeted(_ target: AuthorityMaintenanceBinding, until deadline: ContinuousClock.Instant) async throws -> CleanupRecord.GateReadback {
        guard state == .greeted else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        binding = target; state = .open
        _ = try await send(.reopen, target: target, until: deadline)
        return try await readReleasedGate(target, revision: context.revision,
            incarnation: target.incarnation, requirePeerLive: {}, until: deadline)
    }
    private func readReleasedGate(_ target: AuthorityMaintenanceBinding, revision: Data, incarnation: Data,
        requirePeerLive: @escaping @Sendable () throws -> Void,
        phases: SetupRetainedInvocationReservation.RestorationPhases? = nil,
        until deadline: ContinuousClock.Instant) async throws -> CleanupRecord.GateReadback {
        while ContinuousClock.now < deadline {
            if let phases { try await restorationPhase(phases, state: .open, binding: binding, boundary: .gateBefore, requirePeerLive) }
            else { try requirePeerLive() }
            let q = try AuthorityMaintenanceGateRequest(accountID: context.accountID, attemptID: context.attemptID,
                revision: revision, installationID: context.installationID, gate: context.gate,
                target: target, challenge: AccountPreparationIntent.randomID())
            guard case .bytes(let bytes) = try await invoke(nil, gate: q, until: deadline), let bytes else {
                throw AuthorityMaintenanceClientError.needsOwnerRecovery
            }
            if let phases { try await phases.run(controlled(.gateAfter, requirePeerLive)) }
            else { try requirePeerLive() }
            let result = try AuthorityMaintenanceGateResponse.decode(bytes, expected: q).readback(expectedIncarnation: incarnation)
            guard result.hold == .released else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            if result.admission == .available { return result }
            guard result.admission == .busy else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: interval)))
        }
        throw AuthorityMaintenanceClientError.needsOwnerRecovery
    }

    /// The owner proves closed stores and one native registration. Only its receipt can release the existing drain.
    /// Missing Root or native transport is a usage error. It writes no recovery row.
    func restoreHealthyNative(owner: RuntimeMaintenanceRestoration, until deadline: ContinuousClock.Instant,
        persist: @escaping CleanupCommit) async throws -> CleanupRecord {
        guard getuid() == 0, geteuid() == 0, let native = driver as? NativeMaintenanceClient else { throw JournalLeaseError.rootRequired }
        try requireRestorationContext(owner)
        let pendingReceipt = MaintenanceHealthyPendingReceipt()
        return try await restoreHealthy(window: owner.window, until: deadline,
            makeDriver: { try native.replacement(accountID: owner.window.scope.authority.accountID) },
            verifyScope: { try owner.validateBeforePending() }, preparePeer: { candidate in
                guard let candidate = candidate as? NativeMaintenanceClient else { throw RuntimePreparationError.changedScope }
                try owner.acceptWitness(candidate.captureProcess(job: owner.job, code: owner.code))
            }, requirePeerLive: { try owner.requireWitnessLive() }, makePending: { try owner.pendingRecord(binding: $0) },
            releaseDrain: { _ in try owner.releaseDrain(after: pendingReceipt.require()) },
            recoverRestoring: { try owner.commitOwnerRecovery($0) }, persist: { next, previous in
                let receipt = try persist(next, previous); try receipt.requireReplacement(next, replacing: previous)
                if next.phase == .reopenPending { try pendingReceipt.store(receipt) }
                return receipt.record
            })
    }
    /// Checks the exact owner request before selecting any connection or issuing any RPC.
    private func requireRestorationContext(_ owner: RuntimeMaintenanceRestoration) throws {
        do {
            guard try owner.openRequest(challenge: context.challenge) == context else { throw RuntimePreparationError.changedScope }
        } catch {
            try? owner.commitOwnerRecovery(.changedScope); finish()
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
    }
    /// Exercises the native owner's post-construction API with ordinary-owner process controls.
    /// Root cannot use an injected driver, witness, or record-only writer.
    func restoreHealthyOwned(owner: RuntimeMaintenanceRestoration, until deadline: ContinuousClock.Instant,
        makeDriver: @escaping @Sendable () throws -> any AuthorityMaintenanceClientDriver,
        capturePeer: @escaping @Sendable (any AuthorityMaintenanceClientDriver) throws -> any RuntimeJobExitWitness,
        persist: @escaping @Sendable (CleanupRecord, CleanupRecord) throws -> CleanupRecord) async throws -> CleanupRecord {
        try RuntimeMaintenanceOwnedControl.require(); try requireRestorationContext(owner)
        return try await restoreHealthy(window: owner.window, until: deadline, makeDriver: makeDriver,
            verifyScope: { try owner.validateBeforePending() }, preparePeer: { driver in
                try owner.acceptWitness(capturePeer(driver))
            }, requirePeerLive: { try owner.requireWitnessLive() }, makePending: { try owner.pendingRecord(binding: $0) },
            releaseDrain: { try owner.releaseOwnedDrain(after: $0) }, recoverRestoring: { try owner.commitOwnerRecovery($0) },
            persist: persist)
    }
    /// Owned controls exercise the ordering. They cannot grant native restoration or select system-domain callbacks.
    func restoreHealthyOwned(window: CleanupRecord, drain: UpdateDrainToken, directory: ReleaseDestinationLease,
        until deadline: ContinuousClock.Instant, makeDriver: @escaping @Sendable () throws -> any AuthorityMaintenanceClientDriver,
        verifyScope: @escaping @Sendable () throws -> Void,
        preparePeer: @escaping @Sendable (any AuthorityMaintenanceClientDriver) async throws -> Void,
        requirePeerLive: @escaping @Sendable () throws -> Void,
        makePending: (@Sendable (CleanupRecord, AuthorityMaintenanceBinding) throws -> CleanupRecord)? = nil,
        recoverRestoring: (@Sendable (CleanupRecord.Failure) throws -> Void)? = nil,
        persist: @escaping @Sendable (CleanupRecord, CleanupRecord) throws -> CleanupRecord) async throws -> CleanupRecord {
        try RuntimeMaintenanceOwnedControl.require()
        let ownedDrain = try MaintenanceOwnedDrainBoundary(drain: drain, directory: directory,
            accountID: window.scope.authority.accountID, identity: context.gate)
        return try await restoreHealthy(window: window, until: deadline, makeDriver: makeDriver, verifyScope: {
            try verifyScope(); try ownedDrain.validate()
        }, preparePeer: preparePeer, requirePeerLive: requirePeerLive, makePending: { binding in
            if let makePending { return try makePending(window, binding) }
            return try CleanupRecord(id: window.id, revision: AccountPreparationIntent.randomID(), purpose: window.purpose,
                scope: window.scope, phase: .reopenPending, operation: window.operation, service: .healthy, shutdownBinding: window.shutdownBinding)
        }, releaseDrain: { _ in try ownedDrain.release() }, recoverRestoring: { failure in
            if let recoverRestoring { try recoverRestoring(failure); return }
            let failed = try CleanupRecord(id: window.id, revision: AccountPreparationIntent.randomID(), purpose: window.purpose,
                scope: window.scope, phase: .needsOwnerRecovery, operation: window.operation, service: window.service,
                failure: failure, shutdownBinding: window.shutdownBinding)
            guard try persist(failed, window) == failed else { throw RuntimePreparationError.changedScope }
        }, persist: persist)
    }
    private func restoreHealthy(window: CleanupRecord,
        until deadline: ContinuousClock.Instant, makeDriver: @escaping @Sendable () throws -> any AuthorityMaintenanceClientDriver,
        verifyScope: @escaping @Sendable () throws -> Void,
        preparePeer: @escaping @Sendable (any AuthorityMaintenanceClientDriver) async throws -> Void,
        requirePeerLive: @escaping @Sendable () throws -> Void,
        makePending: @escaping @Sendable (AuthorityMaintenanceBinding) throws -> CleanupRecord,
        releaseDrain: @escaping @Sendable (CleanupRecord) throws -> Void,
        recoverRestoring: @escaping @Sendable (CleanupRecord.Failure) throws -> Void,
        persist: @escaping @Sendable (CleanupRecord, CleanupRecord) throws -> CleanupRecord) async throws -> CleanupRecord {
        guard state == .new, !cleanupUsed, !busy else {
            try? recoverRestoring(.changedScope); finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        cleanupUsed = true; busy = true; defer { busy = false; finish() }
        guard window.purpose == .retainedRuntime, window.phase == .restoring, let stopped = window.shutdownBinding,
              context.accountID == window.scope.authority.accountID, context.attemptID == window.id,
              context.revision == window.revision, context.installationID == window.scope.installationID else {
            try? recoverRestoring(.changedScope); throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        var current = window, attemptedCommit = false, pendingWriteOwned = false
        var connection: AuthorityMaintenanceXPCClient?
        do {
            func beforePending() throws {
                try verify(); try verifyScope()
            }
            try beforePending()
            var opened: Response?
            while ContinuousClock.now < deadline {
                try beforePending()
                let candidateDriver = try makeDriver()
                let candidate = AuthorityMaintenanceXPCClient(context: context, driver: candidateDriver,
                    timeout: timeout, interval: interval, verify: verify, recoveryPhases: nil, ownedSupervisorControl: nil)
                let response: Response
                do { response = try await candidate.start(until: deadline) }
                catch {
                    await candidate.close(); try beforePending()
                    try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: interval)))
                    continue
                }
                guard response.outcome == .applied, response.binding.incarnation != stopped.incarnation else {
                    await candidate.close(); throw RuntimePreparationError.changedScope
                }
                do { try beforePending(); try await preparePeer(candidateDriver); try requirePeerLive(); try beforePending() }
                catch { await candidate.close(); throw error }
                connection = candidate; opened = response; break
            }
            guard let connection, let opened else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            try requirePeerLive(); try beforePending()
            let pending = try makePending(opened.binding)
            pendingWriteOwned = true
            try pending.requireReplacing(window)
            guard pending.phase == .reopenPending, pending.service == .healthy,
                  pending.operation == window.operation, pending.shutdownBinding == stopped else { throw RuntimePreparationError.changedScope }
            attemptedCommit = true
            guard try persist(pending, window) == pending else { throw RuntimePreparationError.changedScope }
            current = pending; attemptedCommit = false
            try requirePeerLive(); try releaseDrain(pending)
            let readback = try await connection.reopenHealthyCandidate(opened.binding, pending: pending,
                stopped: stopped, requirePeerLive: requirePeerLive, until: deadline)
            try requirePeerLive()
            let restored = try CleanupRecord(id: pending.id, revision: AccountPreparationIntent.randomID(), purpose: pending.purpose,
                scope: pending.scope, phase: .restored, operation: pending.operation, service: .healthy, gate: readback)
            try restored.requireReplacing(pending)
            attemptedCommit = true
            guard try persist(restored, pending) == restored else { throw RuntimePreparationError.changedScope }
            await connection.close(); return restored
        } catch {
            if let connection { await connection.close() }
            if !attemptedCommit {
                let failure: CleanupRecord.Failure = current.phase == .reopenPending ? .admissionUnconfirmed : .healthFailed
                if current.phase == .restoring && !pendingWriteOwned { try? recoverRestoring(failure) }
                else if let failed = try? CleanupRecord(id: current.id, revision: AccountPreparationIntent.randomID(), purpose: current.purpose,
                    scope: current.scope, phase: .needsOwnerRecovery, operation: current.operation, service: current.service,
                    failure: failure, shutdownBinding: stopped) { _ = try? persist(failed, current) }
            }
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
    }
    struct OwnedSupervisorPhaseControl: Sendable {
        enum Boundary: String, CaseIterable, Sendable {
            case afterProbe, openRequest, verifyBeforeOpen, healthyBinding, validateBeforePending, capturePeer
            case preparePending, persistPending, releaseDrain, beforeReopen, afterReopen, gateBefore, gateAfter
            case peerBeforeRestored, persistRestored, reconnectValidation, reconnectPending, reconnectRelease
            case beforeRPCDispatch, beforeRPCVerify, afterRPCVerify
        }
        enum RPC: String, CaseIterable, Sendable { case hello, incarnation, open, reopen, gate, other }
        struct RestorationContext: Sendable {
            let proof: AuthorityMaintenanceIncarnationProof, owner: RuntimeMaintenanceRestoration
        }
        struct ReconnectContext: Sendable {
            let proof: AuthorityMaintenanceIncarnationProof, custody: RuntimeMaintenanceStartupRecovery.Custody
        }
        struct Event: Sendable {
            let boundary: Boundary, rpc: RPC?, client: AuthorityMaintenanceXPCClient
            let restoration: RestorationContext?, reconnect: ReconnectContext?
        }
        private let body: @Sendable (Event) throws -> Void
        init(_ body: @escaping @Sendable (Event) throws -> Void) throws {
            try RuntimeMaintenanceOwnedControl.require(); self.body = body
        }
        fileprivate func visit(_ boundary: Boundary, rpc: RPC? = nil, client: AuthorityMaintenanceXPCClient,
            restoration: RestorationContext? = nil, reconnect: ReconnectContext? = nil) throws {
            try RuntimeMaintenanceOwnedControl.require()
            try body(.init(boundary: boundary, rpc: rpc, client: client, restoration: restoration, reconnect: reconnect))
        }
    }
    private func controlled<Value: Sendable>(_ boundary: OwnedSupervisorPhaseControl.Boundary,
        rpc: OwnedSupervisorPhaseControl.RPC? = nil,
        _ body: @escaping @Sendable () throws -> Value) -> @Sendable () throws -> Value {
        let control = ownedSupervisorControl, restoration = ownedSupervisorContext, reconnect = ownedSupervisorReconnectContext
        return { try control?.visit(boundary, rpc: rpc, client: self, restoration: restoration, reconnect: reconnect); return try body() }
    }
    struct OwnedRestorationPhaseControl: Sendable {
        enum Boundary: Int, CaseIterable, Equatable, Sendable { case beforePending, pendingWrite, drainRelease }
        enum Scope: Sendable {
            case healthy(RuntimeMaintenanceRestoration)
            case reconnect(RuntimeMaintenanceStartupRecovery.ExplicitReconnect)
        }
        struct Event: Sendable {
            let boundary: Boundary, client: AuthorityMaintenanceXPCClient
            let proof: AuthorityMaintenanceIncarnationProof, scope: Scope
        }
        private let body: @Sendable (Event) throws -> Void
        init(_ body: @escaping @Sendable (Event) throws -> Void) throws {
            try RuntimeMaintenanceOwnedControl.require(); self.body = body
        }
        fileprivate func visit(_ boundary: Boundary, client: AuthorityMaintenanceXPCClient,
            proof: AuthorityMaintenanceIncarnationProof, scope: Scope) throws {
            try RuntimeMaintenanceOwnedControl.require()
            try body(.init(boundary: boundary, client: client, proof: proof, scope: scope))
        }
    }
    /// Only a supplied phase runner suspends. The path without it executes each body directly on this actor.
    private func restorationPhase<Value: Sendable>(_ phases: SetupRetainedInvocationReservation.RestorationPhases,
        state expected: State, binding expectedBinding: AuthorityMaintenanceBinding?,
        boundary: OwnedSupervisorPhaseControl.Boundary? = nil,
        _ body: @escaping @Sendable () throws -> Value) async throws -> Value {
        try Task.checkCancellation()
        guard cleanupUsed, !busy, state == expected, binding == expectedBinding, lifetime.ifActive() else {
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        busy = true; defer { busy = false }
        let lifetime = self.lifetime, control = ownedSupervisorControl, restoration = ownedSupervisorContext,
            reconnect = ownedSupervisorReconnectContext
        let result = try await phases.run {
            if let boundary { try control?.visit(boundary, client: self, restoration: restoration, reconnect: reconnect) }
            guard lifetime.ifActive() else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            return try body()
        }
        try Task.checkCancellation()
        guard cleanupUsed, busy, state == expected, binding == expectedBinding, lifetime.ifActive() else {
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        return result
    }
    /// Completes healthy restoration on the exact native connection that produced the incarnation proof.
    func restoreStartupHealthyNative(_ proof: AuthorityMaintenanceIncarnationProof, owner: RuntimeMaintenanceRestoration,
        until deadline: ContinuousClock.Instant, persist: @escaping CleanupCommit,
        phases: SetupRetainedInvocationReservation.RestorationPhases? = nil) async throws -> CleanupRecord {
        guard getuid() == 0, geteuid() == 0, let native = driver as? NativeMaintenanceClient else { throw JournalLeaseError.rootRequired }
        let receipts = MaintenanceHealthyPendingReceipt()
        return try await restoreStartupHealthy(proof, owner: owner, until: deadline, capturePeer: {
            try native.captureProcess(job: owner.job, code: owner.code)
        }, requirePeerLive: { witness in
            guard let witness = witness as? RuntimeJobProcessObservation else { throw RuntimePreparationError.changedScope }
            try native.requireProcess(witness)
        }, releaseDrain: { _ in try owner.releaseDrain(after: receipts.require()) }, persist: { next, previous in
            let receipt = try persist(next, previous); try receipt.requireReplacement(next, replacing: previous)
            if next.phase == .reopenPending { try receipts.store(receipt) }; return receipt.record
        }, phases: phases)
    }
    /// Root cannot inject a driver, process witness, or record-only writer.
    func restoreStartupHealthyOwned(_ proof: AuthorityMaintenanceIncarnationProof, owner: RuntimeMaintenanceRestoration,
        capturePeer: @escaping @Sendable () throws -> any RuntimeJobExitWitness,
        requirePeerLive: @escaping @Sendable (any RuntimeJobExitWitness) throws -> Void,
        afterProbe: @escaping @Sendable () -> Void = {}, until deadline: ContinuousClock.Instant,
        persist: @escaping @Sendable (CleanupRecord, CleanupRecord) throws -> CleanupRecord,
        phases: SetupRetainedInvocationReservation.RestorationPhases? = nil,
        ownedPhaseControl: OwnedRestorationPhaseControl? = nil) async throws -> CleanupRecord {
        try RuntimeMaintenanceOwnedControl.require()
        return try await restoreStartupHealthy(proof, owner: owner, afterProbe: afterProbe, until: deadline,
            capturePeer: capturePeer, requirePeerLive: requirePeerLive,
            releaseDrain: { try owner.releaseOwnedDrain(after: $0) }, persist: persist, phases: phases, ownedPhaseControl: ownedPhaseControl)
    }
    private func restoreStartupHealthy(_ proof: AuthorityMaintenanceIncarnationProof, owner: RuntimeMaintenanceRestoration,
        afterProbe: @escaping @Sendable () -> Void = {},
        until deadline: ContinuousClock.Instant,
        capturePeer: @escaping @Sendable () throws -> any RuntimeJobExitWitness,
        requirePeerLive: @escaping @Sendable (any RuntimeJobExitWitness) throws -> Void,
        releaseDrain: @escaping @Sendable (CleanupRecord) throws -> Void,
        persist: @escaping @Sendable (CleanupRecord, CleanupRecord) throws -> CleanupRecord,
        phases: SetupRetainedInvocationReservation.RestorationPhases?,
        ownedPhaseControl: OwnedRestorationPhaseControl? = nil) async throws -> CleanupRecord {
        let installedContext = ownedSupervisorControl != nil && ownedSupervisorContext == nil
        if installedContext { ownedSupervisorContext = .init(proof: proof, owner: owner) }
        defer { if installedContext { ownedSupervisorContext = nil } }
        if let phases { try await phases.run(controlled(.afterProbe) { afterProbe() }) }
        else { afterProbe() }
        try Task.checkCancellation()
        let expectedContext = context
        do {
            let actualContext: AuthorityMaintenanceChannelRequest
            if let phases { actualContext = try await phases.run(controlled(.openRequest) { try owner.openRequest(challenge: expectedContext.challenge) }) }
            else { actualContext = try owner.openRequest(challenge: expectedContext.challenge) }
            guard actualContext == expectedContext else {
                throw RuntimePreparationError.changedScope
            }
        } catch {
            if let phases { try? await phases.cleanup { try owner.commitOwnerRecovery(.changedScope) } }
            else { try? owner.commitOwnerRecovery(.changedScope) }
            finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        guard !cleanupUsed, !busy else {
            if let phases { try? await phases.cleanup { try owner.commitOwnerRecovery(.changedScope) } }
            else { try? owner.commitOwnerRecovery(.changedScope) }; finish()
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        guard state == .greeted, lifetime.ifActive() else { finish(); throw RuntimeMaintenanceStartupAttemptError.beforePending }
        cleanupUsed = true; defer { finish() }
        let window = owner.window, stopped = owner.stoppedBinding
        guard window.purpose == .retainedRuntime, window.phase == .restoring,
              window.shutdownBinding == stopped else {
            if let phases { try? await phases.cleanup { try owner.commitOwnerRecovery(.changedScope) } }
            else { try? owner.commitOwnerRecovery(.changedScope) }
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        var current = window, attemptedCommit = false, pendingWriteOwned = false
        do {
            do { try proof.requireObserved(by: self) }
            catch { throw RuntimeMaintenanceStartupAttemptError.beforePending }
            let check = verify
            if let phases { try await restorationPhase(phases, state: .greeted, binding: nil, boundary: .verifyBeforeOpen) { try check() } }
            else { try check() }
            let opened = try await startObserved(proof, stopped: stopped, until: deadline)
            guard opened.outcome == .applied else { throw RuntimeMaintenanceStartupAttemptError.beforePending }
            if let phases { try await restorationPhase(phases, state: .open, binding: opened.binding, boundary: .healthyBinding) { try owner.requireHealthyBinding(opened.binding) } }
            else { try owner.requireHealthyBinding(opened.binding) }
            try proof.requireObserved(by: self)
            let validate: @Sendable () throws -> Void = {
                try ownedPhaseControl?.visit(.beforePending, client: self, proof: proof, scope: .healthy(owner))
                try owner.validateBeforePending()
            }
            if let phases { try await restorationPhase(phases, state: .open, binding: opened.binding, boundary: .validateBeforePending, validate) }
            else { try validate() }
            let peer: MaintenanceStartupPeer
            do {
                let capture: @Sendable () throws -> MaintenanceStartupPeer = {
                    let peer = MaintenanceStartupPeer(try capturePeer(), check: requirePeerLive)
                    try peer.requireLive(); try peer.accept(owner); return peer
                }
                if let phases { peer = try await restorationPhase(phases, state: .open, binding: opened.binding, boundary: .capturePeer, capture) }
                else { peer = try capture() }
            } catch {
                throw RuntimeMaintenanceStartupFailure(
                    RuntimeMaintenanceStartupRecovery.failure(error, fallback: .serviceUnavailable), error)
            }
            let preparePending: @Sendable () throws -> CleanupRecord = {
                try owner.validateBeforePending(); try peer.requireLive(); try owner.requireWitnessLive()
                return try owner.pendingRecord(binding: opened.binding)
            }
            let pending: CleanupRecord
            if let phases { pending = try await restorationPhase(phases, state: .open, binding: opened.binding, boundary: .preparePending, preparePending) }
            else { pending = try preparePending() }
            pendingWriteOwned = true
            try pending.requireReplacing(window)
            attemptedCommit = true
            let committed: CleanupRecord
            let write: @Sendable () throws -> CleanupRecord = {
                let committed = try persist(pending, window)
                try ownedPhaseControl?.visit(.pendingWrite, client: self, proof: proof, scope: .healthy(owner))
                return committed
            }
            if let phases { committed = try await restorationPhase(phases, state: .open, binding: opened.binding, boundary: .persistPending, write) }
            else { committed = try write() }
            guard committed == pending else { throw PreparationStoreError.staleRevision }
            current = pending; attemptedCommit = false
            let requireLive: @Sendable () throws -> Void = { try peer.requireLive(); try owner.requireWitnessLive() }
            let release: @Sendable () throws -> Void = {
                try requireLive()
                try ownedPhaseControl?.visit(.drainRelease, client: self, proof: proof, scope: .healthy(owner))
                try releaseDrain(pending)
            }
            if let phases { try await restorationPhase(phases, state: .open, binding: opened.binding, boundary: .releaseDrain, release) }
            else { try release() }
            let readback = try await reopenHealthyCandidate(opened.binding, pending: pending, stopped: stopped,
                requirePeerLive: requireLive, phases: phases, until: deadline)
            if let phases { try await phases.run(controlled(.peerBeforeRestored, requireLive)) }
            else { try requireLive() }
            let restored = try CleanupRecord(id: pending.id, revision: AccountPreparationIntent.randomID(), purpose: pending.purpose,
                scope: pending.scope, phase: .restored, operation: pending.operation, service: .healthy, gate: readback)
            try restored.requireReplacing(pending); attemptedCommit = true
            let confirmed: CleanupRecord
            if let phases { confirmed = try await phases.run(controlled(.persistRestored) { try persist(restored, pending) }) }
            else { confirmed = try persist(restored, pending) }
            guard confirmed == restored else { throw PreparationStoreError.staleRevision }
            return restored
        } catch {
            if Task.isCancelled || error is CancellationError { throw CancellationError() }
            if !attemptedCommit {
                if current.phase == .restoring && !pendingWriteOwned {
                    if error is AuthorityMaintenanceClientError || error is RuntimeMaintenanceStartupAttemptError {
                        throw RuntimeMaintenanceStartupAttemptError.beforePending
                    }
                    throw error
                } else if let failed = try? CleanupRecord(id: current.id, revision: AccountPreparationIntent.randomID(), purpose: current.purpose,
                    scope: current.scope, phase: .needsOwnerRecovery, operation: current.operation, service: current.service,
                    failure: current.phase == .reopenPending ? .admissionUnconfirmed : .healthFailed, shutdownBinding: stopped) {
                    let previous = current
                    if let phases { _ = try? await phases.cleanup { try persist(failed, previous) } }
                    else { _ = try? persist(failed, previous) }
                }
            }
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
    }
    func cancelAndReopenStartupNative(_ proof: AuthorityMaintenanceIncarnationProof,
        custody: RuntimeMaintenanceStartupRecovery.Custody, until deadline: ContinuousClock.Instant,
        phases: SetupRetainedInvocationReservation.RestorationPhases? = nil) async throws -> CleanupRecord {
        guard getuid() == 0, geteuid() == 0, driver is NativeMaintenanceClient, custody.native else { throw JournalLeaseError.rootRequired }
        let receipts = MaintenanceHealthyPendingReceipt()
        return try await cancelAndReopenStartup(proof, custody: custody, until: deadline,
            releaseDrain: { pending, previous in
                try custody.releaseCleanupDrain(after: receipts.require(), pending: pending, previous: previous)
            }, persist: { next, previous in
                let receipt = try custody.persistNative(next, previous: previous)
                if next.phase == .reopenPending { try receipts.store(receipt) }; return receipt.record
            }, phases: phases)
    }
    func cancelAndReopenStartupOwned(_ proof: AuthorityMaintenanceIncarnationProof,
        custody: RuntimeMaintenanceStartupRecovery.Custody, until deadline: ContinuousClock.Instant,
        phases: SetupRetainedInvocationReservation.RestorationPhases? = nil) async throws -> CleanupRecord {
        try RuntimeMaintenanceOwnedControl.require()
        guard !custody.native else { throw JournalLeaseError.unsafeMetadata }
        return try await cancelAndReopenStartup(proof, custody: custody, until: deadline,
            releaseDrain: { pending, _ in try custody.releaseOwnedCleanupDrain(after: pending) },
            persist: { try custody.persistOwned($0, previous: $1) }, phases: phases)
    }
    /// The capability comes only from the explicit dispatcher after its needsOwnerRecovery → restoring write.
    func cancelAndReopenExplicitNative(_ proof: AuthorityMaintenanceIncarnationProof,
        prepared: RuntimeMaintenanceStartupRecovery.ExplicitReconnect, until deadline: ContinuousClock.Instant) async throws -> CleanupRecord {
        let custody = prepared.custody
        guard getuid() == 0, geteuid() == 0, driver is NativeMaintenanceClient, custody.native else { throw JournalLeaseError.rootRequired }
        let receipts = MaintenanceHealthyPendingReceipt()
        return try await cancelAndReopenStartup(proof, custody: custody, until: deadline,
            releaseDrain: { pending, previous in
                try custody.releaseCleanupDrain(after: receipts.require(), pending: pending, previous: previous)
            }, persist: { next, previous in
                let write: @Sendable () throws -> CleanupRecord = {
                    let receipt = try custody.persistNative(next, previous: previous)
                    if next.phase == .reopenPending { try receipts.store(receipt) }; return receipt.record
                }
                return try write()
            }, explicit: prepared)
    }
    func cancelAndReopenExplicitOwned(_ proof: AuthorityMaintenanceIncarnationProof,
        prepared: RuntimeMaintenanceStartupRecovery.ExplicitReconnect, until deadline: ContinuousClock.Instant,
        ownedPhaseControl: OwnedRestorationPhaseControl? = nil) async throws -> CleanupRecord {
        try RuntimeMaintenanceOwnedControl.require()
        let custody = prepared.custody
        guard !custody.native else { throw JournalLeaseError.unsafeMetadata }
        return try await cancelAndReopenStartup(proof, custody: custody, until: deadline,
            releaseDrain: { pending, _ in
                try custody.releaseOwnedCleanupDrain(after: pending)
            }, persist: { next, previous in
                try custody.persistOwned(next, previous: previous)
            }, explicit: prepared, ownedPhaseControl: ownedPhaseControl)
    }
    private func cancelAndReopenStartup(_ proof: AuthorityMaintenanceIncarnationProof,
        custody: RuntimeMaintenanceStartupRecovery.Custody, until deadline: ContinuousClock.Instant,
        releaseDrain: @escaping @Sendable (CleanupRecord, CleanupRecord) throws -> Void,
        persist: @escaping @Sendable (CleanupRecord, CleanupRecord) throws -> CleanupRecord,
        explicit: RuntimeMaintenanceStartupRecovery.ExplicitReconnect? = nil,
        phases nativePhases: SetupRetainedInvocationReservation.RestorationPhases? = nil,
        ownedPhaseControl: OwnedRestorationPhaseControl? = nil) async throws -> CleanupRecord {
        try Task.checkCancellation()
        guard state == .greeted, !cleanupUsed, !busy else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        cleanupUsed = true
        if ownedSupervisorControl != nil { ownedSupervisorReconnectContext = .init(proof: proof, custody: custody) }
        defer { ownedSupervisorReconnectContext = nil; finish() }
        let window = custody.current
        let phases = explicit?.phases ?? nativePhases
        let explicitWindow: CleanupRecord?
        if let explicit { explicitWindow = try await explicit.phases.run { try explicit.consume() } }
        else { explicitWindow = nil }
        guard (explicitWindow == nil && window.phase == .draining && window.service == .notStopped
                || explicitWindow == window && window.phase == .restoring && window.service == .restartPending),
              window.operation == .notStarted,
              let target = window.shutdownBinding, target.attemptID == context.attemptID,
              context.accountID == window.scope.authority.accountID, context.installationID == window.scope.installationID else {
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
        var current = window, attemptedCommit = false
        do {
            try proof.requireObserved(by: self)
            guard proof.incarnation == target.incarnation else { throw RuntimePreparationError.changedScope }
            let validate: @Sendable () throws -> Void = {
                if let explicit { try ownedPhaseControl?.visit(.beforePending, client: self, proof: proof, scope: .reconnect(explicit)) }
                try custody.requireCleanup(window)
            }
            if let phases { try await restorationPhase(phases, state: .greeted, binding: nil, boundary: .reconnectValidation, validate) }
            else { try validate() }
            let pending = try CleanupRecord(id: window.id, revision: context.revision, purpose: window.purpose,
                scope: window.scope, phase: .reopenPending, shutdownBinding: target)
            try pending.requireReplacing(window); attemptedCommit = true
            let committed: CleanupRecord
            let write: @Sendable () throws -> CleanupRecord = {
                let committed = try persist(pending, window)
                if let explicit { try ownedPhaseControl?.visit(.pendingWrite, client: self, proof: proof, scope: .reconnect(explicit)) }
                return committed
            }
            if let phases { committed = try await restorationPhase(phases, state: .greeted, binding: nil, boundary: .reconnectPending, write) }
            else { committed = try write() }
            guard committed == pending else { throw PreparationStoreError.staleRevision }
            current = pending; attemptedCommit = false
            try proof.requireObserved(by: self)
            let release: @Sendable () throws -> Void = {
                if let explicit { try ownedPhaseControl?.visit(.drainRelease, client: self, proof: proof, scope: .reconnect(explicit)) }
                try releaseDrain(pending, window)
            }
            if let phases { try await restorationPhase(phases, state: .greeted, binding: nil, boundary: .reconnectRelease, release) }
            else { try release() }
            let readback = try await reopenSavedObserved(proof, target: target, until: deadline)
            let restored = try CleanupRecord(id: pending.id, revision: AccountPreparationIntent.randomID(), purpose: pending.purpose,
                scope: pending.scope, phase: .restored, gate: readback)
            try restored.requireReplacing(pending); attemptedCommit = true
            let confirmed: CleanupRecord
            if let phases { confirmed = try await phases.run(controlled(.persistRestored) { try persist(restored, pending) }) }
            else { confirmed = try persist(restored, pending) }
            guard confirmed == restored else { throw PreparationStoreError.staleRevision }
            return restored
        } catch {
            if Task.isCancelled || error is CancellationError { throw CancellationError() }
            if !attemptedCommit, let failed = try? CleanupRecord(id: current.id, revision: AccountPreparationIntent.randomID(),
                purpose: current.purpose, scope: current.scope, phase: .needsOwnerRecovery, operation: current.operation,
                service: explicit != nil && current.phase == .restoring ? .notStopped : current.service,
                failure: current.phase == .reopenPending ? .admissionUnconfirmed : explicit?.beforePendingFailure ?? .admissionUnconfirmed,
                shutdownBinding: target) {
                let previous = current
                if let phases { _ = try? await phases.cleanup { try persist(failed, previous) } }
                else { _ = try? persist(failed, previous) }
            }
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
    }

    private func reopenHealthyCandidate(_ candidate: AuthorityMaintenanceBinding, pending: CleanupRecord,
        stopped: AuthorityMaintenanceBinding, requirePeerLive: @escaping @Sendable () throws -> Void,
        phases: SetupRetainedInvocationReservation.RestorationPhases? = nil,
        until deadline: ContinuousClock.Instant) async throws -> CleanupRecord.GateReadback {
        guard state == .open, binding == candidate, pending.phase == .reopenPending,
              candidate.incarnation != stopped.incarnation else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        defer { finish() }
        if let phases { try await restorationPhase(phases, state: .open, binding: candidate, boundary: .beforeReopen, requirePeerLive) }
        else { try requirePeerLive() }
        let q = try Request(action: .reopen, accountID: context.accountID, attemptID: context.attemptID,
            revision: pending.revision, installationID: context.installationID, gate: context.gate,
            binding: candidate, challenge: AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID())
        guard case .bytes(let bytes) = try await invoke(q, until: deadline), let bytes,
              try Response.decode(bytes, expected: q).outcome == .applied else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        if let phases { try await restorationPhase(phases, state: .open, binding: candidate, boundary: .afterReopen, requirePeerLive) }
        else { try requirePeerLive() }
        return try await readReleasedGate(stopped, revision: pending.revision,
            incarnation: candidate.incarnation, requirePeerLive: requirePeerLive, phases: phases, until: deadline)
    }

    func close() { finish() }
    private func enter() throws {
        guard !busy else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }; busy = true
    }
    private func send(_ action: Request.Action, target: AuthorityMaintenanceBinding? = nil,
                      until deadline: ContinuousClock.Instant) async throws -> Response {
        do {
            var challenge = Data(count: 32)
            guard challenge.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }) == errSecSuccess else { throw RuntimePreparationError.invalidRecord }
            let q = try Request(action: action, accountID: context.accountID, attemptID: context.attemptID, revision: context.revision,
                installationID: context.installationID, gate: context.gate, binding: action == .open ? nil : target ?? binding, challenge: challenge)
            guard case .bytes(let bytes) = try await invoke(q, until: deadline), let bytes else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            let response = try Response.decode(bytes, expected: q)
            if response.outcome == .refused {
                let error: AuthorityMaintenanceClientError = action == .cancel || action == .reopen ? .needsOwnerRecovery : .cancelled
                finish(error); throw error
            }
            return response
        } catch { finish(); throw (error as? AuthorityMaintenanceClientError) ?? .needsOwnerRecovery }
    }
    private func ownedRPCKind(_ request: Request?, gate: AuthorityMaintenanceGateRequest?,
        incarnation: AuthorityMaintenanceIncarnationRequest?) -> OwnedSupervisorPhaseControl.RPC {
        if gate != nil { return .gate }
        if incarnation != nil { return .incarnation }
        guard let request else { return .hello }
        switch request.action { case .open: return .open; case .reopen: return .reopen; default: return .other }
    }
    private func invoke(_ q: Request?, gate: AuthorityMaintenanceGateRequest? = nil, incarnation: AuthorityMaintenanceIncarnationRequest? = nil,
                        until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceClientReply {
        do {
            try Task.checkCancellation()
            if let recoveryPhases {
                let expectedState = state, expectedBinding = binding, verify = self.verify
                let kind = ownedRPCKind(q, gate: gate, incarnation: incarnation)
                try ownedSupervisorControl?.visit(.beforeRPCDispatch, rpc: kind, client: self,
                    restoration: ownedSupervisorContext, reconnect: ownedSupervisorReconnectContext)
                try await recoveryPhases.run(controlled(.beforeRPCVerify, rpc: kind, verify))
                guard state == expectedState, binding == expectedBinding else { throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            } else { try verify() }
        } catch { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        guard state != .closed, lifetime.ifActive(), ContinuousClock.now < deadline else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        let id = UUID(), end = min(deadline, .now.advanced(by: timeout)), payload = try q?.encoded ?? gate?.encoded ?? incarnation?.encoded
        let value: AuthorityMaintenanceClientReply = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                pending = (id, continuation)
                guard lifetime.begin(id) else { finish(); return }
                timer = Task { [weak self] in
                    do { try await ContinuousClock().sleep(until: end) } catch { return }; await self?.expire(id)
                }
                let reply: @Sendable (AuthorityMaintenanceClientReply) -> Void = { [weak self, lifetime] value in
                    guard lifetime.record(id, value, until: end) else { return }; Task { await self?.received(id) }
                }
                if payload == nil { driver.start { [weak self, lifetime] in lifetime.invalidate(); Task { await self?.finish(preservingReply: true) } } }
                guard lifetime.ifActive({
                    if let payload {
                        if gate != nil { driver.readGate(payload, reply) }
                        else if incarnation != nil { driver.observeIncarnation(payload, reply) } else { driver.exchange(payload, reply) }
                    } else { driver.hello(reply) }
                }) else { finish(); return }
            }
        } onCancel: { [weak self, lifetime, driver] in lifetime.close(); driver.close(); Task { await self?.close() } }
        do {
            try Task.checkCancellation()
            if let recoveryPhases {
                let verify = self.verify, kind = ownedRPCKind(q, gate: gate, incarnation: incarnation)
                try await recoveryPhases.run(controlled(.afterRPCVerify, rpc: kind, verify))
            } else { try verify() }
        } catch { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        guard lifetime.reply(id) != nil else { finish(); throw AuthorityMaintenanceClientError.needsOwnerRecovery }
        if !lifetime.ifActive() { finish(preservingReply: true) }; return value
    }
    private func received(_ id: UUID) {
        guard let p = pending, p.0 == id else { return }
        guard let value = lifetime.reply(id) else { finish(); return }; pending = nil; timer?.cancel(); timer = nil; p.1.resume(returning: value)
    }
    private func expire(_ id: UUID) { if pending?.0 == id { finish(preservingReply: true) } }
    private func finish(_ error: AuthorityMaintenanceClientError = .needsOwnerRecovery, preservingReply: Bool = false) {
        guard state != .closed else { return }
        let p = pending, value = preservingReply ? pending.flatMap { lifetime.reply($0.0) } : nil
        state = .closed; if preservingReply { lifetime.invalidate() } else { lifetime.close() }; timer?.cancel(); timer = nil
        pending = nil; driver.close()
        if let value { p?.1.resume(returning: value) } else { p?.1.resume(throwing: error) }
    }
}

/// Only the authenticated exchange verifier can construct this writer input.
struct VerifiedUnboundGateObservation: Sendable {
    private let challenge: SetupRetainedOrphanClaim.Joined.UnboundGateChallenge
    private let response: AuthorityMaintenanceUnboundGateResponse
    fileprivate init(challenge: SetupRetainedOrphanClaim.Joined.UnboundGateChallenge,
        response: AuthorityMaintenanceUnboundGateResponse) {
        self.challenge = challenge; self.response = response
    }
    var request: AuthorityMaintenanceUnboundRequest { response.request }
    func requireCurrent(joined: SetupRetainedOrphanClaim.Joined, row: RuntimeMaintenanceWindowRecord,
        gate: PreparationFileIdentity) throws {
        try challenge.requireCurrent(joined: joined, row: row, gate: gate)
        guard response.request == challenge.request else { throw RuntimePreparationError.changedScope }
        _ = try response.completedGateReadback()
    }
    func completedGateReadback() throws -> RuntimeMaintenanceWindowRecord.GateReadback {
        try response.completedGateReadback()
    }
}

/// Read-only evidence of the live Authority incarnation, observed on one authenticated maintenance connection.
/// It grants no admission, release, stop or restoration. It proves only what the Authority reported at observation time.
struct AuthorityMaintenanceIncarnationProof: Equatable, Sendable {
    let accountID: Data
    let incarnation: Data
    fileprivate let observer: ObjectIdentifier
    fileprivate init(accountID: Data, incarnation: Data, observer: ObjectIdentifier) {
        self.accountID = accountID; self.incarnation = incarnation; self.observer = observer
    }
    /// Throws unless this client's still-live connection lifetime recorded this exact observation.
    func requireObserved(by client: AuthorityMaintenanceXPCClient) throws {
        guard observer == ObjectIdentifier(client.lifetime),
              client.lifetime.hasObserved(accountID: accountID, incarnation: incarnation) else { throw RuntimePreparationError.changedScope }
    }
}

extension AuthorityMaintenanceChannelWork {
    // Ready is diagnostic. Work counts and the actual arm outcome decide whether stopping can proceed.
    var allowsMaintenanceStop: Bool {
        journal.requests.liveRequests == 0 && journal.requests.commandCaptures == 0 && journal.requests.activityOwners == 0
            && journal.exchanges.active == 0 && !journal.exchanges.stopped && journal.nativeExecutions == 0
            && journal.executionActivityOwners == 0 && execution.started && !execution.stopping && !execution.failed
            && execution.queuedTurns == 0 && execution.rejectedTurns == 0 && pairing.stagedAttempts == 0
            && pairing.activityOwners == 0 && !pairing.operationActive
    }
}

/// Captured arm evidence only. It grants no removal, body loan or journal custody.
final class RuntimeMaintenanceStopCapture: @unchecked Sendable {
    let window: RuntimeMaintenanceWindowRecord, cohort: RuntimeMaintenanceAuthorityCohort
    let marker: AuthorityMaintenanceCloseMarker, witness: any RuntimeJobExitWitness
    let configuration: InstalledAuthorityCommandConfiguration
    let bindingTransition: PreparationIntentStore.RuntimeMaintenanceTransition?
    private let processID = getpid(), ownerUID = getuid()
    private let verifyOwner: @Sendable () throws -> Void, verifyConfiguration: @Sendable () throws -> Void
    fileprivate init(window: RuntimeMaintenanceWindowRecord, cohort: RuntimeMaintenanceAuthorityCohort,
        marker: AuthorityMaintenanceCloseMarker, witness: any RuntimeJobExitWitness, configuration: InstalledAuthorityCommandConfiguration,
        bindingTransition: PreparationIntentStore.RuntimeMaintenanceTransition?, verifyOwner: @escaping @Sendable () throws -> Void, verifyConfiguration: @escaping @Sendable () throws -> Void) {
        self.window = window; self.cohort = cohort; self.marker = marker; self.witness = witness; self.configuration = configuration
        self.bindingTransition = bindingTransition
        self.verifyOwner = verifyOwner; self.verifyConfiguration = verifyConfiguration
    }
    func validate() throws {
        guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
        try verifyOwner(); try verifyConfiguration()
    }
}

enum RuntimeMaintenanceOwnedControl {
    static func allows(realUID: uid_t, effectiveUID: uid_t) -> Bool { realUID > 0 && realUID == effectiveUID }
    static func require() throws {
        guard allows(realUID: getuid(), effectiveUID: geteuid()) else { throw JournalLeaseError.unsafeMetadata }
    }
}

/// One stop and one body entry for captured arm evidence. The clock does not reclassify a completed body.
final class RuntimeMaintenanceStopPermit: @unchecked Sendable {
    let capture: RuntimeMaintenanceStopCapture
    private let deadline: ContinuousClock.Instant, readMarker: () throws -> Void
    private let lock = NSLock()
    private var consumed = false, ownerThread: pthread_t?
    private init(capture: RuntimeMaintenanceStopCapture, deadline: ContinuousClock.Instant, readMarker: @escaping () throws -> Void) {
        self.capture = capture; self.deadline = deadline; self.readMarker = readMarker
    }
    static func openNative(capture: RuntimeMaintenanceStopCapture, until deadline: ContinuousClock.Instant) throws -> RuntimeMaintenanceStopPermit {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }; try capture.validate()
        return .init(capture: capture, deadline: deadline, readMarker: { try AuthorityMaintenanceCloseMarker.readback(capture.marker) })
    }
    static func openOwned(capture: RuntimeMaintenanceStopCapture, until deadline: ContinuousClock.Instant,
        readMarker: @escaping () throws -> Void) throws -> RuntimeMaintenanceStopPermit {
        try RuntimeMaintenanceOwnedControl.require(); try capture.validate()
        return .init(capture: capture, deadline: deadline, readMarker: readMarker)
    }
    func consume(cohort: RuntimeMaintenanceAuthorityCohort, purpose: RuntimeMaintenanceWindowRecord.Purpose) throws -> any RuntimeJobExitWitness {
        try lock.withLock {
            guard !consumed else { throw JournalLeaseError.invalidated }; consumed = true; ownerThread = pthread_self()
        }
        try requireUnexpired()
        guard capture.window.purpose == purpose, cohort.job.bytes == capture.cohort.job.bytes,
              cohort.accountID == capture.cohort.accountID, cohort.targetAccountID == capture.cohort.targetAccountID,
              cohort.machineIdentity == capture.cohort.machineIdentity, cohort.accountIdentity == capture.cohort.accountIdentity,
              try !capture.witness.hasExited() else { throw RuntimePreparationError.changedScope }
        return capture.witness
    }
    func validate() throws {
        try capture.validate()
        try lock.withLock {
            guard consumed, let ownerThread, pthread_equal(pthread_self(), ownerThread) != 0 else { throw JournalLeaseError.invalidated }
        }
    }
    func requireUnexpired() throws {
        try validate(); guard ContinuousClock.now < deadline else { throw JournalLeaseError.invalidated }
    }
    func requireClosed() throws {
        try validate(); guard try capture.witness.hasExited() else { throw RuntimeActivationError.unavailable }
        try readMarker(); try validate()
    }
}
