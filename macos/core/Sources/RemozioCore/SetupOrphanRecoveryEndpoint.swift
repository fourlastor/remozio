import Foundation

/// One session after the facade selected recovery-only. No production caller or native factory exists in this slice.
final class SetupOrphanRecoveryEndpoint: @unchecked Sendable {
    typealias Wire = SetupOrphanRecoveryWire
    typealias Operations = SetupOrphanRecoveryOperations
    private let lock = NSLock()
    private let operations: Operations, peer: Operations.Peer
    private let supportsCapturedTarget: Bool
    private var closed = false
    private var request: Wire.Request?, canonical: Data?, recorded: Data?
    private var deadline: ContinuousClock.Instant?
    private var outcome = Wire.Code.pending
    private var claim: SetupRetainedOrphanClaim?
    private var work: Task<Void, Never>?

    private init(operations: Operations, peer: Operations.Peer, supportsCapturedTarget: Bool) {
        self.operations = operations; self.peer = peer; self.supportsCapturedTarget = supportsCapturedTarget
    }
    static func openOwned(operations: Operations, maximumConnections: Int) throws -> SetupOrphanRecoveryEndpoint {
        try operations.requireOwned()
        guard (1...64).contains(maximumConnections) else { throw AdministrativeSetupError.invalidConfiguration }
        return try .init(operations: operations, peer: operations.effects.verifyPeer(), supportsCapturedTarget: maximumConnections >= 3)
    }
    private func verifyCall() throws {
        try operations.requireOwned()
        guard try operations.effects.verifyPeer() == peer, lock.withLock({ !closed }) else { throw XPCPeerPolicyError.wrongConnection }
    }
    private func requireOpen() throws {
        try operations.requireOwned()
        guard lock.withLock({ !closed }) else { throw SetupAdministratorAuthorizationError.closed }
    }
    private func allowed(_ action: Wire.Action) -> Bool {
        switch operations.effects.routing() {
        case .serving: true
        case .retiring: action != .restore
        case .starting, .discovering, .closed: false
        }
    }
    /// Other selectors refuse one call. They cannot clear the recorded request or abandon its claim.
    func refuseForeignSelector() -> Data? {
        do {
            try verifyCall()
            let id = lock.withLock { request?.requestID }
            let result = try id.map { try Wire.Reply(requestID: $0, code: .refusedUnavailable).bytes }
            try verifyCall(); return result
        } catch { close(); return nil }
    }
    func start(_ bytes: Data, authorization externalForm: Data, reply: @escaping @Sendable (Data?) -> Void) {
        let decoded: Wire.Request
        do { try verifyCall() } catch { close(); reply(nil); return }
        do { decoded = try Wire.Request.decode(bytes) } catch { reply(nil); return }
        let decision = lock.withLock { () -> (first: Bool, bytes: Data?) in
            guard !closed else { return (false, nil) }
            if let canonical {
                if canonical == bytes { return (false, recorded) }
                return (false, try? Wire.Reply(requestID: decoded.requestID, code: .refusedUnavailable).bytes)
            }
            request = decoded; canonical = bytes; deadline = operations.effects.now().advanced(by: .seconds(120))
            recorded = try? Wire.Reply(requestID: decoded.requestID, code: .requestRecorded).bytes
            return (true, recorded)
        }
        do { try verifyCall() } catch { close(); reply(nil); return }
        reply(decision.bytes)
        guard decision.first else { return }
        // Rights import stays on this invocation. Neither the external form nor the reply callback enters the task.
        let authorization: SetupRetainedRecoveryAuthorization
        do {
            try requireOpen()
            guard allowed(decoded.action), operations.effects.checkHost != nil else { finish(.refusedUnavailable); return }
            authorization = try operations.effects.importAuthorization(externalForm)
        } catch { finish(.failedAuthorization); return }
        var adopted = false
        defer { if !adopted { authorization.close() } }
        do {
            try requireOpen()
            guard allowed(decoded.action), authorization.peer == peer.credentials, authorization.currentOwner == peer.owner else {
                finish(.refusedUnavailable); return
            }
            let target = try operations.capture(authorization)
            if let binding = target.binding {
                guard supportsCapturedTarget, decoded.identity == target.identity, binding.matches(peer.owner) else {
                    finish(.refusedUnavailable); return
                }
            } else if decoded.identity != nil || decoded.action != .releaseWindowFree {
                finish(.refusedUnavailable); return
            }
            let value = try operations.claim(target, authorization: authorization)
            let installed = lock.withLock { () -> Bool in
                guard !closed, let deadline else { return false }
                claim = value
                work = Task { [self] in await run(value, target: target, request: decoded, deadline: deadline) }
                return true
            }
            if installed { adopted = true } else { value.abandon() }
        } catch { finish(.refusedUnavailable) }
    }
    private func run(_ value: SetupRetainedOrphanClaim, target: SetupRetainedOrphanClaim.Target,
        request: Wire.Request, deadline: ContinuousClock.Instant) async {
        defer { retireWork() }
        let joined: SetupRetainedOrphanClaim.Joined
        do { joined = try await value.join() } catch { finish(.failedJoin); return }
        do {
            try requireOpen()
            guard allowed(request.action), let host = operations.effects.checkHost else { finish(.refusedUnavailable); return }
            let phases = try joined.restorationPhases()
            let applicability = try await phases.run {
                try host(); try joined.requireCurrentAuthorization()
                return try joined.recoveryApplicability()
            }
            try requireOpen()
            guard allowed(request.action) else { finish(.refusedUnavailable); return }
            switch request.action {
            case .releaseWindowFree:
                guard applicability == .windowFree else {
                    finish(target.window == nil && !joined.evidence.windowWriteNeverPossible ? .repairRequired : .notApplicable); return
                }
                let released = try await phases.run {
                    try host(); try joined.requireCurrentAuthorization(); return try joined.releaseIfWindowFree()
                }
                finish(released ? .released : .notApplicable)
            case .adoptRecordedCompletion:
                guard applicability == .unsettledCompletion else { finish(.notApplicable); return }
                let row = try await operations.effects.adopt(joined, target)
                finish(row.phase == .restored ? .restored : .repairRequired)
            case .restore:
                guard applicability == .noCompletion else { finish(.notApplicable); return }
                guard target.window != nil else { finish(.repairRequired); return }
                guard operations.effects.now() < deadline else { finish(.failedDeadline); return }
                let row = try await operations.effects.restore(joined, target, deadline)
                finish(row.phase == .restored ? .restored : .repairRequired)
            }
        } catch { finish(.failedOperation) }
    }
    private func finish(_ code: Wire.Code) { lock.withLock { if !closed { outcome = code } } }
    private func retireWork() {
        let retired = lock.withLock { () -> Task<Void, Never>? in let old = work; work = nil; return old }
        withExtendedLifetime(retired) {}
    }
    func progress(_ bytes: Data) -> Data? {
        do { try verifyCall() } catch { close(); return nil }
        guard let decoded = try? Wire.Progress.decode(bytes) else { return nil }
        do {
            let code = lock.withLock { request?.requestID == decoded.requestID ? outcome : .refusedUnavailable }
            let result = try Wire.Reply(requestID: decoded.requestID, code: code).bytes
            try verifyCall(); return result
        } catch { close(); return nil }
    }
    func waitForWork() async {
        let value = lock.withLock { work }
        await value?.value
    }
    func close() {
        let retired = lock.withLock { () -> SetupRetainedOrphanClaim? in
            guard !closed else { return nil }; closed = true
            let old = claim; claim = nil; return old
        }
        retired?.abandon()
    }
    deinit { close() }
}
