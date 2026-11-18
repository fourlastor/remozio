import Foundation

/// One restart session on the future recovery-only lane. There is no production caller or native factory.
final class SetupRestartRecoveryEndpoint: @unchecked Sendable {
    typealias Wire = SetupRestartRecoveryWire
    typealias Operations = SetupRestartRecoveryOperations
    private let lock = NSLock()
    private let operations: Operations, peer: Operations.Peer
    private var closed = false
    private var canonical: Data?, recorded: Data?, request: Wire.Request?
    private var deadline: ContinuousClock.Instant?
    private var outcome = Wire.Code.pending
    private var claim: SetupRestartRecovery.Claim?
    private var work: Task<Void, Never>?
    private init(operations: Operations, peer: Operations.Peer) { self.operations = operations; self.peer = peer }
    static func openOwned(operations: Operations) throws -> SetupRestartRecoveryEndpoint {
        try operations.requireOwned()
        return try .init(operations: operations, peer: operations.effects.verifyPeer())
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
    func refuseForeignSelector() -> Data? {
        do {
            try verifyCall()
            let id = lock.withLock { request?.requestID }
            let bytes = try id.map { try Wire.Reply(requestID: $0, code: .refusedUnavailable).bytes }
            try verifyCall(); return bytes
        } catch { close(); return nil }
    }
    func start(_ bytes: Data, authorization externalForm: Data, reply: @escaping @Sendable (Data?) -> Void) {
        do { try verifyCall() } catch { close(); reply(nil); return }
        guard let decoded = try? Wire.Request.decode(bytes) else { reply(nil); return }
        let decision = lock.withLock { () -> (Bool, Data?) in
            guard !closed else { return (false, nil) }
            if let canonical {
                return (false, canonical == bytes ? recorded : (try? Wire.Reply(requestID: decoded.requestID, code: .refusedUnavailable).bytes))
            }
            canonical = bytes; request = decoded; deadline = operations.effects.now().advanced(by: .seconds(120))
            recorded = try? Wire.Reply(requestID: decoded.requestID, code: .requestRecorded).bytes
            return (true, recorded)
        }
        do { try verifyCall() } catch { close(); reply(nil); return }
        reply(decision.1)
        guard decision.0 else { return }
        // Import stays on the accepted invocation. Neither these bytes nor the reply callback enters the task.
        let authorization: SetupRetainedRecoveryAuthorization
        do {
            try requireOpen()
            guard allowed(decoded.action), operations.effects.checkHost != nil else { finish(.refusedUnavailable); return }
            authorization = try operations.effects.importAuthorization(externalForm)
        } catch { finish(.refusedUnavailable); return }
        let installed = lock.withLock { () -> Bool in
            guard !closed, let deadline else { return false }
            work = Task { [self] in await run(decoded, authorization: authorization, deadline: deadline) }
            return true
        }
        if !installed { authorization.close() }
    }
    private func run(_ request: Wire.Request, authorization: SetupRetainedRecoveryAuthorization,
        deadline: ContinuousClock.Instant) async {
        var current: SetupRestartRecovery.Claim?
        defer { authorization.close() }
        do {
            try requireOpen()
            guard allowed(request.action), authorization.peer == peer.credentials, authorization.currentOwner == peer.owner,
                  request.action != .restore || operations.effects.now() < deadline else {
                finish(.refusedUnavailable); await retire(nil); return
            }
            let value = try await operations.claim(authorization, action: request.action, until: deadline)
            current = value
            let installed = lock.withLock { () -> Bool in
                guard !closed else { return false }
                claim = value
                return true
            }
            guard installed else { value.abandon(); await retire(value); return }
            try requireOpen(); try await operations.check(value)
            guard allowed(request.action) else { finish(.notApplicable); await retire(value); return }
            switch request.action {
            case .restore:
                guard operations.effects.now() < deadline else { finish(.failedDeadline); await retire(value); return }
                let row = try await operations.effects.restore(value, deadline)
                guard row.phase == .restored, value.hasCheckedRestorationResult(row) else { throw AdministrativeSetupError.unavailable }
                finish(.restored)
            case .adoptRecordedCompletion:
                let row = try await value.finishRecordedRestoration()
                finish(row.phase == .restored ? .restored : .repairRequired)
            case .releaseIdleSlot:
                var applicable = try await operations.releaseApplicability(value)
                if case .liveWork = applicable {
                    // A deadline never manufactures task return. Progress remains pending while this join waits.
                    try await value.joinPreviousRestoration()
                    applicable = try await operations.releaseApplicability(value)
                }
                switch applicable {
                case .idle:
                    guard try await operations.releaseIdle(value) else { throw AdministrativeSetupError.unavailable }
                    finish(.released)
                case .completionNeedsAdoption, .restoreRequired: finish(.notApplicable)
                case .repairRequired: finish(.repairRequired)
                case .liveWork: throw AdministrativeSetupError.unavailable
                }
            }
        } catch {
            if current != nil {
                // The actual rights object is checked independently of a record that cleanup may already have released.
                // No expiry task can race this check. A callback's error type does not determine rights loss.
                // This extra check runs on the cooperative executor; the native producer must account for its rights callback.
                if (try? authorization.requireCurrent()) == nil { finish(.failedAuthorization) }
                else if let failure = error as? RuntimeMaintenanceStartupFailure, failure.failure == .repairRequired { finish(.repairRequired) }
                else if let failure = error as? PreparationStoreError, failure == .notFound { finish(.notApplicable) }
                else if let failure = error as? SetupRestartRecoveryError {
                    switch failure {
                    case .uncertainWriter, .unsettledWindow: finish(.repairRequired)
                    case .completionNeedsAdoption: finish(.notApplicable)
                    }
                }
                else if operations.effects.now() >= deadline || error is CancellationError { finish(.failedDeadline) }
                else if error is Operations.AuthorizationFailure || error is SetupAdministratorAuthorizationError || error is XPCPeerPolicyError { finish(.failedAuthorization) }
                else { finish(.failedOperation) }
            } else { finish(.refusedUnavailable) }
        }
        await retire(current)
    }
    private func finish(_ value: Wire.Code) { lock.withLock { if !closed { outcome = value } } }
    private func retire(_ value: SetupRestartRecovery.Claim?) async {
        if let value { _ = try? await operations.releaseIdle(value); value.abandon() }
        let retired = lock.withLock { () -> Task<Void, Never>? in
            let old = work; work = nil; claim = nil; return old
        }
        withExtendedLifetime(retired) {}
    }
    func progress(_ bytes: Data) -> Data? {
        do { try verifyCall() } catch { close(); return nil }
        guard let decoded = try? Wire.Progress.decode(bytes) else { return nil }
        do {
            let value = lock.withLock { request?.requestID == decoded.requestID ? outcome : .refusedUnavailable }
            let reply = try Wire.Reply(requestID: decoded.requestID, code: value).bytes
            try verifyCall(); return reply
        } catch { close(); return nil }
    }
    func waitForWork() async { let value = lock.withLock { work }; await value?.value }
    func close() {
        let retired = lock.withLock { () -> SetupRestartRecovery.Claim? in
            guard !closed else { return nil }; closed = true
            let old = claim; claim = nil; return old
        }
        retired?.abandon()
    }
    deinit { close() }
}
