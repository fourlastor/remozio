import Foundation

/// The caller callbacks stay on the exported invocation stack. Tasks retain only the separate work state.
final class SetupOrphanRecoveryEndpoint: @unchecked Sendable {
    typealias Wire = SetupOrphanRecoveryWire
    typealias Operations = SetupOrphanRecoveryOperations
    private struct Caller {
        let verifyPeer: () throws -> Operations.Peer
        let importAuthorization: (Data) throws -> SetupRetainedRecoveryAuthorization
    }
    private let caller: Caller
    private let state: WorkState
    private init(caller: Caller, state: WorkState) { self.caller = caller; self.state = state }
    static func openOwned(operations: Operations, maximumConnections: Int,
        shutdownSession: AdministrativeSetupShutdown.RecoverySessionWork? = nil) throws -> SetupOrphanRecoveryEndpoint {
        let callbacks = try operations.takeCallerOwned()
        guard (1...64).contains(maximumConnections) else { throw AdministrativeSetupError.invalidConfiguration }
        let state = try WorkState(operations: operations, peer: callbacks.verifyPeer(),
            supportsCapturedTarget: maximumConnections >= 3, shutdownSession: shutdownSession)
        shutdownSession?.bindEndpointClose { [weak state] in state?.close() }
        return .init(caller: .init(verifyPeer: callbacks.verifyPeer, importAuthorization: callbacks.importAuthorization), state: state)
    }
    static func openNative(context: AdministrativeSetupService.NativeRecoveryContext,
        invocation: XPCInvocationGuard, close: @escaping @Sendable () -> Void) throws -> SetupOrphanRecoveryEndpoint {
        let operations = try Operations.native(context: context)
        let session = try operations.registerNativeSession()
        do {
            let caller = Caller(verifyPeer: {
                let peer = try invocation.verifyInvocation()
                guard peer.userID > 0, peer.userID < UInt32.max else { throw XPCPeerPolicyError.wrongPeer }
                return .init(credentials: peer, owner: try LocalAccountDirectory.lookup(uid: peer.userID))
            }, importAuthorization: { try .openNative(invocation: invocation, externalForm: $0) })
            let state = try WorkState(operations: operations, peer: caller.verifyPeer(),
                supportsCapturedTarget: context.maximumConnections >= 3, shutdownSession: session, onClose: close)
            session.bindEndpointClose { [weak state] in state?.close() }
            return .init(caller: caller, state: state)
        } catch {
            session.resolveWithoutWork(); session.connectionDidClose(); throw error
        }
    }
    private func verifyCall() throws { try state.verifyPeer(caller.verifyPeer()) }
    func start(_ bytes: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        state.start(bytes, authorization: authorization, verifyCall: verifyCall,
            importAuthorization: caller.importAuthorization, reply: reply)
    }
    func progress(_ bytes: Data) -> Data? { state.progress(bytes, verifyCall: verifyCall) }
    func refuseForeignSelector() -> Data? { state.refuseForeignSelector(verifyCall: verifyCall) }
    func waitForWork() async { await state.waitForWork() }
    func close() { state.close() }

    private final class WorkState: @unchecked Sendable {
        private let lock = NSLock()
        private let operations: Operations, peer: Operations.Peer
        private let supportsCapturedTarget: Bool
        private var closed = false
        private var request: Wire.Request?, canonical: Data?, recorded: Data?
        private var deadline: ContinuousClock.Instant?
        private var outcome = Wire.Code.pending
        private var claim: SetupRetainedOrphanClaim?
        private var work: Task<Void, Never>?
        private let shutdownSession: AdministrativeSetupShutdown.RecoverySessionWork?
        private let onClose: @Sendable () -> Void

        init(operations: Operations, peer: Operations.Peer, supportsCapturedTarget: Bool,
            shutdownSession: AdministrativeSetupShutdown.RecoverySessionWork?, onClose: @escaping @Sendable () -> Void = {}) {
            self.onClose = onClose
            self.operations = operations; self.peer = peer; self.supportsCapturedTarget = supportsCapturedTarget
            self.shutdownSession = shutdownSession
        }
        func verifyPeer(_ actual: Operations.Peer) throws {
            try operations.requireContext()
            guard actual == peer, lock.withLock({ !closed }) else { throw XPCPeerPolicyError.wrongConnection }
        }
        private func requireOpen() throws {
            try operations.requireContext()
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
        func refuseForeignSelector(verifyCall: () throws -> Void) -> Data? {
            do {
                try verifyCall()
                let id = lock.withLock { request?.requestID }
                let result = try id.map { try Wire.Reply(requestID: $0, code: .refusedUnavailable).bytes }
                try verifyCall(); return result
            } catch { close(); return nil }
        }
        func start(_ bytes: Data, authorization externalForm: Data, verifyCall: () throws -> Void,
            importAuthorization: (Data) throws -> SetupRetainedRecoveryAuthorization, reply: @escaping @Sendable (Data?) -> Void) {
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
            if let shutdownSession, !shutdownSession.reservePublication() { finish(.refusedUnavailable); return }
            var published = false
            defer { if !published { shutdownSession?.resolveWithoutWork() } }
            // Rights import stays on this invocation. Neither the external form nor the reply callback enters the task.
            let authorization: SetupRetainedRecoveryAuthorization
            do {
                try requireOpen()
                guard allowed(decoded.action), operations.effects.checkHost != nil else { finish(.refusedUnavailable); return }
                authorization = try importAuthorization(externalForm)
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
                let value = try operations.claim(target, authorization: authorization, shutdownSession: shutdownSession)
                let installed = lock.withLock { () -> Task<Void, Never>? in
                    guard !closed, let deadline else { return nil }
                    claim = value
                    let actual = Task { [self] in await run(value, target: target, request: decoded, deadline: deadline) }
                    work = actual; return actual
                }
                if let installed {
                    adopted = true
                    shutdownSession?.publish(installed); published = true
                } else { value.abandon() }
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
        func progress(_ bytes: Data, verifyCall: () throws -> Void) -> Data? {
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
            let retired = lock.withLock { () -> (Bool, SetupRetainedOrphanClaim?) in
                guard !closed else { return (false, nil) }; closed = true
                let old = claim; claim = nil; return (true, old)
            }
            guard retired.0 else { return }
            retired.1?.abandon()
            shutdownSession?.connectionDidClose()
            onClose()
        }
        deinit { close() }
    }
}
