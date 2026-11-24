import Darwin
import Foundation
import Security
import Synchronization

/// Local pairing setup only. This protocol carries no command decision or credential release.
@objc public protocol AuthorityPairingXPCProtocol {
    func pairingHello(reply: @escaping @Sendable (UInt64) -> Void)
    func pairingContext(reply: @escaping @Sendable (Data?) -> Void)
    func stagePairing(_ proposal: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void)
    func commitPairing(_ setupID: Data, confirmedDigest: Data, biometricProof: Data, authorization: Data,
                       reply: @escaping @Sendable (Data?) -> Void)
    func cancelPairing(reply: @escaping @Sendable (Bool) -> Void)
}

/// Optional management on the same authenticated app channel.
@objc public protocol AuthorityPairedPhoneXPCProtocol {
    func pairedPhoneHello(reply: @escaping @Sendable (UInt64) -> Void)
    func managePairedPhone(_ operation: UInt64, selection: Data, authorization: Data,
                           reply: @escaping @Sendable (Data?) -> Void)
}

/// One signed app connection retains at most one uncommitted attempt. Disconnect discards only that attempt.
final class AuthorityPairingXPCEndpoint: NSObject, AuthorityPairingXPCProtocol, AuthorityPairedPhoneXPCProtocol, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let access: AuthorityPairingSetupAccess
    private let budget: AuthorityXPCWorkBudget
    private let verify: () throws -> Void
    private let authorize: (Data) throws -> Void
    private let invalidate: () -> Void
    private let onHandshake: @Sendable () -> Void
    private struct WorkState {
        var ready = false, closed = false, busy = false
        var phoneManagement = false
        var attempt: PairingEnrollmentAttempt?
        var activity: ReleaseActivityToken?
        var stage: AuthorityMaintenancePairingAdmission.Stage?
        var currentOperation: UUID?, retiringStages: [UUID: [AuthorityMaintenancePairingAdmission.Stage]] = [:]
        var operations: [UUID: Bool] = [:]
    }
    private let state = Mutex(WorkState())
    private var ready: Bool { get { state.withLock { $0.ready } } set { state.withLock { $0.ready = newValue } } }
    private var closed: Bool { get { state.withLock { $0.closed } } set { state.withLock { $0.closed = newValue } } }
    private var busy: Bool { get { state.withLock { $0.busy } } set { state.withLock { $0.busy = newValue } } }
    private var attempt: PairingEnrollmentAttempt? { state.withLock { $0.attempt } }
    private var attemptActivity: ReleaseActivityToken? { state.withLock { $0.activity } }
    private final class Completion {
        let activity: ReleaseActivityToken?
        let finish: () -> Void
        let closed = Mutex(false)
        init(activity: ReleaseActivityToken?, finish: @escaping () -> Void) { self.activity = activity; self.finish = finish }
        func close() {
            guard closed.withLock({ if $0 { return false }; $0 = true; return true }) else { return }
            activity?.close(); finish()
        }
        deinit { close() }
    }
    private var expiryTimer: DispatchSourceTimer?

    convenience init(connection: NSXPCConnection, policy: XPCPeerPolicy, access: AuthorityPairingSetupAccess,
                     budget: AuthorityXPCWorkBudget, onHandshake: @escaping @Sendable () -> Void,
                     onClose: @escaping @Sendable () -> Void) throws {
        guard getuid() == 0, geteuid() == 0, policy.expectedUserID > 0 else { throw JournalLeaseError.rootRequired }
        _ = try policy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: policy)
        try access.verifyCurrent()
        self.init(access: access, budget: budget, verify: { _ = try invocation.verifyInvocation() },
            authorize: { try SetupAdministratorAuthorization.validate(externalForm: $0, invocation: invocation) },
            invalidate: { [weak connection] in connection?.invalidate(); onClose() }, onHandshake: onHandshake)
    }
    // Logical endpoint controls cannot establish native administrator consent or Root identity.
    init(access: AuthorityPairingSetupAccess, budget: AuthorityXPCWorkBudget, verify: @escaping () throws -> Void,
         authorize: @escaping (Data) throws -> Void, invalidate: @escaping () -> Void,
         onHandshake: @escaping @Sendable () -> Void = {}) {
        self.access = access; self.budget = budget; self.verify = verify; self.authorize = authorize
        self.invalidate = invalidate; self.onHandshake = onHandshake
    }
    deinit { expiryTimer?.cancel(); attemptActivity?.close() }
    /// Samples actual ownership without waiting for the operation lock or mutating the pairing lifetime.
    func maintenancePairingWork() throws -> AuthorityMaintenancePairingWork {
        try state.withLock {
            guard !$0.closed else { throw AuthorityPairingSetupError.unavailable }
            return .init(ready: $0.ready, stagedAttempts: $0.attempt == nil ? 0 : 1,
                activityOwners: ($0.activity == nil ? 0 : 1) + $0.operations.values.filter { $0 }.count,
                operationActive: $0.busy || !$0.operations.isEmpty)
        }
    }
    func requireMaintenanceAdmission(_ admission: AuthorityMaintenancePairingAdmission) throws {
        guard access.maintenanceAdmission === admission else { throw RuntimePreparationError.changedScope }
    }
    /// A closed endpoint remains work until its real reply and activity owners settle.
    func retainedMaintenancePairingWork() -> AuthorityMaintenancePairingWork? {
        state.withLock {
            if $0.closed && $0.operations.isEmpty && $0.stage == nil && $0.activity == nil { return nil }
            return .init(ready: $0.ready && !$0.closed, stagedAttempts: $0.attempt == nil ? 0 : 1,
                activityOwners: ($0.activity == nil ? 0 : 1) + $0.operations.values.filter { $0 }.count,
                operationActive: $0.busy || !$0.operations.isEmpty)
        }
    }
    func close() {
        let notify = lock.withLock {
            guard !closed else { return false }
            closed = true; ready = false; clearAttempt(); return true
        }
        if notify { invalidate() }
    }
    func pairingHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work(handshake: true) { ready = true }
            defer { completed.completion.close() }
            onHandshake(); send { reply(1) }
        } catch { close(); reply(0) }
    }
    func pairingContext(reply: @escaping @Sendable (Data?) -> Void) {
        respond(reply) { try access.context() }
    }
    func pairedPhoneHello(reply: @escaping @Sendable (UInt64) -> Void) {
        do {
            let completed = try work { state.withLock { $0.phoneManagement = true } }
            defer { completed.completion.close() }
            send { reply(1) }
        } catch { close(); reply(0) }
    }
    func managePairedPhone(_ operation: UInt64, selection: Data, authorization: Data,
                           reply: @escaping @Sendable (Data?) -> Void) {
        respond(reply) {
            guard state.withLock({ $0.phoneManagement }), let operation = PairedPhoneOperation(rawValue: operation) else {
                throw AuthorityPairingSetupError.unavailable
            }
            switch operation {
            case .list:
                guard selection.isEmpty, authorization.isEmpty else { throw AuthorityPairingSetupError.unavailable }
                return try access.pairedPhones().encode()
            case .listForRePair:
                guard selection.isEmpty, authorization.isEmpty else { throw AuthorityPairingSetupError.unavailable }
                return try access.pairedPhones(includeRePair: true).encode(includeRePair: true)
            case .validateRePair:
                guard authorization.isEmpty else { throw AuthorityPairingSetupError.unavailable }
                return try Data([access.canRePair(.decode(selection)) ? 1 : 0])
            case .status:
                guard authorization.isEmpty else { throw AuthorityPairingSetupError.unavailable }
                return try Data([UInt8(access.revocationStatus(.decode(selection)).rawValue)])
            case .revoke:
                guard attempt == nil, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AuthorityPairingSetupError.unavailable
                }
                let selection = try PairedPhoneSelection.decode(selection)
                try authorize(authorization)
                return try withPhoneMutationAdmission {
                    let status = try access.revokePhone(selection, authorize: { [authorize] in try authorize(authorization) })
                    return Data([UInt8(status.rawValue)])
                }
            case .listExpiredRePairs:
                guard selection.isEmpty, authorization.isEmpty else { throw AuthorityPairingSetupError.unavailable }
                return try access.expiredRePairs().encode()
            case .discardExpiredRePair:
                guard attempt == nil, selection.count == 48,
                      authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                    throw AuthorityPairingSetupError.invalidConfirmation
                }
                try authorize(authorization)
                return try withPhoneMutationAdmission {
                    try access.discardExpiredRePair(setupID: Data(selection.prefix(16)), digest: Data(selection.suffix(32)),
                                                   authorize: { [authorize] in try authorize(authorization) })
                    return Data([1])
                }
            }
        }
    }
    private func withPhoneMutationAdmission(_ body: () throws -> Data) throws -> Data {
        let stage = try access.maintenanceAdmission.reserveStage()
        defer { stage.close() }
        let replyStage = try stage.retained()
        state.withLock { state in
            if let id = state.currentOperation { state.retiringStages[id, default: []].append(replyStage) }
        }
        return try body()
    }

    func stagePairing(_ proposal: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        respond(reply) {
            guard attempt == nil, proposal.count <= 132_000,
                  authorization.count == MemoryLayout<AuthorizationExternalForm>.size else { throw AuthorityPairingSetupError.unavailable }
            try authorize(authorization)
            let stage = try access.maintenanceAdmission.reserveStage()
            let activity: ReleaseActivityToken?
            do { activity = try access.acquireReleaseActivity() } catch { stage.close(); throw error }
            var transferred = false
            defer { if !transferred { activity?.close(); stage.close() } }
            let replyStage = try stage.retained()
            state.withLock { s in if let id = s.currentOperation { s.retiringStages[id, default: []].append(replyStage) } }
            let staged = try access.stage(proposal, authorize: { [authorize] in try authorize(authorization) })
            let bytes = try staged.transcript.encode()
            try state.withLock {
                guard !$0.closed else { throw AuthorityPairingSetupError.unavailable }
                $0.attempt = staged; $0.activity = activity; $0.stage = stage
            }; transferred = true
            startExpiryTimer()
            return bytes
        }
    }
    func commitPairing(_ setupID: Data, confirmedDigest: Data, biometricProof: Data, authorization: Data,
                       reply: @escaping @Sendable (Data?) -> Void) {
        respond(reply) {
            guard let pending = attempt, authorization.count == MemoryLayout<AuthorizationExternalForm>.size else {
                throw AuthorityPairingSetupError.unavailable
            }
            // An ambiguous commit must reconcile its durable receipt. This connection cannot blindly commit again.
            clearAttempt()
            return try access.commit(pending, setupID: setupID, confirmedDigest: confirmedDigest, proof: biometricProof,
                authorize: { [authorize] in try authorize(authorization) })
        }
    }
    func cancelPairing(reply: @escaping @Sendable (Bool) -> Void) {
        do {
            let completed = try work { clearAttempt() }
            defer { completed.completion.close() }
            send { reply(true) }
        }
        catch { close(); reply(false) }
    }
    private func respond(_ reply: @escaping @Sendable (Data?) -> Void, _ body: () throws -> Data) {
        do {
            let completed = try work(body)
            defer { completed.completion.close() }
            send { reply(completed.value) }
        }
        catch { close(); reply(nil) }
    }
    private func work<T>(handshake: Bool = false, _ body: () throws -> T) throws -> (value: T, completion: Completion) {
        // Native checks stay on the original exported invocation stack.
        try verify()
        return try lock.withLock {
            guard !closed, !busy, ready != handshake, budget.acquire() else { throw AuthorityPairingSetupError.unavailable }
            let id = UUID()
            state.withLock { $0.busy = true; $0.currentOperation = id; $0.operations[id] = false }
            var completion: Completion?, transferred = false
            defer {
                state.withLock { $0.busy = false; $0.currentOperation = nil }; budget.release()
                if !transferred {
                    if let completion { completion.close() }
                    else { _ = state.withLock { $0.operations.removeValue(forKey: id) } }
                }
            }
            let activity = try access.acquireReleaseActivity()
            state.withLock { $0.operations[id] = activity != nil }
            let owned = Completion(activity: activity) { [self] in
                let stages = state.withLock { $0.retiringStages.removeValue(forKey: id) }; stages?.forEach { $0.close() }
                _ = state.withLock { $0.operations.removeValue(forKey: id) }
            }
            completion = owned
            try access.verifyCurrent()
            let value = try body()
            try activity?.validate()
            transferred = true
            return (value, owned)
        }
    }
    private func clearAttempt() {
        expiryTimer?.cancel(); expiryTimer = nil
        let stage = state.withLock { s -> AuthorityMaintenancePairingAdmission.Stage? in
            s.attempt = nil; guard let stage = s.stage else { return nil }; s.stage = nil
            if let id = s.currentOperation { s.retiringStages[id, default: []].append(stage); return nil }; return stage
        }
        attemptActivity?.close()
        state.withLock { $0.activity = nil }; stage?.close()
    }
    private func startExpiryTimer() {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        // Recheck the continuous authority clock after wake instead of extending setup by sleep duration.
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1), leeway: .milliseconds(100))
        timer.setEventHandler { [weak self] in self?.expireStagedIfNeeded() }
        expiryTimer = timer; timer.resume()
    }
    func expireStagedIfNeeded() {
        lock.withLock {
            guard !closed, !busy, let attempt else { return }
            do { if try access.isExpired(attempt) { clearAttempt() } }
            catch { clearAttempt() }
        }
    }

    private func send(_ reply: () -> Void) { lock.withLock { if !closed { reply() } } }
}

/// Existing presence selectors keep version 1. Pairing has an independent version handshake on the signed app channel.
@objc public protocol AuthorityAppXPCProtocol: AuthorityPresenceXPCProtocol, AuthorityPairingXPCProtocol, AuthorityPairedPhoneXPCProtocol {}

final class AuthorityAppXPCEndpoint: NSObject, AuthorityAppXPCProtocol, @unchecked Sendable {
    let presence: AuthorityPresenceXPCEndpoint
    let pairing: AuthorityPairingXPCEndpoint
    init(presence: AuthorityPresenceXPCEndpoint, pairing: AuthorityPairingXPCEndpoint) { self.presence = presence; self.pairing = pairing }
    func hello(reply: @escaping @Sendable (UInt64) -> Void) { presence.hello(reply: reply) }
    func current(reply: @escaping @Sendable (Data?) -> Void) { presence.current(reply: reply) }
    func publish(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) { presence.publish(payload, reply: reply) }
    func setMode(_ payload: Data, reply: @escaping @Sendable (Data?) -> Void) { presence.setMode(payload, reply: reply) }
    func pairingHello(reply: @escaping @Sendable (UInt64) -> Void) { pairing.pairingHello(reply: reply) }
    func pairingContext(reply: @escaping @Sendable (Data?) -> Void) { pairing.pairingContext(reply: reply) }
    func pairedPhoneHello(reply: @escaping @Sendable (UInt64) -> Void) { pairing.pairedPhoneHello(reply: reply) }
    func managePairedPhone(_ operation: UInt64, selection: Data, authorization: Data,
                           reply: @escaping @Sendable (Data?) -> Void) {
        pairing.managePairedPhone(operation, selection: selection, authorization: authorization, reply: reply)
    }
    func stagePairing(_ proposal: Data, authorization: Data, reply: @escaping @Sendable (Data?) -> Void) {
        pairing.stagePairing(proposal, authorization: authorization, reply: reply)
    }
    func commitPairing(_ setupID: Data, confirmedDigest: Data, biometricProof: Data, authorization: Data,
                       reply: @escaping @Sendable (Data?) -> Void) {
        pairing.commitPairing(setupID, confirmedDigest: confirmedDigest, biometricProof: biometricProof, authorization: authorization, reply: reply)
    }
    func cancelPairing(reply: @escaping @Sendable (Bool) -> Void) { pairing.cancelPairing(reply: reply) }
}
