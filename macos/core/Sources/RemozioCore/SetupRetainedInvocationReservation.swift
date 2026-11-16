import Darwin
import Foundation

/// Keeps admission and cleanup independently of the invocation. Object loss never proves settlement.
final class SetupRetainedInvocationReservation: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    var description: String { "SetupRetainedInvocationReservation(redacted)" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    // Lock order: owner, record, ledger. The ledger never calls external code while holding its lock.
    // RecoveryToken and SetupRetainedOrphanClaim deinit take this lock. Never release either object under this lock.
    // Keep a strong invocation parameter through each locked weak load. Release removed cleanup closures outside this lock.
    // Invocation deinit takes this lock, so dropping its last strong reference while holding it would deadlock.
    enum State: Equatable { case reserved, attached, orphan, recovering, settled }
    let admission: SetupOwnerAsyncWork.Token
    private let reply: SetupOwnerAsyncWork.Token
    private let activity: ReleaseActivityToken?
    private let statusID = UUID()
    private let authenticatedPeerUID: uid_t
    private let authenticatedOwner: LocalAccountIdentity?
    private let recovery: SetupRetainedRecoveryLedger
    private var recoverySeal: UUID?, recoveryClaimID: UUID?
    private var recoveryClaimLive = false
    private let ownerUID = getuid()
    private var capturedBinding: SetupRetainedInvocationStatus.Binding?
    private var capturedWindow: SetupRetainedInvocationStatus.Window?
    private let incarnation: UUID
    private let process = getpid()
    private let lock: NSLock
    private weak var invocation: SetupRetainedInvocation?
    private var invocationID: ObjectIdentifier?
    private var phase: State = .reserved
    private var worker = false, settling = false

    /// An injected status lock is an ordinary-owner test seam. Root cannot inject this lock.
    init(authenticatedPeer: XPCPeerCredentials, incarnation: UUID, admission: SetupOwnerAsyncWork.Token, reply: SetupOwnerAsyncWork.Token,
         activity: ReleaseActivityToken?, ownedStatusLock: NSLock? = nil, authenticatedOwner: LocalAccountIdentity? = nil,
         recoveryExecutor: SetupAuditUpgradeWorkExecutor? = nil) throws {
        guard authenticatedPeer.processID > 0, authenticatedPeer.userID > 0, authenticatedPeer.userID < UInt32.max else {
            throw XPCPeerPolicyError.wrongPeer
        }
        if ownedStatusLock != nil { try RuntimeMaintenanceOwnedControl.require() }
        guard authenticatedOwner == nil || authenticatedOwner?.uid == authenticatedPeer.userID else { throw XPCPeerPolicyError.wrongPeer }
        self.authenticatedOwner = authenticatedOwner; recovery = .init(executor: recoveryExecutor)
        lock = ownedStatusLock ?? NSLock()
        authenticatedPeerUID = authenticatedPeer.userID
        self.incarnation = incarnation; self.admission = admission; self.reply = reply; self.activity = activity
    }
    /// The caller has already checked the actual exported peer and current directory identity. No native caller exists yet.
    func status(authenticatedPeer peer: XPCPeerCredentials, currentOwner: LocalAccountIdentity) -> SetupRetainedInvocationStatus {
        guard getpid() == process, getuid() == ownerUID, geteuid() == ownerUID,
              peer.processID > 0, peer.userID == authenticatedPeerUID, currentOwner.uid == authenticatedPeerUID,
              lock.try() else { return .unavailable }
        defer { lock.unlock() }
        if let authenticatedOwner, authenticatedOwner != currentOwner { return .unavailable }
        if let capturedBinding, !capturedBinding.matches(currentOwner) { return .unavailable }
        let observed: SetupRetainedInvocationStatus.Reservation
        switch phase {
        case .reserved: observed = .reserved
        case .attached: observed = .attached
        case .orphan: observed = .orphan
        case .recovering: observed = .recovering
        case .settled: observed = .settled
        }
        let cleanupState: SetupRetainedInvocationStatus.Fact<SetupRetainedInvocationStatus.Cleanup>
        if phase == .settled { cleanupState = .observed(.settled) }
        else if settling { cleanupState = .observed(.joining) }
        else { cleanupState = recovery.status() }
        return .reservation(observed, identity: .init(reservationID: statusID, incarnation: incarnation), binding: capturedBinding,
            expectedWindow: capturedWindow, worker: recovery.workerStatus(synchronous: worker), cleanup: cleanupState)
    }
    /// Store only a completed protected capture, never an unvalidated target hint or request UID.
    func bind(_ value: SetupRetainedCallerBinding, invocation owner: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(owner) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try requireAttached(owner)
            guard value.peer == owner.peer, value.peer.userID == authenticatedPeerUID,
                  value.authorityOwner.uid == authenticatedPeerUID, value.incarnation == incarnation else {
                throw XPCPeerPolicyError.wrongPeer
            }
            guard authenticatedOwner == nil || authenticatedOwner == value.authorityOwner else { throw RuntimePreparationError.changedScope }
            let binding = try SetupRetainedInvocationStatus.capturedBinding(value)
            guard capturedBinding == nil || capturedBinding == binding else { throw RuntimePreparationError.changedScope }
            capturedBinding = binding
        }
    }
    /// Pins authorized metadata only. A matching row still needs a protected read before it supplies outcomes.
    func bindWindow(_ window: RuntimeMaintenanceWindowRecord, invocation owner: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(owner) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try requireAttached(owner)
            guard let capturedBinding, capturedBinding.matches(window.scope) else { throw RuntimePreparationError.changedScope }
            let identity = SetupRetainedInvocationStatus.Window(window)
            guard capturedWindow == nil || capturedWindow == identity else { throw RuntimePreparationError.changedScope }
            try recovery.windowMayBeWritten()
            capturedWindow = identity
        }
    }
    /// Captured maintenance inputs can produce writable metadata even without authorizedMaintenanceWindow.
    func maintenanceCaptured(invocation owner: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(owner) {} }
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            try requireAttached(owner)
            guard capturedBinding != nil else { throw RuntimePreparationError.changedScope }
            try recovery.windowMayBeWritten()
        }
    }
    /// Revision changes during the chain. Its window ID, purpose and full immutable scope must stay pinned.
    func recapturingWindow(_ window: RuntimeMaintenanceWindowRecord,
        transitions: [PreparationIntentStore.RuntimeMaintenanceTransition], invocation owner: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(owner) {} }
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            try requireAttached(owner)
            try recovery.windowMayBeWritten()
            guard let capturedWindow, capturedWindow.identifies(window), !transitions.isEmpty,
                  transitions.allSatisfy({ capturedWindow.identifies($0.record) }) else {
                throw RuntimePreparationError.changedScope
            }
        }
    }
    func state() throws -> State {
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        return lock.withLock { currentState() }
    }
    private func currentState() -> State { phase }
    /// A deinit notification avoids taking the last strong invocation reference on the bounded status read path.
    func invocationDidDeinit(_ id: ObjectIdentifier, incarnation: UUID) -> Bool {
        guard getpid() == process else { return false }
        return lock.withLock {
            guard invocationID == id, self.incarnation == incarnation, phase == .attached else { return false }
            phase = .orphan; return true
        }
    }
    func invocationCleanupReturned(_ id: ObjectIdentifier, incarnation: UUID) {
        guard getpid() == process else { return }
        let exact = lock.withLock { invocationID == id && self.incarnation == incarnation && (phase == .orphan || phase == .recovering) }
        if exact { recovery.invocationCleanupReturned() }
    }
    func attach(_ value: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard phase == .reserved, value.belongs(to: self), value.incarnation == incarnation else { throw XPCPeerPolicyError.wrongConnection }
            invocation = value; invocationID = ObjectIdentifier(value); phase = .attached
        }
    }
    func verify() throws {
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            guard currentState() == .reserved || phase == .attached, !settling else { throw AdministrativeSetupError.unavailable }
            try activity?.validate()
        }
    }
    func beginWorker(_ value: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try requireAttached(value)
            guard !worker else { throw AdministrativeSetupError.unavailable }
            try recovery.beginWorker()
            worker = true
        }
    }
    func endWorker(_ value: SetupRetainedInvocation) {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { return }
        lock.withLock { if invocation === value { worker = false } }
    }
    /// Retain the actual cleanup owner before borrowing its resources. Failed cleanup remains in this reservation.
    func retainCleanup(_ value: SetupRetainedInvocation, _ close: @escaping () throws -> Void) throws {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock { try requireAttached(value); try recovery.retainCleanup(close) }
    }
    func retainWorker(_ value: SetupRetainedInvocation, task: Task<Void, Never>) throws {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock { try requireAttached(value); try recovery.retainWorker(task) }
    }
    func ledgerForJoin(_ value: SetupRetainedInvocation) throws -> SetupRetainedRecoveryLedger {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        return try lock.withLock { try requireAttached(value); guard !worker else { throw AdministrativeSetupError.unavailable }; return recovery }
    }
    func withContextLoan<Value>(_ value: SetupRetainedInvocation, body: () throws -> Value) throws -> Value {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        try lock.withLock { try requireAttached(value); guard worker else { throw JournalLeaseError.invalidated } }
        return try recovery.withContextLoan(body)
    }
    private func requireAttached(_ value: SetupRetainedInvocation) throws {
        guard currentState() == .attached, invocation === value, value.incarnation == incarnation, !settling else {
            throw AdministrativeSetupError.unavailable
        }
    }
    /// Construction has no worker or native loan. Only its exact reserved record can take this exit.
    func abortConstruction() {
        guard getpid() == process else { return }
        lock.withLock {
            guard phase == .reserved else { return }
            phase = .settled; activity?.close(); admission.close(); reply.close()
        }
    }
    /// The synchronous worker has returned through all scoped loans. Each retained cleanup must also return successfully.
    func settle(_ value: SetupRetainedInvocation, finalCleanup: () -> Void = {}) throws {
        defer { withExtendedLifetime(value) {} }
        guard getpid() == process else { throw AdministrativeSetupError.unavailable }
        try lock.withLock {
            try requireAttached(value)
            guard !worker else { throw AdministrativeSetupError.unavailable }
            settling = true
        }
        defer { lock.withLock { settling = false } }
        try recovery.closeSynchronousCleanup()
        finalCleanup(); recovery.invocationCleanupReturned()
        lock.withLock {
            phase = .settled; activity?.close(); admission.close(); reply.close()
        }
    }
    /// This target is private metadata from the actual record. Fresh rights still authorize the separate claim.
    func recoveryTarget(authorization: SetupRetainedRecoveryAuthorization) throws -> SetupRetainedOrphanClaim.Target {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        return try lock.withLock {
            try requireRecoveryOwner(authorization)
            guard phase == .orphan || (phase == .recovering && !recoveryClaimLive) else { throw AdministrativeSetupError.unavailable }
            return .init(record: self, identity: .init(reservationID: statusID, incarnation: incarnation),
                binding: capturedBinding, window: capturedWindow)
        }
    }
    private func requireRecoveryOwner(_ authorization: SetupRetainedRecoveryAuthorization) throws {
        guard getpid() == process, getuid() == ownerUID, geteuid() == ownerUID,
              let authenticatedOwner, authorization.peer.processID > 0,
              authorization.peer.userID == authenticatedPeerUID, authorization.currentOwner == authenticatedOwner,
              authorization.incarnation != incarnation else { throw XPCPeerPolicyError.wrongPeer }
        if let capturedBinding, !capturedBinding.matches(authorization.currentOwner) { throw XPCPeerPolicyError.wrongPeer }
    }
    func claim(_ target: SetupRetainedOrphanClaim.Target,
        authorization: SetupRetainedRecoveryAuthorization) throws -> (token: RecoveryToken, retiredTask: Task<Void, any Error>?) {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        return try lock.withLock {
            try requireRecoveryOwner(authorization)
            guard target.record === self, target.identity == .init(reservationID: statusID, incarnation: incarnation),
                  target.binding == capturedBinding, target.window == capturedWindow,
                  phase == .orphan || (phase == .recovering && !recoveryClaimLive), !worker, !settling else {
                throw AdministrativeSetupError.unavailable
            }
            let retiredTask = try recovery.sealForClaim()
            let seal = recoverySeal ?? UUID(), claim = UUID()
            recoverySeal = seal; recoveryClaimID = claim; recoveryClaimLive = true; phase = .recovering
            return (RecoveryToken(record: self, seal: seal, claim: claim), retiredTask)
        }
    }
    private func requireRecovery(seal: UUID, claim: UUID) throws {
        guard getpid() == process, getuid() == ownerUID, geteuid() == ownerUID, phase == .recovering,
              recoverySeal == seal, recoveryClaimID == claim, recoveryClaimLive else { throw JournalLeaseError.invalidated }
    }
    private func releaseWindowFree(seal: UUID, claim: UUID) throws -> Bool {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        return try lock.withLock {
            try requireRecovery(seal: seal, claim: claim)
            let evidence = try recovery.requireJoined()
            guard capturedWindow == nil, evidence.windowWriteNeverPossible else { return false }
            phase = .settled; activity?.close(); admission.close(); reply.close()
            return true
        }
    }
    /// Only this record can mint a token for its sealed generation. The token grants no restoration or body replay.
    final class RecoveryToken: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        var description: String { "SetupRetainedRecoveryToken(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        private let record: SetupRetainedInvocationReservation, seal: UUID, claim: UUID
        fileprivate init(record: SetupRetainedInvocationReservation, seal: UUID, claim: UUID) {
            self.record = record; self.seal = seal; self.claim = claim
        }
        func requireCurrent() throws {
            guard getpid() == record.process else { throw JournalLeaseError.invalidated }
            try record.lock.withLock { try record.requireRecovery(seal: seal, claim: claim) }
        }
        func joinTask() throws -> Task<Void, any Error> { try requireCurrent(); return try record.recovery.joinSealed() }
        func joinedEvidence() throws -> SetupRetainedRecoveryLedger.Evidence { try requireCurrent(); return try record.recovery.requireJoined() }
        func releaseWindowFree() throws -> Bool { try record.releaseWindowFree(seal: seal, claim: claim) }
        func ownerDropped() {
            guard getpid() == record.process else { return }
            record.lock.withLock {
                if record.recoverySeal == seal, record.recoveryClaimID == claim { record.recoveryClaimLive = false }
            }
        }
        deinit { ownerDropped() }
    }

}
