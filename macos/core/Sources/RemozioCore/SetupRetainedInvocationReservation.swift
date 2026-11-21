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
    /// Owns both tokens and the activity. Release goes through this value, so a running phase body keeps them until it returns.
    let hold: SetupAccountOwner.ExecutorAdmission
    private let activity: ReleaseActivityToken?
    private let statusID = UUID()
    private let authenticatedPeerUID: uid_t
    private let authenticatedOwner: LocalAccountIdentity
    private let recovery: SetupRetainedRecoveryLedger
    private let recoveryExecutor: SetupAuditUpgradeWorkExecutor?
    private let recoverySignal: (@Sendable () -> Void)?
    private var recoverySeal: UUID?, recoveryClaimID: UUID?
    private var recoveryClaimLive = false
    private var restorationWork: RestorationWork?
    private var restorationClaimID: UUID?
    private var restorationJoined = true
    private var savedTargetRecoveryTransition: PreparationIntentStore.RuntimeMaintenanceTransition?
    private var unboundAuthorizedRecoveryTransition: PreparationIntentStore.RuntimeMaintenanceTransition?
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
         activity: ReleaseActivityToken?, ownedStatusLock: NSLock? = nil, authenticatedOwner: LocalAccountIdentity,
         recoveryExecutor: SetupAuditUpgradeWorkExecutor? = nil, hold: SetupAccountOwner.ExecutorAdmission? = nil,
         recoverySignal: (@Sendable () -> Void)? = nil) throws {
        guard authenticatedPeer.processID > 0, authenticatedPeer.userID > 0, authenticatedPeer.userID < UInt32.max else {
            throw XPCPeerPolicyError.wrongPeer
        }
        if ownedStatusLock != nil { try RuntimeMaintenanceOwnedControl.require() }
        guard authenticatedOwner.uid == authenticatedPeer.userID else { throw XPCPeerPolicyError.wrongPeer }
        self.authenticatedOwner = authenticatedOwner; self.recoveryExecutor = recoveryExecutor; self.recoverySignal = recoverySignal
        // The owner passes the hold it made for these tokens. Without one, only an Owned test can build a record.
        let recordHold: SetupAccountOwner.ExecutorAdmission
        if let hold { recordHold = hold }
        else { recordHold = try SetupAccountOwner.ExecutorAdmission.durableOwned(admission: admission, reply: reply, activity: activity) }
        guard recordHold.admission === admission, recordHold.reply === reply else { throw AdministrativeSetupError.unavailable }
        self.hold = recordHold; recovery = .init(executor: recoveryExecutor, hold: recordHold)
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
        if authenticatedOwner != currentOwner { return .unavailable }
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
        else if settling || !restorationJoined { cleanupState = .observed(.joining) }
        else { cleanupState = recovery.status() }
        return .reservation(observed, identity: .init(reservationID: statusID, incarnation: incarnation), binding: capturedBinding,
            expectedWindow: capturedWindow,
            worker: !restorationJoined ? .observed(.registered) : recovery.workerStatus(synchronous: worker), cleanup: cleanupState)
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
            guard authenticatedOwner == value.authorityOwner else { throw RuntimePreparationError.changedScope }
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
    /// An actual writer receipt preserves the old phase. Metadata alone cannot grant reconnect eligibility.
    func retainMaintenanceRecoveryTransition(_ receipt: PreparationIntentStore.RuntimeMaintenanceTransition,
        invocation owner: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(owner) {} }
        guard getpid() == process, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
        try lock.withLock {
            try requireAttached(owner)
            guard let capturedWindow, capturedWindow.identifies(receipt.record),
                  capturedBinding?.matches(receipt.record.scope) == true else { throw RuntimePreparationError.changedScope }
            try receipt.requireSavedTargetReconnectOrigin(receipt.record)
            savedTargetRecoveryTransition = receipt
        }
    }
    func retainUnboundAuthorizedOriginTransition(_ receipt: PreparationIntentStore.RuntimeMaintenanceTransition,
        invocation owner: SetupRetainedInvocation) throws {
        defer { withExtendedLifetime(owner) {} }
        guard getpid() == process, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
        let authorized = try receipt.requireUnboundAuthorizedRecoveryOrigin()
        try lock.withLock {
            try requireAttached(owner)
            guard capturedWindow == SetupRetainedInvocationStatus.Window(authorized),
                  capturedBinding?.matches(authorized.scope) == true else { throw RuntimePreparationError.changedScope }
            if let existing = unboundAuthorizedRecoveryTransition {
                guard existing.record == receipt.record,
                      try existing.requireUnboundAuthorizedRecoveryOrigin() == authorized else {
                    throw PreparationStoreError.staleRevision
                }
            }
            unboundAuthorizedRecoveryTransition = receipt
        }
    }
    /// A live in-process record needs its Joined origin. A settled record no longer has that origin.
    func excludesRestart(accountID: Data, owner: LocalAccountIdentity, windowID: Data?) throws -> Bool {
        guard getpid() == process, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
        return lock.withLock {
            phase != .settled && (authenticatedPeerUID == owner.uid
                || capturedBinding?.authority.accountID == accountID || capturedBinding?.target.accountID == accountID
                || (windowID != nil && capturedWindow?.id == windowID))
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
        let changed = lock.withLock {
            guard invocationID == id, self.incarnation == incarnation, phase == .attached else { return false }
            phase = .orphan; return true
        }
        // This deinit callback can acquire owner.lock. Never invoke it while the record lock is held.
        // Owner-locked code must not drop the last invocation reference.
        if changed { recoverySignal?() }
        return changed
    }
    func invocationCleanupReturned(_ id: ObjectIdentifier, incarnation: UUID) {
        guard getpid() == process else { return }
        let exact = lock.withLock { invocationID == id && self.incarnation == incarnation && (phase == .orphan || phase == .recovering) }
        if exact { recovery.invocationCleanupReturned(); recoverySignal?() }
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
        let release = lock.withLock { () -> (@Sendable () -> Void)? in
            guard phase == .reserved else { return nil }
            phase = .settled
            return hold.markRecordReleased()
        }
        release?()
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
        let release = lock.withLock {
            phase = .settled
            return hold.markRecordReleased()
        }
        release()
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
              authorization.peer.processID > 0,
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
        let release = try lock.withLock { () throws -> (@Sendable () -> Void)? in
            try requireRecovery(seal: seal, claim: claim)
            let evidence = try recovery.requireJoined()
            guard capturedWindow == nil, evidence.windowWriteNeverPossible else { return nil }
            phase = .settled
            return hold.markRecordReleased()
        }
        guard let release else { return false }
        release()
        return true
    }
    /// Uses the original owner's executor. This capability never creates another worker executor.
    final class RestorationPhases: @unchecked Sendable {
        /// A phase-named control for ordinary-owner tests. It can shorten, never extend, the real deadline.
        struct OwnedDeadlineControl: Sendable {
            enum Phase: Sendable { case beforePending, beforeRestored, afterRestored }
            /// Declares the test trigger point. Production checks only the expiry predicate.
            let phase: Phase
            let expired: @Sendable () -> Bool
            init(phase: Phase, expired: @escaping @Sendable () -> Bool) throws {
                try RuntimeMaintenanceOwnedControl.require()
                self.phase = phase; self.expired = expired
            }
        }
        private let executor: SetupAuditUpgradeWorkExecutor
        private let hold: SetupAccountOwner.ExecutorAdmission
        private let deadline: ContinuousClock.Instant?
        private let cancellation: SetupAuditUpgradeCancellation?
        private let validate: @Sendable () throws -> Void
        private let ownedExpiration: OwnedDeadlineControl?
        private let unboundStartupPhase: Bool
        private let processID = getpid(), ownerUID = getuid()
        fileprivate init(executor: SetupAuditUpgradeWorkExecutor, hold: SetupAccountOwner.ExecutorAdmission, deadline: ContinuousClock.Instant? = nil,
            ownedExpiration: OwnedDeadlineControl? = nil, cancellation: SetupAuditUpgradeCancellation? = nil,
            validate: @escaping @Sendable () throws -> Void = {}, unboundStartupPhase: Bool = false) {
            self.executor = executor; self.hold = hold; self.deadline = deadline; self.ownedExpiration = ownedExpiration
            self.cancellation = cancellation; self.validate = validate
            self.unboundStartupPhase = unboundStartupPhase
        }
        static func maintenanceRecovery(permit: SetupAccountOwner.MaintenanceRecoveryPhasePermit,
            deadline: ContinuousClock.Instant?, cancellation: SetupAuditUpgradeCancellation?,
            validate: @escaping @Sendable () throws -> Void) -> RestorationPhases {
            .init(executor: permit.executor, hold: permit.held, deadline: deadline, cancellation: cancellation,
                validate: validate, unboundStartupPhase: true)
        }
        static func owned(executor: SetupAuditUpgradeWorkExecutor, hold: SetupAccountOwner.ExecutorAdmission, deadline: ContinuousClock.Instant? = nil,
            cancellation: SetupAuditUpgradeCancellation? = nil) throws -> RestorationPhases {
            try hold.requireFreshOwnedPhaseFixture()
            return .init(executor: executor, hold: hold, deadline: deadline, cancellation: cancellation)
        }
        /// The owner alone can issue this permit. Restart uses that owner's original executor.
        static func restart(permit: SetupAccountOwner.RestartPermit) -> RestorationPhases {
            .init(executor: permit.executor, hold: permit.hold)
        }
        private func requireProcess() throws {
            guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
        }
        func forAttempt(until deadline: ContinuousClock.Instant) throws -> RestorationPhases {
            try requireProcess(); return .init(executor: executor, hold: hold, deadline: deadline, cancellation: cancellation,
                validate: validate, unboundStartupPhase: unboundStartupPhase)
        }
        func forOwnedAttempt(until deadline: ContinuousClock.Instant,
            expiration: OwnedDeadlineControl) throws -> RestorationPhases {
            try RuntimeMaintenanceOwnedControl.require(); try requireProcess()
            return .init(executor: executor, hold: hold, deadline: deadline, ownedExpiration: expiration, cancellation: cancellation,
                validate: validate, unboundStartupPhase: unboundStartupPhase)
        }
        func requireUnboundStartupPhase() throws {
            try requireUnboundStartupPhaseInMemory(); try validate(); try requireUnboundStartupPhaseInMemory()
        }
        func requireUnboundStartupPhaseInMemory() throws {
            try requireProcess()
            guard unboundStartupPhase else { throw JournalLeaseError.invalidated }
            try hold.requireUnboundStartupAdmission()
        }
        private func requireDeadline(_ deadline: ContinuousClock.Instant?) throws {
            if let deadline, ContinuousClock.now >= deadline {
                if cancellation != nil { throw RuntimeMaintenanceStartupAttemptError.deadlineExpired }
                throw CancellationError()
            }
        }
        private func once<Value: Sendable>(until deadline: ContinuousClock.Instant?, cleanup: Bool,
            _ body: @escaping @Sendable () throws -> Value) async throws -> Value {
            try requireProcess(); try Task.checkCancellation()
            let token = cleanup ? SetupAuditUpgradeCancellation() : cancellation ?? SetupAuditUpgradeCancellation()
            let validate = self.validate, ownedExpiration = self.ownedExpiration
            return try await hold.runRestorationPhase(on: executor, cancellation: token) { _ in
                if !cleanup { try validate() }
                try self.requireDeadline(deadline)
                if deadline != nil, ownedExpiration?.expired() == true {
                    if self.cancellation != nil { throw RuntimeMaintenanceStartupAttemptError.deadlineExpired }
                    throw CancellationError()
                }
                try token.check()
                return try body()
            }
        }
        private func admitted<Value: Sendable>(until deadline: ContinuousClock.Instant?, cleanup: Bool = false,
            _ body: @escaping @Sendable () throws -> Value) async throws -> Value {
            while true {
                do { return try await once(until: deadline, cleanup: cleanup, body) }
                catch is SetupAuditUpgradeWorkExecutor.BusyBeforeBody {
                    try Task.checkCancellation()
                    try requireDeadline(deadline)
                    try await ContinuousClock().sleep(for: .milliseconds(25))
                }
            }
        }
        /// Construction makes one admission attempt. A busy result proves that no body started.
        func acquire<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value {
            try await afterRelease(until: deadline, released: { throw JournalLeaseError.invalidated }) {
                try await self.once(until: self.deadline, cleanup: false, body)
            }
        }
        func run<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value {
            try await afterRelease(until: deadline, released: { throw JournalLeaseError.invalidated }) {
                try await self.admitted(until: self.deadline, body)
            }
        }
        /// Actual cleanup ignores caller cancellation and the attempt deadline. It never repeats a started body.
        func cleanup<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value {
            try requireProcess()
            let cleanup = Task { try await self.admitted(until: nil, cleanup: true, body) }
            return try await afterRelease(until: nil, released: { throw JournalLeaseError.invalidated }) {
                try await cleanup.value
            }
        }
        /// No body starts when the record has released its admission.
        func cleanupUnlessReleased<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value? {
            try requireProcess()
            let cleanup = Task { try await self.admitted(until: nil, cleanup: true, body) }
            return try await afterRelease(until: nil, released: { nil }) {
                let value = try await cleanup.value
                return Optional.some(value)
            }
        }
        private func afterRelease<Value>(until deadline: ContinuousClock.Instant?, released: () throws -> Value,
            _ operation: () async throws -> Value) async throws -> Value {
            let result: Result<Value, any Error>
            do { result = .success(try await operation()) }
            catch is SetupAccountOwner.ExecutorAdmission.Released {
                await hold.waitForReleaseAfterRecord(until: deadline)
                return try released()
            }
            catch { result = .failure(error) }
            await hold.waitForReleaseAfterRecord(until: deadline)
            return try result.get()
        }
        /// Records cannot release while their restoration work still owns custody.
        func closeActual(_ body: @escaping @Sendable () -> Void) async throws {
            try await cleanup { body() }
        }
    }
    /// A typed slot for restoration only. The sealed general worker ledger stays closed permanently.
    final class RestorationWork: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        typealias Completion = RuntimeMaintenanceStartupRecovery.ExplicitCompletion
        let id: UUID
        private let task: Task<Completion, any Error>
        private let processID = getpid(), ownerUID = getuid()
        private let lock = NSLock()
        private var returned = false, completed = false
        fileprivate init(id: UUID, start: RestorationStart,
            body: @escaping @Sendable (UUID) async throws -> Completion) {
            self.id = id
            task = Task { await start.wait(); return try await body(id) }
        }
        /// The private start barrier is shared only through an owner-issued restart permit.
        static func restart(permit: SetupAccountOwner.RestartPermit,
            body: @escaping @Sendable (UUID) async throws -> Completion) -> (work: RestorationWork, open: @Sendable () -> Void) {
            let barrier = RestorationStart()
            let work = RestorationWork(id: UUID(), start: barrier, body: body)
            return (work, { barrier.open() })
        }
        func requestCancellation(using _: AdministrativeSetupShutdown.RecoveryCancellation) {
            guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { return }
            task.cancel()
        }
        func value() async throws -> Completion {
            guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
            let result = await task.result
            lock.withLock {
                returned = true
                if case .success = result { completed = true }
            }
            return try result.get()
        }
        var actualReturnObserved: Bool {
            guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { return false }
            return lock.withLock { returned }
        }
        var holdsUnsettledCompletion: Bool { lock.withLock { completed } }
        var description: String { "SetupRetainedRestorationWork(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    }
    /// The slot must retain the actual task before its first custody acquisition or RPC can start.
    fileprivate final class RestorationStart: @unchecked Sendable {
        private let lock = NSLock()
        private var opened = false
        private var waiter: CheckedContinuation<Void, Never>?
        func wait() async {
            await withCheckedContinuation { continuation in
                let ready = lock.withLock {
                    if opened { return true }; waiter = continuation; return false
                }
                if ready { continuation.resume() }
            }
        }
        func open() {
            let pending = lock.withLock { () -> CheckedContinuation<Void, Never>? in
                opened = true; let pending = waiter; waiter = nil; return pending
            }
            pending?.resume()
        }
    }
    private func requireJoinedRecovery(seal: UUID, claim: UUID) throws -> SetupRetainedRecoveryLedger.Evidence {
        try requireRecovery(seal: seal, claim: claim)
        guard restorationJoined else { throw AdministrativeSetupError.unavailable }
        return try recovery.requireJoined()
    }
    enum RecoveryApplicability: Equatable, Sendable { case noCompletion, unsettledCompletion, windowFree }
    /// Reads only this joined claim. No work, writer, state transition or cleanup starts here.
    private func recoveryApplicability(seal: UUID, claim: UUID) throws -> RecoveryApplicability {
        try lock.withLock {
            let evidence = try requireJoinedRecovery(seal: seal, claim: claim)
            if restorationWork?.holdsUnsettledCompletion == true { return .unsettledCompletion }
            if capturedWindow == nil && evidence.windowWriteNeverPossible { return .windowFree }
            return .noCompletion
        }
    }
    private func requireRestorationWindow(_ row: RuntimeMaintenanceWindowRecord, seal: UUID, claim: UUID) throws {
        try requireRecovery(seal: seal, claim: claim)
        guard let capturedWindow, capturedWindow.identifies(row), let capturedBinding,
              capturedBinding.matches(row.scope) else { throw RuntimePreparationError.changedScope }
    }
    private func joinRecovery(seal: UUID, claim: UUID) throws -> Task<Void, any Error> {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        let (original, restoration) = try lock.withLock {
            try requireRecovery(seal: seal, claim: claim)
            return (try recovery.joinSealed(), restorationWork)
        }
        return Task {
            try await original.value
            if let restoration { _ = try? await restoration.value() }
            try self.lock.withLock {
                try self.requireRecovery(seal: seal, claim: claim)
                guard self.restorationWork === restoration else { throw JournalLeaseError.invalidated }
                self.restorationJoined = true
            }
        }
    }
    private func startRestoration(seal: UUID, claim: UUID,
        session: AdministrativeSetupShutdown.RecoverySessionWork? = nil,
        body: @escaping @Sendable (UUID) async throws -> RuntimeMaintenanceStartupRecovery.ExplicitCompletion) throws -> RestorationWork {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        let start = RestorationStart()
        let (current, retired) = try lock.withLock {
            _ = try requireJoinedRecovery(seal: seal, claim: claim)
            guard capturedWindow != nil, capturedBinding != nil, restorationClaimID != claim else {
                throw AdministrativeSetupError.unavailable
            }
            let retired = restorationWork
            guard retired == nil || retired?.actualReturnObserved == true,
                  retired?.holdsUnsettledCompletion != true else { throw AdministrativeSetupError.unavailable }
            let current = RestorationWork(id: UUID(), start: start, body: body)
            restorationWork = current; restorationClaimID = claim; restorationJoined = false
            return (current, retired)
        }
        // A retired result may own a claim through its error. Drop it outside every record or owner lock.
        withExtendedLifetime(retired) {}
        session?.retainRestoration(current)
        start.open()
        return current
    }
    private func currentRestoration(seal: UUID, claim: UUID) throws -> RestorationWork {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        return try lock.withLock {
            try requireRecovery(seal: seal, claim: claim)
            guard let restorationWork else { throw PreparationStoreError.notFound }
            return restorationWork
        }
    }
    private func settleRestoration(_ completed: RuntimeMaintenanceStartupRecovery.ExplicitCompletion,
        work: RestorationWork, seal: UUID, claim: UUID) throws {
        guard getpid() == process else { throw JournalLeaseError.invalidated }
        let release = try lock.withLock {
            try requireRecovery(seal: seal, claim: claim)
            _ = try recovery.requireJoined()
            guard restorationWork === work, work.actualReturnObserved, completed.workID == work.id else {
                throw JournalLeaseError.invalidated
            }
            try requireRestorationWindow(completed.window, seal: seal, claim: claim)
            guard completed.window.phase == .restored, completed.window.gate?.hold == .released,
                  completed.window.gate?.admission == .available else { throw RuntimePreparationError.changedScope }
            try activity?.validate()
            restorationJoined = true
            phase = .settled
            return hold.markRecordReleased()
        }
        release()
        recoverySignal?()
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
        func joinTask() throws -> Task<Void, any Error> { try record.joinRecovery(seal: seal, claim: claim) }
        func joinedEvidence() throws -> SetupRetainedRecoveryLedger.Evidence {
            guard getpid() == record.process else { throw JournalLeaseError.invalidated }
            return try record.lock.withLock { try record.requireJoinedRecovery(seal: seal, claim: claim) }
        }
        func requireRestorationWindow(_ row: RuntimeMaintenanceWindowRecord) throws {
            guard getpid() == record.process else { throw JournalLeaseError.invalidated }
            try record.lock.withLock { try record.requireRestorationWindow(row, seal: seal, claim: claim) }
        }
        func requireUnboundAuthorizedOrigin(_ row: RuntimeMaintenanceWindowRecord) throws -> RuntimeMaintenanceWindowRecord {
            guard getpid() == record.process else { throw JournalLeaseError.invalidated }
            return try record.lock.withLock {
                try record.requireRecovery(seal: seal, claim: claim)
                let evidence = try record.recovery.requireJoined()
                guard evidence.neverEntered, evidence.stopNeverPossible,
                      row.purpose == .retainedRuntime, row.operation == .notStarted, row.service == .notStopped,
                      row.shutdownBinding == nil, row.unboundRelease == nil,
                      record.capturedBinding?.matches(row.scope) == true else { throw RuntimePreparationError.changedScope }
                let authorized: RuntimeMaintenanceWindowRecord
                if row.phase == .authorized { authorized = row }
                else {
                    guard row.phase == .needsOwnerRecovery, let receipt = record.unboundAuthorizedRecoveryTransition,
                          receipt.record == row else { throw RuntimePreparationError.changedScope }
                    authorized = try receipt.requireUnboundAuthorizedRecoveryOrigin()
                }
                guard record.capturedWindow == SetupRetainedInvocationStatus.Window(authorized) else {
                    throw RuntimePreparationError.changedScope
                }
                return authorized
            }
        }
        func requireUnboundIntentReconciliation(_ row: RuntimeMaintenanceWindowRecord) throws {
            guard getpid() == record.process else { throw JournalLeaseError.invalidated }
            try record.lock.withLock {
                try record.requireRecovery(seal: seal, claim: claim)
                let evidence = try record.recovery.requireJoined()
                guard evidence.neverEntered, evidence.stopNeverPossible, let descriptor = row.unboundRelease,
                      let captured = record.capturedWindow, captured.identifies(row),
                      captured.revision == descriptor.authorizedRevision,
                      record.capturedBinding?.matches(row.scope) == true else { throw RuntimePreparationError.changedScope }
                let authorized = try RuntimeMaintenanceWindowRecord(id: captured.id, revision: captured.revision,
                    purpose: captured.purpose, scope: captured.scope)
                guard descriptor.authorizedDigest == (try RuntimeMaintenanceUnboundRelease.digest(authorized)) else {
                    throw RuntimePreparationError.changedScope
                }
            }
        }
        func restorationPhases() throws -> RestorationPhases {
            guard getpid() == record.process else { throw JournalLeaseError.invalidated }
            return try record.lock.withLock {
                try record.requireRecovery(seal: seal, claim: claim)
                guard let executor = record.recoveryExecutor else { throw AdministrativeSetupError.unavailable }
                return .init(executor: executor, hold: record.hold)
            }
        }
        func requireSavedTargetReconnect(_ row: RuntimeMaintenanceWindowRecord) throws {
            guard getpid() == record.process else { throw JournalLeaseError.invalidated }
            try record.lock.withLock {
                try record.requireRestorationWindow(row, seal: seal, claim: claim)
                guard let receipt = record.savedTargetRecoveryTransition else { throw RuntimePreparationError.changedScope }
                try receipt.requireSavedTargetReconnectOrigin(row)
            }
        }
        func requireRestorationAccount(_ accountID: Data) throws {
            guard getpid() == record.process else { throw JournalLeaseError.invalidated }
            try record.lock.withLock {
                try record.requireRecovery(seal: seal, claim: claim)
                guard let captured = record.capturedWindow,
                      captured.scope.authority.accountID == accountID else { throw XPCPeerPolicyError.wrongPeer }
            }
        }
        func startRestoration(session: AdministrativeSetupShutdown.RecoverySessionWork? = nil,
            _ body: @escaping @Sendable (UUID) async throws -> RuntimeMaintenanceStartupRecovery.ExplicitCompletion) throws -> RestorationWork {
            try record.startRestoration(seal: seal, claim: claim, session: session, body: body)
        }
        func currentRestoration() throws -> RestorationWork { try record.currentRestoration(seal: seal, claim: claim) }
        func finishRestorationNative(_ completed: RuntimeMaintenanceStartupRecovery.ExplicitCompletion,
            work: RestorationWork, processLease: SetupProcessLease, joined: SetupRetainedOrphanClaim.Joined) throws {
            try joined.requireCurrentAuthorization(for: self)
            try completed.requireNative(processLease: processLease)
            try joined.requireCurrentAuthorization(for: self)
            try settleRestoration(completed, work: work)
        }
        func finishRestorationOwned(_ completed: RuntimeMaintenanceStartupRecovery.ExplicitCompletion,
            work: RestorationWork, processLease: SetupProcessLease, joined: SetupRetainedOrphanClaim.Joined) throws {
            try RuntimeMaintenanceOwnedControl.require()
            try joined.requireCurrentAuthorization(for: self)
            try completed.requireOwned(processLease: processLease)
            try joined.requireCurrentAuthorization(for: self)
            try settleRestoration(completed, work: work)
        }
        fileprivate func settleRestoration(_ completed: RuntimeMaintenanceStartupRecovery.ExplicitCompletion, work: RestorationWork) throws {
            try record.settleRestoration(completed, work: work, seal: seal, claim: claim)
        }
        func recoveryApplicability() throws -> RecoveryApplicability {
            try record.recoveryApplicability(seal: seal, claim: claim)
        }
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
