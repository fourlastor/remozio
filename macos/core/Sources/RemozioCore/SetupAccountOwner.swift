import CryptoKit
import Darwin
import Foundation
import RemozioProtocol

public enum AdministrativeSetupError: Error, Equatable {
    case invalidConfiguration, unavailable, wrongAccount, changedInstallation, staleProgress
}

/// Serializes setup operations. Production opens a fresh machine writer for each operation.
/// The host retains protected placement and verifies its current signed release on each use.
public final class SetupAccountOwner: @unchecked Sendable {
    private enum Machines {
        // Logical endpoint fixtures can borrow an existing connection. Production uses scoped access.
        case retained(PreparationIntentStore)
        case scoped(() throws -> PreparationIntentStore)
        func use<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            switch self {
            case .retained(let machine): return try body(machine)
            case .scoped(let open):
                let machine = try open()
                do {
                    let value = try body(machine)
                    try machine.close()
                    return value
                } catch { try? machine.close(); throw error }
            }
        }
        // Retry only lease acquisition, never an operation body or an unknown commit.
        func useActivation<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            guard case .scoped(let open) = self else { throw AdministrativeSetupError.unavailable }
            let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
            var next: PreparationIntentStore?
            while next == nil {
                do { next = try open() }
                catch JournalLeaseError.busy {
                    guard DispatchTime.now().uptimeNanoseconds < deadline else { throw JournalLeaseError.busy }
                    usleep(50_000)
                }
            }
            let machine = next!
            do { let value = try body(machine); try machine.close(); return value }
            catch { try? machine.close(); throw error }
        }
        func close() throws { if case .retained(let machine) = self { try machine.close() } }
    }
    private let lock = NSRecursiveLock()
    private let machines: Machines
    private let releaseActivity: ReleaseActivityBarrier?
    private let processID = getpid()
    private let installationID: Data
    private let expectedReleaseDigest: Data
    private let resume: (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent
    private let verifyHost: (InstallationInventory) throws -> Void
    private let accountCodePolicy: AuthorityCodePolicy?
    private let verifyAccountStartup: (Data, Data) throws -> Void
    private let lookupAccount: (uid_t) throws -> LocalAccountIdentity
    private let prepareAccount: (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent
    private let prepareServices: (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> ServiceAccountPlanStorage.State
    private let prepareRuntime: (PreparationIntentStore, AccountPreparationIntent, RuntimePreparationState, Bool, () throws -> Void) throws -> RuntimePreparationState
    private let activationOperations: RuntimeActivationOperations
    private let asynchronousWork = SetupOwnerAsyncWork()
    private let setupReplyWork = SetupOwnerAsyncWork()
    private let retainedStatus = SetupRetainedInvocationStatus.Reader()
    private var retainedApplicabilityRelease: SignedReleaseEvidence?
    private var retainedQuiescenceTask: Task<Void, Never>?
    private var retainedQuiescenceRefresh = false
    private var ownedStatusAccessCounts: OwnedStatusAccessCounts?
    private var retainedInvocationReservation: SetupRetainedInvocationReservation?
    private var restartRecovery: SetupRestartRecovery?
    /// The holder that took the current admission tokens. A restart claim waits only while it is an executor run.
    private weak var admissionHolder: ExecutorAdmission?
    /// Owned-only test observer for the moment a hold decides to release. Root cannot set it.
    private var ownedHoldEndObserver: (@Sendable () -> Void)?
    private var recoverySignal: (@Sendable () -> Void)?
    private let auditUpgradeCleanup = SetupAuditUpgradeCleanupOwner()
    private let auditUpgradeExecutor = SetupAuditUpgradeWorkExecutor()
    private let gatewayJournalOperation: GatewaySetupJournalOperations?
    private let gatewayActivationOperation: GatewaySetupActivationOperations?
    private let gatewaySettingsOperation: GatewaySetupSettingsOperations?
    private let importedGatewayOperation: GatewaySetupImportedRuntimeOperations?
    private var closing = false
    private var closed = false

    public static func open(machineDirectory: String, macID: Data, expectedReleaseDigest: Data) throws -> SetupAccountOwner {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let activity = try ReleaseActivityBarrier.open(machineDirectory: machineDirectory)
        return try .init(openMachine: { try PreparationIntentStore.open(directoryPath: machineDirectory, macID: macID) },
            expectedReleaseDigest: expectedReleaseDigest,
            resume: { try AuthorityAccountInitialization.resume(machine: $0, expected: $1) }, releaseActivity: activity,
            gatewayJournalOperation: .native(machineDirectory: machineDirectory, macID: macID),
            gatewayActivationOperation: .native(machineDirectory: machineDirectory, macID: macID),
            gatewaySettingsOperation: .native(machineDirectory: machineDirectory, macID: macID),
            importedGatewayOperation: .native(machineDirectory: machineDirectory, macID: macID),
            verifyAccountStartup: RuntimeAuditUpgradeStartupFence.requireOpen)
    }
    // Same-owner lifecycle fixtures use the same scoped factory as production.
    convenience init(openMachine: @escaping () throws -> PreparationIntentStore, expectedReleaseDigest: Data,
         resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent,
         verifyHost: @escaping (InstallationInventory) throws -> Void = { _ in },
         accountCodePolicy: AuthorityCodePolicy? = nil,
         lookupAccount: @escaping (uid_t) throws -> LocalAccountIdentity = LocalAccountDirectory.lookup,
         prepareAccount: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent = {
             try AccountPreparationController.resume(machine: $0, expected: $1, verifyCurrent: $2)
         }, prepareServices: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> ServiceAccountPlanStorage.State = {
             try ServiceAccountPreparation.prepare(machine: $0, account: $1, verifyCurrent: $2)
         }, prepareRuntime: @escaping (PreparationIntentStore, AccountPreparationIntent, RuntimePreparationState, Bool, () throws -> Void) throws -> RuntimePreparationState = {
             try RuntimePublicationController.prepare(machine: $0, account: $1, expected: $2, fileCustodyAccepted: $3, verifyCurrent: $4)
         }, activationOperations: RuntimeActivationOperations = .native, releaseActivity: ReleaseActivityBarrier? = nil,
         gatewayJournalOperation: GatewaySetupJournalOperations? = nil, gatewayActivationOperation: GatewaySetupActivationOperations? = nil,
         gatewaySettingsOperation: GatewaySetupSettingsOperations? = nil,
         importedGatewayOperation: GatewaySetupImportedRuntimeOperations? = nil,
         verifyAccountStartup: @escaping (Data, Data) throws -> Void = { _, _ in }) throws {
        try self.init(machines: .scoped(openMachine), expectedReleaseDigest: expectedReleaseDigest, resume: resume, verifyHost: verifyHost,
            accountCodePolicy: accountCodePolicy, lookupAccount: lookupAccount, prepareAccount: prepareAccount, prepareServices: prepareServices, prepareRuntime: prepareRuntime, activationOperations: activationOperations, releaseActivity: releaseActivity, gatewayJournalOperation: gatewayJournalOperation, gatewayActivationOperation: gatewayActivationOperation, gatewaySettingsOperation: gatewaySettingsOperation, importedGatewayOperation: importedGatewayOperation, verifyAccountStartup: verifyAccountStartup)
    }
    // Logical endpoint fixtures retain actual protected storage. They do not prove production lease lifetime.
    convenience init(machine: PreparationIntentStore, expectedReleaseDigest: Data,
         resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent,
         verifyHost: @escaping (InstallationInventory) throws -> Void = { _ in },
         accountCodePolicy: AuthorityCodePolicy? = nil,
         lookupAccount: @escaping (uid_t) throws -> LocalAccountIdentity = LocalAccountDirectory.lookup,
         prepareAccount: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent = {
             try AccountPreparationController.resume(machine: $0, expected: $1, verifyCurrent: $2)
         }, prepareServices: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> ServiceAccountPlanStorage.State = {
             try ServiceAccountPreparation.prepare(machine: $0, account: $1, verifyCurrent: $2)
         }, prepareRuntime: @escaping (PreparationIntentStore, AccountPreparationIntent, RuntimePreparationState, Bool, () throws -> Void) throws -> RuntimePreparationState = {
             try RuntimePublicationController.prepare(machine: $0, account: $1, expected: $2, fileCustodyAccepted: $3, verifyCurrent: $4)
         }, activationOperations: RuntimeActivationOperations = .native, releaseActivity: ReleaseActivityBarrier? = nil,
         gatewayJournalOperation: GatewaySetupJournalOperations? = nil, gatewayActivationOperation: GatewaySetupActivationOperations? = nil,
         gatewaySettingsOperation: GatewaySetupSettingsOperations? = nil,
         importedGatewayOperation: GatewaySetupImportedRuntimeOperations? = nil,
         verifyAccountStartup: @escaping (Data, Data) throws -> Void = { _, _ in }) throws {
        try self.init(machines: .retained(machine), expectedReleaseDigest: expectedReleaseDigest, resume: resume, verifyHost: verifyHost,
            accountCodePolicy: accountCodePolicy, lookupAccount: lookupAccount, prepareAccount: prepareAccount, prepareServices: prepareServices, prepareRuntime: prepareRuntime, activationOperations: activationOperations, releaseActivity: releaseActivity, gatewayJournalOperation: gatewayJournalOperation, gatewayActivationOperation: gatewayActivationOperation, gatewaySettingsOperation: gatewaySettingsOperation, importedGatewayOperation: importedGatewayOperation, verifyAccountStartup: verifyAccountStartup)
    }
    private init(machines: Machines, expectedReleaseDigest: Data,
         resume: @escaping (PreparationIntentStore, AuthorityInitializationIntent) throws -> AuthorityInitializationIntent,
         verifyHost: @escaping (InstallationInventory) throws -> Void,
         accountCodePolicy: AuthorityCodePolicy?, lookupAccount: @escaping (uid_t) throws -> LocalAccountIdentity,
         prepareAccount: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> AccountPreparationIntent,
         prepareServices: @escaping (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> ServiceAccountPlanStorage.State,
         prepareRuntime: @escaping (PreparationIntentStore, AccountPreparationIntent, RuntimePreparationState, Bool, () throws -> Void) throws -> RuntimePreparationState,
         activationOperations: RuntimeActivationOperations, releaseActivity: ReleaseActivityBarrier?,
         gatewayJournalOperation: GatewaySetupJournalOperations?, gatewayActivationOperation: GatewaySetupActivationOperations?, gatewaySettingsOperation: GatewaySetupSettingsOperations?,
         importedGatewayOperation: GatewaySetupImportedRuntimeOperations?, verifyAccountStartup: @escaping (Data, Data) throws -> Void) throws {
        self.verifyAccountStartup = verifyAccountStartup
        self.releaseActivity = releaseActivity; self.gatewayJournalOperation = gatewayJournalOperation
        self.gatewayActivationOperation = gatewayActivationOperation; self.gatewaySettingsOperation = gatewaySettingsOperation
        self.importedGatewayOperation = importedGatewayOperation
        self.machines = machines; self.expectedReleaseDigest = expectedReleaseDigest; self.resume = resume; self.verifyHost = verifyHost
        self.accountCodePolicy = accountCodePolicy; self.lookupAccount = lookupAccount; self.prepareAccount = prepareAccount; self.prepareServices = prepareServices; self.prepareRuntime = prepareRuntime; self.activationOperations = activationOperations
        do {
            let activity = try releaseActivity?.acquireShared()
            defer { activity?.close() }
            installationID = try machines.use { machine in
                guard expectedReleaseDigest.count == 32, let inventory = try machine.inventory(),
                      inventory.releaseDigest == expectedReleaseDigest else { throw AdministrativeSetupError.invalidConfiguration }
                return inventory.installationID
            }
        } catch { try? machines.close(); throw error }
    }
    deinit { try? close() }
    public func close() throws {
        try lock.withLock {
            guard !closed else { return }
            closing = true; asynchronousWork.closeAdmission(); setupReplyWork.closeAdmission()
            guard asynchronousWork.isIdle, setupReplyWork.isIdle else { throw AdministrativeSetupError.unavailable }
            try machines.close(); closed = true; retainedStatus.close()
        }
    }
    func closeWhenIdle() async throws {
        lock.withLock { closing = true; asynchronousWork.closeAdmission(); setupReplyWork.closeAdmission() }
        // A retained maintenance invocation keeps both admissions. Its cleanup needs no rights and no new connection,
        // so shutdown retries it here until it settles. No other path releases that admission.
        while !(auditUpgradeCleanup.retry() && asynchronousWork.isIdle && setupReplyWork.isIdle) {
            await Self.pauseBeforeCleanupRetry()
        }
        await setupReplyWork.waitUntilIdle()
        await asynchronousWork.waitUntilIdle()
        try close()
    }
    private static func pauseBeforeCleanupRetry() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + .milliseconds(50)) { continuation.resume() }
        }
    }
    // On success, invalidate while the owner lock still prevents work from using the new token.
    private func admitSetupMutation() throws -> SetupOwnerAsyncWork.Token {
        let token = try asynchronousWork.admit()
        retainedStatus.invalidateApplicability()
        ownedStatusAccessCounts?.admittedTokens += 1
        return token
    }

    private func admitSetupReply() throws -> SetupOwnerAsyncWork.Token {
        let token = try setupReplyWork.admit()
        retainedStatus.invalidateApplicability()
        ownedStatusAccessCounts?.admittedTokens += 1
        return token
    }

    func acquireSetupReplyAdmission() throws -> SetupOwnerAsyncWork.Token {
        try lock.withLock {
            guard !closed, !closing, getpid() == processID else { throw AdministrativeSetupError.unavailable }
            return try admitSetupReply()
        }
    }
    /// The native endpoint retains this reference through response encoding and the reply callback.
    func acquireReleaseActivity() throws -> ReleaseActivityToken? {
        try lock.withLock {
            guard !closed, !closing else { throw AdministrativeSetupError.unavailable }
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            return try releaseActivity?.acquireShared()
        }
    }

    /// Capability discovery checks the installed signed release and never changes the account startup fence.
    func requireAuditUpgradeSupport() throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try withMachine { machine in
            let inventory = try currentInventory(machine)
            guard let policy = accountCodePolicy, let app = policy.entries.first(where: { $0.role == .app && $0.active }) else {
                throw AdministrativeSetupError.unavailable
            }
            let release = try SignedReleaseInspection.inspect(URL(fileURLWithPath: inventory.bundlePath),
                teamID: app.teamID, appIdentifier: app.identifier)
            try inventory.compareRelease(release)
            try SetupAuditUpgradeLocalContract.validate(release, policy: policy)
            _ = try currentInventory(machine)
        }
    }

    final class MaintenanceRecoveryScope: @unchecked Sendable {
        private weak var owner: SetupAccountOwner?
        fileprivate let held: ExecutorAdmission
        fileprivate init(owner: SetupAccountOwner, held: ExecutorAdmission) { self.owner = owner; self.held = held }
        fileprivate func belongs(to owner: SetupAccountOwner) -> Bool { self.owner === owner }
        func close() { held.releaseRecord() }
        deinit { close() }
    }
    enum MaintenanceRecoveryAdmissionError: Error { case busyBeforeOwner }
    /// Reserves admission and activity before a recovery phase can enter the executor.
    func acquireMaintenanceRecoveryScope(custody: AdministrativeSetupShutdown) throws -> MaintenanceRecoveryScope {
        try lock.withLock {
            guard getpid() == processID, !closing, !closed, custody.belongs(to: self) else {
                throw AdministrativeSetupError.unavailable
            }
            guard restartRecovery == nil || restartRecovery?.isSettled == true,
                  asynchronousWork.isIdle, setupReplyWork.isIdle else {
                throw MaintenanceRecoveryAdmissionError.busyBeforeOwner
            }
            let reply = try admitSetupReply()
            do {
                let admission = try admitSetupMutation()
                do {
                    let held = ExecutorAdmission.durable(admission: admission, reply: reply,
                        activity: try releaseActivity?.acquireShared(), endObserver: ownedHoldEndObserver)
                    admissionHolder = held
                    return .init(owner: self, held: held)
                } catch { admission.close(); throw error }
            } catch { reply.close(); throw error }
        }
    }
    func installMaintenanceRecoverySignal(_ signal: @escaping @Sendable () -> Void) throws {
        try lock.withLock {
            guard getpid() == processID, !closed, !closing, recoverySignal == nil else { throw AdministrativeSetupError.unavailable }
            recoverySignal = signal
        }
    }
    // Invocation deinit can reach this owner lock. Owner-locked code must not drop its last invocation reference.
    // The record releases its lock before this callback. Invoke the external signal after releasing the owner lock.
    private func signalMaintenanceRecovery() { lock.withLock { recoverySignal }?() }
    func maintenanceRecoveryAvailability() -> AsyncStream<Void> {
        lock.withLock {
            if !asynchronousWork.isIdle { return asynchronousWork.availability() }
            return setupReplyWork.availability()
        }
    }
    /// Only the lifecycle calls discovery. Its own admission closes after the checked executor has actually returned.
    func discoverMaintenanceRecovery(custody: AdministrativeSetupShutdown, candidate: SignedReleaseEvidence,
        checkedHost: AdministrativeSetupLifecycle.HostCheck) async throws
        -> [RuntimeMaintenanceWindowRecord] {
        let scope = try acquireMaintenanceRecoveryScope(custody: custody)
        defer { scope.close() }
        let phases = try maintenanceRecoveryPhases(scope: scope, validate: { try custody.validateRecoveryCustody() })
        return try await phases.run {
            try self.withMachine(admission: scope.held.admission) { machine in
                _ = try self.currentInventory(machine, checkedHost: checkedHost)
                let rows = try machine.runtimeMaintenanceStartupWindows(candidate: candidate)
                guard rows.count <= 64 else { throw PreparationStoreError.corruptRecord }
                _ = try self.currentInventory(machine, checkedHost: checkedHost)
                return rows
            }
        }
    }
    func publishMaintenanceRecovery(_ row: RuntimeMaintenanceWindowRecord) {
        guard retainedStatus.publishRecovery(row),
              let reservation = lock.withLock({ retainedInvocationReservation }) else { return }
        publishRetainedQuiescence(reservation)
    }
    func publishMaintenanceRecovery(request: SetupMaintenanceRecoverySupervisor.Request,
        observation: SetupMaintenanceRecoverySupervisor.Observation) {
        retainedStatus.publishRecovery(request: request, observation: observation)
    }
    func observeMaintenanceRecoveryExecutorOwned() throws -> SetupAuditUpgradeWorkExecutor.OwnedAttempts {
        try RuntimeMaintenanceOwnedControl.require()
        return try auditUpgradeExecutor.observeAttemptsOwned()
    }
    final class MaintenanceRecoveryPhasePermit: @unchecked Sendable {
        let executor: SetupAuditUpgradeWorkExecutor
        let held: ExecutorAdmission
        fileprivate init(executor: SetupAuditUpgradeWorkExecutor, held: ExecutorAdmission) {
            self.executor = executor; self.held = held
        }
    }
    /// A permit retains the held scope's admission. Each phase checks that the hold is still live before entry.
    func maintenanceRecoveryPhases(scope: MaintenanceRecoveryScope, until deadline: ContinuousClock.Instant? = nil,
        cancellation: SetupAuditUpgradeCancellation? = nil,
        validate: @escaping @Sendable () throws -> Void = {}) throws -> SetupRetainedInvocationReservation.RestorationPhases {
        try lock.withLock {
            guard getpid() == processID, scope.belongs(to: self), asynchronousWork.permits(scope.held.admission),
                  setupReplyWork.permits(scope.held.reply), scope.held.recordIsHeld else {
                throw AdministrativeSetupError.unavailable
            }
            return .maintenanceRecovery(permit: .init(executor: auditUpgradeExecutor, held: scope.held),
                deadline: deadline, cancellation: cancellation, validate: validate)
        }
    }
    func closeMaintenanceRecoveryAdmission() {
        lock.withLock {
            guard getpid() == processID else { return }
            closing = true; asynchronousWork.closeAdmission(); setupReplyWork.closeAdmission()
        }
    }

    /// The two Setup admission tokens of one holder, its shared release activity, and the holds that keep them open.
    /// Each executor run adds a worker hold before the executor starts and ends it after the body has returned.
    /// One scope, or one durable record (restart record, retained reservation), can add one more hold.
    /// The tokens and the activity close only when no hold is left. So no executor body runs after they closed,
    /// and `closeWhenIdle` cannot see idle admission while a body still runs.
    final class ExecutorAdmission: @unchecked Sendable, CustomStringConvertible, CustomReflectable {
        /// Thrown only when a hold is asked for after the record released, or after every hold ended. Callers map it.
        struct Released: Error { fileprivate init() {} }
        let admission: SetupOwnerAsyncWork.Token, reply: SetupOwnerAsyncWork.Token
        private let lock = NSLock()
        private var workers = 0, scope = false, adopted = false, closed = false
        private var record: Bool
        private let ownedFixture: Bool
        private var activity: ReleaseActivityToken?
        private var closeWaiters: [ReleaseWaiter] = [], releaseDone = false
        /// Owned-only test observer. It runs after the close decision and before the release, outside this lock. It can
        /// only delay or record. It must not take owner, record or invocation locks.
        private let endObserver: (@Sendable () -> Void)?
        var description: String { "SetupExecutorAdmission(redacted)" }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        private init(admission: SetupOwnerAsyncWork.Token, reply: SetupOwnerAsyncWork.Token, record: Bool,
            activity: ReleaseActivityToken?, endObserver: (@Sendable () -> Void)?, ownedFixture: Bool = false) {
            self.admission = admission; self.reply = reply; self.record = record; self.activity = activity
            self.endObserver = endObserver; self.ownedFixture = ownedFixture
        }
        /// The owner adds the first worker hold under its lock before anyone else can see this value.
        fileprivate static func forExecutorRun(admission: SetupOwnerAsyncWork.Token, reply: SetupOwnerAsyncWork.Token,
            endObserver: (@Sendable () -> Void)?) -> ExecutorAdmission {
            .init(admission: admission, reply: reply, record: false, activity: nil, endObserver: endObserver)
        }
        /// A durable record holds these tokens and its activity from creation. Only that record calls `releaseRecord()`.
        fileprivate static func durable(admission: SetupOwnerAsyncWork.Token, reply: SetupOwnerAsyncWork.Token,
            activity: ReleaseActivityToken?, endObserver: (@Sendable () -> Void)?) -> ExecutorAdmission {
            .init(admission: admission, reply: reply, record: true, activity: activity, endObserver: endObserver)
        }
        /// Owned-only. A record built directly by a test, on tokens that are not the owner's, gets its hold here.
        static func durableOwned(admission: SetupOwnerAsyncWork.Token, reply: SetupOwnerAsyncWork.Token,
            activity: ReleaseActivityToken?) throws -> ExecutorAdmission {
            try RuntimeMaintenanceOwnedControl.require()
            try admission.requireOwnedFixture(); try reply.requireOwnedFixture()
            return .init(admission: admission, reply: reply, record: true, activity: activity, endObserver: nil, ownedFixture: true)
        }
        fileprivate var recordIsHeld: Bool { lock.withLock { record && !closed } }
        /// The supervisor phase also proves its private origin. Released admission cannot authorize startup metadata.
        func requireUnboundStartupAdmission() throws {
            try lock.withLock { guard record, !closed else { throw Released() } }
        }
        /// A real record's hold cannot be used to construct an Owned phase fixture.
        func requireFreshOwnedPhaseFixture() throws {
            try RuntimeMaintenanceOwnedControl.require()
            try lock.withLock {
                guard ownedFixture, record, !closed, workers == 0, !scope else { throw AdministrativeSetupError.unavailable }
            }
        }
        /// Adds one worker hold for an audit run or a fresh claim. The returned closure ends it, once.
        fileprivate func beginWorker() throws -> @Sendable () -> Void { try addWorker(requireRecord: false) }
        /// Adds one worker hold for a phase or a reclaim of a durable record. Refuses once the record released,
        /// so no phase can join a released record and keep its tokens after the releasing caller returned.
        fileprivate func beginPhase() throws -> @Sendable () -> Void { try addWorker(requireRecord: true) }
        private func addWorker(requireRecord: Bool) throws -> @Sendable () -> Void {
            try lock.withLock {
                guard !closed, !requireRecord || record else { throw Released() }
                workers += 1
            }
            let once = Once()
            return { [self] in if once.take() { end { $0.workers -= 1 } } }
        }
        /// One scope, once, while a worker runs and no record owns the tokens.
        fileprivate func adoptForScope() throws {
            try lock.withLock {
                guard !closed, workers > 0, !adopted, !record else { throw AdministrativeSetupError.unavailable }
                adopted = true; scope = true
            }
        }
        /// A new restart record now owns these tokens and its activity. It releases them with `releaseRecord()`.
        fileprivate func transferToRecord(activity: ReleaseActivityToken?) throws {
            try lock.withLock {
                guard !closed, workers > 0, !adopted, !record else { throw AdministrativeSetupError.unavailable }
                record = true; self.activity = activity
            }
        }
        /// True while only executor runs hold the tokens, or while the last hold has ended and the release is
        /// in progress. Nothing can reopen the tokens of a closed value, so both cases end on their own.
        fileprivate var isTransientOrEnding: Bool { lock.withLock { closed || (!record && workers > 0) } }
        fileprivate func endScope() { end { $0.scope = false } }
        /// The record's release. A running executor body keeps the tokens until it returns.
        func releaseRecord() { markRecordReleased()() }
        /// Mark under the record lock. Always invoke the returned closure after releasing that lock.
        /// Dropping the result retains the tokens and activity and leaves release waiters pending.
        func markRecordReleased() -> @Sendable () -> Void { prepareEnd { $0.record = false } }
        /// After the record released, waits until every other running body has returned and the release is done.
        /// Returns at once while the record still holds the value. Also returns at once when the calling task is
        /// cancelled or `deadline` passes. A waiter never ends a hold or closes anything; the release continues and
        /// completes when the last real hold ends.
        func waitForReleaseAfterRecord(until deadline: ContinuousClock.Instant?) async {
            let waiter = ReleaseWaiter()
            let registered = lock.withLock { () -> Bool in
                if record || releaseDone { return false }
                closeWaiters.append(waiter); return true
            }
            guard registered else { return }
            let timer = deadline.map { deadline in
                Task { try? await ContinuousClock().sleep(until: deadline); waiter.finish() }
            }
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    if !waiter.install(continuation) { continuation.resume() }
                }
            } onCancel: { waiter.finish() }
            timer?.cancel()
            lock.withLock { closeWaiters.removeAll { $0 === waiter } }
        }
        /// Runs one restoration phase under a new phase hold. `BusyBeforeBody` keeps its meaning. Throws `Released`.
        func runRestorationPhase<Value: Sendable>(on executor: SetupAuditUpgradeWorkExecutor,
            cancellation: SetupAuditUpgradeCancellation = .init(),
            _ body: @escaping @Sendable (SetupAuditUpgradeCancellation) throws -> Value) async throws -> Value {
            let endWorker = try beginPhase()
            return try await executor.runRestorationPhase(cancellation: cancellation, afterReturn: endWorker, body)
        }
        /// Runs one blocking body under a new phase hold. A busy executor is `unavailable`, as before. Throws `Released`.
        func run<Value: Sendable>(on executor: SetupAuditUpgradeWorkExecutor,
            _ body: @escaping @Sendable (SetupAuditUpgradeCancellation) throws -> Value) async throws -> Value {
            let endWorker = try beginPhase()
            return try await executor.run(afterReturn: endWorker, body)
        }
        private func end(_ change: (ExecutorAdmission) -> Void) { prepareEnd(change)() }
        private func prepareEnd(_ change: (ExecutorAdmission) -> Void) -> @Sendable () -> Void {
            let last = lock.withLock { () -> (activity: ReleaseActivityToken?, close: Bool) in
                guard !closed else { return (nil, false) }
                change(self)
                guard workers == 0, !scope, !record else { return (nil, false) }
                closed = true; let activity = self.activity; self.activity = nil; return (activity, true)
            }
            guard last.close else { return {} }
            let once = Once()
            return { [self] in
                guard once.take() else { return }
                endObserver?()
                // The activity closes first, so idle admission always means no activity is left. Never under this lock.
                last.activity?.close(); admission.close(); reply.close()
                let waiters = lock.withLock { () -> [ReleaseWaiter] in
                    releaseDone = true; let waiters = closeWaiters; closeWaiters = []; return waiters
                }
                for waiter in waiters { waiter.finish() }
            }
        }
        /// One waiter. Release, cancellation or the deadline finishes it, whichever comes first, exactly once.
        private final class ReleaseWaiter: @unchecked Sendable {
            private let lock = NSLock()
            private var continuation: CheckedContinuation<Void, Never>?, done = false
            /// False when the waiter already finished; the caller then resumes at once.
            func install(_ continuation: CheckedContinuation<Void, Never>) -> Bool {
                lock.withLock { if done { return false }; self.continuation = continuation; return true }
            }
            func finish() {
                let pending = lock.withLock { () -> CheckedContinuation<Void, Never>? in
                    if done { return nil }; done = true; let pending = continuation; continuation = nil; return pending
                }
                pending?.resume()
            }
        }
        private final class Once: @unchecked Sendable {
            private let lock = NSLock()
            private var taken = false
            func take() -> Bool { lock.withLock { if taken { return false }; taken = true; return true } }
        }
    }
    /// Takes both admissions together with one worker hold. Callers hand `endWorker` to the executor at once.
    private func admitExecutorWork() throws -> (held: ExecutorAdmission, endWorker: @Sendable () -> Void) {
        try lock.withLock {
            guard !closed, !closing, getpid() == processID else { throw AdministrativeSetupError.unavailable }
            let reply = try admitSetupReply()
            let admission: SetupOwnerAsyncWork.Token
            do { admission = try admitSetupMutation() } catch { reply.close(); throw error }
            let held = ExecutorAdmission.forExecutorRun(admission: admission, reply: reply, endObserver: ownedHoldEndObserver)
            let endWorker = try held.beginWorker()
            admissionHolder = held
            return (held, endWorker)
        }
    }
    /// True when every held Setup admission belongs to executor runs only, or to a holder whose release is in
    /// progress. Durable records, scopes kept by failed cleanup, and other setup work return false.
    private func admissionHeldByExecutorRunsOnly() -> Bool {
        guard let holder = admissionHolder, holder.isTransientOrEnding else { return false }
        return asynchronousWork.isIdleOrPermits(holder.admission) && setupReplyWork.isIdleOrPermits(holder.reply)
    }

    /// Blocking maintenance uses the cancellation token of the authorization imported on the exported invocation.
    /// Both Setup admissions are taken before the executor starts. The body receives them for its single scope.
    func performAuditUpgradeWork<Value: Sendable>(authorization: SetupAuditUpgradeAuthorization,
        _ body: @escaping @Sendable (SetupAuditUpgradeCancellation, ExecutorAdmission) throws -> Value) async throws -> Value {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        try Task.checkCancellation(); try authorization.cancellationToken.check()
        let (held, endWorker) = try admitExecutorWork()
        return try await auditUpgradeExecutor.run(cancellation: authorization.cancellationToken,
            afterReturn: endWorker) { try body($0, held) }
    }
    /// Owned-only fixture. It is a transient executor run like an audit: it takes both Setup admissions and a
    /// worker hold before the executor starts, and keeps them until the body returns. Root refuses it.
    func occupyExecutorOwned<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value {
        try RuntimeMaintenanceOwnedControl.require()
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        let (_, endWorker) = try admitExecutorWork()
        return try await auditUpgradeExecutor.run(afterReturn: endWorker) { _ in try body() }
    }
    /// Owned-only. Calls `observer` each time a hold made by this owner has decided to release, before the activity
    /// and tokens close. The observer can only delay or record; it cannot change a result. Root refuses it.
    func observeHoldEndOwned(_ observer: (@Sendable () -> Void)?) throws {
        try RuntimeMaintenanceOwnedControl.require()
        lock.withLock { ownedHoldEndObserver = observer }
    }

    /// The endpoint transfers failed cleanup here before releasing its invocation reference.
    func settleAuditUpgradeInvocation(_ invocation: SetupAuditUpgradeInvocation) -> Bool {
        guard getpid() == processID else { return false }
        return auditUpgradeCleanup.settle(invocation)
    }
    func retryAuditUpgradeCleanup() -> Bool {
        guard getpid() == processID else { return false }
        return auditUpgradeCleanup.retry()
    }

    /// Recovery observations bypass only the account startup fence. Ordinary setup keeps its existing admission checks.
    func auditUpgradeProgress(callerUID: uid_t) throws -> SetupAuditUpgradeProgress? {
        try withMachine { machine in
            let inventory = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            guard account.ownerUID == callerUID, account.storagePrepared,
                  account.macID == inventory.macID, account.installationID == inventory.installationID,
                  account.releaseDigest == inventory.releaseDigest,
                  let policy = accountCodePolicy, try account.initialAuthority.codePolicy.bytes == policy.bytes,
                  let initialization = try machine.initialization(accountID: account.accountID), initialization.complete else {
                throw AdministrativeSetupError.wrongAccount
            }
            try LocalAccountDirectory.validateOwnership(lookupAccount(callerUID), uid: callerUID, directoryID: account.directoryID)
            try machine.validateAccountPreparation(account)
            let progress = try SetupAuditUpgradeProgress.capture(machine: machine, account: account,
                inventory: inventory, initialization: initialization)
            _ = try currentInventory(machine)
            return progress
        }
    }

    /// The exported endpoint must mint this authorization on its authenticated invocation, before task dispatch.
    /// Recovery checks the account independently; normal setup continues to enforce its startup fence.
    /// The scope adopts the admissions that `performAuditUpgradeWork` took before its executor started.
    func acquireAuditUpgradeScope(authorization: SetupAuditUpgradeAuthorization,
                                  admission held: ExecutorAdmission) throws -> SetupAuditUpgradeScope {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        return try lock.withLock {
            guard !closed, !closing, getpid() == processID, asynchronousWork.permits(held.admission),
                  setupReplyWork.permits(held.reply) else { throw AdministrativeSetupError.unavailable }
            try authorization.validate()
            try held.adoptForScope()
            let admission = held.admission, reply = held.reply
            do {
                let values = try machines.use { machine -> (AccountPreparationIntent, InstallationInventory, AuthorityInitializationIntent) in
                    let inventory = try currentInventory(machine)
                    guard let account = try machine.accountPreparation(ownerUID: authorization.callerUID),
                          account.ownerUID == authorization.callerUID, account.storagePrepared,
                          account.macID == inventory.macID, account.installationID == inventory.installationID,
                          account.releaseDigest == inventory.releaseDigest,
                          let policy = accountCodePolicy, try account.initialAuthority.codePolicy.bytes == policy.bytes,
                          let initialization = try machine.initialization(accountID: account.accountID), initialization.complete else {
                        throw AdministrativeSetupError.wrongAccount
                    }
                    try LocalAccountDirectory.validateOwnership(lookupAccount(authorization.callerUID),
                        uid: authorization.callerUID, directoryID: account.directoryID)
                    try machine.validateAccountPreparation(account)
                    return (account, inventory, initialization)
                }
                let (account, inventory, initialization) = values
                func verify() throws {
                    try self.lock.withLock {
                        guard !self.closed, !self.closing, getpid() == self.processID,
                              self.asynchronousWork.permits(admission), self.setupReplyWork.permits(reply) else {
                            throw AdministrativeSetupError.unavailable
                        }
                        try authorization.validate(); try self.releaseActivity?.validate()
                        try self.verifyHost(inventory)
                        try LocalAccountDirectory.validateOwnership(self.lookupAccount(authorization.callerUID),
                            uid: authorization.callerUID, directoryID: account.directoryID)
                    }
                }
                try verify()
                return SetupAuditUpgradeScope(account: account, inventory: inventory, initialization: initialization,
                    authorization: authorization, verifyLease: verify, access: { body in
                        try self.lock.withLock {
                            try verify()
                            try self.machines.use { machine in
                                guard let current = try machine.inventory(), current.installationID == inventory.installationID,
                                      current.macID == inventory.macID, current.releaseDigest == inventory.releaseDigest,
                                      current.bundlePath == inventory.bundlePath,
                                      try machine.accountPreparation(ownerUID: authorization.callerUID) == account,
                                      try machine.initialization(accountID: account.accountID) == initialization else {
                                    throw AdministrativeSetupError.changedInstallation
                                }
                                try verify(); try body(machine); try verify()
                            }
                        }
                    }, closeAdmission: { held.endScope() })
            } catch { held.endScope(); throw error }
        }
    }
    /// Owned-only fixture for scope tests that use no executor. The scope is the only hold. Root refuses it.
    func acquireAuditUpgradeScope(authorization: SetupAuditUpgradeAuthorization) throws -> SetupAuditUpgradeScope {
        try RuntimeMaintenanceOwnedControl.require()
        let (held, endWorker) = try admitExecutorWork()
        defer { endWorker() }
        return try acquireAuditUpgradeScope(authorization: authorization, admission: held)
    }

    private func withMachine<Value>(admission: SetupOwnerAsyncWork.Token? = nil,
                                    _ body: (PreparationIntentStore) throws -> Value) throws -> Value {
        try lock.withLock {
            guard !closed, !closing, asynchronousWork.permits(admission) else { throw AdministrativeSetupError.unavailable }
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            let activity = try releaseActivity?.acquireShared()
            defer { activity?.close() }
            ownedStatusAccessCounts?.storeReads += 1
            let result = try machines.use(body)
            try activity?.validate()
            return result
        }
    }
    /// Returns metadata only. A reserved record with no invocation is still constructing.
    /// The caller supplies an authenticated peer and its current directory identity; the status lane uses the one-argument entry below.
    func retainedInvocationStatus(authenticatedPeer: XPCPeerCredentials, currentOwner: LocalAccountIdentity) -> SetupRetainedInvocationStatus {
        retainedStatus.read(authenticatedPeer: authenticatedPeer, currentOwner: currentOwner)
    }
    /// Library-only v2 projection. The producer slice owns live version routing.
    func retainedInvocationStatusV2(authenticatedPeer: XPCPeerCredentials, currentOwner: LocalAccountIdentity) -> SetupRetainedStatusProjection {
        retainedStatus.readV2(authenticatedPeer: authenticatedPeer, currentOwner: currentOwner)
    }
    /// Ordinary-owner race fixture using the reader's existing after-snapshot seam.
    func retainedInvocationStatusV2Owned(authenticatedPeer: XPCPeerCredentials, currentOwner: LocalAccountIdentity,
        afterSnapshot: @escaping () -> Void) throws -> SetupRetainedStatusProjection {
        try RuntimeMaintenanceOwnedControl.require()
        return try retainedStatus.readV2Owned(authenticatedPeer: authenticatedPeer, currentOwner: currentOwner, afterSnapshot: afterSnapshot)
    }
    enum StatusLaneCheck: Equatable, Sendable { case verified, pinned, busy, refused }
    /// The installation and configuration check for a connection that selects status. It never waits:
    /// - owner lock held by other work, or the store's writer lease busy: `busy`;
    /// - admission held by a reservation or restart slot: `pinned`. Reading the store would borrow that admission, which the status
    ///   lane must never do (contract section 1.2), so only the release barrier and the open owner are checked;
    /// - otherwise the same store-backed check as `verifyCurrent`: `verified`, or `refused` on drift or closure.
    /// `busy` and `pinned` both answer with the in-memory projection only; nothing store-derived is reported.
    func statusLaneCheck() -> StatusLaneCheck {
        guard getpid() == processID else { return .refused }
        guard lock.try() else { return .busy }
        defer { lock.unlock() }
        guard !closed, !closing else { return .refused }
        do {
            guard asynchronousWork.isIdle else { try releaseActivity?.validate(); return .pinned }
            let activity = try releaseActivity?.acquireShared()
            defer { activity?.close() }
            ownedStatusAccessCounts?.storeReads += 1
            _ = try machines.use { try currentInventory($0) }
            try activity?.validate()
            return .verified
        } catch JournalLeaseError.busy {
            return .busy
        } catch { return .refused }
    }
    /// Status lane entry. The directory identity comes from the authenticated peer UID, never from the request.
    /// Neither the owner lock nor the machine store is touched, so a held reservation or a busy writer cannot block it.
    func retainedInvocationStatus(authenticatedPeer: XPCPeerCredentials) -> SetupRetainedInvocationStatus {
        guard getpid() == processID, let currentOwner = try? lookupAccount(authenticatedPeer.userID) else { return .unavailable }
        return retainedStatus.read(authenticatedPeer: authenticatedPeer, currentOwner: currentOwner)
    }
    func retainedInvocationState() throws -> SetupRetainedInvocationReservation.State? {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        let reservation = lock.withLock { retainedInvocationReservation }
        return try reservation?.state()
    }
    func retainedStatusApplicability(authenticatedPeer: XPCPeerCredentials) -> SetupRetainedStatusProjection {
        guard getpid() == processID, let currentOwner = try? lookupAccount(authenticatedPeer.userID) else { return .unavailable }
        return retainedStatusApplicability(authenticatedPeer: authenticatedPeer, currentOwner: currentOwner)
    }

    func retainedStatusApplicability(authenticatedPeer: XPCPeerCredentials,
        currentOwner: LocalAccountIdentity) -> SetupRetainedStatusProjection {
        retainedStatus.readApplicability(authenticatedPeer: authenticatedPeer, currentOwner: currentOwner)
    }

    struct OwnedStatusAccessCounts: Equatable {
        var storeReads = 0
        var admittedTokens = 0
    }

    func statusAccessCountsOwned() throws -> OwnedStatusAccessCounts {
        try RuntimeMaintenanceOwnedControl.require()
        return lock.withLock {
            if let ownedStatusAccessCounts { return ownedStatusAccessCounts }
            let initial = OwnedStatusAccessCounts()
            ownedStatusAccessCounts = initial
            return initial
        }
    }

    func occupyRetainedExecutorOwned(_ body: @escaping @Sendable () throws -> Void) async throws {
        try RuntimeMaintenanceOwnedControl.require()
        let hold = try lock.withLock {
            guard let record = retainedInvocationReservation else { throw AdministrativeSetupError.unavailable }
            return record.hold
        }
        try await hold.run(on: auditUpgradeExecutor) { _ in try body() }
    }

    /// Exercises the owner admission boundary with a seeded hint. Root cannot release a record through this fixture.
    func admitMutationAfterReleasingRetainedHoldOwned() throws -> SetupOwnerAsyncWork.Token {
        try RuntimeMaintenanceOwnedControl.require()
        return try lock.withLock {
            guard let record = retainedInvocationReservation else { throw AdministrativeSetupError.unavailable }
            record.hold.releaseRecord()
            return try admitSetupMutation()
        }
    }

    func republishRestartStatusOwned(accountID: Data, owner: LocalAccountIdentity) throws {
        try RuntimeMaintenanceOwnedControl.require()
        guard try retainedStatus.publishRestartOwned(.init(accountID: accountID, owner: owner)) else {
            throw AdministrativeSetupError.unavailable
        }
    }

    func applicabilityGenerationOwned(for reservation: SetupRetainedInvocationReservation) throws -> UInt64? {
        try RuntimeMaintenanceOwnedControl.require()
        return retainedStatus.applicabilityGeneration(for: reservation)
    }

    func waitForRetainedQuiescenceOwned() async throws {
        try RuntimeMaintenanceOwnedControl.require()
        let task = lock.withLock { retainedQuiescenceTask }
        await task?.value
    }

    /// Native startup supplies the checked release. Owned tests can supply their installed fixture release.
    func installRetainedApplicabilityRelease(_ candidate: SignedReleaseEvidence) throws {
        try lock.withLock {
            guard getpid() == processID, !closed, !closing,
                  try InstallationInventory.digest(candidate) == expectedReleaseDigest else {
                throw AdministrativeSetupError.unavailable
            }
            if retainedApplicabilityRelease == nil { retainedApplicabilityRelease = candidate }
        }
    }

    private enum QuiescenceStep: Equatable { case complete, retryBusy, retryJoin }

    private func publishRetainedQuiescence(_ record: SetupRetainedInvocationReservation) {
        lock.withLock {
            guard !closed, !closing, retainedInvocationReservation === record,
                  retainedApplicabilityRelease != nil else { return }
            if retainedQuiescenceTask != nil {
                retainedQuiescenceRefresh = true
                return
            }
            retainedQuiescenceTask = Task { [weak self] in
                while let step = await self?.sampleRetainedQuiescence(record) {
                    switch step {
                    case .complete:
                        guard self?.continueRetainedQuiescence(record) == true else { return }
                    case .retryBusy, .retryJoin:
                        let delay: Duration = step == .retryBusy ? .milliseconds(25) : .seconds(1)
                        do { try await Task.sleep(for: delay) } catch { return }
                    }
                }
            }
        }
    }

    /// A request that races the current sample gets another pass before the slot is retired.
    private func continueRetainedQuiescence(_ record: SetupRetainedInvocationReservation) -> Bool {
        lock.withLock {
            guard retainedInvocationReservation === record else { return false }
            if !closed, !closing, retainedQuiescenceRefresh {
                retainedQuiescenceRefresh = false
                return true
            }
            retainedQuiescenceTask = nil
            return false
        }
    }

    private func sampleRetainedQuiescence(_ record: SetupRetainedInvocationReservation) async -> QuiescenceStep {
        let pending: (SignedReleaseEvidence, UInt64, SetupRetainedInvocationReservation.Quiescence)? = try? lock.withLock {
            guard !closed, !closing, retainedInvocationReservation === record,
                  asynchronousWork.permits(record.admission), let release = retainedApplicabilityRelease,
                  let evidence = try record.beginQuiescence(),
                  let generation = retainedStatus.applicabilityGeneration(for: record, account: evidence.window.scope.authority) else {
                return nil
            }
            return (release, generation, evidence)
        }
        guard let (release, generation, evidence) = pending else { return .complete }
        withExtendedLifetime(evidence.retiredJoin) {}
        do { try await evidence.joined.value } catch { return .retryJoin }
        // After abandonment, observe actual return. A successful unsettled restoration is never another Restore hint.
        if let restoration = evidence.restoration {
            _ = try? await restoration.value()
        }
        do {
            let row = try await record.hold.runRestorationPhase(on: auditUpgradeExecutor) { _ in
                try self.withMachine(admission: record.admission) { machine in
                    _ = try self.currentInventory(machine)
                    let frame = try machine.runtimeMaintenanceStartupFrame(
                        accountID: evidence.window.scope.authority.accountID, candidate: release)
                    guard let row = frame.window, row.phase == .needsOwnerRecovery,
                          row.purpose == .retainedRuntime, row.shutdownBinding != nil,
                          try record.confirmsQuiescence(evidence, for: row) else {
                        throw AdministrativeSetupError.unavailable
                    }
                    return row
                }
            }
            return try lock.withLock {
                guard !closed, !closing, retainedInvocationReservation === record,
                      asynchronousWork.permits(record.admission),
                      try record.confirmsQuiescence(evidence, for: row) else { return .complete }
                switch retainedStatus.publishRestore(for: record, identity: evidence.identity, row: row,
                    expectedGeneration: generation) {
                case .accepted, .unavailable: return .complete
                case .retry: return .retryBusy
                }
            }
        } catch is SetupAuditUpgradeWorkExecutor.BusyBeforeBody {
            return .retryBusy
        } catch JournalLeaseError.busy {
            return .retryBusy
        } catch {
            return .complete
        }
    }

    /// Reserves both admissions before construction. The private record retains shared activity through orphaning.
    func reserveRetainedInvocation(authenticatedPeer: XPCPeerCredentials, incarnation: UUID,
        authenticatedOwner: LocalAccountIdentity) throws -> (record: SetupRetainedInvocationReservation,
                                                               verify: () throws -> Void) {
        guard getpid() == processID else { throw AdministrativeSetupError.unavailable }
        return try lock.withLock {
            guard !closed, !closing, restartRecovery == nil || restartRecovery?.isSettled == true,
                  try retainedInvocationReservation == nil || retainedInvocationReservation?.state() == .settled else {
                throw AdministrativeSetupError.unavailable
            }
            let reply = try admitSetupReply()
            let admission: SetupOwnerAsyncWork.Token
            do { admission = try admitSetupMutation() } catch { reply.close(); throw error }
            do {
                let activity = try releaseActivity?.acquireShared()
                let record = try SetupRetainedInvocationReservation(authenticatedPeer: authenticatedPeer, incarnation: incarnation, admission: admission, reply: reply,
                    activity: activity, authenticatedOwner: authenticatedOwner, recoveryExecutor: auditUpgradeExecutor,
                    hold: .durable(admission: admission, reply: reply, activity: activity, endObserver: ownedHoldEndObserver),
                    recoverySignal: { [weak self] in self?.signalMaintenanceRecovery() },
                    quiescenceSignal: { [weak self] record in self?.publishRetainedQuiescence(record) })
                retainedInvocationReservation = record; retainedQuiescenceTask = nil; retainedQuiescenceRefresh = false
                admissionHolder = record.hold; retainedStatus.publish(record, owner: authenticatedOwner)
                return (record, {
                    try self.lock.withLock {
                        guard self.retainedInvocationReservation === record, !self.closed, !self.closing,
                              getpid() == self.processID, self.asynchronousWork.permits(admission),
                              self.setupReplyWork.permits(reply) else { throw AdministrativeSetupError.unavailable }
                        try record.verify()
                    }
                })
            } catch { admission.close(); reply.close(); throw error }
        }
    }
    /// Only the owner can mint a permit. It binds the real slot and the original executor without injected checks.
    final class RestartPermit: @unchecked Sendable {
        private weak var owner: SetupAccountOwner?
        let accountID: Data, accountOwner: LocalAccountIdentity, native: Bool
        let admission: SetupOwnerAsyncWork.Token, reply: SetupOwnerAsyncWork.Token
        /// Owns both tokens. The record releases them through this value, never by closing a token.
        let hold: ExecutorAdmission
        let activity: ReleaseActivityToken?, executor: SetupAuditUpgradeWorkExecutor
        fileprivate init(owner: SetupAccountOwner, accountID: Data, accountOwner: LocalAccountIdentity, native: Bool,
            hold: ExecutorAdmission, activity: ReleaseActivityToken?, executor: SetupAuditUpgradeWorkExecutor) {
            self.owner = owner; self.accountID = accountID; self.accountOwner = accountOwner; self.native = native
            self.admission = hold.admission; self.reply = hold.reply; self.hold = hold
            self.activity = activity; self.executor = executor
        }
        func publishCapture(_ record: SetupRestartRecovery, row: RuntimeMaintenanceWindowRecord) {
            owner?.publishRestartCapture(record, row: row)
        }
        func requireOwner(_ record: SetupRestartRecovery, windowID: Data?, starting: Bool = false) throws {
            guard let owner else { throw AdministrativeSetupError.unavailable }
            try owner.verifyRestartSlot(record, windowID: windowID, starting: starting)
        }
    }
    /// Metadata-only capacity fixture. It creates no claim or admission, and Root cannot call it.
    func fillRestartStatusCapacityOwned(_ owners: [LocalAccountIdentity]) throws {
        try RuntimeMaintenanceOwnedControl.require()
        guard owners.count <= 64 else { throw AdministrativeSetupError.invalidConfiguration }
        try lock.withLock {
            guard getpid() == processID, !closed, asynchronousWork.isIdle, setupReplyWork.isIdle else { throw AdministrativeSetupError.unavailable }
            for (index, owner) in owners.enumerated() {
                guard try retainedStatus.publishRestartOwned(.init(accountID: Data(repeating: UInt8(index), count: 16), owner: owner)) else {
                    throw AdministrativeSetupError.unavailable
                }
            }
        }
    }
    private func publishRestartCapture(_ record: SetupRestartRecovery, row: RuntimeMaintenanceWindowRecord) {
        lock.withLock {
            guard getpid() == processID, !closed, restartRecovery === record else { return }
            retainedStatus.supersedeRecovery(row)
        }
    }
    private func verifyRestartSlot(_ record: SetupRestartRecovery, windowID: Data?, starting: Bool) throws {
        try lock.withLock {
            guard getpid() == processID, !closed, !starting || !closing, restartRecovery === record,
                  asynchronousWork.permits(record.admission), setupReplyWork.permits(record.reply),
                  try retainedInvocationReservation?.excludesRestart(accountID: record.accountID,
                    owner: record.accountOwner, windowID: windowID) != true else { throw AdministrativeSetupError.unavailable }
        }
    }
    /// How a restart claim may enter the shared executor. Each entry holds a worker hold before the executor starts.
    /// A fresh claim holds new admissions. A reclaim adds a worker hold to the unsettled record's admissions.
    enum RestartClaimPolicy: Equatable, Sendable { case freshOrReclaim, reclaimOnly }
    private enum RestartEntry: Sendable {
        case fresh(ExecutorAdmission, endWorker: @Sendable () -> Void)
        case reclaim(SetupRestartRecovery, endWorker: @Sendable () -> Void)
        /// Only executor runs hold the admission. Nothing was taken.
        case waitForExecutorRun
    }
    /// The entry check found that the borrowed record settled before the body used it. Nothing was consumed.
    private struct RestartEntryChanged: Error {}
    private func admitRestartEntry(expectedAccountID: Data?, native: Bool, policy: RestartClaimPolicy) throws -> RestartEntry {
        if native { guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired } }
        else { try RuntimeMaintenanceOwnedControl.require() }
        return try lock.withLock {
            guard getpid() == processID, !closed, expectedAccountID == nil || expectedAccountID?.count == 16 else { throw AdministrativeSetupError.unavailable }
            // The worker hold is added under the owner lock. A concurrent abandon() cannot close the tokens under it.
            if let restartRecovery, !restartRecovery.isSettled, let endWorker = try? restartRecovery.hold.beginPhase() {
                return .reclaim(restartRecovery, endWorker: endWorker)
            }
            guard !closing, policy == .freshOrReclaim else { throw AdministrativeSetupError.unavailable }
            if !asynchronousWork.isIdle || !setupReplyWork.isIdle {
                // A live retained reservation, an unsettled restart record or other setup work is durable: refuse.
                guard admissionHeldByExecutorRunsOnly() else { throw AdministrativeSetupError.unavailable }
                return .waitForExecutorRun
            }
            let (held, endWorker) = try admitExecutorWork()
            return .fresh(held, endWorker: endWorker)
        }
    }
    /// Blocking authentication and account reads stay on this owner's original executor.
    /// The Setup admission is taken before the executor starts. A durable holder is refused at once.
    /// An executor run (for example an audit) is waited for, like a busy executor, until the deadline.
    func claimRestartRecovery(authorization: SetupRetainedRecoveryAuthorization, processLease: SetupProcessLease,
        accountID: Data, native: Bool, until deadline: ContinuousClock.Instant) async throws -> SetupRestartRecovery.Claim {
        try await claimRestartRecovery(authorization: authorization, processLease: processLease,
            expectedAccountID: accountID, native: native, policy: .freshOrReclaim, until: deadline)
    }
    /// The endpoint supplies no account identifier. Only the original executor derives the prepared account.
    func claimRestartRecovery(authorization: SetupRetainedRecoveryAuthorization, processLease: SetupProcessLease,
        native: Bool, policy: RestartClaimPolicy, until deadline: ContinuousClock.Instant) async throws -> SetupRestartRecovery.Claim {
        try await claimRestartRecovery(authorization: authorization, processLease: processLease,
            expectedAccountID: nil, native: native, policy: policy, until: deadline)
    }
    private func claimRestartRecovery(authorization: SetupRetainedRecoveryAuthorization, processLease: SetupProcessLease,
        expectedAccountID: Data?, native: Bool, policy: RestartClaimPolicy, until deadline: ContinuousClock.Instant) async throws -> SetupRestartRecovery.Claim {
        do {
            while true {
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw CancellationError() }
                let entry = try admitRestartEntry(expectedAccountID: expectedAccountID, native: native, policy: policy)
                let afterReturn: @Sendable () -> Void
                switch entry {
                case .waitForExecutorRun:
                    try await ContinuousClock().sleep(for: .milliseconds(25)); continue
                case .fresh(_, let endWorker), .reclaim(_, let endWorker): afterReturn = endWorker
                }
                do {
                    return try await auditUpgradeExecutor.runRestorationPhase(afterReturn: afterReturn) { _ in
                        try self.claimRestartRecoveryBlocking(authorization: authorization, processLease: processLease,
                            expectedAccountID: expectedAccountID, native: native, entry: entry)
                    }
                } catch is SetupAuditUpgradeWorkExecutor.BusyBeforeBody {
                    try await ContinuousClock().sleep(for: .milliseconds(25))
                } catch is RestartEntryChanged {}
            }
        } catch { authorization.close(); throw error }
    }
    private func claimRestartRecoveryBlocking(authorization: SetupRetainedRecoveryAuthorization, processLease: SetupProcessLease,
        expectedAccountID: Data?, native: Bool, entry: RestartEntry) throws -> SetupRestartRecovery.Claim {
        if native { guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired } }
        else { try RuntimeMaintenanceOwnedControl.require() }
        try processLease.validate()
        if case .reclaim(let record, _) = entry {
            guard lock.withLock({ restartRecovery === record && !record.isSettled }) else { throw RestartEntryChanged() }
        }
        try authorization.takeForClaim()
        let (claim, retired) = try lock.withLock {
            guard getpid() == processID, !closed else { throw AdministrativeSetupError.unavailable }
            switch entry {
            case .waitForExecutorRun: throw AdministrativeSetupError.unavailable
            case .reclaim(let record, _):
                // The record settled after the entry check. Its admission no longer covers a fresh claim.
                guard restartRecovery === record, !record.isSettled else { throw AdministrativeSetupError.unavailable }
                // Reclaim reenters this owner's NSRecursiveLock. It cannot use a nonrecursive owner lock.
                // Shutdown permits adoption and a safe exit, but the slot refuses starting another attempt.
                let accountID = record.accountID
                guard expectedAccountID == nil || expectedAccountID == accountID,
                      try retainedInvocationReservation?.excludesRestart(accountID: accountID,
                        owner: authorization.currentOwner, windowID: nil) != true else { throw AdministrativeSetupError.unavailable }
                return (try SetupRestartRecovery.reclaim(record, authorization: authorization,
                    processLease: processLease, accountID: accountID, native: native), Optional<SetupRestartRecovery>.none)
            case .fresh(let held, _):
                guard !closing, restartRecovery?.isSettled != false, asynchronousWork.permits(held.admission),
                      setupReplyWork.permits(held.reply) else { throw AdministrativeSetupError.unavailable }
                let accountID = try machines.use { machine in
                    _ = try currentInventory(machine)
                    guard let account = try machine.accountPreparation(ownerUID: authorization.peer.userID),
                          expectedAccountID == nil || account.accountID == expectedAccountID else { throw AdministrativeSetupError.wrongAccount }
                    try LocalAccountDirectory.validateOwnership(authorization.currentOwner, uid: account.ownerUID, directoryID: account.directoryID)
                    return account.accountID
                }
                guard try retainedInvocationReservation?.excludesRestart(accountID: accountID,
                    owner: authorization.currentOwner, windowID: nil) != true else { throw AdministrativeSetupError.unavailable }
                guard retainedStatus.canPublishRestart(owner: authorization.currentOwner) else { throw AdministrativeSetupError.unavailable }
                // On failure the worker hold still closes both tokens after this body returns.
                let activity = try releaseActivity?.acquireShared()
                let permit = RestartPermit(owner: self, accountID: accountID, accountOwner: authorization.currentOwner, native: native,
                    hold: held, activity: activity, executor: auditUpgradeExecutor)
                let created = try SetupRestartRecovery.reserve(permit: permit, authorization: authorization, processLease: processLease)
                try held.transferToRecord(activity: activity)
                let retired = restartRecovery; restartRecovery = created.record
                // This private reader cannot change capacity while the owner's installation section runs.
                precondition(retainedStatus.publishRestart(created.record))
                return (created.claim, retired)
            }
        }
        // An old completion can own cleanup objects. Release them outside the owner lock.
        withExtendedLifetime(retired) {}
        return claim
    }
    /// Owned-only negative fixture. The unregistered permit cannot pass the fixed owner-slot check.
    func unregisteredRestartOwned(authorization: SetupRetainedRecoveryAuthorization, processLease: SetupProcessLease,
        accountID: Data) async throws -> SetupRestartRecovery.Claim {
        try RuntimeMaintenanceOwnedControl.require()
        return try await auditUpgradeExecutor.runRestorationPhase { _ in
            try authorization.takeForClaim()
            let admission = try SetupOwnerAsyncWork().admit(), reply = try SetupOwnerAsyncWork().admit()
            let permit = RestartPermit(owner: self, accountID: accountID, accountOwner: authorization.currentOwner, native: false,
                hold: .durable(admission: admission, reply: reply, activity: nil, endObserver: nil), activity: nil,
                executor: self.auditUpgradeExecutor)
            return try SetupRestartRecovery.reserve(permit: permit, authorization: authorization, processLease: processLease).claim
        }
    }
    /// Recovery observes the retained record. Closing admission does not prevent cleanup of that same record.
    func retainedOrphanTarget(authorization: SetupRetainedRecoveryAuthorization) throws -> SetupRetainedOrphanClaim.Target {
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        try authorization.requireCurrent()
        return try lock.withLock {
            guard !closed, let record = retainedInvocationReservation, asynchronousWork.permits(record.admission) else {
                throw AdministrativeSetupError.unavailable
            }
            return try record.recoveryTarget(authorization: authorization)
        }
    }
    func claimRetainedOrphan(target: SetupRetainedOrphanClaim.Target,
        authorization: SetupRetainedRecoveryAuthorization) throws -> SetupRetainedInvocationReservation.RecoveryToken {
        guard getpid() == processID else { throw JournalLeaseError.invalidated }
        try authorization.takeForClaim()
        let claimed = try lock.withLock {
            guard !closed, let record = retainedInvocationReservation, record === target.record,
                  asynchronousWork.permits(record.admission) else { throw AdministrativeSetupError.unavailable }
            let claimed = try record.claim(target, authorization: authorization)
            retainedStatus.invalidateApplicability()
            return claimed
        }
        // A failed task can retain an error that owns a claim. Drop it only after both locks are released.
        withExtendedLifetime(claimed.retiredTask) {}
        return claimed.token
    }
    /// Call synchronously on the accepted invocation. This captures metadata and does not dispatch retained work.
    func retainedCallerBinding(invocation: XPCInvocationGuard, candidate: SignedReleaseEvidence,
                               admission: SetupOwnerAsyncWork.Token? = nil) throws -> SetupRetainedCallerBinding {
        let peer = try invocation.verifyInvocation()
        return try withMachine(admission: admission) { machine in
            _ = try currentInventory(machine)
            let state = try machine.retainedSetupCallerState(candidate: candidate)
            let selected = try state.target(peerUID: peer.userID)
            let entry = try machine.retainedSetupInitialRuntimeEntry(owner: lookupAccount(selected.ownerUID), candidate: candidate)
            let result = try SetupRetainedCallerBinding.resolve(state: state, peer: peer, incarnation: invocation.incarnation,
                accepted: invocation.acceptedPeerPolicy, entry: entry, lookup: lookupAccount)
            let path = try RuntimePreparationPaths(accountID: result.authorityAccountID).privateDirectory
                + "/" + AdministrativeSetupPublication.File.commandHost.name
            let (_, host) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(runtime: entry.runtime,
                accountID: result.authorityAccountID)
            guard try ProtectedServiceConfiguration.read(path: path) == host.canonicalBytes,
                  try invocation.verifyInvocation() == peer else { throw AdministrativeSetupError.wrongAccount }
            try machine.retainedSetupCallerState(candidate: candidate).requireSame(as: state)
            try machine.retainedSetupInitialRuntimeEntry(owner: result.targetOwner, candidate: candidate).requireSame(as: entry)
            return result
        }
    }

    /// Actual initial choices only. This value is neither a native grant nor an alternative caller resolver.
    struct RetainedMaintenanceCapture {
        let binding: SetupRetainedCallerBinding
        let inputs: MachineUpdateRetainedSetupRuntimeInputs
        var frame: PreparationIntentStore.RetainedImportFrame { (binding.entry, inputs) }
        fileprivate init(binding: SetupRetainedCallerBinding, inputs: MachineUpdateRetainedSetupRuntimeInputs) {
            self.binding = binding; self.inputs = inputs
        }
        /// Ordinary-owner fixtures only. This captures metadata and cannot mint native rights or an XPC peer proof.
        static func openOwned(binding: SetupRetainedCallerBinding, inputs: MachineUpdateRetainedSetupRuntimeInputs) throws -> Self {
            try RuntimeMaintenanceOwnedControl.require()
            try inputs.requireSource(binding.entry.runtime)
            return .init(binding: binding, inputs: inputs)
        }
    }
    func retainedMaintenanceCapture(invocation: XPCInvocationGuard, candidate: SignedReleaseEvidence,
        admission: SetupOwnerAsyncWork.Token) throws -> RetainedMaintenanceCapture {
        let binding = try retainedCallerBinding(invocation: invocation, candidate: candidate, admission: admission)
        return try withMachine(admission: admission) { machine in
            func current() throws {
                guard try invocation.verifyInvocation() == binding.peer else { throw XPCPeerPolicyError.wrongPeer }
                try machine.validateStorageLease()
            }
            try current()
            let entry = try machine.retainedSetupInitialRuntimeEntry(owner: binding.targetOwner, candidate: candidate)
            try binding.requireCapturedState(machine.retainedSetupCallerState(candidate: candidate), entry: entry)
            let inputs = try maintenanceInputs(machine: machine, entry: entry, current: current)
            try binding.requireCapturedState(machine.retainedSetupCallerState(candidate: candidate),
                entry: machine.retainedSetupInitialRuntimeEntry(owner: binding.targetOwner, candidate: candidate))
            try current(); return .init(binding: binding, inputs: inputs)
        }
    }
    func recaptureRetainedMaintenance(expected: RetainedMaintenanceCapture,
        transitions: [PreparationIntentStore.RuntimeMaintenanceTransition], capture: RuntimeMaintenanceStopCapture,
        pair: AuthorityJournalCutoverInspection, candidate: SignedReleaseEvidence, admission: SetupOwnerAsyncWork.Token,
        current: () throws -> Void) throws -> RetainedMaintenanceCapture {
        try RuntimeMaintenanceCommitments.requireProfile(capture.window.purpose)
        let commitments = try RuntimeMaintenanceCommitments.capture(binding: expected.binding, inputs: expected.inputs,
            candidate: candidate, purpose: capture.window.purpose)
        guard capture.window.scope == commitments.scope else { throw RuntimePreparationError.changedScope }
        try current()
        let (initial, _) = try MachineUpdateRetainedSetupPolicyNativeEntry.publishedAuthority(
            runtime: expected.binding.entry.runtime, accountID: expected.binding.authorityAccountID)
        let policy = try pair.maintenancePolicyBoundary(initialization: initial)
        try commitments.requirePolicy(policy.policy.policy)
        guard try policy.policy.policy.bytes == expected.binding.publishedAuthorityPolicy.bytes else { throw RuntimePreparationError.changedScope }
        let result = try withMachine(admission: admission) { machine in
            _ = try currentInventory(machine); try current()
            let state = try machine.retainedSetupCallerState(candidate: candidate)
            let entry = try machine.retainedSetupInitialRuntimeEntry(owner: expected.binding.targetOwner, candidate: candidate)
            let actual = try expected.binding.recapturing(state: state, entry: entry, transitions: transitions,
                candidate: candidate, capture: capture, lookup: lookupAccount)
            let inputs = try maintenanceInputs(machine: machine, entry: entry, current: current)
            try inputs.requireSame(as: expected.inputs)
            guard try RuntimeMaintenanceCommitments.capture(binding: actual, inputs: inputs, candidate: candidate,
                purpose: capture.window.purpose) == commitments else { throw RuntimePreparationError.changedScope }
            try actual.requireCapturedState(machine.retainedSetupCallerState(candidate: candidate),
                entry: machine.retainedSetupInitialRuntimeEntry(owner: actual.targetOwner, candidate: candidate))
            try current(); return RetainedMaintenanceCapture(binding: actual, inputs: inputs)
        }
        guard try pair.maintenancePolicyBoundary(initialization: initial) == policy else { throw AuthorityCodePolicyError.staleRevision }
        try current(); return result
    }
    private func maintenanceInputs(machine: PreparationIntentStore, entry: MachineUpdateRetainedSetupInitialRuntimeEntry,
        current: () throws -> Void) throws -> MachineUpdateRetainedSetupRuntimeInputs {
        try machine.withSharedImportJournal { journal in
            func read(_ relay: (SharedSetupImportIntent) throws -> MachineUpdateRetainedSetupRuntimeInputs.RelaySelection)
                throws -> MachineUpdateRetainedSetupRuntimeInputs {
                try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: entry.runtime, journal: journal,
                    verifyCurrent: { try current(); try machine.validateStorageLease() }, readRelay: relay)
            }
            if let journal { return try machine.withSharedImportSnapshot(journal: journal) { path, owner in
                try read { try .read($0, directory: path, owner: owner) }
            } }
            return try read { _ in throw SharedSetupImportError.wrongScope }
        }
    }
    func requirePortableImportSupport() throws {
        try lock.withLock {
            guard !closed, !closing, importedGatewayOperation != nil else { throw AdministrativeSetupError.unavailable }
        }
    }
    func verifyCurrent() throws {
        try withMachine { _ = try currentInventory($0) }
    }
    func progress(accountID: Data, callerUID: uid_t) throws -> AuthorityInitializationIntent? {
        try withMachine { machine in
            try requireAccount(accountID, callerUID: callerUID, machine: machine)
            let value = try machine.initialization(accountID: accountID)
            _ = try currentInventory(machine)
            return value
        }
    }
    func resumeAccount(accountID: Data, setupID: Data, expectedRevision: Data, callerUID: uid_t) throws -> AuthorityInitializationIntent {
        try withMachine { machine in
            guard setupID.count == 16, expectedRevision.count == 16 else { throw AdministrativeSetupError.invalidConfiguration }
            try requireAccount(accountID, callerUID: callerUID, machine: machine)
            guard let expected = try machine.initialization(accountID: accountID), expected.setupID == setupID,
                  expected.revision == expectedRevision else { throw AdministrativeSetupError.staleProgress }
            let result = try resume(machine, expected)
            _ = try currentInventory(machine)
            return result
        }
    }
    func enrollment(callerUID: uid_t) throws -> AccountPreparationIntent? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            let owner = try lookupAccount(callerUID)
            guard owner.uid == callerUID else { throw AdministrativeSetupError.wrongAccount }
            let retained = try machine.accountPreparation(ownerUID: callerUID)
            if let retained { try verifyEnrollment(retained, callerUID: callerUID, machine: machine) }
            _ = try currentInventory(machine)
            return retained
        }
    }
    // The endpoint supplies the kernel-authenticated UID and validates current administrator rights first.
    func beginEnrollment(callerUID: uid_t, allowedTargetUIDs: Set<UInt32>, disclosureAccepted: Bool) throws -> AccountPreparationIntent {
        try withMachine { machine in
            let inventory = try currentInventory(machine)
            guard let policy = accountCodePolicy else { throw AdministrativeSetupError.unavailable }
            let owner = try lookupAccount(callerUID)
            guard owner.uid == callerUID else { throw AdministrativeSetupError.wrongAccount }
            let intent = try machine.beginAccountPreparation(owner: owner, allowedTargetUIDs: allowedTargetUIDs,
                disclosureAccepted: disclosureAccepted, expectedInventoryRevision: inventory.revision,
                makeInitial: { mac, account in try Self.initialAuthority(macID: mac, accountID: account, codePolicy: policy) })
            try verifyEnrollment(intent, callerUID: callerUID, machine: machine)
            return intent
        }
    }
    func resumeEnrollment(callerUID: uid_t, setupID: Data, expectedRevision: Data) throws -> AccountPreparationIntent {
        try withMachine { machine in
            guard setupID.count == 16, expectedRevision.count == 16,
                  let expected = try machine.accountPreparation(ownerUID: callerUID), expected.setupID == setupID,
                  expected.revision == expectedRevision else { throw AdministrativeSetupError.staleProgress }
            try verifyEnrollment(expected, callerUID: callerUID, machine: machine)
            let result = try prepareAccount(machine, expected, { try self.verifyEnrollment(expected, callerUID: callerUID, machine: machine) })
            try verifyEnrollment(result, callerUID: callerUID, machine: machine)
            return result
        }
    }
    func serviceAccountsProgress(callerUID: uid_t) throws -> SetupServiceAccountProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            guard account.storagePrepared else { return nil }
            let result = try SetupServiceAccountProgress(account: account, state: machine.serviceAccountPlan(accountID: account.accountID))
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            return result
        }
    }
    func resumeServiceAccounts(callerUID: uid_t, expected: SetupServiceAccountProgress) throws -> SetupServiceAccountProgress {
        try withMachine { machine in
            guard expected.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            guard try SetupServiceAccountProgress(account: account, state: machine.serviceAccountPlan(accountID: account.accountID)) == expected else {
                throw AdministrativeSetupError.staleProgress
            }
            let state = try prepareServices(machine, account, { try self.verifyEnrollment(account, callerUID: callerUID, machine: machine) })
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let result = try SetupServiceAccountProgress(account: account, state: state)
            try result.validateCompletion(of: expected)
            return result
        }
    }
    func runtimeProgress(callerUID: uid_t) throws -> SetupRuntimeProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let services = try machine.serviceAccountPlan(accountID: account.accountID)
            guard services.complete else { return nil }
            let value = try SetupRuntimeProgress(account: account, services: services, state: machine.runtimePreparation(accountID: account.accountID))
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            return value
        }
    }
    func resumeRuntime(callerUID: uid_t, expected: SetupRuntimeProgress, fileCustodyAccepted: Bool) throws -> SetupRuntimeProgress {
        try withMachine { machine in
            guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
            guard expected.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let services = try machine.serviceAccountPlan(accountID: account.accountID)
            let state = try machine.runtimePreparation(accountID: account.accountID)
            guard try SetupRuntimeProgress(account: account, services: services, state: state) == expected else {
                throw AdministrativeSetupError.staleProgress
            }
            let result = try prepareRuntime(machine, account, state, fileCustodyAccepted, {
                try self.verifyEnrollment(account, callerUID: callerUID, machine: machine)
            })
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let progress = try SetupRuntimeProgress(account: account, services: services, state: result)
            try progress.validateCompletion(of: expected)
            return progress
        }
    }
    func gatewayProgress(callerUID: uid_t) throws -> SetupGatewayProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            guard try machine.runtimeActivation(accountID: account.accountID).jobsRegistered else { return nil }
            let progress = try gatewayProgress(machine: machine, account: account)
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            return progress
        }
    }
    // The endpoint must authenticate the UID and current administrator rights before this explicit operation.
    func prepareGateway(callerUID: uid_t, expected: SetupGatewayProgress, choices: GatewaySetupPreparationChoices) throws -> SetupGatewayProgress {
        try prepareGateway(callerUID: callerUID, expected: expected) { machine, account, verify in
            try GatewaySetupAccountPreparation.prepare(machine: machine, account: account, choices: choices, verifyCurrent: verify)
        }
    }
    // Owned fixtures keep the real machine store and account checks. The injected preparation proves neither Root admission nor service isolation.
    func prepareGateway(callerUID: uid_t, expected: SetupGatewayProgress,
                        prepare: (PreparationIntentStore, AccountPreparationIntent, () throws -> Void) throws -> Void) throws -> SetupGatewayProgress {
        try withMachine { machine in
            guard expected.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            guard try gatewayProgress(machine: machine, account: account) == expected else { throw AdministrativeSetupError.staleProgress }
            if expected.journalInitialized { return expected }
            try prepare(machine, account, { try self.verifyEnrollment(account, callerUID: callerUID, machine: machine) })
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let progress = try gatewayProgress(machine: machine, account: account)
            try progress.validatePreparation(of: expected)
            return progress
        }
    }
    func resumeGatewayJournal(callerUID: uid_t, expected: SetupGatewayProgress) async throws -> SetupGatewayJournalResult {
        let context = try lock.withLock {
            guard !closed, !closing, getpid() == processID, let operation = gatewayJournalOperation else {
                throw AdministrativeSetupError.unavailable
            }
            let admission = try admitSetupMutation()
            do { return (admission, try releaseActivity?.acquireShared(), operation) }
            catch { admission.close(); throw error }
        }
        defer { context.1?.close(); context.0.close() }
        let digest = try withMachine(admission: context.0) { machine -> Data in
            guard expected.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            guard try gatewayProgress(machine: machine, account: account) == expected,
                  let digest = expected.journalIntentDigest else { throw AdministrativeSetupError.staleProgress }
            return digest
        }
        try Task.checkCancellation()
        // The first writer is closed. The Root operation owns a separate machine lease across its exchange.
        let report = try await context.2.resume(callerUID, digest, { [self] inventory in
            try lock.withLock {
                guard !closed, getpid() == processID else { throw AdministrativeSetupError.unavailable }
                try context.1?.validate(); try releaseActivity?.validate()
                guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
                    throw AdministrativeSetupError.changedInstallation
                }
                try verifyHost(inventory)
            }
        })
        try Task.checkCancellation(); try context.1?.validate()
        guard report.intentDigest == digest else { throw AdministrativeSetupError.staleProgress }
        let progress = try withMachine(admission: context.0) { machine in
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let value = try gatewayProgress(machine: machine, account: account)
            try value.validateJournalCompletion(of: expected)
            return value
        }
        return try .init(progress: progress, cleanupComplete: report.cleanupComplete)
    }
    private func gatewayProgress(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> SetupGatewayProgress {
        try .init(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
            activation: machine.runtimeActivation(accountID: account.accountID),
            material: machine.gatewayPreparation(accountID: account.accountID), journal: machine.gatewayJournalPreparation(accountID: account.accountID))
    }
    func gatewayActivationProgress(callerUID: uid_t) throws -> SetupGatewayActivationProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            guard try machine.runtimeActivation(accountID: account.accountID).jobsRegistered else { return nil }
            let progress = try gatewayActivationProgress(machine: machine, account: account)
            try verifyEnrollment(account, callerUID: callerUID, machine: machine); return progress
        }
    }
    func resumeGatewayActivation(callerUID: uid_t, expected: SetupGatewayActivationProgress,
                                 settings: GatewayRuntimeActivationSettings) async throws -> SetupGatewayActivationProgress {
        let context = try lock.withLock {
            guard !closed, !closing, getpid() == processID, let operation = gatewayActivationOperation else {
                throw AdministrativeSetupError.unavailable
            }
            let admission = try admitSetupMutation()
            do { return (admission, try releaseActivity?.acquireShared(), operation) }
            catch { admission.close(); throw error }
        }
        defer { context.1?.close(); context.0.close() }
        try withMachine(admission: context.0) { machine in
            guard expected.setup.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            guard try gatewayActivationProgress(machine: machine, account: account) == expected else {
                throw AdministrativeSetupError.staleProgress
            }
            guard expected.setup.journalInitialized else { throw GatewayPreparationError.incomplete }
            guard expected.settings == nil || expected.settings == settings else { throw GatewayPreparationError.conflictingMaterial }
        }
        try Task.checkCancellation()
        let report = try await context.2.resume(callerUID, expected, settings, { [self] inventory in
            try lock.withLock {
                guard !closed, getpid() == processID else { throw AdministrativeSetupError.unavailable }
                try context.1?.validate(); try releaseActivity?.validate()
                guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
                    throw AdministrativeSetupError.changedInstallation
                }
                try verifyHost(inventory)
            }
        })
        try Task.checkCancellation(); try context.1?.validate()
        return try withMachine(admission: context.0) { machine in
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let value = try gatewayActivationProgress(machine: machine, account: account)
            try value.validateActivation(of: expected, selectedSettings: settings)
            guard report.planDigest.count == 32, value.planDigest == report.planDigest else { throw AdministrativeSetupError.staleProgress }
            return value
        }
    }
    func prepareImportedGateway(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                fileWakeCustodyAccepted: Bool,
                                prepare: (PreparationIntentStore, AccountPreparationIntent, GatewaySetupPreparationChoices, GatewayRuntimeSettingsSelection, () throws -> Void) throws -> Void = {
                                    try GatewaySetupAccountPreparation.prepareImported(machine: $0, account: $1, choices: $2, selection: $3, verifyCurrent: $4)
                                }, validate: (PreparationIntentStore, AccountPreparationIntent, GatewaySetupPreparationChoices, GatewayRuntimeSettingsSelection, () throws -> Void) throws -> Void = {
                                    try SharedSetupImportGatewayPreparedValidation.validateNative(machine: $0, account: $1, choices: $2, selection: $3, verifyCurrent: $4)
                                }) throws -> SetupPortableImportProgress {
        try withMachine { machine in
            guard expected.runtime.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            func verifyDestination() throws {
                try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                guard try currentInventory(machine) == inventory,
                      try machine.serviceAccountPlan(accountID: account.accountID) == services,
                      try machine.runtimePreparation(accountID: account.accountID) == runtime else {
                    throw AdministrativeSetupError.staleProgress
                }
            }
            return try machine.withSharedImportJournal { journal in
                guard let journal, var retained = try journal.current(scope: scope) else { throw SharedSetupImportError.wrongScope }
                let before = try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
                guard before == expected else { throw AdministrativeSetupError.staleProgress }
                guard try retained.matches(proposal) else { throw SharedSetupImportError.conflict }
                guard retained.phase == .runtimePublished || retained.phase == .gatewayPrepared else {
                    throw SharedSetupImportError.invalidTransition
                }
                func verify() throws {
                    try verifyDestination()
                    guard try journal.current(scope: scope) == retained else { throw SharedSetupImportError.staleRevision }
                }
                func validatePrepared(_ choices: GatewaySetupPreparationChoices?, _ verify: () throws -> Void) throws {
                    if let choices {
                        guard let selection = proposal.defaults.gateway else { throw PortableSetupError.rejected }
                        try withoutActuallyEscaping(verify) { current in
                            try validate(machine, account, choices, selection, current)
                        }
                    } else {
                        try SharedSetupImportGatewayPreparedValidation.validateAbsent(machine: machine, account: account, verifyCurrent: verify)
                    }
                }
                try verify()
                if retained.phase == .runtimePublished {
                    try SharedSetupImportGatewayScope.withReviewedPreparation(machine: machine, account: account,
                        journal: journal, expected: retained, proposal: proposal, fileWakeCustodyAccepted: fileWakeCustodyAccepted,
                        verifyCurrent: verify) { choices, current in
                        try withoutActuallyEscaping(current) { preparedCurrent in
                            if let choices {
                                guard let selection = proposal.defaults.gateway else { throw PortableSetupError.rejected }
                                try prepare(machine, account, choices, selection, preparedCurrent)
                            }
                            try validatePrepared(choices, preparedCurrent)
                        }
                    }
                    try verify(); retained = try journal.advance(retained, to: .gatewayPrepared)
                } else {
                    let choices = proposal.fcm == nil && proposal.pushClient == nil ? nil
                        : try proposal.gatewayPreparationChoices(fileWakeCustodyAccepted: false)
                    try validatePrepared(choices, verify)
                }
                try verify()
                return try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
            }
        }
    }


    func resumeImportedGateway(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                               validatePrepared: @Sendable (PreparationIntentStore, AccountPreparationIntent, GatewaySetupPreparationChoices,
                                   GatewayRuntimeSettingsSelection, () throws -> Void) throws -> Void = {
                                       try SharedSetupImportGatewayPreparedValidation.validateNative(machine: $0, account: $1,
                                           choices: $2, selection: $3, verifyCurrent: $4)
                                   }) async throws -> SetupImportedGatewayRuntimeResult {
        let context = try lock.withLock {
            guard !closed, !closing, getpid() == processID, let operation = importedGatewayOperation else {
                throw AdministrativeSetupError.unavailable
            }
            let admission = try admitSetupMutation()
            do { return (admission, try releaseActivity?.acquireShared(), operation) }
            catch { admission.close(); throw error }
        }
        defer { context.1?.close(); context.0.close() }
        func read() throws -> (SharedSetupImportIntent, SetupGatewayActivationProgress) {
            try withMachine(admission: context.0) { machine in
                guard expected.runtime.ownerUID == callerUID,
                      let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
                try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
                let runtime = try machine.runtimePreparation(accountID: account.accountID)
                let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
                let retained = try machine.withSharedImportJournal { journal in
                    guard let journal, let retained = try journal.current(scope: scope) else { throw SharedSetupImportError.wrongScope }
                    let current = try SetupPortableImportProgress(account: account, inventory: inventory,
                        services: services, runtime: runtime, retained: retained)
                    guard current == expected else { throw AdministrativeSetupError.staleProgress }
                    guard try retained.matches(proposal) else { throw SharedSetupImportError.conflict }
                    return retained
                }
                guard proposal.fcm != nil, proposal.pushClient != nil, let selection = proposal.defaults.gateway else {
                    throw GatewayPreparationError.incomplete
                }
                let choices = try proposal.gatewayPreparationChoices(fileWakeCustodyAccepted: false)
                func verify() throws {
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime else {
                        throw AdministrativeSetupError.staleProgress
                    }
                    try SharedSetupImportGatewayRuntimeScope.validate(machine: machine, account: account,
                        expected: retained, activationSettings: selection.activation)
                }
                try verify(); try validatePrepared(machine, account, choices, selection, verify); try verify()
                return (retained, try gatewayActivationProgress(machine: machine, account: account))
            }
        }
        let before = try read(), retained = before.0
        guard let digest = before.1.setup.journalIntentDigest, let selection = proposal.defaults.gateway else {
            throw GatewayPreparationError.incomplete
        }
        let verifyHost: @Sendable (InstallationInventory) throws -> Void = { [self] inventory in
            try lock.withLock {
                guard !closed, getpid() == processID else { throw AdministrativeSetupError.unavailable }
                try context.1?.validate(); try releaseActivity?.validate()
                guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
                    throw AdministrativeSetupError.changedInstallation
                }
                try self.verifyHost(inventory)
            }
        }
        try Task.checkCancellation()
        let initialized = try await context.2.initialize(callerUID, digest, retained, verifyHost)
        try Task.checkCancellation(); try context.1?.validate()
        let ready = try read()
        guard ready.0 == retained, initialized.intentDigest == digest, ready.1.setup.journalInitialized else {
            throw AdministrativeSetupError.staleProgress
        }
        if !initialized.cleanupComplete {
            return .init(progress: expected, cleanupComplete: false, activation: nil)
        }
        let report = try await context.2.activate(callerUID, ready.1, selection.activation, retained, verifyHost)
        try Task.checkCancellation(); try context.1?.validate()
        let final = try read()
        guard final.0 == retained else { throw AdministrativeSetupError.staleProgress }
        try final.1.validateActivation(of: ready.1, selectedSettings: selection.activation)
        guard final.1.planDigest == report.planDigest else { throw AdministrativeSetupError.staleProgress }
        return .init(progress: expected, cleanupComplete: true, activation: final.1)
    }


    func prepareImportedRelayPlan(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                  selectPort: (Set<UInt16>) throws -> UInt16 = { try SharedSetupRelayPortSelection.choose(reserved: $0) }) throws -> SharedSetupImportRelayPlan {
        try withMachine { machine in
            guard expected.runtime.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            return try machine.withSharedImportJournal { journal in
                guard let journal, let retained = try journal.current(scope: scope) else { throw SharedSetupImportError.wrongScope }
                guard try SetupPortableImportProgress(account: account, inventory: inventory, services: services,
                    runtime: runtime, retained: retained) == expected else { throw AdministrativeSetupError.staleProgress }
                guard try retained.matches(proposal), proposal.cloudflare != nil else { throw SharedSetupImportError.conflict }
                func verify() throws {
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime,
                          try journal.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
                }
                try verify()
                return try machine.withSharedImportRelayDirectory { directory, owner in
                    try SharedSetupImportRelayStorage.prepare(expected: retained, records: journal.records(),
                        runtimePublished: runtime.reference != nil || runtime.configurationPublished,
                        directory: directory, owner: owner, select: selectPort, verifyCurrent: verify)
                }
            }
        }
    }


    func inspectImportedRelayScope(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                   inspect: @escaping @Sendable (SetupCloudflareConfiguration) async throws -> CloudflareProvisioningScope = {
                                       try await CloudflareProvisioningScopeClient.native().inspect($0)
                                   }) async throws -> CloudflareProvisioningScope {
        try await withImportedRelayInspection(callerUID: callerUID, expected: expected, proposal: proposal, requiresPlan: false) { configuration, _ in
            let result = try await inspect(configuration); try result.validate(configuration); return result
        }
    }

    func inspectImportedRelayTunnel(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                    inspect: @escaping @Sendable (SetupCloudflareConfiguration, SharedSetupImportIntent, SharedSetupImportRelayPlan) async throws -> CloudflareImportedRelayInspection = {
                                        try await CloudflareImportedRelayInspection.native(configuration: $0, expected: $1, plan: $2)
                                    }) async throws -> CloudflareImportedRelayInspection {
        try await withImportedRelayInspection(callerUID: callerUID, expected: expected, proposal: proposal, requiresPlan: true) { configuration, binding in
            guard let plan = binding.plan else { throw SharedSetupImportCompletionValidation.Failure.incomplete }
            let result = try await inspect(configuration, binding.retained, plan)
            try result.validate(configuration: configuration, expected: binding.retained, plan: plan); return result
        }
    }

    private struct ImportedRelayInspectionBinding: Sendable {
        let retained: SharedSetupImportIntent
        let inventory: InstallationInventory
        let plan: SharedSetupImportRelayPlan?
        let planSnapshot: SharedSetupImportRelayStorage.Snapshot?
        let admission: SetupOwnerAsyncWork.Token
    }

    func createImportedRelayTunnel(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                    inspect: @escaping @Sendable (SetupCloudflareConfiguration, SharedSetupImportIntent, SharedSetupImportRelayPlan) async throws -> CloudflareImportedRelayInspection = {
                                        try await CloudflareImportedRelayInspection.native(configuration: $0, expected: $1, plan: $2)
                                    },
                                    create: @escaping @Sendable (SetupCloudflareConfiguration, SharedSetupImportIntent, SharedSetupImportRelayPlan, SharedSetupRelayProvisioningRecord) async throws -> CloudflareTunnelCreationOutcome = {
                                        try await CloudflareTunnelCreationClient.native().create($0, expected: $1, plan: $2, dispatched: $3)
                                    }) async throws -> SharedSetupRelayProvisioningRecord {
        try await withImportedRelayInspection(callerUID: callerUID, expected: expected, proposal: proposal, requiresPlan: true) { configuration, binding in
            guard let plan = binding.plan else { throw SharedSetupImportCompletionValidation.Failure.incomplete }
            let prepared = try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { retained, plan, directory, owner, verify in
                try SharedSetupRelayProvisioningStorage.begin(expected: retained, plan: plan, directory: directory, owner: owner, verifyCurrent: verify)
            }
            if prepared.phase == .created { return prepared }
            guard prepared.phase == .prepared else { throw RelayProvisioningError.requiresReconciliation }
            guard [.retained, .runtimePublished, .gatewayPrepared].contains(binding.retained.phase) else { throw RelayProvisioningError.invalidTransition }
            let observed = try await inspect(configuration, binding.retained, plan)
            try observed.validate(configuration: configuration, expected: binding.retained, plan: plan)
            guard observed.tunnel == nil else { throw RelayProvisioningError.wrongScope }
            try Task.checkCancellation()
            let dispatched = try prepared.transition(to: .dispatched)
            try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { retained, plan, directory, owner, verify in
                try Task.checkCancellation()
                try SharedSetupRelayProvisioningStorage.replace(dispatched, previous: prepared, expected: retained, plan: plan,
                    directory: directory, owner: owner, verifyCurrent: verify)
            }
            let outcome: CloudflareTunnelCreationOutcome
            do { outcome = try await create(configuration, binding.retained, plan, dispatched) }
            catch { outcome = .unknown }
            let next: SharedSetupRelayProvisioningRecord
            switch outcome {
            case .created(let observation):
                if observation.accountID == configuration.accountID, observation.name == plan.tunnelName,
                   observation.tunnelID.utf8.count == 36, let uuid = UUID(uuidString: observation.tunnelID),
                   uuid.uuidString.lowercased() == observation.tunnelID {
                    next = try dispatched.transition(to: .created, tunnelID: observation.tunnelID)
                } else { next = try dispatched.transition(to: .unknown) }
            case .rejected(let refusal): next = try dispatched.transition(to: .rejected, refusal: refusal)
            case .unknown: next = try dispatched.transition(to: .unknown)
            }
            // Record an acknowledgement before reporting cancellation. If closing or scope changes prevent this, dispatch remains unresolved.
            try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { retained, plan, directory, owner, verify in
                try SharedSetupRelayProvisioningStorage.replace(next, previous: dispatched, expected: retained, plan: plan,
                    directory: directory, owner: owner, verifyCurrent: verify)
            }
            return next
        }
    }

    /// The endpoint must obtain fresh administrator authorization and bind the exact rejected record before entry.
    /// This reads provider absence and prepares local state only. Creation still requires its own complete preflight.
    func prepareRefusedImportedRelayTunnelRetry(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                    expectedRecordDigest: Data,
                    inspect: @escaping @Sendable (SetupCloudflareConfiguration, SharedSetupImportIntent, SharedSetupImportRelayPlan) async throws -> CloudflareImportedRelayInspection = {
                        try await CloudflareImportedRelayInspection.native(configuration: $0, expected: $1, plan: $2)
                    }) async throws -> SharedSetupRelayProvisioningRecord {
        guard expectedRecordDigest.count == 32 else { throw RelayProvisioningError.invalidRecord }
        return try await withImportedRelayInspection(callerUID: callerUID, expected: expected, proposal: proposal, requiresPlan: true) { configuration, binding in
            guard let plan = binding.plan else { throw SharedSetupImportCompletionValidation.Failure.incomplete }
            guard [.retained, .runtimePublished, .gatewayPrepared].contains(binding.retained.phase) else {
                throw RelayProvisioningError.invalidTransition
            }
            let before = try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard let record = try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: directory, owner: owner),
                      Data(SHA256.hash(data: record.bytes)) == expectedRecordDigest,
                      let snapshot = try SharedSetupRelayProvisioningStorage.snapshot(expected: intent, plan: plan, directory: directory, owner: owner) else {
                    throw RelayProvisioningError.staleRecord
                }
                guard record.phase == .rejected else { throw RelayProvisioningError.invalidTransition }
                try verify(); return (record, snapshot)
            }
            let observed = try await inspect(configuration, binding.retained, plan)
            try observed.validate(configuration: configuration, expected: binding.retained, plan: plan)
            guard observed.tunnel == nil else { throw RelayProvisioningError.requiresReconciliation }
            try Task.checkCancellation()
            return try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: directory, owner: owner) == before.0,
                      try SharedSetupRelayProvisioningStorage.snapshot(expected: intent, plan: plan, directory: directory, owner: owner) == before.1 else {
                    throw RelayProvisioningError.staleRecord
                }
                let next = try before.0.retryAfterRefusal()
                try Task.checkCancellation()
                try SharedSetupRelayProvisioningStorage.replace(next, previous: before.0, expected: intent, plan: plan,
                    directory: directory, owner: owner, verifyCurrent: verify)
                return next
            }
        }
    }

    func applyImportedRelayIngress(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                   send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareTunnelConfigurationObservation {
        try await withCreatedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, created, _, scoped in
            let intent = binding.retained
            let routes = CloudflarePrivateRouteClient(send: scoped)
            _ = try await routes.inspect(configuration, expected: intent, plan: plan, created: created)
            let observed = try await CloudflareTunnelConfigurationClient(send: scoped).apply(configuration, expected: intent, plan: plan, created: created)
            _ = try await routes.inspect(configuration, expected: intent, plan: plan, created: created)
            return observed
        }
    }

    func inspectImportedRelayPrivateRoutes(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                          send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflarePrivateRouteObservation {
        try await withCreatedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, created, _, scoped in
            let intent = binding.retained
            return try await CloudflarePrivateRouteClient(send: scoped).inspect(configuration, expected: intent, plan: plan, created: created)
        }
    }

    func prepareImportedRelayRunCredential(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                        fileCustodyAccepted: Bool, operations: RelayRunCredentialSetupOperations = .native,
                        send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> RelayRunCredentialReference {
        try await withRetainedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) {
            configuration, binding, plan, tunnel, tunnelSnapshot, scoped, verifyRetained in
            @Sendable func prepare(_ credential: CloudflareTunnelRunCredential?) throws -> RelayRunCredentialReference {
                try Task.checkCancellation()
                return try self.withImportedRelayProvisioningContext(binding: binding, callerUID: callerUID, expected: expected,
                    proposal: proposal) { account, inventory, state, intent, plan, directory, owner, verify in
                    guard state.configurationPublished, let runtime = state.reference else { throw RuntimePreparationError.incomplete }
                    func verifyAll() throws {
                        try Task.checkCancellation(); try verify()
                        guard try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: directory, owner: owner) == tunnel,
                              try SharedSetupRelayProvisioningStorage.snapshot(expected: intent, plan: plan, directory: directory, owner: owner) == tunnelSnapshot else {
                            throw RelayProvisioningError.staleRecord
                        }
                    }
                    try verifyAll()
                    let reference = try SharedSetupRelayRunReferenceStorage.read(expected: intent, plan: plan, created: tunnel,
                        directory: directory, owner: owner)
                    let context = RelayRunCredentialSetupContext(account: account, inventory: inventory, expected: intent,
                        plan: plan, created: tunnel, runtime: runtime, reference: reference)
                    let prepared: RelayRunCredentialReference
                    do { prepared = try operations.prepare(context, credential, fileCustodyAccepted, verifyAll) }
                    catch RelayRunCredentialSetupError.credentialRequired {
                        guard reference == nil, credential == nil else { throw RuntimePreparationError.missingMaterial }
                        guard fileCustodyAccepted else { throw RuntimePreparationError.custodyNotAccepted }
                        guard [.runtimePublished, .gatewayPrepared].contains(intent.phase) else { throw RuntimePreparationError.incomplete }
                        throw RelayRunCredentialSetupError.credentialRequired
                    }
                    _ = try RelayRunCredentialReference.decode(prepared.encoded, expected: intent, plan: plan, created: tunnel,
                        runtime: runtime, account: account, inventory: inventory)
                    try verifyAll()
                    let accepted = try SharedSetupRelayRunReferenceStorage.retain(prepared, expected: intent, plan: plan,
                        created: tunnel, runtime: runtime, directory: directory, owner: owner, verifyCurrent: verifyAll)
                    try operations.publish(context, accepted, verifyAll)
                    guard try SharedSetupRelayRunReferenceStorage.read(expected: intent, plan: plan, created: tunnel,
                        directory: directory, owner: owner) == accepted else { throw RelayProvisioningError.staleRecord }
                    try verifyAll(); return accepted
                }
            }
            do { return try prepare(nil) }
            catch RelayRunCredentialSetupError.credentialRequired {
                let credential = try await CloudflareTunnelTokenClient(send: scoped).read(configuration,
                    expected: binding.retained, plan: plan, created: tunnel)
                try Task.checkCancellation(); try verifyRetained()
                return try prepare(credential)
            }
        }
    }

    func readImportedRelayRunCredential(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                        send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareTunnelRunCredential {
        try await withCreatedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, _, scoped in
            try await CloudflareTunnelTokenClient(send: scoped).read(configuration, expected: binding.retained, plan: plan, created: tunnel)
        }
    }

    func createImportedAccessApplication(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                         send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> SharedSetupAccessApplicationRecord {
        try await withCreatedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, tunnelSnapshot, scoped in
            let initial = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                let record = try SharedSetupAccessApplicationStorage.begin(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner, verifyCurrent: verify)
                let snapshot = try Self.requireAccessSnapshot(SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner))
                return (record, snapshot)
            }
            if initial.0.phase == .created { return initial.0 }
            guard initial.0.phase == .prepared else { throw RelayProvisioningError.requiresReconciliation }
            guard [.retained, .runtimePublished, .gatewayPrepared].contains(binding.retained.phase) else { throw RelayProvisioningError.invalidTransition }
            let client = CloudflareAccessApplicationClient(send: scoped)
            try await client.inspectAbsent(configuration, expected: binding.retained, plan: plan, createdTunnel: tunnel)
            try Task.checkCancellation()
            let dispatched = try initial.0.transition(to: .dispatched)
            let sentSnapshot = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) == initial.1 else { throw RelayProvisioningError.staleRecord }
                try Task.checkCancellation()
                try SharedSetupAccessApplicationStorage.replace(dispatched, previous: initial.0, expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner, verifyCurrent: verify)
                return try Self.requireAccessSnapshot(SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner))
            }
            let outcome: CloudflareAccessApplicationCreationOutcome
            do { outcome = try await client.create(configuration, expected: binding.retained, plan: plan, createdTunnel: tunnel, dispatched: dispatched) }
            catch { outcome = .unknown }
            let next: SharedSetupAccessApplicationRecord
            switch outcome {
            case .created(let app):
                if app.accountID == configuration.accountID, app.name == plan.accessApplicationName, app.hostname == plan.hostname,
                   let value = try? dispatched.transition(to: .created, applicationID: app.applicationID, audience: app.audience) { next = value }
                else { next = try dispatched.transition(to: .unknown) }
            case .rejected(let refusal): next = try dispatched.transition(to: .rejected, refusal: refusal)
            case .unknown: next = try dispatched.transition(to: .unknown)
            }
            try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) == sentSnapshot else { throw RelayProvisioningError.staleRecord }
                try SharedSetupAccessApplicationStorage.replace(next, previous: dispatched, expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner, verifyCurrent: verify)
            }
            return next
        }
    }

    /// Requires fresh administrator authorization for the exact rejected record. This operation sends reads only.
    func prepareRefusedImportedAccessApplicationRetry(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                    expectedRecordDigest: Data, send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> SharedSetupAccessApplicationRecord {
        guard expectedRecordDigest.count == 32 else { throw RelayProvisioningError.invalidRecord }
        return try await withRetainedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) {
            configuration, binding, plan, tunnel, tunnelSnapshot, scoped, _ in
            guard [.retained, .runtimePublished, .gatewayPrepared].contains(binding.retained.phase) else { throw RelayProvisioningError.invalidTransition }
            let before = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard let record = try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner), Data(SHA256.hash(data: record.bytes)) == expectedRecordDigest else { throw RelayProvisioningError.staleRecord }
                guard record.phase == .rejected else { throw RelayProvisioningError.invalidTransition }
                let snapshot = try Self.requireAccessSnapshot(SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner)); try verify(); return (record, snapshot)
            }
            @Sendable func verifyRejected() throws {
                try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                    callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                    guard try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == before.0,
                          try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == before.1 else { throw RelayProvisioningError.staleRecord }
                    try verify()
                }
            }
            let reads: CloudflareProvisioningScopeClient.Send = { request in
                try Task.checkCancellation(); try verifyRejected()
                let response = try await scoped(request)
                try Task.checkCancellation(); try verifyRejected(); return response
            }
            do {
                _ = try await CloudflareCreatedTunnelClient(send: reads).inspect(configuration, expected: binding.retained, plan: plan, created: tunnel)
                try await CloudflareAccessApplicationClient(send: reads).inspectAbsent(configuration, expected: binding.retained, plan: plan, createdTunnel: tunnel)
                try verifyRejected()
            } catch { try Task.checkCancellation(); try verifyRejected(); throw error }
            return try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) == before.0,
                      try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) == before.1 else { throw RelayProvisioningError.staleRecord }
                try Task.checkCancellation(); let next = try before.0.retryAfterRefusal()
                try SharedSetupAccessApplicationStorage.replace(next, previous: before.0, expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner, verifyCurrent: verify)
                return next
            }
        }
    }

    func inspectImportedInitialAccessApplication(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                                send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareInitialAccessObservation {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, _, application, scoped in
            try await CloudflareAccessApplicationClient(send: scoped).inspectInitial(configuration, expected: binding.retained,
                plan: plan, createdTunnel: tunnel, application: application)
        }
    }

    func inspectImportedAccessHostnameInventory(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                               send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareAccessHostnameInventory {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, _, application, scoped in
            try await CloudflareAccessHostnameClient(send: scoped).inspect(configuration, expected: binding.retained,
                plan: plan, createdTunnel: tunnel, application: application)
        }
    }

    func inspectImportedRelayPublicationPreflight(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                                send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareRelayPublicationPreflight {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, _, application, scoped in
            try await CloudflareRelayPublicationPreflightClient(send: scoped).inspect(configuration, expected: binding.retained,
                plan: plan, createdTunnel: tunnel, application: application)
        }
    }

    func createImportedDNSRecord(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                 send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> SharedSetupDNSRecord {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, tunnelSnapshot, application, scoped in
            let initial = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                let record = try SharedSetupDNSStorage.begin(expected: intent, plan: plan, createdTunnel: tunnel, application: application,
                    directory: directory, owner: owner, verifyCurrent: verify)
                guard let snapshot = try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) else { throw RelayProvisioningError.staleRecord }
                let accessSnapshot = try Self.requireAccessSnapshot(SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner))
                return (record, snapshot, accessSnapshot)
            }
            if initial.0.phase == .created { return initial.0 }
            guard initial.0.phase == .prepared else { throw RelayProvisioningError.requiresReconciliation }
            guard [.retained, .runtimePublished, .gatewayPrepared].contains(binding.retained.phase) else { throw RelayProvisioningError.invalidTransition }
            @Sendable func verifyDNS(_ record: SharedSetupDNSRecord, _ snapshot: SharedSetupDNSStorage.Snapshot) throws {
                try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                    callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                    guard try SharedSetupDNSStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: application, directory: directory, owner: owner) == record,
                          try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: application, directory: directory, owner: owner) == snapshot,
                          try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                            directory: directory, owner: owner) == initial.2 else { throw RelayProvisioningError.staleRecord }
                    try verify()
                }
            }
            let preflightSend: CloudflareProvisioningScopeClient.Send = { request in
                try Task.checkCancellation(); try verifyDNS(initial.0, initial.1); return try await scoped(request)
            }
            let observed: CloudflareRelayPublicationPreflight
            do {
                observed = try await CloudflareRelayPublicationPreflightClient(send: preflightSend).inspect(configuration,
                    expected: binding.retained, plan: plan, createdTunnel: tunnel, application: application)
                try verifyDNS(initial.0, initial.1)
            } catch { try Task.checkCancellation(); try verifyDNS(initial.0, initial.1); throw error }
            switch observed.hostnameAssessment {
            case .noOtherMatchObserved, .exactHostnamePrecedesBroaderWildcardRoots: break
            case .requiresPrecedenceVerification: throw RelayProvisioningError.requiresReconciliation
            }
            try Task.checkCancellation()
            let dispatched = try initial.0.transition(to: .dispatched)
            let sentSnapshot = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) == initial.1,
                      try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == initial.2 else { throw RelayProvisioningError.staleRecord }
                try Task.checkCancellation()
                try SharedSetupDNSStorage.replace(dispatched, previous: initial.0, expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner, verifyCurrent: verify)
                guard let snapshot = try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) else { throw RelayProvisioningError.staleRecord }
                return snapshot
            }
            let creationSend: CloudflareProvisioningScopeClient.Send = { request in
                try Task.checkCancellation(); try verifyDNS(dispatched, sentSnapshot); return try await scoped(request)
            }
            let outcome: CloudflareDNSCreationOutcome
            do {
                outcome = try await CloudflareDNSRecordClient(send: creationSend).create(configuration, expected: binding.retained,
                    plan: plan, createdTunnel: tunnel, application: application, dispatched: dispatched)
            } catch { outcome = .unknown }
            let next: SharedSetupDNSRecord
            switch outcome {
            case .created(let identity):
                if identity.zoneID == configuration.zoneID, identity.hostname == plan.hostname,
                   identity.target == dispatched.tunnelID + ".cfargotunnel.com",
                   let created = try? dispatched.transition(to: .created, dnsRecordID: identity.recordID) { next = created }
                else { next = try dispatched.transition(to: .unknown) }
            case .rejected(let refusal): next = try dispatched.transition(to: .rejected, refusal: refusal)
            case .unknown: next = try dispatched.transition(to: .unknown)
            }
            try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) == sentSnapshot,
                      try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == initial.2 else { throw RelayProvisioningError.staleRecord }
                try SharedSetupDNSStorage.replace(next, previous: dispatched, expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner, verifyCurrent: verify)
            }
            return next
        }
    }

    /// Requires fresh administrator authorization for the exact rejected record. This operation sends reads only.
    func prepareRefusedImportedDNSRecordRetry(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                    expectedRecordDigest: Data, send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> SharedSetupDNSRecord {
        guard expectedRecordDigest.count == 32 else { throw RelayProvisioningError.invalidRecord }
        return try await withRetainedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) {
            configuration, binding, plan, tunnel, tunnelSnapshot, scoped, _ in
            guard [.retained, .runtimePublished, .gatewayPrepared].contains(binding.retained.phase) else { throw RelayProvisioningError.invalidTransition }
            let before = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard let application = try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) else { throw RelayProvisioningError.requiresReconciliation }
                _ = try application.createdApplication(expected: intent, plan: plan, createdTunnel: tunnel)
                guard let record = try SharedSetupDNSStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner), Data(SHA256.hash(data: record.bytes)) == expectedRecordDigest else { throw RelayProvisioningError.staleRecord }
                guard record.phase == .rejected else { throw RelayProvisioningError.invalidTransition }
                guard let snapshot = try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) else { throw RelayProvisioningError.staleRecord }
                let accessSnapshot = try Self.requireAccessSnapshot(SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner)); try verify(); return (record, snapshot, application, accessSnapshot)
            }
            @Sendable func verifyRejected() throws {
                try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                    callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                    guard try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == before.2,
                          try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == before.3,
                          try SharedSetupDNSStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: before.2, directory: directory, owner: owner) == before.0,
                          try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: before.2, directory: directory, owner: owner) == before.1 else { throw RelayProvisioningError.staleRecord }
                    try verify()
                }
            }
            let reads: CloudflareProvisioningScopeClient.Send = { request in
                try Task.checkCancellation(); try verifyRejected()
                let response = try await scoped(request)
                try Task.checkCancellation(); try verifyRejected(); return response
            }
            let observed: CloudflareRelayPublicationPreflight
            do {
                _ = try await CloudflareCreatedTunnelClient(send: reads).inspect(configuration, expected: binding.retained, plan: plan, created: tunnel)
                observed = try await CloudflareRelayPublicationPreflightClient(send: reads).inspect(configuration,
                    expected: binding.retained, plan: plan, createdTunnel: tunnel, application: before.2)
                try verifyRejected()
            } catch { try Task.checkCancellation(); try verifyRejected(); throw error }
            switch observed.hostnameAssessment {
            case .noOtherMatchObserved, .exactHostnamePrecedesBroaderWildcardRoots: break
            case .requiresPrecedenceVerification: throw RelayProvisioningError.requiresReconciliation
            }
            return try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) == before.2,
                      try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) == before.3,
                      try SharedSetupDNSStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: before.2, directory: directory, owner: owner) == before.0,
                      try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: before.2, directory: directory, owner: owner) == before.1 else { throw RelayProvisioningError.staleRecord }
                try Task.checkCancellation(); let next = try before.0.retryAfterRefusal()
                try SharedSetupDNSStorage.replace(next, previous: before.0, expected: intent, plan: plan, createdTunnel: tunnel,
                    application: before.2, directory: directory, owner: owner, verifyCurrent: verify)
                return next
            }
        }
    }

    private struct ImportedRelayConnectorSelection: Equatable, Sendable {
        let context: RelayRunCredentialSetupContext
        let dns: SharedSetupDNSRecord
        let dnsSnapshot: SharedSetupDNSStorage.Snapshot
        let accessSnapshot: SharedSetupAccessApplicationStorage.Snapshot
        let runSnapshot: SharedSetupRelayRunReferenceStorage.Snapshot
    }

    /// Checks the live provider configuration before publishing the selected connector's startup metadata.
    /// This does not advance import completion or claim that a connector has reached the provider.
    func publishImportedRelayConnector(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                       operations: RelayConnectorSetupOperations = .native,
                                       send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> AdministrativeSetupPublicationResult {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) {
            configuration, binding, plan, tunnel, tunnelSnapshot, application, scoped in
            @Sendable func withSelection<Value>(_ body: (ImportedRelayConnectorSelection, () throws -> Void) throws -> Value) throws -> Value {
                try self.withImportedRelayProvisioningContext(binding: binding, callerUID: callerUID, expected: expected,
                    proposal: proposal) { account, inventory, state, intent, plan, directory, owner, verify in
                    guard state.configurationPublished, let runtime = state.reference else { throw RuntimePreparationError.incomplete }
                    return try withoutActuallyEscaping(verify) { verifyBase in
                        func read() throws -> ImportedRelayConnectorSelection {
                            try Task.checkCancellation(); try verifyBase()
                            guard try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: directory, owner: owner) == tunnel,
                                  try SharedSetupRelayProvisioningStorage.snapshot(expected: intent, plan: plan, directory: directory, owner: owner) == tunnelSnapshot,
                                  try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                                    directory: directory, owner: owner) == application,
                                  let accessSnapshot = try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                                    createdTunnel: tunnel, directory: directory, owner: owner),
                                  let dns = try SharedSetupDNSStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                                    application: application, directory: directory, owner: owner),
                                  let dnsSnapshot = try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                                    application: application, directory: directory, owner: owner),
                                  let run = try SharedSetupRelayRunReferenceStorage.snapshot(expected: intent, plan: plan,
                                    created: tunnel, directory: directory, owner: owner) else { throw RelayProvisioningError.staleRecord }
                            _ = try dns.createdRecord(expected: intent, plan: plan, createdTunnel: tunnel, application: application)
                            _ = try RelayRunCredentialReference.decode(run.reference.encoded, expected: intent, plan: plan, created: tunnel,
                                runtime: runtime, account: account, inventory: inventory)
                            try verifyBase()
                            return .init(context: .init(account: account, inventory: inventory, expected: intent, plan: plan,
                                created: tunnel, runtime: runtime, reference: run.reference), dns: dns, dnsSnapshot: dnsSnapshot,
                                accessSnapshot: accessSnapshot, runSnapshot: run)
                        }
                        let selected = try read()
                        func verifySelection() throws {
                            guard try read() == selected else { throw RelayProvisioningError.staleRecord }
                        }
                        try verifySelection(); let result = try body(selected, verifySelection); try verifySelection(); return result
                    }
                }
            }
            let selected = try withSelection { selected, _ in selected }
            @Sendable func verifySelected() throws {
                try withSelection { current, _ in guard current == selected else { throw RelayProvisioningError.staleRecord } }
            }
            let preflightSend: CloudflareProvisioningScopeClient.Send = { request in
                try verifySelected(); return try await scoped(request)
            }
            do {
                _ = try await CloudflareRelayConnectorPreflightClient(send: preflightSend).inspect(configuration,
                    expected: binding.retained, plan: plan, createdTunnel: tunnel, application: application, record: selected.dns)
                try Task.checkCancellation(); try verifySelected()
            } catch { try Task.checkCancellation(); try verifySelected(); throw error }
            return try withSelection { current, verify in
                guard current == selected else { throw RelayProvisioningError.staleRecord }
                let mode: RelayRunCredentialPublication.Mode = [.runtimePublished, .gatewayPrepared].contains(current.context.expected.phase)
                    ? .prepareUnactivated : .validateRetained
                return try operations.publish(current.context, current.runSnapshot.reference, mode, verify)
            }
        }
    }

    func inspectImportedDNSRecord(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                  send: CloudflareProvisioningScopeClient.Send? = nil) async throws -> CloudflareDNSRecordObservation {
        try await withCreatedImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, tunnelSnapshot, application, scoped in
            let retained = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard let record = try SharedSetupDNSStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) else { throw RelayProvisioningError.requiresReconciliation }
                _ = try record.createdRecord(expected: intent, plan: plan, createdTunnel: tunnel, application: application)
                guard let snapshot = try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                    application: application, directory: directory, owner: owner) else { throw RelayProvisioningError.staleRecord }
                try verify(); return (record, snapshot)
            }
            @Sendable func verifyDNS() throws {
                try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                    callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                    guard try SharedSetupDNSStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: application, directory: directory, owner: owner) == retained.0,
                          try SharedSetupDNSStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        application: application, directory: directory, owner: owner) == retained.1 else { throw RelayProvisioningError.staleRecord }
                    try verify()
                }
            }
            let dnsSend: CloudflareProvisioningScopeClient.Send = { request in try Task.checkCancellation(); try verifyDNS(); return try await scoped(request) }
            do {
                let result = try await CloudflareDNSRecordClient(send: dnsSend).inspect(configuration, expected: binding.retained,
                    plan: plan, createdTunnel: tunnel, application: application, record: retained.0)
                try verifyDNS(); return result
            } catch { try Task.checkCancellation(); try verifyDNS(); throw error }
        }
    }

    private func withCreatedImportedAccessApplication<Value: Sendable>(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                        send: CloudflareProvisioningScopeClient.Send?,
                        operation: @escaping @Sendable (SetupCloudflareConfiguration, ImportedRelayInspectionBinding, SharedSetupImportRelayPlan,
                            SharedSetupRelayProvisioningRecord, SharedSetupRelayProvisioningStorage.Snapshot, SharedSetupAccessApplicationRecord, @escaping CloudflareProvisioningScopeClient.Send) async throws -> Value) async throws -> Value {
        try await withCreatedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) { configuration, binding, plan, tunnel, tunnelSnapshot, scoped in
            let retained = try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard let record = try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                    directory: directory, owner: owner) else { throw RelayProvisioningError.requiresReconciliation }
                _ = try record.createdApplication(expected: intent, plan: plan, createdTunnel: tunnel)
                let snapshot = try Self.requireAccessSnapshot(SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan,
                    createdTunnel: tunnel, directory: directory, owner: owner)); try verify(); return (record, snapshot)
            }
            @Sendable func verifyAccess() throws {
                try self.withImportedAccessDirectory(binding: binding, tunnel: tunnel, tunnelSnapshot: tunnelSnapshot,
                    callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                    guard try SharedSetupAccessApplicationStorage.read(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == retained.0,
                          try SharedSetupAccessApplicationStorage.snapshot(expected: intent, plan: plan, createdTunnel: tunnel,
                        directory: directory, owner: owner) == retained.1 else { throw RelayProvisioningError.staleRecord }; try verify()
                }
            }
            let accessSend: CloudflareProvisioningScopeClient.Send = { request in try Task.checkCancellation(); try verifyAccess(); return try await scoped(request) }
            do {
                let result = try await operation(configuration, binding, plan, tunnel, tunnelSnapshot, retained.0, accessSend)
                try verifyAccess(); return result
            } catch { try Task.checkCancellation(); try verifyAccess(); throw error }
        }
    }

    private static func requireAccessSnapshot(_ value: SharedSetupAccessApplicationStorage.Snapshot?) throws -> SharedSetupAccessApplicationStorage.Snapshot {
        guard let value else { throw RelayProvisioningError.staleRecord }; return value
    }

    private func withImportedAccessDirectory<Value>(binding: ImportedRelayInspectionBinding, tunnel: SharedSetupRelayProvisioningRecord,
                        tunnelSnapshot: SharedSetupRelayProvisioningStorage.Snapshot, callerUID: uid_t, expected: SetupPortableImportProgress,
                        proposal: PortableSetup,
                        body: (SharedSetupImportIntent, SharedSetupImportRelayPlan, ProtectedSetupDirectory, uid_t, () throws -> Void) throws -> Value) throws -> Value {
        try withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
            return try withoutActuallyEscaping(verify) { current in
                func verifyAll() throws {
                    try current()
                    guard try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: directory, owner: owner) == tunnel,
                          try SharedSetupRelayProvisioningStorage.snapshot(expected: intent, plan: plan, directory: directory, owner: owner) == tunnelSnapshot else {
                        throw RelayProvisioningError.staleRecord
                    }
                }
                try verifyAll(); let result = try body(intent, plan, directory, owner, verifyAll); try verifyAll(); return result
            }
        }
    }

    private func withCreatedImportedRelay<Value: Sendable>(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                            send: CloudflareProvisioningScopeClient.Send?,
                            operation: @escaping @Sendable (SetupCloudflareConfiguration, ImportedRelayInspectionBinding, SharedSetupImportRelayPlan,
                                SharedSetupRelayProvisioningRecord, SharedSetupRelayProvisioningStorage.Snapshot, @escaping CloudflareProvisioningScopeClient.Send) async throws -> Value) async throws -> Value {
        try await withRetainedImportedRelay(callerUID: callerUID, expected: expected, proposal: proposal, send: send) {
            configuration, binding, plan, tunnel, snapshot, scoped, verify in
            _ = try await CloudflareCreatedTunnelClient(send: scoped).inspect(configuration, expected: binding.retained, plan: plan, created: tunnel)
            try Task.checkCancellation(); try verify()
            return try await operation(configuration, binding, plan, tunnel, snapshot, scoped)
        }
    }

    private func withRetainedImportedRelay<Value: Sendable>(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                            send: CloudflareProvisioningScopeClient.Send?,
                            operation: @escaping @Sendable (SetupCloudflareConfiguration, ImportedRelayInspectionBinding, SharedSetupImportRelayPlan,
                                SharedSetupRelayProvisioningRecord, SharedSetupRelayProvisioningStorage.Snapshot, @escaping CloudflareProvisioningScopeClient.Send, @escaping @Sendable () throws -> Void) async throws -> Value) async throws -> Value {
        try await withImportedRelayInspection(callerUID: callerUID, expected: expected, proposal: proposal, requiresPlan: true) { configuration, binding in
            guard let plan = binding.plan else { throw SharedSetupImportCompletionValidation.Failure.incomplete }
            let retained = try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                guard let record = try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: directory, owner: owner),
                      let snapshot = try SharedSetupRelayProvisioningStorage.snapshot(expected: intent, plan: plan, directory: directory, owner: owner) else {
                    throw RelayProvisioningError.requiresReconciliation
                }
                _ = try record.createdTunnel(expected: intent, plan: plan); try verify(); return (record, snapshot)
            }
            @Sendable func verifyRetained() throws {
                try self.withImportedRelayProvisioning(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) { intent, plan, directory, owner, verify in
                    guard try SharedSetupRelayProvisioningStorage.read(expected: intent, plan: plan, directory: directory, owner: owner) == retained.0,
                          try SharedSetupRelayProvisioningStorage.snapshot(expected: intent, plan: plan, directory: directory, owner: owner) == retained.1 else {
                        throw RelayProvisioningError.staleRecord
                    }
                    try verify()
                }
            }
            let transport: CloudflareProvisioningScopeClient.Send
            if let send { transport = send }
            else { let native = try FCMHTTPTransport(timeoutSeconds: 30); transport = { try await native.send($0) } }
            let scoped: CloudflareProvisioningScopeClient.Send = { request in
                try Task.checkCancellation(); try verifyRetained()
                return try await transport(request)
            }
            do {
                let observed = try await operation(configuration, binding, plan, retained.0, retained.1, scoped, verifyRetained)
                try Task.checkCancellation(); try verifyRetained(); return observed
            } catch {
                try Task.checkCancellation(); try verifyRetained()
                throw error
            }
        }
    }

    private func withImportedRelayProvisioning<Value>(binding: ImportedRelayInspectionBinding, callerUID: uid_t,
                    expected: SetupPortableImportProgress, proposal: PortableSetup,
                    body: (SharedSetupImportIntent, SharedSetupImportRelayPlan, ProtectedSetupDirectory, uid_t, () throws -> Void) throws -> Value) throws -> Value {
        try withImportedRelayProvisioningContext(binding: binding, callerUID: callerUID, expected: expected, proposal: proposal) {
            _, _, _, intent, plan, directory, owner, verify in
            try withoutActuallyEscaping(verify) { current in
                try body(intent, plan, directory, owner, current)
            }
        }
    }

    private func withImportedRelayProvisioningContext<Value>(binding: ImportedRelayInspectionBinding, callerUID: uid_t,
                    expected: SetupPortableImportProgress, proposal: PortableSetup,
                    body: (AccountPreparationIntent, InstallationInventory, RuntimePreparationState, SharedSetupImportIntent, SharedSetupImportRelayPlan, ProtectedSetupDirectory, uid_t, () throws -> Void) throws -> Value) throws -> Value {
        try withMachine(admission: binding.admission) { machine in
            guard expected.runtime.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            guard inventory == binding.inventory else { throw AdministrativeSetupError.staleProgress }
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            return try machine.withSharedImportJournal { journal in
                guard let journal, let retained = try journal.current(scope: scope), retained == binding.retained,
                      try retained.matches(proposal),
                      try SetupPortableImportProgress(account: account, inventory: inventory, services: services,
                        runtime: runtime, retained: retained) == expected else { throw AdministrativeSetupError.staleProgress }
                return try machine.withSharedImportRelayDirectory { directory, owner in
                    try SharedSetupImportRelayStorage.validateTrackedFiles(records: journal.records(), directory: directory)
                    guard let plan = try SharedSetupImportRelayStorage.read(expected: retained, directory: directory, owner: owner),
                          plan == binding.plan,
                          try SharedSetupImportRelayStorage.snapshot(expected: retained, directory: directory, owner: owner) == binding.planSnapshot else {
                        throw AdministrativeSetupError.staleProgress
                    }
                    func verify() throws {
                        try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                        guard try currentInventory(machine) == binding.inventory,
                              try machine.serviceAccountPlan(accountID: account.accountID) == services,
                              try machine.runtimePreparation(accountID: account.accountID) == runtime,
                              try journal.current(scope: scope) == retained,
                              try SharedSetupImportRelayStorage.snapshot(expected: retained, directory: directory, owner: owner) == binding.planSnapshot else {
                            throw AdministrativeSetupError.staleProgress
                        }
                    }
                    try verify(); let result = try body(account, inventory, runtime, retained, plan, directory, owner, verify); try verify(); return result
                }
            }
        }
    }

    private func withImportedRelayInspection<Value: Sendable>(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                requiresPlan: Bool,
                                inspect: @escaping @Sendable (SetupCloudflareConfiguration, ImportedRelayInspectionBinding) async throws -> Value) async throws -> Value {
        let context = try lock.withLock {
            guard !closed, !closing, getpid() == processID else { throw AdministrativeSetupError.unavailable }
            let admission = try admitSetupMutation()
            do { return (admission, try releaseActivity?.acquireShared()) }
            catch { admission.close(); throw error }
        }
        defer { context.1?.close(); context.0.close() }
        func read() throws -> (SharedSetupImportIntent, InstallationInventory, SharedSetupImportRelayPlan?, SharedSetupImportRelayStorage.Snapshot?) {
            try withMachine(admission: context.0) { machine in
                guard expected.runtime.ownerUID == callerUID,
                      let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
                try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
                let runtime = try machine.runtimePreparation(accountID: account.accountID)
                let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
                return try machine.withSharedImportJournal { journal in
                    guard let journal, let retained = try journal.current(scope: scope) else { throw SharedSetupImportError.wrongScope }
                    let progress = try SetupPortableImportProgress(account: account, inventory: inventory,
                        services: services, runtime: runtime, retained: retained)
                    guard progress == expected else { throw AdministrativeSetupError.staleProgress }
                    guard try retained.matches(proposal) else { throw SharedSetupImportError.conflict }
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime,
                          try journal.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
                    var plan: SharedSetupImportRelayPlan?, snapshot: SharedSetupImportRelayStorage.Snapshot?
                    if requiresPlan {
                        try machine.withSharedImportRelayDirectory { directory, owner in
                            try SharedSetupImportRelayStorage.validateTrackedFiles(records: journal.records(), directory: directory)
                            guard let value = try SharedSetupImportRelayStorage.read(expected: retained, directory: directory, owner: owner),
                                  let identity = try SharedSetupImportRelayStorage.snapshot(expected: retained, directory: directory, owner: owner) else {
                                throw SharedSetupImportCompletionValidation.Failure.incomplete
                            }
                            plan = value; snapshot = identity
                        }
                    }
                    return (retained, inventory, plan, snapshot)
                }
            }
        }
        try Task.checkCancellation()
        let before = try read()
        guard let configuration = proposal.cloudflare else { throw SharedSetupImportCompletionValidation.Failure.incomplete }
        try Task.checkCancellation()
        let result = try await inspect(configuration, .init(retained: before.0, inventory: before.1, plan: before.2,
            planSnapshot: before.3, admission: context.0))
        try Task.checkCancellation(); try context.1?.validate()
        let after = try read()
        guard after.0 == before.0, after.1 == before.1, after.2 == before.2, after.3 == before.3 else {
            throw AdministrativeSetupError.staleProgress
        }
        try Task.checkCancellation()
        return result
    }

    /// Advances historical setup markers only after validating the retained local outputs.
    /// It creates no resource, repairs no file and makes no claim about a live provider connection.
    func completePortableImport(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                operations: SharedSetupImportCompletionValidation.Operations = .native) throws -> SetupPortableImportProgress {
        try withMachine { machine in
            guard expected.runtime.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            return try machine.withSharedImportJournal { journal in
                guard let journal, var retained = try journal.current(scope: scope) else { throw SharedSetupImportError.wrongScope }
                guard try SetupPortableImportProgress(account: account, inventory: inventory, services: services,
                    runtime: runtime, retained: retained) == expected else { throw AdministrativeSetupError.staleProgress }
                guard try retained.matches(proposal) else { throw SharedSetupImportError.conflict }
                guard [.gatewayPrepared, .relayPrepared, .rootComplete].contains(retained.phase) else {
                    throw SharedSetupImportCompletionValidation.Failure.incomplete
                }
                func verify() throws {
                    try Task.checkCancellation(); try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime,
                          try journal.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
                }
                func validate() throws {
                    try verify()
                    try SharedSetupImportCompletionValidation.validate(machine: machine, account: account, retained: retained,
                        proposal: proposal, operations: operations, verifyCurrent: verify)
                    try verify()
                }
                while retained.phase != .rootComplete {
                    try validate()
                    let next: SetupPortableImportProgress.Phase = retained.phase == .gatewayPrepared ? .relayPrepared : .rootComplete
                    retained = try journal.advance(retained, to: next)
                    try verify()
                }
                try validate()
                return try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
            }
        }
    }

    func verifiedPortableImportCompletion(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                                           operations: SharedSetupImportCompletionValidation.Operations = .native) throws -> SetupPortableImportProgress {
        try withMachine { machine in
            guard expected.runtime.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let inventory = try currentInventory(machine), services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            return try machine.withSharedImportJournal { journal in
                guard let journal, let retained = try journal.current(scope: scope), retained.phase == .rootComplete else {
                    throw SharedSetupImportCompletionValidation.Failure.incomplete
                }
                let current = try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
                guard current == expected else { throw AdministrativeSetupError.staleProgress }
                func verify() throws {
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime,
                          try journal.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
                }
                try verify()
                try SharedSetupImportCompletionValidation.validate(machine: machine, account: account, retained: retained,
                    proposal: proposal, operations: operations, verifyCurrent: verify)
                try verify(); return current
            }
        }
    }

    func portableImportProgress(callerUID: uid_t) throws -> SetupPortableImportProgress? {
        try withMachine { machine in
            let inventory = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let services = try machine.serviceAccountPlan(accountID: account.accountID)
            guard services.complete else { return nil }
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            return try machine.withSharedImportJournal { journal in
                let retained = try journal?.current(scope: scope)
                func verify() throws {
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory,
                          try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime,
                          try journal?.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
                }
                try verify()
                let result = try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
                try verify(); return result
            }
        }
    }
    /// Reads retained public metadata only. It creates no plan, credential or provider resource.
    func portableImportRecovery(callerUID: uid_t) throws -> SetupPortableImportRecovery? {
        try withMachine { machine in
            let inventory = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let services = try machine.serviceAccountPlan(accountID: account.accountID)
            guard services.complete else { return nil }
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            return try machine.withSharedImportJournal { journal in
                let retained = try journal?.current(scope: scope)
                func verify() throws {
                    try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                    guard try currentInventory(machine) == inventory, try machine.serviceAccountPlan(accountID: account.accountID) == services,
                          try machine.runtimePreparation(accountID: account.accountID) == runtime,
                          try journal?.current(scope: scope) == retained else { throw AdministrativeSetupError.staleProgress }
                }
                try verify()
                let progress = try SetupPortableImportProgress(account: account, inventory: inventory, services: services, runtime: runtime, retained: retained)
                guard let retained else {
                    let value = try SetupPortableImportRecovery(progress: progress, relayConfigured: false, relayScope: nil, records: [])
                    try verify(); return value
                }
                guard let journal else { throw SharedSetupImportError.wrongScope }
                return try machine.withSharedImportRelayDirectory { directory, owner in
                    try SharedSetupImportRelayStorage.validateTrackedFiles(records: journal.records(), directory: directory)
                    let snapshot = try SharedSetupImportRecoveryProjection.capture(expected: retained, directory: directory, owner: owner)
                    let value = try snapshot.recovery(progress: progress, retained: retained)
                    try verify(); try snapshot.requireCurrent(expected: retained, directory: directory, owner: owner)
                    try verify(); return value
                }
            }
        }
    }

    /// The endpoint must authenticate the invocation and administrator authorization before dispatch.
    /// One request performs one step; unresolved provider writes are never replayed here.
    func performPortableImportOperation(callerUID: uid_t, request: SetupPortableImportOperation) async throws -> SetupPortableImportOperationResult {
        let activity = try acquireReleaseActivity()
        defer { activity?.close() }
        func check() throws {
            try Task.checkCancellation(); try activity?.validate()
            guard callerUID == request.expected.runtime.ownerUID,
                  try portableImportProgress(callerUID: callerUID) == request.expected else { throw AdministrativeSetupError.staleProgress }
        }
        var status = SetupPortableImportOperationResult.Status.applied
        let proposal = request.proposal, expected = request.expected
        switch request.action {
        case .retain, .prepareRelayPlan, .prepareRuntime, .activateRuntime, .prepareGateway, .complete:
            try lock.withLock {
                try check()
                switch request.action {
                case .retain: _ = try retainPortableImport(callerUID: callerUID, expected: expected, proposal: proposal)
                case .prepareRelayPlan: _ = try prepareImportedRelayPlan(callerUID: callerUID, expected: expected, proposal: proposal)
                case .prepareRuntime:
                    _ = try resumeRuntime(callerUID: callerUID, expected: expected.runtime, fileCustodyAccepted: request.fileCustodyAccepted)
                case .activateRuntime:
                    guard let progress = try activationProgress(callerUID: callerUID) else { throw RuntimeActivationError.incomplete }
                    _ = try resumeActivation(callerUID: callerUID, expected: progress)
                case .prepareGateway:
                    _ = try prepareImportedGateway(callerUID: callerUID, expected: expected, proposal: proposal,
                        fileWakeCustodyAccepted: request.fileCustodyAccepted)
                case .complete: _ = try completePortableImport(callerUID: callerUID, expected: expected, proposal: proposal)
                default: throw AdministrativeSetupError.invalidConfiguration
                }
            }
        case .activateGateway:
            try check()
            let result = try await resumeImportedGateway(callerUID: callerUID, expected: expected, proposal: proposal)
            if !result.cleanupComplete { status = .waitingForCleanup }
            else { guard result.activation != nil else { throw GatewayPreparationError.incomplete } }
        case .createTunnel:
            let result = try await createImportedRelayTunnel(callerUID: callerUID, expected: expected, proposal: proposal)
            switch result.phase { case .created: break; case .rejected: status = .providerRejected; default: status = .requiresReconciliation }
        case .applyIngress: _ = try await applyImportedRelayIngress(callerUID: callerUID, expected: expected, proposal: proposal)
        case .prepareRunCredential:
            _ = try await prepareImportedRelayRunCredential(callerUID: callerUID, expected: expected, proposal: proposal,
                fileCustodyAccepted: request.fileCustodyAccepted)
        case .createAccess:
            let result = try await createImportedAccessApplication(callerUID: callerUID, expected: expected, proposal: proposal)
            switch result.phase { case .created: break; case .rejected: status = .providerRejected; default: status = .requiresReconciliation }
        case .createDNS:
            let result = try await createImportedDNSRecord(callerUID: callerUID, expected: expected, proposal: proposal)
            switch result.phase { case .created: break; case .rejected: status = .providerRejected; default: status = .requiresReconciliation }
        case .prepareRefusedTunnelRetry:
            guard let digest = request.expectedRejectedRecordDigest else { throw AdministrativeSetupChannelError.invalidMessage }
            try check(); _ = try await prepareRefusedImportedRelayTunnelRetry(callerUID: callerUID, expected: expected, proposal: proposal, expectedRecordDigest: digest)
        case .prepareRefusedAccessRetry:
            guard let digest = request.expectedRejectedRecordDigest else { throw AdministrativeSetupChannelError.invalidMessage }
            try check(); _ = try await prepareRefusedImportedAccessApplicationRetry(callerUID: callerUID, expected: expected, proposal: proposal, expectedRecordDigest: digest)
        case .prepareRefusedDNSRetry:
            guard let digest = request.expectedRejectedRecordDigest else { throw AdministrativeSetupChannelError.invalidMessage }
            try check(); _ = try await prepareRefusedImportedDNSRecordRetry(callerUID: callerUID, expected: expected, proposal: proposal, expectedRecordDigest: digest)
        case .publishConnector: _ = try await publishImportedRelayConnector(callerUID: callerUID, expected: expected, proposal: proposal)
        }
        try Task.checkCancellation(); try activity?.validate()
        guard let progress = try portableImportProgress(callerUID: callerUID) else { throw AdministrativeSetupError.staleProgress }
        return try .init(request: request, progress: progress, status: status)
    }

    // A future native endpoint must supply the authenticated UID and fresh administrator authorization.
    // Retention grants no credential custody, runtime publication or service activation.
    func retainPortableImport(callerUID: uid_t, expected: SetupPortableImportProgress, proposal: PortableSetup,
                              didStage: (SharedSetupImportPublication.Stage) throws -> Void = { _ in }) throws -> SetupPortableImportProgress {
        try withMachine { machine in
            guard expected.runtime.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            let inventory = try currentInventory(machine)
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let services = try machine.serviceAccountPlan(accountID: account.accountID)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            let scope = try SharedSetupImportIntent.Scope(account: account, inventory: inventory)
            func verifyDestination() throws {
                try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                guard try currentInventory(machine) == inventory,
                      try machine.serviceAccountPlan(accountID: account.accountID) == services,
                      try machine.runtimePreparation(accountID: account.accountID) == runtime else {
                    throw AdministrativeSetupError.staleProgress
                }
            }
            let existing: SharedSetupImportIntent? = try machine.withSharedImportJournal { journal in
                let retained = try journal?.current(scope: scope)
                let progress = try SetupPortableImportProgress(account: account, inventory: inventory,
                    services: services, runtime: runtime, retained: retained)
                guard progress == expected else { throw AdministrativeSetupError.staleProgress }
                try verifyDestination()
                guard let journal else { return nil }
                // Atomic first publication never exposes an empty journal. Do not repair an unexplained final directory.
                guard try !journal.records().isEmpty else { throw SharedSetupImportError.corruptRecord }
                return try SharedSetupImportRetention.retain(machine: machine, account: account, expectedRuntime: expected.runtime,
                    expectedImport: retained, proposal: proposal, journal: journal, verifyCurrent: verifyDestination)
            }
            let retained: SharedSetupImportIntent
            if let existing { retained = existing }
            else {
                guard expected.operationID == nil else { throw AdministrativeSetupError.staleProgress }
                func verifyUnconfigured() throws {
                    try verifyDestination()
                    try SharedSetupImportRetention.requireUnconfiguredDestination(machine: machine, account: account, runtime: runtime)
                }
                try verifyUnconfigured()
                let intent = try SharedSetupImportIntent(scope: scope, proposal: proposal)
                retained = try machine.publishSharedImport(intent, verifyCurrent: verifyUnconfigured, didStage: didStage)
            }
            try verifyDestination()
            let result = try SetupPortableImportProgress(account: account, inventory: inventory,
                services: services, runtime: runtime, retained: retained)
            try result.validateRetention(of: expected, proposalDigest: Data(SHA256.hash(data: try proposal.canonicalBytes())))
            return result
        }
    }

    func gatewaySettingsProgress(callerUID: uid_t) throws -> SetupGatewaySettingsProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let activation = try gatewayActivationProgress(machine: machine, account: account)
            guard activation.jobRegistered else { return nil }
            let value = try gatewaySettingsProgress(machine: machine, account: account)
            try verifyEnrollment(account, callerUID: callerUID, machine: machine); return value
        }
    }

    func retainGatewaySettings(callerUID: uid_t, expected: SetupGatewaySettingsProgress,
                               selection: GatewayRuntimeSettingsSelection) throws -> SetupGatewaySettingsProgress {
        try withMachine { machine in
            guard expected.activation.setup.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            guard expected.supportsSettingsChanges else { throw GatewayPreparationError.incomplete }
            guard try gatewaySettingsProgress(machine: machine, account: account) == expected,
                  try expected.pending == nil else { throw AdministrativeSetupError.staleProgress }
            let inventory = try currentInventory(machine)
            guard let activation = try machine.gatewayRuntimeActivation(accountID: account.accountID).plan,
                  let foreground = try machine.runtimeActivation(accountID: account.accountID).plan,
                  foreground.consumerHosts != nil else { throw GatewayPreparationError.incomplete }
            var id = UUID().uuid
            let revision = try GatewayRuntimeSettingsRevision(id: withUnsafeBytes(of: &id) { Data($0) },
                selection: selection, activation: activation, previous: expected.active,
                journal: machine.gatewayJournalPreparation(accountID: account.accountID),
                foreground: foreground, inventory: inventory)
            try machine.retainGatewaySettingsTransition(revision)
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            return try gatewaySettingsProgress(machine: machine, account: account)
        }
    }

    func resumeGatewaySettings(callerUID: uid_t, expected: SetupGatewaySettingsProgress) async throws -> SetupGatewaySettingsProgress {
        let context = try lock.withLock {
            guard !closed, !closing, getpid() == processID, expected.supportsSettingsChanges, let operation = gatewaySettingsOperation else {
                throw AdministrativeSetupError.unavailable
            }
            let admission = try admitSetupMutation()
            do { return (admission, try releaseActivity?.acquireShared(), operation) }
            catch { admission.close(); throw error }
        }
        defer { context.1?.close(); context.0.close() }
        let revision = try withMachine(admission: context.0) { machine in
            guard expected.activation.setup.ownerUID == callerUID,
                  let account = try machine.accountPreparation(ownerUID: callerUID) else {
                throw AdministrativeSetupError.wrongAccount
            }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            try SharedSetupImportGatewayScope.requireLegacyMutationAllowed(machine: machine, account: account)
            guard try gatewaySettingsProgress(machine: machine, account: account) == expected,
                  let revision = try expected.pending else { throw AdministrativeSetupError.staleProgress }
            return revision
        }
        try Task.checkCancellation()
        let report = try await context.2.resume(callerUID, expected.activation, revision, { [self] inventory in
            try lock.withLock {
                guard !closed, getpid() == processID else { throw AdministrativeSetupError.unavailable }
                try context.1?.validate(); try releaseActivity?.validate()
                guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
                    throw AdministrativeSetupError.changedInstallation
                }
                try verifyHost(inventory)
            }
        })
        try Task.checkCancellation(); try context.1?.validate()
        return try withMachine(admission: context.0) { machine in
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { throw AdministrativeSetupError.wrongAccount }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let value = try gatewaySettingsProgress(machine: machine, account: account)
            try value.validateCompletion(of: expected)
            guard try report.revisionDigest == revision.digest else { throw AdministrativeSetupError.staleProgress }
            return value
        }
    }

    private func gatewaySettingsProgress(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> SetupGatewaySettingsProgress {
        guard let plan = try machine.gatewayRuntimeActivation(accountID: account.accountID).plan,
              let foreground = try machine.runtimeActivation(accountID: account.accountID).plan else {
            throw GatewayPreparationError.incomplete
        }
        let initial = try GatewayRuntimeSettingsSelection(activation: plan,
            journal: machine.gatewayJournalPreparation(accountID: account.accountID),
            foreground: foreground, inventory: currentInventory(machine))
        return try .init(activation: gatewayActivationProgress(machine: machine, account: account),
            state: machine.gatewaySettingsTransition(accountID: account.accountID), initialSelection: initial,
            supportsSettingsChanges: foreground.consumerHosts != nil)
    }
    private func gatewayActivationProgress(machine: PreparationIntentStore, account: AccountPreparationIntent) throws -> SetupGatewayActivationProgress {
        try .init(setup: gatewayProgress(machine: machine, account: account), state: machine.gatewayRuntimeActivation(accountID: account.accountID))
    }
    func activationProgress(callerUID: uid_t) throws -> SetupActivationProgress? {
        try withMachine { machine in
            _ = try currentInventory(machine)
            guard let account = try machine.accountPreparation(ownerUID: callerUID) else { return nil }
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            let runtime = try machine.runtimePreparation(accountID: account.accountID)
            guard runtime.configurationPublished else { return nil }
            let result = try SetupActivationProgress(account: account, runtime: runtime,
                state: machine.runtimeActivation(accountID: account.accountID))
            try verifyEnrollment(account, callerUID: callerUID, machine: machine)
            return result
        }
    }
    func resumeActivation(callerUID: uid_t, expected: SetupActivationProgress) throws -> SetupActivationProgress {
        try lock.withLock {
            guard !closed, !closing, asynchronousWork.permits(nil) else { throw AdministrativeSetupError.unavailable }
            guard getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            let activity = try releaseActivity?.acquireShared()
            defer { activity?.close() }
            // Activity spans both writer scopes and native registration between them.
            // No native command runs within this first machine-writer scope.
            let context = try machines.useActivation { machine -> (AccountPreparationIntent, AuthorityInitializationIntent, RuntimeActivationPlan, SharedSetupImportIntent?) in
                guard expected.ownerUID == callerUID, let account = try machine.accountPreparation(ownerUID: callerUID) else {
                    throw AdministrativeSetupError.wrongAccount
                }
                try verifyEnrollment(account, callerUID: callerUID, machine: machine)
                let runtime = try machine.runtimePreparation(accountID: account.accountID)
                let state = try machine.runtimeActivation(accountID: account.accountID)
                guard try SetupActivationProgress(account: account, runtime: runtime, state: state) == expected,
                      let initial = try machine.initialization(accountID: account.accountID), initial.complete else {
                    throw AdministrativeSetupError.staleProgress
                }
                let inventory = try currentInventory(machine)
                let imported = try SharedSetupImportActivationScope.current(machine: machine, account: account)
                let relayPlan = try imported.flatMap { try machine.sharedImportRelayPlan(expected: $0) }
                let selectedRelease: SignedReleaseEvidence?
                if state.plan == nil, runtime.reference?.serviceActivity != nil {
                    guard let app = try account.initialAuthority.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
                        throw AdministrativeSetupError.changedInstallation
                    }
                    selectedRelease = try SignedReleaseInspection.inspect(URL(fileURLWithPath: inventory.bundlePath),
                        teamID: app.teamID, appIdentifier: app.identifier)
                } else { selectedRelease = nil }
                let plan = try state.plan ?? RuntimeActivationPlan(account: account, initialization: initial,
                    runtime: runtime, inventory: inventory, gatewaySettingsRelease: selectedRelease, importIntent: imported, relayPlan: relayPlan)
                try machine.retainRuntimeActivation(plan); try activationOperations.didStage(.intentRetained)
                func verify() throws {
                    _ = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: false, expectedImport: imported)
                }
                try verify()
                try activationOperations.prepare(plan, account, initial, inventory, verify)
                try activationOperations.didStage(.filesPublished); try verify()
                _ = try machine.enrollRuntimeActivation(plan)
                try activationOperations.didStage(.inventoryEnrolled)
                _ = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true, expectedImport: imported)
                return (account, initial, plan, imported)
            }
            let (account, initial, plan, imported) = context
            func verifyReady() throws {
                try machines.useActivation { machine in
                    let inventory = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true, expectedImport: imported)
                    try activationOperations.validate(plan, account, initial, inventory, {
                        _ = try self.verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true, expectedImport: imported)
                    })
                }
            }
            try verifyReady()
            for (index, job) in [plan.authorityJob, plan.transportJob].enumerated() {
                try activationOperations.register(job, verifyReady)
                try activationOperations.didStage(index == 0 ? .authorityRegistered : .transportRegistered)
                try verifyReady()
            }
            return try machines.useActivation { machine in
                _ = try verifyActivation(machine: machine, account: account, initialization: initial, plan: plan, callerUID: callerUID, enrolled: true, expectedImport: imported)
                try machine.markRuntimeJobsRegistered(plan); try activationOperations.didStage(.completed)
                let value = try SetupActivationProgress(account: account, runtime: machine.runtimePreparation(accountID: account.accountID),
                    state: machine.runtimeActivation(accountID: account.accountID))
                try value.validateCompletion(of: expected); return value
            }
        }
    }
    private func verifyActivation(machine: PreparationIntentStore, account: AccountPreparationIntent,
                                  initialization: AuthorityInitializationIntent, plan: RuntimeActivationPlan,
                                  callerUID: uid_t, enrolled: Bool, expectedImport: SharedSetupImportIntent?) throws -> InstallationInventory {
        try verifyEnrollment(account, callerUID: callerUID, machine: machine); try machine.validateAccountPreparation(account)
        let runtime = try machine.runtimePreparation(accountID: account.accountID)
        let services = try machine.serviceAccountPlan(accountID: account.accountID)
        guard services.complete, services.plan == plan.reference.services,
              runtime.configurationPublished, runtime.reference == plan.reference,
              try machine.initialization(accountID: account.accountID) == initialization,
              let retained = try machine.runtimeActivation(accountID: account.accountID).plan,
              try retained.encoded == plan.encoded else { throw RuntimeActivationError.changedScope }
        try plan.validate(account: account, reference: plan.reference)
        let inventory = try currentInventory(machine), desired = try plan.enrolledInventory(inventory)
        guard !enrolled || desired == inventory else { throw RuntimeActivationError.incomplete }
        try SharedSetupImportActivationScope.verify(machine: machine, account: account, initialization: initialization,
            plan: plan, inventory: inventory, expected: expectedImport)
        return inventory
    }
    private func verifyEnrollment(_ value: AccountPreparationIntent, callerUID: uid_t, machine: PreparationIntentStore) throws {
        guard value.ownerUID == callerUID else { throw AdministrativeSetupError.wrongAccount }
        let inventory = try currentInventory(machine)
        guard value.macID == inventory.macID, value.installationID == inventory.installationID,
              value.releaseDigest == inventory.releaseDigest,
              let accountCodePolicy, try value.initialAuthority.codePolicy.bytes == accountCodePolicy.bytes else {
            throw AdministrativeSetupError.changedInstallation
        }
        try LocalAccountDirectory.validateOwnership(lookupAccount(callerUID), uid: callerUID, directoryID: value.directoryID)
        try verifyAccountStartup(value.macID, value.accountID)
    }
    private static func initialAuthority(macID: Data, accountID: Data, codePolicy: AuthorityCodePolicy) throws -> AuthorityJournalInitialization {
        let limits = try CBORLimits(maxBytes: 16384, maxDepth: 8, maxItems: 512)
        let descriptor = try AuditEpochDescriptor.decode(DeterministicCBOR.encode(.map([
            0: .unsigned(1), 1: .bytes(macID), 2: .bytes(accountID), 3: .bytes(AccountPreparationIntent.randomID()),
            4: .unsigned(1), 5: .unsigned(AuditEpochCause.initial.rawValue), 6: .null, 7: .null, 8: .null]), limits: limits), limits: limits)
        let contract = try RequestContract(requestKind: .command, wireVersion: 1,
            schemaVersion: AuthorityCommandStartupConfiguration.captureSchemaVersion)
        return .init(descriptor: descriptor, codePolicy: codePolicy, capabilities: .init(contracts: [contract: []]),
            allowedContracts: [contract], installCommandReplay: true)
    }
    private func currentInventory(_ machine: PreparationIntentStore, checkedHost: AdministrativeSetupLifecycle.HostCheck? = nil) throws -> InstallationInventory {
        try releaseActivity?.validate()
        guard !closed, let inventory = try machine.inventory() else { throw AdministrativeSetupError.unavailable }
        if let checkedHost { try checkedHost.verifyInventory(inventory) }
        else { try verifyHost(inventory) }
        guard inventory.installationID == installationID, inventory.releaseDigest == expectedReleaseDigest else {
            throw AdministrativeSetupError.changedInstallation
        }
        return inventory
    }
    private func requireAccount(_ accountID: Data, callerUID: uid_t, machine: PreparationIntentStore) throws {
        guard accountID.count == 16, callerUID > 0, callerUID < UInt32.max,
              try currentInventory(machine).accounts.contains(where: { $0.accountID == accountID && $0.ownerUID == callerUID }) else {
            throw AdministrativeSetupError.wrongAccount
        }
        try verifyAccountStartup(currentInventory(machine).macID, accountID)
    }
}

/// Local app progress only. It carries no paths, release policy, credential or runtime health assertion.
public struct SetupAccountProgress: Equatable, Sendable {
    public let accountID: Data
    public let setupID: Data
    public let revision: Data
    public let checkpointCaptured: Bool
    public let complete: Bool
    init(_ value: AuthorityInitializationIntent) {
        accountID = value.accountID; setupID = value.setupID; revision = value.revision
        checkpointCaptured = value.checkpoint != nil; complete = value.complete
    }
    public var bytes: Data {
        get throws {
            try DeterministicCBOR.encode(.map([0: .unsigned(1), 1: .bytes(accountID), 2: .bytes(setupID), 3: .bytes(revision),
                4: .unsigned(checkpointCaptured ? 1 : 0), 5: .unsigned(complete ? 1 : 0)]), limits: Self.limits())
        }
    }
    public static func decode(_ bytes: Data) throws -> Self {
        guard case .map(let f) = try DeterministicCBOR.decode(bytes, limits: limits()), Set(f.keys) == [0, 1, 2, 3, 4, 5],
              f[0] == .unsigned(1), case .bytes(let account) = f[1], account.count == 16,
              case .bytes(let setup) = f[2], setup.count == 16, case .bytes(let revision) = f[3], revision.count == 16,
              case .unsigned(let captured) = f[4], captured <= 1, case .unsigned(let complete) = f[5], complete <= 1,
              complete == 0 || captured == 1 else { throw AdministrativeSetupError.invalidConfiguration }
        let value = Self(accountID: account, setupID: setup, revision: revision, checkpointCaptured: captured == 1, complete: complete == 1)
        guard try value.bytes == bytes else { throw AdministrativeSetupError.invalidConfiguration }; return value
    }
    private init(accountID: Data, setupID: Data, revision: Data, checkpointCaptured: Bool, complete: Bool) {
        self.accountID = accountID; self.setupID = setupID; self.revision = revision
        self.checkpointCaptured = checkpointCaptured; self.complete = complete
    }
    private static func limits() throws -> CBORLimits { try .init(maxBytes: 256, maxDepth: 2, maxItems: 16) }
}
