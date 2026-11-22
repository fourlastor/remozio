import Darwin
import Foundation

/// A retained owner can retry cleanup without acquiring a new scope or running again.
protocol SetupMaintenanceRecoveryOwnerCleanup: Sendable {
    func join() async
}

/// Fixed native construction only. It adds no startup caller and never replays an acquired owner.
enum SetupMaintenanceRecoveryNativeAdapter {
    typealias Supervisor = SetupMaintenanceRecoverySupervisor
    private enum OpeningDeadline: Error { case expired }
    struct OwnedCloseWait: Sendable {
        let maximum: Duration
        init(shorteningTo maximum: Duration) throws {
            try RuntimeMaintenanceOwnedControl.require()
            guard maximum > .zero, maximum <= .seconds(5) else { throw AdministrativeSetupError.invalidConfiguration }
            self.maximum = maximum
        }
    }

    final class Custody: SetupMaintenanceRecoveryProcessCustody, CustomReflectable, @unchecked Sendable {
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        let shutdown: AdministrativeSetupShutdown
        private typealias CloseResult = AdministrativeSetupShutdown.RecoveryCloseResult
        private struct PendingOwner: Sendable {
            let owner: any Sendable
            var retryAfter: ContinuousClock.Instant?
            var retryDelay: Duration = .seconds(1)
        }
        private typealias CloseAttempt = (id: UUID, task: Task<CloseResult, Never>)
        private enum CloseStart {
            case result(CloseResult)
            case attempt(CloseAttempt)
        }

        private let lock = NSLock()
        private let closeWait: Duration
        private let retryNow: @Sendable () -> ContinuousClock.Instant
        private let closeBody: @Sendable () -> AdministrativeSetupShutdown.RecoveryCloseResult
        private let releaseBody: @Sendable () -> Void
        private var pendingOwners: [UUID: PendingOwner] = [:]
        private var closing: CloseAttempt?
        convenience init(owner: SetupAccountOwner, shutdown: AdministrativeSetupShutdown, ownedCloseWait: OwnedCloseWait? = nil,
                         ownedRetryNow: @escaping @Sendable () -> ContinuousClock.Instant = { .now }) throws {
            try RuntimeMaintenanceOwnedControl.require()
            try self.init(owner: owner, shutdown: shutdown, closeWait: ownedCloseWait?.maximum ?? .seconds(5),
                retryNow: ownedRetryNow, expectsPublication: false,
                closeBody: { (try? shutdown.closeAfterRecoveryJoinedOwned()) ?? .failed },
                releaseBody: { try? shutdown.releaseRecoverySupervisorOwned() })
        }
        fileprivate convenience init(nativeOwner: SetupAccountOwner, shutdown: AdministrativeSetupShutdown,
            closeBody: @escaping @Sendable () -> AdministrativeSetupShutdown.RecoveryCloseResult,
            releaseBody: @escaping @Sendable () -> Void) throws {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try self.init(owner: nativeOwner, shutdown: shutdown, closeWait: .seconds(5), retryNow: { .now },
                expectsPublication: true, closeBody: closeBody, releaseBody: releaseBody)
        }
        private init(owner: SetupAccountOwner, shutdown: AdministrativeSetupShutdown, closeWait: Duration,
            retryNow: @escaping @Sendable () -> ContinuousClock.Instant, expectsPublication: Bool,
            closeBody: @escaping @Sendable () -> AdministrativeSetupShutdown.RecoveryCloseResult,
            releaseBody: @escaping @Sendable () -> Void) throws {
            self.closeWait = closeWait; self.retryNow = retryNow; self.closeBody = closeBody; self.releaseBody = releaseBody
            guard shutdown.belongs(to: owner) else { throw RuntimePreparationError.changedScope }
            try shutdown.validateRecoveryCustody()
            try shutdown.reserveRecoverySupervisor(expectsPublication: expectsPublication)
            self.shutdown = shutdown
            shutdown.retainRecoverySupervisor(self)
        }
        func retain(_ owner: any Sendable, id: UUID) { lock.withLock { pendingOwners[id] = .init(owner: owner) } }
        func joined(_ id: UUID) { _ = lock.withLock { pendingOwners.removeValue(forKey: id) } }
        func cleanupFailed(_ id: UUID) {
            lock.withLock {
                guard var pending = pendingOwners[id] else { return }
                pending.retryAfter = retryNow().advanced(by: pending.retryDelay)
                pending.retryDelay = min(pending.retryDelay * 2, .seconds(30))
                pendingOwners[id] = pending
            }
        }
        func validate() throws { try shutdown.validateRecoveryCustody() }
        /// One fixed lease inspection, with no executor admission or retry wait.
        func validateForRecovery() async -> Bool {
            do { try validate(); return true } catch { return false }
        }
        func bindSupervisor(_ actual: Supervisor) { shutdown.bindRecoverySupervisor(actual) }
        func joinRecoverySessions() async { await shutdown.joinRecoverySessions() }
        func observeRecoverySessionsForDisposal() async { await shutdown.observeRecoverySessionsForDisposal() }
        func retainSupervisorDisposal(_ actual: Task<Void, Never>) { shutdown.retainRecoverySupervisorDisposal(actual) }
        func closeAdmission() { shutdown.closeRecoveryAdmission() }
        func closeAfterJoining() async { _ = await closeAfterJoiningResult() }
        func closeAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
            await closeAfterJoining(retryCleanup: false)
        }
        func retryCloseAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
            await closeAfterJoining(retryCleanup: true)
        }
        private func closeAfterJoining(retryCleanup: Bool) async -> CloseResult {
            await shutdown.joinRecoverySessions()
            switch beginClose(retryCleanup: retryCleanup) {
            case .result(let result):
                return result
            case .attempt(let attempt):
                let result = await Self.boundedClose(attempt.task, until: .now.advanced(by: closeWait))
                if result != .timedOut {
                    lock.withLock { if closing?.id == attempt.id { closing = nil } }
                }
                return result
            }
        }
        private func beginClose(retryCleanup: Bool) -> CloseStart {
            lock.withLock {
                if let closing { return .attempt(closing) }
                let retryOwners: [any SetupMaintenanceRecoveryOwnerCleanup]
                if retryCleanup, !pendingOwners.isEmpty {
                    let now = retryNow()
                    retryOwners = pendingOwners.values.compactMap { pending in
                        guard let retryAfter = pending.retryAfter, now >= retryAfter else { return nil }
                        return pending.owner as? any SetupMaintenanceRecoveryOwnerCleanup
                    }
                } else {
                    retryOwners = []
                }
                if retryOwners.isEmpty, let result = pendingCloseResult() { return .result(result) }

                // The original owner retries cleanup through its held scope. Final close waits for every actual join.
                let task = Task {
                    for owner in retryOwners { await owner.join() }
                    if let result = self.lock.withLock({ self.pendingCloseResult() }) { return result }
                    return self.closeBody()
                }
                let attempt = (id: UUID(), task: task)
                closing = attempt
                return .attempt(attempt)
            }
        }
        /// The caller holds the custody lock.
        private func pendingCloseResult() -> CloseResult? {
            guard !pendingOwners.isEmpty else { return nil }
            return pendingOwners.values.contains { $0.retryAfter != nil } ? .failed : .pending
        }
        func closeAttemptIDOwned() throws -> UUID? {
            try RuntimeMaintenanceOwnedControl.require(); return lock.withLock { closing?.id }
        }
        /// A cancelled caller returns timedOut immediately. Neither cancellation nor timeout cancels the actual close.
        /// The result never proves resource release. Only the retained task can close the leases.
        static func boundedClose(_ actual: Task<AdministrativeSetupShutdown.RecoveryCloseResult, Never>,
            until deadline: ContinuousClock.Instant) async -> AdministrativeSetupShutdown.RecoveryCloseResult {
            let signal = AsyncStream<AdministrativeSetupShutdown.RecoveryCloseResult>.makeStream()
            let returned = Task { signal.continuation.yield(await actual.value); signal.continuation.finish() }
            let timer = Task {
                do { try await ContinuousClock().sleep(until: deadline) }
                catch { return }
                signal.continuation.yield(.timedOut); signal.continuation.finish()
            }
            defer { timer.cancel(); returned.cancel() }
            for await result in signal.stream { return result }
            return .timedOut
        }
        func releaseAfterJoining() {
            guard lock.withLock({ pendingOwners.isEmpty && closing == nil }) else { return }
            releaseBody()
        }
    }

    struct OwnedAcquisitionControl: Sendable {
        let beforeMint: @Sendable (SetupAccountOwner.MaintenanceRecoveryScope) -> Void
        let observe: @Sendable (Supervisor.Request) throws -> Supervisor.Observation
        init(beforeMint: @escaping @Sendable (SetupAccountOwner.MaintenanceRecoveryScope) -> Void = { _ in },
            observe: @escaping @Sendable (Supervisor.Request) throws -> Supervisor.Observation) throws {
            try RuntimeMaintenanceOwnedControl.require()
            self.beforeMint = beforeMint; self.observe = observe
        }
    }
    private final class WorkCustody: SetupMaintenanceRecoveryWorkCustody, CustomReflectable, @unchecked Sendable {
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        private let custody: Custody
        init(_ custody: Custody) { self.custody = custody }
        func validate() throws { try custody.validate() }
        func validateForRecovery() async -> Bool { await custody.validateForRecovery() }
        func acquireScope(owner: SetupAccountOwner) throws -> SetupAccountOwner.MaintenanceRecoveryScope {
            try owner.acquireMaintenanceRecoveryScope(custody: custody.shutdown)
        }
        func retain(_ owner: any Sendable, id: UUID) { custody.retain(owner, id: id) }
        func joined(_ id: UUID) { custody.joined(id) }
        func cleanupFailed(_ id: UUID) { custody.cleanupFailed(id) }
    }
    private final class FinalClose: SetupMaintenanceRecoveryFinalClose, CustomReflectable, @unchecked Sendable {
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        private let custody: Custody
        init(_ custody: Custody) { self.custody = custody }
        func joinRecoverySessions() async { await custody.joinRecoverySessions() }
        func observeRecoverySessionsForDisposal() async { await custody.observeRecoverySessionsForDisposal() }
        func retainSupervisorDisposal(_ actual: Task<Void, Never>) { custody.retainSupervisorDisposal(actual) }
        func closeAdmission() { custody.closeAdmission() }
        func closeAfterJoining() async { await custody.closeAfterJoining() }
        func closeAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
            await custody.closeAfterJoiningResult()
        }
        func retryCloseAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
            await custody.retryCloseAfterJoiningResult()
        }
        func releaseAfterJoining() { custody.releaseAfterJoining() }
    }
    static func supervisor(owner: SetupAccountOwner, shutdown: AdministrativeSetupShutdown,
        closeAfterJoining: @escaping @Sendable () -> AdministrativeSetupShutdown.RecoveryCloseResult,
        releaseAfterJoining: @escaping @Sendable () -> Void) throws -> Supervisor {
        let retained = try Custody(nativeOwner: owner, shutdown: shutdown,
            closeBody: closeAfterJoining, releaseBody: releaseAfterJoining), work = WorkCustody(retained)
        let actual = try Supervisor(nativeWork: work, finalClose: FinalClose(retained),
            driver: makeDriver(owner: owner, custody: work, owned: nil),
            publish: { request, observation in owner.publishMaintenanceRecovery(request: request, observation: observation) })
        retained.bindSupervisor(actual)
        return actual
    }
    static func driver(owner: SetupAccountOwner, custody: Custody) -> Supervisor.Driver {
        let driver = makeDriver(owner: owner, custody: WorkCustody(custody), owned: nil)
        return .init(acquire: { request, deadline in
            try RuntimeMaintenanceOwnedControl.require()
            return try await driver.acquire(request, deadline)
        })
    }
    static func driverOwned(owner: SetupAccountOwner, custody: Custody,
        control: OwnedAcquisitionControl) throws -> Supervisor.Driver {
        try RuntimeMaintenanceOwnedControl.require()
        return makeDriver(owner: owner, custody: WorkCustody(custody), owned: control)
    }
    private static func makeDriver(owner: SetupAccountOwner, custody: WorkCustody,
        owned: OwnedAcquisitionControl?) -> Supervisor.Driver {
        .init(acquire: { request, deadline in
            do {
                if owned != nil { try RuntimeMaintenanceOwnedControl.require() }
                try custody.validate()
                let scope = try custody.acquireScope(owner: owner)
                let cancellation = SetupAuditUpgradeCancellation()
                do {
                    owned?.beforeMint(scope)
                    let phases = try owner.maintenanceRecoveryPhases(scope: scope, until: deadline, cancellation: cancellation,
                        validate: { try custody.validate() })
                    let acquisition: Supervisor.Acquisition = try await phases.acquire { [custody] in
                        guard ContinuousClock.now < deadline else { throw OpeningDeadline.expired }
                        if let owned { return .terminal(try owned.observe(request)) }
                        switch try RuntimeMaintenanceStartupRecovery.openForSupervisor(accountID: request.key.accountID,
                            phases: phases, cancellation: cancellation, validate: { try custody.validate() }) {
                        case .terminal(let row):
                            if let row { owner.publishMaintenanceRecovery(row) }
                            return .terminal(terminalObservation(row, request: request))
                        case .owner(let recovery):
                            let row = recovery.window
                            guard row.id == request.key.windowID, row.revision == request.revision,
                                  row.scope.authority.accountID == request.key.accountID else {
                                recovery.closeNativeCustody(); return .terminal(.failed(.changedScope))
                            }
                            let id = UUID()
                            let held = NativeOwner(recovery: recovery, scope: scope, phases: phases, cancellation: cancellation,
                                joined: { [weak custody] in custody?.joined(id) },
                                failed: { [weak custody] in custody?.cleanupFailed(id) },
                                publish: { owner.publishMaintenanceRecovery($0) })
                            custody.retain(held, id: id)
                            return .owner(.init(run: { try await held.run(until: $0) },
                                cancel: { held.cancel() }, join: { await held.join() }))
                        }
                    }
                    // The actual acquisition body has returned before its admission can become available.
                    if case .terminal = acquisition { scope.close() }
                    return acquisition
                } catch { scope.close(); throw error }
            } catch is SetupAuditUpgradeWorkExecutor.BusyBeforeBody { return .busyBeforeOwner }
              catch SetupAccountOwner.MaintenanceRecoveryAdmissionError.busyBeforeOwner { return .busyBeforeOwner }
              catch ReleaseActivityError.busy { return .busyBeforeOwner }
              catch JournalLeaseError.busy { return .busyBeforeOwner }
              catch UpdateAdmissionBarrierError.busy { return .busyBeforeOwner }
              catch OpeningDeadline.expired { return .busyBeforeOwner }
              catch RuntimeMaintenanceStartupAttemptError.deadlineExpired { return .busyBeforeOwner }
        })
    }
    /// Terminal metadata grants no rights. Any terminal phase for the same account and window can have a later revision.
    static func terminalObservation(_ row: RuntimeMaintenanceWindowRecord?, request: Supervisor.Request) -> Supervisor.Observation {
        guard let row else { return .noWindow }
        guard row.id == request.key.windowID, row.scope.authority.accountID == request.key.accountID else {
            return .failed(.changedScope)
        }
        return .phase(row.phase)
    }
    private final class NativeOwner: SetupMaintenanceRecoveryOwnerCleanup, @unchecked Sendable {
        private let lock = NSLock()
        private let recovery: RuntimeMaintenanceStartupRecovery
        private let scope: SetupAccountOwner.MaintenanceRecoveryScope
        private let phases: SetupRetainedInvocationReservation.RestorationPhases
        private let cancellation: SetupAuditUpgradeCancellation
        private let didJoin: @Sendable () -> Void
        private let didFailCleanup: @Sendable () -> Void
        private let publish: @Sendable (RuntimeMaintenanceWindowRecord) -> Void
        private var task: Task<RuntimeMaintenanceWindowRecord, any Error>?
        private var cancelled = false, started = false, joined = false
        init(recovery: RuntimeMaintenanceStartupRecovery, scope: SetupAccountOwner.MaintenanceRecoveryScope,
            phases: SetupRetainedInvocationReservation.RestorationPhases, cancellation: SetupAuditUpgradeCancellation,
            joined: @escaping @Sendable () -> Void, failed: @escaping @Sendable () -> Void,
            publish: @escaping @Sendable (RuntimeMaintenanceWindowRecord) -> Void) {
            self.recovery = recovery; self.scope = scope; self.phases = phases; self.cancellation = cancellation; didJoin = joined; didFailCleanup = failed; self.publish = publish
        }
        func run(until deadline: ContinuousClock.Instant) async throws -> Supervisor.Observation {
            let actual = try lock.withLock {
                guard !started, !joined, !cancelled else { throw CancellationError() }
                started = true
                let recovery = self.recovery
                // Created on the async caller, never inside the blocking executor body.
                let actual = Task { try await recovery.runNative(until: deadline) }
                task = actual; return actual
            }
            let row = try await actual.value
            publish(row)
            return .phase(row.phase)
        }
        /// Marks cancellation only. It never closes resources or waits for an executor body.
        func cancel() {
            let actual = lock.withLock { cancelled = true; return task }
            cancellation.cancel(); actual?.cancel()
        }
        func join() async {
            if let actual = lock.withLock({ task }) { _ = await actual.result }
            // The executor returns only after the real thread exits. Cleanup retains both admissions until then.
            do {
                try await phases.closeActual { self.recovery.closeNativeCustody() }
                scope.close()
                lock.withLock { joined = true; task = nil }
                didJoin()
            } catch {
                // Keep every resource, but surface a typed failure rather than permanent pending.
                didFailCleanup()
            }
        }
    }
}
