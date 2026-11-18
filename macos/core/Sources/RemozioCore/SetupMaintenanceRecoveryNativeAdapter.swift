import Darwin
import Foundation

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
        private struct PendingOwner: Sendable {
            let owner: any Sendable
            var cleanupFailed = false
        }
        private let lock = NSLock()
        private let closeWait: Duration
        private let closeBody: @Sendable () -> AdministrativeSetupShutdown.RecoveryCloseResult
        private let releaseBody: @Sendable () -> Void
        private var pendingOwners: [UUID: PendingOwner] = [:]
        private var closing: (id: UUID, task: Task<AdministrativeSetupShutdown.RecoveryCloseResult, Never>)?
        convenience init(owner: SetupAccountOwner, shutdown: AdministrativeSetupShutdown, ownedCloseWait: OwnedCloseWait? = nil) throws {
            try RuntimeMaintenanceOwnedControl.require()
            try self.init(owner: owner, shutdown: shutdown, closeWait: ownedCloseWait?.maximum ?? .seconds(5),
                closeBody: { (try? shutdown.closeAfterRecoveryJoinedOwned()) ?? .failed },
                releaseBody: { try? shutdown.releaseRecoverySupervisorOwned() })
        }
        fileprivate convenience init(nativeOwner: SetupAccountOwner, shutdown: AdministrativeSetupShutdown,
            closeBody: @escaping @Sendable () -> AdministrativeSetupShutdown.RecoveryCloseResult,
            releaseBody: @escaping @Sendable () -> Void) throws {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try self.init(owner: nativeOwner, shutdown: shutdown, closeWait: .seconds(5), closeBody: closeBody, releaseBody: releaseBody)
        }
        private init(owner: SetupAccountOwner, shutdown: AdministrativeSetupShutdown, closeWait: Duration,
            closeBody: @escaping @Sendable () -> AdministrativeSetupShutdown.RecoveryCloseResult,
            releaseBody: @escaping @Sendable () -> Void) throws {
            self.closeWait = closeWait; self.closeBody = closeBody; self.releaseBody = releaseBody
            guard shutdown.belongs(to: owner) else { throw RuntimePreparationError.changedScope }
            try shutdown.validateRecoveryCustody()
            try shutdown.reserveRecoverySupervisor()
            self.shutdown = shutdown
            shutdown.retainRecoverySupervisor(self)
        }
        func retain(_ owner: any Sendable, id: UUID) { lock.withLock { pendingOwners[id] = .init(owner: owner) } }
        func joined(_ id: UUID) { _ = lock.withLock { pendingOwners.removeValue(forKey: id) } }
        func cleanupFailed(_ id: UUID) { lock.withLock { pendingOwners[id]?.cleanupFailed = true } }
        func validate() throws { try shutdown.validateRecoveryCustody() }
        /// One fixed lease inspection, with no executor admission or retry wait.
        func validateForRecovery() async -> Bool {
            do { try validate(); return true } catch { return false }
        }
        func closeAdmission() { shutdown.closeRecoveryAdmission() }
        func closeAfterJoining() async { _ = await closeAfterJoiningResult() }
        func closeAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
            let held = lock.withLock { (pendingOwners.isEmpty, pendingOwners.values.contains { $0.cleanupFailed }) }
            if held.1 { return .failed }
            guard held.0 else { return .pending }
            // Admission is already closed. Final shutdown runs here only after every join and keeps its actual task.
            // It cannot use the work executor without taking admission from the closing owner.
            let attempt = lock.withLock {
                if let closing { return closing }
                let closeBody = self.closeBody, id = UUID()
                // Final close may overlap a cancelled startup host check. A live recovery scope makes owner.close refuse;
                // after closure, the host check observes an invalid lease. Neither path can reopen dispatch.
                let task = Task { closeBody() }
                let attempt = (id: id, task: task); closing = attempt; return attempt
            }
            let result = await Self.boundedClose(attempt.task, until: .now.advanced(by: closeWait))
            if result != .timedOut {
                lock.withLock { if closing?.id == attempt.id { closing = nil } }
            }
            return result
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
        func closeAdmission() { custody.closeAdmission() }
        func closeAfterJoining() async { await custody.closeAfterJoining() }
        func closeAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
            await custody.closeAfterJoiningResult()
        }
        func releaseAfterJoining() { custody.releaseAfterJoining() }
    }
    static func supervisor(owner: SetupAccountOwner, shutdown: AdministrativeSetupShutdown,
        closeAfterJoining: @escaping @Sendable () -> AdministrativeSetupShutdown.RecoveryCloseResult,
        releaseAfterJoining: @escaping @Sendable () -> Void) throws -> Supervisor {
        let retained = try Custody(nativeOwner: owner, shutdown: shutdown,
            closeBody: closeAfterJoining, releaseBody: releaseAfterJoining), work = WorkCustody(retained)
        return try Supervisor(nativeWork: work, finalClose: FinalClose(retained),
            driver: makeDriver(owner: owner, custody: work, owned: nil),
            publish: { request, observation in owner.publishMaintenanceRecovery(request: request, observation: observation) })
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
                    let acquisition: Supervisor.Acquisition = try await phases.acquire {
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
    private final class NativeOwner: @unchecked Sendable {
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
