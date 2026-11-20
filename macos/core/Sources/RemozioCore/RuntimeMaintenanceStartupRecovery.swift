import Darwin
import Foundation

enum RuntimeMaintenanceStartupAttemptError: Error, Equatable { case beforePending, deadlineExpired }

struct RuntimeMaintenanceStartupFailure: Error {
    let failure: RuntimeMaintenanceWindowRecord.Failure
    let underlying: Error
    init(_ failure: RuntimeMaintenanceWindowRecord.Failure, _ underlying: Error) {
        self.failure = failure; self.underlying = underlying
    }
}

/// Owns new startup custody. A retained row selects work but never constructs a stop owner or an exit witness.
final class RuntimeMaintenanceStartupRecovery: @unchecked Sendable {
    typealias Record = RuntimeMaintenanceWindowRecord
    typealias Transition = PreparationIntentStore.RuntimeMaintenanceTransition
    typealias Frame = RuntimeMaintenanceStartupFrame
    enum Result: Sendable {
        case nothing, ownerRecovery(Record), probeRequired
        case cancelAndReopen(Custody)
        case restoration(PreparedRestoration)
    }
    /// A completion is issued by the actual explicit runner after the restored writer and protected readback.
    /// Its reader owns no live restoration custody after the registered task returns.
    final class ExplicitCompletion: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        let window: Record, workID: UUID
        let originalRunFailed: Bool
        private let floor: RuntimeMaintenanceStartupFloor, release: SignedReleaseEvidence
        private let read: @Sendable () throws -> Frame, verifySetup: @Sendable () throws -> Void
        private let native: Bool, processID = getpid()
        fileprivate init(window: Record, workID: UUID, custody: Custody, originalRunFailed: Bool) throws {
            guard window.phase == .restored, custody.current == window,
                  window.gate?.hold == .released, window.gate?.admission == .available else {
                throw RuntimePreparationError.changedScope
            }
            try custody.requireExplicitCompletion(window)
            self.window = window; self.workID = workID; self.originalRunFailed = originalRunFailed
            floor = custody.floor; release = custody.release
            read = custody.completionReader; verifySetup = custody.completionVerifier; native = custody.native
        }
        func requireNative(processLease: SetupProcessLease) throws {
            guard native, getpid() == processID, getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try requireCurrent(processLease: processLease)
        }
        func requireOwned(processLease: SetupProcessLease) throws {
            try RuntimeMaintenanceOwnedControl.require()
            guard !native, getpid() == processID else { throw JournalLeaseError.unsafeMetadata }
            try requireCurrent(processLease: processLease)
        }
        private func requireCurrent(processLease: SetupProcessLease) throws {
            try processLease.validate(); try verifySetup()
            let first = try read(); try floor.requireCurrent(first, window: window, release: release)
            let second = try read(); try floor.requireCurrent(second, window: window, release: release)
            try second.source.actual.requireSame(as: first.source.actual)
            try verifySetup(); try processLease.validate()
        }
        var description: String { "RuntimeMaintenanceExplicitCompletion(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
    }
    /// Only the real restart runners can construct this attempt or record its custody and writer state.
    final class RestartAttempt: @unchecked Sendable {
        private typealias Body = @Sendable (RestartAttempt, UUID) async throws -> ExplicitCompletion
        private let lock = NSLock(), processID = getpid(), ownerUID = getuid()
        private var body: Body?
        private var custodyOpened = false, custodyClosed = true, uncertainWriter = false, forwardEffects = false, rowAtRest = true
        private weak var statusRecord: SetupRestartRecovery?
        func attachStatus(to record: SetupRestartRecovery) { lock.withLock { statusRecord = record } }
        var statusFacts: (opened: Bool, closed: Bool, uncertain: Bool) {
            lock.withLock { (custodyOpened, custodyClosed, uncertainWriter) }
        }
        fileprivate init(_ body: @escaping @Sendable (RestartAttempt, UUID) async throws -> ExplicitCompletion) { self.body = body }
        func run(workID: UUID) async throws -> ExplicitCompletion {
            guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
            let current = try lock.withLock {
                guard let body else { throw JournalLeaseError.invalidated }
                self.body = nil; return body
            }
            return try await current(self, workID)
        }
        fileprivate func beginCustody() {
            let record = lock.withLock { custodyClosed = false; return statusRecord }
            record?.observeStatus(self)
        }
        fileprivate func didOpenCustody() {
            let record = lock.withLock { custodyOpened = true; return statusRecord }
            record?.observeStatus(self)
        }
        fileprivate func didCloseCustody(uncertain: Bool) {
            let record = lock.withLock { custodyClosed = true; uncertainWriter = uncertainWriter || uncertain; return statusRecord }
            record?.observeStatus(self)
        }
        fileprivate func willUseForwardEffects() { lock.withLock { forwardEffects = true } }
        fileprivate func confirmedRow(_ row: Record) {
            let record = lock.withLock { rowAtRest = row.phase == .needsOwnerRecovery || row.phase == .restored; return statusRecord }
            record?.observeStatus(self, row: row)
        }
        var hasUncertainWriter: Bool { lock.withLock { uncertainWriter } }
        var hasRestingRow: Bool { lock.withLock { rowAtRest } }
        func permitsRelease(allowForwardEffects: Bool) -> Bool {
            lock.withLock { custodyClosed && !uncertainWriter && rowAtRest && (allowForwardEffects || !forwardEffects) }
        }
    }
    /// Origins share the restoration flow. Restart never constructs in-process join evidence.
    private final class ExplicitAuthority: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        var description: String { "RuntimeMaintenanceExplicitAuthority(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        private enum Origin { case inProcess(SetupRetainedOrphanClaim.Joined), restart(SetupRestartRecovery.Claim, RestartAttempt) }
        private let origin: Origin
        private let allowUnbound: Bool
        let processLease: SetupProcessLease
        let phases: SetupRetainedInvocationReservation.RestorationPhases
        private let lock = NSLock()
        private var captured: SetupRetainedInvocationStatus.Window?
        init(joined: SetupRetainedOrphanClaim.Joined, processLease: SetupProcessLease, native: Bool,
            phases: SetupRetainedInvocationReservation.RestorationPhases, allowUnbound: Bool = false) throws {
            if native { guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired } }
            else { try RuntimeMaintenanceOwnedControl.require() }
            origin = .inProcess(joined); self.processLease = processLease; self.phases = phases
            self.allowUnbound = allowUnbound
            try requireCurrent()
        }
        init(restart: SetupRestartRecovery.Claim, attempt: RestartAttempt, native: Bool,
            phases: SetupRetainedInvocationReservation.RestorationPhases) throws {
            if native { guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired } }
            else { try RuntimeMaintenanceOwnedControl.require() }
            origin = .restart(restart, attempt); processLease = restart.processLease; self.phases = phases
            allowUnbound = false
            try requireCurrent()
        }
        func requireCurrent() throws {
            try processLease.validate()
            switch origin {
            case .inProcess(let joined): try joined.requireCurrentAuthorization()
            case .restart(let claim, _): try claim.requireCurrentAuthorization()
            }
        }
        var restartAttempt: RestartAttempt? {
            if case .restart(_, let attempt) = origin { return attempt }; return nil
        }
        var unboundJoined: SetupRetainedOrphanClaim.Joined? {
            if allowUnbound, case .inProcess(let joined) = origin { return joined }; return nil
        }
        func willUseForwardEffects() throws {
            if case .restart(_, let attempt) = origin { attempt.willUseForwardEffects() }
        }
        func requireSavedTargetReconnect(_ row: Record) throws {
            switch origin {
            case .inProcess(let joined): try joined.requireSavedTargetReconnect(row)
            // A restart has no retained writer receipt proving the previous draining row.
            case .restart: throw RuntimePreparationError.changedScope
            }
        }
        func capture(_ row: Record) throws {
            try requireCurrent()
            switch origin {
            case .inProcess(let joined): try joined.requireRestorationWindow(row)
            case .restart(let claim, _): try claim.capture(row)
            }
            if let joined = unboundJoined {
                if row.unboundRelease == nil { _ = try joined.requireUnboundAuthorizedOrigin(row) }
                else { try joined.requireUnboundIntentReconciliation(row) }
            } else {
                guard row.phase == .needsOwnerRecovery, row.shutdownBinding != nil, row.purpose == .retainedRuntime,
                      let failure = row.failure, failure != .repairRequired else {
                    throw RuntimeMaintenanceStartupFailure(.repairRequired, RuntimePreparationError.changedScope)
                }
            }
            try lock.withLock {
                guard captured == nil else { throw JournalLeaseError.invalidated }
                captured = .init(row)
            }
        }
        func requireWindow(_ row: Record) throws {
            try requireCurrent()
            switch origin {
            case .inProcess(let joined): try joined.requireRestorationWindow(row)
            case .restart(let claim, _): try claim.requireRestorationWindow(row)
            }
            try lock.withLock {
                guard captured?.identifies(row) == true else { throw RuntimePreparationError.changedScope }
            }
        }
    }
    fileprivate struct OwnedUnboundWriters: Sendable {
        let intent: @Sendable (Record, SetupRetainedOrphanClaim.Joined, Frame) throws -> Transition
        let completion: @Sendable (Record, SetupRetainedOrphanClaim.Joined, VerifiedUnboundGateObservation, Frame) throws -> Transition
    }
    /// Only the explicit dispatcher can issue this capability after committing its exact restoring row.
    final class ExplicitReconnect: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        var description: String { "RuntimeMaintenanceExplicitReconnect(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: EmptyCollection<Mirror.Child>()) }
        let custody: Custody
        let phases: SetupRetainedInvocationReservation.RestorationPhases
        private let window: Record, origin: Record
        var beforePendingFailure: Record.Failure { origin.failure ?? .cleanupPending }
        private let lock = NSLock(), processID = getpid()
        private var used = false
        fileprivate init(custody: Custody, window: Record, origin: Record,
            phases: SetupRetainedInvocationReservation.RestorationPhases) throws {
            guard origin.phase == .needsOwnerRecovery, origin.service == .notStopped,
                  origin.operation == .notStarted else { throw PreparationStoreError.invalidTransition }
            try window.requireReplacing(origin)
            self.custody = custody; self.window = window; self.origin = origin; self.phases = phases
        }
        func consume() throws -> Record {
            guard getpid() == processID else { throw JournalLeaseError.invalidated }
            try lock.withLock { guard !used else { throw JournalLeaseError.invalidated }; used = true }
            guard window.phase == .restoring, window.service == .restartPending, window.operation == .notStarted else {
                throw PreparationStoreError.invalidTransition
            }
            try custody.requireCleanup(window); return window
        }
    }
    final class Custody: @unchecked Sendable {
        let floor: RuntimeMaintenanceStartupFloor
        let admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken, directory: ReleaseDestinationLease
        let native: Bool
        let verifyConfiguration: @Sendable () throws -> Void
        private let verifyCaller: @Sendable () throws -> Void
        private let restartAttempt: RestartAttempt?
        private let cancellation: SetupAuditUpgradeCancellation?
        let inspect: @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation
        let observe: @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness
        private let read: @Sendable () throws -> Frame
        private let verifySetupIdentity: @Sendable () throws -> Void
        private var restoredTransition: Transition?, restoredOwned: Record?
        private let writeNative: (@Sendable (Record, Record, Frame) throws -> Transition)?
        private let writeOwned: (@Sendable (Record, Record) throws -> Record)?
        fileprivate let release: SignedReleaseEvidence
        private let lock = NSRecursiveLock(), processID = getpid(), ownerUID = getuid()
        private var row: Record, invalidated = false, registrationUsed = false, recoveryUsed = false
        private var writerUncertain = false
        private let nativeUnboundFiles: NativeFiles?
        private let ownedUnboundWriters: OwnedUnboundWriters?
        private let unboundJoined: SetupRetainedOrphanClaim.Joined?
        private var unboundDrainReleased = false
        fileprivate var hasUncertainWriter: Bool { lock.withLock { writerUncertain } }
        fileprivate init(floor: RuntimeMaintenanceStartupFloor, row: Record, admission: UpdateOrdinaryAdmissionLease,
            drain: UpdateDrainToken, directory: ReleaseDestinationLease, release: SignedReleaseEvidence,
            read: @escaping @Sendable () throws -> Frame,
            writeNative: (@Sendable (Record, Record, Frame) throws -> Transition)?,
            writeOwned: (@Sendable (Record, Record) throws -> Record)?,
            verifyCaller: @escaping @Sendable () throws -> Void,
            verifyConfiguration: @escaping @Sendable () throws -> Void,
            inspect: @escaping @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation,
            observe: @escaping @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness,
            verifySetupIdentity: @escaping @Sendable () throws -> Void = {}, restartAttempt: RestartAttempt? = nil,
            cancellation: SetupAuditUpgradeCancellation? = nil, nativeUnboundFiles: NativeFiles? = nil,
            ownedUnboundWriters: OwnedUnboundWriters? = nil, unboundJoined: SetupRetainedOrphanClaim.Joined? = nil) {
            self.verifySetupIdentity = verifySetupIdentity; self.restartAttempt = restartAttempt
            self.cancellation = cancellation; restartAttempt?.confirmedRow(row)
            self.nativeUnboundFiles = nativeUnboundFiles; self.ownedUnboundWriters = ownedUnboundWriters
            self.unboundJoined = unboundJoined
            self.floor = floor; self.row = row; self.admission = admission; self.drain = drain; self.directory = directory
            self.release = release; self.read = read; self.writeNative = writeNative; self.writeOwned = writeOwned
            native = writeNative != nil; self.verifyCaller = verifyCaller; self.verifyConfiguration = verifyConfiguration
            self.inspect = inspect; self.observe = observe
            restartAttempt?.didOpenCustody()
        }
        private func checkCancellation() throws {
            try cancellation?.check(); try Task.checkCancellation()
        }
        var current: Record { lock.withLock { row } }
        func validateResources(recovery: Bool = false) throws {
            try cancellation?.check()
            try lock.withLock {
                guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID, !invalidated else {
                    throw JournalLeaseError.invalidated
                }
                try admission.validateMachineBoundary(directory: directory, expected: floor.cohort.machineIdentity)
                // The committed pending row is the only boundary after which the client may close the drain.
                if row.phase != .reopenPending && row.phase != .restored && !unboundDrainReleased {
                    try drain.validateAccountBoundary(directory: directory, accountID: floor.cohort.accountID,
                        expected: floor.cohort.accountIdentity)
                }
                if recovery { try verifyCaller() } else { try verifyConfiguration() }
                try admission.validateMachineBoundary(directory: directory, expected: floor.cohort.machineIdentity)
            }
        }
        func withRegistration(_ expected: Record, body: () throws -> Void) throws {
            try lock.withLock {
                guard !registrationUsed else { throw JournalLeaseError.invalidated }; registrationUsed = true
                try requireRestoring(expected); try checkCancellation(); try body(); try requireRestoring(expected)
            }
        }
        fileprivate func requireCurrent(_ expected: Record) throws -> Frame {
            try lock.withLock {
                try validateResources(); guard row == expected else { throw PreparationStoreError.staleRevision }
                let first = try read(); try floor.requireCurrent(first, window: expected, release: release)
                let second = try read(); try floor.requireCurrent(second, window: expected, release: release)
                try second.source.actual.requireSame(as: first.source.actual)
                try validateResources(); return second
            }
        }
        func requireRestoring(_ expected: Record) throws {
            guard expected.phase == .restoring else { throw PreparationStoreError.invalidTransition }
            _ = try requireCurrent(expected)
            try drain.validateAccountBoundary(directory: directory, accountID: floor.cohort.accountID,
                expected: floor.cohort.accountIdentity)
        }
        func persistNative(_ next: Record, previous: Record) throws -> Transition {
            if next.phase == .needsOwnerRecovery { return try persistNativeFailure(next, previous: previous) }
            return try persistNativeChecked(next, previous: previous)
        }
        private func persistNativeChecked(_ next: Record, previous: Record) throws -> Transition {
            try lock.withLock {
                guard native, let writeNative else { throw JournalLeaseError.rootRequired }
                let frame = try requireCurrent(previous); try next.requireReplacing(previous)
                try checkCancellation()
                // Every error after entering the writer is uncertain. No recovery write or RPC follows it.
                let receipt: Transition
                do {
                    receipt = try writeNative(next, previous, frame)
                    try receipt.requireReplacement(next, replacing: previous)
                } catch { invalidated = true; writerUncertain = true; throw AuthorityMaintenanceClientError.needsOwnerRecovery }
                row = next; restartAttempt?.confirmedRow(next)
                if next.phase == .restored { restoredTransition = receipt }
                do { _ = try requireCurrent(next) }
                catch {
                    // The commit is confirmed. A failed scope check can attempt exactly one recovery write.
                    _ = try? persistRecovery(next, failure: .changedScope)
                    throw RuntimePreparationError.changedScope
                }
                return receipt
            }
        }
        func persistOwned(_ next: Record, previous: Record) throws -> Record {
            try RuntimeMaintenanceOwnedControl.require()
            if next.phase == .needsOwnerRecovery { return try persistOwnedFailure(next, previous: previous) }
            return try persistOwnedChecked(next, previous: previous)
        }
        private func persistOwnedChecked(_ next: Record, previous: Record) throws -> Record {
            try RuntimeMaintenanceOwnedControl.require()
            return try lock.withLock {
                guard !native, let writeOwned else { throw JournalLeaseError.unsafeMetadata }
                _ = try requireCurrent(previous); try next.requireReplacing(previous)
                try checkCancellation()
                do {
                    guard try writeOwned(next, previous) == next else { throw PreparationStoreError.staleRevision }
                } catch { invalidated = true; writerUncertain = true; throw AuthorityMaintenanceClientError.needsOwnerRecovery }
                row = next; restartAttempt?.confirmedRow(next)
                if next.phase == .restored { restoredOwned = next }
                do { _ = try requireCurrent(next) }
                catch {
                    _ = try? persistRecovery(next, failure: .changedScope)
                    throw RuntimePreparationError.changedScope
                }
                return next
            }
        }
        /// A confirmed row can record one failure under fresh caller and lock checks.
        /// Host or job drift must not prevent the failure record. An uncertain write still forbids it.
        private func failureFrame(_ next: Record, previous: Record) throws -> Frame {
            try checkCancellation()
            guard !invalidated, !recoveryUsed, row == previous, previous.phase != .needsOwnerRecovery,
                  previous.phase != .restored, next.phase == .needsOwnerRecovery else { throw JournalLeaseError.invalidated }
            recoveryUsed = true; try next.requireReplacing(previous)
            try validateResources(recovery: true)
            let frame = try read()
            guard frame.window == previous else { throw PreparationStoreError.staleRevision }
            try validateResources(recovery: true)
            return frame
        }
        private func persistNativeFailure(_ next: Record, previous: Record) throws -> Transition {
            try lock.withLock {
                guard native, let writeNative else { throw JournalLeaseError.rootRequired }
                let frame = try failureFrame(next, previous: previous)
                try checkCancellation()
                do {
                    let receipt = try writeNative(next, previous, frame)
                    try receipt.requireReplacement(next, replacing: previous); row = next; restartAttempt?.confirmedRow(next); return receipt
                } catch { invalidated = true; writerUncertain = true; throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            }
        }
        private func persistOwnedFailure(_ next: Record, previous: Record) throws -> Record {
            try RuntimeMaintenanceOwnedControl.require()
            return try lock.withLock {
                guard !native, let writeOwned else { throw JournalLeaseError.unsafeMetadata }
                _ = try failureFrame(next, previous: previous)
                try checkCancellation()
                do {
                    guard try writeOwned(next, previous) == next else { throw PreparationStoreError.staleRevision }
                    row = next; restartAttempt?.confirmedRow(next); return next
                } catch { invalidated = true; writerUncertain = true; throw AuthorityMaintenanceClientError.needsOwnerRecovery }
            }
        }
        fileprivate func persistRecovery(_ previous: Record, failure: Record.Failure,
            service: Record.ServiceOutcome? = nil) throws -> Record {
            let next = try RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                service: service ?? previous.service, failure: failure)
            if native { _ = try persistNativeFailure(next, previous: previous) }
            else { _ = try persistOwnedFailure(next, previous: previous) }
            return next
        }
        fileprivate func persistRestartBridge(_ next: Record, previous: Record) throws -> Transition? {
            guard [.draining, .stopping].contains(previous.phase), previous.operation == .notStarted,
                  next.phase == .needsOwnerRecovery, next.failure == .serviceUnavailable else {
                throw PreparationStoreError.invalidTransition
            }
            if native { return try persistNativeChecked(next, previous: previous) }
            _ = try persistOwnedChecked(next, previous: previous); return nil
        }
        fileprivate func requireBeforePendingRetry() throws {
            try lock.withLock {
                guard !invalidated, !recoveryUsed, [.draining, .stopping, .restoring].contains(row.phase) else {
                    throw JournalLeaseError.invalidated
                }
                try validateResources(recovery: true)
            }
        }
        func requireCleanup(_ expected: Record) throws { _ = try requireCurrent(expected) }
        func releaseCleanupDrain(after receipt: Transition, pending: Record, previous: Record) throws {
            guard native else { throw JournalLeaseError.rootRequired }
            try receipt.requireReplacement(pending, replacing: previous); try releaseCleanup(pending)
        }
        func releaseOwnedCleanupDrain(after pending: Record) throws {
            try RuntimeMaintenanceOwnedControl.require()
            guard !native else { throw JournalLeaseError.unsafeMetadata }; try releaseCleanup(pending)
        }
        private func releaseCleanup(_ pending: Record) throws {
            try lock.withLock {
                guard row == pending, pending.phase == .reopenPending, pending.service == .notStopped,
                      pending.operation == .notStarted else { throw PreparationStoreError.invalidTransition }
                try validateResources()
                try drain.validateAccountBoundary(directory: directory, accountID: floor.cohort.accountID,
                    expected: floor.cohort.accountIdentity)
                drain.close()
            }
        }
        fileprivate func persist(_ next: Record, previous: Record) throws -> Transition? {
            if native { return try persistNative(next, previous: previous) }
            _ = try persistOwned(next, previous: previous); return nil
        }
        fileprivate var completionReader: @Sendable () throws -> Frame { read }
        fileprivate var completionVerifier: @Sendable () throws -> Void { verifySetupIdentity }
        fileprivate func requireExplicitCompletion(_ expected: Record) throws {
            try lock.withLock {
                guard !invalidated, expected.phase == .restored, row == expected else { throw RuntimePreparationError.changedScope }
                if native {
                    guard let restoredTransition, restoredTransition.record == expected else { throw PreparationStoreError.invalidTransition }
                } else {
                    try RuntimeMaintenanceOwnedControl.require()
                    guard restoredOwned == expected else { throw PreparationStoreError.invalidTransition }
                }
                // Recording a confirmed completion is cleanup, not a new caller action.
                // An expired caller cannot erase its actual receipt. Releasing admission still needs fresh rights.
                try admission.validateMachineBoundary(directory: directory, expected: floor.cohort.machineIdentity)
                try verifySetupIdentity()
                let first = try read(); try floor.requireCurrent(first, window: expected, release: release)
                let second = try read(); try floor.requireCurrent(second, window: expected, release: release)
                try second.source.actual.requireSame(as: first.source.actual)
                try verifySetupIdentity()
                try admission.validateMachineBoundary(directory: directory, expected: floor.cohort.machineIdentity)
            }
        }
        func persistUnboundIntent() throws -> Transition {
            try lock.withLock {
                guard let joined = unboundJoined else { throw RuntimePreparationError.changedScope }
                let previous = row, frame = try requireCurrent(row)
                _ = try joined.requireUnboundAuthorizedOrigin(previous)
                try checkCancellation()
                let receipt: Transition
                do {
                    if let nativeUnboundFiles { receipt = try nativeUnboundFiles.writeUnboundIntent(previous, joined: joined, frame: frame) }
                    else if let ownedUnboundWriters {
                        try RuntimeMaintenanceOwnedControl.require()
                        receipt = try ownedUnboundWriters.intent(previous, joined, frame)
                    } else { throw RuntimePreparationError.changedScope }
                    try receipt.requireReplacement(receipt.record, replacing: previous)
                    guard receipt.record.phase == .reopenPending, receipt.record.unboundRelease != nil else {
                        throw PreparationStoreError.invalidTransition
                    }
                } catch let refusal as PreparationIntentStore.RuntimeMaintenancePretransactionRefusal {
                    throw refusal.underlying
                } catch { invalidated = true; writerUncertain = true; throw error }
                row = receipt.record
                _ = try requireCurrent(row)
                return receipt
            }
        }
        func releaseUnboundCleanupDrain() throws {
            try lock.withLock {
                guard let joined = unboundJoined else { throw RuntimePreparationError.changedScope }
                try joined.requireUnboundIntentReconciliation(row)
                _ = try requireCurrent(row)
                if !unboundDrainReleased {
                    try drain.validateAccountBoundary(directory: directory, accountID: floor.cohort.accountID,
                        expected: floor.cohort.accountIdentity)
                    drain.close(); unboundDrainReleased = true
                }
            }
        }
        func persistUnboundCompletion(_ observation: VerifiedUnboundGateObservation) throws -> Transition {
            try lock.withLock {
                guard let joined = unboundJoined, unboundDrainReleased else { throw RuntimePreparationError.changedScope }
                let previous = row, frame = try requireCurrent(row)
                try joined.requireUnboundIntentReconciliation(previous)
                guard let gate = frame.source.actual.admission.accounts.first(where: {
                    $0.accountID == previous.scope.authority.accountID
                }) else { throw RuntimePreparationError.changedScope }
                try observation.requireCurrent(joined: joined, row: previous, gate: gate.identity)
                _ = try observation.completedGateReadback()
                try checkCancellation()
                let receipt: Transition
                do {
                    if let nativeUnboundFiles {
                        receipt = try nativeUnboundFiles.writeUnboundCompletion(previous, joined: joined, observation: observation, frame: frame)
                    } else if let ownedUnboundWriters {
                        try RuntimeMaintenanceOwnedControl.require()
                        receipt = try ownedUnboundWriters.completion(previous, joined, observation, frame)
                    } else { throw RuntimePreparationError.changedScope }
                    try receipt.requireReplacement(receipt.record, replacing: previous)
                    try receipt.record.requireUnboundCompletionReplacing(previous)
                } catch let refusal as PreparationIntentStore.RuntimeMaintenancePretransactionRefusal {
                    throw refusal.underlying
                } catch { invalidated = true; writerUncertain = true; throw error }
                row = receipt.record
                if native { restoredTransition = receipt } else { restoredOwned = row }
                _ = try requireCurrent(row)
                return receipt
            }
        }
        func requireUnboundCleanup() throws {
            try lock.withLock {
                guard unboundJoined != nil else { throw RuntimePreparationError.changedScope }
                _ = try requireCurrent(row)
            }
        }
        @discardableResult func persistUnboundFailure(_ failure: Record.Failure) throws -> Record {
            try lock.withLock {
                guard unboundJoined != nil, !invalidated, !writerUncertain else { throw JournalLeaseError.invalidated }
                if row.phase == .needsOwnerRecovery || row.phase == .restored || row.unboundRelease == nil { return row }
                return try persistRecovery(row, failure: failure)
            }
        }
        fileprivate func requireUnboundCompletion() throws {
            guard unboundJoined != nil else { throw RuntimePreparationError.changedScope }
            try requireExplicitCompletion(current)
        }
        func closeUnboundCustody() {
            guard unboundJoined != nil else { return }
            close()
        }
        fileprivate func close() { lock.withLock { invalidated = true; drain.close(); admission.close(); directory.close() } }
        deinit { close() }
    }
    /// Issued after the exact restoring row and one registration or adoption under fresh custody.
    final class PreparedRestoration: @unchecked Sendable {
        let window: Record, previous: Record
        private let custody: Custody, receipt: Transition?
        private let lock = NSLock(), processID = getpid()
        private var consumed = false
        fileprivate init(custody: Custody, window: Record, previous: Record, receipt: Transition?) {
            self.custody = custody; self.window = window; self.previous = previous; self.receipt = receipt
        }
        func requireReceipt() throws {
            guard getpid() == processID else { throw JournalLeaseError.invalidated }
            if let receipt { try receipt.requireReplacement(window, replacing: previous) }
            // A preexisting restoring row has no new receipt. It requires exact protected readback instead.
            try custody.requireRestoring(window)
        }
        func consume() throws -> Custody {
            try lock.withLock {
                guard !consumed else { throw JournalLeaseError.invalidated }; consumed = true
            }
            try requireReceipt(); return custody
        }
    }
    fileprivate final class NativeFiles: @unchecked Sendable {
        let configuration: AdministrativeSetupConfiguration, release: SignedReleaseEvidence
        let directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken
        let accountID: Data
        private let processID = getpid()
        init(configuration: AdministrativeSetupConfiguration, release: SignedReleaseEvidence, accountID: Data,
            directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken) {
            self.configuration = configuration; self.release = release; self.accountID = accountID
            self.directory = directory; self.admission = admission; self.drain = drain
        }
        func read() throws -> Frame {
            try use { try $0.runtimeMaintenanceStartupFrame(accountID: accountID, candidate: release) }
        }
        func write(_ next: Record, _ previous: Record, _ frame: Frame) throws -> Transition {
            try use { machine in
                try machine.validateUpdateAdmissionDirectory(directory)
                return try machine.writeRuntimeMaintenanceTransition(next, replacing: previous,
                    expected: frame.source.actual, candidate: release, directory: directory,
                    admission: admission, accountDrain: drain)
            }
        }
        func writeUnboundIntent(_ previous: Record, joined: SetupRetainedOrphanClaim.Joined, frame: Frame) throws -> Transition {
            try use {
                try $0.writeRuntimeMaintenanceUnboundIntent(replacing: previous, joined: joined,
                    expected: frame.source.actual, candidate: release, directory: directory, admission: admission)
            }
        }
        func writeUnboundCompletion(_ previous: Record, joined: SetupRetainedOrphanClaim.Joined,
            observation: VerifiedUnboundGateObservation, frame: Frame) throws -> Transition {
            try use {
                try $0.writeRuntimeMaintenanceUnboundCompletion(replacing: previous, joined: joined, observation: observation,
                    expected: frame.source.actual, candidate: release, directory: directory, admission: admission)
            }
        }
        func discardUnboundStartup(_ initial: Frame, startupPhases: SetupRetainedInvocationReservation.RestorationPhases?, hasExplicitAuthority: Bool,
            verify: @escaping @Sendable () throws -> Void) throws -> Frame {
            try RuntimeMaintenanceStartupRecovery.prepareUnboundStartupFrame(frame: initial, hasExplicitAuthority: hasExplicitAuthority,
                startupPhases: startupPhases, directory: directory, admission: admission, drain: drain,
                verify: verify, read: { try self.read() },
                persistFailure: { try self.write($0, $1, $2) },
                persistDiscard: { previous, authorization, frame in
                    try self.use { machine in
                        try machine.writeRuntimeMaintenanceUnboundStartupDiscard(replacing: previous,
                            authorization: authorization, expected: frame.source.actual, candidate: self.release,
                            directory: self.directory, admission: self.admission)
                    }
                })
        }

        private func use<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            guard getpid() == processID, getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.invalidated }
            let machine = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
            do { let value = try body(machine); try machine.close(); return value }
            catch { try? machine.close(); throw error }
        }
    }
    private let custody: Custody
    private let explicitAuthority: ExplicitAuthority?
    private let nativePhases: SetupRetainedInvocationReservation.RestorationPhases?
    private let ownedSupervisorWork: OwnedSupervisorWork?
    private var phases: SetupRetainedInvocationReservation.RestorationPhases? { explicitAuthority?.phases ?? nativePhases }
    private let observeOperation: @Sendable (Record) -> RuntimeMaintenanceRuntimeObservation.State
    private let register: @Sendable (Custody, Record) throws -> Void
    private let lock = NSRecursiveLock()
    private var prepared = false, probePending = false, runUsed = false
    private let afterProbePolicy: @Sendable (Record, Bool) throws -> RuntimeMaintenanceStartupPolicy.Action
    private let continuationRevision = AccountPreparationIntent.randomID()
    private init(custody: Custody, explicitAuthority: ExplicitAuthority? = nil,
        nativePhases: SetupRetainedInvocationReservation.RestorationPhases? = nil, ownedSupervisorWork: OwnedSupervisorWork? = nil,
        observeOperation: @escaping @Sendable (Record) -> RuntimeMaintenanceRuntimeObservation.State,
        register: @escaping @Sendable (Custody, Record) throws -> Void,
        afterProbePolicy: @escaping @Sendable (Record, Bool) throws -> RuntimeMaintenanceStartupPolicy.Action = {
            try RuntimeMaintenanceStartupPolicy.afterProbe($0, sameIncarnation: $1)
        }) {
        self.nativePhases = nativePhases ?? ownedSupervisorWork?.phases; self.ownedSupervisorWork = ownedSupervisorWork
        self.custody = custody; self.explicitAuthority = explicitAuthority; self.observeOperation = observeOperation; self.register = register; self.afterProbePolicy = afterProbePolicy
    }
    var window: Record { custody.current }
    func closeNativeCustody() { custody.close() }

    /// Fixed installed Setup only. Busy means no row write and no RPC.
    static func open(accountID: Data) throws -> RuntimeMaintenanceStartupRecovery? {
        try open(accountID: accountID, explicit: nil)
    }
    struct OwnedStartupWriters: Sendable {
        let failure: @Sendable (Record, Record, Frame) throws -> Transition
        let discard: @Sendable (Record, UnboundStartupDiscardAuthorization, Frame) throws -> Transition
    }
    struct OwnedSupervisorWork: Sendable {
        let phases: SetupRetainedInvocationReservation.RestorationPhases
        let cancellation: SetupAuditUpgradeCancellation
        let control: AuthorityMaintenanceXPCClient.OwnedSupervisorPhaseControl?
        let verifyClient: @Sendable () throws -> Void
        init(phases: SetupRetainedInvocationReservation.RestorationPhases, cancellation: SetupAuditUpgradeCancellation,
            control: AuthorityMaintenanceXPCClient.OwnedSupervisorPhaseControl? = nil,
            verifyClient: @escaping @Sendable () throws -> Void = {}) throws {
            try RuntimeMaintenanceOwnedControl.require()
            self.phases = phases; self.cancellation = cancellation; self.control = control; self.verifyClient = verifyClient
        }
    }
    enum NativeOpening: Sendable { case terminal(Record?), owner(RuntimeMaintenanceStartupRecovery) }
    /// Minted only by fixed startup construction or the separate ordinary-owner fixture entry.
    final class UnboundStartupDiscardAuthorization: @unchecked Sendable {
        private let process = getpid(), owner = getuid()
        private let row: Record, source: MachineUpdateStableReleaseSnapshot
        private let directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken
        private let verify: @Sendable () throws -> Void
        private let startupPhases: SetupRetainedInvocationReservation.RestorationPhases
        fileprivate init(frame: Frame, directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease,
            drain: UpdateDrainToken, startupPhases: SetupRetainedInvocationReservation.RestorationPhases,
            verify: @escaping @Sendable () throws -> Void) throws {
            try startupPhases.requireUnboundStartupPhase()
            guard let row = frame.window, row.phase == .needsOwnerRecovery, row.unboundRelease != nil,
                  row.scope.macID == frame.source.actual.inventory.macID,
                  row.scope.installationID == frame.source.actual.inventory.installationID else {
                throw RuntimePreparationError.changedScope
            }
            self.row = row; source = frame.source.actual; self.directory = directory
            self.admission = admission; self.drain = drain; self.verify = verify
            self.startupPhases = startupPhases
        }
        func requireExternalAuthorization() throws {
            try startupPhases.requireUnboundStartupPhase(); try verify()
        }
        func requireCurrentInMemory(_ previous: Record, expected: MachineUpdateStableReleaseSnapshot) throws {
            guard getpid() == process, getuid() == owner, geteuid() == owner, previous == row,
                  let account = source.admission.accounts.first(where: { $0.accountID == row.scope.authority.accountID }) else {
                throw JournalLeaseError.invalidated
            }
            try source.requireSame(as: expected)
            try startupPhases.requireUnboundStartupPhaseInMemory()
            try admission.validateMachineBoundary(directory: directory, expected: source.admission.machine)
            try drain.validateAccountBoundary(directory: directory, accountID: account.accountID, expected: account.identity)
        }
    }
    private final class NativeTerminalCapture: @unchecked Sendable {
        private let lock = NSLock()
        private var captured: Record?
        func store(_ row: Record) { lock.withLock { captured = row } }
        var row: Record? { lock.withLock { captured } }
    }
    private static func terminalRow(_ frame: Frame, accountID: Data) throws -> Record? {
        guard let row = frame.window, row.phase == .restored || row.phase == .needsOwnerRecovery else { return nil }
        let inventory = frame.source.actual.inventory
        guard row.scope.authority.accountID == accountID, row.scope.macID == inventory.macID,
              row.scope.installationID == inventory.installationID else { throw RuntimePreparationError.changedScope }
        return row
    }
    static func terminalForSupervisorOwned(frame: Frame, accountID: Data) throws -> Record? {
        try RuntimeMaintenanceOwnedControl.require()
        return try terminalRow(frame, accountID: accountID)
    }
    /// A terminal row grants no recovery owner and does not need the current release's restoration floor.
    static func openForSupervisor(accountID: Data, phases: SetupRetainedInvocationReservation.RestorationPhases,
        cancellation: SetupAuditUpgradeCancellation, validate: @escaping @Sendable () throws -> Void) throws -> NativeOpening {
        let terminal = NativeTerminalCapture()
        if let owner = try open(accountID: accountID, explicit: nil, nativePhases: phases,
            cancellation: cancellation, validate: validate, terminal: terminal) { return .owner(owner) }
        return .terminal(terminal.row)
    }
    private static func open(accountID: Data, explicit: ExplicitAuthority?,
        nativePhases: SetupRetainedInvocationReservation.RestorationPhases? = nil,
        cancellation: SetupAuditUpgradeCancellation? = nil,
        validate: @escaping @Sendable () throws -> Void = {},
        terminal: NativeTerminalCapture? = nil) throws -> RuntimeMaintenanceStartupRecovery? {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let configuration = try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath)
        guard configuration.machineDirectory == MachineBootstrap.machineDirectory,
              let setup = configuration.codePolicy.entries.first(where: { $0.role == .setupController && $0.active }),
              let app = configuration.codePolicy.entries.first(where: { $0.role == .app && $0.active }) else {
            throw RuntimePreparationError.changedScope
        }
        let policy = try XPCPeerPolicy(teamID: setup.teamID, componentIdentifier: setup.identifier,
            approvedCodeDirectoryHashes: [setup.codeDirectoryHash], expectedUserID: 0)
        let processID = getpid()
        let verifySetupIdentity: @Sendable () throws -> Void = {
            guard getpid() == processID, getuid() == 0, geteuid() == 0,
                  try DynamicCodeValidation.selfPath() == MachineBootstrap.bundlePath + "/" + AdministrativeSetupConfiguration.executablePath,
                  try AdministrativeSetupConfiguration.load(path: AdministrativeSetupConfiguration.startupPath).canonicalBytes
                    == configuration.canonicalBytes else { throw RuntimePreparationError.changedScope }
            try DynamicCodeValidation.validateSelf(requirement: policy.requirement
                + " and info[\"RemozioSecurityGeneration\"] = \"\(setup.installedGeneration)\"")
        }
        let verify: @Sendable () throws -> Void = {
            try cancellation?.check(); try validate(); try verifySetupIdentity(); try explicit?.requireCurrent()
        }
        let instance = explicit?.processLease
        let verifyCompletionIdentity: @Sendable () throws -> Void = {
            try cancellation?.check(); try validate(); try verifySetupIdentity(); try instance?.validate()
        }
        try verify()
        let release = try SignedReleaseInspection.inspect(URL(fileURLWithPath: MachineBootstrap.bundlePath),
            teamID: app.teamID, appIdentifier: app.identifier)
        try configuration.validate(release: release)
        func closedMachine<Value>(_ body: (PreparationIntentStore) throws -> Value) throws -> Value {
            let machine = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
            do { let value = try body(machine); try machine.close(); return value }
            catch { try? machine.close(); throw error }
        }
        // This read discovers gate identities only. No pre-custody row is used for recovery.
        let registration = try closedMachine { try $0.stableMachineUpdateSnapshot(candidate: release).admission }
        guard let account = registration.accounts.first(where: { $0.accountID == accountID }) else {
            throw RuntimePreparationError.changedScope
        }
        let directory = try ReleaseDestinationLease.acquire(path: configuration.machineDirectory)
        do {
            let admission = try UpdateOrdinaryAdmissionLease.open(machineDirectory: configuration.machineDirectory, expected: registration.machine)
            do {
                let drain = try UpdateAdmissionBarrier.open(machineDirectory: configuration.machineDirectory,
                    expected: account.identity, scope: .account(accountID)).beginDrain()
                do {
                    let files = NativeFiles(configuration: configuration, release: release, accountID: accountID,
                        directory: directory, admission: admission, drain: drain)
                    let read: @Sendable () throws -> Frame = { try files.read() }
                    var frame = try read()
                    frame = try files.discardUnboundStartup(frame, startupPhases: nativePhases,
                        hasExplicitAuthority: explicit != nil, verify: verify)
                    guard let row = frame.window else { drain.close(); admission.close(); directory.close(); return nil }
                    if let terminal, let row = try terminalRow(frame, accountID: accountID) {
                        guard frame.source.actual.admission == registration else { throw RuntimePreparationError.changedScope }
                        try configuration.validate(inventory: frame.source.actual.inventory, release: release)
                        try verify(); terminal.store(row)
                        drain.close(); admission.close(); directory.close(); return nil
                    }
                    if let explicit { try explicit.capture(row) }
                    else if nativePhases == nil && (row.phase == .restored || row.phase == .needsOwnerRecovery) {
                        drain.close(); admission.close(); directory.close(); return nil
                    }
                    guard frame.source.actual.admission == registration else { throw RuntimePreparationError.changedScope }
                    try configuration.validate(inventory: frame.source.actual.inventory, release: release)
                    let floor = try RuntimeMaintenanceStartupFloor(frame: frame, release: release)
                    let verifyHost: @Sendable () throws -> Void = {
                        try verifyCompletionIdentity()
                        guard try ProtectedServiceConfiguration.read(path: floor.cohort.job.configurationPath) == floor.host.canonicalBytes else {
                            throw RuntimePreparationError.changedScope
                        }
                        let jobDirectory = try ProtectedSetupDirectory(anchor: "/",
                            relativePath: String(InstalledAccountJobManifest.directory.dropFirst()), owner: 0,
                            visibility: .sharedMetadata, createIfMissing: false)
                        defer { jobDirectory.close() }
                        _ = try MachineUpdateRetainedSetupPromotionSourceValidation.retainedJobBytes(
                            floor.cohort.job, directory: jobDirectory, owner: 0)
                        for account in [row.scope.authority, row.scope.target] {
                            guard let prepared = floor.source.preparations.first(where: { $0.accountID == account.accountID }) else {
                                throw RuntimePreparationError.changedScope
                            }
                            try LocalAccountDirectory.validateOwnership(LocalAccountDirectory.lookup(uid: account.ownerUID),
                                uid: account.ownerUID, directoryID: prepared.directoryID)
                        }

                    }
                    let custody = Custody(floor: floor, row: row, admission: admission, drain: drain, directory: directory,
                        release: release, read: read, writeNative: { try files.write($0, $1, $2) },
                        writeOwned: nil, verifyCaller: verifyCompletionIdentity, verifyConfiguration: {
                            try explicit?.requireCurrent(); try verifyHost()
                        }, inspect: { job in
                            try RuntimeJobStopSession.classify(BoundedNativeCommand.run(executable: "/bin/launchctl",
                                arguments: ["print", "system/" + job.declaration.label]), job: job)
                        }, observe: { try RuntimeJobProcessObservation.open(job: $0, code: $1, processID: $2) },
                        verifySetupIdentity: verifyHost, restartAttempt: explicit?.restartAttempt, cancellation: cancellation,
                        nativeUnboundFiles: explicit?.unboundJoined == nil ? nil : files, unboundJoined: explicit?.unboundJoined)
                    _ = try custody.requireCurrent(row)
                    return .init(custody: custody, explicitAuthority: explicit, nativePhases: nativePhases, observeOperation: { window in
                        // The synchronous M08 loan opens B only and ends before any async transfer.
                        do {
                            try custody.validateResources()
                            let machine = try PreparationIntentStore.open(directoryPath: configuration.machineDirectory, macID: configuration.macID)
                            let frame: PreparationIntentStore.RetainedImportFrame
                            do {
                                let target = try LocalAccountDirectory.lookup(uid: window.scope.target.ownerUID)
                                let entry = try machine.retainedSetupInitialRuntimeEntry(owner: target, candidate: release)
                                let inputs = try machine.withSharedImportJournal { journal in
                                    if let journal { return try machine.withSharedImportSnapshot(journal: journal) { path, owner in
                                        try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: entry.runtime, journal: journal,
                                            verifyCurrent: { try machine.validateStorageLease() },
                                            readRelay: { try .read($0, directory: path, owner: owner) })
                                    } }
                                    return try MachineUpdateRetainedSetupRuntimeInputs.capture(expected: entry.runtime, journal: nil,
                                        verifyCurrent: { try machine.validateStorageLease() }, readRelay: { _ in throw SharedSetupImportError.wrongScope })
                                }
                                frame = (entry, inputs); try machine.close()
                            } catch { try? machine.close(); throw error }
                            return try MachineUpdateRetainedSetupRuntimeNativeContext.withNativeCustody(
                                machineDirectory: configuration.machineDirectory, expected: frame, candidate: release) { loan in
                                try custody.validateResources()
                                return RuntimeMaintenanceRuntimeObservation.observeNative(window: window, expected: frame,
                                    candidate: release, custody: loan)
                            }
                        } catch { return .unknown }
                    }, register: { custody, restoring in
                        try RuntimeJobRegistration.ensureStartupRestoration(custody, window: restoring)
                    })
                } catch { drain.close(); throw error }
            } catch { admission.close(); throw error }
        } catch { directory.close(); throw error }
    }

    /// The actual task is retained in the claim's typed slot before this factory opens any custody.
    /// This library method adds no endpoint and never acquires another Setup reservation.
    static func restoreExplicitNative(joined: SetupRetainedOrphanClaim.Joined, processLease: SetupProcessLease,
        accountID: Data, until deadline: ContinuousClock.Instant) async throws -> Record {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let phases = try joined.restorationPhases().forAttempt(until: deadline)
        try await phases.run { try joined.requireRestorationAccount(accountID) }
        let work = try await joined.startRestoration { workID in
            try Task.checkCancellation()
            guard ContinuousClock.now < deadline else { throw CancellationError() }
            let recovery = try await phases.run {
                let authority = try ExplicitAuthority(joined: joined, processLease: processLease, native: true, phases: phases)
                guard let recovery = try open(accountID: accountID, explicit: authority) else { throw PreparationStoreError.notFound }
                return recovery
            }
            let outcome: Swift.Result<ExplicitCompletion, any Error>
            do { outcome = .success(try await recovery.finishExplicit(workID: workID) { try await recovery.runNative(until: deadline) }) }
            catch { outcome = .failure(error) }
            try await phases.closeActual { recovery.custody.close() }
            return try outcome.get()
        }
        return try await joined.finishRestorationNative(work: work, processLease: processLease)
    }

    /// Ordinary-owner control data only. The native factory cannot accept this bundle or its callbacks.
    private struct OwnedExplicitInputs: @unchecked Sendable {
        let frame: Frame, release: SignedReleaseEvidence
        let admission: UpdateOrdinaryAdmissionLease, directory: ReleaseDestinationLease, accountBarrier: UpdateAdmissionBarrier
        let read: @Sendable () throws -> Frame, persist: @Sendable (Record, Record) throws -> Record
        let verify: @Sendable () throws -> Void
        let inspect: @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation
        let observe: @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness
        let register: @Sendable () throws -> Void
        let makeDriver: @Sendable () throws -> any AuthorityMaintenanceClientDriver
        let capturePeer: @Sendable () throws -> any RuntimeJobExitWitness
        let requirePeerLive: @Sendable (any RuntimeJobExitWitness) throws -> Void
        let phaseControl: AuthorityMaintenanceXPCClient.OwnedRestorationPhaseControl?
    }
    static func restoreExplicitOwned(joined: SetupRetainedOrphanClaim.Joined, processLease: SetupProcessLease,
        frame: Frame, release: SignedReleaseEvidence, admission: UpdateOrdinaryAdmissionLease,
        directory: ReleaseDestinationLease, accountBarrier: UpdateAdmissionBarrier,
        read: @escaping @Sendable () throws -> Frame, persist: @escaping @Sendable (Record, Record) throws -> Record,
        verify: @escaping @Sendable () throws -> Void,
        inspect: @escaping @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation,
        observe: @escaping @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness,
        register: @escaping @Sendable () throws -> Void,
        makeDriver: @escaping @Sendable () throws -> any AuthorityMaintenanceClientDriver,
        capturePeer: @escaping @Sendable () throws -> any RuntimeJobExitWitness,
        requirePeerLive: @escaping @Sendable (any RuntimeJobExitWitness) throws -> Void,
        ownedDeadline: SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl? = nil,
        ownedPhaseControl: AuthorityMaintenanceXPCClient.OwnedRestorationPhaseControl? = nil,
        until deadline: ContinuousClock.Instant) async throws -> Record {
        try RuntimeMaintenanceOwnedControl.require()
        guard let window = frame.window else { throw PreparationStoreError.notFound }
        let originalPhases = try joined.restorationPhases()
        let phases: SetupRetainedInvocationReservation.RestorationPhases
        if let ownedDeadline { phases = try originalPhases.forOwnedAttempt(until: deadline, expiration: ownedDeadline) }
        else { phases = try originalPhases.forAttempt(until: deadline) }
        try await phases.run { try joined.requireRestorationAccount(window.scope.authority.accountID) }
        let inputs = OwnedExplicitInputs(frame: frame, release: release, admission: admission, directory: directory,
            accountBarrier: accountBarrier, read: read, persist: persist, verify: verify, inspect: inspect, observe: observe,
            register: register, makeDriver: makeDriver, capturePeer: capturePeer, requirePeerLive: requirePeerLive, phaseControl: ownedPhaseControl)
        let work = try await joined.startRestoration { workID in
            try RuntimeMaintenanceOwnedControl.require()
            try Task.checkCancellation()
            guard ContinuousClock.now < deadline else { throw CancellationError() }
            let recovery = try await phases.run {
                let authority = try ExplicitAuthority(joined: joined, processLease: processLease, native: false, phases: phases)
                return try openOwned(frame: inputs.frame, release: inputs.release, admission: inputs.admission,
                    directory: inputs.directory, accountBarrier: inputs.accountBarrier, read: inputs.read,
                    persist: inputs.persist, verify: inputs.verify, inspect: inputs.inspect, observe: inputs.observe,
                    observeOperation: { _ in .unknown }, register: inputs.register,
                    afterProbePolicy: { try RuntimeMaintenanceStartupPolicy.afterProbe($0, sameIncarnation: $1) }, explicit: authority)
            }
            let outcome: Swift.Result<ExplicitCompletion, any Error>
            do {
                outcome = .success(try await recovery.finishExplicit(workID: workID) {
                    try await recovery.runOwned(makeDriver: inputs.makeDriver, capturePeer: inputs.capturePeer,
                        requirePeerLive: inputs.requirePeerLive, ownedPhaseControl: inputs.phaseControl, until: deadline)
                })
            } catch { outcome = .failure(error) }
            try await phases.closeActual { recovery.custody.close() }
            return try outcome.get()
        }
        return try await joined.finishRestorationOwned(work: work, processLease: processLease)
    }

    /// Restart owns a distinct claim and retains the actual task before opening fresh custody.
    static func restoreRestartNative(claim: SetupRestartRecovery.Claim,
        accountID: Data, until deadline: ContinuousClock.Instant) async throws -> Record {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        do {
            let phases = try claim.restorationPhases().forAttempt(until: deadline)
            try await claim.joinPreviousRestoration()
            try await phases.run { try claim.requireRestorationAccount(accountID) }
            let attempt = RestartAttempt { execution, workID in
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw CancellationError() }
                execution.beginCustody()
                let recovery: RuntimeMaintenanceStartupRecovery
                do { recovery = try await phases.run {
                    let authority = try ExplicitAuthority(restart: claim, attempt: execution, native: true, phases: phases)
                    guard let recovery = try open(accountID: accountID, explicit: authority) else { throw PreparationStoreError.notFound }
                    return recovery
                }
                } catch { execution.didCloseCustody(uncertain: false); throw error }
                let outcome: Swift.Result<ExplicitCompletion, any Error>
                do { outcome = .success(try await recovery.finishExplicit(workID: workID) { try await recovery.runNative(until: deadline) }) }
                catch { outcome = .failure(error) }
                try await phases.closeActual {
                    let uncertain = recovery.custody.hasUncertainWriter
                    recovery.custody.close(); execution.didCloseCustody(uncertain: uncertain)
                }
                return try outcome.get()
            }
            let work = try claim.startRestoration(attempt)
            return try await claim.finishRestoration(work: work)
        } catch { await claim.releaseRefusedAttemptIfSafe(); throw error }
    }

    static func restoreRestartOwned(claim: SetupRestartRecovery.Claim,
        frame: Frame, release: SignedReleaseEvidence, admission: UpdateOrdinaryAdmissionLease,
        directory: ReleaseDestinationLease, accountBarrier: UpdateAdmissionBarrier,
        read: @escaping @Sendable () throws -> Frame, persist: @escaping @Sendable (Record, Record) throws -> Record,
        verify: @escaping @Sendable () throws -> Void,
        inspect: @escaping @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation,
        observe: @escaping @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness,
        register: @escaping @Sendable () throws -> Void,
        makeDriver: @escaping @Sendable () throws -> any AuthorityMaintenanceClientDriver,
        capturePeer: @escaping @Sendable () throws -> any RuntimeJobExitWitness,
        requirePeerLive: @escaping @Sendable (any RuntimeJobExitWitness) throws -> Void,
        ownedDeadline: SetupRetainedInvocationReservation.RestorationPhases.OwnedDeadlineControl? = nil,
        beforeCustody: @escaping @Sendable () async throws -> Void = {},
        until deadline: ContinuousClock.Instant) async throws -> Record {
        try RuntimeMaintenanceOwnedControl.require()
        do {
            guard let window = frame.window else { throw PreparationStoreError.notFound }
            let originalPhases = claim.restorationPhases()
            try await claim.joinPreviousRestoration()
            let phases: SetupRetainedInvocationReservation.RestorationPhases
            if let ownedDeadline { phases = try originalPhases.forOwnedAttempt(until: deadline, expiration: ownedDeadline) }
            else { phases = try originalPhases.forAttempt(until: deadline) }
            try await phases.run { try claim.requireRestorationAccount(window.scope.authority.accountID) }
            let inputs = OwnedExplicitInputs(frame: frame, release: release, admission: admission, directory: directory,
                accountBarrier: accountBarrier, read: read, persist: persist, verify: verify, inspect: inspect, observe: observe,
                register: register, makeDriver: makeDriver, capturePeer: capturePeer, requirePeerLive: requirePeerLive, phaseControl: nil)
            let attempt = RestartAttempt { execution, workID in
                try RuntimeMaintenanceOwnedControl.require()
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw CancellationError() }
                try await beforeCustody()
                try Task.checkCancellation()
                guard ContinuousClock.now < deadline else { throw CancellationError() }
                execution.beginCustody()
                let recovery: RuntimeMaintenanceStartupRecovery
                do { recovery = try await phases.run {
                    let authority = try ExplicitAuthority(restart: claim, attempt: execution, native: false, phases: phases)
                    return try openOwned(frame: inputs.frame, release: inputs.release, admission: inputs.admission,
                        directory: inputs.directory, accountBarrier: inputs.accountBarrier, read: inputs.read,
                        persist: inputs.persist, verify: inputs.verify, inspect: inputs.inspect, observe: inputs.observe,
                        observeOperation: { _ in .unknown }, register: inputs.register,
                        afterProbePolicy: { try RuntimeMaintenanceStartupPolicy.afterProbe($0, sameIncarnation: $1) }, explicit: authority)
                }
                } catch { execution.didCloseCustody(uncertain: false); throw error }
                let outcome: Swift.Result<ExplicitCompletion, any Error>
                do {
                    outcome = .success(try await recovery.finishExplicit(workID: workID) {
                        try await recovery.runOwned(makeDriver: inputs.makeDriver, capturePeer: inputs.capturePeer,
                            requirePeerLive: inputs.requirePeerLive, until: deadline)
                    })
                } catch { outcome = .failure(error) }
                try await phases.closeActual {
                    let uncertain = recovery.custody.hasUncertainWriter
                    recovery.custody.close(); execution.didCloseCustody(uncertain: uncertain)
                }
                return try outcome.get()
            }
            let work = try claim.startRestoration(attempt)
            return try await claim.finishRestoration(work: work)
        } catch { await claim.releaseRefusedAttemptIfSafe(); throw error }
    }

    /// Native and record-only constructors are separate. Root cannot inject readers, writes, or native callbacks.
    static func openOwned(frame: Frame, release: SignedReleaseEvidence, admission: UpdateOrdinaryAdmissionLease,
        directory: ReleaseDestinationLease, accountBarrier: UpdateAdmissionBarrier,
        read: @escaping @Sendable () throws -> Frame,
        persist: @escaping @Sendable (Record, Record) throws -> Record,
        verify: @escaping @Sendable () throws -> Void,
        inspect: @escaping @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation,
        observe: @escaping @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness,
        observeOperation: @escaping @Sendable (Record) -> RuntimeMaintenanceRuntimeObservation.State,
        register: @escaping @Sendable () throws -> Void,
        afterProbePolicy: @escaping @Sendable (Record, Bool) throws -> RuntimeMaintenanceStartupPolicy.Action = {
            try RuntimeMaintenanceStartupPolicy.afterProbe($0, sameIncarnation: $1)
        }, supervisorWork: OwnedSupervisorWork? = nil,
        startupWriters: OwnedStartupWriters? = nil) throws -> RuntimeMaintenanceStartupRecovery {
        try openOwned(frame: frame, release: release, admission: admission, directory: directory, accountBarrier: accountBarrier,
            read: read, persist: persist, verify: verify, inspect: inspect, observe: observe,
            observeOperation: observeOperation, register: register, afterProbePolicy: afterProbePolicy, explicit: nil, supervisorWork: supervisorWork, startupWriters: startupWriters)
    }
    private static func openOwned(frame: Frame, release: SignedReleaseEvidence, admission: UpdateOrdinaryAdmissionLease,
        directory: ReleaseDestinationLease, accountBarrier: UpdateAdmissionBarrier,
        read: @escaping @Sendable () throws -> Frame, persist: @escaping @Sendable (Record, Record) throws -> Record,
        verify: @escaping @Sendable () throws -> Void,
        inspect: @escaping @Sendable (InstalledAccountJobManifest) throws -> RuntimeJobStopSession.Observation,
        observe: @escaping @Sendable (InstalledAccountJobManifest, AuthorityCodeEntry, pid_t) throws -> any RuntimeJobExitWitness,
        observeOperation: @escaping @Sendable (Record) -> RuntimeMaintenanceRuntimeObservation.State,
        register: @escaping @Sendable () throws -> Void,
        afterProbePolicy: @escaping @Sendable (Record, Bool) throws -> RuntimeMaintenanceStartupPolicy.Action,
        explicit: ExplicitAuthority?, supervisorWork: OwnedSupervisorWork? = nil,
        ownedUnboundWriters: OwnedUnboundWriters? = nil,
        startupWriters: OwnedStartupWriters? = nil) throws -> RuntimeMaintenanceStartupRecovery {
        try RuntimeMaintenanceOwnedControl.require()
        guard supervisorWork == nil || explicit == nil else { throw RuntimePreparationError.changedScope }
        let drain = try accountBarrier.beginDrain()
        do {
            let frame = try prepareUnboundStartupFrame(frame: frame, hasExplicitAuthority: explicit != nil,
                startupPhases: supervisorWork?.phases, directory: directory, admission: admission, drain: drain,
                verify: verify, read: read,
                persistFailure: { next, previous, frame in
                    guard let startupWriters else { throw RuntimePreparationError.changedScope }
                    return try startupWriters.failure(next, previous, frame)
                }, persistDiscard: { previous, authorization, frame in
                    guard let startupWriters else { throw RuntimePreparationError.changedScope }
                    return try startupWriters.discard(previous, authorization, frame)
                })
            guard let row = frame.window else { throw PreparationStoreError.notFound }
            if let explicit { try explicit.capture(row) }
            let floor = try RuntimeMaintenanceStartupFloor(frame: frame, release: release)
            let instance = explicit?.processLease
            let custody = Custody(floor: floor, row: row, admission: admission, drain: drain, directory: directory,
                release: release, read: read, writeNative: nil, writeOwned: persist,
                verifyCaller: { try instance?.validate() }, verifyConfiguration: { try verify(); try explicit?.requireCurrent() },
                inspect: inspect, observe: observe, verifySetupIdentity: verify,
                restartAttempt: explicit?.restartAttempt, cancellation: supervisorWork?.cancellation,
                ownedUnboundWriters: ownedUnboundWriters, unboundJoined: explicit?.unboundJoined)
            _ = try custody.requireCurrent(row)
            return .init(custody: custody, explicitAuthority: explicit, ownedSupervisorWork: supervisorWork,
                observeOperation: observeOperation, register: { custody, restoring in
                try custody.withRegistration(restoring) { try register() }
            }, afterProbePolicy: afterProbePolicy)
        } catch { drain.close(); throw error }
    }

    /// Library only. The concrete runner calls this on its original executor after it owns the actual work slot.
    static func makeUnboundJoinedCustodyNative(joined: SetupRetainedOrphanClaim.Joined, processLease: SetupProcessLease,
        accountID: Data, until deadline: ContinuousClock.Instant) throws -> Custody {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let phases = try joined.restorationPhases().forAttempt(until: deadline)
        try joined.requireRestorationAccount(accountID)
        let authority = try ExplicitAuthority(joined: joined, processLease: processLease, native: true,
            phases: phases, allowUnbound: true)
        guard let recovery = try open(accountID: accountID, explicit: authority) else { throw PreparationStoreError.notFound }
        return recovery.custody
    }
    static func makeUnboundJoinedCustodyOwned(joined: SetupRetainedOrphanClaim.Joined, processLease: SetupProcessLease,
        frame: Frame, release: SignedReleaseEvidence, admission: UpdateOrdinaryAdmissionLease,
        directory: ReleaseDestinationLease, accountBarrier: UpdateAdmissionBarrier,
        read: @escaping @Sendable () throws -> Frame, persist: @escaping @Sendable (Record, Record) throws -> Record,
        writeIntent: @escaping @Sendable (Record, SetupRetainedOrphanClaim.Joined, Frame) throws -> Transition,
        writeCompletion: @escaping @Sendable (Record, SetupRetainedOrphanClaim.Joined, VerifiedUnboundGateObservation, Frame) throws -> Transition,
        verify: @escaping @Sendable () throws -> Void, until deadline: ContinuousClock.Instant) throws -> Custody {
        try RuntimeMaintenanceOwnedControl.require()
        let phases = try joined.restorationPhases().forAttempt(until: deadline)
        let authority = try ExplicitAuthority(joined: joined, processLease: processLease, native: false,
            phases: phases, allowUnbound: true)
        let recovery = try openOwned(frame: frame, release: release, admission: admission, directory: directory,
            accountBarrier: accountBarrier, read: read, persist: persist, verify: verify,
            inspect: { _ in throw RuntimePreparationError.changedScope }, observe: { _, _, _ in throw RuntimePreparationError.changedScope },
            observeOperation: { _ in .unknown }, register: { throw RuntimePreparationError.changedScope },
            afterProbePolicy: { _, _ in throw RuntimePreparationError.changedScope }, explicit: authority,
            ownedUnboundWriters: .init(intent: writeIntent, completion: writeCompletion))
        return recovery.custody
    }
    static func makeUnboundExplicitCompletion(custody: Custody, workID: UUID,
        originalRunFailed: Bool = false) throws -> ExplicitCompletion {
        try custody.requireUnboundCompletion()
        return try ExplicitCompletion(window: custody.current, workID: workID, custody: custody, originalRunFailed: originalRunFailed)
    }
    /// Ordinary-owner entry uses the same preflight as native open, before terminal or policy handling.
    static func openUnboundStartupOwned(frame: Frame, processLease: SetupProcessLease,
        startupPhases: SetupRetainedInvocationReservation.RestorationPhases,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken,
        read: () throws -> Frame, persistFailure: (Record, Record, Frame) throws -> Transition,
        persistDiscard: (Record, UnboundStartupDiscardAuthorization, Frame) throws -> Transition) throws -> NativeOpening {
        try RuntimeMaintenanceOwnedControl.require(); try processLease.validate()
        let result = try prepareUnboundStartupFrame(frame: frame, hasExplicitAuthority: false, startupPhases: startupPhases,
            directory: directory, admission: admission, drain: drain, verify: { try processLease.validate() },
            read: read, persistFailure: persistFailure, persistDiscard: persistDiscard)
        guard let row = try terminalRow(result, accountID: frame.window?.scope.authority.accountID ?? Data()) else {
            throw RuntimePreparationError.changedScope
        }
        return .terminal(row)
    }
    private static func prepareUnboundStartupFrame(frame: Frame, hasExplicitAuthority: Bool,
        startupPhases: SetupRetainedInvocationReservation.RestorationPhases?,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken,
        verify: @escaping @Sendable () throws -> Void,
        read: () throws -> Frame, persistFailure: (Record, Record, Frame) throws -> Transition,
        persistDiscard: (Record, UnboundStartupDiscardAuthorization, Frame) throws -> Transition) throws -> Frame {
        guard !hasExplicitAuthority, frame.window?.unboundRelease != nil else { return frame }
        guard let startupPhases else { throw RuntimePreparationError.changedScope }
        return try unboundStartupPreflight(frame: frame, startupPhases: startupPhases,
            directory: directory, admission: admission, drain: drain, verify: verify,
            read: read, persistFailure: persistFailure, persistDiscard: persistDiscard)
    }
    private static func unboundStartupPreflight(frame initial: Frame,
        startupPhases: SetupRetainedInvocationReservation.RestorationPhases,
        directory: ReleaseDestinationLease, admission: UpdateOrdinaryAdmissionLease, drain: UpdateDrainToken,
        verify: @escaping @Sendable () throws -> Void,
        read: () throws -> Frame, persistFailure: (Record, Record, Frame) throws -> Transition,
        persistDiscard: (Record, UnboundStartupDiscardAuthorization, Frame) throws -> Transition) throws -> Frame {
        try startupPhases.requireUnboundStartupPhase(); try verify()
        guard var previous = initial.window, previous.unboundRelease != nil else { return initial }
        var frame = initial
        if previous.phase == .reopenPending {
            let next = try RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                service: .notStopped, failure: .admissionUnconfirmed)
            let receipt = try persistFailure(next, previous, frame)
            try receipt.requireReplacement(next, replacing: previous)
            frame = try read(); guard frame.window == next else { throw PreparationStoreError.staleRevision }
            previous = next
        }
        let authorization = try UnboundStartupDiscardAuthorization(frame: frame, directory: directory,
            admission: admission, drain: drain, startupPhases: startupPhases, verify: verify)
        let receipt = try persistDiscard(previous, authorization, frame)
        try receipt.requireReplacement(receipt.record, replacing: previous)
        try receipt.record.requireUnboundStartupDiscardReplacing(previous)
        let result = try read()
        guard result.window == receipt.record else { throw PreparationStoreError.staleRevision }
        try verify()
        return result
    }
    private func blockingPhase<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value {
        if let phases { return try await phases.run(body) }
        return try body()
    }
    private func cleanupPhase<Value: Sendable>(_ body: @escaping @Sendable () throws -> Value) async throws -> Value {
        if let phases { return try await phases.cleanup(body) }
        return try body()
    }
    /// Preserve a real final receipt if the caller disappears after its confirmed restored write.
    /// The registered task closes custody before its result can release either retained admission.
    private func finishExplicit(workID: UUID, operation: @Sendable () async throws -> Record) async throws -> ExplicitCompletion {
        let failure: (any Error)?
        do {
            let row = try await operation()
            guard row == custody.current else { throw PreparationStoreError.staleRevision }
            failure = nil
        } catch { failure = error }
        return try await cleanupPhase {
            if self.custody.current.phase == .restored {
                return try ExplicitCompletion(window: self.custody.current, workID: workID, custody: self.custody, originalRunFailed: failure != nil)
            }
            if let failure { throw failure }
            throw AuthorityMaintenanceClientError.needsOwnerRecovery
        }
    }

    /// A one-shot synchronous dispatcher. A probe is the only branch that continues after this returns.
    fileprivate func prepare() throws -> Result {
        try lock.withLock {
            guard !prepared else { throw JournalLeaseError.invalidated }; prepared = true
            let row = custody.current
            _ = try custody.requireCurrent(row)
            if let explicitAuthority {
                try explicitAuthority.requireWindow(row)
                guard row.phase == .needsOwnerRecovery else { throw PreparationStoreError.invalidTransition }
                if row.service == .notStopped && row.operation == .notStarted {
                    probePending = true; return .probeRequired
                }
                return .restoration(try restoring(row))
            }
            switch try RuntimeMaintenanceStartupPolicy.initial(row) {
            case .nothing: return .nothing
            case .ownerRecovery(let failure): return .ownerRecovery(try recover(row, failure: failure))
            case .probeIncarnation: probePending = true; return .probeRequired
            case .observeOperation:
                let operation = RuntimeMaintenanceStartupPolicy.operation(observeOperation(row))
                _ = try custody.requireCurrent(row)
                let settled = try RuntimeMaintenanceStartupPolicy.row(row, phase: .workSettled, operation: operation, service: .stopped)
                _ = try custody.persist(settled, previous: row)
                return .restoration(try restoring(settled))
            case .restore: return .restoration(try restoring(row))
            case .cancelAndReopen, .restartRestoration: throw PreparationStoreError.invalidTransition
            }
        }
    }
    /// The decision uses only the authenticated proof. The caller closes this client before restart work.
    fileprivate func afterAuthenticatedProbe(_ proof: AuthorityMaintenanceIncarnationProof,
        client: AuthorityMaintenanceXPCClient) throws -> RuntimeMaintenanceStartupPolicy.Action {
        try lock.withLock {
            guard prepared, probePending else { throw JournalLeaseError.invalidated }
            let row = custody.current
            do { try proof.requireObserved(by: client) }
            catch { throw RuntimeMaintenanceStartupAttemptError.beforePending }
            guard let target = row.shutdownBinding, proof.accountID == row.scope.authority.accountID else {
                throw RuntimePreparationError.changedScope
            }
            probePending = false
            if let explicitAuthority {
                try explicitAuthority.requireWindow(row)
                guard row.phase == .needsOwnerRecovery, row.operation == .notStarted, row.service == .notStopped else {
                    throw PreparationStoreError.invalidTransition
                }
                if proof.incarnation == target.incarnation {
                    do { try explicitAuthority.requireSavedTargetReconnect(row) }
                    catch { throw RuntimeMaintenanceStartupFailure(.repairRequired, error) }
                    return .cancelAndReopen
                }
                return .restartRestoration
            }
            return try afterProbePolicy(row, proof.incarnation == target.incarnation)
        }
    }
    private struct OwnedClients: Sendable {
        let makeDriver: @Sendable () throws -> any AuthorityMaintenanceClientDriver
        let capturePeer: @Sendable () throws -> any RuntimeJobExitWitness
        let requirePeerLive: @Sendable (any RuntimeJobExitWitness) throws -> Void
        let beforeHealthyOpen: @Sendable (AuthorityMaintenanceXPCClient) async -> Void
        let afterProbe: @Sendable () -> Void
        let beforeCancel: @Sendable (AuthorityMaintenanceXPCClient) async -> Void
        let phaseControl: AuthorityMaintenanceXPCClient.OwnedRestorationPhaseControl?
    }
    private enum ClientMode { case native, owned(OwnedClients) }
    func runNative(until deadline: ContinuousClock.Instant) async throws -> Record {
        guard getuid() == 0, geteuid() == 0, custody.native else { throw JournalLeaseError.rootRequired }
        return try await run(mode: .native, until: deadline)
    }
    func runOwned(makeDriver: @escaping @Sendable () throws -> any AuthorityMaintenanceClientDriver,
        capturePeer: @escaping @Sendable () throws -> any RuntimeJobExitWitness,
        requirePeerLive: @escaping @Sendable (any RuntimeJobExitWitness) throws -> Void,
        beforeHealthyOpen: @escaping @Sendable (AuthorityMaintenanceXPCClient) async -> Void = { _ in },
        afterProbe: @escaping @Sendable () -> Void = {},
        beforeCancel: @escaping @Sendable (AuthorityMaintenanceXPCClient) async -> Void = { _ in },
        ownedPhaseControl: AuthorityMaintenanceXPCClient.OwnedRestorationPhaseControl? = nil,
        until deadline: ContinuousClock.Instant) async throws -> Record {
        try RuntimeMaintenanceOwnedControl.require()
        guard !custody.native else { throw JournalLeaseError.unsafeMetadata }
        return try await run(mode: .owned(.init(makeDriver: makeDriver, capturePeer: capturePeer,
            requirePeerLive: requirePeerLive, beforeHealthyOpen: beforeHealthyOpen,
            afterProbe: afterProbe, beforeCancel: beforeCancel, phaseControl: ownedPhaseControl)), until: deadline)
    }
    private func makeClient(_ mode: ClientMode, context: AuthorityMaintenanceChannelRequest) throws -> AuthorityMaintenanceXPCClient {
        try explicitAuthority?.willUseForwardEffects()
        switch mode {
        case .native:
            guard let setup = custody.floor.host.codePolicy.entries.first(where: { $0.role == .setupController && $0.active }) else {
                throw RuntimePreparationError.changedScope
            }
            return try .init(context: context, authority: custody.floor.code, setup: setup, release: custody.release, recoveryPhases: nativePhases)
        case .owned(let owned):
            if let work = ownedSupervisorWork {
                return try .openOwned(context: context, driver: owned.makeDriver(), verify: work.verifyClient,
                    recoveryPhases: work.phases, ownedSupervisorControl: work.control)
            }
            return try .openOwned(context: context, driver: owned.makeDriver())
        }
    }
    private func observe(_ client: AuthorityMaintenanceXPCClient, mode: ClientMode,
        until deadline: ContinuousClock.Instant) async throws -> AuthorityMaintenanceIncarnationProof {
        switch mode {
        case .native: return try await client.observeIncarnationNative(until: deadline)
        case .owned: return try await client.observeIncarnationOwned(until: deadline)
        }
    }
    private func run(mode: ClientMode, until deadline: ContinuousClock.Instant) async throws -> Record {
        // A repeated call cannot reach the fallback writer of the first call.
        try lock.withLock {
            guard !runUsed else { throw JournalLeaseError.invalidated }
            runUsed = true
        }
        var reconnectOrigin: Record?
        do {
            try Task.checkCancellation()
            let owner: RuntimeMaintenanceRestoration
            switch try await blockingPhase({ try self.prepare() }) {
            case .nothing: return window
            case .ownerRecovery(let row): return row
            case .restoration(let prepared): owner = try await blockingPhase { try .openStartup(prepared) }
            case .probeRequired:
                let row = window
                let context = try AuthorityMaintenanceChannelRequest(action: .open,
                    accountID: row.scope.authority.accountID, attemptID: row.id, revision: continuationRevision,
                    installationID: row.scope.installationID, gate: custody.floor.cohort.accountIdentity,
                    binding: nil, challenge: AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID())
                let (client, proof, decision) = try await decisionProbe(mode, context: context, until: deadline)
                do {
                    if decision == .cancelAndReopen {
                        let restored: Record
                        let explicitReconnect: ExplicitReconnect?
                        if let explicitAuthority {
                            reconnectOrigin = row
                            explicitReconnect = try await blockingPhase {
                                try explicitAuthority.requireWindow(row)
                                let restoring = try RuntimeMaintenanceStartupPolicy.row(row, phase: .restoring, service: .restartPending)
                                _ = try self.custody.persist(restoring, previous: row)
                                return try ExplicitReconnect(custody: self.custody, window: restoring, origin: row, phases: explicitAuthority.phases)
                            }
                        } else { explicitReconnect = nil }
                        switch mode {
                        case .native:
                            if let explicitReconnect {
                                restored = try await client.cancelAndReopenExplicitNative(proof, prepared: explicitReconnect, until: deadline)
                            } else {
                                restored = try await client.cancelAndReopenStartupNative(proof, custody: custody, until: deadline, phases: phases)
                            }
                        case .owned(let owned):
                            await owned.beforeCancel(client)
                            if let explicitReconnect {
                                restored = try await client.cancelAndReopenExplicitOwned(proof, prepared: explicitReconnect, until: deadline, ownedPhaseControl: owned.phaseControl)
                            } else {
                                restored = try await client.cancelAndReopenStartupOwned(proof, custody: custody, until: deadline, phases: nativePhases)
                            }
                        }
                        await client.close()
                        return restored
                    }
                } catch {
                    await client.close()
                    throw error
                }
                // No store write, registration or process observation uses the decision connection.
                await client.close()
                switch decision {
                case .ownerRecovery(let failure): return try await blockingPhase { try self.recover(self.window, failure: failure) }
                case .restartRestoration:
                    if explicitAuthority != nil {
                        owner = try await blockingPhase { try .openStartup(self.restoring(self.window)) }; break
                    }
                    let previous = window
                    let bridge = try RuntimeMaintenanceStartupPolicy.row(previous, phase: .needsOwnerRecovery,
                        service: previous.service, failure: .serviceUnavailable)
                    owner = try await blockingPhase {
                        _ = try self.custody.persistRestartBridge(bridge, previous: previous)
                        return try .openStartup(self.restoring(bridge))
                    }
                default: throw PreparationStoreError.invalidTransition
                }
            case .cancelAndReopen: throw PreparationStoreError.invalidTransition
            }
            return try await restoreHealthy(owner, mode: mode, until: deadline)
        } catch {
            let cancelled = Task.isCancelled || error is CancellationError
            let row = window
            if explicitAuthority != nil || !cancelled {
                // A deadline can stop a phase before its body starts. Use the last confirmed row.
                // An uncertain writer invalidates custody and still refuses this cleanup write.
                let pending = row.phase == .reopenPending
                let reconnect = reconnectOrigin != nil && row.phase == .restoring
                let fallback: Record.Failure = pending ? .admissionUnconfirmed
                    : reconnect ? reconnectOrigin?.failure ?? .cleanupPending : .healthFailed
                let failure: Record.Failure = pending ? .admissionUnconfirmed
                    : explicitAuthority != nil && cancelled ? fallback : Self.failure(error, fallback: .healthFailed)
                let service: Record.ServiceOutcome? = reconnect ? .notStopped : nil
                _ = try? await cleanupPhase { try self.custody.persistRecovery(row, failure: failure, service: service) }
            }
            if cancelled { throw CancellationError() }
            if let failure = error as? RuntimeMaintenanceStartupFailure { throw failure.underlying }
            throw error
        }
    }
    private func decisionProbe(_ mode: ClientMode, context: AuthorityMaintenanceChannelRequest,
        until deadline: ContinuousClock.Instant) async throws -> (AuthorityMaintenanceXPCClient, AuthorityMaintenanceIncarnationProof, RuntimeMaintenanceStartupPolicy.Action) {
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            _ = try await blockingPhase { try self.custody.requireCurrent(self.window) }
            let client = try await blockingPhase { try self.makeClient(mode, context: context) }
            do {
                let proof = try await observe(client, mode: mode, until: deadline)
                if case .owned(let owned) = mode { owned.afterProbe() }
                try Task.checkCancellation()
                let decision = try await blockingPhase { try self.afterAuthenticatedProbe(proof, client: client) }
                return (client, proof, decision)
            } catch {
                await client.close(); try Task.checkCancellation()
                guard error is AuthorityMaintenanceClientError || error is RuntimeMaintenanceStartupAttemptError else { throw error }
                _ = try await blockingPhase { try self.custody.requireCurrent(self.window) }
                try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: .milliseconds(250))))
            }
        }
        throw RuntimeMaintenanceStartupFailure(.serviceUnavailable, AuthorityMaintenanceClientError.needsOwnerRecovery)
    }
    private func restoreHealthy(_ owner: RuntimeMaintenanceRestoration, mode: ClientMode,
        until deadline: ContinuousClock.Instant) async throws -> Record {
        var refreshWitness = false
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            let discardWitness = refreshWitness
            try await blockingPhase {
                try self.custody.requireBeforePendingRetry()
                if discardWitness { try owner.discardStartupCandidate() }
            }
            try await requireRestoringProcess(until: deadline)
            // Check protected metadata and job liveness before creating the new connection.
            let context = try await blockingPhase {
                try owner.validateBeforePending()
                return try owner.openRequest(challenge: AccountPreparationIntent.randomID() + AccountPreparationIntent.randomID())
            }
            let client = try await blockingPhase { try self.makeClient(mode, context: context) }
            do {
                let proof: AuthorityMaintenanceIncarnationProof
                do { proof = try await observe(client, mode: mode, until: deadline) }
                catch { throw RuntimeMaintenanceStartupAttemptError.beforePending }
                let restored: Record
                switch mode {
                case .native:
                    restored = try await client.restoreStartupHealthyNative(proof, owner: owner, until: deadline,
                        persist: { try self.custody.persistNative($0, previous: $1) }, phases: phases)
                case .owned(let owned):
                    await owned.beforeHealthyOpen(client)
                    restored = try await client.restoreStartupHealthyOwned(proof, owner: owner,
                        capturePeer: owned.capturePeer, requirePeerLive: owned.requirePeerLive, afterProbe: owned.afterProbe, until: deadline,
                        persist: { try self.custody.persistOwned($0, previous: $1) }, phases: phases, ownedPhaseControl: owned.phaseControl)
                }
                await client.close()
                return restored
            } catch {
                await client.close()
                try Task.checkCancellation()
                guard case RuntimeMaintenanceStartupAttemptError.beforePending = error else { throw error }
                // Scope failures and policy refusals end the run instead of entering a hidden retry loop.
                try await blockingPhase { try self.custody.requireRestoring(owner.window) }
                refreshWitness = true
                try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: .milliseconds(250))))
            }
        }
        throw RuntimeMaintenanceStartupFailure(.healthFailed, AuthorityMaintenanceClientError.needsOwnerRecovery)
    }
    static func failure(_ error: Error, fallback: Record.Failure) -> Record.Failure {
        if let failure = error as? RuntimeMaintenanceStartupFailure { return failure.failure }
        if error is AuthorityMaintenanceClientError { return .healthFailed }
        if error is RuntimePreparationError || error is PreparationStoreError || error is JournalLeaseError { return .changedScope }
        if error is RuntimeActivationError { return .serviceUnavailable }
        return fallback
    }
    private func recover(_ row: Record, failure: Record.Failure) throws -> Record {
        try custody.persistRecovery(row, failure: failure)
    }
    private func restoring(_ previous: Record) throws -> PreparedRestoration {
        try explicitAuthority?.willUseForwardEffects()
        let restoring: Record, receipt: Transition?
        // An explicit restoring row is already authorized. After a crash, automatic M09d
        // resumes it with fresh custody and the same healthy path as its own restoring row.
        if previous.phase == .restoring { restoring = previous; receipt = nil }
        else {
            restoring = try RuntimeMaintenanceStartupPolicy.row(previous, phase: .restoring, service: .restartPending,
                revision: continuationRevision)
            receipt = try custody.persist(restoring, previous: previous)
        }
        try custody.requireRestoring(restoring)
        do {
            if try custody.inspect(custody.floor.cohort.job) == .absent { try register(custody, restoring) }
        } catch {
            throw RuntimeMaintenanceStartupFailure(Self.failure(error, fallback: .serviceUnavailable), error)
        }
        try custody.requireRestoring(restoring)
        return .init(custody: custody, window: restoring, previous: previous, receipt: receipt)
    }
    private func requireRestoringProcess(until deadline: ContinuousClock.Instant) async throws {
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            try await blockingPhase { try self.custody.requireRestoring(self.window) }
            let live: Bool
            do {
                live = try await blockingPhase {
                    switch try self.custody.inspect(self.custody.floor.cohort.job) {
                    case .absent, .matching(nil): return false
                    case .conflicting: throw RuntimeActivationError.unavailable
                    case .matching(let pid?):
                        guard pid > 1 else { throw RuntimeActivationError.unavailable }
                        let observed = try self.custody.observe(self.custody.floor.cohort.job, self.custody.floor.code, pid)
                        guard observed.processID == pid, try !observed.hasExited(),
                              try self.custody.inspect(self.custody.floor.cohort.job) == .matching(pid) else {
                            throw RuntimeActivationError.unavailable
                        }
                        return true
                    }
                }
            } catch { throw RuntimeMaintenanceStartupFailure(Self.failure(error, fallback: .serviceUnavailable), error) }
            if live { return }
            try await ContinuousClock().sleep(until: min(deadline, .now.advanced(by: .milliseconds(250))))
        }
        throw RuntimeMaintenanceStartupFailure(.serviceUnavailable, RuntimeActivationError.unavailable)
    }
}
