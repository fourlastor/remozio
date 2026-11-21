import Darwin
import Foundation

/// Retains host placement until admitted Setup work and recovery have joined.
final class AdministrativeSetupShutdown: @unchecked Sendable {
    /// Only the shutdown finalizer can mint cancellation authority.
    final class RecoveryCancellation: Sendable { fileprivate init() {} }
    private let recoveryCancellation = RecoveryCancellation()

    /// Retains one real session task until shutdown has observed its actual return.
    final class RecoverySessionWork: @unchecked Sendable {
        private enum Publication: Equatable { case idle, reserved, published, neverCreated }
        struct OwnedPublicationControl: Sendable {
            let beforeRetaining: @Sendable () -> Void
            init(beforeRetaining: @escaping @Sendable () -> Void) throws {
                try RuntimeMaintenanceOwnedControl.require(); self.beforeRetaining = beforeRetaining
            }
        }
        private let ownedPublicationControl: OwnedPublicationControl?
        let id = UUID()
        private let lock = NSLock()
        private var publication = Publication.idle
        private var task: Task<Void, Never>?
        private var restoration: SetupRetainedInvocationReservation.RestorationWork?
        private var endpointClose: (@Sendable () -> Void)?
        private var publicationWaiters: [CheckedContinuation<Void, Never>] = []
        private var shutdownCancellation: RecoveryCancellation?
        private var shutdownRequested = false
        private var joined = false
        private var connectionClosed = false
        private var retirement: Task<Void, Never>?
        private let didRetire: @Sendable (UUID) -> Void

        fileprivate init(didRetire: @escaping @Sendable (UUID) -> Void = { _ in },
            ownedPublicationControl: OwnedPublicationControl? = nil) {
            self.didRetire = didRetire; self.ownedPublicationControl = ownedPublicationControl
        }
        static func owned() throws -> RecoverySessionWork {
            try RuntimeMaintenanceOwnedControl.require(); return .init()
        }
        func bindEndpointClose(_ close: @escaping @Sendable () -> Void) {
            let alreadyClosing = lock.withLock { endpointClose = close; return shutdownRequested }
            if alreadyClosing { close() }
        }
        func reservePublication() -> Bool {
            lock.withLock {
                guard !shutdownRequested, !joined, publication == .idle else { return false }
                publication = .reserved; return true
            }
        }
        func publish(_ actual: Task<Void, Never>) {
            let (cancel, waiters) = lock.withLock {
                precondition(publication == .reserved && task == nil)
                task = actual; publication = .published
                let waiters = publicationWaiters; publicationWaiters = []
                return (shutdownRequested, waiters)
            }
            if cancel { actual.cancel() }
            for waiter in waiters { waiter.resume() }
        }
        func resolveWithoutWork() {
            let waiters = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
                guard publication == .reserved || publication == .idle else { return [] }
                publication = .neverCreated
                let waiters = publicationWaiters; publicationWaiters = []; return waiters
            }
            for waiter in waiters { waiter.resume() }
        }
        func retainRestoration(_ actual: SetupRetainedInvocationReservation.RestorationWork) {
            ownedPublicationControl?.beforeRetaining()
            let (cancel, retired) = lock.withLock {
                let retired = restoration; restoration = actual
                return (shutdownCancellation, retired)
            }
            if let cancel { actual.requestCancellation(using: cancel) }
            withExtendedLifetime(retired) {}
        }
        fileprivate func requestShutdown(using cancellation: RecoveryCancellation) {
            let values = lock.withLock {
                shutdownRequested = true; shutdownCancellation = cancellation
                let waiters: [CheckedContinuation<Void, Never>]
                if publication == .idle {
                    publication = .neverCreated; waiters = publicationWaiters; publicationWaiters = []
                } else { waiters = [] }
                return (endpointClose, task, restoration, waiters)
            }
            values.0?()
            values.2?.requestCancellation(using: cancellation)
            values.1?.cancel()
            for waiter in values.3 { waiter.resume() }
        }
        func connectionDidClose() {
            let waiters = lock.withLock { () -> [CheckedContinuation<Void, Never>] in
                guard !connectionClosed else { return [] }
                connectionClosed = true
                if publication == .idle { publication = .neverCreated }
                let waiters: [CheckedContinuation<Void, Never>]
                if publication == .neverCreated { waiters = publicationWaiters; publicationWaiters = [] }
                else { waiters = [] }
                if retirement == nil {
                    retirement = Task {
                        await self.joinActualWork()
                        self.didRetire(self.id)
                        self.lock.withLock { self.retirement = nil }
                    }
                }
                return waiters
            }
            for waiter in waiters { waiter.resume() }
        }
        private func waitForPublication() async {
            await withCheckedContinuation { continuation in
                let ready = lock.withLock {
                    if publication == .published || publication == .neverCreated { return true }
                    publicationWaiters.append(continuation); return false
                }
                if ready { continuation.resume() }
            }
        }
        fileprivate func observeActualWork() async {
            guard lock.withLock({ publication != .idle }) else { return }
            await waitForPublication()
            let actual = lock.withLock { task }
            await actual?.value
            let restoration = lock.withLock { self.restoration }
            if let restoration { _ = try? await restoration.value() }
        }
        fileprivate func joinActualWork() async {
            await waitForPublication()
            let actual = lock.withLock { task }
            await actual?.value
            let restoration = lock.withLock { self.restoration }
            if let restoration { _ = try? await restoration.value() }
            let retired = lock.withLock {
                joined = true
                let retired = (task, self.restoration, endpointClose)
                task = nil; self.restoration = nil; endpointClose = nil
                return retired
            }
            withExtendedLifetime(retired) {}
        }
    }

    private var recoverySessions: [UUID: RecoverySessionWork] = [:]
    private var recoverySessionAdmissionClosed = false
    private var recoverySessionJoin: Task<Void, Never>?
    private var recoverySessionsJoined = false

    private final class RecoverySupervisorRegistration: @unchecked Sendable {
        private let lock = NSLock()
        private weak var supervisor: SetupMaintenanceRecoverySupervisor?
        private let expectsPublication: Bool
        private var disposal: Task<Void, Never>?
        private var published = false, released = false
        init(expectsPublication: Bool) { self.expectsPublication = expectsPublication }
        func retainDisposal(_ actual: Task<Void, Never>) {
            let waiters = lock.withLock {
                disposal = actual
                let waiters = releaseWaiters; releaseWaiters = []; return waiters
            }
            for waiter in waiters { waiter.resume() }
        }
        private var publicationWaiters: [CheckedContinuation<Void, Never>] = []
        private var releaseWaiters: [CheckedContinuation<Void, Never>] = []
        func publish(_ actual: SetupMaintenanceRecoverySupervisor) {
            let waiters = lock.withLock {
                guard !released else { return [CheckedContinuation<Void, Never>]() }
                supervisor = actual; published = true
                let waiters = publicationWaiters; publicationWaiters = []; return waiters
            }
            for waiter in waiters { waiter.resume() }
        }
        func finish() {
            let waiters = lock.withLock {
                released = true
                let waiters = publicationWaiters + releaseWaiters
                publicationWaiters = []; releaseWaiters = []; return waiters
            }
            for waiter in waiters { waiter.resume() }
        }
        func closeAndJoin() async -> Bool {
            await withCheckedContinuation { continuation in
                let ready = lock.withLock {
                    if published || released || !expectsPublication { return true }
                    publicationWaiters.append(continuation); return false
                }
                if ready { continuation.resume() }
            }
            if let actual = lock.withLock({ supervisor }) {
                await actual.close()
                return true
            } else {
                guard lock.withLock({ published || released }) else { return false }
                await withCheckedContinuation { continuation in
                    let ready = lock.withLock {
                        if released || disposal != nil { return true }
                        releaseWaiters.append(continuation); return false
                    }
                    if ready { continuation.resume() }
                }
                let actual = lock.withLock { disposal }
                await actual?.value
                return true
            }
        }
    }
    private var recoverySupervisorRegistration: RecoverySupervisorRegistration?
    private var directClose: (id: UUID, task: Task<Void, any Error>)?


    func registerRecoverySession(owner candidate: SetupAccountOwner) throws -> RecoverySessionWork {
        try registerRecoverySession(owner: candidate, publicationControl: nil)
    }
    func registerRecoverySessionOwned(owner candidate: SetupAccountOwner,
        publicationControl: RecoverySessionWork.OwnedPublicationControl) throws -> RecoverySessionWork {
        try RuntimeMaintenanceOwnedControl.require()
        return try registerRecoverySession(owner: candidate, publicationControl: publicationControl)
    }
    private func registerRecoverySession(owner candidate: SetupAccountOwner,
        publicationControl: RecoverySessionWork.OwnedPublicationControl?) throws -> RecoverySessionWork {
        try processLease.validate()
        return try lock.withLock {
            guard !closed, !externalClosing, !recoverySessionAdmissionClosed, owner === candidate else {
                throw AdministrativeSetupError.unavailable
            }
            let work = RecoverySessionWork(didRetire: { [weak self] id in self?.retireRecoverySession(id) },
                ownedPublicationControl: publicationControl)
            recoverySessions[work.id] = work; return work
        }
    }
    private func retireRecoverySession(_ id: UUID) {
        let retired = lock.withLock { recoverySessions.removeValue(forKey: id) }
        withExtendedLifetime(retired) {}
    }
    var acceptsRecoverySessions: Bool {
        lock.withLock { !closed && !externalClosing && !recoverySessionAdmissionClosed }
    }
    func observeRecoverySessionsForDisposal() async {
        let sessions = lock.withLock { Array(recoverySessions.values) }
        for session in sessions { await session.observeActualWork() }
    }
    func joinRecoverySessions() async {
        closeRecoverySessionAdmission()
        let actual = lock.withLock {
            if let recoverySessionJoin { return recoverySessionJoin }
            let sessions = Array(recoverySessions.values)
            let actual = Task {
                for session in sessions { await session.joinActualWork() }
                let retired = self.lock.withLock {
                    let retired = self.recoverySessions; self.recoverySessions = [:]
                    self.recoverySessionsJoined = true; return retired
                }
                withExtendedLifetime(retired) {}
            }
            recoverySessionJoin = actual; return actual
        }
        await actual.value
    }

    enum RecoveryCloseResult: Equatable, Sendable { case closed, pending, failed, timedOut }
    private let lock = NSLock()
    private var owner: SetupAccountOwner?
    private let placement: ReleaseDestinationLease
    private let processLease: SetupProcessLease
    private var closed = false, recoveryBound = false, externalClosing = false
    private var recoveryRetention: (any Sendable)?
    init(owner: SetupAccountOwner, placement: ReleaseDestinationLease, processLease: SetupProcessLease) {
        self.owner = owner; self.placement = placement; self.processLease = processLease
    }
    init(placement: ReleaseDestinationLease, processLease: SetupProcessLease) {
        self.placement = placement; self.processLease = processLease
    }
    func bind(_ candidate: SetupAccountOwner) throws {
        try lock.withLock {
            guard !closed, !externalClosing, owner == nil else { throw AdministrativeSetupError.unavailable }
            owner = candidate
        }
    }
    func belongs(to candidate: SetupAccountOwner) -> Bool { lock.withLock { owner === candidate } }
    func validateRecoveryCustody() throws { try processLease.validate() }
    private func closeRecoverySessionAdmission() {
        let sessions = lock.withLock {
            recoverySessionAdmissionClosed = true; return Array(recoverySessions.values)
        }
        for session in sessions { session.requestShutdown(using: recoveryCancellation) }
    }
    func closeRecoveryAdmission() {
        closeRecoverySessionAdmission()
        lock.withLock { owner }?.closeMaintenanceRecoveryAdmission()
    }
    func bindRecoverySupervisor(_ actual: SetupMaintenanceRecoverySupervisor) {
        lock.withLock { recoverySupervisorRegistration }?.publish(actual)
    }
    func retainRecoverySupervisorDisposal(_ actual: Task<Void, Never>) {
        lock.withLock { recoverySupervisorRegistration }?.retainDisposal(actual)
    }
    func reserveRecoverySupervisor(expectsPublication: Bool) throws {
        try lock.withLock {
            guard !closed, !recoveryBound, !externalClosing else { throw AdministrativeSetupError.unavailable }
            recoveryBound = true; recoverySupervisorRegistration = RecoverySupervisorRegistration(expectsPublication: expectsPublication)
        }
    }
    func retainRecoverySupervisor(_ custody: any Sendable) { lock.withLock { recoveryRetention = custody } }
    /// Ordinary supervisor disposal joins its tasks but leaves the Setup lifecycle to its caller.
    private func releaseRecoverySupervisorAfterJoining() {
        let retired = lock.withLock {
            let retired = (recoverySupervisorRegistration, recoveryRetention)
            recoveryBound = false; recoveryRetention = nil; recoverySupervisorRegistration = nil
            return retired
        }
        retired.0?.finish()
        withExtendedLifetime(retired.1) {}
    }
    /// One attempt after every recovery join. Failure keeps both leases and remains retryable by the lifecycle owner.
    private func closeAfterRecoveryJoined() -> RecoveryCloseResult {
        guard let owner = lock.withLock({ recoveryBound && (recoverySessionsJoined || recoverySessions.isEmpty) ? owner : nil }) else { return .failed }
        closeRecoveryAdmission()
        guard owner.retryAuditUpgradeCleanup() else { return .pending }
        do { try owner.close() } catch AdministrativeSetupError.unavailable { return .pending }
        catch { return .failed }
        lock.withLock {
            if !closed { placement.close(); processLease.close(); closed = true }
        }
        releaseRecoverySupervisorAfterJoining()
        return .closed
    }
    /// Only this factory exports the supervisor. Its close and release capabilities never escape to the service.
    func recoverySupervisor(owner: SetupAccountOwner) throws -> SetupMaintenanceRecoverySupervisor {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard belongs(to: owner) else { throw RuntimePreparationError.changedScope }
        return try SetupMaintenanceRecoveryNativeAdapter.supervisor(owner: owner, shutdown: self,
            closeAfterJoining: { self.closeAfterRecoveryJoined() },
            releaseAfterJoining: { self.releaseRecoverySupervisorAfterJoining() })
    }
    func closeAfterRecoveryJoinedOwned() throws -> RecoveryCloseResult {
        try RuntimeMaintenanceOwnedControl.require(); return closeAfterRecoveryJoined()
    }
    func releaseRecoverySupervisorOwned() throws {
        try RuntimeMaintenanceOwnedControl.require(); releaseRecoverySupervisorAfterJoining()
    }
    func close() async throws {
        closeRecoveryAdmission()
        let actual = lock.withLock {
            externalClosing = true
            if let directClose { return directClose.task }
            let id = UUID(), registration = recoverySupervisorRegistration
            let actual = Task<Void, any Error> {
                defer {
                    self.lock.withLock { if self.directClose?.id == id { self.directClose = nil } }
                }
                if let registration, !(await registration.closeAndJoin()) {
                    throw AdministrativeSetupError.unavailable
                }
                await self.joinRecoverySessions()
                let state = self.lock.withLock { (self.closed, self.recoveryBound, self.owner) }
                if state.0 { return }
                guard !state.1 else { throw AdministrativeSetupError.unavailable }
                if let owner = state.2 { try await owner.closeWhenIdle() }
                self.lock.withLock {
                    if !self.closed { self.placement.close(); self.processLease.close(); self.closed = true }
                }
            }
            directClose = (id, actual); return actual
        }
        try await actual.value
    }
}
