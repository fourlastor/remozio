import Darwin
import Foundation

/// The lifecycle owner joins its remaining work before releasing the process custody.
protocol SetupMaintenanceRecoveryWorkCustody: AnyObject, Sendable {
    func validate() throws
    func validateForRecovery() async -> Bool
}
protocol SetupMaintenanceRecoveryFinalClose: AnyObject, Sendable {
    func joinRecoverySessions() async
    func observeRecoverySessionsForDisposal() async
    func retainSupervisorDisposal(_ actual: Task<Void, Never>)
    func closeAfterJoining() async
    func closeAdmission()
    func closeAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult
    func retryCloseAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult
    func releaseAfterJoining()
}
extension SetupMaintenanceRecoveryFinalClose {
    func retryCloseAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
        await closeAfterJoiningResult()
    }
}
/// The combined interface remains an Owned fixture adapter. Native work receives the separate work interface.
protocol SetupMaintenanceRecoveryProcessCustody: SetupMaintenanceRecoveryWorkCustody, SetupMaintenanceRecoveryFinalClose {}
extension SetupMaintenanceRecoveryProcessCustody {
    // Existing ordinary-owner fixtures retain their synchronous validation and close hooks.
    func validateForRecovery() async -> Bool { do { try validate(); return true } catch { return false } }
    func closeAdmission() {}
    func closeAfterJoiningResult() async -> AdministrativeSetupShutdown.RecoveryCloseResult {
        await closeAfterJoining(); return .closed
    }
    func releaseAfterJoining() {}
}

/// Scheduling only. The owned factory cannot construct native recovery or authorize a store write.
actor SetupMaintenanceRecoverySupervisor {
    struct Key: Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        let accountID: Data, windowID: Data
        init(accountID: Data, windowID: Data) throws {
            guard accountID.count == 16, windowID.count == 16 else { throw RuntimePreparationError.invalidRecord }
            self.accountID = accountID; self.windowID = windowID
        }
        var description: String { "SetupMaintenanceRecoveryKey(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: [:]) }
    }
    struct Request: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        let key: Key
        let revision: Data
        init(accountID: Data, windowID: Data, revision: Data) throws {
            key = try .init(accountID: accountID, windowID: windowID)
            guard revision.count == 16 else { throw RuntimePreparationError.invalidRecord }
            self.revision = revision
        }
        var description: String { "SetupMaintenanceRecoveryRequest(redacted)" }
        var debugDescription: String { description }
        var customMirror: Mirror { Mirror(self, children: [:]) }
    }
    enum Observation: Equatable, Sendable, CustomStringConvertible {
        case recovering, joining, busy, noWindow, phase(RuntimeMaintenanceWindowRecord.Phase)
        case failed(RuntimeMaintenanceWindowRecord.Failure), cancelled, retired
        var description: String { "SetupMaintenanceRecoveryObservation(redacted)" }
    }
    struct Owner: Sendable {
        fileprivate let run: @Sendable (ContinuousClock.Instant) async throws -> Observation
        fileprivate let cancel: @Sendable () -> Void
        fileprivate let join: @Sendable () async -> Void
        /// Cancellation is idempotent. Join waits for actual work even after an earlier close failed.
        init(run: @escaping @Sendable (ContinuousClock.Instant) async throws -> Observation,
             cancel: @escaping @Sendable () -> Void = {}, join: @escaping @Sendable () async -> Void) {
            self.run = run; self.cancel = cancel; self.join = join
        }
    }
    enum Acquisition: Sendable { case busyBeforeOwner, terminal(Observation), owner(Owner) }
    struct Driver: Sendable {
        let acquire: @Sendable (Request, ContinuousClock.Instant) async throws -> Acquisition
    }
    struct Timing: Sendable {
        let now: @Sendable () -> ContinuousClock.Instant
        let sleep: @Sendable (ContinuousClock.Instant) async throws -> Void
        static let continuous = Timing(now: { .now }, sleep: { try await ContinuousClock().sleep(until: $0) })
    }
    private struct Entry: Sendable {
        let task: Task<Void, Never>
        let request: Request
        var observation: Observation = .recovering
        var finished = false
    }
    private let processID = getpid(), ownerUID = getuid()
    private let custody: any SetupMaintenanceRecoveryWorkCustody
    private let finalClose: any SetupMaintenanceRecoveryFinalClose
    private let publish: @Sendable (Request, Observation) -> Void
    private var initialWaiters: [UUID: AsyncStream<Void>.Continuation] = [:]
    private let runner: Runner
    private var entries: [Key: Entry] = [:]
    private var active: Key?
    private enum SlotClaim: Sendable {
        case claimed, closed, waiting(AsyncStream<Void>), finishing(Key, Task<Void, Never>)
    }
    private var slotWaiters: [AsyncStream<Void>.Continuation] = []
    private var availabilityWaiters: [UUID: AsyncStream<Void>.Continuation] = [:]
    private(set) var closureResult: AdministrativeSetupShutdown.RecoveryCloseResult?
    private var accepting = true, retired = false, joined = false
    private var closing: Task<Void, Never>?
    private var retryingClosure = false

    static func openOwned(custody: any SetupMaintenanceRecoveryProcessCustody,
                          driver: Driver, timing: Timing = .continuous) throws -> SetupMaintenanceRecoverySupervisor {
        try RuntimeMaintenanceOwnedControl.require()
        let actual = Self(custody: custody, driver: driver, timing: timing)
        if let native = custody as? SetupMaintenanceRecoveryNativeAdapter.Custody { native.bindSupervisor(actual) }
        return actual
    }
    /// Construction validates the lease and retains its lifecycle binding until release.
    /// M10d must retain this supervisor and close or retire it during explicit service shutdown.
    static func openNative(owner: SetupAccountOwner, shutdown: AdministrativeSetupShutdown) throws -> SetupMaintenanceRecoverySupervisor {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return try shutdown.recoverySupervisor(owner: owner)
    }
    private init(custody: any SetupMaintenanceRecoveryProcessCustody, driver: Driver, timing: Timing) {
        self.custody = custody; finalClose = custody; publish = { _, _ in }
        runner = .init(custody: custody, driver: driver, timing: timing)
    }
    init(nativeWork: any SetupMaintenanceRecoveryWorkCustody, finalClose: any SetupMaintenanceRecoveryFinalClose,
        driver: Driver, publish: @escaping @Sendable (Request, Observation) -> Void) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        custody = nativeWork; self.finalClose = finalClose; self.publish = publish
        runner = .init(custody: nativeWork, driver: driver, timing: .continuous)
    }
    /// Does not acquire Setup admission. Completed observations cannot substitute for this custody check.
    func validateIdleCustody() async -> Bool {
        guard currentProcess else { return false }
        return await custody.validateForRecovery()
    }
    /// A busy attempt settles only after its actual owner joins and yields the active slot.
    func waitForInitialAttempt(_ key: Key) async {
        while currentProcess, let entry = entries[key] {
            if entry.finished { await entry.task.value; return }
            if entry.observation == .busy && active != key { return }
            let id = UUID(), signal = AsyncStream<Void>.makeStream()
            initialWaiters[id] = signal.continuation
            for await _ in signal.stream { break }
            initialWaiters.removeValue(forKey: id)?.finish()
            if Task.isCancelled { return }
        }
    }
    private var currentProcess: Bool { getpid() == processID && getuid() == ownerUID && geteuid() == ownerUID }

    /// A revision never changes the key. Completed entries also refuse replay in this process.
    func schedule(_ request: Request) async -> Bool {
        guard currentProcess, accepting, !retired, entries[request.key] == nil else { return false }
        if let prior = active {
            guard let entry = entries[prior], entry.finished else { return false }
            await entry.task.value
            guard currentProcess, accepting, !retired, active == prior, entries[request.key] == nil else { return false }
        }
        active = request.key
        let task = Self.launch(runner: runner, request: request, observe: { [weak self] observation in
            await self?.observe(request.key, observation)
        }, releaseSlot: { [weak self] in
            await self?.releaseSlot(request.key)
        }, claimSlot: { [weak self] in
            while !Task.isCancelled {
                switch await self?.claimSlot(request.key) ?? .closed {
                case .claimed: return true
                case .closed: return false
                case .waiting(let signal):
                    for await _ in signal { break }
                case .finishing(let prior, let task):
                    await task.value
                    await self?.releaseSlot(prior)
                }
            }
            return false
        }, finish: { [weak self] observation in
            await self?.finish(request.key, observation)
        })
        entries[request.key] = .init(task: task, request: request)
        return true
    }
    enum SchedulingResult: Equatable, Sendable {
        case scheduled, duplicate, deadlineReached, cancelled, closed, retired, invalidProcess
    }
    /// Waits only for scheduling, capped at 120 seconds. The wait never acquires recovery custody.
    func scheduleWhenAvailable(_ request: Request, until deadline: ContinuousClock.Instant) async -> SchedulingResult {
        let expires = min(deadline, runner.timing.now().advanced(by: .seconds(120)))
        while true {
            guard currentProcess else { return .invalidProcess }
            guard !retired else { return .retired }
            guard accepting else { return .closed }
            guard !Task.isCancelled else { return .cancelled }
            guard runner.timing.now() < expires else { return .deadlineReached }
            guard entries[request.key] == nil else { return .duplicate }
            if await schedule(request) { return .scheduled }
            guard currentProcess, accepting, !retired, !Task.isCancelled, entries[request.key] == nil else { continue }
            guard let active, let entry = entries[active], !entry.finished else { continue }
            let signal = AsyncStream<Void>.makeStream(), id = UUID()
            availabilityWaiters[id] = signal.continuation
            await Self.waitForAvailability(signal.stream, until: expires, timing: runner.timing)
            availabilityWaiters.removeValue(forKey: id)?.finish()
        }
    }
    private nonisolated static func waitForAvailability(_ signal: AsyncStream<Void>, until deadline: ContinuousClock.Instant,
        timing: Timing) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { for await _ in signal { break } }
            group.addTask { try? await timing.sleep(deadline) }
            _ = await group.next(); group.cancelAll()
        }
    }
    func observation(for key: Key) -> Observation? { entries[key]?.observation }
    var isClosed: Bool { joined }
    var shouldExit: Bool { retired && joined && closureResult == .closed }
    /// Explicit service shutdown. A pending close retains custody and can be retried by this caller.
    func close() async {
        guard currentProcess else { return }
        let retry = joined
        startClosing()
        await closing?.value
        if retry { await retryClosure() }
    }
    /// Retirement closes admission immediately. Exit becomes eligible only after every actual join.
    func retire() async {
        guard currentProcess else { return }
        let retry = joined
        retired = true; startClosing()
        await closing?.value
        if retry { await retryClosure() }
    }
    private func retryClosure() async {
        guard joined, closureResult != .closed, !retryingClosure else { return }
        retryingClosure = true
        defer { retryingClosure = false }
        closureResult = await finalClose.retryCloseAfterJoiningResult()
    }
    private func observe(_ key: Key, _ observation: Observation) {
        entries[key]?.observation = observation
        if let request = entries[key]?.request { publish(request, observation) }
        wakeInitialWaiters()
    }
    private func wakeInitialWaiters() {
        let waiters = initialWaiters; initialWaiters = [:]
        for waiter in waiters.values { waiter.finish() }
    }
    private func releaseSlot(_ key: Key) {
        guard active == key else { return }
        active = nil; wakeSlotWaiters(); wakeInitialWaiters()
    }
    private func claimSlot(_ key: Key) -> SlotClaim {
        guard currentProcess, accepting, !retired else { return .closed }
        guard let prior = active else { active = key; return .claimed }
        if let entry = entries[prior], entry.finished { return .finishing(prior, entry.task) }
        let signal = AsyncStream<Void>.makeStream()
        slotWaiters.append(signal.continuation)
        return .waiting(signal.stream)
    }
    private func wakeSlotWaiters() {
        let pending = slotWaiters; slotWaiters = []
        for waiter in pending { waiter.finish() }
        let available = availabilityWaiters; availabilityWaiters = [:]
        for waiter in available.values { waiter.finish() }
    }
    private func finish(_ key: Key, _ observation: Observation) {
        observe(key, observation); entries[key]?.finished = true
        wakeInitialWaiters()
        wakeSlotWaiters()
        if observation == .retired { retired = true; startClosing() }
    }
    private func startClosing() {
        guard closing == nil else { return }
        accepting = false
        let tasks = entries.values.map(\.task)
        // Cancellation handlers only signal. Close admission before awaiting the joins.
        for task in tasks { task.cancel() }
        finalClose.closeAdmission(); wakeSlotWaiters(); wakeInitialWaiters()
        closing = Self.join(tasks, custody: finalClose, finished: { [weak self] in
            await self?.didJoin($0)
        })
    }
    private func didJoin(_ result: AdministrativeSetupShutdown.RecoveryCloseResult?) { joined = true; closureResult = result }
    private nonisolated static func launch(runner: Runner, request: Request,
        observe: @escaping @Sendable (Observation) async -> Void,
        releaseSlot: @escaping @Sendable () async -> Void,
        claimSlot: @escaping @Sendable () async -> Bool,
        finish: @escaping @Sendable (Observation) async -> Void) -> Task<Void, Never> {
        Task {
            let result = await runner.run(request, observe: observe, releaseSlot: releaseSlot, claimSlot: claimSlot)
            await finish(result)
        }
    }
    private nonisolated static func join(_ tasks: [Task<Void, Never>], custody: any SetupMaintenanceRecoveryFinalClose,
        shutdown: Bool = true,
        finished: @escaping @Sendable (AdministrativeSetupShutdown.RecoveryCloseResult?) async -> Void) -> Task<Void, Never> {
        return Task {
            for task in tasks { await task.value }
            if shutdown {
                await custody.joinRecoverySessions()
                await finished(await custody.closeAfterJoiningResult())
            } else {
                await custody.observeRecoverySessionsForDisposal()
                custody.releaseAfterJoining(); await finished(nil)
            }
        }
    }
    deinit {
        guard getpid() == processID else { return }
        if let closing { finalClose.retainSupervisorDisposal(closing); return }
        let start = AsyncStream<Void>.makeStream()
        let tasks = entries.values.map(\.task), custody = finalClose
        let actual = Task {
            for await _ in start.stream {}
            for task in tasks { task.cancel() }
            await Self.join(tasks, custody: custody, shutdown: false, finished: { _ in }).value
        }
        custody.retainSupervisorDisposal(actual)
        start.continuation.finish()
    }

    private struct Runner: Sendable {
        let custody: any SetupMaintenanceRecoveryWorkCustody
        let driver: Driver
        let timing: Timing
        private enum OwnerResult: Sendable { case finished(Observation), unusedAtDeadline }
        private func current() async -> Bool { await custody.validateForRecovery() }
        private func validated(_ result: Observation) -> Observation {
            switch result {
            case .phase, .failed, .noWindow: return result
            default: return .failed(.serviceUnavailable)
            }
        }
        func run(_ request: Request, observe: @escaping @Sendable (Observation) async -> Void,
            releaseSlot: @escaping @Sendable () async -> Void,
            claimSlot: @escaping @Sendable () async -> Bool) async -> Observation {
            do {
                while true {
                    try Task.checkCancellation()
                    guard await current() else { return .retired }
                    let deadline = timing.now().advanced(by: .seconds(120))
                    var backoff: Duration = .milliseconds(250)
                    await observe(.recovering)
                    acquisition: while timing.now() < deadline {
                        try Task.checkCancellation()
                        guard await current() else { return .retired }
                        switch try await driver.acquire(request, deadline) {
                        case .terminal(let observation): return Task.isCancelled ? .cancelled : validated(observation)
                        case .owner(let owner):
                            switch await runOwner(owner, deadline: deadline, observe: observe) {
                            case .finished(let result): return result
                            case .unusedAtDeadline: break acquisition
                            }
                        case .busyBeforeOwner:
                            try Task.checkCancellation()
                            try await timing.sleep(min(deadline, timing.now().advanced(by: backoff)))
                            backoff = min(backoff * 2, .seconds(2))
                        }
                    }
                    await releaseSlot()
                    await observe(.busy)
                    try await timing.sleep(timing.now().advanced(by: .seconds(60)))
                    guard await claimSlot() else { return .cancelled }
                }
            } catch {
                guard await current() else { return .retired }
                return Task.isCancelled ? .cancelled : .failed(.serviceUnavailable)
            }
        }
        private func runOwner(_ owner: Owner, deadline: ContinuousClock.Instant,
            observe: @escaping @Sendable (Observation) async -> Void) async -> OwnerResult {
            await withTaskCancellationHandler {
                await runAndJoinOwner(owner, deadline: deadline, observe: observe)
            } onCancel: { owner.cancel() }
        }
        private func runAndJoinOwner(_ owner: Owner, deadline: ContinuousClock.Instant,
            observe: @escaping @Sendable (Observation) async -> Void) async -> OwnerResult {
            let result: Observation
            let unusedAtDeadline: Bool
            if Task.isCancelled { owner.cancel(); result = .cancelled; unusedAtDeadline = false }
            else if !(await current()) { owner.cancel(); result = .retired; unusedAtDeadline = false }
            else if timing.now() >= deadline { owner.cancel(); result = .busy; unusedAtDeadline = true }
            else {
                unusedAtDeadline = false
                do {
                    try Task.checkCancellation()
                    result = validated(try await owner.run(deadline))
                } catch {
                    if !(await current()) { result = .retired }
                    else { result = Task.isCancelled ? .cancelled : .failed(.serviceUnavailable) }
                }
            }
            await observe(.joining)
            let cleanup = Task { await owner.join() }
            await cleanup.value
            if unusedAtDeadline {
                if Task.isCancelled { return .finished(.cancelled) }
                guard await current() else { return .finished(.retired) }
                return .unusedAtDeadline
            }
            return .finished(result)
        }
    }
}
