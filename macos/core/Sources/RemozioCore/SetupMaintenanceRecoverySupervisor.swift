import Darwin
import Foundation

/// The lifecycle owner joins its remaining work before releasing the process custody.
protocol SetupMaintenanceRecoveryProcessCustody: AnyObject, Sendable {
    func validate() throws
    func closeAfterJoining() async
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
        var observation: Observation = .recovering
        var finished = false
    }
    private let processID = getpid(), ownerUID = getuid()
    private let custody: any SetupMaintenanceRecoveryProcessCustody
    private let runner: Runner
    private var entries: [Key: Entry] = [:]
    private var active: Key?
    private enum SlotClaim: Sendable {
        case claimed, closed, waiting(AsyncStream<Void>), finishing(Key, Task<Void, Never>)
    }
    private var slotWaiters: [AsyncStream<Void>.Continuation] = []
    private var accepting = true, retired = false, joined = false
    private var closing: Task<Void, Never>?

    static func openOwned(custody: any SetupMaintenanceRecoveryProcessCustody,
                          driver: Driver, timing: Timing = .continuous) throws -> SetupMaintenanceRecoverySupervisor {
        try RuntimeMaintenanceOwnedControl.require()
        return .init(custody: custody, driver: driver, timing: timing)
    }
    private init(custody: any SetupMaintenanceRecoveryProcessCustody, driver: Driver, timing: Timing) {
        self.custody = custody; runner = .init(custody: custody, driver: driver, timing: timing)
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
        entries[request.key] = .init(task: task)
        return true
    }
    func observation(for key: Key) -> Observation? { entries[key]?.observation }
    var isClosed: Bool { joined }
    var shouldExit: Bool { retired && joined }
    func close() async {
        guard currentProcess else { return }
        startClosing()
        await closing?.value
    }
    /// Retirement closes admission immediately. Exit becomes eligible only after every actual join.
    func retire() async {
        guard currentProcess else { return }
        retired = true; startClosing()
        await closing?.value
    }
    private func observe(_ key: Key, _ observation: Observation) { entries[key]?.observation = observation }
    private func releaseSlot(_ key: Key) {
        guard active == key else { return }
        active = nil; wakeSlotWaiters()
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
    }
    private func finish(_ key: Key, _ observation: Observation) {
        entries[key]?.observation = observation; entries[key]?.finished = true
        wakeSlotWaiters()
        if observation == .retired { retired = true; startClosing() }
    }
    private func startClosing() {
        guard closing == nil else { return }
        accepting = false; wakeSlotWaiters()
        closing = Self.join(entries.values.map(\.task), custody: custody, finished: { [weak self] in
            await self?.didJoin()
        })
    }
    private func didJoin() { joined = true }
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
    private nonisolated static func join(_ tasks: [Task<Void, Never>], custody: any SetupMaintenanceRecoveryProcessCustody,
        finished: @escaping @Sendable () async -> Void) -> Task<Void, Never> {
        for task in tasks { task.cancel() }
        return Task {
            for task in tasks { await task.value }
            await custody.closeAfterJoining()
            await finished()
        }
    }
    deinit {
        guard getpid() == processID, closing == nil else { return }
        _ = Self.join(entries.values.map(\.task), custody: custody, finished: {})
    }

    private struct Runner: Sendable {
        let custody: any SetupMaintenanceRecoveryProcessCustody
        let driver: Driver
        let timing: Timing
        private enum OwnerResult: Sendable { case finished(Observation), unusedAtDeadline }
        private func current() -> Bool { do { try custody.validate(); return true } catch { return false } }
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
                    guard current() else { return .retired }
                    let deadline = timing.now().advanced(by: .seconds(120))
                    var backoff: Duration = .milliseconds(250)
                    await observe(.recovering)
                    acquisition: while timing.now() < deadline {
                        try Task.checkCancellation()
                        guard current() else { return .retired }
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
                return Task.isCancelled || error is CancellationError ? .cancelled : .failed(.serviceUnavailable)
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
            else if !current() { owner.cancel(); result = .retired; unusedAtDeadline = false }
            else if timing.now() >= deadline { owner.cancel(); result = .busy; unusedAtDeadline = true }
            else {
                unusedAtDeadline = false
                do {
                    try Task.checkCancellation()
                    result = validated(try await owner.run(deadline))
                } catch {
                    result = Task.isCancelled || error is CancellationError ? .cancelled : .failed(.serviceUnavailable)
                }
            }
            await observe(.joining)
            let cleanup = Task { await owner.join() }
            await cleanup.value
            if unusedAtDeadline {
                if Task.isCancelled { return .finished(.cancelled) }
                guard current() else { return .finished(.retired) }
                return .unusedAtDeadline
            }
            return .finished(result)
        }
    }
}
