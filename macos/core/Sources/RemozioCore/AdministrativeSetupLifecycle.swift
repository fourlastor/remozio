import Darwin
import Dispatch
import Foundation

/// Composes the existing recovery supervisor with startup routing and process retirement.
actor AdministrativeSetupLifecycle {
    typealias Supervisor = SetupMaintenanceRecoverySupervisor
    typealias Timing = Supervisor.Timing
    enum State: Equatable, Sendable { case starting, discovering, serving, retiring, closed }

    final class Routing: @unchecked Sendable {
        private let lock = NSLock(), process = getpid()
        private let validateStartup: @Sendable () throws -> Void
        private var current: State = .starting
        private var owner: SetupAccountOwner?
        init(validateStartup: @escaping @Sendable () throws -> Void) { self.validateStartup = validateStartup }
        var state: State { lock.withLock { current } }
        var allowsNormal: Bool { lock.withLock { getpid() == process && current == .serving && owner != nil } }
        func install(_ owner: SetupAccountOwner) throws {
            try lock.withLock {
                guard getpid() == process, self.owner == nil, current == .starting || current == .discovering else {
                    throw AdministrativeSetupError.unavailable
                }
                self.owner = owner
            }
        }
        func move(to state: State) {
            lock.withLock {
                guard getpid() == process, current != .closed, current != .retiring || state == .closed else { return }
                current = state
            }
        }
        func normalOwner() throws -> SetupAccountOwner {
            try lock.withLock {
                guard getpid() == process, current == .serving, let owner else { throw AdministrativeSetupError.unavailable }
                return owner
            }
        }
        func checkStatus() -> SetupAccountOwner.StatusLaneCheck {
            guard getpid() == process else { return .refused }
            guard lock.try() else { return .busy }
            let (state, owner) = (current, owner); lock.unlock()
            guard state != .closed else { return .refused }
            if state == .serving, let owner { return owner.statusLaneCheck() }
            // Pending status uses only fixed process custody. Signature and configuration checks belong to the lifecycle.
            do { try validateStartup(); return .busy } catch { return .refused }
        }
        func status(_ peer: XPCPeerCredentials) -> SetupRetainedInvocationStatus {
            guard getpid() == process else { return .unavailable }
            guard lock.try() else { return .unavailable }
            let owner = current == .closed ? nil : self.owner; lock.unlock()
            return owner?.retainedInvocationStatus(authenticatedPeer: peer) ?? .unavailable
        }
        static func verifiedOwner(_ owner: SetupAccountOwner) throws -> Routing {
            try owner.verifyCurrent()
            let routing = Routing(validateStartup: { try owner.verifyCurrent() })
            try routing.install(owner); routing.move(to: .serving)
            return routing
        }
    }

    /// Checked host facts for one lifecycle attempt. This value grants no admission or native operation authority.
    struct HostCheck: Sendable {
        let verifyInventory: @Sendable (InstallationInventory) throws -> Void
    }
    struct Runtime: Sendable {
        fileprivate let owner: SetupAccountOwner?
        let supervisor: Supervisor
        let discover: @Sendable (HostCheck) async throws -> [RuntimeMaintenanceWindowRecord]
        let confirmServing: @Sendable (HostCheck) async throws -> Void
        let publish: @Sendable (RuntimeMaintenanceWindowRecord) -> Void
        let availability: @Sendable () -> AsyncStream<Void>
        private let ownedSchedulingResult: (@Sendable () -> Supervisor.SchedulingResult?)?
        private init(owner: SetupAccountOwner?, supervisor: Supervisor,
            discover: @escaping @Sendable (HostCheck) async throws -> [RuntimeMaintenanceWindowRecord],
            confirmServing: @escaping @Sendable (HostCheck) async throws -> Void,
            publish: @escaping @Sendable (RuntimeMaintenanceWindowRecord) -> Void,
            availability: @escaping @Sendable () -> AsyncStream<Void>,
            ownedSchedulingResult: (@Sendable () -> Supervisor.SchedulingResult?)? = nil) {
            self.owner = owner; self.supervisor = supervisor; self.discover = discover
            self.confirmServing = confirmServing; self.publish = publish; self.availability = availability
            self.ownedSchedulingResult = ownedSchedulingResult
        }
        static func native(owner: SetupAccountOwner, shutdown: AdministrativeSetupShutdown,
            candidate: SignedReleaseEvidence) throws -> Runtime {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            let supervisor = try Supervisor.openNative(owner: owner, shutdown: shutdown)
            return .init(owner: owner, supervisor: supervisor,
                discover: { try await owner.discoverMaintenanceRecovery(custody: shutdown, candidate: candidate, checkedHost: $0) },
                confirmServing: { checkedHost in
                    _ = try await owner.discoverMaintenanceRecovery(custody: shutdown, candidate: candidate, checkedHost: checkedHost)
                }, publish: { owner.publishMaintenanceRecovery($0) },
                availability: { owner.maintenanceRecoveryAvailability() })
        }
        static func owned(supervisor: Supervisor,
            discover: @escaping @Sendable (HostCheck) async throws -> [RuntimeMaintenanceWindowRecord],
            confirmServing: @escaping @Sendable (HostCheck) async throws -> Void = { _ in },
            publish: @escaping @Sendable (RuntimeMaintenanceWindowRecord) -> Void = { _ in },
            availability: @escaping @Sendable () -> AsyncStream<Void> = { AsyncStream { $0.finish() } },
            terminalSchedulingResult: (@Sendable () -> Supervisor.SchedulingResult?)? = nil) throws -> Runtime {
            try RuntimeMaintenanceOwnedControl.require()
            if let result = terminalSchedulingResult?() {
                switch result {
                case .retired, .invalidProcess, .closed, .cancelled: break
                default: throw JournalLeaseError.unsafeMetadata
                }
            }
            return .init(owner: nil, supervisor: supervisor, discover: discover, confirmServing: confirmServing, publish: publish,
                availability: availability, ownedSchedulingResult: terminalSchedulingResult)
        }
        /// Ordinary-owner tests can terminate scheduling, but cannot inject an admitted request.
        fileprivate func scheduleWhenAvailable(_ request: Supervisor.Request, until deadline: ContinuousClock.Instant) async -> Supervisor.SchedulingResult {
            if let ownedSchedulingResult {
                do { try RuntimeMaintenanceOwnedControl.require() }
                catch { return .invalidProcess }
                if let result = ownedSchedulingResult() {
                    switch result {
                    case .retired, .invalidProcess, .closed, .cancelled: return result
                    default: return .invalidProcess
                    }
                }
            }
            return await supervisor.scheduleWhenAvailable(request, until: deadline)
        }
    }

    /// The native timer runs on its own Dispatch queue. Owned clocks supply an explicit timer driver.
    final class RetirementWatchdog: @unchecked Sendable {
        struct TimerDriver: Sendable {
            let arm: @Sendable (ContinuousClock.Instant, @escaping @Sendable () -> Void) -> Void
            let cancel: @Sendable () -> Void
            static func owned(arm: @escaping @Sendable (ContinuousClock.Instant, @escaping @Sendable () -> Void) -> Void,
                cancel: @escaping @Sendable () -> Void) throws -> TimerDriver {
                try RuntimeMaintenanceOwnedControl.require(); return .init(arm: arm, cancel: cancel)
            }
        }
        private final class DispatchTimer: @unchecked Sendable {
            private let queue = DispatchQueue(label: "dev.sebastiano.remozio.setup.retirement-watchdog", qos: .utility)
            private var timer: DispatchSourceTimer?
            private var cancelled = false
            func arm(_ deadline: ContinuousClock.Instant, callback: @escaping @Sendable () -> Void) {
                queue.async { [self] in
                    guard !cancelled else { return }
                    let source: DispatchSourceTimer
                    if let timer { source = timer }
                    else {
                        source = DispatchSource.makeTimerSource(queue: queue); timer = source
                        source.resume()
                    }
                    let parts = ContinuousClock.now.duration(to: deadline).components
                    let seconds = max(0, Double(parts.seconds) + Double(parts.attoseconds) / 1_000_000_000_000_000_000)
                    source.setEventHandler(handler: callback)
                    // Wall-deadline delivery includes system sleep. The once-only continuous deadline rejects early clock jumps.
                    source.schedule(wallDeadline: .now() + seconds, leeway: .nanoseconds(0))
                }
            }
            func cancel() {
                queue.async { [self] in cancelled = true; timer?.cancel(); timer = nil }
            }
        }
        private let lock = NSLock()
        private let timing: Timing
        private let driver: TimerDriver
        private let terminate: @Sendable (Int32) -> Void
        private var deadline: ContinuousClock.Instant?
        private var closed = false, fired = false
        init(timing: Timing, timer: TimerDriver? = nil, terminate: @escaping @Sendable (Int32) -> Void) {
            self.timing = timing; self.terminate = terminate
            if let timer { driver = timer }
            else {
                let timer = DispatchTimer()
                driver = .init(arm: { timer.arm($0, callback: $1) }, cancel: { timer.cancel() })
            }
        }
        @discardableResult func start() -> ContinuousClock.Instant {
            let (expires, newlyStarted) = lock.withLock {
                if let deadline { return (deadline, false) }
                let expires = timing.now().advanced(by: .seconds(300)); deadline = expires
                return (expires, true)
            }
            if newlyStarted { arm(expires) }
            return expires
        }
        private func arm(_ expires: ContinuousClock.Instant) {
            driver.arm(expires) { [weak self] in self?.timerFired(expires) }
        }
        private func timerFired(_ expires: ContinuousClock.Instant) {
            let action = lock.withLock { () -> Int in
                guard !closed, !fired else { return 0 }
                guard timing.now() >= expires else { return 1 }
                fired = true; return 2
            }
            if action == 1 { arm(expires) }
            else if action == 2 { driver.cancel(); terminate(75) }
        }
        func didClose() {
            lock.withLock { closed = true }
            driver.cancel()
        }
    }

    private let routing: Routing
    private let timing: Timing
    private let idleSleep: @Sendable (ContinuousClock.Instant) async throws -> Void
    private let validateStartup: @Sendable () throws -> Void
    private let validateHost: @Sendable () async throws -> HostCheck
    private let prepare: @Sendable (HostCheck) async throws -> Runtime
    private let closeWithoutRuntime: @Sendable () async throws -> Void
    private let stopListener: @Sendable () -> Void
    private let watchdog: RetirementWatchdog
    private var runtime: Runtime?
    private var discovery: Task<Void, Never>?, idle: Task<Void, Never>?, retirement: Task<Void, Never>?
    private var rearming: [Supervisor.Key: Task<Void, Never>] = [:]
    private var discoveryRequested = false
    private var stopped: [CheckedContinuation<Void, Never>] = []
    private var startupComplete = false

    private init(routing: Routing, timing: Timing,
        validateStartup: @escaping @Sendable () throws -> Void,
        validateHost: @escaping @Sendable () async throws -> HostCheck,
        prepare: @escaping @Sendable (HostCheck) async throws -> Runtime,
        closeWithoutRuntime: @escaping @Sendable () async throws -> Void,
        stopListener: @escaping @Sendable () -> Void, terminate: @escaping @Sendable (Int32) -> Void,
        idleSleep: (@Sendable (ContinuousClock.Instant) async throws -> Void)? = nil,
        watchdogTimer: RetirementWatchdog.TimerDriver? = nil) {
        self.routing = routing; self.timing = timing; self.idleSleep = idleSleep ?? timing.sleep
        self.validateStartup = validateStartup; self.validateHost = validateHost; self.prepare = prepare
        self.closeWithoutRuntime = closeWithoutRuntime; self.stopListener = stopListener
        watchdog = .init(timing: timing, timer: watchdogTimer, terminate: terminate)
    }
    static func native(routing: Routing, validateStartup: @escaping @Sendable () throws -> Void,
        validateHost: @escaping @Sendable () async throws -> HostCheck,
        prepare: @escaping @Sendable (HostCheck) async throws -> Runtime,
        closeWithoutRuntime: @escaping @Sendable () async throws -> Void,
        stopListener: @escaping @Sendable () -> Void, terminate: @escaping @Sendable (Int32) -> Void) throws -> AdministrativeSetupLifecycle {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        return .init(routing: routing, timing: .continuous, validateStartup: validateStartup, validateHost: validateHost, prepare: prepare,
            closeWithoutRuntime: closeWithoutRuntime, stopListener: stopListener, terminate: terminate,
            idleSleep: { try await ContinuousClock().sleep(until: $0, tolerance: .milliseconds(100)) })
    }
    static func openOwned(routing: Routing, timing: Timing,
        validateStartup: @escaping @Sendable () throws -> Void = {},
        validateHost: @escaping @Sendable () async throws -> HostCheck = { .init(verifyInventory: { _ in }) },
        watchdogTimer: RetirementWatchdog.TimerDriver,
        prepare: @escaping @Sendable (HostCheck) async throws -> Runtime,
        closeWithoutRuntime: @escaping @Sendable () async throws -> Void = {},
        stopListener: @escaping @Sendable () -> Void = {}, terminate: @escaping @Sendable (Int32) -> Void) throws -> AdministrativeSetupLifecycle {
        try RuntimeMaintenanceOwnedControl.require()
        return .init(routing: routing, timing: timing, validateStartup: validateStartup, validateHost: validateHost, prepare: prepare,
            closeWithoutRuntime: closeWithoutRuntime, stopListener: stopListener, terminate: terminate, watchdogTimer: watchdogTimer)
    }
    func start() {
        guard routing.state == .starting, discovery == nil else { return }
        idle = Task { [weak self] in await self?.checkIdleCustody() }
        beginDiscovery()
    }
    func requestDiscovery() {
        guard routing.state != .retiring, routing.state != .closed else { return }
        guard discovery == nil else { discoveryRequested = true; return }
        beginDiscovery()
    }
    private func beginDiscovery() { discovery = Task { await self.discover() } }
    private func discover() async {
        defer {
            discovery = nil
            if discoveryRequested, routing.state != .retiring, routing.state != .closed {
                discoveryRequested = false; beginDiscovery()
            }
        }
        while !Task.isCancelled, routing.state != .retiring, routing.state != .closed {
            do {
                let checkedHost: HostCheck
                do { try validateStartup(); checkedHost = try await validateHost() }
                catch { requestRetirement(); return }
                if runtime == nil {
                    let opened = try await prepare(checkedHost)
                    runtime = opened
                    guard routing.state != .retiring, !Task.isCancelled else { return }
                    if let owner = opened.owner { try routing.install(owner) }
                }
                guard let runtime else { return }
                if !startupComplete { routing.move(to: .discovering) }
                let rows = try await runtime.discover(checkedHost)
                do { try validateStartup() } catch { requestRetirement(); return }
                guard rows.count <= 64, !Task.isCancelled, routing.state != .retiring else { return }
                for row in rows { runtime.publish(row) }
                var requests: [Supervisor.Request] = []
                for row in rows {
                    let request = try Supervisor.Request(accountID: row.scope.authority.accountID, windowID: row.id, revision: row.revision)
                    requests.append(request)
                }
                guard Set(requests.map(\.key)).count == requests.count else { throw PreparationStoreError.corruptRecord }
                for request in requests {
                    scheduling: while !Task.isCancelled, routing.state != .retiring {
                        // Scheduling waits do not consume this window's own 120-second attempt in the supervisor.
                        let deadline = timing.now().advanced(by: .seconds(120))
                        switch await runtime.scheduleWhenAvailable(request, until: deadline) {
                        case .scheduled, .duplicate:
                            await runtime.supervisor.waitForInitialAttempt(request.key)
                            break scheduling
                        case .deadlineReached:
                            runtime.owner?.publishMaintenanceRecovery(request: request, observation: .busy)
                            if startupComplete { rearm(request, runtime: runtime); break scheduling }
                            continue scheduling
                        case .retired, .invalidProcess, .closed, .cancelled:
                            requestRetirement()
                            return
                        }
                    }
                }
                guard !Task.isCancelled, routing.state != .retiring else { return }
                guard await runtime.supervisor.validateIdleCustody() else { requestRetirement(); return }
                try validateStartup()
                // Startup completion is a separate fresh check after all actual joins, not another unreadable-store retry.
                let finalHost: HostCheck
                if startupComplete { finalHost = checkedHost }
                else {
                    do { finalHost = try await validateHost() }
                    catch { requestRetirement(); return }
                }
                try await runtime.confirmServing(finalHost)
                guard !Task.isCancelled, routing.state != .retiring else { return }
                try validateStartup()
                if !startupComplete { startupComplete = true; routing.move(to: .serving) }
                return
            } catch {
                guard !Task.isCancelled, routing.state != .retiring else { return }
                // This attempt already ran its full host check. The next retry checks again after its wait.
                do { try validateStartup() } catch { requestRetirement(); return }
                if error is AdministrativeSetupServiceError || (error as? AdministrativeSetupError) == .changedInstallation {
                    requestRetirement(); return
                }
                if let activityError = error as? ReleaseActivityError {
                    if case .busy = activityError {
                        do { try await timing.sleep(timing.now().advanced(by: .seconds(60))) } catch { return }
                        continue
                    }
                    requestRetirement(); return
                }
                if error is SetupAccountOwner.MaintenanceRecoveryAdmissionError || error is SetupAuditUpgradeWorkExecutor.BusyBeforeBody {
                    if let runtime { await waitForDiscoveryAvailability(runtime) }
                    else { do { try await timing.sleep(timing.now().advanced(by: .seconds(60))) } catch { return } }
                    continue
                }
                // A complete host check passed. Only the returned open/read failure stays visibly pending.
                do { try await timing.sleep(timing.now().advanced(by: .milliseconds(500))) } catch { return }
            }
        }
    }
    private func waitForDiscoveryAvailability(_ runtime: Runtime) async {
        let signal = runtime.availability(), deadline = timing.now().advanced(by: .seconds(60)), timing = self.timing
        await withTaskGroup(of: Void.self) { group in
            group.addTask { for await _ in signal { break } }
            group.addTask { try? await timing.sleep(deadline) }
            _ = await group.next(); group.cancelAll()
        }
    }
    private func rearm(_ request: Supervisor.Request, runtime: Runtime) {
        guard rearming[request.key] == nil, rearming.count < 64 else { return }
        let timing = self.timing
        rearming[request.key] = Task {
            while !Task.isCancelled {
                do { try await timing.sleep(timing.now().advanced(by: .seconds(60))) } catch { break }
                guard !Task.isCancelled else { break }
                switch await runtime.scheduleWhenAvailable(request, until: timing.now().advanced(by: .seconds(120))) {
                case .deadlineReached: continue
                case .scheduled, .duplicate, .cancelled: break
                case .retired, .invalidProcess, .closed:
                    requestRetirement()
                }
                break
            }
            self.didRearm(request.key)
        }
    }
    private func didRearm(_ key: Supervisor.Key) { rearming.removeValue(forKey: key) }
    private func checkIdleCustody() async {
        while !Task.isCancelled, routing.state != .retiring, routing.state != .closed {
            do { try validateStartup() } catch { requestRetirement(); return }
            if let runtime, !(await runtime.supervisor.validateIdleCustody()) { requestRetirement(); return }
            do { try await idleSleep(timing.now().advanced(by: .seconds(1))) } catch { return }
        }
    }
    func requestRetirement() {
        guard routing.state != .retiring, routing.state != .closed else { return }
        routing.move(to: .retiring)
        watchdog.start()
        let discovery = self.discovery, idle = self.idle, retries = Array(rearming.values)
        discovery?.cancel(); idle?.cancel(); for task in retries { task.cancel() }
        let firstSupervisor = runtime?.supervisor
        retirement = Task {
            // Retire stops supervisor admission before any composition join can block this task.
            if let firstSupervisor { await firstSupervisor.retire() }
            await discovery?.value
            // prepare can have returned a runtime while cancelled discovery was joining.
            if let runtime, firstSupervisor !== runtime.supervisor { await runtime.supervisor.retire() }
            await idle?.value
            for task in retries { await task.value }
            while true {
                if let runtime {
                    if await runtime.supervisor.shouldExit { didClose(); return }
                    await retirementDelay()
                    await runtime.supervisor.retire()
                } else {
                    do { try await closeWithoutRuntime(); didClose(); return }
                    catch { await retirementDelay() }
                }
            }
        }
    }
    private func retirementDelay() async {
        do { try await timing.sleep(timing.now().advanced(by: .milliseconds(250))) }
        catch {
            await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + .milliseconds(250)) { continuation.resume() }
            }
        }
    }
    private func didClose() {
        watchdog.didClose(); stopListener(); routing.move(to: .closed)
        let waiters = stopped; stopped = []
        for waiter in waiters { waiter.resume() }
    }
    func waitUntilStopped() async {
        guard routing.state != .closed else { return }
        await withCheckedContinuation { stopped.append($0) }
    }
    func close() async { requestRetirement(); await waitUntilStopped() }
}
