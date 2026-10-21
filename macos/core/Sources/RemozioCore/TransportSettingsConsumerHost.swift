import Foundation
import Synchronization

protocol OwnedTransportSettingsControl: Sendable {
    func start() async throws
    func poll() async throws
    func close() async throws
}
extension GatewaySettingsConsumerHost: OwnedTransportSettingsControl {}

/// Closing prevents later connector startup. The host also joins any outstanding poll before releasing activity.
protocol OwnedTransportRelayConnector: Sendable {
    func poll() async throws
    func close() async throws
}

protocol OwnedTransportSettingsForeground: AnyObject, Sendable {
    func start() async throws
    func poll() async throws
    func retire()
    func closeAndWait() async throws
}

/// Keeps direct service polling independent from the optional wake handshake and its settings controls.
actor TransportSettingsConsumerHost {
    private final class Completion: Sendable { let done = Mutex(false) }
    private let control: any OwnedTransportSettingsControl
    private let lifetime: any OwnedReleaseActivity
    private let connector: (any OwnedTransportRelayConnector)?
    private let makeForeground: @Sendable () throws -> any OwnedTransportSettingsForeground
    private let retryDelay: Duration
    private var retryAt = ContinuousClock.now
    private var controlStart: Task<Void, Error>?
    private var controlPoll: (id: UUID, task: Task<Void, Error>, completion: Completion)?
    private var connectorPoll: (id: UUID, task: Task<Void, Error>, completion: Completion)?
    private var foreground: (any OwnedTransportSettingsForeground)?
    private var foregroundStart: Task<Void, Error>?
    private var foregroundPoll: Task<Void, Error>?
    private var foregroundCleanup: (id: UUID, task: Task<Void, Error>)?
    private var closing: (id: UUID, task: Task<Void, Error>)?
    private var started = false
    private var polling = false
    private var foregroundReady = false
    private var cleanupRequired = false
    private var retiring = false
    private var settled = false

    init(control: any OwnedTransportSettingsControl, lifetime: any OwnedReleaseActivity,
         retryMilliseconds: Int = 1000, connector: (any OwnedTransportRelayConnector)? = nil,
         makeForeground: @escaping @Sendable () throws -> any OwnedTransportSettingsForeground) throws {
        guard (100...60000).contains(retryMilliseconds) else { throw GatewayPreparationError.invalidRecord }
        self.control = control; self.lifetime = lifetime; self.connector = connector; self.makeForeground = makeForeground
        retryDelay = .milliseconds(retryMilliseconds)
    }
    func start() async throws {
        guard !started, !retiring else { throw GatewayServiceError.unavailable }
        try lifetime.validate(); started = true
        let control = control, start = Task { try await control.start() }; controlStart = start
        try await start.value
        guard !retiring else { throw GatewayServiceError.unavailable }
        try lifetime.validate()
    }
    private func pollControl() async throws {
        if let current = controlPoll {
            guard current.completion.done.withLock({ $0 }) else { return }
            _ = await current.task.result
            if controlPoll?.id == current.id { controlPoll = nil }
        }
        guard !retiring else { throw GatewayServiceError.unavailable }
        let control = control, completion = Completion()
        let task = Task {
            defer { completion.done.withLock { $0 = true } }
            try await control.poll()
        }
        controlPoll = (UUID(), task, completion)
    }
    private func pollConnector() async {
        if let pending = connectorPoll {
            guard pending.completion.done.withLock({ $0 }) else { return }
            _ = await pending.task.result
            if connectorPoll?.id == pending.id { connectorPoll = nil }
        }
        guard !retiring, let connector else { return }
        let completion = Completion()
        let task = Task {
            defer { completion.done.withLock { $0 = true } }
            try await connector.poll()
        }
        connectorPoll = (UUID(), task, completion)
    }
    /// Optional failure leaves direct routes available. Invalid whole-process scope still stops this host.
    func poll() async throws {
        guard started, !retiring else { throw GatewayServiceError.unavailable }
        guard !polling else { return }
        polling = true; defer { polling = false }
        try Task.checkCancellation(); try lifetime.validate(); try await pollControl(); await pollConnector()
        if cleanupRequired {
            do { try await settleForeground() } catch {}
            try lifetime.validate(); return
        }
        guard ContinuousClock.now >= retryAt else { return }
        do {
            if foreground == nil {
                let instance = try makeForeground(); foreground = instance
                let startup = Task { try await instance.start() }; foregroundStart = startup
                try await startup.value
                guard !retiring else { throw GatewayServiceError.unavailable }
                try lifetime.validate(); foregroundStart = nil; foregroundReady = true
            }
            guard !retiring, foregroundReady, let foreground else { throw GatewayServiceError.unavailable }
            let work = Task { try await foreground.poll() }; foregroundPoll = work
            try await work.value
            guard !retiring else { throw GatewayServiceError.unavailable }
            foregroundPoll = nil; try Task.checkCancellation()
        } catch {
            if retiring { throw error }
            do { try await settleForeground() } catch {}
            retryAt = ContinuousClock.now.advanced(by: retryDelay)
        }
        guard !retiring else { throw GatewayServiceError.unavailable }
        try lifetime.validate()
    }
    private func beginForegroundCleanup() -> (id: UUID, task: Task<Void, Error>)? {
        if let foregroundCleanup { return foregroundCleanup }
        guard let foreground else { return nil }
        foreground.retire(); foregroundStart?.cancel(); foregroundPoll?.cancel()
        foregroundReady = false; cleanupRequired = true
        let start = foregroundStart, poll = foregroundPoll
        let pending = (UUID(), Task { _ = await start?.result; _ = await poll?.result; try await foreground.closeAndWait() })
        foregroundCleanup = pending; return pending
    }
    private func settleForeground() async throws {
        guard let pending = beginForegroundCleanup() else { return }
        do {
            try await pending.task.value
            if foregroundCleanup?.id == pending.id {
                foreground = nil; foregroundStart = nil; foregroundPoll = nil
                foregroundCleanup = nil; foregroundReady = false; cleanupRequired = false
            }
        } catch {
            if foregroundCleanup?.id == pending.id { foregroundCleanup = nil }
            throw error
        }
    }
    /// All owners begin cleanup before results are awaited. Failure keeps the baseline lock for retry.
    func close() async throws {
        retiring = true
        if settled { return }
        let pending: (id: UUID, task: Task<Void, Error>)
        if let closing { pending = closing }
        else {
            let foregroundCleanup = beginForegroundCleanup()
            controlStart?.cancel(); controlPoll?.task.cancel(); connectorPoll?.task.cancel()
            let start = controlStart, poll = controlPoll?.task, control = control, lifetime = lifetime
            let connector = connector, connectorPoll = connectorPoll?.task
            pending = (UUID(), Task {
                let controlClose = Task { _ = await start?.result; try await control.close() }
                let connectorClose = Task { try await connector?.close() }
                let controlResult = await controlClose.result, connectorResult = await connectorClose.result
                var foregroundResult = Result<Void, Error>.success(())
                if let foregroundCleanup { foregroundResult = await foregroundCleanup.task.result }
                _ = await poll?.result; _ = await connectorPoll?.result
                try controlResult.get(); try foregroundResult.get(); try connectorResult.get(); lifetime.close()
            })
            closing = pending
        }
        do {
            try await pending.task.value
            if closing?.id == pending.id {
                closing = nil; settled = true; controlStart = nil; controlPoll = nil; connectorPoll = nil
                foreground = nil; foregroundStart = nil; foregroundPoll = nil; foregroundCleanup = nil
            }
        } catch {
            if closing?.id == pending.id {
                closing = nil
                if let cleanup = foregroundCleanup, case .failure = await cleanup.task.result {
                    if foregroundCleanup?.id == cleanup.id { foregroundCleanup = nil }
                }
            }
            throw error
        }
    }
    deinit {
        if settled { return }
        foreground?.retire(); foregroundStart?.cancel(); foregroundPoll?.cancel()
        controlStart?.cancel(); controlPoll?.task.cancel(); connectorPoll?.task.cancel()
        let control = control, lifetime = lifetime, pending = closing?.task
        let connector = connector, connectorPoll = connectorPoll?.task
        let start = controlStart, poll = controlPoll?.task, foreground = foreground
        let foregroundStart = foregroundStart, foregroundPoll = foregroundPoll, foregroundCleanup = foregroundCleanup?.task
        Task {
            if let pending, (try? await pending.value) != nil { return }
            let firstConnectorClose = Task { try await connector?.close() }
            _ = await start?.result; _ = await foregroundStart?.result; _ = await foregroundPoll?.result
            var connectorDone = connector == nil
            var initialConnectorClose: Task<Void?, any Error>? = firstConnectorClose
            var foregroundDone = foreground == nil
            if let foregroundCleanup { foregroundDone = (try? await foregroundCleanup.value) != nil }
            while true {
                let controlClose = Task { try await control.close() }
                let alreadyForegroundDone = foregroundDone
                let closeForeground = Task { if !alreadyForegroundDone { try await foreground?.closeAndWait() } }
                let alreadyConnectorDone = connectorDone
                let closeConnector = initialConnectorClose ?? Task { if !alreadyConnectorDone { return try await connector?.close() }; return nil }
                initialConnectorClose = nil
                let controlResult = await controlClose.result, foregroundResult = await closeForeground.result
                let connectorResult = await closeConnector.result
                _ = await poll?.result; _ = await connectorPoll?.result
                if case .success = foregroundResult { foregroundDone = true }
                if case .success = connectorResult { connectorDone = true }
                if case .success = controlResult, foregroundDone, connectorDone { lifetime.close(); return }
                try? await Task.sleep(for: .milliseconds(100))
            }
        }
    }
}
