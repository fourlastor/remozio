import Foundation

protocol OwnedGatewaySettingsConsumerListener: Sendable {
    func start() throws
    func close()
    func closeAndWait() async
}
extension GatewaySettingsConsumerXPCListener: OwnedGatewaySettingsConsumerListener {}

/// Starts control before any optional backend. Provider failure does not remove the control listener.
actor GatewaySettingsConsumerHost {
    private let owner: GatewaySettingsConsumerOwner
    private let listeners: [any OwnedGatewaySettingsConsumerListener]
    private let activity: any OwnedReleaseActivity
    private let retryDelay: Duration
    private var retryAt = ContinuousClock.now
    private var started = false
    private var retiring = false
    private var settled = false
    private var closing: (id: UUID, task: Task<Void, Error>)?

    init(owner: GatewaySettingsConsumerOwner, listener: any OwnedGatewaySettingsConsumerListener,
         activity: any OwnedReleaseActivity, retryMilliseconds: Int = 1000,
         recoveryListener: (any OwnedGatewaySettingsConsumerListener)? = nil) throws {
        guard (100...60000).contains(retryMilliseconds) else { throw GatewayPreparationError.invalidRecord }
        self.owner = owner; listeners = [listener] + (recoveryListener.map { [$0] } ?? [])
        self.activity = activity; retryDelay = .milliseconds(retryMilliseconds)
    }
    func start() throws {
        guard !started, !retiring else { throw GatewayServiceError.unavailable }
        started = true
        do {
            try activity.validate()
            for listener in listeners { try listener.start(); try activity.validate() }
        }
        catch { retiring = true; listeners.forEach { $0.close() }; throw error }
    }
    /// Initial or accepted work can start. Provider failure keeps observation and quiescence available.
    func poll() async throws {
        guard started, !retiring else { throw GatewayServiceError.unavailable }
        try activity.validate()
        guard ContinuousClock.now >= retryAt else { return }
        do { _ = try await owner.startConfiguredRuntimeIfNeeded() }
        catch { retryAt = ContinuousClock.now.advanced(by: retryDelay) }
        try activity.validate()
    }
    func close() async throws {
        retiring = true; listeners.forEach { $0.close() }
        if settled { return }
        let pending: (id: UUID, task: Task<Void, Error>)
        if let closing { pending = closing }
        else {
            let listeners = listeners, owner = owner, activity = activity
            pending = (UUID(), Task {
                await owner.retire()
                for listener in listeners { await listener.closeAndWait() }
                try await owner.close()
                activity.close()
            })
            closing = pending
        }
        do {
            try await pending.task.value
            if closing?.id == pending.id { closing = nil; settled = true }
        } catch {
            if closing?.id == pending.id { closing = nil }
            throw error
        }
    }
    deinit {
        if settled { return }
        let listeners = listeners, owner = owner, activity = activity, pending = closing?.task
        listeners.forEach { $0.close() }
        Task {
            if let pending, (try? await pending.value) != nil { return }
            await owner.retire()
            for listener in listeners { await listener.closeAndWait() }
            while true {
                do { try await owner.close(); activity.close(); return }
                catch { try? await Task.sleep(for: .milliseconds(100)) }
            }
        }
    }
}
