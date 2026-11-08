import Foundation

protocol OwnedSettingsConsumerHost: Sendable {
    func start() async throws
    func poll() async throws
    func close() async throws
}
extension GatewaySettingsConsumerHost: OwnedSettingsConsumerHost {}
extension TransportSettingsConsumerHost: OwnedSettingsConsumerHost {}

protocol OwnedMachineUpdateConsumerHealthListener: Sendable {
    func start() throws
    func close()
    func closeAndWait() async throws
}
extension MachineUpdateConsumerHealthXPCListener: OwnedMachineUpdateConsumerHealthListener {}

/// Owns only the health listener. Ordinary control, provider, relay, pairing and direct routes never start here.
actor MachineUpdateConsumerHealthHost: OwnedSettingsConsumerHost {
    private let listener: any OwnedMachineUpdateConsumerHealthListener
    private let activity: any OwnedReleaseActivity
    private var started = false, retiring = false, settled = false
    private var closing: (id: UUID, task: Task<Void, Error>)?

    init(listener: any OwnedMachineUpdateConsumerHealthListener, activity: any OwnedReleaseActivity) {
        self.listener = listener; self.activity = activity
    }
    func start() throws {
        guard !started, !retiring else { throw GatewayServiceError.unavailable }
        started = true
        do { try activity.validate(); try listener.start(); try activity.validate() }
        catch { retiring = true; listener.close(); throw error }
    }
    func poll() throws {
        guard started, !retiring else { throw GatewayServiceError.unavailable }
        do { try activity.validate() }
        catch { retiring = true; listener.close(); throw error }
    }
    /// Join admitted owners before releasing the native scope. A failed close keeps that scope for a later retry.
    func close() async throws {
        retiring = true; listener.close()
        guard !settled else { return }
        let pending: (id: UUID, task: Task<Void, Error>)
        if let closing { pending = closing }
        else {
            let listener = listener, activity = activity
            pending = (UUID(), Task { try await listener.closeAndWait(); activity.close() })
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
        let listener = listener, activity = activity, pending = closing?.task
        listener.close()
        Task {
            if let pending, (try? await pending.value) != nil { return }
            while true {
                do { try await listener.closeAndWait(); activity.close(); return }
                catch { try? await Task.sleep(for: .milliseconds(100)) }
            }
        }
    }
}
