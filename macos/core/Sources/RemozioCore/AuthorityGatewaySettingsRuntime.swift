import Foundation

protocol OwnedGatewaySettingsControlListener: AnyObject, Sendable {
    func start() throws
    func closeAndWait() async
}
extension GatewaySettingsControlXPCListener: OwnedGatewaySettingsControlListener {}

/// Retains a settings listener through startup failure and joins its work before the enclosing journal can close.
actor AuthorityGatewaySettingsRuntime {
    private let makeListener: @Sendable () throws -> (any OwnedGatewaySettingsControlListener)?
    private var listener: (any OwnedGatewaySettingsControlListener)?
    private var started = false
    private var closed = false
    private var closing: Task<Void, Never>?

    init(makeListener: @escaping @Sendable () throws -> (any OwnedGatewaySettingsControlListener)?) {
        self.makeListener = makeListener
    }
    deinit {
        let pending = closing, previous = listener
        Task {
            if let pending { await pending.value }
            else { await previous?.closeAndWait() }
        }
    }
    func start() throws {
        guard !started, !closed else { throw GatewayPreparationError.changedScope }
        started = true
        listener = try makeListener()
        try listener?.start()
    }
    func close() async {
        if let closing { await closing.value; return }
        guard !closed else { return }
        closed = true
        let previous = listener
        let cleanup = Task<Void, Never> { await previous?.closeAndWait() }
        closing = cleanup
        await cleanup.value
        listener = nil; closing = nil
    }
}
