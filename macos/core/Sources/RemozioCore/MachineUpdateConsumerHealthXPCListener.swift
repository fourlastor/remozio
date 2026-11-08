import Foundation

/// Shared settlement only. Each endpoint keeps its own peer, codec and owner checks.
protocol MachineUpdateHealthEndpoint: AnyObject, Sendable {
    func close()
    func closeAndWait() async throws
}
extension MachineUpdateConsumerHealthXPCEndpoint: MachineUpdateHealthEndpoint {}

protocol MachineUpdateConsumerHealthEndpointBuilding: Sendable {
    func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
        onHandshake: @escaping @Sendable () -> Void,
        onClose: @escaping @Sendable () -> Void) throws -> any MachineUpdateHealthEndpoint
}

private final class NativeMachineUpdateHealthConnection: OwnedAuthorityConnection, @unchecked Sendable {
    let connection: NSXPCConnection
    let endpoint: any MachineUpdateHealthEndpoint
    init(connection: NSXPCConnection, endpoint: any MachineUpdateHealthEndpoint) {
        self.connection = connection; self.endpoint = endpoint
    }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
}

/// Owns the health listener and its admitted endpoints. Failed settlement retains its resources and budget.
final class MachineUpdateConsumerHealthXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let budget: AuthorityXPCWorkBudget
    private let builder: any MachineUpdateConsumerHealthEndpointBuilding
    private let verifyCurrent: @Sendable () throws -> Void
    private let makeConnection: @Sendable (NSXPCConnection, any MachineUpdateHealthEndpoint) -> any OwnedAuthorityConnection
    private var active: [UUID: any MachineUpdateHealthEndpoint] = [:]
    private var retired: [UUID: any MachineUpdateHealthEndpoint] = [:]
    private var started = false
    private var closed = false

    /// Anonymous listeners and owned builders prove lifecycle behavior only. They grant no native admission.
    init(listener: NSXPCListener, builder: any MachineUpdateConsumerHealthEndpointBuilding,
        maximumConnections: Int = 2, handshakeTimeoutMilliseconds: UInt64 = 5000,
        verifyCurrent: @escaping @Sendable () throws -> Void,
        makeConnection: @escaping @Sendable (NSXPCConnection, any MachineUpdateHealthEndpoint) -> any OwnedAuthorityConnection = {
            NativeMachineUpdateHealthConnection(connection: $0, endpoint: $1)
        }) throws {
        self.makeConnection = makeConnection
        self.listener = listener; self.builder = builder; self.verifyCurrent = verifyCurrent
        registry = try .init(maximum: maximumConnections, timeoutMilliseconds: handshakeTimeoutMilliseconds)
        budget = try .init(maximum: 1)
        super.init(); listener.delegate = self
    }
    deinit {
        listener.invalidate(); registry.close()
        let pending = Array(active.values) + Array(retired.values)
        Task { for endpoint in pending { try? await endpoint.closeAndWait() } }
    }
    func start() throws {
        try lock.withLock {
            guard !closed, !started else { throw MachineUpdateRoleChallengeError.unavailable }
            try verifyCurrent(); try registry.start(); started = true; listener.activate()
        }
    }
    func close() {
        lock.withLock {
            closed = true; listener.invalidate(); listener.delegate = nil
            for (id, endpoint) in active { retired[id] = endpoint }
            active.removeAll()
        }
        registry.close()
    }
    /// The host must retain its native scope when this throws. No failed close is converted into a successful health result.
    func closeAndWait() async throws {
        close()
        let pending = lock.withLock { retired }
        var failure: Error?
        for (id, endpoint) in pending {
            do { try await endpoint.closeAndWait(); reaped(id) }
            catch { if failure == nil { failure = error } }
        }
        if let failure { throw failure }
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard listener === self.listener, started, !closed, let id = registry.reserve() else {
                connection.invalidate(); return false
            }
            do {
                try verifyCurrent()
                let endpoint = try builder.make(connection: connection, budget: budget,
                    onHandshake: { [weak registry] in registry?.handshake(id) },
                    onClose: { [weak self] in self?.retire(id) })
                active[id] = endpoint
                return registry.install(makeConnection(connection, endpoint), id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
    private func retire(_ id: UUID) {
        let endpoint = lock.withLock { () -> (any MachineUpdateHealthEndpoint)? in
            guard let endpoint = active.removeValue(forKey: id) else { return nil }
            retired[id] = endpoint; return endpoint
        }
        registry.remove(id)
        if let endpoint {
            Task { [weak self] in
                do { try await endpoint.closeAndWait(); self?.reaped(id) }
                catch { /* Retain the failed owner until the enclosing host retries settlement. */ }
            }
        }
    }
    private func reaped(_ id: UUID) { lock.withLock { retired[id] = nil } }
}
