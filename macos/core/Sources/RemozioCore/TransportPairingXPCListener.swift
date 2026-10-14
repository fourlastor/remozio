import Foundation
import Security

private final class NativeTransportPairingConnection: OwnedAuthorityConnection, @unchecked Sendable {
    let connection: NSXPCConnection
    let endpoint: TransportPairingXPCEndpoint
    init(_ connection: NSXPCConnection, _ endpoint: TransportPairingXPCEndpoint) {
        self.connection = connection; self.endpoint = endpoint
    }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
}

/// A dedicated transport account exposes setup control only to the configured interactive account's signed app.
public final class TransportPairingXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let policy: XPCPeerPolicy
    private let ownerFactory: @Sendable () throws -> TransportPairingSetupOwner
    private var endpoints: [UUID: TransportPairingXPCEndpoint] = [:]
    private var retired: [UUID: TransportPairingXPCEndpoint] = [:]
    private var started = false
    private var closed = false
    public init(configuration: TransportPairingControlConfiguration, identity: SecIdentity) throws {
        try DedicatedServiceAccount.requireCurrent(serviceUID: configuration.transportUID, ownerUID: configuration.ownerUID)
        let holder = TransportPairingListenerIdentity(identity)
        ownerFactory = { try TransportPairingSetupOwner(configuration: configuration, identity: holder.value) }
        policy = configuration.appPolicy
        registry = try AuthorityConnectionRegistry(maximum: 1, timeoutMilliseconds: configuration.timeoutMilliseconds)
        listener = NSXPCListener(machServiceName: configuration.serviceName)
        super.init(); policy.configure(listener); listener.delegate = self
    }
    deinit { listener.invalidate(); registry.close() }
    public func start() throws {
        try lock.withLock {
            guard !started, !closed else { throw TransportPairingControlError.closed }
            try registry.start(); started = true; listener.activate()
        }
    }
    public func close() {
        lock.withLock {
            closed = true; listener.invalidate(); listener.delegate = nil
            for (id, endpoint) in endpoints { retired[id] = endpoint }; endpoints.removeAll()
        }
        registry.close()
    }
    public func closeAndWait() async {
        close()
        let owned = lock.withLock { Array(retired.values) }
        for endpoint in owned { await endpoint.closeAndWait() }
    }
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard listener === self.listener, started, !closed, let id = registry.reserve() else { connection.invalidate(); return false }
            do {
                policy.configure(connection)
                let endpoint = try TransportPairingXPCEndpoint(connection: connection, policy: policy, owner: ownerFactory(),
                    onHandshake: { [weak registry] in registry?.handshake(id) }, onClose: { [weak self] in self?.retire(id) })
                connection.exportedInterface = NSXPCInterface(with: TransportPairingXPCProtocol.self)
                connection.exportedObject = endpoint
                connection.interruptionHandler = { [weak endpoint] in endpoint?.close() }
                connection.invalidationHandler = { [weak endpoint] in endpoint?.close() }
                endpoints[id] = endpoint
                return registry.install(NativeTransportPairingConnection(connection, endpoint), id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
    private func retire(_ id: UUID) {
        let endpoint = lock.withLock { () -> TransportPairingXPCEndpoint? in
            guard let endpoint = endpoints.removeValue(forKey: id) else { return nil }; retired[id] = endpoint; return endpoint
        }
        registry.remove(id)
        if let endpoint {
            Task { [weak self] in await endpoint.closeAndWait(); self?.reaped(id) }
        }
    }
    private func reaped(_ id: UUID) { lock.withLock { retired[id] = nil } }
}
private final class TransportPairingListenerIdentity: @unchecked Sendable {
    let value: SecIdentity
    init(_ value: SecIdentity) { self.value = value }
}
