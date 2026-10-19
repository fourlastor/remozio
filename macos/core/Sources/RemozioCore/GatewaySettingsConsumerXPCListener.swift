import Darwin
import Foundation

protocol GatewaySettingsConsumerEndpointBuilding: Sendable {
    func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
              onHandshake: @escaping @Sendable () -> Void,
              onClose: @escaping @Sendable () -> Void) throws -> GatewaySettingsConsumerXPCEndpoint
}

private struct NativeGatewaySettingsConsumerEndpointBuilder: GatewaySettingsConsumerEndpointBuilding {
    let setupCode: AuthorityCodeEntry
    let access: GatewaySettingsConsumerAccess
    let acquireActivity: @Sendable () throws -> ReleaseActivityToken?
    func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
              onHandshake: @escaping @Sendable () -> Void,
              onClose: @escaping @Sendable () -> Void) throws -> GatewaySettingsConsumerXPCEndpoint {
        try .init(connection: connection, setupCode: setupCode, access: access, budget: budget,
            acquireActivity: acquireActivity, onHandshake: onHandshake, onClose: onClose)
    }
}

private final class NativeGatewaySettingsConsumerConnection: OwnedAuthorityConnection, @unchecked Sendable {
    let connection: NSXPCConnection
    let endpoint: GatewaySettingsConsumerXPCEndpoint
    init(_ connection: NSXPCConnection, _ endpoint: GatewaySettingsConsumerXPCEndpoint) {
        self.connection = connection; self.endpoint = endpoint
    }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
}

/// Owns a separate settings endpoint and joins disconnected work before the runtime can close its journal.
final class GatewaySettingsConsumerXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let budget: AuthorityXPCWorkBudget
    private let builder: any GatewaySettingsConsumerEndpointBuilding
    private let verifyCurrent: @Sendable () throws -> Void
    private var endpoints: [UUID: GatewaySettingsConsumerXPCEndpoint] = [:]
    private var retired: [UUID: GatewaySettingsConsumerXPCEndpoint] = [:]
    private var started = false
    private var closed = false

    convenience init(consumerCode: AuthorityCodeEntry, setupCode: AuthorityCodeEntry,
                     release: SignedReleaseEvidence, access: GatewaySettingsConsumerAccess,
                     acquireActivity: @escaping @Sendable () throws -> ReleaseActivityToken?) throws {
        try access.requireNativeProcess()
        try GatewaySettingsConsumerReleaseValidation.validate(release, role: access.binding.role, consumer: consumerCode, setup: setupCode)
        let localPolicy = try XPCPeerPolicy(teamID: consumerCode.teamID, componentIdentifier: consumerCode.identifier,
            approvedCodeDirectoryHashes: [consumerCode.codeDirectoryHash], expectedUserID: access.serviceUID)
        let setupPolicy = try XPCPeerPolicy(teamID: setupCode.teamID, componentIdentifier: setupCode.identifier,
            approvedCodeDirectoryHashes: [setupCode.codeDirectoryHash], expectedUserID: 0)
        let verify: @Sendable () throws -> Void = {
            try access.requireNativeProcess()
            try DynamicCodeValidation.validateSelf(requirement: localPolicy.requirement)
            try access.verifyCurrent()
        }
        try verify()
        let listener = NSXPCListener(machServiceName: try access.binding.role.serviceName(accountID: access.binding.accountID))
        setupPolicy.configure(listener)
        try self.init(listener: listener, builder: NativeGatewaySettingsConsumerEndpointBuilder(
            setupCode: setupCode, access: access, acquireActivity: acquireActivity), verifyCurrent: verify)
    }

    // Anonymous listeners and owned builders test lifecycle behavior without granting native peer admission.
    init(listener: NSXPCListener, builder: any GatewaySettingsConsumerEndpointBuilding,
         maximumConnections: Int = 2, maximumOperations: Int = 1, handshakeTimeoutMilliseconds: UInt64 = 5000,
         verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        self.listener = listener; self.builder = builder; self.verifyCurrent = verifyCurrent
        registry = try .init(maximum: maximumConnections, timeoutMilliseconds: handshakeTimeoutMilliseconds)
        budget = try .init(maximum: maximumOperations)
        super.init(); listener.delegate = self
    }
    deinit {
        listener.invalidate(); registry.close()
        let pending = Array(endpoints.values) + Array(retired.values)
        Task { for endpoint in pending { await endpoint.closeAndWait() } }
    }
    func start() throws {
        try lock.withLock {
            guard !started, !closed else { throw GatewayPreparationError.changedScope }
            try verifyCurrent(); try registry.start(); started = true; listener.activate()
        }
    }
    func close() {
        lock.withLock {
            closed = true; listener.invalidate(); listener.delegate = nil
            for (id, endpoint) in endpoints { retired[id] = endpoint }
            endpoints.removeAll()
        }
        registry.close()
    }
    func closeAndWait() async {
        close()
        let pending = lock.withLock { Array(retired.values) }
        for endpoint in pending { await endpoint.closeAndWait() }
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
                endpoints[id] = endpoint
                return registry.install(NativeGatewaySettingsConsumerConnection(connection, endpoint), id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
    private func retire(_ id: UUID) {
        let endpoint = lock.withLock { () -> GatewaySettingsConsumerXPCEndpoint? in
            guard let endpoint = endpoints.removeValue(forKey: id) else { return nil }
            retired[id] = endpoint; return endpoint
        }
        registry.remove(id)
        if let endpoint {
            Task { [weak self] in
                await endpoint.closeAndWait()
                self?.reaped(id)
            }
        }
    }
    private func reaped(_ id: UUID) { lock.withLock { retired[id] = nil } }
}
