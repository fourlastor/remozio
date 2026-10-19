import Darwin
import Foundation

protocol GatewaySettingsControlEndpointBuilding: Sendable {
    func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
              onHandshake: @escaping @Sendable () -> Void,
              onClose: @escaping @Sendable () -> Void) throws -> GatewaySettingsControlXPCEndpoint
}

private struct NativeGatewaySettingsControlEndpointBuilder: GatewaySettingsControlEndpointBuilding {
    let setupCode: AuthorityCodeEntry
    let access: AuthorityGatewaySettingsAccess
    let acquireActivity: @Sendable () throws -> ReleaseActivityToken?
    func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
              onHandshake: @escaping @Sendable () -> Void,
              onClose: @escaping @Sendable () -> Void) throws -> GatewaySettingsControlXPCEndpoint {
        try .init(connection: connection, setupCode: setupCode, access: access, budget: budget,
            acquireActivity: acquireActivity, onHandshake: onHandshake, onClose: onClose)
    }
}

private final class NativeGatewaySettingsControlConnection: OwnedAuthorityConnection, @unchecked Sendable {
    let connection: NSXPCConnection
    let endpoint: GatewaySettingsControlXPCEndpoint
    init(_ connection: NSXPCConnection, _ endpoint: GatewaySettingsControlXPCEndpoint) {
        self.connection = connection; self.endpoint = endpoint
    }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
}

/// Owns a separate settings endpoint and joins disconnected work before the runtime can close its journal.
final class GatewaySettingsControlXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let budget: AuthorityXPCWorkBudget
    private let builder: any GatewaySettingsControlEndpointBuilding
    private let verifyCurrent: @Sendable () throws -> Void
    private var endpoints: [UUID: GatewaySettingsControlXPCEndpoint] = [:]
    private var retired: [UUID: GatewaySettingsControlXPCEndpoint] = [:]
    private var started = false
    private var closed = false

    convenience init(accountID: Data, authorityCode: AuthorityCodeEntry, setupCode: AuthorityCodeEntry,
                     release: SignedReleaseEvidence, access: AuthorityGatewaySettingsAccess,
                     acquireActivity: @escaping @Sendable () throws -> ReleaseActivityToken?) throws {
        guard getuid() == 0, geteuid() == 0, accountID == access.binding.accountID else {
            throw GatewayPreparationError.changedScope
        }
        try GatewaySettingsControlReleaseValidation.validate(release, authority: authorityCode, setup: setupCode)
        let rootPolicy = try XPCPeerPolicy(teamID: authorityCode.teamID, componentIdentifier: authorityCode.identifier,
            approvedCodeDirectoryHashes: [authorityCode.codeDirectoryHash], expectedUserID: 0)
        let setupPolicy = try XPCPeerPolicy(teamID: setupCode.teamID, componentIdentifier: setupCode.identifier,
            approvedCodeDirectoryHashes: [setupCode.codeDirectoryHash], expectedUserID: 0)
        let verify: @Sendable () throws -> Void = {
            guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
            try DynamicCodeValidation.validateSelf(requirement: rootPolicy.requirement)
            try access.verifyCurrent()
        }
        try verify()
        let listener = NSXPCListener(machServiceName: try GatewaySettingsControlAddress.serviceName(accountID: accountID))
        setupPolicy.configure(listener)
        try self.init(listener: listener, builder: NativeGatewaySettingsControlEndpointBuilder(
            setupCode: setupCode, access: access, acquireActivity: acquireActivity), verifyCurrent: verify)
    }

    // Anonymous listeners and owned builders test lifecycle behavior without granting native peer admission.
    init(listener: NSXPCListener, builder: any GatewaySettingsControlEndpointBuilding,
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
                return registry.install(NativeGatewaySettingsControlConnection(connection, endpoint), id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
    private func retire(_ id: UUID) {
        let endpoint = lock.withLock { () -> GatewaySettingsControlXPCEndpoint? in
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
