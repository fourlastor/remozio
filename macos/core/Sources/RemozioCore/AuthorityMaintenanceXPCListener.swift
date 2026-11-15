import Darwin
import Foundation

/// Fixed address and signed participant metadata. These checks do not declare a reachable product service.
enum AuthorityMaintenanceChannelScope {
    static let formatName = "authority.maintenance-channel"
    static func serviceName(accountID: Data) throws -> String { try RuntimePreparationPaths(accountID: accountID).presenceService }
    static func validate(_ release: SignedReleaseEvidence, authority: AuthorityCodeEntry, setup: AuthorityCodeEntry) throws {
        guard authority.role == .authority, setup.role == .setupController, authority.active, setup.active,
              authority.teamID == setup.teamID else { throw RuntimePreparationError.changedScope }
        for entry in [authority, setup] {
            let path = entry.role == .authority ? InstalledAuthorityCommandConfiguration.executablePath : AdministrativeSetupConfiguration.executablePath
            guard let c = release.manifest.components.first(where: { $0.role == entry.role }),
                  c.identifier == entry.identifier, c.teamID == entry.teamID, c.generation == entry.installedGeneration,
                  c.relativePath == path, c.codeDirectoryHash == entry.codeDirectoryHash,
                  release.codeDirectoryHashes[entry.role] == entry.codeDirectoryHash,
                  let format = c.formats.first(where: { $0.name == formatName }),
                  format.readers.contains(1), format.writers.contains(1),
                  let close = c.formats.first(where: { $0.name == AuthorityMaintenanceCloseMarker.formatName }), close.readers.contains(1),
                  entry.role == .authority ? close.writers.contains(1) : close.writers.isEmpty else { throw RuntimePreparationError.changedScope }
        }
    }
}
protocol AuthorityMaintenanceEndpointBuilding: Sendable {
    func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
        onHandshake: @escaping @Sendable () -> Void, onClose: @escaping @Sendable () -> Void) throws -> AuthorityMaintenanceXPCEndpoint
}
private struct NativeMaintenanceEndpointBuilder: AuthorityMaintenanceEndpointBuilding {
    let setupCode: AuthorityCodeEntry, access: AuthorityMaintenanceChannelAccess
    func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget,
        onHandshake: @escaping @Sendable () -> Void, onClose: @escaping @Sendable () -> Void) throws -> AuthorityMaintenanceXPCEndpoint {
        try .init(connection: connection, setupCode: setupCode, access: access, budget: budget, onHandshake: onHandshake, onClose: onClose)
    }
}
private final class NativeMaintenanceConnection: OwnedAuthorityConnection, @unchecked Sendable {
    let connection: NSXPCConnection, endpoint: AuthorityMaintenanceXPCEndpoint
    init(_ connection: NSXPCConnection, _ endpoint: AuthorityMaintenanceXPCEndpoint) { self.connection = connection; self.endpoint = endpoint }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
}

/// Owns maintenance connections independently of the presence listener. Closing this owner never closes pairing admission.
final class AuthorityMaintenanceConnections: @unchecked Sendable {
    private let lock = NSRecursiveLock(), processID = getpid(), ownerUID = getuid()
    private let registry: AuthorityConnectionRegistry, budget: AuthorityXPCWorkBudget
    let setupPolicy: XPCPeerPolicy?
    private let builder: any AuthorityMaintenanceEndpointBuilding
    private let verifyCurrent: @Sendable () throws -> Void
    private var endpoints: [UUID: AuthorityMaintenanceXPCEndpoint] = [:], retired: [UUID: AuthorityMaintenanceXPCEndpoint] = [:]
    private var started = false, closed = false
    convenience init(accountID: Data, authorityCode: AuthorityCodeEntry, setupCode: AuthorityCodeEntry,
        release: SignedReleaseEvidence, access: AuthorityMaintenanceChannelAccess) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try access.validateIdentity(); try access.admission.requireAccount(accountID)
        try AuthorityMaintenanceChannelScope.validate(release, authority: authorityCode, setup: setupCode)
        let requirement = try AuthoritySelfValidation.requirement(for: authorityCode)
        let setupPolicy = try XPCPeerPolicy(teamID: setupCode.teamID, componentIdentifier: setupCode.identifier,
            approvedCodeDirectoryHashes: [setupCode.codeDirectoryHash], expectedUserID: 0)
        let verify: @Sendable () throws -> Void = {
            guard getuid() == 0, geteuid() == 0,
                  try DynamicCodeValidation.selfPath() == MachineBootstrap.bundlePath + "/" + InstalledAuthorityCommandConfiguration.executablePath else {
                throw RuntimePreparationError.changedScope
            }
            try access.validateIdentity(); try access.admission.requireAccount(accountID)
            try DynamicCodeValidation.validateSelf(requirement: requirement)
        }
        try verify()
        try self.init(builder: NativeMaintenanceEndpointBuilder(setupCode: setupCode, access: access), setupPolicy: setupPolicy,
            maximumConnections: 2, maximumOperations: 1, handshakeTimeoutMilliseconds: 5000, verifyCurrent: verify)
    }
    private init(builder: any AuthorityMaintenanceEndpointBuilding, setupPolicy: XPCPeerPolicy?, maximumConnections: Int,
        maximumOperations: Int, handshakeTimeoutMilliseconds: UInt64, verifyCurrent: @escaping @Sendable () throws -> Void) throws {
        self.setupPolicy = setupPolicy; self.builder = builder; self.verifyCurrent = verifyCurrent
        registry = try .init(maximum: maximumConnections, timeoutMilliseconds: handshakeTimeoutMilliseconds)
        budget = try .init(maximum: maximumOperations)
    }
    static func openOwned(builder: any AuthorityMaintenanceEndpointBuilding, setupPolicy: XPCPeerPolicy? = nil,
        maximumConnections: Int = 2, maximumOperations: Int = 1, handshakeTimeoutMilliseconds: UInt64 = 5000,
        verifyCurrent: @escaping @Sendable () throws -> Void = {}) throws -> AuthorityMaintenanceConnections {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return try .init(builder: builder, setupPolicy: setupPolicy, maximumConnections: maximumConnections, maximumOperations: maximumOperations,
            handshakeTimeoutMilliseconds: handshakeTimeoutMilliseconds, verifyCurrent: verifyCurrent)
    }
    deinit {
        guard getpid() == processID else { return }
        registry.close()
        let pending = Array(endpoints.values) + Array(retired.values)
        Task { for endpoint in pending { await endpoint.closeAndWait() } }
    }
    private func requireIdentity() throws {
        guard getpid() == processID, getuid() == ownerUID, geteuid() == ownerUID else { throw JournalLeaseError.invalidated }
    }
    func start() throws {
        try lock.withLock {
            try requireIdentity(); guard !started, !closed else { throw AuthorityXPCEndpointError.unavailable }
            try verifyCurrent(); try registry.start(); started = true
        }
    }
    func close() {
        guard getpid() == processID else { return }
        lock.withLock {
            closed = true
            for (id, endpoint) in endpoints { retired[id] = endpoint }; endpoints.removeAll()
        }
        registry.close()
    }
    func closeAndWait() async {
        guard getpid() == processID else { return }; close()
        let pending = lock.withLock { retired }
        for (id, endpoint) in pending { await endpoint.closeAndWait(); reaped(id) }
    }
    func retainedEndpoints() -> Int { lock.withLock { endpoints.count + retired.count } }
    func accept(_ connection: NSXPCConnection) -> Bool {
        guard getpid() == processID else { return false }
        return lock.withLock {
            guard started, !closed else { connection.invalidate(); return false }
            do {
                try requireIdentity(); try verifyCurrent()
                guard let id = registry.reserve() else { connection.invalidate(); return false }
                do {
                    let endpoint = try builder.make(connection: connection, budget: budget,
                        onHandshake: { [weak registry] in registry?.handshake(id) }, onClose: { [weak self] in self?.retire(id) })
                    endpoints[id] = endpoint
                    let accepted = registry.install(NativeMaintenanceConnection(connection, endpoint), id: id)
                    if !accepted { retire(id) }; return accepted
                } catch { registry.remove(id); throw error }
            } catch { connection.invalidate(); return false }
        }
    }
    private func retire(_ id: UUID) {
        let endpoint = lock.withLock { () -> AuthorityMaintenanceXPCEndpoint? in
            guard let endpoint = endpoints.removeValue(forKey: id) else { return nil }; retired[id] = endpoint; return endpoint
        }
        registry.remove(id)
        if let endpoint { Task { [weak self] in await endpoint.closeAndWait(); self?.reaped(id) } }
    }
    private func reaped(_ id: UUID) { lock.withLock { retired[id] = nil } }
}
