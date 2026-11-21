import Darwin
import Foundation

private final class NativeAdministrativeSetupConnection: OwnedAuthorityConnection, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let facade: AdministrativeSetupConnectionFacade
    init(connection: NSXPCConnection, facade: AdministrativeSetupConnectionFacade) {
        self.connection = connection; self.facade = facade
    }
    func activate() { connection.activate() }
    func close() { facade.close(); connection.invalidate() }
    deinit { connection.invalidate() }
}

/// Root local listener. The host must verify protected code placement and launchd registration independently.
/// Each app connection uses its kernel UID. The shared setup owner checks account ownership on every operation.
/// A connection first chooses a lane: status (bounded, never takes the owner lock) or a normal hello (builds the endpoint).
public final class AdministrativeSetupXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: SetupConnectionSlots
    private let routing: AdministrativeSetupLifecycle.Routing
    private let validateStartup: @Sendable () throws -> Void
    private let nativeRecoveryContext: AdministrativeSetupService.NativeRecoveryContext?
    private let teamID: String
    private let appIdentifier: String
    private let appHashes: Set<Data>
    private var running = false
    private var closed = false

    public convenience init(serviceName: String, teamID: String, appIdentifier: String, appHashes: Set<Data>, owner: SetupAccountOwner,
                maximumConnections: Int = 8, handshakeTimeoutMilliseconds: UInt64 = 5000) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        let routing = try AdministrativeSetupLifecycle.Routing.verifiedOwner(owner)
        try self.init(serviceName: serviceName, teamID: teamID, appIdentifier: appIdentifier, appHashes: appHashes,
            routing: routing, validateStartup: { try owner.verifyCurrent() },
            maximumConnections: maximumConnections, handshakeTimeoutMilliseconds: handshakeTimeoutMilliseconds)
    }
    init(serviceName: String, teamID: String, appIdentifier: String, appHashes: Set<Data>,
        routing: AdministrativeSetupLifecycle.Routing, validateStartup: @escaping @Sendable () throws -> Void,
        maximumConnections: Int = 8, handshakeTimeoutMilliseconds: UInt64 = 5000,
        nativeRecoveryContext: AdministrativeSetupService.NativeRecoveryContext? = nil) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard MacServiceNamespace.accepts(serviceName), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }) else {
            throw AdministrativeSetupError.invalidConfiguration
        }
        let template = try XPCPeerPolicy(teamID: teamID, componentIdentifier: appIdentifier,
            approvedCodeDirectoryHashes: appHashes, expectedUserID: 0)
        registry = try SetupConnectionSlots(maximumConnections: maximumConnections, timeoutMilliseconds: handshakeTimeoutMilliseconds)
        listener = NSXPCListener(machServiceName: serviceName)
        self.routing = routing; self.validateStartup = validateStartup; self.nativeRecoveryContext = nativeRecoveryContext
        self.teamID = teamID; self.appIdentifier = appIdentifier; self.appHashes = appHashes
        super.init()
        template.configure(listener)
        listener.delegate = self
    }
    deinit { listener.invalidate(); registry.close() }
    public func start() throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try lock.withLock {
            guard !running, !closed else { throw AdministrativeSetupError.unavailable }
            try validateStartup()
            try registry.start(); running = true; listener.activate()
        }
    }
    /// Close the listener before closing its shared setup owner.
    public func close() {
        lock.withLock { closed = true; running = false; listener.invalidate(); listener.delegate = nil }
        registry.close()
    }
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard getuid() == 0, geteuid() == 0, listener === self.listener, running, !closed,
                  let id = registry.reserve() else { connection.invalidate(); return false }
            do {
                let uid = connection.effectiveUserIdentifier
                guard uid > 0, uid < UInt32.max else { throw AdministrativeSetupError.wrongAccount }
                let policy = try XPCPeerPolicy(teamID: teamID, componentIdentifier: appIdentifier,
                    approvedCodeDirectoryHashes: appHashes, expectedUserID: uid)
                let facade = try Self.facade(connection: connection, policy: policy, routing: routing, registry: registry, id: id, nativeRecoveryContext: nativeRecoveryContext)
                let retained = NativeAdministrativeSetupConnection(connection: connection, facade: facade)
                return registry.install(retained, id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
    /// Accept-time work: real credentials, the lifetime observer and the facade only. No owner access, no store, no admission.
    private static func facade(connection: NSXPCConnection, policy: XPCPeerPolicy, routing: AdministrativeSetupLifecycle.Routing,
                               registry: SetupConnectionSlots, id: UUID,
                               nativeRecoveryContext: AdministrativeSetupService.NativeRecoveryContext?) throws -> AdministrativeSetupConnectionFacade {
        _ = try policy.verifyCredentials(connection)
        let invocation = XPCInvocationGuard(connection: connection, policy: policy)
        let facade = AdministrativeSetupConnectionFacade(
            verify: { try invocation.verifyInvocation() },
            select: { [weak registry] in registry?.select($0, id: id) ?? false },
            openNormal: { [registry] close in
                try AdministrativeSetupXPCEndpoint.openNormal(invocation: invocation, owner: routing.normalOwner(),
                    onHandshake: { [weak registry] in registry?.handshake(id) }, close: close)
            },
            status: { routing.status($0) },
            check: { routing.checkStatus() },
            touch: { [weak registry] in registry?.touch(id) },
            normalAllowed: { routing.allowsNormal },
            openRecovery: { close in
                guard let nativeRecoveryContext else { throw AdministrativeSetupError.unavailable }
                return try SetupOrphanRecoveryEndpoint.openNative(context: nativeRecoveryContext, invocation: invocation, close: close)
            },
            recoveryAllowed: { nativeRecoveryContext?.permitsSession() ?? false },
            onRecoveryHandshake: { [weak registry] in registry?.recoveryHandshake(id) },
            invalidate: { [weak connection, weak registry] in invocation.retireConnection(); connection?.invalidate(); registry?.remove(id) })
        policy.configure(connection)
        connection.exportedInterface = NSXPCInterface(with: AdministrativeSetupServiceXPCProtocol.self)
        connection.exportedObject = facade
        // Handler execution retires the context before the prior handler and the facade close.
        try invocation.observeConnectionLifetime(onClose: { [weak facade] in facade?.close() })
        return facade
    }
}
