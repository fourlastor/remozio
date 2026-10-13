import Darwin
import Foundation

private final class NativeAdministrativeSetupConnection: OwnedAuthorityConnection, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let endpoint: AdministrativeSetupXPCEndpoint
    init(connection: NSXPCConnection, endpoint: AdministrativeSetupXPCEndpoint) {
        self.connection = connection; self.endpoint = endpoint
    }
    func activate() { connection.activate() }
    func close() { endpoint.close(); connection.invalidate() }
    deinit { connection.invalidate() }
}

/// Root local listener. The host must verify protected code placement and launchd registration independently.
/// Each app connection uses its kernel UID. The shared setup owner checks account ownership on every operation.
public final class AdministrativeSetupXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let owner: SetupAccountOwner
    private let teamID: String
    private let appIdentifier: String
    private let appHashes: Set<Data>
    private var running = false
    private var closed = false

    public init(serviceName: String, teamID: String, appIdentifier: String, appHashes: Set<Data>, owner: SetupAccountOwner,
                maximumConnections: Int = 8, handshakeTimeoutMilliseconds: UInt64 = 5000) throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        guard serviceName.hasPrefix("dev.remozio."), (1...255).contains(serviceName.utf8.count),
              serviceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 46 || $0 == 45 }) else {
            throw AdministrativeSetupError.invalidConfiguration
        }
        let template = try XPCPeerPolicy(teamID: teamID, componentIdentifier: appIdentifier,
            approvedCodeDirectoryHashes: appHashes, expectedUserID: 0)
        registry = try AuthorityConnectionRegistry(maximum: maximumConnections, timeoutMilliseconds: handshakeTimeoutMilliseconds)
        listener = NSXPCListener(machServiceName: serviceName)
        self.owner = owner; self.teamID = teamID; self.appIdentifier = appIdentifier; self.appHashes = appHashes
        super.init()
        template.configure(listener)
        listener.delegate = self
    }
    deinit { listener.invalidate(); registry.close() }
    public func start() throws {
        guard getuid() == 0, geteuid() == 0 else { throw JournalLeaseError.rootRequired }
        try lock.withLock {
            guard !running, !closed else { throw AdministrativeSetupError.unavailable }
            try owner.verifyCurrent()
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
                let endpoint = try AdministrativeSetupXPCEndpoint(connection: connection, peerPolicy: policy, owner: owner,
                    onHandshake: { [weak registry] in registry?.handshake(id) }, onClose: { [weak registry] in registry?.remove(id) })
                let retained = NativeAdministrativeSetupConnection(connection: connection, endpoint: endpoint)
                return registry.install(retained, id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
}
