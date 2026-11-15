import Darwin
import Foundation

/// Protected installation selects a distinct Mach service and the interactive account's signed app.
public struct AuthorityPresenceEndpointConfiguration: Sendable {
    public let serviceName: String
    public let appPolicy: XPCPeerPolicy
    public init(serviceName: String, appPolicy: XPCPeerPolicy) throws {
        guard GatewayWakeEndpointConfiguration.validServiceName(serviceName),
              appPolicy.expectedUserID > 0, appPolicy.expectedUserID < UInt32.max else { throw AuthorityPresenceError.invalidConfiguration }
        self.serviceName = serviceName; self.appPolicy = appPolicy
    }
}

private final class NativePresenceConnection: OwnedAuthorityConnection, @unchecked Sendable {
    private let connection: NSXPCConnection
    private let endpoint: AuthorityPresenceXPCEndpoint
    private let pairing: AuthorityPairingXPCEndpoint?
    init(connection: NSXPCConnection, endpoint: AuthorityPresenceXPCEndpoint, pairing: AuthorityPairingXPCEndpoint? = nil) {
        self.connection = connection; self.endpoint = endpoint; self.pairing = pairing
    }
    func activate() { connection.activate() }
    func close() { pairing?.close(); endpoint.close(); connection.invalidate() }
    deinit { connection.invalidate() }
}

protocol AuthorityPresenceOwnedEndpointBuilding: Sendable {
    func make(connection: NSXPCConnection, budget: AuthorityXPCWorkBudget, onHandshake: @escaping @Sendable () -> Void,
        onClose: @escaping @Sendable () -> Void) throws -> any OwnedAuthorityConnection
}
/// Root owns this listener independently of the transport interface. Installation must register its Mach service.
public final class AuthorityPresenceXPCListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    /// Ordinary-owner controls exercise routing only. They cannot construct a native Root listener.
    struct OwnedControls: @unchecked Sendable {
        let listener: NSXPCListener, builder: any AuthorityPresenceOwnedEndpointBuilding
        let peerUID: @Sendable (NSXPCConnection) -> uid_t
        let configure: @Sendable (String) -> Void
        let supportsMaintenance: Bool
        let validateSelf: @Sendable (JournalTransaction) throws -> Void
    }
    private let owned: OwnedControls?
    private let lock = NSRecursiveLock()
    private let listener: NSXPCListener
    private let registry: AuthorityConnectionRegistry
    private let budget: AuthorityXPCWorkBudget
    private let policy: XPCPeerPolicy
    private let presence: AuthorityPresenceRuntime
    private let access: AuthorityPresenceAccess
    private let pairingAccess: AuthorityPairingSetupAccess?
    private let maintenancePairingOwners: AuthorityMaintenancePairingOwners?
    private let clock: AuthorityClock
    private var maintenance: AuthorityMaintenanceConnections?, setupPolicy: XPCPeerPolicy?
    var supportsMaintenance: Bool { maintenancePairingOwners != nil || owned?.supportsMaintenance == true }
    private var running = false
    private var closed = false
    public convenience init(configuration: AuthorityPresenceEndpointConfiguration, journal: AuthorityJournal,
                presence: AuthorityPresenceRuntime, clock: AuthorityClock,
                pairingConfiguration: AuthorityPairingSetupConfiguration? = nil, signer: EnclaveAuthorityRequestSigner? = nil,
                minimumEnvelopeVersion: UInt64 = 1, auditVersions: Set<UInt64> = [], maximumConnections: Int = 4, handshakeTimeoutMilliseconds: UInt64 = 5000, maximumOperations: Int = 4) throws {
        try self.init(configuration: configuration, journal: journal, presence: presence, clock: clock,
            pairingConfiguration: pairingConfiguration, signer: signer, minimumEnvelopeVersion: minimumEnvelopeVersion,
            auditVersions: auditVersions, maximumConnections: maximumConnections,
            handshakeTimeoutMilliseconds: handshakeTimeoutMilliseconds, maximumOperations: maximumOperations, owned: nil)
    }
    static func openOwned(configuration: AuthorityPresenceEndpointConfiguration, journal: AuthorityJournal,
        presence: AuthorityPresenceRuntime, clock: AuthorityClock, controls: OwnedControls, maximumConnections: Int = 1) throws -> AuthorityPresenceXPCListener {
        guard getuid() > 0, getuid() == geteuid() else { throw JournalLeaseError.unsafeMetadata }
        return try .init(configuration: configuration, journal: journal, presence: presence, clock: clock,
            maximumConnections: maximumConnections, owned: controls)
    }
    private init(configuration: AuthorityPresenceEndpointConfiguration, journal: AuthorityJournal,
                presence: AuthorityPresenceRuntime, clock: AuthorityClock,
                pairingConfiguration: AuthorityPairingSetupConfiguration? = nil, signer: EnclaveAuthorityRequestSigner? = nil,
                minimumEnvelopeVersion: UInt64 = 1, auditVersions: Set<UInt64> = [], maximumConnections: Int = 4, handshakeTimeoutMilliseconds: UInt64 = 5000, maximumOperations: Int = 4, owned: OwnedControls?) throws {
        self.owned = owned
        registry = try AuthorityConnectionRegistry(maximum: maximumConnections, timeoutMilliseconds: handshakeTimeoutMilliseconds)
        budget = try AuthorityXPCWorkBudget(maximum: maximumOperations)
        policy = configuration.appPolicy; self.presence = presence; self.clock = clock
        access = try AuthorityPresenceAccess(journal: journal, presence: presence, appPolicy: configuration.appPolicy,
            now: { try clock.now() }, validateSelf: owned?.validateSelf ?? AuthoritySelfValidation.validate)
        if let pairingConfiguration {
            guard let signer, signer.macID == presence.configuration.macID, signer.accountID == presence.configuration.accountID else {
                throw AuthorityPairingSetupError.wrongScope
            }
            pairingAccess = try .init(journal: journal, signer: signer, appPolicy: configuration.appPolicy,
                configuration: pairingConfiguration, minimumEnvelopeVersion: minimumEnvelopeVersion, auditVersions: auditVersions, now: { try clock.now() })
        } else { pairingAccess = nil }
        maintenancePairingOwners = pairingAccess.map { .init(admission: $0.maintenanceAdmission) }
        listener = owned?.listener ?? NSXPCListener(machServiceName: configuration.serviceName)
        super.init()
        if let owned { owned.configure(policy.requirement) } else { policy.configure(listener) }; listener.delegate = self
    }
    deinit {
        listener.invalidate(); registry.close(); let owner = maintenance
        owner?.close(); Task { await owner?.closeAndWait() }
    }
    func prepareMaintenance(policy setup: XPCPeerPolicy) throws {
        try lock.withLock {
            guard !running, !closed, supportsMaintenance, policy.expectedUserID > 0, setup.expectedUserID == 0,
                  setupPolicy == nil else { throw AuthorityPresenceIPCError.unavailable }
            let requirement = "(\(policy.requirement)) or (\(setup.requirement))"
            if let owned { owned.configure(requirement) } else { listener.setConnectionCodeSigningRequirement(requirement) }
            setupPolicy = setup
        }
    }
    func installMaintenance(_ owner: AuthorityMaintenanceConnections) throws {
        try lock.withLock {
            guard running, !closed, maintenance == nil, let setupPolicy,
                  owner.setupPolicy?.requirement == setupPolicy.requirement else { throw AuthorityPresenceIPCError.unavailable }
            try owner.start(); maintenance = owner
        }
    }
    func closeMaintenanceAndWait() async {
        let owner = lock.withLock { maintenance }
        await owner?.closeAndWait()
        lock.withLock { if maintenance === owner { maintenance = nil } }
    }
    public func start() throws {
        try lock.withLock {
            guard owned != nil || (getuid() == 0 && geteuid() == 0), !running, !closed else { throw AuthorityPresenceIPCError.unavailable }
            if owned == nil { try access.verifyCurrent(); try pairingAccess?.verifyCurrent() }
            try registry.start(); running = true; listener.activate()
        }
    }
    var armedMaintenanceCloseAdmission: AuthorityMaintenancePairingAdmission? {
        guard let admission = maintenancePairingOwners?.admission, admission.hasArmedShutdown else { return nil }
        return admission
    }
    func currentMaintenancePairingOwners() throws -> AuthorityMaintenancePairingOwners {
        try lock.withLock {
            guard running, !closed, let maintenancePairingOwners else { throw AuthorityPairingSetupError.unavailable }
            try pairingAccess?.verifyCurrent(); return maintenancePairingOwners
        }
    }
    public func close() {
        let owner = lock.withLock { closed = true; running = false; listener.invalidate(); listener.delegate = nil; return maintenance }
        registry.close(); owner?.close()
    }
    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.withLock {
            guard listener === self.listener, running, !closed else { connection.invalidate(); return false }
            if (owned?.peerUID(connection) ?? connection.effectiveUserIdentifier) == 0 {
                guard let maintenance else { connection.invalidate(); return false }
                return maintenance.accept(connection)
            }
            guard let id = registry.reserve() else { connection.invalidate(); return false }
            do {
                if let owned {
                    let app = try owned.builder.make(connection: connection, budget: budget,
                        onHandshake: { [weak registry] in registry?.handshake(id) }, onClose: { [weak registry] in registry?.remove(id) })
                    return registry.install(app, id: id)
                }
                let binding = try AuthorityPresenceBinding(macID: presence.configuration.macID, accountID: presence.configuration.accountID,
                    clockEpoch: clock.epoch, connectionID: id)
                let endpoint = try AuthorityPresenceXPCEndpoint(connection: connection, policy: policy, binding: binding,
                    budget: budget, access: access, onHandshake: { [weak registry] in registry?.handshake(id) },
                    onClose: { [weak registry] in registry?.remove(id) })
                let pairing: AuthorityPairingXPCEndpoint?
                if let pairingAccess {
                    let local = try AuthorityPairingXPCEndpoint(connection: connection, policy: policy, access: pairingAccess,
                        budget: budget, onHandshake: { [weak registry] in registry?.handshake(id) },
                        onClose: { [weak registry] in registry?.remove(id) })
                    try maintenancePairingOwners?.retain(local, id: id)
                    pairing = local
                    connection.exportedInterface = NSXPCInterface(with: AuthorityAppXPCProtocol.self)
                    connection.exportedObject = AuthorityAppXPCEndpoint(presence: endpoint, pairing: local)
                    connection.interruptionHandler = { [weak endpoint, weak local] in local?.close(); endpoint?.close() }
                    connection.invalidationHandler = { [weak endpoint, weak local] in local?.close(); endpoint?.close() }
                } else { pairing = nil }
                return registry.install(NativePresenceConnection(connection: connection, endpoint: endpoint, pairing: pairing), id: id)
            } catch { registry.remove(id); connection.invalidate(); return false }
        }
    }
}
